// SPDX-License-Identifier: GPL-2.0

//! Safe wrappers over the crypto `skcipher` framework for virtio-crypto and similar async cipher
//! drivers. Wraps: registering an `skcipher_alg` (`crypto_register_skcipher`), the `crypto_skcipher`
//! tfm + `skcipher_request` accessors (ctx/src/dst/cryptlen/iv/ivsize/reqtfm), and async completion
//! (`skcipher_request_complete`). The classic async `encrypt`/`decrypt` callbacks (return
//! `-EINPROGRESS`, complete later) are used — NOT the `crypto_engine` queueing helper (omitted as
//! documented minimal scope), so this abstraction wraps no engine.
//!
//! The C-boundary `unsafe` — the `skcipher_alg` vtable trampolines, raw `crypto_skcipher`/
//! `skcipher_request` pointers, the tfm/request ctx offset arithmetic, `cra_name`/`cra_driver_name`
//! `[c_char; 128]` initialisation — lives here; a driver built on this module is 0-unsafe. Wrapper
//! methods are `#[inline(always)]` so the driver `.ko` references the C symbols directly.
//!
//! C header: [`include/crypto/skcipher.h`](srctree/include/crypto/skcipher.h).

use crate::{
    bindings,
    error::{from_result, to_result, Result},
    prelude::*,
};
use core::{
    ffi::c_int,
    marker::PhantomData,
    mem::size_of,
    ptr::NonNull,
};

/// `-EINPROGRESS` — the return value signalling async completion (the request will be completed
/// later via [`SkcipherRequest::complete`]). `EINPROGRESS = 115` (`include/uapi/asm-generic/errno.h`).
const EINPROGRESS_RET: c_int = -(bindings::EINPROGRESS as c_int);

/// `CRYPTO_ALG_ASYNC` — the alg flag for an async skcipher (`include/linux/crypto.h`).
const CRYPTO_ALG_ASYNC: u32 = bindings::CRYPTO_ALG_ASYNC;

/// Implement this trait to interface the crypto `skcipher` framework as an async cipher. The
/// framework calls [`Operations::setkey`] to program a key (create a device session), then
/// [`Operations::encrypt`]/[`Operations::decrypt`] for each request; the driver submits to the
/// device + later calls [`SkcipherRequest::complete`] (from a vq callback). Mirrors
/// `struct skcipher_alg` (the classic async `encrypt`/`decrypt` callbacks; no `crypto_engine`).
pub trait Operations: Sized {
    /// Per-tfm context (sized by `cra_ctxsize`), e.g. the device session ids.
    type TfmCtx;
    /// Per-request context (sized by `reqsize`), e.g. the in-flight virtio request state.
    type ReqCtx;

    /// The algorithm name users request, e.g. `b"cbc(aes)"` (NUL not required — the field is zeroed).
    const ALG_NAME: &'static [u8];
    /// The driver-specific name, e.g. `b"virtio-cbc-aes"`.
    const DRIVER_NAME: &'static [u8];
    /// `cra_priority` (the C virtio-crypto uses 0).
    const PRIORITY: i32 = 0;
    /// `min_keysize`.
    const MIN_KEYSIZE: u32;
    /// `max_keysize`.
    const MAX_KEYSIZE: u32;
    /// `ivsize`.
    const IVSIZE: u32;
    /// `cra_blocksize` (default 1).
    const BLOCKSIZE: u32 = 1;
    /// `cra_alignmask` (default 0).
    const ALIGNMASK: u32 = 0;

    /// `setkey`: program `key` into the device (create a session); store the session id in the tfm
    /// ctx. Mirrors `skcipher_alg.setkey`.
    fn setkey(tfm: &SkcipherTfm<Self>, key: &[u8]) -> Result;

    /// `encrypt`: submit the request to the device; return `Ok(())` to signal async completion
    /// (the framework sees `-EINPROGRESS`; the driver MUST call [`SkcipherRequest::complete`]
    /// later), or `Err(_)` with an errno. Mirrors `skcipher_alg.encrypt`.
    fn encrypt(req: &SkcipherRequest<Self>) -> Result;

    /// `decrypt`: like [`Operations::encrypt`] for decryption.
    fn decrypt(req: &SkcipherRequest<Self>) -> Result;

    /// `init` (optional): called when a tfm is allocated. Default no-op.
    fn init(_tfm: &SkcipherTfm<Self>) -> Result {
        Ok(())
    }

    /// `exit` (optional): called when a tfm is freed (destroy sessions here). Default no-op.
    fn exit(_tfm: &SkcipherTfm<Self>) {}
}

/// The vtable builder. Generic in the driver `T`; the `unsafe extern "C"` trampolines recover the
/// typed [`SkcipherTfm`]/[`SkcipherRequest`] handles + dispatch to [`Operations`].
pub(crate) struct OperationsVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> OperationsVTable<T> {
    unsafe extern "C" fn setkey_callback(
        tfm: *mut bindings::crypto_skcipher,
        key: *const u8,
        keylen: core::ffi::c_uint,
    ) -> c_int {
        from_result(|| {
            let tfm = SkcipherTfm::<T>::from_raw(tfm);
            // SAFETY: the framework passes a valid `key` of `keylen` bytes.
            let key = unsafe { core::slice::from_raw_parts(key, keylen as usize) };
            T::setkey(&tfm, key)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn encrypt_callback(req: *mut bindings::skcipher_request) -> c_int {
        // SAFETY: the framework passes a valid `skcipher_request` (live for the call; the driver
        // may keep a handle to complete it async).
        let req = SkcipherRequest::<T>::from_raw(req);
        match T::encrypt(&req) {
            Ok(()) => EINPROGRESS_RET,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn decrypt_callback(req: *mut bindings::skcipher_request) -> c_int {
        let req = SkcipherRequest::<T>::from_raw(req);
        match T::decrypt(&req) {
            Ok(()) => EINPROGRESS_RET,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn init_callback(tfm: *mut bindings::crypto_skcipher) -> c_int {
        from_result(|| {
            let tfm = SkcipherTfm::<T>::from_raw(tfm);
            T::init(&tfm)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn exit_callback(tfm: *mut bindings::crypto_skcipher) {
        let tfm = SkcipherTfm::<T>::from_raw(tfm);
        T::exit(&tfm);
    }

    /// Build a `skcipher_alg` for `T`. Heap-allocated + owned by [`SkcipherAlg`] (it must outlive
    /// registration: `crypto_register_skcipher` adds `&alg->base` to the crypto list by pointer).
    /// Zero-initialised + the minimal fields set.
    fn build_alg(module: *mut bindings::module) -> Result<KBox<bindings::skcipher_alg>> {
        // SAFETY: a zeroed `skcipher_alg` is valid — all callback pointers NULL (absent), scalars 0,
        // `cra_name`/`cra_driver_name` zeroed (empty strings). `crypto_register_skcipher` fills the
        // internal fields.
        let mut alg: bindings::skcipher_alg = unsafe { core::mem::zeroed() };
        alg.setkey = Some(Self::setkey_callback);
        alg.encrypt = Some(Self::encrypt_callback);
        alg.decrypt = Some(Self::decrypt_callback);
        alg.init = Some(Self::init_callback);
        alg.exit = Some(Self::exit_callback);
        // The common fields (min_keysize/max_keysize/ivsize/chunksize/statesize/base) live in the
        // anonymous `__bindgen_anon_1` UNION (from the `SKCIPHER_ALG_COMMON` macro); the `co`
        // variant is `skcipher_alg_common`. Union field access is unsafe.
        unsafe {
            alg.__bindgen_anon_1.co.min_keysize = T::MIN_KEYSIZE as core::ffi::c_uint;
            alg.__bindgen_anon_1.co.max_keysize = T::MAX_KEYSIZE as core::ffi::c_uint;
            alg.__bindgen_anon_1.co.ivsize = T::IVSIZE as core::ffi::c_uint;
            alg.__bindgen_anon_1.co.chunksize = T::BLOCKSIZE as core::ffi::c_uint;
            let base = &mut alg.__bindgen_anon_1.co.base;
            base.cra_module = module;
            base.cra_priority = T::PRIORITY;
            base.cra_flags = CRYPTO_ALG_ASYNC;
            base.cra_blocksize = T::BLOCKSIZE as core::ffi::c_uint;
            base.cra_ctxsize = size_of::<T::TfmCtx>() as core::ffi::c_uint;
            base.cra_alignmask = T::ALIGNMASK as core::ffi::c_uint;
            copy_bytes_into(&mut base.cra_name, T::ALG_NAME);
            copy_bytes_into(&mut base.cra_driver_name, T::DRIVER_NAME);
        }
        Ok(KBox::new(alg, GFP_KERNEL)?)
    }
}

/// Copy `src` bytes into a zeroed `[c_char; N]` field (the trailing NUL is the existing zero). No-op
/// if `src` doesn't fit (N is 128 — far larger than any alg name). Byte-wise (`c_char` may be
/// signed `i8`).
fn copy_bytes_into<const N: usize>(dst: &mut [crate::ffi::c_char; N], src: &[u8]) {
    if src.len() < N {
        // SAFETY: `src` fits in `dst` (checked); both are valid byte-aligned buffers.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr() as *mut u8, src.len())
        };
    }
}

/// An owning handle to a registered `skcipher_alg`. `Drop` calls `crypto_unregister_skcipher`.
pub struct SkcipherAlg<T: Operations> {
    #[allow(dead_code)]
    alg: KBox<bindings::skcipher_alg>,
    _t: PhantomData<T>,
}

// SAFETY: `SkcipherAlg` is a raw handle to a C `skcipher_alg`; the crypto framework serialises
// registration/access. Carries only a heap alg + PhantomData.
unsafe impl<T: Operations> Send for SkcipherAlg<T> {}
unsafe impl<T: Operations> Sync for SkcipherAlg<T> {}

impl<T: Operations> SkcipherAlg<T> {
    /// Register `T`'s `skcipher_alg`. Mirrors C `crypto_register_skcipher(&alg)`.
    pub fn register(module: *mut bindings::module) -> Result<Self> {
        let mut alg = OperationsVTable::<T>::build_alg(module)?;
        to_result(unsafe { bindings::crypto_register_skcipher(&mut *alg) })?;
        Ok(SkcipherAlg { alg, _t: PhantomData })
    }
}

impl<T: Operations> Drop for SkcipherAlg<T> {
    fn drop(&mut self) {
        // SAFETY: `self.alg` was registered by `register`; `crypto_unregister_skcipher` is the
        // matching teardown (waits for in-flight tfms to drain).
        unsafe { bindings::crypto_unregister_skcipher(&mut *self.alg) };
    }
}

/// A borrowed handle to a `struct crypto_skcipher` (the tfm), passed to `setkey`/`init`/`exit`.
pub struct SkcipherTfm<T: Operations>(NonNull<bindings::crypto_skcipher>, PhantomData<T>);

// SAFETY: a borrowed raw-pointer handle to a framework-owned tfm; the driver accesses a given tfm
// single-threaded (the framework's tfm lock).
unsafe impl<T: Operations> Send for SkcipherTfm<T> {}
unsafe impl<T: Operations> Sync for SkcipherTfm<T> {}

impl<T: Operations> SkcipherTfm<T> {
    /// Recover a `SkcipherTfm` from a raw pointer. The caller MUST pass a valid `*mut
    /// crypto_skcipher` (the framework guarantees this in the callbacks).
    pub fn from_raw(ptr: *mut bindings::crypto_skcipher) -> Self {
        // SAFETY: by contract, `ptr` is a valid `*mut crypto_skcipher`.
        Self(unsafe { NonNull::new_unchecked(ptr) }, PhantomData)
    }

    /// The per-tfm context (`crypto_skcipher_ctx`), typed as `T::TfmCtx`. The framework allocated
    /// this (sized by `cra_ctxsize`); the driver owns its contents for the tfm's life.
    #[inline(always)]
    pub fn ctx(&self) -> &mut T::TfmCtx {
        // SAFETY: `crypto_skcipher_ctx` returns the `cra_ctxsize` area; the framework allocated
        // `size_of::<T::TfmCtx>()` bytes there, suitably aligned.
        let p = unsafe { bindings::crypto_skcipher_ctx(self.0.as_ptr()) } as *mut T::TfmCtx;
        unsafe { &mut *p }
    }

    /// `crypto_skcipher_ivsize`.
    #[inline(always)]
    pub fn ivsize(&self) -> u32 {
        unsafe { bindings::crypto_skcipher_ivsize(self.0.as_ptr()) }
    }
}

/// A borrowed handle to a `struct skcipher_request`, passed to `encrypt`/`decrypt`. Valid until
/// [`SkcipherRequest::complete`] is called.
pub struct SkcipherRequest<T: Operations>(NonNull<bindings::skcipher_request>, PhantomData<T>);

// SAFETY: a borrowed raw-pointer handle to a framework-owned request; the driver accesses a given
// request single-threaded (encrypt/decrypt submits, the vq callback completes — not concurrently).
unsafe impl<T: Operations> Send for SkcipherRequest<T> {}
unsafe impl<T: Operations> Sync for SkcipherRequest<T> {}

impl<T: Operations> SkcipherRequest<T> {
    /// Recover a `SkcipherRequest` from a raw pointer. The caller MUST pass a valid `*mut
    /// skcipher_request` (the framework guarantees this in `encrypt`/`decrypt`).
    pub fn from_raw(ptr: *mut bindings::skcipher_request) -> Self {
        // SAFETY: by contract, `ptr` is a valid `*mut skcipher_request`.
        Self(unsafe { NonNull::new_unchecked(ptr) }, PhantomData)
    }

    /// The raw `struct skcipher_request *` (e.g. to use as a vq data token).
    #[inline(always)]
    pub fn as_raw(&self) -> *mut bindings::skcipher_request {
        self.0.as_ptr()
    }

    /// The per-request context (`skcipher_request_ctx`), typed as `T::ReqCtx`.
    #[inline(always)]
    pub fn ctx(&self) -> &mut T::ReqCtx {
        let p = unsafe { bindings::skcipher_request_ctx(self.0.as_ptr()) } as *mut T::ReqCtx;
        unsafe { &mut *p }
    }

    /// `req->src` (the source scatterlist chain head).
    #[inline(always)]
    pub fn src(&self) -> *mut bindings::scatterlist {
        unsafe { (*self.0.as_ptr()).src }
    }

    /// `req->dst` (the destination scatterlist chain head).
    #[inline(always)]
    pub fn dst(&self) -> *mut bindings::scatterlist {
        unsafe { (*self.0.as_ptr()).dst }
    }

    /// `req->cryptlen`.
    #[inline(always)]
    pub fn cryptlen(&self) -> u32 {
        unsafe { (*self.0.as_ptr()).cryptlen }
    }

    /// `req->iv`.
    #[inline(always)]
    pub fn iv(&self) -> *mut u8 {
        unsafe { (*self.0.as_ptr()).iv }
    }

    /// The tfm this request is bound to (`crypto_skcipher_reqtfm`).
    #[inline(always)]
    pub fn tfm(&self) -> SkcipherTfm<T> {
        // SAFETY: `crypto_skcipher_reqtfm` returns the request's valid tfm.
        SkcipherTfm::from_raw(unsafe { bindings::crypto_skcipher_reqtfm(self.0.as_ptr()) })
    }

    /// Complete the request (`skcipher_request_complete`). `err` = 0 on success, a negative errno
    /// on failure. After this, the handle must not be used. Mirrors C
    /// `skcipher_request_complete(req, err)`.
    #[inline(always)]
    pub fn complete(&self, err: c_int) {
        unsafe { bindings::skcipher_request_complete(self.0.as_ptr(), err) };
    }
}
