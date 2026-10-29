// SPDX-License-Identifier: GPL-2.0

//! Safe wrappers over the hvc console subsystem (`drivers/tty/hvc/hvc_console.h`) for virtio-console
//! and similar drivers. Wraps `hvc_alloc`/`hvc_remove` + the `hv_ops` vtable (get_chars/put_chars/
//! notifier_add/del). The C-boundary `unsafe` (opaque `hvc_struct`, the `hv_ops` fn-pointer table,
//! the trampolines, the vtermno→driver registry) lives here; a driver implementing [`HvcOps`] is
//! 0-unsafe.
//!
//! hvc's `hv_ops` callbacks receive only a `vtermno` (get_chars/put_chars) or the `hvc_struct`
//! (notifier_add/del) — NOT a driver-data pointer — so the abstraction keeps a small
//! `vtermno → *mut c_void` registry the driver registers against before `hvc_alloc`; the
//! trampolines recover the driver `T` from `vtermno`. (Single console: vtermno 0.)

use crate::{bindings, error::*, prelude::*};
use core::{
    ffi::{c_int, c_void},
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

/// The hvc console vtable (`struct hv_ops`). Each method is called by the hvc core in process
/// context (get_chars/put_chars on console read/write; notifier_add/del on open/close). The
/// abstraction recovers `&self` from the `vtermno` registry, so the driver need not.
pub trait HvcOps {
    /// Read up to `buf.len()` chars from the device into `buf`; return the number read (0 = none).
    fn get_chars(&self, vtermno: u32, buf: &mut [u8]) -> usize;
    /// Write `buf` to the device; return the number written.
    fn put_chars(&self, vtermno: u32, buf: &[u8]) -> usize;
    /// Console opened (`notifier_add`). Default no-op (returns 0 = success).
    fn notifier_add(&self, vtermno: u32) -> c_int {
        let _ = (self, vtermno);
        0
    }
    /// Console closed (`notifier_del`). Default no-op.
    fn notifier_del(&self, vtermno: u32) {
        let _ = (self, vtermno);
    }
}

/// `vtermno → driver ptr` registry (single console: vtermno 0). The driver registers itself (as
/// `*mut c_void`) before `hvc_alloc`; the trampolines recover it via `vtermno`.
static REGISTRY: [AtomicPtr<c_void>; 1] = [const { AtomicPtr::new(ptr::null_mut()) }; 1];

#[inline(always)]
fn register(vtermno: u32, p: *mut c_void) {
    if (vtermno as usize) < REGISTRY.len() {
        REGISTRY[vtermno as usize].store(p, Ordering::Relaxed);
    }
}

#[inline(always)]
fn lookup(vtermno: u32) -> *mut c_void {
    if (vtermno as usize) < REGISTRY.len() {
        REGISTRY[vtermno as usize].load(Ordering::Relaxed)
    } else {
        ptr::null_mut()
    }
}

unsafe extern "C" fn get_chars_trampoline<T: HvcOps>(vtermno: u32, buf: *mut u8, count: usize) -> isize {
    let p = lookup(vtermno) as *const T;
    if p.is_null() || buf.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: the driver registered a valid `&T` for `vtermno` (alive until `hvc_remove`); `buf`
    // is a valid writable `count`-byte buffer from the hvc core.
    let this = unsafe { &*p };
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, count) };
    this.get_chars(vtermno, slice) as isize
}

unsafe extern "C" fn put_chars_trampoline<T: HvcOps>(vtermno: u32, buf: *const u8, count: usize) -> isize {
    let p = lookup(vtermno) as *const T;
    if p.is_null() || buf.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: `buf` is a valid `count`-byte readable buffer from the hvc core.
    let this = unsafe { &*p };
    let slice = unsafe { core::slice::from_raw_parts(buf, count) };
    this.put_chars(vtermno, slice) as isize
}

unsafe extern "C" fn notifier_add_trampoline<T: HvcOps>(_hp: *mut bindings::hvc_struct, _irq: c_int) -> c_int {
    // Single-console case: vtermno 0. (A multi-console driver would read `(*hp).vtermno`.)
    let p = lookup(0) as *const T;
    if p.is_null() {
        return 0;
    }
    // SAFETY: registered `&T`, alive until `hvc_remove`.
    unsafe { (&*p).notifier_add(0) }
}

unsafe extern "C" fn notifier_del_trampoline<T: HvcOps>(_hp: *mut bindings::hvc_struct, _irq: c_int) {
    let p = lookup(0) as *const T;
    if p.is_null() {
        return;
    }
    // SAFETY: registered `&T`, alive until `hvc_remove`.
    unsafe { (&*p).notifier_del(0) };
}

/// An allocated hvc console. Owning handle: `Drop` calls `hvc_remove`.
pub struct HvcConsole {
    hp: *mut bindings::hvc_struct,
    /// The `hv_ops` table must outlive the `hvc_struct` (hvc stores `*const hv_ops`); freed in Drop
    /// after `hvc_remove`.
    _ops: KBox<bindings::hv_ops>,
}

// SAFETY: the handle only carries raw pointers; the hvc core serializes access.
unsafe impl Send for HvcConsole {}
unsafe impl Sync for HvcConsole {}

impl HvcConsole {
    /// Register a console: registers `driver` (as `*mut c_void`) for `vtermno`, builds the `hv_ops`
    /// with `T`'s trampolines, and calls `hvc_alloc`. Mirrors `hvc_alloc(vtermno, 0, &ops, outbuf)`.
    /// `driver` MUST stay alive + pinned until this `HvcConsole` is dropped.
    #[inline(always)]
    pub fn alloc<T: HvcOps>(vtermno: u32, driver: *mut c_void, outbuf_size: c_int) -> Result<Self> {
        register(vtermno, driver);
        let ops = KBox::new(
            bindings::hv_ops {
                get_chars: Some(get_chars_trampoline::<T>),
                put_chars: Some(put_chars_trampoline::<T>),
                flush: None,
                notifier_add: Some(notifier_add_trampoline::<T>),
                notifier_del: Some(notifier_del_trampoline::<T>),
                notifier_hangup: None,
                tiocmget: None,
                tiocmset: None,
                dtr_rts: None,
            },
            GFP_KERNEL,
        )?;
        // SAFETY: `ops` is a valid `hv_ops` (T's trampolines); `vtermno` is registered.
        let hp = unsafe { bindings::hvc_alloc(vtermno, 0, &*ops, outbuf_size) };
        if hp.is_null() {
            return Err(ENOMEM);
        }
        Ok(HvcConsole { hp, _ops: ops })
    }

    /// Notify the hvc core that input may be available (call from the vq callback). Mirrors
    /// `hvc_poll`.
    #[inline(always)]
    pub fn poll(&self) {
        // SAFETY: `self.hp` is a valid `hvc_struct` from `hvc_alloc`.
        unsafe { bindings::hvc_poll(self.hp) };
    }
}

impl Drop for HvcConsole {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: `self.hp` came from a successful `hvc_alloc`; `hvc_remove` is the matching
        // teardown. The `hv_ops` (`_ops`) is dropped after, once hvc no longer references it.
        unsafe { bindings::hvc_remove(self.hp) };
    }
}
