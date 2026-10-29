// SPDX-License-Identifier: GPL-2.0

//! Safe wrappers over the SCSI midlayer for virtio-scsi and similar HBA drivers.
//!
//! Wraps the narrow surface an HBA driver uses: allocate a `struct Scsi_Host` from a
//! `scsi_host_template` (`scsi_host_alloc`), publish + scan it (`scsi_add_host` /
//! `scsi_scan_host`), remove + put it (`scsi_remove_host` / `scsi_host_put`), with the
//! per-host private area (`shost_priv`) carrying a back-pointer to the driver instance; and the
//! per-command surface — the midlayer-allocated private area (`scsi_cmd_priv`, sized by
//! `cmd_size`) + the `scsi_cmnd` accessors (cdb / data-direction / sg-list / flags / result /
//! resid / sense / `scsi_done`).
//!
//! The C-boundary `unsafe` — the `scsi_host_template` vtable trampoline, raw `scsi_cmnd` /
//! `Scsi_Host` pointers, `scsi_cmd_priv` offset arithmetic, sense-buffer memcpy — lives here; a
//! driver built on this module is 0-unsafe. The wrapper methods are `#[inline(always)]` so the
//! driver `.ko` references the C symbols directly (no renamed abstraction symbol for the
//! binary-trace gate to expand), mirroring `nvdimm.rs` / `hvc.rs`.
//!
//! C header: [`include/scsi/scsi_host.h`](srctree/include/scsi/scsi_host.h),
//! [`include/scsi/scsi_cmnd.h`](srctree/include/scsi/scsi_cmnd.h).

use crate::{
    bindings, device,
    error::{to_result, Result},
    prelude::*,
    str::CStr,
};
use core::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem::size_of,
    ptr::NonNull,
};

/// `SCSI_MLQUEUE_HOST_BUSY` — returned by `queuecommand` to tell the midlayer to requeue (the
/// virtqueue was full). `include/scsi/scsi.h`.
const SCSI_MLQUEUE_HOST_BUSY: c_int = 0x1055;

/// `SCMD_LAST` (`1 << 2`) — set on the last `scsi_cmnd` of a batch; the driver must kick the
/// virtqueue when set. `include/scsi/scsi_cmnd.h`.
pub const SCMD_LAST: i32 = 1 << 2;

/// DMA data-direction values (`enum dma_data_direction`, `include/linux/dma-direction.h`).
pub mod dma_data_direction {
    /// `DMA_BIDIRECTIONAL = 0`.
    pub const BIDIRECTIONAL: u32 = crate::bindings::dma_data_direction_DMA_BIDIRECTIONAL as u32;
    /// `DMA_TO_DEVICE = 1` (host → device: a WRITE).
    pub const TO_DEVICE: u32 = crate::bindings::dma_data_direction_DMA_TO_DEVICE as u32;
    /// `DMA_FROM_DEVICE = 2` (device → host: a READ).
    pub const FROM_DEVICE: u32 = crate::bindings::dma_data_direction_DMA_FROM_DEVICE as u32;
    /// `DMA_NONE = 3` (no data transfer).
    pub const NONE: u32 = crate::bindings::dma_data_direction_DMA_NONE as u32;
}

/// Implement this trait to interface the SCSI midlayer as a host (HBA). The midlayer calls
/// [`Operations::queuecommand`] for each `scsi_cmnd` (concurrently across CPUs for different
/// commands); the driver submits it to the device and later calls [`ScsiCmnd::done`] (from a
/// virtqueue callback, or inline before returning). Mirrors `struct scsi_host_template`.
///
/// No `Send`/`Sync` bound (mirrors `block::mq::Operations`): the `queuecommand` trampoline shares
/// `&Self` across CPUs, so the driver MUST ensure only `Sync` fields are touched from `queuecommand`
/// / the vq callback (e.g. guard mutable state with a spinlock); `!Sync` fields like `LateInit` may
/// only be touched from serialized contexts (`start`/`unbind`).
pub trait Operations: Sized {
    /// Per-command private data, allocated by the midlayer at the end of `struct scsi_cmnd`
    /// (sized by `scsi_host_template.cmd_size`). Recovered via [`ScsiCmnd::cmd_priv`]. Unlike
    /// blk-mq's `Request`-based PDU, this area is owned by the midlayer (allocated/freed with the
    /// command), so the driver must not free it — it owns only the contents for the command's life.
    type Cmd;

    /// Queue a SCSI command. Return `Ok(())` if accepted (the driver MUST call
    /// [`ScsiCmnd::done`] later, or inline before returning); `Err(_)` requeues with
    /// `SCSI_MLQUEUE_HOST_BUSY`. Mirrors `scsi_host_template.queuecommand`.
    fn queuecommand(this: &Self, sc: &ScsiCmnd) -> Result;
}

/// The vtable builder. Generic in the driver `T`; the `unsafe extern "C"` `queuecommand`
/// trampoline recovers `&T` from the host's `shost_priv` (a `*const T` stored by
/// [`ScsiHost::set_host_data`]). Mirrors `block::mq::OperationsVTable`.
pub(crate) struct OperationsVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> OperationsVTable<T> {
    /// `scsi_host_template.queuecommand` trampoline. Recovers `&T` from `shost_priv` (the
    /// hostdata back-pointer) and dispatches to [`Operations::queuecommand`].
    unsafe extern "C" fn queuecommand_callback(
        shost: *mut bindings::Scsi_Host,
        sc: *mut bindings::scsi_cmnd,
    ) -> c_int {
        // SAFETY: `shost_priv` returns the hostdata area; `ScsiHost::set_host_data` stored a valid
        // `*const T` there (a live `&T` while the host is registered — the host is
        // `scsi_remove_host`'d before the driver drops).
        let pp = unsafe { bindings::shost_priv(shost) } as *const *const T;
        let this = unsafe { &*(*pp) };
        let sc = ScsiCmnd::from_raw(sc as *mut c_void);
        if T::queuecommand(this, &sc).is_ok() {
            0
        } else {
            SCSI_MLQUEUE_HOST_BUSY
        }
    }

    /// Build a `scsi_host_template` for `T`. Heap-allocated + owned by the [`ScsiHost`] (it must
    /// outlive the host: `scsi_host_alloc` stores `shost->hostt = &template`, a pointer).
    /// Zero-initialised (NULL callbacks = absent) + the minimal fields set.
    fn build_template(
        name: &CStr,
        proc_name: &CStr,
        module: *mut bindings::module,
        dma_boundary: u64,
    ) -> Result<KBox<bindings::scsi_host_template>> {
        // SAFETY: a zeroed `scsi_host_template` is valid — all function-pointer/scalar fields are
        // NULL/0 (the midlayer treats NULL callbacks as absent), matching the C driver's static
        // const template (unset fields are 0/NULL). The bitfields are part of a zeroed bitfield
        // unit.
        let mut t: bindings::scsi_host_template = unsafe { core::mem::zeroed() };
        t.module = module;
        t.name = name.as_char_ptr() as *const _;
        t.proc_name = proc_name.as_char_ptr() as *const _;
        t.this_id = -1;
        t.cmd_size = size_of::<T::Cmd>() as u32;
        t.queuecommand = Some(Self::queuecommand_callback);
        t.dma_boundary = dma_boundary as _;
        // (`track_queue_depth` left 0 — only relevant with `change_queue_depth`, dropped in
        // minimal scope.)
        Ok(KBox::new(t, GFP_KERNEL)?)
    }
}

/// An owning handle to a `struct Scsi_Host` allocated via `scsi_host_alloc`. `Drop` calls
/// `scsi_host_put` (the matching teardown after `scsi_remove_host`). The hostdata area carries a
/// back-pointer to the driver `T` (set via [`ScsiHost::set_host_data`], recovered by the
/// `queuecommand` trampoline).
///
/// `T` is unconstrained on the struct so that `Send`/`Sync` can be unconditional (a driver `T`
/// that itself stores a `ScsiHost<T>` would otherwise form a `Send` cycle through `T: Operations`
/// → `T: Send` → `ScsiHost<T>: Send`). The `Operations` bound is on the `impl` blocks that need it.
pub struct ScsiHost<T> {
    shost: NonNull<bindings::Scsi_Host>,
    /// The `scsi_host_template`; must outlive the host (`shost->hostt` points here). Owned here;
    /// dropped after `scsi_host_put` (the host no longer derefs `hostt` after `scsi_remove_host`
    /// + the last `put`). Never read directly — kept alive for its lifetime guarantee.
    #[allow(dead_code)]
    template: KBox<bindings::scsi_host_template>,
    _t: PhantomData<T>,
}

// SAFETY: `ScsiHost` is a raw handle to a C `Scsi_Host`; the driver serialises access (probe/remove
// + the midlayer's own locking). Carries only raw pointers + a heap template. Unconditional (no
// `T: Operations` bound) to avoid a `Send` cycle for drivers that store a `ScsiHost<T>` in `T`.
unsafe impl<T> Send for ScsiHost<T> {}
unsafe impl<T> Sync for ScsiHost<T> {}

impl<T: Operations> ScsiHost<T> {
    /// Allocate a `Scsi_Host` from `T`'s template. `cmd_size = size_of::<T::Cmd>()` (per-command
    /// private area); `privsize = size_of::<*const T>()` (the hostdata back-pointer). Mirrors C
    /// `scsi_host_alloc(&template, privsize)`.
    pub fn alloc(
        name: &CStr,
        proc_name: &CStr,
        module: *mut bindings::module,
        dma_boundary: u64,
    ) -> Result<Self> {
        let template = OperationsVTable::<T>::build_template(name, proc_name, module, dma_boundary)?;
        let privsize = size_of::<*const T>() as c_int;
        // SAFETY: `template` is a fully-initialised `scsi_host_template`; `privsize` is the
        // hostdata size. The template KBox outlives the host (owned by the returned `ScsiHost`).
        let shost = unsafe { bindings::scsi_host_alloc(&*template as *const _, privsize) };
        let shost = NonNull::new(shost).ok_or(ENOMEM)?;
        Ok(ScsiHost {
            shost,
            template,
            _t: PhantomData,
        })
    }

    /// Store a back-pointer to the driver instance `T` in the host's hostdata (recovered by the
    /// `queuecommand` trampoline via `shost_priv`). Mirrors C `shost_priv(shost) = vscsi`. Must be
    /// called before `scsi_scan_host` (so the first `queuecommand` can recover `&T`).
    #[inline(always)]
    pub fn set_host_data(&self, t: *const T) {
        // SAFETY: `self.shost` is a valid `Scsi_Host`; `shost_priv` returns the hostdata area of
        // size `size_of::<*const T>()` (the privsize passed to `alloc`).
        let p = unsafe { bindings::shost_priv(self.shost.as_ptr()) } as *mut *const T;
        unsafe { *p = t };
    }

    /// `shost->can_queue`. Mirrors C `shost->can_queue = ...` (set after `scsi_host_alloc`).
    #[inline(always)]
    pub fn set_can_queue(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).can_queue = v as c_int };
    }
    /// `shost->sg_tablesize`.
    #[inline(always)]
    pub fn set_sg_tablesize(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).sg_tablesize = v as u16 };
    }
    /// `shost->cmd_per_lun`.
    #[inline(always)]
    pub fn set_cmd_per_lun(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).cmd_per_lun = v as i16 };
    }
    /// `shost->max_sectors`.
    #[inline(always)]
    pub fn set_max_sectors(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).max_sectors = v };
    }
    /// `shost->max_lun`.
    #[inline(always)]
    pub fn set_max_lun(&self, v: u64) {
        unsafe { (*self.shost.as_ptr()).max_lun = v };
    }
    /// `shost->max_id`.
    #[inline(always)]
    pub fn set_max_id(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).max_id = v };
    }
    /// `shost->max_channel`.
    #[inline(always)]
    pub fn set_max_channel(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).max_channel = v };
    }
    /// `shost->max_cmd_len`.
    #[inline(always)]
    pub fn set_max_cmd_len(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).max_cmd_len = v as u16 };
    }
    /// `shost->nr_hw_queues`.
    #[inline(always)]
    pub fn set_nr_hw_queues(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).nr_hw_queues = v };
    }
    /// `shost->nr_maps`.
    #[inline(always)]
    pub fn set_nr_maps(&self, v: u32) {
        unsafe { (*self.shost.as_ptr()).nr_maps = v };
    }

    /// `scsi_add_host(host, parent)`. Publishes the host (does not scan). Mirrors C
    /// `scsi_add_host`.
    #[inline(always)]
    pub fn add_host<Ctx: device::DeviceContext>(&self, parent: &device::Device<Ctx>) -> Result {
        to_result(unsafe { bindings::scsi_add_host(self.shost.as_ptr(), parent.as_raw()) })
    }

    /// `scsi_scan_host(host)`. Scans for LUNs — may issue INQUIRY commands (→ `queuecommand`).
    /// Mirrors C `scsi_scan_host`.
    #[inline(always)]
    pub fn scan_host(&self) {
        unsafe { bindings::scsi_scan_host(self.shost.as_ptr()) };
    }

    /// `scsi_remove_host(host)`. Quiesces the host (no new commands, waits for in-flight).
    /// Mirrors C `scsi_remove_host`. Must be called before `drop` (which `scsi_host_put`s).
    #[inline(always)]
    pub fn remove_host(&self) {
        unsafe { bindings::scsi_remove_host(self.shost.as_ptr()) };
    }
}

impl<T> Drop for ScsiHost<T> {
    fn drop(&mut self) {
        // SAFETY: `self.shost` came from a successful `scsi_host_alloc`; `scsi_host_put` is the
        // matching teardown (decrements the refcount; the host is freed on the last put, after
        // `scsi_remove_host` quiesced it). The template KBox drops after this (field order).
        unsafe { bindings::scsi_host_put(self.shost.as_ptr()) };
    }
}

/// A borrowed handle to a `struct scsi_cmnd` — a SCSI command the midlayer passed to
/// `queuecommand`. Valid until [`ScsiCmnd::done`] is called. A thin raw-pointer wrapper; recover
/// from the virtqueue data token via [`ScsiCmnd::from_raw`] (the driver passes [`as_raw`] as the
/// `add_sgs` token, then recovers it on completion — mirroring how the C driver uses the
/// `scsi_cmnd *` pointer as the vq data).
///
/// [`as_raw`]: ScsiCmnd::as_raw
#[repr(transparent)]
pub struct ScsiCmnd(NonNull<bindings::scsi_cmnd>);

// SAFETY: `ScsiCmnd` is a borrowed raw-pointer handle to a midlayer-owned `scsi_cmnd`; the driver
// accesses a given command single-threaded (queuecommand submits, the vq callback completes —
// never concurrently). Not stored in driver state (only recovered transiently from a token).
unsafe impl Send for ScsiCmnd {}
unsafe impl Sync for ScsiCmnd {}

impl ScsiCmnd {
    /// Recover a `ScsiCmnd` from a raw pointer (e.g. the virtqueue data token). The driver MUST
    /// only pass a token that is a valid `*mut scsi_cmnd` (the buffer-management contract of
    /// `add_sgs`: the token passed in is the token returned by `get_buf`).
    pub fn from_raw(ptr: *mut c_void) -> Self {
        // SAFETY: by contract, `ptr` is a valid `*mut scsi_cmnd`.
        Self(unsafe { NonNull::new_unchecked(ptr as *mut bindings::scsi_cmnd) })
    }

    /// The raw `struct scsi_cmnd *` (e.g. to use as the `add_sgs` data token).
    #[inline(always)]
    pub fn as_raw(&self) -> *mut bindings::scsi_cmnd {
        self.0.as_ptr()
    }

    /// The per-command private area (`scsi_cmd_priv`), typed as `T`. The midlayer allocated this
    /// (sized by `cmd_size = size_of::<T>()`); the driver owns its contents for the command's
    /// lifetime. Mirrors C `cmd = scsi_cmd_priv(sc)`.
    #[inline(always)]
    pub fn cmd_priv<U>(&self) -> &mut U {
        // SAFETY: `scsi_cmd_priv` returns the `cmd_size` area right after `scsi_cmnd`; the
        // midlayer allocated `size_of::<T>()` bytes there, suitably aligned (the kernel ensures
        // the priv area alignment).
        let p = unsafe { bindings::scsi_cmd_priv(self.0.as_ptr()) } as *mut U;
        unsafe { &mut *p }
    }

    /// The CDB (`sc->cmnd`, `sc->cmd_len` bytes). Mirrors C `memcpy(cdb, sc->cmnd, cmd_len)`.
    #[inline(always)]
    pub fn cdb(&self) -> &[u8] {
        let len = self.cmd_len() as usize;
        // SAFETY: `cmnd` is an embedded `[u8; 32]`; valid for reads for the command's life.
        unsafe {
            let cmnd = &(*self.0.as_ptr()).cmnd;
            &cmnd[..len]
        }
    }

    /// `sc->cmd_len`.
    #[inline(always)]
    pub fn cmd_len(&self) -> u8 {
        unsafe { (*self.0.as_ptr()).cmd_len as u8 }
    }

    /// `sc->sc_data_direction` (a `dma_data_direction` value — see [`dma_data_direction`]).
    #[inline(always)]
    pub fn data_direction(&self) -> u32 {
        unsafe { (*self.0.as_ptr()).sc_data_direction as u32 }
    }

    /// `sc->flags` (test against [`SCMD_LAST`]).
    #[inline(always)]
    pub fn flags(&self) -> i32 {
        unsafe { (*self.0.as_ptr()).flags }
    }

    /// The data scatterlist chain head (`scsi_sglist`: `sc->sdb.table.sgl`).
    #[inline(always)]
    pub fn sgl(&self) -> *mut bindings::scatterlist {
        unsafe { bindings::scsi_sglist(self.0.as_ptr()) }
    }

    /// The data scatterlist count (`scsi_sg_count`: `sc->sdb.table.nents`).
    #[inline(always)]
    pub fn sg_count(&self) -> u32 {
        unsafe { bindings::scsi_sg_count(self.0.as_ptr()) }
    }

    /// The data buffer length (`scsi_bufflen`: `sc->sdb.length`).
    #[inline(always)]
    pub fn bufflen(&self) -> u32 {
        unsafe { bindings::scsi_bufflen(self.0.as_ptr()) }
    }

    /// `sc->result = status` (the low 8 bits = SCSI status byte). Mirrors C
    /// `sc->result = resp->status`.
    #[inline(always)]
    pub fn set_result(&self, status: i32) {
        unsafe { (*self.0.as_ptr()).result = status };
    }

    /// `set_host_byte(sc, b)` — sets the host byte (bits 16-23 of `result`).
    #[inline(always)]
    pub fn set_host_byte(&self, b: u8) {
        unsafe { bindings::set_host_byte(self.0.as_ptr(), b) };
    }

    /// `set_status_byte(sc, b)` — sets the status byte (bits 0-7 of `result`).
    #[inline(always)]
    pub fn set_status_byte(&self, b: u8) {
        unsafe { bindings::set_status_byte(self.0.as_ptr(), b) };
    }

    /// `scsi_set_resid(sc, resid)` — sets `sc->resid_len`. Mirrors C
    /// `virtscsi_compute_resid` (`scsi_set_resid(sc, min(resid, scsi_bufflen(sc)))`).
    #[inline(always)]
    pub fn set_resid(&self, resid: u32) {
        unsafe { bindings::scsi_set_resid(self.0.as_ptr(), resid) };
    }

    /// The sense buffer (`sc->sense_buffer`, `SCSI_SENSE_BUFFERSIZE` = 96 bytes). Mirrors C
    /// `memcpy(sc->sense_buffer, resp->sense, ...)`.
    #[inline(always)]
    pub fn sense_buffer(&self) -> &mut [u8] {
        // SAFETY: `sense_buffer` is a valid `*mut u8` to a 96-byte buffer owned by the midlayer,
        // valid for the command's life.
        unsafe { core::slice::from_raw_parts_mut((*self.0.as_ptr()).sense_buffer, 96) }
    }

    /// The target id of the command's device (`sc->device->id`).
    #[inline(always)]
    pub fn device_id(&self) -> u32 {
        unsafe { (*(*self.0.as_ptr()).device).id as u32 }
    }

    /// The LUN of the command's device (`sc->device->lun`).
    #[inline(always)]
    pub fn device_lun(&self) -> u64 {
        unsafe { (*(*self.0.as_ptr()).device).lun }
    }

    /// Complete the command (`scsi_done`). After this, the handle must not be used. Mirrors C
    /// `scsi_done(sc)`.
    #[inline(always)]
    pub fn done(&self) {
        unsafe { bindings::scsi_done(self.0.as_ptr()) };
    }
}
