// SPDX-License-Identifier: GPL-2.0

//! Safe wrappers over `libnvdimm` for virtio-pmem and similar drivers.
//!
//! Wraps the narrow surface `drivers/nvdimm/virtio_pmem.c` uses: register a nvdimm bus
//! (`nvdimm_bus_register` with a provider name + module), create a pmem region over a resource
//! range with an asynchronous-flush callback (`nvdimm_pmem_region_create`), and unregister on
//! teardown. The C-boundary `unsafe` — opaque `nvdimm_bus`/`nd_region` pointers, the
//! `nvdimm_bus_descriptor`/`nd_region_desc` struct layout, and the C `flush` callback trampoline
//! — lives here; a driver built on this module is 0-unsafe.
//!
//! The wrappers are `#[inline(always)]` so the driver `.ko` references the C symbols
//! (`nvdimm_bus_register`, `nvdimm_pmem_region_create`, `nvdimm_bus_unregister`,
//! `nd_region_provider_data`) directly — exactly as the C driver does — with no renamed
//! abstraction symbol for the binary-trace gate to expand.

use crate::{
    bindings,
    device,
    error::{code::{EIO, ENXIO}, Result},
    prelude::*,
    str::CStr,
};
use core::{
    ffi::{c_int, c_void},
    marker::PhantomData,
};

/// A registered nvdimm bus. Owning handle: `Drop` calls `nvdimm_bus_unregister`. Created with
/// [`NvdimmBus::register`]; any region created on it is freed when the bus unregisters.
pub struct NvdimmBus {
    ptr: *mut bindings::nvdimm_bus,
}

// SAFETY: a `nvdimm_bus` is a device-bound object the C core serializes; the handle only carries
// a raw pointer and all access is through the C API.
unsafe impl Send for NvdimmBus {}
// SAFETY: `&NvdimmBus` only yields a raw pointer; the C API is thread-safe.
unsafe impl Sync for NvdimmBus {}

impl NvdimmBus {
    /// Register a nvdimm bus under `parent` with `provider_name` + `module`. Mirrors
    /// `nvdimm_bus_register`: builds a `struct nvdimm_bus_descriptor` with only `provider_name`
    /// + `module` set (the rest NULL/zero, as the C virtio-pmem driver does) and registers it.
    #[inline(always)]
    pub fn register<Ctx: device::DeviceContext>(
        parent: &device::Device<Ctx>,
        provider_name: &CStr,
        module: *mut bindings::module,
    ) -> Result<Self> {
        // SAFETY: a zeroed `nvdimm_bus_descriptor` is valid — all pointer/function-pointer fields
        // are NULL (treated as absent by the C core), matching the C driver's zero-initialized
        // descriptor.
        let mut desc: bindings::nvdimm_bus_descriptor = unsafe { core::mem::zeroed() };
        desc.provider_name = provider_name.as_char_ptr() as *mut _;
        desc.module = module;
        // SAFETY: `parent.as_raw()` is a valid `struct device` (the virtio device's embedded
        // `dev`); `desc` is fully initialized for the fields the C core reads.
        let ptr = unsafe { bindings::nvdimm_bus_register(parent.as_raw(), &mut desc) };
        if ptr.is_null() {
            return Err(ENXIO);
        }
        Ok(NvdimmBus { ptr })
    }

    /// The raw `struct nvdimm_bus *`.
    #[inline(always)]
    pub fn as_raw(&self) -> *mut bindings::nvdimm_bus {
        self.ptr
    }
}

impl Drop for NvdimmBus {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: `self.ptr` came from a successful `nvdimm_bus_register`;
        // `nvdimm_bus_unregister` is the matching teardown (it also frees any regions created on
        // the bus).
        unsafe { bindings::nvdimm_bus_unregister(self.ptr) };
    }
}

/// Trait providing the asynchronous-flush callback for a pmem region. The single [`flush`]
/// method is invoked by libnvdimm (in process context) when the region must be flushed.
///
/// [`flush`]: PmemFlushOps::flush
pub trait PmemFlushOps {
    /// Flush the region. `bio` is the originating bio (may be NULL for a synchronous flush).
    /// Return 0 on success, a negative `errno` on failure. A minimal driver performs the device
    /// flush synchronously and ignores `bio`'s async-chaining path (the C `async_pmem_flush`
    /// bio-clone/chain/submit path is omitted as documented minimal scope).
    fn flush(this: &Self, bio: *mut bindings::bio) -> c_int;
}

/// A handle to a created pmem region. The region is owned by its [`NvdimmBus`] (freed when the
/// bus unregisters), so this handle performs no teardown — it only guards the create result.
pub struct NdRegion {
    #[allow(dead_code)]
    ptr: *mut bindings::nd_region,
    _t: PhantomData<()>,
}

// SAFETY: an `nd_region` is a device-bound object; the handle only carries a raw pointer.
unsafe impl Send for NdRegion {}
unsafe impl Sync for NdRegion {}

impl NdRegion {
    /// Create a pmem region on `bus` over `[start, start+size-1]` with the given NUMA nodes,
    /// `provider` (recovered by the flush callback via `nd_region->provider_data`), and the
    /// [`PmemFlushOps`] flush trampoline. Mirrors `nvdimm_pmem_region_create` with an
    /// `nd_region_desc` built as the C virtio-pmem driver does (res, numa/target node,
    /// provider_data, flush, ND_REGION_PAGEMAP|ND_REGION_ASYNC).
    #[inline(always)]
    pub fn create_pmem_region<T: PmemFlushOps>(
        bus: &NvdimmBus,
        start: u64,
        size: u64,
        numa_node: c_int,
        target_node: c_int,
        provider: &T,
    ) -> Result<Self> {
        // SAFETY: zeroed `resource` is valid (NULL name, zero flags); start/end set below.
        let mut res: bindings::resource = unsafe { core::mem::zeroed() };
        res.start = start;
        res.end = if size == 0 { start } else { start + size - 1 };
        // SAFETY: zeroed `nd_region_desc` is valid (NULL mappings, zero counts); the fields the C
        // virtio-pmem driver sets are assigned below.
        let mut desc: bindings::nd_region_desc = unsafe { core::mem::zeroed() };
        desc.res = &mut res as *mut _;
        desc.numa_node = numa_node;
        desc.target_node = target_node;
        desc.provider_data = provider as *const T as *mut c_void;
        desc.flush = Some(flush_trampoline::<T>);
        // ND_REGION_PAGEMAP (0) | ND_REGION_ASYNC (3): the region backs a page map + flushes async.
        desc.flags = (1usize << (bindings::ND_REGION_PAGEMAP as u32))
            | (1usize << (bindings::ND_REGION_ASYNC as u32));
        // SAFETY: `bus.as_raw()` is a valid registered bus; `res` + `desc` are fully initialized
        // and alive for the duration of this call (the C core copies what it needs).
        let ptr = unsafe { bindings::nvdimm_pmem_region_create(bus.as_raw(), &mut desc) };
        if ptr.is_null() {
            return Err(ENXIO);
        }
        Ok(NdRegion { ptr, _t: PhantomData })
    }
}

/// The C `nd_region_desc.flush` trampoline. Recovers the driver `T` from the region's
/// `provider_data` (set in [`NdRegion::create_pmem_region`]) and dispatches to
/// [`PmemFlushOps::flush`]. Generic in `T` ⇒ monomorphizes into the driver module (no new
/// vmlinux symbol); the `unsafe` (the `extern "C"` ABI + raw-pointer recovery) lives here, so
/// the driver writes no `unsafe extern "C"` callback of its own.
///
/// # Safety
///
/// Called by libnvdimm with a valid `nd_region` whose `provider_data` was set by
/// [`NdRegion::create_pmem_region`] to a `&T` that outlives the region (the driver drops the bus
/// — which frees the region — before dropping `T`).
unsafe extern "C" fn flush_trampoline<T: PmemFlushOps>(
    ndr: *mut bindings::nd_region,
    bio: *mut bindings::bio,
) -> c_int {
    // SAFETY: `ndr` is the region libnvdimm created; `nd_region_provider_data` returns the
    // `provider_data` set in `create_pmem_region` (a valid `&T` while the region is alive).
    let pd = unsafe { bindings::nd_region_provider_data(ndr) };
    if pd.is_null() {
        return EIO.to_errno();
    }
    // SAFETY: `pd` is a valid `&T` (set in `create_pmem_region`); flush runs while `T` is alive
    // (the region is freed before `T`).
    let this = unsafe { &*(pd as *const T) };
    T::flush(this, bio)
}
