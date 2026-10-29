// SPDX-License-Identifier: GPL-2.0

//! PCI memory-mapped I/O infrastructure.

use super::Device;
use crate::{
    bindings, device,
    devres::Devres,
    error::to_result,
    io::{
        Io,
        IoRaw, //
    },
    prelude::*,
    revocable::Revocable,
    sync::{aref::ARef, Arc, Mutex, SpinLockIrqSave},
};
use core::{mem, ops::Deref, ptr::NonNull};
use pin_init::{pin_data, PinInit};

/// An exclusive claim on all memory BARs of a PCI function.
///
/// This is intentionally separate from [`RemappableBar`]: NVMe claims its BAR
/// resources once at probe time but may replace the CPU mapping of BAR 0 as
/// the required doorbell window grows during queue setup.
pub struct MemoryRegions {
    pdev: ARef<Device>,
}

impl Drop for MemoryRegions {
    fn drop(&mut self) {
        // SAFETY: Construction succeeds only after the matching request, and
        // the retained device reference keeps `pdev` alive through release.
        unsafe { bindings::pci_release_mem_regions(self.pdev.as_raw()) };
    }
}

/// An allocation from a PCI peer-to-peer memory pool.
///
/// The allocation is CPU accessible and has a bus address suitable for the
/// owning PCI function's submission queue. It is returned to the P2P pool on
/// drop.
pub struct P2pAllocation {
    pdev: ARef<Device>,
    address: NonNull<c_void>,
    bus_address: bindings::pci_bus_addr_t,
    size: usize,
}

// SAFETY: Ownership of the allocation is unique. Mutable CPU access requires
// `&mut self`; immutable methods expose only scalar metadata.
unsafe impl Send for P2pAllocation {}
// SAFETY: See `Send`; no shared method dereferences the allocation.
unsafe impl Sync for P2pAllocation {}

impl P2pAllocation {
    /// Allocate `size` bytes from this function's published P2P pool.
    pub fn new(pdev: &Device, size: usize) -> Result<Self> {
        if size == 0 {
            return Err(EINVAL);
        }
        // SAFETY: `pdev` is live and the PCI P2P allocator validates the
        // requested size against its registered resources.
        let address = unsafe { bindings::pci_alloc_p2pmem(pdev.as_raw(), size) };
        let Some(address) = NonNull::new(address) else {
            return Err(ENOMEM);
        };
        // SAFETY: `address` is the live allocation returned immediately above.
        let bus_address =
            unsafe { bindings::pci_p2pmem_virt_to_bus(pdev.as_raw(), address.as_ptr()) };
        if bus_address == 0 {
            // SAFETY: This is the unique allocation and no pointer escaped.
            unsafe { bindings::pci_free_p2pmem(pdev.as_raw(), address.as_ptr(), size) };
            return Err(EIO);
        }
        Ok(Self {
            pdev: pdev.into(),
            address,
            bus_address,
            size,
        })
    }

    /// Bus address of the first byte.
    pub fn bus_address(&self) -> bindings::pci_bus_addr_t {
        self.bus_address
    }

    /// Allocation size in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Whether the allocation is empty (always false for a constructed value).
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Copy bytes into the CPU mapping at `offset`.
    pub fn copy_from(&mut self, offset: usize, source: &[u8]) -> Result {
        let end = offset.checked_add(source.len()).ok_or(EINVAL)?;
        if end > self.size {
            return Err(EINVAL);
        }
        // SAFETY: Bounds were checked, `&mut self` guarantees exclusive CPU
        // access and both ranges are valid for `source.len()` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                source.as_ptr(),
                self.address.as_ptr().cast::<u8>().add(offset),
                source.len(),
            )
        };
        Ok(())
    }

    /// Zero a byte range in the allocation.
    pub fn zero(&mut self, offset: usize, len: usize) -> Result {
        let end = offset.checked_add(len).ok_or(EINVAL)?;
        if end > self.size {
            return Err(EINVAL);
        }
        // SAFETY: Bounds were checked and `&mut self` guarantees exclusive
        // CPU access.
        unsafe {
            self.address
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .write_bytes(0, len)
        };
        Ok(())
    }
}

impl Drop for P2pAllocation {
    fn drop(&mut self) {
        // SAFETY: This object uniquely owns the allocation and retained the
        // device reference used to allocate it.
        unsafe { bindings::pci_free_p2pmem(self.pdev.as_raw(), self.address.as_ptr(), self.size) };
    }
}

struct RawBarMapping {
    io: IoRaw,
}

impl RawBarMapping {
    fn map(start: bindings::resource_size_t, resource_len: usize, size: usize) -> Result<Self> {
        if size == 0 {
            return Err(EINVAL);
        }
        if size > resource_len {
            return Err(EINVAL);
        }
        // SAFETY: The caller owns the BAR resource and the checked range lies
        // wholly within it. `ioremap` validates architecture-specific details.
        let address = unsafe { bindings::ioremap(start, size) };
        if address.is_null() {
            return Err(ENOMEM);
        }
        Ok(Self {
            io: IoRaw::new(address as usize, size)?,
        })
    }

    fn io(&self) -> &Io {
        // SAFETY: `RawBarMapping` owns an active `ioremap` of exactly
        // `self.io.maxsize()` bytes until its `Drop` runs.
        unsafe { Io::from_raw(&self.io) }
    }
}

impl Drop for RawBarMapping {
    fn drop(&mut self) {
        // SAFETY: `self.io.addr()` is the mapping returned by `ioremap` in
        // `RawBarMapping::map`, and this object owns it uniquely.
        unsafe { bindings::iounmap(self.io.addr() as *mut c_void) };
    }
}

/// A non-owning MMIO view. The mapping owner revokes every copy before
/// dropping its underlying ioremap, and every access holds an RCU guard.
struct BarLeaseView {
    io: IoRaw,
}

impl BarLeaseView {
    fn io(&self) -> &Io {
        // SAFETY: The only caller holds this view's Revocable read guard.
        // LeaseableBarMapping::drop waits for all such guards before iounmap.
        unsafe { Io::from_raw(&self.io) }
    }
}

/// One revocable, bounds-checked 32-bit register within a remappable BAR.
///
/// The handle can be retained across interrupts and shared across CPUs. It
/// does not retain access after revocation: reads of a revoked generation
/// fail with ENODEV. Acquiring a new handle is a cold setup operation; each
/// write only enters an RCU read-side section and performs the MMIO access.
/// Callers still serialize accesses to the hardware register as required by
/// their device protocol. This handle does not provide a register lock.
pub struct BarWrite32Lease {
    view: Arc<Revocable<BarLeaseView>>,
    offset: usize,
}

impl BarWrite32Lease {
    /// Write a little-endian register, or fail if the mapping was revoked.
    #[inline]
    pub fn write(&self, value: u32) -> Result {
        let view = self.view.try_access().ok_or(ENODEV)?;
        view.io().try_write32(value, self.offset)
    }
}

/// The sole ioremap owner paired with a revocable non-owning fast view.
///
/// Drop may sleep, like the underlying iounmap. The view is always revoked
/// and all concurrent RCU readers drained before the raw mapping is dropped.
struct LeaseableBarMapping {
    raw: RawBarMapping,
    view: Arc<Revocable<BarLeaseView>>,
}

impl LeaseableBarMapping {
    fn make_view(raw: &RawBarMapping, flags: crate::alloc::Flags)
        -> Result<Arc<Revocable<BarLeaseView>>>
    {
        let view = BarLeaseView {
            io: IoRaw::new(raw.io.addr(), raw.io.maxsize())?,
        };
        Arc::pin_init(Revocable::new(Ok::<_, Error>(view)), flags)
    }

    fn map(start: bindings::resource_size_t, resource_len: usize, size: usize) -> Result<Self> {
        let raw = RawBarMapping::map(start, resource_len, size)?;
        let view = Self::make_view(&raw, GFP_KERNEL)?;
        Ok(Self { raw, view })
    }

    fn io(&self) -> &Io {
        self.raw.io()
    }

    fn lease_write32(&mut self, offset: usize) -> Result<BarWrite32Lease> {
        if offset % core::mem::align_of::<u32>() != 0
            || offset.checked_add(core::mem::size_of::<u32>()).ok_or(EINVAL)? > self.raw.io.maxsize()
        {
            return Err(EINVAL);
        }
        if self.view.try_access().is_none() {
            // Called only during transport setup with the mapping lock held.
            // A reset can revoke I/O leases while retaining the admin mapping.
            // GFP_ATOMIC ensures that renewing this tiny view never sleeps
            // under the irq-save lock. Allocation failure remains explicit.
            self.view = Self::make_view(&self.raw, GFP_ATOMIC)?;
        }
        Ok(BarWrite32Lease { view: self.view.clone(), offset })
    }
}

impl Drop for LeaseableBarMapping {
    fn drop(&mut self) {
        // Drop runs outside the mapping lock. No view can reach `raw` after
        // revoke returns, even when callers retained leases across a remap.
        self.view.revoke();
    }
}

/// A BAR prefix whose `ioremap` can be safely replaced while interrupts are
/// quiesced.
///
/// Management MMIO accesses briefly hold an irq-save spinlock. Queue hot
/// paths may acquire a revocable register lease during setup and use RCU
/// read-side protection instead. A remap allocates the new mapping before
/// taking the lock, swaps mappings under it, then revokes old leases and waits
/// for readers before unmapping outside the lock. All mapping destruction,
/// including final Drop, must run in sleepable context. Lease acquisition,
/// remap, revocation and device power transitions must be serialized by the
/// transport's lifecycle lock.
#[pin_data]
pub struct RemappableBar {
    _pdev: ARef<Device>,
    resource_start: bindings::resource_size_t,
    resource_len: usize,
    // Serialize complete cold transitions, including the RCU grace period.
    // Revocable::revoke returns immediately to a second revoker, so merely
    // serializing the pointer swap would not protect concurrent unmap.
    #[pin]
    lease_lifecycle: Mutex<()>,
    #[pin]
    mapping: SpinLockIrqSave<Option<LeaseableBarMapping>>,
}

impl RemappableBar {
    /// Map the first `size` bytes of `bar`.
    pub fn new<'a>(
        pdev: &'a Device<device::Core>,
        bar_index: u32,
        size: usize,
    ) -> impl PinInit<Self, Error> + 'a {
        try_pin_init!(Self {
            _pdev: pdev.into(),
            resource_start: pdev.resource_start(bar_index)?,
            resource_len: usize::try_from(pdev.resource_len(bar_index)?)?,
            lease_lifecycle <- crate::new_mutex!(()),
            mapping <- crate::new_spinlock_irqsave!(Some(LeaseableBarMapping::map(
                pdev.resource_start(bar_index)?,
                usize::try_from(pdev.resource_len(bar_index)?)?,
                size,
            )?)),
        })
    }

    /// Replace the current mapping with a prefix of `size` bytes.
    ///
    /// The transport must first stop hardware users whose multi-register
    /// transactions require stronger serialization than an individual access.
    pub fn remap(&self, size: usize) -> Result {
        let _lifecycle = self.lease_lifecycle.lock();
        let next = LeaseableBarMapping::map(self.resource_start, self.resource_len, size)?;
        let previous = {
            let mut mapping = self.mapping.lock();
            mem::replace(&mut *mapping, Some(next))
        };
        drop(previous);
        Ok(())
    }

    /// Unmap the BAR prefix. Further accesses fail with [`ENODEV`].
    pub fn unmap(&self) {
        let _lifecycle = self.lease_lifecycle.lock();
        let previous = {
            let mut mapping = self.mapping.lock();
            mapping.take()
        };
        drop(previous);
    }

    /// Acquire a queue-local fast handle to one 32-bit register.
    ///
    /// This is a cold setup operation. The transport must serialize it with
    /// remap, revocation and PCI power transitions. An earlier revoked lease
    /// stays revoked; acquiring a new one starts a new view generation.
    pub fn lease_write32(&self, offset: usize) -> Result<BarWrite32Lease> {
        let _lifecycle = self.lease_lifecycle.lock();
        let mut mapping = self.mapping.lock();
        Option::as_mut(&mut *mapping)
            .ok_or(ENODEV)?
            .lease_write32(offset)
    }

    /// Revoke all currently issued queue leases without unmapping admin MMIO.
    ///
    /// Quiesce queue users and serialize lifecycle operations first. This may
    /// sleep while waiting for in-flight MMIO readers; no spinlock is held
    /// during that wait. Existing leases subsequently return ENODEV. A later
    /// queue setup may acquire leases for a fresh generation on this mapping.
    pub fn revoke_leases(&self) {
        let _lifecycle = self.lease_lifecycle.lock();
        let view = self.mapping.lock().as_ref().map(|mapping| mapping.view.clone());
        if let Some(view) = view {
            view.revoke();
        }
    }

    /// Full BAR resource length, independent of the current mapped prefix.
    pub fn resource_len(&self) -> usize {
        self.resource_len
    }

    /// Length of the current mapping, or zero when unmapped.
    pub fn mapped_len(&self) -> usize {
        self.mapping
            .lock()
            .as_ref()
            .map(|mapping| mapping.raw.io.maxsize())
            .unwrap_or(0)
    }

    /// Read a little-endian 32-bit register at a runtime-checked offset.
    #[inline]
    pub fn read32(&self, offset: usize) -> Result<u32> {
        let mapping = self.mapping.lock();
        mapping.as_ref().ok_or(ENODEV)?.io().try_read32(offset)
    }

    /// Write a little-endian 32-bit register at a runtime-checked offset.
    #[inline]
    pub fn write32(&self, value: u32, offset: usize) -> Result {
        let mapping = self.mapping.lock();
        mapping
            .as_ref()
            .ok_or(ENODEV)?
            .io()
            .try_write32(value, offset)
    }

    /// Read a 64-bit register as low dword followed by high dword.
    pub fn read64_lo_hi(&self, offset: usize) -> Result<u64> {
        let mapping = self.mapping.lock();
        let io = mapping.as_ref().ok_or(ENODEV)?.io();
        let low = io.try_read32(offset)? as u64;
        let high = io.try_read32(offset.checked_add(4).ok_or(EINVAL)?)? as u64;
        Ok(low | (high << 32))
    }

    /// Write a 64-bit register as high dword followed by low dword.
    pub fn write64_hi_lo(&self, value: u64, offset: usize) -> Result {
        let mapping = self.mapping.lock();
        let io = mapping.as_ref().ok_or(ENODEV)?.io();
        io.try_write32((value >> 32) as u32, offset.checked_add(4).ok_or(EINVAL)?)?;
        io.try_write32(value as u32, offset)
    }

    /// Copy bytes to MMIO at a runtime-checked offset.
    pub fn copy_to(&self, offset: usize, source: &[u8]) -> Result {
        let mapping = self.mapping.lock();
        let io = mapping.as_ref().ok_or(ENODEV)?.io();
        let end = offset.checked_add(source.len()).ok_or(EINVAL)?;
        if end > io.maxsize() {
            return Err(EINVAL);
        }
        // SAFETY: Bounds were checked against the live mapping while its lock
        // is held; `source` is readable for its full length.
        unsafe {
            bindings::memcpy_toio(
                (io.addr() + offset) as *mut c_void,
                source.as_ptr().cast(),
                source.len(),
            )
        };
        Ok(())
    }

    /// Zero a byte range in MMIO.
    pub fn zero(&self, offset: usize, len: usize) -> Result {
        let mapping = self.mapping.lock();
        let io = mapping.as_ref().ok_or(ENODEV)?.io();
        let end = offset.checked_add(len).ok_or(EINVAL)?;
        if end > io.maxsize() {
            return Err(EINVAL);
        }
        // SAFETY: Bounds were checked against the live mapping while its lock
        // is held.
        unsafe { bindings::memset_io((io.addr() + offset) as *mut c_void, 0, len) };
        Ok(())
    }
}

/// A PCI BAR to perform I/O-Operations on.
///
/// # Invariants
///
/// `Bar` always holds an `IoRaw` inststance that holds a valid pointer to the start of the I/O
/// memory mapped PCI BAR and its size.
pub struct Bar<const SIZE: usize = 0> {
    pdev: ARef<Device>,
    io: IoRaw<SIZE>,
    num: i32,
}

impl<const SIZE: usize> Bar<SIZE> {
    pub(super) fn new(pdev: &Device, num: u32, name: &CStr) -> Result<Self> {
        let len = pdev.resource_len(num)?;
        if len == 0 {
            return Err(ENOMEM);
        }

        // Convert to `i32`, since that's what all the C bindings use.
        let num = i32::try_from(num)?;

        // SAFETY:
        // `pdev` is valid by the invariants of `Device`.
        // `num` is checked for validity by a previous call to `Device::resource_len`.
        // `name` is always valid.
        let ret = unsafe { bindings::pci_request_region(pdev.as_raw(), num, name.as_char_ptr()) };
        if ret != 0 {
            return Err(EBUSY);
        }

        // SAFETY:
        // `pdev` is valid by the invariants of `Device`.
        // `num` is checked for validity by a previous call to `Device::resource_len`.
        // `name` is always valid.
        let ioptr: usize = unsafe { bindings::pci_iomap(pdev.as_raw(), num, 0) } as usize;
        if ioptr == 0 {
            // SAFETY:
            // `pdev` valid by the invariants of `Device`.
            // `num` is checked for validity by a previous call to `Device::resource_len`.
            unsafe { bindings::pci_release_region(pdev.as_raw(), num) };
            return Err(ENOMEM);
        }

        let io = match IoRaw::new(ioptr, len as usize) {
            Ok(io) => io,
            Err(err) => {
                // SAFETY:
                // `pdev` is valid by the invariants of `Device`.
                // `ioptr` is guaranteed to be the start of a valid I/O mapped memory region.
                // `num` is checked for validity by a previous call to `Device::resource_len`.
                unsafe { Self::do_release(pdev, ioptr, num) };
                return Err(err);
            }
        };

        Ok(Bar {
            pdev: pdev.into(),
            io,
            num,
        })
    }

    /// # Safety
    ///
    /// `ioptr` must be a valid pointer to the memory mapped PCI BAR number `num`.
    unsafe fn do_release(pdev: &Device, ioptr: usize, num: i32) {
        // SAFETY:
        // `pdev` is valid by the invariants of `Device`.
        // `ioptr` is valid by the safety requirements.
        // `num` is valid by the safety requirements.
        unsafe {
            bindings::pci_iounmap(pdev.as_raw(), ioptr as *mut c_void);
            bindings::pci_release_region(pdev.as_raw(), num);
        }
    }

    fn release(&self) {
        // SAFETY: The safety requirements are guaranteed by the type invariant of `self.pdev`.
        unsafe { Self::do_release(&self.pdev, self.io.addr(), self.num) };
    }
}

impl Bar {
    #[inline]
    pub(super) fn index_is_valid(index: u32) -> bool {
        // A `struct pci_dev` owns an array of resources with at most `PCI_NUM_RESOURCES` entries.
        index < bindings::PCI_NUM_RESOURCES
    }
}

impl<const SIZE: usize> Drop for Bar<SIZE> {
    fn drop(&mut self) {
        self.release();
    }
}

impl<const SIZE: usize> Deref for Bar<SIZE> {
    type Target = Io<SIZE>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: By the type invariant of `Self`, the MMIO range in `self.io` is properly mapped.
        unsafe { Io::from_raw(&self.io) }
    }
}

impl Device<device::Bound> {
    /// Maps an entire PCI BAR after performing a region-request on it. I/O operation bound checks
    /// can be performed on compile time for offsets (plus the requested type size) < SIZE.
    pub fn iomap_region_sized<'a, const SIZE: usize>(
        &'a self,
        bar: u32,
        name: &'a CStr,
    ) -> impl PinInit<Devres<Bar<SIZE>>, Error> + 'a {
        Devres::new(self.as_ref(), Bar::<SIZE>::new(self, bar, name))
    }

    /// Maps an entire PCI BAR after performing a region-request on it.
    pub fn iomap_region<'a>(
        &'a self,
        bar: u32,
        name: &'a CStr,
    ) -> impl PinInit<Devres<Bar>, Error> + 'a {
        self.iomap_region_sized::<0>(bar, name)
    }
}

impl Device<device::Core> {
    /// Claim every memory BAR of this PCI function until the returned guard is
    /// dropped.
    pub fn request_mem_regions(&self, name: &CStr) -> Result<MemoryRegions> {
        // SAFETY: `self` is a live PCI function in probe context and `name` is
        // NUL terminated. The guard balances this successful request exactly
        // once.
        to_result(unsafe { bindings::pci_request_mem_regions(self.as_raw(), name.as_char_ptr()) })?;
        Ok(MemoryRegions { pdev: self.into() })
    }
}
