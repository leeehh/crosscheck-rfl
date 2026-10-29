// SPDX-License-Identifier: GPL-2.0

//! Direct memory access (DMA).
//!
//! C header: [`include/linux/dma-mapping.h`](srctree/include/linux/dma-mapping.h)

use crate::{
    bindings, build_assert, device,
    device::{Bound, Core},
    error::{to_result, Result},
    prelude::*,
    str::CStr,
    sync::aref::ARef,
    sync::Arc,
    transmute::{AsBytes, FromBytes},
};
use core::{marker::PhantomData, mem::size_of, ptr::NonNull};

/// DMA address type.
///
/// Represents a bus address used for Direct Memory Access (DMA) operations.
///
/// This is an alias of the kernel's `dma_addr_t`, which may be `u32` or `u64` depending on
/// `CONFIG_ARCH_DMA_ADDR_T_64BIT`.
///
/// Note that this may be `u64` even on 32-bit architectures.
pub type DmaAddress = bindings::dma_addr_t;

/// Trait to be implemented by DMA capable bus devices.
///
/// The [`dma::Device`](Device) trait should be implemented by bus specific device representations,
/// where the underlying bus is DMA capable, such as [`pci::Device`](::kernel::pci::Device) or
/// [`platform::Device`](::kernel::platform::Device).
pub trait Device: AsRef<device::Device<Core>> {
    /// Set up the device's DMA streaming addressing capabilities.
    ///
    /// This method is usually called once from `probe()` as soon as the device capabilities are
    /// known.
    ///
    /// # Safety
    ///
    /// This method must not be called concurrently with any DMA allocation or mapping primitives,
    /// such as [`CoherentAllocation::alloc_attrs`].
    unsafe fn dma_set_mask(&self, mask: DmaMask) -> Result {
        // SAFETY:
        // - By the type invariant of `device::Device`, `self.as_ref().as_raw()` is valid.
        // - The safety requirement of this function guarantees that there are no concurrent calls
        //   to DMA allocation and mapping primitives using this mask.
        to_result(unsafe { bindings::dma_set_mask(self.as_ref().as_raw(), mask.value()) })
    }

    /// Set up the device's DMA coherent addressing capabilities.
    ///
    /// This method is usually called once from `probe()` as soon as the device capabilities are
    /// known.
    ///
    /// # Safety
    ///
    /// This method must not be called concurrently with any DMA allocation or mapping primitives,
    /// such as [`CoherentAllocation::alloc_attrs`].
    unsafe fn dma_set_coherent_mask(&self, mask: DmaMask) -> Result {
        // SAFETY:
        // - By the type invariant of `device::Device`, `self.as_ref().as_raw()` is valid.
        // - The safety requirement of this function guarantees that there are no concurrent calls
        //   to DMA allocation and mapping primitives using this mask.
        to_result(unsafe { bindings::dma_set_coherent_mask(self.as_ref().as_raw(), mask.value()) })
    }

    /// Set up the device's DMA addressing capabilities.
    ///
    /// This is a combination of [`Device::dma_set_mask`] and [`Device::dma_set_coherent_mask`].
    ///
    /// This method is usually called once from `probe()` as soon as the device capabilities are
    /// known.
    ///
    /// # Safety
    ///
    /// This method must not be called concurrently with any DMA allocation or mapping primitives,
    /// such as [`CoherentAllocation::alloc_attrs`].
    unsafe fn dma_set_mask_and_coherent(&self, mask: DmaMask) -> Result {
        // SAFETY:
        // - By the type invariant of `device::Device`, `self.as_ref().as_raw()` is valid.
        // - The safety requirement of this function guarantees that there are no concurrent calls
        //   to DMA allocation and mapping primitives using this mask.
        to_result(unsafe {
            bindings::dma_set_mask_and_coherent(self.as_ref().as_raw(), mask.value())
        })
    }

    /// Set up both DMA masks while the bus driver's `probe()` callback has exclusive ownership of
    /// the device.
    ///
    /// Bus adapters implement this trait only for their `Core`-context device handle. During
    /// `probe()` that handle has not yet been published to data-path callbacks, so no DMA
    /// allocation or mapping can run concurrently. This method captures that adapter guarantee
    /// and keeps the C-boundary `unsafe` operation out of individual drivers.
    fn dma_set_mask_and_coherent_for_probe(&self, mask: DmaMask) -> Result {
        // SAFETY: The bus adapter's Core/probe context guarantees exclusive setup: the candidate
        // driver cannot publish a DMA allocation or mapping until probe returns successfully.
        unsafe { self.dma_set_mask_and_coherent(mask) }
    }

    /// Set the minimum DMA alignment mask during exclusive probe setup.
    fn dma_set_min_align_mask_for_probe(&self, mask: u32) {
        // SAFETY: The bus adapter's Core/probe context prevents concurrent
        // DMA mappings while the device parameters are being established.
        unsafe { bindings::dma_set_min_align_mask(self.as_ref().as_raw(), mask) };
    }

    /// Set the maximum DMA segment size during exclusive probe setup.
    fn dma_set_max_segment_size_for_probe(&self, size: u32) {
        // SAFETY: See `dma_set_min_align_mask_for_probe`.
        unsafe { bindings::dma_set_max_seg_size(self.as_ref().as_raw(), size) };
    }
}

/// Largest single DMA mapping supported by `dev`.
#[inline]
pub fn max_mapping_size(dev: &device::Device) -> usize {
    // SAFETY: This is a value-only query on a live device.
    unsafe { bindings::dma_max_mapping_size(dev.as_raw()) }
}

/// Preferred upper bound for one DMA mapping on `dev`.
#[inline]
pub fn optimal_mapping_size(dev: &device::Device) -> usize {
    // SAFETY: This is a value-only query on a live device.
    unsafe { bindings::dma_opt_mapping_size(dev.as_raw()) }
}

/// Boundary mask across which DMA ranges cannot be merged.
#[inline]
pub fn merge_boundary(dev: &device::Device) -> usize {
    // SAFETY: This is a value-only query on a live device.
    unsafe { bindings::dma_get_merge_boundary(dev.as_raw()) as usize }
}

/// A DMA mask that holds a bitmask with the lowest `n` bits set.
///
/// Use [`DmaMask::new`] or [`DmaMask::try_new`] to construct a value. Values
/// are guaranteed to never exceed the bit width of `u64`.
///
/// This is the Rust equivalent of the C macro `DMA_BIT_MASK()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaMask(u64);

impl DmaMask {
    /// Constructs a `DmaMask` with the lowest `n` bits set to `1`.
    ///
    /// For `n <= 64`, sets exactly the lowest `n` bits.
    /// For `n > 64`, results in a build error.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::dma::DmaMask;
    ///
    /// let mask0 = DmaMask::new::<0>();
    /// assert_eq!(mask0.value(), 0);
    ///
    /// let mask1 = DmaMask::new::<1>();
    /// assert_eq!(mask1.value(), 0b1);
    ///
    /// let mask64 = DmaMask::new::<64>();
    /// assert_eq!(mask64.value(), u64::MAX);
    ///
    /// // Build failure.
    /// // let mask_overflow = DmaMask::new::<100>();
    /// ```
    #[inline]
    pub const fn new<const N: u32>() -> Self {
        let Ok(mask) = Self::try_new(N) else {
            build_error!("Invalid DMA Mask.");
        };

        mask
    }

    /// Constructs a `DmaMask` with the lowest `n` bits set to `1`.
    ///
    /// For `n <= 64`, sets exactly the lowest `n` bits.
    /// For `n > 64`, returns [`EINVAL`].
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::dma::DmaMask;
    ///
    /// let mask0 = DmaMask::try_new(0)?;
    /// assert_eq!(mask0.value(), 0);
    ///
    /// let mask1 = DmaMask::try_new(1)?;
    /// assert_eq!(mask1.value(), 0b1);
    ///
    /// let mask64 = DmaMask::try_new(64)?;
    /// assert_eq!(mask64.value(), u64::MAX);
    ///
    /// let mask_overflow = DmaMask::try_new(100);
    /// assert!(mask_overflow.is_err());
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    pub const fn try_new(n: u32) -> Result<Self> {
        Ok(Self(match n {
            0 => 0,
            1..=64 => u64::MAX >> (64 - n),
            _ => return Err(EINVAL),
        }))
    }

    /// Returns the underlying `u64` bitmask value.
    #[inline]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

/// Possible attributes associated with a DMA mapping.
///
/// They can be combined with the operators `|`, `&`, and `!`.
///
/// Values can be used from the [`attrs`] module.
///
/// # Examples
///
/// ```
/// # use kernel::device::{Bound, Device};
/// use kernel::dma::{attrs::*, CoherentAllocation};
///
/// # fn test(dev: &Device<Bound>) -> Result {
/// let attribs = DMA_ATTR_FORCE_CONTIGUOUS | DMA_ATTR_NO_WARN;
/// let c: CoherentAllocation<u64> =
///     CoherentAllocation::alloc_attrs(dev, 4, GFP_KERNEL, attribs)?;
/// # Ok::<(), Error>(()) }
/// ```
#[derive(Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct Attrs(u32);

impl Attrs {
    /// No special DMA mapping attributes.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Get the raw representation of this attribute.
    pub(crate) fn as_raw(self) -> crate::ffi::c_ulong {
        self.0 as crate::ffi::c_ulong
    }

    /// Check whether `flags` is contained in `self`.
    pub fn contains(self, flags: Attrs) -> bool {
        (self & flags) == flags
    }
}

impl core::ops::BitOr for Attrs {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Attrs {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::Not for Attrs {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

/// DMA mapping attributes.
pub mod attrs {
    use super::Attrs;

    /// Specifies that reads and writes to the mapping may be weakly ordered, that is that reads
    /// and writes may pass each other.
    pub const DMA_ATTR_WEAK_ORDERING: Attrs = Attrs(bindings::DMA_ATTR_WEAK_ORDERING);

    /// Specifies that writes to the mapping may be buffered to improve performance.
    pub const DMA_ATTR_WRITE_COMBINE: Attrs = Attrs(bindings::DMA_ATTR_WRITE_COMBINE);

    /// Lets the platform to avoid creating a kernel virtual mapping for the allocated buffer.
    pub const DMA_ATTR_NO_KERNEL_MAPPING: Attrs = Attrs(bindings::DMA_ATTR_NO_KERNEL_MAPPING);

    /// Allows platform code to skip synchronization of the CPU cache for the given buffer assuming
    /// that it has been already transferred to 'device' domain.
    pub const DMA_ATTR_SKIP_CPU_SYNC: Attrs = Attrs(bindings::DMA_ATTR_SKIP_CPU_SYNC);

    /// Forces contiguous allocation of the buffer in physical memory.
    pub const DMA_ATTR_FORCE_CONTIGUOUS: Attrs = Attrs(bindings::DMA_ATTR_FORCE_CONTIGUOUS);

    /// Hints DMA-mapping subsystem that it's probably not worth the time to try
    /// to allocate memory to in a way that gives better TLB efficiency.
    pub const DMA_ATTR_ALLOC_SINGLE_PAGES: Attrs = Attrs(bindings::DMA_ATTR_ALLOC_SINGLE_PAGES);

    /// This tells the DMA-mapping subsystem to suppress allocation failure reports (similarly to
    /// `__GFP_NOWARN`).
    pub const DMA_ATTR_NO_WARN: Attrs = Attrs(bindings::DMA_ATTR_NO_WARN);

    /// Indicates that the buffer is fully accessible at an elevated privilege level (and
    /// ideally inaccessible or at least read-only at lesser-privileged levels).
    pub const DMA_ATTR_PRIVILEGED: Attrs = Attrs(bindings::DMA_ATTR_PRIVILEGED);

    /// Indicates that the buffer is MMIO memory.
    pub const DMA_ATTR_MMIO: Attrs = Attrs(bindings::DMA_ATTR_MMIO);
}

/// DMA data direction.
///
/// Corresponds to the C [`enum dma_data_direction`].
///
/// [`enum dma_data_direction`]: srctree/include/linux/dma-direction.h
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum DataDirection {
    /// The DMA mapping is for bidirectional data transfer.
    ///
    /// This is used when the buffer can be both read from and written to by the device.
    /// The cache for the corresponding memory region is both flushed and invalidated.
    Bidirectional = Self::const_cast(bindings::dma_data_direction_DMA_BIDIRECTIONAL),

    /// The DMA mapping is for data transfer from memory to the device (write).
    ///
    /// The CPU has prepared data in the buffer, and the device will read it.
    /// The cache for the corresponding memory region is flushed before device access.
    ToDevice = Self::const_cast(bindings::dma_data_direction_DMA_TO_DEVICE),

    /// The DMA mapping is for data transfer from the device to memory (read).
    ///
    /// The device will write data into the buffer for the CPU to read.
    /// The cache for the corresponding memory region is invalidated before CPU access.
    FromDevice = Self::const_cast(bindings::dma_data_direction_DMA_FROM_DEVICE),

    /// The DMA mapping is not for data transfer.
    ///
    /// This is primarily for debugging purposes. With this direction, the DMA mapping API
    /// will not perform any cache coherency operations.
    None = Self::const_cast(bindings::dma_data_direction_DMA_NONE),
}

impl DataDirection {
    /// Casts the bindgen-generated enum type to a `u32` at compile time.
    ///
    /// This function will cause a compile-time error if the underlying value of the
    /// C enum is out of bounds for `u32`.
    const fn const_cast(val: bindings::dma_data_direction) -> u32 {
        // CAST: The C standard allows compilers to choose different integer types for enums.
        // To safely check the value, we cast it to a wide signed integer type (`i128`)
        // which can hold any standard C integer enum type without truncation.
        let wide_val = val as i128;

        // Check if the value is outside the valid range for the target type `u32`.
        // CAST: `u32::MAX` is cast to `i128` to match the type of `wide_val` for the comparison.
        if wide_val < 0 || wide_val > u32::MAX as i128 {
            // Trigger a compile-time error in a const context.
            build_error!("C enum value is out of bounds for the target type `u32`.");
        }

        // CAST: This cast is valid because the check above guarantees that `wide_val`
        // is within the representable range of `u32`.
        wide_val as u32
    }
}

impl From<DataDirection> for bindings::dma_data_direction {
    /// Returns the raw representation of [`enum dma_data_direction`].
    fn from(direction: DataDirection) -> Self {
        // CAST: `direction as u32` gets the underlying representation of our `#[repr(u32)]` enum.
        // The subsequent cast to `Self` (the bindgen type) assumes the C enum is compatible
        // with the enum variants of `DataDirection`, which is a valid assumption given our
        // compile-time checks.
        direction as u32 as Self
    }
}

/// An owned DMA allocation without a CPU-accessible mapping.
///
/// This wraps `dma_alloc_attrs()` with [`attrs::DMA_ATTR_NO_KERNEL_MAPPING`].
/// The value returned in the C `cpu_addr` position may be an opaque cookie rather
/// than a dereferenceable pointer, so this abstraction deliberately exposes only
/// the DMA address and allocation size. The cookie is retained solely for the
/// matching `dma_free_attrs()` call.
///
/// Platforms may ignore `DMA_ATTR_NO_KERNEL_MAPPING` and create a CPU mapping
/// anyway. This type still does not expose it, which preserves the same safe API
/// and ownership rules on every platform.
pub struct NoKernelMappingAllocation {
    dev: ARef<device::Device>,
    dma_handle: DmaAddress,
    size: usize,
    cookie: NonNull<u8>,
    dma_attrs: Attrs,
}

impl NoKernelMappingAllocation {
    /// Allocates `size` bytes of coherent DMA memory without requesting a CPU
    /// mapping.
    ///
    /// `dma_attrs` contains any additional allocation attributes; this method
    /// always adds [`attrs::DMA_ATTR_NO_KERNEL_MAPPING`].
    pub fn new(
        dev: &device::Device<Bound>,
        size: usize,
        gfp_flags: kernel::alloc::Flags,
        dma_attrs: Attrs,
    ) -> Result<Self> {
        if size == 0 {
            return Err(EINVAL);
        }

        let dma_attrs = dma_attrs | attrs::DMA_ATTR_NO_KERNEL_MAPPING;
        let mut dma_handle = 0;
        // SAFETY: `dev` is valid by the `Device` type invariant. The returned
        // value is treated only as an opaque release cookie and is never
        // dereferenced.
        let cookie = unsafe {
            bindings::dma_alloc_attrs(
                dev.as_raw(),
                size,
                &mut dma_handle,
                gfp_flags.as_raw(),
                dma_attrs.as_raw(),
            )
        };
        let cookie = NonNull::new(cookie).ok_or(ENOMEM)?.cast();

        Ok(Self {
            dev: dev.into(),
            dma_handle,
            size,
            cookie,
            dma_attrs,
        })
    }

    /// Returns the size of the allocation in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the DMA address base of the allocation.
    pub fn dma_handle(&self) -> DmaAddress {
        self.dma_handle
    }
}

/// The device must be halted before this object is dropped.
impl Drop for NoKernelMappingAllocation {
    fn drop(&mut self) {
        // SAFETY: The device reference, size, opaque cookie, DMA address and
        // attributes are exactly those retained from the successful allocation.
        unsafe {
            bindings::dma_free_attrs(
                self.dev.as_raw(),
                self.size,
                self.cookie.as_ptr().cast(),
                self.dma_handle,
                self.dma_attrs.as_raw(),
            )
        }
    }
}

// SAFETY: Ownership of the allocation and its release cookie moves with the
// value; the type exposes no CPU-accessible memory.
unsafe impl Send for NoKernelMappingAllocation {}

/// An abstraction of the `dma_alloc_coherent` API.
///
/// This is an abstraction around the `dma_alloc_coherent` API which is used to allocate and map
/// large coherent DMA regions.
///
/// A [`CoherentAllocation`] instance contains a pointer to the allocated region (in the
/// processor's virtual address space) and the device address which can be given to the device
/// as the DMA address base of the region. The region is released once [`CoherentAllocation`]
/// is dropped.
///
/// # Invariants
///
/// - For the lifetime of an instance of [`CoherentAllocation`], the `cpu_addr` is a valid pointer
///   to an allocated region of coherent memory and `dma_handle` is the DMA address base of the
///   region.
/// - The size in bytes of the allocation is equal to `size_of::<T> * count`.
/// - `size_of::<T> * count` fits into a `usize`.
// TODO
//
// DMA allocations potentially carry device resources (e.g.IOMMU mappings), hence for soundness
// reasons DMA allocation would need to be embedded in a `Devres` container, in order to ensure
// that device resources can never survive device unbind.
//
// However, it is neither desirable nor necessary to protect the allocated memory of the DMA
// allocation from surviving device unbind; it would require RCU read side critical sections to
// access the memory, which may require subsequent unnecessary copies.
//
// Hence, find a way to revoke the device resources of a `CoherentAllocation`, but not the
// entire `CoherentAllocation` including the allocated memory itself.
pub struct CoherentAllocation<T: AsBytes + FromBytes> {
    dev: ARef<device::Device>,
    dma_handle: DmaAddress,
    count: usize,
    cpu_addr: NonNull<T>,
    dma_attrs: Attrs,
}

impl<T: AsBytes + FromBytes> CoherentAllocation<T> {
    /// Allocates a region of `size_of::<T> * count` of coherent memory.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kernel::device::{Bound, Device};
    /// use kernel::dma::{attrs::*, CoherentAllocation};
    ///
    /// # fn test(dev: &Device<Bound>) -> Result {
    /// let c: CoherentAllocation<u64> =
    ///     CoherentAllocation::alloc_attrs(dev, 4, GFP_KERNEL, DMA_ATTR_NO_WARN)?;
    /// # Ok::<(), Error>(()) }
    /// ```
    pub fn alloc_attrs(
        dev: &device::Device<Bound>,
        count: usize,
        gfp_flags: kernel::alloc::Flags,
        dma_attrs: Attrs,
    ) -> Result<CoherentAllocation<T>> {
        build_assert!(
            core::mem::size_of::<T>() > 0,
            "It doesn't make sense for the allocated type to be a ZST"
        );

        let size = count
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(EOVERFLOW)?;
        let mut dma_handle = 0;
        // SAFETY: Device pointer is guaranteed as valid by the type invariant on `Device`.
        let addr = unsafe {
            bindings::dma_alloc_attrs(
                dev.as_raw(),
                size,
                &mut dma_handle,
                gfp_flags.as_raw(),
                dma_attrs.as_raw(),
            )
        };
        let addr = NonNull::new(addr).ok_or(ENOMEM)?;
        // INVARIANT:
        // - We just successfully allocated a coherent region which is accessible for
        //   `count` elements, hence the cpu address is valid. We also hold a refcounted reference
        //   to the device.
        // - The allocated `size` is equal to `size_of::<T> * count`.
        // - The allocated `size` fits into a `usize`.
        Ok(Self {
            dev: dev.into(),
            dma_handle,
            count,
            cpu_addr: addr.cast(),
            dma_attrs,
        })
    }

    /// Performs the same functionality as [`CoherentAllocation::alloc_attrs`], except the
    /// `dma_attrs` is 0 by default.
    pub fn alloc_coherent(
        dev: &device::Device<Bound>,
        count: usize,
        gfp_flags: kernel::alloc::Flags,
    ) -> Result<CoherentAllocation<T>> {
        CoherentAllocation::alloc_attrs(dev, count, gfp_flags, Attrs(0))
    }

    /// Returns the number of elements `T` in this allocation.
    ///
    /// Note that this is not the size of the allocation in bytes, which is provided by
    /// [`Self::size`].
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the size in bytes of this allocation.
    pub fn size(&self) -> usize {
        // INVARIANT: The type invariant of `Self` guarantees that `size_of::<T> * count` fits into
        // a `usize`.
        self.count * core::mem::size_of::<T>()
    }

    /// Returns the base address to the allocated region in the CPU's virtual address space.
    pub fn start_ptr(&self) -> *const T {
        self.cpu_addr.as_ptr()
    }

    /// Returns the base address to the allocated region in the CPU's virtual address space as
    /// a mutable pointer.
    pub fn start_ptr_mut(&mut self) -> *mut T {
        self.cpu_addr.as_ptr()
    }

    /// Returns a DMA handle which may be given to the device as the DMA address base of
    /// the region.
    pub fn dma_handle(&self) -> DmaAddress {
        self.dma_handle
    }

    /// Returns a DMA handle starting at `offset` (in units of `T`) which may be given to the
    /// device as the DMA address base of the region.
    ///
    /// Returns `EINVAL` if `offset` is not within the bounds of the allocation.
    pub fn dma_handle_with_offset(&self, offset: usize) -> Result<DmaAddress> {
        if offset >= self.count {
            Err(EINVAL)
        } else {
            // INVARIANT: The type invariant of `Self` guarantees that `size_of::<T> * count` fits
            // into a `usize`, and `offset` is inferior to `count`.
            Ok(self.dma_handle + (offset * core::mem::size_of::<T>()) as DmaAddress)
        }
    }

    /// Common helper to validate a range applied from the allocated region in the CPU's virtual
    /// address space.
    fn validate_range(&self, offset: usize, count: usize) -> Result {
        if offset.checked_add(count).ok_or(EOVERFLOW)? > self.count {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// Returns the data from the region starting from `offset` as a slice.
    /// `offset` and `count` are in units of `T`, not the number of bytes.
    ///
    /// For ringbuffer type of r/w access or use-cases where the pointer to the live data is needed,
    /// [`CoherentAllocation::start_ptr`] or [`CoherentAllocation::start_ptr_mut`] could be used
    /// instead.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that the device does not read/write to/from memory while the returned
    ///   slice is live.
    /// * Callers must ensure that this call does not race with a write to the same region while
    ///   the returned slice is live.
    pub unsafe fn as_slice(&self, offset: usize, count: usize) -> Result<&[T]> {
        self.validate_range(offset, count)?;
        // SAFETY:
        // - The pointer is valid due to type invariant on `CoherentAllocation`,
        //   we've just checked that the range and index is within bounds. The immutability of the
        //   data is also guaranteed by the safety requirements of the function.
        // - `offset + count` can't overflow since it is smaller than `self.count` and we've checked
        //   that `self.count` won't overflow early in the constructor.
        Ok(unsafe { core::slice::from_raw_parts(self.start_ptr().add(offset), count) })
    }

    /// Performs the same functionality as [`CoherentAllocation::as_slice`], except that a mutable
    /// slice is returned.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that the device does not read/write to/from memory while the returned
    ///   slice is live.
    /// * Callers must ensure that this call does not race with a read or write to the same region
    ///   while the returned slice is live.
    pub unsafe fn as_slice_mut(&mut self, offset: usize, count: usize) -> Result<&mut [T]> {
        self.validate_range(offset, count)?;
        // SAFETY:
        // - The pointer is valid due to type invariant on `CoherentAllocation`,
        //   we've just checked that the range and index is within bounds. The immutability of the
        //   data is also guaranteed by the safety requirements of the function.
        // - `offset + count` can't overflow since it is smaller than `self.count` and we've checked
        //   that `self.count` won't overflow early in the constructor.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.start_ptr_mut().add(offset), count) })
    }

    /// Writes data to the region starting from `offset`. `offset` is in units of `T`, not the
    /// number of bytes.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that the device does not read/write to/from memory while the returned
    ///   slice is live.
    /// * Callers must ensure that this call does not race with a read or write to the same region
    ///   that overlaps with this write.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn test(alloc: &mut kernel::dma::CoherentAllocation<u8>) -> Result {
    /// let somedata: [u8; 4] = [0xf; 4];
    /// let buf: &[u8] = &somedata;
    /// // SAFETY: There is no concurrent HW operation on the device and no other R/W access to the
    /// // region.
    /// unsafe { alloc.write(buf, 0)?; }
    /// # Ok::<(), Error>(()) }
    /// ```
    pub unsafe fn write(&mut self, src: &[T], offset: usize) -> Result {
        self.validate_range(offset, src.len())?;
        // SAFETY:
        // - The pointer is valid due to type invariant on `CoherentAllocation`
        //   and we've just checked that the range and index is within bounds.
        // - `offset + count` can't overflow since it is smaller than `self.count` and we've checked
        //   that `self.count` won't overflow early in the constructor.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.start_ptr_mut().add(offset),
                src.len(),
            )
        };
        Ok(())
    }

    /// Returns a pointer to an element from the region with bounds checking. `offset` is in
    /// units of `T`, not the number of bytes.
    ///
    /// Public but hidden since it should only be used from [`dma_read`] and [`dma_write`] macros.
    #[doc(hidden)]
    pub fn item_from_index(&self, offset: usize) -> Result<*mut T> {
        if offset >= self.count {
            return Err(EINVAL);
        }
        // SAFETY:
        // - The pointer is valid due to type invariant on `CoherentAllocation`
        // and we've just checked that the range and index is within bounds.
        // - `offset` can't overflow since it is smaller than `self.count` and we've checked
        // that `self.count` won't overflow early in the constructor.
        Ok(unsafe { self.cpu_addr.as_ptr().add(offset) })
    }

    /// Reads the value of `field` and ensures that its type is [`FromBytes`].
    ///
    /// # Safety
    ///
    /// This must be called from the [`dma_read`] macro which ensures that the `field` pointer is
    /// validated beforehand.
    ///
    /// Public but hidden since it should only be used from [`dma_read`] macro.
    #[doc(hidden)]
    pub unsafe fn field_read<F: FromBytes>(&self, field: *const F) -> F {
        // SAFETY:
        // - By the safety requirements field is valid.
        // - Using read_volatile() here is not sound as per the usual rules, the usage here is
        // a special exception with the following notes in place. When dealing with a potential
        // race from a hardware or code outside kernel (e.g. user-space program), we need that
        // read on a valid memory is not UB. Currently read_volatile() is used for this, and the
        // rationale behind is that it should generate the same code as READ_ONCE() which the
        // kernel already relies on to avoid UB on data races. Note that the usage of
        // read_volatile() is limited to this particular case, it cannot be used to prevent
        // the UB caused by racing between two kernel functions nor do they provide atomicity.
        unsafe { field.read_volatile() }
    }

    /// Writes a value to `field` and ensures that its type is [`AsBytes`].
    ///
    /// # Safety
    ///
    /// This must be called from the [`dma_write`] macro which ensures that the `field` pointer is
    /// validated beforehand.
    ///
    /// Public but hidden since it should only be used from [`dma_write`] macro.
    #[doc(hidden)]
    pub unsafe fn field_write<F: AsBytes>(&self, field: *mut F, val: F) {
        // SAFETY:
        // - By the safety requirements field is valid.
        // - Using write_volatile() here is not sound as per the usual rules, the usage here is
        // a special exception with the following notes in place. When dealing with a potential
        // race from a hardware or code outside kernel (e.g. user-space program), we need that
        // write on a valid memory is not UB. Currently write_volatile() is used for this, and the
        // rationale behind is that it should generate the same code as WRITE_ONCE() which the
        // kernel already relies on to avoid UB on data races. Note that the usage of
        // write_volatile() is limited to this particular case, it cannot be used to prevent
        // the UB caused by racing between two kernel functions nor do they provide atomicity.
        unsafe { field.write_volatile(val) }
    }
}

/// Note that the device configured to do DMA must be halted before this object is dropped.
impl<T: AsBytes + FromBytes> Drop for CoherentAllocation<T> {
    fn drop(&mut self) {
        let size = self.count * core::mem::size_of::<T>();
        // SAFETY: Device pointer is guaranteed as valid by the type invariant on `Device`.
        // The cpu address, and the dma handle are valid due to the type invariants on
        // `CoherentAllocation`.
        unsafe {
            bindings::dma_free_attrs(
                self.dev.as_raw(),
                size,
                self.start_ptr_mut().cast(),
                self.dma_handle,
                self.dma_attrs.as_raw(),
            )
        }
    }
}

// SAFETY: It is safe to send a `CoherentAllocation` to another thread if `T`
// can be sent to another thread.
unsafe impl<T: AsBytes + FromBytes + Send> Send for CoherentAllocation<T> {}

/// A fixed-size coherent allocation pool bound to a DMA device.
///
/// Every checked-out [`DmaPoolAllocation`] retains an [`Arc`] to its source
/// pool. Consequently `dma_pool_destroy()` cannot run until all allocations
/// have been returned, and an allocation cannot be freed through a different
/// pool instance.
pub struct DmaPool<T: FromBytes + Copy> {
    raw: NonNull<bindings::dma_pool>,
    _dev: ARef<device::Device>,
    _p: PhantomData<T>,
}

// SAFETY: The DMA pool API serializes allocation/free operations. Values of T
// are exclusively owned by their DmaPoolAllocation.
unsafe impl<T: FromBytes + Copy + Send> Send for DmaPool<T> {}
// SAFETY: Shared pool access only allocates distinct elements.
unsafe impl<T: FromBytes + Copy + Send> Sync for DmaPool<T> {}

impl<T: FromBytes + Copy> DmaPool<T> {
    /// Create a pool for one `T` per allocation on `node`.
    pub fn new(
        name: &CStr,
        dev: &device::Device<Bound>,
        alignment: usize,
        boundary: usize,
        node: i32,
        flags: crate::alloc::Flags,
    ) -> Result<Arc<Self>> {
        if size_of::<T>() == 0 || alignment == 0 || !alignment.is_power_of_two() {
            return Err(EINVAL);
        }
        if boundary != 0 && !boundary.is_power_of_two() {
            return Err(EINVAL);
        }
        // SAFETY: `dev` is bound for this construction call, `name` is NUL
        // terminated, and size/alignment/boundary satisfy dma_pool's input
        // contract. The returned pool is paired with Drop below.
        let raw = unsafe {
            bindings::dma_pool_create_node(
                name.as_char_ptr(),
                dev.as_raw(),
                size_of::<T>(),
                alignment,
                boundary,
                node,
            )
        };
        let raw = NonNull::new(raw).ok_or(ENOMEM)?;
        Arc::new(
            Self {
                raw,
                _dev: dev.into(),
                _p: PhantomData,
            },
            flags,
        )
        .map_err(|_| ENOMEM)
    }

    /// Allocate and zero one pool element.
    pub fn allocate(self: &Arc<Self>, flags: crate::alloc::Flags) -> Result<DmaPoolAllocation<T>> {
        let mut dma_address = 0;
        // SAFETY: The Arc keeps the live pool stable; dma_pool_alloc returns
        // exclusive storage for exactly one T and writes its DMA address.
        let cpu_address = unsafe {
            bindings::dma_pool_alloc(self.raw.as_ptr(), flags.as_raw(), &mut dma_address)
        };
        let cpu_address = NonNull::new(cpu_address.cast::<T>()).ok_or(ENOMEM)?;
        // SAFETY: Pool storage is suitably aligned and sized for T. Zeroing
        // establishes a valid value for a FromBytes type; Copy excludes Drop.
        unsafe { cpu_address.as_ptr().write_bytes(0, 1) };
        Ok(DmaPoolAllocation {
            cpu_address,
            dma_address,
            pool: self.clone(),
        })
    }
}

impl<T: FromBytes + Copy> Drop for DmaPool<T> {
    fn drop(&mut self) {
        // SAFETY: Each allocation retains an Arc, so the final pool reference
        // can disappear only after every allocation has been returned.
        unsafe { bindings::dma_pool_destroy(self.raw.as_ptr()) };
    }
}

/// One typed allocation checked out from a [`DmaPool`].
pub struct DmaPoolAllocation<T: FromBytes + Copy> {
    cpu_address: NonNull<T>,
    dma_address: DmaAddress,
    pool: Arc<DmaPool<T>>,
}

// SAFETY: The allocation is uniquely owned and its pool/device are retained.
unsafe impl<T: FromBytes + Copy + Send> Send for DmaPoolAllocation<T> {}

impl<T: FromBytes + Copy> DmaPoolAllocation<T> {
    /// DMA address to place in a device descriptor.
    #[inline]
    pub fn dma_address(&self) -> DmaAddress {
        self.dma_address
    }

    /// CPU pointer to the allocation.
    ///
    /// # Safety
    ///
    /// The caller must prevent concurrent device access for the duration of
    /// any reference or operation derived from this pointer.
    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        self.cpu_address.as_ptr()
    }

    /// Read-only CPU pointer to the allocation.
    ///
    /// # Safety
    ///
    /// The caller must prevent concurrent device writes to the allocation.
    #[inline]
    pub unsafe fn as_ptr(&self) -> *const T {
        self.cpu_address.as_ptr()
    }
}

impl<T: FromBytes + Copy> Drop for DmaPoolAllocation<T> {
    fn drop(&mut self) {
        // SAFETY: This allocation came from this exact retained pool and has
        // not previously been returned.
        unsafe {
            bindings::dma_pool_free(
                self.pool.raw.as_ptr(),
                self.cpu_address.as_ptr().cast(),
                self.dma_address,
            )
        };
    }
}

/// One DMA segment in a noncontiguous allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoncontiguousSegment {
    address: DmaAddress,
    length: usize,
}

impl NoncontiguousSegment {
    /// Device-visible base address.
    #[inline]
    pub fn address(self) -> DmaAddress {
        self.address
    }

    /// Segment length in bytes.
    #[inline]
    pub fn length(self) -> usize {
        self.length
    }
}

/// An owned `dma_alloc_noncontiguous()` allocation.
pub struct NoncontiguousAllocation {
    dev: ARef<device::Device>,
    table: NonNull<bindings::sg_table>,
    size: usize,
    direction: DataDirection,
}

// SAFETY: The allocation and mapping are owned and may be transferred after
// the device has been quiesced according to the DMA API contract.
unsafe impl Send for NoncontiguousAllocation {}

impl NoncontiguousAllocation {
    /// Allocate a potentially physically fragmented DMA region.
    pub fn new(
        dev: &device::Device<Bound>,
        size: usize,
        direction: DataDirection,
        flags: crate::alloc::Flags,
        attrs: Attrs,
    ) -> Result<Self> {
        if size == 0 {
            return Err(EINVAL);
        }
        // SAFETY: `dev` is bound, arguments describe a nonzero allocation,
        // and Drop uses the exact same device, size, table, and direction.
        let table = unsafe {
            bindings::dma_alloc_noncontiguous(
                dev.as_raw(),
                size,
                direction.into(),
                flags.as_raw(),
                attrs.as_raw(),
            )
        };
        Ok(Self {
            dev: dev.into(),
            table: NonNull::new(table).ok_or(ENOMEM)?,
            size,
            direction,
        })
    }

    /// Requested allocation size.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Iterate over the DMA-mapped segments.
    pub fn segments(&self) -> NoncontiguousSegments<'_> {
        // SAFETY: The owned table remains initialized for self's lifetime.
        let table = unsafe { self.table.as_ref() };
        NoncontiguousSegments {
            current: NonNull::new(table.sgl),
            remaining: table.nents,
            _lifetime: PhantomData,
        }
    }

    /// Base address when the DMA layer coalesced the allocation into a single
    /// device-visible range.
    pub fn single_dma_address(&self) -> Result<DmaAddress> {
        let mut segments = self.segments();
        let first = segments.next().ok_or(EIO)?;
        if segments.next().is_some() || first.length < self.size {
            return Err(E2BIG);
        }
        Ok(first.address)
    }
}

impl Drop for NoncontiguousAllocation {
    fn drop(&mut self) {
        // SAFETY: Exact inverse of the successful allocation in `new`; callers
        // must quiesce the device before dropping any DMA allocation.
        unsafe {
            bindings::dma_free_noncontiguous(
                self.dev.as_raw(),
                self.size,
                self.table.as_ptr(),
                self.direction.into(),
            )
        };
    }
}

/// Iterator over DMA segments owned by a [`NoncontiguousAllocation`].
pub struct NoncontiguousSegments<'a> {
    current: Option<NonNull<bindings::scatterlist>>,
    remaining: u32,
    _lifetime: PhantomData<&'a NoncontiguousAllocation>,
}

impl Iterator for NoncontiguousSegments<'_> {
    type Item = NoncontiguousSegment;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        if self.remaining == 0 {
            self.current = None;
            return None;
        }
        // SAFETY: `current` is one of the remaining live entries in the
        // allocation's sg_table and the table is DMA mapped.
        let segment = NoncontiguousSegment {
            address: unsafe { bindings::sg_dma_address(current.as_ptr()) },
            length: unsafe { bindings::sg_dma_len(current.as_ptr()) as usize },
        };
        self.remaining -= 1;
        // SAFETY: sg_next returns the next table entry or NULL.
        self.current = NonNull::new(unsafe { bindings::sg_next(current.as_ptr()) });
        Some(segment)
    }
}

/// Reads a field of an item from an allocated region of structs.
///
/// # Examples
///
/// ```
/// use kernel::device::Device;
/// use kernel::dma::{attrs::*, CoherentAllocation};
///
/// struct MyStruct { field: u32, }
///
/// // SAFETY: All bit patterns are acceptable values for `MyStruct`.
/// unsafe impl kernel::transmute::FromBytes for MyStruct{};
/// // SAFETY: Instances of `MyStruct` have no uninitialized portions.
/// unsafe impl kernel::transmute::AsBytes for MyStruct{};
///
/// # fn test(alloc: &kernel::dma::CoherentAllocation<MyStruct>) -> Result {
/// let whole = kernel::dma_read!(alloc[2]);
/// let field = kernel::dma_read!(alloc[1].field);
/// # Ok::<(), Error>(()) }
/// ```
#[macro_export]
macro_rules! dma_read {
    ($dma:expr, $idx: expr, $($field:tt)*) => {{
        (|| -> ::core::result::Result<_, $crate::error::Error> {
            let item = $crate::dma::CoherentAllocation::item_from_index(&$dma, $idx)?;
            // SAFETY: `item_from_index` ensures that `item` is always a valid pointer and can be
            // dereferenced. The compiler also further validates the expression on whether `field`
            // is a member of `item` when expanded by the macro.
            unsafe {
                let ptr_field = ::core::ptr::addr_of!((*item) $($field)*);
                ::core::result::Result::Ok(
                    $crate::dma::CoherentAllocation::field_read(&$dma, ptr_field)
                )
            }
        })()
    }};
    ($dma:ident [ $idx:expr ] $($field:tt)* ) => {
        $crate::dma_read!($dma, $idx, $($field)*)
    };
    ($($dma:ident).* [ $idx:expr ] $($field:tt)* ) => {
        $crate::dma_read!($($dma).*, $idx, $($field)*)
    };
}

/// Writes to a field of an item from an allocated region of structs.
///
/// # Examples
///
/// ```
/// use kernel::device::Device;
/// use kernel::dma::{attrs::*, CoherentAllocation};
///
/// struct MyStruct { member: u32, }
///
/// // SAFETY: All bit patterns are acceptable values for `MyStruct`.
/// unsafe impl kernel::transmute::FromBytes for MyStruct{};
/// // SAFETY: Instances of `MyStruct` have no uninitialized portions.
/// unsafe impl kernel::transmute::AsBytes for MyStruct{};
///
/// # fn test(alloc: &kernel::dma::CoherentAllocation<MyStruct>) -> Result {
/// kernel::dma_write!(alloc[2].member = 0xf);
/// kernel::dma_write!(alloc[1] = MyStruct { member: 0xf });
/// # Ok::<(), Error>(()) }
/// ```
#[macro_export]
macro_rules! dma_write {
    ($dma:ident [ $idx:expr ] $($field:tt)*) => {{
        $crate::dma_write!($dma, $idx, $($field)*)
    }};
    ($($dma:ident).* [ $idx:expr ] $($field:tt)* ) => {{
        $crate::dma_write!($($dma).*, $idx, $($field)*)
    }};
    ($dma:expr, $idx: expr, = $val:expr) => {
        (|| -> ::core::result::Result<_, $crate::error::Error> {
            let item = $crate::dma::CoherentAllocation::item_from_index(&$dma, $idx)?;
            // SAFETY: `item_from_index` ensures that `item` is always a valid item.
            unsafe { $crate::dma::CoherentAllocation::field_write(&$dma, item, $val) }
            ::core::result::Result::Ok(())
        })()
    };
    ($dma:expr, $idx: expr, $(.$field:ident)* = $val:expr) => {
        (|| -> ::core::result::Result<_, $crate::error::Error> {
            let item = $crate::dma::CoherentAllocation::item_from_index(&$dma, $idx)?;
            // SAFETY: `item_from_index` ensures that `item` is always a valid pointer and can be
            // dereferenced. The compiler also further validates the expression on whether `field`
            // is a member of `item` when expanded by the macro.
            unsafe {
                let ptr_field = ::core::ptr::addr_of_mut!((*item) $(.$field)*);
                $crate::dma::CoherentAllocation::field_write(&$dma, ptr_field, $val)
            }
            ::core::result::Result::Ok(())
        })()
    };
}
