// SPDX-License-Identifier: GPL-2.0

//! Port-mapped I/O (PIO).
//!
//! Safe accessors (`inb`/`outb` and friends) for the architecture's I/O port
//! address space, mirroring the memory-mapped [`Io`](crate::io::Io) abstraction.
//!
//! Where MMIO addresses are mapped pointers, PIO "addresses" are 16-bit port
//! numbers reached through the architecture `in*`/`out*` instructions. Ownership
//! of a port range is acquired with [`PortRegion`], which requests the range via
//! `request_region` and releases it on drop.
//!
//! C header: [`arch/x86/include/asm/io.h`](srctree/arch/x86/include/asm/io.h)

use core::ops::Deref;

use crate::{
    bindings,
    io::{
        resource::{Flags, Region, Resource},
        IoRaw, PhysAddr, ResourceSize,
    },
    prelude::*,
    str::CString,
};

/// Raw accessors to a range of the I/O port (PIO) address space.
///
/// This is the port-mapped counterpart of [`Io`](crate::io::Io): "addresses" are
/// 16-bit port numbers and accesses go through the architecture `in*`/`out*`
/// instructions rather than dereferencing a mapped pointer.
///
/// By itself an `IoPort` provides no guarantee that the underlying ports are
/// owned. Obtain one through a [`PortRegion`], which requests the range first.
///
/// # Invariant
///
/// The range `[base, base + SIZE)` is contained in the 16-bit port-number space
/// (`[0, 0x1_0000)`). This holds for *every* `IoPort`, established by both
/// constructors: [`PortRegion`] validates it before requesting the range, and
/// the `unsafe` [`Self::from_raw`] places the same obligation on its caller.
/// This containment is what makes the unchecked `as u16` in `port_addr_assert`
/// non-truncating.
///
/// In addition, when an `IoPort` is reached through a [`PortRegion`] — or a
/// [`Self::from_raw`] whose caller upheld its contract — that range is
/// exclusively owned for the lifetime of the borrow, which is what makes the
/// `in*`/`out*` accesses sound.
#[repr(transparent)]
pub struct IoPort<const SIZE: usize = 0>(IoRaw<SIZE>);

macro_rules! define_port_read {
    ($(#[$attr:meta])* $name:ident, $try_name:ident, $c_fn:ident -> $type_name:ty) => {
        /// Read from the port at `offset` from the region base.
        ///
        /// Bound checks are performed at compile time; if `offset` is not known
        /// at compile time, the build will fail. Use the `try_` variant for a
        /// runtime-checked access.
        $(#[$attr])*
        #[inline]
        pub fn $name(&self, offset: usize) -> $type_name {
            let port = self.port_addr_assert::<$type_name>(offset);

            // SAFETY: By the type invariant `port` is a valid, owned I/O port.
            unsafe { bindings::$c_fn(port) }
        }

        /// Read from the port at `offset` from the region base.
        ///
        /// Bound checks are performed at run time; fails with [`EINVAL`] if the
        /// offset (plus the access size) is out of bounds.
        $(#[$attr])*
        pub fn $try_name(&self, offset: usize) -> Result<$type_name> {
            let port = self.port_addr::<$type_name>(offset)?;

            // SAFETY: By the type invariant `port` is a valid, owned I/O port.
            Ok(unsafe { bindings::$c_fn(port) })
        }
    };
}

macro_rules! define_port_write {
    ($(#[$attr:meta])* $name:ident, $try_name:ident, $c_fn:ident <- $type_name:ty) => {
        /// Write to the port at `offset` from the region base.
        ///
        /// Bound checks are performed at compile time; if `offset` is not known
        /// at compile time, the build will fail. Use the `try_` variant for a
        /// runtime-checked access.
        $(#[$attr])*
        #[inline]
        pub fn $name(&self, value: $type_name, offset: usize) {
            let port = self.port_addr_assert::<$type_name>(offset);

            // SAFETY: By the type invariant `port` is a valid, owned I/O port.
            unsafe { bindings::$c_fn(value, port) }
        }

        /// Write to the port at `offset` from the region base.
        ///
        /// Bound checks are performed at run time; fails with [`EINVAL`] if the
        /// offset (plus the access size) is out of bounds.
        $(#[$attr])*
        pub fn $try_name(&self, value: $type_name, offset: usize) -> Result {
            let port = self.port_addr::<$type_name>(offset)?;

            // SAFETY: By the type invariant `port` is a valid, owned I/O port.
            unsafe { bindings::$c_fn(value, port) }
            Ok(())
        }
    };
}

impl<const SIZE: usize> IoPort<SIZE> {
    /// Converts an [`IoRaw`] into an `IoPort`, providing the port accessors.
    ///
    /// # Safety
    ///
    /// Callers must ensure that `raw`'s base is the start of an owned I/O port
    /// range of size `maxsize`, contained within the 16-bit port space.
    pub unsafe fn from_raw(raw: &IoRaw<SIZE>) -> &Self {
        // SAFETY: `IoPort` is a transparent wrapper around `IoRaw`.
        unsafe { &*core::ptr::from_ref(raw).cast() }
    }

    /// Returns the base port number of this region.
    #[inline]
    pub fn base(&self) -> usize {
        self.0.addr()
    }

    /// Returns the size of this region, in ports.
    #[inline]
    pub fn maxsize(&self) -> usize {
        self.0.maxsize()
    }

    #[inline]
    const fn offset_valid<U>(offset: usize, size: usize) -> bool {
        let type_size = core::mem::size_of::<U>();
        if let Some(end) = offset.checked_add(type_size) {
            end <= size && offset % type_size == 0
        } else {
            false
        }
    }

    #[inline]
    fn port_addr<U>(&self, offset: usize) -> Result<u16> {
        if !Self::offset_valid::<U>(offset, self.maxsize()) {
            return Err(EINVAL);
        }

        let port = self.base().checked_add(offset).ok_or(EINVAL)?;
        u16::try_from(port).map_err(|_| EINVAL)
    }

    #[inline]
    fn port_addr_assert<U>(&self, offset: usize) -> u16 {
        build_assert!(Self::offset_valid::<U>(offset, SIZE));

        // The base is established within the 16-bit port space by the type
        // invariant, and `offset < SIZE` by the assert above.
        (self.base() + offset) as u16
    }

    define_port_read!(inb, try_inb, inb -> u8);
    define_port_read!(inw, try_inw, inw -> u16);
    define_port_read!(inl, try_inl, inl -> u32);

    define_port_read!(inb_p, try_inb_p, inb_p -> u8);
    define_port_read!(inw_p, try_inw_p, inw_p -> u16);
    define_port_read!(inl_p, try_inl_p, inl_p -> u32);

    define_port_write!(outb, try_outb, outb <- u8);
    define_port_write!(outw, try_outw, outw <- u16);
    define_port_write!(outl, try_outl, outl <- u32);

    define_port_write!(outb_p, try_outb_p, outb_p <- u8);
    define_port_write!(outw_p, try_outw_p, outw_p <- u16);
    define_port_write!(outl_p, try_outl_p, outl_p <- u32);
}

/// An owned, requested range of I/O ports with [`IoPort`] accessors.
///
/// Requests `[base, base + SIZE)` from the global PIO space via `request_region`
/// (or `request_muxed_region`) and releases it on drop, then exposes
/// `inb`/`outb` access by dereferencing to [`IoPort`]. This mirrors how
/// [`IoMem`](crate::io::mem::IoMem) owns an `ioremap` mapping and derefs to
/// [`Io`](crate::io::Io).
///
/// # Examples
///
/// ```no_run
/// use kernel::{c_str, io::PortRegion, str::CString};
///
/// # fn no_run() -> Result<(), kernel::error::Error> {
/// // SMBus controllers carve out a small window of legacy I/O ports.
/// const EXTENT: usize = 8;
/// let name = CString::try_from_fmt(format_args!("my-smbus"))?;
/// let ports = PortRegion::<EXTENT>::request(0xE800, name)?;
///
/// // Index/data idiom: select a register, then read it back.
/// ports.outb(0x02, 0x00);
/// let status = ports.inb(0x01);
/// # let _ = status;
/// # Ok(())
/// # }
/// ```
pub struct PortRegion<const SIZE: usize = 0> {
    raw: IoRaw<SIZE>,
    // Releases the requested range on drop. The `Deref` impl borrows `&self`, so
    // no `IoPort` reference it hands out can outlive the region.
    _region: Region,
}

impl<const SIZE: usize> PortRegion<SIZE> {
    /// Requests exclusive ownership of the `SIZE` ports starting at `base`.
    ///
    /// `name` labels the region in `/proc/ioports`. Returns [`EBUSY`] if any
    /// port in the range is already in use, or [`EINVAL`] if `[base, base+SIZE)`
    /// does not fit the 16-bit port space.
    pub fn request(base: u16, name: CString) -> Result<Self> {
        Self::request_with_flags(base, name, Flags::IORESOURCE_IO)
    }

    /// Like [`Self::request`], but for a software-muxed port range
    /// (`request_muxed_region`); blocks until the range becomes free instead of
    /// failing when it is busy.
    pub fn request_muxed(base: u16, name: CString) -> Result<Self> {
        Self::request_with_flags(base, name, Flags::IORESOURCE_IO | Flags::IORESOURCE_MUXED)
    }

    fn request_with_flags(base: u16, name: CString, flags: Flags) -> Result<Self> {
        // Establishes `[base, base + SIZE)` within the 16-bit port space.
        let last = (base as usize).checked_add(SIZE).ok_or(EINVAL)?;
        if last > u16::MAX as usize + 1 {
            return Err(EINVAL);
        }
        let raw = IoRaw::new(base as usize, SIZE)?;

        let region = Resource::ioport()
            .request_region(base as PhysAddr, SIZE as ResourceSize, name, flags)
            .ok_or(EBUSY)?;

        Ok(Self {
            raw,
            _region: region,
        })
    }
}

impl<const SIZE: usize> Deref for PortRegion<SIZE> {
    type Target = IoPort<SIZE>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `self.raw` describes a port range that is exclusively owned by
        // `self._region` for as long as `self` is alive.
        unsafe { IoPort::from_raw(&self.raw) }
    }
}

/// [`IoPort`] accessors for a fixed range that is **not** region-claimed.
///
/// Where [`PortRegion`] calls `request_region` (and therefore fails with
/// [`EBUSY`](crate::error::code::EBUSY) when the range is already held),
/// `UnclaimedPorts` performs no claim at all. It exists for the uncommon case
/// where another driver legitimately holds the `request_region` for the range
/// but does not drive the hardware — for example a driver coexisting with the
/// in-kernel 8250 on a legacy COM port that the 8250 registers but never opens.
///
/// Prefer [`PortRegion`] whenever the range can be owned exclusively; reach for
/// `UnclaimedPorts` only when sharing with a non-driving region holder is
/// required and the caller has determined the access is safe to perform.
///
/// Construction and access are safe: port I/O has no Rust memory-safety impact
/// (offsets are bounds-checked against `SIZE`, and ports are confined to the
/// 16-bit space), so the only obligation — not conflicting with another driver
/// that *does* drive the range — is a coordination concern, not a soundness
/// one.
///
/// # Invariant
///
/// `[base, base + SIZE)` lies within the 16-bit port space.
pub struct UnclaimedPorts<const SIZE: usize> {
    raw: IoRaw<SIZE>,
}

impl<const SIZE: usize> UnclaimedPorts<SIZE> {
    /// Creates accessors for `[base, base + SIZE)` without claiming the region.
    ///
    /// Returns [`EINVAL`](crate::error::code::EINVAL) if the range does not fit
    /// the 16-bit port space.
    pub fn request_none(base: u16) -> Result<Self> {
        // Establish `[base, base + SIZE)` within the 16-bit port space.
        let last = (base as usize).checked_add(SIZE).ok_or(EINVAL)?;
        if last > u16::MAX as usize + 1 {
            return Err(EINVAL);
        }
        Ok(Self {
            raw: IoRaw::new(base as usize, SIZE)?,
        })
    }
}

impl<const SIZE: usize> Deref for UnclaimedPorts<SIZE> {
    type Target = IoPort<SIZE>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: by the type invariant `self.raw` lies within the 16-bit port
        // space; region ownership is intentionally forgone (see the type docs),
        // and port I/O on a 16-bit-bounded range carries no memory-safety risk.
        unsafe { IoPort::from_raw(&self.raw) }
    }
}
