// SPDX-License-Identifier: GPL-2.0

//! Clock abstractions.
//!
//! C header: [`include/linux/clk.h`](srctree/include/linux/clk.h)
//!
//! Reference: <https://docs.kernel.org/driver-api/clk.html>

use crate::ffi::c_ulong;

/// The frequency unit.
///
/// Represents a frequency in hertz, wrapping a [`c_ulong`] value.
///
/// # Examples
///
/// ```
/// use kernel::clk::Hertz;
///
/// let hz = 1_000_000_000;
/// let rate = Hertz(hz);
///
/// assert_eq!(rate.as_hz(), hz);
/// assert_eq!(rate, Hertz(hz));
/// assert_eq!(rate, Hertz::from_khz(hz / 1_000));
/// assert_eq!(rate, Hertz::from_mhz(hz / 1_000_000));
/// assert_eq!(rate, Hertz::from_ghz(hz / 1_000_000_000));
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Hertz(pub c_ulong);

impl Hertz {
    const KHZ_TO_HZ: c_ulong = 1_000;
    const MHZ_TO_HZ: c_ulong = 1_000_000;
    const GHZ_TO_HZ: c_ulong = 1_000_000_000;

    /// Create a new instance from kilohertz (kHz)
    pub const fn from_khz(khz: c_ulong) -> Self {
        Self(khz * Self::KHZ_TO_HZ)
    }

    /// Create a new instance from megahertz (MHz)
    pub const fn from_mhz(mhz: c_ulong) -> Self {
        Self(mhz * Self::MHZ_TO_HZ)
    }

    /// Create a new instance from gigahertz (GHz)
    pub const fn from_ghz(ghz: c_ulong) -> Self {
        Self(ghz * Self::GHZ_TO_HZ)
    }

    /// Get the frequency in hertz
    pub const fn as_hz(&self) -> c_ulong {
        self.0
    }

    /// Get the frequency in kilohertz
    pub const fn as_khz(&self) -> c_ulong {
        self.0 / Self::KHZ_TO_HZ
    }

    /// Get the frequency in megahertz
    pub const fn as_mhz(&self) -> c_ulong {
        self.0 / Self::MHZ_TO_HZ
    }

    /// Get the frequency in gigahertz
    pub const fn as_ghz(&self) -> c_ulong {
        self.0 / Self::GHZ_TO_HZ
    }
}

impl From<Hertz> for c_ulong {
    fn from(freq: Hertz) -> Self {
        freq.0
    }
}

impl From<u32> for Hertz {
    fn from(freq: u32) -> Self {
        Self(freq as c_ulong)
    }
}

#[cfg(CONFIG_COMMON_CLK)]
mod common_clk {
    use super::Hertz;
    use crate::{
        device::{self, Device},
        error::{from_err_ptr, to_result, Result},
        ffi::c_ulong,
        io,
        of,
        prelude::*,
    };

    use core::{ffi::c_void, marker::PhantomData, ops::Deref, ptr};

    /// A reference-counted clock.
    ///
    /// Rust abstraction for the C [`struct clk`].
    ///
    /// # Invariants
    ///
    /// A [`Clk`] instance holds either a pointer to a valid [`struct clk`] created by the C
    /// portion of the kernel or a NULL pointer.
    ///
    /// Instances of this type are reference-counted. Calling [`Clk::get`] ensures that the
    /// allocation remains valid for the lifetime of the [`Clk`].
    ///
    /// # Examples
    ///
    /// The following example demonstrates how to obtain and configure a clock for a device.
    ///
    /// ```
    /// use kernel::c_str;
    /// use kernel::clk::{Clk, Hertz};
    /// use kernel::device::Device;
    /// use kernel::error::Result;
    ///
    /// fn configure_clk(dev: &Device) -> Result {
    ///     let clk = Clk::get(dev, Some(c_str!("apb_clk")))?;
    ///
    ///     clk.prepare_enable()?;
    ///
    ///     let expected_rate = Hertz::from_ghz(1);
    ///
    ///     if clk.rate() != expected_rate {
    ///         clk.set_rate(expected_rate)?;
    ///     }
    ///
    ///     clk.disable_unprepare();
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`struct clk`]: https://docs.kernel.org/driver-api/clk.html
    #[repr(transparent)]
    pub struct Clk(*mut bindings::clk);

    impl Clk {
        /// Gets [`Clk`] corresponding to a [`Device`] and a connection id.
        ///
        /// Equivalent to the kernel's [`clk_get`] API.
        ///
        /// [`clk_get`]: https://docs.kernel.org/core-api/kernel-api.html#c.clk_get
        pub fn get(dev: &Device, name: Option<&CStr>) -> Result<Self> {
            let con_id = name.map_or(ptr::null(), |n| n.as_char_ptr());

            // SAFETY: It is safe to call [`clk_get`] for a valid device pointer.
            //
            // INVARIANT: The reference-count is decremented when [`Clk`] goes out of scope.
            Ok(Self(from_err_ptr(unsafe {
                bindings::clk_get(dev.as_raw(), con_id)
            })?))
        }

        /// Obtain the raw [`struct clk`] pointer.
        #[inline]
        pub fn as_raw(&self) -> *mut bindings::clk {
            self.0
        }

        /// Enable the clock.
        ///
        /// Equivalent to the kernel's [`clk_enable`] API.
        ///
        /// [`clk_enable`]: https://docs.kernel.org/core-api/kernel-api.html#c.clk_enable
        #[inline]
        pub fn enable(&self) -> Result {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_enable`].
            to_result(unsafe { bindings::clk_enable(self.as_raw()) })
        }

        /// Disable the clock.
        ///
        /// Equivalent to the kernel's [`clk_disable`] API.
        ///
        /// [`clk_disable`]: https://docs.kernel.org/core-api/kernel-api.html#c.clk_disable
        #[inline]
        pub fn disable(&self) {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_disable`].
            unsafe { bindings::clk_disable(self.as_raw()) };
        }

        /// Prepare the clock.
        ///
        /// Equivalent to the kernel's [`clk_prepare`] API.
        ///
        /// [`clk_prepare`]: https://docs.kernel.org/core-api/kernel-api.html#c.clk_prepare
        #[inline]
        pub fn prepare(&self) -> Result {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_prepare`].
            to_result(unsafe { bindings::clk_prepare(self.as_raw()) })
        }

        /// Unprepare the clock.
        ///
        /// Equivalent to the kernel's [`clk_unprepare`] API.
        ///
        /// [`clk_unprepare`]: https://docs.kernel.org/core-api/kernel-api.html#c.clk_unprepare
        #[inline]
        pub fn unprepare(&self) {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_unprepare`].
            unsafe { bindings::clk_unprepare(self.as_raw()) };
        }

        /// Prepare and enable the clock.
        ///
        /// Equivalent to calling [`Clk::prepare`] followed by [`Clk::enable`].
        #[inline]
        pub fn prepare_enable(&self) -> Result {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_prepare_enable`].
            to_result(unsafe { bindings::clk_prepare_enable(self.as_raw()) })
        }

        /// Disable and unprepare the clock.
        ///
        /// Equivalent to calling [`Clk::disable`] followed by [`Clk::unprepare`].
        #[inline]
        pub fn disable_unprepare(&self) {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_disable_unprepare`].
            unsafe { bindings::clk_disable_unprepare(self.as_raw()) };
        }

        /// Get clock's rate.
        ///
        /// Equivalent to the kernel's [`clk_get_rate`] API.
        ///
        /// [`clk_get_rate`]: https://docs.kernel.org/core-api/kernel-api.html#c.clk_get_rate
        #[inline]
        pub fn rate(&self) -> Hertz {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_get_rate`].
            Hertz(unsafe { bindings::clk_get_rate(self.as_raw()) })
        }

        /// Set clock's rate.
        ///
        /// Equivalent to the kernel's [`clk_set_rate`] API.
        ///
        /// [`clk_set_rate`]: https://docs.kernel.org/core-api/kernel-api.html#c.clk_set_rate
        #[inline]
        pub fn set_rate(&self, rate: Hertz) -> Result {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for
            // [`clk_set_rate`].
            to_result(unsafe { bindings::clk_set_rate(self.as_raw(), rate.as_hz()) })
        }
    }

    impl Drop for Clk {
        fn drop(&mut self) {
            // SAFETY: By the type invariants, self.as_raw() is a valid argument for [`clk_put`].
            unsafe { bindings::clk_put(self.as_raw()) };
        }
    }

    /// A reference-counted optional clock.
    ///
    /// A lightweight wrapper around an optional [`Clk`]. An [`OptionalClk`] represents a [`Clk`]
    /// that a driver can function without but may improve performance or enable additional
    /// features when available.
    ///
    /// # Invariants
    ///
    /// An [`OptionalClk`] instance encapsulates a [`Clk`] with either a valid [`struct clk`] or
    /// `NULL` pointer.
    ///
    /// Instances of this type are reference-counted. Calling [`OptionalClk::get`] ensures that the
    /// allocation remains valid for the lifetime of the [`OptionalClk`].
    ///
    /// # Examples
    ///
    /// The following example demonstrates how to obtain and configure an optional clock for a
    /// device. The code functions correctly whether or not the clock is available.
    ///
    /// ```
    /// use kernel::c_str;
    /// use kernel::clk::{OptionalClk, Hertz};
    /// use kernel::device::Device;
    /// use kernel::error::Result;
    ///
    /// fn configure_clk(dev: &Device) -> Result {
    ///     let clk = OptionalClk::get(dev, Some(c_str!("apb_clk")))?;
    ///
    ///     clk.prepare_enable()?;
    ///
    ///     let expected_rate = Hertz::from_ghz(1);
    ///
    ///     if clk.rate() != expected_rate {
    ///         clk.set_rate(expected_rate)?;
    ///     }
    ///
    ///     clk.disable_unprepare();
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`struct clk`]: https://docs.kernel.org/driver-api/clk.html
    pub struct OptionalClk(Clk);

    impl OptionalClk {
        /// Gets [`OptionalClk`] corresponding to a [`Device`] and a connection id.
        ///
        /// Equivalent to the kernel's [`clk_get_optional`] API.
        ///
        /// [`clk_get_optional`]:
        /// https://docs.kernel.org/core-api/kernel-api.html#c.clk_get_optional
        pub fn get(dev: &Device, name: Option<&CStr>) -> Result<Self> {
            let con_id = name.map_or(ptr::null(), |n| n.as_char_ptr());

            // SAFETY: It is safe to call [`clk_get_optional`] for a valid device pointer.
            //
            // INVARIANT: The reference-count is decremented when [`OptionalClk`] goes out of
            // scope.
            Ok(Self(Clk(from_err_ptr(unsafe {
                bindings::clk_get_optional(dev.as_raw(), con_id)
            })?)))
        }
    }

    // Make [`OptionalClk`] behave like [`Clk`].
    impl Deref for OptionalClk {
        type Target = Clk;

        fn deref(&self) -> &Clk {
            &self.0
        }
    }

    /// Use the parent clock accuracy for a fixed-rate clock.
    pub const CLK_FIXED_RATE_PARENT_ACCURACY: u32 = 1 << 0;

    /// A basic gate bit set disables the clock.
    pub const CLK_GATE_SET_TO_DISABLE: u8 = 1 << 0;

    /// Gate writes use the high word as a write mask.
    pub const CLK_GATE_HIWORD_MASK: u8 = 1 << 1;

    /// Gate registers are big-endian.
    pub const CLK_GATE_BIG_ENDIAN: u8 = 1 << 2;

    /// Clock rate changes should propagate to the parent.
    pub const CLK_SET_RATE_PARENT: c_ulong = 1 << 2;

    /// Divider value is one-based.
    pub const CLK_DIVIDER_ONE_BASED: c_ulong = 1 << 0;

    /// Divider value encodes a power-of-two divisor.
    pub const CLK_DIVIDER_POWER_OF_TWO: c_ulong = 1 << 1;

    /// Allow zero divider values.
    pub const CLK_DIVIDER_ALLOW_ZERO: c_ulong = 1 << 2;

    /// Divider writes use the high word as a write mask.
    pub const CLK_DIVIDER_HIWORD_MASK: c_ulong = 1 << 3;

    /// Round divider rates to the closest supported value.
    pub const CLK_DIVIDER_ROUND_CLOSEST: c_ulong = 1 << 4;

    /// Divider is read-only.
    pub const CLK_DIVIDER_READ_ONLY: c_ulong = 1 << 5;

    /// Zero represents the maximum divider value.
    pub const CLK_DIVIDER_MAX_AT_ZERO: c_ulong = 1 << 6;

    /// Divider registers are big-endian.
    pub const CLK_DIVIDER_BIG_ENDIAN: c_ulong = 1 << 7;

    /// Divider values encode even integer divisors.
    pub const CLK_DIVIDER_EVEN_INTEGERS: c_ulong = 1 << 8;

    /// Provider-side clock hardware callbacks.
    ///
    /// This trait is intentionally small for the first COMMON_CLK provider
    /// ratchet. Focused registration helpers such as
    /// [`HwRegistration::register_fixed_rate_with_accuracy`] can cover simple
    /// providers while later waves add generic callback trampolines.
    pub trait HwOps {
        /// Recalculate the clock rate from the parent rate.
        fn recalc_rate(&self, parent_rate: u64) -> u64;

        /// Recalculate the clock accuracy from the parent accuracy.
        fn recalc_accuracy(&self, parent_accuracy: u32) -> u32 {
            parent_accuracy
        }

        /// Enable a gateable clock.
        fn enable(&self) -> Result {
            Err(ENOTSUPP)
        }

        /// Disable a gateable clock.
        fn disable(&self) {}

        /// Return whether a gateable clock is enabled.
        fn is_enabled(&self) -> bool {
            true
        }
    }

    /// A clock rate-change request.
    pub struct RateRequest {
        raw: bindings::clk_rate_request,
    }

    impl RateRequest {
        /// Create a rate request initialized with `rate`.
        pub fn new(rate: Hertz) -> Self {
            let mut raw = bindings::clk_rate_request::default();
            raw.rate = rate.as_hz();
            Self { raw }
        }

        /// Return the requested rate.
        pub fn rate(&self) -> Hertz {
            Hertz(self.raw.rate)
        }

        /// Set the requested rate.
        pub fn set_rate(&mut self, rate: Hertz) {
            self.raw.rate = rate.as_hz();
        }

        /// Return the best parent rate selected for this request.
        pub fn best_parent_rate(&self) -> Hertz {
            Hertz(self.raw.best_parent_rate)
        }

        /// Set the best parent rate selected for this request.
        pub fn set_best_parent_rate(&mut self, rate: Hertz) {
            self.raw.best_parent_rate = rate.as_hz();
        }
    }

    /// A registered provider-side `struct clk_hw`.
    ///
    /// The current implementation owns fixed-rate clocks registered through
    /// [`HwRegistration::register_fixed_rate_with_accuracy`]. Dropping the
    /// registration unregisters that fixed-rate clock exactly once.
    pub struct HwRegistration<T = ()> {
        hw: *mut bindings::clk_hw,
        _type: PhantomData<T>,
    }

    impl<T> HwRegistration<T> {
        /// Register a fixed-rate clock with optional parent-name and accuracy.
        pub fn register_fixed_rate_with_accuracy<Ctx: device::DeviceContext>(
            dev: Option<&Device<Ctx>>,
            name: &CStr,
            parent_name: Option<&CStr>,
            flags: c_ulong,
            fixed_rate: Hertz,
            fixed_accuracy: u32,
        ) -> Result<Self> {
            let dev = dev.map_or(ptr::null_mut(), |dev| dev.as_raw());
            let parent_name = parent_name.map_or(ptr::null(), |name| name.as_char_ptr());

            // SAFETY:
            // - `dev` is either NULL or a valid device pointer borrowed from `Device`.
            // - `name` and `parent_name` are NULL-terminated C strings when present.
            // - The returned `clk_hw` is owned by the registration and unregistered in `Drop`.
            let hw = from_err_ptr(unsafe {
                bindings::clk_hw_register_fixed_rate_with_accuracy(
                    dev,
                    name.as_char_ptr(),
                    parent_name,
                    flags,
                    fixed_rate.as_hz(),
                    fixed_accuracy as c_ulong,
                )
            })?;

            Ok(Self {
                hw,
                _type: PhantomData,
            })
        }

        /// Obtain the raw `struct clk_hw *`.
        pub(crate) fn as_raw(&self) -> *mut bindings::clk_hw {
            self.hw
        }
    }

    impl<T> Drop for HwRegistration<T> {
        fn drop(&mut self) {
            if self.hw.is_null() {
                return;
            }

            // SAFETY: `self.hw` was returned by the fixed-rate registration helper and is still
            // owned by `self`.
            unsafe { bindings::clk_hw_unregister_fixed_rate(self.hw) };
        }
    }

    // SAFETY: `HwRegistration` only owns a CCF registration pointer; unregistering it does not
    // depend on the thread that drops the Rust owner.
    unsafe impl<T> Send for HwRegistration<T> {}

    // SAFETY: Shared references only expose the stable raw pointer to other safe wrappers.
    unsafe impl<T> Sync for HwRegistration<T> {}

    /// An Open Firmware provider for one `struct clk_hw`.
    pub struct HwProvider {
        node: *mut bindings::device_node,
    }

    impl HwProvider {
        /// Register `hw` as a simple OF clock provider for `node`.
        pub fn add_simple<T>(node: &of::DeviceNode, hw: &HwRegistration<T>) -> Result<Self> {
            // SAFETY: `node` and `hw` are valid borrowed provider objects. The returned provider
            // must be dropped before the device node goes away.
            to_result(unsafe {
                bindings::of_clk_add_hw_provider_simple(node.as_raw(), hw.as_raw())
            })?;
            Ok(Self {
                node: node.as_raw(),
            })
        }
    }

    impl Drop for HwProvider {
        fn drop(&mut self) {
            // SAFETY: `self.node` is the same node used by `add_simple`.
            unsafe { bindings::of_clk_del_provider(self.node) };
        }
    }

    // SAFETY: The provider is a registration handle keyed by an OF node; removal is safe from Drop.
    unsafe impl Send for HwProvider {}

    // SAFETY: Shared references do not mutate provider state.
    unsafe impl Sync for HwProvider {}

    /// A device-managed gate `struct clk_hw` registration.
    ///
    /// The registration is released by device-managed cleanup, mirroring
    /// `devm_clk_hw_register_gate`.
    pub struct GateRegistration {
        _hw: *mut bindings::clk_hw,
    }

    impl GateRegistration {
        /// Register a device-managed gate clock backed by an MMIO register.
        pub fn devm_register<Ctx: device::DeviceContext, const SIZE: usize>(
            dev: &Device<Ctx>,
            name: &CStr,
            parent_name: Option<&CStr>,
            flags: c_ulong,
            io: &io::Io<SIZE>,
            offset: usize,
            bit_idx: u8,
            gate_flags: u8,
        ) -> Result<Self> {
            let access_size = core::mem::size_of::<u32>();
            let end = offset.checked_add(access_size).ok_or(EINVAL)?;
            if end > io.maxsize() || offset % access_size != 0 {
                return Err(EINVAL);
            }

            let reg = io.addr().checked_add(offset).ok_or(EINVAL)? as *mut c_void;
            let parent_name = parent_name.map_or(ptr::null(), |name| name.as_char_ptr());

            // SAFETY:
            // - `dev` is a valid device pointer.
            // - `name` and `parent_name` are NULL-terminated C strings when present.
            // - `reg` points within the supplied MMIO mapping and is aligned for a u32 gate
            //   register access.
            // - The returned `clk_hw` is device-managed by the CCF/devres helper.
            let hw = from_err_ptr(unsafe {
                bindings::devm_clk_hw_register_gate(
                    dev.as_raw(),
                    name.as_char_ptr(),
                    parent_name,
                    flags,
                    reg,
                    bit_idx,
                    gate_flags,
                )
            })?;

            Ok(Self { _hw: hw })
        }
    }

    // SAFETY: The registration handle refers to a devres-owned CCF object tied to its device.
    unsafe impl Send for GateRegistration {}

    // SAFETY: Shared references only expose the stable raw pointer to other safe wrappers.
    unsafe impl Sync for GateRegistration {}

    /// Divider clock helpers.
    pub mod divider {
        use super::*;

        pub use super::{
            CLK_DIVIDER_ALLOW_ZERO, CLK_DIVIDER_BIG_ENDIAN, CLK_DIVIDER_EVEN_INTEGERS,
            CLK_DIVIDER_HIWORD_MASK, CLK_DIVIDER_MAX_AT_ZERO, CLK_DIVIDER_ONE_BASED,
            CLK_DIVIDER_POWER_OF_TWO, CLK_DIVIDER_READ_ONLY, CLK_DIVIDER_ROUND_CLOSEST,
        };

        /// One entry in a divider lookup table.
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Entry {
            /// Encoded register value.
            pub val: u32,
            /// Divider represented by `val`; a zero divider terminates a table.
            pub div: u32,
        }

        /// A static, zero-terminated divider table.
        pub struct Table {
            entries: &'static [Entry],
        }

        impl Table {
            /// Create a divider table from a static zero-terminated entry slice.
            pub fn new(entries: &'static [Entry]) -> Result<Self> {
                let Some(last) = entries.last() else {
                    return Err(EINVAL);
                };
                if last.div != 0 {
                    return Err(EINVAL);
                }

                Ok(Self { entries })
            }

            /// Return the raw entries, including the terminating zero-divider entry.
            pub fn entries(&self) -> &'static [Entry] {
                self.entries
            }

            /// Iterate over the raw entries, including the terminating zero-divider entry.
            pub fn iter(&self) -> core::slice::Iter<'static, Entry> {
                self.entries.iter()
            }

            pub(super) fn as_raw(&self) -> *const bindings::clk_div_table {
                build_assert!(
                    core::mem::size_of::<Entry>()
                        == core::mem::size_of::<bindings::clk_div_table>()
                );
                build_assert!(
                    core::mem::align_of::<Entry>()
                        == core::mem::align_of::<bindings::clk_div_table>()
                );
                self.entries.as_ptr().cast()
            }
        }

        /// Return the bit mask for a divider field of `width` bits.
        #[inline]
        pub fn div_mask(width: u8) -> u32 {
            if width >= u32::BITS as u8 {
                u32::MAX
            } else {
                (1u32 << width) - 1
            }
        }
    }

    /// A device-managed divider `struct clk_hw` registration.
    ///
    /// The registration is released by device-managed cleanup, mirroring
    /// `__devm_clk_hw_register_divider`.
    pub struct DividerRegistration {
        _hw: *mut bindings::clk_hw,
    }

    impl DividerRegistration {
        /// Register a device-managed divider clock backed by an MMIO register.
        pub fn devm_register<Ctx: device::DeviceContext, const SIZE: usize>(
            dev: &Device<Ctx>,
            name: &CStr,
            parent_name: Option<&CStr>,
            flags: c_ulong,
            io: &io::Io<SIZE>,
            offset: usize,
            shift: u8,
            width: u8,
            divider_flags: c_ulong,
            table: Option<&divider::Table>,
        ) -> Result<Self> {
            let access_size = core::mem::size_of::<u32>();
            let end = offset.checked_add(access_size).ok_or(EINVAL)?;
            if end > io.maxsize() || offset % access_size != 0 {
                return Err(EINVAL);
            }

            let reg = io.addr().checked_add(offset).ok_or(EINVAL)? as *mut c_void;
            let parent_name = parent_name.map_or(ptr::null(), |name| name.as_char_ptr());
            let table = table.map_or(ptr::null(), |table| table.as_raw());

            // SAFETY:
            // - `dev` is a valid device pointer.
            // - `name` and `parent_name` are NULL-terminated C strings when present.
            // - `reg` points within the supplied MMIO mapping and is aligned for a u32 divider
            //   register access.
            // - `table` is either NULL or a static zero-terminated divider table.
            // - The returned `clk_hw` is device-managed by the CCF/devres helper.
            let hw = from_err_ptr(unsafe {
                bindings::__devm_clk_hw_register_divider(
                    dev.as_raw(),
                    ptr::null_mut(),
                    name.as_char_ptr(),
                    parent_name,
                    ptr::null(),
                    ptr::null(),
                    flags,
                    reg,
                    shift,
                    width,
                    divider_flags,
                    table,
                    ptr::null_mut(),
                )
            })?;

            Ok(Self { _hw: hw })
        }
    }

    // SAFETY: The registration handle refers to a devres-owned CCF object tied to its device.
    unsafe impl Send for DividerRegistration {}

    // SAFETY: Shared references only expose the stable raw pointer to other safe wrappers.
    unsafe impl Sync for DividerRegistration {}
}

#[cfg(CONFIG_COMMON_CLK)]
pub use common_clk::*;
