// SPDX-License-Identifier: GPL-2.0

//! Regulator abstractions, providing a standard kernel interface to control
//! voltage and current regulators.
//!
//! The intention is to allow systems to dynamically control regulator power
//! output in order to save power and prolong battery life. This applies to both
//! voltage regulators (where voltage output is controllable) and current sinks
//! (where current limit is controllable).
//!
//! C header: [`include/linux/regulator/consumer.h`](srctree/include/linux/regulator/consumer.h)
//!
//! Regulators are modeled in Rust with a collection of states. Each state may
//! enforce a given invariant, and they may convert between each other where applicable.
//!
//! See [Voltage and current regulator API](https://docs.kernel.org/driver-api/regulator.html)
//! for more information.

use crate::{
    bindings,
    device::{self, Bound, Device},
    error::{from_err_ptr, to_result, Result},
    ffi::{c_uint, c_ulong, c_void},
    of, regmap,
    prelude::*,
};

use core::{marker::PhantomData, mem::ManuallyDrop, ptr, ptr::NonNull};

mod private {
    pub trait Sealed {}

    impl Sealed for super::Enabled {}
    impl Sealed for super::Disabled {}
}

/// A trait representing the different states a [`Regulator`] can be in.
pub trait RegulatorState: private::Sealed + 'static {
    /// Whether the regulator should be disabled when dropped.
    const DISABLE_ON_DROP: bool;
}

/// A state where the [`Regulator`] is known to be enabled.
///
/// The `enable` reference count held by this state is decremented when it is
/// dropped.
pub struct Enabled;

/// A state where this [`Regulator`] handle has not specifically asked for the
/// underlying regulator to be enabled. This means that this reference does not
/// own an `enable` reference count, but the regulator may still be on.
pub struct Disabled;

impl RegulatorState for Enabled {
    const DISABLE_ON_DROP: bool = true;
}

impl RegulatorState for Disabled {
    const DISABLE_ON_DROP: bool = false;
}

/// A trait that abstracts the ability to check if a [`Regulator`] is enabled.
pub trait IsEnabled: RegulatorState {}
impl IsEnabled for Disabled {}

/// An error that can occur when trying to convert a [`Regulator`] between states.
pub struct Error<State: RegulatorState> {
    /// The error that occurred.
    pub error: kernel::error::Error,

    /// The regulator that caused the error, so that the operation may be retried.
    pub regulator: Regulator<State>,
}
/// Obtains and enables a [`devres`]-managed regulator for a device.
///
/// This calls [`regulator_disable()`] and [`regulator_put()`] automatically on
/// driver detach.
///
/// This API is identical to `devm_regulator_get_enable()`, and should be
/// preferred over the [`Regulator<T: RegulatorState>`] API if the caller only
/// cares about the regulator being enabled.
///
/// [`devres`]: https://docs.kernel.org/driver-api/driver-model/devres.html
/// [`regulator_disable()`]: https://docs.kernel.org/driver-api/regulator.html#c.regulator_disable
/// [`regulator_put()`]: https://docs.kernel.org/driver-api/regulator.html#c.regulator_put
pub fn devm_enable(dev: &Device<Bound>, name: &CStr) -> Result {
    // SAFETY: `dev` is a valid and bound device, while `name` is a valid C
    // string.
    to_result(unsafe { bindings::devm_regulator_get_enable(dev.as_raw(), name.as_char_ptr()) })
}

/// Same as [`devm_enable`], but calls `devm_regulator_get_enable_optional`
/// instead.
///
/// This obtains and enables a [`devres`]-managed regulator for a device, but
/// does not print a message nor provides a dummy if the regulator is not found.
///
/// This calls [`regulator_disable()`] and [`regulator_put()`] automatically on
/// driver detach.
///
/// [`devres`]: https://docs.kernel.org/driver-api/driver-model/devres.html
/// [`regulator_disable()`]: https://docs.kernel.org/driver-api/regulator.html#c.regulator_disable
/// [`regulator_put()`]: https://docs.kernel.org/driver-api/regulator.html#c.regulator_put
pub fn devm_enable_optional(dev: &Device<Bound>, name: &CStr) -> Result {
    // SAFETY: `dev` is a valid and bound device, while `name` is a valid C
    // string.
    to_result(unsafe {
        bindings::devm_regulator_get_enable_optional(dev.as_raw(), name.as_char_ptr())
    })
}

/// Provider-side regulator operation table.
///
/// This is a small safe wrapper over `struct regulator_ops` for common provider
/// patterns. Driver-specific callback trampolines can be added incrementally as
/// later regulator ratchets require them.
pub struct Ops {
    raw: bindings::regulator_ops,
}

impl Ops {
    /// Regmap-backed voltage regulator ops with linear voltage selectors and
    /// optional current-limit table support.
    pub const fn regmap_linear_voltage_current() -> Self {
        Self {
            raw: bindings::regulator_ops {
                list_voltage: Some(bindings::regulator_ops_list_voltage_linear),
                set_voltage: None,
                map_voltage: None,
                set_voltage_sel: Some(bindings::regulator_ops_set_voltage_sel_regmap),
                get_voltage: None,
                get_voltage_sel: Some(bindings::regulator_ops_get_voltage_sel_regmap),
                set_current_limit: Some(bindings::regulator_ops_set_current_limit_regmap),
                get_current_limit: Some(bindings::regulator_ops_get_current_limit_regmap),
                set_input_current_limit: None,
                set_over_current_protection: None,
                set_over_voltage_protection: None,
                set_under_voltage_protection: None,
                set_thermal_protection: None,
                set_active_discharge: None,
                enable: Some(bindings::regulator_ops_enable_regmap),
                disable: Some(bindings::regulator_ops_disable_regmap),
                is_enabled: Some(bindings::regulator_ops_is_enabled_regmap),
                set_mode: None,
                get_mode: None,
                get_error_flags: None,
                enable_time: None,
                set_ramp_delay: None,
                set_voltage_time: None,
                set_voltage_time_sel: None,
                set_soft_start: None,
                get_status: None,
                get_optimum_mode: None,
                set_load: None,
                set_bypass: None,
                get_bypass: None,
                set_suspend_voltage: None,
                set_suspend_enable: None,
                set_suspend_disable: None,
                set_suspend_mode: None,
                resume: None,
                set_pull_down: None,
            },
        }
    }

    const fn as_raw(&self) -> *const bindings::regulator_ops {
        &self.raw
    }
}

// SAFETY: `Ops` is immutable after construction and contains only C function pointers.
unsafe impl Sync for Ops {}

/// Parameters for a linear, regmap-backed voltage regulator descriptor.
pub struct LinearRegmapDesc {
    /// Regulator name.
    pub name: &'static CStr,
    /// Regulator id.
    pub id: i32,
    /// Operation table.
    pub ops: &'static Ops,
    /// Number of voltage selectors.
    pub n_voltages: c_uint,
    /// Minimum voltage in microvolts.
    pub min_uv: c_uint,
    /// Voltage step in microvolts.
    pub uv_step: c_uint,
    /// Voltage selector register.
    pub vsel_reg: c_uint,
    /// Voltage selector mask.
    pub vsel_mask: c_uint,
    /// Enable register.
    pub enable_reg: c_uint,
    /// Enable mask.
    pub enable_mask: c_uint,
    /// Optional current-limit selector table.
    pub current_limits: Option<&'static [c_uint]>,
    /// Current selector register.
    pub csel_reg: c_uint,
    /// Current selector mask.
    pub csel_mask: c_uint,
}

/// Static provider-side regulator descriptor.
pub struct Descriptor {
    raw: bindings::regulator_desc,
}

impl Descriptor {
    /// Create a descriptor for a linear voltage regulator controlled through regmap.
    pub const fn regmap_linear_voltage_current(desc: LinearRegmapDesc) -> Self {
        let (curr_table, n_current_limits) = match desc.current_limits {
            Some(table) => (table.as_ptr(), table.len() as c_uint),
            None => (ptr::null(), 0),
        };

        Self {
            raw: bindings::regulator_desc {
                name: crate::str::as_char_ptr_in_const_context(desc.name),
                supply_name: ptr::null(),
                of_match: ptr::null(),
                of_match_full_name: false,
                regulators_node: ptr::null(),
                of_parse_cb: None,
                init_cb: None,
                id: desc.id,
                _bitfield_align_1: [],
                _bitfield_1: bindings::__BindgenBitfieldUnit::new([0u8; 1]),
                n_voltages: desc.n_voltages,
                n_current_limits,
                ops: desc.ops.as_raw(),
                irq: 0,
                type_: bindings::regulator_type_REGULATOR_VOLTAGE,
                owner: ptr::null_mut(),
                min_uV: desc.min_uv,
                uV_step: desc.uv_step,
                linear_min_sel: 0,
                fixed_uV: 0,
                ramp_delay: 0,
                min_dropout_uV: 0,
                linear_ranges: ptr::null(),
                linear_range_selectors_bitfield: ptr::null(),
                n_linear_ranges: 0,
                volt_table: ptr::null(),
                curr_table,
                vsel_range_reg: 0,
                vsel_range_mask: 0,
                range_applied_by_vsel: false,
                vsel_reg: desc.vsel_reg,
                vsel_mask: desc.vsel_mask,
                vsel_step: 0,
                csel_reg: desc.csel_reg,
                csel_mask: desc.csel_mask,
                apply_reg: 0,
                apply_bit: 0,
                enable_reg: desc.enable_reg,
                enable_mask: desc.enable_mask,
                enable_val: 0,
                disable_val: 0,
                enable_is_inverted: false,
                bypass_reg: 0,
                bypass_mask: 0,
                bypass_val_on: 0,
                bypass_val_off: 0,
                active_discharge_on: 0,
                active_discharge_off: 0,
                active_discharge_mask: 0,
                active_discharge_reg: 0,
                soft_start_reg: 0,
                soft_start_mask: 0,
                soft_start_val_on: 0,
                pull_down_reg: 0,
                pull_down_mask: 0,
                pull_down_val_on: 0,
                ramp_reg: 0,
                ramp_mask: 0,
                ramp_delay_table: ptr::null(),
                n_ramp_values: 0,
                enable_time: 0,
                off_on_delay: 0,
                poll_enabled_time: 0,
                of_map_mode: None,
            },
        }
    }

    fn as_raw(&self) -> *const bindings::regulator_desc {
        &self.raw
    }
}

// SAFETY: `Descriptor` is immutable after construction and only contains static
// pointers supplied by the driver.
unsafe impl Sync for Descriptor {}

/// Regulator initialization data returned by firmware parsing.
pub struct InitData {
    ptr: *mut bindings::regulator_init_data,
}

impl InitData {
    /// Parse regulator init data from an Open Firmware node.
    pub fn from_of<Ctx: device::DeviceContext>(
        dev: &Device<Ctx>,
        node: Option<&of::DeviceNode>,
        desc: &Descriptor,
    ) -> Option<Self> {
        let node = node.map_or(ptr::null_mut(), |node| node.as_raw());

        // SAFETY: `dev`, optional `node`, and `desc` are valid borrowed kernel objects.
        let ptr = unsafe { bindings::regulator_of_get_init_data(dev.as_raw(), node, desc.as_raw()) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }
}

/// Dynamic provider-side regulator registration config.
pub struct Config<'a> {
    raw: bindings::regulator_config,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Config<'a> {
    /// Create a zeroed config for `dev`.
    pub fn new<Ctx: device::DeviceContext>(dev: &Device<Ctx>) -> Self {
        let mut raw = bindings::regulator_config::default();
        raw.dev = dev.as_raw();
        Self {
            raw,
            _lifetime: PhantomData,
        }
    }

    /// Set firmware/platform initialization data.
    pub fn set_init_data(&mut self, init_data: Option<&InitData>) -> &mut Self {
        self.raw.init_data = init_data.map_or(ptr::null(), |data| data.ptr);
        self
    }

    /// Set driver data stored in `struct regulator_config`.
    pub fn set_driver_data<T>(&mut self, data: &'a T) -> &mut Self {
        self.raw.driver_data = (data as *const T).cast_mut().cast::<c_void>();
        self
    }

    /// Set the regmap backing the common regmap regulator ops.
    pub fn set_regmap(&mut self, map: regmap::RegMap) -> &mut Self {
        self.raw.regmap = map.as_raw();
        self
    }

    /// Set the OF node associated with this regulator.
    pub fn set_of_node(&mut self, node: Option<&of::DeviceNode>) -> &mut Self {
        self.raw.of_node = node.map_or(ptr::null_mut(), |node| node.as_raw());
        self
    }

    fn as_raw(&self) -> *const bindings::regulator_config {
        &self.raw
    }
}

/// Device-managed provider-side regulator registration.
pub struct RegulatorDev<'a> {
    ptr: NonNull<bindings::regulator_dev>,
    _lifetime: PhantomData<&'a Descriptor>,
}

impl<'a> RegulatorDev<'a> {
    /// Register a regulator provider with devres-managed cleanup.
    pub fn devm_register<Ctx: device::DeviceContext>(
        dev: &Device<Ctx>,
        desc: &'a Descriptor,
        config: &Config<'a>,
    ) -> Result<Self> {
        // SAFETY: `dev`, `desc`, and `config` are valid for this registration. The C regulator
        // core/devres owns the returned `regulator_dev`.
        let ptr = from_err_ptr(unsafe {
            bindings::regulator_devm_register(dev.as_raw(), desc.as_raw(), config.as_raw())
        })?;
        let ptr = NonNull::new(ptr).ok_or(ENODEV)?;

        Ok(Self {
            ptr,
            _lifetime: PhantomData,
        })
    }

    /// Notify regulator consumers about an event.
    pub fn notify(&self, event: Event) -> Result {
        // SAFETY: `self.ptr` is a valid `struct regulator_dev *`; no event payload is supplied.
        to_result(unsafe {
            bindings::regulator_notify(self.ptr.as_ptr(), event.0, ptr::null_mut())
        })
    }

}

// SAFETY: `RegulatorDev` is a devres-managed registration handle tied to its device.
unsafe impl Send for RegulatorDev<'_> {}

// SAFETY: Shared references only expose notifier calls and the stable raw pointer.
unsafe impl Sync for RegulatorDev<'_> {}

/// Regulator notifier event.
#[derive(Clone, Copy)]
pub struct Event(c_ulong);

impl Event {
    /// Over-current event.
    pub const OVER_CURRENT: Self = Self(bindings::REGULATOR_EVENT_OVER_CURRENT as c_ulong);
    /// Under-voltage event.
    pub const UNDER_VOLTAGE: Self = Self(bindings::REGULATOR_EVENT_UNDER_VOLTAGE as c_ulong);
    /// Over-temperature event.
    pub const OVER_TEMP: Self = Self(bindings::REGULATOR_EVENT_OVER_TEMP as c_ulong);
    /// Regulation-out event.
    pub const REGULATION_OUT: Self = Self(bindings::REGULATOR_EVENT_REGULATION_OUT as c_ulong);
}

/// A `struct regulator` abstraction.
///
/// # Examples
///
/// ## Enabling a regulator
///
/// This example uses [`Regulator<Enabled>`], which is suitable for drivers that
/// enable a regulator at probe time and leave them on until the device is
/// removed or otherwise shutdown.
///
/// These users can store [`Regulator<Enabled>`] directly in their driver's
/// private data struct.
///
/// ```
/// # use kernel::prelude::*;
/// # use kernel::c_str;
/// # use kernel::device::Device;
/// # use kernel::regulator::{Voltage, Regulator, Disabled, Enabled};
/// fn enable(dev: &Device, min_voltage: Voltage, max_voltage: Voltage) -> Result {
///     // Obtain a reference to a (fictitious) regulator.
///     let regulator: Regulator<Disabled> = Regulator::<Disabled>::get(dev, c_str!("vcc"))?;
///
///     // The voltage can be set before enabling the regulator if needed, e.g.:
///     regulator.set_voltage(min_voltage, max_voltage)?;
///
///     // The same applies for `get_voltage()`, i.e.:
///     let voltage: Voltage = regulator.get_voltage()?;
///
///     // Enables the regulator, consuming the previous value.
///     //
///     // From now on, the regulator is known to be enabled because of the type
///     // `Enabled`.
///     //
///     // If this operation fails, the `Error` will contain the regulator
///     // reference, so that the operation may be retried.
///     let regulator: Regulator<Enabled> =
///         regulator.try_into_enabled().map_err(|error| error.error)?;
///
///     // The voltage can also be set after enabling the regulator, e.g.:
///     regulator.set_voltage(min_voltage, max_voltage)?;
///
///     // The same applies for `get_voltage()`, i.e.:
///     let voltage: Voltage = regulator.get_voltage()?;
///
///     // Dropping an enabled regulator will disable it. The refcount will be
///     // decremented.
///     drop(regulator);
///
///     // ...
///
///     Ok(())
/// }
/// ```
///
/// A more concise shortcut is available for enabling a regulator. This is
/// equivalent to `regulator_get_enable()`:
///
/// ```
/// # use kernel::prelude::*;
/// # use kernel::c_str;
/// # use kernel::device::Device;
/// # use kernel::regulator::{Voltage, Regulator, Enabled};
/// fn enable(dev: &Device) -> Result {
///     // Obtain a reference to a (fictitious) regulator and enable it.
///     let regulator: Regulator<Enabled> = Regulator::<Enabled>::get(dev, c_str!("vcc"))?;
///
///     // Dropping an enabled regulator will disable it. The refcount will be
///     // decremented.
///     drop(regulator);
///
///     // ...
///
///     Ok(())
/// }
/// ```
///
/// If a driver only cares about the regulator being on for as long it is bound
/// to a device, then it should use [`devm_enable`] or [`devm_enable_optional`].
/// This should be the default use-case unless more fine-grained control over
/// the regulator's state is required.
///
/// [`devm_enable`]: crate::regulator::devm_enable
/// [`devm_optional`]: crate::regulator::devm_enable_optional
///
/// ```
/// # use kernel::prelude::*;
/// # use kernel::c_str;
/// # use kernel::device::{Bound, Device};
/// # use kernel::regulator;
/// fn enable(dev: &Device<Bound>) -> Result {
///     // Obtain a reference to a (fictitious) regulator and enable it. This
///     // call only returns whether the operation succeeded.
///     regulator::devm_enable(dev, c_str!("vcc"))?;
///
///     // The regulator will be disabled and put when `dev` is unbound.
///     Ok(())
/// }
/// ```
///
/// ## Disabling a regulator
///
/// ```
/// # use kernel::prelude::*;
/// # use kernel::device::Device;
/// # use kernel::regulator::{Regulator, Enabled, Disabled};
/// fn disable(dev: &Device, regulator: Regulator<Enabled>) -> Result {
///     // We can also disable an enabled regulator without reliquinshing our
///     // refcount:
///     //
///     // If this operation fails, the `Error` will contain the regulator
///     // reference, so that the operation may be retried.
///     let regulator: Regulator<Disabled> =
///         regulator.try_into_disabled().map_err(|error| error.error)?;
///
///     // The refcount will be decremented when `regulator` is dropped.
///     drop(regulator);
///
///     // ...
///
///     Ok(())
/// }
/// ```
///
/// # Invariants
///
/// - `inner` is a non-null wrapper over a pointer to a `struct
///   regulator` obtained from [`regulator_get()`].
///
/// [`regulator_get()`]: https://docs.kernel.org/driver-api/regulator.html#c.regulator_get
pub struct Regulator<State>
where
    State: RegulatorState,
{
    inner: NonNull<bindings::regulator>,
    _phantom: PhantomData<State>,
}

impl<T: RegulatorState> Regulator<T> {
    /// Sets the voltage for the regulator.
    ///
    /// This can be used to ensure that the device powers up cleanly.
    pub fn set_voltage(&self, min_voltage: Voltage, max_voltage: Voltage) -> Result {
        // SAFETY: Safe as per the type invariants of `Regulator`.
        to_result(unsafe {
            bindings::regulator_set_voltage(
                self.inner.as_ptr(),
                min_voltage.as_microvolts(),
                max_voltage.as_microvolts(),
            )
        })
    }

    /// Gets the current voltage of the regulator.
    pub fn get_voltage(&self) -> Result<Voltage> {
        // SAFETY: Safe as per the type invariants of `Regulator`.
        let voltage = unsafe { bindings::regulator_get_voltage(self.inner.as_ptr()) };

        to_result(voltage).map(|()| Voltage::from_microvolts(voltage))
    }

    fn get_internal(dev: &Device, name: &CStr) -> Result<Regulator<T>> {
        let inner =
            // SAFETY: It is safe to call `regulator_get()`, on a device pointer
            // received from the C code.
            from_err_ptr(unsafe { bindings::regulator_get(dev.as_raw(), name.as_char_ptr()) })?;

        // SAFETY: We can safely trust `inner` to be a pointer to a valid
        // regulator if `ERR_PTR` was not returned.
        let inner = unsafe { NonNull::new_unchecked(inner) };

        Ok(Self {
            inner,
            _phantom: PhantomData,
        })
    }

    fn enable_internal(&self) -> Result {
        // SAFETY: Safe as per the type invariants of `Regulator`.
        to_result(unsafe { bindings::regulator_enable(self.inner.as_ptr()) })
    }

    fn disable_internal(&self) -> Result {
        // SAFETY: Safe as per the type invariants of `Regulator`.
        to_result(unsafe { bindings::regulator_disable(self.inner.as_ptr()) })
    }
}

impl Regulator<Disabled> {
    /// Obtains a [`Regulator`] instance from the system.
    pub fn get(dev: &Device, name: &CStr) -> Result<Self> {
        Regulator::get_internal(dev, name)
    }

    /// Attempts to convert the regulator to an enabled state.
    pub fn try_into_enabled(self) -> Result<Regulator<Enabled>, Error<Disabled>> {
        // We will be transferring the ownership of our `regulator_get()` count to
        // `Regulator<Enabled>`.
        let regulator = ManuallyDrop::new(self);

        regulator
            .enable_internal()
            .map(|()| Regulator {
                inner: regulator.inner,
                _phantom: PhantomData,
            })
            .map_err(|error| Error {
                error,
                regulator: ManuallyDrop::into_inner(regulator),
            })
    }
}

impl Regulator<Enabled> {
    /// Obtains a [`Regulator`] instance from the system and enables it.
    ///
    /// This is equivalent to calling `regulator_get_enable()` in the C API.
    pub fn get(dev: &Device, name: &CStr) -> Result<Self> {
        Regulator::<Disabled>::get_internal(dev, name)?
            .try_into_enabled()
            .map_err(|error| error.error)
    }

    /// Attempts to convert the regulator to a disabled state.
    pub fn try_into_disabled(self) -> Result<Regulator<Disabled>, Error<Enabled>> {
        // We will be transferring the ownership of our `regulator_get()` count
        // to `Regulator<Disabled>`.
        let regulator = ManuallyDrop::new(self);

        regulator
            .disable_internal()
            .map(|()| Regulator {
                inner: regulator.inner,
                _phantom: PhantomData,
            })
            .map_err(|error| Error {
                error,
                regulator: ManuallyDrop::into_inner(regulator),
            })
    }
}

impl<T: IsEnabled> Regulator<T> {
    /// Checks if the regulator is enabled.
    pub fn is_enabled(&self) -> bool {
        // SAFETY: Safe as per the type invariants of `Regulator`.
        unsafe { bindings::regulator_is_enabled(self.inner.as_ptr()) != 0 }
    }
}

impl<T: RegulatorState> Drop for Regulator<T> {
    fn drop(&mut self) {
        if T::DISABLE_ON_DROP {
            // SAFETY: By the type invariants, we know that `self` owns a
            // reference on the enabled refcount, so it is safe to relinquish it
            // now.
            unsafe { bindings::regulator_disable(self.inner.as_ptr()) };
        }
        // SAFETY: By the type invariants, we know that `self` owns a reference,
        // so it is safe to relinquish it now.
        unsafe { bindings::regulator_put(self.inner.as_ptr()) };
    }
}

// SAFETY: It is safe to send a `Regulator<T>` across threads. In particular, a
// Regulator<T> can be dropped from any thread.
unsafe impl<T: RegulatorState> Send for Regulator<T> {}

// SAFETY: It is safe to send a &Regulator<T> across threads because the C side
// handles its own locking.
unsafe impl<T: RegulatorState> Sync for Regulator<T> {}

/// A voltage.
///
/// This type represents a voltage value in microvolts.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Voltage(i32);

impl Voltage {
    /// Creates a new `Voltage` from a value in microvolts.
    pub fn from_microvolts(uv: i32) -> Self {
        Self(uv)
    }

    /// Returns the value of the voltage in microvolts as an [`i32`].
    pub fn as_microvolts(self) -> i32 {
        self.0
    }
}
