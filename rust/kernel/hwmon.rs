// SPDX-License-Identifier: GPL-2.0

//! Hardware monitoring subsystem abstractions.
//!
//! C header: [`include/linux/hwmon.h`](srctree/include/linux/hwmon.h)

use crate::{
    bindings,
    device::{self, Bound},
    error::{from_err_ptr, to_result},
    ffi::{c_char, c_int, c_long, c_void},
    prelude::*,
};

use core::{
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    ptr::NonNull,
};

/// File mode returned by hwmon visibility callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mode(bindings::umode_t);

impl Mode {
    /// Attribute is not visible.
    pub const NONE: Self = Self(0);
    /// Read-only attribute, equivalent to `0444`.
    pub const READ: Self = Self(0o444);
    /// Read/write attribute, equivalent to `0644`.
    pub const READ_WRITE: Self = Self(0o644);

    fn as_raw(self) -> bindings::umode_t {
        self.0
    }
}

/// HWMON sensor type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorType {
    /// Chip-global attributes.
    Chip,
    /// Temperature channel.
    Temp,
    /// Humidity channel.
    Humidity,
}

impl SensorType {
    const fn as_raw(self) -> bindings::hwmon_sensor_types {
        match self {
            Self::Chip => bindings::hwmon_sensor_types_hwmon_chip,
            Self::Temp => bindings::hwmon_sensor_types_hwmon_temp,
            Self::Humidity => bindings::hwmon_sensor_types_hwmon_humidity,
        }
    }

    fn from_raw(raw: bindings::hwmon_sensor_types) -> Option<Self> {
        match raw {
            bindings::hwmon_sensor_types_hwmon_chip => Some(Self::Chip),
            bindings::hwmon_sensor_types_hwmon_temp => Some(Self::Temp),
            bindings::hwmon_sensor_types_hwmon_humidity => Some(Self::Humidity),
            _ => None,
        }
    }
}

/// HWMON attribute numbers passed to callbacks.
pub mod attr {
    /// `hwmon_chip_register_tz`.
    pub const CHIP_REGISTER_TZ: u32 = super::bindings::hwmon_chip_attributes_hwmon_chip_register_tz;
    /// `hwmon_chip_update_interval`.
    pub const CHIP_UPDATE_INTERVAL: u32 =
        super::bindings::hwmon_chip_attributes_hwmon_chip_update_interval;
    /// `hwmon_temp_input`.
    pub const TEMP_INPUT: u32 = super::bindings::hwmon_temp_attributes_hwmon_temp_input;
    /// `hwmon_temp_label`.
    pub const TEMP_LABEL: u32 = super::bindings::hwmon_temp_attributes_hwmon_temp_label;
    /// `hwmon_temp_max`.
    pub const TEMP_MAX: u32 = super::bindings::hwmon_temp_attributes_hwmon_temp_max;
    /// `hwmon_temp_max_hyst`.
    pub const TEMP_MAX_HYST: u32 = super::bindings::hwmon_temp_attributes_hwmon_temp_max_hyst;
    /// `hwmon_temp_alarm`.
    pub const TEMP_ALARM: u32 = super::bindings::hwmon_temp_attributes_hwmon_temp_alarm;
    /// `hwmon_humidity_input`.
    pub const HUMIDITY_INPUT: u32 = super::bindings::hwmon_humidity_attributes_hwmon_humidity_input;
}

/// HWMON channel configuration bits.
pub mod config {
    /// `HWMON_C_REGISTER_TZ`.
    pub const CHIP_REGISTER_TZ: u32 = 1 << super::attr::CHIP_REGISTER_TZ;
    /// `HWMON_C_UPDATE_INTERVAL`.
    pub const CHIP_UPDATE_INTERVAL: u32 = 1 << super::attr::CHIP_UPDATE_INTERVAL;
    /// `HWMON_T_INPUT`.
    pub const TEMP_INPUT: u32 = 1 << super::attr::TEMP_INPUT;
    /// `HWMON_T_LABEL`.
    pub const TEMP_LABEL: u32 = 1 << super::attr::TEMP_LABEL;
    /// `HWMON_T_MAX`.
    pub const TEMP_MAX: u32 = 1 << super::attr::TEMP_MAX;
    /// `HWMON_T_MAX_HYST`.
    pub const TEMP_MAX_HYST: u32 = 1 << super::attr::TEMP_MAX_HYST;
    /// `HWMON_T_ALARM`.
    pub const TEMP_ALARM: u32 = 1 << super::attr::TEMP_ALARM;
    /// `HWMON_H_INPUT`.
    pub const HUMIDITY_INPUT: u32 = 1 << super::attr::HUMIDITY_INPUT;
}

/// Notify userspace that a hwmon attribute changed.
pub fn notify_event<Ctx: device::DeviceContext>(
    dev: &device::Device<Ctx>,
    sensor_type: SensorType,
    attr: u32,
    channel: i32,
) -> Result {
    // `hwmon_notify_event` only emits a sysfs/uevent notification for a registered
    // hwmon device, which is valid in any device context (e.g. an `ARef<Device>`
    // held by an IRQ handler), so this is not restricted to `Bound`.
    to_result(unsafe {
        bindings::hwmon_notify_event(dev.as_raw(), sensor_type.as_raw(), attr, channel)
    })
}

/// One hwmon channel descriptor.
#[repr(transparent)]
pub struct ChannelInfo(bindings::hwmon_channel_info);

impl ChannelInfo {
    /// Create a channel descriptor.
    ///
    /// `config` must be a static, zero-terminated list of `HWMON_*` configuration bits.
    pub const fn new(sensor_type: SensorType, config: &'static [u32]) -> Self {
        Self(bindings::hwmon_channel_info {
            type_: sensor_type.as_raw(),
            config: config.as_ptr(),
        })
    }

    const fn as_raw(&'static self) -> *const bindings::hwmon_channel_info {
        &self.0
    }
}

// SAFETY: Channel descriptors are immutable after construction.
unsafe impl Sync for ChannelInfo {}

/// A zero-terminated list of hwmon channel descriptors.
pub struct ChannelList<const N: usize> {
    entries: [*const bindings::hwmon_channel_info; N],
}

impl<const N: usize> ChannelList<N> {
    /// Create a channel list. The last entry must be `None`.
    pub const fn new(entries: [Option<&'static ChannelInfo>; N]) -> Self {
        let mut raw = [core::ptr::null(); N];
        let mut i = 0;

        while i < N {
            raw[i] = match entries[i] {
                Some(channel) => channel.as_raw(),
                None => core::ptr::null(),
            };
            i += 1;
        }

        Self { entries: raw }
    }

    fn as_raw(&self) -> *const *const bindings::hwmon_channel_info {
        self.entries.as_ptr()
    }
}

// SAFETY: Channel lists point only to immutable static channel descriptors.
unsafe impl<const N: usize> Sync for ChannelList<N> {}

/// Trait implemented by hwmon providers.
pub trait HwmonOps: Sync {
    /// Return the file mode for an attribute, or [`Mode::NONE`] to hide it.
    fn is_visible(&self, sensor_type: SensorType, attr: u32, channel: i32) -> Mode;

    /// Read a numeric attribute.
    fn read(&self, sensor_type: SensorType, attr: u32, channel: i32) -> Result<c_long>;

    /// Read a string attribute.
    fn read_string(&self, _sensor_type: SensorType, _attr: u32, _channel: i32) -> Result<&CStr> {
        Err(EOPNOTSUPP)
    }

    /// Write a numeric attribute.
    fn write(&self, _sensor_type: SensorType, _attr: u32, _channel: i32, _value: c_long) -> Result {
        Err(EOPNOTSUPP)
    }
}

struct Adapter<T: HwmonOps> {
    _p: PhantomData<T>,
}

impl<T: HwmonOps> Adapter<T> {
    const VTABLE: HwmonOpsVTable = create_hwmon_ops::<T>();

    unsafe fn drvdata_from_dev<'a>(dev: *mut bindings::device) -> Result<&'a T> {
        if dev.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: `dev` is a valid hwmon device for the callback duration.
        let data = unsafe { bindings::dev_get_drvdata(dev) };
        if data.is_null() {
            return Err(ENOENT);
        }

        // SAFETY: `Registration::new` registers this vtable with `drvdata` pointing to a `T`
        // value that lives for at least as long as the hwmon device.
        Ok(unsafe { &*data.cast::<T>() })
    }

    fn sensor_from_raw(raw: bindings::hwmon_sensor_types) -> Result<SensorType> {
        SensorType::from_raw(raw).ok_or(EOPNOTSUPP)
    }

    unsafe extern "C" fn is_visible_callback(
        data: *const c_void,
        sensor_type: bindings::hwmon_sensor_types,
        attr: u32,
        channel: c_int,
    ) -> bindings::umode_t {
        if data.is_null() {
            return Mode::NONE.as_raw();
        }

        let Some(sensor_type) = SensorType::from_raw(sensor_type) else {
            return Mode::NONE.as_raw();
        };

        // SAFETY: `Registration::new` registers this vtable with `drvdata` pointing to a `T`
        // value that lives for at least as long as the hwmon device.
        let data = unsafe { &*data.cast::<T>() };
        data.is_visible(sensor_type, attr, channel).as_raw()
    }

    unsafe extern "C" fn read_callback(
        dev: *mut bindings::device,
        sensor_type: bindings::hwmon_sensor_types,
        attr: u32,
        channel: c_int,
        val: *mut c_long,
    ) -> c_int {
        if val.is_null() {
            return EINVAL.to_errno();
        }

        let result: Result<c_int> = (|| {
            // SAFETY: The hwmon core passes a valid hwmon device pointer.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;
            let sensor_type = Self::sensor_from_raw(sensor_type)?;
            let value = data.read(sensor_type, attr, channel)?;

            // SAFETY: `val` was checked non-null and is provided by the hwmon core for output.
            unsafe { *val = value };
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn write_callback(
        dev: *mut bindings::device,
        sensor_type: bindings::hwmon_sensor_types,
        attr: u32,
        channel: c_int,
        val: c_long,
    ) -> c_int {
        let result: Result<c_int> = (|| {
            // SAFETY: The hwmon core passes a valid hwmon device pointer.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;
            let sensor_type = Self::sensor_from_raw(sensor_type)?;
            data.write(sensor_type, attr, channel, val)?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn read_string_callback(
        dev: *mut bindings::device,
        sensor_type: bindings::hwmon_sensor_types,
        attr: u32,
        channel: c_int,
        str_: *mut *const c_char,
    ) -> c_int {
        if str_.is_null() {
            return EINVAL.to_errno();
        }

        let result: Result<c_int> = (|| {
            // SAFETY: The hwmon core passes a valid hwmon device pointer.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;
            let sensor_type = Self::sensor_from_raw(sensor_type)?;
            let value = data.read_string(sensor_type, attr, channel)?;

            // SAFETY: `str_` was checked non-null and is provided by the hwmon core for output.
            unsafe { *str_ = value.as_char_ptr() };
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }
}

/// Wrapper for `struct hwmon_ops`.
#[repr(transparent)]
pub struct HwmonOpsVTable(bindings::hwmon_ops);

// SAFETY: The vtable is immutable function pointers.
unsafe impl Send for HwmonOpsVTable {}
// SAFETY: The vtable is immutable function pointers.
unsafe impl Sync for HwmonOpsVTable {}

/// Create a hwmon operations vtable for `T`.
pub const fn create_hwmon_ops<T: HwmonOps>() -> HwmonOpsVTable {
    let mut ops: bindings::hwmon_ops = unsafe { core::mem::zeroed() };

    ops.is_visible = Some(Adapter::<T>::is_visible_callback);
    ops.read = Some(Adapter::<T>::read_callback);
    ops.read_string = Some(Adapter::<T>::read_string_callback);
    ops.write = Some(Adapter::<T>::write_callback);

    HwmonOpsVTable(ops)
}

/// A hwmon registration that unregisters the device on drop.
///
/// # Lifetime / drop ordering
///
/// The kernel retains the `_ops`/`_chip` pointers for the whole lifetime of the registered hwmon
/// device, and the `drvdata` callbacks dereference. This registration therefore unregisters the
/// hwmon device in [`Drop`] (via `hwmon_device_unregister`) rather than relying on the parent's
/// devres release, which runs *after* the bus `.remove` callback has already freed the driver
/// object (`drvdata`) that embeds this registration.
///
/// Because `Drop::drop` runs before this struct's own fields are dropped and before the embedding
/// driver object's memory is freed, `hwmon_device_unregister` — which removes the sysfs attributes
/// and drains any in-flight `read`/`write`/`is_visible` callbacks — completes while `_ops`, `_chip`
/// and the driver data are all still valid.
///
/// Drivers MUST declare this `Registration` *before* any sibling field whose data the hwmon
/// callbacks access (i.e. as the first such field). Struct fields are dropped in declaration order,
/// so a `Registration` declared first is dropped first: its [`Drop`] unregisters the device (and
/// drains in-flight callbacks) while the data those callbacks touch is still alive. Declaring it
/// *after* that data would leave a window where a sysfs access dereferences already-dropped state.
/// (Conversely, the registration-time `is_visible` callback runs during `Registration::new` and so
/// must not read fields declared after this one — they are not yet initialized at that point; in
/// practice `is_visible` only reads the static channel configuration.)
#[pin_data(PinnedDrop)]
pub struct Registration<T: HwmonOps + 'static, const N: usize> {
    _hwdev: NonNull<bindings::device>,
    _ops: HwmonOpsVTable,
    _chip: bindings::hwmon_chip_info,
    _p: PhantomData<T>,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: HwmonOps + 'static, const N: usize> Registration<T, N> {
    /// Register a hwmon device that is unregistered when this object is dropped.
    ///
    /// # Safety
    ///
    /// `drvdata` must point to a valid `T` for as long as this `Registration` is alive (i.e. until
    /// its [`Drop`] runs and unregisters the hwmon device). In practice, drivers pass their pinned
    /// driver object from `probe` and store this `Registration` as a field of that same object.
    pub unsafe fn new<'a>(
        dev: &'a device::Device<Bound>,
        name: Option<&'a CStr>,
        drvdata: *const T,
        channels: &'static ChannelList<N>,
    ) -> impl PinInit<Self, Error> + 'a {
        try_pin_init!(&this in Self {
            _ops: Adapter::<T>::VTABLE,
            _chip: {
                bindings::hwmon_chip_info {
                    ops: unsafe { (&raw const (*this.as_ptr())._ops).cast::<bindings::hwmon_ops>() },
                    info: channels.as_raw(),
                }
            },
            _hwdev: {
                if drvdata.is_null() {
                    return Err(EINVAL);
                }

                let name = name.map_or(core::ptr::null(), |name| name.as_char_ptr());
                let chip = unsafe { &raw const (*this.as_ptr())._chip };
                let hwdev = from_err_ptr(unsafe {
                    bindings::hwmon_device_register_with_info(
                        dev.as_raw(),
                        name,
                        drvdata.cast_mut().cast::<c_void>(),
                        chip,
                        core::ptr::null_mut(),
                    )
                })?;
                NonNull::new(hwdev).ok_or(ENOMEM)?
            },
            _p: PhantomData,
            _pin: PhantomPinned,
        })
    }

    /// Register a hwmon device **safely**, borrowing the driver's private data as a pinned
    /// reference instead of a raw pointer.
    ///
    /// This is the safe counterpart to [`new`]. The caller passes `data: Pin<&T>` — typically the
    /// driver's own pinned object obtained in the bus driver's *bound* phase — and the resulting
    /// registration must be stored inside that same `T` (devres-owned), so the pointer the hwmon
    /// core keeps stays valid for the registration's lifetime.
    ///
    /// [`new`]: Self::new
    pub fn register<'a>(
        dev: &'a device::Device<Bound>,
        name: Option<&'a CStr>,
        data: Pin<&'a T>,
        channels: &'static ChannelList<N>,
    ) -> impl PinInit<Self, Error> + 'a {
        let drvdata: *const T = data.get_ref();
        // SAFETY: `data` is a pinned reference to a `T` that the caller keeps alive (the
        // registration is stored inside that same `T`, which is devres-owned), so `drvdata`
        // stays valid for at least as long as this registration.
        unsafe { Self::new(dev, name, drvdata, channels) }
    }

    /// Return the registered hwmon class device.
    pub fn device(&self) -> &device::Device {
        // SAFETY: `hwdev` is valid until this registration is dropped.
        unsafe { device::Device::from_raw(self._hwdev.as_ptr()) }
    }
}

#[pinned_drop]
impl<T: HwmonOps + 'static, const N: usize> PinnedDrop for Registration<T, N> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: `_hwdev` was returned by `hwmon_device_register_with_info` and has not been
        // unregistered yet. `hwmon_device_unregister` removes the sysfs attributes and drains any
        // in-flight callbacks before returning, after which the kernel no longer references
        // `_ops`/`_chip`/`drvdata`.
        unsafe { bindings::hwmon_device_unregister(self._hwdev.as_ptr()) };
    }
}

// SAFETY: Registration only stores kernel-owned pointers and immutable callback metadata.
unsafe impl<T: HwmonOps + 'static, const N: usize> Send for Registration<T, N> {}
// SAFETY: Callbacks access driver data through `T: Sync`.
unsafe impl<T: HwmonOps + 'static, const N: usize> Sync for Registration<T, N> {}
