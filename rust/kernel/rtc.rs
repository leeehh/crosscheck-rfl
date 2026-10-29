// SPDX-License-Identifier: GPL-2.0

//! Real-time clock subsystem abstractions.
//!
//! C header: [`include/linux/rtc.h`](srctree/include/linux/rtc.h)

use crate::{
    bindings,
    device::{self, Bound},
    error::{from_err_ptr, to_result},
    prelude::*,
};

use core::{
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    ptr::NonNull,
};

/// RTC interrupt event flags.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IrqEvents(c_ulong);

impl IrqEvents {
    /// Periodic interrupt.
    pub const PF: Self = Self(bindings::RTC_PF as c_ulong);

    /// Alarm interrupt.
    pub const AF: Self = Self(bindings::RTC_AF as c_ulong);

    /// Update interrupt.
    pub const UF: Self = Self(bindings::RTC_UF as c_ulong);

    /// Generic RTC interrupt flag.
    pub const IRQF: Self = Self(bindings::RTC_IRQF as c_ulong);

    fn into_raw(self) -> c_ulong {
        self.0
    }
}

impl core::ops::BitOr for IrqEvents {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Alarm-capable RTC feature bit.
pub const FEATURE_ALARM: u32 = bindings::RTC_FEATURE_ALARM;

/// Minute-resolution alarm feature bit.
pub const FEATURE_ALARM_RES_MINUTE: u32 = bindings::RTC_FEATURE_ALARM_RES_MINUTE;

/// Weekday-required RTC feature bit.
pub const FEATURE_NEED_WEEK_DAY: u32 = bindings::RTC_FEATURE_NEED_WEEK_DAY;

/// Two-second-resolution alarm feature bit.
pub const FEATURE_ALARM_RES_2S: u32 = bindings::RTC_FEATURE_ALARM_RES_2S;

/// Update-interrupt RTC feature bit.
pub const FEATURE_UPDATE_INTERRUPT: u32 = bindings::RTC_FEATURE_UPDATE_INTERRUPT;

/// Calendar time used by RTC callbacks.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct RtcTime(bindings::rtc_time);

impl RtcTime {
    /// Creates an RTC time from raw calendar components.
    pub fn new(
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
    ) -> Self {
        Self(bindings::rtc_time {
            tm_sec,
            tm_min,
            tm_hour,
            tm_mday,
            tm_mon,
            tm_year,
            tm_wday,
            ..Default::default()
        })
    }

    /// Converts seconds since the Unix epoch into an RTC calendar time.
    #[inline]
    pub fn from_seconds(seconds: i64) -> Self {
        // SAFETY: All-zero `struct rtc_time` is a valid temporary output buffer.
        let mut raw: bindings::rtc_time = unsafe { core::mem::zeroed() };

        // SAFETY: `raw` is a valid output pointer for the duration of the call.
        unsafe { bindings::rtc_time64_to_tm(seconds, &mut raw) };

        Self(raw)
    }

    /// Converts this RTC calendar time into seconds since the Unix epoch.
    #[inline]
    pub fn to_seconds(&self) -> i64 {
        let mut raw = self.0;

        // SAFETY: `raw` is a valid `struct rtc_time` copy for the duration of the call.
        unsafe { bindings::rtc_tm_to_time64(&mut raw) }
    }

    unsafe fn from_raw(raw: *const bindings::rtc_time) -> Result<Self> {
        if raw.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: The caller guarantees that `raw` points to a valid `struct rtc_time`.
        Ok(Self(unsafe { core::ptr::read(raw) }))
    }

    unsafe fn write_to_raw(&self, raw: *mut bindings::rtc_time) -> Result {
        if raw.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: The caller guarantees that `raw` points to writable `struct rtc_time` storage.
        unsafe { core::ptr::write(raw, self.0) };
        Ok(())
    }

    /// Seconds field, in the range expected by the RTC core.
    pub fn second(&self) -> i32 {
        self.0.tm_sec
    }

    /// Minute field, in the range expected by the RTC core.
    pub fn minute(&self) -> i32 {
        self.0.tm_min
    }

    /// Hour field, in the range expected by the RTC core.
    pub fn hour(&self) -> i32 {
        self.0.tm_hour
    }

    /// Day-of-month field, in the range expected by the RTC core.
    pub fn month_day(&self) -> i32 {
        self.0.tm_mday
    }

    /// Month field, in the range expected by the RTC core.
    pub fn month(&self) -> i32 {
        self.0.tm_mon
    }

    /// Year field, in the range expected by the RTC core.
    pub fn year(&self) -> i32 {
        self.0.tm_year
    }

    /// Weekday field, in the range expected by the RTC core.
    pub fn week_day(&self) -> i32 {
        self.0.tm_wday
    }
}

/// RTC wake alarm state.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct WakeAlarm(bindings::rtc_wkalrm);

impl WakeAlarm {
    /// Creates an RTC wake alarm state.
    pub fn new(time: RtcTime, enabled: bool, pending: bool) -> Self {
        Self(bindings::rtc_wkalrm {
            enabled: enabled as c_uchar,
            pending: pending as c_uchar,
            time: time.0,
        })
    }

    unsafe fn from_raw(raw: *const bindings::rtc_wkalrm) -> Result<Self> {
        if raw.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: The caller guarantees that `raw` points to a valid `struct rtc_wkalrm`.
        Ok(Self(unsafe { core::ptr::read(raw) }))
    }

    unsafe fn write_to_raw(&self, raw: *mut bindings::rtc_wkalrm) -> Result {
        if raw.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: The caller guarantees that `raw` points to writable `struct rtc_wkalrm` storage.
        unsafe { core::ptr::write(raw, self.0) };
        Ok(())
    }

    /// Return the alarm time.
    pub fn time(&self) -> RtcTime {
        RtcTime(self.0.time)
    }

    /// Return whether the alarm is enabled.
    pub fn enabled(&self) -> bool {
        self.0.enabled != 0
    }

    /// Return whether the alarm is pending.
    pub fn pending(&self) -> bool {
        self.0.pending != 0
    }
}

/// Trait implemented by RTC providers.
pub trait RtcOps: Sync {
    /// Whether this provider implements alarm operations.
    const HAS_ALARM: bool = false;

    /// Whether this provider implements an ioctl callback.
    const HAS_IOCTL: bool = false;

    /// Read the current hardware time.
    fn read_time(self: Pin<&Self>) -> Result<RtcTime>;

    /// Set the current hardware time.
    fn set_time(self: Pin<&Self>, time: &RtcTime) -> Result;

    /// Read the configured wake alarm.
    fn read_alarm(self: Pin<&Self>) -> Result<WakeAlarm> {
        Err(ENOIOCTLCMD)
    }

    /// Set the wake alarm.
    fn set_alarm(self: Pin<&Self>, alarm: &WakeAlarm) -> Result {
        let _ = alarm;
        Err(ENOIOCTLCMD)
    }

    /// Enable or disable wake-alarm interrupts.
    fn alarm_irq_enable(self: Pin<&Self>, enabled: bool) -> Result {
        let _ = enabled;
        Err(ENOIOCTLCMD)
    }

    /// Handle an RTC ioctl command.
    fn ioctl(self: Pin<&Self>, cmd: u32, arg: usize) -> Result<i32> {
        let _ = (cmd, arg);
        Err(ENOIOCTLCMD)
    }
}

/// Optional RTC NVMEM callbacks.
pub trait NvmemOps: RtcOps {
    /// Read bytes from the RTC-backed NVMEM area.
    fn nvmem_read(self: Pin<&Self>, offset: u32, value: &mut [u8]) -> Result;

    /// Write bytes into the RTC-backed NVMEM area.
    fn nvmem_write(self: Pin<&Self>, offset: u32, value: &[u8]) -> Result;
}

struct Adapter<T: RtcOps> {
    _p: PhantomData<T>,
}

impl<T: RtcOps> Adapter<T> {
    const VTABLE: RtcOpsVTable = create_rtc_ops::<T>();

    unsafe fn drvdata_from_dev<'a>(dev: *mut bindings::device) -> Result<Pin<&'a T>> {
        if dev.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: The RTC core passes the parent device pointer for the callback duration.
        let data = unsafe { bindings::dev_get_drvdata(dev) };
        if data.is_null() {
            return Err(ENOENT);
        }

        // SAFETY: `Registration::new` stores a `T` pointer in the parent device before
        // registering the RTC device; bus driver registration later stores the same object as
        // typed driver data. The object is pinned and valid while the RTC device is registered.
        Ok(unsafe { Pin::new_unchecked(&*data.cast::<T>()) })
    }

    unsafe extern "C" fn read_time_callback(
        dev: *mut bindings::device,
        tm: *mut bindings::rtc_time,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            // SAFETY: The RTC core passes the parent device for the callback duration.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;
            let value = data.read_time()?;

            // SAFETY: `tm` is an output pointer supplied by the RTC core.
            unsafe { value.write_to_raw(tm) }?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn set_time_callback(
        dev: *mut bindings::device,
        tm: *mut bindings::rtc_time,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            // SAFETY: The RTC core passes the parent device for the callback duration.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;

            // SAFETY: `tm` is an input pointer supplied by the RTC core.
            let value = unsafe { RtcTime::from_raw(tm) }?;
            data.set_time(&value)?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn read_alarm_callback(
        dev: *mut bindings::device,
        alarm: *mut bindings::rtc_wkalrm,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            // SAFETY: The RTC core passes the parent device for the callback duration.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;
            let value = data.read_alarm()?;

            // SAFETY: `alarm` is an output pointer supplied by the RTC core.
            unsafe { value.write_to_raw(alarm) }?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn set_alarm_callback(
        dev: *mut bindings::device,
        alarm: *mut bindings::rtc_wkalrm,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            // SAFETY: The RTC core passes the parent device for the callback duration.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;

            // SAFETY: `alarm` is an input pointer supplied by the RTC core.
            let value = unsafe { WakeAlarm::from_raw(alarm) }?;
            data.set_alarm(&value)?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn alarm_irq_enable_callback(
        dev: *mut bindings::device,
        enabled: kernel::ffi::c_uint,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            // SAFETY: The RTC core passes the parent device for the callback duration.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;
            data.alarm_irq_enable(enabled != 0)?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn ioctl_callback(
        dev: *mut bindings::device,
        cmd: kernel::ffi::c_uint,
        arg: kernel::ffi::c_ulong,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            // SAFETY: The RTC core passes the parent device for the callback duration.
            let data = unsafe { Self::drvdata_from_dev(dev) }?;
            data.ioctl(cmd, arg as usize)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn nvmem_read_callback<N: NvmemOps>(
        priv_: *mut c_void,
        offset: c_uint,
        value: *mut c_void,
        bytes: usize,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            if priv_.is_null() || value.is_null() {
                return Err(EINVAL);
            }

            // SAFETY: `priv_` is the pinned driver pointer installed by `register_nvmem`, and
            // the RTC devres lifetime keeps it valid while NVMEM callbacks may run.
            let data = unsafe { Pin::new_unchecked(&*priv_.cast::<N>()) };

            // SAFETY: The NVMEM core supplies `value` as a writable byte buffer of `bytes`.
            let value = unsafe { core::slice::from_raw_parts_mut(value.cast::<u8>(), bytes) };
            data.nvmem_read(offset, value)?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn nvmem_write_callback<N: NvmemOps>(
        priv_: *mut c_void,
        offset: c_uint,
        value: *mut c_void,
        bytes: usize,
    ) -> kernel::ffi::c_int {
        let result: Result<kernel::ffi::c_int> = (|| {
            if priv_.is_null() || value.is_null() {
                return Err(EINVAL);
            }

            // SAFETY: `priv_` is the pinned driver pointer installed by `register_nvmem`, and
            // the RTC devres lifetime keeps it valid while NVMEM callbacks may run.
            let data = unsafe { Pin::new_unchecked(&*priv_.cast::<N>()) };

            // SAFETY: The NVMEM core supplies `value` as a readable byte buffer of `bytes`.
            let value = unsafe { core::slice::from_raw_parts(value.cast::<u8>(), bytes) };
            data.nvmem_write(offset, value)?;
            Ok(0)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }
}

/// Wrapper for `struct rtc_class_ops`.
#[repr(transparent)]
pub struct RtcOpsVTable(bindings::rtc_class_ops);

// SAFETY: The vtable is immutable function pointers.
unsafe impl Send for RtcOpsVTable {}
// SAFETY: The vtable is immutable function pointers.
unsafe impl Sync for RtcOpsVTable {}

/// Create an RTC operations vtable for `T`.
pub const fn create_rtc_ops<T: RtcOps>() -> RtcOpsVTable {
    let mut ops: bindings::rtc_class_ops = unsafe { core::mem::zeroed() };

    ops.read_time = Some(Adapter::<T>::read_time_callback);
    ops.set_time = Some(Adapter::<T>::set_time_callback);
    if T::HAS_ALARM {
        ops.read_alarm = Some(Adapter::<T>::read_alarm_callback);
        ops.set_alarm = Some(Adapter::<T>::set_alarm_callback);
        ops.alarm_irq_enable = Some(Adapter::<T>::alarm_irq_enable_callback);
    }
    if T::HAS_IOCTL {
        ops.ioctl = Some(Adapter::<T>::ioctl_callback);
    }

    RtcOpsVTable(ops)
}

/// An RTC registration.
///
/// # Lifetime / drop ordering
///
/// The RTC `rtc_device` itself is owned by the parent device's devres (allocated with
/// `devm_rtc_allocate_device`), so this object intentionally has no `Drop`: the RTC core tears the
/// device down during the parent's devres release.
///
/// Two precautions keep RTC callbacks sound across teardown, since the natural RFL pattern frees
/// the driver object (`drvdata`) in the bus `.remove` callback, which runs *before* devres unwinds:
///
/// - `rtc->ops` points at a `'static` per-`T` vtable (see [`Adapter::VTABLE`]), not at storage
///   inside this registration, so it can never dangle even after this object is dropped.
/// - The callbacks recover `drvdata` from the parent device via `dev_get_drvdata`. The bus core
///   NULLs that pointer when it takes back the driver object in `.remove`
///   (`Device::drvdata_obtain`), so a callback that observes the NULL returns `ENOENT` instead of
///   dereferencing freed driver data.
///
/// Note that the `drvdata` NULLing only *narrows* the teardown race: the C driver model runs the
/// bus `.remove` (which frees the driver object) before `devres_release_all` unregisters the RTC
/// chardev, so a callback already in flight on `/dev/rtcN` can still capture the live pointer just
/// before `.remove` NULLs and frees it. This residual TOCTOU window is inherent to the RFL pattern
/// of freeing `drvdata` in `.remove` and is not specific to this abstraction; fully closing it
/// requires draining in-flight callbacks before the free (e.g. an `srcu`/`Revocable` gate), which
/// the current RFL device model does not yet provide.
#[pin_data]
pub struct Registration<T: RtcOps + 'static> {
    _rtc: NonNull<bindings::rtc_device>,
    _p: PhantomData<T>,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: RtcOps + 'static> Registration<T> {
    /// Register a devres-managed RTC device.
    ///
    /// # Safety
    ///
    /// `drvdata` must point to a valid, pinned `T` for as long as the parent device may keep the
    /// RTC device registered. Initialize all fields used by RTC callbacks before this field.
    pub unsafe fn new<'a>(
        dev: &'a device::Device<Bound>,
        drvdata: *const T,
        range_max: u64,
    ) -> impl PinInit<Self, Error> + 'a {
        // SAFETY: This forwards the caller's `drvdata` lifetime contract unchanged.
        unsafe { Self::new_with_range(dev, drvdata, 0, range_max) }
    }

    /// Register a devres-managed RTC device with an explicit valid timestamp range.
    ///
    /// # Safety
    ///
    /// `drvdata` must point to a valid, pinned `T` for as long as the parent device may keep the
    /// RTC device registered. Initialize all fields used by RTC callbacks before this field.
    pub unsafe fn new_with_range<'a>(
        dev: &'a device::Device<Bound>,
        drvdata: *const T,
        range_min: i64,
        range_max: u64,
    ) -> impl PinInit<Self, Error> + 'a {
        // SAFETY: forwards the caller's `drvdata` contract unchanged. Alarm is advertised by
        // default: the RTC core keeps `RTC_FEATURE_ALARM` whenever the ops provide alarm methods.
        unsafe { Self::register_pinned(dev, drvdata, range_min, range_max, true) }
    }

    /// Like [`new_with_range`], but when `advertise_alarm` is `false` the `RTC_FEATURE_ALARM`
    /// bit is cleared right after registration, so the core reports no alarm.
    ///
    /// Use this when alarm ops are compiled in (`RtcOps::HAS_ALARM`) yet a *particular* device has
    /// no usable alarm — e.g. no alarm IRQ is wired and the device is not wakeup-capable. This
    /// mirrors C RTC drivers that call `clear_bit(RTC_FEATURE_ALARM, rtc->features)` in that case
    /// (see `rtc-ds1307.c`). Keeping the feature-bitmap poke inside the abstraction means drivers
    /// no longer need raw access to the just-registered device to gate alarm advertisement.
    ///
    /// # Safety
    ///
    /// Same contract as [`new_with_range`].
    pub unsafe fn new_with_range_gated<'a>(
        dev: &'a device::Device<Bound>,
        drvdata: *const T,
        range_min: i64,
        range_max: u64,
        advertise_alarm: bool,
    ) -> impl PinInit<Self, Error> + 'a {
        // SAFETY: forwards the caller's `drvdata` contract unchanged.
        unsafe { Self::register_pinned(dev, drvdata, range_min, range_max, advertise_alarm) }
    }

    /// Shared implementation for the registration constructors.
    ///
    /// # Safety
    ///
    /// Same contract as [`new_with_range`].
    unsafe fn register_pinned<'a>(
        dev: &'a device::Device<Bound>,
        drvdata: *const T,
        range_min: i64,
        range_max: u64,
        advertise_alarm: bool,
    ) -> impl PinInit<Self, Error> + 'a {
        try_pin_init!(&this in Self {
            _rtc: {
                if drvdata.is_null() {
                    return Err(EINVAL);
                }

                // Make callback recovery work even if RTC registration immediately calls an op.
                // The bus driver will install the same object as typed driver data after probe.
                // SAFETY: `dev` is a valid parent device and `drvdata` is valid by contract.
                unsafe { bindings::dev_set_drvdata(dev.as_raw(), drvdata.cast_mut().cast()) };

                let rtc = from_err_ptr(unsafe { bindings::devm_rtc_allocate_device(dev.as_raw()) })?;
                let rtc = NonNull::new(rtc).ok_or(ENOMEM)?;

                // SAFETY: `rtc` is freshly allocated and owned by devres. `&Adapter::<T>::VTABLE`
                // references an associated `const`, which is promoted to a `'static`; the `ops`
                // pointer therefore remains valid for the whole lifetime of the RTC device,
                // independent of this registration object's lifetime.
                unsafe {
                    (*rtc.as_ptr()).ops =
                        (&Adapter::<T>::VTABLE as *const RtcOpsVTable).cast::<bindings::rtc_class_ops>();
                    (*rtc.as_ptr()).range_min = range_min;
                    (*rtc.as_ptr()).range_max = range_max;
                }

                // NOTE: The C macro `devm_rtc_register_device()` passes `THIS_MODULE`. The current
                // Rust bus-driver probe traits do not thread `ThisModule` into provider
                // registrations, so the owner is left NULL, matching other initial provider
                // abstractions that cannot yet receive a module owner.
                to_result(unsafe {
                    bindings::__devm_rtc_register_device(core::ptr::null_mut(), rtc.as_ptr())
                })?;

                // Gate alarm advertisement in the abstraction (replaces drivers poking
                // `rtc->features` through a raw self-pointer).
                if !advertise_alarm {
                    // SAFETY: `rtc` was just registered; `features` is a valid bitmap of
                    // `RTC_FEATURE_CNT` bits owned by the RTC device.
                    unsafe {
                        let bitmap = crate::bitmap::Bitmap::from_raw_mut(
                            (*rtc.as_ptr()).features.as_mut_ptr().cast(),
                            bindings::RTC_FEATURE_CNT as usize,
                        );
                        bitmap.clear_bit(bindings::RTC_FEATURE_ALARM as usize);
                    }
                }

                rtc
            },
            _p: PhantomData,
            _pin: PhantomPinned,
        })
    }

    /// Register a devres-managed RTC device **safely**, recovering the driver's private data in
    /// callbacks via the parent device's typed driver data.
    ///
    /// Unlike [`new`]/[`new_with_range`], this takes no raw `drvdata` pointer and is **not**
    /// `unsafe`: the RTC callbacks recover `T` from the parent device's typed driver data
    /// ([`Device::drvdata`]). For that to be populated, call this from the bus driver's *bound*
    /// phase (e.g. `i2c::Driver::bound`), i.e. after the core has stored the typed driver data —
    /// not from `probe` (where the slot is not yet set). Calling it too early is still memory-safe
    /// (callbacks just return `ENOENT` until the data is published).
    ///
    /// `advertise_alarm` works as in [`new_with_range_gated`].
    ///
    /// [`new`]: Self::new
    /// [`new_with_range`]: Self::new_with_range
    /// [`new_with_range_gated`]: Self::new_with_range_gated
    /// [`Device::drvdata`]: device::Device::drvdata
    pub fn register<'a>(
        dev: &'a device::Device<Bound>,
        range_min: i64,
        range_max: u64,
        advertise_alarm: bool,
    ) -> impl PinInit<Self, Error> + 'a {
        try_pin_init!(&this in Self {
            _rtc: {
                let _ = &this;

                // No eager `dev_set_drvdata`: the bus core has already published the typed
                // driver data before this runs, and callbacks recover it via `Device::drvdata`.
                let rtc = from_err_ptr(unsafe { bindings::devm_rtc_allocate_device(dev.as_raw()) })?;
                let rtc = NonNull::new(rtc).ok_or(ENOMEM)?;

                // SAFETY: see `register_pinned`: the vtable is a promoted `'static` const.
                unsafe {
                    (*rtc.as_ptr()).ops =
                        (&Adapter::<T>::VTABLE as *const RtcOpsVTable).cast::<bindings::rtc_class_ops>();
                    (*rtc.as_ptr()).range_min = range_min;
                    (*rtc.as_ptr()).range_max = range_max;
                }

                to_result(unsafe {
                    bindings::__devm_rtc_register_device(core::ptr::null_mut(), rtc.as_ptr())
                })?;

                if !advertise_alarm {
                    // SAFETY: `rtc` was just registered; `features` is a valid `RTC_FEATURE_CNT`-bit
                    // bitmap owned by the RTC device.
                    unsafe {
                        let bitmap = crate::bitmap::Bitmap::from_raw_mut(
                            (*rtc.as_ptr()).features.as_mut_ptr().cast(),
                            bindings::RTC_FEATURE_CNT as usize,
                        );
                        bitmap.clear_bit(bindings::RTC_FEATURE_ALARM as usize);
                    }
                }

                rtc
            },
            _p: PhantomData,
            _pin: PhantomPinned,
        })
    }

    /// Return the registered RTC class device.
    pub fn device(&self) -> &device::Device {
        // SAFETY: `_rtc` is valid while the parent device has not run its devres release.
        unsafe { device::Device::from_raw(&raw mut (*self._rtc.as_ptr()).dev) }
    }

    /// Notify the RTC core that interrupt events have occurred.
    pub fn update_irq(&self, count: c_ulong, events: IrqEvents) {
        // SAFETY: `_rtc` is valid while this registration is alive.
        unsafe { bindings::rtc_update_irq(self._rtc.as_ptr(), count, events.into_raw()) };
    }

    /// Clear a feature bit on this RTC device.
    pub fn clear_feature(&self, feature: u32) -> Result {
        if feature >= bindings::RTC_FEATURE_CNT {
            return Err(EINVAL);
        }

        // SAFETY: `_rtc` is valid while this registration is alive, and `feature` was bounds
        // checked against the kernel-provided feature bitmap size.
        unsafe {
            let bitmap = crate::bitmap::Bitmap::from_raw_mut(
                (*self._rtc.as_ptr()).features.as_mut_ptr().cast(),
                bindings::RTC_FEATURE_CNT as usize,
            );
            bitmap.clear_bit(feature as usize);
        }

        Ok(())
    }

    /// Return whether the RTC UIE timer is enabled.
    pub fn uie_timer_enabled(&self) -> bool {
        // SAFETY: `_rtc` is valid while this registration is alive.
        unsafe { (*self._rtc.as_ptr()).uie_rtctimer.enabled != 0 }
    }

    /// Return whether the RTC AIE timer is enabled.
    pub fn aie_timer_enabled(&self) -> bool {
        // SAFETY: `_rtc` is valid while this registration is alive.
        unsafe { (*self._rtc.as_ptr()).aie_timer.enabled != 0 }
    }

    /// Register a devres-managed RTC NVMEM provider.
    ///
    /// `owner` is borrowed as a pinned reference rather than a raw pointer, so callers need no
    /// `unsafe`. For this to be sound, `owner` must be the driver's **devres-owned** object (the
    /// same value installed as drvdata) and **this registration must be stored inside that same
    /// object**, so the NVMEM core's retained `priv_` pointer (dereferenced by the
    /// `reg_read`/`reg_write` callbacks for the whole lifetime of the devres-managed NVMEM device)
    /// never dangles. Obtain `owner` in the bus driver's `bound()` phase. (This shares the residual
    /// teardown race documented on [`Registration`]: the bus core frees drvdata in `.remove` before
    /// devres unregisters the NVMEM device; not specific to this method.)
    pub fn register_nvmem<N: NvmemOps>(
        &self,
        owner: Pin<&N>,
        name: &'static CStr,
        size: i32,
        word_size: i32,
        stride: i32,
    ) -> Result {
        if size <= 0 || word_size <= 0 || stride <= 0 {
            return Err(EINVAL);
        }

        let mut config = bindings::nvmem_config {
            name: name.as_char_ptr(),
            size,
            word_size,
            stride,
            reg_read: Some(Adapter::<T>::nvmem_read_callback::<N>),
            reg_write: Some(Adapter::<T>::nvmem_write_callback::<N>),
            priv_: owner.get_ref() as *const N as *mut c_void,
            ..Default::default()
        };

        // SAFETY: `_rtc` is valid while this registration is alive. `devm_rtc_nvmem_register`
        // copies the callback pointers and private pointer into the managed nvmem device.
        to_result(unsafe { bindings::devm_rtc_nvmem_register(self._rtc.as_ptr(), &mut config) })
    }
}

// SAFETY: Registration only stores kernel-owned pointers and immutable callback metadata.
unsafe impl<T: RtcOps + 'static> Send for Registration<T> {}
// SAFETY: Callbacks access driver data through `T: Sync`.
unsafe impl<T: RtcOps + 'static> Sync for Registration<T> {}
