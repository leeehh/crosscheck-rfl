// SPDX-License-Identifier: GPL-2.0

//! Input subsystem abstractions.
//!
//! C header: [`include/linux/input.h`](srctree/include/linux/input.h)

use crate::{
    bindings,
    device::{self, DeviceContext},
    error::{from_result, to_result},
    ffi::{c_char, c_int, c_uint, c_ulong, c_void},
    prelude::*,
};

use core::ptr::NonNull;

/// Input event types.
pub mod event {
    /// `EV_SYN`.
    pub const SYN: u32 = super::bindings::EV_SYN;
    /// `EV_KEY`.
    pub const KEY: u32 = super::bindings::EV_KEY;
    /// `EV_REL`.
    pub const RELATIVE: u32 = super::bindings::EV_REL;
    /// `EV_REL`.
    pub const REL: u32 = RELATIVE;
    /// `EV_ABS`.
    pub const ABSOLUTE: u32 = super::bindings::EV_ABS;
    /// `EV_ABS`.
    pub const ABS: u32 = ABSOLUTE;
    /// `EV_SW`.
    pub const SWITCH: u32 = super::bindings::EV_SW;
    /// `EV_REP`.
    pub const REPEAT: u32 = super::bindings::EV_REP;
    /// `EV_REP`.
    pub const REP: u32 = REPEAT;
    /// `EV_MSC`.
    pub const MISC: u32 = super::bindings::EV_MSC;
    /// `EV_MSC`.
    pub const MSC: u32 = MISC;
    /// `EV_LED`.
    pub const LED: u32 = super::bindings::EV_LED;
    /// `EV_SND`.
    pub const SND: u32 = super::bindings::EV_SND;
}

/// Synchronization event codes.
pub mod sync {
    /// `SYN_REPORT`.
    pub const REPORT: u32 = super::bindings::SYN_REPORT;
}

/// Relative-axis metadata.
pub mod relative {
    /// Number of relative-axis codes.
    pub const COUNT: u32 = super::bindings::REL_CNT;
}

/// Absolute-axis metadata.
pub mod absolute {
    /// Number of absolute-axis codes.
    pub const COUNT: u32 = super::bindings::ABS_CNT;
}

/// Common input key codes.
pub mod key {
    /// `KEY_POWER`.
    pub const POWER: u32 = super::bindings::KEY_POWER;
    /// `BTN_0`.
    pub const BTN_0: u32 = super::bindings::BTN_0;
}

/// Input key code.
pub type Key = u32;

/// Input bus identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BusType(u16);

impl BusType {
    /// `BUS_HOST`.
    pub const HOST: Self = Self(bindings::BUS_HOST as u16);
    /// `BUS_I2C`.
    pub const I2C: Self = Self(bindings::BUS_I2C as u16);
    /// `BUS_VIRTUAL`.
    pub const VIRTUAL: Self = Self(bindings::BUS_VIRTUAL as u16);

    /// Construct from a raw bus id (e.g. a config-read `bustype`).
    #[inline]
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    const fn as_raw(self) -> u16 {
        self.0
    }
}

/// Callback invoked by the input core when a polled input device should report state.
pub trait Poller: Sync {
    /// Poll the hardware and report pending events through `input`.
    fn poll(&self, input: Device);
}

/// Callback invoked by the input core when a polled input device has no driver state.
pub trait StatelessPoller {
    /// Poll the hardware and report pending events through `input`.
    fn poll(input: Device);
}

/// Callback invoked by the input core when an event is sent *to* the device (e.g. `EV_LED` /
/// `EV_SND` from userspace via evdev). Mirrors C `struct input_dev::event` — called under
/// `event_lock`, must not sleep. The trampoline recovers `&T` via [`Device::drvdata`], so the
/// driver must have called [`Device::set_drvdata_pinned`] beforehand.
pub trait EventCallback {
    /// Handle an event directed at the device. Return `Ok(())` to accept; `Err` signals failure
    /// (the input core mostly ignores the return value for `EV_LED`/`EV_SND`).
    fn event(data: &Self, event_type: u32, code: u32, value: i32) -> Result;
}

/// A devres-managed input device handle.
#[derive(Clone, Copy)]
pub struct Device(NonNull<bindings::input_dev>);

impl Device {
    /// Allocate an input device tied to `dev` with devres.
    #[inline]
    pub fn devm_allocate<Ctx: DeviceContext>(dev: &device::Device<Ctx>) -> Result<Self> {
        // SAFETY: `dev.as_raw()` is a valid parent device pointer.
        let raw = unsafe { bindings::devm_input_allocate_device(dev.as_raw()) };
        let raw = NonNull::new(raw).ok_or(ENOMEM)?;

        Ok(Self(raw))
    }

    /// Allocate an input device (non-devres). Mirrors C `input_allocate_device`. Pair with
    /// [`Self::register`] and an explicit [`Self::unregister`] in the bus driver's unbind path
    /// (before the driver data the callbacks recover is dropped) — needed when the input device's
    /// callbacks recover driver data whose lifetime is tied to the bus device, not to devres.
    #[inline]
    pub fn allocate() -> Result<Self> {
        // SAFETY: `input_allocate_device` returns a valid zeroed `struct input_dev *` or NULL.
        let raw = unsafe { bindings::input_allocate_device() };
        let raw = NonNull::new(raw).ok_or(ENOMEM)?;
        Ok(Self(raw))
    }

    /// Unregister the input device. Mirrors C `input_unregister_device`. After this returns no
    /// further callbacks (`event`/`poll`) fire, so it is safe to drop the driver data they recover
    /// via [`Self::drvdata`]. A registered device is freed by this call (via its refcount).
    #[inline]
    pub fn unregister(self) {
        // SAFETY: `self` points to a registered `struct input_dev`.
        unsafe { bindings::input_unregister_device(self.as_raw()) };
    }

    /// Free an input device that was allocated but never registered (the probe-error path).
    /// Mirrors C `input_free_device`. Do not call on a registered device (use [`Self::unregister`]).
    #[inline]
    pub fn free(self) {
        // SAFETY: `self` points to an unregistered `struct input_dev`.
        unsafe { bindings::input_free_device(self.as_raw()) };
    }

    #[inline]
    fn as_raw(self) -> *mut bindings::input_dev {
        self.0.as_ptr()
    }

    /// Set the device name. The string must be static, as required by `struct input_dev`.
    #[inline]
    pub fn set_name(self, name: &'static CStr) {
        // SAFETY: `self` points to a live `struct input_dev`, and `name` has static lifetime.
        unsafe { (*self.as_raw()).name = name.as_char_ptr() };
    }

    /// Set the physical path string. The string must be static, as required by `struct input_dev`.
    #[inline]
    pub fn set_phys(self, phys: &'static CStr) {
        // SAFETY: `self` points to a live `struct input_dev`, and `phys` has static lifetime.
        unsafe { (*self.as_raw()).phys = phys.as_char_ptr() };
    }

    /// Set the device name from a runtime buffer (`const char *` borrowed for the device's registered
    /// lifetime). Mirrors C `idev->name = buf` for config-read names (the [`Self::set_name`] `'static`
    /// bound is too strict for runtime strings).
    ///
    /// # Safety
    ///
    /// `name` must point to a NUL-terminated string that outlives the input device's registration
    /// (i.e. until [`Self::unregister`]).
    #[inline]
    pub unsafe fn set_name_raw(self, name: *const c_char) {
        // SAFETY: `self` points to a live `struct input_dev`; the caller guarantees `name` outlives
        // registration.
        unsafe { (*self.as_raw()).name = name };
    }

    /// Set the physical path from a runtime buffer. See [`Self::set_name_raw`].
    ///
    /// # Safety
    ///
    /// `phys` must point to a NUL-terminated string that outlives the device's registration.
    #[inline]
    pub unsafe fn set_phys_raw(self, phys: *const c_char) {
        // SAFETY: `self` points to a live `struct input_dev`; the caller guarantees `phys` outlives
        // registration.
        unsafe { (*self.as_raw()).phys = phys };
    }

    /// Set the unique-id string from a runtime buffer. Mirrors C `idev->uniq = buf`.
    ///
    /// # Safety
    ///
    /// `uniq` must point to a NUL-terminated string that outlives the device's registration.
    #[inline]
    pub unsafe fn set_uniq_raw(self, uniq: *const c_char) {
        // SAFETY: `self` points to a live `struct input_dev`; the caller guarantees `uniq` outlives
        // registration.
        unsafe { (*self.as_raw()).uniq = uniq };
    }

    /// Set the device name from a runtime `&CStr` (e.g. a config-read name). Unlike [`Self::set_name`]
    /// (which requires `&'static`), this COPIES the string into device-managed storage tied to the
    /// input device's `struct device`, so it soundly outlives registration without the driver holding
    /// a `&'static`. (The input core does NOT copy `name`/`phys`/`uniq` — sysfs/hotplug/procfs
    /// dereference the stored `const char *` throughout registration — so a borrowed pointer would
    /// have to outlive registration, a contract the type system can't enforce; copying into devres
    /// makes the wrapper genuinely sound.) Returns `ENOMEM` if the devres allocation fails.
    #[inline]
    pub fn set_name_cstr(self, name: &CStr) -> Result {
        // SAFETY: `self` points to a live `struct input_dev`; `dev` is its embedded `struct device`
        // (initialized by `input_allocate_device` → `device_initialize`, so devres is available).
        let dev = unsafe { &raw mut (*self.as_raw()).dev };
        // SAFETY: `dev` is valid; `name.as_char_ptr()` is a valid NUL-terminated string for the call.
        let ptr = unsafe { bindings::devm_kstrdup(dev, name.as_char_ptr(), bindings::GFP_KERNEL) };
        if ptr.is_null() {
            return Err(ENOMEM);
        }
        // SAFETY: `self` points to a live `struct input_dev`; `ptr` is a devres-owned NUL string
        // valid for the device's registered lifetime (freed at `struct device` release).
        unsafe { (*self.as_raw()).name = ptr };
        Ok(())
    }

    /// Set the physical path from a runtime `&CStr` (copied into devres). See [`Self::set_name_cstr`].
    #[inline]
    pub fn set_phys_cstr(self, phys: &CStr) -> Result {
        // SAFETY: `self` points to a live `struct input_dev`; `dev` is its embedded `struct device`.
        let dev = unsafe { &raw mut (*self.as_raw()).dev };
        // SAFETY: `dev` is valid; `phys.as_char_ptr()` is a valid NUL-terminated string.
        let ptr = unsafe { bindings::devm_kstrdup(dev, phys.as_char_ptr(), bindings::GFP_KERNEL) };
        if ptr.is_null() {
            return Err(ENOMEM);
        }
        // SAFETY: `self` is live; `ptr` is a devres-owned NUL string.
        unsafe { (*self.as_raw()).phys = ptr };
        Ok(())
    }

    /// Set the unique-id from a runtime `&CStr` (copied into devres). See [`Self::set_name_cstr`].
    #[inline]
    pub fn set_uniq_cstr(self, uniq: &CStr) -> Result {
        // SAFETY: `self` points to a live `struct input_dev`; `dev` is its embedded `struct device`.
        let dev = unsafe { &raw mut (*self.as_raw()).dev };
        // SAFETY: `dev` is valid; `uniq.as_char_ptr()` is a valid NUL-terminated string.
        let ptr = unsafe { bindings::devm_kstrdup(dev, uniq.as_char_ptr(), bindings::GFP_KERNEL) };
        if ptr.is_null() {
            return Err(ENOMEM);
        }
        // SAFETY: `self` is live; `ptr` is a devres-owned NUL string.
        unsafe { (*self.as_raw()).uniq = ptr };
        Ok(())
    }

    /// Set the bus type in `input_dev::id`.
    #[inline]
    pub fn set_bustype(self, bustype: BusType) {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { (*self.as_raw()).id.bustype = bustype.as_raw() };
    }

    /// Set the vendor id in `input_dev::id`.
    #[inline]
    pub fn set_vendor(self, vendor: u16) {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { (*self.as_raw()).id.vendor = vendor };
    }

    /// Set the product id in `input_dev::id`.
    #[inline]
    pub fn set_product(self, product: u16) {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { (*self.as_raw()).id.product = product };
    }

    /// Set the version in `input_dev::id`.
    #[inline]
    pub fn set_version(self, version: u16) {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { (*self.as_raw()).id.version = version };
    }

    /// Advertise an event type without an associated event code.
    ///
    /// Out-of-range event types (`>= EV_CNT`) are ignored, since writing them would corrupt memory
    /// past the `evbit` bitmap.
    #[inline]
    pub fn enable_event_type(self, event_type: u32) {
        if event_type >= bindings::EV_CNT {
            return;
        }
        // SAFETY: `self` points to a live `struct input_dev` and `evbit` is its event bitmap;
        // `event_type` was bounds-checked against the bitmap size (`EV_CNT`).
        unsafe { bindings::__set_bit(event_type as c_ulong, (*self.as_raw()).evbit.as_mut_ptr()) };
    }

    /// Advertise one event capability.
    #[inline]
    pub fn set_capability(self, event_type: u32, code: u32) {
        // SAFETY: `self` points to a live `struct input_dev`. `input_set_capability` validates the
        // `event_type`/`code` pair internally and ignores unknown types.
        unsafe { bindings::input_set_capability(self.as_raw(), event_type, code) };
    }

    /// Set absolute-axis parameters.
    ///
    /// Out-of-range axes (`>= ABS_CNT`) are ignored, since `input_set_abs_params` would otherwise
    /// write past the `absbit`/`absinfo` arrays.
    #[inline]
    pub fn set_abs_params(self, axis: u32, min: i32, max: i32, fuzz: i32, flat: i32) {
        if axis >= bindings::ABS_CNT {
            return;
        }
        // SAFETY: `self` points to a live `struct input_dev`; `axis` was bounds-checked against the
        // `absbit`/`absinfo` array size (`ABS_CNT`).
        unsafe {
            bindings::input_set_abs_params(
                self.as_raw(),
                axis as c_uint,
                min as c_int,
                max as c_int,
                fuzz as c_int,
                flat as c_int,
            )
        };
    }

    /// Set an absolute-axis resolution. Mirrors C `input_abs_set_res(dev, axis, res)`.
    #[inline]
    pub fn set_abs_res(self, axis: u32, res: i32) {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { bindings::input_abs_set_res(self.as_raw(), axis as c_uint, res as c_int) };
    }

    /// Read an absolute-axis maximum. Mirrors C `input_abs_get_max(dev, axis)`.
    #[inline]
    pub fn abs_max(self, axis: u32) -> i32 {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { bindings::input_abs_get_max(self.as_raw(), axis as c_uint) as i32 }
    }

    /// Advertise one input property (`propbit`). Mirrors C `__set_bit(code, dev->propbit)`.
    /// Out-of-range codes (`>= INPUT_PROP_CNT`) are ignored.
    #[inline]
    pub fn set_property(self, code: u32) {
        if code >= bindings::INPUT_PROP_CNT {
            return;
        }
        // SAFETY: `self` points to a live `struct input_dev`; `propbit` is its property bitmap;
        // `code` was bounds-checked against `INPUT_PROP_CNT`.
        unsafe { bindings::__set_bit(code as c_ulong, (*self.as_raw()).propbit.as_mut_ptr()) };
    }

    /// Whether an event type is advertised (`test_bit(type, evbit)`).
    #[inline]
    pub fn has_event_type(self, event_type: u32) -> bool {
        // SAFETY: `self` points to a live `struct input_dev`; `evbit` is `[c_ulong; 1]` (covers all
        // `EV_CNT` = 32 event types on 64-bit).
        let bits = unsafe { (*self.as_raw()).evbit[0] };
        event_type < 64 && (bits >> event_type) & 1 != 0
    }

    /// Whether an absolute axis is advertised (`test_bit(axis, absbit)`).
    #[inline]
    pub fn has_abs(self, axis: u32) -> bool {
        // SAFETY: `self` points to a live `struct input_dev`; `absbit` is `[c_ulong; 1]`.
        let bits = unsafe { (*self.as_raw()).absbit[0] };
        axis < 64 && (bits >> axis) & 1 != 0
    }

    /// Whether the device has multitouch state initialized ([`Self::mt_init_slots`] succeeded).
    #[inline]
    pub fn has_mt(self) -> bool {
        // SAFETY: `self` points to a live `struct input_dev`; `mt` is a pointer (NULL until MT init).
        !unsafe { (*self.as_raw()).mt }.is_null()
    }

    /// Initialize multitouch slots. Mirrors C `input_mt_init_slots(dev, nslots, flags)`.
    #[inline]
    pub fn mt_init_slots(self, num_slots: u32, flags: u32) -> Result {
        // SAFETY: `self` points to a live `struct input_dev`.
        to_result(unsafe {
            bindings::input_mt_init_slots(self.as_raw(), num_slots as c_uint, flags as c_uint)
        })
    }

    /// Install a polling callback for this input device.
    pub fn setup_polling<P: Poller>(self) -> Result {
        to_result(unsafe { bindings::input_setup_polling(self.as_raw(), Some(poll_callback::<P>)) })
    }

    /// Install a polling callback that does not need driver private data.
    pub fn setup_polling_stateless<P: StatelessPoller>(self) -> Result {
        to_result(unsafe {
            bindings::input_setup_polling(self.as_raw(), Some(stateless_poll_callback::<P>))
        })
    }

    /// Set the polling interval in milliseconds.
    #[inline]
    pub fn set_poll_interval(self, interval_ms: u32) {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { bindings::input_set_poll_interval(self.as_raw(), interval_ms as c_uint) };
    }

    /// Register the input device.
    #[inline]
    pub fn register(self) -> Result {
        // SAFETY: `self` points to a configured `struct input_dev`.
        to_result(unsafe { bindings::input_register_device(self.as_raw()) })
    }

    /// Install the `event` callback (`struct input_dev::event`), dispatched to
    /// [`EventCallback::event`] with `&T` recovered via [`Device::drvdata`]. Call
    /// [`Device::set_drvdata_pinned`] beforehand so the callback can recover `&T`. Mirrors C
    /// `idev->event = cb;`.
    #[inline]
    pub fn set_event_callback<T: EventCallback + 'static>(self) {
        // SAFETY: `self` points to a live `struct input_dev`; `event` is a function-pointer field.
        unsafe { (*self.as_raw()).event = Some(event_callback::<T>) };
    }

    /// Emit an input event.
    #[inline]
    pub fn event(self, event_type: u32, code: u32, value: i32) {
        // SAFETY: `self` points to a live `struct input_dev`.
        unsafe { bindings::input_event(self.as_raw(), event_type, code, value as c_int) };
    }

    /// Report a key state.
    #[inline]
    pub fn report_key(self, code: u32, pressed: bool) {
        self.event(event::KEY, code, i32::from(pressed));
    }

    /// Report a switch state.
    #[inline]
    pub fn report_switch(self, code: u32, enabled: bool) {
        self.event(event::SWITCH, code, i32::from(enabled));
    }

    /// Report a relative-axis change. Mirrors C `input_report_rel`.
    #[inline]
    pub fn report_rel(self, code: u32, value: i32) {
        self.event(event::RELATIVE, code, value);
    }

    /// Report an absolute-axis change. Mirrors C `input_report_abs`.
    #[inline]
    pub fn report_abs(self, code: u32, value: i32) {
        self.event(event::ABSOLUTE, code, value);
    }

    /// Synchronize pending input events.
    #[inline]
    pub fn sync(self) {
        self.event(event::SYN, sync::REPORT, 0);
    }

    /// Store caller-owned data on the input device.
    ///
    /// # Safety
    ///
    /// `data` must remain valid while callbacks may recover it from the input device.
    #[inline]
    pub unsafe fn set_drvdata<T>(self, data: *const T) {
        // SAFETY: `self` points to a live `struct input_dev`.
        let dev = unsafe { &raw mut (*self.as_raw()).dev };

        // SAFETY: `dev` is the embedded `struct device` and `data` validity is guaranteed by
        // the caller.
        unsafe { bindings::dev_set_drvdata(dev, data.cast_mut().cast::<c_void>()) };
    }

    /// Store pinned driver state on the input device.
    ///
    /// This is the safe counterpart to [`set_drvdata`]. The caller passes `data: Pin<&T>` — the
    /// driver's own pinned object obtained in a `pin_chain` or the bus driver's *bound* phase —
    /// which must stay valid while the input device is registered (the device is owned by, or
    /// devres-tied to, that same `T`). No caller-side `unsafe` is required.
    ///
    /// [`set_drvdata`]: Self::set_drvdata
    #[inline]
    pub fn set_drvdata_pinned<T>(self, data: Pin<&T>) {
        // SAFETY: `data` is a pinned reference to a `T` the caller keeps alive for at least the
        // input device's registered lifetime, so the stored pointer stays valid while callbacks
        // may recover it.
        unsafe { self.set_drvdata(Pin::get_ref(data)) };
    }

    /// Recover caller-owned data previously stored by [`Self::set_drvdata`].
    ///
    /// # Safety
    ///
    /// The stored pointer must have type `T` and remain valid for the returned reference.
    #[inline]
    pub unsafe fn drvdata<'a, T>(self) -> Result<&'a T> {
        // SAFETY: `self` points to a live `struct input_dev`.
        let dev = unsafe { &raw mut (*self.as_raw()).dev };

        // SAFETY: `dev` is valid.
        let ptr = unsafe { bindings::dev_get_drvdata(dev) };
        if ptr.is_null() {
            return Err(ENOENT);
        }

        // SAFETY: Guaranteed by the caller.
        Ok(unsafe { &*ptr.cast::<T>() })
    }
}

// SAFETY: `Device` only exposes input-core operations that are safe to issue through a shared
// handle; the input core synchronizes them internally. This makes a driver object embedding a
// `Device` `Sync`, which is what the `Poller: Sync` bound requires for the poll callback to access
// `&T` from the input core's workqueue.
unsafe impl Sync for Device {}

// SAFETY: The `input_dev` is a kernel-managed object that the input core may access from any thread
// under its own locking. The intended use of a `Device` is embedded in a bus driver's drvdata
// object; that object's lifetime equals the bound device's (drvdata is freed in the bus `.remove`,
// before the devres that owns the `input_dev` is released), so the handle can never outlive the
// `input_dev` even when the driver object is moved between threads — which `platform::Driver: Send`
// (and the i2c equivalent) require. This mirrors `reset::Control`, which is `Send` for the same
// devres-embedded pattern.
unsafe impl Send for Device {}

unsafe extern "C" fn poll_callback<P: Poller>(dev: *mut bindings::input_dev) {
    let Some(dev) = NonNull::new(dev) else {
        return;
    };

    let input = Device(dev);

    // SAFETY: `setup_polling::<P>` is useful only after the driver stored a `P` pointer on the
    // input device with `set_drvdata`; if it did not, the callback simply reports no events.
    if let Ok(data) = unsafe { input.drvdata::<P>() } {
        data.poll(input);
    }
}

unsafe extern "C" fn stateless_poll_callback<P: StatelessPoller>(dev: *mut bindings::input_dev) {
    let Some(dev) = NonNull::new(dev) else {
        return;
    };

    P::poll(Device(dev));
}

unsafe extern "C" fn event_callback<T: EventCallback + 'static>(
    dev: *mut bindings::input_dev,
    event_type: c_uint,
    code: c_uint,
    value: c_int,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return 0;
    };

    let input = Device(dev);
    // SAFETY: `set_event_callback::<T>` is useful only after the driver stored a `T` pointer via
    // `set_drvdata`; `drvdata` returns `ENOENT` if none, so the callback is a no-op then.
    match unsafe { input.drvdata::<T>() } {
        Ok(data) => from_result(|| {
            T::event(data, event_type as u32, code as u32, value as i32)?;
            Ok(0)
        }),
        Err(_) => 0,
    }
}
