// SPDX-License-Identifier: GPL-2.0

//! Reboot and sys-off handler abstractions.
//!
//! C header: [`include/linux/reboot.h`](srctree/include/linux/reboot.h)

use crate::{
    bindings,
    error::from_err_ptr,
    ffi::{c_int, c_void},
    prelude::*,
    types::Opaque,
};

use core::{
    marker::{PhantomData, PhantomPinned},
    ptr::NonNull,
};

/// Sys-off callback mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SysOffMode {
    /// Prepare for power-off; callbacks may sleep.
    PowerOffPrepare,
    /// Power off the system; callbacks must not sleep.
    PowerOff,
    /// Prepare for restart; callbacks may sleep.
    RestartPrepare,
    /// Restart the system; callbacks must not sleep.
    Restart,
}

impl SysOffMode {
    fn as_raw(self) -> c_int {
        match self {
            Self::PowerOffPrepare => 0,
            Self::PowerOff => 1,
            Self::RestartPrepare => 2,
            Self::Restart => 3,
        }
    }
}

/// Standard sys-off priorities.
pub mod prio {
    /// Platform-level handler priority.
    pub const PLATFORM: i32 = -256;
    /// Last-resort handler priority.
    pub const LOW: i32 = -128;
    /// Default handler priority.
    pub const DEFAULT: i32 = 0;
    /// High handler priority.
    pub const HIGH: i32 = 192;
    /// Firmware handler priority.
    pub const FIRMWARE: i32 = 224;
}

/// Sys-off callback return value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Notify {
    /// Equivalent to `NOTIFY_DONE`.
    Done,
}

impl Notify {
    fn as_raw(self) -> c_int {
        match self {
            Self::Done => 0,
        }
    }
}

/// Reboot mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootMode {
    /// Hard reboot.
    Hard,
}

impl RebootMode {
    fn as_raw(self) -> c_int {
        match self {
            Self::Hard => 2,
        }
    }
}

/// Set the global reboot mode.
pub fn set_reboot_mode(mode: RebootMode) {
    // SAFETY: The helper only assigns the global `reboot_mode` enum.
    unsafe { bindings::set_reboot_mode(mode.as_raw()) };
}

/// Invoke the architecture restart hook.
pub fn machine_restart(cmd: Option<&CStr>) {
    let cmd = cmd.map_or(core::ptr::null_mut(), |s| s.as_char_ptr().cast_mut());
    // SAFETY: The helper forwards the optional NUL-terminated command pointer to C.
    unsafe { bindings::reboot_machine_restart(cmd) };
}

/// Raw sys-off callback data.
pub struct SysOffData<'a> {
    raw: *mut bindings::sys_off_data,
    _p: PhantomData<&'a Opaque<bindings::sys_off_data>>,
}

impl SysOffData<'_> {
    /// Return the raw C mode value passed by the kernel.
    pub fn mode_raw(&self) -> c_int {
        // SAFETY: `raw` is provided by the sys-off core for callback duration.
        unsafe { (*self.raw).mode }
    }
}

/// Trait implemented by sys-off handlers.
pub trait SysOffHandler: Send + Sync {
    /// Run the handler.
    fn handle(&self, data: &SysOffData<'_>) -> Notify;
}

/// A registered sys-off handler.
///
/// The handler is unregistered when this guard is dropped.
#[pin_data(PinnedDrop)]
pub struct Registration<T: SysOffHandler + 'static> {
    #[pin]
    handler: T,
    raw: NonNull<bindings::sys_off_handler>,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: SysOffHandler + 'static> Registration<T> {
    /// Register a sys-off handler.
    pub fn new(
        mode: SysOffMode,
        priority: i32,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<Self, Error> {
        try_pin_init!(&this in Self {
            handler <- handler,
            raw: {
                let raw = from_err_ptr(unsafe {
                    bindings::register_sys_off_handler(
                        mode.as_raw() as u32,
                        priority,
                        Some(Self::callback),
                        this.as_ptr().cast::<c_void>(),
                    )
                })?;
                NonNull::new(raw).ok_or(ENOMEM)?
            },
            _pin: PhantomPinned,
        })
    }

    unsafe extern "C" fn callback(data: *mut bindings::sys_off_data) -> c_int {
        // SAFETY: `cb_data` was set to `Registration<T>` in `Registration::new`.
        let registration = unsafe { &*((*data).cb_data.cast::<Self>()) };
        let data = SysOffData {
            raw: data,
            _p: PhantomData,
        };

        registration.handler.handle(&data).as_raw()
    }
}

#[pinned_drop]
impl<T: SysOffHandler + 'static> PinnedDrop for Registration<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: `raw` was returned by `register_sys_off_handler` and has not been unregistered.
        unsafe { bindings::unregister_sys_off_handler(self.raw.as_ptr()) };
    }
}

// SAFETY: `Registration` only exposes shared access to the handler; unregister is serialized by drop.
unsafe impl<T: SysOffHandler + 'static> Send for Registration<T> {}

// SAFETY: callbacks access `T` through shared references and `T: Sync`.
unsafe impl<T: SysOffHandler + 'static> Sync for Registration<T> {}
