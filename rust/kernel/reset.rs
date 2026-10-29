// SPDX-License-Identifier: GPL-2.0

//! Reset controller consumer abstractions.
//!
//! C header: [`include/linux/reset.h`](srctree/include/linux/reset.h)

use crate::{
    bindings,
    device::{Device, DeviceContext},
    error::{from_err_ptr, to_result, Result},
    prelude::*,
};

use core::ptr::NonNull;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Flags {
    Exclusive,
    OptionalExclusive,
    Shared,
    OptionalShared,
}

impl Flags {
    fn as_raw(self) -> u32 {
        match self {
            Self::Exclusive => 1 << 2,
            Self::OptionalExclusive => (1 << 1) | (1 << 2),
            Self::Shared => 1,
            Self::OptionalShared => (1 << 1) | 1,
        }
    }

    fn is_optional(self) -> bool {
        matches!(self, Self::OptionalExclusive | Self::OptionalShared)
    }
}

/// A devres-managed reset control handle.
pub struct Control(NonNull<bindings::reset_control>);

impl Control {
    fn as_raw(&self) -> *mut bindings::reset_control {
        self.0.as_ptr()
    }

    /// Assert this reset control.
    pub fn assert(&self) -> Result {
        to_result(unsafe { bindings::reset_control_do_assert(self.as_raw()) })
    }

    /// Deassert this reset control.
    pub fn deassert(&self) -> Result {
        to_result(unsafe { bindings::reset_control_do_deassert(self.as_raw()) })
    }

    /// Trigger a reset pulse.
    pub fn reset(&self) -> Result {
        to_result(unsafe { bindings::reset_control_do_reset(self.as_raw()) })
    }
}

fn devm_get_with_flags<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    id: Option<&CStr>,
    flags: Flags,
) -> Result<Option<Control>> {
    let id = id.map_or(core::ptr::null(), |s| s.as_char_ptr());
    let rst = from_err_ptr(unsafe {
        bindings::reset_control_devm_get(dev.as_raw(), id, flags.as_raw())
    })?;

    if rst.is_null() {
        if flags.is_optional() {
            return Ok(None);
        }
        return Err(ENODEV);
    }

    Ok(Some(Control(NonNull::new(rst).ok_or(ENODEV)?)))
}

/// Get a devres-managed exclusive reset control.
pub fn devm_get_exclusive<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    id: Option<&CStr>,
) -> Result<Control> {
    devm_get_with_flags(dev, id, Flags::Exclusive)?.ok_or(ENODEV)
}

/// Get a devres-managed exclusive reset control.
pub fn devm_get<Ctx: DeviceContext>(dev: &Device<Ctx>, id: Option<&CStr>) -> Result<Control> {
    devm_get_exclusive(dev, id)
}

/// Get an optional devres-managed exclusive reset control.
pub fn devm_get_optional_exclusive<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    id: Option<&CStr>,
) -> Result<Option<Control>> {
    devm_get_with_flags(dev, id, Flags::OptionalExclusive)
}

/// Get an optional devres-managed exclusive reset control.
pub fn devm_get_optional<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    id: Option<&CStr>,
) -> Result<Option<Control>> {
    devm_get_optional_exclusive(dev, id)
}

/// Get a devres-managed shared reset control.
pub fn devm_get_shared<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    id: Option<&CStr>,
) -> Result<Control> {
    devm_get_with_flags(dev, id, Flags::Shared)?.ok_or(ENODEV)
}

/// Get an optional devres-managed shared reset control.
pub fn devm_get_optional_shared<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    id: Option<&CStr>,
) -> Result<Option<Control>> {
    devm_get_with_flags(dev, id, Flags::OptionalShared)
}

// SAFETY: reset control lifetime and synchronization are managed by the reset core.
unsafe impl Send for Control {}

// SAFETY: shared reset control operations are synchronized by the reset core.
unsafe impl Sync for Control {}
