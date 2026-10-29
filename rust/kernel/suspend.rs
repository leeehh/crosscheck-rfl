// SPDX-License-Identifier: GPL-2.0

//! System-wide suspend policy queries.
//!
//! C header: [`include/linux/suspend.h`](srctree/include/linux/suspend.h).

use crate::bindings;

/// Whether platform firmware participates in the current suspend transition.
///
/// The mutable PM target and flag globals stay private to the C power core;
/// drivers receive only the same Boolean snapshot as
/// `pm_suspend_via_firmware()`.
#[inline]
pub fn via_firmware() -> bool {
    // SAFETY: This helper is a value-only snapshot with no pointer arguments.
    unsafe { bindings::pm_suspend_via_firmware() }
}
