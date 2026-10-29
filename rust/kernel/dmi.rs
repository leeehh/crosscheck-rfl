// SPDX-License-Identifier: GPL-2.0

//! Desktop Management Interface helpers.
//!
//! C header: [`include/linux/dmi.h`](srctree/include/linux/dmi.h).

use crate::{bindings, build_assert, prelude::*, str::as_char_ptr_in_const_context};

/// DMI string field selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field(bindings::dmi_field);

impl Field {
    /// DMI board name.
    pub const BOARD_NAME: Self = Self(bindings::dmi_field_DMI_BOARD_NAME);
    /// DMI board vendor.
    pub const BOARD_VENDOR: Self = Self(bindings::dmi_field_DMI_BOARD_VENDOR);
    /// DMI product name.
    pub const PRODUCT_NAME: Self = Self(bindings::dmi_field_DMI_PRODUCT_NAME);
    /// DMI system vendor.
    pub const SYS_VENDOR: Self = Self(bindings::dmi_field_DMI_SYS_VENDOR);
}

/// Test one DMI field for an exact string match.
///
/// This is the typed counterpart of `dmi_match`; callers cannot pass an
/// arbitrary field number or a non-NUL-terminated value.
pub fn matches(field: Field, value: &CStr) -> bool {
    // SAFETY: `field` is a closed typed selector and `value` is a live C
    // string for the duration of the query. The DMI core retains neither.
    unsafe { bindings::dmi_match(field.0, value.as_char_ptr()) }
}

/// One DMI string match.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Match(bindings::dmi_strmatch);

impl Match {
    const MAX_SUBSTR: usize = 79;

    const fn bitfield(slot: u8, exact_match: bool) -> bindings::__BindgenBitfieldUnit<[u8; 1]> {
        let exact = exact_match as u8;

        #[cfg(target_endian = "little")]
        {
            bindings::__BindgenBitfieldUnit::new([(slot & 0x7f) | (exact << 7)])
        }

        #[cfg(target_endian = "big")]
        {
            bindings::__BindgenBitfieldUnit::new([((slot & 0x7f) << 1) | exact])
        }
    }

    const fn empty() -> Self {
        Self(bindings::dmi_strmatch {
            _bitfield_1: Self::bitfield(0, false),
            substr: [0; Self::MAX_SUBSTR],
            _bitfield_align_1: [],
        })
    }

    /// Create an exact DMI string match.
    //
    // `#[inline(always)]` so the `build_assert!` below is always evaluated against the caller's
    // concrete `value` at compile time. Without it, an out-of-line monomorphization keeps the
    // assert as a runtime `rust_build_error` reference, which fails the vmlinux link (the symbol is
    // only resolved at final link, not when building an external module against the kernel).
    #[inline(always)]
    pub const fn exact(field: Field, value: &'static CStr) -> Self {
        let src = value.to_bytes_with_nul();
        build_assert!(
            src.len() <= Self::MAX_SUBSTR,
            "DMI match string is too long"
        );

        let mut out = Self::empty();
        out.0._bitfield_1 = Self::bitfield(field.0 as u8, true);

        let mut i = 0;
        while i < src.len() {
            out.0.substr[i] = src[i] as c_char;
            i += 1;
        }
        out
    }
}

/// One DMI system-id table entry.
#[repr(transparent)]
pub struct SystemId(bindings::dmi_system_id);

impl SystemId {
    /// Create a DMI system-id entry from up to four matches.
    pub const fn new(matches: [Option<Match>; 4]) -> Self {
        let mut raw_matches = [Match::empty().0; 4];
        let mut i = 0;
        while i < 4 {
            if let Some(m) = matches[i] {
                raw_matches[i] = m.0;
            }
            i += 1;
        }

        Self(bindings::dmi_system_id {
            callback: None,
            ident: core::ptr::null(),
            matches: raw_matches,
            driver_data: core::ptr::null_mut(),
        })
    }

    /// Create a named DMI system-id entry from up to four matches.
    pub const fn new_ident(ident: &'static CStr, matches: [Option<Match>; 4]) -> Self {
        let mut out = Self::new(matches);
        out.0.ident = as_char_ptr_in_const_context(ident);
        out
    }

    /// Create the terminating empty system-id entry required by the C API.
    pub const fn terminator() -> Self {
        Self(bindings::dmi_system_id {
            callback: None,
            ident: core::ptr::null(),
            matches: [Match::empty().0; 4],
            driver_data: core::ptr::null_mut(),
        })
    }
}

// SAFETY: DMI system-id entries are immutable after construction.
unsafe impl Sync for SystemId {}

/// Return the first DMI table match.
///
/// The last entry must be [`SystemId::terminator`], matching the C API's sentinel table.
pub fn first_match(table: &'static [SystemId]) -> Option<&'static SystemId> {
    // Mirror C's `dmi_is_end_of_table()`, which detects the sentinel by `matches[0].slot ==
    // DMI_NONE` (`DMI_NONE == 0`). Checking `ident` instead would be unreliable: `SystemId::new()`
    // leaves `ident` NULL even for real entries, so a missing terminator could slip past and let
    // `dmi_first_match()` walk off the end of the slice.
    if !matches!(table.last(), Some(last) if last.0.matches[0].slot() == 0) {
        return None;
    }

    // SAFETY: `table` is static and sentinel-terminated as checked above.
    let found =
        unsafe { bindings::dmi_first_match(table.as_ptr().cast::<bindings::dmi_system_id>()) };
    if found.is_null() {
        None
    } else {
        // SAFETY: `dmi_first_match` returns a pointer into `table`.
        Some(unsafe { &*found.cast::<SystemId>() })
    }
}
