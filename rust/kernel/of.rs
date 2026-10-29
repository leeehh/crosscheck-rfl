// SPDX-License-Identifier: GPL-2.0

//! Device Tree / Open Firmware abstractions.

use crate::{
    bindings,
    device_id::{RawDeviceId, RawDeviceIdIndex},
    prelude::*,
    types::Opaque,
};

/// IdTable type for OF drivers.
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// A borrowed Open Firmware device node.
///
/// This is a non-owning wrapper for a `struct device_node` whose lifetime is
/// tied to the object that returned it, for example a [`Device`](crate::device::Device).
#[repr(transparent)]
pub struct DeviceNode(Opaque<bindings::device_node>);

impl DeviceNode {
    /// Obtain the raw `struct device_node *`.
    pub(crate) fn as_raw(&self) -> *mut bindings::device_node {
        self.0.get()
    }

    /// Convert a raw C `struct device_node` pointer to a borrowed [`DeviceNode`].
    ///
    /// # Safety
    ///
    /// Callers must ensure that `ptr` is valid for the returned lifetime.
    pub(crate) unsafe fn from_raw<'a>(ptr: *mut bindings::device_node) -> &'a Self {
        // SAFETY: Guaranteed by the safety requirements of this function.
        unsafe { &*ptr.cast() }
    }

    /// Return the node name.
    pub fn name(&self) -> &CStr {
        // SAFETY: `self.as_raw()` is valid by the type invariant.
        let name = unsafe { (*self.as_raw()).name };
        if name.is_null() {
            crate::c_str!("")
        } else {
            // SAFETY: OF node names are stored as NUL-terminated C strings.
            unsafe { CStr::from_char_ptr(name) }
        }
    }
}

#[cfg(CONFIG_COMMON_CLK)]
pub mod clk {
    //! Open Firmware clock-provider helpers.

    pub use crate::clk::HwProvider;
}

/// An open firmware device id.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::of_device_id);

// SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `struct of_device_id` and
// does not add additional invariants, so it's safe to transmute to `RawType`.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::of_device_id;
}

// SAFETY: `DRIVER_DATA_OFFSET` is the offset to the `data` field.
unsafe impl RawDeviceIdIndex for DeviceId {
    const DRIVER_DATA_OFFSET: usize = core::mem::offset_of!(bindings::of_device_id, data);

    fn index(&self) -> usize {
        self.0.data as usize
    }
}

impl DeviceId {
    /// Create a new device id from an OF 'compatible' string.
    pub const fn new(compatible: &'static CStr) -> Self {
        let src = compatible.to_bytes_with_nul();
        // Replace with `bindings::of_device_id::default()` once stabilized for `const`.
        // SAFETY: FFI type is valid to be zero-initialized.
        let mut of: bindings::of_device_id = unsafe { core::mem::zeroed() };

        // TODO: Use `copy_from_slice` once stabilized for `const`.
        let mut i = 0;
        while i < src.len() {
            of.compatible[i] = src[i];
            i += 1;
        }

        Self(of)
    }
}

/// Create an OF `IdTable` with an "alias" for modpost.
#[macro_export]
macro_rules! of_device_table {
    ($table_name:ident, $module_table_name:ident, $id_info_type: ty, $table_data: expr) => {
        const $table_name: $crate::device_id::IdArray<
            $crate::of::DeviceId,
            $id_info_type,
            { $table_data.len() },
        > = $crate::device_id::IdArray::new($table_data);

        $crate::module_device_table!("of", $module_table_name, $table_name);
    };
}
