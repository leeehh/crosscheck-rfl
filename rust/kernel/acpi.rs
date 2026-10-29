// SPDX-License-Identifier: GPL-2.0

//! Advanced Configuration and Power Interface abstractions.

use crate::{
    bindings,
    device::{self, DeviceContext},
    device_id::{RawDeviceId, RawDeviceIdIndex},
    error::to_result,
    prelude::*,
    str::CStrExt as _,
    types::Opaque,
};

/// IdTable type for ACPI drivers.
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// An ACPI device id.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::acpi_device_id);

// SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `acpi_device_id` and does not add
// additional invariants, so it's safe to transmute to `RawType`.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::acpi_device_id;
}

/// An ACPI companion device.
#[repr(transparent)]
pub struct AcpiDevice(Opaque<bindings::acpi_device>);

impl AcpiDevice {
    fn as_raw(&self) -> *mut bindings::acpi_device {
        self.0.get()
    }

    /// Creates a borrowed ACPI device from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid `struct acpi_device` for the returned lifetime.
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::acpi_device) -> &'a Self {
        // SAFETY: Guaranteed by the function safety requirements.
        unsafe { &*ptr.cast() }
    }
}

impl<Ctx: DeviceContext> device::Device<Ctx> {
    /// Return this device's ACPI companion, if any.
    pub fn acpi_companion(&self) -> Option<&AcpiDevice> {
        // SAFETY: `self.as_raw()` is a valid `struct device *`.
        let adev = unsafe { bindings::acpi_companion(self.as_raw()) };
        if adev.is_null() {
            None
        } else {
            // SAFETY: ACPI companion lifetime is tied to the device.
            Some(unsafe { AcpiDevice::from_raw(adev) })
        }
    }

    /// Whether platform firmware requests D3 for this device during suspend.
    ///
    /// This encapsulates the ACPI `StorageD3Enable` policy query. Platforms
    /// without the required ACPI/PM support deterministically return `false`.
    pub fn storage_d3(&self) -> bool {
        #[cfg(all(CONFIG_ACPI, CONFIG_PM))]
        {
            // SAFETY: `self` is a live device and the query does not retain
            // the pointer or mutate driver-owned state.
            unsafe { bindings::acpi_storage_d3(self.as_raw()) }
        }

        #[cfg(not(all(CONFIG_ACPI, CONFIG_PM)))]
        false
    }
}

/// ACPI GPIO lookup parameters.
#[repr(transparent)]
pub struct GpioParams(bindings::acpi_gpio_params);

impl GpioParams {
    /// Create ACPI GPIO lookup parameters.
    pub const fn new(crs_entry_index: u32, line_index: u16, active_low: bool) -> Self {
        Self(bindings::acpi_gpio_params {
            crs_entry_index,
            line_index,
            active_low,
        })
    }
}

/// ACPI GPIO mapping quirk flags.
///
/// These mirror the `ACPI_GPIO_QUIRK_*` bit flags and may be combined with `|`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GpioMappingQuirks(u32);

impl GpioMappingQuirks {
    /// No quirks.
    pub const NONE: Self = Self(0);
    /// Ignore the IoRestriction field in the ACPI resource.
    pub const NO_IO_RESTRICTION: Self = Self(1 << 0);
    /// Only consider `GpioIo` (not `GpioInt`) resources.
    pub const ONLY_GPIOIO: Self = Self(1 << 1);
    /// Treat ACPI GPIO numbers as absolute.
    pub const ABSOLUTE_NUMBER: Self = Self(1 << 2);

    /// Combine two sets of quirk flags.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for GpioMappingQuirks {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

/// One ACPI GPIO mapping entry.
#[repr(transparent)]
pub struct GpioMapping(bindings::acpi_gpio_mapping);

impl GpioMapping {
    /// Create an ACPI GPIO mapping entry.
    ///
    /// `params` is the backing array of lookup parameters; its length is reported to the kernel as
    /// the mapping `size`, so the C resolver (which reads `params[index]` for `index < size`) can
    /// never index past the storage. Most mappings use a single-element slice.
    pub const fn new(
        name: &'static CStr,
        params: &'static [GpioParams],
        quirks: GpioMappingQuirks,
    ) -> Self {
        // SAFETY-RELEVANT: `GpioParams` is `#[repr(transparent)]` over `acpi_gpio_params`, so the
        // slice base reinterprets directly, and `size` is tied to the slice length.
        Self(bindings::acpi_gpio_mapping {
            name: crate::str::as_char_ptr_in_const_context(name),
            data: params.as_ptr().cast::<bindings::acpi_gpio_params>(),
            size: params.len() as u32,
            quirks: quirks.0,
        })
    }

    /// Create the terminating empty mapping entry required by the C API.
    pub const fn terminator() -> Self {
        Self(bindings::acpi_gpio_mapping {
            name: core::ptr::null(),
            data: core::ptr::null(),
            size: 0,
            quirks: 0,
        })
    }
}

// SAFETY: ACPI GPIO mapping entries are immutable after construction.
unsafe impl Sync for GpioMapping {}

/// Add device-managed ACPI GPIO mappings for this driver.
///
/// The last entry must be [`GpioMapping::terminator`], matching the C API's sentinel table.
pub fn devm_add_driver_gpios<Ctx: DeviceContext>(
    dev: &device::Device<Ctx>,
    mappings: &'static [GpioMapping],
) -> Result {
    if !matches!(mappings.last(), Some(last) if last.0.name.is_null()) {
        return Err(EINVAL);
    }

    // SAFETY: `dev` is valid and `mappings` is static and sentinel-terminated as checked above.
    to_result(unsafe {
        bindings::devm_acpi_dev_add_driver_gpios(
            dev.as_raw(),
            mappings.as_ptr().cast::<bindings::acpi_gpio_mapping>(),
        )
    })
}

/// Return the IRQ number for a named ACPI GPIO resource.
pub fn gpio_irq_get_by(adev: &AcpiDevice, name: &CStr, index: u32) -> Result<u32> {
    if index > c_int::MAX as u32 {
        return Err(EINVAL);
    }

    // SAFETY: `adev` is valid, `name` is NUL-terminated, and `index` was range-checked.
    let irq = unsafe {
        bindings::acpi_dev_gpio_irq_get_by(adev.as_raw(), name.as_char_ptr(), index as c_int)
    };
    to_result(irq)?;
    Ok(irq as u32)
}

// SAFETY: `DRIVER_DATA_OFFSET` is the offset to the `driver_data` field.
unsafe impl RawDeviceIdIndex for DeviceId {
    const DRIVER_DATA_OFFSET: usize = core::mem::offset_of!(bindings::acpi_device_id, driver_data);

    fn index(&self) -> usize {
        self.0.driver_data
    }
}

impl DeviceId {
    const ACPI_ID_LEN: usize = 16;

    /// Create a new device id from an ACPI 'id' string.
    #[inline(always)]
    pub const fn new(id: &'static CStr) -> Self {
        let src = id.to_bytes_with_nul();
        build_assert!(src.len() <= Self::ACPI_ID_LEN, "ID exceeds 16 bytes");
        let mut acpi: bindings::acpi_device_id = pin_init::zeroed();
        let mut i = 0;
        while i < src.len() {
            acpi.id[i] = src[i];
            i += 1;
        }

        Self(acpi)
    }
}

/// Create an ACPI `IdTable` with an "alias" for modpost.
#[macro_export]
macro_rules! acpi_device_table {
    ($table_name:ident, $module_table_name:ident, $id_info_type: ty, $table_data: expr) => {
        const $table_name: $crate::device_id::IdArray<
            $crate::acpi::DeviceId,
            $id_info_type,
            { $table_data.len() },
        > = $crate::device_id::IdArray::new($table_data);

        $crate::module_device_table!("acpi", $module_table_name, $table_name);
    };
}
