// SPDX-License-Identifier: GPL-2.0

//! IRQ abstractions.
//!
//! An IRQ is an interrupt request from a device. It is used to get the CPU's
//! attention so it can service a hardware event in a timely manner.
//!
//! The current abstractions handle IRQ requests and handlers, i.e.: it allows
//! drivers to register a handler for a given IRQ line.
//!
//! C header: [`include/linux/device.h`](srctree/include/linux/interrupt.h)

/// Flags to be used when registering IRQ handlers.
mod flags;

/// IRQ allocation and handling.
mod request;

pub use flags::Flags;

pub use request::{
    Handler, IrqRequest, IrqReturn, Registration, ThreadedHandler, ThreadedIrqReturn,
    ThreadedRegistration, ThreadedRegistrationRef,
};

use crate::{
    bindings,
    error::{from_result, to_result},
    prelude::*,
    seq_file::SeqFile,
    str::as_char_ptr_in_const_context, types::Opaque,
};

/// IRQ trigger type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Type(c_uint);

impl Type {
    /// No trigger type configured.
    pub const NONE: Self = Self(bindings::IRQ_TYPE_NONE);
    /// Rising edge trigger.
    pub const EDGE_RISING: Self = Self(bindings::IRQ_TYPE_EDGE_RISING);
    /// Falling edge trigger.
    pub const EDGE_FALLING: Self = Self(bindings::IRQ_TYPE_EDGE_FALLING);
    /// Both-edge trigger.
    pub const EDGE_BOTH: Self = Self(bindings::IRQ_TYPE_EDGE_BOTH);
    /// High-level trigger.
    pub const LEVEL_HIGH: Self = Self(bindings::IRQ_TYPE_LEVEL_HIGH);
    /// Low-level trigger.
    pub const LEVEL_LOW: Self = Self(bindings::IRQ_TYPE_LEVEL_LOW);

    /// Build an IRQ type from a raw kernel trigger-type word.
    pub const fn from_raw(raw: c_uint) -> Self {
        Self(raw)
    }

    #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
    pub(crate) const fn as_raw(self) -> c_uint {
        self.0
    }

    /// Returns whether all bits in `other` are set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether any bit in `other` is set in `self`.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl core::ops::BitOr for Type {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Type {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// IRQ-chip flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipFlags(c_ulong);

impl ChipFlags {
    /// No IRQ-chip flags.
    pub const NONE: Self = Self(0);
    /// The IRQ-chip table is immutable and must use resource helpers when required.
    pub const IMMUTABLE: Self = Self(bindings::IRQCHIP_IMMUTABLE as c_ulong);

    pub(crate) const fn as_raw(self) -> c_ulong {
        self.0
    }
}

/// Borrowed IRQ callback data.
#[repr(transparent)]
pub struct Data(Opaque<bindings::irq_data>);

impl Data {
    /// Creates a borrowed [`Data`] from a raw IRQ core pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid `struct irq_data` for the returned lifetime.
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::irq_data) -> &'a Self {
        // SAFETY: Guaranteed by the function safety requirements.
        unsafe { &*ptr.cast() }
    }

    fn as_raw(&self) -> *mut bindings::irq_data {
        self.0.get()
    }

    /// Return the Linux IRQ number for this IRQ data.
    #[inline]
    pub fn irq(&self) -> u32 {
        // SAFETY: `self.as_raw()` is valid by the type invariant.
        unsafe { (*self.as_raw()).irq }
    }

    /// Return the hardware IRQ number for this IRQ data.
    #[inline]
    pub fn hwirq(&self) -> usize {
        // SAFETY: `self.as_raw()` is valid by the type invariant.
        unsafe { (*self.as_raw()).hwirq as usize }
    }

    /// Return the opaque IRQ-chip data pointer.
    #[inline]
    #[cfg(CONFIG_GPIOLIB)]
    pub(crate) fn chip_data(&self) -> *mut c_void {
        // SAFETY: `self.as_raw()` is valid by the type invariant.
        unsafe { (*self.as_raw()).chip_data }
    }
}

/// Borrowed IRQ domain.
#[repr(transparent)]
pub struct Domain(Opaque<bindings::irq_domain>);

impl Domain {
    /// Creates a borrowed [`Domain`] from a raw IRQ core pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid `struct irq_domain` for the returned lifetime.
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::irq_domain) -> &'a Self {
        // SAFETY: Guaranteed by the function safety requirements.
        unsafe { &*ptr.cast() }
    }

    fn as_raw(&self) -> *mut bindings::irq_domain {
        self.0.get()
    }

    /// Find the Linux IRQ mapped from a hardware IRQ number.
    pub fn find_mapping(&self, hwirq: usize) -> Option<u32> {
        // SAFETY: `self.as_raw()` is valid by the type invariant.
        let irq = unsafe {
            bindings::irq_find_mapping(self.as_raw(), hwirq as bindings::irq_hw_number_t)
        };
        if irq == 0 {
            None
        } else {
            Some(irq)
        }
    }
}

/// IRQ-chip callback table operations.
pub trait ChipOps: Sync + Sized {
    /// IRQ-chip name.
    const NAME: &'static CStr;
    /// IRQ-chip flags.
    const FLAGS: ChipFlags = ChipFlags::NONE;
    /// Whether to install `GPIOCHIP_IRQ_RESOURCE_HELPERS` callbacks.
    const GPIOCHIP_RESOURCE_HELPERS: bool = false;
    /// Whether this chip implements [`set_type`](ChipOps::set_type).
    ///
    /// When `false`, the `irq_set_type` callback is left NULL so the IRQ core accepts any requested
    /// trigger type (matching a C irq-chip with a NULL `irq_set_type`). When `true`, the callback is
    /// installed; leaving the default body in place while setting this to `true` would make trigger
    /// configuration fail with `ENOTSUPP`.
    const HAS_SET_TYPE: bool = false;
    /// Whether this chip implements [`set_wake`](ChipOps::set_wake).
    ///
    /// When `false`, the `irq_set_wake` callback is left NULL (the IRQ core handles wake bookkeeping
    /// itself). When `true`, the callback is installed.
    const HAS_SET_WAKE: bool = false;

    /// Mask an IRQ line.
    fn mask(data: &Data) {
        let _ = data;
    }

    /// Unmask an IRQ line.
    fn unmask(data: &Data) {
        let _ = data;
    }

    /// Set IRQ wake state.
    fn set_wake(data: &Data, on: bool) -> Result {
        let _ = (data, on);
        Err(ENOTSUPP)
    }

    /// Lock the IRQ bus.
    fn bus_lock(data: &Data) {
        let _ = data;
    }

    /// Synchronize and unlock the IRQ bus.
    fn bus_sync_unlock(data: &Data) {
        let _ = data;
    }

    /// Set IRQ trigger type.
    fn set_type(data: &Data, flow_type: Type) -> Result {
        let _ = (data, flow_type);
        Err(ENOTSUPP)
    }

    /// Shutdown an IRQ line.
    fn shutdown(data: &Data) {
        let _ = data;
    }

    /// Print this IRQ chip.
    fn print_chip(data: &Data, seq: &SeqFile) {
        let _ = (data, seq);
    }
}

struct ChipAdapter<T: ChipOps>(core::marker::PhantomData<T>);

impl<T: ChipOps> ChipAdapter<T> {
    unsafe extern "C" fn shutdown_callback(data: *mut bindings::irq_data) {
        // SAFETY: The IRQ core passes a valid `irq_data` pointer for the callback duration.
        T::shutdown(unsafe { Data::from_raw(data) });
    }

    unsafe extern "C" fn mask_callback(data: *mut bindings::irq_data) {
        // SAFETY: The IRQ core passes a valid `irq_data` pointer for the callback duration.
        T::mask(unsafe { Data::from_raw(data) });
    }

    unsafe extern "C" fn unmask_callback(data: *mut bindings::irq_data) {
        // SAFETY: The IRQ core passes a valid `irq_data` pointer for the callback duration.
        T::unmask(unsafe { Data::from_raw(data) });
    }

    unsafe extern "C" fn set_wake_callback(
        data: *mut bindings::irq_data,
        on: c_uint,
    ) -> c_int {
        from_result(|| {
            // SAFETY: The IRQ core passes a valid `irq_data` pointer for the callback duration.
            T::set_wake(unsafe { Data::from_raw(data) }, on != 0)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn bus_lock_callback(data: *mut bindings::irq_data) {
        // SAFETY: The IRQ core passes a valid `irq_data` pointer for the callback duration.
        T::bus_lock(unsafe { Data::from_raw(data) });
    }

    unsafe extern "C" fn bus_sync_unlock_callback(data: *mut bindings::irq_data) {
        // SAFETY: The IRQ core passes a valid `irq_data` pointer for the callback duration.
        T::bus_sync_unlock(unsafe { Data::from_raw(data) });
    }

    unsafe extern "C" fn set_type_callback(
        data: *mut bindings::irq_data,
        flow_type: c_uint,
    ) -> c_int {
        from_result(|| {
            // SAFETY: The IRQ core passes a valid `irq_data` pointer for the callback duration.
            T::set_type(unsafe { Data::from_raw(data) }, Type::from_raw(flow_type))?;
            Ok(0)
        })
    }

    unsafe extern "C" fn print_chip_callback(
        data: *mut bindings::irq_data,
        seq: *mut bindings::seq_file,
    ) {
        // SAFETY: The IRQ core passes valid callback arguments for the callback duration.
        let data = unsafe { Data::from_raw(data) };
        // SAFETY: The IRQ core passes a valid `seq_file` for the callback duration.
        let seq = unsafe { SeqFile::from_raw(seq) };
        T::print_chip(data, seq);
    }
}

/// Static IRQ-chip callback table.
#[repr(transparent)]
pub struct Chip<T: ChipOps> {
    raw: bindings::irq_chip,
    _p: core::marker::PhantomData<T>,
}

impl<T: ChipOps> Chip<T> {
    /// Create an IRQ-chip callback table.
    pub const fn new() -> Self {
        Self {
            raw: bindings::irq_chip {
                name: as_char_ptr_in_const_context(T::NAME),
                irq_startup: None,
                irq_shutdown: Some(ChipAdapter::<T>::shutdown_callback),
                irq_enable: None,
                irq_disable: None,
                irq_ack: None,
                irq_mask: Some(ChipAdapter::<T>::mask_callback),
                irq_mask_ack: None,
                irq_unmask: Some(ChipAdapter::<T>::unmask_callback),
                irq_eoi: None,
                irq_set_affinity: None,
                irq_retrigger: None,
                irq_set_type: if T::HAS_SET_TYPE {
                    Some(ChipAdapter::<T>::set_type_callback)
                } else {
                    None
                },
                irq_set_wake: if T::HAS_SET_WAKE {
                    Some(ChipAdapter::<T>::set_wake_callback)
                } else {
                    None
                },
                irq_bus_lock: Some(ChipAdapter::<T>::bus_lock_callback),
                irq_bus_sync_unlock: Some(ChipAdapter::<T>::bus_sync_unlock_callback),
                irq_suspend: None,
                irq_resume: None,
                irq_pm_shutdown: None,
                irq_calc_mask: None,
                irq_print_chip: Some(ChipAdapter::<T>::print_chip_callback),
                irq_request_resources: if T::GPIOCHIP_RESOURCE_HELPERS {
                    Some(bindings::gpiochip_irq_reqres)
                } else {
                    None
                },
                irq_release_resources: if T::GPIOCHIP_RESOURCE_HELPERS {
                    Some(bindings::gpiochip_irq_relres)
                } else {
                    None
                },
                irq_compose_msi_msg: None,
                irq_write_msi_msg: None,
                irq_get_irqchip_state: None,
                irq_set_irqchip_state: None,
                irq_set_vcpu_affinity: None,
                ipi_send_single: None,
                ipi_send_mask: None,
                irq_nmi_setup: None,
                irq_nmi_teardown: None,
                irq_force_complete_move: None,
                flags: T::FLAGS.as_raw(),
            },
            _p: core::marker::PhantomData,
        }
    }

    /// Return the raw IRQ-chip pointer.
    pub fn as_raw(&'static self) -> *const bindings::irq_chip {
        &self.raw
    }
}

// SAFETY: IRQ-chip callback tables are immutable after construction.
unsafe impl<T: ChipOps> Sync for Chip<T> {}

/// Enable an IRQ line as a system wake source.
#[inline]
pub fn enable_wake(irq: u32) -> Result {
    // SAFETY: The caller supplies an IRQ number obtained from the kernel.
    to_result(unsafe { bindings::enable_irq_wake(irq) })
}

/// Disable an IRQ line as a system wake source.
#[inline]
pub fn disable_wake(irq: u32) -> Result {
    // SAFETY: The caller supplies an IRQ number obtained from the kernel.
    to_result(unsafe { bindings::disable_irq_wake(irq) })
}

/// Enable or disable an IRQ line as a system wake source.
#[inline]
pub fn set_wake(irq: u32, enable: bool) -> Result {
    // SAFETY: The caller supplies an IRQ number obtained from the kernel.
    to_result(unsafe { bindings::irq_set_irq_wake(irq, enable as u32) })
}

/// Disable an IRQ line and wait until any running handler completes.
#[inline]
pub fn disable(irq: u32) {
    // SAFETY: The caller supplies an IRQ number obtained from the kernel.
    unsafe { bindings::disable_irq(irq) };
}

/// Enable an IRQ line.
#[inline]
pub fn enable(irq: u32) {
    // SAFETY: The caller supplies an IRQ number obtained from the kernel.
    unsafe { bindings::enable_irq(irq) };
}

/// Invoke a nested-threaded IRQ handler.
#[inline]
pub fn handle_nested(irq: u32) {
    // SAFETY: The caller supplies an IRQ number produced by the IRQ domain/core.
    unsafe { bindings::handle_nested_irq(irq) };
}
