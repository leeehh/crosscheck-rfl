// SPDX-License-Identifier: GPL-2.0

//! Abstractions for the PCI bus.
//!
//! C header: [`include/linux/pci.h`](srctree/include/linux/pci.h)

use crate::{
    bindings,
    container_of,
    device,
    device_id::{
        RawDeviceId,
        RawDeviceIdIndex, //
    },
    driver,
    error::{
        from_result,
        to_result, //
    },
    prelude::*,
    str::CStr,
    types::Opaque,
    ThisModule, //
};
use core::{
    marker::PhantomData,
    mem::offset_of,
    ptr::{
        addr_of_mut,
        NonNull, //
    },
};

mod id;
mod io;
mod irq;

pub use self::id::{
    Class,
    ClassMask,
    Vendor, //
};
pub use self::io::{Bar, MemoryRegions, P2pAllocation, RemappableBar};
pub use self::irq::{
    AffinityCalculator,
    AffinitySetSizes,
    DynamicIrqHandler,
    DynamicIrqRegistration,
    DynamicIrqVectors,
    DynamicThreadedIrqHandler,
    DynamicThreadedIrqRegistration,
    IrqType,
    IrqTypes,
    IrqVector, //
};

/// PCI channel state passed to an AER `error_detected` callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelState {
    /// The channel is operating normally.
    Normal,
    /// The channel is frozen and requires a reset.
    Frozen,
    /// The channel has permanently failed.
    PermanentFailure,
    /// A value introduced by a newer PCI core.
    Unknown(bindings::pci_channel_state_t),
}

impl ChannelState {
    fn from_raw(state: bindings::pci_channel_state_t) -> Self {
        match state {
            bindings::pci_channel_io_normal => Self::Normal,
            bindings::pci_channel_io_frozen => Self::Frozen,
            bindings::pci_channel_io_perm_failure => Self::PermanentFailure,
            value => Self::Unknown(value),
        }
    }
}

/// Result returned by PCI error-recovery callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ErrorRecoveryResult {
    /// No recovery action was selected.
    None = bindings::pci_ers_result_PCI_ERS_RESULT_NONE,
    /// The driver can recover without a slot reset.
    CanRecover = bindings::pci_ers_result_PCI_ERS_RESULT_CAN_RECOVER,
    /// A slot reset is required.
    NeedReset = bindings::pci_ers_result_PCI_ERS_RESULT_NEED_RESET,
    /// Disconnect this driver from the device.
    Disconnect = bindings::pci_ers_result_PCI_ERS_RESULT_DISCONNECT,
    /// Recovery completed successfully.
    Recovered = bindings::pci_ers_result_PCI_ERS_RESULT_RECOVERED,
    /// No AER driver is available.
    NoAerDriver = bindings::pci_ers_result_PCI_ERS_RESULT_NO_AER_DRIVER,
}

impl ErrorRecoveryResult {
    fn as_raw(self) -> bindings::pci_ers_result_t {
        self as bindings::pci_ers_result_t
    }
}

/// Alignment required for a PCI P2P memory resource on this platform.
#[inline]
pub fn p2p_resource_alignment() -> usize {
    // SAFETY: This is a read-only platform capability query.
    unsafe { bindings::memremap_compat_align() as usize }
}

/// An adapter for the registration of PCI drivers.
pub struct Adapter<T: Driver>(T);

// SAFETY: A call to `unregister` for a given instance of `RegType` is guaranteed to be valid if
// a preceding call to `register` has been successful.
unsafe impl<T: Driver + 'static> driver::RegistrationOps for Adapter<T> {
    type RegType = bindings::pci_driver;

    unsafe fn register(
        pdrv: &Opaque<Self::RegType>,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        // SAFETY: It's safe to set the fields of `struct pci_driver` on initialization.
        unsafe {
            (*pdrv.get()).name = name.as_char_ptr();
            (*pdrv.get()).probe = Some(Self::probe_callback);
            (*pdrv.get()).remove = Some(Self::remove_callback);
            (*pdrv.get()).id_table = T::ID_TABLE.as_ptr();
            (*pdrv.get()).shutdown = if T::HAS_SHUTDOWN {
                Some(Self::shutdown_callback)
            } else {
                None
            };
            (*pdrv.get()).sriov_configure = if T::HAS_SRIOV_CONFIGURE {
                Some(Self::sriov_configure_callback)
            } else {
                None
            };
            (*pdrv.get()).err_handler = if T::HAS_AER {
                Self::error_handlers()
            } else {
                core::ptr::null()
            };
            (*pdrv.get()).driver.probe_type = if T::PREFER_ASYNCHRONOUS_PROBE {
                bindings::probe_type_PROBE_PREFER_ASYNCHRONOUS
            } else {
                bindings::probe_type_PROBE_DEFAULT_STRATEGY
            };
            (*pdrv.get()).driver.pm = if cfg!(CONFIG_PM_SLEEP) && T::HAS_PM_SLEEP {
                Self::pm_ops()
            } else {
                core::ptr::null()
            };
        }

        // SAFETY: `pdrv` is guaranteed to be a valid `RegType`.
        to_result(unsafe {
            bindings::__pci_register_driver(pdrv.get(), module.0, name.as_char_ptr())
        })
    }

    unsafe fn unregister(pdrv: &Opaque<Self::RegType>) {
        // SAFETY: `pdrv` is guaranteed to be a valid `RegType`.
        unsafe { bindings::pci_unregister_driver(pdrv.get()) }
    }
}

impl<T: Driver + 'static> Adapter<T> {
    const PM_OPS: bindings::dev_pm_ops = bindings::dev_pm_ops {
        prepare: None,
        complete: None,
        suspend: Some(Self::suspend_callback),
        resume: Some(Self::resume_callback),
        freeze: Some(Self::freeze_callback),
        thaw: Some(Self::thaw_callback),
        poweroff: Some(Self::poweroff_callback),
        restore: Some(Self::restore_callback),
        suspend_late: None,
        resume_early: None,
        freeze_late: None,
        thaw_early: None,
        poweroff_late: None,
        restore_early: None,
        suspend_noirq: None,
        resume_noirq: None,
        freeze_noirq: None,
        thaw_noirq: None,
        poweroff_noirq: None,
        restore_noirq: None,
        runtime_suspend: None,
        runtime_resume: None,
        runtime_idle: None,
    };

    const ERROR_HANDLERS: bindings::pci_error_handlers = bindings::pci_error_handlers {
        error_detected: Some(Self::error_detected_callback),
        mmio_enabled: None,
        slot_reset: Some(Self::slot_reset_callback),
        reset_prepare: Some(Self::reset_prepare_callback),
        reset_done: Some(Self::reset_done_callback),
        resume: Some(Self::error_resume_callback),
        cor_error_detected: None,
    };

    fn pm_ops() -> &'static bindings::dev_pm_ops {
        &Self::PM_OPS
    }

    fn error_handlers() -> &'static bindings::pci_error_handlers {
        &Self::ERROR_HANDLERS
    }

    /// Recover a bound PCI device and its pinned driver data for a bus
    /// callback. The PCI core serializes these callbacks against remove.
    unsafe fn callback_data<'a>(
        pdev: *mut bindings::pci_dev,
    ) -> (&'a Device<device::CoreInternal>, Pin<&'a T>) {
        // SAFETY: Required by this helper's callback-only contract.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal>>() };
        // SAFETY: These callbacks run after successful probe and before the
        // PCI core invokes remove, so the exact `T` stored by `set_drvdata`
        // remains foreign-owned for the callback duration.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T>() };
        (pdev, data)
    }

    /// Convert a generic PM device back to PCI and borrow its driver data.
    unsafe fn pm_callback_data<'a>(
        dev: *mut bindings::device,
    ) -> Result<(&'a Device<device::CoreInternal>, Pin<&'a T>)> {
        if dev.is_null() {
            return Err(ENODEV);
        }
        // SAFETY: The PM core supplies a live `struct device` for this callback.
        let dev = unsafe { &*dev.cast::<device::Device<device::CoreInternal>>() };
        let pdev = <&Device<device::CoreInternal>>::try_from(dev)?;
        // SAFETY: PM callbacks are serialized against unbind by the driver
        // core, so the `T` installed at probe remains foreign-owned.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T>() };
        Ok((pdev, data))
    }

    extern "C" fn shutdown_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: This callback is installed only for a successfully bound
        // `T` and the PCI core supplies its live `pci_dev`.
        let (pdev, data) = unsafe { Self::callback_data(pdev) };
        T::shutdown(pdev, data);
    }

    extern "C" fn sriov_configure_callback(pdev: *mut bindings::pci_dev, num_vfs: c_int) -> c_int {
        // SAFETY: See `shutdown_callback`.
        let (pdev, data) = unsafe { Self::callback_data(pdev) };
        match T::sriov_configure(pdev, data, num_vfs) {
            Ok(value) => value,
            Err(error) => error.to_errno(),
        }
    }

    extern "C" fn suspend_callback(dev: *mut bindings::device) -> c_int {
        from_result(|| {
            // SAFETY: This is invoked only by the PM core for the registered
            // PCI driver while it remains bound.
            let (pdev, data) = unsafe { Self::pm_callback_data(dev) }?;
            T::suspend(pdev, data)?;
            Ok(0)
        })
    }

    extern "C" fn resume_callback(dev: *mut bindings::device) -> c_int {
        from_result(|| {
            // SAFETY: See `suspend_callback`.
            let (pdev, data) = unsafe { Self::pm_callback_data(dev) }?;
            T::resume(pdev, data)?;
            Ok(0)
        })
    }

    extern "C" fn freeze_callback(dev: *mut bindings::device) -> c_int {
        from_result(|| {
            // SAFETY: See `suspend_callback`.
            let (pdev, data) = unsafe { Self::pm_callback_data(dev) }?;
            T::freeze(pdev, data)?;
            Ok(0)
        })
    }

    extern "C" fn thaw_callback(dev: *mut bindings::device) -> c_int {
        from_result(|| {
            // SAFETY: See `suspend_callback`.
            let (pdev, data) = unsafe { Self::pm_callback_data(dev) }?;
            T::thaw(pdev, data)?;
            Ok(0)
        })
    }

    extern "C" fn poweroff_callback(dev: *mut bindings::device) -> c_int {
        from_result(|| {
            // SAFETY: See `suspend_callback`.
            let (pdev, data) = unsafe { Self::pm_callback_data(dev) }?;
            T::poweroff(pdev, data)?;
            Ok(0)
        })
    }

    extern "C" fn restore_callback(dev: *mut bindings::device) -> c_int {
        from_result(|| {
            // SAFETY: See `suspend_callback`.
            let (pdev, data) = unsafe { Self::pm_callback_data(dev) }?;
            T::restore(pdev, data)?;
            Ok(0)
        })
    }

    extern "C" fn error_detected_callback(
        pdev: *mut bindings::pci_dev,
        state: bindings::pci_channel_state_t,
    ) -> bindings::pci_ers_result_t {
        // SAFETY: See `shutdown_callback`; AER callbacks are serialized with
        // remove by the PCI error-recovery core.
        let (pdev, data) = unsafe { Self::callback_data(pdev) };
        T::error_detected(pdev, data, ChannelState::from_raw(state)).as_raw()
    }

    extern "C" fn slot_reset_callback(pdev: *mut bindings::pci_dev) -> bindings::pci_ers_result_t {
        // SAFETY: See `error_detected_callback`.
        let (pdev, data) = unsafe { Self::callback_data(pdev) };
        T::slot_reset(pdev, data).as_raw()
    }

    extern "C" fn reset_prepare_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: See `error_detected_callback`.
        let (pdev, data) = unsafe { Self::callback_data(pdev) };
        T::reset_prepare(pdev, data);
    }

    extern "C" fn reset_done_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: See `error_detected_callback`.
        let (pdev, data) = unsafe { Self::callback_data(pdev) };
        T::reset_done(pdev, data);
    }

    extern "C" fn error_resume_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: See `error_detected_callback`.
        let (pdev, data) = unsafe { Self::callback_data(pdev) };
        T::error_resume(pdev, data);
    }

    extern "C" fn probe_callback(
        pdev: *mut bindings::pci_dev,
        id: *const bindings::pci_device_id,
    ) -> c_int {
        // SAFETY: The PCI bus only ever calls the probe callback with a valid pointer to a
        // `struct pci_dev`.
        //
        // INVARIANT: `pdev` is valid for the duration of `probe_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal>>() };

        // SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `struct pci_device_id` and
        // does not add additional invariants, so it's safe to transmute.
        let id = unsafe { &*id.cast::<DeviceId>() };
        let info = T::ID_TABLE.info(id.index());

        from_result(|| {
            let data = T::probe(pdev, info);

            pdev.as_ref().set_drvdata(data)?;
            Ok(0)
        })
    }

    extern "C" fn remove_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: The PCI bus only ever calls the remove callback with a valid pointer to a
        // `struct pci_dev`.
        //
        // INVARIANT: `pdev` is valid for the duration of `remove_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal>>() };

        // SAFETY: `remove_callback` is only ever called after a successful call to
        // `probe_callback`, hence it's guaranteed that `Device::set_drvdata()` has been called
        // and stored a `Pin<KBox<T>>`.
        let data = unsafe { pdev.as_ref().drvdata_obtain::<T>() };

        T::unbind(pdev, data.as_ref());
    }
}

/// Declares a kernel module that exposes a single PCI driver.
///
/// # Examples
///
///```ignore
/// kernel::module_pci_driver! {
///     type: MyDriver,
///     name: "Module name",
///     authors: ["Author name"],
///     description: "Description",
///     license: "GPL v2",
/// }
///```
#[macro_export]
macro_rules! module_pci_driver {
($($f:tt)*) => {
    $crate::module_driver!(<T>, $crate::pci::Adapter<T>, { $($f)* });
};
}

/// Abstraction for the PCI device ID structure ([`struct pci_device_id`]).
///
/// [`struct pci_device_id`]: https://docs.kernel.org/PCI/pci.html#c.pci_device_id
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::pci_device_id);

impl DeviceId {
    const PCI_ANY_ID: u32 = !0;

    /// Equivalent to C's `PCI_DEVICE` macro.
    ///
    /// Create a new `pci::DeviceId` from a vendor and device ID.
    #[inline]
    pub const fn from_id(vendor: Vendor, device: u32) -> Self {
        Self(bindings::pci_device_id {
            vendor: vendor.as_raw() as u32,
            device,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class: 0,
            class_mask: 0,
            driver_data: 0,
            override_only: 0,
        })
    }

    /// Equivalent to C's `PCI_DEVICE_CLASS` macro.
    ///
    /// Create a new `pci::DeviceId` from a class number and mask.
    #[inline]
    pub const fn from_class(class: u32, class_mask: u32) -> Self {
        Self(bindings::pci_device_id {
            vendor: DeviceId::PCI_ANY_ID,
            device: DeviceId::PCI_ANY_ID,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class,
            class_mask,
            driver_data: 0,
            override_only: 0,
        })
    }

    /// Create a new [`DeviceId`] from a class number, mask, and specific vendor.
    ///
    /// This is more targeted than [`DeviceId::from_class`]: in addition to matching by [`Vendor`],
    /// it also matches the PCI [`Class`] (up to the entire 24 bits, depending on the
    /// [`ClassMask`]).
    #[inline]
    pub const fn from_class_and_vendor(
        class: Class,
        class_mask: ClassMask,
        vendor: Vendor,
    ) -> Self {
        Self(bindings::pci_device_id {
            vendor: vendor.as_raw() as u32,
            device: DeviceId::PCI_ANY_ID,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class: class.as_raw(),
            class_mask: class_mask.as_raw(),
            driver_data: 0,
            override_only: 0,
        })
    }
}

// SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `pci_device_id` and does not add
// additional invariants, so it's safe to transmute to `RawType`.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::pci_device_id;
}

// SAFETY: `DRIVER_DATA_OFFSET` is the offset to the `driver_data` field.
unsafe impl RawDeviceIdIndex for DeviceId {
    const DRIVER_DATA_OFFSET: usize = core::mem::offset_of!(bindings::pci_device_id, driver_data);

    fn index(&self) -> usize {
        self.0.driver_data
    }
}

/// `IdTable` type for PCI.
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// Create a PCI `IdTable` with its alias for modpost.
#[macro_export]
macro_rules! pci_device_table {
    ($table_name:ident, $module_table_name:ident, $id_info_type: ty, $table_data: expr) => {
        const $table_name: $crate::device_id::IdArray<
            $crate::pci::DeviceId,
            $id_info_type,
            { $table_data.len() },
        > = $crate::device_id::IdArray::new($table_data);

        $crate::module_device_table!("pci", $module_table_name, $table_name);
    };
}

/// The PCI driver trait.
///
/// # Examples
///
///```
/// # use kernel::{bindings, device::Core, pci};
///
/// struct MyDriver;
///
/// kernel::pci_device_table!(
///     PCI_TABLE,
///     MODULE_PCI_TABLE,
///     <MyDriver as pci::Driver>::IdInfo,
///     [
///         (
///             pci::DeviceId::from_id(pci::Vendor::REDHAT, bindings::PCI_ANY_ID as u32),
///             (),
///         )
///     ]
/// );
///
/// impl pci::Driver for MyDriver {
///     type IdInfo = ();
///     const ID_TABLE: pci::IdTable<Self::IdInfo> = &PCI_TABLE;
///
///     fn probe(
///         _pdev: &pci::Device<Core>,
///         _id_info: &Self::IdInfo,
///     ) -> impl PinInit<Self, Error> {
///         Err(ENODEV)
///     }
/// }
///```
/// Drivers must implement this trait in order to get a PCI driver registered. Please refer to the
/// `Adapter` documentation for an example.
pub trait Driver: Send {
    /// The type holding information about each device id supported by the driver.
    // TODO: Use `associated_type_defaults` once stabilized:
    //
    // ```
    // type IdInfo: 'static = ();
    // ```
    type IdInfo: 'static;

    /// The table of device ids supported by the driver.
    const ID_TABLE: IdTable<Self::IdInfo>;

    /// Prefer asynchronous probing, equivalent to
    /// `PROBE_PREFER_ASYNCHRONOUS` in `struct device_driver`.
    const PREFER_ASYNCHRONOUS_PROBE: bool = false;

    /// Whether [`Driver::shutdown`] is installed in `struct pci_driver`.
    const HAS_SHUTDOWN: bool = false;

    /// Whether [`Driver::sriov_configure`] is installed.
    const HAS_SRIOV_CONFIGURE: bool = false;

    /// Whether the six system-sleep callbacks are installed as a
    /// `struct dev_pm_ops` table.
    const HAS_PM_SLEEP: bool = false;

    /// Whether the AER error-recovery callback table is installed.
    const HAS_AER: bool = false;

    /// PCI driver probe.
    ///
    /// Called when a new pci device is added or discovered. Implementers should
    /// attempt to initialize the device here.
    fn probe(dev: &Device<device::Core>, id_info: &Self::IdInfo) -> impl PinInit<Self, Error>;

    /// PCI driver unbind.
    ///
    /// Called when a [`Device`] is unbound from its bound [`Driver`]. Implementing this callback
    /// is optional.
    ///
    /// This callback serves as a place for drivers to perform teardown operations that require a
    /// `&Device<Core>` or `&Device<Bound>` reference. For instance, drivers may try to perform I/O
    /// operations to gracefully tear down the device.
    ///
    /// Otherwise, release operations for driver resources should be performed in `Self::drop`.
    fn unbind(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Prepare the device for system shutdown.
    fn shutdown(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Configure SR-IOV virtual functions and return the enabled count.
    fn sriov_configure(
        dev: &Device<device::Core>,
        this: Pin<&Self>,
        num_vfs: c_int,
    ) -> Result<c_int> {
        let _ = (dev, this, num_vfs);
        Err(EOPNOTSUPP)
    }

    /// System suspend callback.
    fn suspend(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// System resume callback.
    fn resume(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// Hibernation freeze callback.
    fn freeze(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// Hibernation thaw callback.
    fn thaw(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// Hibernation poweroff callback.
    fn poweroff(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// Hibernation restore callback.
    fn restore(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// PCI AER channel-error notification.
    fn error_detected(
        dev: &Device<device::Core>,
        this: Pin<&Self>,
        state: ChannelState,
    ) -> ErrorRecoveryResult {
        let _ = (dev, this, state);
        ErrorRecoveryResult::NoAerDriver
    }

    /// PCI AER slot-reset callback.
    fn slot_reset(dev: &Device<device::Core>, this: Pin<&Self>) -> ErrorRecoveryResult {
        let _ = (dev, this);
        ErrorRecoveryResult::NoAerDriver
    }

    /// Called before the PCI core resets the function.
    fn reset_prepare(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Called after the PCI core reset is complete.
    fn reset_done(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Resume normal operation after PCI AER recovery.
    fn error_resume(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }
}

/// The PCI device representation.
///
/// This structure represents the Rust abstraction for a C `struct pci_dev`. The implementation
/// abstracts the usage of an already existing C `struct pci_dev` within Rust code that we get
/// passed from the C side.
///
/// # Invariants
///
/// A [`Device`] instance represents a valid `struct pci_dev` created by the C portion of the
/// kernel.
#[repr(transparent)]
pub struct Device<Ctx: device::DeviceContext = device::Normal>(
    Opaque<bindings::pci_dev>,
    PhantomData<Ctx>,
);

impl<Ctx: device::DeviceContext> Device<Ctx> {
    #[inline]
    fn as_raw(&self) -> *mut bindings::pci_dev {
        self.0.get()
    }
}

impl Device {
    /// Returns the PCI vendor ID as [`Vendor`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kernel::{device::Core, pci::{self, Vendor}, prelude::*};
    /// fn log_device_info(pdev: &pci::Device<Core>) -> Result {
    ///     // Get an instance of `Vendor`.
    ///     let vendor = pdev.vendor_id();
    ///     dev_info!(
    ///         pdev.as_ref(),
    ///         "Device: Vendor={}, Device=0x{:x}\n",
    ///         vendor,
    ///         pdev.device_id()
    ///     );
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn vendor_id(&self) -> Vendor {
        // SAFETY: `self.as_raw` is a valid pointer to a `struct pci_dev`.
        let vendor_id = unsafe { (*self.as_raw()).vendor };
        Vendor::from_raw(vendor_id)
    }

    /// Returns the PCI device ID.
    #[inline]
    pub fn device_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).device }
    }

    /// Returns the PCI revision ID.
    #[inline]
    pub fn revision_id(&self) -> u8 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).revision }
    }

    /// Returns the PCI bus device/function.
    #[inline]
    pub fn dev_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { bindings::pci_dev_id(self.as_raw()) }
    }

    /// Returns the PCI subsystem vendor ID.
    #[inline]
    pub fn subsystem_vendor_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).subsystem_vendor }
    }

    /// Returns the PCI subsystem device ID.
    #[inline]
    pub fn subsystem_device_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).subsystem_device }
    }

    /// Whether the PCI function is currently enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        // SAFETY: `self.as_raw()` is a live PCI function.
        unsafe { bindings::pci_is_enabled(self.as_raw()) }
    }

    /// Whether config-space reads still indicate that the device is present.
    #[inline]
    pub fn is_present(&self) -> bool {
        // SAFETY: `self.as_raw()` is a live PCI function object; the helper
        // handles physically removed devices.
        unsafe { bindings::pci_device_is_present(self.as_raw()) }
    }

    /// Current PCI channel error state.
    #[inline]
    pub fn channel_state(&self) -> ChannelState {
        // SAFETY: The field is maintained by the PCI error-recovery core and
        // is valid for a live `pci_dev`.
        ChannelState::from_raw(unsafe { (*self.as_raw()).error_state })
    }

    /// Whether the PCI channel is offline.
    #[inline]
    pub fn channel_offline(&self) -> bool {
        // SAFETY: `self.as_raw()` is a live PCI function.
        unsafe { bindings::pci_channel_offline(self.as_raw()) }
    }

    /// Whether the PCI device has been permanently disconnected.
    #[inline]
    pub fn is_disconnected(&self) -> bool {
        // SAFETY: `self.as_raw()` is a live PCI function object; this tests
        // its channel state rather than dereferencing hardware resources.
        unsafe { bindings::pci_dev_is_disconnected(self.as_raw()) }
    }

    /// Whether this function's DMA path supports PCI peer-to-peer memory.
    #[inline]
    pub fn supports_p2p_dma(&self) -> bool {
        // SAFETY: `self.as_ref()` is the embedded live generic device.
        unsafe { bindings::dma_pci_p2pdma_supported(self.as_ref().as_raw()) }
    }

    /// Returns the start of the given PCI BAR resource.
    pub fn resource_start(&self, bar: u32) -> Result<bindings::resource_size_t> {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `bar` is a valid bar number, as guaranteed by the above call to `Bar::index_is_valid`,
        // - by its type invariant `self.as_raw` is always a valid pointer to a `struct pci_dev`.
        Ok(unsafe { bindings::pci_resource_start(self.as_raw(), bar.try_into()?) })
    }

    /// Returns the size of the given PCI BAR resource.
    pub fn resource_len(&self, bar: u32) -> Result<bindings::resource_size_t> {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `bar` is a valid bar number, as guaranteed by the above call to `Bar::index_is_valid`,
        // - by its type invariant `self.as_raw` is always a valid pointer to a `struct pci_dev`.
        Ok(unsafe { bindings::pci_resource_len(self.as_raw(), bar.try_into()?) })
    }

    /// Returns the resource flags of the given PCI BAR.
    ///
    /// Mirrors C's `pci_resource_flags(dev, bar)`, which expands to a plain field
    /// read `dev->resource[bar].flags`; this accessor reads that field directly,
    /// so it introduces no new exported kernel symbol. Drivers use it to test
    /// what kind of resource a BAR is — e.g.
    /// `flags.contains(Flags::IORESOURCE_IO)` to gate on a port-I/O window versus
    /// an MMIO window.
    #[inline]
    pub fn resource_flags(&self, bar: u32) -> Result<crate::io::resource::Flags> {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `bar` is a valid bar number, as guaranteed by the above call to `Bar::index_is_valid`,
        //   and `pci_dev::resource` is an array of `PCI_NUM_RESOURCES` (>= 6) entries,
        // - by its type invariant `self.as_raw` is always a valid pointer to a `struct pci_dev`.
        let raw = unsafe { (*self.as_raw()).resource[bar as usize].flags };
        Ok(crate::io::resource::Flags::from_raw(raw))
    }

    /// Bus address of the start of a BAR resource.
    pub fn bus_address(&self, bar: u32) -> Result<bindings::pci_bus_addr_t> {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }
        // SAFETY: The BAR index was validated and `self` is a live PCI
        // function.
        Ok(unsafe { bindings::pci_bus_address(self.as_raw(), bar as c_int) })
    }

    /// Returns the PCI class as a `Class` struct.
    #[inline]
    pub fn pci_class(&self) -> Class {
        // SAFETY: `self.as_raw` is a valid pointer to a `struct pci_dev`.
        Class::from_raw(unsafe { (*self.as_raw()).class })
    }

    /// Returns the IRQ number assigned to this device.
    ///
    /// Only meaningful after the device has been enabled (e.g. via
    /// [`enable_device`](Device::<device::Core>::enable_device)), which is when
    /// the PCI core programs the interrupt line.
    #[inline]
    pub fn irq(&self) -> u32 {
        // SAFETY: `self.as_raw` is a valid pointer to a `struct pci_dev`.
        unsafe { (*self.as_raw()).irq }
    }

    /// Reads a byte from this device's PCI configuration space at `offset`.
    ///
    /// Returns [`EIO`] if the access does not complete successfully (the
    /// underlying `pci_read_config_byte` returns a non-`PCIBIOS_SUCCESSFUL`
    /// code).
    #[inline]
    pub fn read_config_byte(&self, offset: i32) -> Result<u8> {
        let mut val = 0u8;
        // SAFETY: By its type invariant `self.as_raw()` is a valid pointer to a
        // `struct pci_dev`; `&mut val` is valid for a `u8` write.
        let ret = unsafe { bindings::pci_read_config_byte(self.as_raw(), offset, &mut val) };
        if ret != 0 {
            return Err(EIO);
        }
        Ok(val)
    }

    /// Reads a word from this device's PCI configuration space at `offset`.
    ///
    /// Returns [`EIO`] if the access does not complete successfully.
    #[inline]
    pub fn read_config_word(&self, offset: i32) -> Result<u16> {
        let mut val = 0u16;
        // SAFETY: By its type invariant `self.as_raw()` is a valid pointer to a
        // `struct pci_dev`; `&mut val` is valid for a `u16` write.
        let ret = unsafe { bindings::pci_read_config_word(self.as_raw(), offset, &mut val) };
        if ret != 0 {
            return Err(EIO);
        }
        Ok(val)
    }

    /// Reads a dword from this device's PCI configuration space at `offset`.
    ///
    /// Returns [`EIO`] if the access does not complete successfully.
    #[inline]
    pub fn read_config_dword(&self, offset: i32) -> Result<u32> {
        let mut val = 0u32;
        // SAFETY: By its type invariant `self.as_raw()` is a valid pointer to a
        // `struct pci_dev`; `&mut val` is valid for a `u32` write.
        let ret = unsafe { bindings::pci_read_config_dword(self.as_raw(), offset, &mut val) };
        if ret != 0 {
            return Err(EIO);
        }
        Ok(val)
    }

    /// Writes a byte to this device's PCI configuration space at `offset`.
    ///
    /// Returns [`EIO`] if the access does not complete successfully.
    #[inline]
    pub fn write_config_byte(&self, offset: i32, val: u8) -> Result {
        // SAFETY: By its type invariant `self.as_raw()` is a valid pointer to a
        // `struct pci_dev`.
        let ret = unsafe { bindings::pci_write_config_byte(self.as_raw(), offset, val) };
        if ret != 0 {
            return Err(EIO);
        }
        Ok(())
    }

    /// Writes a word to this device's PCI configuration space at `offset`.
    ///
    /// Returns [`EIO`] if the access does not complete successfully.
    #[inline]
    pub fn write_config_word(&self, offset: i32, val: u16) -> Result {
        // SAFETY: By its type invariant `self.as_raw()` is a valid pointer to a
        // `struct pci_dev`.
        let ret = unsafe { bindings::pci_write_config_word(self.as_raw(), offset, val) };
        if ret != 0 {
            return Err(EIO);
        }
        Ok(())
    }

    /// Writes a dword to this device's PCI configuration space at `offset`.
    ///
    /// Returns [`EIO`] if the access does not complete successfully.
    #[inline]
    pub fn write_config_dword(&self, offset: i32, val: u32) -> Result {
        // SAFETY: By its type invariant `self.as_raw()` is a valid pointer to a
        // `struct pci_dev`.
        let ret = unsafe { bindings::pci_write_config_dword(self.as_raw(), offset, val) };
        if ret != 0 {
            return Err(EIO);
        }
        Ok(())
    }

    /// Enable memory decoding while an already-bound driver's serialized
    /// lifecycle (reset, timeout, suspend, or error recovery) owns the
    /// function transition.
    ///
    /// Unlike [`Device::<device::Core>::enable_device_mem`], this variant can
    /// be used through a retained reference. The caller must first quiesce all
    /// data-path users that could race the PCI state transition.
    pub fn enable_device_mem_for_lifecycle(&self) -> Result {
        // SAFETY: `self` retains a live PCI function. PCI enable is internally
        // reference counted; the transport supplies lifecycle serialization.
        to_result(unsafe { bindings::pci_enable_device_mem(self.as_raw()) })
    }

    /// Enable bus mastering during a serialized bound-driver lifecycle.
    #[inline]
    pub fn set_master_for_lifecycle(&self) {
        // SAFETY: The retained function is live and the transport serializes
        // this with its DMA setup/teardown.
        unsafe { bindings::pci_set_master(self.as_raw()) };
    }

    /// Disable the function after the bound driver has quiesced DMA and IRQs.
    #[inline]
    pub fn disable_device_for_lifecycle(&self) {
        // SAFETY: The function object is live; the caller contract supplies
        // the same serialization required by `pci_disable_device` in C.
        unsafe { bindings::pci_disable_device(self.as_raw()) };
    }

    /// Save PCI configuration state during reset or power-management work.
    #[inline]
    pub fn save_state_for_lifecycle(&self) -> Result {
        // SAFETY: This value belongs to the retained live PCI function and the
        // lifecycle owner excludes concurrent state replacement.
        to_result(unsafe { bindings::pci_save_state(self.as_raw()) })
    }

    /// Restore the state saved by [`Self::save_state_for_lifecycle`].
    #[inline]
    pub fn restore_state_for_lifecycle(&self) {
        // SAFETY: The caller pairs this with a saved state or PCI-core reset.
        unsafe { bindings::pci_restore_state(self.as_raw()) };
    }

    /// Perform a function-level reset from serialized transport reset work.
    #[inline]
    pub fn reset_flr_for_lifecycle(&self, probe: bool) -> Result {
        // SAFETY: The transport has quiesced the function and the PCI core
        // owns the actual FLR protocol.
        to_result(unsafe { bindings::pcie_reset_flr(self.as_raw(), probe) })
    }

    /// Register a CMB BAR range as P2P memory during serialized setup.
    pub fn add_p2p_resource_for_lifecycle(
        &self,
        bar: u32,
        size: usize,
        offset: bindings::resource_size_t,
    ) -> Result {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }
        let end = offset
            .checked_add(bindings::resource_size_t::try_from(size)?)
            .ok_or(EINVAL)?;
        if end > self.resource_len(bar)? {
            return Err(EINVAL);
        }
        // SAFETY: The checked range belongs to this live PCI function; the
        // PCI P2P core owns the registration after this synchronous call.
        to_result(unsafe {
            bindings::pci_p2pdma_add_resource(self.as_raw(), bar as c_int, size, offset)
        })
    }

    /// Publish P2P memory previously registered by the lifecycle owner.
    #[inline]
    pub fn publish_p2p_memory_for_lifecycle(&self, publish: bool) {
        // SAFETY: The P2P core serializes publication for this live function.
        unsafe { bindings::pci_p2pmem_publish(self.as_raw(), publish) };
    }
}

impl Device<device::Core> {
    /// Enable memory resources for this device.
    pub fn enable_device_mem(&self) -> Result {
        // SAFETY: `self.as_raw` is guaranteed to be a pointer to a valid `struct pci_dev`.
        to_result(unsafe { bindings::pci_enable_device_mem(self.as_raw()) })
    }

    /// Enable this device (devres-managed), decoding both its I/O and memory BAR
    /// resources.
    ///
    /// Unlike [`enable_device_mem`](Self::enable_device_mem) (which enables only
    /// memory decoding), this also enables I/O-space decoding (`PCI_COMMAND_IO`),
    /// which is required to access registers behind an I/O BAR (e.g. a PCI 16550
    /// UART). Equivalent to C's `pcim_enable_device()`: the enable is released
    /// automatically (the device is disabled) when the device is torn down, i.e.
    /// after the driver's remove/unbind, so no explicit disable is needed.
    pub fn enable_device(&self) -> Result {
        // SAFETY: `self.as_raw` is guaranteed to be a pointer to a valid `struct pci_dev`.
        to_result(unsafe { bindings::pcim_enable_device(self.as_raw()) })
    }

    /// Enable bus-mastering for this device.
    #[inline]
    pub fn set_master(&self) {
        // SAFETY: `self.as_raw` is guaranteed to be a pointer to a valid `struct pci_dev`.
        unsafe { bindings::pci_set_master(self.as_raw()) };
    }

    /// Disable the PCI function.
    #[inline]
    pub fn disable_device(&self) {
        // SAFETY: The driver serializes this operation with DMA and IRQ
        // teardown, and `self` is the bound PCI function.
        unsafe { bindings::pci_disable_device(self.as_raw()) };
    }

    /// Save PCI configuration state for a later restore.
    #[inline]
    pub fn save_state(&self) -> Result {
        // SAFETY: `self` is a live PCI function and the driver core serializes
        // power/error transitions.
        to_result(unsafe { bindings::pci_save_state(self.as_raw()) })
    }

    /// Restore the last saved PCI configuration state.
    #[inline]
    pub fn restore_state(&self) {
        // SAFETY: `self` is live and the caller invokes this only after a
        // successful state save or a PCI-core-managed reset.
        unsafe { bindings::pci_restore_state(self.as_raw()) };
    }

    /// Discard the saved PCI state so generic PM may control the function.
    #[inline]
    pub fn discard_saved_state(&self) -> Result {
        // SAFETY: Passing NULL has the documented `pci_load_saved_state`
        // meaning of discarding the currently saved state.
        to_result(unsafe { bindings::pci_load_saved_state(self.as_raw(), core::ptr::null_mut()) })
    }

    /// Whether PCIe ASPM is enabled for this function.
    #[inline]
    pub fn aspm_enabled(&self) -> bool {
        // SAFETY: `self` is a live PCIe/PCI function; the PCI core handles the
        // non-PCIe case.
        unsafe { bindings::pcie_aspm_enabled(self.as_raw()) }
    }

    /// Perform a PCIe function-level reset.
    #[inline]
    pub fn reset_flr(&self, probe: bool) -> Result {
        // SAFETY: The caller has quiesced the function and PCI core owns the
        // reset protocol.
        to_result(unsafe { bindings::pcie_reset_flr(self.as_raw(), probe) })
    }

    /// Register a BAR subrange as PCI peer-to-peer memory.
    pub fn add_p2p_resource(
        &self,
        bar: u32,
        size: usize,
        offset: bindings::resource_size_t,
    ) -> Result {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }
        let end = offset
            .checked_add(bindings::resource_size_t::try_from(size)?)
            .ok_or(EINVAL)?;
        if end > self.resource_len(bar)? {
            return Err(EINVAL);
        }
        // SAFETY: The BAR and range were validated, and the PCI P2P core owns
        // the resource registration lifetime.
        to_result(unsafe {
            bindings::pci_p2pdma_add_resource(self.as_raw(), bar as c_int, size, offset)
        })
    }

    /// Publish or withdraw this function's registered P2P memory.
    #[inline]
    pub fn publish_p2p_memory(&self, publish: bool) {
        // SAFETY: `self` is live and the P2P core serializes pool publication.
        unsafe { bindings::pci_p2pmem_publish(self.as_raw(), publish) };
    }

    /// Configure SR-IOV using the PCI core's standard implementation.
    ///
    /// A non-negative return value is the number of enabled virtual functions;
    /// a negative kernel errno is converted to [`Error`].
    #[inline]
    pub fn configure_sriov_simple(&self, num_vfs: c_int) -> Result<c_int> {
        // SAFETY: `self.as_raw()` is a live PCI device and the PCI core owns
        // serialization of its SR-IOV configuration callback.
        let ret = unsafe { bindings::pci_sriov_configure_simple(self.as_raw(), num_vfs) };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret)
        }
    }
}

// SAFETY: `pci::Device` is a transparent wrapper of `struct pci_dev`.
// The offset is guaranteed to point to a valid device field inside `pci::Device`.
unsafe impl<Ctx: device::DeviceContext> device::AsBusDevice<Ctx> for Device<Ctx> {
    const OFFSET: usize = offset_of!(bindings::pci_dev, dev);
}

// SAFETY: `Device` is a transparent wrapper of a type that doesn't depend on `Device`'s generic
// argument.
kernel::impl_device_context_deref!(unsafe { Device });
kernel::impl_device_context_into_aref!(Device);

impl crate::dma::Device for Device<device::Core> {}

// SAFETY: Instances of `Device` are always reference-counted.
unsafe impl crate::sync::aref::AlwaysRefCounted for Device {
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference guarantees that the refcount is non-zero.
        unsafe { bindings::pci_dev_get(self.as_raw()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is non-zero.
        unsafe { bindings::pci_dev_put(obj.cast().as_ptr()) }
    }
}

impl<Ctx: device::DeviceContext> AsRef<device::Device<Ctx>> for Device<Ctx> {
    fn as_ref(&self) -> &device::Device<Ctx> {
        // SAFETY: By the type invariant of `Self`, `self.as_raw()` is a pointer to a valid
        // `struct pci_dev`.
        let dev = unsafe { addr_of_mut!((*self.as_raw()).dev) };

        // SAFETY: `dev` points to a valid `struct device`.
        unsafe { device::Device::from_raw(dev) }
    }
}

impl<Ctx: device::DeviceContext> TryFrom<&device::Device<Ctx>> for &Device<Ctx> {
    type Error = kernel::error::Error;

    fn try_from(dev: &device::Device<Ctx>) -> Result<Self, Self::Error> {
        // SAFETY: By the type invariant of `Device`, `dev.as_raw()` is a valid pointer to a
        // `struct device`.
        if !unsafe { bindings::dev_is_pci(dev.as_raw()) } {
            return Err(EINVAL);
        }

        // SAFETY: We've just verified that the bus type of `dev` equals `bindings::pci_bus_type`,
        // hence `dev` must be embedded in a valid `struct pci_dev` as guaranteed by the
        // corresponding C code.
        let pdev = unsafe { container_of!(dev.as_raw(), bindings::pci_dev, dev) };

        // SAFETY: `pdev` is a valid pointer to a `struct pci_dev`.
        Ok(unsafe { &*pdev.cast() })
    }
}

// SAFETY: A `Device` is always reference-counted and can be released from any thread.
unsafe impl Send for Device {}

// SAFETY: `Device` can be shared among threads because all methods of `Device`
// (i.e. `Device<Normal>) are thread safe.
unsafe impl Sync for Device {}
