// SPDX-License-Identifier: GPL-2.0

//! I2C Driver subsystem

// I2C Driver abstractions.
use crate::{
    acpi,
    container_of,
    device,
    device_id::{
        RawDeviceId,
        RawDeviceIdIndex, //
    },
    devres::Devres,
    driver,
    error::*,
    irq,
    of,
    prelude::*,
    types::{
        AlwaysRefCounted,
        Opaque, //
    }, //
};

use core::{
    marker::PhantomData,
    mem::offset_of,
    ptr::{
        from_ref,
        NonNull, //
    }, //
};

use kernel::types::ARef;

/// An I2C device id table.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::i2c_device_id);

impl DeviceId {
    const I2C_NAME_SIZE: usize = 20;

    /// Create a new device id from an I2C 'id' string.
    #[inline(always)]
    pub const fn new(id: &'static CStr) -> Self {
        let src = id.to_bytes_with_nul();
        build_assert!(src.len() <= Self::I2C_NAME_SIZE, "ID exceeds 20 bytes");
        let mut i2c: bindings::i2c_device_id = pin_init::zeroed();
        let mut i = 0;
        while i < src.len() {
            i2c.name[i] = src[i];
            i += 1;
        }

        Self(i2c)
    }
}

// SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `i2c_device_id` and does not add
// additional invariants, so it's safe to transmute to `RawType`.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::i2c_device_id;
}

// SAFETY: `DRIVER_DATA_OFFSET` is the offset to the `driver_data` field.
unsafe impl RawDeviceIdIndex for DeviceId {
    const DRIVER_DATA_OFFSET: usize = core::mem::offset_of!(bindings::i2c_device_id, driver_data);

    fn index(&self) -> usize {
        self.0.driver_data
    }
}

/// IdTable type for I2C
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// Create a I2C `IdTable` with its alias for modpost.
#[macro_export]
macro_rules! i2c_device_table {
    ($table_name:ident, $module_table_name:ident, $id_info_type: ty, $table_data: expr) => {
        const $table_name: $crate::device_id::IdArray<
            $crate::i2c::DeviceId,
            $id_info_type,
            { $table_data.len() },
        > = $crate::device_id::IdArray::new($table_data);

        $crate::module_device_table!("i2c", $module_table_name, $table_name);
    };
}

/// An adapter for the registration of I2C drivers.
pub struct Adapter<T: Driver>(T);

// SAFETY: A call to `unregister` for a given instance of `RegType` is guaranteed to be valid if
// a preceding call to `register` has been successful.
unsafe impl<T: Driver + 'static> driver::RegistrationOps for Adapter<T> {
    type RegType = bindings::i2c_driver;

    unsafe fn register(
        idrv: &Opaque<Self::RegType>,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        build_assert!(
            T::ACPI_ID_TABLE.is_some() || T::OF_ID_TABLE.is_some() || T::I2C_ID_TABLE.is_some(),
            "At least one of ACPI/OF/Legacy tables must be present when registering an i2c driver"
        );

        let i2c_table = match T::I2C_ID_TABLE {
            Some(table) => table.as_ptr(),
            None => core::ptr::null(),
        };

        let of_table = match T::OF_ID_TABLE {
            Some(table) => table.as_ptr(),
            None => core::ptr::null(),
        };

        let acpi_table = match T::ACPI_ID_TABLE {
            Some(table) => table.as_ptr(),
            None => core::ptr::null(),
        };

        // SAFETY: It's safe to set the fields of `struct i2c_client` on initialization.
        unsafe {
            (*idrv.get()).driver.name = name.as_char_ptr();
            (*idrv.get()).probe = Some(Self::probe_callback);
            (*idrv.get()).remove = Some(Self::remove_callback);
            (*idrv.get()).shutdown = Some(Self::shutdown_callback);
            (*idrv.get()).driver.pm = if T::HAS_PM {
                &Self::PM_OPS
            } else {
                core::ptr::null()
            };
            (*idrv.get()).id_table = i2c_table;
            (*idrv.get()).driver.of_match_table = of_table;
            (*idrv.get()).driver.acpi_match_table = acpi_table;
        }

        // SAFETY: `idrv` is guaranteed to be a valid `RegType`.
        to_result(unsafe { bindings::i2c_register_driver(module.0, idrv.get()) })
    }

    unsafe fn unregister(idrv: &Opaque<Self::RegType>) {
        // SAFETY: `idrv` is guaranteed to be a valid `RegType`.
        unsafe { bindings::i2c_del_driver(idrv.get()) }
    }
}

impl<T: Driver + 'static> Adapter<T> {
    const PM_OPS: bindings::dev_pm_ops = bindings::dev_pm_ops {
        prepare: None,
        complete: None,
        suspend: Some(Self::suspend_pm_callback),
        resume: Some(Self::resume_pm_callback),
        freeze: Some(Self::suspend_pm_callback),
        thaw: Some(Self::resume_pm_callback),
        poweroff: Some(Self::suspend_pm_callback),
        restore: Some(Self::resume_pm_callback),
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

    extern "C" fn probe_callback(idev: *mut bindings::i2c_client) -> kernel::ffi::c_int {
        // SAFETY: The I2C bus only ever calls the probe callback with a valid pointer to a
        // `struct i2c_client`.
        //
        // INVARIANT: `idev` is valid for the duration of `probe_callback()`.
        let idev = unsafe { &*idev.cast::<I2cClient<device::CoreInternal>>() };

        let info =
            Self::i2c_id_info(idev).or_else(|| <Self as driver::Adapter>::id_info(idev.as_ref()));

        from_result(|| {
            let data = T::probe(idev, info);

            idev.as_ref().set_drvdata(data)?;

            // Phase 2: the typed driver data is now published, so `Device::drvdata` works. Let the
            // driver register subsystems whose callbacks recover that data via the bound device
            // (e.g. rtc/hwmon), which therefore need it set *before* they register.
            //
            // SAFETY: `set_drvdata()` above succeeded, so the device is bound with `T` data for the
            // duration of `probe_callback()`.
            let dev = unsafe { device::Device::<device::Bound>::from_raw(idev.as_ref().as_raw()) };
            let bound = <&I2cClient<device::Bound>>::try_from(dev)?;
            let this = dev.drvdata::<T>()?;
            if let Err(e) = T::bound(bound, this) {
                // The driver's `bound` failed; fail probe and reclaim the driver data.
                // SAFETY: `set_drvdata()` succeeded above and `drvdata_obtain()` is called
                // exactly once (probe is about to return an error, so no later callback runs).
                drop(unsafe { idev.as_ref().drvdata_obtain::<T>() });
                return Err(e);
            }
            Ok(0)
        })
    }

    extern "C" fn remove_callback(idev: *mut bindings::i2c_client) {
        // SAFETY: `idev` is a valid pointer to a `struct i2c_client`.
        let idev = unsafe { &*idev.cast::<I2cClient<device::CoreInternal>>() };

        // SAFETY: `remove_callback` is only ever called after a successful call to
        // `probe_callback`, hence it's guaranteed that `I2cClient::set_drvdata()` has been called
        // and stored a `Pin<KBox<T>>`.
        let data = unsafe { idev.as_ref().drvdata_obtain::<T>() };

        T::unbind(idev, data.as_ref());
    }

    extern "C" fn shutdown_callback(idev: *mut bindings::i2c_client) {
        // SAFETY: `shutdown_callback` is only ever called for a valid `idev`
        let idev = unsafe { &*idev.cast::<I2cClient<device::CoreInternal>>() };

        // SAFETY: `shutdown_callback` is only ever called after a successful call to
        // `probe_callback`, hence it's guaranteed that `Device::set_drvdata()` has been called
        // and stored a `Pin<KBox<T>>`.
        let data = unsafe { idev.as_ref().drvdata_obtain::<T>() };

        T::shutdown(idev, data.as_ref());
    }

    unsafe extern "C" fn suspend_pm_callback(dev: *mut bindings::device) -> kernel::ffi::c_int {
        from_result(|| {
            if dev.is_null() {
                return Err(EINVAL);
            }

            // SAFETY: PM callbacks are invoked with the bound device for the callback duration.
            let dev = unsafe { device::Device::<device::Bound>::from_raw(dev) };
            let idev = <&I2cClient<device::Bound>>::try_from(dev)?;
            let data = dev.drvdata::<T>()?;

            T::suspend(idev, data).map(|()| 0)
        })
    }

    unsafe extern "C" fn resume_pm_callback(dev: *mut bindings::device) -> kernel::ffi::c_int {
        from_result(|| {
            if dev.is_null() {
                return Err(EINVAL);
            }

            // SAFETY: PM callbacks are invoked with the bound device for the callback duration.
            let dev = unsafe { device::Device::<device::Bound>::from_raw(dev) };
            let idev = <&I2cClient<device::Bound>>::try_from(dev)?;
            let data = dev.drvdata::<T>()?;

            T::resume(idev, data).map(|()| 0)
        })
    }

    /// The [`i2c::IdTable`] of the corresponding driver.
    fn i2c_id_table() -> Option<IdTable<<Self as driver::Adapter>::IdInfo>> {
        T::I2C_ID_TABLE
    }

    /// Returns the driver's private data from the matching entry in the [`i2c::IdTable`], if any.
    ///
    /// If this returns `None`, it means there is no match with an entry in the [`i2c::IdTable`].
    fn i2c_id_info(dev: &I2cClient) -> Option<&'static <Self as driver::Adapter>::IdInfo> {
        let table = Self::i2c_id_table()?;

        // SAFETY:
        // - `table` has static lifetime, hence it's valid for reads
        // - `dev` is guaranteed to be valid while it's alive, and so is `dev.as_raw()`.
        let raw_id = unsafe { bindings::i2c_match_id(table.as_ptr(), dev.as_raw()) };

        if raw_id.is_null() {
            return None;
        }

        // SAFETY: `DeviceId` is a `#[repr(transparent)` wrapper of `struct i2c_device_id` and
        // does not add additional invariants, so it's safe to transmute.
        let id = unsafe { &*raw_id.cast::<DeviceId>() };

        Some(table.info(<DeviceId as RawDeviceIdIndex>::index(id)))
    }
}

impl<T: Driver + 'static> driver::Adapter for Adapter<T> {
    type IdInfo = T::IdInfo;

    fn of_id_table() -> Option<of::IdTable<Self::IdInfo>> {
        T::OF_ID_TABLE
    }

    fn acpi_id_table() -> Option<acpi::IdTable<Self::IdInfo>> {
        T::ACPI_ID_TABLE
    }
}

/// Declares a kernel module that exposes a single i2c driver.
///
/// # Examples
///
/// ```ignore
/// kernel::module_i2c_driver! {
///     type: MyDriver,
///     name: "Module name",
///     authors: ["Author name"],
///     description: "Description",
///     license: "GPL v2",
/// }
/// ```
#[macro_export]
macro_rules! module_i2c_driver {
    ($($f:tt)*) => {
        $crate::module_driver!(<T>, $crate::i2c::Adapter<T>, { $($f)* });
    };
}

/// The i2c driver trait.
///
/// Drivers must implement this trait in order to get a i2c driver registered.
///
/// # Example
///
///```
/// # use kernel::{acpi, bindings, c_str, device::Core, i2c, of};
///
/// struct MyDriver;
///
/// kernel::acpi_device_table!(
///     ACPI_TABLE,
///     MODULE_ACPI_TABLE,
///     <MyDriver as i2c::Driver>::IdInfo,
///     [
///         (acpi::DeviceId::new(c_str!("LNUXBEEF")), ())
///     ]
/// );
///
/// kernel::i2c_device_table!(
///     I2C_TABLE,
///     MODULE_I2C_TABLE,
///     <MyDriver as i2c::Driver>::IdInfo,
///     [
///          (i2c::DeviceId::new(c_str!("rust_driver_i2c")), ())
///     ]
/// );
///
/// kernel::of_device_table!(
///     OF_TABLE,
///     MODULE_OF_TABLE,
///     <MyDriver as i2c::Driver>::IdInfo,
///     [
///         (of::DeviceId::new(c_str!("test,device")), ())
///     ]
/// );
///
/// impl i2c::Driver for MyDriver {
///     type IdInfo = ();
///     const I2C_ID_TABLE: Option<i2c::IdTable<Self::IdInfo>> = Some(&I2C_TABLE);
///     const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);
///     const ACPI_ID_TABLE: Option<acpi::IdTable<Self::IdInfo>> = Some(&ACPI_TABLE);
///
///     fn probe(
///         _idev: &i2c::I2cClient<Core>,
///         _id_info: Option<&Self::IdInfo>,
///     ) -> impl PinInit<Self, Error> {
///         Err(ENODEV)
///     }
///
///     fn shutdown(_idev: &i2c::I2cClient<Core>, this: Pin<&Self>) {
///     }
/// }
///```
pub trait Driver: Send {
    /// The type holding information about each device id supported by the driver.
    // TODO: Use `associated_type_defaults` once stabilized:
    //
    // ```
    // type IdInfo: 'static = ();
    // ```
    type IdInfo: 'static;

    /// The table of device ids supported by the driver.
    const I2C_ID_TABLE: Option<IdTable<Self::IdInfo>> = None;

    /// The table of OF device ids supported by the driver.
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = None;

    /// The table of ACPI device ids supported by the driver.
    const ACPI_ID_TABLE: Option<acpi::IdTable<Self::IdInfo>> = None;

    /// Whether this driver supplies simple system sleep PM callbacks.
    const HAS_PM: bool = false;

    /// I2C driver probe.
    ///
    /// Called when a new i2c client is added or discovered.
    /// Implementers should attempt to initialize the client here.
    fn probe(
        dev: &I2cClient<device::Core>,
        id_info: Option<&Self::IdInfo>,
    ) -> impl PinInit<Self, Error>;

    /// Called right after [`probe`] succeeds, once the driver's private data has been published as
    /// typed driver data (so [`device::Device::drvdata`] works on this client).
    ///
    /// This is a phase-2 hook for registering subsystems whose callbacks recover the driver data
    /// via the bound device — e.g. `rtc::Registration::register` / `hwmon::Registration::register`
    /// — which require that data to be set *before* they register. Storing such registrations in
    /// interior-mutable fields (e.g. [`kernel::sync::SetOnce`]) of the driver object lets them be
    /// created here without a raw self-pointer. Returning an error fails the probe and the core
    /// reclaims the driver data.
    ///
    /// Implementing this callback is optional; the default is a no-op.
    ///
    /// [`probe`]: Self::probe
    fn bound(client: &I2cClient<device::Bound>, this: Pin<&Self>) -> Result {
        let _ = (client, this);
        Ok(())
    }

    /// I2C driver shutdown.
    ///
    /// Called by the kernel during system reboot or power-off to allow the [`Driver`] to bring the
    /// [`I2cClient`] into a safe state. Implementing this callback is optional.
    ///
    /// Typical actions include stopping transfers, disabling interrupts, or resetting the hardware
    /// to prevent undesired behavior during shutdown.
    ///
    /// This callback is distinct from final resource cleanup, as the driver instance remains valid
    /// after it returns. Any deallocation or teardown of driver-owned resources should instead be
    /// handled in `Self::drop`.
    fn shutdown(dev: &I2cClient<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// I2C driver unbind.
    ///
    /// Called when the [`I2cClient`] is unbound from its bound [`Driver`]. Implementing this
    /// callback is optional.
    ///
    /// This callback serves as a place for drivers to perform teardown operations that require a
    /// `&Device<Core>` or `&Device<Bound>` reference. For instance, drivers may try to perform I/O
    /// operations to gracefully tear down the device.
    ///
    /// Otherwise, release operations for driver resources should be performed in `Self::drop`.
    fn unbind(dev: &I2cClient<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// System sleep suspend callback.
    fn suspend(dev: &I2cClient<device::Bound>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// System sleep resume callback.
    fn resume(dev: &I2cClient<device::Bound>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }
}

/// The i2c adapter representation.
///
/// This structure represents the Rust abstraction for a C `struct i2c_adapter`. The
/// implementation abstracts the usage of an existing C `struct i2c_adapter` that
/// gets passed from the C side
///
/// # Invariants
///
/// A [`I2cAdapter`] instance represents a valid `struct i2c_adapter` created by the C portion of
/// the kernel.
#[repr(transparent)]
pub struct I2cAdapter<Ctx: device::DeviceContext = device::Normal>(
    Opaque<bindings::i2c_adapter>,
    PhantomData<Ctx>,
);

impl<Ctx: device::DeviceContext> I2cAdapter<Ctx> {
    fn as_raw(&self) -> *mut bindings::i2c_adapter {
        self.0.get()
    }

    /// Return this adapter's nesting depth in the I2C mux tree.
    pub fn depth(&self) -> u32 {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct i2c_adapter`.
        unsafe { bindings::i2c_adapter_depth(self.as_raw()) }
    }
}

impl I2cAdapter {
    /// Returns the I2C Adapter index.
    #[inline]
    pub fn index(&self) -> i32 {
        // SAFETY: `self.as_raw` is a valid pointer to a `struct i2c_adapter`.
        unsafe { (*self.as_raw()).nr }
    }

    /// Gets pointer to an `i2c_adapter` by index.
    pub fn get(index: i32) -> Result<ARef<Self>> {
        // SAFETY: `index` must refer to a valid I2C adapter; the kernel
        // guarantees that `i2c_get_adapter(index)` returns either a valid
        // pointer or NULL. `NonNull::new` guarantees the correct check.
        let adapter = NonNull::new(unsafe { bindings::i2c_get_adapter(index) }).ok_or(ENODEV)?;

        // SAFETY: `adapter` is non-null and points to a live `i2c_adapter`.
        // `I2cAdapter` is #[repr(transparent)], so this cast is valid.
        Ok(unsafe { (&*adapter.as_ptr().cast::<I2cAdapter<device::Normal>>()).into() })
    }
}

// SAFETY: `I2cAdapter` is a transparent wrapper of a type that doesn't depend on
// `I2cAdapter`'s generic argument.
kernel::impl_device_context_deref!(unsafe { I2cAdapter });
kernel::impl_device_context_into_aref!(I2cAdapter);

// SAFETY: Instances of `I2cAdapter` are always reference-counted.
unsafe impl crate::types::AlwaysRefCounted for I2cAdapter {
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference guarantees that the refcount is non-zero.
        unsafe { bindings::i2c_get_adapter(self.index()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is non-zero.
        unsafe { bindings::i2c_put_adapter(obj.as_ref().as_raw()) }
    }
}

/// The i2c board info representation
///
/// This structure represents the Rust abstraction for a C `struct i2c_board_info` structure,
/// which is used for manual I2C client creation.
#[repr(transparent)]
pub struct I2cBoardInfo(bindings::i2c_board_info);

impl I2cBoardInfo {
    const I2C_TYPE_SIZE: usize = 20;
    /// Create a new [`I2cBoardInfo`] for a kernel driver.
    #[inline(always)]
    pub const fn new(type_: &'static CStr, addr: u16) -> Self {
        let src = type_.to_bytes_with_nul();
        build_assert!(src.len() <= Self::I2C_TYPE_SIZE, "Type exceeds 20 bytes");
        let mut i2c_board_info: bindings::i2c_board_info = pin_init::zeroed();
        let mut i: usize = 0;
        while i < src.len() {
            i2c_board_info.type_[i] = src[i];
            i += 1;
        }

        i2c_board_info.addr = addr;
        Self(i2c_board_info)
    }

    fn as_raw(&self) -> *const bindings::i2c_board_info {
        from_ref(&self.0)
    }
}

/// The i2c client representation.
///
/// This structure represents the Rust abstraction for a C `struct i2c_client`. The
/// implementation abstracts the usage of an existing C `struct i2c_client` that
/// gets passed from the C side
///
/// # Invariants
///
/// A [`I2cClient`] instance represents a valid `struct i2c_client` created by the C portion of
/// the kernel.
#[repr(transparent)]
pub struct I2cClient<Ctx: device::DeviceContext = device::Normal>(
    Opaque<bindings::i2c_client>,
    PhantomData<Ctx>,
);

impl<Ctx: device::DeviceContext> I2cClient<Ctx> {
    pub(crate) fn as_raw(&self) -> *mut bindings::i2c_client {
        self.0.get()
    }

    /// Return the client name.
    pub fn name(&self) -> &CStr {
        // SAFETY: The kernel stores a NUL-terminated name in `i2c_client::name`.
        unsafe { CStr::from_char_ptr((*self.as_raw()).name.as_ptr()) }
    }

    /// Return the client address.
    pub fn addr(&self) -> u16 {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct i2c_client`.
        unsafe { (*self.as_raw()).addr }
    }

    /// Return the client IRQ if one is assigned.
    pub fn irq(&self) -> Option<u32> {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct i2c_client`.
        let irq = unsafe { (*self.as_raw()).irq };
        if irq > 0 {
            Some(irq as u32)
        } else {
            None
        }
    }

    /// Return whether the client adapter supports all requested functionality bits.
    pub fn check_functionality(&self, functionality: u32) -> bool {
        // SAFETY: `self.as_raw()` is valid by the type invariant.
        let adapter = unsafe { (*self.as_raw()).adapter };
        if adapter.is_null() {
            return false;
        }

        // SAFETY: `adapter` is owned by the I2C core and valid while the client exists.
        let algo = unsafe { (*adapter).algo };
        if algo.is_null() {
            return false;
        }

        // SAFETY: `algo` is valid while the adapter exists.
        let Some(get_functionality) = (unsafe { (*algo).functionality }) else {
            return false;
        };

        // SAFETY: `adapter` is valid as established above.
        let supported = unsafe { get_functionality(adapter) };
        supported & functionality == functionality
    }

    /// Return the adapter that owns this client, if it is present.
    pub fn adapter(&self) -> Option<&I2cAdapter> {
        // SAFETY: `self.as_raw()` is valid by the type invariant.
        let adapter = unsafe { (*self.as_raw()).adapter };
        if adapter.is_null() {
            None
        } else {
            // SAFETY: The I2C core owns the adapter and keeps it valid while the client exists.
            Some(unsafe { &*adapter.cast::<I2cAdapter>() })
        }
    }

    /// Issue a single I2C master transmit transfer.
    ///
    /// Returns the number of bytes transferred on success.
    pub fn master_send(&self, buf: &[u8]) -> Result<usize> {
        // `i2c_transfer_buffer_flags()` builds a `struct i2c_msg` whose `len` field is `__u16`, so
        // a longer buffer would be silently truncated to 16 bits and result in a short transfer.
        if buf.len() > u16::MAX as usize {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `self.as_raw()` is a valid I2C client.
        // - `buf` is valid for reads of `buf.len()` bytes for the duration of the call.
        let ret = unsafe {
            bindings::i2c_transfer_buffer_flags(
                self.as_raw(),
                buf.as_ptr().cast_mut().cast(),
                buf.len() as i32,
                0,
            )
        };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as usize)
        }
    }

    /// Issue a single I2C master receive transfer.
    ///
    /// Returns the number of bytes transferred on success.
    pub fn master_recv(&self, buf: &mut [u8]) -> Result<usize> {
        // `i2c_transfer_buffer_flags()` builds a `struct i2c_msg` whose `len` field is `__u16`, so
        // a longer buffer would be silently truncated to 16 bits and result in a short transfer.
        if buf.len() > u16::MAX as usize {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `self.as_raw()` is a valid I2C client.
        // - `buf` is valid for writes of `buf.len()` bytes for the duration of the call.
        let ret = unsafe {
            bindings::i2c_transfer_buffer_flags(
                self.as_raw(),
                buf.as_mut_ptr().cast(),
                buf.len() as i32,
                bindings::I2C_M_RD as u16,
            )
        };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as usize)
        }
    }

    /// Issue a combined one-message write followed by a one-message read.
    ///
    /// This is the common register-pointer read sequence represented in C as two `struct i2c_msg`
    /// entries passed to `i2c_transfer()`.
    ///
    /// Returns the number of messages transferred on success (`2` when both the write and the read
    /// complete), mirroring `i2c_transfer()`'s return value rather than a byte count.
    pub fn write_read(&self, write: &[u8], read: &mut [u8]) -> Result<usize> {
        if write.len() > u16::MAX as usize || read.len() > u16::MAX as usize {
            return Err(EINVAL);
        }

        // SAFETY: `self.as_raw()` is a valid pointer to a `struct i2c_client`.
        let raw = unsafe { &*self.as_raw() };
        if raw.adapter.is_null() {
            return Err(ENODEV);
        }

        let mut msgs = [
            bindings::i2c_msg {
                addr: raw.addr,
                flags: 0,
                len: write.len() as u16,
                buf: write.as_ptr().cast_mut(),
            },
            bindings::i2c_msg {
                addr: raw.addr,
                flags: bindings::I2C_M_RD as u16,
                len: read.len() as u16,
                buf: read.as_mut_ptr(),
            },
        ];

        // SAFETY:
        // - `raw.adapter` is a live adapter owned by the I2C core while the client exists.
        // - `msgs` points to two initialized messages.
        // - `write` and `read` remain valid for the duration of the call.
        let ret =
            unsafe { bindings::i2c_transfer(raw.adapter, msgs.as_mut_ptr(), msgs.len() as i32) };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as usize)
        }
    }

    /// Read one SMBus byte-data register.
    pub fn smbus_read_byte_data(&self, command: u8) -> Result<u32> {
        let ret = unsafe { bindings::i2c_smbus_read_byte_data(self.as_raw(), command) };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as u32)
        }
    }

    /// Read one SMBus word-data register.
    pub fn smbus_read_word_data(&self, command: u8) -> Result<u16> {
        let ret = unsafe { bindings::i2c_smbus_read_word_data(self.as_raw(), command) };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as u16)
        }
    }

    /// Read one SMBus word-data register and swap the returned byte order.
    pub fn smbus_read_word_swapped(&self, command: u8) -> Result<u16> {
        Ok(self.smbus_read_word_data(command)?.swap_bytes())
    }

    /// Write one SMBus byte-data register.
    pub fn smbus_write_byte_data(&self, command: u8, value: u8) -> Result {
        to_result(unsafe { bindings::i2c_smbus_write_byte_data(self.as_raw(), command, value) })
    }

    /// Write one SMBus word-data register.
    pub fn smbus_write_word_data(&self, command: u8, value: u16) -> Result {
        to_result(unsafe { bindings::i2c_smbus_write_word_data(self.as_raw(), command, value) })
    }

    /// Write one SMBus word-data register after swapping byte order.
    pub fn smbus_write_word_swapped(&self, command: u8, value: u16) -> Result {
        self.smbus_write_word_data(command, value.swap_bytes())
    }

    /// Read an SMBus I2C block-data register.
    pub fn smbus_read_i2c_block_data(&self, command: u8, values: &mut [u8]) -> Result<usize> {
        if values.len() > bindings::I2C_SMBUS_BLOCK_MAX as usize {
            return Err(EINVAL);
        }

        let ret = unsafe {
            bindings::i2c_smbus_read_i2c_block_data(
                self.as_raw(),
                command,
                values.len() as u8,
                values.as_mut_ptr(),
            )
        };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as usize)
        }
    }

    /// Write an SMBus I2C block-data register.
    pub fn smbus_write_i2c_block_data(&self, command: u8, values: &[u8]) -> Result {
        if values.len() > bindings::I2C_SMBUS_BLOCK_MAX as usize {
            return Err(EINVAL);
        }

        to_result(unsafe {
            bindings::i2c_smbus_write_i2c_block_data(
                self.as_raw(),
                command,
                values.len() as u8,
                values.as_ptr(),
            )
        })
    }
}

impl I2cClient<device::Core> {
    /// Create an IRQ request for this client's assigned IRQ.
    pub fn irq_request(&self) -> Result<irq::IrqRequest<'_>> {
        let irq = self.irq().ok_or(ENXIO)?;
        let dev: &device::Device<device::Bound> = self.as_ref();

        // SAFETY: The IRQ number comes from the I2C core's `i2c_client::irq` field for this
        // device, so it is an interrupt source associated with `dev`.
        Ok(unsafe { irq::IrqRequest::new(dev, irq) })
    }
}

impl I2cClient<device::Bound> {
    /// Create an IRQ request for this client's assigned IRQ.
    pub fn irq_request(&self) -> Result<irq::IrqRequest<'_>> {
        let irq = self.irq().ok_or(ENXIO)?;

        // SAFETY: The IRQ number comes from the I2C core's `i2c_client::irq` field for this
        // device, so it is an interrupt source associated with this bound device.
        Ok(unsafe { irq::IrqRequest::new(self.as_ref(), irq) })
    }
}

/// Short alias used in mapping documents for I2C client callbacks.
pub type Client<Ctx = device::Normal> = I2cClient<Ctx>;

// SAFETY: `I2cClient` is a transparent wrapper of `struct i2c_client`.
// The offset is guaranteed to point to a valid device field inside `I2cClient`.
unsafe impl<Ctx: device::DeviceContext> device::AsBusDevice<Ctx> for I2cClient<Ctx> {
    const OFFSET: usize = offset_of!(bindings::i2c_client, dev);
}

// SAFETY: `I2cClient` is a transparent wrapper of a type that doesn't depend on
// `I2cClient`'s generic argument.
kernel::impl_device_context_deref!(unsafe { I2cClient });
kernel::impl_device_context_into_aref!(I2cClient);

// SAFETY: Instances of `I2cClient` are always reference-counted.
unsafe impl AlwaysRefCounted for I2cClient {
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference guarantees that the refcount is non-zero.
        unsafe { bindings::get_device(self.as_ref().as_raw()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is non-zero.
        unsafe { bindings::put_device(&raw mut (*obj.as_ref().as_raw()).dev) }
    }
}

impl<Ctx: device::DeviceContext> AsRef<device::Device<Ctx>> for I2cClient<Ctx> {
    fn as_ref(&self) -> &device::Device<Ctx> {
        let raw = self.as_raw();
        // SAFETY: By the type invariant of `Self`, `self.as_raw()` is a pointer to a valid
        // `struct i2c_client`.
        let dev = unsafe { &raw mut (*raw).dev };

        // SAFETY: `dev` points to a valid `struct device`.
        unsafe { device::Device::from_raw(dev) }
    }
}

impl<Ctx: device::DeviceContext> TryFrom<&device::Device<Ctx>> for &I2cClient<Ctx> {
    type Error = kernel::error::Error;

    fn try_from(dev: &device::Device<Ctx>) -> Result<Self, Self::Error> {
        // SAFETY: By the type invariant of `Device`, `dev.as_raw()` is a valid pointer to a
        // `struct device`.
        if unsafe { bindings::i2c_verify_client(dev.as_raw()).is_null() } {
            return Err(EINVAL);
        }

        // SAFETY: We've just verified that the type of `dev` equals to
        // `bindings::i2c_client_type`, hence `dev` must be embedded in a valid
        // `struct i2c_client` as guaranteed by the corresponding C code.
        let idev = unsafe { container_of!(dev.as_raw(), bindings::i2c_client, dev) };

        // SAFETY: `idev` is a valid pointer to a `struct i2c_client`.
        Ok(unsafe { &*idev.cast() })
    }
}

// SAFETY: A `I2cClient` is always reference-counted and can be released from any thread.
unsafe impl Send for I2cClient {}

// SAFETY: `I2cClient` can be shared among threads because all methods of `I2cClient`
// (i.e. `I2cClient<Normal>) are thread safe.
unsafe impl Sync for I2cClient {}

/// The registration of an i2c client device.
///
/// This type represents the registration of a [`struct i2c_client`]. When an instance of this
/// type is dropped, its respective i2c client device will be unregistered from the system.
///
/// # Invariants
///
/// `self.0` always holds a valid pointer to an initialized and registered
/// [`struct i2c_client`].
#[repr(transparent)]
pub struct Registration(NonNull<bindings::i2c_client>);

impl Registration {
    /// The C `i2c_new_client_device` function wrapper for manual I2C client creation.
    pub fn new<'a>(
        i2c_adapter: &I2cAdapter,
        i2c_board_info: &I2cBoardInfo,
        parent_dev: &'a device::Device<device::Bound>,
    ) -> impl PinInit<Devres<Self>, Error> + 'a {
        Devres::new(parent_dev, Self::try_new(i2c_adapter, i2c_board_info))
    }

    fn try_new(i2c_adapter: &I2cAdapter, i2c_board_info: &I2cBoardInfo) -> Result<Self> {
        // SAFETY: the kernel guarantees that `i2c_new_client_device()` returns either a valid
        // pointer or NULL. `from_err_ptr` separates errors. Following `NonNull::new`
        // checks for NULL.
        let raw_dev = from_err_ptr(unsafe {
            bindings::i2c_new_client_device(i2c_adapter.as_raw(), i2c_board_info.as_raw())
        })?;

        let dev_ptr = NonNull::new(raw_dev).ok_or(ENODEV)?;

        Ok(Self(dev_ptr))
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // SAFETY: `Drop` is only called for a valid `Registration`, which by invariant
        // always contains a non-null pointer to an `i2c_client`.
        unsafe { bindings::i2c_unregister_device(self.0.as_ptr()) }
    }
}

// SAFETY: A `Registration` of a `struct i2c_client` can be released from any thread.
unsafe impl Send for Registration {}

// SAFETY: `Registration` offers no interior mutability (no mutation through &self
// and no mutable access is exposed)
unsafe impl Sync for Registration {}

// ============================================================================
// I2C bus-controller (provider) side.
//
// The types above register an i2c *client* driver. The types below let a Rust
// driver *provide* an i2c bus: implement [`Algorithm`] (the SMBus engine) and
// register it as an adapter via [`AdapterRegistration`]. Modeled on the
// `net::phy` vtable pattern, with the driver state recovered from the
// registered `struct i2c_adapter` via `container_of!`.
// ============================================================================

/// SMBus transaction sizes — the `size` argument of [`Algorithm::smbus_xfer`].
///
/// These mirror the C `I2C_SMBUS_*` protocol constants.
pub mod smbus {
    /// `I2C_SMBUS_QUICK`: a single R/W bit, no data.
    pub const QUICK: u32 = crate::bindings::I2C_SMBUS_QUICK;
    /// `I2C_SMBUS_BYTE`: a single byte, no command.
    pub const BYTE: u32 = crate::bindings::I2C_SMBUS_BYTE;
    /// `I2C_SMBUS_BYTE_DATA`: a command byte plus a data byte.
    pub const BYTE_DATA: u32 = crate::bindings::I2C_SMBUS_BYTE_DATA;
    /// `I2C_SMBUS_WORD_DATA`: a command byte plus a data word.
    pub const WORD_DATA: u32 = crate::bindings::I2C_SMBUS_WORD_DATA;
    /// `I2C_SMBUS_PROC_CALL`: write a word, read a word back.
    pub const PROC_CALL: u32 = crate::bindings::I2C_SMBUS_PROC_CALL;
    /// `I2C_SMBUS_BLOCK_DATA`: a command byte plus a length-prefixed block.
    pub const BLOCK_DATA: u32 = crate::bindings::I2C_SMBUS_BLOCK_DATA;
    /// `I2C_SMBUS_BLOCK_PROC_CALL`: write a block, read a block back.
    pub const BLOCK_PROC_CALL: u32 = crate::bindings::I2C_SMBUS_BLOCK_PROC_CALL;
    /// `I2C_SMBUS_I2C_BLOCK_DATA`: an I2C-style block transfer.
    pub const I2C_BLOCK_DATA: u32 = crate::bindings::I2C_SMBUS_I2C_BLOCK_DATA;
}

/// `I2C_FUNC_*` capability flags returned by [`Algorithm::functionality`].
pub mod functionality {
    /// `I2C_FUNC_I2C`.
    pub const I2C: u32 = crate::bindings::I2C_FUNC_I2C;
    /// `I2C_FUNC_SMBUS_QUICK`.
    pub const SMBUS_QUICK: u32 = crate::bindings::I2C_FUNC_SMBUS_QUICK;
    /// `I2C_FUNC_SMBUS_BYTE`.
    pub const SMBUS_BYTE: u32 = crate::bindings::I2C_FUNC_SMBUS_BYTE;
    /// `I2C_FUNC_SMBUS_BYTE_DATA`.
    pub const SMBUS_BYTE_DATA: u32 = crate::bindings::I2C_FUNC_SMBUS_BYTE_DATA;
    /// `I2C_FUNC_SMBUS_WORD_DATA`.
    pub const SMBUS_WORD_DATA: u32 = crate::bindings::I2C_FUNC_SMBUS_WORD_DATA;
    /// `I2C_FUNC_SMBUS_PROC_CALL`.
    pub const SMBUS_PROC_CALL: u32 = crate::bindings::I2C_FUNC_SMBUS_PROC_CALL;
    /// `I2C_FUNC_SMBUS_BLOCK_DATA`.
    pub const SMBUS_BLOCK_DATA: u32 = crate::bindings::I2C_FUNC_SMBUS_BLOCK_DATA;
    /// `I2C_FUNC_SMBUS_I2C_BLOCK`.
    pub const SMBUS_I2C_BLOCK: u32 = crate::bindings::I2C_FUNC_SMBUS_I2C_BLOCK;
}

/// I2C adapter classes (legacy auto-probe hints) for [`AdapterRegistration::new`].
pub mod class {
    /// No class (the common case).
    pub const NONE: u32 = 0;
    /// Hardware-monitoring devices.
    pub const HWMON: u32 = crate::bindings::I2C_CLASS_HWMON;
}

/// Whether an SMBus transaction reads from or writes to the device.
///
/// Mirrors the C `read_write` argument (`I2C_SMBUS_READ` / `I2C_SMBUS_WRITE`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ReadWrite {
    /// `I2C_SMBUS_READ`.
    Read,
    /// `I2C_SMBUS_WRITE`.
    Write,
}

impl ReadWrite {
    fn from_raw(v: kernel::ffi::c_char) -> Self {
        if v as u32 == bindings::I2C_SMBUS_READ {
            ReadWrite::Read
        } else {
            ReadWrite::Write
        }
    }
}

/// Safe view over a C `union i2c_smbus_data` for an in-progress SMBus transfer.
///
/// For a write transaction the relevant member holds the value to send; for a
/// read transaction the driver stores the result into the matching member.
#[repr(transparent)]
pub struct SmbusData(Opaque<bindings::i2c_smbus_data>);

impl SmbusData {
    /// # Safety
    ///
    /// `ptr` must point to a valid `i2c_smbus_data` for the duration of `'a`,
    /// and must not be aliased for that duration.
    unsafe fn from_raw<'a>(ptr: *mut bindings::i2c_smbus_data) -> &'a mut Self {
        // SAFETY: `SmbusData` is `#[repr(transparent)]` over `Opaque<i2c_smbus_data>`;
        // the caller guarantees `ptr` is valid and unaliased for `'a`.
        unsafe { &mut *ptr.cast::<Self>() }
    }

    /// Reads the `byte` member.
    pub fn byte(&self) -> u8 {
        // SAFETY: `byte` is always a valid read of the union's first byte.
        unsafe { (*self.0.get()).byte }
    }

    /// Writes the `byte` member.
    pub fn set_byte(&mut self, value: u8) {
        // SAFETY: writing the `byte` member of a valid `i2c_smbus_data`.
        unsafe { (*self.0.get()).byte = value };
    }

    /// Reads the `word` member.
    pub fn word(&self) -> u16 {
        // SAFETY: `word` is a valid member of a valid `i2c_smbus_data`.
        unsafe { (*self.0.get()).word }
    }

    /// Writes the `word` member.
    pub fn set_word(&mut self, value: u16) {
        // SAFETY: writing the `word` member of a valid `i2c_smbus_data`.
        unsafe { (*self.0.get()).word = value };
    }

    /// Returns the `block` member (`block[0]` is the length).
    pub fn block(&self) -> &[u8; 34] {
        // SAFETY: `block` is a valid member of a valid `i2c_smbus_data`.
        unsafe { &(*self.0.get()).block }
    }

    /// Returns a mutable reference to the `block` member (`block[0]` is the length).
    pub fn block_mut(&mut self) -> &mut [u8; 34] {
        // SAFETY: `block` is a valid member of a valid `i2c_smbus_data`.
        unsafe { &mut (*self.0.get()).block }
    }
}

/// The SMBus algorithm a Rust i2c *bus controller* implements.
///
/// This is the provider counterpart of [`Driver`]: instead of consuming an i2c
/// bus, the implementer *is* the bus. Register it with [`AdapterRegistration`].
/// The methods mirror the relevant fields of C `struct i2c_algorithm`.
#[vtable]
pub trait Algorithm {
    /// Issues a single SMBus transaction.
    ///
    /// Mirrors `i2c_algorithm::smbus_xfer`. Return `Ok(())` on success or an
    /// error (e.g. [`EOPNOTSUPP`], [`ETIMEDOUT`]) on failure.
    fn smbus_xfer(
        &self,
        addr: u16,
        flags: u16,
        read_write: ReadWrite,
        command: u8,
        size: u32,
        data: &mut SmbusData,
    ) -> Result {
        let _ = (addr, flags, read_write, command, size, data);
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    /// Returns the `I2C_FUNC_*` capability mask of this adapter.
    ///
    /// Mirrors `i2c_algorithm::functionality`.
    fn functionality(&self) -> u32 {
        build_error!(VTABLE_DEFAULT_ERROR)
    }
}

/// Builds a `struct i2c_algorithm` vtable from an [`Algorithm`] implementation.
const fn create_algorithm<T: Algorithm>() -> bindings::i2c_algorithm {
    bindings::i2c_algorithm {
        smbus_xfer: if T::HAS_SMBUS_XFER {
            Some(AdapterRegistration::<T>::smbus_xfer_callback)
        } else {
            None
        },
        functionality: if T::HAS_FUNCTIONALITY {
            Some(AdapterRegistration::<T>::functionality_callback)
        } else {
            None
        },
        // SAFETY: The rest is zeroed out, leaving every other `Option<fn>` as `None`
        // and the I2C-level `xfer` union NULL (SMBus-only adapter).
        ..unsafe { core::mem::MaybeUninit::<bindings::i2c_algorithm>::zeroed().assume_init() }
    }
}

/// Registration of a Rust-provided i2c bus (`struct i2c_adapter`).
///
/// Owns the C `i2c_adapter`, its generated [`Algorithm`] vtable and the driver
/// state `T`. On creation it registers the adapter with `i2c_add_adapter`; when
/// dropped it unregisters it with `i2c_del_adapter`. Store it (directly or in a
/// wrapper) as the driver's pinned private data so the kernel never sees a
/// dangling adapter.
///
/// # Invariants
///
/// Once an instance exists, `self.adapter` is a registered `struct i2c_adapter`.
#[pin_data(PinnedDrop)]
pub struct AdapterRegistration<T: Algorithm> {
    #[pin]
    adapter: Opaque<bindings::i2c_adapter>,
    #[pin]
    algorithm: Opaque<bindings::i2c_algorithm>,
    #[pin]
    data: T,
}

impl<T: Algorithm> AdapterRegistration<T> {
    /// Creates and registers an i2c adapter backed by `data`.
    ///
    /// `parent` is the device that owns the bus (e.g. the PCI device), `name`
    /// labels the adapter (copied into the fixed `name[48]` field) and `class`
    /// is an [`class`] hint (usually [`class::NONE`]).
    pub fn new<Ctx: device::DeviceContext>(
        parent: &device::Device<Ctx>,
        name: &CStr,
        class: u32,
        data: impl PinInit<T, Error>,
    ) -> impl PinInit<Self, Error> {
        let parent_raw = parent.as_raw();
        // Copy the name into an owned, fixed buffer so the returned initializer does
        // not borrow `name` (the C `name` field is likewise a fixed `[c_char; 48]`).
        let mut name_buf = [0u8; 48];
        let src = name.to_bytes_with_nul();
        let n = core::cmp::min(src.len(), 47);
        name_buf[..n].copy_from_slice(&src[..n]);

        try_pin_init!(Self {
            data <- data,
            algorithm <- Opaque::ffi_init(move |slot: *mut bindings::i2c_algorithm| {
                // SAFETY: `slot` is a valid, uninitialized `i2c_algorithm`.
                unsafe { slot.write(create_algorithm::<T>()) };
            }),
            adapter <- Opaque::try_ffi_init(move |slot: *mut bindings::i2c_adapter| -> Result {
                // SAFETY: `slot` is a valid, uninitialized `i2c_adapter`; zero it, then
                // fill the fields the i2c core expects before `i2c_add_adapter`.
                unsafe {
                    slot.write(core::mem::zeroed());
                    (*slot).class = class;
                    (*slot).dev.parent = parent_raw;

                    // NOTE: `owner` is left NULL. C providers set `adap->owner =
                    // THIS_MODULE` so the i2c core's `try_module_get` pins the providing
                    // module while a client holds the adapter. The `pci::Driver` framework
                    // does not thread the module owner into `probe`, so that pinning is not
                    // wired up here; the adapter's lifetime is instead tied to the pinned
                    // registration stored as driver data, which `i2c_del_adapter`s on unbind.
                    // A future increment should thread `&'static ThisModule` through `new`.

                    core::ptr::copy_nonoverlapping(
                        name_buf.as_ptr(),
                        (*slot).name.as_mut_ptr().cast::<u8>(),
                        48,
                    );

                    // `algorithm` is initialized before `adapter`, so this points
                    // the adapter at its (now address-stable) sibling vtable.
                    let reg: *mut Self =
                        container_of!(slot.cast::<Opaque<bindings::i2c_adapter>>(), Self, adapter);
                    (*slot).algo = (*reg).algorithm.get() as *const bindings::i2c_algorithm;
                }

                // SAFETY: `slot` is now a fully-initialized `i2c_adapter`. If this
                // fails, the field is treated as uninitialized and `PinnedDrop`
                // does not run, so no unbalanced `i2c_del_adapter` occurs.
                to_result(unsafe { bindings::i2c_add_adapter(slot) })
            }),
        })
    }

    unsafe extern "C" fn smbus_xfer_callback(
        adap: *mut bindings::i2c_adapter,
        addr: u16,
        flags: kernel::ffi::c_ushort,
        read_write: kernel::ffi::c_char,
        command: u8,
        size: kernel::ffi::c_int,
        data: *mut bindings::i2c_smbus_data,
    ) -> kernel::ffi::c_int {
        // SAFETY: `adap` is the `adapter` field of a live `AdapterRegistration<T>`.
        let reg =
            unsafe { &*container_of!(adap.cast::<Opaque<bindings::i2c_adapter>>(), Self, adapter) };
        // SAFETY: For the duration of this call `data` is a valid, unaliased `i2c_smbus_data`.
        let data = unsafe { SmbusData::from_raw(data) };

        from_result(|| {
            T::smbus_xfer(
                &reg.data,
                addr,
                flags,
                ReadWrite::from_raw(read_write),
                command,
                size as u32,
                data,
            )?;
            Ok(0)
        })
    }

    unsafe extern "C" fn functionality_callback(adap: *mut bindings::i2c_adapter) -> u32 {
        // SAFETY: `adap` is the `adapter` field of a live `AdapterRegistration<T>`.
        let reg =
            unsafe { &*container_of!(adap.cast::<Opaque<bindings::i2c_adapter>>(), Self, adapter) };
        T::functionality(&reg.data)
    }

    /// Returns a shared reference to the driver state behind this adapter.
    pub fn data(&self) -> &T {
        &self.data
    }
}

#[pinned_drop]
impl<T: Algorithm> PinnedDrop for AdapterRegistration<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: By the type invariant, `self.adapter` was registered via
        // `i2c_add_adapter` in `new`.
        unsafe { bindings::i2c_del_adapter(self.adapter.get()) };
    }
}

// SAFETY: `AdapterRegistration` only exposes shared access to its data; the C
// `i2c_adapter` it owns may be used from any thread, and `i2c_del_adapter` may be
// called from any thread.
unsafe impl<T: Algorithm + Send + Sync> Send for AdapterRegistration<T> {}
// SAFETY: All access to the inner `i2c_adapter`/state goes through `&self` and is
// synchronized by the i2c core (which serializes transfers per adapter).
unsafe impl<T: Algorithm + Send + Sync> Sync for AdapterRegistration<T> {}
