// SPDX-License-Identifier: GPL-2.0

//! Abstractions for the virtio bus.
//!
//! C header: [`include/linux/virtio.h`](srctree/include/linux/virtio.h)
//!
//! This wraps the *driver-facing* virtio API only. The virtio transports
//! (`virtio_pci_modern.c`, `virtio_mmio.c`) and the vring engine
//! (`virtio_ring.c`) stay upstream C; a Rust driver consumes the
//! `virtio_config_ops` they install and the `virtqueue` API they provide.

use crate::{
    alloc, bindings,
    cpumask::Cpumask,
    device,
    device_id::RawDeviceId,
    dma, driver,
    error::{from_result, to_result, Error, Result},
    net::device::{TxPacket, XdpFrame},
    new_spinlock,
    page::{Page, PAGE_SIZE},
    prelude::*,
    str::CStr,
    sync::{aref::AlwaysRefCounted, Arc, SpinLock},
    types::{ForeignOwnable, Opaque},
    ThisModule,
};
use core::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem::{offset_of, MaybeUninit},
    ops::Range,
    pin::Pin,
    ptr::{addr_of_mut, NonNull},
};

/// An adapter for the registration of virtio drivers.
pub struct Adapter<T: Driver>(T);

// SAFETY: A call to `unregister` for a given instance of `RegType` is guaranteed to be valid if
// a preceding call to `register` has been successful.
unsafe impl<T: Driver + 'static> driver::RegistrationOps for Adapter<T> {
    type RegType = bindings::virtio_driver;

    unsafe fn register(
        drv: &Opaque<Self::RegType>,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        // SAFETY: It's safe to set the fields of `struct virtio_driver` on initialization. The
        // storage was zero-initialized by `Registration::new`, so unset callback pointers remain
        // NULL (the virtio core treats NULL callbacks as absent).
        unsafe {
            (*drv.get()).driver.name = name.as_char_ptr();
            (*drv.get()).id_table = T::ID_TABLE.as_ptr();
            // Driver-declared feature tables (modern + optional legacy). The C core's
            // `virtio_dev_probe` ACKs these against the device's offered features during
            // negotiation (ACK/DRIVER/FEATURES_OK), before calling `probe`. `None` legacy ⇒ the
            // core reuses the modern table (C's default when `feature_table_legacy` is NULL).
            (*drv.get()).feature_table = T::FEATURE_TABLE.as_ptr();
            (*drv.get()).feature_table_size = T::FEATURE_TABLE.len() as u32;
            let legacy = T::FEATURE_TABLE_LEGACY.unwrap_or(T::FEATURE_TABLE);
            (*drv.get()).feature_table_legacy = legacy.as_ptr();
            (*drv.get()).feature_table_size_legacy = legacy.len() as u32;
            (*drv.get()).validate = Some(Self::validate_callback);
            (*drv.get()).probe = Some(Self::probe_callback);
            (*drv.get()).remove = Some(Self::remove_callback);
            (*drv.get()).scan = Some(Self::scan_callback);
            (*drv.get()).config_changed = Some(Self::config_changed_callback);
            if T::HAS_PM {
                (*drv.get()).freeze = Some(Self::freeze_callback);
                (*drv.get()).restore = Some(Self::restore_callback);
            }
        }

        // SAFETY: `drv` is guaranteed to be a valid `RegType`.
        to_result(unsafe { bindings::__register_virtio_driver(drv.get(), module.0) })
    }

    unsafe fn unregister(drv: &Opaque<Self::RegType>) {
        // SAFETY: `drv` is guaranteed to be a valid `RegType`.
        unsafe { bindings::unregister_virtio_driver(drv.get()) }
    }
}

impl<T: Driver + 'static> Adapter<T> {
    /// `validate` trampoline. The core calls this *before* `probe` (and before `vdev->priv` is set),
    /// so it takes no driver data; dispatches to [`Driver::validate`] (default accepts). Mirrors C's
    /// `virtio_dev_probe` calling `drv->validate` after feature negotiation, before `drv->probe`.
    extern "C" fn validate_callback(vdev: *mut bindings::virtio_device) -> c_int {
        // SAFETY: The virtio bus only ever calls validate with a valid `struct virtio_device`.
        //
        // INVARIANT: `vdev` is valid for the duration of `validate_callback()`.
        let vdev = unsafe { &*vdev.cast::<Device<device::CoreInternal>>() };
        from_result(|| {
            T::validate(vdev)?;
            Ok(0)
        })
    }

    extern "C" fn probe_callback(vdev: *mut bindings::virtio_device) -> c_int {
        // SAFETY: The virtio bus only ever calls probe with a valid `struct virtio_device`.
        //
        // INVARIANT: `vdev` is valid for the duration of `probe_callback()`.
        let vdev = unsafe { &*vdev.cast::<Device<device::CoreInternal>>() };

        from_result(|| {
            let data = T::probe(vdev);
            // Store driver-private data in `vdev->priv` (the C convention; the vq trampoline
            // recovers it via `vq->vdev->priv`).
            if let Err(error) = vdev.set_priv(data) {
                T::probe_error(vdev);
                return Err(error);
            }
            // Bring the device to DRIVER_OK + start it, now that `vdev->priv` is set (the vq
            // trampoline recovers the driver data via `vdev->priv`, so this must run after
            // `set_priv`). Mirrors C `virtio_device_ready` + the initial `request_entropy` that
            // run at the end of `probe_common`, before the core calls `scan`. The Adapter does the
            // (unsafe) priv recovery here so the driver's `start` receives a safe `Pin<&Self>`.
            // SAFETY: `set_priv` above stored a `Pin<KBox<T>>` in `vdev->priv`; borrowing it as
            // `Pin<&T>` for the duration of this call is valid.
            let this = unsafe { vdev.priv_borrow::<T>() };
            if let Err(error) = T::start_result(vdev, this.as_ref()) {
                // SAFETY: `set_priv` above installed exactly one pinned `T`.
                // A failed post-probe start is not followed by the core's
                // remove callback, so unwind the driver's resources here.
                let data = unsafe { vdev.priv_obtain::<T>() };
                T::unbind(vdev, data.as_ref());
                drop(data);
                return Err(error);
            }
            Ok(0)
        })
    }

    extern "C" fn remove_callback(vdev: *mut bindings::virtio_device) {
        // SAFETY: The virtio bus only ever calls remove with a valid `struct virtio_device`.
        let vdev = unsafe { &*vdev.cast::<Device<device::CoreInternal>>() };

        // SAFETY: `remove_callback` only runs after a successful `probe_callback`, so `set_priv()`
        // has stored a `Pin<KBox<T>>` in `vdev->priv`.
        let data = unsafe { vdev.priv_obtain::<T>() };

        T::unbind(vdev, data.as_ref());
    }

    extern "C" fn scan_callback(vdev: *mut bindings::virtio_device) {
        // SAFETY: The virtio bus only ever calls scan with a valid `struct virtio_device`.
        let vdev = unsafe { &*vdev.cast::<Device<device::CoreInternal>>() };

        // SAFETY: `scan` runs after a successful `probe`, so `vdev->priv` is valid.
        let data = unsafe { vdev.priv_borrow::<T>() };

        T::scan(vdev, data.as_ref());
    }

    /// `config_changed` trampoline. The core calls this (after `probe`, while the driver is bound)
    /// when the device raises a config-change interrupt. Recovers `&T` from `vdev->priv` and
    /// dispatches to [`Driver::config_changed`] (default no-op). Mirrors C `drv->config_changed`.
    extern "C" fn config_changed_callback(vdev: *mut bindings::virtio_device) {
        // SAFETY: The virtio bus only ever calls config_changed with a valid, bound
        // `struct virtio_device` (priv is set).
        let vdev = unsafe { &*vdev.cast::<Device<device::CoreInternal>>() };
        // SAFETY: `config_changed` runs while the driver is bound, so `vdev->priv` is valid.
        let data = unsafe { vdev.priv_borrow::<T>() };
        T::config_changed(vdev, data.as_ref());
    }

    /// System-sleep freeze trampoline. It is installed only when [`Driver::HAS_PM`] is true.
    extern "C" fn freeze_callback(vdev: *mut bindings::virtio_device) -> c_int {
        // SAFETY: The virtio PM core calls freeze only for a successfully bound device, before
        // removing the driver's private data.
        let vdev = unsafe { &*vdev.cast::<Device<device::CoreInternal>>() };
        // SAFETY: A successful probe stored `T` in `vdev->priv`, which remains live across PM.
        let data = unsafe { vdev.priv_borrow::<T>() };
        from_result(|| {
            T::freeze(vdev, data.as_ref())?;
            Ok(0)
        })
    }

    /// System-sleep restore trampoline. It is installed only when [`Driver::HAS_PM`] is true.
    extern "C" fn restore_callback(vdev: *mut bindings::virtio_device) -> c_int {
        // SAFETY: The virtio PM core calls restore only for a successfully bound device whose
        // private data survived freeze.
        let vdev = unsafe { &*vdev.cast::<Device<device::CoreInternal>>() };
        // SAFETY: `vdev->priv` still contains the `T` installed by probe.
        let data = unsafe { vdev.priv_borrow::<T>() };
        from_result(|| {
            T::restore(vdev, data.as_ref())?;
            Ok(0)
        })
    }

    /// vq notification trampoline. The transport calls this (in IRQ context) when the device
    /// notifies a virtqueue; it recovers `&T` from `vq->vdev->priv` and dispatches to the safe
    /// [`Driver::vq_callback`], so the driver writes no `unsafe extern "C"` callback of its own.
    unsafe extern "C" fn vq_callback(vq: *mut bindings::virtqueue) {
        // SAFETY: The transport only calls this with a valid registered `struct virtqueue`, whose
        // `vdev->priv` holds our `Pin<KBox<T>>` (a live registration ⇒ `T` is alive).
        let vdev = unsafe { Device::from_vq(vq) };
        let data = unsafe { vdev.priv_borrow::<T>() };
        // SAFETY: `vq` is a valid registered virtqueue for the lifetime of this call.
        let vq = unsafe { VirtQueue::borrow(vq) };
        data.as_ref().vq_callback(&vq);
    }
}

impl<T: QueueRecycle + 'static> Adapter<T> {
    /// Synchronous queue-reset/resize buffer-recycling trampoline.
    unsafe extern "C" fn vq_recycle_callback(vq: *mut bindings::virtqueue, token: *mut c_void) {
        // SAFETY: virtio_ring invokes this callback synchronously with a live queue belonging to
        // a bound device. The Adapter stored `T` in `vdev->priv` before queues became active.
        let vdev = unsafe { Device::from_vq(vq) };
        let data = unsafe { vdev.priv_borrow::<T>() };
        // SAFETY: The callback argument is the live queue currently being reset or resized.
        let vq = unsafe { VirtQueue::borrow(vq) };
        data.as_ref().recycle_buffer(&vq, token);
    }

    /// Synchronous end-of-recycling trampoline.
    unsafe extern "C" fn vq_recycle_done_callback(vq: *mut bindings::virtqueue) {
        // SAFETY: Same bound-device and queue lifetime as `vq_recycle_callback`.
        let vdev = unsafe { Device::from_vq(vq) };
        let data = unsafe { vdev.priv_borrow::<T>() };
        // SAFETY: The callback argument is live for this synchronous invocation.
        let vq = unsafe { VirtQueue::borrow(vq) };
        data.as_ref().recycle_done(&vq);
    }
}

/// Declares a kernel module that exposes a single virtio driver.
#[macro_export]
macro_rules! module_virtio_driver {
    ($($f:tt)*) => {
        $crate::module_driver!(<T>, $crate::virtio::Adapter<T>, { $($f)* });
    };
}

/// Abstraction for `bindings::virtio_device_id`.
///
/// `struct virtio_device_id` has only `{device, vendor}` and **no** `driver_data` field, so the ID
/// table is built with `IdArray::new_without_index` and `probe` receives no per-id info (mirroring
/// C's `int (*probe)(struct virtio_device *)`).
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::virtio_device_id);

/// Well-known virtio device/vendor id values (from `include/uapi/linux/virtio_ids.h` +
/// `linux/mod_devicetable.h`), exposed as typed constants so drivers need not reach into
/// `bindings::` to build an [`IdTable`].
pub mod device_id {
    use crate::bindings;
    /// virtio memory-balloon device id (`VIRTIO_ID_BALLOON`).
    pub const BALLOON: u32 = bindings::VIRTIO_ID_BALLOON as u32;
    /// virtio RNG device id (`VIRTIO_ID_RNG`).
    pub const RNG: u32 = bindings::VIRTIO_ID_RNG as u32;
    /// Wildcard vendor/device id (`VIRTIO_DEV_ANY_ID`).
    pub const ANY: u32 = bindings::VIRTIO_DEV_ANY_ID as u32;
}

/// Well-known transport feature bits exposed without a driver-side
/// `bindings::` dependency.
pub mod feature {
    use crate::bindings;

    /// Device uses the platform DMA-access mechanism.
    pub const ACCESS_PLATFORM: u32 = bindings::VIRTIO_F_ACCESS_PLATFORM as u32;
}

impl DeviceId {
    /// Create a new [`DeviceId`] from a virtio device id and vendor id.
    #[inline]
    pub const fn new(device: u32, vendor: u32) -> Self {
        // SAFETY: FFI type is valid to be zero-initialized; both fields are then set.
        let _zero: bindings::virtio_device_id = unsafe { core::mem::zeroed() };
        let _ = _zero;
        Self(bindings::virtio_device_id { device, vendor })
    }
}

// SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `virtio_device_id` and does not add
// additional invariants, so it's safe to transmute to `RawType`.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::virtio_device_id;
}

/// IdTable type for virtio drivers.
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// Create a virtio `IdTable` with its alias for modpost.
///
/// Uses `IdArray::new_without_index` because `struct virtio_device_id` has no `driver_data`.
#[macro_export]
macro_rules! virtio_device_table {
    ($table_name:ident, $module_table_name:ident, $id_info_type: ty, $table_data: expr) => {
        const $table_name: $crate::device_id::IdArray<
            $crate::virtio::DeviceId,
            $id_info_type,
            { $table_data.len() },
        > = $crate::device_id::IdArray::new_without_index($table_data);

        $crate::module_device_table!("virtio", $module_table_name, $table_name);
    };
}

/// The virtio driver trait.
///
/// `probe` runs after the core has set ACKNOWLEDGE/DRIVER/FEATURES_OK; the driver finds its
/// virtqueues and calls [`Device::device_ready`] (DRIVER_OK) there. `scan` runs after a successful
/// `probe` and is the place to register with the target subsystem (C `virtio-rng` registers
/// `hwrng` in `scan`). Queue and configuration callbacks may execute concurrently on different
/// CPUs, so implementations must be [`Sync`].
pub trait Driver: Sized + Send + Sync + 'static {
    /// The type holding information about each device id supported by the driver.
    type IdInfo: 'static;

    /// The table of device ids supported by the driver.
    const ID_TABLE: IdTable<Self::IdInfo>;

    /// Feature bits this driver offers to negotiate (modern transport). Mirrors C
    /// `virtio_driver.feature_table`; the C core ACKs these against the device's offered features
    /// during `virtio_dev_probe`. Empty by default (drivers with no driver-specific feature bits,
    /// e.g. virtio-rng/virtio-input).
    const FEATURE_TABLE: &'static [u32] = &[];

    /// Legacy feature bits (only for drivers that distinguish a legacy feature set). `None` ⇒ the
    /// core reuses [`FEATURE_TABLE`](Self::FEATURE_TABLE) for legacy too (C's default when
    /// `feature_table_legacy` is NULL). `Some(_)` when the driver has legacy-only features (e.g.
    /// virtio-blk, where `VIRTIO_BLK_F_ZONED` is modern-only).
    const FEATURE_TABLE_LEGACY: Option<&'static [u32]> = None;

    /// Whether to install the system-sleep `freeze` and `restore` callbacks. Drivers that set this
    /// must quiesce and reconstruct their queues in the corresponding methods below. Keeping this
    /// false preserves the C convention of NULL PM callbacks.
    const HAS_PM: bool = false;

    /// Virtio driver probe.
    fn probe(dev: &Device<device::Core>) -> impl PinInit<Self, Error>;

    /// Release resources created while constructing the probe initializer when pinned driver-data
    /// allocation or initialization fails before `vdev->priv` can be installed.
    ///
    /// The callback has no driver data by construction. Drivers that discover virtqueues or
    /// acquire other device-owned resources before returning their initializer must override it.
    fn probe_error(dev: &Device<device::Core>) {
        let _ = dev;
    }

    /// Validate the device before `probe` (after the core has negotiated features). Mirrors C
    /// `virtio_driver.validate`. Default accepts; override to reject devices missing required
    /// features (e.g. virtio-input rejects pre-`VIRTIO_F_VERSION_1` devices). Called with no driver
    /// data (`vdev->priv` is not set yet).
    fn validate(dev: &Device<device::Core>) -> Result {
        let _ = dev;
        Ok(())
    }

    /// Called (in IRQ context) when the device notifies a virtqueue. The Adapter's trampoline
    /// recovers `&self` from `vdev->priv` and calls this, so the driver writes no `unsafe extern "C"`
    /// callback. Mirrors C `virtio-rng`'s `random_recv_done` (which the transport invokes as the
    /// vq's `callback`). A single-vq driver receives its only vq here; a multi-vq driver
    /// distinguishes by the `vq` handle. Default is a no-op.
    fn vq_callback(&self, vq: &VirtQueue) {
        let _ = vq;
    }

    /// Virtio driver start (optional). Called after [`probe`](Self::probe) once the private data is
    /// stored in `vdev->priv`. Use this to bring the device to `DRIVER_OK` and begin interacting
    /// with it (the vq trampoline can now recover the driver data). Mirrors the tail of C's
    /// `probe_common` (`virtio_device_ready` + the initial request), which runs before the core
    /// calls `scan`.
    fn start(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Fallible post-probe start hook.
    ///
    /// The default preserves existing drivers by invoking [`Self::start`]. A
    /// driver whose first device interaction can fail may override this hook;
    /// the Adapter then calls [`Self::unbind`] and releases private data before
    /// returning the probe error to the virtio core.
    fn start_result(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        Self::start(dev, this);
        Ok(())
    }

    /// Virtio driver unbind (optional). Called before the private data is dropped on removal.
    fn unbind(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Virtio driver scan (optional). Called after a successful `probe`.
    fn scan(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Config-space change notification (optional). Called after `probe`, while bound, when the
    /// device raises a config-change interrupt (e.g. virtio-blk capacity change). Mirrors C
    /// `virtio_driver.config_changed`. Default no-op.
    fn config_changed(dev: &Device<device::Core>, this: Pin<&Self>) {
        let _ = (dev, this);
    }

    /// Quiesce the device for system suspend or hibernation. Called only when [`Self::HAS_PM`] is
    /// true, after the virtio core disables configuration-change delivery.
    fn freeze(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }

    /// Recreate queues and driver state after system resume. Called only when [`Self::HAS_PM`] is
    /// true, after the core has reset the device and renegotiated features.
    fn restore(dev: &Device<device::Core>, this: Pin<&Self>) -> Result {
        let _ = (dev, this);
        Ok(())
    }
}

/// Driver-owned recycling of buffers detached synchronously by queue reset or resize.
///
/// The virtio ring passes back exactly the opaque tokens previously submitted by the driver.
/// Implementations distinguish queues by [`VirtQueue`] identity and recover the token through a
/// typed ownership helper; all C callback and private-data recovery stays inside the Adapter.
pub trait QueueRecycle: Driver {
    /// Reclaim one token detached from `vq`.
    fn recycle_buffer(self: Pin<&Self>, vq: &VirtQueue, token: *mut c_void);

    /// Called after every detached token has been returned, when requested by reset/resize.
    fn recycle_done(self: Pin<&Self>, vq: &VirtQueue) {
        let _ = (self, vq);
    }
}

/// Per-virtqueue creation info for [`Device::find_vqs`]: a name, whether to install the Adapter's
/// safe callback trampoline, and whether to request a context token. Mirrors C
/// `struct virtqueue_info { name, callback, ctx }`. Callback-enabled queues dispatch to
/// [`Driver::vq_callback`]; callback-free queues mirror a C `NULL` callback and never invoke the
/// driver from virtqueue interrupt handling.
pub struct VqInfo {
    name: &'static CStr,
    callback: bool,
    ctx: bool,
}

impl VqInfo {
    /// Create callback-enabled virtqueue creation info. `ctx` requests a context token
    /// (retrievable via [`VirtQueue::get_buf_ctx`]); most drivers pass `false`.
    pub const fn new(name: &'static CStr, ctx: bool) -> Self {
        Self {
            name,
            callback: true,
            ctx,
        }
    }

    /// Create callback-free virtqueue creation info, equivalent to a C `virtqueue_info` whose
    /// `callback` field is `NULL`.
    ///
    /// Use this only when the driver polls or otherwise does not consume virtqueue interrupts;
    /// the Adapter will not dispatch [`Driver::vq_callback`] for this queue.
    pub const fn without_callback(name: &'static CStr, ctx: bool) -> Self {
        Self {
            name,
            callback: false,
            ctx,
        }
    }

    /// The virtqueue name (C string, e.g. `c"events"`).
    pub fn name(&self) -> &'static CStr {
        self.name
    }
}

/// The virtio device representation.
///
/// # Invariants
///
/// A [`Device`] instance represents a valid `struct virtio_device` created by the C virtio core.
#[repr(transparent)]
pub struct Device<Ctx: device::DeviceContext = device::Normal>(
    Opaque<bindings::virtio_device>,
    PhantomData<Ctx>,
);

impl<Ctx: device::DeviceContext> Device<Ctx> {
    #[inline]
    fn as_raw(&self) -> *mut bindings::virtio_device {
        self.0.get()
    }

    /// Byte order used by this negotiated virtio transport/configuration.
    pub fn is_little_endian(&self) -> bool {
        // SAFETY: `self.as_raw()` is a live virtio device.
        unsafe { bindings::virtio_is_little_endian(self.as_raw()) }
    }

    /// Convert a native `u16` to the negotiated virtio byte order.
    pub fn cpu_to_virtio16(&self, value: u16) -> u16 {
        if self.is_little_endian() {
            value.to_le()
        } else {
            value.to_be()
        }
    }

    /// Convert a native `u32` to the negotiated virtio byte order.
    pub fn cpu_to_virtio32(&self, value: u32) -> u32 {
        if self.is_little_endian() {
            value.to_le()
        } else {
            value.to_be()
        }
    }

    /// Convert a native `u64` to the negotiated virtio byte order.
    pub fn cpu_to_virtio64(&self, value: u64) -> u64 {
        if self.is_little_endian() {
            value.to_le()
        } else {
            value.to_be()
        }
    }

    /// Mark the underlying device's wakeup source active.
    pub fn stay_awake(&self) {
        // SAFETY: `self.as_raw()` is live and embeds a valid `struct device`.
        unsafe { bindings::pm_stay_awake(core::ptr::addr_of_mut!((*self.as_raw()).dev)) };
    }

    /// Release one active wakeup-source hold on the underlying device.
    pub fn relax(&self) {
        // SAFETY: `self.as_raw()` is live and embeds a valid `struct device`.
        unsafe { bindings::pm_relax(core::ptr::addr_of_mut!((*self.as_raw()).dev)) };
    }

    /// Configure whether the underlying device is wakeup-capable.
    pub fn set_wakeup_capable(&self, capable: bool) {
        // SAFETY: `self.as_raw()` is live and embeds a valid `struct device`.
        unsafe {
            bindings::device_set_wakeup_capable(
                core::ptr::addr_of_mut!((*self.as_raw()).dev),
                capable,
            )
        };
    }

    /// Whether the transport provides readable device configuration space.
    pub fn has_config_access(&self) -> bool {
        // SAFETY: A live virtio device has a valid config-operations table; reading the optional
        // function pointer has no side effects and matches the core driver's validation check.
        unsafe { (*(*self.as_raw()).config).get.is_some() }
    }

    /// Return the transport-specific bus name used by device diagnostics and ethtool.
    pub fn bus_name(&self) -> &CStr {
        // SAFETY: A live virtio device has a live config table. The optional transport callback
        // returns a transport-owned NUL-terminated string that remains valid with the device.
        let name = unsafe {
            let config = (*self.as_raw()).config;
            match (*config).bus_name {
                Some(bus_name) => bus_name(self.as_raw()),
                None => return crate::c_str!("virtio"),
            }
        };
        if name.is_null() {
            crate::c_str!("virtio")
        } else {
            // SAFETY: Guaranteed by the virtio transport `bus_name` callback contract.
            unsafe { CStr::from_char_ptr(name) }
        }
    }

    /// Store driver-private data in `vdev->priv`. Mirrors C's `vdev->priv = data`.
    ///
    /// Crate-private: only the Adapter stores the driver data (the driver returns it from `probe`).
    pub(crate) fn set_priv<T: 'static>(&self, data: impl PinInit<T, Error>) -> Result {
        let data = KBox::pin_init(data, GFP_KERNEL)?;
        let ptr = data.into_foreign();
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `priv` is a plain `void *`.
        unsafe { (*self.as_raw()).priv_ = ptr };
        Ok(())
    }

    /// Take ownership of the private data in `vdev->priv`.
    ///
    /// # Safety
    ///
    /// Must only be called once after [`Device::set_priv`], and `T` must match.
    pub unsafe fn priv_obtain<T: 'static>(&self) -> Pin<KBox<T>> {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        let ptr = unsafe { (*self.as_raw()).priv_ };
        // SAFETY: Clear `priv` so the slot is not reclaimed twice.
        unsafe { (*self.as_raw()).priv_ = core::ptr::null_mut() };
        // SAFETY: `ptr` was stored by a preceding `set_priv()` call.
        unsafe { Pin::<KBox<T>>::from_foreign(ptr.cast()) }
    }

    /// Borrow the private data in `vdev->priv`.
    ///
    /// Crate-private: only the Adapter's callbacks/trampolines recover the driver data (so the
    /// driver itself never performs `priv` recovery — mirroring how `pci::Adapter` alone calls
    /// `drvdata_obtain`).
    ///
    /// # Safety
    ///
    /// Must only be called after [`Device::set_priv`] and before [`Device::priv_obtain`], and `T`
    /// must match.
    pub(crate) unsafe fn priv_borrow<T: 'static>(&self) -> Pin<&T> {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        let ptr = unsafe { (*self.as_raw()).priv_ };
        // SAFETY: `ptr` was stored by a preceding `set_priv()` and is still valid.
        unsafe { Pin::<KBox<T>>::borrow(ptr.cast()) }
    }

    /// Find the single virtqueue and wire it to the driver's [`Driver::vq_callback`]. Mirrors C's
    /// `virtio_find_single_vq(vdev, cb, name)`, but the callback is the Adapter's own trampoline
    /// (which dispatches to the safe trait method) — the driver passes only the vq name.
    pub fn find_single_vq<D: Driver>(&self, name: &CStr) -> Result<VirtQueue> {
        self.find_single_vq_inner::<D>(name, None)
    }

    /// Find one callback-enabled virtqueue using the transport's default IRQ affinity policy.
    ///
    /// This passes a zero-initialized `struct irq_affinity`, matching C callers of
    /// `virtio_find_vqs` that request automatic interrupt spreading without a custom callback.
    /// The PCI transport reserves its configuration vector and requests managed affinity for
    /// the queue when it can use a separate MSI-X vector. Other transports and interrupt
    /// fallbacks retain their own policies. No CPU mask or queue count is selected here.
    pub fn find_single_vq_with_default_affinity<D: Driver>(
        &self,
        name: &CStr,
    ) -> Result<VirtQueue> {
        let mut affinity = bindings::irq_affinity::default();
        self.find_single_vq_inner::<D>(name, Some(&mut affinity))
    }

    fn find_single_vq_inner<D: Driver>(
        &self,
        name: &CStr,
        affinity: Option<&mut bindings::irq_affinity>,
    ) -> Result<VirtQueue> {
        let mut info = bindings::virtqueue_info {
            name: name.as_char_ptr(),
            callback: Some(Adapter::<D>::vq_callback),
            ctx: false,
        };
        let mut vq: *mut bindings::virtqueue = core::ptr::null_mut();

        let affinity = affinity.map_or(core::ptr::null_mut(), |value| value as *mut _);
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `config` is installed by the
        // transport. `info` describes one vq; `vq` receives the created virtqueue. The optional
        // affinity descriptor is exclusively borrowed for this synchronous call. As with C's
        // stack-allocated descriptors, the transport may update it but does not retain its
        // pointer. It contains no Rust callback or private-data pointer.
        let config = unsafe { (*self.as_raw()).config };
        let find_vqs = unsafe { (*config).find_vqs.ok_or(EINVAL)? };
        to_result(unsafe { find_vqs(self.as_raw(), 1, &mut vq, &mut info, affinity) })?;

        VirtQueue::new(vq)
    }

    /// Bring the device to `DRIVER_OK`. Mirrors C's `virtio_device_ready(vdev)`.
    ///
    /// With `CONFIG_VIRTIO_HARDEN_NOTIFICATION` off (this kernel does not set it), the C inline is
    /// exactly `set_status(get_status() | VIRTIO_CONFIG_S_DRIVER_OK)`. We do the same via the config
    /// ops directly, so the driver `.ko` needs no extra helper symbol.
    pub fn device_ready(&self) {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `config` is installed by the
        // transport and `get_status`/`set_status` are always present for virtio-pci-modern.
        let config = unsafe { (*self.as_raw()).config };
        let status = unsafe { (*config).get_status.unwrap()(self.as_raw()) };
        unsafe {
            (*config).set_status.unwrap()(
                self.as_raw(),
                status | bindings::VIRTIO_CONFIG_S_DRIVER_OK as u8,
            )
        };
    }

    /// Reset the device. Mirrors C's `virtio_reset_device(vdev)`.
    pub fn reset_device(&self) {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        unsafe { bindings::virtio_reset_device(self.as_raw()) };
    }

    /// Delete all virtqueues. Mirrors C's `vdev->config->del_vqs(vdev)`.
    pub fn del_vqs(&self) {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        let config = unsafe { (*self.as_raw()).config };
        if let Some(del_vqs) = unsafe { (*config).del_vqs } {
            // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
            unsafe { del_vqs(self.as_raw()) };
        }
    }

    /// Find multiple virtqueues. Callback-enabled [`VqInfo`] entries are wired to
    /// [`Driver::vq_callback`]; callback-free entries pass `NULL`, mirroring C
    /// `virtio_find_vqs(vdev, nvqs, vqs, info, NULL)`. The driver distinguishes callback-enabled
    /// vqs by identity ([`VirtQueue`] implements [`PartialEq`]). For a single callback-enabled vq,
    /// prefer [`Device::find_single_vq`].
    pub fn find_vqs<D: Driver>(&self, infos: &[VqInfo]) -> Result<KVec<VirtQueue>> {
        let nvqs = infos.len();
        let mut info_arr = KVec::with_capacity(nvqs, GFP_KERNEL)?;
        for info in infos {
            let _ = info_arr.push(
                bindings::virtqueue_info {
                    name: info.name.as_char_ptr(),
                    callback: if info.callback {
                        Some(Adapter::<D>::vq_callback)
                    } else {
                        None
                    },
                    ctx: info.ctx,
                },
                GFP_KERNEL,
            );
        }
        let mut raw_vqs = KVec::with_capacity(nvqs, GFP_KERNEL)?;
        for _ in 0..nvqs {
            let _ = raw_vqs.push(core::ptr::null_mut::<bindings::virtqueue>(), GFP_KERNEL);
        }

        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `config` is installed by the
        // transport. `info_arr`/`raw_vqs` are contiguous arrays of `nvqs` entries each.
        let config = unsafe { (*self.as_raw()).config };
        let find_vqs = unsafe { (*config).find_vqs.ok_or(EINVAL)? };
        to_result(unsafe {
            find_vqs(
                self.as_raw(),
                nvqs as u32,
                raw_vqs.as_mut_ptr(),
                info_arr.as_mut_ptr(),
                core::ptr::null_mut(),
            )
        })?;

        let mut vqs = KVec::with_capacity(nvqs, GFP_KERNEL)?;
        for &raw in &raw_vqs {
            // SAFETY: `find_vqs` populated `raw_vqs` with valid registered virtqueues (on success).
            let _ = vqs.push(VirtQueue::new(raw)?, GFP_KERNEL);
        }
        Ok(vqs)
    }

    /// Find multiple virtqueues while preserving protocol-defined queue-index holes.
    ///
    /// A `None` entry passes a null name and callback for that exact queue index,
    /// matching a C `virtqueue_info` entry whose `name` is `NULL`. This is needed
    /// by devices such as virtio-balloon whose later optional queues retain their
    /// fixed numeric indices when an earlier optional feature is not negotiated.
    pub fn find_vqs_sparse<D: Driver>(
        &self,
        infos: &[Option<VqInfo>],
    ) -> Result<KVec<Option<VirtQueue>>> {
        let nvqs = infos.len();
        let mut info_arr = KVec::with_capacity(nvqs, GFP_KERNEL)?;
        for info in infos {
            let raw = match info {
                Some(info) => bindings::virtqueue_info {
                    name: info.name.as_char_ptr(),
                    callback: if info.callback {
                        Some(Adapter::<D>::vq_callback)
                    } else {
                        None
                    },
                    ctx: info.ctx,
                },
                None => bindings::virtqueue_info {
                    name: core::ptr::null(),
                    callback: None,
                    ctx: false,
                },
            };
            let _ = info_arr.push(raw, GFP_KERNEL);
        }
        let mut raw_vqs = KVec::with_capacity(nvqs, GFP_KERNEL)?;
        for _ in 0..nvqs {
            let _ = raw_vqs.push(core::ptr::null_mut::<bindings::virtqueue>(), GFP_KERNEL);
        }

        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `config` is installed by the
        // transport. `info_arr`/`raw_vqs` are contiguous arrays of `nvqs` entries each. Null names
        // are the documented C representation of unused fixed queue indices.
        let config = unsafe { (*self.as_raw()).config };
        let find_vqs = unsafe { (*config).find_vqs.ok_or(EINVAL)? };
        to_result(unsafe {
            find_vqs(
                self.as_raw(),
                nvqs as u32,
                raw_vqs.as_mut_ptr(),
                info_arr.as_mut_ptr(),
                core::ptr::null_mut(),
            )
        })?;

        let mut vqs = KVec::with_capacity(nvqs, GFP_KERNEL)?;
        for (info, &raw) in infos.iter().zip(&raw_vqs) {
            let queue = match info {
                Some(_) => Some(VirtQueue::new(raw)?),
                None => None,
            };
            let _ = vqs.push(queue, GFP_KERNEL);
        }
        Ok(vqs)
    }

    /// Read the device status byte. Mirrors `vdev->config->get_status`.
    pub fn get_status(&self) -> u8 {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `get_status` is always present
        // for virtio-pci-modern.
        let config = unsafe { (*self.as_raw()).config };
        unsafe { (*config).get_status.unwrap()(self.as_raw()) }
    }

    /// The virtio device index (mirrors `vdev->index`), e.g. used to format a stable device path.
    pub fn index(&self) -> u32 {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `index` is a plain `int`.
        unsafe { (*self.as_raw()).index as u32 }
    }

    /// Set the device status byte. Mirrors `vdev->config->set_status`.
    pub fn set_status(&self, status: u8) {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        let config = unsafe { (*self.as_raw()).config };
        unsafe { (*config).set_status.unwrap()(self.as_raw(), status) };
    }

    /// Read the config-space generation counter (0 if the transport provides none). Mirrors
    /// `vdev->config->generation`.
    pub fn generation(&self) -> u32 {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        let config = unsafe { (*self.as_raw()).config };
        match unsafe { (*config).generation } {
            Some(g) => unsafe { g(self.as_raw()) },
            None => 0,
        }
    }

    /// Test whether feature bit `fbit` was negotiated. Mirrors `virtio_has_feature(vdev, fbit)`
    /// (`__virtio_test_bit`), including extended feature words above bit 63.
    pub fn has_feature(&self, fbit: u32) -> bool {
        // SAFETY: `self.as_raw()` is a live virtio device and the helper bounds
        // `fbit` against the kernel's complete negotiated feature bitmap.
        unsafe { bindings::virtio_has_feature(self.as_raw(), fbit) }
    }

    /// Clear one negotiated feature during the driver's validation phase.
    ///
    /// Virtio drivers use this for optional configuration values whose device
    /// payload is invalid (for example, an Ethernet MTU below the subsystem
    /// minimum) and for optional feature pairs whose dependency is absent.
    /// The core finalizes the resulting bitmap after `Driver::validate`
    /// returns, exactly as for C's `__virtio_clear_bit()`.
    pub fn clear_feature(&self, fbit: u32) -> Result {
        // SAFETY: `self.as_raw()` is a live virtio device in core-owned driver
        // context; the helper validates `fbit` against the full bitmap width.
        to_result(unsafe { bindings::virtio_clear_feature(self.as_raw(), fbit) })
    }

    /// Read the device's offered features bitmap. Mirrors `vdev->config->get_features`.
    pub fn get_features(&self) -> u64 {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        let config = unsafe { (*self.as_raw()).config };
        unsafe { (*config).get_features.unwrap()(self.as_raw()) }
    }

    /// Finalize features (write the driver's negotiated feature set back to the device). Mirrors
    /// `vdev->config->finalize_features`. The C core calls this during `virtio_dev_probe`; exposed
    /// for drivers that re-negotiate after reset/restore.
    pub fn finalize_features(&self) -> Result {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        let config = unsafe { (*self.as_raw()).config };
        to_result(unsafe { (*config).finalize_features.unwrap()(self.as_raw()) })
    }

    /// Signal a config-space change (set `config_change_pending`). Mirrors `virtio_config_changed`.
    pub fn config_changed(&self) {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`.
        unsafe { bindings::virtio_config_changed(self.as_raw()) };
    }

    /// Temporarily suppress delivery of driver config-change callbacks. Calls may be nested and
    /// must be balanced by [`Self::config_driver_enable`].
    pub fn config_driver_disable(&self) {
        // SAFETY: `self.as_raw()` is a live virtio device; the core serializes the nesting state.
        unsafe { bindings::virtio_config_driver_disable(self.as_raw()) };
    }

    /// Re-enable driver config-change callbacks, delivering one pending change when the outermost
    /// disable is balanced.
    pub fn config_driver_enable(&self) {
        // SAFETY: `self.as_raw()` is a live virtio device; callers balance a preceding disable.
        unsafe { bindings::virtio_config_driver_enable(self.as_raw()) };
    }

    /// Query a shared-memory region by id. Mirrors `virtio_get_shm_region(vdev, &region, id)`:
    /// calls the transport's `get_shm_region` config op, returning `(addr, len)` (the guest
    /// physical address + byte length of the region) or `None` if the transport has no such op or
    /// reports no region for `id`. Used by virtio-pmem to discover the persistent-memory range.
    pub fn get_shm_region(&self, id: u8) -> Option<(u64, u64)> {
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `config` is its ops table.
        let config = unsafe { (*self.as_raw()).config };
        let mut shm = bindings::virtio_shm_region { addr: 0, len: 0 };
        match unsafe { (*config).get_shm_region } {
            Some(f) => {
                // SAFETY: `self.as_raw()` is valid; `shm` is a valid out-param of the right type.
                if unsafe { f(self.as_raw(), &mut shm, id) } {
                    Some((shm.addr, shm.len))
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Read a 1-byte config-space field at byte `offset`. Mirrors `virtio_cread8` (raw, no
    /// byte-swap). The abstraction targets modern virtio (`VIRTIO_F_VERSION_1`); all translated
    /// drivers require it.
    pub fn cread8(&self, offset: u32) -> u8 {
        let mut val: u8 = 0;
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `get` writes 1 byte into `val`.
        let config = unsafe { (*self.as_raw()).config };
        unsafe {
            (*config).get.unwrap()(self.as_raw(), offset, &mut val as *mut u8 as *mut c_void, 1)
        };
        val
    }

    /// Read a 2-byte config-space field at byte `offset` (little-endian on modern virtio). Mirrors
    /// `virtio_cread16` (modern ⇒ `virtio16_to_cpu` = `le16_to_cpu`).
    pub fn cread16(&self, offset: u32) -> u16 {
        let mut val: u16 = 0;
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `get` writes 2 bytes into `val`.
        let config = unsafe { (*self.as_raw()).config };
        unsafe {
            (*config).get.unwrap()(
                self.as_raw(),
                offset,
                &mut val as *mut u16 as *mut c_void,
                2,
            )
        };
        u16::from_le(val)
    }

    /// Read a 4-byte config-space field at byte `offset` (little-endian on modern virtio). Mirrors
    /// `virtio_cread32`.
    pub fn cread32(&self, offset: u32) -> u32 {
        let mut val: u32 = 0;
        let config = unsafe { (*self.as_raw()).config };
        unsafe {
            (*config).get.unwrap()(
                self.as_raw(),
                offset,
                &mut val as *mut u32 as *mut c_void,
                4,
            )
        };
        u32::from_le(val)
    }

    /// Read an 8-byte config-space field at byte `offset` (little-endian on modern virtio). Mirrors
    /// `virtio_cread64`.
    pub fn cread64(&self, offset: u32) -> u64 {
        let mut val: u64 = 0;
        let config = unsafe { (*self.as_raw()).config };
        unsafe {
            (*config).get.unwrap()(
                self.as_raw(),
                offset,
                &mut val as *mut u64 as *mut c_void,
                8,
            )
        };
        u64::from_le(val)
    }

    /// Write a 1-byte config-space field at byte `offset`. Mirrors `virtio_cwrite8` (raw).
    pub fn cwrite8(&self, offset: u32, val: u8) {
        let config = unsafe { (*self.as_raw()).config };
        // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `set` reads 1 byte from `val`.
        unsafe {
            (*config).set.unwrap()(self.as_raw(), offset, &val as *const u8 as *const c_void, 1)
        };
    }

    /// Write a 2-byte config-space field at byte `offset` (little-endian on modern virtio). Mirrors
    /// `virtio_cwrite16`.
    pub fn cwrite16(&self, offset: u32, val: u16) {
        let val = val.to_le();
        let config = unsafe { (*self.as_raw()).config };
        unsafe {
            (*config).set.unwrap()(
                self.as_raw(),
                offset,
                &val as *const u16 as *const c_void,
                2,
            )
        };
    }

    /// Write a 4-byte config-space field at byte `offset` (little-endian on modern virtio). Mirrors
    /// `virtio_cwrite32`.
    pub fn cwrite32(&self, offset: u32, val: u32) {
        let val = val.to_le();
        let config = unsafe { (*self.as_raw()).config };
        unsafe {
            (*config).set.unwrap()(
                self.as_raw(),
                offset,
                &val as *const u32 as *const c_void,
                4,
            )
        };
    }

    /// Write an 8-byte config-space field at byte `offset` (little-endian on modern virtio). Mirrors
    /// `virtio_cwrite64`.
    pub fn cwrite64(&self, offset: u32, val: u64) {
        let val = val.to_le();
        let config = unsafe { (*self.as_raw()).config };
        unsafe {
            (*config).set.unwrap()(
                self.as_raw(),
                offset,
                &val as *const u64 as *const c_void,
                8,
            )
        };
    }

    /// Read `buf.len()` raw bytes from config space at byte `offset`, retrying on a generation
    /// change (mirrors C `__virtio_cread_many` / `virtio_cread_bytes`). Reads one byte at a time:
    /// the transport's `get` op (`vp_get` on virtio-pci-modern) handles only `len ∈ {1,2,4,8}` and
    /// `BUG()`s otherwise — exactly matching C's `__virtio_cread_many(.., count=len, bytes=1)`.
    pub fn cread_bytes(&self, offset: u32, buf: &mut [u8]) {
        let config = unsafe { (*self.as_raw()).config };
        let get = unsafe { (*config).get.unwrap() };
        let generation = unsafe { (*config).generation };
        let mut gen = match generation {
            Some(g) => unsafe { g(self.as_raw()) },
            None => 0,
        };
        loop {
            let old = gen;
            for i in 0..buf.len() {
                // SAFETY: `self.as_raw()` is a valid `struct virtio_device`; `get` writes 1 byte
                // into `buf[i]` (the transport handles `len = 1`).
                unsafe {
                    get(
                        self.as_raw(),
                        offset + i as u32,
                        &mut buf[i] as *mut u8 as *mut c_void,
                        1,
                    )
                };
            }
            gen = match generation {
                Some(g) => unsafe { g(self.as_raw()) },
                None => 0,
            };
            if gen == old {
                break;
            }
        }
    }
}

impl Device {
    /// Recover the [`Device`] from a `struct virtqueue *` (`vq->vdev`), for the Adapter's vq
    /// trampoline. Crate-private (the driver never calls it).
    ///
    /// # Safety
    ///
    /// `vq` must be a valid pointer to a registered `struct virtqueue`.
    pub(crate) unsafe fn from_vq<'a>(vq: *mut bindings::virtqueue) -> &'a Self {
        // SAFETY: A registered `struct virtqueue` has a valid `vdev` back-pointer.
        let vdev = unsafe { (*vq).vdev };
        // SAFETY: `vdev` is a valid pointer to a `struct virtio_device`.
        unsafe { &*vdev.cast::<Self>() }
    }
}

// SAFETY: `virtio::Device` is a transparent wrapper of `struct virtio_device`; the offset points
// to the embedded `struct device` field.
unsafe impl<Ctx: device::DeviceContext> device::AsBusDevice<Ctx> for Device<Ctx> {
    const OFFSET: usize = offset_of!(bindings::virtio_device, dev);
}

// SAFETY: `Device` is a transparent wrapper of a type that doesn't depend on `Device`'s generic
// argument.
kernel::impl_device_context_deref!(unsafe { Device });
kernel::impl_device_context_into_aref!(Device);

// SAFETY: Instances of `Device` are always reference-counted (via the embedded `struct device`).
unsafe impl AlwaysRefCounted for Device {
    fn inc_ref(&self) {
        // SAFETY: A shared reference guarantees the refcount is non-zero.
        unsafe { bindings::get_device(self.as_ref().as_raw()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: `obj` is a valid pointer to a `struct virtio_device`.
        let vdev: *mut bindings::virtio_device = obj.cast().as_ptr();
        let dev = unsafe { addr_of_mut!((*vdev).dev) };
        // SAFETY: The safety requirements guarantee the refcount is non-zero.
        unsafe { bindings::put_device(dev) }
    }
}

impl<Ctx: device::DeviceContext> AsRef<device::Device<Ctx>> for Device<Ctx> {
    fn as_ref(&self) -> &device::Device<Ctx> {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct virtio_device`.
        let dev = unsafe { addr_of_mut!((*self.as_raw()).dev) };
        // SAFETY: `dev` points to a valid `struct device`.
        unsafe { device::Device::from_raw(dev) }
    }
}

// SAFETY: A `Device` is always reference-counted and can be released from any thread.
unsafe impl Send for Device {}

// SAFETY: `Device` can be shared among threads; all methods of `Device<Normal>` are thread safe.
unsafe impl Sync for Device {}

/// One validated DMA segment for a premapped virtqueue submission.
///
/// Fields are private so an external driver cannot manufacture a bus address. Segments are created
/// by [`DmaBuffer::segment`] or by another in-kernel safe DMA provider (for example, the future
/// AF_XDP pool wrapper).
#[derive(Clone, Copy)]
pub struct DmaSegment {
    queue: NonNull<bindings::virtqueue>,
    address: dma::DmaAddress,
    length: u32,
}

impl DmaSegment {
    // `address..address + length` must remain mapped for `queue` until the submitted descriptor is
    // returned or detached. Keep raw construction private until another safe provider (such as an
    // AF_XDP pool wrapper) needs a crate-visible constructor.
    unsafe fn from_raw_parts(
        queue: NonNull<bindings::virtqueue>,
        address: dma::DmaAddress,
        length: u32,
    ) -> Result<Self> {
        if length == 0 {
            return Err(EINVAL);
        }
        Ok(Self {
            queue,
            address,
            length,
        })
    }

    /// Construct a segment from another crate-owned DMA provider.
    ///
    /// # Safety
    ///
    /// `address..address + length` must be a live mapping for `queue` and must remain mapped until
    /// every descriptor built from the returned segment has completed or been synchronously
    /// detached.
    pub(crate) unsafe fn from_provider(
        queue: &VirtQueue,
        address: dma::DmaAddress,
        length: u32,
    ) -> Result<Self> {
        // SAFETY: The caller supplies the mapping lifetime and queue-identity guarantees.
        unsafe { Self::from_raw_parts(queue.0, address, length) }
    }
}

/// An owned array of DMA-populated scatterlist entries.
///
/// `sg_init_table` establishes the chain/end markers and the RFL helper fills the configuration-
/// dependent DMA address/length fields. Construction rejects empty or cross-queue chains.
pub struct PremappedSg<const N: usize> {
    queue: NonNull<bindings::virtqueue>,
    entries: [bindings::scatterlist; N],
}

/// A runtime-sized owned array of DMA-populated scatterlist entries.
///
/// This is kept private because drivers should submit one of the typed owners below rather than
/// assemble a dynamic premapped chain and an unrelated token themselves.
struct PremappedSgDyn {
    queue: NonNull<bindings::virtqueue>,
    entries: KVec<MaybeUninit<bindings::scatterlist>>,
}

impl PremappedSgDyn {
    fn new(segments: &[DmaSegment], flags: alloc::Flags) -> Result<Self> {
        if segments.is_empty() || segments.len() > u32::MAX as usize {
            return Err(EINVAL);
        }
        let queue = segments[0].queue;
        if segments.iter().any(|segment| segment.queue != queue) {
            return Err(EINVAL);
        }

        let mut entries = KVec::with_capacity(segments.len(), flags)?;
        entries.resize(segments.len(), MaybeUninit::uninit(), flags)?;
        // SAFETY: `entries` is contiguous storage for exactly `segments.len()` scatterlist
        // entries, and the non-empty/count bounds were checked above.
        unsafe { bindings::sg_init_table(entries.as_mut_ptr().cast(), segments.len() as u32) };
        for (entry, segment) in entries.iter_mut().zip(segments) {
            // SAFETY: `sg_init_table` initialized every entry and each segment came from the same
            // live typed DMA owner.
            unsafe { bindings::sg_set_dma(entry.as_mut_ptr(), segment.address, segment.length) };
        }
        Ok(Self { queue, entries })
    }

    fn as_mut_ptr(&mut self) -> *mut bindings::scatterlist {
        self.entries.as_mut_ptr().cast()
    }

    fn len(&self) -> u32 {
        self.entries.len() as u32
    }
}

impl<const N: usize> PremappedSg<N> {
    /// Build a scatterlist from trusted DMA segments belonging to one queue.
    pub fn new(segments: [DmaSegment; N]) -> Result<Self> {
        if N == 0 || N > u32::MAX as usize {
            return Err(EINVAL);
        }
        let queue = segments[0].queue;
        if segments.iter().any(|segment| segment.queue != queue) {
            return Err(EINVAL);
        }

        let mut entries = core::mem::MaybeUninit::<[bindings::scatterlist; N]>::uninit();
        // SAFETY: `entries` provides contiguous storage for exactly N entries and N is non-zero.
        unsafe { bindings::sg_init_table(entries.as_mut_ptr().cast(), N as u32) };
        // SAFETY: `sg_init_table` initialized every entry.
        let mut entries = unsafe { entries.assume_init() };
        for (entry, segment) in entries.iter_mut().zip(segments) {
            // SAFETY: `entry` is initialized and `segment` came from a trusted DMA provider.
            unsafe { bindings::sg_set_dma(entry, segment.address, segment.length) };
        }
        Ok(Self { queue, entries })
    }

    fn as_mut_ptr(&mut self) -> *mut bindings::scatterlist {
        self.entries.as_mut_ptr()
    }
}

/// Owned streaming DMA mapping backed by a fixed-length kernel vector.
///
/// The buffer cannot reallocate after construction. Submission methods consume its [`KBox`], so
/// driver code cannot access the bytes while the device owns the descriptor. Completion or reset
/// returns the same box, and dropping it unmaps before freeing the storage. The queue must remain
/// live until all submitted mappings have been completed or recycled, matching the virtqueue
/// teardown rule already required by [`Device::del_vqs`].
pub struct DmaBuffer {
    queue: NonNull<bindings::virtqueue>,
    bytes: KVec<u8>,
    address: dma::DmaAddress,
    direction: dma::DataDirection,
    unmap_attrs: dma::Attrs,
    need_sync: bool,
    submitted: Option<Range<usize>>,
}

// SAFETY: Moving a mapping does not move its separately allocated backing bytes or alter the DMA
// address. Access remains exclusive because submission consumes the owning `KBox`.
unsafe impl Send for DmaBuffer {}

impl DmaBuffer {
    /// Allocate zeroed bytes and create one streaming mapping for this queue.
    pub fn new(
        queue: &VirtQueue,
        length: usize,
        direction: dma::DataDirection,
        attrs: dma::Attrs,
        flags: alloc::Flags,
    ) -> Result<KBox<Self>> {
        Self::new_with_unmap_attrs(queue, length, direction, attrs, attrs, flags)
    }

    /// Allocate and map a buffer while selecting separate unmap attributes. This models drivers
    /// that perform explicit cache synchronization and use `DMA_ATTR_SKIP_CPU_SYNC` only during
    /// teardown.
    pub fn new_with_unmap_attrs(
        queue: &VirtQueue,
        length: usize,
        direction: dma::DataDirection,
        map_attrs: dma::Attrs,
        unmap_attrs: dma::Attrs,
        flags: alloc::Flags,
    ) -> Result<KBox<Self>> {
        if length == 0 || length > u32::MAX as usize {
            return Err(EINVAL);
        }
        let mut bytes = KVec::with_capacity(length, flags)?;
        bytes.resize(length, 0, flags)?;
        // SAFETY: `bytes` is a stable, initialized allocation of `length` bytes. It remains private
        // and cannot reallocate for the lifetime of the mapping.
        let address = unsafe {
            bindings::virtqueue_map_single_attrs(
                queue.0.as_ptr(),
                bytes.as_mut_ptr().cast(),
                length,
                direction.into(),
                map_attrs.as_raw(),
            )
        };
        // SAFETY: The address was returned for this same queue.
        if unsafe { bindings::virtqueue_map_mapping_error(queue.0.as_ptr(), address) } != 0 {
            return Err(ENOMEM);
        }
        // SAFETY: The mapping is live and belongs to this queue.
        let need_sync = unsafe { bindings::virtqueue_map_need_sync(queue.0.as_ptr(), address) };

        Ok(KBox::new(
            Self {
                queue: queue.0,
                bytes,
                address,
                direction,
                unmap_attrs,
                need_sync,
                submitted: None,
            },
            flags,
        )?)
    }

    /// Number of mapped bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the mapping is empty (always false for a successfully constructed buffer).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// CPU-readable bytes while the caller owns this box.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// CPU-writable bytes while the caller owns this box.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Produce one checked DMA segment within this mapping.
    pub fn segment(&self, range: Range<usize>) -> Result<DmaSegment> {
        if range.start >= range.end || range.end > self.bytes.len() {
            return Err(EINVAL);
        }
        let offset: dma::DmaAddress = range.start.try_into()?;
        let address = self.address.checked_add(offset).ok_or(EOVERFLOW)?;
        let length = (range.end - range.start).try_into()?;
        // SAFETY: The checked range lies inside this live mapping.
        unsafe { DmaSegment::from_raw_parts(self.queue, address, length) }
    }

    /// Whether explicit CPU/device synchronization is required for this mapping.
    pub fn needs_sync(&self) -> bool {
        self.need_sync
    }

    /// Synchronize a checked range before CPU access when the DMA backend requires it.
    pub fn sync_for_cpu(&self, range: Range<usize>) -> Result {
        let _ = self.segment(range.clone())?;
        if self.need_sync {
            // SAFETY: The checked range is within this live mapping and the caller owns the box.
            unsafe {
                bindings::virtqueue_map_sync_single_range_for_cpu(
                    self.queue.as_ptr(),
                    self.address,
                    range.start,
                    range.end - range.start,
                    self.direction.into(),
                )
            };
        }
        Ok(())
    }

    /// Synchronize a checked range before returning ownership to the device.
    pub fn sync_for_device(&self, range: Range<usize>) -> Result {
        let _ = self.segment(range.clone())?;
        if self.need_sync {
            // SAFETY: The checked range is within this live mapping and the caller owns the box.
            unsafe {
                bindings::virtqueue_map_sync_single_range_for_device(
                    self.queue.as_ptr(),
                    self.address,
                    range.start,
                    range.end - range.start,
                    self.direction.into(),
                )
            };
        }
        Ok(())
    }

    fn prepare_submission(&mut self, range: Range<usize>) -> Result<DmaSegment> {
        if self.submitted.is_some() {
            return Err(EBUSY);
        }
        let segment = self.segment(range.clone())?;
        self.sync_for_device(range.clone())?;
        self.submitted = Some(range);
        Ok(segment)
    }

    fn finish_submission(&mut self, used_length: Option<u32>) -> Result {
        let range = self.submitted.take().ok_or(EINVAL)?;
        let length = match used_length {
            Some(length) => {
                let length = length as usize;
                if length > range.end - range.start {
                    return Err(EIO);
                }
                length
            }
            None => range.end - range.start,
        };
        if length != 0 && self.direction != dma::DataDirection::ToDevice {
            self.sync_for_cpu(range.start..range.start + length)?;
        }
        Ok(())
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // SAFETY: These are the exact queue, address, length, direction and attributes used by
        // `new`; Drop runs before `bytes` is freed.
        unsafe {
            bindings::virtqueue_unmap_single_attrs(
                self.queue.as_ptr(),
                self.address,
                self.bytes.len(),
                self.direction.into(),
                self.unmap_attrs.as_raw(),
            )
        };
    }
}

struct RxPagePoolState {
    free_pages: KVec<Page>,
    fragment_page: Option<Arc<SharedRxPage>>,
    fragment_offset: usize,
}

/// A queue-local receive-page allocator and cache.
///
/// Dedicated pages returned before networking-core ownership are cached for later large receive
/// buffers. Small and mergeable receive buffers take disjoint slices from one shared, page-wide
/// DMA mapping. The mapping remains live until both the allocator and every outstanding slice
/// release their [`Arc`] references.
pub struct RxPagePool {
    queue: NonNull<bindings::virtqueue>,
    map_attrs: dma::Attrs,
    unmap_attrs: dma::Attrs,
    state: Pin<KBox<SpinLock<RxPagePoolState>>>,
}

// SAFETY: All mutable allocator state is protected by `state`; the transport queue has the same
// driver-serialized access contract as `VirtQueue`.
unsafe impl Send for RxPagePool {}

// SAFETY: Shared access only mutates allocator state through the spinlock. Allocated page slices
// are disjoint and their DMA ownership is tracked independently.
unsafe impl Sync for RxPagePool {}

impl RxPagePool {
    /// Create a page pool whose mappings belong to `queue`.
    pub fn new(
        queue: &VirtQueue,
        map_attrs: dma::Attrs,
        unmap_attrs: dma::Attrs,
        flags: alloc::Flags,
    ) -> Result<Arc<Self>> {
        let state = KBox::pin_init(
            new_spinlock!(RxPagePoolState {
                free_pages: KVec::new(),
                fragment_page: None,
                fragment_offset: 0,
            }),
            flags,
        )?;
        Ok(Arc::new(
            Self {
                queue: queue.0,
                map_attrs,
                unmap_attrs,
                state,
            },
            flags,
        )?)
    }

    fn take_page(&self, flags: alloc::Flags) -> Result<Page> {
        if let Some(page) = self.state.lock().free_pages.pop() {
            return Ok(page);
        }
        Page::alloc_page(flags).map_err(|_| ENOMEM)
    }

    fn give_page(&self, page: Page) {
        // Failure simply drops the page. This matches the cache's best-effort nature and keeps
        // reclaim paths infallible.
        let _ = self.state.lock().free_pages.push(page, GFP_ATOMIC);
    }

    fn existing_fragment(&self, allocation: usize, headroom: usize) -> Option<SharedRxSlice> {
        let mut state = self.state.lock();
        let end = state.fragment_offset.checked_add(allocation)?;
        if end > PAGE_SIZE {
            return None;
        }
        let page = state.fragment_page.as_ref()?.clone();
        let offset = state.fragment_offset.checked_add(headroom)?;
        state.fragment_offset = end;
        Some(SharedRxSlice {
            page,
            offset: offset as u32,
            length: (allocation - headroom) as u32,
            truesize: allocation as u32,
        })
    }

    fn allocate_fragment(
        self: &Arc<Self>,
        length: usize,
        headroom: usize,
        tailroom: usize,
        flags: alloc::Flags,
    ) -> Result<SharedRxSlice> {
        let allocation = headroom
            .checked_add(length)
            .and_then(|value| value.checked_add(tailroom))
            .ok_or(EOVERFLOW)?;
        if length == 0 || allocation > PAGE_SIZE || allocation > u32::MAX as usize {
            return Err(EINVAL);
        }
        if let Some(mut slice) = self.existing_fragment(allocation, headroom) {
            slice.length = length as u32;
            return Ok(slice);
        }

        let page = self.take_page(flags)?;
        let replacement = Arc::new(SharedRxPage::new(self, page)?, flags)?;
        let (slice, unused) = {
            let mut state = self.state.lock();
            let existing_end = state.fragment_offset.checked_add(allocation);
            if existing_end.is_some_and(|end| end <= PAGE_SIZE) && state.fragment_page.is_some() {
                let page = state.fragment_page.as_ref().ok_or(EIO)?.clone();
                let offset = state
                    .fragment_offset
                    .checked_add(headroom)
                    .ok_or(EOVERFLOW)?;
                state.fragment_offset = existing_end.ok_or(EOVERFLOW)?;
                (
                    SharedRxSlice {
                        page,
                        offset: offset as u32,
                        length: length as u32,
                        truesize: allocation as u32,
                    },
                    Some(replacement),
                )
            } else {
                let unused = state.fragment_page.replace(replacement.clone());
                state.fragment_offset = allocation;
                (
                    SharedRxSlice {
                        page: replacement,
                        offset: headroom as u32,
                        length: length as u32,
                        truesize: allocation as u32,
                    },
                    unused,
                )
            }
        };
        drop(unused);
        Ok(slice)
    }

    /// Release allocator-owned fragment mappings and cached dedicated pages.
    ///
    /// Queue users must reclaim all outstanding receive tokens first and call this before the
    /// transport destroys the queue.
    pub fn clear(&self) {
        let fragment_page = {
            let mut state = self.state.lock();
            state.fragment_offset = 0;
            state.free_pages.clear();
            state.fragment_page.take()
        };
        drop(fragment_page);
    }

    /// Number of dedicated pages currently available for reuse.
    pub fn cached_pages(&self) -> usize {
        self.state.lock().free_pages.len()
    }
}

struct SharedRxPage {
    queue: NonNull<bindings::virtqueue>,
    page: Page,
    address: dma::DmaAddress,
    need_sync: bool,
    unmap_attrs: dma::Attrs,
}

// SAFETY: The mapped page is stable, and all slices created by the allocator are disjoint.
unsafe impl Send for SharedRxPage {}

// SAFETY: Concurrent operations only synchronize or access disjoint ranges. Mapping teardown is
// deferred until the final `Arc` is released.
unsafe impl Sync for SharedRxPage {}

impl SharedRxPage {
    fn new(pool: &RxPagePool, page: Page) -> Result<Self> {
        // SAFETY: `page` is live and remains owned by this object for the mapping lifetime.
        let address = unsafe {
            bindings::virtqueue_map_page_attrs(
                pool.queue.as_ptr(),
                page.as_ptr(),
                0,
                PAGE_SIZE,
                dma::DataDirection::FromDevice.into(),
                pool.map_attrs.as_raw(),
            )
        };
        // SAFETY: The address was returned for this same queue.
        if unsafe { bindings::virtqueue_map_mapping_error(pool.queue.as_ptr(), address) } != 0 {
            return Err(ENOMEM);
        }
        // SAFETY: The mapping is live and belongs to this queue.
        let need_sync = unsafe { bindings::virtqueue_map_need_sync(pool.queue.as_ptr(), address) };
        Ok(Self {
            queue: pool.queue,
            page,
            address,
            need_sync,
            unmap_attrs: pool.unmap_attrs,
        })
    }

    fn segment(&self, offset: u32, length: u32) -> Result<DmaSegment> {
        let end = offset.checked_add(length).ok_or(EOVERFLOW)?;
        if length == 0 || end as usize > PAGE_SIZE {
            return Err(EINVAL);
        }
        let address = self.address.checked_add(offset.into()).ok_or(EOVERFLOW)?;
        // SAFETY: The checked range lies within this live page-wide mapping.
        unsafe { DmaSegment::from_raw_parts(self.queue, address, length) }
    }

    fn sync_for_device(&self, offset: u32, length: u32) {
        if self.need_sync {
            // SAFETY: The checked allocator slice is live and is being transferred to the device.
            unsafe {
                bindings::virtqueue_map_sync_single_range_for_device(
                    self.queue.as_ptr(),
                    self.address,
                    offset as usize,
                    length as usize,
                    dma::DataDirection::FromDevice.into(),
                )
            };
        }
    }

    fn sync_for_cpu(&self, offset: u32, length: usize) {
        if self.need_sync && length != 0 {
            // SAFETY: Completion returned this checked slice range to the CPU.
            unsafe {
                bindings::virtqueue_map_sync_single_range_for_cpu(
                    self.queue.as_ptr(),
                    self.address,
                    offset as usize,
                    length,
                    dma::DataDirection::FromDevice.into(),
                )
            };
        }
    }
}

impl Drop for SharedRxPage {
    fn drop(&mut self) {
        // SAFETY: These are the exact queue, address, length, direction and attributes used for
        // this live page-wide mapping, and the final `Arc` proves no slice still uses it.
        unsafe {
            bindings::virtqueue_unmap_page_attrs(
                self.queue.as_ptr(),
                self.address,
                PAGE_SIZE,
                dma::DataDirection::FromDevice.into(),
                self.unmap_attrs.as_raw(),
            )
        };
    }
}

struct SharedRxSlice {
    page: Arc<SharedRxPage>,
    offset: u32,
    length: u32,
    truesize: u32,
}

struct MappedRxPage {
    queue: NonNull<bindings::virtqueue>,
    page: Option<Page>,
    address: dma::DmaAddress,
    offset: u32,
    length: u32,
    need_sync: bool,
    unmap_attrs: dma::Attrs,
    mapped: bool,
    recycle: Option<Arc<RxPagePool>>,
}

// SAFETY: Moving this value does not move the page or alter its DMA address. The page remains
// inaccessible outside its unique `RxPageBuffer` owner while it is submitted.
unsafe impl Send for MappedRxPage {}

impl MappedRxPage {
    fn unmap(&mut self) {
        if !self.mapped {
            return;
        }
        // SAFETY: These are the exact queue, address, length, direction and attributes used for
        // this live page mapping.
        unsafe {
            bindings::virtqueue_unmap_page_attrs(
                self.queue.as_ptr(),
                self.address,
                self.length as usize,
                dma::DataDirection::FromDevice.into(),
                self.unmap_attrs.as_raw(),
            )
        };
        self.mapped = false;
    }

    fn segment(&self) -> Result<DmaSegment> {
        // SAFETY: The address and length describe this live mapping and remain valid until the
        // owning buffer is completed, detached or synchronously recycled.
        unsafe { DmaSegment::from_raw_parts(self.queue, self.address, self.length) }
    }

    fn segment_range(&self, offset: u32, length: u32) -> Result<DmaSegment> {
        let end = offset.checked_add(length).ok_or(EOVERFLOW)?;
        if length == 0 || end > self.length {
            return Err(EINVAL);
        }
        let address = self.address.checked_add(offset.into()).ok_or(EOVERFLOW)?;
        // SAFETY: The checked subrange lies within this live mapping.
        unsafe { DmaSegment::from_raw_parts(self.queue, address, length) }
    }

    fn sync_for_device(&self) {
        if self.need_sync {
            // SAFETY: The whole mapped range is live and uniquely owned by the buffer being
            // transferred to the device.
            unsafe {
                bindings::virtqueue_map_sync_single_range_for_device(
                    self.queue.as_ptr(),
                    self.address,
                    0,
                    self.length as usize,
                    dma::DataDirection::FromDevice.into(),
                )
            };
        }
    }

    fn sync_for_cpu(&self, length: usize) {
        if self.need_sync && length != 0 {
            // SAFETY: `length` is bounded by this mapping by the caller and the device has
            // returned ownership of the descriptor.
            unsafe {
                bindings::virtqueue_map_sync_single_range_for_cpu(
                    self.queue.as_ptr(),
                    self.address,
                    0,
                    length,
                    dma::DataDirection::FromDevice.into(),
                )
            };
        }
    }
}

impl Drop for MappedRxPage {
    fn drop(&mut self) {
        self.unmap();
        if let (Some(pool), Some(page)) = (self.recycle.take(), self.page.take()) {
            pool.give_page(page);
        }
    }
}

enum RxPageFragmentBacking {
    Dedicated(Page),
    Shared(Arc<SharedRxPage>),
}

/// One owned page fragment in a completed receive frame.
pub(crate) struct RxPageFragment {
    backing: RxPageFragmentBacking,
    pub(crate) offset: u32,
    pub(crate) length: u32,
    pub(crate) truesize: u32,
}

impl RxPageFragment {
    pub(crate) fn page(&self) -> &Page {
        match &self.backing {
            RxPageFragmentBacking::Dedicated(page) => page,
            RxPageFragmentBacking::Shared(page) => &page.page,
        }
    }
}

enum RxPageMapping {
    Dedicated(MappedRxPage),
    Shared(SharedRxSlice),
}

impl RxPageMapping {
    fn length(&self) -> u32 {
        match self {
            Self::Dedicated(page) => page.length,
            Self::Shared(slice) => slice.length,
        }
    }

    fn offset(&self) -> u32 {
        match self {
            Self::Dedicated(page) => page.offset,
            Self::Shared(slice) => slice.offset,
        }
    }

    fn truesize(&self) -> u32 {
        match self {
            Self::Dedicated(_) => PAGE_SIZE as u32,
            Self::Shared(slice) => slice.truesize,
        }
    }

    fn page(&self) -> Result<&Page> {
        match self {
            Self::Dedicated(page) => page.page.as_ref().ok_or(EIO),
            Self::Shared(slice) => Ok(&slice.page.page),
        }
    }

    fn segment(&self) -> Result<DmaSegment> {
        match self {
            Self::Dedicated(page) => page.segment(),
            Self::Shared(slice) => slice.page.segment(slice.offset, slice.length),
        }
    }

    fn segment_range(&self, offset: u32, length: u32) -> Result<DmaSegment> {
        match self {
            Self::Dedicated(page) => page.segment_range(offset, length),
            Self::Shared(slice) => {
                let end = offset.checked_add(length).ok_or(EOVERFLOW)?;
                if length == 0 || end > slice.length {
                    return Err(EINVAL);
                }
                slice
                    .page
                    .segment(slice.offset.checked_add(offset).ok_or(EOVERFLOW)?, length)
            }
        }
    }

    fn sync_for_device(&self) {
        match self {
            Self::Dedicated(page) => page.sync_for_device(),
            Self::Shared(slice) => slice.page.sync_for_device(slice.offset, slice.length),
        }
    }

    fn sync_for_cpu(&self, length: usize) {
        match self {
            Self::Dedicated(page) => page.sync_for_cpu(length),
            Self::Shared(slice) => slice.page.sync_for_cpu(slice.offset, length),
        }
    }

    fn into_fragment(self, length: u32) -> Result<RxPageFragment> {
        if length == 0 || length > self.length() {
            return Err(EINVAL);
        }
        let offset = self.offset();
        let truesize = self.truesize();
        let backing = match self {
            Self::Dedicated(mut page) => {
                page.unmap();
                RxPageFragmentBacking::Dedicated(page.page.take().ok_or(EIO)?)
            }
            Self::Shared(slice) => RxPageFragmentBacking::Shared(slice.page),
        };
        Ok(RxPageFragment {
            backing,
            offset,
            length,
            truesize,
        })
    }
}

/// Inline storage for the overwhelmingly common one-mapping receive buffer.
///
/// Multi-page drivers retain the dynamically sized representation, while small and mergeable
/// virtio-net buffers avoid allocating a one-element vector for every descriptor.
enum RxPageMappings {
    Inline(Option<RxPageMapping>),
    Dynamic(KVec<RxPageMapping>),
}

impl RxPageMappings {
    fn with_capacity(count: usize, flags: alloc::Flags) -> Result<Self> {
        if count == 1 {
            Ok(Self::Inline(None))
        } else {
            Ok(Self::Dynamic(KVec::with_capacity(count, flags)?))
        }
    }

    fn push(&mut self, mapping: RxPageMapping, flags: alloc::Flags) -> Result {
        match self {
            Self::Inline(slot) if slot.is_none() => {
                *slot = Some(mapping);
                Ok(())
            }
            Self::Inline(_) => Err(EOVERFLOW),
            Self::Dynamic(mappings) => Ok(mappings.push(mapping, flags)?),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline(mapping) => usize::from(mapping.is_some()),
            Self::Dynamic(mappings) => mappings.len(),
        }
    }

    fn get(&self, index: usize) -> Option<&RxPageMapping> {
        match self {
            Self::Inline(mapping) if index == 0 => mapping.as_ref(),
            Self::Inline(_) => None,
            Self::Dynamic(mappings) => mappings.get(index),
        }
    }
}

/// A completed receive frame backed by owned page references.
///
/// The frame is no longer DMA mapped. It may be extended with subsequent mergeable-buffer
/// completions, read for bounded protocol metadata, or consumed synchronously by networking core.
pub struct RxPageFrame {
    fragments: KVec<RxPageFragment>,
    length: usize,
}

// SAFETY: Each fragment owns its page reference and there are no exposed writable aliases.
unsafe impl Send for RxPageFrame {}

impl RxPageFrame {
    /// Total bytes across all fragments.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Whether this frame contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Append all fragments from a subsequent mergeable receive completion.
    pub fn append(&mut self, mut tail: Self, flags: alloc::Flags) -> Result {
        let length = self.length.checked_add(tail.length).ok_or(EOVERFLOW)?;
        self.fragments.reserve(tail.fragments.len(), flags)?;
        for fragment in tail.fragments.drain_all() {
            // Capacity was reserved for the complete tail above.
            self.fragments
                .push_within_capacity(fragment)
                .map_err(|_| ENOMEM)?;
        }
        self.length = length;
        tail.length = 0;
        Ok(())
    }

    /// Copy one checked logical range from the completed frame.
    pub fn copy_to_slice(&self, offset: usize, output: &mut [u8]) -> Result {
        let end = offset.checked_add(output.len()).ok_or(EOVERFLOW)?;
        if end > self.length {
            return Err(EINVAL);
        }
        if output.is_empty() {
            return Ok(());
        }
        let mut logical = 0usize;
        let mut copied = 0usize;
        for fragment in &self.fragments {
            let fragment_end = logical + fragment.length as usize;
            if offset + copied >= fragment_end {
                logical = fragment_end;
                continue;
            }
            let within = (offset + copied).saturating_sub(logical);
            let available = fragment.length as usize - within;
            let count = available.min(output.len() - copied);
            // SAFETY: The page is uniquely owned by this frame, the fragment was constructed from
            // a checked mapping range, and the output slice is valid and non-overlapping.
            unsafe {
                fragment.page().read_raw(
                    output[copied..].as_mut_ptr(),
                    fragment.offset as usize + within,
                    count,
                )?
            };
            copied += count;
            if copied == output.len() {
                return Ok(());
            }
            logical = fragment_end;
        }
        Err(EIO)
    }

    pub(crate) fn fragments(&self) -> &[RxPageFragment] {
        &self.fragments
    }
}

/// An owned receive allocation consisting of one or more page mappings.
///
/// Submission consumes its [`KBox`]. Completion, detach, reset or resize restores the same unique
/// owner. A completed owner can be resubmitted, or converted into an unmapped [`RxPageFrame`] whose
/// pages may be borrowed synchronously by networking core. This keeps DMA ownership, page
/// references and virtqueue tokens in one typed state machine.
pub struct RxPageBuffer {
    queue: NonNull<bindings::virtqueue>,
    pages: RxPageMappings,
    length: usize,
    submitted: bool,
    completed_length: Option<usize>,
    first_segment_length: Option<u32>,
}

// SAFETY: Pages and mappings remain stable when the owner moves, and submission consumes the only
// Rust owner until the queue returns it.
unsafe impl Send for RxPageBuffer {}

impl RxPageBuffer {
    /// Allocate and map enough pages for one receive descriptor chain.
    ///
    /// `headroom` and `tailroom` reserve CPU-owned bytes before and after the device-visible range.
    /// Both are checked against the complete order-0 page allocation.
    pub fn new(
        queue: &VirtQueue,
        length: usize,
        headroom: usize,
        tailroom: usize,
        map_attrs: dma::Attrs,
        unmap_attrs: dma::Attrs,
        flags: alloc::Flags,
    ) -> Result<KBox<Self>> {
        Self::new_dedicated(
            queue,
            None,
            length,
            headroom,
            tailroom,
            map_attrs,
            unmap_attrs,
            flags,
        )
    }

    /// Allocate a dedicated receive descriptor chain from a queue-local page cache.
    pub fn new_cached(
        pool: &Arc<RxPagePool>,
        length: usize,
        headroom: usize,
        tailroom: usize,
        flags: alloc::Flags,
    ) -> Result<KBox<Self>> {
        let queue = VirtQueue(pool.queue);
        Self::new_dedicated(
            &queue,
            Some(pool),
            length,
            headroom,
            tailroom,
            pool.map_attrs,
            pool.unmap_attrs,
            flags,
        )
    }

    /// Allocate one small or mergeable receive buffer from a shared page-wide mapping.
    pub fn new_fragment(
        pool: &Arc<RxPagePool>,
        length: usize,
        headroom: usize,
        tailroom: usize,
        flags: alloc::Flags,
    ) -> Result<KBox<Self>> {
        let slice = pool.allocate_fragment(length, headroom, tailroom, flags)?;
        Ok(KBox::new(
            Self {
                queue: pool.queue,
                pages: RxPageMappings::Inline(Some(RxPageMapping::Shared(slice))),
                length,
                submitted: false,
                completed_length: None,
                first_segment_length: None,
            },
            flags,
        )?)
    }

    /// Reuse a completed receive-owner allocation with a fresh shared-page fragment.
    ///
    /// Networking core may retain the old page after a synchronous receive helper takes its own
    /// reference. Replacing the mapping releases this owner's old reference while retaining the
    /// allocation that serves as the virtqueue token.
    #[inline]
    pub fn renew_fragment(
        mut buffer: KBox<Self>,
        pool: &Arc<RxPagePool>,
        length: usize,
        headroom: usize,
        tailroom: usize,
        flags: alloc::Flags,
    ) -> Result<KBox<Self>> {
        if buffer.queue != pool.queue || buffer.submitted || buffer.completed_length.is_none() {
            return Err(EBUSY);
        }
        let slice = pool.allocate_fragment(length, headroom, tailroom, flags)?;
        buffer.pages = RxPageMappings::Inline(Some(RxPageMapping::Shared(slice)));
        buffer.length = length;
        buffer.completed_length = None;
        buffer.first_segment_length = None;
        Ok(buffer)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_dedicated(
        queue: &VirtQueue,
        pool: Option<&Arc<RxPagePool>>,
        length: usize,
        headroom: usize,
        tailroom: usize,
        map_attrs: dma::Attrs,
        unmap_attrs: dma::Attrs,
        flags: alloc::Flags,
    ) -> Result<KBox<Self>> {
        if pool.is_some_and(|pool| pool.queue != queue.0) {
            return Err(EINVAL);
        }
        if length == 0 || length > u32::MAX as usize || headroom >= PAGE_SIZE {
            return Err(EINVAL);
        }
        let device_end = headroom.checked_add(length).ok_or(EOVERFLOW)?;
        let allocation = device_end.checked_add(tailroom).ok_or(EOVERFLOW)?;
        let page_count = device_end.checked_add(PAGE_SIZE - 1).ok_or(EOVERFLOW)? / PAGE_SIZE;
        if page_count == 0 || page_count > u32::MAX as usize {
            return Err(EINVAL);
        }
        if allocation > page_count.checked_mul(PAGE_SIZE).ok_or(EOVERFLOW)? {
            return Err(EINVAL);
        }

        let mut pages = RxPageMappings::with_capacity(page_count, flags)?;
        let mut remaining = length;
        let mut offset = headroom;
        while remaining != 0 {
            let mapped_length = remaining.min(PAGE_SIZE - offset);
            let page = if let Some(pool) = pool {
                pool.take_page(flags)?
            } else {
                Page::alloc_page(flags).map_err(|_| ENOMEM)?
            };
            // SAFETY: `page` is live, the checked offset/range lies in it, and it remains owned by
            // the mapping object until unmap.
            let address = unsafe {
                bindings::virtqueue_map_page_attrs(
                    queue.0.as_ptr(),
                    page.as_ptr(),
                    offset as crate::ffi::c_ulong,
                    mapped_length,
                    dma::DataDirection::FromDevice.into(),
                    map_attrs.as_raw(),
                )
            };
            // SAFETY: The address was returned for this same queue.
            if unsafe { bindings::virtqueue_map_mapping_error(queue.0.as_ptr(), address) } != 0 {
                return Err(ENOMEM);
            }
            // SAFETY: The mapping is live and belongs to this queue.
            let need_sync = unsafe { bindings::virtqueue_map_need_sync(queue.0.as_ptr(), address) };
            pages.push(
                RxPageMapping::Dedicated(MappedRxPage {
                    queue: queue.0,
                    page: Some(page),
                    address,
                    offset: offset as u32,
                    length: mapped_length as u32,
                    need_sync,
                    unmap_attrs,
                    mapped: true,
                    recycle: pool.cloned(),
                }),
                flags,
            )?;
            remaining -= mapped_length;
            offset = 0;
        }

        Ok(KBox::new(
            Self {
                queue: queue.0,
                pages,
                length,
                submitted: false,
                completed_length: None,
                first_segment_length: None,
            },
            flags,
        )?)
    }

    /// Number of device-visible bytes in this allocation.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Whether this allocation is empty (always false after successful construction).
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Split the first mapped page into a header segment and a data segment.
    ///
    /// Legacy virtio layouts use this to keep the device header in its own descriptor while the
    /// typed owner still manages one mapping and one page reference.
    pub fn split_first_segment(mut buffer: KBox<Self>, length: u32) -> Result<KBox<Self>> {
        let first = buffer.pages.get(0).ok_or(EINVAL)?;
        if length == 0 || length >= first.length() || buffer.submitted {
            return Err(EINVAL);
        }
        buffer.first_segment_length = Some(length);
        Ok(buffer)
    }

    /// Copy a checked range after the device has returned this buffer.
    pub fn copy_to_slice(&self, offset: usize, output: &mut [u8]) -> Result {
        let completed = self.completed_length.ok_or(EBUSY)?;
        let end = offset.checked_add(output.len()).ok_or(EOVERFLOW)?;
        if end > completed {
            return Err(EINVAL);
        }
        if output.is_empty() {
            return Ok(());
        }
        let mut logical = 0usize;
        let mut copied = 0usize;
        for index in 0..self.pages.len() {
            let mapped = self.pages.get(index).ok_or(EIO)?;
            let mapped_end = logical + mapped.length() as usize;
            if offset + copied >= mapped_end {
                logical = mapped_end;
                continue;
            }
            let within = (offset + copied).saturating_sub(logical);
            let available = mapped.length() as usize - within;
            let count = available.min(output.len() - copied);
            let page = mapped.page()?;
            // SAFETY: Completion synchronized this range for CPU access and this unique owner
            // prevents concurrent device or CPU writes.
            unsafe {
                page.read_raw(
                    output[copied..].as_mut_ptr(),
                    mapped.offset() as usize + within,
                    count,
                )?
            };
            copied += count;
            if copied == output.len() {
                return Ok(());
            }
            logical = mapped_end;
        }
        Err(EIO)
    }

    /// Number of bytes returned by the device for this completed buffer.
    pub(crate) fn completed_len(&self) -> Result<usize> {
        self.completed_length.ok_or(EBUSY)
    }

    /// Number of mappings that may contribute to the completed frame.
    pub(crate) fn mapping_count(&self) -> usize {
        self.pages.len()
    }

    /// Return the single non-empty range of a completed receive buffer.
    pub(crate) fn single_completed_range(&self) -> Result<(*mut bindings::page, u32, u32, u32)> {
        if self.pages.len() != 1 {
            return Err(E2BIG);
        }
        let mapped = self.pages.get(0).ok_or(EIO)?;
        let length = self.completed_len()?.min(mapped.length() as usize);
        if length == 0 || length != self.completed_len()? {
            return Err(EIO);
        }
        Ok((
            mapped.page()?.as_ptr(),
            mapped.offset(),
            length as u32,
            mapped.truesize(),
        ))
    }

    /// Visit the non-empty page ranges returned by the device without allocating metadata arrays.
    pub(crate) fn for_each_completed_range(
        &self,
        mut visit: impl FnMut(*mut bindings::page, u32, u32, u32),
    ) -> Result<usize> {
        let mut remaining = self.completed_len()?;
        let mut count = 0usize;
        for index in 0..self.pages.len() {
            let mapped = self.pages.get(index).ok_or(EIO)?;
            let length = remaining.min(mapped.length() as usize);
            if length == 0 {
                break;
            }
            visit(
                mapped.page()?.as_ptr(),
                mapped.offset(),
                length as u32,
                mapped.truesize(),
            );
            count += 1;
            remaining -= length;
        }
        if remaining == 0 && count != 0 {
            Ok(count)
        } else {
            Err(EIO)
        }
    }

    fn prepare_submission(&mut self, flags: alloc::Flags) -> Result<KVec<DmaSegment>> {
        if self.submitted {
            return Err(EBUSY);
        }
        let capacity = self
            .pages
            .len()
            .checked_add(usize::from(self.first_segment_length.is_some()))
            .ok_or(EOVERFLOW)?;
        let mut segments = KVec::with_capacity(capacity, flags)?;
        for index in 0..self.pages.len() {
            let mapped = self.pages.get(index).ok_or(EIO)?;
            mapped.sync_for_device();
            if index == 0 {
                if let Some(header) = self.first_segment_length {
                    segments.push(mapped.segment_range(0, header)?, flags)?;
                    segments.push(
                        mapped.segment_range(header, mapped.length() - header)?,
                        flags,
                    )?;
                    continue;
                }
            }
            segments.push(mapped.segment()?, flags)?;
        }
        self.completed_length = None;
        self.submitted = true;
        Ok(segments)
    }

    fn prepare_single_submission(&mut self) -> Result<Option<DmaSegment>> {
        if self.submitted {
            return Err(EBUSY);
        }
        if self.pages.len() != 1 || self.first_segment_length.is_some() {
            return Ok(None);
        }
        let mapped = self.pages.get(0).ok_or(EIO)?;
        mapped.sync_for_device();
        let segment = mapped.segment()?;
        self.completed_length = None;
        self.submitted = true;
        Ok(Some(segment))
    }

    fn finish_submission(&mut self, used_length: Option<u32>) -> Result {
        if !self.submitted {
            return Err(EINVAL);
        }
        let used = used_length.map_or(self.length, |length| length as usize);
        if used > self.length {
            return Err(EIO);
        }
        let mut remaining = used;
        for index in 0..self.pages.len() {
            let mapped = self.pages.get(index).ok_or(EIO)?;
            let length = remaining.min(mapped.length() as usize);
            mapped.sync_for_cpu(length);
            remaining -= length;
        }
        self.submitted = false;
        self.completed_length = Some(used);
        Ok(())
    }

    /// Consume a completed mapping and return its unmapped page fragments.
    pub fn into_frame(buffer: KBox<Self>, flags: alloc::Flags) -> Result<RxPageFrame> {
        let mut buffer = KBox::into_inner(buffer);
        let used = buffer.completed_length.take().ok_or(EBUSY)?;
        let mut fragments = KVec::with_capacity(buffer.pages.len(), flags)?;
        let mut remaining = used;
        let mut append = |mapped: RxPageMapping| -> Result {
            let length = remaining.min(mapped.length() as usize);
            remaining -= length;
            if length != 0 {
                fragments.push(mapped.into_fragment(length as u32)?, flags)?;
            }
            Ok(())
        };
        match buffer.pages {
            RxPageMappings::Inline(Some(mapped)) => append(mapped)?,
            RxPageMappings::Inline(None) => return Err(EIO),
            RxPageMappings::Dynamic(mut mappings) => {
                for mapped in mappings.drain_all() {
                    append(mapped)?;
                }
            }
        }
        if remaining != 0 {
            return Err(EIO);
        }
        Ok(RxPageFrame {
            fragments,
            length: used,
        })
    }
}

/// Opaque queue state captured while re-enabling callbacks.
///
/// The token borrows its originating queue and is consumed by [`Self::poll`], preventing a caller
/// from accidentally testing state against a different virtqueue.
#[must_use = "callback re-enable state must be polled after completing the current work batch"]
pub struct CallbackPoll<'a> {
    queue: &'a VirtQueue,
    opaque: u32,
}

impl CallbackPoll<'_> {
    /// Return whether the device used another buffer in the race window after callback re-enable.
    #[inline(always)]
    pub fn poll(self) -> bool {
        // SAFETY: `opaque` came from `virtqueue_enable_cb_prepare` for this same live queue.
        unsafe { bindings::virtqueue_poll(self.queue.0.as_ptr(), self.opaque) }
    }
}

/// Options for converting an owned TX skb into a virtio-net header and descriptor chain.
#[derive(Clone, Copy)]
pub struct NetTxOptions {
    header_len: u32,
    allow_inline_header: bool,
    tunnel_header_negotiated: bool,
    little_endian: bool,
    vlan_header_len: u16,
    has_data_valid: bool,
    orphan_after_submit: bool,
}

impl NetTxOptions {
    /// Create options for a negotiated header size and virtio byte order.
    #[inline]
    pub fn new(header_len: u32, little_endian: bool) -> Result<Self> {
        // The basic header is ten bytes and skb->cb is the separate-header upper bound.
        if !(10..=48).contains(&header_len) {
            return Err(EINVAL);
        }
        Ok(Self {
            header_len,
            allow_inline_header: false,
            tunnel_header_negotiated: false,
            little_endian,
            vlan_header_len: 0,
            has_data_valid: false,
            orphan_after_submit: false,
        })
    }

    /// Permit the zero-allocation headroom optimization when skb alignment and cloning allow it.
    #[inline]
    pub fn allow_inline_header(mut self, allow: bool) -> Self {
        self.allow_inline_header = allow;
        self
    }

    /// Declare negotiated UDP tunnel-header support.
    #[inline]
    pub fn tunnel_header(mut self, negotiated: bool) -> Self {
        self.tunnel_header_negotiated = negotiated;
        self
    }

    /// Set the outer VLAN header length used by checksum/GSO conversion.
    #[inline]
    pub fn vlan_header_len(mut self, bytes: u16) -> Self {
        self.vlan_header_len = bytes;
        self
    }

    /// Permit `VIRTIO_NET_HDR_F_DATA_VALID` when the receiving contract supports it.
    #[inline]
    pub fn data_valid(mut self, enabled: bool) -> Self {
        self.has_data_valid = enabled;
        self
    }

    /// Release socket and conntrack ownership only after queue submission succeeds.
    #[inline]
    pub fn orphan_after_submit(mut self, enabled: bool) -> Self {
        self.orphan_after_submit = enabled;
        self
    }
}

/// Failed virtio-net TX submission retaining unique packet ownership.
pub struct TxSubmissionError {
    error: Error,
    packet: TxPacket,
}

/// Failed virtio-net XDP submission retaining unique frame ownership.
pub struct XdpSubmissionError {
    error: Error,
    frame: XdpFrame,
}

impl XdpSubmissionError {
    /// Kernel error returned by frame conversion or virtqueue submission.
    pub fn error(&self) -> Error {
        self.error
    }

    /// Split the failure into its error and still-owned frame.
    pub fn into_parts(self) -> (Error, XdpFrame) {
        (self.error, self.frame)
    }
}

/// Typed completion returned by a virtio-net transmit queue shared by skb, XDP and AF_XDP traffic.
pub enum NetTxCompletion {
    /// Networking-stack skb submitted through `ndo_start_xmit`.
    Packet {
        /// Packet whose unique ownership was returned by the virtqueue.
        packet: TxPacket,
        /// Whether submission selected TX NAPI and therefore charged byte queue limits.
        byte_queue_limits: bool,
    },
    /// Native XDP frame submitted by RX action or `ndo_xdp_xmit`.
    Xdp(XdpFrame),
    /// AF_XDP userspace descriptor; completion returns its byte length to the bound pool.
    Xsk {
        /// Descriptor payload length encoded in the queue token.
        length: u32,
    },
}

impl TxSubmissionError {
    /// Kernel error returned by header conversion or virtqueue submission.
    pub fn error(&self) -> Error {
        self.error
    }

    /// Recover the unsubmitted packet for BUSY return or intentional drop.
    pub fn into_packet(self) -> TxPacket {
        self.packet
    }

    /// Split the failure into its error and retained packet.
    pub fn into_parts(self) -> (Error, TxPacket) {
        (self.error, self.packet)
    }
}

/// A handle to a created virtqueue.
///
/// Wraps a `struct virtqueue *` from [`Device::find_single_vq`]. The transport owns the vring; this
/// handle exposes only the driver-facing add/get/kick API. The virtqueue is freed by
/// [`Device::del_vqs`].
#[derive(Clone, Copy)]
pub struct VirtQueue(NonNull<bindings::virtqueue>);

// SAFETY: A `VirtQueue` is a raw handle to a transport-owned virtqueue; access is confined to a
// single driver instance's probe/remove/callback contexts.
unsafe impl Send for VirtQueue {}

// SAFETY: `&VirtQueue` only performs immutable virtqueue queries; concurrent add/get is serialized
// by the driver (e.g. a completion). Marked `Sync` so the driver data holding it can be `Sync`.
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    const NET_TX_TOKEN_MASK: usize = 0x3;
    const NET_TX_TOKEN_PACKET_ORPHAN: usize = 0x1;
    const NET_TX_TOKEN_XDP: usize = 0x2;
    const NET_TX_TOKEN_XSK: usize = 0x3;

    fn new(vq: *mut bindings::virtqueue) -> Result<Self> {
        Ok(Self(NonNull::new(vq).ok_or(ENOMEM)?))
    }

    /// Borrow a raw virtqueue pointer as a `VirtQueue` for the duration of a callback. The returned
    /// handle must not outlive the callback (the transport owns the vq); used by the Adapter's vq
    /// trampoline. `VirtQueue` has no `Drop`, so this does not free the vq.
    ///
    /// # Safety
    ///
    /// `vq` must be a valid pointer to a registered `struct virtqueue`, live for the returned
    /// handle's use.
    pub(crate) unsafe fn borrow(vq: *mut bindings::virtqueue) -> Self {
        // SAFETY: the caller guarantees `vq` is a valid registered virtqueue.
        Self(unsafe { NonNull::new_unchecked(vq) })
    }

    /// Raw queue pointer for crate-owned abstractions that pin the transport lifetime separately.
    pub(crate) fn as_raw(&self) -> *mut bindings::virtqueue {
        self.0.as_ptr()
    }

    /// Recover the [`Device`] this virtqueue belongs to (`vq->vdev`). Safe wrapper over the
    /// crate-private `Device::from_vq` — lets a driver obtain the device from a `VirtQueue` it
    /// holds (e.g. a virtio-balloon `config_changed`-deferred work closure that has `&VirtQueue`
    /// but not `&Device`, needed to read `num_pages` / write `actual` config fields).
    pub fn device(&self) -> &Device {
        // SAFETY: `self` is a valid registered virtqueue (invariant); `from_vq` recovers its vdev.
        unsafe { Device::from_vq(self.0.as_ptr()) }
    }

    /// Zero-based queue index assigned by the virtio core.
    pub fn index(&self) -> u32 {
        // SAFETY: The queue is live and `index` is immutable after discovery.
        unsafe { (*self.0.as_ptr()).index }
    }

    /// Transport-owned diagnostic name for this queue.
    pub fn name(&self) -> &CStr {
        // SAFETY: A live queue's non-null name is NUL-terminated and remains owned by the driver
        // until `del_vqs`; the returned borrow is tied to this live queue handle.
        let name = unsafe { (*self.0.as_ptr()).name };
        if name.is_null() {
            crate::c_str!("virtqueue")
        } else {
            unsafe { CStr::from_char_ptr(name) }
        }
    }

    /// Submit a single input buffer. Mirrors C's `virtqueue_add_inbuf(vq, &sg, 1, data, gfp)`. The
    /// `flags` (e.g. [`GFP_ATOMIC`] from an IRQ callback, [`GFP_KERNEL`] from process context) reach
    /// the virtqueue allocator verbatim.
    #[inline]
    pub fn add_inbuf(
        &self,
        buf: *mut core::ffi::c_void,
        len: u32,
        token: *mut core::ffi::c_void,
        flags: alloc::Flags,
    ) -> Result {
        let mut sg = core::mem::MaybeUninit::<bindings::scatterlist>::uninit();
        // SAFETY: `sg` is valid uninitialized storage; `sg_init_one` initializes it in place.
        unsafe { bindings::sg_init_one(sg.as_mut_ptr(), buf, len) };
        // SAFETY: `self.0` is a valid virtqueue; `sg` is a valid 1-entry scatterlist.
        to_result(unsafe {
            bindings::virtqueue_add_inbuf(
                self.0.as_ptr(),
                sg.as_mut_ptr(),
                1,
                token,
                flags.as_raw(),
            )
        })
    }

    /// Submit a single output buffer. Mirrors C's `virtqueue_add_outbuf(vq, &sg, 1, data, gfp)`.
    pub fn add_outbuf(
        &self,
        buf: *mut core::ffi::c_void,
        len: u32,
        token: *mut core::ffi::c_void,
        flags: alloc::Flags,
    ) -> Result {
        let mut sg = core::mem::MaybeUninit::<bindings::scatterlist>::uninit();
        // SAFETY: `sg` is valid uninitialized storage; `sg_init_one` initializes it in place.
        unsafe { bindings::sg_init_one(sg.as_mut_ptr(), buf, len) };
        // SAFETY: `self.0` is a valid virtqueue; `sg` is a valid 1-entry scatterlist.
        to_result(unsafe {
            bindings::virtqueue_add_outbuf(
                self.0.as_ptr(),
                sg.as_mut_ptr(),
                1,
                token,
                flags.as_raw(),
            )
        })
    }

    /// Build a virtio-net header/scatterlist and transfer an owned TX packet to this queue.
    ///
    /// On failure the error retains the same packet; on success only
    /// [`Self::get_tx_packet`] or reset recycling can restore ownership.
    #[inline]
    pub fn add_tx_packet(
        &self,
        mut packet: TxPacket,
        options: NetTxOptions,
        flags: alloc::Flags,
    ) -> core::result::Result<(), TxSubmissionError> {
        const CAPACITY: usize = bindings::MAX_SKB_FRAGS as usize + 2;
        let packet_address = packet.as_raw() as usize;
        if packet_address & Self::NET_TX_TOKEN_MASK != 0 {
            return Err(TxSubmissionError {
                error: EINVAL,
                packet,
            });
        }
        let token = (packet_address
            | if options.orphan_after_submit {
                Self::NET_TX_TOKEN_PACKET_ORPHAN
            } else {
                0
            }) as *mut c_void;
        let mut sg = core::mem::MaybeUninit::<[bindings::scatterlist; CAPACITY]>::uninit();
        // SAFETY: `packet` owns a live skb; `sg` has CAPACITY writable entries. The helper
        // initializes exactly the positive count it returns and restores skb data position.
        let count = unsafe {
            bindings::virtio_net_build_tx_sg(
                packet.as_raw(),
                sg.as_mut_ptr().cast(),
                CAPACITY as u32,
                options.header_len,
                options.allow_inline_header,
                options.tunnel_header_negotiated,
                options.little_endian,
                options.vlan_header_len.into(),
                options.has_data_valid,
            )
        };
        if count < 0 {
            return Err(TxSubmissionError {
                error: Error::from_errno(count),
                packet,
            });
        }
        // SAFETY: The helper initialized `count` SG entries whose backing storage is the owned
        // skb. Virtqueue consumes the SG metadata synchronously and retains only the skb token.
        let result = unsafe {
            bindings::virtqueue_add_outbuf(
                self.0.as_ptr(),
                sg.as_mut_ptr().cast(),
                count as u32,
                token,
                flags.as_raw(),
            )
        };
        if result < 0 {
            return Err(TxSubmissionError {
                error: Error::from_errno(result),
                packet,
            });
        }
        if options.orphan_after_submit {
            packet.orphan_and_reset_conntrack();
        }
        core::mem::forget(packet);
        Ok(())
    }

    pub(crate) fn add_borrowed_xdp_frame(
        &self,
        frame: *mut bindings::xdp_frame,
        header_len: u32,
        flags: alloc::Flags,
    ) -> Result {
        let address = frame as usize;
        if frame.is_null() || address & Self::NET_TX_TOKEN_MASK != 0 {
            return Err(EINVAL);
        }
        let token = (address | Self::NET_TX_TOKEN_XDP) as *mut c_void;
        // SAFETY: The callback-scoped frame remains owned by networking core unless this helper
        // succeeds. The helper builds the SG list synchronously and retains only the tagged token.
        to_result(unsafe {
            bindings::virtqueue_add_xdp_frame(
                self.0.as_ptr(),
                frame,
                header_len,
                token,
                flags.as_raw(),
            )
        })
    }

    /// Prepend a zeroed virtio-net header and transfer one owned native XDP frame to this queue.
    pub fn add_xdp_frame(
        &self,
        frame: XdpFrame,
        header_len: u32,
        flags: alloc::Flags,
    ) -> core::result::Result<(), XdpSubmissionError> {
        if let Err(error) = self.add_borrowed_xdp_frame(frame.as_raw(), header_len, flags) {
            return Err(XdpSubmissionError { error, frame });
        }
        let _ = frame.into_raw();
        Ok(())
    }

    /// Submit a trusted premapped input scatterlist. All segments must have been constructed for
    /// this queue and must remain mapped until the token is completed or recycled.
    pub fn add_inbuf_premapped<const N: usize>(
        &self,
        sg: &mut PremappedSg<N>,
        token: *mut c_void,
        context: *mut c_void,
        flags: alloc::Flags,
    ) -> Result {
        if sg.queue != self.0 {
            return Err(EINVAL);
        }
        // SAFETY: `PremappedSg` contains N initialized, chained entries with DMA mappings for this
        // queue. The virtio ring consumes the descriptors synchronously and retains only `token`.
        to_result(unsafe {
            bindings::virtqueue_add_inbuf_premapped(
                self.0.as_ptr(),
                sg.as_mut_ptr(),
                N as u32,
                token,
                context,
                flags.as_raw(),
            )
        })
    }

    /// Submit a trusted premapped output scatterlist.
    pub fn add_outbuf_premapped<const N: usize>(
        &self,
        sg: &mut PremappedSg<N>,
        token: *mut c_void,
        flags: alloc::Flags,
    ) -> Result {
        if sg.queue != self.0 {
            return Err(EINVAL);
        }
        // SAFETY: Same initialized-chain and mapping lifetime guarantee as the input variant.
        to_result(unsafe {
            bindings::virtqueue_add_outbuf_premapped(
                self.0.as_ptr(),
                sg.as_mut_ptr(),
                N as u32,
                token,
                flags.as_raw(),
            )
        })
    }

    /// Submit the shared zero virtio header and one AF_XDP UMEM data segment.
    pub(crate) fn add_xsk_tx_segments(
        &self,
        segments: [DmaSegment; 2],
        length: u32,
        flags: alloc::Flags,
    ) -> Result {
        if length == 0 || length as usize > usize::MAX >> 2 {
            return Err(EINVAL);
        }
        let token = (((length as usize) << 2) | Self::NET_TX_TOKEN_XSK) as *mut c_void;
        let mut sg = PremappedSg::new(segments)?;
        self.add_outbuf_premapped(&mut sg, token, flags)
    }

    /// Transfer an owned mapped buffer to one input descriptor. On submission failure the mapping
    /// is reclaimed and dropped; on success the queue owns it until completion or reset recycling.
    pub fn add_dma_inbuf(
        &self,
        mut buffer: KBox<DmaBuffer>,
        range: Range<usize>,
        context: *mut c_void,
        flags: alloc::Flags,
    ) -> Result {
        if buffer.queue != self.0 {
            return Err(EINVAL);
        }
        let segment = buffer.prepare_submission(range)?;
        let mut sg = PremappedSg::new([segment])?;
        let raw = KBox::into_raw(buffer);
        match self.add_inbuf_premapped(&mut sg, raw.cast(), context, flags) {
            Ok(()) => Ok(()),
            Err(error) => {
                // SAFETY: Submission failed, so the queue did not take ownership of `raw`.
                drop(unsafe { KBox::<DmaBuffer>::from_raw(raw) });
                Err(error)
            }
        }
    }

    /// Transfer an owned page-backed receive allocation to one premapped input descriptor chain.
    /// On failure the mappings and page references are reclaimed and dropped; on success the
    /// queue owns them until completion or synchronous recycling.
    #[inline]
    pub fn add_rx_page_buffer(
        &self,
        mut buffer: KBox<RxPageBuffer>,
        context: *mut c_void,
        flags: alloc::Flags,
    ) -> Result {
        if buffer.queue != self.0 {
            return Err(EINVAL);
        }
        if let Some(segment) = buffer.prepare_single_submission()? {
            let mut sg = PremappedSg::new([segment])?;
            let raw = KBox::into_raw(buffer);
            match self.add_inbuf_premapped(&mut sg, raw.cast(), context, flags) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    // SAFETY: Submission failed, so the queue did not take ownership of `raw`.
                    drop(unsafe { KBox::<RxPageBuffer>::from_raw(raw) });
                    return Err(error);
                }
            }
        }
        let segments = buffer.prepare_submission(flags)?;
        let mut sg = PremappedSgDyn::new(&segments, flags)?;
        if sg.queue != self.0 {
            return Err(EINVAL);
        }
        let raw = KBox::into_raw(buffer);
        // SAFETY: `sg` is an initialized premapped chain for this queue. The queue consumes only
        // its descriptor values; `raw` keeps every mapping and page live until completion.
        let result = to_result(unsafe {
            bindings::virtqueue_add_inbuf_premapped(
                self.0.as_ptr(),
                sg.as_mut_ptr(),
                sg.len(),
                raw.cast(),
                context,
                flags.as_raw(),
            )
        });
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                // SAFETY: Submission failed, so the queue did not take ownership of `raw`.
                drop(unsafe { KBox::<RxPageBuffer>::from_raw(raw) });
                Err(error)
            }
        }
    }

    /// Transfer an owned mapped buffer to one output descriptor, with the same failure ownership
    /// semantics as [`Self::add_dma_inbuf`].
    pub fn add_dma_outbuf(
        &self,
        mut buffer: KBox<DmaBuffer>,
        range: Range<usize>,
        flags: alloc::Flags,
    ) -> Result {
        if buffer.queue != self.0 {
            return Err(EINVAL);
        }
        let segment = buffer.prepare_submission(range)?;
        let mut sg = PremappedSg::new([segment])?;
        let raw = KBox::into_raw(buffer);
        match self.add_outbuf_premapped(&mut sg, raw.cast(), flags) {
            Ok(()) => Ok(()),
            Err(error) => {
                // SAFETY: Submission failed, so the queue did not take ownership of `raw`.
                drop(unsafe { KBox::<DmaBuffer>::from_raw(raw) });
                Err(error)
            }
        }
    }

    /// Submit a chain of scatterlists in both directions. Mirrors C's
    /// `virtio_add_sgs(vq, sgs, out, in, data, gfp)`: `sgs[..out]` are out-direction chains (each a
    /// `*mut scatterlist` to a NULL-terminated chain), `sgs[out..out+in]` are in-direction chains.
    /// Used by drivers that build multi-element requests (e.g. virtio-blk's out-header/data/in-header).
    ///
    /// Each entry of `sgs` must point to a valid, NULL-terminated scatterlist chain that outlives the
    /// buffer's residence in the virtqueue (reclaimed by [`VirtQueue::get_buf`]) — the caller owns
    /// this chain management (the same contract as [`Self::add_inbuf`]); the abstraction owns the
    /// FFI. (Previously `unsafe fn`; made safe so drivers calling it stay 0-unsafe.)
    pub fn add_sgs(
        &self,
        sgs: &[*mut bindings::scatterlist],
        out: u32,
        in_count: u32,
        token: *mut core::ffi::c_void,
        flags: alloc::Flags,
    ) -> Result {
        // SAFETY: the caller guarantees each `sgs` entry is a valid NULL-terminated chain.
        to_result(unsafe {
            bindings::virtqueue_add_sgs(
                self.0.as_ptr(),
                sgs.as_ptr() as *mut *mut bindings::scatterlist,
                out,
                in_count,
                token,
                flags.as_raw(),
            )
        })
    }

    /// Send one synchronous virtio-net control command.
    ///
    /// `out` contains at most two device-readable payload segments after the
    /// two-byte class/command header. `reply`, when present, follows the
    /// one-byte acknowledgement in the device-writable descriptor stream. The
    /// method does not return until the device completes the command, so every
    /// borrowed slice remains valid for the entire DMA-visible interval.
    ///
    /// Callers must serialize this method with every other user of the same
    /// control queue. It may reschedule while waiting and therefore must not be
    /// called from hard IRQ or while holding a spin lock.
    pub fn send_net_control_command(
        &self,
        class: u8,
        command: u8,
        out: &[&[u8]],
        mut reply: Option<&mut [u8]>,
        flags: alloc::Flags,
    ) -> Result {
        const MAX_PAYLOAD_SEGMENTS: usize = 2;
        const MAX_SGS: usize = 5;
        if out.len() > MAX_PAYLOAD_SEGMENTS
            || out
                .iter()
                .any(|segment| segment.is_empty() || segment.len() > u32::MAX as usize)
            || reply
                .as_ref()
                .is_some_and(|segment| segment.is_empty() || segment.len() > u32::MAX as usize)
        {
            return Err(EINVAL);
        }

        let header = [class, command];
        let mut acknowledgement = u8::MAX;
        let completion_token = core::ptr::from_mut(&mut acknowledgement).cast::<c_void>();
        let mut entries = core::mem::MaybeUninit::<[bindings::scatterlist; MAX_SGS]>::uninit();
        let entries = entries.as_mut_ptr().cast::<bindings::scatterlist>();
        let mut sgs = [core::ptr::null_mut(); MAX_SGS];
        let mut entry = 0usize;

        // SAFETY: `entries` has MAX_SGS writable slots and header lives until
        // the synchronous completion below.
        unsafe {
            bindings::sg_init_one(
                entries.add(entry),
                header.as_ptr().cast(),
                header.len() as u32,
            )
        };
        sgs[entry] = unsafe { entries.add(entry) };
        entry += 1;

        for segment in out {
            // SAFETY: The explicit bound check permits the length conversion;
            // every borrowed segment outlives this synchronous transaction.
            unsafe {
                bindings::sg_init_one(
                    entries.add(entry),
                    segment.as_ptr().cast(),
                    segment.len() as u32,
                )
            };
            sgs[entry] = unsafe { entries.add(entry) };
            entry += 1;
        }
        let out_count = entry as u32;

        // SAFETY: `acknowledgement` is writable and lives until completion.
        unsafe {
            bindings::sg_init_one(
                entries.add(entry),
                core::ptr::from_mut(&mut acknowledgement).cast(),
                1,
            )
        };
        sgs[entry] = unsafe { entries.add(entry) };
        entry += 1;

        if let Some(segment) = reply.as_deref_mut() {
            // SAFETY: The mutable borrow is exclusive and remains live until
            // the synchronous completion.
            unsafe {
                bindings::sg_init_one(
                    entries.add(entry),
                    segment.as_mut_ptr().cast(),
                    segment.len() as u32,
                )
            };
            sgs[entry] = unsafe { entries.add(entry) };
            entry += 1;
        }
        let in_count = entry as u32 - out_count;

        // SAFETY: Every pointer in the used prefix names an initialized,
        // single-entry scatterlist; all backing storage remains live until the
        // matching completion token is retrieved below.
        to_result(unsafe {
            bindings::virtqueue_add_sgs(
                self.0.as_ptr(),
                sgs.as_mut_ptr(),
                out_count,
                in_count,
                completion_token,
                flags.as_raw(),
            )
        })?;
        if !self.kick() {
            return Err(EIO);
        }

        loop {
            if let Some((token, _length)) = self.get_buf() {
                if token != completion_token {
                    return Err(EIO);
                }
                break;
            }
            // SAFETY: The queue remains live for this synchronous method.
            if unsafe { bindings::virtqueue_is_broken(self.0.as_ptr()) } {
                return Err(EIO);
            }
            // SAFETY: This method is restricted to a reschedulable context.
            unsafe { bindings::__cond_resched() };
            core::hint::spin_loop();
        }

        if acknowledgement == 0 {
            Ok(())
        } else {
            Err(EIO)
        }
    }

    /// Retrieve a completed buffer. Mirrors C's `virtqueue_get_buf(vq, &len)`.
    #[inline(always)]
    pub fn get_buf(&self) -> Option<(*mut core::ffi::c_void, u32)> {
        let mut len: core::ffi::c_uint = 0;
        // SAFETY: `self.0` is a valid virtqueue.
        let ptr = unsafe { bindings::virtqueue_get_buf(self.0.as_ptr(), &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some((ptr, len))
        }
    }

    /// Restore a completed packet submitted by [`Self::add_tx_packet`].
    pub fn get_tx_packet(&self) -> Option<(TxPacket, u32)> {
        let (token, length) = self.get_buf()?;
        let address = token as usize;
        debug_assert!(matches!(
            address & Self::NET_TX_TOKEN_MASK,
            0 | Self::NET_TX_TOKEN_PACKET_ORPHAN
        ));
        // SAFETY: A queue using this typed completion method submits only `TxPacket` tokens.
        Some((
            unsafe {
                TxPacket::from_raw((address & !Self::NET_TX_TOKEN_MASK) as *mut bindings::sk_buff)
            },
            length,
        ))
    }

    /// Restore one packet token returned synchronously by reset, resize, or detach.
    pub fn reclaim_tx_packet(token: *mut c_void) -> TxPacket {
        let address = token as usize;
        debug_assert!(matches!(
            address & Self::NET_TX_TOKEN_MASK,
            0 | Self::NET_TX_TOKEN_PACKET_ORPHAN
        ));
        // SAFETY: The token contract requires a value previously submitted by `add_tx_packet`.
        unsafe {
            TxPacket::from_raw((address & !Self::NET_TX_TOKEN_MASK) as *mut bindings::sk_buff)
        }
    }

    #[inline]
    fn restore_net_tx(token: *mut c_void) -> Result<NetTxCompletion> {
        let address = token as usize;
        match address & Self::NET_TX_TOKEN_MASK {
            0 => {
                // SAFETY: An untagged token in a typed net TX queue came from `add_tx_packet`.
                Ok(NetTxCompletion::Packet {
                    packet: unsafe { TxPacket::from_raw(token.cast()) },
                    byte_queue_limits: true,
                })
            }
            Self::NET_TX_TOKEN_PACKET_ORPHAN => {
                let raw = (address & !Self::NET_TX_TOKEN_MASK) as *mut bindings::sk_buff;
                // SAFETY: The orphan tag is installed only after successful skb submission and
                // completion/reset restores unique driver ownership.
                Ok(NetTxCompletion::Packet {
                    packet: unsafe { TxPacket::from_raw(raw) },
                    byte_queue_limits: false,
                })
            }
            Self::NET_TX_TOKEN_XDP => {
                let raw = (address & !Self::NET_TX_TOKEN_MASK) as *mut bindings::xdp_frame;
                // SAFETY: The XDP tag is installed only after successful frame submission and
                // completion/reset restores unique driver ownership.
                Ok(NetTxCompletion::Xdp(unsafe { XdpFrame::from_raw(raw)? }))
            }
            Self::NET_TX_TOKEN_XSK => Ok(NetTxCompletion::Xsk {
                length: (address >> 2).try_into().map_err(|_| EOVERFLOW)?,
            }),
            _ => unreachable!(),
        }
    }

    /// Retrieve one typed skb/XDP/AF_XDP completion from a shared virtio-net TX queue.
    #[inline]
    pub fn get_net_tx_completion(&self) -> Result<Option<(NetTxCompletion, u32)>> {
        let Some((token, length)) = self.get_buf() else {
            return Ok(None);
        };
        Ok(Some((Self::restore_net_tx(token)?, length)))
    }

    /// Restore one typed skb/XDP/AF_XDP token returned synchronously by reset, resize, or detach.
    pub fn reclaim_net_tx(token: *mut c_void) -> Result<NetTxCompletion> {
        Self::restore_net_tx(token)
    }

    /// Retrieve a completed buffer and its context token. Mirrors C's
    /// `virtqueue_get_buf_ctx(vq, &len, &ctx)` (only meaningful for vqs created with `ctx = true`).
    pub fn get_buf_ctx(&self) -> Option<(*mut core::ffi::c_void, u32, *mut core::ffi::c_void)> {
        let mut len: core::ffi::c_uint = 0;
        let mut ctx: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `self.0` is a valid virtqueue.
        let ptr = unsafe { bindings::virtqueue_get_buf_ctx(self.0.as_ptr(), &mut len, &mut ctx) };
        if ptr.is_null() {
            None
        } else {
            Some((ptr, len, ctx))
        }
    }

    /// Retrieve a completed buffer submitted by [`Self::add_dma_inbuf`] or
    /// [`Self::add_dma_outbuf`] and restore its unique ownership.
    ///
    /// A queue using this method must use `DmaBuffer` tokens consistently; mixing unrelated token
    /// types is a driver contract violation, just as with the typed C completion callback.
    pub fn get_dma_buffer_ctx(&self) -> Result<Option<(KBox<DmaBuffer>, u32, *mut c_void)>> {
        let Some((token, length, context)) = self.get_buf_ctx() else {
            return Ok(None);
        };
        let mut buffer = Self::reclaim_dma_buffer_raw(token);
        buffer.finish_submission(Some(length))?;
        Ok(Some((buffer, length, context)))
    }

    /// Retrieve a completed page-backed receive allocation from a queue without context tokens.
    pub fn get_rx_page_buffer(&self) -> Result<Option<(KBox<RxPageBuffer>, u32)>> {
        let Some((token, length)) = self.get_buf() else {
            return Ok(None);
        };
        let mut buffer = Self::reclaim_rx_page_buffer_raw(token);
        buffer.finish_submission(Some(length))?;
        Ok(Some((buffer, length)))
    }

    /// Retrieve a completed page-backed receive allocation and restore its unique ownership.
    #[inline]
    pub fn get_rx_page_buffer_ctx(&self) -> Result<Option<(KBox<RxPageBuffer>, u32, *mut c_void)>> {
        let Some((token, length, context)) = self.get_buf_ctx() else {
            return Ok(None);
        };
        let mut buffer = Self::reclaim_rx_page_buffer_raw(token);
        buffer.finish_submission(Some(length))?;
        Ok(Some((buffer, length, context)))
    }

    /// Reclaim a page-backed receive token returned by detach, reset or resize.
    pub fn reclaim_rx_page_buffer(token: *mut c_void) -> Result<KBox<RxPageBuffer>> {
        let mut buffer = Self::reclaim_rx_page_buffer_raw(token);
        buffer.finish_submission(None)?;
        Ok(buffer)
    }

    fn reclaim_rx_page_buffer_raw(token: *mut c_void) -> KBox<RxPageBuffer> {
        // SAFETY: By contract, `token` came from `add_rx_page_buffer`, which stores exactly one
        // `KBox<RxPageBuffer>::into_raw` value as the queue token.
        unsafe { KBox::from_raw(token.cast()) }
    }

    /// Reclaim a DMA buffer token returned by completion, detach, reset, or resize.
    pub fn reclaim_dma_buffer(token: *mut c_void) -> Result<KBox<DmaBuffer>> {
        let mut buffer = Self::reclaim_dma_buffer_raw(token);
        buffer.finish_submission(None)?;
        Ok(buffer)
    }

    fn reclaim_dma_buffer_raw(token: *mut c_void) -> KBox<DmaBuffer> {
        // SAFETY: By contract, `token` came from `add_dma_inbuf` or `add_dma_outbuf`, which stores
        // `KBox<DmaBuffer>::into_raw` as the opaque token exactly once.
        unsafe { KBox::from_raw(token.cast()) }
    }

    /// Notify the device that buffers are available. Mirrors C's `virtqueue_kick(vq)`.
    #[inline(always)]
    pub fn kick(&self) -> bool {
        // SAFETY: `self.0` is a valid virtqueue.
        unsafe { bindings::virtqueue_kick(self.0.as_ptr()) }
    }

    /// Read the vring size (max descriptors). Mirrors C's `virtqueue_get_vring_size(vq)`.
    pub fn vring_size(&self) -> u32 {
        // SAFETY: `self.0` is a valid virtqueue.
        unsafe { bindings::virtqueue_get_vring_size(self.0.as_ptr()) as u32 }
    }

    /// Maximum ring size supported by this virtqueue's transport.
    pub fn max_ring_size(&self) -> u32 {
        // SAFETY: `self.0` is a live virtqueue and `num_max` is immutable after discovery.
        unsafe { (*self.0.as_ptr()).num_max }
    }

    /// Number of currently free descriptors. Driver-side queue serialization
    /// must cover this snapshot and the following submission decision.
    #[inline(always)]
    pub fn num_free(&self) -> u32 {
        // SAFETY: `self.0` is a live virtqueue and the driver serializes ring mutation.
        unsafe { (*self.0.as_ptr()).num_free }
    }

    /// Prepare a kick (expose buffers to the device) without notifying. Mirrors C's
    /// `virtqueue_kick_prepare(vq)`; pair with [`VirtQueue::notify`] to batch notifications.
    #[inline(always)]
    pub fn kick_prepare(&self) -> bool {
        // SAFETY: `self.0` is a valid virtqueue.
        unsafe { bindings::virtqueue_kick_prepare(self.0.as_ptr()) }
    }

    /// Notify the device (the second half of a batched kick). Mirrors C's `virtqueue_notify(vq)`.
    #[inline(always)]
    pub fn notify(&self) -> bool {
        // SAFETY: `self.0` is a valid virtqueue.
        unsafe { bindings::virtqueue_notify(self.0.as_ptr()) }
    }

    /// Disable callbacks on this virtqueue. Mirrors C's `virtqueue_disable_cb(vq)`.
    #[inline(always)]
    pub fn disable_cb(&self) {
        // SAFETY: `self.0` is a valid virtqueue.
        unsafe { bindings::virtqueue_disable_cb(self.0.as_ptr()) };
    }

    /// Re-enable callbacks; returns `false` if more buffers are pending. Mirrors C's
    /// `virtqueue_enable_cb(vq)`.
    #[inline(always)]
    pub fn enable_cb(&self) -> bool {
        // SAFETY: `self.0` is a valid virtqueue.
        unsafe { bindings::virtqueue_enable_cb(self.0.as_ptr()) }
    }

    /// Re-enable callbacks while capturing the opaque queue state needed to close the NAPI
    /// completion race. Consume the returned token with [`CallbackPoll::poll`].
    #[inline(always)]
    pub fn enable_cb_prepare(&self) -> CallbackPoll<'_> {
        // SAFETY: `self.0` is a valid virtqueue.
        let opaque = unsafe { bindings::virtqueue_enable_cb_prepare(self.0.as_ptr()) };
        CallbackPoll {
            queue: self,
            opaque,
        }
    }

    /// Re-enable callbacks with the virtio delayed-event threshold. Returns `false` when work is
    /// already pending and the caller must schedule/drain the queue again.
    #[inline(always)]
    pub fn enable_cb_delayed(&self) -> bool {
        // SAFETY: `self.0` is a valid virtqueue.
        unsafe { bindings::virtqueue_enable_cb_delayed(self.0.as_ptr()) }
    }

    /// Best-effort transport affinity hint. `None` removes a previously installed hint.
    pub fn set_affinity(&self, mask: Option<&Cpumask>) -> Result {
        // SAFETY: Every live virtqueue points at its live owning virtio device and config table.
        let vdev = unsafe { (*self.0.as_ptr()).vdev };
        let config = unsafe { (*vdev).config };
        let Some(set_affinity) = (unsafe { (*config).set_vq_affinity }) else {
            return Ok(());
        };
        let raw_mask = mask.map_or(core::ptr::null(), |mask| mask.as_raw().cast_const());
        // SAFETY: The queue is live and `raw_mask` is either NULL or borrowed for this call.
        to_result(unsafe { set_affinity(self.0.as_ptr(), raw_mask) })
    }

    /// Reset this queue and synchronously return every unused token through [`QueueRecycle`].
    /// `notify_done` selects the C `recycle_done` callback used by TX accounting paths.
    pub fn reset<D: QueueRecycle>(&self, notify_done: bool) -> Result {
        // SAFETY: The driver guarantees its normal queue users are quiesced. The Adapter callbacks
        // recover the bound `D` and run synchronously before this function returns.
        to_result(unsafe {
            bindings::virtqueue_reset(
                self.0.as_ptr(),
                Some(Adapter::<D>::vq_recycle_callback),
                notify_done.then_some(Adapter::<D>::vq_recycle_done_callback),
            )
        })
    }

    /// Resize this queue and synchronously return tokens detached from the old ring through
    /// [`QueueRecycle`]. The virtio core rejects zero or unsupported sizes.
    pub fn resize<D: QueueRecycle>(&self, new_size: u32, notify_done: bool) -> Result {
        // SAFETY: The driver guarantees its normal queue users are quiesced. Callback ownership is
        // identical to [`Self::reset`] and remains valid for this synchronous call.
        to_result(unsafe {
            bindings::virtqueue_resize(
                self.0.as_ptr(),
                new_size,
                Some(Adapter::<D>::vq_recycle_callback),
                notify_done.then_some(Adapter::<D>::vq_recycle_done_callback),
            )
        })
    }

    /// Detach an unused (never-consumed) buffer, reclaiming its token. Mirrors C's
    /// `virtqueue_detach_unused_buf(vq)`. Used in remove/freeze to reclaim buffers the device never
    /// consumed.
    pub fn detach_unused_buf(&self) -> Option<*mut core::ffi::c_void> {
        // SAFETY: `self.0` is a valid virtqueue.
        let ptr = unsafe { bindings::virtqueue_detach_unused_buf(self.0.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    /// Read a `Copy` payload out of a vq token — a `void *` returned by [`Self::get_buf`] for an
    /// in-direction buffer the driver manages (e.g. a slot of a static array). The abstraction owns
    /// the `ptr::read`, so the driver dereferences no raw pointer and stays 0-unsafe.
    ///
    /// The driver MUST only pass a token that is a valid, aligned, initialized `*const T` (the
    /// buffer-management contract of [`Self::add_inbuf`]). Generic so it monomorphizes into the
    /// driver module (no extra exported symbol); not a protocol step, so it is invisible to the
    /// vq-lifecycle protocol checks (the driver still calls `get_buf` / `add_inbuf` for those).
    pub fn read_token<T: Copy>(token: *mut core::ffi::c_void) -> T {
        // SAFETY: by contract, `token` is a valid, aligned, initialized `*const T`.
        unsafe { core::ptr::read(token as *const T) }
    }

    /// Reclaim an owned (`KBox`-allocated) buffer from its vq token, reconstructing the `KBox`
    /// internally so the driver never calls `KBox::from_raw`. Dropping the returned box frees the
    /// allocation (mirrors C `kfree`). The driver MUST only pass a token produced by
    /// `KBox::into_raw::<T>` (e.g. a buffer submitted via [`Self::add_outbuf`]). Generic so it
    /// monomorphizes into the driver module; not a protocol step.
    pub fn reclaim_boxed<T>(token: *mut core::ffi::c_void) -> KBox<T> {
        // SAFETY: by contract, `token` was produced by `KBox::into_raw::<T>`.
        unsafe { KBox::from_raw(token as *mut T) }
    }
}

// Identity comparison by the underlying virtqueue pointer (a driver with multiple vqs distinguishes
// them in `vq_callback` via `==`).
impl PartialEq for VirtQueue {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ptr() == other.0.as_ptr()
    }
}
