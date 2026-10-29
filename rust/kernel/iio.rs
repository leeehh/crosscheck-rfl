// SPDX-License-Identifier: GPL-2.0

//! Industrial I/O subsystem abstractions.
//!
//! C headers: [`include/linux/iio/iio.h`](srctree/include/linux/iio/iio.h),
//! [`include/linux/iio/buffer.h`](srctree/include/linux/iio/buffer.h), and
//! [`include/linux/iio/triggered_buffer.h`](srctree/include/linux/iio/triggered_buffer.h)

use crate::{
    bindings,
    device::{self, Device},
    error::{from_err_ptr, from_result, to_result},
    ffi::{c_int, c_long, c_ulong, c_void},
    fmt, irq,
    prelude::*,
    str::CString,
};

use core::{marker::PhantomData, mem::size_of, ptr, ptr::NonNull};

/// Return value tags for IIO `read_raw` callbacks.
pub mod value {
    use crate::{bindings, ffi::c_int};

    /// `IIO_VAL_INT`.
    pub const INT: c_int = bindings::IIO_VAL_INT as c_int;
    /// `IIO_VAL_INT_PLUS_MICRO`.
    pub const INT_PLUS_MICRO: c_int = bindings::IIO_VAL_INT_PLUS_MICRO as c_int;
    /// `IIO_VAL_FRACTIONAL_LOG2`.
    pub const FRACTIONAL_LOG2: c_int = bindings::IIO_VAL_FRACTIONAL_LOG2 as c_int;
}

/// IIO channel information masks.
pub mod info {
    use crate::{bindings, ffi::c_ulong};

    /// `IIO_CHAN_INFO_RAW`.
    pub const RAW: c_ulong = bindings::iio_chan_info_enum_IIO_CHAN_INFO_RAW as c_ulong;
    /// `IIO_CHAN_INFO_SCALE`.
    pub const SCALE: c_ulong = bindings::iio_chan_info_enum_IIO_CHAN_INFO_SCALE as c_ulong;
    /// `IIO_CHAN_INFO_SAMP_FREQ`.
    pub const SAMP_FREQ: c_ulong = bindings::iio_chan_info_enum_IIO_CHAN_INFO_SAMP_FREQ as c_ulong;

    /// Bit for [`RAW`].
    pub const RAW_BIT: c_ulong = 1 << RAW;
    /// Bit for [`SCALE`].
    pub const SCALE_BIT: c_ulong = 1 << SCALE;
    /// Bit for [`SAMP_FREQ`].
    pub const SAMP_FREQ_BIT: c_ulong = 1 << SAMP_FREQ;
}

/// IIO operating modes.
pub mod mode {
    use crate::{bindings, ffi::c_int};

    /// `INDIO_DIRECT_MODE`.
    pub const DIRECT: c_int = bindings::INDIO_DIRECT_MODE as c_int;
}

/// IIO channel type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelType(bindings::iio_chan_type);

impl ChannelType {
    /// `IIO_VOLTAGE`.
    pub const VOLTAGE: Self = Self(bindings::iio_chan_type_IIO_VOLTAGE);
    /// `IIO_TEMP`.
    pub const TEMP: Self = Self(bindings::iio_chan_type_IIO_TEMP);
    /// `IIO_TIMESTAMP`.
    pub const TIMESTAMP: Self = Self(bindings::iio_chan_type_IIO_TIMESTAMP);

    const fn as_raw(self) -> bindings::iio_chan_type {
        self.0
    }

    fn from_raw(raw: bindings::iio_chan_type) -> Self {
        Self(raw)
    }
}

/// IIO scan endianness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endianness(bindings::iio_endian);

impl Endianness {
    /// `IIO_CPU`.
    pub const CPU: Self = Self(bindings::iio_endian_IIO_CPU);
    /// `IIO_BE`.
    pub const BE: Self = Self(bindings::iio_endian_IIO_BE);

    const fn as_raw(self) -> bindings::iio_endian {
        self.0
    }
}

/// Buffered scan layout for one IIO channel.
#[derive(Clone, Copy)]
pub struct ScanType {
    /// Channel sign, usually `b'u'` or `b's'`.
    pub sign: u8,
    /// Number of real data bits.
    pub realbits: u8,
    /// Number of storage bits.
    pub storagebits: u8,
    /// Right shift applied by the IIO core.
    pub shift: u8,
    /// Repeat count.
    pub repeat: u8,
    /// Storage endianness.
    pub endianness: Endianness,
}

impl ScanType {
    /// Create a scan type.
    pub const fn new(
        sign: u8,
        realbits: u8,
        storagebits: u8,
        shift: u8,
        endianness: Endianness,
    ) -> Self {
        Self {
            sign,
            realbits,
            storagebits,
            shift,
            repeat: 0,
            endianness,
        }
    }

    const fn as_raw(self) -> bindings::iio_scan_type {
        bindings::iio_scan_type {
            sign: self.sign,
            realbits: self.realbits,
            storagebits: self.storagebits,
            shift: self.shift,
            repeat: self.repeat,
            endianness: self.endianness.as_raw(),
        }
    }
}

/// Static IIO channel descriptor.
#[repr(transparent)]
pub struct ChannelSpec(bindings::iio_chan_spec);

impl ChannelSpec {
    /// Create a simple channel descriptor with a single scan type.
    pub const fn new(
        type_: ChannelType,
        info_mask_separate: c_ulong,
        info_mask_shared_by_type: c_ulong,
        info_mask_shared_by_all: c_ulong,
        scan_index: c_int,
        scan_type: ScanType,
    ) -> Self {
        Self(bindings::iio_chan_spec {
            type_: type_.as_raw(),
            channel: 0,
            channel2: 0,
            address: 0,
            scan_index,
            __bindgen_anon_1: bindings::iio_chan_spec__bindgen_ty_1 {
                scan_type: scan_type.as_raw(),
            },
            info_mask_separate,
            info_mask_separate_available: 0,
            info_mask_shared_by_type,
            info_mask_shared_by_type_available: 0,
            info_mask_shared_by_dir: 0,
            info_mask_shared_by_dir_available: 0,
            info_mask_shared_by_all,
            info_mask_shared_by_all_available: 0,
            event_spec: ptr::null(),
            num_event_specs: 0,
            ext_info: ptr::null(),
            extend_name: ptr::null(),
            datasheet_name: ptr::null(),
            _bitfield_align_1: [],
            _bitfield_1: bindings::__BindgenBitfieldUnit::new([0u8; 1]),
            __bindgen_padding_0: [0u8; 7],
        })
    }

    /// Create an `IIO_CHAN_SOFT_TIMESTAMP(index)` descriptor.
    pub const fn soft_timestamp(scan_index: c_int) -> Self {
        Self(bindings::iio_chan_spec {
            type_: ChannelType::TIMESTAMP.as_raw(),
            channel: -1,
            channel2: 0,
            address: 0,
            scan_index,
            __bindgen_anon_1: bindings::iio_chan_spec__bindgen_ty_1 {
                scan_type: ScanType::new(b's', 64, 64, 0, Endianness::CPU).as_raw(),
            },
            info_mask_separate: 0,
            info_mask_separate_available: 0,
            info_mask_shared_by_type: 0,
            info_mask_shared_by_type_available: 0,
            info_mask_shared_by_dir: 0,
            info_mask_shared_by_dir_available: 0,
            info_mask_shared_by_all: 0,
            info_mask_shared_by_all_available: 0,
            event_spec: ptr::null(),
            num_event_specs: 0,
            ext_info: ptr::null(),
            extend_name: ptr::null(),
            datasheet_name: ptr::null(),
            _bitfield_align_1: [],
            _bitfield_1: bindings::__BindgenBitfieldUnit::new([0u8; 1]),
            __bindgen_padding_0: [0u8; 7],
        })
    }

    /// Return the channel type.
    pub fn channel_type(&self) -> ChannelType {
        ChannelType::from_raw(self.0.type_)
    }
}

// SAFETY: Channel descriptors are immutable after construction.
unsafe impl Sync for ChannelSpec {}

/// Value written by an IIO `read_raw` callback.
#[derive(Clone, Copy)]
pub struct RawValue {
    val: c_int,
    val2: c_int,
    kind: c_int,
}

impl RawValue {
    /// Integer result.
    pub const fn int(val: c_int) -> Self {
        Self {
            val,
            val2: 0,
            kind: value::INT,
        }
    }

    /// Integer plus micro-units result.
    pub const fn int_plus_micro(val: c_int, val2: c_int) -> Self {
        Self {
            val,
            val2,
            kind: value::INT_PLUS_MICRO,
        }
    }

    /// Fractional result encoded as `val / 2^val2`.
    pub const fn fractional_log2(val: c_int, val2: c_int) -> Self {
        Self {
            val,
            val2,
            kind: value::FRACTIONAL_LOG2,
        }
    }
}

/// IIO callback operations.
pub trait InfoOps: Sync + Sized {
    /// Read one channel value.
    fn read_raw(
        &self,
        indio_dev: &IioDevice<Self>,
        channel: &ChannelSpec,
        mask: c_long,
    ) -> Result<RawValue>;

    /// Write one channel value.
    fn write_raw(
        &self,
        _indio_dev: &IioDevice<Self>,
        _channel: &ChannelSpec,
        _val: c_int,
        _val2: c_int,
        _mask: c_long,
    ) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Triggered-buffer bottom-half handler.
    fn trigger_handler(&self, _indio_dev: &IioDevice<Self>) -> irq::IrqReturn {
        irq::IrqReturn::Handled
    }
}

/// IIO trigger operations.
pub trait TriggerOps: InfoOps {
    /// Enable or disable the trigger.
    fn set_trigger_state(&self, indio_dev: &IioDevice<Self>, state: bool) -> Result;
}

struct Adapter<T: InfoOps> {
    _p: PhantomData<T>,
}

impl<T: InfoOps> Adapter<T> {
    unsafe fn drvdata<'a>(indio_dev: *mut bindings::iio_dev) -> Result<&'a T> {
        if indio_dev.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: `indio_dev` is valid for the callback duration.
        let data = unsafe { bindings::iio_device_get_drvdata(indio_dev) };
        if data.is_null() {
            return Err(ENOENT);
        }

        // SAFETY: `IioDevice::set_drvdata` stores a pointer to `T` that lives for the
        // registered IIO device lifetime.
        Ok(unsafe { &*data.cast::<T>() })
    }

    unsafe extern "C" fn read_raw_callback(
        indio_dev: *mut bindings::iio_dev,
        chan: *const bindings::iio_chan_spec,
        val: *mut c_int,
        val2: *mut c_int,
        mask: c_long,
    ) -> c_int {
        if chan.is_null() || val.is_null() || val2.is_null() {
            return EINVAL.to_errno();
        }

        let result: Result<c_int> = (|| {
            // SAFETY: The IIO core passes a valid device pointer for the callback duration.
            let data = unsafe { Self::drvdata(indio_dev) }?;
            // SAFETY: `indio_dev` is valid for the callback duration.
            let indio = unsafe { IioDevice::from_raw(indio_dev) };
            // SAFETY: `chan` was checked non-null and points to an entry registered by this
            // module, which uses `ChannelSpec` as a transparent wrapper.
            let channel = unsafe { &*chan.cast::<ChannelSpec>() };
            let value = data.read_raw(&indio, channel, mask)?;

            // SAFETY: output pointers were checked non-null and are owned by the IIO core.
            unsafe {
                *val = value.val;
                *val2 = value.val2;
            }

            Ok(value.kind)
        })();

        match result {
            Ok(v) => v,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn write_raw_callback(
        indio_dev: *mut bindings::iio_dev,
        chan: *const bindings::iio_chan_spec,
        val: c_int,
        val2: c_int,
        mask: c_long,
    ) -> c_int {
        if chan.is_null() {
            return EINVAL.to_errno();
        }

        from_result(|| {
            // SAFETY: The IIO core passes a valid device pointer for the callback duration.
            let data = unsafe { Self::drvdata(indio_dev) }?;
            // SAFETY: `indio_dev` is valid for the callback duration.
            let indio = unsafe { IioDevice::from_raw(indio_dev) };
            // SAFETY: `chan` was checked non-null and points to an entry registered by this
            // module, which uses `ChannelSpec` as a transparent wrapper.
            let channel = unsafe { &*chan.cast::<ChannelSpec>() };
            data.write_raw(&indio, channel, val, val2, mask)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn buffer_thread_callback(
        _irq: c_int,
        ptr: *mut c_void,
    ) -> bindings::irqreturn_t {
        if ptr.is_null() {
            return bindings::irqreturn_IRQ_NONE;
        }

        // SAFETY: The IIO triggered-buffer core passes a valid `struct iio_poll_func *`.
        let poll = unsafe { &*ptr.cast::<bindings::iio_poll_func>() };
        let indio_dev = poll.indio_dev;
        if indio_dev.is_null() {
            return bindings::irqreturn_IRQ_NONE;
        }

        // SAFETY: `indio_dev` is valid for the callback duration.
        let data = match unsafe { Self::drvdata(indio_dev) } {
            Ok(data) => data,
            Err(_) => return bindings::irqreturn_IRQ_NONE,
        };
        // SAFETY: `indio_dev` is valid for the callback duration.
        let indio = unsafe { IioDevice::from_raw(indio_dev) };

        data.trigger_handler(&indio) as bindings::irqreturn_t
    }

    unsafe extern "C" fn set_trigger_state_callback(
        trig: *mut bindings::iio_trigger,
        state: bool,
    ) -> c_int
    where
        T: TriggerOps,
    {
        if trig.is_null() {
            return EINVAL.to_errno();
        }

        from_result(|| {
            // SAFETY: The IIO trigger core passes a valid trigger pointer for the callback
            // duration. The wrapper stores the associated `iio_dev *` as trigger drvdata.
            let indio_dev =
                unsafe { bindings::iio_trigger_get_drvdata(trig) }.cast::<bindings::iio_dev>();
            if indio_dev.is_null() {
                return Err(ENOENT);
            }

            // SAFETY: `indio_dev` is valid for the callback duration.
            let data = unsafe { Self::drvdata(indio_dev) }?;
            // SAFETY: `indio_dev` is valid for the callback duration.
            let indio = unsafe { IioDevice::from_raw(indio_dev) };
            data.set_trigger_state(&indio, state)?;
            Ok(0)
        })
    }
}

/// Wrapper for `struct iio_info`.
#[repr(transparent)]
pub struct Info<T: InfoOps> {
    raw: bindings::iio_info,
    _p: PhantomData<T>,
}

impl<T: InfoOps> Info<T> {
    /// Create an IIO info table with `read_raw` and `write_raw` callbacks.
    pub const fn new() -> Self {
        let mut raw: bindings::iio_info = unsafe { core::mem::zeroed() };
        raw.read_raw = Some(Adapter::<T>::read_raw_callback);
        raw.write_raw = Some(Adapter::<T>::write_raw_callback);
        Self {
            raw,
            _p: PhantomData,
        }
    }

    fn as_raw(&self) -> *const bindings::iio_info {
        &self.raw
    }
}

// SAFETY: The info table is immutable callback metadata.
unsafe impl<T: InfoOps> Sync for Info<T> {}

/// Borrowed/devres-managed IIO device handle.
#[derive(Clone, Copy)]
pub struct IioDevice<T = ()> {
    ptr: NonNull<bindings::iio_dev>,
    _p: PhantomData<T>,
}

impl<T> IioDevice<T> {
    /// Create a borrowed IIO device from a raw callback pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid `struct iio_dev *` for the returned handle's use.
    pub unsafe fn from_raw(ptr: *mut bindings::iio_dev) -> Self {
        Self {
            ptr: NonNull::new(ptr).expect("IioDevice::from_raw received NULL"),
            _p: PhantomData,
        }
    }

    fn as_raw(&self) -> *mut bindings::iio_dev {
        self.ptr.as_ptr()
    }

    /// Allocate a devres-managed IIO device with no C private area.
    pub fn devm_alloc<Ctx: device::DeviceContext>(dev: &Device<Ctx>) -> Result<Self> {
        let ptr = from_err_ptr(unsafe { bindings::iio_devm_device_alloc(dev.as_raw()) })?;
        let ptr = NonNull::new(ptr).ok_or(ENOMEM)?;
        Ok(Self {
            ptr,
            _p: PhantomData,
        })
    }

    /// Store Rust driver data for IIO callbacks.
    ///
    /// # Safety
    ///
    /// `data` must remain valid for as long as the IIO device is registered.
    pub unsafe fn set_drvdata(&self, data: *const T) {
        unsafe { bindings::iio_device_set_drvdata(self.as_raw(), data.cast_mut().cast()) };
    }

    /// Store Rust driver data for IIO callbacks from a pinned reference.
    ///
    /// This is the safe counterpart to [`set_drvdata`]. The caller passes `data: Pin<&T>` —
    /// typically the driver's own pinned object obtained in a `pin_chain` or the bus driver's
    /// *bound* phase — which must stay valid (i.e. the devres-managed `IioDevice` lives inside, or
    /// alongside, that same `T`) for as long as the IIO device is registered. No caller-side
    /// `unsafe` is required.
    ///
    /// [`set_drvdata`]: Self::set_drvdata
    pub fn set_drvdata_pinned(&self, data: Pin<&T>) {
        // SAFETY: `data` is a pinned reference to a `T` the caller keeps alive for at least the
        // IIO device's registration lifetime (the driver object that owns this devres-managed
        // device), so the stored pointer stays valid while the device is registered.
        unsafe { self.set_drvdata(Pin::get_ref(data)) };
    }

    /// Set `iio_dev::name`.
    pub fn set_name(&self, name: &CStr) {
        // SAFETY: `self.as_raw()` is valid and the name pointer remains valid for the device
        // lifetime when supplied from a static C string or device-owned name.
        unsafe { (*self.as_raw()).name = name.as_char_ptr() };
    }

    /// Set `iio_dev::modes`.
    pub fn set_modes(&self, modes: c_int) {
        unsafe { (*self.as_raw()).modes = modes };
    }

    /// Set the IIO info table.
    pub fn set_info(&self, info: &'static Info<T>)
    where
        T: InfoOps,
    {
        unsafe { (*self.as_raw()).info = info.as_raw() };
    }

    /// Set the static channel list.
    pub fn set_channels(&self, channels: &'static [ChannelSpec]) {
        unsafe {
            (*self.as_raw()).channels = channels.as_ptr().cast::<bindings::iio_chan_spec>();
            (*self.as_raw()).num_channels = channels.len() as c_int;
        }
    }

    /// Set the zero-terminated available scan masks.
    pub fn set_available_scan_masks(&self, masks: &'static [c_ulong]) {
        unsafe { (*self.as_raw()).available_scan_masks = masks.as_ptr() };
    }

    /// Register this IIO device with devres-managed cleanup.
    pub fn devm_register<Ctx: device::DeviceContext>(&self, dev: &Device<Ctx>) -> Result {
        to_result(unsafe { bindings::iio_devm_device_register(dev.as_raw(), self.as_raw()) })
    }

    /// Return the IIO core device id.
    pub fn id(&self) -> c_int {
        unsafe { bindings::iio_device_id_safe(self.as_raw()) }
    }

    /// Return an IIO timestamp in nanoseconds.
    pub fn time_ns(&self) -> i64 {
        unsafe { bindings::iio_time_ns(self.as_raw()) }
    }

    /// Push one scan sample to the active IIO buffers with a timestamp.
    pub fn push_to_buffers_with_ts<D>(&self, data: &D, timestamp: i64) -> Result {
        to_result(unsafe {
            bindings::iio_push_to_buffers_with_ts(
                self.as_raw(),
                (data as *const D).cast(),
                size_of::<D>(),
                timestamp,
            )
        })
    }

    /// Claim direct mode until the returned guard is dropped.
    pub fn claim_direct(&self) -> Result<DirectModeGuard<'_, T>> {
        let claimed = unsafe { bindings::iio_device_claim_direct(self.as_raw()) };
        if claimed {
            Ok(DirectModeGuard { dev: self })
        } else {
            Err(EBUSY)
        }
    }

    /// Configure a standard triggered buffer using [`InfoOps::trigger_handler`].
    pub fn devm_triggered_buffer_setup<Ctx>(&self, dev: &Device<Ctx>) -> Result
    where
        Ctx: device::DeviceContext,
        T: InfoOps,
    {
        to_result(unsafe {
            bindings::iio_devm_triggered_buffer_setup(
                dev.as_raw(),
                self.as_raw(),
                None,
                Some(Adapter::<T>::buffer_thread_callback),
            )
        })
    }

    /// Notify the current trigger that the triggered-buffer handler is done.
    pub fn trigger_notify_done(&self) {
        unsafe { bindings::iio_notify_trigger_done(self.as_raw()) };
    }

    /// Set this device's current trigger, taking the IIO trigger reference required by C
    /// `indio_dev->trig = iio_trigger_get(trig)`.
    pub fn set_trigger(&self, trigger: &DeviceManagedTrigger<T>) -> Result {
        to_result(unsafe { bindings::iio_device_set_trigger(self.as_raw(), trigger.as_raw()) })
    }
}

/// Devres-managed IIO trigger handle.
#[derive(Clone, Copy)]
pub struct DeviceManagedTrigger<T = ()> {
    ptr: NonNull<bindings::iio_trigger>,
    _p: PhantomData<T>,
}

impl<T> DeviceManagedTrigger<T> {
    fn as_raw(&self) -> *mut bindings::iio_trigger {
        self.ptr.as_ptr()
    }

    /// Allocate a devres-managed IIO trigger with the given preformatted name.
    pub fn devm_alloc<Ctx: device::DeviceContext>(dev: &Device<Ctx>, name: &CStr) -> Result<Self> {
        let ptr = from_err_ptr(unsafe {
            bindings::iio_devm_trigger_alloc(dev.as_raw(), name.as_char_ptr())
        })?;
        let ptr = NonNull::new(ptr).ok_or(ENOMEM)?;
        Ok(Self {
            ptr,
            _p: PhantomData,
        })
    }

    /// Allocate a devres-managed IIO trigger from formatted arguments.
    pub fn devm_alloc_fmt<Ctx: device::DeviceContext>(
        dev: &Device<Ctx>,
        args: fmt::Arguments<'_>,
    ) -> Result<Self> {
        let name = CString::try_from_fmt(args)?;
        Self::devm_alloc(dev, &name)
    }

    /// Install Rust trigger operations on this trigger.
    pub fn devm_set_ops<Ctx: device::DeviceContext>(&self, dev: &Device<Ctx>) -> Result
    where
        T: TriggerOps,
    {
        to_result(unsafe {
            bindings::iio_trigger_set_ops(
                dev.as_raw(),
                self.as_raw(),
                Some(Adapter::<T>::set_trigger_state_callback),
            )
        })
    }

    /// Store the associated IIO device as trigger driver data.
    pub fn set_iio_device_drvdata(&self, indio_dev: &IioDevice<T>) {
        unsafe { bindings::iio_trigger_set_drvdata(self.as_raw(), indio_dev.as_raw().cast()) };
    }

    /// Register this trigger with devres-managed cleanup.
    pub fn devm_register<Ctx: device::DeviceContext>(&self, dev: &Device<Ctx>) -> Result {
        to_result(unsafe { bindings::iio_devm_trigger_register(dev.as_raw(), self.as_raw()) })
    }

    /// Request an IRQ whose hard handler calls `iio_trigger_generic_data_rdy_poll`.
    pub fn devm_request_data_ready_irq(
        &self,
        request: irq::IrqRequest<'_>,
        flags: irq::Flags,
        name: &'static CStr,
    ) -> Result {
        to_result(unsafe {
            bindings::iio_devm_request_trigger_data_rdy_irq(
                request.device().as_raw(),
                request.irq(),
                flags.into_inner(),
                name.as_char_ptr(),
                self.as_raw(),
            )
        })
    }
}

// SAFETY: The handle points to a kernel-owned devres-managed IIO trigger.
unsafe impl<T> Send for DeviceManagedTrigger<T> {}
// SAFETY: Shared access delegates synchronization to the IIO core.
unsafe impl<T> Sync for DeviceManagedTrigger<T> {}

/// Guard for IIO direct mode.
pub struct DirectModeGuard<'a, T> {
    dev: &'a IioDevice<T>,
}

impl<T> Drop for DirectModeGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { bindings::iio_device_release_direct(self.dev.as_raw()) };
    }
}

// SAFETY: The handle points to a kernel-owned IIO device; operations rely on IIO core locking.
unsafe impl<T> Send for IioDevice<T> {}
// SAFETY: Shared access delegates synchronization to the IIO core or to driver callbacks.
unsafe impl<T> Sync for IioDevice<T> {}
