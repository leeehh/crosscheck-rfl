// SPDX-License-Identifier: GPL-2.0

//! Register map helpers.
//!
//! C headers: [`include/linux/regmap.h`](srctree/include/linux/regmap.h) and
//! [`include/linux/mfd/syscon.h`](srctree/include/linux/mfd/syscon.h)

use crate::{
    bindings,
    device::{Device, DeviceContext},
    error::{from_err_ptr, from_result, to_result, Result},
    ffi::{c_int, c_uint, c_void},
    i2c,
    prelude::*,
};

use core::{
    marker::PhantomData,
    ptr::{self, NonNull},
};

/// Endianness used when formatting register or value fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    /// Use the regmap bus default.
    Default,
    /// Big-endian values.
    Big,
    /// Little-endian values.
    Little,
    /// Native CPU-endian values.
    Native,
}

impl Endian {
    const fn as_raw(self) -> bindings::regmap_endian {
        match self {
            Self::Default => bindings::regmap_endian_REGMAP_ENDIAN_DEFAULT,
            Self::Big => bindings::regmap_endian_REGMAP_ENDIAN_BIG,
            Self::Little => bindings::regmap_endian_REGMAP_ENDIAN_LITTLE,
            Self::Native => bindings::regmap_endian_REGMAP_ENDIAN_NATIVE,
        }
    }
}

/// Regmap cache implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheType {
    /// No cache.
    None,
    /// Maple-tree-backed cache.
    Maple,
}

impl CacheType {
    const fn as_raw(self) -> bindings::regcache_type {
        match self {
            Self::None => bindings::regcache_type_REGCACHE_NONE,
            Self::Maple => bindings::regcache_type_REGCACHE_MAPLE,
        }
    }
}

/// Optional register-access policy for a [`Config`].
pub trait ConfigOps {
    /// Return whether `reg` may be read.
    fn readable_reg(_dev: &Device, _reg: u32) -> bool {
        true
    }

    /// Return whether `reg` may be written.
    fn writeable_reg(_dev: &Device, _reg: u32) -> bool {
        true
    }

    /// Return whether `reg` is volatile.
    fn volatile_reg(_dev: &Device, _reg: u32) -> bool {
        false
    }
}

/// Default regmap access policy.
pub struct NoConfigOps;

impl ConfigOps for NoConfigOps {}

/// Low-level regmap bus callbacks for register-oriented buses.
pub trait BusOps<C>: Sync {
    /// Read one register from `context`.
    fn reg_read(context: &C, reg: u32) -> Result<u32>;

    /// Write one register through `context`.
    fn reg_write(context: &C, reg: u32, val: u32) -> Result;
}

/// Static regmap bus descriptor backed by Rust callbacks.
pub struct Bus<B, C> {
    raw: bindings::regmap_bus,
    _p: PhantomData<(B, C)>,
}

impl<B, C> Bus<B, C>
where
    B: BusOps<C>,
    C: Sync,
{
    /// Create a regmap bus with register read/write callbacks.
    pub const fn new() -> Self {
        Self {
            raw: bindings::regmap_bus {
                fast_io: false,
                free_on_exit: false,
                write: None,
                gather_write: None,
                async_write: None,
                reg_write: Some(bus_reg_write_callback::<B, C>),
                reg_noinc_write: None,
                reg_update_bits: None,
                read: None,
                reg_read: Some(bus_reg_read_callback::<B, C>),
                reg_noinc_read: None,
                free_context: None,
                async_alloc: None,
                read_flag_mask: 0,
                reg_format_endian_default: bindings::regmap_endian_REGMAP_ENDIAN_DEFAULT,
                val_format_endian_default: bindings::regmap_endian_REGMAP_ENDIAN_DEFAULT,
                max_raw_read: 0,
                max_raw_write: 0,
            },
            _p: PhantomData,
        }
    }

    fn as_raw(&self) -> *const bindings::regmap_bus {
        &self.raw
    }
}

// SAFETY: Bus descriptors contain immutable function pointers and marker data.
unsafe impl<B, C> Sync for Bus<B, C> {}

/// Register-map configuration.
pub struct Config<T: ConfigOps = NoConfigOps> {
    raw: bindings::regmap_config,
    _p: PhantomData<T>,
}

impl<T: ConfigOps> Config<T> {
    /// Create a register-map configuration.
    pub fn new(reg_bits: i32, val_bits: i32) -> Self {
        let mut raw = bindings::regmap_config::default();

        raw.reg_bits = reg_bits;
        raw.val_bits = val_bits;
        raw.readable_reg = Some(readable_reg_callback::<T>);
        raw.writeable_reg = Some(writeable_reg_callback::<T>);
        raw.volatile_reg = Some(volatile_reg_callback::<T>);

        Self {
            raw,
            _p: PhantomData,
        }
    }

    /// Set the maximum valid register address.
    pub fn max_register(mut self, max_register: u32) -> Self {
        self.raw.max_register = max_register;
        self
    }

    /// Set the value formatting endian.
    pub fn val_format_endian(mut self, endian: Endian) -> Self {
        self.raw.val_format_endian = endian.as_raw();
        self
    }

    /// Set the regmap cache implementation.
    pub fn cache_type(mut self, cache_type: CacheType) -> Self {
        self.raw.cache_type = cache_type.as_raw();
        self
    }

    /// Set a flag ORed into register addresses for reads.
    pub fn read_flag_mask(mut self, mask: usize) -> Self {
        self.raw.read_flag_mask = mask;
        self
    }

    /// Set a flag ORed into register addresses for writes.
    pub fn write_flag_mask(mut self, mask: usize) -> Self {
        self.raw.write_flag_mask = mask;
        self
    }

    /// Disable regmap's internal locking when the caller provides locking.
    pub fn disable_locking(mut self, disable: bool) -> Self {
        self.raw.disable_locking = disable;
        self
    }

    /// Force single-register reads.
    pub fn use_single_read(mut self, use_single_read: bool) -> Self {
        self.raw.use_single_read = use_single_read;
        self
    }

    /// Force single-register writes.
    pub fn use_single_write(mut self, use_single_write: bool) -> Self {
        self.raw.use_single_write = use_single_write;
        self
    }

    fn as_raw(&self) -> *const bindings::regmap_config {
        &self.raw
    }
}

unsafe extern "C" fn readable_reg_callback<T: ConfigOps>(
    dev: *mut bindings::device,
    reg: kernel::ffi::c_uint,
) -> bindings::bool_ {
    if dev.is_null() {
        return false;
    }

    // SAFETY: The regmap core passes the owning device for the callback duration.
    let dev = unsafe { Device::from_raw(dev) };
    T::readable_reg(dev, reg as u32)
}

unsafe extern "C" fn writeable_reg_callback<T: ConfigOps>(
    dev: *mut bindings::device,
    reg: kernel::ffi::c_uint,
) -> bindings::bool_ {
    if dev.is_null() {
        return false;
    }

    // SAFETY: The regmap core passes the owning device for the callback duration.
    let dev = unsafe { Device::from_raw(dev) };
    T::writeable_reg(dev, reg as u32)
}

unsafe extern "C" fn volatile_reg_callback<T: ConfigOps>(
    dev: *mut bindings::device,
    reg: kernel::ffi::c_uint,
) -> bindings::bool_ {
    if dev.is_null() {
        return false;
    }

    // SAFETY: The regmap core passes the owning device for the callback duration.
    let dev = unsafe { Device::from_raw(dev) };
    T::volatile_reg(dev, reg as u32)
}

/// A borrowed register map handle.
///
/// The underlying `struct regmap` is owned by the device/syscon provider that
/// returned it. The handle is copyable so drivers may store it in callback
/// state, matching how C drivers store a `struct regmap *`.
#[derive(Clone, Copy)]
pub struct RegMap(NonNull<bindings::regmap>);

impl RegMap {
    fn from_raw(raw: *mut bindings::regmap) -> Result<Self> {
        let raw = from_err_ptr(raw)?;
        Ok(Self(NonNull::new(raw).ok_or(ENODEV)?))
    }

    pub(crate) fn as_raw(self) -> *mut bindings::regmap {
        self.0.as_ptr()
    }

    /// Create a devres-managed I2C regmap.
    pub fn devm_init_i2c<Ctx: DeviceContext, T: ConfigOps>(
        client: &i2c::I2cClient<Ctx>,
        config: &Config<T>,
    ) -> Result<Self> {
        Self::from_raw(unsafe {
            bindings::__devm_regmap_init_i2c(
                client.as_raw(),
                config.as_raw(),
                ptr::null_mut(),
                ptr::null(),
            )
        })
    }

    /// Create a devres-managed regmap on `client`'s device, backed by a custom
    /// register bus whose context is the device's own `i2c_client`.
    ///
    /// This is the safe counterpart of [`RegMap::devm_init`] specialised for I2C.
    /// Unlike that general constructor — whose context may be decoupled from `dev`
    /// and which is therefore `unsafe` — here the bus context *is* `client`, and
    /// the regmap is registered with devres on `client`'s own device. The I2C core
    /// releases the `struct i2c_client` only after that device's devres release
    /// runs, so the context provably outlives every bus callback the regmap may
    /// invoke. No caller-side `unsafe` contract is required.
    ///
    /// Use this when an I2C device needs per-register custom transfers (e.g.
    /// word-swapped vs byte access) that the stock bus from [`RegMap::devm_init_i2c`]
    /// cannot express.
    pub fn devm_init_i2c_bus<Ctx: DeviceContext, T, B>(
        client: &i2c::I2cClient<Ctx>,
        bus: &'static Bus<B, i2c::I2cClient>,
        config: &Config<T>,
    ) -> Result<Self>
    where
        T: ConfigOps,
        B: BusOps<i2c::I2cClient>,
    {
        let dev: &Device<Ctx> = client.as_ref();
        // SAFETY: `dev` is `client`'s device, so the regmap is devres-managed on
        // the same device that owns the `struct i2c_client` we install as the bus
        // context. `client.as_raw()` is layout-compatible with `*const
        // I2cClient<Normal>` (`I2cClient` is `#[repr(transparent)]`), which is what
        // the bus callbacks reconstruct. The I2C core frees the i2c_client only
        // after this device's devres runs, so the context outlives every callback;
        // `I2cClient<Normal>` is `Sync`, as `Bus`/`BusOps` require.
        Self::from_raw(unsafe {
            bindings::__devm_regmap_init(
                dev.as_raw(),
                bus.as_raw(),
                client.as_raw().cast::<c_void>(),
                config.as_raw(),
                ptr::null_mut(),
                ptr::null(),
            )
        })
    }

    /// Create a devres-managed regmap with a custom bus and context.
    ///
    /// # Safety
    ///
    /// `context` must stay valid for as long as the regmap may invoke the bus callbacks — i.e.
    /// until the parent device's devres release runs. The regmap core stores `context` as
    /// `map->bus_context` and dereferences it (as `&C`) from every register access for the whole
    /// lifetime of the devres-managed regmap, which outlives this call. In practice, pass a context
    /// owned by the same device (e.g. the pinned driver object) so its lifetime provably exceeds the
    /// regmap.
    pub unsafe fn devm_init<Ctx: DeviceContext, T, B, C>(
        dev: &Device<Ctx>,
        bus: &'static Bus<B, C>,
        context: &C,
        config: &Config<T>,
    ) -> Result<Self>
    where
        T: ConfigOps,
        B: BusOps<C>,
        C: Sync,
    {
        Self::from_raw(unsafe {
            bindings::__devm_regmap_init(
                dev.as_raw(),
                bus.as_raw(),
                (context as *const C).cast_mut().cast::<c_void>(),
                config.as_raw(),
                ptr::null_mut(),
                ptr::null(),
            )
        })
    }

    /// Look up a regmap attached to `dev`.
    pub fn dev_get<Ctx: DeviceContext>(dev: &Device<Ctx>, name: Option<&CStr>) -> Result<Self> {
        let name = name.map_or(ptr::null(), CStr::as_char_ptr);

        Self::from_raw(unsafe { bindings::dev_get_regmap(dev.as_raw(), name) })
    }

    /// Return the device that owns this regmap.
    pub fn device(&self) -> Result<&Device> {
        // SAFETY: `self.as_raw()` is a valid regmap pointer by type invariant.
        let dev = unsafe { bindings::regmap_get_device(self.as_raw()) };
        if dev.is_null() {
            return Err(ENODEV);
        }

        // SAFETY: `regmap_get_device` returns the device associated with the regmap.
        Ok(unsafe { Device::from_raw(dev) })
    }

    /// Look up a regmap attached to the parent of `dev`.
    pub fn dev_get_parent<Ctx: DeviceContext>(
        dev: &Device<Ctx>,
        name: Option<&CStr>,
    ) -> Result<Self> {
        // SAFETY: `dev.as_raw()` is valid by the `Device` type invariant.
        let parent = unsafe { (*dev.as_raw()).parent };
        if parent.is_null() {
            return Err(ENODEV);
        }

        // SAFETY: The driver core holds a parent reference for the lifetime of `dev`.
        let parent: &Device = unsafe { Device::from_raw(parent) };
        Self::dev_get(parent, name)
    }

    /// Look up a syscon-backed regmap through an OF phandle property on `dev`.
    pub fn syscon_lookup_by_phandle<Ctx: DeviceContext>(
        dev: &Device<Ctx>,
        property: &CStr,
    ) -> Result<Self> {
        Self::from_raw(unsafe {
            bindings::syscon_regmap_lookup_by_phandle(dev.as_raw(), property.as_char_ptr())
        })
    }

    /// Look up the parent device node as a syscon-backed regmap.
    pub fn syscon_node_to_regmap_parent<Ctx: DeviceContext>(dev: &Device<Ctx>) -> Result<Self> {
        Self::from_raw(unsafe { bindings::syscon_node_to_regmap_parent(dev.as_raw()) })
    }

    /// Update masked bits in a register.
    pub fn update_bits(self, reg: u32, mask: u32, val: u32) -> Result {
        to_result(unsafe {
            bindings::regmap_update_bits(self.as_raw(), reg as _, mask as _, val as _)
        })
    }

    /// Set all bits in `bits`.
    #[inline]
    pub fn set_bits(self, reg: u32, bits: u32) -> Result {
        self.update_bits(reg, bits, bits)
    }

    /// Clear all bits in `bits`.
    #[inline]
    pub fn clear_bits(self, reg: u32, bits: u32) -> Result {
        self.update_bits(reg, bits, 0)
    }

    /// Read one register.
    pub fn read(self, reg: u32) -> Result<u32> {
        let mut val = 0;

        to_result(unsafe { bindings::regmap_read(self.as_raw(), reg as _, &mut val) })?;
        Ok(val)
    }

    /// Write one register.
    pub fn write(self, reg: u32, val: u32) -> Result {
        to_result(unsafe { bindings::regmap_write(self.as_raw(), reg as _, val as _) })
    }

    /// Number of bytes per register value for this map.
    ///
    /// Wraps `regmap_get_val_bytes()`.
    pub fn val_bytes(self) -> Result<usize> {
        let ret = unsafe { bindings::regmap_get_val_bytes(self.as_raw()) };
        if ret <= 0 {
            return Err(EINVAL);
        }
        Ok(ret as usize)
    }

    /// Read a contiguous register range into `values`.
    ///
    /// `values` is a raw byte buffer; its length must be an exact multiple of the map's value size
    /// (see [`val_bytes`](Self::val_bytes)). The C `regmap_bulk_read()` takes a *register* count and
    /// accesses `val_count * val_bytes` bytes, so the byte length is converted to a register count
    /// here — passing the byte length directly would over-read by a factor of `val_bytes`.
    pub fn bulk_read(self, reg: u32, values: &mut [u8]) -> Result {
        let val_bytes = self.val_bytes()?;
        if values.len() % val_bytes != 0 {
            return Err(EINVAL);
        }
        let val_count = values.len() / val_bytes;

        to_result(unsafe {
            bindings::regmap_bulk_read(
                self.as_raw(),
                reg as _,
                values.as_mut_ptr().cast::<c_void>(),
                val_count,
            )
        })
    }

    /// Write a contiguous register range from `values`.
    ///
    /// `values` is a raw byte buffer; its length must be an exact multiple of the map's value size
    /// (see [`val_bytes`](Self::val_bytes)). As with [`bulk_read`](Self::bulk_read), the byte length
    /// is converted to a register count for the C `regmap_bulk_write()`, which would otherwise
    /// over-read the source by a factor of `val_bytes`.
    pub fn bulk_write(self, reg: u32, values: &[u8]) -> Result {
        let val_bytes = self.val_bytes()?;
        if values.len() % val_bytes != 0 {
            return Err(EINVAL);
        }
        let val_count = values.len() / val_bytes;

        to_result(unsafe {
            bindings::regmap_bulk_write(
                self.as_raw(),
                reg as _,
                values.as_ptr().cast::<c_void>(),
                val_count,
            )
        })
    }

    /// Enable or disable cache-only mode for this regmap.
    #[inline]
    pub fn cache_only(self, enable: bool) {
        // SAFETY: `self.as_raw()` is a valid regmap pointer by type invariant.
        unsafe { bindings::regcache_cache_only(self.as_raw(), enable) };
    }

    /// Mark the cached register contents dirty.
    #[inline]
    pub fn mark_dirty(self) {
        // SAFETY: `self.as_raw()` is a valid regmap pointer by type invariant.
        unsafe { bindings::regcache_mark_dirty(self.as_raw()) };
    }

    /// Synchronize the entire regmap cache to hardware.
    #[inline]
    pub fn sync(self) -> Result {
        to_result(unsafe { bindings::regcache_sync(self.as_raw()) })
    }

    /// Synchronize a register range from the regmap cache to hardware.
    #[inline]
    pub fn sync_region(self, min: u32, max: u32) -> Result {
        to_result(unsafe { bindings::regcache_sync_region(self.as_raw(), min as _, max as _) })
    }
}

// SAFETY: `RegMap` is a borrowed pointer to a kernel regmap. Regmap operations
// are internally synchronized by the regmap core.
unsafe impl Send for RegMap {}

// SAFETY: `RegMap` only exposes regmap-core operations, which are internally
// synchronized.
unsafe impl Sync for RegMap {}

unsafe extern "C" fn bus_reg_read_callback<B, C>(
    context: *mut c_void,
    reg: c_uint,
    val: *mut c_uint,
) -> c_int
where
    B: BusOps<C>,
    C: Sync,
{
    from_result(|| {
        if context.is_null() || val.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: `RegMap::devm_init` installs `context` as a pointer to `C`, and the regmap core
        // only invokes this callback while the registered bus context is valid.
        let context = unsafe { &*context.cast::<C>() };
        let read = B::reg_read(context, reg as u32)?;

        // SAFETY: `val` was checked non-null and is the regmap core's out parameter.
        unsafe { *val = read as c_uint };
        Ok(0)
    })
}

unsafe extern "C" fn bus_reg_write_callback<B, C>(
    context: *mut c_void,
    reg: c_uint,
    val: c_uint,
) -> c_int
where
    B: BusOps<C>,
    C: Sync,
{
    from_result(|| {
        if context.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: `RegMap::devm_init` installs `context` as a pointer to `C`, and the regmap core
        // only invokes this callback while the registered bus context is valid.
        let context = unsafe { &*context.cast::<C>() };
        B::reg_write(context, reg as u32, val as u32)?;
        Ok(0)
    })
}
