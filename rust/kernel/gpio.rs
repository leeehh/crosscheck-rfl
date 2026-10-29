// SPDX-License-Identifier: GPL-2.0

//! GPIO consumer abstractions.
//!
//! C header: [`include/linux/gpio/consumer.h`](srctree/include/linux/gpio/consumer.h)

use crate::{
    bindings,
    device::{property::FwNode, Device, DeviceContext},
    error::{from_err_ptr, to_result, Result},
    prelude::*,
};
#[cfg(CONFIG_GPIOLIB)]
use crate::types::Opaque;

#[cfg(CONFIG_GPIOLIB)]
use core::{
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
};
use core::{
    ptr::NonNull,
};

/// Legacy integer GPIO APIs.
///
/// These APIs mirror the deprecated global GPIO-number interface used by old
/// platform drivers. Prefer descriptor-based GPIOs for new drivers.
pub mod legacy {
    use super::{bindings, to_result, Result};

    /// A legacy global GPIO number.
    pub struct Gpio {
        nr: u32,
    }

    impl Gpio {
        /// Create a legacy GPIO handle from a platform GPIO number.
        pub const fn new(nr: u32) -> Self {
            Self { nr }
        }

        /// Create a legacy GPIO handle from a raw platform GPIO number.
        ///
        /// # Safety
        ///
        /// This is kept for older translations that treated integer GPIO numbers as raw handles.
        /// Prefer [`Self::new`].
        pub unsafe fn from_raw(nr: u32) -> Self {
            Self::new(nr)
        }

        /// Configure the GPIO as an input.
        pub fn direction_input(&self) -> Result {
            // SAFETY: The caller guarantees that `nr` is meaningful for this platform.
            to_result(unsafe { bindings::gpio_direction_input(self.nr) })
        }

        /// Read the raw GPIO value.
        pub fn get_value(&self) -> bool {
            // SAFETY: The caller guarantees that `nr` is meaningful for this platform.
            unsafe { bindings::gpio_get_value(self.nr) != 0 }
        }
    }
}

/// GPIO descriptor request flags.
///
/// These mirror `enum gpiod_flags`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flags {
    /// Do not change direction or value.
    AsIs,
    /// Configure as input.
    In,
    /// Configure as output and drive low.
    OutLow,
    /// Configure as output and drive high.
    OutHigh,
    /// Configure as open-drain output and drive low.
    OutLowOpenDrain,
    /// Configure as open-drain output and drive high.
    OutHighOpenDrain,
}

impl Flags {
    fn as_raw(self) -> u32 {
        match self {
            Self::AsIs => 0,
            Self::In => 1,
            Self::OutLow => 1 | 2,
            Self::OutHigh => 1 | 2 | 4,
            Self::OutLowOpenDrain => 1 | 2 | 8,
            Self::OutHighOpenDrain => 1 | 2 | 4 | 8,
        }
    }
}

/// A devres-managed GPIO descriptor handle.
///
/// # Invariants / lifetime
///
/// The wrapped `gpio_desc` is owned by the requesting device's devres and is freed
/// (`devm_gpiod_release` → `gpiod_put`) when that device unbinds. This handle carries no Rust
/// lifetime tie to the device, so it is the holder's responsibility not to use it after the device
/// has unbound. The safe pattern is to store the `Desc` inside the driver's private data (the
/// object bound as `drvdata`): that object is dropped in the bus `.remove` callback, i.e. *before*
/// devres frees the descriptor, so the `Desc` never outlives the underlying `gpio_desc`. Do not
/// move a `Desc` into storage that can outlive the bound device (e.g. a `static`).
pub struct Desc(NonNull<bindings::gpio_desc>);

impl Desc {
    fn as_raw(&self) -> *mut bindings::gpio_desc {
        self.0.as_ptr()
    }

    /// Read the GPIO logical value from a context that may sleep.
    pub fn get_value_cansleep(&self) -> Result<bool> {
        let value = unsafe { bindings::gpiod_get_value_cansleep(self.as_raw()) };
        to_result(value)?;
        Ok(value != 0)
    }

    /// Configure this GPIO as output and set its initial logical value.
    pub fn direction_output(&self, value: bool) -> Result {
        to_result(unsafe { bindings::gpiod_direction_output(self.as_raw(), value as i32) })
    }

    /// Set the GPIO logical value from a non-sleeping context.
    pub fn set_value(&self, value: bool) -> Result {
        to_result(unsafe { bindings::gpiod_set_value(self.as_raw(), value as i32) })
    }

    /// Set the GPIO logical value from a context that may sleep.
    pub fn set_value_cansleep(&self, value: bool) -> Result {
        to_result(unsafe { bindings::gpiod_set_value_cansleep(self.as_raw(), value as i32) })
    }

    /// Return the IRQ number associated with this GPIO.
    pub fn to_irq(&self) -> Result<u32> {
        let irq = unsafe { bindings::gpiod_to_irq(self.as_raw()) };
        to_result(irq)?;
        Ok(irq as u32)
    }
}

/// Get a devres-managed GPIO descriptor.
pub fn devm_get<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    con_id: Option<&CStr>,
    flags: Flags,
) -> Result<Desc> {
    let con_id = con_id.map_or(core::ptr::null(), |s| s.as_char_ptr());
    let desc =
        from_err_ptr(unsafe { bindings::devm_gpiod_get(dev.as_raw(), con_id, flags.as_raw()) })?;

    Ok(Desc(NonNull::new(desc).ok_or(ENODEV)?))
}

/// Get an optional devres-managed GPIO descriptor.
pub fn devm_get_optional<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    con_id: Option<&CStr>,
    flags: Flags,
) -> Result<Option<Desc>> {
    let con_id = con_id.map_or(core::ptr::null(), |s| s.as_char_ptr());
    let desc = from_err_ptr(unsafe {
        bindings::devm_gpiod_get_optional(dev.as_raw(), con_id, flags.as_raw())
    })?;
    if desc.is_null() {
        return Ok(None);
    }

    Ok(Some(Desc(NonNull::new(desc).ok_or(ENODEV)?)))
}

/// Get a devres-managed GPIO descriptor from a firmware node.
pub fn devm_fwnode_get<Ctx: DeviceContext>(
    dev: &Device<Ctx>,
    fwnode: &FwNode,
    con_id: Option<&CStr>,
    flags: Flags,
    label: Option<&CStr>,
) -> Result<Desc> {
    let con_id = con_id.map_or(core::ptr::null(), |s| s.as_char_ptr());
    let label = label.map_or(core::ptr::null(), |s| s.as_char_ptr());
    let desc = from_err_ptr(unsafe {
        bindings::devm_fwnode_gpiod_get(
            dev.as_raw(),
            fwnode.as_raw(),
            con_id,
            flags.as_raw(),
            label,
        )
    })?;

    Ok(Desc(NonNull::new(desc).ok_or(ENODEV)?))
}

/// GPIO provider-side abstractions.
#[cfg(CONFIG_GPIOLIB)]
pub mod provider {
    use super::*;
    use crate::error::from_result;
    pub use crate::bitmap::Bitmap;

    /// Direction returned by GPIO provider callbacks.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Direction {
        /// The line is configured as an output.
        Out,
        /// The line is configured as an input.
        In,
    }

    impl Direction {
        fn as_raw(self) -> c_int {
            match self {
                Self::Out => bindings::GPIO_LINE_DIRECTION_OUT as c_int,
                Self::In => bindings::GPIO_LINE_DIRECTION_IN as c_int,
            }
        }
    }

    /// Configuration for a GPIO provider chip.
    pub struct ChipConfig<'a> {
        label: &'a CStr,
        parent: &'a Device,
        base: c_int,
        ngpio: u16,
        can_sleep: bool,
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        irq_chip: Option<*const bindings::irq_chip>,
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        irq_default_type: crate::irq::Type,
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        irq_threaded: bool,
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        irq_first: c_uint,
    }

    impl<'a> ChipConfig<'a> {
        /// Create a GPIO chip configuration.
        pub fn new(parent: &'a Device, label: &'a CStr, ngpio: u16) -> Self {
            Self {
                label,
                parent,
                base: -1,
                ngpio,
                can_sleep: false,
                #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
                irq_chip: None,
                #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
                irq_default_type: crate::irq::Type::NONE,
                #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
                irq_threaded: false,
                #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
                irq_first: 0,
            }
        }

        /// Set the legacy global GPIO base. Use `-1` for dynamic allocation.
        pub fn base(mut self, base: c_int) -> Self {
            self.base = base;
            self
        }

        /// Mark callbacks as sleepable.
        pub fn can_sleep(mut self, can_sleep: bool) -> Self {
            self.can_sleep = can_sleep;
            self
        }

        /// Configure the GPIO irq-chip backing `irq_chip`.
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        pub fn irq_chip<T: crate::irq::ChipOps>(
            mut self,
            chip: &'static crate::irq::Chip<T>,
        ) -> Self {
            self.irq_chip = Some(chip.as_raw());
            self
        }

        /// Set the default GPIO IRQ trigger type.
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        pub fn irq_default_type(mut self, irq_type: crate::irq::Type) -> Self {
            self.irq_default_type = irq_type;
            self
        }

        /// Set whether the GPIO IRQ domain is nested-threaded.
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        pub fn irq_threaded(mut self, threaded: bool) -> Self {
            self.irq_threaded = threaded;
            self
        }

        /// Set the first Linux IRQ base for legacy GPIO IRQ allocation.
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        pub fn irq_first(mut self, first: c_uint) -> Self {
            self.irq_first = first;
            self
        }
    }

    /// Trait implemented by GPIO provider state.
    pub trait ChipOps: Sync + Sized {
        /// Whether this chip implements `get_direction`.
        const HAS_GET_DIRECTION: bool = false;
        /// Whether this chip implements `direction_input`.
        const HAS_DIRECTION_INPUT: bool = false;
        /// Whether this chip implements `direction_output`.
        const HAS_DIRECTION_OUTPUT: bool = false;
        /// Whether this chip implements `get`.
        const HAS_GET: bool = false;
        /// Whether this chip implements `get_multiple`.
        const HAS_GET_MULTIPLE: bool = false;
        /// Whether this chip implements `set`.
        const HAS_SET: bool = false;
        /// Whether this chip implements `set_multiple`.
        const HAS_SET_MULTIPLE: bool = false;
        /// Whether this chip implements `set_config`.
        const HAS_SET_CONFIG: bool = false;
        /// Whether this chip implements `to_irq`.
        const HAS_TO_IRQ: bool = false;

        /// Return the line direction.
        fn get_direction(self: Pin<&Self>, chip: &Chip<Self>, offset: u32) -> Result<Direction> {
            let _ = (chip, offset);
            Err(EOPNOTSUPP)
        }

        /// Configure a line as input.
        fn direction_input(self: Pin<&Self>, chip: &Chip<Self>, offset: u32) -> Result {
            let _ = (chip, offset);
            Err(EOPNOTSUPP)
        }

        /// Configure a line as output and set its value.
        fn direction_output(
            self: Pin<&Self>,
            chip: &Chip<Self>,
            offset: u32,
            value: bool,
        ) -> Result {
            let _ = (chip, offset, value);
            Err(EOPNOTSUPP)
        }

        /// Read one line.
        fn get(self: Pin<&Self>, chip: &Chip<Self>, offset: u32) -> Result<bool> {
            let _ = (chip, offset);
            Err(EOPNOTSUPP)
        }

        /// Read several lines selected by `mask` into `bits`.
        fn get_multiple(
            self: Pin<&Self>,
            chip: &Chip<Self>,
            mask: &Bitmap,
            bits: &mut Bitmap,
        ) -> Result {
            let _ = (chip, mask, bits);
            Err(EOPNOTSUPP)
        }

        /// Set one line.
        fn set(self: Pin<&Self>, chip: &Chip<Self>, offset: u32, value: bool) -> Result {
            let _ = (chip, offset, value);
            Ok(())
        }

        /// Set several lines selected by `mask` from `bits`.
        fn set_multiple(
            self: Pin<&Self>,
            chip: &Chip<Self>,
            mask: &Bitmap,
            bits: &Bitmap,
        ) -> Result {
            let _ = (chip, mask, bits);
            Ok(())
        }

        /// Apply a pin configuration word to a line.
        fn set_config(self: Pin<&Self>, chip: &Chip<Self>, offset: u32, config: c_ulong) -> Result {
            let _ = (chip, offset, config);
            Err(EOPNOTSUPP)
        }

        /// Return the IRQ number associated with a line.
        fn to_irq(self: Pin<&Self>, chip: &Chip<Self>, offset: u32) -> Result<u32> {
            let _ = (chip, offset);
            Err(EOPNOTSUPP)
        }
    }

    struct Adapter<T: ChipOps> {
        _p: PhantomData<T>,
    }

    impl<T: ChipOps> Adapter<T> {
        unsafe fn chip_and_data<'a>(
            gc: *mut bindings::gpio_chip,
        ) -> Result<(&'a Chip<T>, Pin<&'a T>)> {
            if gc.is_null() {
                return Err(EINVAL);
            }

            // SAFETY: `gc` is valid for the GPIO core callback duration.
            let chip = unsafe { Chip::<T>::from_raw(gc) };
            // SAFETY: `gc` is valid and registered by `Registration::devm_register`.
            let data = unsafe { bindings::gpiochip_get_data(gc) };
            if data.is_null() {
                return Err(ENOENT);
            }

            // SAFETY: `Registration::devm_register` installed a pointer to a pinned `T`.
            let data = unsafe { Pin::new_unchecked(&*data.cast::<T>()) };
            Ok((chip, data))
        }

        unsafe extern "C" fn get_direction_callback(
            gc: *mut bindings::gpio_chip,
            offset: c_uint,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                Ok(data.get_direction(chip, offset)?.as_raw())
            })
        }

        unsafe extern "C" fn direction_input_callback(
            gc: *mut bindings::gpio_chip,
            offset: c_uint,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                data.direction_input(chip, offset)?;
                Ok(0)
            })
        }

        unsafe extern "C" fn direction_output_callback(
            gc: *mut bindings::gpio_chip,
            offset: c_uint,
            value: c_int,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                data.direction_output(chip, offset, value != 0)?;
                Ok(0)
            })
        }

        unsafe extern "C" fn get_callback(
            gc: *mut bindings::gpio_chip,
            offset: c_uint,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                Ok(data.get(chip, offset)? as c_int)
            })
        }

        unsafe extern "C" fn get_multiple_callback(
            gc: *mut bindings::gpio_chip,
            mask: *mut c_ulong,
            bits: *mut c_ulong,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                let nbits = chip.ngpio() as usize;
                // SAFETY: The GPIO core supplies bitmaps large enough for `ngpio` bits.
                let mask = unsafe { Bitmap::from_raw(mask.cast::<usize>(), nbits) };
                // SAFETY: The GPIO core supplies bitmaps large enough for `ngpio` bits.
                let bits = unsafe { Bitmap::from_raw_mut(bits.cast::<usize>(), nbits) };
                data.get_multiple(chip, mask, bits)?;
                Ok(0)
            })
        }

        unsafe extern "C" fn set_callback(
            gc: *mut bindings::gpio_chip,
            offset: c_uint,
            value: c_int,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                data.set(chip, offset, value != 0)?;
                Ok(0)
            })
        }

        unsafe extern "C" fn set_multiple_callback(
            gc: *mut bindings::gpio_chip,
            mask: *mut c_ulong,
            bits: *mut c_ulong,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                let nbits = chip.ngpio() as usize;
                // SAFETY: The GPIO core supplies bitmaps large enough for `ngpio` bits.
                let mask = unsafe { Bitmap::from_raw(mask.cast::<usize>(), nbits) };
                // SAFETY: The GPIO core supplies bitmaps large enough for `ngpio` bits.
                let bits = unsafe { Bitmap::from_raw(bits.cast::<usize>(), nbits) };
                data.set_multiple(chip, mask, bits)?;
                Ok(0)
            })
        }

        unsafe extern "C" fn set_config_callback(
            gc: *mut bindings::gpio_chip,
            offset: c_uint,
            config: c_ulong,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                data.set_config(chip, offset, config)?;
                Ok(0)
            })
        }

        unsafe extern "C" fn to_irq_callback(
            gc: *mut bindings::gpio_chip,
            offset: c_uint,
        ) -> c_int {
            from_result(|| {
                // SAFETY: The GPIO core passes a valid chip for the callback duration.
                let (chip, data) = unsafe { Self::chip_and_data(gc) }?;
                let irq = data.to_irq(chip, offset)?;
                if irq > c_int::MAX as u32 {
                    return Err(EINVAL);
                }
                Ok(irq as c_int)
            })
        }
    }

    /// A borrowed GPIO provider chip.
    #[repr(transparent)]
    pub struct Chip<T: ChipOps>(Opaque<bindings::gpio_chip>, PhantomData<T>);

    impl<T: ChipOps> Chip<T> {
        /// Creates a borrowed chip from a raw GPIO core pointer.
        ///
        /// # Safety
        ///
        /// `ptr` must point to a valid `struct gpio_chip` for the returned lifetime.
        pub unsafe fn from_raw<'a>(ptr: *mut bindings::gpio_chip) -> &'a Self {
            // SAFETY: Guaranteed by the function safety requirements.
            unsafe { &*ptr.cast() }
        }

        fn as_raw(&self) -> *mut bindings::gpio_chip {
            self.0.get()
        }

        /// Return the number of lines exposed by this chip.
        pub fn ngpio(&self) -> u16 {
            // SAFETY: `self.as_raw()` is valid by the type invariant.
            unsafe { (*self.as_raw()).ngpio }
        }

        /// Return the parent device.
        pub fn parent(&self) -> Option<&Device> {
            // SAFETY: `self.as_raw()` is valid by the type invariant.
            let parent = unsafe { (*self.as_raw()).parent };
            if parent.is_null() {
                None
            } else {
                // SAFETY: The GPIO core keeps the parent device valid while the chip exists.
                Some(unsafe { Device::from_raw(parent) })
            }
        }

        /// Return the typed provider state associated with this chip.
        pub fn data(&self) -> Result<Pin<&T>> {
            // SAFETY: `self.as_raw()` is valid by the type invariant.
            let data = unsafe { bindings::gpiochip_get_data(self.as_raw()) };
            if data.is_null() {
                return Err(ENOENT);
            }

            // SAFETY: `Registration::devm_register` installed a pointer to a pinned `T`.
            Ok(unsafe { Pin::new_unchecked(&*data.cast::<T>()) })
        }

        /// Disable IRQ handling for a GPIO line while the irq-chip callback updates masks.
        pub fn disable_irq(&self, offset: u32) {
            // SAFETY: `self.as_raw()` is valid and `offset` is supplied by the GPIO/IRQ core.
            unsafe { bindings::gpiochip_disable_irq(self.as_raw(), offset) };
        }

        /// Re-enable IRQ handling for a GPIO line after masks have been updated.
        pub fn enable_irq(&self, offset: u32) {
            // SAFETY: `self.as_raw()` is valid and `offset` is supplied by the GPIO/IRQ core.
            unsafe { bindings::gpiochip_enable_irq(self.as_raw(), offset) };
        }

        /// Return the GPIO IRQ domain, if one has been created for this chip.
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        pub fn irq_domain(&self) -> Option<&crate::irq::Domain> {
            // SAFETY: `self.as_raw()` is valid by the type invariant.
            let domain = unsafe { (*self.as_raw()).irq.domain };
            if domain.is_null() {
                None
            } else {
                // SAFETY: The IRQ domain is owned by gpiolib and is valid while the chip exists.
                Some(unsafe { crate::irq::Domain::from_raw(domain) })
            }
        }
    }

    /// A GPIO chip registration that unregisters the chip on drop.
    ///
    /// # Lifetime / drop ordering
    ///
    /// gpiolib retains and writes through the `gpio_chip` pointer (`gc->gpiodev`) for the whole
    /// lifetime of the registered chip, and the GPIO callbacks dereference `drvdata`. This
    /// registration therefore removes the chip in [`Drop`] (via `gpiochip_remove`) rather than
    /// relying on the parent's devres release, which runs *after* the bus `.remove` callback has
    /// already freed the driver object (`drvdata`) that embeds this registration. Because
    /// `Drop::drop` runs before this struct's own `chip` storage is freed and before the embedding
    /// driver object's memory is released, `gpiochip_remove` — which unregisters the chip and drains
    /// in-flight callbacks — completes while the inline `gpio_chip` and the driver data are still
    /// valid.
    ///
    /// Drivers MUST declare this `Registration` *before* any sibling field whose data the GPIO
    /// callbacks access (i.e. as the first such field). Struct fields are dropped in declaration
    /// order, so a `Registration` declared first is dropped first: its [`Drop`] removes the chip
    /// (and drains in-flight callbacks) while the data those callbacks touch is still alive.
    /// Declaring it *after* that data would leave a window where a GPIO access dereferences
    /// already-dropped state.
    #[pin_data(PinnedDrop)]
    pub struct Registration<T: ChipOps + 'static> {
        #[pin]
        chip: Opaque<bindings::gpio_chip>,
        _p: PhantomData<T>,
        #[pin]
        _pin: PhantomPinned,
    }

    impl<T: ChipOps + 'static> Registration<T> {
        /// Register a GPIO chip that is unregistered when this object is dropped.
        ///
        /// Despite the name, this is not backed by `devres`: the chip is added with the non-devm
        /// `gpiochip_add_data_with_key` and removed in [`Drop`], which gives the correct teardown
        /// ordering (see the type-level documentation).
        ///
        /// # Safety
        ///
        /// `drvdata` must point to a valid, pinned `T` for as long as this `Registration` is alive
        /// (i.e. until its [`Drop`] runs and removes the GPIO chip). Initialize all fields used by
        /// GPIO callbacks before this registration field.
        pub unsafe fn devm_register<'a>(
            dev: &'a Device<crate::device::Bound>,
            drvdata: *const T,
            config: ChipConfig<'a>,
        ) -> impl PinInit<Self, Error> + 'a {
            let _ = dev;
            try_pin_init!(Self {
                chip <- Opaque::try_ffi_init(|gc: *mut bindings::gpio_chip| {
                    if drvdata.is_null() {
                        return Err(EINVAL);
                    }

                    // SAFETY: `gc` points to uninitialized registration storage owned by `Self`.
                    unsafe {
                        core::ptr::write(gc, bindings::gpio_chip::default());
                        (*gc).label = config.label.as_char_ptr();
                        (*gc).parent = config.parent.as_raw();
                        (*gc).base = config.base;
                        (*gc).ngpio = config.ngpio;
                        (*gc).can_sleep = config.can_sleep;

                        if T::HAS_GET_DIRECTION {
                            (*gc).get_direction = Some(Adapter::<T>::get_direction_callback);
                        }
                        if T::HAS_DIRECTION_INPUT {
                            (*gc).direction_input = Some(Adapter::<T>::direction_input_callback);
                        }
                        if T::HAS_DIRECTION_OUTPUT {
                            (*gc).direction_output = Some(Adapter::<T>::direction_output_callback);
                        }
                        if T::HAS_GET {
                            (*gc).get = Some(Adapter::<T>::get_callback);
                        }
                        if T::HAS_GET_MULTIPLE {
                            (*gc).get_multiple = Some(Adapter::<T>::get_multiple_callback);
                        }
                        if T::HAS_SET {
                            (*gc).set = Some(Adapter::<T>::set_callback);
                        }
                        if T::HAS_SET_MULTIPLE {
                            (*gc).set_multiple = Some(Adapter::<T>::set_multiple_callback);
                        }
                        if T::HAS_SET_CONFIG {
                            (*gc).set_config = Some(Adapter::<T>::set_config_callback);
                        }
                        if T::HAS_TO_IRQ {
                            (*gc).to_irq = Some(Adapter::<T>::to_irq_callback);
                        }

                        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
                        if let Some(irq_chip) = config.irq_chip {
                            let girq = &raw mut (*gc).irq;
                            bindings::gpio_irq_chip_set_chip(girq, irq_chip);
                            (*girq).parent_handler = None;
                            (*girq).num_parents = 0;
                            (*girq).parents = core::ptr::null_mut();
                            (*girq).default_type = config.irq_default_type.as_raw();
                            (*girq).handler = Some(bindings::handle_simple_irq);
                            (*girq).threaded = config.irq_threaded;
                            (*girq).first = config.irq_first;
                        }
                    }

                    // SAFETY: `gc` has been initialized above (including `gc->parent`) and `drvdata`
                    // is valid by contract. The non-devm `gpiochip_add_data_with_key` is paired with
                    // `gpiochip_remove` in this registration's `Drop`.
                    to_result(unsafe {
                        bindings::gpiochip_add_data_with_key(
                            gc,
                            drvdata.cast_mut().cast::<c_void>(),
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                        )
                    })
                }),
                _p: PhantomData,
                _pin: PhantomPinned,
            })
        }

        /// Return the registered GPIO chip.
        pub fn chip(&self) -> &Chip<T> {
            // SAFETY: `self.chip` is initialized by `devm_register`.
            unsafe { Chip::from_raw(self.chip.get()) }
        }

        /// Return the GPIO IRQ domain, if one has been created for this registration.
        #[cfg(CONFIG_GPIOLIB_IRQCHIP)]
        pub fn irq_domain(&self) -> Option<&crate::irq::Domain> {
            self.chip().irq_domain()
        }
    }

    #[pinned_drop]
    impl<T: ChipOps + 'static> PinnedDrop for Registration<T> {
        fn drop(self: Pin<&mut Self>) {
            // SAFETY: `self.chip` was registered with `gpiochip_add_data_with_key` in
            // `devm_register` and has not been removed yet. `gpiochip_remove` unregisters the chip
            // and drains any in-flight callbacks before returning, after which gpiolib no longer
            // references the inline `gpio_chip` storage or `drvdata`.
            unsafe { bindings::gpiochip_remove(self.chip.get()) };
        }
    }

    // SAFETY: Registration only stores kernel-owned GPIO metadata and immutable callback
    // dispatch; callbacks access driver data through `T: Sync`.
    unsafe impl<T: ChipOps + 'static> Send for Registration<T> {}
    // SAFETY: Shared access to the registration only exposes immutable metadata and callback entry.
    unsafe impl<T: ChipOps + 'static> Sync for Registration<T> {}

    impl crate::irq::Data {
        /// Return the GPIO chip associated with this GPIO IRQ data.
        pub fn gpio_chip<T: ChipOps>(&self) -> Result<&Chip<T>> {
            let data = self.chip_data();
            if data.is_null() {
                return Err(ENOENT);
            }

            // SAFETY: For GPIO irq-chip callbacks, `irq_data::chip_data` is a `struct gpio_chip *`.
            Ok(unsafe { Chip::<T>::from_raw(data.cast::<bindings::gpio_chip>()) })
        }
    }
}

// SAFETY: GPIO descriptor operations on a shared `&Desc` (reads, value sets) are internally
// synchronized by the GPIO core's per-chip locks, so a `&Desc` may be used concurrently from
// multiple threads.
unsafe impl Sync for Desc {}

// SAFETY: The `gpio_desc` is owned by the bound device's devres and is accessed under the GPIO
// core's locking. The intended use of a `Desc` is embedded in a bus driver's drvdata object; that
// object's lifetime equals the bound device's, so the handle never outlives the descriptor even
// when the driver object is moved between threads — which `platform::Driver: Send` (and the i2c
// equivalent) require. This mirrors `reset::Control`, which is `Send` for the same devres-embedded
// pattern.
unsafe impl Send for Desc {}
