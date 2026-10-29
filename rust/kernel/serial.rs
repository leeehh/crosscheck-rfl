// SPDX-License-Identifier: GPL-2.0

//! Safe abstractions for the serial (UART) core.
//!
//! C header: [`include/linux/serial_core.h`](srctree/include/linux/serial_core.h)
//!
//! This is a minimal abstraction: enough to register a [`Driver`], add a single
//! [`Port`], drive it from a Rust [`Ops`] implementation (interrupt-driven RX/TX
//! through the tty layer), and tear it down. It deliberately covers only the
//! pieces a basic 16550-style `UPIO_PORT` driver needs.

use crate::{
    bindings,
    device,
    error::{to_result, Result},
    ffi,
    io::{IoPort, IoRaw},
    prelude::*,
    str::CStr,
    types::Opaque,
    ThisModule,
};
use core::{marker::PhantomData, ptr};

/// Number of I/O-port registers a 16550 exposes.
const NREG: usize = 8;

/// Modem-control bit constants (`TIOCM_*`), re-exported for driver convenience.
pub mod mctrl {
    /// Data Terminal Ready.
    pub const DTR: u32 = bindings::TIOCM_DTR;
    /// Request To Send.
    pub const RTS: u32 = bindings::TIOCM_RTS;
    /// User-output 1.
    pub const OUT1: u32 = bindings::TIOCM_OUT1;
    /// User-output 2.
    pub const OUT2: u32 = bindings::TIOCM_OUT2;
    /// Loopback enable.
    pub const LOOP: u32 = bindings::TIOCM_LOOP;
    /// Clear To Send (input).
    pub const CTS: u32 = bindings::TIOCM_CTS;
    /// Data Set Ready (input).
    pub const DSR: u32 = bindings::TIOCM_DSR;
    /// Ring Indicator (input).
    pub const RI: u32 = bindings::TIOCM_RI;
    /// Carrier Detect (input).
    pub const CAR: u32 = bindings::TIOCM_CAR;
}

/// Return value of an interrupt handler.
#[repr(u32)]
pub enum IrqReturn {
    /// The interrupt was not for this device.
    None = bindings::irqreturn_IRQ_NONE,
    /// The interrupt was handled.
    Handled = bindings::irqreturn_IRQ_HANDLED,
}

/// A borrowed `struct ktermios`.
#[repr(transparent)]
pub struct Ktermios(Opaque<bindings::ktermios>);

impl Ktermios {
    /// # Safety
    /// `ptr` must be valid for the returned reference's lifetime.
    unsafe fn from_raw<'a>(ptr: *mut bindings::ktermios) -> &'a Ktermios {
        // SAFETY: `Ktermios` is `repr(transparent)` over `Opaque<ktermios>`.
        unsafe { &*ptr.cast() }
    }

    fn as_raw(&self) -> *mut bindings::ktermios {
        self.0.get()
    }

    /// The control-mode flags (`c_cflag`).
    pub fn cflag(&self) -> u32 {
        // SAFETY: valid for the lifetime of `self`.
        unsafe { (*self.0.get()).c_cflag }
    }

    /// The input-mode flags (`c_iflag`).
    pub fn iflag(&self) -> u32 {
        // SAFETY: valid for the lifetime of `self`.
        unsafe { (*self.0.get()).c_iflag }
    }
}

/// A borrowed `struct uart_port`.
///
/// Callbacks in [`Ops`] receive `&Port`; it exposes the fields and operations a
/// low-level driver needs.
#[repr(transparent)]
pub struct Port(Opaque<bindings::uart_port>);

impl Port {
    /// # Safety
    /// `ptr` must point to a valid `uart_port` for the returned lifetime.
    unsafe fn from_raw<'a>(ptr: *mut bindings::uart_port) -> &'a Port {
        // SAFETY: `Port` is `repr(transparent)` over `Opaque<uart_port>`.
        unsafe { &*ptr.cast() }
    }

    fn as_raw(&self) -> *mut bindings::uart_port {
        self.0.get()
    }

    /// The I/O port base address.
    pub fn iobase(&self) -> usize {
        // SAFETY: valid for the lifetime of `self`.
        unsafe { (*self.as_raw()).iobase as usize }
    }

    /// The IRQ number.
    pub fn irq(&self) -> u32 {
        // SAFETY: valid for the lifetime of `self`.
        unsafe { (*self.as_raw()).irq }
    }

    /// The base UART clock, in Hz.
    pub fn uartclk(&self) -> u32 {
        // SAFETY: valid for the lifetime of `self`.
        unsafe { (*self.as_raw()).uartclk }
    }

    /// Sets `read_status_mask` (which RX status bits reach the tty layer).
    pub fn set_read_status_mask(&self, mask: u32) {
        // SAFETY: valid for the lifetime of `self`; called under the port lock.
        unsafe { (*self.as_raw()).read_status_mask = mask };
    }

    // --- port I/O (UPIO_PORT: byte-wide inb/outb on iobase + offset) ---------
    //
    // We access the registers directly via `IoPort::from_raw` rather than
    // claiming the region: on this platform the in-kernel 8250 already holds
    // COM2's I/O region (it registers but never opens its ttyS), so the region
    // is effectively ours. This is the irreducible `unsafe` of a raw-port UART,
    // equivalent to the C baseline's bare `inb`/`outb`.

    fn io(&self) -> Option<IoRaw<NREG>> {
        IoRaw::<NREG>::new(self.iobase(), NREG).ok()
    }

    /// Reads register `off` (a runtime offset, so the bounds-checked variant).
    pub fn in8(&self, off: usize) -> u8 {
        let Some(raw) = self.io() else { return 0 };
        // SAFETY: the COM port range is ours for the device lifetime.
        unsafe { IoPort::<NREG>::from_raw(&raw).try_inb_p(off).unwrap_or(0) }
    }

    /// Writes `val` to register `off` (a runtime offset, so the bounds-checked variant).
    pub fn out8(&self, val: u8, off: usize) {
        let Some(raw) = self.io() else { return };
        // SAFETY: the COM port range is ours for the device lifetime.
        let _ = unsafe { IoPort::<NREG>::from_raw(&raw).try_outb_p(val, off) };
    }

    // --- port lock -----------------------------------------------------------

    /// Acquires the port spinlock, returning the saved IRQ flags.
    pub fn lock_irqsave(&self) -> ffi::c_ulong {
        let mut flags: ffi::c_ulong = 0;
        // SAFETY: `as_raw()` is a valid `uart_port`.
        unsafe { bindings::uart_port_lock_irqsave(self.as_raw(), &mut flags) };
        flags
    }

    /// Releases the port spinlock with the given saved flags.
    pub fn unlock_irqrestore(&self, flags: ffi::c_ulong) {
        // SAFETY: `as_raw()` is a valid `uart_port`; `flags` came from a paired lock.
        unsafe { bindings::uart_port_unlock_irqrestore(self.as_raw(), flags) };
    }

    // --- RX ------------------------------------------------------------------

    /// Pushes one received character into the tty flip buffer.
    pub fn insert_char(&self, status: u32, overrun: u32, ch: u8, flag: u8) {
        // SAFETY: `as_raw()` is a valid `uart_port`.
        unsafe { bindings::uart_insert_char(self.as_raw(), status, overrun, ch, flag) };
    }

    /// Flushes the tty flip buffer to the line discipline.
    pub fn flip_buffer_push(&self) {
        // SAFETY: `state` is non-null while the port is added; `&(*state).port`
        // is the embedded `tty_port`.
        unsafe { bindings::tty_flip_buffer_push(&mut (*(*self.as_raw()).state).port) };
    }

    // --- TX ------------------------------------------------------------------

    /// Pumps the TX path: pulls bytes from the xmit FIFO and writes each via
    /// `T::put_char` while `T::tx_ready` returns `true`, stopping TX when empty.
    pub fn tx_pump<T: Ops>(&self) {
        // SAFETY: `as_raw()` is valid; the trampolines recover `&T` from
        // `private_data` which is alive for the registered port's lifetime.
        unsafe {
            bindings::uart_port_tx(
                self.as_raw(),
                Some(Adapter::<T>::tx_ready_cb),
                Some(Adapter::<T>::put_char_cb),
            );
        }
    }

    // --- termios helpers -----------------------------------------------------

    /// Computes the baud rate requested by `termios`, clamped to `[min, max]`.
    pub fn get_baud_rate(
        &self,
        termios: &Ktermios,
        old: Option<&Ktermios>,
        min: u32,
        max: u32,
    ) -> u32 {
        let old = old.map_or(ptr::null(), |o| o.as_raw() as *const _);
        // SAFETY: all pointers are valid for the call.
        unsafe { bindings::uart_get_baud_rate(self.as_raw(), termios.as_raw(), old, min, max) }
    }

    /// Computes the clock divisor for `baud`.
    pub fn get_divisor(&self, baud: u32) -> u32 {
        // SAFETY: `as_raw()` is a valid `uart_port`.
        unsafe { bindings::uart_get_divisor(self.as_raw(), baud) }
    }

    /// Updates the port's per-character timeout for `cflag`/`baud`.
    pub fn update_timeout(&self, cflag: u32, baud: u32) {
        // SAFETY: `as_raw()` is a valid `uart_port`.
        unsafe { bindings::uart_update_timeout(self.as_raw(), cflag, baud) };
    }

    // --- IRQ -----------------------------------------------------------------

    /// Requests a shared interrupt routed to `T::interrupt`.
    pub fn request_irq<T: Ops>(&self, name: &'static CStr) -> Result {
        // SAFETY: `dev_id` is the port pointer, recovered in the trampoline.
        let ret = unsafe {
            bindings::request_threaded_irq(
                self.irq(),
                Some(Adapter::<T>::irq_cb),
                None,
                bindings::IRQF_SHARED as ffi::c_ulong,
                name.as_char_ptr(),
                self.as_raw().cast(),
            )
        };
        to_result(ret)
    }

    /// Frees the interrupt requested by [`request_irq`](Self::request_irq).
    pub fn free_irq(&self) {
        // SAFETY: paired with a successful `request_irq`; `dev_id` matches.
        unsafe { bindings::free_irq(self.irq(), self.as_raw().cast()) };
    }
}

/// Low-level UART operations implemented by a driver.
///
/// Every method receives `&self` (recovered from the port's `private_data`) and
/// the `&Port`. Implementors are `Sync` because the callbacks run from both
/// process and hard-IRQ context.
pub trait Ops: Sized + Sync + 'static {
    /// Returns whether the transmitter is fully drained.
    fn tx_empty(&self, port: &Port) -> bool;
    /// Programs the modem-control lines from a `TIOCM_*` bitmask.
    fn set_mctrl(&self, port: &Port, mctrl: u32);
    /// Reads the modem-status lines as a `TIOCM_*` bitmask.
    fn get_mctrl(&self, port: &Port) -> u32;
    /// Disables the TX (THRE) interrupt.
    fn stop_tx(&self, port: &Port);
    /// Enables the TX (THRE) interrupt.
    fn start_tx(&self, port: &Port);
    /// Disables the RX interrupt.
    fn stop_rx(&self, port: &Port);
    /// Brings the port up: request IRQ, enable RX, etc.
    fn startup(&self, port: &Port) -> Result;
    /// Takes the port down: mask interrupts, free IRQ.
    fn shutdown(&self, port: &Port);
    /// Applies line settings (baud, word length, parity, ...).
    fn set_termios(&self, port: &Port, new: &Ktermios, old: Option<&Ktermios>);
    /// Returns a human-readable port-type name.
    fn port_type(&self) -> &'static CStr;
    /// Reports whether the HW can accept another TX byte (TX pump callback).
    fn tx_ready(&self, port: &Port) -> bool;
    /// Writes one byte to the HW (TX pump callback).
    fn put_char(&self, port: &Port, ch: u8);
    /// The hardware interrupt handler.
    fn interrupt(&self, port: &Port) -> IrqReturn;

    /// Sets the port type during config (default: 16550A). No region request.
    fn config_port(&self, port: &Port, _flags: i32) {
        // SAFETY: called by the core with a valid port; setting the type only.
        unsafe { (*port.as_raw()).type_ = bindings::PORT_16550A };
    }
    /// Requests port resources (default: none — we tolerate the 8250's hold).
    fn request_port(&self, _port: &Port) -> Result {
        Ok(())
    }
    /// Releases port resources (default: none).
    fn release_port(&self, _port: &Port) {}
}

/// Builds the C `uart_ops` vtable and trampolines for a given [`Ops`].
struct Adapter<T: Ops>(PhantomData<T>);

impl<T: Ops> Adapter<T> {
    const VTABLE: bindings::uart_ops = Self::build();

    const fn build() -> bindings::uart_ops {
        // SAFETY: an all-zero `uart_ops` is valid (all fields nullable fn ptrs).
        let mut ops: bindings::uart_ops = unsafe { core::mem::zeroed() };
        ops.tx_empty = Some(Self::tx_empty_cb);
        ops.set_mctrl = Some(Self::set_mctrl_cb);
        ops.get_mctrl = Some(Self::get_mctrl_cb);
        ops.stop_tx = Some(Self::stop_tx_cb);
        ops.start_tx = Some(Self::start_tx_cb);
        ops.stop_rx = Some(Self::stop_rx_cb);
        ops.startup = Some(Self::startup_cb);
        ops.shutdown = Some(Self::shutdown_cb);
        ops.set_termios = Some(Self::set_termios_cb);
        ops.type_ = Some(Self::type_cb);
        ops.config_port = Some(Self::config_port_cb);
        ops.request_port = Some(Self::request_port_cb);
        ops.release_port = Some(Self::release_port_cb);
        ops.verify_port = Some(Self::verify_port_cb);
        ops
    }

    /// # Safety
    /// `port` must be a valid `uart_port` whose `private_data` points to a `T`.
    unsafe fn ctx<'a>(port: *mut bindings::uart_port) -> (&'a T, &'a Port) {
        // SAFETY: per the contract.
        let t = unsafe { &*((*port).private_data as *const T) };
        // SAFETY: per the contract.
        let p = unsafe { Port::from_raw(port) };
        (t, p)
    }

    unsafe extern "C" fn tx_empty_cb(port: *mut bindings::uart_port) -> ffi::c_uint {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        if t.tx_empty(p) {
            bindings::TIOCSER_TEMT
        } else {
            0
        }
    }

    unsafe extern "C" fn set_mctrl_cb(port: *mut bindings::uart_port, mctrl: ffi::c_uint) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.set_mctrl(p, mctrl);
    }

    unsafe extern "C" fn get_mctrl_cb(port: *mut bindings::uart_port) -> ffi::c_uint {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.get_mctrl(p)
    }

    unsafe extern "C" fn stop_tx_cb(port: *mut bindings::uart_port) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.stop_tx(p);
    }

    unsafe extern "C" fn start_tx_cb(port: *mut bindings::uart_port) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.start_tx(p);
    }

    unsafe extern "C" fn stop_rx_cb(port: *mut bindings::uart_port) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.stop_rx(p);
    }

    unsafe extern "C" fn startup_cb(port: *mut bindings::uart_port) -> ffi::c_int {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        match t.startup(p) {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn shutdown_cb(port: *mut bindings::uart_port) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.shutdown(p);
    }

    unsafe extern "C" fn set_termios_cb(
        port: *mut bindings::uart_port,
        new: *mut bindings::ktermios,
        old: *const bindings::ktermios,
    ) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        // SAFETY: `new` is valid; `old` may be null.
        let new = unsafe { Ktermios::from_raw(new) };
        let old = if old.is_null() {
            None
        } else {
            // SAFETY: non-null and valid for the call.
            Some(unsafe { Ktermios::from_raw(old.cast_mut()) })
        };
        t.set_termios(p, new, old);
    }

    unsafe extern "C" fn type_cb(port: *mut bindings::uart_port) -> *const ffi::c_char {
        // SAFETY: trampoline contract.
        let (t, _p) = unsafe { Self::ctx(port) };
        t.port_type().as_char_ptr()
    }

    unsafe extern "C" fn config_port_cb(port: *mut bindings::uart_port, flags: ffi::c_int) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.config_port(p, flags);
    }

    unsafe extern "C" fn request_port_cb(port: *mut bindings::uart_port) -> ffi::c_int {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        match t.request_port(p) {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn release_port_cb(port: *mut bindings::uart_port) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.release_port(p);
    }

    unsafe extern "C" fn verify_port_cb(
        _port: *mut bindings::uart_port,
        _ser: *mut bindings::serial_struct,
    ) -> ffi::c_int {
        0
    }

    unsafe extern "C" fn tx_ready_cb(port: *mut bindings::uart_port) -> bool {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.tx_ready(p)
    }

    unsafe extern "C" fn put_char_cb(port: *mut bindings::uart_port, ch: ffi::c_uchar) {
        // SAFETY: trampoline contract.
        let (t, p) = unsafe { Self::ctx(port) };
        t.put_char(p, ch);
    }

    unsafe extern "C" fn irq_cb(
        _irq: ffi::c_int,
        dev_id: *mut ffi::c_void,
    ) -> bindings::irqreturn_t {
        let port = dev_id.cast::<bindings::uart_port>();
        // SAFETY: `dev_id` is the port pointer registered in `request_irq`.
        let (t, p) = unsafe { Self::ctx(port) };
        t.interrupt(p) as bindings::irqreturn_t
    }
}

/// A registered `uart_driver` (created at module init, unregistered on drop).
///
/// The boxed `uart_driver` has a stable address that the serial core retains;
/// the [`Driver`] must outlive every [`PortRegistration`] it owns.
pub struct Driver {
    inner: KBox<Opaque<bindings::uart_driver>>,
}

// SAFETY: the serial core serialises access to the registered driver.
unsafe impl Send for Driver {}
// SAFETY: as above.
unsafe impl Sync for Driver {}

impl Driver {
    /// Registers a new `uart_driver` with `nr` ports under `/dev/<dev_name>N`.
    pub fn new(
        module: &'static ThisModule,
        driver_name: &'static CStr,
        dev_name: &'static CStr,
        nr: i32,
    ) -> Result<Self> {
        let inner = KBox::new(Opaque::<bindings::uart_driver>::zeroed(), GFP_KERNEL)?;
        let p = inner.get();
        // SAFETY: `p` is a freshly-allocated, zeroed `uart_driver`.
        unsafe {
            (*p).owner = module.as_ptr();
            (*p).driver_name = driver_name.as_char_ptr();
            (*p).dev_name = dev_name.as_char_ptr();
            (*p).nr = nr;
            to_result(bindings::uart_register_driver(p))?;
        }
        Ok(Driver { inner })
    }

    /// The raw `uart_driver` pointer (stable; the boxed struct never moves).
    ///
    /// Useful for sharing the registered driver with a platform `probe` through
    /// a module-global, then passing it to [`PortRegistration::new`].
    pub fn as_ptr(&self) -> *mut bindings::uart_driver {
        self.inner.get()
    }

    /// Configures and adds a single port driven by `data: T`, parented to `dev`.
    pub fn add_port<T: Ops, Ctx: device::DeviceContext>(
        &self,
        dev: &device::Device<Ctx>,
        cfg: PortConfig,
        data: T,
    ) -> Result<PortRegistration<T>> {
        // SAFETY: `self` is a registered driver that outlives the returned port.
        unsafe { PortRegistration::new(self.as_ptr(), dev, cfg, data) }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // SAFETY: registered in `new`; no ports remain (they hold a ref and drop first).
        unsafe { bindings::uart_unregister_driver(self.inner.get()) };
    }
}

/// A module-global slot that publishes a registered [`Driver`] so a bus
/// `probe` (a static method, with no access to module state) can add a port to
/// it without any `unsafe` in the driver.
///
/// Typical use: declare a `static SHARED: SharedDriver = SharedDriver::new();`,
/// call [`set`](Self::set) once in `Module::init` after registering the
/// [`Driver`], and call [`add_port`](Self::add_port) from `probe`.
///
/// # Soundness contract
///
/// The [`Driver`] passed to [`set`] must outlive every port added through this
/// handle. The idiomatic way to guarantee this is to own the [`Driver`] in the
/// module struct and declare it *after* the bus registration, so the bus
/// driver is unregistered (its devices unbound and their ports removed) before
/// the [`Driver`] is dropped. `add_port` only runs from `probe`, which cannot
/// fire after the bus driver is unregistered, so the published pointer is live
/// for the duration of every `add_port` call.
pub struct SharedDriver(core::sync::atomic::AtomicPtr<bindings::uart_driver>);

// `AtomicPtr` is `Sync`, so `SharedDriver` is usable as a `static`.
impl SharedDriver {
    /// Creates an empty slot.
    pub const fn new() -> Self {
        SharedDriver(core::sync::atomic::AtomicPtr::new(ptr::null_mut()))
    }

    /// Publishes `driver` (see the type's soundness contract).
    pub fn set(&self, driver: &Driver) {
        self.0
            .store(driver.as_ptr(), core::sync::atomic::Ordering::Release);
    }

    /// Adds a port driven by `data: T` (parented to `dev`) to the published
    /// driver. Returns [`ENODEV`] if no driver has been [`set`](Self::set).
    pub fn add_port<T: Ops, Ctx: device::DeviceContext>(
        &self,
        dev: &device::Device<Ctx>,
        cfg: PortConfig,
        data: T,
    ) -> Result<PortRegistration<T>> {
        let drv = self.0.load(core::sync::atomic::Ordering::Acquire);
        if drv.is_null() {
            return Err(ENODEV);
        }
        // SAFETY: a non-null `drv` was published by `set` from a `&Driver`
        // registered via `Driver::new`; the type's soundness contract
        // guarantees that driver outlives this (and the returned) port.
        unsafe { PortRegistration::new(drv, dev, cfg, data) }
    }
}

impl Default for SharedDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Static configuration for a port added via [`Driver::add_port`].
pub struct PortConfig {
    /// I/O port base address.
    pub iobase: usize,
    /// IRQ number.
    pub irq: u32,
    /// Base UART clock (Hz).
    pub uartclk: u32,
    /// TX FIFO size.
    pub fifosize: u32,
    /// Port index (`0..nr`).
    pub line: u32,
}

/// An added `uart_port`. Removes the port (and frees its data) on drop.
pub struct PortRegistration<T: Ops> {
    drv: *mut bindings::uart_driver,
    port: KBox<Opaque<bindings::uart_port>>,
    _data: KBox<T>,
}

// SAFETY: the serial core serialises access to the registered port.
unsafe impl<T: Ops> Send for PortRegistration<T> {}
// SAFETY: as above.
unsafe impl<T: Ops> Sync for PortRegistration<T> {}

impl<T: Ops> PortRegistration<T> {
    /// Builds a `uart_port` (parented to `dev`) and adds it to `uart_drv`.
    ///
    /// # Safety
    ///
    /// `uart_drv` must point to a `uart_driver` registered via [`Driver::new`]
    /// that outlives the returned registration.
    pub unsafe fn new<Ctx: device::DeviceContext>(
        uart_drv: *mut bindings::uart_driver,
        dev: &device::Device<Ctx>,
        cfg: PortConfig,
        data: T,
    ) -> Result<Self> {
        let data = KBox::new(data, GFP_KERNEL)?;
        let port = KBox::new(Opaque::<bindings::uart_port>::zeroed(), GFP_KERNEL)?;
        let pp = port.get();
        // SAFETY: `pp` is a freshly-allocated, zeroed `uart_port`; `uart_drv` is
        // valid per the contract; `private_data` points to the boxed `data`
        // which lives as long as `self`.
        unsafe {
            (*pp).iobase = cfg.iobase as ffi::c_ulong;
            (*pp).iotype = bindings::uart_iotype_UPIO_PORT;
            (*pp).irq = cfg.irq;
            (*pp).uartclk = cfg.uartclk;
            (*pp).fifosize = cfg.fifosize;
            (*pp).type_ = bindings::PORT_16550A;
            (*pp).line = cfg.line;
            (*pp).dev = dev.as_raw();
            (*pp).ops = &Adapter::<T>::VTABLE;
            (*pp).private_data = &*data as *const T as *mut ffi::c_void;
            to_result(bindings::uart_add_one_port(uart_drv, pp))?;
        }
        Ok(PortRegistration {
            drv: uart_drv,
            port,
            _data: data,
        })
    }
}

impl<T: Ops> Drop for PortRegistration<T> {
    fn drop(&mut self) {
        // SAFETY: `drv` is the still-alive driver and `port` was added to it.
        // Removing first guarantees no callback runs after `_data` is freed.
        unsafe { bindings::uart_remove_one_port(self.drv, self.port.get()) };
    }
}
