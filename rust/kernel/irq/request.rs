// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright 2025 Collabora ltd.

//! This module provides types like [`Registration`] and
//! [`ThreadedRegistration`], which allow users to register handlers for a given
//! IRQ line.

use core::marker::{PhantomData, PhantomPinned};

use crate::alloc::Allocator;
use crate::device::{Bound, Device};
use crate::devres::Devres;
use crate::error::to_result;
use crate::irq::flags::Flags;
use crate::prelude::*;
use crate::str::CStr;
use crate::sync::Arc;

/// The value that can be returned from a [`Handler`] or a [`ThreadedHandler`].
#[repr(u32)]
pub enum IrqReturn {
    /// The interrupt was not from this device or was not handled.
    None = bindings::irqreturn_IRQ_NONE,

    /// The interrupt was handled by this device.
    Handled = bindings::irqreturn_IRQ_HANDLED,
}

/// Callbacks for an IRQ handler.
pub trait Handler: Sync {
    /// The hard IRQ handler.
    ///
    /// This is executed in interrupt context, hence all corresponding
    /// limitations do apply.
    ///
    /// All work that does not necessarily need to be executed from
    /// interrupt context, should be deferred to a threaded handler.
    /// See also [`ThreadedRegistration`].
    fn handle(&self, device: &Device<Bound>) -> IrqReturn;
}

impl<T: ?Sized + Handler + Send> Handler for Arc<T> {
    fn handle(&self, device: &Device<Bound>) -> IrqReturn {
        T::handle(self, device)
    }
}

impl<T: ?Sized + Handler, A: Allocator> Handler for Box<T, A> {
    fn handle(&self, device: &Device<Bound>) -> IrqReturn {
        T::handle(self, device)
    }
}

/// # Invariants
///
/// - `self.irq` is the same as the one passed to `request_{threaded}_irq`.
/// - `cookie` was passed to `request_{threaded}_irq` as the cookie. It is guaranteed to be unique
///   by the type system, since each call to `new` will return a different instance of
///   `Registration`.
#[pin_data(PinnedDrop)]
struct RegistrationInner {
    irq: u32,
    cookie: *mut c_void,
}

impl RegistrationInner {
    fn synchronize(&self) {
        // SAFETY: safe as per the invariants of `RegistrationInner`
        unsafe { bindings::synchronize_irq(self.irq) };
    }
}

#[pinned_drop]
impl PinnedDrop for RegistrationInner {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY:
        //
        // Safe as per the invariants of `RegistrationInner` and:
        //
        // - The containing struct is `!Unpin` and was initialized using
        // pin-init, so it occupied the same memory location for the entirety of
        // its lifetime.
        //
        // Notice that this will block until all handlers finish executing,
        // i.e.: at no point will &self be invalid while the handler is running.
        unsafe { bindings::free_irq(self.irq, self.cookie) };
    }
}

// SAFETY: We only use `inner` on drop, which called at most once with no
// concurrent access.
unsafe impl Sync for RegistrationInner {}

// SAFETY: It is safe to send `RegistrationInner` across threads.
unsafe impl Send for RegistrationInner {}

/// A request for an IRQ line for a given device.
///
/// # Invariants
///
/// - `ìrq` is the number of an interrupt source of `dev`.
/// - `irq` has not been registered yet.
pub struct IrqRequest<'a> {
    dev: &'a Device<Bound>,
    irq: u32,
}

impl<'a> IrqRequest<'a> {
    /// Creates a new IRQ request for the given device and IRQ number.
    ///
    /// # Safety
    ///
    /// - `irq` should be a valid IRQ number for `dev`.
    pub(crate) unsafe fn new(dev: &'a Device<Bound>, irq: u32) -> Self {
        // INVARIANT: `irq` is a valid IRQ number for `dev`.
        IrqRequest { dev, irq }
    }

    /// Returns the IRQ number of an [`IrqRequest`].
    pub fn irq(&self) -> u32 {
        self.irq
    }

    pub(crate) fn device(&self) -> &Device<Bound> {
        self.dev
    }
}

/// A registration of an IRQ handler for a given IRQ line.
///
/// # Examples
///
/// The following is an example of using `Registration`. It uses a
/// [`Completion`] to coordinate between the IRQ
/// handler and process context. [`Completion`] uses interior mutability, so the
/// handler can signal with [`Completion::complete_all()`] and the process
/// context can wait with [`Completion::wait_for_completion()`] even though
/// there is no way to get a mutable reference to the any of the fields in
/// `Data`.
///
/// [`Completion`]: kernel::sync::Completion
/// [`Completion::complete_all()`]: kernel::sync::Completion::complete_all
/// [`Completion::wait_for_completion()`]: kernel::sync::Completion::wait_for_completion
///
/// ```
/// use kernel::c_str;
/// use kernel::device::{Bound, Device};
/// use kernel::irq::{self, Flags, IrqRequest, IrqReturn, Registration};
/// use kernel::prelude::*;
/// use kernel::sync::{Arc, Completion};
///
/// // Data shared between process and IRQ context.
/// #[pin_data]
/// struct Data {
///     #[pin]
///     completion: Completion,
/// }
///
/// impl irq::Handler for Data {
///     // Executed in IRQ context.
///     fn handle(&self, _dev: &Device<Bound>) -> IrqReturn {
///         self.completion.complete_all();
///         IrqReturn::Handled
///     }
/// }
///
/// // Registers an IRQ handler for the given IrqRequest.
/// //
/// // This runs in process context and assumes `request` was previously acquired from a device.
/// fn register_irq(
///     handler: impl PinInit<Data, Error>,
///     request: IrqRequest<'_>,
/// ) -> Result<Arc<Registration<Data>>> {
///     let registration = Registration::new(request, Flags::SHARED, c_str!("my_device"), handler);
///
///     let registration = Arc::pin_init(registration, GFP_KERNEL)?;
///
///     registration.handler().completion.wait_for_completion();
///
///     Ok(registration)
/// }
/// # Ok::<(), Error>(())
/// ```
///
/// # Invariants
///
/// * We own an irq handler whose cookie is a pointer to `Self`.
#[pin_data]
pub struct Registration<T: Handler + 'static> {
    #[pin]
    inner: Devres<RegistrationInner>,

    #[pin]
    handler: T,

    /// Pinned because we need address stability so that we can pass a pointer
    /// to the callback.
    #[pin]
    _pin: PhantomPinned,
}

impl<T: Handler + 'static> Registration<T> {
    /// Registers the IRQ handler with the system for the given IRQ number.
    pub fn new<'a>(
        request: IrqRequest<'a>,
        flags: Flags,
        name: &'static CStr,
        handler: impl PinInit<T, Error> + 'a,
    ) -> impl PinInit<Self, Error> + 'a {
        try_pin_init!(&this in Self {
            handler <- handler,
            inner <- Devres::new(
                request.dev,
                try_pin_init!(RegistrationInner {
                    // INVARIANT: `this` is a valid pointer to the `Registration` instance
                    cookie: this.as_ptr().cast::<c_void>(),
                    irq: {
                        // SAFETY:
                        // - The callbacks are valid for use with request_irq.
                        // - If this succeeds, the slot is guaranteed to be valid until the
                        //   destructor of Self runs, which will deregister the callbacks
                        //   before the memory location becomes invalid.
                        // - When request_irq is called, everything that handle_irq_callback will
                        //   touch has already been initialized, so it's safe for the callback to
                        //   be called immediately.
                        to_result(unsafe {
                            bindings::request_irq(
                                request.irq,
                                Some(handle_irq_callback::<T>),
                                flags.into_inner(),
                                name.as_char_ptr(),
                                this.as_ptr().cast::<c_void>(),
                            )
                        })?;
                        request.irq
                    }
                })
            ),
            _pin: PhantomPinned,
        })
    }

    /// Returns a reference to the handler that was registered with the system.
    pub fn handler(&self) -> &T {
        &self.handler
    }

    /// Wait for pending IRQ handlers on other CPUs.
    ///
    /// This will attempt to access the inner [`Devres`] container.
    pub fn try_synchronize(&self) -> Result {
        let inner = self.inner.try_access().ok_or(ENODEV)?;
        inner.synchronize();
        Ok(())
    }

    /// Wait for pending IRQ handlers on other CPUs.
    pub fn synchronize(&self, dev: &Device<Bound>) -> Result {
        let inner = self.inner.access(dev)?;
        inner.synchronize();
        Ok(())
    }
}

/// # Safety
///
/// This function should be only used as the callback in `request_irq`.
unsafe extern "C" fn handle_irq_callback<T: Handler>(_irq: i32, ptr: *mut c_void) -> c_uint {
    // SAFETY: `ptr` is a pointer to `Registration<T>` set in `Registration::new`
    let registration = unsafe { &*(ptr as *const Registration<T>) };
    // SAFETY: The irq callback is removed before the device is unbound, so the fact that the irq
    // callback is running implies that the device has not yet been unbound.
    let device = unsafe { registration.inner.device().as_bound() };

    T::handle(&registration.handler, device) as c_uint
}

/// The value that can be returned from [`ThreadedHandler::handle`].
#[repr(u32)]
pub enum ThreadedIrqReturn {
    /// The interrupt was not from this device or was not handled.
    None = bindings::irqreturn_IRQ_NONE,

    /// The interrupt was handled by this device.
    Handled = bindings::irqreturn_IRQ_HANDLED,

    /// The handler wants the handler thread to wake up.
    WakeThread = bindings::irqreturn_IRQ_WAKE_THREAD,
}

/// Callbacks for a threaded IRQ handler.
pub trait ThreadedHandler: Sync {
    /// The hard IRQ handler.
    ///
    /// This is executed in interrupt context, hence all corresponding
    /// limitations do apply. All work that does not necessarily need to be
    /// executed from interrupt context, should be deferred to the threaded
    /// handler, i.e. [`ThreadedHandler::handle_threaded`].
    ///
    /// The default implementation returns [`ThreadedIrqReturn::WakeThread`].
    #[expect(unused_variables)]
    fn handle(&self, device: &Device<Bound>) -> ThreadedIrqReturn {
        ThreadedIrqReturn::WakeThread
    }

    /// The threaded IRQ handler.
    ///
    /// This is executed in process context. The kernel creates a dedicated
    /// `kthread` for this purpose.
    fn handle_threaded(&self, device: &Device<Bound>) -> IrqReturn;
}

impl<T: ?Sized + ThreadedHandler + Send> ThreadedHandler for Arc<T> {
    fn handle(&self, device: &Device<Bound>) -> ThreadedIrqReturn {
        T::handle(self, device)
    }

    fn handle_threaded(&self, device: &Device<Bound>) -> IrqReturn {
        T::handle_threaded(self, device)
    }
}

impl<T: ?Sized + ThreadedHandler, A: Allocator> ThreadedHandler for Box<T, A> {
    fn handle(&self, device: &Device<Bound>) -> ThreadedIrqReturn {
        T::handle(self, device)
    }

    fn handle_threaded(&self, device: &Device<Bound>) -> IrqReturn {
        T::handle_threaded(self, device)
    }
}

/// A registration of a threaded IRQ handler for a given IRQ line.
///
/// Two callbacks are required: one to handle the IRQ, and one to handle any
/// other work in a separate thread.
///
/// The thread handler is only called if the IRQ handler returns
/// [`ThreadedIrqReturn::WakeThread`].
///
/// # Examples
///
/// The following is an example of using [`ThreadedRegistration`]. It uses a
/// [`Mutex`](kernel::sync::Mutex) to provide interior mutability.
///
/// ```
/// use kernel::c_str;
/// use kernel::device::{Bound, Device};
/// use kernel::irq::{
///   self, Flags, IrqRequest, IrqReturn, ThreadedHandler, ThreadedIrqReturn,
///   ThreadedRegistration,
/// };
/// use kernel::prelude::*;
/// use kernel::sync::{Arc, Mutex};
///
/// // Declare a struct that will be passed in when the interrupt fires. The u32
/// // merely serves as an example of some internal data.
/// //
/// // [`irq::ThreadedHandler::handle`] takes `&self`. This example
/// // illustrates how interior mutability can be used when sharing the data
/// // between process context and IRQ context.
/// #[pin_data]
/// struct Data {
///     #[pin]
///     value: Mutex<u32>,
/// }
///
/// impl ThreadedHandler for Data {
///     // This will run (in a separate kthread) if and only if
///     // [`ThreadedHandler::handle`] returns [`WakeThread`], which it does by
///     // default.
///     fn handle_threaded(&self, _dev: &Device<Bound>) -> IrqReturn {
///         let mut data = self.value.lock();
///         *data += 1;
///         IrqReturn::Handled
///     }
/// }
///
/// // Registers a threaded IRQ handler for the given [`IrqRequest`].
/// //
/// // This is executing in process context and assumes that `request` was
/// // previously acquired from a device.
/// fn register_threaded_irq(
///     handler: impl PinInit<Data, Error>,
///     request: IrqRequest<'_>,
/// ) -> Result<Arc<ThreadedRegistration<Data>>> {
///     let registration =
///         ThreadedRegistration::new(request, Flags::SHARED, c_str!("my_device"), handler);
///
///     let registration = Arc::pin_init(registration, GFP_KERNEL)?;
///
///     {
///         // The data can be accessed from process context too.
///         let mut data = registration.handler().value.lock();
///         *data += 1;
///     }
///
///     Ok(registration)
/// }
/// # Ok::<(), Error>(())
/// ```
///
/// # Invariants
///
/// * We own an irq handler whose cookie is a pointer to `Self`.
#[pin_data]
pub struct ThreadedRegistration<T: ThreadedHandler + 'static> {
    #[pin]
    inner: Devres<RegistrationInner>,

    #[pin]
    handler: T,

    /// Pinned because we need address stability so that we can pass a pointer
    /// to the callback.
    #[pin]
    _pin: PhantomPinned,
}

impl<T: ThreadedHandler + 'static> ThreadedRegistration<T> {
    /// Registers the IRQ handler with the system for the given IRQ number.
    pub fn new<'a>(
        request: IrqRequest<'a>,
        flags: Flags,
        name: &'static CStr,
        handler: impl PinInit<T, Error> + 'a,
    ) -> impl PinInit<Self, Error> + 'a {
        try_pin_init!(&this in Self {
            handler <- handler,
            inner <- Devres::new(
                request.dev,
                try_pin_init!(RegistrationInner {
                    // INVARIANT: `this` is a valid pointer to the `ThreadedRegistration` instance.
                    cookie: this.as_ptr().cast::<c_void>(),
                    irq: {
                        // SAFETY:
                        // - The callbacks are valid for use with request_threaded_irq.
                        // - If this succeeds, the slot is guaranteed to be valid until the
                        //   destructor of Self runs, which will deregister the callbacks
                        //   before the memory location becomes invalid.
                        // - When request_threaded_irq is called, everything that the two callbacks
                        //   will touch has already been initialized, so it's safe for the
                        //   callbacks to be called immediately.
                        to_result(unsafe {
                            bindings::request_threaded_irq(
                                request.irq,
                                Some(handle_threaded_irq_callback::<T>),
                                Some(thread_fn_callback::<T>),
                                flags.into_inner(),
                                name.as_char_ptr(),
                                this.as_ptr().cast::<c_void>(),
                            )
                        })?;
                        request.irq
                    }
                })
            ),
            _pin: PhantomPinned,
        })
    }

    /// Returns a reference to the handler that was registered with the system.
    pub fn handler(&self) -> &T {
        &self.handler
    }

    /// Wait for pending IRQ handlers on other CPUs.
    ///
    /// This will attempt to access the inner [`Devres`] container.
    pub fn try_synchronize(&self) -> Result {
        let inner = self.inner.try_access().ok_or(ENODEV)?;
        inner.synchronize();
        Ok(())
    }

    /// Wait for pending IRQ handlers on other CPUs.
    pub fn synchronize(&self, dev: &Device<Bound>) -> Result {
        let inner = self.inner.access(dev)?;
        inner.synchronize();
        Ok(())
    }
}

/// A threaded IRQ registration whose callback data is an already-pinned driver state.
///
/// This models C `devm_request_threaded_irq(..., data)` users where the IRQ handler should
/// operate on the same provider state that owns the registration, without embedding another
/// copy of that state in the registration object.
///
/// # Drop ordering (self-referential use)
///
/// Unlike [`ThreadedRegistration`], which *owns* its callback data, this variant only *borrows*
/// it through a raw `*const T`. When this registration is dropped, its inner [`Devres`] drops
/// first and calls `free_irq`, which **blocks until all in-flight handlers have finished** — and
/// those handlers dereference the borrowed `T`. The borrowed `T` must therefore stay fully valid
/// until this registration's drop has *completed*, not merely until the registration is "alive".
///
/// In the natural self-referential pattern the registration is a sibling field of the same `T` it
/// points at. Struct fields drop in declaration order, so this registration MUST be declared
/// *before* any field whose data its handlers touch (ideally the first field): only then does its
/// `free_irq` drain run while that data is still alive. Declaring it *after* such a field would
/// leave a window where a draining handler dereferences already-dropped state — a use-after-free
/// on unbind. (If the handler data is genuinely owned rather than borrowed, prefer
/// [`ThreadedRegistration`], which is immune to this because it keeps the data alive through the
/// drain.)
#[pin_data]
pub struct ThreadedRegistrationRef<T: ThreadedHandler + 'static> {
    #[pin]
    inner: Devres<RegistrationInner>,
    data: *const T,
    _p: PhantomData<T>,

    /// Pinned because we pass a pointer to `Self` as the IRQ cookie.
    #[pin]
    _pin: PhantomPinned,
}

impl<T: ThreadedHandler + 'static> ThreadedRegistrationRef<T> {
    /// Registers a threaded IRQ handler backed by a pinned driver state pointer.
    ///
    /// # Safety
    ///
    /// `data` must point to a valid, pinned `T` that stays fully valid until this registration's
    /// [`Drop`] has completed (i.e. until the `free_irq` drain in drop returns), not merely while
    /// the registration is alive — see the [type-level drop-ordering note]. The pointed-to value
    /// must have initialized all fields used by the IRQ callbacks before this registration is
    /// created.
    ///
    /// [type-level drop-ordering note]: ThreadedRegistrationRef#drop-ordering-self-referential-use
    pub unsafe fn new<'a>(
        request: IrqRequest<'a>,
        flags: Flags,
        name: &'static CStr,
        data: *const T,
    ) -> impl PinInit<Self, Error> + 'a {
        try_pin_init!(&this in Self {
            data: {
                if data.is_null() {
                    return Err(EINVAL);
                }
                data
            },
            inner <- Devres::new(
                request.dev,
                try_pin_init!(RegistrationInner {
                    // INVARIANT: `this` is a valid pointer to the `ThreadedRegistrationRef`
                    // instance. The driver-data pointer is stored inside `Self`.
                    cookie: this.as_ptr().cast::<c_void>(),
                    irq: {
                        // SAFETY:
                        // - The callbacks are valid for use with request_threaded_irq.
                        // - `data` is valid by this function's safety contract.
                        // - `Self` is pinned, so the IRQ cookie remains stable until drop.
                        to_result(unsafe {
                            bindings::request_threaded_irq(
                                request.irq,
                                Some(handle_threaded_irq_ref_callback::<T>),
                                Some(thread_fn_ref_callback::<T>),
                                flags.into_inner(),
                                name.as_char_ptr(),
                                this.as_ptr().cast::<c_void>(),
                            )
                        })?;
                        request.irq
                    }
                })
            ),
            _p: PhantomData,
            _pin: PhantomPinned,
        })
    }

    /// Registers a threaded IRQ handler backed by a pinned driver-state reference.
    ///
    /// This is the safe counterpart to [`new`]. The caller passes `data: Pin<&T>` — typically the
    /// driver's own pinned object obtained in the bus driver's *bound* phase — and the resulting
    /// registration must be stored inside that same `T` (devres-owned) and declared *before* the
    /// fields its handlers touch (see the [type-level drop-ordering note]), so the borrowed pointer
    /// stays valid through the `free_irq` drain in drop. No caller-side `unsafe` is required.
    ///
    /// [`new`]: Self::new
    /// [type-level drop-ordering note]: ThreadedRegistrationRef#drop-ordering-self-referential-use
    pub fn register<'a>(
        request: IrqRequest<'a>,
        flags: Flags,
        name: &'static CStr,
        data: Pin<&'a T>,
    ) -> impl PinInit<Self, Error> + 'a {
        let data: *const T = data.get_ref();
        // SAFETY: `data` is a pinned reference to a `T` the caller keeps alive — the registration
        // is stored inside that same devres-owned `T`, declared before the fields its handlers
        // touch — so the pointer stays valid until this registration's drop (the `free_irq` drain)
        // completes. All fields used by the callbacks are initialized before `bound()` runs.
        unsafe { Self::new(request, flags, name, data) }
    }

    /// Return the borrowed callback data.
    pub fn data(&self) -> &T {
        // SAFETY: Guaranteed by the constructor safety contract and registration lifetime.
        unsafe { &*self.data }
    }

    /// Wait for pending IRQ handlers on other CPUs.
    ///
    /// # Context
    ///
    /// May sleep, and does so while holding the RCU read-side lock that guards the underlying
    /// [`Devres`] access (the registration must stay alive across `synchronize_irq`, which itself
    /// may block waiting for an in-flight *threaded* handler to finish). It must therefore not be
    /// called from atomic context. When a bound [`Device`] reference is available, prefer
    /// [`synchronize`](Self::synchronize), which does not hold the RCU read lock across the wait.
    pub fn try_synchronize(&self) -> Result {
        let inner = self.inner.try_access().ok_or(ENODEV)?;
        inner.synchronize();
        Ok(())
    }

    /// Wait for pending IRQ handlers on other CPUs.
    ///
    /// May sleep; must be called from a sleepable context.
    pub fn synchronize(&self, dev: &Device<Bound>) -> Result {
        let inner = self.inner.access(dev)?;
        inner.synchronize();
        Ok(())
    }
}

// SAFETY: Registration state only stores kernel-owned devres state plus a pinned driver-data
// pointer whose callbacks require `T: Sync`.
unsafe impl<T: ThreadedHandler + 'static> Send for ThreadedRegistrationRef<T> {}
// SAFETY: Callbacks access driver data through `T: Sync`.
unsafe impl<T: ThreadedHandler + 'static> Sync for ThreadedRegistrationRef<T> {}

/// # Safety
///
/// This function should be only used as the callback in `request_threaded_irq`.
unsafe extern "C" fn handle_threaded_irq_callback<T: ThreadedHandler>(
    _irq: i32,
    ptr: *mut c_void,
) -> c_uint {
    // SAFETY: `ptr` is a pointer to `ThreadedRegistration<T>` set in `ThreadedRegistration::new`
    let registration = unsafe { &*(ptr as *const ThreadedRegistration<T>) };
    // SAFETY: The irq callback is removed before the device is unbound, so the fact that the irq
    // callback is running implies that the device has not yet been unbound.
    let device = unsafe { registration.inner.device().as_bound() };

    T::handle(&registration.handler, device) as c_uint
}

/// # Safety
///
/// This function should be only used as the callback in `request_threaded_irq`.
unsafe extern "C" fn thread_fn_callback<T: ThreadedHandler>(_irq: i32, ptr: *mut c_void) -> c_uint {
    // SAFETY: `ptr` is a pointer to `ThreadedRegistration<T>` set in `ThreadedRegistration::new`
    let registration = unsafe { &*(ptr as *const ThreadedRegistration<T>) };
    // SAFETY: The irq callback is removed before the device is unbound, so the fact that the irq
    // callback is running implies that the device has not yet been unbound.
    let device = unsafe { registration.inner.device().as_bound() };

    T::handle_threaded(&registration.handler, device) as c_uint
}

/// # Safety
///
/// This function should be only used as the callback in `request_threaded_irq`.
unsafe extern "C" fn handle_threaded_irq_ref_callback<T: ThreadedHandler + 'static>(
    _irq: i32,
    ptr: *mut c_void,
) -> c_uint {
    // SAFETY: `ptr` is a pointer to `ThreadedRegistrationRef<T>` set in
    // `ThreadedRegistrationRef::new`.
    let registration = unsafe { &*(ptr as *const ThreadedRegistrationRef<T>) };
    // SAFETY: The irq callback is removed before the device is unbound, so the fact that the irq
    // callback is running implies that the device has not yet been unbound.
    let device = unsafe { registration.inner.device().as_bound() };

    T::handle(registration.data(), device) as c_uint
}

/// # Safety
///
/// This function should be only used as the callback in `request_threaded_irq`.
unsafe extern "C" fn thread_fn_ref_callback<T: ThreadedHandler + 'static>(
    _irq: i32,
    ptr: *mut c_void,
) -> c_uint {
    // SAFETY: `ptr` is a pointer to `ThreadedRegistrationRef<T>` set in
    // `ThreadedRegistrationRef::new`.
    let registration = unsafe { &*(ptr as *const ThreadedRegistrationRef<T>) };
    // SAFETY: The irq callback is removed before the device is unbound, so the fact that the irq
    // callback is running implies that the device has not yet been unbound.
    let device = unsafe { registration.inner.device().as_bound() };

    T::handle_threaded(registration.data(), device) as c_uint
}
