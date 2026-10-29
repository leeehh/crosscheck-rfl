// SPDX-License-Identifier: GPL-2.0

//! PCI interrupt infrastructure.

use super::Device;
use crate::{
    bindings,
    device,
    device::Bound,
    devres,
    error::to_result,
    irq::{
        self,
        IrqRequest, //
    },
    prelude::*,
    str::{CStr, CString},
    sync::{aref::ARef, Arc}, //
};
use core::{marker::PhantomPinned, ops::RangeInclusive};
use pin_init::{pin_data, pinned_drop};

static_assert!(bindings::IRQ_AFFINITY_MAX_SETS >= 2);

/// IRQ type flags for PCI interrupt allocation.
#[derive(Debug, Clone, Copy)]
pub enum IrqType {
    /// INTx interrupts.
    Intx,
    /// Message Signaled Interrupts (MSI).
    Msi,
    /// Extended Message Signaled Interrupts (MSI-X).
    MsiX,
}

impl IrqType {
    /// Convert to the corresponding kernel flags.
    const fn as_raw(self) -> u32 {
        match self {
            IrqType::Intx => bindings::PCI_IRQ_INTX,
            IrqType::Msi => bindings::PCI_IRQ_MSI,
            IrqType::MsiX => bindings::PCI_IRQ_MSIX,
        }
    }
}

/// Set of IRQ types that can be used for PCI interrupt allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct IrqTypes(u32);

impl IrqTypes {
    /// Create a set containing all IRQ types (MSI-X, MSI, and INTx).
    pub const fn all() -> Self {
        Self(bindings::PCI_IRQ_ALL_TYPES)
    }

    /// Build a set of IRQ types.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Create a set with only MSI and MSI-X (no INTx interrupts).
    /// let msi_only = IrqTypes::default()
    ///     .with(IrqType::Msi)
    ///     .with(IrqType::MsiX);
    /// ```
    pub const fn with(self, irq_type: IrqType) -> Self {
        Self(self.0 | irq_type.as_raw())
    }

    /// Get the raw flags value.
    const fn as_raw(self) -> u32 {
        self.0
    }
}

/// Sizes of up to four IRQ affinity sets.
#[derive(Clone, Copy, Debug)]
pub struct AffinitySetSizes {
    sizes: [u32; bindings::IRQ_AFFINITY_MAX_SETS as usize],
    count: u32,
}

impl AffinitySetSizes {
    /// One affinity set.
    pub const fn one(size: u32) -> Self {
        let mut sizes = [0; bindings::IRQ_AFFINITY_MAX_SETS as usize];
        sizes[0] = size;
        Self { sizes, count: 1 }
    }

    /// Two affinity sets, for example default and read queues.
    pub const fn two(first: u32, second: u32) -> Self {
        let mut sizes = [0; bindings::IRQ_AFFINITY_MAX_SETS as usize];
        sizes[0] = first;
        sizes[1] = second;
        Self { sizes, count: 2 }
    }
}

/// Calculates queue-set sizes after the PCI core has selected a vector count.
///
/// The callback runs synchronously inside
/// `pci_alloc_irq_vectors_affinity`; the mutable borrow cannot escape that
/// call.
pub trait AffinityCalculator {
    /// Split `available_vectors` into affinity sets.
    fn calculate(&mut self, available_vectors: u32) -> AffinitySetSizes;
}

/// Represents an allocated IRQ vector for a specific PCI device.
///
/// This type ties an IRQ vector to the device it was allocated for,
/// ensuring the vector is only used with the correct device.
#[derive(Clone, Copy)]
pub struct IrqVector<'a> {
    dev: &'a Device<Bound>,
    index: u32,
}

impl<'a> IrqVector<'a> {
    /// Creates a new [`IrqVector`] for the given device and index.
    ///
    /// # Safety
    ///
    /// - `index` must be a valid IRQ vector index for `dev`.
    /// - `dev` must point to a [`Device`] that has successfully allocated IRQ vectors.
    unsafe fn new(dev: &'a Device<Bound>, index: u32) -> Self {
        Self { dev, index }
    }

    /// Returns the raw vector index.
    fn index(&self) -> u32 {
        self.index
    }
}

struct DynamicIrqVectorsInner {
    dev: ARef<Device>,
    count: u32,
}

impl Drop for DynamicIrqVectorsInner {
    fn drop(&mut self) {
        // SAFETY: The last reference owns the successful vector allocation.
        // Registrations retain a reference, so they have already run
        // `free_irq` before this point.
        unsafe { bindings::pci_free_irq_vectors(self.dev.as_raw()) };
    }
}

/// An explicitly managed PCI IRQ-vector allocation.
///
/// Unlike [`Device::alloc_irq_vectors`], this allocation is not devres-owned:
/// transports that reset hardware may replace it while the function remains
/// bound. Registrations retain the shared inner allocation, making it
/// impossible to free vectors while a handler is still installed.
#[derive(Clone)]
pub struct DynamicIrqVectors {
    inner: Arc<DynamicIrqVectorsInner>,
}

impl DynamicIrqVectors {
    /// Allocate vectors without an affinity layout.
    pub fn new(dev: &Device, min_vecs: u32, max_vecs: u32, irq_types: IrqTypes) -> Result<Self> {
        // SAFETY: `dev` is live; the PCI core validates counts and flags.
        let ret = unsafe {
            bindings::pci_alloc_irq_vectors(dev.as_raw(), min_vecs, max_vecs, irq_types.as_raw())
        };
        if ret < 0 {
            return Err(Error::from_errno(ret));
        }
        Ok(Self {
            inner: Arc::new(
                DynamicIrqVectorsInner {
                    dev: dev.into(),
                    count: ret as u32,
                },
                GFP_KERNEL,
            )?,
        })
    }

    /// Allocate vectors with a driver-defined affinity-set calculation.
    pub fn with_affinity<C: AffinityCalculator>(
        dev: &Device,
        min_vecs: u32,
        max_vecs: u32,
        irq_types: IrqTypes,
        pre_vectors: u32,
        post_vectors: u32,
        calculator: &mut C,
    ) -> Result<Self> {
        unsafe extern "C" fn calculate<C: AffinityCalculator>(
            affinity: *mut bindings::irq_affinity,
            available_vectors: u32,
        ) {
            // SAFETY: `with_affinity` stores its exclusive, synchronous
            // `calculator` borrow in `priv_` for this C call only.
            let calculator = unsafe { &mut *((*affinity).priv_.cast::<C>()) };
            let sets = calculator.calculate(available_vectors);
            // SAFETY: `affinity` is the writable descriptor supplied by
            // `with_affinity`; `AffinitySetSizes` enforces the array bound.
            unsafe {
                (*affinity).nr_sets = sets.count;
                (*affinity).set_size = sets.sizes;
            }
        }

        let mut affinity: bindings::irq_affinity = unsafe { core::mem::zeroed() };
        affinity.pre_vectors = pre_vectors;
        affinity.post_vectors = post_vectors;
        affinity.calc_sets = Some(calculate::<C>);
        affinity.priv_ = core::ptr::from_mut(calculator).cast();

        // SAFETY: `affinity` and `calculator` remain live and exclusively
        // borrowed for the synchronous allocation call. Counts and flags are
        // validated by the PCI/IRQ cores.
        let ret = unsafe {
            bindings::pci_alloc_irq_vectors_affinity(
                dev.as_raw(),
                min_vecs,
                max_vecs,
                irq_types.as_raw() | bindings::PCI_IRQ_AFFINITY,
                &mut affinity,
            )
        };
        if ret < 0 {
            return Err(Error::from_errno(ret));
        }
        Ok(Self {
            inner: Arc::new(
                DynamicIrqVectorsInner {
                    dev: dev.into(),
                    count: ret as u32,
                },
                GFP_KERNEL,
            )?,
        })
    }

    /// Number of allocated vectors.
    pub fn len(&self) -> u32 {
        self.inner.count
    }

    /// Whether no vector is allocated (always false for a constructed value).
    pub fn is_empty(&self) -> bool {
        self.inner.count == 0
    }

    /// Resolve a checked vector index to its Linux IRQ number.
    pub fn irq_number(&self, index: u32) -> Result<u32> {
        if index >= self.inner.count {
            return Err(EINVAL);
        }
        // SAFETY: The index was checked against this live allocation.
        let irq = unsafe { bindings::pci_irq_vector(self.inner.dev.as_raw(), index) };
        if irq < 0 {
            Err(Error::from_errno(irq))
        } else {
            Ok(irq as u32)
        }
    }

    /// Create an IRQ registration for one vector.
    pub fn request_irq<T: DynamicIrqHandler + 'static>(
        &self,
        index: u32,
        flags: irq::Flags,
        name: &'static CStr,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<DynamicIrqRegistration<T>, Error> {
        DynamicIrqRegistration::new(
            self.clone(),
            self.irq_number(index),
            flags,
            DynamicIrqName::Static(name),
            handler,
        )
    }

    /// Create an IRQ registration that owns its dynamically formatted name.
    pub fn request_irq_with_name<T: DynamicIrqHandler + 'static>(
        &self,
        index: u32,
        flags: irq::Flags,
        name: CString,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<DynamicIrqRegistration<T>, Error> {
        DynamicIrqRegistration::new(
            self.clone(),
            self.irq_number(index),
            flags,
            DynamicIrqName::Owned(name),
            handler,
        )
    }

    /// Create a threaded IRQ registration for one vector.
    pub fn request_threaded_irq<T: DynamicThreadedIrqHandler + 'static>(
        &self,
        index: u32,
        flags: irq::Flags,
        name: &'static CStr,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<DynamicThreadedIrqRegistration<T>, Error> {
        DynamicThreadedIrqRegistration::new(
            self.clone(),
            self.irq_number(index),
            flags,
            DynamicIrqName::Static(name),
            handler,
        )
    }

    /// Create a threaded IRQ registration that owns its dynamically formatted
    /// name.
    pub fn request_threaded_irq_with_name<T: DynamicThreadedIrqHandler + 'static>(
        &self,
        index: u32,
        flags: irq::Flags,
        name: CString,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<DynamicThreadedIrqRegistration<T>, Error> {
        DynamicThreadedIrqRegistration::new(
            self.clone(),
            self.irq_number(index),
            flags,
            DynamicIrqName::Owned(name),
            handler,
        )
    }
}

enum DynamicIrqName {
    Static(&'static CStr),
    Owned(CString),
}

impl DynamicIrqName {
    fn as_char_ptr(&self) -> *const crate::ffi::c_char {
        match self {
            Self::Static(name) => name.as_char_ptr(),
            Self::Owned(name) => name.as_char_ptr(),
        }
    }
}

/// Hard-IRQ callback for an explicitly managed PCI vector.
pub trait DynamicIrqHandler: Sync {
    /// Handle the interrupt without relying on a forged bound-device borrow.
    fn handle(&self) -> irq::IrqReturn;
}

/// Hard and threaded callbacks for an explicitly managed PCI vector.
pub trait DynamicThreadedIrqHandler: Sync {
    /// Hard-IRQ phase. The default wakes the threaded phase.
    fn handle(&self) -> irq::ThreadedIrqReturn {
        irq::ThreadedIrqReturn::WakeThread
    }

    /// Threaded phase.
    fn handle_threaded(&self) -> irq::IrqReturn;
}

#[pin_data(PinnedDrop)]
struct DynamicRegistrationInner {
    irq: u32,
    cookie: *mut c_void,
}

impl DynamicRegistrationInner {
    fn synchronize(&self) {
        // SAFETY: The IRQ and cookie remain registered for this object's life.
        unsafe { bindings::synchronize_irq(self.irq) };
    }

    fn with_irq_disabled<R>(&self, operation: impl FnOnce() -> R) -> R {
        // SAFETY: The registration keeps this IRQ allocated for the entire
        // borrow. `disable_irq` drains any in-flight hard/threaded handler;
        // the matching enable happens before the borrow can end.
        unsafe { bindings::disable_irq(self.irq) };
        let result = operation();
        // SAFETY: This exactly balances the disable above while the same
        // registration and vector allocation are still live.
        unsafe { bindings::enable_irq(self.irq) };
        result
    }
}

#[pinned_drop]
impl PinnedDrop for DynamicRegistrationInner {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: This is the unique matching release. `free_irq` drains all
        // in-flight callbacks before returning.
        unsafe { bindings::free_irq(self.irq, self.cookie) };
    }
}

// SAFETY: Drop is the only mutable operation and executes once.
unsafe impl Send for DynamicRegistrationInner {}
// SAFETY: Shared access only synchronizes the registered IRQ.
unsafe impl Sync for DynamicRegistrationInner {}

/// A non-devres IRQ registration that keeps its vector allocation alive.
#[pin_data]
pub struct DynamicIrqRegistration<T: DynamicIrqHandler + 'static> {
    #[pin]
    inner: DynamicRegistrationInner,
    #[pin]
    handler: T,
    _vectors: DynamicIrqVectors,
    _name: DynamicIrqName,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: DynamicIrqHandler + 'static> DynamicIrqRegistration<T> {
    fn new(
        vectors: DynamicIrqVectors,
        irq: Result<u32>,
        flags: irq::Flags,
        name: DynamicIrqName,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<Self, Error> {
        let name_ptr = name.as_char_ptr();
        try_pin_init!(&this in Self {
            handler <- handler,
            _vectors: vectors,
            _name: name,
            inner <- try_pin_init!(DynamicRegistrationInner {
                cookie: this.as_ptr().cast::<c_void>(),
                irq: {
                    let irq = irq?;
                    // SAFETY: `this` is pinned, its handler is initialized,
                    // and `vectors` keeps the IRQ allocation alive.
                    to_result(unsafe {
                        bindings::request_irq(
                            irq,
                            Some(dynamic_irq_callback::<T>),
                            flags.into_inner(),
                            name_ptr,
                            this.as_ptr().cast::<c_void>(),
                        )
                    })?;
                    irq
                },
            }),
            _pin: PhantomPinned,
        })
    }

    /// Wait for all in-flight handlers.
    pub fn synchronize(&self) {
        self.inner.synchronize();
    }

    /// Run `operation` while this IRQ is disabled and all prior handlers have
    /// completed.
    ///
    /// The operation must not wait for work that requires this IRQ and must
    /// not be called from this IRQ's own hard or threaded handler.
    pub fn with_irq_disabled<R>(&self, operation: impl FnOnce() -> R) -> R {
        self.inner.with_irq_disabled(operation)
    }

    /// Handler state.
    pub fn handler(&self) -> &T {
        &self.handler
    }
}

unsafe extern "C" fn dynamic_irq_callback<T: DynamicIrqHandler + 'static>(
    _irq: c_int,
    cookie: *mut c_void,
) -> c_uint {
    // SAFETY: The cookie is the pinned registration supplied to request_irq;
    // `free_irq` drains this callback before that registration is dropped.
    let registration = unsafe { &*cookie.cast::<DynamicIrqRegistration<T>>() };
    T::handle(&registration.handler) as c_uint
}

/// A non-devres threaded IRQ registration that retains its vector allocation.
#[pin_data]
pub struct DynamicThreadedIrqRegistration<T: DynamicThreadedIrqHandler + 'static> {
    #[pin]
    inner: DynamicRegistrationInner,
    #[pin]
    handler: T,
    _vectors: DynamicIrqVectors,
    _name: DynamicIrqName,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: DynamicThreadedIrqHandler + 'static> DynamicThreadedIrqRegistration<T> {
    fn new(
        vectors: DynamicIrqVectors,
        irq: Result<u32>,
        flags: irq::Flags,
        name: DynamicIrqName,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<Self, Error> {
        let name_ptr = name.as_char_ptr();
        try_pin_init!(&this in Self {
            handler <- handler,
            _vectors: vectors,
            _name: name,
            inner <- try_pin_init!(DynamicRegistrationInner {
                cookie: this.as_ptr().cast::<c_void>(),
                irq: {
                    let irq = irq?;
                    // SAFETY: Both callbacks and their pinned state remain
                    // valid until `free_irq` drains them in drop.
                    to_result(unsafe {
                        bindings::request_threaded_irq(
                            irq,
                            Some(dynamic_threaded_irq_callback::<T>),
                            Some(dynamic_thread_fn_callback::<T>),
                            flags.into_inner(),
                            name_ptr,
                            this.as_ptr().cast::<c_void>(),
                        )
                    })?;
                    irq
                },
            }),
            _pin: PhantomPinned,
        })
    }

    /// Wait for both hard and threaded handlers to finish.
    pub fn synchronize(&self) {
        self.inner.synchronize();
    }

    /// Run `operation` while both phases of this IRQ are disabled and all
    /// prior handlers have completed.
    ///
    /// The operation must not wait for work that requires this IRQ and must
    /// not be called from this IRQ's own hard or threaded handler.
    pub fn with_irq_disabled<R>(&self, operation: impl FnOnce() -> R) -> R {
        self.inner.with_irq_disabled(operation)
    }

    /// Handler state.
    pub fn handler(&self) -> &T {
        &self.handler
    }
}

unsafe extern "C" fn dynamic_threaded_irq_callback<T: DynamicThreadedIrqHandler + 'static>(
    _irq: c_int,
    cookie: *mut c_void,
) -> c_uint {
    // SAFETY: See `dynamic_irq_callback`.
    let registration = unsafe { &*cookie.cast::<DynamicThreadedIrqRegistration<T>>() };
    T::handle(&registration.handler) as c_uint
}

unsafe extern "C" fn dynamic_thread_fn_callback<T: DynamicThreadedIrqHandler + 'static>(
    _irq: c_int,
    cookie: *mut c_void,
) -> c_uint {
    // SAFETY: See `dynamic_irq_callback`.
    let registration = unsafe { &*cookie.cast::<DynamicThreadedIrqRegistration<T>>() };
    T::handle_threaded(&registration.handler) as c_uint
}

impl<'a> TryInto<IrqRequest<'a>> for IrqVector<'a> {
    type Error = Error;

    fn try_into(self) -> Result<IrqRequest<'a>> {
        // SAFETY: `self.as_raw` returns a valid pointer to a `struct pci_dev`.
        let irq = unsafe { bindings::pci_irq_vector(self.dev.as_raw(), self.index()) };
        if irq < 0 {
            return Err(crate::error::Error::from_errno(irq));
        }
        // SAFETY: `irq` is a valid IRQ number for this bound device.
        Ok(unsafe { IrqRequest::new(self.dev.as_ref(), irq as u32) })
    }
}

/// Represents an IRQ vector allocation for a PCI device.
///
/// This type ensures that IRQ vectors are properly allocated and freed by
/// tying the allocation to the lifetime of this registration object.
///
/// # Invariants
///
/// The [`Device`] has successfully allocated IRQ vectors.
struct IrqVectorRegistration {
    dev: ARef<Device>,
}

impl IrqVectorRegistration {
    /// Allocate and register IRQ vectors for the given PCI device.
    ///
    /// Allocates IRQ vectors and registers them with devres for automatic cleanup.
    /// Returns a range of valid IRQ vectors.
    fn register<'a>(
        dev: &'a Device<Bound>,
        min_vecs: u32,
        max_vecs: u32,
        irq_types: IrqTypes,
    ) -> Result<RangeInclusive<IrqVector<'a>>> {
        // SAFETY:
        // - `dev.as_raw()` is guaranteed to be a valid pointer to a `struct pci_dev`
        //   by the type invariant of `Device`.
        // - `pci_alloc_irq_vectors` internally validates all other parameters
        //   and returns error codes.
        let ret = unsafe {
            bindings::pci_alloc_irq_vectors(dev.as_raw(), min_vecs, max_vecs, irq_types.as_raw())
        };

        to_result(ret)?;
        let count = ret as u32;

        // SAFETY:
        // - `pci_alloc_irq_vectors` returns the number of allocated vectors on success.
        // - Vectors are 0-based, so valid indices are [0, count-1].
        // - `pci_alloc_irq_vectors` guarantees `count >= min_vecs > 0`, so both `0` and
        //   `count - 1` are valid IRQ vector indices for `dev`.
        let range = unsafe { IrqVector::new(dev, 0)..=IrqVector::new(dev, count - 1) };

        // INVARIANT: The IRQ vector allocation for `dev` above was successful.
        let irq_vecs = Self { dev: dev.into() };
        devres::register(dev.as_ref(), irq_vecs, GFP_KERNEL)?;

        Ok(range)
    }
}

impl Drop for IrqVectorRegistration {
    fn drop(&mut self) {
        // SAFETY:
        // - By the type invariant, `self.dev.as_raw()` is a valid pointer to a `struct pci_dev`.
        // - `self.dev` has successfully allocated IRQ vectors.
        unsafe { bindings::pci_free_irq_vectors(self.dev.as_raw()) };
    }
}

impl Device<device::Bound> {
    /// Returns a [`kernel::irq::Registration`] for the given IRQ vector.
    pub fn request_irq<'a, T: crate::irq::Handler + 'static>(
        &'a self,
        vector: IrqVector<'a>,
        flags: irq::Flags,
        name: &'static CStr,
        handler: impl PinInit<T, Error> + 'a,
    ) -> impl PinInit<irq::Registration<T>, Error> + 'a {
        pin_init::pin_init_scope(move || {
            let request = vector.try_into()?;

            Ok(irq::Registration::<T>::new(request, flags, name, handler))
        })
    }

    /// Returns a [`kernel::irq::ThreadedRegistration`] for the given IRQ vector.
    pub fn request_threaded_irq<'a, T: crate::irq::ThreadedHandler + 'static>(
        &'a self,
        vector: IrqVector<'a>,
        flags: irq::Flags,
        name: &'static CStr,
        handler: impl PinInit<T, Error> + 'a,
    ) -> impl PinInit<irq::ThreadedRegistration<T>, Error> + 'a {
        pin_init::pin_init_scope(move || {
            let request = vector.try_into()?;

            Ok(irq::ThreadedRegistration::<T>::new(
                request, flags, name, handler,
            ))
        })
    }

    /// Allocate IRQ vectors for this PCI device with automatic cleanup.
    ///
    /// Allocates between `min_vecs` and `max_vecs` interrupt vectors for the device.
    /// The allocation will use MSI-X, MSI, or INTx interrupts based on the `irq_types`
    /// parameter and hardware capabilities. When multiple types are specified, the kernel
    /// will try them in order of preference: MSI-X first, then MSI, then INTx interrupts.
    ///
    /// The allocated vectors are automatically freed when the device is unbound, using the
    /// devres (device resource management) system.
    ///
    /// # Arguments
    ///
    /// * `min_vecs` - Minimum number of vectors required.
    /// * `max_vecs` - Maximum number of vectors to allocate.
    /// * `irq_types` - Types of interrupts that can be used.
    ///
    /// # Returns
    ///
    /// Returns a range of IRQ vectors that were successfully allocated, or an error if the
    /// allocation fails or cannot meet the minimum requirement.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kernel::{ device::Bound, pci};
    /// # fn no_run(dev: &pci::Device<Bound>) -> Result {
    /// // Allocate using any available interrupt type in the order mentioned above.
    /// let vectors = dev.alloc_irq_vectors(1, 32, pci::IrqTypes::all())?;
    ///
    /// // Allocate MSI or MSI-X only (no INTx interrupts).
    /// let msi_only = pci::IrqTypes::default()
    ///     .with(pci::IrqType::Msi)
    ///     .with(pci::IrqType::MsiX);
    /// let vectors = dev.alloc_irq_vectors(4, 16, msi_only)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn alloc_irq_vectors(
        &self,
        min_vecs: u32,
        max_vecs: u32,
        irq_types: IrqTypes,
    ) -> Result<RangeInclusive<IrqVector<'_>>> {
        IrqVectorRegistration::register(self, min_vecs, max_vecs, irq_types)
    }
}
