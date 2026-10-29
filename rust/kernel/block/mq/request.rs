// SPDX-License-Identifier: GPL-2.0

//! This module provides a wrapper for the C `struct request` type.
//!
//! C header: [`include/linux/blk-mq.h`](srctree/include/linux/blk-mq.h)

use crate::{
    bindings,
    block::mq::{BlockStatus, Operations, BLK_STS_IOERR},
    device,
    dma,
    prelude::*,
    sync::{
        aref::{ARef, AlwaysRefCounted},
        atomic::Relaxed,
        Refcount,
    },
    types::Opaque,
};
use core::{marker::PhantomData, mem::MaybeUninit, ptr::NonNull};

/// A wrapper around a blk-mq [`struct request`]. This represents an IO request.
///
/// # Implementation details
///
/// There are four states for a request that the Rust bindings care about:
///
/// 1. Request is owned by block layer (refcount 0).
/// 2. Request is owned by driver but with zero [`ARef`]s in existence
///    (refcount 1).
/// 3. Request is owned by driver with exactly one [`ARef`] in existence
///    (refcount 2).
/// 4. Request is owned by driver with more than one [`ARef`] in existence
///    (refcount > 2).
///
///
/// We need to track 1 and 2 to ensure we fail tag to request conversions for
/// requests that are not owned by the driver.
///
/// We need to track 3 and 4 to ensure that it is safe to end the request and hand
/// back ownership to the block layer.
///
/// Note that the driver can still obtain new `ARef` even if there is no `ARef`s in existence by
/// using `tag_to_rq`, hence the need to distinguish B and C.
///
/// The states are tracked through the private `refcount` field of
/// `RequestDataWrapper`. This structure lives in the private data area of the C
/// [`struct request`].
///
/// # Invariants
///
/// * `self.0` is a valid [`struct request`] created by the C portion of the
///   kernel.
/// * The private data area associated with this request must be an initialized
///   and valid `RequestDataWrapper<T>`.
/// * `self` is reference counted by atomic modification of
///   `self.wrapper_ref().refcount()`.
///
/// [`struct request`]: srctree/include/linux/blk-mq.h
///
#[repr(transparent)]
pub struct Request<T>(Opaque<bindings::request>, PhantomData<T>);

impl<T: Operations> Request<T> {
    /// Create an [`ARef<Request>`] from a [`struct request`] pointer.
    ///
    /// # Safety
    ///
    /// * The caller must own a refcount on `ptr` that is transferred to the
    ///   returned [`ARef`].
    /// * The type invariants for [`Request`] must hold for the pointee of `ptr`.
    ///
    /// [`struct request`]: srctree/include/linux/blk-mq.h
    pub(crate) unsafe fn aref_from_raw(ptr: *mut bindings::request) -> ARef<Self> {
        // INVARIANT: By the safety requirements of this function, invariants are upheld.
        // SAFETY: By the safety requirement of this function, we own a
        // reference count that we can pass to `ARef`.
        unsafe { ARef::from_raw(NonNull::new_unchecked(ptr.cast())) }
    }

    /// Notify the block layer that a request is going to be processed now.
    ///
    /// The block layer uses this hook to do proper initializations such as
    /// starting the timeout timer. It is a requirement that block device
    /// drivers call this function when starting to process a request.
    ///
    /// # Safety
    ///
    /// The caller must have exclusive ownership of `self`, that is
    /// `self.wrapper_ref().refcount() == 2`.
    pub(crate) unsafe fn start_unchecked(this: &ARef<Self>) {
        // SAFETY: By type invariant, `self.0` is a valid `struct request` and
        // we have exclusive access.
        unsafe { bindings::blk_mq_start_request(this.0.get()) };
    }

    /// Try to take exclusive ownership of `this` by dropping the refcount to 0.
    /// This fails if `this` is not the only [`ARef`] pointing to the underlying
    /// [`Request`].
    ///
    /// If the operation is successful, [`Ok`] is returned with a pointer to the
    /// C [`struct request`]. If the operation fails, `this` is returned in the
    /// [`Err`] variant.
    ///
    /// [`struct request`]: srctree/include/linux/blk-mq.h
    fn try_set_end(this: ARef<Self>) -> Result<*mut bindings::request, ARef<Self>> {
        // To hand back the ownership, we need the current refcount to be 2.
        // Since we can race with `TagSet::tag_to_rq`, this needs to atomically reduce
        // refcount to 0. `Refcount` does not provide a way to do this, so use the underlying
        // atomics directly.
        if let Err(_old) = this
            .wrapper_ref()
            .refcount()
            .as_atomic()
            .cmpxchg(2, 0, Relaxed)
        {
            return Err(this);
        }

        let request_ptr = this.0.get();
        core::mem::forget(this);

        Ok(request_ptr)
    }

    /// Notify the block layer that the request has been completed without errors.
    ///
    /// This function will return [`Err`] if `this` is not the only [`ARef`]
    /// referencing the request.
    pub fn end_ok(this: ARef<Self>) -> Result<(), ARef<Self>> {
        let request_ptr = Self::try_set_end(this)?;

        // SAFETY: By type invariant, `this.0` was a valid `struct request`. The
        // success of the call to `try_set_end` guarantees that there are no
        // `ARef`s pointing to this request. Therefore it is safe to hand it
        // back to the block layer.
        unsafe {
            bindings::blk_mq_end_request(
                request_ptr,
                bindings::BLK_STS_OK as bindings::blk_status_t,
            )
        };

        Ok(())
    }

    /// Notify the block layer that the request has completed with `status`. Mirrors C
    /// `blk_mq_end_request(req, status)`. Use `BLK_STS_DEV_RESOURCE` to signal "retry later"
    /// (e.g. a full virtqueue) — the block layer requeues internally, avoiding a driver-side
    /// `blk_mq_requeue_request` + `blk_mq_stop_hw_queue` dance.
    pub fn end_request(this: ARef<Self>, status: bindings::blk_status_t) -> Result<(), ARef<Self>> {
        let request_ptr = Self::try_set_end(this)?;
        // SAFETY: same as `end_ok` — `try_set_end` succeeded, so no `ARef`s remain + `request_ptr`
        // is a valid `struct request` to hand back to the block layer.
        unsafe { bindings::blk_mq_end_request(request_ptr, status) };
        Ok(())
    }

    /// Complete the request by scheduling `Operations::complete` for
    /// execution.
    ///
    /// The function may be scheduled locally, via SoftIRQ or remotely via IPMI.
    /// See `blk_mq_complete_request_remote` in [`blk-mq.c`] for details.
    ///
    /// [`blk-mq.c`]: srctree/block/blk-mq.c
    pub fn complete(this: ARef<Self>) {
        let ptr = ARef::into_raw(this).cast::<bindings::request>().as_ptr();
        // SAFETY: By type invariant, `self.0` is a valid `struct request`
        if !unsafe { bindings::blk_mq_complete_request_remote(ptr) } {
            // SAFETY: We released a refcount above that we can reclaim here.
            let this = unsafe { Request::aref_from_raw(ptr) };
            T::complete(this);
        }
    }

    /// Complete a request identified by its raw `struct request *`, transferring the in-flight
    /// refcount to an [`ARef`] + scheduling [`Operations::complete`]. Use from a driver's
    /// device-completion callback (e.g. a virtio vq callback) that recovers the request pointer
    /// from its per-request data.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid `struct request *` whose driver-owned in-flight refcount the caller
    /// transfers to this call (i.e. the request was in flight + the device has now completed it).
    pub unsafe fn complete_raw(ptr: *mut bindings::request) {
        // SAFETY: the caller transfers the in-flight refcount to the ARef.
        let this = unsafe { Self::aref_from_raw(ptr) };
        Self::complete(this);
    }

    /// The request operation (`req_op(req)` = `cmd_flags & REQ_OP_MASK`): one of `REQ_OP_READ`,
    /// `REQ_OP_WRITE`, `REQ_OP_FLUSH`, `REQ_OP_DISCARD`, …
    pub fn req_op(&self) -> u32 {
        // SAFETY: `self.0` is a valid `struct request` by the type invariant.
        unsafe { bindings::req_op(self.0.get()) }
    }

    /// `true` if this is a write request (`rq_data_dir(req) == WRITE`).
    pub fn is_write(&self) -> bool {
        // SAFETY: `self.0` is a valid `struct request` by the type invariant.
        unsafe { bindings::rq_data_dir(self.0.get()) != 0 }
    }

    /// The starting sector (`blk_rq_pos(req)`).
    pub fn sector(&self) -> u64 {
        // SAFETY: `self.0` is a valid `struct request` by the type invariant.
        unsafe { bindings::blk_rq_pos(self.0.get()) }
    }

    /// The number of physical segments (`blk_rq_nr_phys_segments(req)`).
    pub fn nr_phys_segments(&self) -> u32 {
        // SAFETY: `self.0` is a valid `struct request` by the type invariant.
        unsafe { bindings::blk_rq_nr_phys_segments(self.0.get()) as u32 }
    }

    /// The request tag (the blk-mq tag, usable as an index into a per-tag driver array).
    pub fn tag(&self) -> u32 {
        // SAFETY: `self.0` is a valid `struct request` by the type invariant.
        unsafe { (*self.0.get()).tag as u32 }
    }

    /// The total data length in bytes (`req->__data_len`).
    pub fn data_len(&self) -> u32 {
        // SAFETY: `self.0` is a valid `struct request` by the type invariant.
        unsafe { (*self.0.get()).__data_len }
    }

    /// The raw `struct request *` (for driver-side recovery of queue data, e.g. a virtio-blk
    /// `complete` op reading `rq->q->queuedata` to find its per-device state).
    pub fn as_raw(&self) -> *mut bindings::request {
        self.0.get()
    }

    /// Map the request's bios into `sglist` (a contiguous `scatterlist` array of at least
    /// `nr_phys_segments` entries) and return the count. Mirrors C `blk_rq_map_sg(req, sglist)`:
    /// the last entry is marked end. The caller owns `sglist` for the request's lifetime.
    pub fn map_sg(&self, sglist: *mut bindings::scatterlist) -> i32 {
        // SAFETY: `self.0` is a valid `struct request` by the type invariant; the caller guarantees
        // `sglist` is a valid array large enough for `nr_phys_segments` entries.
        unsafe { bindings::blk_rq_map_sg(self.0.get(), sglist) }
    }

    /// Return a pointer to the [`RequestDataWrapper`] stored in the private area
    /// of the request structure.
    ///
    /// # Safety
    ///
    /// - `this` must point to a valid allocation of size at least size of
    ///   [`Self`] plus size of [`RequestDataWrapper`].
    pub(crate) unsafe fn wrapper_ptr(this: *mut Self) -> NonNull<RequestDataWrapper> {
        let request_ptr = this.cast::<bindings::request>();
        // SAFETY: By safety requirements for this function, `this` is a
        // valid allocation.
        let wrapper_ptr =
            unsafe { bindings::blk_mq_rq_to_pdu(request_ptr).cast::<RequestDataWrapper>() };
        // SAFETY: By C API contract, `wrapper_ptr` points to a valid allocation
        // and is not null.
        unsafe { NonNull::new_unchecked(wrapper_ptr) }
    }

    /// Return a reference to the [`RequestDataWrapper`] stored in the private
    /// area of the request structure.
    pub(crate) fn wrapper_ref(&self) -> &RequestDataWrapper {
        // SAFETY: By type invariant, `self.0` is a valid allocation. Further,
        // the private data associated with this request is initialized and
        // valid. The existence of `&self` guarantees that the private data is
        // valid as a shared reference.
        unsafe { Self::wrapper_ptr(core::ptr::from_ref(self).cast_mut()).as_ref() }
    }
}

/// A non-refcounted handle to a blk-mq `struct request`, for drivers that store the request pointer
/// in per-request data and complete it later from a device callback (e.g. a virtio-blk vq callback
/// that ends the request directly via `blk_mq_end_request`, bypassing the `Request::complete`
/// scheduling — the RFL `Request::end_request`/`end_ok` path assumes refcount 2 from the `queue_rq`
/// `ARef`, while a vq callback recovers only the in-flight refcount). The handle holds NO refcount —
/// it borrows the driver-owned in-flight refcount — so it must only be used while the request is in
/// flight. `Send`+`Sync`: blk-mq guarantees one in-flight request per tag, so the pointer is
/// race-free to send/share. Generic over `T` ⇒ monomorphized into the driver module (no exported
/// symbol; the `.ko` calls `blk_mq_end_request` directly, as C does).
pub struct RequestHandle<T: Operations>(*mut bindings::request, PhantomData<fn() -> T>);

// SAFETY: `RequestHandle` wraps a `*mut request` that blk-mq guarantees is tag-exclusive (one
// in-flight request per tag), so sending/sharing the handle across threads is race-free. The
// `PhantomData<fn() -> T>` marker carries no ownership/Send implications.
unsafe impl<T: Operations> Send for RequestHandle<T> {}
unsafe impl<T: Operations> Sync for RequestHandle<T> {}

impl<T: Operations> RequestHandle<T> {
    /// Wrap a raw `struct request *` (e.g. from [`Request::as_raw`]). The handle borrows the
    /// driver-owned in-flight refcount; do not use it after the request is ended.
    #[inline]
    pub fn from_raw(ptr: *mut bindings::request) -> Self {
        Self(ptr, PhantomData)
    }

    /// End the request directly with `status` (mirrors C `blk_mq_end_request(req, status)`). This
    /// bypasses the `Request::complete`/`end_ok` refcount dance — use when the caller holds only
    /// the in-flight refcount (e.g. a virtio vq callback recovering the request from per-request
    /// data), not a full `ARef<Request>`.
    #[inline]
    pub fn end_request(&self, status: bindings::blk_status_t) {
        // SAFETY: by contract, `self.0` is a valid in-flight `struct request *` the caller owns the
        // in-flight refcount for.
        unsafe { bindings::blk_mq_end_request(self.0, status) };
    }
}

/// An unmapped request that must be completed exactly once.
///
/// [`RequestDmaMapping::take_completion`] returns this owner after removing the DMA mapping. It can
/// be moved out of a queue lock and consumed there, so `blk_mq_end_request()` does not run while the
/// driver's queue-state spinlock is held.
pub struct RequestCompletion<T: Operations>(RequestHandle<T>);

impl<T: Operations> RequestCompletion<T> {
    /// End the request with `status`, consuming the only completion owner.
    pub fn complete(self, status: BlockStatus) {
        self.0.end_request(status);
    }
}

/// One page-bounded, DMA-mapped blk-mq request buffer.
///
/// This is the safe RFL counterpart of the common C sequence
/// `blk_rq_map_sg()` -> `dma_map_sg()` -> `sg_dma_address()` ->
/// `dma_unmap_sg()` -> `blk_mq_end_request()`. It deliberately supports one physical segment:
/// drivers using it must publish matching queue limits. The scatterlist itself is heap-backed so
/// its address stays stable from map through unmap even when this handle is moved.
pub struct RequestDmaMapping<T: Operations> {
    sg: KBox<bindings::scatterlist>,
    dev: Option<ARef<device::Device>>,
    direction: Option<dma::DataDirection>,
    request: Option<RequestHandle<T>>,
    dma_len: usize,
}

// The scatterlist storage is separately heap allocated and the owner contains no self-reference,
// so moving an idle or active owner does not move any address given to the DMA API.
impl<T: Operations> Unpin for RequestDmaMapping<T> {}

// SAFETY: The embedded scatterlist is heap-backed and used by exactly one in-flight blk-mq tag.
// Moving the owner between queue and IRQ context does not move the scatterlist allocation. The
// DMA API and blk-mq keep the request pages alive until `complete()` ends the stored request.
unsafe impl<T: Operations> Send for RequestDmaMapping<T> {}

impl<T: Operations> RequestDmaMapping<T> {
    /// Allocate an idle mapping slot. This is intended for probe-time allocation and later reuse,
    /// avoiding allocation in `queue_rq`.
    pub fn new(flags: crate::alloc::Flags) -> Result<Self> {
        let mut sg = MaybeUninit::<bindings::scatterlist>::uninit();
        // SAFETY: `sg` is valid uninitialized storage for one entry; `sg_init_table` initializes
        // that entry, including CONFIG_DEBUG_SG metadata and the end marker.
        unsafe { bindings::sg_init_table(sg.as_mut_ptr(), 1) };
        // SAFETY: the preceding initializer wrote the complete one-entry table.
        let sg = unsafe { sg.assume_init() };
        Ok(Self {
            sg: KBox::new(sg, flags)?,
            dev: None,
            direction: None,
            request: None,
            dma_len: 0,
        })
    }

    /// Map a single-segment request for device DMA and retain its in-flight completion handle.
    ///
    /// The mapped segment must be wholly contained in one kernel page, which is sufficient for a
    /// single NVMe PRP entry and similar one-page device descriptors. The request remains owned by
    /// the driver until [`take_completion`](Self::take_completion) or [`complete`](Self::complete)
    /// is called.
    pub fn map(
        &mut self,
        request: &Request<T>,
        dev: &device::Device,
        direction: dma::DataDirection,
    ) -> Result {
        if self.request.is_some() {
            return Err(EBUSY);
        }
        let data_len = request.data_len() as usize;
        if data_len == 0 || data_len > crate::page::PAGE_SIZE || request.nr_phys_segments() != 1 {
            return Err(EINVAL);
        }

        // Reinitialize the reusable single entry before blk_rq_map_sg fills it. In particular this
        // restores CONFIG_DEBUG_SG metadata and clears flags left by the preceding request.
        // SAFETY: the slot is idle and therefore not DMA mapped; the box points to one valid entry.
        unsafe { bindings::sg_init_table(&mut *self.sg, 1) };
        if request.map_sg(&mut *self.sg) != 1 {
            return Err(EINVAL);
        }

        // SAFETY: `dev` is a live bound DMA device; `self.sg` is a valid one-entry scatterlist
        // populated from the live request; the mapping is paired with `unmap()` below.
        let mapped = unsafe {
            bindings::dma_map_sg_attrs(
                dev.as_raw(),
                &mut *self.sg,
                1,
                direction.into(),
                0,
            )
        };
        if mapped != 1 {
            if mapped > 0 {
                // SAFETY: the preceding call mapped the original one-entry list with these exact
                // device/direction/attribute arguments.
                unsafe {
                    bindings::dma_unmap_sg_attrs(
                        dev.as_raw(),
                        &mut *self.sg,
                        1,
                        direction.into(),
                        0,
                    )
                };
            }
            return Err(EIO);
        }

        // SAFETY: the entry was successfully DMA mapped above.
        let dma_address = unsafe { bindings::sg_dma_address(&mut *self.sg) } as usize;
        // SAFETY: the entry was successfully DMA mapped above.
        let dma_len = unsafe { bindings::sg_dma_len(&mut *self.sg) } as usize;
        if dma_len != data_len
            || (dma_address & (crate::page::PAGE_SIZE - 1)) + dma_len > crate::page::PAGE_SIZE
        {
            // SAFETY: exact inverse of the successful map above.
            unsafe {
                bindings::dma_unmap_sg_attrs(
                    dev.as_raw(),
                    &mut *self.sg,
                    1,
                    direction.into(),
                    0,
                )
            };
            return Err(EINVAL);
        }

        self.dev = Some(dev.into());
        self.direction = Some(direction);
        self.request = Some(RequestHandle::from_raw(request.as_raw()));
        self.dma_len = dma_len;
        Ok(())
    }

    /// Whether this slot currently owns an in-flight request mapping.
    pub fn is_active(&self) -> bool {
        self.request.is_some()
    }

    /// Device address of the mapped request buffer.
    pub fn dma_address(&mut self) -> Result<dma::DmaAddress> {
        if self.request.is_none() {
            return Err(ENODEV);
        }
        // SAFETY: an active slot has a successfully DMA-mapped scatterlist.
        Ok(unsafe { bindings::sg_dma_address(&mut *self.sg) })
    }

    /// Length in bytes of the mapped request buffer.
    pub fn len(&self) -> usize {
        self.dma_len
    }

    fn unmap(&mut self) {
        if let (Some(dev), Some(direction)) = (self.dev.take(), self.direction.take()) {
            // SAFETY: `map()` created this exact one-entry mapping and it has not been unmapped.
            unsafe {
                bindings::dma_unmap_sg_attrs(
                    dev.as_raw(),
                    &mut *self.sg,
                    1,
                    direction.into(),
                    0,
                )
            };
        }
        self.dma_len = 0;
    }

    /// Unmap the buffer and take an exactly-once completion owner.
    ///
    /// Callers should do this while holding their queue-state lock, release that lock, and only
    /// then call [`RequestCompletion::complete`].
    pub fn take_completion(&mut self) -> Option<RequestCompletion<T>> {
        self.unmap();
        self.request.take().map(RequestCompletion)
    }

    /// Unmap and complete immediately. Prefer [`take_completion`](Self::take_completion) when the
    /// mapping is protected by a queue-state lock.
    pub fn complete(&mut self, status: BlockStatus) {
        if let Some(completion) = self.take_completion() {
            completion.complete(status);
        }
    }

    /// Undo a mapping before a command is published to hardware. The request remains owned by
    /// blk-mq and may be returned from `queue_rq` with an error/retry status.
    pub fn cancel(&mut self) {
        self.unmap();
        let _ = self.request.take();
    }
}

impl<T: Operations> Drop for RequestDmaMapping<T> {
    fn drop(&mut self) {
        // Fail closed if driver teardown reaches a still-active slot.
        self.complete(BLK_STS_IOERR);
    }
}

/// A wrapper around data stored in the private area of the C [`struct request`].
///
/// [`struct request`]: srctree/include/linux/blk-mq.h
pub(crate) struct RequestDataWrapper {
    /// The Rust request refcount has the following states:
    ///
    /// - 0: The request is owned by C block layer.
    /// - 1: The request is owned by Rust abstractions but there are no [`ARef`] references to it.
    /// - 2+: There are [`ARef`] references to the request.
    refcount: Refcount,
}

impl RequestDataWrapper {
    /// Return a reference to the refcount of the request that is embedding
    /// `self`.
    pub(crate) fn refcount(&self) -> &Refcount {
        &self.refcount
    }

    /// Return a pointer to the refcount of the request that is embedding the
    /// pointee of `this`.
    ///
    /// # Safety
    ///
    /// - `this` must point to a live allocation of at least the size of `Self`.
    pub(crate) unsafe fn refcount_ptr(this: *mut Self) -> *mut Refcount {
        // SAFETY: Because of the safety requirements of this function, the
        // field projection is safe.
        unsafe { &raw mut (*this).refcount }
    }
}

// SAFETY: Exclusive access is thread-safe for `Request`. `Request` has no `&mut
// self` methods and `&self` methods that mutate `self` are internally
// synchronized.
unsafe impl<T: Operations> Send for Request<T> {}

// SAFETY: Shared access is thread-safe for `Request`. `&self` methods that
// mutate `self` are internally synchronized`
unsafe impl<T: Operations> Sync for Request<T> {}

// SAFETY: All instances of `Request<T>` are reference counted. This
// implementation of `AlwaysRefCounted` ensure that increments to the ref count
// keeps the object alive in memory at least until a matching reference count
// decrement is executed.
unsafe impl<T: Operations> AlwaysRefCounted for Request<T> {
    fn inc_ref(&self) {
        self.wrapper_ref().refcount().inc();
    }

    unsafe fn dec_ref(obj: core::ptr::NonNull<Self>) {
        // SAFETY: The type invariants of `ARef` guarantee that `obj` is valid
        // for read.
        let wrapper_ptr = unsafe { Self::wrapper_ptr(obj.as_ptr()).as_ptr() };
        // SAFETY: The type invariant of `Request` guarantees that the private
        // data area is initialized and valid.
        let refcount = unsafe { &*RequestDataWrapper::refcount_ptr(wrapper_ptr) };

        #[cfg_attr(not(CONFIG_DEBUG_MISC), allow(unused_variables))]
        let is_zero = refcount.dec_and_test();

        #[cfg(CONFIG_DEBUG_MISC)]
        if is_zero {
            panic!("Request reached refcount zero in Rust abstractions");
        }
    }
}
