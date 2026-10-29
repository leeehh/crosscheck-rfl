// SPDX-License-Identifier: GPL-2.0

//! Memory-balloon support.
//!
//! This module owns the unsafe boundary around the MM balloon page list,
//! movable-page callbacks, free-page hint blocks, shrinkers, OOM notifiers,
//! VM-stat collection, and page-reporting callbacks.  Device-specific policy
//! and virtio queue sequencing remain in the bus driver.

use crate::{
    alloc::Flags,
    bindings,
    error::{code::*, to_result, Result},
    ffi::{c_int, c_long, c_ulong, c_void},
    virtio::VirtQueue,
};
use core::{
    marker::PhantomData,
    mem,
    pin::Pin,
    ptr::NonNull,
};

/// One page allocated for the ordinary inflate/deflate balloon.
///
/// Ownership is released with `put_page` unless it is transferred to
/// [`BalloonPages`].
pub struct BalloonPage {
    raw: NonNull<c_void>,
}

// SAFETY: The page allocation has no CPU affinity and unique ownership moves
// with this value.
unsafe impl Send for BalloonPage {}

impl BalloonPage {
    /// Allocate one page using the kernel balloon allocator.
    pub fn alloc() -> Option<Self> {
        // SAFETY: The helper returns either NULL or one owned balloon-page reference.
        let raw = unsafe { bindings::balloon_page_alloc() };
        NonNull::new(raw).map(|raw| Self { raw })
    }

    /// Linux PFN for this page.
    pub fn pfn(&self) -> c_ulong {
        // SAFETY: `raw` is a live owned page.
        unsafe { bindings::balloon_page_pfn(self.raw.as_ptr()) }
    }

    /// Adjust this page's zone managed-page count.
    pub fn adjust_managed(&self, delta: isize) {
        // SAFETY: `raw` is a live page and the caller applies the same balanced
        // accounting used by the C balloon core.
        unsafe {
            bindings::balloon_page_adjust_managed(
                self.raw.as_ptr(),
                delta as c_long,
            )
        };
    }
}

impl Drop for BalloonPage {
    fn drop(&mut self) {
        // SAFETY: This value owns exactly one page reference.
        unsafe { bindings::balloon_page_put(self.raw.as_ptr()) };
    }
}

/// Driver callback used when compaction migrates an isolated balloon page.
pub trait MigrationOps: Send + Sync {
    /// Tell the device to replace `migration.old_page()` with
    /// `migration.new_page()`.
    fn migrate_balloon_page(&self, migration: Migration<'_>) -> Result;
}

/// A not-yet-committed compaction migration.
pub struct Migration<'a> {
    pages: NonNull<c_void>,
    new_page: NonNull<c_void>,
    old_page: NonNull<c_void>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Migration<'a> {
    /// PFN of the replacement page.
    pub fn new_pfn(&self) -> c_ulong {
        // SAFETY: The MM migration callback keeps both pages live.
        unsafe { bindings::balloon_page_pfn(self.new_page.as_ptr()) }
    }

    /// PFN of the isolated page being replaced.
    pub fn old_pfn(&self) -> c_ulong {
        // SAFETY: The MM migration callback keeps both pages live.
        unsafe { bindings::balloon_page_pfn(self.old_page.as_ptr()) }
    }

    /// Insert the replacement page into the balloon list and transfer its
    /// balloon reference.  Dropping the returned guard finalizes the old page.
    pub fn prepare(self) -> PreparedMigration<'a> {
        // SAFETY: All three pointers originate from the active movable-page
        // callback for this exact balloon list.
        unsafe {
            bindings::balloon_migration_prepare(
                self.pages.as_ptr(),
                self.new_page.as_ptr(),
                self.old_page.as_ptr(),
            )
        };
        PreparedMigration {
            old_page: self.old_page,
            _lifetime: PhantomData,
        }
    }
}

/// Guard for a committed balloon-page migration.
pub struct PreparedMigration<'a> {
    old_page: NonNull<c_void>,
    _lifetime: PhantomData<&'a ()>,
}

impl Drop for PreparedMigration<'_> {
    fn drop(&mut self) {
        // SAFETY: `Migration::prepare` installed the new page and this guard
        // uniquely owns finalization of the old balloon reference.
        unsafe { bindings::balloon_migration_finish(self.old_page.as_ptr()) };
    }
}

/// A compaction-aware list of pages currently owned by the balloon.
pub struct BalloonPages<T: MigrationOps> {
    raw: NonNull<c_void>,
    _owner: PhantomData<T>,
}

// This wrapper's address is not exposed to C; only its separately allocated
// helper state is pinned by ownership.
impl<T: MigrationOps> Unpin for BalloonPages<T> {}

// SAFETY: The C balloon list supplies its own spin lock; callback access to T
// is constrained by `MigrationOps: Send + Sync`.
unsafe impl<T: MigrationOps> Send for BalloonPages<T> {}
// SAFETY: Same reasoning as for `Send`.
unsafe impl<T: MigrationOps> Sync for BalloonPages<T> {}

impl<T: MigrationOps> BalloonPages<T> {
    /// Allocate an empty balloon page list.
    pub fn new(deflate_on_oom: bool) -> Result<Self> {
        // SAFETY: The helper returns a fresh allocation or NULL.
        let raw = unsafe { bindings::balloon_pages_alloc(deflate_on_oom) };
        Ok(Self {
            raw: NonNull::new(raw).ok_or(ENOMEM)?,
            _owner: PhantomData,
        })
    }

    /// Install the pinned driver object used by compaction callbacks.
    ///
    /// The owner must outlive this page list. A driver satisfies that by
    /// embedding the list in the owner and draining callbacks before drop.
    pub fn set_migration_owner(&self, owner: Pin<&T>) {
        // SAFETY: The method contract pins and keeps `owner` alive until this
        // list is dropped; the callback signature exactly matches the helper.
        unsafe {
            bindings::balloon_pages_set_migration(
                self.raw.as_ptr(),
                core::ptr::from_ref(&*owner).cast_mut().cast(),
                Some(Self::migration_trampoline),
            )
        };
    }

    /// Transfer an allocated page into the compaction-aware balloon list.
    pub fn enqueue(&self, page: BalloonPage) {
        let raw_page = page.raw.as_ptr();
        mem::forget(page);
        // SAFETY: Ownership of the live page reference was forgotten above and
        // is transferred exactly once to this list.
        unsafe { bindings::balloon_page_enqueue(self.raw.as_ptr(), raw_page) };
    }

    /// Remove and return one page from the balloon list.
    pub fn dequeue(&self) -> Option<BalloonPage> {
        // SAFETY: The helper returns NULL or transfers one list-owned page reference.
        let raw = unsafe { bindings::balloon_page_dequeue(self.raw.as_ptr()) };
        NonNull::new(raw).map(|raw| BalloonPage { raw })
    }

    unsafe extern "C" fn migration_trampoline(
        context: *mut c_void,
        pages: *mut c_void,
        new_page: *mut c_void,
        old_page: *mut c_void,
    ) -> c_int {
        let Some(owner) = NonNull::new(context.cast::<T>()) else {
            return EINVAL.to_errno();
        };
        let (Some(pages), Some(new_page), Some(old_page)) = (
            NonNull::new(pages),
            NonNull::new(new_page),
            NonNull::new(old_page),
        ) else {
            return EINVAL.to_errno();
        };

        let migration = Migration {
            pages,
            new_page,
            old_page,
            _lifetime: PhantomData,
        };
        // SAFETY: `set_migration_owner` guarantees a pinned live owner until
        // all callbacks have quiesced.
        match unsafe { owner.as_ref() }.migrate_balloon_page(migration) {
            Ok(()) => 0,
            Err(error) => error.to_errno(),
        }
    }
}

impl<T: MigrationOps> Drop for BalloonPages<T> {
    fn drop(&mut self) {
        // SAFETY: This value uniquely owns the helper allocation. The helper
        // drains any residual pages defensively.
        unsafe { bindings::balloon_pages_free(self.raw.as_ptr()) };
    }
}

/// One high-order block allocated for the free-page-hint protocol.
pub struct FreePageBlock {
    page: NonNull<c_void>,
}

// SAFETY: The block is uniquely owned and has no CPU affinity.
unsafe impl Send for FreePageBlock {}

impl FreePageBlock {
    /// Allocate a high-order hint block with the kernel's no-retry flags.
    #[inline]
    pub fn alloc() -> Option<Self> {
        // SAFETY: Returns NULL or an owned high-order page allocation.
        let page = unsafe { bindings::balloon_hint_block_alloc() };
        NonNull::new(page).map(|page| Self { page })
    }

    /// Kernel virtual address covering the entire contiguous block.
    #[inline]
    pub fn address(&self) -> *mut c_void {
        // SAFETY: `page` owns a low-memory high-order allocation.
        unsafe { bindings::balloon_hint_block_address(self.page.as_ptr()) }
    }

    /// Size of this block in bytes.
    #[inline]
    pub fn bytes(&self) -> usize {
        // SAFETY: Constant value query.
        unsafe { bindings::balloon_hint_block_bytes() as usize }
    }
}

impl Drop for FreePageBlock {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: This value uniquely owns the high-order allocation.
        unsafe { bindings::balloon_hint_block_free(self.page.as_ptr()) };
    }
}

/// Storage for free-page-hint blocks that may be reclaimed before the device
/// consumes their read-only descriptors, as explicitly permitted by the
/// virtio-balloon protocol.
pub struct FreePagePool {
    raw: NonNull<c_void>,
}

// SAFETY: The helper serializes its intrusive list with a spin lock.
unsafe impl Send for FreePagePool {}
// SAFETY: Same reasoning as for `Send`.
unsafe impl Sync for FreePagePool {}

impl FreePagePool {
    /// Allocate an empty pool.
    #[inline]
    pub fn new() -> Result<Self> {
        // SAFETY: Returns a fresh helper allocation or NULL.
        let raw = unsafe { bindings::balloon_free_pool_alloc() };
        Ok(Self {
            raw: NonNull::new(raw).ok_or(ENOMEM)?,
        })
    }

    /// Transfer a submitted block into the reclaimable pool.
    #[inline]
    pub fn store(&self, block: FreePageBlock) {
        let page = block.page.as_ptr();
        mem::forget(block);
        // SAFETY: Ownership is transferred exactly once into the pool list.
        unsafe { bindings::balloon_free_pool_store(self.raw.as_ptr(), page) };
    }

    /// Return up to `blocks` allocations to the MM.
    #[inline]
    pub fn return_blocks(&self, blocks: usize) -> usize {
        // SAFETY: The helper serializes the pool and returns the exact number freed.
        unsafe {
            bindings::balloon_free_pool_return(self.raw.as_ptr(), blocks as c_ulong)
                as usize
        }
    }

    /// Number of high-order blocks currently retained.
    #[inline]
    pub fn block_count(&self) -> usize {
        // SAFETY: Synchronized snapshot.
        unsafe { bindings::balloon_free_pool_count(self.raw.as_ptr()) as usize }
    }

    /// Number of base pages in one hint block.
    #[inline]
    pub fn pages_per_block() -> usize {
        // SAFETY: Constant value query.
        unsafe { bindings::balloon_hint_block_pages() as usize }
    }
}

impl Drop for FreePagePool {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: This value uniquely owns the helper pool, which drains all blocks.
        unsafe { bindings::balloon_free_pool_free(self.raw.as_ptr()) };
    }
}

/// Submit one high-order free-page block on the hint queue.
///
/// The descriptor is read-only from the host's perspective. The protocol
/// explicitly lets the guest reclaim/reuse the backing allocation before
/// completion; [`FreePagePool`] models that exception to ordinary virtqueue
/// buffer-lifetime rules.
#[inline]
pub fn submit_free_page_hint(
    queue: &VirtQueue,
    block: &FreePageBlock,
    flags: Flags,
) -> Result {
    queue.add_inbuf(
        block.address(),
        block.bytes().try_into().map_err(|_| EOVERFLOW)?,
        block.address(),
        flags,
    )
}

/// Submit one high-order free-page block and notify the host.
///
/// This is the transaction-level form of [`submit_free_page_hint`]. Keeping
/// descriptor publication and notification in one safe abstraction also
/// preserves their shared queue identity for protocol checkers.
#[inline]
pub fn submit_free_page_hint_and_kick(
    queue: &VirtQueue,
    block: &FreePageBlock,
    flags: Flags,
) -> Result {
    queue.add_inbuf(
        block.address(),
        block.bytes().try_into().map_err(|_| EOVERFLOW)?,
        block.address(),
        flags,
    )?;
    queue.kick();
    Ok(())
}

/// One host-endian VM statistic collected from the MM.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct StatValue {
    /// Virtio-balloon statistic tag.
    pub tag: u16,
    /// Statistic value.
    pub value: u64,
}

impl StatValue {
    /// Zero value suitable for an output array.
    #[inline]
    pub const fn zero() -> Self {
        Self { tag: 0, value: 0 }
    }
}

/// Fill `values` with the current VM and memory-information snapshot.
#[inline]
pub fn collect_stats(values: &mut [StatValue]) -> usize {
    // SAFETY: `values` is writable for `len` naturally aligned C-layout entries.
    unsafe {
        bindings::balloon_collect_stats(
            values.as_mut_ptr().cast(),
            values.len(),
        )
    }
}

/// Whether page initialization/poisoning makes free-page reporting safe.
#[inline]
pub fn can_report_free_pages() -> bool {
    // SAFETY: Read-only kernel policy query.
    unsafe { bindings::balloon_can_report_free_pages() }
}

/// Poison value advertised to a host when PAGE_POISON is negotiated.
#[inline]
pub fn page_poison_value() -> u32 {
    // SAFETY: Read-only kernel policy query.
    unsafe { bindings::balloon_page_poison_value() }
}

/// Callbacks for a registered shrinker.
pub trait ShrinkOps: Send + Sync {
    /// Number of reclaimable base pages.
    fn count_reclaimable(&self) -> usize;
    /// Reclaim up to `pages` base pages and return the actual count.
    fn scan_reclaimable(&self, pages: usize) -> usize;
}

/// Registered kernel shrinker tied to a pinned owner.
pub struct Shrinker<T: ShrinkOps> {
    raw: NonNull<c_void>,
    _owner: PhantomData<T>,
}

// Moving the Rust handle does not move the separately allocated registration.
impl<T: ShrinkOps> Unpin for Shrinker<T> {}

// SAFETY: Kernel shrinker registration serializes callback lifetime; T is
// explicitly Send + Sync.
unsafe impl<T: ShrinkOps> Send for Shrinker<T> {}
// SAFETY: Same reasoning as for `Send`.
unsafe impl<T: ShrinkOps> Sync for Shrinker<T> {}

impl<T: ShrinkOps> Shrinker<T> {
    /// Register a shrinker.
    pub fn register(owner: Pin<&T>) -> Result<Self> {
        // SAFETY: The caller keeps the pinned owner alive until this registration
        // is dropped; trampolines have the exact helper signatures.
        let raw = unsafe {
            bindings::balloon_shrinker_register(
                core::ptr::from_ref(&*owner).cast_mut().cast(),
                Some(Self::count_trampoline),
                Some(Self::scan_trampoline),
            )
        };
        Ok(Self {
            raw: NonNull::new(raw).ok_or(ENOMEM)?,
            _owner: PhantomData,
        })
    }

    unsafe extern "C" fn count_trampoline(context: *mut c_void) -> c_ulong {
        // SAFETY: Registration pins and keeps the owner live.
        unsafe { &*context.cast::<T>() }.count_reclaimable() as c_ulong
    }

    unsafe extern "C" fn scan_trampoline(
        context: *mut c_void,
        pages: c_ulong,
    ) -> c_ulong {
        // SAFETY: Registration pins and keeps the owner live.
        unsafe { &*context.cast::<T>() }.scan_reclaimable(pages as usize) as c_ulong
    }
}

impl<T: ShrinkOps> Drop for Shrinker<T> {
    fn drop(&mut self) {
        // SAFETY: Unregistration synchronizes callbacks before freeing state.
        unsafe { bindings::balloon_shrinker_unregister(self.raw.as_ptr()) };
    }
}

/// Callback for a registered OOM notifier.
pub trait OomOps: Send + Sync {
    /// Deflate and return the number of base pages released.
    fn reclaim_on_oom(&self) -> usize;
}

/// Registered OOM notifier tied to a pinned owner.
pub struct OomNotifier<T: OomOps> {
    raw: NonNull<c_void>,
    _owner: PhantomData<T>,
}

// Moving the Rust handle does not move the separately allocated registration.
impl<T: OomOps> Unpin for OomNotifier<T> {}

// SAFETY: Notifier unregistration synchronizes callback lifetime.
unsafe impl<T: OomOps> Send for OomNotifier<T> {}
// SAFETY: Same reasoning as for `Send`.
unsafe impl<T: OomOps> Sync for OomNotifier<T> {}

impl<T: OomOps> OomNotifier<T> {
    /// Register an OOM notifier at `priority`.
    pub fn register(owner: Pin<&T>, priority: i32) -> Result<Self> {
        // SAFETY: The pinned owner outlives registration.
        let raw = unsafe {
            bindings::balloon_oom_register(
                core::ptr::from_ref(&*owner).cast_mut().cast(),
                Some(Self::reclaim_trampoline),
                priority,
            )
        };
        Ok(Self {
            raw: NonNull::new(raw).ok_or(ENOMEM)?,
            _owner: PhantomData,
        })
    }

    unsafe extern "C" fn reclaim_trampoline(context: *mut c_void) -> c_ulong {
        // SAFETY: Registration pins and keeps the owner live.
        unsafe { &*context.cast::<T>() }.reclaim_on_oom() as c_ulong
    }
}

impl<T: OomOps> Drop for OomNotifier<T> {
    fn drop(&mut self) {
        // SAFETY: Unregistration synchronizes callbacks before freeing state.
        unsafe { bindings::balloon_oom_unregister(self.raw.as_ptr()) };
    }
}

/// A page-reporting scatterlist borrowed from the MM callback.
pub struct PageReportBatch<'a> {
    scatterlist: NonNull<c_void>,
    entries: u32,
    _lifetime: PhantomData<&'a ()>,
}

impl PageReportBatch<'_> {
    /// Submit the complete callback-owned scatterlist as one input chain.
    #[inline]
    pub fn submit(self, queue: &VirtQueue, token: *mut c_void, flags: Flags) -> Result {
        // SAFETY: The page-reporting core guarantees `scatterlist` contains
        // `entries` valid elements for the duration of its callback. Consuming
        // the batch prevents safe callers from submitting that borrowed list
        // more than once.
        to_result(unsafe {
            bindings::virtqueue_add_inbuf(
                queue.as_raw(),
                self.scatterlist.as_ptr().cast(),
                self.entries,
                token,
                flags.as_raw(),
            )
        })
    }
}

/// Callback for the kernel free-page reporting framework.
pub trait PageReportOps: Send + Sync {
    /// Report this batch synchronously.
    fn report_free_pages(&self, batch: PageReportBatch<'_>) -> Result;
}

/// Registered page-reporting device tied to a pinned owner.
pub struct PageReporter<T: PageReportOps> {
    raw: NonNull<c_void>,
    _owner: PhantomData<T>,
}

// Moving the Rust handle does not move the separately allocated registration.
impl<T: PageReportOps> Unpin for PageReporter<T> {}

// SAFETY: Page-reporting unregistration synchronizes callback lifetime.
unsafe impl<T: PageReportOps> Send for PageReporter<T> {}
// SAFETY: Same reasoning as for `Send`.
unsafe impl<T: PageReportOps> Sync for PageReporter<T> {}

impl<T: PageReportOps> PageReporter<T> {
    /// Register a page-reporting device with the requested minimum order.
    pub fn register(owner: Pin<&T>, order: u32) -> Result<Self> {
        // SAFETY: The pinned owner outlives registration.
        let raw = unsafe {
            bindings::balloon_page_reporter_register(
                core::ptr::from_ref(&*owner).cast_mut().cast(),
                Some(Self::report_trampoline),
                order,
            )
        };
        Ok(Self {
            raw: NonNull::new(raw).ok_or(ENOMEM)?,
            _owner: PhantomData,
        })
    }

    unsafe extern "C" fn report_trampoline(
        context: *mut c_void,
        scatterlist: *mut c_void,
        entries: u32,
    ) -> c_int {
        let Some(scatterlist) = NonNull::new(scatterlist) else {
            return EINVAL.to_errno();
        };
        let batch = PageReportBatch {
            scatterlist,
            entries,
            _lifetime: PhantomData,
        };
        // SAFETY: Registration pins and keeps the owner live.
        match unsafe { &*context.cast::<T>() }.report_free_pages(batch) {
            Ok(()) => 0,
            Err(error) => error.to_errno(),
        }
    }
}

impl<T: PageReportOps> Drop for PageReporter<T> {
    fn drop(&mut self) {
        // SAFETY: Unregistration synchronizes callbacks before freeing state.
        unsafe { bindings::balloon_page_reporter_unregister(self.raw.as_ptr()) };
    }
}
