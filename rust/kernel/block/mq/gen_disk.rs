// SPDX-License-Identifier: GPL-2.0

//! Generic disk abstraction.
//!
//! C header: [`include/linux/blkdev.h`](srctree/include/linux/blkdev.h)
//! C header: [`include/linux/blk-mq.h`](srctree/include/linux/blk-mq.h)

use crate::{
    bindings,
    block::mq::{Operations, TagSet},
    error::{self, from_err_ptr, Result},
    fmt::{self, Write},
    prelude::*,
    static_lock_class,
    str::NullTerminatedFormatter,
    sync::Arc,
    types::{ForeignOwnable, ScopeGuard},
};

/// A builder for [`GenDisk`].
///
/// Use this struct to configure and add new [`GenDisk`] to the VFS.
pub struct GenDiskBuilder {
    rotational: bool,
    write_cache: bool,
    logical_block_size: u32,
    physical_block_size: u32,
    capacity_sectors: u64,
    max_segments: u32,
    max_segment_size: u32,
    max_hw_sectors: u32,
    virt_boundary_mask: u64,
    major: u32,
    first_minor: u32,
    minors: u32,
}

impl Default for GenDiskBuilder {
    fn default() -> Self {
        Self {
            rotational: false,
            write_cache: false,
            logical_block_size: bindings::PAGE_SIZE as u32,
            physical_block_size: bindings::PAGE_SIZE as u32,
            capacity_sectors: 0,
            max_segments: 0,
            max_segment_size: 0,
            max_hw_sectors: 0,
            virt_boundary_mask: !0u64, // sentinel: don't set (no boundary)
            major: 0,
            first_minor: 0,
            minors: 1, // single minor (no partitions) unless overridden
        }
    }
}

impl GenDiskBuilder {
    /// Create a new instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the rotational media attribute for the device to be built.
    pub fn rotational(mut self, rotational: bool) -> Self {
        self.rotational = rotational;
        self
    }

    /// Publish whether writes may complete in a volatile device cache.
    ///
    /// Drivers enabling this limit must implement the corresponding cache flush operation.
    pub fn write_cache(mut self, write_cache: bool) -> Self {
        self.write_cache = write_cache;
        self
    }

    /// Validate block size by verifying that it is between 512 and `PAGE_SIZE`,
    /// and that it is a power of two.
    pub fn validate_block_size(size: u32) -> Result {
        if !(512..=bindings::PAGE_SIZE as u32).contains(&size) || !size.is_power_of_two() {
            Err(error::code::EINVAL)
        } else {
            Ok(())
        }
    }

    /// Set the logical block size of the device to be built.
    ///
    /// This method will check that block size is a power of two and between 512
    /// and 4096. If not, an error is returned and the block size is not set.
    ///
    /// This is the smallest unit the storage device can address. It is
    /// typically 4096 bytes.
    pub fn logical_block_size(mut self, block_size: u32) -> Result<Self> {
        Self::validate_block_size(block_size)?;
        self.logical_block_size = block_size;
        Ok(self)
    }

    /// Set the physical block size of the device to be built.
    ///
    /// This method will check that block size is a power of two and between 512
    /// and 4096. If not, an error is returned and the block size is not set.
    ///
    /// This is the smallest unit a physical storage device can write
    /// atomically. It is usually the same as the logical block size but may be
    /// bigger. One example is SATA drives with 4096 byte physical block size
    /// that expose a 512 byte logical block size to the operating system.
    pub fn physical_block_size(mut self, block_size: u32) -> Result<Self> {
        Self::validate_block_size(block_size)?;
        self.physical_block_size = block_size;
        Ok(self)
    }

    /// Set the capacity of the device to be built, in sectors (512 bytes).
    pub fn capacity_sectors(mut self, capacity: u64) -> Self {
        self.capacity_sectors = capacity;
        self
    }

    /// Set the maximum number of segments (scatterlist entries) per request. Mirrors C
    /// `queue_limits.max_segments` (from `VIRTIO_BLK_F_SEG_MAX`). 0 ⇒ leave the default.
    pub fn max_segments(mut self, max_segments: u32) -> Self {
        self.max_segments = max_segments;
        self
    }

    /// Set the maximum size in bytes of a single segment. Mirrors `queue_limits.max_segment_size`
    /// (from `VIRTIO_BLK_F_SIZE_MAX`). 0 ⇒ leave the default.
    pub fn max_segment_size(mut self, max_segment_size: u32) -> Self {
        self.max_segment_size = max_segment_size;
        self
    }

    /// Set the maximum sectors per request (`queue_limits.max_hw_sectors`). 0 ⇒ leave the default.
    pub fn max_hw_sectors(mut self, max_hw_sectors: u32) -> Self {
        self.max_hw_sectors = max_hw_sectors;
        self
    }

    /// Set the virt boundary mask — segments are NOT merged across `mask+1`-aligned boundaries.
    /// virtio-blk sets this to `PAGE_SIZE-1` (DMA on individual pages). Default: no boundary.
    pub fn virt_boundary_mask(mut self, mask: u64) -> Self {
        self.virt_boundary_mask = mask;
        self
    }

    /// Set the block major number (from `register_blkdev`). Mirrors C `disk->major = major`.
    pub fn major(mut self, major: u32) -> Self {
        self.major = major;
        self
    }

    /// Set the first minor number. Mirrors C `disk->first_minor`.
    pub fn first_minor(mut self, first_minor: u32) -> Self {
        self.first_minor = first_minor;
        self
    }

    /// Set the number of minors (partitions + 1). Mirrors C `disk->minors`.
    pub fn minors(mut self, minors: u32) -> Self {
        self.minors = minors;
        self
    }

    /// Build a new `GenDisk` and add it to the VFS.
    pub fn build<T: Operations>(
        self,
        name: fmt::Arguments<'_>,
        tagset: Arc<TagSet<T>>,
        queue_data: T::QueueData,
    ) -> Result<GenDisk<T>> {
        let data = queue_data.into_foreign();
        let recover_data = ScopeGuard::new(|| {
            // SAFETY: T::QueueData was created by the call to `into_foreign()` above
            drop(unsafe { T::QueueData::from_foreign(data) });
        });

        // SAFETY: `bindings::queue_limits` contain only fields that are valid when zeroed.
        let mut lim: bindings::queue_limits = unsafe { core::mem::zeroed() };

        lim.logical_block_size = self.logical_block_size;
        lim.physical_block_size = self.physical_block_size;
        if self.rotational {
            lim.features |= bindings::BLK_FEAT_ROTATIONAL;
        }
        if self.write_cache {
            lim.features |= bindings::BLK_FEAT_WRITE_CACHE;
        }
        if self.max_segments != 0 {
            lim.max_segments = self.max_segments as u16;
        }
        if self.max_segment_size != 0 {
            lim.max_segment_size = self.max_segment_size;
        }
        if self.max_hw_sectors != 0 {
            lim.max_hw_sectors = self.max_hw_sectors;
        }
        if self.virt_boundary_mask != !0u64 {
            lim.virt_boundary_mask = self.virt_boundary_mask as usize;
        }

        // SAFETY: `tagset.raw_tag_set()` points to a valid and initialized tag set
        let gendisk = from_err_ptr(unsafe {
            bindings::__blk_mq_alloc_disk(
                tagset.raw_tag_set(),
                &mut lim,
                data,
                static_lock_class!().as_ptr(),
            )
        })?;

        const TABLE: bindings::block_device_operations = bindings::block_device_operations {
            submit_bio: None,
            open: None,
            release: None,
            ioctl: None,
            compat_ioctl: None,
            check_events: None,
            unlock_native_capacity: None,
            getgeo: None,
            set_read_only: None,
            swap_slot_free_notify: None,
            report_zones: None,
            devnode: None,
            alternative_gpt_sector: None,
            get_unique_id: None,
            // TODO: Set to THIS_MODULE. Waiting for const_refs_to_static feature to
            // be merged (unstable in rustc 1.78 which is staged for linux 6.10)
            // <https://github.com/rust-lang/rust/issues/119618>
            owner: core::ptr::null_mut(),
            pr_ops: core::ptr::null_mut(),
            free_disk: None,
            poll_bio: None,
        };

        // SAFETY: `gendisk` is a valid pointer as we initialized it above
        unsafe { (*gendisk).fops = &TABLE };

        let mut writer = NullTerminatedFormatter::new(
            // SAFETY: `gendisk` points to a valid and initialized instance. We
            // have exclusive access, since the disk is not added to the VFS
            // yet.
            unsafe { &mut (*gendisk).disk_name },
        )
        .ok_or(EINVAL)?;
        writer.write_fmt(name)?;

        // SAFETY: `gendisk` points to a valid and initialized instance of
        // `struct gendisk`. `set_capacity` takes a lock to synchronize this
        // operation, so we will not race.
        unsafe { bindings::set_capacity(gendisk, self.capacity_sectors) };

        // SAFETY: `gendisk` is a valid, exclusively-owned (not yet added) `struct gendisk`.
        unsafe {
            (*gendisk).major = self.major as i32;
            (*gendisk).first_minor = self.first_minor as i32;
            (*gendisk).minors = self.minors as i32;
        }

        crate::error::to_result(
            // SAFETY: `gendisk` points to a valid and initialized instance of
            // `struct gendisk`.
            unsafe {
                bindings::device_add_disk(core::ptr::null_mut(), gendisk, core::ptr::null_mut())
            },
        )?;

        recover_data.dismiss();

        // INVARIANT: `gendisk` was initialized above.
        // INVARIANT: `gendisk` was added to the VFS via `device_add_disk` above.
        // INVARIANT: `gendisk.queue.queue_data` is set to `data` in the call to
        // `__blk_mq_alloc_disk` above.
        Ok(GenDisk {
            _tagset: tagset,
            gendisk,
        })
    }
}

/// A generic block device.
///
/// # Invariants
///
///  - `gendisk` must always point to an initialized and valid `struct gendisk`.
///  - `gendisk` was added to the VFS through a call to
///    `bindings::device_add_disk`.
///  - `self.gendisk.queue.queuedata` is initialized by a call to `ForeignOwnable::into_foreign`.
pub struct GenDisk<T: Operations> {
    _tagset: Arc<TagSet<T>>,
    gendisk: *mut bindings::gendisk,
}

// SAFETY: `GenDisk` is an owned pointer to a `struct gendisk` (kernel object) + an `Arc<TagSet>`.
// The gendisk/queue are thread-safe (C core synchronizes). Sendable iff `T: Send`; shareable iff
// `T: Sync`.
unsafe impl<T: Operations + Send> Send for GenDisk<T> {}
unsafe impl<T: Operations + Sync> Sync for GenDisk<T> {}

impl<T: Operations> Drop for GenDisk<T> {
    fn drop(&mut self) {
        // SAFETY: By type invariant of `Self`, `self.gendisk` points to a valid
        // and initialized instance of `struct gendisk`, and, `queuedata` was
        // initialized with the result of a call to
        // `ForeignOwnable::into_foreign`.
        let queue_data = unsafe { (*(*self.gendisk).queue).queuedata };

        // SAFETY: By type invariant, `self.gendisk` points to a valid and
        // initialized instance of `struct gendisk`, and it was previously added
        // to the VFS.
        unsafe { bindings::del_gendisk(self.gendisk) };

        // SAFETY: `queue.queuedata` was created by `GenDiskBuilder::build` with
        // a call to `ForeignOwnable::into_foreign` to create `queuedata`.
        // `ForeignOwnable::from_foreign` is only called here.
        drop(unsafe { T::QueueData::from_foreign(queue_data) });
    }
}
