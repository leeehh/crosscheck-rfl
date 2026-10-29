// SPDX-License-Identifier: GPL-2.0

//! Typed memory pools.
//!
//! C header: [`include/linux/mempool.h`](srctree/include/linux/mempool.h)

use crate::{alloc::Flags, bindings, error::Result, prelude::*, sync::Arc, transmute::FromBytes};
use core::{
    marker::PhantomData,
    mem::size_of,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

/// A reserve-backed pool of fixed-size, plain-data elements.
///
/// The pool is reference counted by every checked-out [`Element`], so the C
/// pool cannot be destroyed until all elements have been returned. The type
/// parameter also prevents returning storage to a pool with a different
/// element layout.
pub struct Mempool<T: FromBytes + Copy> {
    raw: NonNull<bindings::mempool>,
    _p: PhantomData<T>,
}

// SAFETY: The C mempool serializes its free list, and `T` is accessed only
// through the unique `Element` that owns one checked-out allocation.
unsafe impl<T: FromBytes + Copy + Send> Send for Mempool<T> {}
// SAFETY: Pool allocation and return are internally synchronized by mempool.
unsafe impl<T: FromBytes + Copy + Send> Sync for Mempool<T> {}

impl<T: FromBytes + Copy> Mempool<T> {
    /// Create a pool with `minimum` elements reserved on the default NUMA
    /// node.
    pub fn new(minimum: u32, flags: Flags) -> Result<Arc<Self>> {
        Self::new_node(minimum, flags, bindings::NUMA_NO_NODE)
    }

    /// Create a pool whose reserve allocations prefer `node`.
    pub fn new_node(minimum: u32, flags: Flags, node: i32) -> Result<Arc<Self>> {
        if minimum == 0 || size_of::<T>() == 0 {
            return Err(EINVAL);
        }
        let minimum = i32::try_from(minimum).map_err(|_| EOVERFLOW)?;
        // `mempool_kmalloc` interprets `pool_data` as the allocation size.
        let pool_data = size_of::<T>() as *mut core::ffi::c_void;
        // SAFETY: The callbacks are the matching kernel kmalloc/kfree pair;
        // `pool_data` encodes the nonzero size of `T` exactly as the C helper
        // `mempool_create_kmalloc_pool_node` does.
        let raw = unsafe {
            bindings::mempool_create_node_noprof(
                minimum,
                Some(bindings::mempool_kmalloc),
                Some(bindings::mempool_kfree),
                pool_data,
                flags.as_raw(),
                node,
            )
        };
        let raw = NonNull::new(raw).ok_or(ENOMEM)?;
        Arc::new(
            Self {
                raw,
                _p: PhantomData,
            },
            flags,
        )
        .map_err(|_| ENOMEM)
    }

    /// Check out one element, waiting according to `flags` if only the
    /// reserve can satisfy the allocation.
    pub fn allocate(self: &Arc<Self>, flags: Flags) -> Result<Element<T>> {
        // SAFETY: `raw` remains live through `self`; mempool returns exclusive
        // storage of exactly `size_of::<T>()` bytes or NULL.
        let raw = unsafe { bindings::mempool_alloc_noprof(self.raw.as_ptr(), flags.as_raw()) };
        let raw = NonNull::new(raw.cast::<T>()).ok_or(ENOMEM)?;
        // SAFETY: The allocation is suitably aligned and large enough for T.
        // Zeroing establishes a valid value because every bit pattern of a
        // `FromBytes` type is valid. `Copy` excludes destructors.
        unsafe { raw.as_ptr().write_bytes(0, 1) };
        Ok(Element {
            raw,
            pool: self.clone(),
        })
    }
}

impl<T: FromBytes + Copy> Drop for Mempool<T> {
    fn drop(&mut self) {
        // SAFETY: Every checked-out element holds an Arc to this pool, hence
        // the final Arc can be dropped only after all elements were returned.
        unsafe { bindings::mempool_destroy(self.raw.as_ptr()) };
    }
}

/// One exclusively checked-out element from a typed [`Mempool`].
pub struct Element<T: FromBytes + Copy> {
    raw: NonNull<T>,
    pool: Arc<Mempool<T>>,
}

// SAFETY: An Element uniquely owns its allocation and the pool is thread-safe.
unsafe impl<T: FromBytes + Copy + Send> Send for Element<T> {}

impl<T: FromBytes + Copy> Deref for Element<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Allocation initialized T and remains checked out while self
        // is live. Shared access follows the ordinary Rust borrow rules.
        unsafe { self.raw.as_ref() }
    }
}

impl<T: FromBytes + Copy> DerefMut for Element<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The Element is the unique owner and `&mut self` excludes all
        // other Rust references to the allocation.
        unsafe { self.raw.as_mut() }
    }
}

impl<T: FromBytes + Copy> Drop for Element<T> {
    fn drop(&mut self) {
        // SAFETY: `raw` came from this exact pool and has not been returned;
        // the retained Arc keeps the pool alive through the operation.
        unsafe { bindings::mempool_free(self.raw.as_ptr().cast(), self.pool.raw.as_ptr()) };
    }
}
