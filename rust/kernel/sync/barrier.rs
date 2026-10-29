// SPDX-License-Identifier: GPL-2.0

//! Memory barriers.
//!
//! These primitives have the same semantics as their C counterparts: and the precise definitions
//! of semantics can be found at [`LKMM`].
//!
//! [`LKMM`]: srctree/tools/memory-model/

/// A compiler barrier.
///
/// A barrier that prevents compiler from reordering memory accesses across the barrier.
#[inline(always)]
pub(crate) fn barrier() {
    // By default, Rust inline asms are treated as being able to access any memory or flags, hence
    // it suffices as a compiler barrier.
    //
    // SAFETY: An empty asm block.
    unsafe { core::arch::asm!("") };
}

/// A full mandatory memory barrier.
///
/// Unlike [`smp_mb`], this barrier also orders accesses against devices and is
/// not elided on uniprocessor systems.
#[inline(always)]
pub fn mb() {
    // SAFETY: `mb()` is safe to call.
    unsafe { bindings::mb() };
}

/// A mandatory write-write memory barrier.
///
/// Unlike [`smp_wmb`], this barrier also orders writes against devices and is
/// not elided on uniprocessor systems.
#[inline(always)]
pub fn wmb() {
    // SAFETY: `wmb()` is safe to call.
    unsafe { bindings::wmb() };
}

/// A mandatory read-read memory barrier.
///
/// Unlike [`smp_rmb`], this barrier also orders reads against devices and is
/// not elided on uniprocessor systems.
#[inline(always)]
pub fn rmb() {
    // SAFETY: `rmb()` is safe to call.
    unsafe { bindings::rmb() };
}

/// Orders coherent DMA writes before subsequent CPU reads.
#[inline(always)]
pub fn dma_rmb() {
    // SAFETY: `dma_rmb()` is safe to call.
    unsafe { bindings::dma_rmb() };
}

/// Orders CPU writes before subsequent coherent DMA reads.
#[inline(always)]
pub fn dma_wmb() {
    // SAFETY: `dma_wmb()` is safe to call.
    unsafe { bindings::dma_wmb() };
}

/// A full memory barrier.
///
/// A barrier that prevents compiler and CPU from reordering memory accesses across the barrier.
#[inline(always)]
pub fn smp_mb() {
    if cfg!(CONFIG_SMP) {
        // SAFETY: `smp_mb()` is safe to call.
        unsafe { bindings::smp_mb() };
    } else {
        barrier();
    }
}

/// A write-write memory barrier.
///
/// A barrier that prevents compiler and CPU from reordering memory write accesses across the
/// barrier.
#[inline(always)]
pub fn smp_wmb() {
    if cfg!(CONFIG_SMP) {
        // SAFETY: `smp_wmb()` is safe to call.
        unsafe { bindings::smp_wmb() };
    } else {
        barrier();
    }
}

/// A read-read memory barrier.
///
/// A barrier that prevents compiler and CPU from reordering memory read accesses across the
/// barrier.
#[inline(always)]
pub fn smp_rmb() {
    if cfg!(CONFIG_SMP) {
        // SAFETY: `smp_rmb()` is safe to call.
        unsafe { bindings::smp_rmb() };
    } else {
        barrier();
    }
}
