// SPDX-License-Identifier: GPL-2.0

//! Abstractions for the hwrng (hardware RNG) subsystem.
//!
//! C header: [`include/linux/hw_random.h`](srctree/include/linux/hw_random.h)
//!
//! A driver embeds an [`HwrngSlot`] (which OWNS the C `struct hwrng`) in its driver data and
//! implements the [`Hwrng`] trait. It then calls the SAFE [`HwrngSlot::register`] (typically from a
//! virtio `scan` callback) and [`HwrngSlot::unregister`] on remove — the `unsafe` C-boundary work
//! (trampolines, `priv` back-pointer, `hwrng_register`) lives entirely here, so the driver needs no
//! `unsafe`. The read/cleanup trampolines recover `&T` from the C struct's `priv` field
//! (`struct hwrng { ...; unsigned long priv; }`, hw_random.h) — mirroring C `virtio-rng`'s
//! `hwrng.priv = (unsigned long)vi`.

use crate::{
    bindings,
    error::{from_result, to_result, Result},
    str::{CStrExt, CString},
    types::Opaque,
};
use core::{
    ffi::{c_int, c_void},
    sync::atomic::{AtomicBool, Ordering},
};

/// A hardware RNG provider.
///
/// Implemented by the per-device driver-data type that embeds an [`HwrngSlot`]. The `read` callback
/// is invoked by the hwrng core in process context (e.g. a `/dev/hwrng` read); `cleanup` is invoked
/// on unregister. Both recover `&self` from the C struct's `priv` back-pointer, set by
/// [`HwrngSlot::register`].
pub trait Hwrng: Sized + Sync + 'static {
    /// Read up to `buf.len()` bytes of entropy into `buf`.
    ///
    /// `wait` is true when the caller is willing to block for more data. Returns the number of
    /// bytes written into `buf`.
    fn read(&self, buf: &mut [u8], wait: bool) -> Result<usize>;

    /// Cleanup callback (optional). Default is a no-op.
    fn cleanup(&self) {}
}

/// An owned `struct hwrng` slot, embedded in the driver data.
///
/// Owns the C `struct hwrng` and its `name` string. The `unsafe` FFI (trampoline install, `priv`
/// back-pointer, `hwrng_register`/`hwrng_unregister`) is confined here; the driver embeds this as a
/// field and drives it through the safe [`register`](Self::register)/[`unregister`](Self::unregister)
/// methods. On drop, unregisters if still registered (a backstop; the driver should unregister
/// explicitly in its remove path so it happens before the rest of the driver data is torn down).
pub struct HwrngSlot {
    hwrng: Opaque<bindings::hwrng>,
    name: CString,
    registered: AtomicBool,
}

// SAFETY: `HwrngSlot` wraps a C `struct hwrng`. It is only mutated through `register`/`unregister`
// (which the hwrng core serializes w.r.t. its own state) and read through the trampolines under a
// live registration; the contained pointers are valid for the slot's lifetime. So it is safe to
// send/share across threads.
unsafe impl Send for HwrngSlot {}
unsafe impl Sync for HwrngSlot {}

impl HwrngSlot {
    /// Create a new slot with the given RNG `name` (which the C `struct hwrng.name` will point at;
    /// the [`CString`] is owned by the slot, so the pointer stays valid).
    pub fn new(name: CString) -> Self {
        Self {
            hwrng: Opaque::zeroed(),
            name,
            registered: AtomicBool::new(false),
        }
    }

    /// Register with the hwrng core. Mirrors C's `hwrng_register`. `data` is a back-pointer to the
    /// driver data the trampolines recover as `&T` (stored in the C struct's `priv`); it must be the
    /// object that embeds this slot.
    ///
    /// Safe to expose: the trampolines only deref `priv` while the registration is live, and the
    /// slot (embedded in `T`) unregisters on drop, so the `&T` back-pointer never outlives `T`.
    pub fn register<T: Hwrng>(&self, data: &T) -> Result {
        let slot = self.hwrng.get();
        // SAFETY: `slot` is a valid, zeroed `struct hwrng` owned by this slot; setting its fields is
        // safe. `read`/`cleanup` are the trampolines for `T`; `name` points at our owned `CString`;
        // `priv` holds the `&T` back-pointer the trampolines recover.
        unsafe {
            (*slot).read = Some(read_cb::<T>);
            (*slot).cleanup = Some(cleanup_cb::<T>);
            (*slot).name = self.name.as_char_ptr();
            (*slot).priv_ = data as *const T as usize as _;
        }
        // SAFETY: `slot` is initialized above and remains valid (owned by this slot) until
        // `unregister`/drop.
        to_result(unsafe { bindings::hwrng_register(slot) })?;
        self.registered.store(true, Ordering::Release);
        Ok(())
    }

    /// Unregister from the hwrng core (idempotent). Mirrors C's `hwrng_unregister`.
    pub fn unregister(&self) {
        if self.registered.swap(false, Ordering::AcqRel) {
            // SAFETY: `self.hwrng` was previously registered by `register`.
            unsafe { bindings::hwrng_unregister(self.hwrng.get()) };
        }
    }
}

impl Drop for HwrngSlot {
    fn drop(&mut self) {
        // Backstop: unregister if the driver did not. (The driver should unregister explicitly in
        // its remove path so it happens before earlier-declared fields are dropped.)
        self.unregister();
    }
}

/// Recover `*const T` from the C `struct hwrng`'s `priv` back-pointer.
#[inline]
fn recover<T: Hwrng>(rng: *mut bindings::hwrng) -> *const T {
    // SAFETY: `rng` is the struct our `register::<T>` installed, whose `priv` holds a `*const T`.
    (unsafe { (*rng).priv_ }) as *const T
}

unsafe extern "C" fn read_cb<T: Hwrng>(
    rng: *mut bindings::hwrng,
    data: *mut c_void,
    max: usize,
    wait: bool,
) -> c_int {
    let this = recover::<T>(rng);
    // SAFETY: `data` is a writable buffer of `max` bytes provided by the hwrng core.
    let buf = unsafe { core::slice::from_raw_parts_mut(data as *mut u8, max) };
    from_result(|| {
        // SAFETY: `this` is the live driver data (its slot is registered, so `T` outlives this call).
        let n = unsafe { (*this).read(buf, wait) }?;
        Ok(n as c_int)
    })
}

unsafe extern "C" fn cleanup_cb<T: Hwrng>(rng: *mut bindings::hwrng) {
    let this = recover::<T>(rng);
    // SAFETY: `this` is the live driver data; `cleanup` takes `&self`.
    unsafe { (*this).cleanup() };
}
