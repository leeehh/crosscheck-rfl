// SPDX-License-Identifier: GPL-2.0

//! Generic CPU definitions.
//!
//! C header: [`include/linux/cpu.h`](srctree/include/linux/cpu.h)

use crate::{
    bindings,
    device::Device,
    error::{from_result, Error, Result},
    prelude::*,
    str::CStr,
    types::Opaque,
};
use core::{
    ffi::c_void,
    marker::PhantomData,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering},
};

const CPU_HOTPLUG_STATE_UNREGISTERED: i32 = -1;
const CPU_HOTPLUG_STATE_REGISTERING: i32 = -2;
const CPU_HOTPLUG_INSTANCE_DETACHED: u8 = 0;
const CPU_HOTPLUG_INSTANCE_ATTACHING: u8 = 1;
const CPU_HOTPLUG_INSTANCE_ATTACHED: u8 = 2;
const CPU_HOTPLUG_INSTANCE_DETACHING: u8 = 3;

/// A stable view of the online-CPU mask.
///
/// Implementations prove that CPU hotplug cannot change the mask while it is
/// being inspected. Drivers can therefore share affinity-building code between
/// ordinary process context and CPU-hotplug callbacks.
pub trait StableOnlineCpuSet {
    /// Number of CPUs in this stable online set.
    fn online_count(&self) -> u32;

    /// Find the first online CPU at or after `start`, wrapping once.
    fn next_online(&self, start: u32) -> Option<CpuId>;
}

fn stable_online_count() -> u32 {
    num_online_cpus()
}

fn stable_next_online(start: u32) -> Option<CpuId> {
    let possible = nr_cpu_ids();
    if possible == 0 {
        return None;
    }
    let start = start % possible;
    for offset in 0..possible {
        let cpu = if offset < possible - start {
            start + offset
        } else {
            offset - (possible - start)
        };
        // SAFETY: `cpu` is bounded by `nr_cpu_ids()`. Callers hold either the
        // CPU read lock or the CPU-hotplug callback serialization guarantee.
        let online = unsafe {
            bindings::cpumask_test_cpu(
                cpu as i32,
                core::ptr::addr_of!(bindings::__cpu_online_mask).cast_mut(),
            )
        };
        if online {
            // SAFETY: The range check above establishes the CpuId invariant.
            return Some(unsafe { CpuId::from_u32_unchecked(cpu) });
        }
    }
    None
}

/// Guard that keeps the online-CPU mask stable while queue affinity is rebuilt.
pub struct OnlineCpuReadGuard {
    _not_send: PhantomData<*mut ()>,
}

/// Lock CPU hotplug against online-mask and queue-affinity updates.
pub fn read_lock() -> OnlineCpuReadGuard {
    // SAFETY: The returned guard releases this exact read-side lock on drop.
    unsafe { bindings::cpus_read_lock_compat() };
    OnlineCpuReadGuard {
        _not_send: PhantomData,
    }
}

impl OnlineCpuReadGuard {
    /// Number of online CPUs in this stable read-side snapshot.
    pub fn online_count(&self) -> u32 {
        StableOnlineCpuSet::online_count(self)
    }

    /// Find the first online CPU at or after `start`, wrapping once at `nr_cpu_ids()`.
    pub fn next_online(&self, start: u32) -> Option<CpuId> {
        StableOnlineCpuSet::next_online(self, start)
    }
}

impl StableOnlineCpuSet for OnlineCpuReadGuard {
    fn online_count(&self) -> u32 {
        stable_online_count()
    }

    fn next_online(&self, start: u32) -> Option<CpuId> {
        stable_next_online(start)
    }
}

impl Drop for OnlineCpuReadGuard {
    fn drop(&mut self) {
        // SAFETY: Construction acquired exactly one CPU hotplug read lock in this task.
        unsafe { bindings::cpus_read_unlock_compat() };
    }
}

/// Stable online-CPU context passed only while a CPU-hotplug callback runs.
///
/// This type cannot be constructed by drivers. Its existence proves that the
/// CPU hotplug core is serializing changes to the online mask, so callbacks
/// must not acquire [`read_lock`] again.
pub struct HotplugCallbackContext {
    _private: (),
}

impl StableOnlineCpuSet for HotplugCallbackContext {
    fn online_count(&self) -> u32 {
        stable_online_count()
    }

    fn next_online(&self, start: u32) -> Option<CpuId> {
        stable_next_online(start)
    }
}

/// Driver callbacks installed into a CPU hotplug multi-state.
pub trait MultiStateCallbacks: Send + Sync + 'static {
    /// Whether this state has a startup callback.
    const HAS_STARTUP: bool;

    /// Whether this state has a teardown callback.
    const HAS_TEARDOWN: bool;

    /// Called when a CPU reaches this state.
    fn startup(&self, _cpu: CpuId, _online: &HotplugCallbackContext) -> Result {
        Ok(())
    }

    /// Called when a CPU leaves this state.
    fn teardown(&self, _cpu: CpuId, _online: &HotplugCallbackContext) -> Result {
        Ok(())
    }
}

/// Well-known placement of a CPU hotplug multi-state.
#[derive(Clone, Copy)]
pub enum MultiStateKind {
    /// Allocate a dynamic state in the AP-online range.
    DynamicOnline,

    /// The fixed teardown state reserved by the kernel for virtio-net.
    VirtioNetDead,
}

impl MultiStateKind {
    fn raw(self) -> bindings::cpuhp_state {
        match self {
            Self::DynamicOnline => bindings::cpuhp_state_CPUHP_AP_ONLINE_DYN,
            Self::VirtioNetDead => bindings::cpuhp_state_CPUHP_VIRT_NET_DEAD,
        }
    }
}

/// A typed global rendezvous point between a module-level multi-state and its
/// per-device instances.
pub struct CpuHotplugStateKey<T: MultiStateCallbacks> {
    state: AtomicI32,
    instances: AtomicU32,
    owner_alive: AtomicBool,
    _callbacks: PhantomData<fn() -> T>,
}

impl<T: MultiStateCallbacks> CpuHotplugStateKey<T> {
    /// Create an unregistered key suitable for a `static`.
    pub const fn new() -> Self {
        Self {
            state: AtomicI32::new(CPU_HOTPLUG_STATE_UNREGISTERED),
            instances: AtomicU32::new(0),
            owner_alive: AtomicBool::new(false),
            _callbacks: PhantomData,
        }
    }

    fn acquire_instance(&self) -> Result<bindings::cpuhp_state> {
        if !self.owner_alive.load(Ordering::Acquire) {
            return Err(ENODEV);
        }
        let state = self.state.load(Ordering::Acquire);
        if state < 0 {
            return Err(ENODEV);
        }
        if self
            .instances
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .is_err()
        {
            return Err(EOVERFLOW);
        }
        if !self.owner_alive.load(Ordering::Acquire) || self.state.load(Ordering::Acquire) != state
        {
            self.release_instance();
            return Err(ENODEV);
        }
        Ok(state)
    }

    fn release_instance(&self) {
        let previous = self.instances.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        if previous == 1 {
            self.remove_if_unused();
        }
    }

    fn remove_if_unused(&self) {
        if self.owner_alive.load(Ordering::Acquire) || self.instances.load(Ordering::Acquire) != 0 {
            return;
        }
        let state = self.state.load(Ordering::Acquire);
        if state < 0
            || self
                .state
                .compare_exchange(
                    state,
                    CPU_HOTPLUG_STATE_REGISTERING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return;
        }
        // SAFETY: The key owns this successful setup, its module owner has
        // gone, and the instance count proves every node is detached.
        unsafe { bindings::cpuhp_remove_multi_state(state) };
        self.state
            .store(CPU_HOTPLUG_STATE_UNREGISTERED, Ordering::Release);
    }
}

/// Module-owned registration of one CPU hotplug multi-state.
///
/// Drop reverses `cpuhp_setup_state_multi` after the last typed instance has
/// detached. Declaring a bus-driver registration before this field still gives
/// the clearest teardown order, but the key also safely defers removal when a
/// registration owner is dropped first.
pub struct CpuHotplugStateRegistration<T: MultiStateCallbacks> {
    key: &'static CpuHotplugStateKey<T>,
    state: bindings::cpuhp_state,
}

// SAFETY: The CPU hotplug core serializes state setup/removal. This value only
// owns a numeric state and a reference to an atomic key.
unsafe impl<T: MultiStateCallbacks> Send for CpuHotplugStateRegistration<T> {}
// SAFETY: Shared access exposes no mutating operation; removal requires Drop's
// exclusive ownership.
unsafe impl<T: MultiStateCallbacks> Sync for CpuHotplugStateRegistration<T> {}

impl<T: MultiStateCallbacks> CpuHotplugStateRegistration<T> {
    /// Register callbacks for a multi-instance CPU hotplug state.
    pub fn register(
        key: &'static CpuHotplugStateKey<T>,
        kind: MultiStateKind,
        name: &'static CStr,
    ) -> Result<Self> {
        if key
            .state
            .compare_exchange(
                CPU_HOTPLUG_STATE_UNREGISTERED,
                CPU_HOTPLUG_STATE_REGISTERING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(EBUSY);
        }

        let requested = kind.raw();
        // SAFETY: The name is static, the generic trampolines match the C
        // callback ABI, and the key prevents two live registrations of T.
        let startup = if T::HAS_STARTUP {
            CpuHotplugInstance::<T>::startup_callback as *const () as *mut c_void
        } else {
            core::ptr::null_mut()
        };
        let teardown = if T::HAS_TEARDOWN {
            CpuHotplugInstance::<T>::teardown_callback as *const () as *mut c_void
        } else {
            core::ptr::null_mut()
        };
        let result = unsafe {
            bindings::cpuhp_setup_state_multi(requested, name.as_char_ptr(), startup, teardown)
        };
        if result < 0 {
            key.state
                .store(CPU_HOTPLUG_STATE_UNREGISTERED, Ordering::Release);
            return Err(Error::from_errno(result));
        }

        let state = match kind {
            MultiStateKind::DynamicOnline => result,
            MultiStateKind::VirtioNetDead => requested,
        };
        debug_assert_eq!(key.instances.load(Ordering::Acquire), 0);
        key.owner_alive.store(true, Ordering::Release);
        key.state.store(state, Ordering::Release);
        Ok(Self { key, state })
    }
}

impl<T: MultiStateCallbacks> Drop for CpuHotplugStateRegistration<T> {
    fn drop(&mut self) {
        debug_assert_eq!(self.key.state.load(Ordering::Acquire), self.state);
        self.key.owner_alive.store(false, Ordering::Release);
        self.key.remove_if_unused();
    }
}

/// One pinned driver instance attached to a CPU hotplug multi-state.
#[pin_data(PinnedDrop)]
pub struct CpuHotplugInstance<T: MultiStateCallbacks> {
    data: T,
    key: &'static CpuHotplugStateKey<T>,
    #[pin]
    node: Opaque<bindings::hlist_node>,
    lifecycle: AtomicU8,
    attached_state: AtomicI32,
}

// SAFETY: The node is only mutated by the CPU hotplug core while registered;
// attach/detach use an atomic lifecycle and the callback payload is Send+Sync.
unsafe impl<T: MultiStateCallbacks> Send for CpuHotplugInstance<T> {}
// SAFETY: Callback access is shared and T is Sync. The C core serializes list
// mutation against callback traversal.
unsafe impl<T: MultiStateCallbacks> Sync for CpuHotplugInstance<T> {}

impl<T: MultiStateCallbacks> CpuHotplugInstance<T> {
    /// Create a detached, pinned instance.
    pub fn new(key: &'static CpuHotplugStateKey<T>, data: T) -> impl PinInit<Self> {
        pin_init!(Self {
            data,
            key,
            node <- Opaque::ffi_init(|slot: *mut bindings::hlist_node| {
                // SAFETY: `slot` points to the instance's uninitialized node.
                unsafe { slot.write(bindings::hlist_node::default()) };
            }),
            lifecycle: AtomicU8::new(CPU_HOTPLUG_INSTANCE_DETACHED),
            attached_state: AtomicI32::new(CPU_HOTPLUG_STATE_UNREGISTERED),
        })
    }

    /// Attach without replaying startup callbacks for CPUs already online.
    pub fn attach(self: Pin<&Self>) -> Result {
        match self.lifecycle.compare_exchange(
            CPU_HOTPLUG_INSTANCE_DETACHED,
            CPU_HOTPLUG_INSTANCE_ATTACHING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(CPU_HOTPLUG_INSTANCE_ATTACHED) => return Ok(()),
            Err(_) => return Err(EBUSY),
        }

        let state = match self.key.acquire_instance() {
            Ok(state) => state,
            Err(error) => {
                self.lifecycle
                    .store(CPU_HOTPLUG_INSTANCE_DETACHED, Ordering::Release);
                return Err(error);
            }
        };
        // SAFETY: `self` is pinned, so the zeroed hlist node stays at this
        // address until detach. The state key has the matching callback type.
        let result = unsafe { bindings::cpuhp_state_add_instance_nocalls(state, self.node.get()) };
        if result < 0 {
            self.key.release_instance();
            self.lifecycle
                .store(CPU_HOTPLUG_INSTANCE_DETACHED, Ordering::Release);
            return Err(Error::from_errno(result));
        }
        self.attached_state.store(state, Ordering::Release);
        self.lifecycle
            .store(CPU_HOTPLUG_INSTANCE_ATTACHED, Ordering::Release);
        Ok(())
    }

    /// Detach without replaying teardown callbacks for online CPUs.
    pub fn detach(self: Pin<&Self>) -> Result {
        match self.lifecycle.compare_exchange(
            CPU_HOTPLUG_INSTANCE_ATTACHED,
            CPU_HOTPLUG_INSTANCE_DETACHING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(CPU_HOTPLUG_INSTANCE_DETACHED) => return Ok(()),
            Err(_) => return Err(EBUSY),
        }

        let state = self.attached_state.load(Ordering::Acquire);
        debug_assert!(state >= 0);
        if state < 0 {
            self.lifecycle
                .store(CPU_HOTPLUG_INSTANCE_ATTACHED, Ordering::Release);
            return Err(ENODEV);
        }
        // SAFETY: The successful attach of this pinned node is still live and
        // CPU hotplug synchronizes callback completion before returning.
        let result =
            unsafe { bindings::cpuhp_state_remove_instance_nocalls(state, self.node.get()) };
        if result < 0 {
            self.lifecycle
                .store(CPU_HOTPLUG_INSTANCE_ATTACHED, Ordering::Release);
            return Err(Error::from_errno(result));
        }
        self.attached_state
            .store(CPU_HOTPLUG_STATE_UNREGISTERED, Ordering::Release);
        self.lifecycle
            .store(CPU_HOTPLUG_INSTANCE_DETACHED, Ordering::Release);
        self.key.release_instance();
        Ok(())
    }

    unsafe extern "C" fn startup_callback(cpu: u32, node: *mut bindings::hlist_node) -> i32 {
        // SAFETY: The node was linked only by `attach` for this exact generic
        // instance type and remains pinned until the callback is quiesced.
        let this = unsafe {
            &*crate::container_of!(
                node.cast::<Opaque<bindings::hlist_node>>(),
                CpuHotplugInstance<T>,
                node
            )
        };
        from_result(|| {
            // SAFETY: CPU hotplug callbacks receive a valid logical CPU id.
            let cpu = unsafe { CpuId::from_u32_unchecked(cpu) };
            T::startup(&this.data, cpu, &HotplugCallbackContext { _private: () })?;
            Ok(0)
        })
    }

    unsafe extern "C" fn teardown_callback(cpu: u32, node: *mut bindings::hlist_node) -> i32 {
        // SAFETY: Same registration and pinning invariant as startup_callback.
        let this = unsafe {
            &*crate::container_of!(
                node.cast::<Opaque<bindings::hlist_node>>(),
                CpuHotplugInstance<T>,
                node
            )
        };
        from_result(|| {
            // SAFETY: CPU hotplug callbacks receive a valid logical CPU id.
            let cpu = unsafe { CpuId::from_u32_unchecked(cpu) };
            T::teardown(&this.data, cpu, &HotplugCallbackContext { _private: () })?;
            Ok(0)
        })
    }
}

#[pinned_drop]
impl<T: MultiStateCallbacks> PinnedDrop for CpuHotplugInstance<T> {
    fn drop(self: Pin<&mut Self>) {
        let _ = self.as_ref().detach();
    }
}

/// Returns the number of CPUs that are currently online.
///
/// This is a snapshot, matching C's `num_online_cpus()`. Callers that need to
/// react to subsequent CPU hotplug events must also register a hotplug state.
#[inline]
pub fn num_online_cpus() -> u32 {
    // SAFETY: The helper takes no arguments and reads the kernel-maintained
    // online CPU mask.
    unsafe { bindings::num_online_cpus() }
}

/// Returns the maximum number of possible CPUs in the current system configuration.
#[inline]
pub fn nr_cpu_ids() -> u32 {
    #[cfg(any(NR_CPUS_1, CONFIG_FORCE_NR_CPUS))]
    {
        bindings::NR_CPUS
    }

    #[cfg(not(any(NR_CPUS_1, CONFIG_FORCE_NR_CPUS)))]
    // SAFETY: `nr_cpu_ids` is a valid global provided by the kernel.
    unsafe {
        bindings::nr_cpu_ids
    }
}

/// The CPU ID.
///
/// Represents a CPU identifier as a wrapper around an [`u32`].
///
/// # Invariants
///
/// The CPU ID lies within the range `[0, nr_cpu_ids())`.
///
/// # Examples
///
/// ```
/// use kernel::cpu::CpuId;
///
/// let cpu = 0;
///
/// // SAFETY: 0 is always a valid CPU number.
/// let id = unsafe { CpuId::from_u32_unchecked(cpu) };
///
/// assert_eq!(id.as_u32(), cpu);
/// assert!(CpuId::from_i32(0).is_some());
/// assert!(CpuId::from_i32(-1).is_none());
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CpuId(u32);

impl CpuId {
    /// Creates a new [`CpuId`] from the given `id` without checking bounds.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `id` is a valid CPU ID (i.e., `0 <= id < nr_cpu_ids()`).
    #[inline]
    pub unsafe fn from_i32_unchecked(id: i32) -> Self {
        debug_assert!(id >= 0);
        debug_assert!((id as u32) < nr_cpu_ids());

        // INVARIANT: The function safety guarantees `id` is a valid CPU id.
        Self(id as u32)
    }

    /// Creates a new [`CpuId`] from the given `id`, checking that it is valid.
    pub fn from_i32(id: i32) -> Option<Self> {
        if id < 0 || id as u32 >= nr_cpu_ids() {
            None
        } else {
            // INVARIANT: `id` has just been checked as a valid CPU ID.
            Some(Self(id as u32))
        }
    }

    /// Creates a new [`CpuId`] from the given `id` without checking bounds.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `id` is a valid CPU ID (i.e., `0 <= id < nr_cpu_ids()`).
    #[inline]
    pub unsafe fn from_u32_unchecked(id: u32) -> Self {
        debug_assert!(id < nr_cpu_ids());

        // Ensure the `id` fits in an [`i32`] as it's also representable that way.
        debug_assert!(id <= i32::MAX as u32);

        // INVARIANT: The function safety guarantees `id` is a valid CPU id.
        Self(id)
    }

    /// Creates a new [`CpuId`] from the given `id`, checking that it is valid.
    pub fn from_u32(id: u32) -> Option<Self> {
        if id >= nr_cpu_ids() {
            None
        } else {
            // INVARIANT: `id` has just been checked as a valid CPU ID.
            Some(Self(id))
        }
    }

    /// Returns CPU number.
    #[inline]
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Returns the ID of the CPU the code is currently running on.
    ///
    /// The returned value is considered unstable because it may change
    /// unexpectedly due to preemption or CPU migration. It should only be
    /// used when the context ensures that the task remains on the same CPU
    /// or the users could use a stale (yet valid) CPU ID.
    #[inline]
    pub fn current() -> Self {
        // SAFETY: raw_smp_processor_id() always returns a valid CPU ID.
        unsafe { Self::from_u32_unchecked(bindings::raw_smp_processor_id()) }
    }
}

impl From<CpuId> for u32 {
    fn from(id: CpuId) -> Self {
        id.as_u32()
    }
}

impl From<CpuId> for i32 {
    fn from(id: CpuId) -> Self {
        id.as_u32() as i32
    }
}

/// Creates a new instance of CPU's device.
///
/// # Safety
///
/// Reference counting is not implemented for the CPU device in the C code. When a CPU is
/// hot-unplugged, the corresponding CPU device is unregistered, but its associated memory
/// is not freed.
///
/// Callers must ensure that the CPU device is not used after it has been unregistered.
/// This can be achieved, for example, by registering a CPU hotplug notifier and removing
/// any references to the CPU device within the notifier's callback.
pub unsafe fn from_cpu(cpu: CpuId) -> Result<&'static Device> {
    // SAFETY: It is safe to call `get_cpu_device()` for any CPU.
    let ptr = unsafe { bindings::get_cpu_device(u32::from(cpu)) };
    if ptr.is_null() {
        return Err(ENODEV);
    }

    // SAFETY: The pointer returned by `get_cpu_device()`, if not `NULL`, is a valid pointer to
    // a `struct device` and is never freed by the C code.
    Ok(unsafe { Device::from_raw(ptr) })
}
