// SPDX-License-Identifier: GPL-2.0

//! Abstractions for NVMe transport drivers.
//!
//! The NVMe host transport interface is private to `drivers/nvme/host`: both
//! `struct nvme_ctrl` and `struct nvme_ctrl_ops` are declared in the private
//! `nvme.h`.  This module keeps that ABI and all raw callback dispatch inside
//! the kernel crate.  A transport owns a pinned [`Controller`] and gives the
//! NVMe core one reference to its [`Arc`]-allocated state.  The core returns
//! that reference from its final `free_ctrl` callback, which matches the
//! lifetime used by the C PCI transport.
//!
//! C header: [`drivers/nvme/host/nvme.h`](srctree/drivers/nvme/host/nvme.h).

use crate::{
    bindings, device, dma,
    error::{from_err_ptr, to_result, Result},
    ffi::{c_char, c_int, c_void},
    mempool,
    page::PAGE_SIZE,
    prelude::*,
    str::{BStr, CStr, Formatter},
    sync::{aref::ARef, Arc, ArcBorrow},
    time,
    transmute::FromBytes,
    types::{ForeignOwnable, Opaque},
    ThisModule,
};
use core::{
    marker::PhantomData,
    mem::{align_of, size_of},
    pin::Pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering},
};
use pin_init::{pin_data, pinned_drop, PinInit};

/// `NVME_F_METADATA_SUPPORTED` for a transport operations table.
pub const METADATA_SUPPORTED: u32 = bindings::NVME_F_METADATA_SUPPORTED;

/// NVMe-core controller quirks accepted by [`Controller::init`].
///
/// These names intentionally omit the C `NVME_QUIRK_` prefix while retaining
/// the exact private-core bit values. Transports can therefore construct PCI
/// ID metadata without duplicating `drivers/nvme/host/nvme.h` ABI constants.
pub mod quirks {
    use crate::bindings;

    /// Prefer the vendor stripe size for I/O alignment.
    pub const STRIPE_SIZE: usize = bindings::nvme_quirks_NVME_QUIRK_STRIPE_SIZE as usize;
    /// Restrict Identify CNS values for broken controllers.
    pub const IDENTIFY_CNS: usize = bindings::nvme_quirks_NVME_QUIRK_IDENTIFY_CNS as usize;
    /// Deallocated blocks deterministically read as zero.
    pub const DEALLOCATE_ZEROES: usize =
        bindings::nvme_quirks_NVME_QUIRK_DEALLOCATE_ZEROES as usize;
    /// Delay before the first controller-ready check.
    pub const DELAY_BEFORE_CHK_RDY: usize =
        bindings::nvme_quirks_NVME_QUIRK_DELAY_BEFORE_CHK_RDY as usize;
    /// Disable autonomous power-state transitions.
    pub const NO_APST: usize = bindings::nvme_quirks_NVME_QUIRK_NO_APST as usize;
    /// Exclude the deepest power state.
    pub const NO_DEEPEST_PS: usize = bindings::nvme_quirks_NVME_QUIRK_NO_DEEPEST_PS as usize;
    /// Limit the queue depth to one command.
    pub const QDEPTH_ONE: usize = bindings::nvme_quirks_NVME_QUIRK_QDEPTH_ONE as usize;
    /// Create submission queues at medium priority.
    pub const MEDIUM_PRIO_SQ: usize = bindings::nvme_quirks_NVME_QUIRK_MEDIUM_PRIO_SQ as usize;
    /// Ignore the controller-provided subsystem NQN.
    pub const IGNORE_DEV_SUBNQN: usize =
        bindings::nvme_quirks_NVME_QUIRK_IGNORE_DEV_SUBNQN as usize;
    /// Disable Write Zeroes.
    pub const DISABLE_WRITE_ZEROES: usize =
        bindings::nvme_quirks_NVME_QUIRK_DISABLE_WRITE_ZEROES as usize;
    /// Force the simple suspend and resume path.
    pub const SIMPLE_SUSPEND: usize = bindings::nvme_quirks_NVME_QUIRK_SIMPLE_SUSPEND as usize;
    /// Use one interrupt vector for all queues.
    pub const SINGLE_VECTOR: usize = bindings::nvme_quirks_NVME_QUIRK_SINGLE_VECTOR as usize;
    /// Use non-standard 128-byte submission entries.
    pub const SQES_128_BYTES: usize = bindings::nvme_quirks_NVME_QUIRK_128_BYTES_SQES as usize;
    /// Prevent request-tag overlap between queues.
    pub const SHARED_TAGS: usize = bindings::nvme_quirks_NVME_QUIRK_SHARED_TAGS as usize;
    /// Do not modify temperature thresholds.
    pub const NO_TEMP_THRESH_CHANGE: usize =
        bindings::nvme_quirks_NVME_QUIRK_NO_TEMP_THRESH_CHANGE as usize;
    /// Do not issue Identify Namespace Descriptor List.
    pub const NO_NS_DESC_LIST: usize = bindings::nvme_quirks_NVME_QUIRK_NO_NS_DESC_LIST as usize;
    /// Restrict DMA addresses to 48 bits.
    pub const DMA_ADDRESS_BITS_48: usize =
        bindings::nvme_quirks_NVME_QUIRK_DMA_ADDRESS_BITS_48 as usize;
    /// Do not encode a generation counter in command identifiers.
    pub const SKIP_CID_GEN: usize = bindings::nvme_quirks_NVME_QUIRK_SKIP_CID_GEN as usize;
    /// Ignore invalid namespace identifiers.
    pub const BOGUS_NID: usize = bindings::nvme_quirks_NVME_QUIRK_BOGUS_NID as usize;
    /// Disable non-composite temperature thresholds.
    pub const NO_SECONDARY_TEMP_THRESH: usize =
        bindings::nvme_quirks_NVME_QUIRK_NO_SECONDARY_TEMP_THRESH as usize;
    /// Prohibit the simple suspend and resume path.
    pub const FORCE_NO_SIMPLE_SUSPEND: usize =
        bindings::nvme_quirks_NVME_QUIRK_FORCE_NO_SIMPLE_SUSPEND as usize;
    /// MSI is broken while MSI-X remains usable.
    pub const BROKEN_MSI: usize = bindings::nvme_quirks_NVME_QUIRK_BROKEN_MSI as usize;
    /// Align DMA-pool elements to 512 bytes.
    pub const DMAPOOL_ALIGN_512: usize =
        bindings::nvme_quirks_NVME_QUIRK_DMAPOOL_ALIGN_512 as usize;
}

/// Current NVMe I/O request timeout, converted to kernel ticks.
#[inline]
pub fn io_timeout_jiffies<T: Operations>() -> time::Jiffies {
    // SAFETY: The NVMe core accessor reads its module parameter. The generic
    // transport type keeps this reference in the transport module when the
    // NVMe core itself is modular.
    unsafe { bindings::nvme_io_timeout_jiffies() }
}

/// Current NVMe admin request timeout, converted to kernel ticks.
#[inline]
pub fn admin_timeout_jiffies<T: Operations>() -> time::Jiffies {
    // SAFETY: See `io_timeout_jiffies`; this is the admin parameter accessor.
    unsafe { bindings::nvme_admin_timeout_jiffies() }
}

/// Drain the NVMe core's non-reset workqueue after transport unregistration.
///
/// This is the module-exit barrier corresponding to
/// `flush_workqueue(nvme_wq)`. It may sleep, and all transport registrations
/// must already have been removed so no new transport work can be enqueued.
#[inline(always)]
pub fn flush_workqueue<T: Operations>() {
    // SAFETY: Implementing an NVMe transport requires a live NVMe core
    // dependency, which owns this custom workqueue. The generic parameter
    // keeps the call in the transport module when NVMe core is modular.
    unsafe { bindings::__flush_workqueue(bindings::nvme_wq) };
}

/// State of an NVMe controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum State {
    /// The controller has been initialized but not started.
    New = bindings::nvme_ctrl_state_NVME_CTRL_NEW,
    /// The controller is live and accepts I/O.
    Live = bindings::nvme_ctrl_state_NVME_CTRL_LIVE,
    /// A reset is in progress.
    Resetting = bindings::nvme_ctrl_state_NVME_CTRL_RESETTING,
    /// A transport connection is being established.
    Connecting = bindings::nvme_ctrl_state_NVME_CTRL_CONNECTING,
    /// The controller is being deleted.
    Deleting = bindings::nvme_ctrl_state_NVME_CTRL_DELETING,
    /// The controller is being deleted without I/O.
    DeletingNoIo = bindings::nvme_ctrl_state_NVME_CTRL_DELETING_NOIO,
    /// The controller is permanently dead.
    Dead = bindings::nvme_ctrl_state_NVME_CTRL_DEAD,
}

impl State {
    #[inline]
    fn as_raw(self) -> bindings::nvme_ctrl_state {
        self as bindings::nvme_ctrl_state
    }

    fn from_raw(state: bindings::nvme_ctrl_state) -> Option<Self> {
        match state {
            bindings::nvme_ctrl_state_NVME_CTRL_NEW => Some(Self::New),
            bindings::nvme_ctrl_state_NVME_CTRL_LIVE => Some(Self::Live),
            bindings::nvme_ctrl_state_NVME_CTRL_RESETTING => Some(Self::Resetting),
            bindings::nvme_ctrl_state_NVME_CTRL_CONNECTING => Some(Self::Connecting),
            bindings::nvme_ctrl_state_NVME_CTRL_DELETING => Some(Self::Deleting),
            bindings::nvme_ctrl_state_NVME_CTRL_DELETING_NOIO => Some(Self::DeletingNoIo),
            bindings::nvme_ctrl_state_NVME_CTRL_DEAD => Some(Self::Dead),
            _ => None,
        }
    }
}

/// Operations implemented by an NVMe transport.
///
/// Callback methods may run concurrently and after the bus driver's remove
/// callback has started.  Consequently the implementation must be `Send +
/// Sync`, and its state must remain alive until [`Operations::free_ctrl`] has
/// returned.  [`Controller::init`] arranges that lifetime by transferring an
/// [`Arc`] reference to the NVMe core.
pub trait Operations: Send + Sync + Sized + 'static {
    /// Name reported by the NVMe core (for example, `"pcie"`).
    const NAME: &'static CStr;

    /// `NVME_F_*` transport flags.
    const FLAGS: u32;

    /// Whether this transport implements [`Operations::subsystem_reset`].
    const HAS_SUBSYSTEM_RESET: bool = false;

    /// Return the controller embedded in this transport state.
    ///
    /// This identity is checked by [`Controller::init`] before ownership is
    /// transferred, preventing callbacks from being attached to a different
    /// allocation.
    fn controller(&self) -> &Controller<Self>;

    /// Optional transport-specific controller sysfs attribute groups.
    ///
    /// The returned table must be static and NULL terminated.  Implementations
    /// normally obtain it from a subsystem abstraction rather than building a
    /// raw table in the driver.
    fn device_attribute_groups() -> *mut *const bindings::attribute_group {
        ptr::null_mut()
    }

    /// Optional lifetime-safe transport-specific controller attributes.
    ///
    /// The group must be owned by `self`. [`Controller::init`] installs its
    /// stable pointer table while transferring an [`Arc`] reference to the
    /// NVMe core, so the table and every callback target remain live until
    /// `free_ctrl` has quiesced all controller entry points.
    fn controller_attribute_group(&self) -> Option<&ControllerAttributeGroup<Self>> {
        None
    }

    /// Whether the controller attribute identified by `key` is currently
    /// visible.
    fn controller_attribute_visible(&self, _key: usize) -> bool {
        true
    }

    /// Format a controller attribute into the sysfs page buffer.
    fn show_controller_attribute(&self, _key: usize, _output: &mut Formatter<'_>) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Apply a controller attribute write while the transport parent remains
    /// bound.
    fn store_controller_attribute(
        &self,
        _parent: &device::Device<device::Bound>,
        _key: usize,
        _input: &BStr,
    ) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Read a 32-bit controller register.
    fn reg_read32(&self, offset: u32) -> Result<u32>;

    /// Write a 32-bit controller register.
    fn reg_write32(&self, offset: u32, value: u32) -> Result;

    /// Read a 64-bit controller register.
    fn reg_read64(&self, offset: u32) -> Result<u64>;

    /// Submit another asynchronous-event command.
    fn submit_async_event(&self);

    /// Execute the transport-specific controller reset work item.
    ///
    /// The NVMe reset workqueue invokes this with the core-owned [`Arc`]
    /// reference still live. Implementations must not call
    /// [`Controller::uninit`] from this callback because uninitialization
    /// synchronously drains this work item.
    fn reset_work(&self, _parent: &device::Device<device::Bound>) {}

    /// Reset the whole NVM subsystem.
    fn subsystem_reset(&self) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Write the transport address into `buffer` and return the byte count.
    fn get_address(&self, buffer: &mut [u8]) -> Result<usize>;

    /// Print transport-specific controller identification.
    fn print_device_info(&self);

    /// Whether peer-to-peer DMA is supported by this controller.
    fn supports_pci_p2pdma(&self) -> bool;

    /// Return the DMA virtual-boundary mask for an admin or I/O queue.
    fn get_virt_boundary(&self, is_admin: bool) -> usize;

    /// Final transport release hook.
    ///
    /// It runs from the NVMe core's `free_ctrl` callback immediately before
    /// the core-owned [`Arc`] reference is dropped.  Ordinary Rust fields can
    /// instead be released by the implementation's `Drop`.
    fn free_ctrl(&self) {}
}

/// Description of one transport-specific NVMe controller attribute.
///
/// `key` is transport-defined and is passed unchanged to the corresponding
/// [`Operations`] callbacks. Attribute names are static C strings because the
/// sysfs core retains their pointers for the lifetime of the controller.
#[derive(Clone, Copy)]
pub struct ControllerAttribute {
    name: &'static CStr,
    key: usize,
    mode: bindings::umode_t,
    readable: bool,
    writable: bool,
}

impl ControllerAttribute {
    /// Create a read-only (`0444`) controller attribute.
    pub const fn read_only(name: &'static CStr, key: usize) -> Self {
        Self {
            name,
            key,
            mode: 0o444,
            readable: true,
            writable: false,
        }
    }

    /// Create a read/write (`0644`) controller attribute.
    pub const fn read_write(name: &'static CStr, key: usize) -> Self {
        Self {
            name,
            key,
            mode: 0o644,
            readable: true,
            writable: true,
        }
    }
}

#[repr(C)]
struct ControllerAttributeSlot<T: Operations> {
    raw: bindings::device_attribute,
    key: usize,
    _p: PhantomData<fn() -> T>,
}

/// Owned, stable sysfs callback storage for an NVMe transport.
///
/// The attribute records, pointer arrays and group are allocated separately so
/// moving this Rust value before it is placed in the transport owner never
/// invalidates a C-visible address. No allocation is resized after its pointer
/// has been published into another record.
pub struct ControllerAttributeGroup<T: Operations> {
    groups: KVec<*const bindings::attribute_group>,
    group: KBox<bindings::attribute_group>,
    _attribute_ptrs: KVec<*mut bindings::attribute>,
    _slots: KVec<ControllerAttributeSlot<T>>,
}

// SAFETY: Construction freezes all C-visible allocations. The sysfs core only
// reads the tables, and mutable driver state is reached through the `T: Sync`
// callback interface rather than by mutating these records.
unsafe impl<T: Operations> Send for ControllerAttributeGroup<T> {}
// SAFETY: See the `Send` implementation. Callback records and pointer arrays
// are immutable after construction and remain owned by the live transport.
unsafe impl<T: Operations> Sync for ControllerAttributeGroup<T> {}

impl<T: Operations> ControllerAttributeGroup<T> {
    /// Allocate a controller attribute group and its NULL-terminated tables.
    pub fn new(attributes: &[ControllerAttribute]) -> Result<Self> {
        if attributes.is_empty() {
            return Err(EINVAL);
        }

        let mut slots = KVec::with_capacity(attributes.len(), GFP_KERNEL)?;
        for attribute in attributes {
            slots.push(
                ControllerAttributeSlot {
                    raw: bindings::device_attribute {
                        attr: bindings::attribute {
                            name: attribute.name.as_char_ptr(),
                            mode: attribute.mode,
                        },
                        show: attribute
                            .readable
                            .then_some(Self::show_callback as unsafe extern "C" fn(_, _, _) -> _),
                        store: attribute.writable.then_some(
                            Self::store_callback as unsafe extern "C" fn(_, _, _, _) -> _,
                        ),
                    },
                    key: attribute.key,
                    _p: PhantomData,
                },
                GFP_KERNEL,
            )?;
        }

        let pointer_count = attributes.len().checked_add(1).ok_or(EOVERFLOW)?;
        let mut attribute_ptrs = KVec::with_capacity(pointer_count, GFP_KERNEL)?;
        for index in 0..slots.len() {
            // SAFETY: `index` is in bounds and `slots` is never resized after
            // this loop starts, so every recorded field address is stable.
            let raw = unsafe { &raw mut (*slots.as_mut_ptr().add(index)).raw.attr };
            attribute_ptrs.push(raw, GFP_KERNEL)?;
        }
        attribute_ptrs.push(ptr::null_mut(), GFP_KERNEL)?;

        let group = KBox::new(
            bindings::attribute_group {
                name: ptr::null(),
                __bindgen_anon_1: bindings::attribute_group__bindgen_ty_1 {
                    is_visible: Some(Self::visibility_callback),
                },
                is_bin_visible: None,
                bin_size: None,
                __bindgen_anon_2: bindings::attribute_group__bindgen_ty_2 {
                    attrs: attribute_ptrs.as_ptr().cast_mut(),
                },
                bin_attrs: ptr::null(),
            },
            GFP_KERNEL,
        )?;

        let mut groups = KVec::with_capacity(3, GFP_KERNEL)?;
        groups.push(ptr::addr_of!(bindings::nvme_dev_attrs_group), GFP_KERNEL)?;
        groups.push(ptr::from_ref(&*group), GFP_KERNEL)?;
        groups.push(ptr::null(), GFP_KERNEL)?;

        Ok(Self {
            groups,
            group,
            _attribute_ptrs: attribute_ptrs,
            _slots: slots,
        })
    }

    fn as_groups_ptr(&self) -> *mut *const bindings::attribute_group {
        self.groups.as_ptr().cast_mut()
    }

    /// Re-evaluate this group's dynamic visibility on a registered controller.
    pub fn update(&self, controller: &Controller<T>) -> Result {
        let device = controller.device().ok_or(ENODEV)?;
        // SAFETY: `device` is the live controller class device and `group` is
        // the same stable record installed by `Controller::init`.
        to_result(unsafe {
            bindings::sysfs_update_group(
                ptr::addr_of_mut!((*device.as_raw()).kobj),
                ptr::from_ref(&*self.group),
            )
        })
    }

    unsafe fn owner_from_device<'a>(device: *mut bindings::device) -> Option<ArcBorrow<'a, T>> {
        if device.is_null() {
            return None;
        }
        // SAFETY: The NVMe core stores its live `nvme_ctrl` in the controller
        // class device's driver data before sysfs registration.
        let ctrl = unsafe { bindings::dev_get_drvdata(device) }.cast::<bindings::nvme_ctrl>();
        if ctrl.is_null() {
            return None;
        }
        // SAFETY: The device is registered only while this controller and its
        // transferred owner reference are live.
        unsafe { Controller::<T>::owner_from_raw(ctrl) }
    }

    unsafe extern "C" fn visibility_callback(
        kobject: *mut bindings::kobject,
        attribute: *mut bindings::attribute,
        _index: c_int,
    ) -> bindings::umode_t {
        if kobject.is_null() || attribute.is_null() {
            return 0;
        }
        // SAFETY: The sysfs core passes the embedded kobject of the controller
        // class device and one of the attributes installed by this group.
        let device = unsafe { crate::container_of!(kobject, bindings::device, kobj) };
        // SAFETY: `device` is the live callback device described above.
        let Some(owner) = (unsafe { Self::owner_from_device(device) }) else {
            return 0;
        };
        // SAFETY: `attribute` is the first field through both
        // `device_attribute` and our `repr(C)` slot.
        let slot = unsafe { &*attribute.cast::<ControllerAttributeSlot<T>>() };
        if T::controller_attribute_visible(&owner, slot.key) {
            slot.raw.attr.mode
        } else {
            0
        }
    }

    unsafe extern "C" fn show_callback(
        device: *mut bindings::device,
        attribute: *mut bindings::device_attribute,
        buffer: *mut c_char,
    ) -> isize {
        if attribute.is_null() || buffer.is_null() {
            return EINVAL.to_errno() as isize;
        }
        // SAFETY: The sysfs core passes a live callback device.
        let Some(owner) = (unsafe { Self::owner_from_device(device) }) else {
            return ENODEV.to_errno() as isize;
        };
        // SAFETY: `device_attribute` is the first field of our `repr(C)` slot.
        let slot = unsafe { &*attribute.cast::<ControllerAttributeSlot<T>>() };
        // SAFETY: Sysfs show callbacks receive a writable PAGE_SIZE buffer.
        let output = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), PAGE_SIZE) };
        let mut formatter = Formatter::new(output);
        match T::show_controller_attribute(&owner, slot.key, &mut formatter) {
            Ok(()) if formatter.bytes_written() <= PAGE_SIZE => formatter.bytes_written() as isize,
            Ok(()) => E2BIG.to_errno() as isize,
            Err(error) => error.to_errno() as isize,
        }
    }

    unsafe extern "C" fn store_callback(
        device: *mut bindings::device,
        attribute: *mut bindings::device_attribute,
        buffer: *const c_char,
        count: usize,
    ) -> isize {
        if attribute.is_null() || buffer.is_null() {
            return EINVAL.to_errno() as isize;
        }
        if count > isize::MAX as usize {
            return EOVERFLOW.to_errno() as isize;
        }
        // SAFETY: The sysfs core passes a live callback device.
        let Some(owner) = (unsafe { Self::owner_from_device(device) }) else {
            return ENODEV.to_errno() as isize;
        };
        // SAFETY: `device_attribute` is the first field of our `repr(C)` slot.
        let slot = unsafe { &*attribute.cast::<ControllerAttributeSlot<T>>() };
        // SAFETY: A transport attribute can be entered only while its group is
        // installed on the live controller device. Controller teardown removes
        // the group and drains active sysfs callbacks before the bus unbind can
        // release the transport parent, so it remains bound for this call.
        let parent = unsafe { bindings::nvme_ctrl_parent_device(owner.controller().as_raw()) };
        let Some(parent) = NonNull::new(parent) else {
            return ENODEV.to_errno() as isize;
        };
        // SAFETY: The sysfs callback lifetime argument above proves the Bound
        // context, and the reference does not escape this invocation.
        let parent = unsafe { device::Device::<device::Bound>::from_raw(parent.as_ptr()) };
        // SAFETY: The sysfs core guarantees a readable input buffer of `count`
        // bytes for the callback duration; NUL termination is not required.
        let input =
            BStr::from_bytes(unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), count) });
        match T::store_controller_attribute(&owner, parent, slot.key, input) {
            Ok(()) => count as isize,
            Err(error) => error.to_errno() as isize,
        }
    }
}

/// A pinned NVMe controller and its transport operations table.
///
/// The controller does not call `nvme_uninit_ctrl` from `Drop`: the NVMe core
/// itself may drop the final reference from `free_ctrl`, so teardown has to be
/// initiated explicitly by the transport.  Once [`Controller::uninit`] is
/// called, the object may be destroyed before that function returns and the
/// caller must not access it again unless it owns another [`Arc`] reference.
#[pin_data]
pub struct Controller<T: Operations> {
    #[pin]
    ctrl: Opaque<bindings::nvme_ctrl>,
    #[pin]
    ops: Opaque<bindings::nvme_ctrl_ops>,
    owner: AtomicPtr<c_void>,
    initialized: AtomicBool,
    initial_reference_held: AtomicBool,
    added_reference_held: AtomicBool,
    _p: PhantomData<T>,
}

// SAFETY: All access to the C controller after initialization is through the
// NVMe core's own synchronization or methods whose caller contracts provide
// serialization. `owner` and `initialized` are atomic.
unsafe impl<T: Operations> Send for Controller<T> {}
// SAFETY: See the `Send` implementation; transport callbacks only receive
// shared references to the `Sync` operations implementation.
unsafe impl<T: Operations> Sync for Controller<T> {}

impl<T: Operations> Controller<T> {
    /// Create an uninitialized, pinned controller.
    pub fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            ctrl <- Opaque::ffi_init(|slot: *mut bindings::nvme_ctrl| {
                // SAFETY: `slot` points to pinned uninitialized storage. The
                // NVMe core expects the controller to start zeroed except for
                // transport-owned work initialized before `nvme_init_ctrl`.
                unsafe {
                    slot.write(core::mem::zeroed());
                    bindings::nvme_ctrl_init_reset_work(
                        slot,
                        Some(Self::reset_work_callback),
                    );
                }
            }),
            ops <- Opaque::ffi_init(|slot: *mut bindings::nvme_ctrl_ops| {
                // SAFETY: The operations table is filled by `init` before the
                // NVMe core can observe it.
                unsafe { slot.write(core::mem::zeroed()) };
            }),
            owner: AtomicPtr::new(ptr::null_mut()),
            initialized: AtomicBool::new(false),
            initial_reference_held: AtomicBool::new(false),
            added_reference_held: AtomicBool::new(false),
            _p: PhantomData,
        })
    }

    /// Initialize the controller and transfer one `Arc<T>` reference to the
    /// NVMe core.
    ///
    /// `owner` must contain this exact controller.  On failure, ownership is
    /// returned (the supplied reference is dropped) and the controller remains
    /// uninitialized. On success, the core-owned `Arc` remains published until
    /// `free_ctrl`, which runs either when [`Controller::add`] fails or after
    /// [`Controller::uninit`] releases a successfully added controller.
    pub fn init(
        self: Pin<&Self>,
        owner: Arc<T>,
        parent: &device::Device<device::Core>,
        module: &'static ThisModule,
        quirks: usize,
    ) -> Result {
        if !ptr::eq(owner.controller(), self.get_ref()) {
            return Err(EINVAL);
        }

        let device_attribute_groups = owner
            .controller_attribute_group()
            .map(ControllerAttributeGroup::as_groups_ptr)
            .unwrap_or_else(T::device_attribute_groups);

        let owner_ptr = owner.into_foreign();
        if self
            .owner
            .compare_exchange(
                ptr::null_mut(),
                owner_ptr,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // SAFETY: `owner_ptr` was just produced by `Arc::into_foreign` and
            // was not published by the failed compare-exchange.
            drop(unsafe { Arc::<T>::from_foreign(owner_ptr) });
            return Err(EBUSY);
        }

        let ops = bindings::nvme_ctrl_ops {
            name: T::NAME.as_char_ptr(),
            module: module.0,
            flags: T::FLAGS,
            dev_attr_groups: device_attribute_groups,
            reg_read32: Some(Self::reg_read32_callback),
            reg_write32: Some(Self::reg_write32_callback),
            reg_read64: Some(Self::reg_read64_callback),
            free_ctrl: Some(Self::free_ctrl_callback),
            submit_async_event: Some(Self::submit_async_event_callback),
            subsystem_reset: if T::HAS_SUBSYSTEM_RESET {
                Some(Self::subsystem_reset_callback)
            } else {
                None
            },
            delete_ctrl: None,
            stop_ctrl: None,
            get_address: Some(Self::get_address_callback),
            print_device_info: Some(Self::print_device_info_callback),
            supports_pci_p2pdma: Some(Self::supports_pci_p2pdma_callback),
            get_virt_boundary: Some(Self::get_virt_boundary_callback),
        };

        // SAFETY: The operations table is pinned and exclusively initialized
        // here before publication to the C core.
        unsafe { self.ops.get().write(ops) };
        // SAFETY: `ctrl` has the C transport's required initial state,
        // including its reset work; `ops` is fully initialized and pinned;
        // `parent` is live; and the owner Arc remains published until the
        // final callback.
        let ret = unsafe {
            bindings::nvme_init_ctrl(
                self.ctrl.get(),
                parent.as_raw(),
                self.ops.get(),
                quirks as _,
            )
        };
        if let Err(error) = to_result(ret) {
            let ptr = self.owner.swap(ptr::null_mut(), Ordering::AcqRel);
            // SAFETY: Initialization failed before the NVMe core acquired
            // ownership; this is the single matching `from_foreign` call.
            drop(unsafe { Arc::<T>::from_foreign(ptr) });
            return Err(error);
        }

        self.initial_reference_held.store(true, Ordering::Release);
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// Whether `nvme_init_ctrl` completed successfully and final release has
    /// not started.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Publish the controller character device and release the initial
    /// `nvme_init_ctrl` device reference.
    ///
    /// `owner` keeps the transport and this embedded controller live if
    /// publication fails and releasing the initial reference invokes the
    /// final `free_ctrl` callback. On success, `nvme_add_ctrl` has acquired
    /// the reference later released by [`Self::uninit`].
    pub fn add(&self, owner: &Arc<T>) -> Result {
        if !ptr::eq(owner.controller(), self)
            || self
                .initial_reference_held
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(EINVAL);
        }

        let result = to_result(unsafe { bindings::nvme_add_ctrl(self.ctrl.get()) });
        if result.is_ok() {
            self.added_reference_held.store(true, Ordering::Release);
        }
        // SAFETY: `init` established exactly one initial reference and the
        // successful compare-exchange claimed its only release. `owner`
        // independently keeps `self` live if this invokes `free_ctrl`.
        unsafe { bindings::nvme_put_ctrl(self.ctrl.get()) };
        result
    }

    /// Finish controller identification after queues have been established.
    #[inline]
    pub fn init_finish(&self, was_suspended: bool) -> Result {
        to_result(unsafe { bindings::nvme_init_ctrl_finish(self.ctrl.get(), was_suspended) })
    }

    /// Start namespace discovery and asynchronous event handling.
    #[inline]
    pub fn start(&self) {
        unsafe { bindings::nvme_start_ctrl(self.ctrl.get()) };
    }

    /// Stop namespace discovery, keep-alive and asynchronous event handling.
    #[inline]
    pub fn stop(&self) {
        unsafe { bindings::nvme_stop_ctrl(self.ctrl.get()) };
    }

    /// Change the NVMe core state using its validated transition table.
    #[inline]
    pub fn change_state(&self, state: State) -> bool {
        unsafe { bindings::nvme_change_ctrl_state(self.ctrl.get(), state.as_raw()) }
    }

    /// Current controller state, or `None` if the C core contains an unknown
    /// value from a newer ABI.
    #[inline]
    pub fn state(&self) -> Option<State> {
        // SAFETY: `ctrl` is live while the transport owner is live; the helper
        // uses the NVMe core's READ_ONCE accessor.
        State::from_raw(unsafe { bindings::nvme_ctrl_state(self.ctrl.get()) })
    }

    /// Whether the controller has reached a state that can never return live.
    #[inline]
    pub fn state_is_terminal(&self) -> bool {
        // SAFETY: `ctrl` is live while the transport owner is live.
        unsafe { bindings::nvme_state_terminal(self.ctrl.get()) }
    }

    /// NVMe core class device used for controller logging and attributes.
    pub fn device(&self) -> Option<&device::Device> {
        // SAFETY: The helper reads the core-owned pointer. A non-NULL device
        // remains live for the initialized controller's lifetime.
        let raw = unsafe { bindings::nvme_ctrl_device(self.ctrl.get()) };
        (!raw.is_null()).then(|| {
            // SAFETY: Proven by the helper result and controller lifetime.
            unsafe { device::Device::from_raw(raw) }
        })
    }

    /// Copy the controller subsystem model string into `buffer`.
    ///
    /// The returned byte count excludes any trailing NUL or space padding.
    pub fn copy_model(&self, buffer: &mut [u8]) -> usize {
        // SAFETY: The controller owns its subsystem while live, and `buffer`
        // is writable for exactly the supplied capacity. The helper clamps
        // its copy and returns no more than that capacity.
        unsafe {
            bindings::nvme_ctrl_copy_model(
                self.ctrl.get(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        }
    }

    /// Copy the controller subsystem firmware revision into `buffer`.
    ///
    /// The returned byte count excludes any trailing NUL or space padding.
    pub fn copy_firmware_revision(&self, buffer: &mut [u8]) -> usize {
        // SAFETY: The same live-subsystem and bounded-output contract as
        // `copy_model` applies.
        unsafe {
            bindings::nvme_ctrl_copy_firmware_rev(
                self.ctrl.get(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        }
    }

    /// Controller quirk mask established during initialization.
    #[inline]
    pub fn quirks(&self) -> usize {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_quirks(self.ctrl.get()) as usize }
    }

    /// Cached NVMe CAP register value.
    #[inline]
    pub fn capabilities(&self) -> u64 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_cap(self.ctrl.get()) }
    }

    /// Update the cached NVMe CAP register during serialized reset setup.
    #[inline]
    pub fn set_capabilities(&self, value: u64) {
        // SAFETY: WRITE_ONCE preserves the C transport's reset-time access
        // semantics without exposing the private controller field.
        unsafe { bindings::nvme_ctrl_set_cap(self.ctrl.get(), value) };
    }

    /// Cached controller configuration register.
    #[inline]
    pub fn configuration(&self) -> u32 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_config(self.ctrl.get()) }
    }

    /// Number of queues currently constructed, including the admin queue.
    #[inline]
    pub fn queue_count(&self) -> u32 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_queue_count(self.ctrl.get()) }
    }

    /// Set the constructed queue count in a serialized queue rebuild path.
    #[inline]
    pub fn set_queue_count(&self, value: u32) {
        // SAFETY: The helper provides the same WRITE_ONCE update used by the
        // abstraction's serialized reset/queue lifecycle.
        unsafe { bindings::nvme_ctrl_set_queue_count(self.ctrl.get(), value) };
    }

    /// Zero-based maximum submission queue entry index.
    #[inline]
    pub fn submission_queue_size(&self) -> u16 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_sqsize(self.ctrl.get()) }
    }

    /// Publish the negotiated zero-based submission queue size.
    #[inline]
    pub fn set_submission_queue_size(&self, value: u16) {
        // SAFETY: Queue rebuild serialization is captured by the controller
        // lifecycle; the C helper performs a WRITE_ONCE update.
        unsafe { bindings::nvme_ctrl_set_sqsize(self.ctrl.get(), value) };
    }

    /// Set the NUMA node used by the NVMe core for queue allocations.
    #[inline]
    pub fn set_numa_node(&self, node: i32) {
        // SAFETY: This is configured by probe/reset before new allocations.
        unsafe { bindings::nvme_ctrl_set_numa_node(self.ctrl.get(), node) };
    }

    /// Stable controller instance number allocated by the core.
    #[inline]
    pub fn instance(&self) -> i32 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_instance(self.ctrl.get()) }
    }

    /// Set block limits owned by the NVMe core before queue publication.
    pub fn set_io_limits(
        &self,
        max_hw_sectors: u32,
        max_segments: u32,
        max_integrity_segments: u32,
    ) {
        // SAFETY: Helpers perform WRITE_ONCE updates. The transport invokes
        // this only in probe/reset while its queues are absent or quiesced.
        unsafe {
            bindings::nvme_ctrl_set_max_hw_sectors(self.ctrl.get(), max_hw_sectors);
            bindings::nvme_ctrl_set_max_segments(self.ctrl.get(), max_segments);
            bindings::nvme_ctrl_set_max_integrity_segments(self.ctrl.get(), max_integrity_segments);
        }
    }

    /// Update only the integrity-segment limit after controller identify.
    #[inline]
    pub fn set_max_integrity_segments(&self, value: u32) {
        // SAFETY: Reset path has quiesced queues before this WRITE_ONCE update.
        unsafe { bindings::nvme_ctrl_set_max_integrity_segments(self.ctrl.get(), value) };
    }

    /// Optional admin-command capability bits.
    #[inline]
    pub fn optional_admin_command_support(&self) -> u16 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_oacs(self.ctrl.get()) }
    }

    /// Highest supported power-state index.
    #[inline]
    pub fn power_state_count(&self) -> u8 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_npss(self.ctrl.get()) }
    }

    /// Update the cached non-operational power-state count.
    ///
    /// Transports clear this after a protocol-level suspend command is
    /// rejected so resume is forced through controller re-identification.
    #[inline]
    pub fn set_power_state_count(&self, value: u8) {
        // SAFETY: This is a value-only WRITE_ONCE update serialized by the
        // transport's suspend/reset lifecycle.
        unsafe { bindings::nvme_ctrl_set_npss(self.ctrl.get(), value) };
    }

    /// Host-memory-buffer preferred size in controller pages.
    #[inline]
    pub fn hmb_preferred_pages(&self) -> u32 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_hmpre(self.ctrl.get()) }
    }

    /// Host-memory-buffer minimum size in controller pages.
    #[inline]
    pub fn hmb_minimum_pages(&self) -> u32 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_hmmin(self.ctrl.get()) }
    }

    /// Minimum HMB descriptor entry size in controller pages.
    #[inline]
    pub fn hmb_minimum_descriptor_pages(&self) -> u32 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_hmminds(self.ctrl.get()) }
    }

    /// Maximum number of HMB descriptors, or zero when unrestricted.
    #[inline]
    pub fn hmb_maximum_descriptors(&self) -> u16 {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_hmmaxd(self.ctrl.get()) }
    }

    /// Whether the controller supports data SGLs for this transport.
    #[inline]
    pub fn supports_sgl(&self) -> bool {
        // SAFETY: As in nvme_ctrl_sgl_supported(), the Identify capability is
        // stable while requests are dispatched; reset quiesces those requests.
        let sgls = unsafe { (*self.ctrl.get()).sgls };
        sgls & (bindings::NVME_CTRL_SGLS_BYTE_ALIGNED
            | bindings::NVME_CTRL_SGLS_DWORD_ALIGNED) != 0
    }

    /// Whether the controller supports metadata SGLs.
    #[inline]
    pub fn supports_metadata_sgl(&self) -> bool {
        // Controller initialization installs T's operations table, so its
        // flags are the same flags tested by nvme_ctrl_meta_sgl_supported().
        if T::FLAGS & bindings::NVME_F_FABRICS != 0 {
            return true;
        }
        // SAFETY: The Identify capability is stable during queue dispatch, as
        // in the C helper. Reset changes it only while requests are quiesced.
        unsafe { (*self.ctrl.get()).sgls & bindings::NVME_CTRL_SGLS_MSDS != 0 }
    }

    /// Whether the core currently owns an admin request queue.
    #[inline]
    pub fn has_admin_queue(&self) -> bool {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_has_admin_queue(self.ctrl.get()) }
    }

    /// Whether the core currently owns an I/O tag set.
    #[inline]
    pub fn has_io_tag_set(&self) -> bool {
        // SAFETY: Value-only READ_ONCE helper on a live controller.
        unsafe { bindings::nvme_ctrl_has_io_tagset(self.ctrl.get()) }
    }

    /// Reserve one slot from the controller's bounded abort-command budget.
    #[inline]
    pub fn try_acquire_abort(&self) -> bool {
        // SAFETY: The helper atomically decrements and rolls back on failure.
        unsafe { bindings::nvme_ctrl_try_get_abort(self.ctrl.get()) }
    }

    /// Return one previously acquired abort-command slot.
    #[inline]
    pub fn release_abort(&self) {
        // SAFETY: Callers own one slot returned by `try_acquire_abort`.
        unsafe { bindings::nvme_ctrl_put_abort(self.ctrl.get()) };
    }

    /// Enable the hardware controller through the NVMe core.
    #[inline]
    pub fn enable(&self) -> Result {
        to_result(unsafe { bindings::nvme_enable_ctrl(self.ctrl.get()) })
    }

    /// Disable the hardware controller through the NVMe core.
    #[inline]
    pub fn disable(&self, shutdown: bool) -> Result {
        to_result(unsafe { bindings::nvme_disable_ctrl(self.ctrl.get(), shutdown) })
    }

    /// Remove all namespaces owned by this controller.
    #[inline]
    pub fn remove_namespaces(&self) {
        unsafe { bindings::nvme_remove_namespaces(self.ctrl.get()) };
    }

    /// Quiesce all I/O queues.
    #[inline]
    pub fn quiesce_io_queues(&self) {
        unsafe { bindings::nvme_quiesce_io_queues(self.ctrl.get()) };
    }

    /// Resume all I/O queues.
    #[inline]
    pub fn unquiesce_io_queues(&self) {
        unsafe { bindings::nvme_unquiesce_io_queues(self.ctrl.get()) };
    }

    /// Quiesce the admin queue.
    #[inline]
    pub fn quiesce_admin_queue(&self) {
        unsafe { bindings::nvme_quiesce_admin_queue(self.ctrl.get()) };
    }

    /// Resume the admin queue.
    #[inline]
    pub fn unquiesce_admin_queue(&self) {
        unsafe { bindings::nvme_unquiesce_admin_queue(self.ctrl.get()) };
    }

    /// Synchronize all namespace and admin queues.
    #[inline]
    pub fn sync_queues(&self) {
        unsafe { bindings::nvme_sync_queues(self.ctrl.get()) };
    }

    /// Begin freezing all namespace queues from a non-owner context.
    #[inline]
    pub fn start_freeze(&self) {
        unsafe { bindings::nvme_start_freeze(self.ctrl.get()) };
    }

    /// Wait until every namespace queue is frozen.
    ///
    /// This may sleep.
    #[inline]
    pub fn wait_freeze(&self) {
        unsafe { bindings::nvme_wait_freeze(self.ctrl.get()) };
    }

    /// Wait up to `timeout` ticks for every namespace queue to freeze.
    ///
    /// Returns `true` when time remained after all queues froze. This may
    /// sleep.
    #[inline]
    pub fn wait_freeze_timeout(&self, timeout: time::Jiffies) -> bool {
        // SAFETY: The C API accepts the kernel's signed jiffy representation;
        // the cast matches the C transport's implicit conversion from the
        // unsigned timeout macro. It only traverses this controller's queues.
        unsafe { bindings::nvme_wait_freeze_timeout(self.ctrl.get(), timeout as _) > 0 }
    }

    /// Unfreeze all namespace queues previously frozen by this controller.
    #[inline]
    pub fn unfreeze(&self) {
        unsafe { bindings::nvme_unfreeze(self.ctrl.get()) };
    }

    /// Complete and drain every in-flight I/O request in the controller tag
    /// set as cancelled.
    #[inline]
    pub fn cancel_io_tag_set(&self) {
        unsafe { bindings::nvme_cancel_tagset(self.ctrl.get()) };
    }

    /// Complete and drain every in-flight admin request as cancelled.
    #[inline]
    pub fn cancel_admin_tag_set(&self) {
        unsafe { bindings::nvme_cancel_admin_tagset(self.ctrl.get()) };
    }

    /// Mark all namespaces dead after an unrecoverable transport failure.
    #[inline]
    pub fn mark_namespaces_dead(&self) {
        unsafe { bindings::nvme_mark_namespaces_dead(self.ctrl.get()) };
    }

    /// Wait for, or enter, the controller's resetting state.
    ///
    /// Returns `false` when the controller reached a terminal state instead.
    /// This may sleep.
    #[inline]
    pub fn wait_reset(&self) -> bool {
        unsafe { bindings::nvme_wait_reset(self.ctrl.get()) }
    }

    /// Schedule an asynchronous controller reset.
    #[inline]
    pub fn reset(&self) -> Result {
        to_result(unsafe { bindings::nvme_reset_ctrl(self.ctrl.get()) })
    }

    /// Queue reset work after the caller has already entered `Resetting`.
    #[inline]
    pub fn try_schedule_reset(&self) -> Result {
        to_result(unsafe { bindings::nvme_try_sched_reset(self.ctrl.get()) })
    }

    /// Wait until this controller's transport reset work is idle.
    ///
    /// This may sleep and must not be called by the reset work callback.
    #[inline]
    pub fn flush_reset_work(&self) -> bool {
        // SAFETY: The embedded work was initialized by `init`; the controller
        // allocation remains pinned and live for this call.
        unsafe { bindings::nvme_ctrl_flush_reset_work(self.ctrl.get()) }
    }

    /// Wait until the NVMe core's namespace scan work is idle.
    ///
    /// This may sleep and must not be called by the scan work item itself.
    #[inline]
    pub fn flush_scan_work(&self) -> bool {
        if !self.is_initialized() {
            return false;
        }
        // SAFETY: `nvme_init_ctrl` initializes this embedded work before a
        // successful `Controller::init` returns.
        unsafe { bindings::nvme_ctrl_flush_scan_work(self.ctrl.get()) }
    }

    /// Reset the controller synchronously.
    #[inline]
    pub fn reset_sync(&self) -> Result {
        to_result(unsafe { bindings::nvme_reset_ctrl_sync(self.ctrl.get()) })
    }

    /// Schedule controller deletion.
    #[inline]
    pub fn delete(&self) -> Result {
        to_result(unsafe { bindings::nvme_delete_ctrl(self.ctrl.get()) })
    }

    /// Queue a namespace scan.
    #[inline]
    pub fn queue_scan(&self) {
        unsafe { bindings::nvme_queue_scan(self.ctrl.get()) };
    }

    /// Ask the NVMe core to negotiate a number of I/O queues.
    pub fn negotiate_queue_count(&self, requested: u32) -> Result<u32> {
        let mut count = c_int::try_from(requested).map_err(|_| EOVERFLOW)?;
        // SAFETY: `count` is writable and `ctrl` is an initialized controller.
        to_result(unsafe { bindings::nvme_set_queue_count(self.ctrl.get(), &mut count) })?;
        u32::try_from(count).map_err(|_| EIO)
    }

    /// Read the controller's current power-state feature.
    ///
    /// The status preserves positive NVMe completion codes separately from
    /// negative kernel errors. The value is meaningful when the status is
    /// non-negative, matching `nvme_get_features`.
    pub fn get_power_state(&self) -> (AdminCommandStatus, u32) {
        let mut state = 0u32;
        // SAFETY: No data buffer is supplied and `state` is writable for the
        // duration of this synchronous admin command.
        let status = unsafe {
            bindings::nvme_get_features(
                self.ctrl.get(),
                bindings::NVME_FEAT_POWER_MGMT,
                0,
                ptr::null_mut(),
                0,
                (&raw mut state).cast::<c_void>(),
            )
        };
        (AdminCommandStatus(status), state)
    }

    /// Select a controller power state through the power-management feature.
    ///
    /// The returned status preserves positive NVMe completion codes and
    /// negative kernel errors.
    pub fn set_power_state(&self, state: u32) -> AdminCommandStatus {
        // SAFETY: The power-management feature accepts its state in dword 11
        // and uses no data or result buffer.
        AdminCommandStatus(unsafe {
            bindings::nvme_set_features(
                self.ctrl.get(),
                bindings::NVME_FEAT_POWER_MGMT,
                state,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        })
    }

    /// Submit one admin command synchronously without a data buffer.
    ///
    /// The returned status preserves positive NVMe completion codes as well
    /// as negative kernel errors.
    pub fn submit_admin(&self, command: &mut Command) -> AdminCommandStatus {
        // SAFETY: The controller and its admin queue are owned by the NVMe
        // core. `command` is a valid 64-byte capsule and no buffer is supplied.
        let status = unsafe {
            let queue = (*self.ctrl.get()).admin_q;
            if queue.is_null() {
                ENODEV.to_errno()
            } else {
                bindings::nvme_submit_sync_cmd(queue, command.as_raw(), ptr::null_mut(), 0)
            }
        };
        AdminCommandStatus(status)
    }

    /// Submit an admin command asynchronously and transfer one completion
    /// reference to blk-mq.
    pub fn submit_admin_async<C: AdminCompletion>(
        &self,
        command: &mut Command,
        completion: Arc<C>,
    ) -> Result {
        // SAFETY: `ctrl` remains live through the admin queue lifetime.
        let queue = unsafe { (*self.ctrl.get()).admin_q };
        if queue.is_null() {
            return Err(ENODEV);
        }
        // SAFETY: The helper only inspects the initialized command opcode.
        let operation = unsafe { bindings::nvme_req_op(command.as_raw()) } as bindings::blk_opf_t;
        // SAFETY: `queue` is a live admin request queue. NOWAIT matches the
        // timeout and queue-delete paths and cannot sleep for request tags.
        let request = from_err_ptr(unsafe {
            bindings::blk_mq_alloc_request(queue, operation, bindings::BLK_MQ_REQ_NOWAIT)
        })?;
        let Some(request) = NonNull::new(request) else {
            return Err(ENOMEM);
        };

        // SAFETY: The allocated request belongs to an NVMe admin tag set and
        // `command` remains valid while `nvme_init_request` copies it.
        unsafe { bindings::nvme_init_request(request.as_ptr(), command.as_raw()) };
        let completion = completion.into_foreign();
        // SAFETY: The request is exclusively owned before submission. The
        // callback reclaims `completion` and frees the request exactly once.
        unsafe {
            (*request.as_ptr()).end_io = Some(Self::admin_completion_callback::<C>);
            (*request.as_ptr()).end_io_data = completion;
            bindings::blk_execute_rq_nowait(request.as_ptr(), false);
        }
        Ok(())
    }

    /// Complete an asynchronous-event notification delivered without a
    /// blk-mq request object.
    pub fn complete_async_event(&self, status: u16, mut result: CompletionResult) {
        // SAFETY: `status` and `result` are copied from a live CQ entry; the
        // core consumes the result synchronously.
        unsafe {
            bindings::nvme_complete_async_event(self.ctrl.get(), status.to_le(), &raw mut result.0)
        };
    }

    /// Whether a command identifier denotes the admin queue's reserved AEN
    /// slot rather than a blk-mq request.
    #[inline]
    pub fn is_async_event_request(queue_id: u16, command_id: u16) -> bool {
        // SAFETY: This helper performs only value-level NVMe CID decoding.
        unsafe { bindings::nvme_is_aen_req(queue_id, command_id) }
    }

    /// Tear down the NVMe core controller.
    ///
    /// The final reference may be dropped from inside this call.  Callers must
    /// arrange an independent owner reference if they need to access the
    /// transport state after it returns.
    #[inline]
    pub fn uninit(&self) {
        if !self.initialized.swap(false, Ordering::AcqRel) {
            return;
        }
        // The typed reset callback borrows the core-owned Arc. Draining it
        // before `nvme_uninit_ctrl` can run `free_ctrl` makes that lifetime
        // guarantee unconditional for safe users of this abstraction.
        self.flush_reset_work();
        if self.added_reference_held.swap(false, Ordering::AcqRel) {
            // SAFETY: A successful `add` acquired the publication reference
            // released by `nvme_uninit_ctrl`, and this swap claims it once.
            unsafe { bindings::nvme_uninit_ctrl(self.ctrl.get()) };
        } else if self.initial_reference_held.swap(false, Ordering::AcqRel) {
            // SAFETY: Initialization succeeded but publication was never
            // attempted; release the one initial reference exactly once.
            unsafe { bindings::nvme_put_ctrl(self.ctrl.get()) };
        }
    }

    /// Raw controller pointer for other in-kernel abstractions (not drivers).
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> *mut bindings::nvme_ctrl {
        self.ctrl.get()
    }

    unsafe fn from_raw_ctrl<'a>(ctrl: *mut bindings::nvme_ctrl) -> &'a Self {
        // SAFETY: Every callback in our vtable is installed only on the `ctrl`
        // field of a live `Controller<T>`.
        unsafe { &*crate::container_of!(ctrl.cast::<Opaque<bindings::nvme_ctrl>>(), Self, ctrl) }
    }

    unsafe fn owner_from_raw<'a>(ctrl: *mut bindings::nvme_ctrl) -> Option<ArcBorrow<'a, T>> {
        // SAFETY: Forwarded from the callback contract.
        let this = unsafe { Self::from_raw_ctrl(ctrl) };
        let owner = this.owner.load(Ordering::Acquire);
        if owner.is_null() {
            None
        } else {
            // SAFETY: `owner` is the still-published result of exactly one
            // `Arc<T>::into_foreign`; final release swaps it to NULL first.
            Some(unsafe { Arc::<T>::borrow(owner) })
        }
    }

    unsafe extern "C" fn reg_read32_callback(
        ctrl: *mut bindings::nvme_ctrl,
        offset: u32,
        value: *mut u32,
    ) -> c_int {
        if value.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: The NVMe core invokes this through our live operations table.
        let Some(owner) = (unsafe { Self::owner_from_raw(ctrl) }) else {
            return ENODEV.to_errno();
        };
        match T::reg_read32(&owner, offset) {
            Ok(v) => {
                // SAFETY: The callback contract supplies writable output storage.
                unsafe { value.write(v) };
                0
            }
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn reg_write32_callback(
        ctrl: *mut bindings::nvme_ctrl,
        offset: u32,
        value: u32,
    ) -> c_int {
        // SAFETY: The NVMe core invokes this through our live operations table.
        let Some(owner) = (unsafe { Self::owner_from_raw(ctrl) }) else {
            return ENODEV.to_errno();
        };
        match T::reg_write32(&owner, offset, value) {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn reg_read64_callback(
        ctrl: *mut bindings::nvme_ctrl,
        offset: u32,
        value: *mut u64,
    ) -> c_int {
        if value.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: The NVMe core invokes this through our live operations table.
        let Some(owner) = (unsafe { Self::owner_from_raw(ctrl) }) else {
            return ENODEV.to_errno();
        };
        match T::reg_read64(&owner, offset) {
            Ok(v) => {
                // SAFETY: The callback contract supplies writable output storage.
                unsafe { value.write(v) };
                0
            }
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn submit_async_event_callback(ctrl: *mut bindings::nvme_ctrl) {
        // SAFETY: The NVMe core invokes this through our live operations table.
        if let Some(owner) = unsafe { Self::owner_from_raw(ctrl) } {
            T::submit_async_event(&owner);
        }
    }

    unsafe extern "C" fn reset_work_callback(work: *mut bindings::work_struct) {
        if work.is_null() {
            return;
        }
        // SAFETY: The helper initialized this callback on the `reset_work`
        // field embedded in the live controller.
        let ctrl = unsafe { crate::container_of!(work, bindings::nvme_ctrl, reset_work) };
        // SAFETY: Every reset-work queueing path retains the controller until
        // the work is drained, and `uninit` drains it before releasing owner.
        if let Some(owner) = unsafe { Self::owner_from_raw(ctrl) } {
            // SAFETY: Reset work is queued only while the transport remains
            // bound. `Controller::uninit` drains it before the bus unbind
            // callback may return, so this reference cannot escape the bound
            // interval.
            let parent = unsafe { bindings::nvme_ctrl_parent_device(ctrl) };
            if let Some(parent) = NonNull::new(parent) {
                // SAFETY: The lifecycle argument above proves the Bound
                // context for exactly this callback invocation.
                let parent = unsafe { device::Device::<device::Bound>::from_raw(parent.as_ptr()) };
                T::reset_work(&owner, parent);
            }
        }
    }

    unsafe extern "C" fn subsystem_reset_callback(ctrl: *mut bindings::nvme_ctrl) -> c_int {
        // SAFETY: The NVMe core invokes this through our live operations table.
        let Some(owner) = (unsafe { Self::owner_from_raw(ctrl) }) else {
            return ENODEV.to_errno();
        };
        match T::subsystem_reset(&owner) {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn get_address_callback(
        ctrl: *mut bindings::nvme_ctrl,
        buffer: *mut c_char,
        size: c_int,
    ) -> c_int {
        if buffer.is_null() || size <= 0 {
            return EINVAL.to_errno();
        }
        // SAFETY: The NVMe core invokes this through our live operations table.
        let Some(owner) = (unsafe { Self::owner_from_raw(ctrl) }) else {
            return ENODEV.to_errno();
        };
        // SAFETY: The callback contract gives a writable buffer of `size`
        // bytes for the duration of this call.
        let buffer = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), size as usize) };
        match T::get_address(&owner, buffer) {
            Ok(written) if written <= buffer.len() && written <= c_int::MAX as usize => {
                written as c_int
            }
            Ok(_) => EOVERFLOW.to_errno(),
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn print_device_info_callback(ctrl: *mut bindings::nvme_ctrl) {
        // SAFETY: The NVMe core invokes this through our live operations table.
        if let Some(owner) = unsafe { Self::owner_from_raw(ctrl) } {
            T::print_device_info(&owner);
        }
    }

    unsafe extern "C" fn supports_pci_p2pdma_callback(
        ctrl: *mut bindings::nvme_ctrl,
    ) -> bindings::bool_ {
        // SAFETY: The NVMe core invokes this through our live operations table.
        unsafe { Self::owner_from_raw(ctrl) }
            .map(|owner| T::supports_pci_p2pdma(&owner))
            .unwrap_or(false)
    }

    unsafe extern "C" fn get_virt_boundary_callback(
        ctrl: *mut bindings::nvme_ctrl,
        is_admin: bindings::bool_,
    ) -> usize {
        // SAFETY: The NVMe core invokes this through our live operations table.
        unsafe { Self::owner_from_raw(ctrl) }
            .map(|owner| T::get_virt_boundary(&owner, is_admin))
            .unwrap_or(0)
    }

    unsafe extern "C" fn free_ctrl_callback(ctrl: *mut bindings::nvme_ctrl) {
        // SAFETY: The NVMe core invokes this exactly once for a successfully
        // initialized controller, after all other controller callbacks have
        // been quiesced.
        let this = unsafe { Self::from_raw_ctrl(ctrl) };
        this.initialized.store(false, Ordering::Release);
        this.initial_reference_held.store(false, Ordering::Release);
        this.added_reference_held.store(false, Ordering::Release);
        let owner = this.owner.swap(ptr::null_mut(), Ordering::AcqRel);
        if owner.is_null() {
            return;
        }

        // SAFETY: The swap claimed the single reference transferred by
        // `init`, so this is its sole matching `from_foreign` call.
        let owner = unsafe { Arc::<T>::from_foreign(owner) };
        T::free_ctrl(&owner);
        drop(owner);
    }

    unsafe extern "C" fn admin_completion_callback<C: AdminCompletion>(
        request: *mut bindings::request,
        block_status: bindings::blk_status_t,
    ) -> bindings::rq_end_io_ret {
        if request.is_null() {
            return bindings::rq_end_io_ret_RQ_END_IO_NONE;
        }
        // SAFETY: `submit_admin_async` stored the sole foreign Arc reference
        // in this request before submission; blk-mq invokes end_io once.
        let completion = unsafe { (*request).end_io_data };
        if !completion.is_null() {
            // Clear the slot before calling driver code, making accidental
            // re-entry fail closed instead of reclaiming the Arc twice.
            unsafe { (*request).end_io_data = ptr::null_mut() };
            // SAFETY: This is the sole matching `from_foreign` operation.
            let completion = unsafe { Arc::<C>::from_foreign(completion) };
            // SAFETY: Every NVMe request PDU begins with `nvme_request`.
            let core =
                unsafe { &*bindings::blk_mq_rq_to_pdu(request).cast::<bindings::nvme_request>() };
            C::complete(&completion, core.status, block_status);
            drop(completion);
        }
        // SAFETY: The async submit path transferred request ownership to this
        // callback and no references remain after the completion hook.
        unsafe { bindings::blk_mq_free_request(request) };
        bindings::rq_end_io_ret_RQ_END_IO_NONE
    }
}

/// Status returned by a blk-mq submission callback.
pub type BlockStatus = bindings::blk_status_t;

/// The request was accepted by the transport.
pub const BLK_STS_OK: BlockStatus = bindings::BLK_STS_OK as BlockStatus;

/// The request failed because of an I/O error.
pub const BLK_STS_IOERR: BlockStatus = 10;

/// The host is temporarily short of a shared resource.
pub const BLK_STS_RESOURCE: BlockStatus = 9;

/// This device is temporarily short of a private resource.
pub const BLK_STS_DEV_RESOURCE: BlockStatus = 13;

/// Completion hook for a request submitted through
/// [`Controller::submit_admin_async`].
pub trait AdminCompletion: Send + Sync + Sized + 'static {
    /// The NVMe status and blk-mq status reported for the admin request.
    ///
    /// The request has already stopped using the command capsule, and it is
    /// freed immediately after this method returns.
    fn complete(&self, nvme_status: u16, block_status: BlockStatus);
}

/// Raw outcome of a synchronous NVMe admin command.
///
/// Zero denotes success, a positive value is an NVMe status, and a negative
/// value is a kernel errno, matching `nvme_submit_sync_cmd`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminCommandStatus(c_int);

impl AdminCommandStatus {
    /// Whether the command completed successfully.
    #[inline]
    pub fn is_success(self) -> bool {
        self.0 == 0
    }

    /// Original NVMe status or kernel errno.
    #[inline]
    pub fn as_raw(self) -> c_int {
        self.0
    }

    /// Convert any nonzero outcome into a kernel error for lifecycle paths
    /// that do not distinguish controller status codes.
    pub fn into_result(self) -> Result {
        match self.0 {
            0 => Ok(()),
            value if value < 0 => to_result(value),
            _ => Err(EIO),
        }
    }
}

/// Action returned by a blk-mq timeout callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TimeoutAction {
    /// Timeout processing completed; do not restart the timer.
    Done = bindings::blk_eh_timer_return_BLK_EH_DONE,
    /// Restart the request timeout timer.
    ResetTimer = bindings::blk_eh_timer_return_BLK_EH_RESET_TIMER,
}

impl TimeoutAction {
    #[inline]
    fn as_raw(self) -> bindings::blk_eh_timer_return {
        self as bindings::blk_eh_timer_return
    }
}

/// An NVMe command capsule.
///
/// Transport drivers access command fields through methods on this wrapper;
/// the private C union is not exposed as part of the driver API.
#[repr(transparent)]
pub struct Command(bindings::nvme_command);

static_assert!(size_of::<bindings::nvme_command>() == Command::SIZE);
static_assert!(size_of::<bindings::nvme_create_cq>() == Command::SIZE);
static_assert!(size_of::<bindings::nvme_create_sq>() == Command::SIZE);
static_assert!(size_of::<bindings::nvme_delete_queue>() == Command::SIZE);

impl Command {
    /// Size in bytes of one command capsule in an NVMe submission queue.
    pub const SIZE: usize = 64;

    /// Create a zeroed command capsule.
    #[inline]
    pub fn zeroed() -> Self {
        // SAFETY: All-zero is the specified initial representation of an NVMe
        // command before an opcode and its fields are assigned.
        Self(unsafe { core::mem::zeroed() })
    }

    /// Command for an asynchronous-event request on the reserved admin CID.
    pub fn async_event() -> Self {
        let mut command = Self::zeroed();
        // SAFETY: We initialize and subsequently read the common union member.
        let common = unsafe { &mut command.0.__bindgen_anon_1.common };
        common.opcode = bindings::nvme_admin_opcode_nvme_admin_async_event as u8;
        common.command_id = bindings::NVME_AQ_BLK_MQ_DEPTH as u16;
        command
    }

    /// Doorbell-buffer configuration command.
    pub fn doorbell_buffer(doorbells: u64, event_indices: u64) -> Self {
        let mut command = Self::zeroed();
        // SAFETY: We initialize the doorbell-buffer union member.
        let dbbuf = unsafe { &mut command.0.__bindgen_anon_1.dbbuf };
        dbbuf.opcode = bindings::nvme_admin_opcode_nvme_admin_dbbuf as u8;
        dbbuf.prp1 = doorbells.to_le();
        dbbuf.prp2 = event_indices.to_le();
        command
    }

    /// Delete an I/O submission queue.
    pub fn delete_submission_queue(queue_id: u16) -> Self {
        Self::delete_queue(
            bindings::nvme_admin_opcode_nvme_admin_delete_sq as u8,
            queue_id,
        )
    }

    /// Delete an I/O completion queue.
    pub fn delete_completion_queue(queue_id: u16) -> Self {
        Self::delete_queue(
            bindings::nvme_admin_opcode_nvme_admin_delete_cq as u8,
            queue_id,
        )
    }

    fn delete_queue(opcode: u8, queue_id: u16) -> Self {
        let mut command = Self::zeroed();
        // SAFETY: We initialize the delete-queue union member.
        let delete = unsafe { &mut command.0.__bindgen_anon_1.delete_queue };
        delete.opcode = opcode;
        delete.qid = queue_id.to_le();
        command
    }

    /// Create an I/O completion queue.
    pub fn create_completion_queue(
        queue_id: u16,
        depth: u16,
        dma_address: u64,
        flags: u16,
        interrupt_vector: u16,
    ) -> Result<Self> {
        let queue_size = depth.checked_sub(1).ok_or(EINVAL)?;
        let mut command = Self::zeroed();
        // SAFETY: We initialize the create-CQ union member.
        let create = unsafe { &mut command.0.__bindgen_anon_1.create_cq };
        create.opcode = bindings::nvme_admin_opcode_nvme_admin_create_cq as u8;
        create.prp1 = dma_address.to_le();
        create.cqid = queue_id.to_le();
        create.qsize = queue_size.to_le();
        create.cq_flags = flags.to_le();
        create.irq_vector = interrupt_vector.to_le();
        Ok(command)
    }

    /// Create an I/O submission queue paired with the same completion queue.
    pub fn create_submission_queue(
        queue_id: u16,
        depth: u16,
        dma_address: u64,
        flags: u16,
    ) -> Result<Self> {
        let queue_size = depth.checked_sub(1).ok_or(EINVAL)?;
        let mut command = Self::zeroed();
        // SAFETY: We initialize the create-SQ union member.
        let create = unsafe { &mut command.0.__bindgen_anon_1.create_sq };
        create.opcode = bindings::nvme_admin_opcode_nvme_admin_create_sq as u8;
        create.prp1 = dma_address.to_le();
        create.sqid = queue_id.to_le();
        create.qsize = queue_size.to_le();
        create.sq_flags = flags.to_le();
        create.cqid = queue_id.to_le();
        Ok(command)
    }

    /// Abort one command on an I/O submission queue.
    pub fn abort(queue_id: u16, command_id: u16) -> Self {
        let mut command = Self::zeroed();
        // SAFETY: We initialize the abort-command union member.
        let abort = unsafe { &mut command.0.__bindgen_anon_1.abort };
        abort.opcode = bindings::nvme_admin_opcode_nvme_admin_abort_cmd as u8;
        abort.sqid = queue_id.to_le();
        abort.cid = command_id;
        command
    }

    /// Configure or release the controller's Host Memory Buffer.
    pub fn host_memory_buffer(
        flags: u32,
        size_pages: u32,
        descriptor_address: u64,
        descriptor_count: u32,
    ) -> Self {
        let mut command = Self::zeroed();
        // SAFETY: We initialize the set-features union member.
        let features = unsafe { &mut command.0.__bindgen_anon_1.features };
        features.opcode = bindings::nvme_admin_opcode_nvme_admin_set_features as u8;
        features.fid = (bindings::NVME_FEAT_HOST_MEM_BUF as u32).to_le();
        features.dword11 = flags.to_le();
        features.dword12 = size_pages.to_le();
        features.dword13 = (descriptor_address as u32).to_le();
        features.dword14 = ((descriptor_address >> 32) as u32).to_le();
        features.dword15 = descriptor_count.to_le();
        command
    }

    /// Opcode in the common command header.
    #[inline]
    pub fn opcode(&self) -> u8 {
        // SAFETY: Every member of `union nvme_command` starts with the common
        // command header, and a request command is initialized before use.
        unsafe { self.0.__bindgen_anon_1.common.opcode }
    }

    /// Store two physical-region-page pointers and select PRP format.
    pub fn set_prps(&mut self, first: dma::DmaAddress, second: dma::DmaAddress) {
        // SAFETY: The common command member is valid for every opcode and the
        // PRP pair occupies the data-pointer union selected by clearing SGL.
        unsafe {
            let common = &mut self.0.__bindgen_anon_1.common;
            common.flags &= !(bindings::NVME_CMD_SGL_ALL as u8);
            common.dptr.__bindgen_anon_1.prp1 = first.to_le();
            common.dptr.__bindgen_anon_1.prp2 = second.to_le();
        }
    }

    /// Select the transport data-SGL command format exactly.
    ///
    /// This replaces the complete common flags byte, matching transports
    /// whose SGL preparation deliberately discards any pre-existing fused or
    /// pointer-format bits before installing a data descriptor.
    pub fn select_data_sgl_format(&mut self) {
        self.0.__bindgen_anon_1.common.flags = bindings::NVME_CMD_SGL_METABUF as u8;
    }

    /// Select the transport metadata-SGL command format exactly.
    ///
    /// This replaces the complete common flags byte before the metadata
    /// segment pointer is installed.
    pub fn select_metadata_sgl_format(&mut self) {
        self.0.__bindgen_anon_1.common.flags = bindings::NVME_CMD_SGL_METASEG as u8;
    }

    /// Store one inline data SGL descriptor.
    pub fn set_data_sgl(&mut self, address: dma::DmaAddress, length: u32) {
        // SAFETY: We select and initialize the SGL member of the common data
        // pointer union before the command can become visible to hardware.
        unsafe {
            let common = &mut self.0.__bindgen_anon_1.common;
            common.flags = (common.flags & !(bindings::NVME_CMD_SGL_ALL as u8))
                | bindings::NVME_CMD_SGL_METABUF as u8;
            common.dptr.sgl = bindings::nvme_sgl_desc {
                addr: address.to_le(),
                length: length.to_le(),
                rsvd: [0; 3],
                type_: (bindings::NVME_SGL_FMT_DATA_DESC << 4) as u8,
            };
        }
    }

    /// Point the command at a last-segment SGL descriptor list.
    pub fn set_data_sgl_list(
        &mut self,
        address: dma::DmaAddress,
        descriptor_count: usize,
    ) -> Result {
        let length = descriptor_count
            .checked_mul(size_of::<bindings::nvme_sgl_desc>())
            .ok_or(EOVERFLOW)?;
        let length = u32::try_from(length).map_err(|_| EOVERFLOW)?;
        // SAFETY: Same union selection as `set_data_sgl`; this descriptor
        // points at a complete external list prepared before submission.
        unsafe {
            let common = &mut self.0.__bindgen_anon_1.common;
            common.flags = (common.flags & !(bindings::NVME_CMD_SGL_ALL as u8))
                | bindings::NVME_CMD_SGL_METABUF as u8;
            common.dptr.sgl = bindings::nvme_sgl_desc {
                addr: address.to_le(),
                length: length.to_le(),
                rsvd: [0; 3],
                type_: (bindings::NVME_SGL_FMT_LAST_SEG_DESC << 4) as u8,
            };
        }
        Ok(())
    }

    /// Store a traditional metadata pointer and clear metadata-SGL format.
    pub fn set_metadata_pointer(&mut self, address: dma::DmaAddress) {
        // SAFETY: The metadata field is part of every common command header.
        unsafe {
            let common = &mut self.0.__bindgen_anon_1.common;
            common.flags &= !(bindings::NVME_CMD_SGL_METASEG as u8);
            common.metadata = address.to_le();
        }
    }

    /// Select metadata SGL format and point at its segment descriptor.
    pub fn set_metadata_sgl(&mut self, address: dma::DmaAddress) {
        // SAFETY: The metadata field is part of every common command header;
        // the caller prepares the descriptor before submission.
        unsafe {
            let common = &mut self.0.__bindgen_anon_1.common;
            common.flags = (common.flags & !(bindings::NVME_CMD_SGL_ALL as u8))
                | bindings::NVME_CMD_SGL_METASEG as u8;
            common.metadata = address.to_le();
        }
    }

    /// Whether the data pointer currently uses an SGL encoding.
    #[inline]
    pub fn uses_data_sgl(&self) -> bool {
        // SAFETY: Every command has a common header.
        unsafe {
            self.0.__bindgen_anon_1.common.flags
                & (bindings::NVME_CMD_SGL_METABUF | bindings::NVME_CMD_SGL_METASEG) as u8
                != 0
        }
    }

    /// Whether metadata is represented by an SGL segment.
    #[inline]
    pub fn uses_metadata_sgl(&self) -> bool {
        // SAFETY: Every command has a common header.
        unsafe {
            self.0.__bindgen_anon_1.common.flags & bindings::NVME_CMD_SGL_ALL as u8
                == bindings::NVME_CMD_SGL_METASEG as u8
        }
    }

    /// Return the complete command capsule in its device-visible byte layout.
    ///
    /// This view lets a transport copy a prepared command into either coherent
    /// host memory or PCI peer-to-peer submission-queue memory without exposing
    /// the private C union or requiring driver-side unsafe code.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        // SAFETY: `Command` is transparent over the statically asserted
        // 64-byte C union. Every constructor starts from a completely zeroed
        // capsule and field setters only replace initialized bytes, so the
        // entire representation is initialized and may be read as bytes.
        unsafe { &*((&raw const self.0).cast::<[u8; Self::SIZE]>()) }
    }

    #[inline]
    fn as_raw(&mut self) -> *mut bindings::nvme_command {
        &raw mut self.0
    }
}

/// Completion result copied from an NVMe completion queue entry.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct CompletionResult(bindings::nvme_completion_nvme_result);

impl CompletionResult {
    /// Construct a result from the raw little-endian 64-bit CQ field.
    #[inline]
    pub fn from_raw(value: u64) -> Self {
        Self(bindings::nvme_completion_nvme_result {
            u64_: value.to_le(),
        })
    }

    /// Return the result as a host-endian 64-bit value.
    #[inline]
    pub fn as_u64(self) -> u64 {
        // SAFETY: The result union is always a 64-bit CQ field; reading the
        // widest member preserves all command-specific result bits.
        u64::from_le(unsafe { self.0.u64_ })
    }
}

/// One typed NVMe PRP/SGL descriptor allocation from a DMA pool.
///
/// `N` is the pool element size (normally 256 bytes for the small pool or one
/// controller page for the large pool). All CPU access stays inside this type;
/// drivers can only write bounded, correctly encoded descriptor entries.
pub struct Descriptor<const N: usize> {
    allocation: dma::DmaPoolAllocation<[u8; N]>,
    sgl_data_start: usize,
    sgl_data_count: usize,
    sgl_request: usize,
    sgl_payload: Option<DmaPayload>,
}

impl<const N: usize> Descriptor<N> {
    /// Allocate one zeroed descriptor buffer.
    pub fn allocate(pool: &Arc<dma::DmaPool<[u8; N]>>, flags: crate::alloc::Flags) -> Result<Self> {
        Ok(Self {
            allocation: pool.allocate(flags)?,
            sgl_data_start: 0,
            sgl_data_count: 0,
            sgl_request: 0,
            sgl_payload: None,
        })
    }

    /// Device-visible base address of this descriptor.
    #[inline]
    pub fn dma_address(&self) -> dma::DmaAddress {
        self.allocation.dma_address()
    }

    /// Number of PRP addresses this buffer can contain.
    #[inline]
    pub const fn prp_capacity() -> usize {
        N / size_of::<u64>()
    }

    /// Number of SGL descriptors this buffer can contain.
    #[inline]
    pub const fn sgl_capacity() -> usize {
        N / size_of::<bindings::nvme_sgl_desc>()
    }

    /// Write one PRP address in little-endian form.
    pub fn write_prp(&mut self, index: usize, address: dma::DmaAddress) -> Result {
        if index >= Self::prp_capacity() {
            return Err(E2BIG);
        }
        // SAFETY: Bounds were checked above and no device may access the
        // descriptor before submission. Use an unaligned write so soundness
        // does not depend on a caller-provided pool alignment.
        unsafe {
            self.allocation
                .as_mut_ptr()
                .cast::<u64>()
                .add(index)
                .write_unaligned(address.to_le())
        };
        Ok(())
    }

    /// Read one PRP address while constructing a chained list.
    pub fn read_prp(&self, index: usize) -> Result<dma::DmaAddress> {
        if index >= Self::prp_capacity() {
            return Err(E2BIG);
        }
        // SAFETY: Same bounds argument as `write_prp`; descriptor construction
        // occurs before the device can read this allocation.
        let value = unsafe {
            self.allocation
                .as_ptr()
                .cast::<u64>()
                .add(index)
                .read_unaligned()
        };
        Ok(u64::from_le(value) as dma::DmaAddress)
    }

    /// Write one data-block SGL descriptor.
    pub fn write_data_sgl(
        &mut self,
        index: usize,
        address: dma::DmaAddress,
        length: u32,
    ) -> Result {
        let expected = self
            .sgl_data_start
            .checked_add(self.sgl_data_count)
            .ok_or(EOVERFLOW)?;
        if self.sgl_data_count == 0 {
            self.sgl_data_start = index;
        } else if index != expected {
            return Err(EINVAL);
        }
        self.write_sgl(
            index,
            bindings::nvme_sgl_desc {
                addr: address.to_le(),
                length: length.to_le(),
                rsvd: [0; 3],
                type_: (bindings::NVME_SGL_FMT_DATA_DESC << 4) as u8,
            },
        )?;
        self.sgl_data_count += 1;
        Ok(())
    }

    /// Write a last-segment descriptor pointing to `descriptor_count` SGLs.
    pub fn write_last_segment_sgl(
        &mut self,
        index: usize,
        address: dma::DmaAddress,
        descriptor_count: usize,
    ) -> Result {
        let length = descriptor_count
            .checked_mul(size_of::<bindings::nvme_sgl_desc>())
            .ok_or(EOVERFLOW)?;
        self.write_sgl(
            index,
            bindings::nvme_sgl_desc {
                addr: address.to_le(),
                length: u32::try_from(length).map_err(|_| EOVERFLOW)?.to_le(),
                rsvd: [0; 3],
                type_: (bindings::NVME_SGL_FMT_LAST_SEG_DESC << 4) as u8,
            },
        )
    }

    fn write_sgl(&mut self, index: usize, descriptor: bindings::nvme_sgl_desc) -> Result {
        if index >= Self::sgl_capacity() {
            return Err(E2BIG);
        }
        // SAFETY: Index is in bounds and construction is complete before
        // hardware sees the list. An unaligned write avoids relying on the
        // pool creator's chosen alignment for Rust validity.
        unsafe {
            self.allocation
                .as_mut_ptr()
                .cast::<bindings::nvme_sgl_desc>()
                .add(index)
                .write_unaligned(descriptor)
        };
        Ok(())
    }

    fn sgl_data_segment(&self, ordinal: usize) -> Option<DmaSegment> {
        if ordinal >= self.sgl_data_count {
            return None;
        }
        let index = self.sgl_data_start.checked_add(ordinal)?;
        if index >= Self::sgl_capacity() {
            return None;
        }
        // SAFETY: The descriptor allocation remains CPU-owned while request
        // DMA is being unwound. The tracked range contains only entries
        // initialized by `write_data_sgl`, and unaligned access matches the
        // corresponding write.
        let descriptor = unsafe {
            self.allocation
                .as_ptr()
                .cast::<bindings::nvme_sgl_desc>()
                .add(index)
                .read_unaligned()
        };
        if descriptor.type_ != (bindings::NVME_SGL_FMT_DATA_DESC << 4) as u8 {
            return None;
        }
        Some(DmaSegment {
            address: u64::from_le(descriptor.addr) as dma::DmaAddress,
            length: u32::from_le(descriptor.length),
            _padding: 0,
        })
    }
}

/// Standard NVMe small descriptor allocation.
pub type SmallDescriptor = Descriptor<256>;

/// Standard one-page NVMe descriptor allocation.
pub type LargeDescriptor = Descriptor<4096>;

/// Driver-private command data placed after the NVMe core request prefix.
///
/// The first two fields deliberately match the beginning of C
/// `struct nvme_iod`. The NVMe core treats the first field as
/// `struct nvme_request`, and `nvme_request.cmd` always points at the second
/// field. Keeping the prefix in the abstraction prevents a Rust transport from
/// accidentally inserting metadata before it.
#[repr(C)]
struct RequestPdu<D> {
    core: bindings::nvme_request,
    command: Command,
    data: D,
}

/// Inline equivalent of blk_rq_nr_phys_segments(), including its special
/// payload override. All callers own the live request for the callback.
#[inline]
unsafe fn request_phys_segments(request: *const bindings::request) -> u32 {
    // SAFETY: The caller supplies a live, callback-owned C request header.
    // This borrow does not cover the separately typed PDU that follows it.
    let request = unsafe { &*request };
    if request.rq_flags & (1 << bindings::rqf_flags___RQF_SPECIAL_PAYLOAD) != 0 {
        1
    } else {
        u32::from(request.nr_phys_segments)
    }
}

/// A request borrowed from blk-mq for the duration of a callback.
pub struct MqRequest<'a, O: MqOperations> {
    raw: NonNull<bindings::request>,
    _p: PhantomData<(&'a bindings::request, O)>,
}

impl<'a, O: MqOperations> MqRequest<'a, O> {
    unsafe fn from_raw(raw: *mut bindings::request) -> Option<Self> {
        NonNull::new(raw).map(|raw| Self {
            raw,
            _p: PhantomData,
        })
    }

    #[inline]
    fn pdu_ptr(&self) -> *mut RequestPdu<O::RequestData> {
        // SAFETY: blk_mq_rq_to_pdu() is exactly `rq + 1` in blk-mq.h.
        // blk-mq allocates the request and `cmd_size` bytes in one allocation;
        // TagSet<O> reserves RequestPdu<O::RequestData> there and verifies that
        // its alignment does not exceed the request's alignment. The binding
        // supplies the actual C request size, so no layout offset is hard-coded.
        // This callback borrow keeps that allocation live for all PDU accesses.
        unsafe { self.raw.as_ptr().add(1).cast() }
    }

    /// Driver-private per-request state.
    #[inline]
    pub fn data(&self) -> &O::RequestData {
        // SAFETY: `init_request_callback` initializes `data` before blk-mq can
        // dispatch the request and `exit_request_callback` runs afterwards.
        unsafe { &*ptr::addr_of!((*self.pdu_ptr()).data) }
    }

    /// Exclusive transport-private request data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut O::RequestData {
        // SAFETY: blk-mq gives each queue/completion callback exclusive
        // ownership of this request, and `&mut self` preserves that guarantee.
        unsafe { &mut *ptr::addr_of_mut!((*self.pdu_ptr()).data) }
    }

    /// Command capsule populated by the NVMe core for this request.
    #[inline]
    pub fn command(&self) -> &Command {
        // SAFETY: The command field is initialized before this request is
        // published to blk-mq and remains live until request exit.
        unsafe { &*ptr::addr_of!((*self.pdu_ptr()).command) }
    }

    /// Mutably borrow the command while preparing it for submission.
    ///
    /// The caller must finish all command mutations before making the command
    /// visible to hardware. blk-mq serializes preparation of one request.
    #[inline]
    pub fn command_mut(&mut self) -> &mut Command {
        // SAFETY: A queue callback owns preparation of this request; the
        // returned borrow cannot outlive that callback's request wrapper.
        unsafe { &mut *ptr::addr_of_mut!((*self.pdu_ptr()).command) }
    }

    /// The owning transport state, if controller teardown has not started.
    #[inline]
    pub fn transport(&self) -> Option<ArcBorrow<'_, O::Transport>> {
        // SAFETY: The core prefix is initialized by `init_request_callback`.
        let ctrl = unsafe { (*ptr::addr_of!((*self.pdu_ptr()).core)).ctrl };
        if ctrl.is_null() {
            None
        } else {
            // SAFETY: The request belongs to this operations implementation,
            // whose tag set was allocated for `O::Transport`.
            unsafe { Controller::<O::Transport>::owner_from_raw(ctrl) }
        }
    }

    /// Typed hardware-queue state associated with this request.
    #[inline]
    pub fn hctx_data(&self) -> Option<&O::HctxData> {
        // SAFETY: `raw` is a live request for this callback.
        let hctx = unsafe { self.raw.as_ref().mq_hctx };
        if hctx.is_null() {
            return None;
        }
        // SAFETY: `init_hctx_callback` stores a pointer returned by
        // `O::init_hctx`, and blk-mq keeps it live through request callbacks.
        unsafe { (*hctx).driver_data.cast::<O::HctxData>().as_ref() }
    }

    /// Map a single data vector directly in this request's private mapping slot.
    ///
    /// `select` returns the mapping field in the request's transport data. The
    /// request token is captured before borrowing that field, so no overlapping
    /// mutable request/data references are created and the mapping need not be
    /// moved out and copied back. Mapping checks and unmap ownership are the
    /// same as [`RequestDmaMapping::map_single_data_bvec`].
    #[inline]
    pub fn map_single_data_in_place(
        &mut self,
        dev: &device::Device,
        select: fn(&mut O::RequestData) -> &mut RequestDmaMapping<O>,
        should_map: impl FnOnce(u32, u32) -> bool,
    ) -> core::result::Result<Option<DmaBvecSegment>, BlockStatus> {
        let raw = self.raw;
        let mapping = select(self.data_mut());
        // SAFETY: This exclusive callback borrow keeps the request live. The
        // selected mapping is borrowed from its disjoint PDU region and
        // the raw implementation reads only the C request/bio, not RequestData.
        unsafe { mapping.map_single_data_bvec_raw(raw, dev, should_map) }
    }

    /// blk-mq request tag.
    #[inline]
    pub fn tag(&self) -> u16 {
        // SAFETY: `raw` is a live request for this callback. NVMe queue depths
        // fit in the non-negative 16-bit command-id tag field.
        unsafe { self.raw.as_ref().tag as u16 }
    }

    /// Total data payload in bytes.
    #[inline]
    pub fn data_len(&self) -> u32 {
        // SAFETY: `raw` is a live request for this callback.
        unsafe { self.raw.as_ref().__data_len }
    }

    /// Number of physical data segments in the request.
    #[inline]
    pub fn nr_phys_segments(&self) -> u32 {
        // SAFETY: `raw` is a live request for this callback.
        unsafe { request_phys_segments(self.raw.as_ptr()) }
    }

    /// Total request payload bytes after block-layer slicing.
    #[inline]
    pub fn payload_bytes(&self) -> u32 {
        // SAFETY: `raw` is a live request for this callback.
        unsafe { bindings::blk_rq_payload_bytes(self.raw.as_ptr()) }
    }

    /// Physical page-gap mask used to decide whether PRPs can represent the
    /// payload without SGLs.
    #[inline]
    pub fn physical_gap_mask(&self) -> usize {
        // SAFETY: The callback owns this request, so the block layer cannot
        // change its segment-gap encoding during command preparation.
        let bit = unsafe { self.raw.as_ref().phys_gap_bit };
        if bit < 31 {
            // req_phys_gap_mask uses a signed C int shift. For 0..=30 the
            // expression below has exactly the same (sign-extended) mask;
            // wrapping_sub preserves the zero-gap encoding at bit == 0.
            !(((1usize << bit) >> 1).wrapping_sub(1))
        } else {
            // Keep the architecture's existing C behavior at the signed-shift
            // boundary instead of introducing a new interpretation here.
            // SAFETY: The request remains live for this value-only helper.
            unsafe { bindings::req_phys_gap_mask(self.raw.as_ptr()) as usize }
        }
    }

    /// Whether this request carries integrity metadata.
    #[inline]
    pub fn has_integrity(&self) -> bool {
        // SAFETY: Value-only helper on a live request.
        unsafe { bindings::blk_integrity_rq(self.raw.as_ptr()) }
    }

    /// Number of integrity metadata segments.
    #[inline]
    pub fn nr_integrity_segments(&self) -> u32 {
        #[cfg(CONFIG_BLK_DEV_INTEGRITY)]
        // SAFETY: `raw` is a live request and the field is stable during
        // transport preparation/completion.
        return unsafe { self.raw.as_ref().nr_integrity_segments as u32 };
        #[cfg(not(CONFIG_BLK_DEV_INTEGRITY))]
        return 0;
    }

    /// Whether the NVMe core marked this as a userspace passthrough command.
    #[inline]
    pub fn is_user_command(&self) -> bool {
        // SAFETY: The NVMe request prefix is initialized for request lifetime.
        unsafe {
            (*ptr::addr_of!((*self.pdu_ptr()).core)).flags & bindings::NVME_REQ_USERCMD as u8 != 0
        }
    }

    /// Whether blk-mq still considers this request in flight.
    #[inline]
    pub fn is_in_flight(&self) -> bool {
        // SAFETY: `raw` is a live request for this callback.
        unsafe { self.raw.as_ref().state == bindings::mq_rq_state_MQ_RQ_IN_FLIGHT }
    }

    /// Mark this request cancelled so late completions are classified by the
    /// NVMe core exactly like the C transport timeout path.
    #[inline]
    pub fn mark_cancelled(&mut self) {
        // SAFETY: The mutable request wrapper gives this callback exclusive
        // access to the NVMe request flags.
        unsafe { bindings::nvme_req_mark_cancelled(self.raw.as_ptr()) };
    }

    /// NVMe command identifier combining the request tag and generation.
    #[inline]
    pub fn command_id(&self) -> u16 {
        // SAFETY: `raw` is a live NVMe request.
        unsafe { bindings::nvme_cid(self.raw.as_ptr()) }
    }

    /// Ask the NVMe core whether this request may be submitted in the current
    /// controller state.
    #[inline]
    pub fn check_ready(&self, queue_live: bool) -> bool {
        let Some(transport) = self.transport() else {
            return false;
        };
        let controller = transport.controller().as_raw();
        // SAFETY: The request belongs to this live controller; the helper uses
        // the NVMe core's READ_ONCE accessor.
        let state = unsafe { bindings::nvme_ctrl_state(controller) };
        if state == bindings::nvme_ctrl_state_NVME_CTRL_LIVE {
            return true;
        }
        if O::Transport::FLAGS & bindings::NVME_F_FABRICS != 0
            && state == bindings::nvme_ctrl_state_NVME_CTRL_DELETING
        {
            return queue_live;
        }
        // SAFETY: This exported NVMe-core function accepts the paired live
        // controller/request and the state read immediately above.
        unsafe { bindings::__nvme_check_ready(controller, self.raw.as_ptr(), queue_live, state) }
    }

    /// Let the NVMe core choose the failure status for a non-ready request.
    #[inline]
    pub fn fail_nonready(&self) -> BlockStatus {
        let Some(transport) = self.transport() else {
            return BLK_STS_IOERR;
        };
        // SAFETY: The request and controller are paired by the PDU prefix.
        unsafe {
            bindings::nvme_fail_nonready_command(transport.controller().as_raw(), self.raw.as_ptr())
        }
    }

    /// Populate the command capsule through the NVMe core namespace path.
    #[inline]
    pub fn setup_command(&mut self) -> BlockStatus {
        // SAFETY: A live request has a live queue. NVMe stores either an
        // `nvme_ns *` or NULL in queuedata as required by `nvme_setup_cmd`.
        let namespace = unsafe {
            let queue = self.raw.as_ref().q;
            if queue.is_null() {
                ptr::null_mut()
            } else {
                (*queue).queuedata.cast::<bindings::nvme_ns>()
            }
        };
        // SAFETY: The queue callback exclusively prepares this request.
        unsafe { bindings::nvme_setup_cmd(namespace, self.raw.as_ptr()) }
    }

    /// Release command resources after a preparation or mapping failure.
    #[inline]
    pub fn cleanup_command(&mut self) {
        // SAFETY: This request is still owned by the queue callback and any
        // core command resources were initialized by `setup_command`.
        unsafe { bindings::nvme_cleanup_cmd(self.raw.as_ptr()) };
    }

    /// Mark the fully prepared NVMe request in flight and arm its timeout.
    #[inline]
    pub fn start(&mut self) {
        // SAFETY: The queue callback calls this once after successful command
        // and DMA preparation and before exposing the SQ entry to hardware.
        unsafe {
            #[cfg(CONFIG_NVME_MULTIPATH)]
            if self.raw.as_ref().cmd_flags & (1u32 << bindings::req_flag_bits___REQ_DRV as u32) != 0
            {
                bindings::nvme_mpath_start_request(self.raw.as_ptr());
            }
            bindings::blk_mq_start_request(self.raw.as_ptr());
        }
    }

    /// Complete a submission failure as an NVMe host-path error.
    #[inline]
    pub fn host_path_error(&mut self) -> BlockStatus {
        // SAFETY: The request is owned by this transport and all
        // transport-specific mappings have already been unwound.
        unsafe { bindings::nvme_host_path_error(self.raw.as_ptr()) }
    }

    /// NVMe completion status stored in the core request prefix.
    #[inline]
    pub fn nvme_status(&self) -> u16 {
        // SAFETY: The request PDU prefix is initialized for its lifetime.
        unsafe { (*ptr::addr_of!((*self.pdu_ptr()).core)).status }
    }

    fn complete_core(&mut self) {
        // SAFETY: Transport completion has released its mappings and blk-mq
        // dispatched this request through the operations vtable.
        unsafe { bindings::nvme_complete_rq(self.raw.as_ptr()) };
    }

    fn complete_batch_core(&mut self) {
        // SAFETY: Same as `complete_core`, but the enclosing batch owns the
        // final `blk_mq_end_request_batch` operation.
        unsafe { bindings::nvme_complete_batch_req(self.raw.as_ptr()) };
    }
}

/// Maximum number of independently mapped DMA ranges supported by the NVMe
/// PCI transport's SGL format.
pub const MAX_DMA_SEGMENTS: usize = 256;

/// One device-visible range yielded by a request DMA iterator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct DmaSegment {
    address: dma::DmaAddress,
    length: u32,
    _padding: u32,
}

// SAFETY: `DmaSegment` contains only integers and no interior mutability.
unsafe impl FromBytes for DmaSegment {}

impl DmaSegment {
    /// Device-visible base address.
    #[inline]
    pub fn address(self) -> dma::DmaAddress {
        self.address
    }

    /// Length of this range in bytes.
    #[inline]
    pub fn length(self) -> u32 {
        self.length
    }
}

/// One directly mapped request bio vector and its original page offset.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DmaBvecSegment {
    segment: DmaSegment,
    page_offset: u32,
}

impl DmaBvecSegment {
    /// Device-visible address and length of the mapped vector.
    #[inline]
    pub fn segment(self) -> DmaSegment {
        self.segment
    }

    /// Byte offset of the vector within its source page.
    #[inline]
    pub fn page_offset(self) -> u32 {
        self.page_offset
    }
}

/// Preallocated direct-mapping unwind storage used by [`RequestDmaMapping`].
pub type DmaSegmentStorage = [DmaSegment; MAX_DMA_SEGMENTS];

/// Which part of a blk-mq request is being mapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaPayload {
    /// Request data bios.
    Data,
    /// Integrity metadata bios.
    Metadata,
}

/// Peer-to-peer address class selected by the DMA iterator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaMapKind {
    /// Ordinary DMA mapping.
    HostMemory,
    /// PCI peer memory already expressed as a bus address.
    PciBusAddress,
    /// Peer or MMIO memory mapped through the host bridge.
    ThroughHostBridge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DmaUnwindMode {
    Undecided,
    Prp,
    SglDescriptor,
    Single,
}

impl DmaMapKind {
    fn from_raw(raw: bindings::pci_p2pdma_map_type) -> Option<Self> {
        match raw {
            bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_NONE => Some(Self::HostMemory),
            bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_BUS_ADDR => Some(Self::PciBusAddress),
            bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_THRU_HOST_BRIDGE => {
                Some(Self::ThroughHostBridge)
            }
            _ => None,
        }
    }
}

/// Owned DMA state for the data or metadata of one NVMe request.
///
/// Mapping may use one coalesced IOVA, PCI peer bus addresses, MMIO through a
/// host bridge, or a sequence of ordinary DMA ranges. The last case retains a
/// typed mempool element containing every range needed for exact unmap. Drop
/// is idempotent and fails closed by removing any still-active mapping.
pub struct RequestDmaMapping<O: MqOperations> {
    request: Option<NonNull<bindings::request>>,
    // Retained while idle as well as active. Reusing a request tag on the same
    // device must not take/drop an identical device reference on every I/O.
    dev: Option<ARef<device::Device>>,
    state: bindings::dma_iova_state,
    direction: Option<dma::DataDirection>,
    payload: Option<DmaPayload>,
    single_bvec: Option<DmaSegment>,
    first_iter_segment: Option<DmaSegment>,
    map_raw: bindings::pci_p2pdma_map_type,
    direct: Option<mempool::Element<DmaSegmentStorage>>,
    direct_count: usize,
    mapped_segments: usize,
    mapped_len: usize,
    needs_direct_unwind: bool,
    unwind_mode: DmaUnwindMode,
    iteration_status: BlockStatus,
    _p: PhantomData<O>,
}

// SAFETY: An active mapping belongs to one blk-mq request/tag and all movable
// storage is heap-backed. The device, mempool, and request remain live until
// the queue completion path calls unmap.
unsafe impl<O: MqOperations> Send for RequestDmaMapping<O> {}

impl<O: MqOperations> RequestDmaMapping<O> {
    /// Create an idle reusable mapping slot for request-private storage.
    pub fn new() -> Self {
        Self {
            request: None,
            dev: None,
            state: bindings::dma_iova_state::default(),
            direction: None,
            payload: None,
            single_bvec: None,
            first_iter_segment: None,
            map_raw: bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_NONE,
            direct: None,
            direct_count: 0,
            mapped_segments: 0,
            mapped_len: 0,
            needs_direct_unwind: false,
            unwind_mode: DmaUnwindMode::Undecided,
            iteration_status: BLK_STS_OK,
            _p: PhantomData,
        }
    }

    /// Retain the DMA device until this reusable slot is destroyed. The caller
    /// has already rejected active mappings; an idle slot may change devices.
    fn cache_device(&mut self, dev: &device::Device) {
        if self.dev.as_ref().is_some_and(|cached| cached.as_raw() == dev.as_raw()) {
            return;
        }
        self.dev = Some(dev.into());
    }

    /// Map the first integrity bio vector for a direct NVMe metadata pointer.
    ///
    /// `Ok(None)` means that the vector belongs to PCI peer memory and must be
    /// mapped through the request DMA iterator instead. A successful mapping
    /// is retained by `self` and released exactly once by [`Self::unmap`].
    pub fn map_single_metadata_bvec(
        &mut self,
        request: &mut MqRequest<'_, O>,
        dev: &device::Device,
    ) -> core::result::Result<Option<DmaSegment>, BlockStatus> {
        if self.request.is_some() {
            return Err(BLK_STS_DEV_RESOURCE);
        }
        if !request.has_integrity() {
            return Err(BLK_STS_IOERR);
        }

        let raw = request.raw.as_ptr();
        // SAFETY: `raw` is a live integrity request exclusively owned by this
        // callback; the helper returns the first bio vector by value.
        let mut vector = unsafe { bindings::rq_integrity_vec(raw) };
        // SAFETY: `vector` contains the live request's page reference. The
        // helper only classifies that page and does not retain it.
        if unsafe { bindings::bvec_is_pci_p2pdma(&vector) } {
            return Ok(None);
        }
        // SAFETY: The live request fixes one valid DMA direction for the
        // complete lifetime of this mapping.
        let direction = match unsafe { bindings::rq_dma_dir(raw) } {
            bindings::dma_data_direction_DMA_BIDIRECTIONAL => dma::DataDirection::Bidirectional,
            bindings::dma_data_direction_DMA_TO_DEVICE => dma::DataDirection::ToDevice,
            bindings::dma_data_direction_DMA_FROM_DEVICE => dma::DataDirection::FromDevice,
            _ => return Err(BLK_STS_IOERR),
        };
        // SAFETY: `vector` belongs to this live request and remains valid for
        // the call; `dev` and the request's direction are retained for unmap.
        let address = unsafe {
            bindings::dma_map_bvec(dev.as_raw(), &mut vector, direction.into(), 0)
        };
        // SAFETY: The DMA API permits checking the returned address against
        // the same live device immediately after mapping.
        if unsafe { bindings::dma_mapping_error(dev.as_raw(), address) } != 0 {
            return Err(BLK_STS_IOERR);
        }

        let segment = DmaSegment {
            address,
            length: vector.bv_len,
            _padding: 0,
        };
        self.cache_device(dev);
        self.request = Some(request.raw);
        self.state = bindings::dma_iova_state::default();
        self.direction = Some(direction);
        self.payload = Some(DmaPayload::Metadata);
        self.single_bvec = Some(segment);
        self.first_iter_segment = None;
        self.map_raw = bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_NONE;
        self.direct = None;
        self.direct_count = 0;
        self.mapped_segments = 0;
        self.mapped_len = segment.length as usize;
        self.needs_direct_unwind = false;
        self.unwind_mode = DmaUnwindMode::Single;
        self.iteration_status = BLK_STS_OK;
        Ok(Some(segment))
    }

    /// Map a one-segment data request without entering the DMA iterator.
    ///
    /// `should_map` receives the original page offset and length before any
    /// DMA operation. `Ok(None)` means that predicate declined the fast path
    /// or the vector is PCI peer memory, so the caller must use the arbitrary
    /// request iterator.
    pub fn map_single_data_bvec(
        &mut self,
        request: &mut MqRequest<'_, O>,
        dev: &device::Device,
        should_map: impl FnOnce(u32, u32) -> bool,
    ) -> core::result::Result<Option<DmaBvecSegment>, BlockStatus> {
        // SAFETY: The callback exclusively owns this live request. `self` is
        // separate from the borrowed request wrapper and its private data.
        unsafe { self.map_single_data_bvec_raw(request.raw, dev, should_map) }
    }

    /// # Safety
    ///
    /// `request` must be live and exclusively owned by the queue callback.
    /// The implementation must not construct a request/data reference: its
    /// caller may already hold a mutable borrow of a field in RequestData.
    unsafe fn map_single_data_bvec_raw(
        &mut self,
        request: NonNull<bindings::request>,
        dev: &device::Device,
        should_map: impl FnOnce(u32, u32) -> bool,
    ) -> core::result::Result<Option<DmaBvecSegment>, BlockStatus> {
        if self.request.is_some() {
            return Err(BLK_STS_DEV_RESOURCE);
        }
        // SAFETY: The callback owns this live request; this accessor reads
        // only the C request header, disjoint from the private mapping slot.
        if unsafe { request_phys_segments(request.as_ptr()) } != 1 {
            return Err(BLK_STS_IOERR);
        }

        let raw = request.as_ptr();
        // SAFETY: `raw` is a live one-segment data request exclusively owned
        // by this callback; the helper returns its first bio vector by value.
        let mut vector = unsafe { bindings::req_bvec(raw) };
        if !should_map(vector.bv_offset, vector.bv_len) {
            return Ok(None);
        }
        // SAFETY: `vector` contains the live request's page reference. The
        // helper only classifies that page and does not retain it.
        if unsafe { bindings::bvec_is_pci_p2pdma(&vector) } {
            return Ok(None);
        }
        // SAFETY: The live request fixes one valid DMA direction for the
        // complete lifetime of this mapping.
        let direction = match unsafe { bindings::rq_dma_dir(raw) } {
            bindings::dma_data_direction_DMA_BIDIRECTIONAL => dma::DataDirection::Bidirectional,
            bindings::dma_data_direction_DMA_TO_DEVICE => dma::DataDirection::ToDevice,
            bindings::dma_data_direction_DMA_FROM_DEVICE => dma::DataDirection::FromDevice,
            _ => return Err(BLK_STS_IOERR),
        };
        // SAFETY: `vector` belongs to this live request and remains valid for
        // the call; `dev` and the request's direction are retained for unmap.
        let address = unsafe {
            bindings::dma_map_bvec(dev.as_raw(), &mut vector, direction.into(), 0)
        };
        // SAFETY: The DMA API permits checking the returned address against
        // the same live device immediately after mapping.
        if unsafe { bindings::dma_mapping_error(dev.as_raw(), address) } != 0 {
            return Err(BLK_STS_RESOURCE);
        }

        let segment = DmaSegment {
            address,
            length: vector.bv_len,
            _padding: 0,
        };
        self.cache_device(dev);
        self.request = Some(request);
        self.state = bindings::dma_iova_state::default();
        self.direction = Some(direction);
        self.payload = Some(DmaPayload::Data);
        self.single_bvec = Some(segment);
        self.first_iter_segment = None;
        self.map_raw = bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_NONE;
        self.direct = None;
        self.direct_count = 0;
        self.mapped_segments = 0;
        self.mapped_len = segment.length as usize;
        self.needs_direct_unwind = false;
        self.unwind_mode = DmaUnwindMode::Single;
        self.iteration_status = BLK_STS_OK;
        Ok(Some(DmaBvecSegment {
            segment,
            page_offset: vector.bv_offset,
        }))
    }

    /// Begin mapping a request payload and return its device-visible ranges.
    ///
    /// The caller selects the exact unwind representation after inspecting
    /// coalescing and choosing PRP or SGL command format. No PRP-only mempool
    /// element is consumed merely to discover the first mapped segment.
    pub fn map<'a>(
        &'a mut self,
        request: &mut MqRequest<'_, O>,
        dev: &device::Device,
        payload: DmaPayload,
    ) -> core::result::Result<RequestDmaSegments<'a, O>, BlockStatus> {
        if self.request.is_some() {
            return Err(BLK_STS_DEV_RESOURCE);
        }

        let mut iterator = bindings::blk_dma_iter::default();
        let mut state = bindings::dma_iova_state::default();
        let raw = request.raw.as_ptr();
        // SAFETY: `raw` is a live request exclusively owned by this callback;
        // `dev`, `state`, and `iterator` remain valid for the whole call.
        let mapped = unsafe {
            match payload {
                DmaPayload::Data => bindings::blk_rq_dma_map_iter_start(
                    raw,
                    dev.as_raw(),
                    &mut state,
                    &mut iterator,
                ),
                DmaPayload::Metadata => bindings::blk_rq_integrity_dma_map_iter_start(
                    raw,
                    dev.as_raw(),
                    &mut state,
                    &mut iterator,
                ),
            }
        };
        if !mapped {
            return Err(if iterator.status == BLK_STS_OK {
                BLK_STS_IOERR
            } else {
                iterator.status
            });
        }
        let Some(map_kind) = DmaMapKind::from_raw(iterator.p2pdma.map) else {
            return Err(BLK_STS_RESOURCE);
        };
        // SAFETY: The request operation fixes one valid DMA direction for its
        // complete mapping lifetime.
        let direction = match unsafe { bindings::rq_dma_dir(raw) } {
            bindings::dma_data_direction_DMA_BIDIRECTIONAL => dma::DataDirection::Bidirectional,
            bindings::dma_data_direction_DMA_TO_DEVICE => dma::DataDirection::ToDevice,
            bindings::dma_data_direction_DMA_FROM_DEVICE => dma::DataDirection::FromDevice,
            _ => return Err(BLK_STS_IOERR),
        };
        // SAFETY: `state` was initialized by the successful iterator start;
        // the query functions do not mutate the mapping.
        let needs_direct_unwind = unsafe {
            map_kind != DmaMapKind::PciBusAddress
                && !bindings::dma_use_iova(&mut state)
                && bindings::dma_need_unmap(dev.as_raw())
        };

        self.cache_device(dev);
        self.request = Some(request.raw);
        self.state = state;
        self.direction = Some(direction);
        self.payload = Some(payload);
        self.single_bvec = None;
        self.first_iter_segment = None;
        self.map_raw = iterator.p2pdma.map;
        self.direct = None;
        self.direct_count = 0;
        self.mapped_segments = 0;
        self.mapped_len = 0;
        self.needs_direct_unwind = needs_direct_unwind;
        self.unwind_mode = DmaUnwindMode::Undecided;
        self.iteration_status = BLK_STS_OK;

        let first = DmaSegment {
            address: iterator.addr,
            length: iterator.len,
            _padding: 0,
        };
        self.first_iter_segment = Some(first);
        self.mapped_segments = 1;
        self.mapped_len = first.length as usize;
        Ok(RequestDmaSegments {
            mapping: self,
            iterator,
            payload,
            first: Some(first),
            ended: false,
        })
    }

    fn record(&mut self, segment: DmaSegment) -> bool {
        let Some(total) = self.mapped_len.checked_add(segment.length as usize) else {
            return false;
        };
        let Some(count) = self.mapped_segments.checked_add(1) else {
            return false;
        };
        if self.needs_direct_unwind
            && self.unwind_mode == DmaUnwindMode::Prp
            && self.direct.is_none()
        {
            return false;
        }
        if let Some(storage) = self.direct.as_mut() {
            if self.direct_count == storage.len() {
                return false;
            }
            storage[self.direct_count] = segment;
            self.direct_count += 1;
        }
        self.mapped_len = total;
        self.mapped_segments = count;
        true
    }

    /// Whether this slot currently owns a DMA mapping.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.request.is_some()
    }

    /// Address class selected for the active mapping.
    pub fn map_kind(&self) -> Option<DmaMapKind> {
        self.request
            .is_some()
            .then(|| DmaMapKind::from_raw(self.map_raw))
            .flatten()
    }

    /// Total bytes successfully mapped by the iterator so far.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.mapped_len
    }

    /// Final block status produced while advancing the iterator.
    #[inline]
    pub fn iteration_status(&self) -> BlockStatus {
        self.iteration_status
    }

    /// Whether an active multi-range mapping must be unwound through the SGL
    /// descriptor that owns its exact device-visible ranges.
    #[inline]
    pub fn requires_sgl_descriptor(&self) -> bool {
        self.request.is_some() && self.unwind_mode == DmaUnwindMode::SglDescriptor
    }

    fn clear_mapping_state(&mut self) {
        self.request = None;
        // Keep the device reference for the next use of this request slot.
        // DMA mappings and all descriptor resources are still released now.
        self.state = bindings::dma_iova_state::default();
        self.direction = None;
        self.payload = None;
        self.single_bvec = None;
        self.first_iter_segment = None;
        self.map_raw = bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_NONE;
        self.direct = None;
        self.direct_count = 0;
        self.mapped_segments = 0;
        self.mapped_len = 0;
        self.needs_direct_unwind = false;
        self.unwind_mode = DmaUnwindMode::Undecided;
        self.iteration_status = BLK_STS_OK;
    }

    /// Remove a multi-range SGL mapping using the descriptor that was filled
    /// from its iterator. Calling this on an idle slot is a no-op.
    pub fn unmap_sgl<const N: usize>(&mut self, descriptor: &Descriptor<N>) {
        if self.unwind_mode != DmaUnwindMode::SglDescriptor {
            self.unmap();
            return;
        }
        let Some(active_request) = self.request else {
            return;
        };
        if descriptor.sgl_request != active_request.as_ptr() as usize
            || descriptor.sgl_payload != self.payload
        {
            return;
        }
        let (Some(request), Some(dev), Some(direction)) =
            (self.request.take(), self.dev.as_ref(), self.direction.take())
        else {
            return;
        };
        // SAFETY: These are the exact values retained from the successful map.
        // A false return means every direct range must be recovered from the
        // driver-owned SGL descriptor before that descriptor is released.
        let finished = unsafe {
            bindings::blk_rq_dma_unmap(
                request.as_ptr(),
                dev.as_raw(),
                &mut self.state,
                self.mapped_len,
                self.map_raw,
            )
        };
        if !finished {
            let mut total = 0usize;
            let mut valid = descriptor.sgl_data_count == self.mapped_segments;
            for ordinal in 0..descriptor.sgl_data_count {
                let Some(segment) = descriptor.sgl_data_segment(ordinal) else {
                    valid = false;
                    break;
                };
                let Some(next) = total.checked_add(segment.length as usize) else {
                    valid = false;
                    break;
                };
                total = next;
            }
            valid &= total == self.mapped_len;
            if valid {
                let attrs = if self.map_raw
                    == bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_THRU_HOST_BRIDGE
                {
                    bindings::DMA_ATTR_MMIO as usize
                } else {
                    0
                };
                for ordinal in 0..descriptor.sgl_data_count {
                    if let Some(segment) = descriptor.sgl_data_segment(ordinal) {
                        // SAFETY: Every tracked entry was written from this
                        // mapping's iterator, and the count and total length
                        // were validated before any range was removed.
                        unsafe {
                            bindings::dma_unmap_phys(
                                dev.as_raw(),
                                segment.address,
                                segment.length as usize,
                                direction.into(),
                                attrs,
                            )
                        };
                    }
                }
            }
        }
        self.clear_mapping_state();
    }

    /// Remove the mapping exactly once. Calling this on an idle slot is a
    /// no-op.
    pub fn unmap(&mut self) {
        let (Some(request), Some(dev), Some(direction)) =
            (self.request.take(), self.dev.as_ref(), self.direction.take())
        else {
            return;
        };
        if let Some(segment) = self.single_bvec.take() {
            // SAFETY: This is the exact address, length, device and direction
            // returned by `dma_map_bvec`, and it has not yet been unmapped.
            unsafe {
                bindings::dma_unmap_page(
                    dev.as_raw(),
                    segment.address,
                    segment.length,
                    direction.into(),
                    0,
                )
            };
            self.clear_mapping_state();
            return;
        }
        // SAFETY: These are the exact values retained from the successful map.
        // The helper handles peer-bus, IOVA, and no-unmap platforms. A false
        // return requires explicit unmap of the recorded direct ranges.
        let finished = unsafe {
            bindings::blk_rq_dma_unmap(
                request.as_ptr(),
                dev.as_raw(),
                &mut self.state,
                self.mapped_len,
                self.map_raw,
            )
        };
        if !finished {
            let attrs =
                if self.map_raw == bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_THRU_HOST_BRIDGE {
                    bindings::DMA_ATTR_MMIO as usize
                } else {
                    0
                };
            if let Some(storage) = self.direct.as_ref() {
                for segment in &storage[..self.direct_count] {
                    // SAFETY: Each range was returned by the iterator for this
                    // exact device/direction and has not yet been unmapped.
                    unsafe {
                        bindings::dma_unmap_phys(
                            dev.as_raw(),
                            segment.address,
                            segment.length as usize,
                            direction.into(),
                            attrs,
                        )
                    };
                }
            } else if self.mapped_segments == 1 {
                if let Some(segment) = self.first_iter_segment {
                    // SAFETY: A single-range SGL or MPTR mapping retains the
                    // exact first iterator result and has no later ranges.
                    unsafe {
                        bindings::dma_unmap_phys(
                            dev.as_raw(),
                            segment.address,
                            segment.length as usize,
                            direction.into(),
                            attrs,
                        )
                    };
                }
            }
        }
        self.clear_mapping_state();
    }
}

impl<O: MqOperations> Default for RequestDmaMapping<O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O: MqOperations> Drop for RequestDmaMapping<O> {
    fn drop(&mut self) {
        self.unmap();
    }
}

/// Iterator over the mapped device ranges of one request payload.
pub struct RequestDmaSegments<'a, O: MqOperations> {
    mapping: &'a mut RequestDmaMapping<O>,
    iterator: bindings::blk_dma_iter,
    payload: DmaPayload,
    first: Option<DmaSegment>,
    ended: bool,
}

impl<O: MqOperations> RequestDmaSegments<'_, O> {
    /// Whether all physical ranges were coalesced into the first IOVA range.
    #[inline]
    pub fn is_coalesced(&mut self) -> bool {
        // SAFETY: The mapping state remains live and initialized while the
        // iterator borrows it exclusively.
        unsafe { bindings::blk_rq_dma_map_coalesce(&mut self.mapping.state) }
    }

    /// Final iterator status. This is meaningful after `next()` returned
    /// `None`.
    #[inline]
    pub fn status(&self) -> BlockStatus {
        self.mapping.iteration_status
    }

    /// Select PRP unwind ownership before advancing beyond the first mapped
    /// range. Direct-mapped platforms reserve the same bounded mempool element
    /// used by the C transport; IOVA, peer-bus, and no-unmap platforms do not.
    pub fn prepare_prp_unwind(
        &mut self,
        unwind_pool: &Arc<mempool::Mempool<DmaSegmentStorage>>,
        flags: crate::alloc::Flags,
    ) -> core::result::Result<(), BlockStatus> {
        if self.mapping.unwind_mode != DmaUnwindMode::Undecided {
            return Err(BLK_STS_IOERR);
        }
        self.mapping.unwind_mode = DmaUnwindMode::Prp;
        if !self.mapping.needs_direct_unwind {
            return Ok(());
        }
        let mut unwind = unwind_pool
            .allocate(flags)
            .map_err(|_| BLK_STS_RESOURCE)?;
        let Some(first) = self.mapping.first_iter_segment else {
            return Err(BLK_STS_IOERR);
        };
        unwind[0] = first;
        self.mapping.direct_count = 1;
        self.mapping.direct = Some(unwind);
        Ok(())
    }

    /// Select descriptor-backed SGL unwind ownership before advancing beyond
    /// the first mapped range.
    pub fn prepare_sgl_unwind<const N: usize>(
        &mut self,
        descriptor: &mut Descriptor<N>,
    ) -> core::result::Result<(), BlockStatus> {
        if self.mapping.unwind_mode != DmaUnwindMode::Undecided
            || descriptor.sgl_data_count != 0
            || descriptor.sgl_request != 0
            || descriptor.sgl_payload.is_some()
        {
            return Err(BLK_STS_IOERR);
        }
        let Some(request) = self.mapping.request else {
            return Err(BLK_STS_IOERR);
        };
        descriptor.sgl_request = request.as_ptr() as usize;
        descriptor.sgl_payload = Some(self.payload);
        self.mapping.unwind_mode = DmaUnwindMode::SglDescriptor;
        Ok(())
    }

    /// Finish a direct SGL or MPTR mapping that consumes only the first range,
    /// exactly like the corresponding C fast path.
    pub fn finish_single(&mut self) -> core::result::Result<(), BlockStatus> {
        if self.mapping.unwind_mode != DmaUnwindMode::Undecided
            || self.mapping.mapped_segments != 1
        {
            return Err(BLK_STS_IOERR);
        }
        self.mapping.unwind_mode = DmaUnwindMode::Single;
        self.mapping.iteration_status = BLK_STS_OK;
        self.ended = true;
        Ok(())
    }

    /// Validate that an exhausted SGL iterator is represented exactly by the
    /// descriptor retained for completion-time unwind.
    pub fn finish_sgl<const N: usize>(
        &mut self,
        descriptor: &Descriptor<N>,
    ) -> core::result::Result<(), BlockStatus> {
        if self.mapping.unwind_mode != DmaUnwindMode::SglDescriptor
            || !self.ended
            || self.mapping.iteration_status != BLK_STS_OK
            || descriptor.sgl_data_count != self.mapping.mapped_segments
            || descriptor.sgl_request
                != self.mapping.request.map_or(0, |request| request.as_ptr() as usize)
            || descriptor.sgl_payload != self.mapping.payload
        {
            return Err(BLK_STS_IOERR);
        }
        let mut total = 0usize;
        for ordinal in 0..descriptor.sgl_data_count {
            let segment = descriptor
                .sgl_data_segment(ordinal)
                .ok_or(BLK_STS_IOERR)?;
            total = total
                .checked_add(segment.length as usize)
                .ok_or(BLK_STS_IOERR)?;
        }
        if total != self.mapping.mapped_len {
            return Err(BLK_STS_IOERR);
        }
        Ok(())
    }

    /// Unwind a partially or fully constructed descriptor-backed SGL mapping.
    pub fn unmap_sgl<const N: usize>(&mut self, descriptor: &Descriptor<N>) {
        self.ended = true;
        self.mapping.unmap_sgl(descriptor);
    }
}

impl<O: MqOperations> Iterator for RequestDmaSegments<'_, O> {
    type Item = DmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first) = self.first.take() {
            return Some(first);
        }
        if self.ended {
            return None;
        }
        if self.mapping.unwind_mode == DmaUnwindMode::Undecided
            || self.mapping.mapped_segments == MAX_DMA_SEGMENTS
        {
            self.ended = true;
            self.mapping.iteration_status = BLK_STS_IOERR;
            return None;
        }
        let request = self.mapping.request?;
        let dev = self.mapping.dev.as_ref()?;
        let dev_raw = dev.as_raw();
        // SAFETY: The iterator, mapping state, request, and device are the
        // exact objects initialized by `map` and remain exclusively borrowed.
        let mapped = unsafe {
            match self.payload {
                DmaPayload::Data => bindings::blk_rq_dma_map_iter_next(
                    request.as_ptr(),
                    dev_raw,
                    &mut self.mapping.state,
                    &mut self.iterator,
                ),
                DmaPayload::Metadata => bindings::blk_rq_integrity_dma_map_iter_next(
                    request.as_ptr(),
                    dev_raw,
                    &mut self.iterator,
                ),
            }
        };
        if !mapped {
            self.ended = true;
            self.mapping.iteration_status = self.iterator.status;
            return None;
        }
        let segment = DmaSegment {
            address: self.iterator.addr,
            length: self.iterator.len,
            _padding: 0,
        };
        if !self.mapping.record(segment) {
            // This just-mapped range was not admitted to unwind storage, so
            // remove it immediately before reporting the bounded-storage
            // failure. Earlier ranges remain owned by `mapping`.
            if self.mapping.direct.is_some() {
                let attrs = if self.mapping.map_raw
                    == bindings::pci_p2pdma_map_type_PCI_P2PDMA_MAP_THRU_HOST_BRIDGE
                {
                    bindings::DMA_ATTR_MMIO as usize
                } else {
                    0
                };
                if let Some(direction) = self.mapping.direction {
                    // SAFETY: This range was mapped by the immediately
                    // preceding iterator call and was not stored elsewhere.
                    unsafe {
                        bindings::dma_unmap_phys(
                            dev_raw,
                            segment.address,
                            segment.length as usize,
                            direction.into(),
                            attrs,
                        )
                    };
                }
            }
            self.ended = true;
            self.mapping.iteration_status = BLK_STS_IOERR;
            return None;
        }
        Some(segment)
    }
}

impl<O: MqOperations> Drop for RequestDmaSegments<'_, O> {
    fn drop(&mut self) {
        if !self.ended {
            // A caller that abandons iteration cannot safely submit a partial
            // descriptor chain. Preserve the mapping for RAII unwind but mark
            // the preparation result as failed.
            self.mapping.iteration_status = BLK_STS_IOERR;
        }
    }
}

/// Result of attempting to dispatch one request from a blk-mq batch.
pub enum BatchRequestDisposition {
    /// The callback started and submitted the detached request.
    Submitted,
    /// Return the detached request to blk-mq for a later dispatch attempt.
    Requeue,
}

/// A mutable blk-mq request list passed to a batch submission callback.
pub struct RequestList<'a, O: MqOperations> {
    raw: NonNull<bindings::rq_list>,
    _p: PhantomData<(&'a mut bindings::rq_list, O)>,
}

impl<'a, O: MqOperations> RequestList<'a, O> {
    unsafe fn from_raw(raw: *mut bindings::rq_list) -> Option<Self> {
        NonNull::new(raw).map(|raw| Self {
            raw,
            _p: PhantomData,
        })
    }

    /// Whether the list contains no requests.
    #[inline]
    pub fn is_empty(&self) -> bool {
        // SAFETY: `raw` is the live list borrowed by this callback.
        unsafe { self.raw.as_ref().head.is_null() }
    }

    /// Remove and return the first request.
    pub fn pop_front(&mut self) -> Option<MqRequest<'a, O>> {
        // SAFETY: `raw` is exclusively borrowed by this wrapper.
        let list = unsafe { self.raw.as_mut() };
        let request = list.head;
        if request.is_null() {
            return None;
        }

        // SAFETY: A request on an `rq_list` has an initialized `rq_next`
        // union member. We unlink it before returning the callback borrow.
        let next = unsafe { (*request).__bindgen_anon_1.rq_next };
        list.head = next;
        if next.is_null() {
            list.tail = ptr::null_mut();
        }
        // SAFETY: The removed request is exclusively owned by this list
        // callback until it is submitted or returned to a list.
        unsafe { (*request).__bindgen_anon_1.rq_next = ptr::null_mut() };
        // SAFETY: `request` was a non-NULL member of the live list.
        unsafe { MqRequest::from_raw(request) }
    }

    /// Append a removed request to the list.
    pub fn push_back(&mut self, request: MqRequest<'a, O>) {
        let request = request.raw.as_ptr();
        // SAFETY: The token represents a request currently detached from an
        // `rq_list`; this wrapper owns the destination list.
        unsafe { (*request).__bindgen_anon_1.rq_next = ptr::null_mut() };
        // SAFETY: `raw` is exclusively borrowed by this wrapper.
        let list = unsafe { self.raw.as_mut() };
        if list.tail.is_null() {
            list.head = request;
        } else {
            // SAFETY: A non-NULL tail is a request in this live list.
            unsafe { (*list.tail).__bindgen_anon_1.rq_next = request };
        }
        list.tail = request;
    }

    /// Insert a removed request at the front of the list.
    pub fn push_front(&mut self, request: MqRequest<'a, O>) {
        let request = request.raw.as_ptr();
        // SAFETY: The token is detached and `raw` is exclusively borrowed.
        let list = unsafe { self.raw.as_mut() };
        unsafe { (*request).__bindgen_anon_1.rq_next = list.head };
        list.head = request;
        if list.tail.is_null() {
            list.tail = request;
        }
    }

    /// Drain the complete input list and retain each failed dispatch for requeue.
    ///
    /// Requests returned as [`BatchRequestDisposition::Requeue`] preserve their
    /// input order. Successfully submitted requests remain detached from the
    /// list, and the callback continues with every later request.
    pub fn dispatch_all(
        &mut self,
        mut dispatch: impl FnMut(&mut MqRequest<'a, O>) -> BatchRequestDisposition,
    ) {
        let mut requeue = bindings::rq_list::default();
        while let Some(mut request) = self.pop_front() {
            if matches!(dispatch(&mut request), BatchRequestDisposition::Submitted) {
                continue;
            }

            let request = request.raw.as_ptr();
            // SAFETY: `request` is detached from the input list, and
            // `requeue` is private to this exclusive list operation.
            unsafe { (*request).__bindgen_anon_1.rq_next = ptr::null_mut() };
            if requeue.tail.is_null() {
                requeue.head = request;
            } else {
                // SAFETY: The non-NULL tail belongs to the private requeue
                // list and may be linked to this detached request.
                unsafe { (*requeue.tail).__bindgen_anon_1.rq_next = request };
            }
            requeue.tail = request;
        }

        // SAFETY: `self` exclusively owns the now-empty input list, and all
        // nodes in `requeue` were detached from that same list above.
        unsafe { *self.raw.as_ptr() = requeue };
    }
}

/// Completion accumulator supplied by blk-mq polling or an IRQ handler.
#[repr(transparent)]
pub struct CompletionBatch<O: MqOperations>(bindings::io_comp_batch, PhantomData<O>);

impl<O: MqOperations> CompletionBatch<O> {
    /// Create an empty completion batch for an interrupt handler.
    pub fn new() -> Self {
        Self(bindings::io_comp_batch::default(), PhantomData)
    }

    /// Whether no request has been appended to this batch.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.req_list.head.is_null()
    }

    /// Finish every request currently accumulated in the batch.
    ///
    /// This is normally called once after an IRQ-side CQ polling loop. A batch
    /// supplied by blk-mq polling is completed by the block layer instead.
    pub fn finish(&mut self) {
        if self.is_empty() {
            return;
        }
        // SAFETY: This batch is typed for `O`; the callback releases each
        // transport mapping, performs NVMe batch completion, then ends it.
        unsafe { MqOperationsVTable::<O>::complete_batch_callback(&raw mut self.0) };
    }

    #[inline]
    fn as_raw(&mut self) -> *mut bindings::io_comp_batch {
        &raw mut self.0
    }
}

impl<O: MqOperations> Default for CompletionBatch<O> {
    fn default() -> Self {
        Self::new()
    }
}

/// One CPU-to-hardware-queue mapping in a tag set.
#[repr(transparent)]
pub struct QueueMap(bindings::blk_mq_queue_map);

impl QueueMap {
    /// Number of hardware queues represented by this map.
    #[inline]
    pub fn nr_queues(&self) -> u32 {
        self.0.nr_queues
    }

    /// First hardware queue number represented by this map.
    #[inline]
    pub fn queue_offset(&self) -> u32 {
        self.0.queue_offset
    }

    /// Configure the queue count and offset before generating the CPU map.
    #[inline]
    pub fn configure(&mut self, nr_queues: u32, queue_offset: u32) {
        self.0.nr_queues = nr_queues;
        self.0.queue_offset = queue_offset;
    }

    /// Generate the regular blk-mq CPU mapping.
    #[inline]
    pub fn map_cpus(&mut self) {
        // SAFETY: This map belongs to a tag set currently in its map callback.
        unsafe { bindings::blk_mq_map_queues(&raw mut self.0) };
    }

    /// Generate an interrupt-affinity-aware mapping for `device`.
    #[inline]
    pub fn map_device<Ctx: device::DeviceContext>(
        &mut self,
        device: &device::Device<Ctx>,
        vector_offset: u32,
    ) {
        // SAFETY: The map is live for the callback and `device` is a live
        // kernel device. The block core initializes the map's CPU array.
        unsafe { bindings::blk_mq_map_hw_queues(&raw mut self.0, device.as_raw(), vector_offset) };
    }
}

/// Mutable view of the queue maps in an NVMe I/O tag set.
pub struct QueueMaps<'a> {
    set: NonNull<bindings::blk_mq_tag_set>,
    _p: PhantomData<&'a mut bindings::blk_mq_tag_set>,
}

impl QueueMaps<'_> {
    unsafe fn from_raw(set: *mut bindings::blk_mq_tag_set) -> Option<Self> {
        NonNull::new(set).map(|set| Self {
            set,
            _p: PhantomData,
        })
    }

    /// Number of active maps.
    #[inline]
    pub fn len(&self) -> usize {
        // SAFETY: `set` is live for the map callback.
        unsafe { self.set.as_ref().nr_maps as usize }
    }

    /// Whether the tag set has no queue maps.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Mutably borrow one active map.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut QueueMap> {
        if index >= self.len() || index >= bindings::hctx_type_HCTX_MAX_TYPES as usize {
            return None;
        }
        // SAFETY: The bounds check limits `index` to the fixed map array and
        // this wrapper exclusively borrows the tag set for the callback.
        let map = unsafe { &mut self.set.as_mut().map[index] };
        // SAFETY: `QueueMap` is transparent over the binding type.
        Some(unsafe { &mut *(map as *mut bindings::blk_mq_queue_map).cast::<QueueMap>() })
    }
}

/// Operations implemented by an NVMe transport's blk-mq queues.
///
/// Unlike the general Rust blk-mq abstraction, this interface preserves the
/// NVMe core's mandatory request-PDU prefix and recovers transport ownership
/// from `nvme_ctrl`. Queue and request data are therefore typed without adding
/// a refcount or driver pointer to the C-visible prefix.
pub trait MqOperations: Send + Sync + Sized + 'static {
    /// NVMe transport state that owns these queues.
    type Transport: Operations;

    /// Per-request transport data stored after the core request and command.
    ///
    /// blk-mq transfers exclusive ownership of a request to each transport
    /// callback, so this data may move between CPUs but is never shared
    /// concurrently. Requiring `Sync` here would reject owned DMA mappings,
    /// whose unmap state is intentionally single-owner.
    type RequestData: Send + 'static;

    /// State associated with one hardware queue.
    type HctxData: Send + Sync + 'static;

    /// Install the batch-submission callback.
    const HAS_QUEUE_RQS: bool = false;

    /// Install the deferred-doorbell callback.
    const HAS_COMMIT_RQS: bool = false;

    /// Install the polling callback.
    const HAS_POLL: bool = false;

    /// Install the queue-map callback.
    const HAS_MAP_QUEUES: bool = false;

    /// Resolve the typed queue for a newly created blk-mq hardware context.
    ///
    /// The returned object must be stored within `transport` (or otherwise
    /// live until this tag set is removed).
    fn init_hctx<'a>(
        transport: &'a Self::Transport,
        parent: &device::Device<device::Bound>,
        hctx_index: u32,
        numa_node: u32,
    ) -> Result<&'a Self::HctxData>;

    /// Construct transport-private data for one request allocation.
    fn init_request_data(
        transport: &Self::Transport,
        hctx_index: u32,
        numa_node: u32,
    ) -> Result<Self::RequestData>;

    /// Submit one request.
    fn queue_rq(
        hctx: &Self::HctxData,
        request: &mut MqRequest<'_, Self>,
        last: bool,
    ) -> BlockStatus;

    /// Submit a batch of requests, leaving requests that were not accepted in
    /// `requests` for blk-mq to submit individually.
    fn queue_rqs(_requests: &mut RequestList<'_, Self>) {}

    /// Commit requests whose doorbell was deferred by [`MqOperations::queue_rq`].
    fn commit_rqs(_hctx: &Self::HctxData) {}

    /// Finish an asynchronously completed request.
    fn complete(request: &mut MqRequest<'_, Self>);

    /// Handle a request timeout.
    fn timeout(request: &mut MqRequest<'_, Self>) -> TimeoutAction;

    /// Poll one hardware queue for completions.
    fn poll(_hctx: &Self::HctxData, _batch: Option<&mut CompletionBatch<Self>>) -> c_int {
        0
    }

    /// Configure CPU-to-hardware-queue mappings.
    fn map_queues(_transport: &Self::Transport, _maps: &mut QueueMaps<'_>) {}
}

struct MqOperationsVTable<O: MqOperations>(PhantomData<O>);

impl<O: MqOperations> MqOperationsVTable<O> {
    unsafe extern "C" fn queue_rq_callback(
        hctx: *mut bindings::blk_mq_hw_ctx,
        data: *const bindings::blk_mq_queue_data,
    ) -> bindings::blk_status_t {
        if hctx.is_null() || data.is_null() {
            return BLK_STS_IOERR;
        }
        // SAFETY: blk-mq supplies live callback arguments.
        let hctx_data = unsafe { (*hctx).driver_data.cast::<O::HctxData>().as_ref() };
        // SAFETY: `data` is live for this callback.
        let Some(mut request) = (unsafe { MqRequest::<O>::from_raw((*data).rq) }) else {
            return BLK_STS_IOERR;
        };
        let Some(hctx_data) = hctx_data else {
            return BLK_STS_IOERR;
        };
        // SAFETY: `data` is live for this callback.
        O::queue_rq(hctx_data, &mut request, unsafe { (*data).last })
    }

    unsafe extern "C" fn queue_rqs_callback(list: *mut bindings::rq_list) {
        // SAFETY: blk-mq supplies exclusive access to the live request list.
        if let Some(mut list) = unsafe { RequestList::<O>::from_raw(list) } {
            O::queue_rqs(&mut list);
        }
    }

    unsafe extern "C" fn commit_rqs_callback(hctx: *mut bindings::blk_mq_hw_ctx) {
        if hctx.is_null() {
            return;
        }
        // SAFETY: blk-mq invokes this only between hctx init and exit.
        if let Some(data) = unsafe { (*hctx).driver_data.cast::<O::HctxData>().as_ref() } {
            O::commit_rqs(data);
        }
    }

    unsafe extern "C" fn complete_callback(request: *mut bindings::request) {
        // SAFETY: blk-mq supplies the live completed request.
        if let Some(mut request) = unsafe { MqRequest::<O>::from_raw(request) } {
            O::complete(&mut request);
            request.complete_core();
        }
    }

    unsafe extern "C" fn complete_batch_callback(batch: *mut bindings::io_comp_batch) {
        if batch.is_null() {
            return;
        }
        // SAFETY: The batch owns a linked list of live completed requests.
        let mut raw = unsafe { (*batch).req_list.head };
        while !raw.is_null() {
            // Read the link before core completion may repurpose request state.
            // SAFETY: `raw` is the current member of the batch request list.
            let next = unsafe { (*raw).__bindgen_anon_1.rq_next };
            // SAFETY: Every request admitted to this batch uses `O`'s tagset.
            if let Some(mut request) = unsafe { MqRequest::<O>::from_raw(raw) } {
                O::complete(&mut request);
                request.complete_batch_core();
            }
            raw = next;
        }
        // SAFETY: All requests have undergone NVMe batch completion; blk-mq
        // now owns the final list completion and accounting operation.
        unsafe { bindings::blk_mq_end_request_batch(batch) };
    }

    unsafe extern "C" fn timeout_callback(
        request: *mut bindings::request,
    ) -> bindings::blk_eh_timer_return {
        // SAFETY: blk-mq supplies a live timed-out request.
        unsafe { MqRequest::<O>::from_raw(request) }
            .map(|mut request| O::timeout(&mut request).as_raw())
            .unwrap_or(bindings::blk_eh_timer_return_BLK_EH_DONE)
    }

    unsafe extern "C" fn poll_callback(
        hctx: *mut bindings::blk_mq_hw_ctx,
        batch: *mut bindings::io_comp_batch,
    ) -> c_int {
        if hctx.is_null() {
            return 0;
        }
        // SAFETY: blk-mq invokes this only between hctx init and exit.
        let Some(data) = (unsafe { (*hctx).driver_data.cast::<O::HctxData>().as_ref() }) else {
            return 0;
        };
        // SAFETY: `CompletionBatch` is transparent and a non-NULL `batch` is
        // exclusively borrowed for this polling callback.
        let batch = unsafe { batch.cast::<CompletionBatch<O>>().as_mut() };
        O::poll(data, batch)
    }

    unsafe extern "C" fn init_hctx_callback(
        hctx: *mut bindings::blk_mq_hw_ctx,
        data: *mut c_void,
        hctx_index: u32,
    ) -> c_int {
        if hctx.is_null() || data.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: NVMe core stores its live controller in tagset driver_data.
        let Some(owner) = (unsafe {
            Controller::<O::Transport>::owner_from_raw(data.cast::<bindings::nvme_ctrl>())
        }) else {
            return ENODEV.to_errno();
        };
        // SAFETY: Hardware contexts are initialized only while the transport's
        // tag set is live. Tag-set removal completes before bus unbind can
        // release the parent, so it remains bound for this callback.
        let parent = unsafe {
            bindings::nvme_ctrl_parent_device(data.cast::<bindings::nvme_ctrl>())
        };
        let Some(parent) = NonNull::new(parent) else {
            return ENODEV.to_errno();
        };
        // SAFETY: The tag-set lifetime above proves the Bound context, and the
        // reference does not escape the init callback.
        let parent = unsafe { device::Device::<device::Bound>::from_raw(parent.as_ptr()) };
        // SAFETY: `hctx` is writable during its init callback.
        let numa_node = unsafe { (*hctx).numa_node };
        match O::init_hctx(&owner, parent, hctx_index, numa_node) {
            Ok(queue) => {
                // SAFETY: The trait contract keeps `queue` live through hctx
                // teardown, and blk-mq owns this field during initialization.
                unsafe { (*hctx).driver_data = ptr::from_ref(queue).cast_mut().cast() };
                0
            }
            Err(error) => error.to_errno(),
        }
    }

    unsafe extern "C" fn init_request_callback(
        set: *mut bindings::blk_mq_tag_set,
        request: *mut bindings::request,
        hctx_index: u32,
        numa_node: u32,
    ) -> c_int {
        if set.is_null() || request.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: NVMe core initializes driver_data to its live controller.
        let ctrl = unsafe { (*set).driver_data.cast::<bindings::nvme_ctrl>() };
        if ctrl.is_null() {
            return ENODEV.to_errno();
        }
        // SAFETY: The tag set belongs to `O::Transport`.
        let Some(owner) = (unsafe { Controller::<O::Transport>::owner_from_raw(ctrl) }) else {
            return ENODEV.to_errno();
        };
        let data = match O::init_request_data(&owner, hctx_index, numa_node) {
            Ok(data) => data,
            Err(error) => return error.to_errno(),
        };

        // SAFETY: TagSet reserved a PDU of this exact type after `request`.
        let pdu =
            unsafe { bindings::blk_mq_rq_to_pdu(request) }.cast::<RequestPdu<O::RequestData>>();
        let core = unsafe { ptr::addr_of_mut!((*pdu).core) };
        let command = unsafe { ptr::addr_of_mut!((*pdu).command) };
        let private = unsafe { ptr::addr_of_mut!((*pdu).data) };
        // SAFETY: These PDU fields are uninitialized, writable storage. The
        // first two are plain C data whose zero representation is valid.
        unsafe {
            core.write(core::mem::zeroed());
            command.write(Command(core::mem::zeroed()));
            (*core).ctrl = ctrl;
            (*core).cmd = (*command).as_raw();
            private.write(data);
        }
        0
    }

    unsafe extern "C" fn exit_request_callback(
        _set: *mut bindings::blk_mq_tag_set,
        request: *mut bindings::request,
        _hctx_index: u32,
    ) {
        if request.is_null() {
            return;
        }
        // SAFETY: A successful init callback constructed exactly one data
        // value, and blk-mq calls exit exactly once before freeing the PDU.
        let pdu =
            unsafe { bindings::blk_mq_rq_to_pdu(request) }.cast::<RequestPdu<O::RequestData>>();
        unsafe { ptr::drop_in_place(ptr::addr_of_mut!((*pdu).data)) };
    }

    unsafe extern "C" fn map_queues_callback(set: *mut bindings::blk_mq_tag_set) {
        // SAFETY: blk-mq supplies the live tag set exclusively for mapping.
        let Some(mut maps) = (unsafe { QueueMaps::from_raw(set) }) else {
            return;
        };
        // SAFETY: NVMe core initializes driver_data to its live controller.
        let ctrl = unsafe {
            set.as_ref()
                .unwrap()
                .driver_data
                .cast::<bindings::nvme_ctrl>()
        };
        if ctrl.is_null() {
            return;
        }
        // SAFETY: This vtable is only installed for `O::Transport`.
        if let Some(owner) = unsafe { Controller::<O::Transport>::owner_from_raw(ctrl) } {
            O::map_queues(&owner, &mut maps);
        }
    }

    const VTABLE: bindings::blk_mq_ops = bindings::blk_mq_ops {
        queue_rq: Some(Self::queue_rq_callback),
        commit_rqs: if O::HAS_COMMIT_RQS {
            Some(Self::commit_rqs_callback)
        } else {
            None
        },
        queue_rqs: if O::HAS_QUEUE_RQS {
            Some(Self::queue_rqs_callback)
        } else {
            None
        },
        get_budget: None,
        put_budget: None,
        set_rq_budget_token: None,
        get_rq_budget_token: None,
        timeout: Some(Self::timeout_callback),
        poll: if O::HAS_POLL {
            Some(Self::poll_callback)
        } else {
            None
        },
        complete: Some(Self::complete_callback),
        init_hctx: Some(Self::init_hctx_callback),
        exit_hctx: None,
        init_request: Some(Self::init_request_callback),
        exit_request: Some(Self::exit_request_callback),
        cleanup_rq: None,
        busy: None,
        map_queues: if O::HAS_MAP_QUEUES {
            Some(Self::map_queues_callback)
        } else {
            None
        },
        #[cfg(CONFIG_BLK_DEBUG_FS)]
        show_rq: None,
    };

    const fn build() -> &'static bindings::blk_mq_ops {
        &Self::VTABLE
    }
}

const TAGSET_EMPTY: u8 = 0;
const TAGSET_ALLOCATING: u8 = 1;
const TAGSET_ADMIN: u8 = 2;
const TAGSET_IO: u8 = 3;
const TAGSET_REMOVING: u8 = 4;

/// Result of resolving and dispatching one completion queue entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDisposition {
    /// The command identifier did not name a live request in this tag set.
    InvalidCommandId,
    /// The request was completed directly, queued remotely, or added to the
    /// supplied completion batch.
    Handled,
}

/// Submission-queue position recorded by a completion entry.
///
/// Both values are in native byte order. The head is the controller's view
/// from the completion entry, while the tail is the host's current producer
/// position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmissionQueuePosition {
    head: u16,
    tail: u16,
}

impl SubmissionQueuePosition {
    /// Construct a submission-queue trace position.
    #[inline]
    pub const fn new(head: u16, tail: u16) -> Self {
        Self { head, tail }
    }

    /// Submission head observed by the controller.
    #[inline]
    pub const fn head(self) -> u16 {
        self.head
    }

    /// Submission tail maintained by the host.
    #[inline]
    pub const fn tail(self) -> u16 {
        self.tail
    }
}

/// A pinned blk-mq tag set allocated through the NVMe core.
///
/// NVMe core, rather than the transport, selects queue depth, timeouts,
/// reserved tags and controller linkage. Explicit [`TagSet::remove`] preserves
/// the C teardown order; pinned drop performs the same removal as a final
/// safeguard on probe unwind.
#[pin_data(PinnedDrop)]
pub struct TagSet<O: MqOperations> {
    #[pin]
    inner: Opaque<bindings::blk_mq_tag_set>,
    state: AtomicU8,
    controller: AtomicPtr<bindings::nvme_ctrl>,
    _p: PhantomData<O>,
}

// SAFETY: The C block and NVMe cores synchronize a successfully allocated tag
// set. Rust state used during allocation/removal is atomic.
unsafe impl<O: MqOperations> Send for TagSet<O> {}
// SAFETY: See the `Send` implementation.
unsafe impl<O: MqOperations> Sync for TagSet<O> {}

impl<O: MqOperations> TagSet<O> {
    /// Create an empty, pinned tag-set container.
    pub fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            inner <- Opaque::ffi_init(|slot: *mut bindings::blk_mq_tag_set| {
                // SAFETY: An all-zero tag set is the required input to the
                // NVMe core allocation helpers.
                unsafe { slot.write(core::mem::zeroed()) };
            }),
            state: AtomicU8::new(TAGSET_EMPTY),
            controller: AtomicPtr::new(ptr::null_mut()),
            _p: PhantomData,
        })
    }

    fn command_size() -> Result<u32> {
        if align_of::<RequestPdu<O::RequestData>>() > align_of::<bindings::request>() {
            return Err(EINVAL);
        }
        u32::try_from(size_of::<RequestPdu<O::RequestData>>()).map_err(|_| EOVERFLOW)
    }

    fn begin_allocate(&self, controller: &Controller<O::Transport>) -> Result<u32> {
        if !controller.is_initialized() {
            return Err(ENODEV);
        }
        self.state
            .compare_exchange(
                TAGSET_EMPTY,
                TAGSET_ALLOCATING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| EBUSY)?;
        match Self::command_size() {
            Ok(size) => Ok(size),
            Err(error) => {
                self.state.store(TAGSET_EMPTY, Ordering::Release);
                Err(error)
            }
        }
    }

    /// Allocate the controller's admin tag set and admin request queue.
    pub fn allocate_admin(self: Pin<&Self>, controller: &Controller<O::Transport>) -> Result {
        let command_size = self.begin_allocate(controller)?;
        // SAFETY: `inner` is pinned and empty, `controller` is initialized,
        // and this generic vtable uses the matching transport type and PDU.
        let result = to_result(unsafe {
            bindings::nvme_alloc_admin_tag_set(
                controller.as_raw(),
                self.inner.get(),
                MqOperationsVTable::<O>::build(),
                command_size,
            )
        });
        match result {
            Ok(()) => {
                self.controller
                    .store(controller.as_raw(), Ordering::Release);
                self.state.store(TAGSET_ADMIN, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.state.store(TAGSET_EMPTY, Ordering::Release);
                Err(error)
            }
        }
    }

    /// Allocate the controller's I/O tag set.
    pub fn allocate_io(
        self: Pin<&Self>,
        controller: &Controller<O::Transport>,
        nr_maps: u32,
    ) -> Result {
        if nr_maps == 0 || nr_maps > bindings::hctx_type_HCTX_MAX_TYPES {
            return Err(EINVAL);
        }
        let command_size = self.begin_allocate(controller)?;
        // SAFETY: Same invariants as `allocate_admin`; `nr_maps` was checked
        // against the fixed array in `blk_mq_tag_set`.
        let result = to_result(unsafe {
            bindings::nvme_alloc_io_tag_set(
                controller.as_raw(),
                self.inner.get(),
                MqOperationsVTable::<O>::build(),
                nr_maps,
                command_size,
            )
        });
        match result {
            Ok(()) => {
                self.controller
                    .store(controller.as_raw(), Ordering::Release);
                self.state.store(TAGSET_IO, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.state.store(TAGSET_EMPTY, Ordering::Release);
                Err(error)
            }
        }
    }

    /// Whether the NVMe core currently owns this tag set.
    #[inline]
    pub fn is_allocated(&self) -> bool {
        matches!(self.state.load(Ordering::Acquire), TAGSET_ADMIN | TAGSET_IO)
    }

    /// Update the number of hardware queues in an allocated I/O tag set.
    pub fn update_nr_hw_queues(&self, nr_hw_queues: u32) -> Result {
        if self.state.load(Ordering::Acquire) != TAGSET_IO || nr_hw_queues == 0 {
            return Err(EINVAL);
        }
        let nr_hw_queues = c_int::try_from(nr_hw_queues).map_err(|_| EOVERFLOW)?;
        // SAFETY: An I/O allocation initializes the pinned tag set; the block
        // core serializes queue-count updates against map and teardown paths.
        unsafe { bindings::blk_mq_update_nr_hw_queues(self.inner.get(), nr_hw_queues) };
        Ok(())
    }

    /// Resolve a command identifier in one hardware queue and dispatch its
    /// completion through the NVMe and blk-mq cores.
    pub fn complete(
        &self,
        hardware_queue: usize,
        command_id: u16,
        status: u16,
        result: CompletionResult,
        batch: Option<&mut CompletionBatch<O>>,
    ) -> CompletionDisposition {
        self.complete_inner(hardware_queue, command_id, None, status, result, batch)
    }

    /// Trace and dispatch one PCI submission-queue completion.
    ///
    /// The trace is emitted after the command identifier resolves to a live
    /// request and before its completion state is changed, matching the C PCI
    /// transport's `trace_nvme_sq()` call site. Generated tracepoint and
    /// static-call symbols remain encapsulated by the NVMe core.
    pub fn complete_with_sq_trace(
        &self,
        hardware_queue: usize,
        command_id: u16,
        position: SubmissionQueuePosition,
        status: u16,
        result: CompletionResult,
        batch: Option<&mut CompletionBatch<O>>,
    ) -> CompletionDisposition {
        self.complete_inner(
            hardware_queue,
            command_id,
            Some(position),
            status,
            result,
            batch,
        )
    }

    fn complete_inner(
        &self,
        hardware_queue: usize,
        command_id: u16,
        position: Option<SubmissionQueuePosition>,
        status: u16,
        result: CompletionResult,
        batch: Option<&mut CompletionBatch<O>>,
    ) -> CompletionDisposition {
        if !self.is_allocated() {
            return CompletionDisposition::InvalidCommandId;
        }
        // SAFETY: A successful tag-set allocation initializes these fields and
        // they remain stable until `remove` begins after IRQ synchronization.
        let set = unsafe { &*self.inner.get() };
        if hardware_queue >= set.nr_hw_queues as usize || set.tags.is_null() {
            return CompletionDisposition::InvalidCommandId;
        }
        // SAFETY: The bounds check covers the `tags` array allocated by
        // blk-mq for `nr_hw_queues` entries.
        let tags = unsafe { *set.tags.add(hardware_queue) };
        if tags.is_null() {
            return CompletionDisposition::InvalidCommandId;
        }
        // SAFETY: The helper validates both tag range and NVMe generation.
        let request = unsafe { bindings::nvme_find_rq(tags, command_id) };
        if request.is_null() {
            return CompletionDisposition::InvalidCommandId;
        }
        if let Some(position) = position {
            // SAFETY: `request` was resolved in this live tag set. The NVMe
            // core wrapper converts the typed native-endian position and owns
            // all generated tracepoint/static-call details.
            unsafe { bindings::nvme_trace_sq(request, position.head, position.tail) };
        }
        let batch = batch.map_or(ptr::null_mut(), CompletionBatch::as_raw);
        // SAFETY: `request` was validated against this tag set and therefore
        // has the exact NVMe request prefix allocated by `TagSet`. This is the
        // Rust equivalent of `nvme_try_complete_req`: it records the CQ data,
        // advances the command-id generation, then lets blk-mq choose direct,
        // remote, or batched completion.
        let deferred = unsafe {
            // As in blk_mq_rq_to_pdu(), the NVMe PDU immediately follows
            // this live request in the tag-set allocation. The generated
            // request type provides the C stride; RequestPdu is repr(C) and
            // its first member is the NVMe core prefix.
            let core = request.add(1).cast::<bindings::nvme_request>();
            let controller = (*core).ctrl;
            if controller.is_null() {
                return CompletionDisposition::InvalidCommandId;
            }
            if (*controller).quirks & bindings::nvme_quirks_NVME_QUIRK_SKIP_CID_GEN as usize == 0 {
                (*core).genctr = (*core).genctr.wrapping_add(1);
            }
            (*core).status = status >> 1;
            (*core).result = result.0;

            #[cfg(CONFIG_FAULT_INJECTION_DEBUG_FS)]
            bindings::nvme_should_fail(request);

            // Match blk_should_fake_timeout()'s IS_ENABLED test exactly.
            // With fault timeouts disabled the C inline is a constant false;
            // when enabled, retain its queue-flag check and injection helper.
            #[cfg(CONFIG_FAIL_IO_TIMEOUT)]
            let fake_timeout = bindings::blk_should_fake_timeout((*request).q);
            #[cfg(not(CONFIG_FAIL_IO_TIMEOUT))]
            let fake_timeout = false;

            fake_timeout || bindings::blk_mq_complete_request_remote(request)
                || bindings::blk_mq_add_to_batch(
                    request,
                    batch,
                    (*core).status != bindings::NVME_SC_SUCCESS as u16,
                    Some(MqOperationsVTable::<O>::complete_batch_callback),
                )
        };
        if !deferred {
            // SAFETY: The helper returned false, transferring direct
            // completion responsibility to this callback.
            unsafe { MqOperationsVTable::<O>::complete_callback(request) };
        }
        CompletionDisposition::Handled
    }

    /// Remove queues and free tag storage using the matching NVMe core helper.
    ///
    /// Call this before controller uninitialization. It is idempotent.
    pub fn remove(self: Pin<&Self>) {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state != TAGSET_ADMIN && state != TAGSET_IO {
                return;
            }
            match self.state.compare_exchange(
                state,
                TAGSET_REMOVING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(next) => state = next,
            }
        }

        let controller = self.controller.swap(ptr::null_mut(), Ordering::AcqRel);
        if !controller.is_null() {
            // SAFETY: A successful allocation stored this exact live
            // controller and the state transition grants exclusive removal.
            unsafe {
                if state == TAGSET_ADMIN {
                    bindings::nvme_remove_admin_tag_set(controller);
                } else {
                    bindings::nvme_remove_io_tag_set(controller);
                }
            }
        }
        self.state.store(TAGSET_EMPTY, Ordering::Release);
    }
}

#[pinned_drop]
impl<O: MqOperations> PinnedDrop for TagSet<O> {
    fn drop(self: Pin<&mut Self>) {
        self.as_ref().remove();
    }
}
