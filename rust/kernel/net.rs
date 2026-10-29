// SPDX-License-Identifier: GPL-2.0

//! Networking.

#![allow(missing_docs, unreachable_pub)]

#[cfg(CONFIG_RUST_PHYLIB_ABSTRACTIONS)]
pub mod phy;

/// Reference-counted network-device registration and callback ownership.
pub mod device;

/// Netdev abstraction (`struct net_device` + `net_device_ops` + `sk_buff`) for virtio-net and
/// similar network drivers. Minimal: alloc/register a netdev, the ndo_open/stop/start_xmit
/// callbacks, + sk_buff alloc/put/data/len/free. The C-boundary `unsafe` (the netdev_ops vtable
/// trampolines, raw net_device/sk_buff pointers, netdev_priv offset) lives here; a driver built on
/// this is 0-unsafe.
pub mod ndev {
    use crate::{
        bindings,
        error::{from_result, to_result, Result},
        prelude::*,
        str::CStr,
    };
    use core::{
        ffi::{c_int, c_void},
        marker::PhantomData,
        ptr::NonNull,
    };

    /// Implement this trait to interface the netdev layer. The framework calls `open`/`stop` on
    /// interface up/down, `start_xmit` for each TX packet. Mirrors `struct net_device_ops` (minimal).
    pub trait Operations: Sized {
        fn open(dev: &NetDev<Self>) -> Result;
        fn stop(dev: &NetDev<Self>);
        fn start_xmit(skb: &SkBuff, dev: &NetDev<Self>) -> bindings::netdev_tx_t;
    }

    pub(crate) struct OperationsVTable<T: Operations>(PhantomData<T>);

    impl<T: Operations> OperationsVTable<T> {
        unsafe extern "C" fn open_cb(dev: *mut bindings::net_device) -> c_int {
            from_result(|| { T::open(&NetDev::from_raw(dev))?; Ok(0) })
        }
        unsafe extern "C" fn stop_cb(dev: *mut bindings::net_device) -> c_int {
            T::stop(&NetDev::from_raw(dev)); 0
        }
        unsafe extern "C" fn xmit_cb(skb: *mut bindings::sk_buff, dev: *mut bindings::net_device) -> bindings::netdev_tx_t {
            T::start_xmit(&SkBuff::from_raw(skb), &NetDev::from_raw(dev))
        }
        /// The `alloc_netdev_mqs` setup callback — installs `T`'s netdev_ops.
        unsafe extern "C" fn setup_cb(dev: *mut bindings::net_device) {
            unsafe { (*dev).netdev_ops = Self::build_ops(); }
        }
        fn build_ops() -> &'static bindings::net_device_ops {
            use core::sync::atomic::{AtomicUsize, Ordering};
            static SLOT: AtomicUsize = AtomicUsize::new(0);
            let p = SLOT.load(Ordering::Acquire);
            if p != 0 { return unsafe { &*(p as *const bindings::net_device_ops) }; }
            let mut ops: bindings::net_device_ops = unsafe { core::mem::zeroed() };
            ops.ndo_open = Some(Self::open_cb);
            ops.ndo_stop = Some(Self::stop_cb);
            ops.ndo_start_xmit = Some(Self::xmit_cb);
            let boxed = KBox::new(ops, GFP_KERNEL).unwrap();
            let raw = KBox::into_raw(boxed) as *mut bindings::net_device_ops as usize;
            match SLOT.compare_exchange(0, raw, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => unsafe { &*(raw as *const bindings::net_device_ops) },
                Err(other) => {
                    unsafe { drop(KBox::from_raw(raw as *mut bindings::net_device_ops)); }
                    unsafe { &*(other as *const bindings::net_device_ops) }
                }
            }
        }
    }

    /// An owning handle to a registered `struct net_device`. `Drop` calls `unregister_netdev` +
    /// `free_netdev`.
    pub struct NetDev<T: Operations> {
        dev: NonNull<bindings::net_device>,
        _t: PhantomData<T>,
    }
    unsafe impl<T: Operations> Send for NetDev<T> {}
    unsafe impl<T: Operations> Sync for NetDev<T> {}

    impl<T: Operations> NetDev<T> {
        /// Allocate a netdev with `T`'s ops installed (via the setup callback). Mirrors
        /// `alloc_netdev_mqs(sizeof_priv=0, name, 0, setup, 1, 1)`.
        pub fn alloc(name: &CStr) -> Result<Self> {
            let dev = unsafe {
                bindings::alloc_netdev_mqs(0, name.as_char_ptr(), 0,
                    Some(OperationsVTable::<T>::setup_cb), 1, 1)
            };
            Ok(NetDev { dev: NonNull::new(dev).ok_or(ENOMEM)?, _t: PhantomData })
        }
        /// Register the netdev (publishes it). Mirrors `register_netdev`.
        pub fn register(&self) -> Result {
            to_result(unsafe { bindings::register_netdev(self.dev.as_ptr()) })
        }
        /// The per-netdev private data (`netdev_priv`), typed as `TPriv`.
        pub fn priv_<TPriv>(&self) -> &mut TPriv {
            let p = unsafe { bindings::netdev_priv(self.dev.as_ptr()) } as *mut TPriv;
            unsafe { &mut *p }
        }
        pub fn as_raw(&self) -> *mut bindings::net_device { self.dev.as_ptr() }
        pub fn from_raw(dev: *mut bindings::net_device) -> Self {
            Self { dev: unsafe { NonNull::new_unchecked(dev) }, _t: PhantomData }
        }
    }

    impl<T: Operations> Drop for NetDev<T> {
        fn drop(&mut self) {
            unsafe { bindings::unregister_netdev(self.dev.as_ptr()); bindings::free_netdev(self.dev.as_ptr()); }
        }
    }

    /// A borrowed handle to a `struct sk_buff` (a network packet). Passed to `start_xmit`.
    pub struct SkBuff(NonNull<bindings::sk_buff>);
    unsafe impl Send for SkBuff {}
    unsafe impl Sync for SkBuff {}

    impl SkBuff {
        pub fn from_raw(skb: *mut bindings::sk_buff) -> Self {
            Self(unsafe { NonNull::new_unchecked(skb) })
        }
        pub fn data(&self) -> *mut u8 { unsafe { (*self.0.as_ptr()).data as *mut u8 } }
        pub fn len(&self) -> u32 { unsafe { (*self.0.as_ptr()).len } }
        pub fn alloc(size: u32) -> Result<Self> {
            let skb = unsafe { bindings::__alloc_skb(size, bindings::GFP_KERNEL, 0, bindings::NUMA_NO_NODE) };
            Ok(Self(NonNull::new(skb).ok_or(ENOMEM)?))
        }
        pub fn put(&self, len: u32) -> *mut c_void {
            unsafe { bindings::skb_put(self.0.as_ptr(), len) }
        }
        pub fn free(self) {
            unsafe { bindings::kfree_skb(self.0.as_ptr()) };
        }
        pub fn as_raw(&self) -> *mut bindings::sk_buff { self.0.as_ptr() }
    }
}
