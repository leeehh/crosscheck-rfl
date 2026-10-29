// SPDX-License-Identifier: GPL-2.0

#![allow(missing_docs, unreachable_pub)]

//! Safe wrappers over the ALSA `snd_card` / `snd_pcm` framework for virtio-snd and similar sound
//! drivers. Wraps: allocating + registering a `struct snd_card` (`snd_card_new` / `snd_card_register`
//! / `snd_card_free`), creating a `struct snd_pcm` + installing `snd_pcm_ops` (`snd_pcm_new` /
//! `snd_pcm_set_ops`), and the `snd_pcm_substream` / `snd_pcm_runtime` accessor surface (buffer_size,
//! periods, rate, channels, format, dma_area, stream direction).
//!
//! The C-boundary `unsafe` — the `snd_pcm_ops` vtable trampolines, raw `snd_card`/`snd_pcm`/
//! `snd_pcm_substream` pointers — lives here; a driver built on this module is 0-unsafe. The
//! `snd_pcm_indirect` hw_ptr math + the PCM vq message flow are driver-side (wrapped via helpers
//! where they are static inlines).
//!
//! C headers: [`include/sound/core.h`](srctree/include/sound/core.h),
//! [`include/sound/pcm.h`](srctree/include/sound/pcm.h).

use crate::{
    bindings,
    device,
    error::{from_result, to_result, Result},
    prelude::*,
};
use core::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    ptr::NonNull,
};

/// `SNDRV_PCM_STREAM_PLAYBACK = 0`, `SNDRV_PCM_STREAM_CAPTURE = 1`.
pub const STREAM_PLAYBACK: c_int = 0;
pub const STREAM_CAPTURE: c_int = 1;

/// Implement this trait to interface ALSA as a PCM driver. The framework calls these per-substream
/// (`open`/`close` on stream open/close, `hw_params`/`hw_free` on parameter setup/teardown,
/// `prepare`/`trigger` to arm/start/stop, `pointer` for the hw position, `ack` on appl_ptr advance).
/// Mirrors `struct snd_pcm_ops` (the minimal subset; ioctl/sync_stop/copy/page/mmap default NULL).
pub trait Operations: Sized {
    fn open(substream: &PcmSubstream) -> Result;
    fn close(substream: &PcmSubstream);
    fn hw_params(substream: &PcmSubstream) -> Result;
    fn hw_free(substream: &PcmSubstream);
    fn prepare(substream: &PcmSubstream) -> Result;
    fn trigger(substream: &PcmSubstream, cmd: c_int) -> Result;
    fn pointer(substream: &PcmSubstream) -> u64;
    fn ack(substream: &PcmSubstream) -> Result {
        let _ = substream;
        Ok(())
    }
}

pub(crate) struct OperationsVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> OperationsVTable<T> {
    unsafe extern "C" fn open_callback(ss: *mut bindings::snd_pcm_substream) -> c_int {
        from_result(|| { T::open(&PcmSubstream::from_raw(ss))?; Ok(0) })
    }
    unsafe extern "C" fn close_callback(ss: *mut bindings::snd_pcm_substream) -> c_int {
        T::close(&PcmSubstream::from_raw(ss));
        0
    }
    unsafe extern "C" fn hw_params_callback(ss: *mut bindings::snd_pcm_substream,
        _p: *mut bindings::snd_pcm_hw_params) -> c_int {
        from_result(|| { T::hw_params(&PcmSubstream::from_raw(ss))?; Ok(0) })
    }
    unsafe extern "C" fn hw_free_callback(ss: *mut bindings::snd_pcm_substream) -> c_int {
        T::hw_free(&PcmSubstream::from_raw(ss)); 0
    }
    unsafe extern "C" fn prepare_callback(ss: *mut bindings::snd_pcm_substream) -> c_int {
        from_result(|| { T::prepare(&PcmSubstream::from_raw(ss))?; Ok(0) })
    }
    unsafe extern "C" fn trigger_callback(ss: *mut bindings::snd_pcm_substream, cmd: c_int) -> c_int {
        from_result(|| { T::trigger(&PcmSubstream::from_raw(ss), cmd)?; Ok(0) })
    }
    unsafe extern "C" fn pointer_callback(ss: *mut bindings::snd_pcm_substream) -> bindings::snd_pcm_uframes_t {
        T::pointer(&PcmSubstream::from_raw(ss)) as bindings::snd_pcm_uframes_t
    }
    unsafe extern "C" fn ack_callback(ss: *mut bindings::snd_pcm_substream) -> c_int {
        from_result(|| { T::ack(&PcmSubstream::from_raw(ss))?; Ok(0) })
    }

    /// Build the `snd_pcm_ops` vtable (static — the framework stores a pointer for the card's life).
    pub const fn build() -> &'static bindings::snd_pcm_ops {
        &Self::OPS
    }

    const OPS: bindings::snd_pcm_ops = bindings::snd_pcm_ops {
        open: Some(Self::open_callback),
        close: Some(Self::close_callback),
        ioctl: None,
        hw_params: Some(Self::hw_params_callback),
        hw_free: Some(Self::hw_free_callback),
        prepare: Some(Self::prepare_callback),
        trigger: Some(Self::trigger_callback),
        sync_stop: None,
        pointer: Some(Self::pointer_callback),
        get_time_info: None,
        fill_silence: None,
        copy: None,
        page: None,
        mmap: None,
        ack: Some(Self::ack_callback),
    };
}

/// An owning handle to a registered `struct snd_card`. `Drop` calls `snd_card_free`.
pub struct SndCard {
    card: NonNull<bindings::snd_card>,
}
unsafe impl Send for SndCard {}
unsafe impl Sync for SndCard {}

impl SndCard {
    /// Allocate a new sound card. Mirrors `snd_card_new(parent, idx=-1, xid=NULL, module, 0, &card)`.
    pub fn new<Ctx: device::DeviceContext>(parent: &device::Device<Ctx>, module: *mut bindings::module) -> Result<Self> {
        let mut card: *mut bindings::snd_card = core::ptr::null_mut();
        to_result(unsafe {
            bindings::snd_card_new(parent.as_raw(), -1, core::ptr::null(), module, 0, &mut card)
        })?;
        Ok(SndCard { card: NonNull::new(card).ok_or(ENOMEM)? })
    }

    /// Register the card (publishes it to userspace — `/proc/asound/cards`, ALSA controls).
    pub fn register(&self) -> Result {
        to_result(unsafe { bindings::snd_card_register(self.card.as_ptr()) })
    }

    pub fn as_raw(&self) -> *mut bindings::snd_card {
        self.card.as_ptr()
    }
}

impl Drop for SndCard {
    fn drop(&mut self) {
        // SAFETY: `self.card` came from a successful `snd_card_new`; `snd_card_free` is the teardown.
        unsafe { bindings::snd_card_free(self.card.as_ptr()) };
    }
}

/// A `struct snd_pcm` created on a card. `snd_pcm_new` + `snd_pcm_set_ops`.
pub struct SndPcm {
    pcm: NonNull<bindings::snd_pcm>,
}
unsafe impl Send for SndPcm {}
unsafe impl Sync for SndPcm {}

impl SndPcm {
    /// Create a PCM device on `card` with `playback` + `capture` streams. Mirrors `snd_pcm_new`.
    pub fn new(card: &SndCard, id: &crate::str::CStr, device: c_int, playback: bool, capture: bool) -> Result<Self> {
        let mut pcm: *mut bindings::snd_pcm = core::ptr::null_mut();
        to_result(unsafe {
            bindings::snd_pcm_new(card.as_raw(), id.as_char_ptr(), device,
                                  playback as c_int, capture as c_int, &mut pcm)
        })?;
        Ok(SndPcm { pcm: NonNull::new(pcm).ok_or(ENOMEM)? })
    }

    /// Install `T`'s `snd_pcm_ops` on `direction` (PLAYBACK/CAPTURE). Mirrors `snd_pcm_set_ops`.
    pub fn set_ops<T: Operations>(&self, direction: c_int) {
        // SAFETY: `self.pcm` is a valid `snd_pcm`; the ops is a static built by `OperationsVTable`.
        unsafe { bindings::snd_pcm_set_ops(self.pcm.as_ptr(), direction, OperationsVTable::<T>::build()) };
    }

    pub fn as_raw(&self) -> *mut bindings::snd_pcm {
        self.pcm.as_ptr()
    }
}

/// A borrowed handle to a `struct snd_pcm_substream`, passed to the `PcmOps` callbacks.
pub struct PcmSubstream(NonNull<bindings::snd_pcm_substream>);
unsafe impl Send for PcmSubstream {}
unsafe impl Sync for PcmSubstream {}

impl PcmSubstream {
    pub fn from_raw(ptr: *mut bindings::snd_pcm_substream) -> Self {
        Self(unsafe { NonNull::new_unchecked(ptr) })
    }
    pub fn as_raw(&self) -> *mut bindings::snd_pcm_substream {
        self.0.as_ptr()
    }
    /// The stream direction (`STREAM_PLAYBACK` / `STREAM_CAPTURE`).
    pub fn stream(&self) -> c_int {
        unsafe { (*self.0.as_ptr()).stream }
    }
    /// The `snd_pcm` this substream belongs to.
    pub fn pcm(&self) -> *mut bindings::snd_pcm {
        unsafe { (*self.0.as_ptr()).pcm }
    }
    /// `runtime->buffer_size` (in frames).
    pub fn buffer_size(&self) -> u64 {
        unsafe { (*(*self.0.as_ptr()).runtime).buffer_size as u64 }
    }
    /// `runtime->periods`.
    pub fn periods(&self) -> u32 {
        unsafe { (*(*self.0.as_ptr()).runtime).periods }
    }
    /// `runtime->period_size` (in frames).
    pub fn period_size(&self) -> u64 {
        unsafe { (*(*self.0.as_ptr()).runtime).period_size as u64 }
    }
    /// `runtime->rate`.
    pub fn rate(&self) -> u32 {
        unsafe { (*(*self.0.as_ptr()).runtime).rate }
    }
    /// `runtime->channels`.
    pub fn channels(&self) -> u32 {
        unsafe { (*(*self.0.as_ptr()).runtime).channels }
    }
    /// `runtime->format` (a `snd_pcm_format_t` value).
    pub fn format(&self) -> i32 {
        unsafe { (*(*self.0.as_ptr()).runtime).format as i32 }
    }
    /// `runtime->frame_bits` (bits per frame = channels × bits_per_sample).
    pub fn frame_bits(&self) -> u32 {
        unsafe { (*(*self.0.as_ptr()).runtime).frame_bits }
    }
    /// `runtime->dma_area` (the ALSA buffer — allocated by `lib_malloc_pages`).
    pub fn dma_area(&self) -> *mut u8 {
        unsafe { (*(*self.0.as_ptr()).runtime).dma_area as *mut u8 }
    }
    /// `snd_pcm_lib_malloc_pages(substream, size)` — allocate the ALSA buffer (`runtime->dma_area`).
    pub fn lib_malloc_pages(&self, size: usize) -> Result {
        to_result(unsafe { bindings::snd_pcm_lib_malloc_pages(self.0.as_ptr(), size) })
    }
    /// `snd_pcm_lib_free_pages(substream)` — free the ALSA buffer.
    pub fn lib_free_pages(&self) {
        unsafe { bindings::snd_pcm_lib_free_pages(self.0.as_ptr()) };
    }

    /// Set the substream's private data (the driver's per-substream chip), recovered by the
    /// `PcmCopyOps` trampoline. Mirrors C `snd_pcm_substream_chip(substream) = chip`.
    pub fn set_chip<T>(&self, chip: *mut T) {
        // SAFETY: `self.0` is a valid `snd_pcm_substream`; `private_data` is a plain `void *`.
        unsafe { (*self.0.as_ptr()).private_data = chip as *mut c_void };
    }

    /// `snd_pcm_indirect_playback_transfer(substream, &mut indirect, copy)` — the indirect playback
    /// transfer, calling `T::copy` for each chunk. The FFI + the trampoline live here (0-unsafe
    /// driver). Mirrors C `snd_pcm_indirect_playback_transfer`.
    pub fn playback_transfer<T: PcmCopyOps>(&self, indirect: &mut PcmIndirect) -> Result {
        let rc = unsafe {
            bindings::snd_pcm_indirect_playback_transfer(
                self.0.as_ptr(),
                indirect.as_mut_ptr(),
                Some(copy_trampoline::<T>),
            )
        };
        if rc < 0 {
            return Err(crate::error::code::EIO);
        }
        Ok(())
    }

    /// `snd_pcm_indirect_playback_pointer(substream, &indirect, hw_ptr)` — the hw position.
    pub fn playback_pointer(&self, indirect: &PcmIndirect, hw_ptr: u32) -> u64 {
        unsafe {
            bindings::snd_pcm_indirect_playback_pointer(
                self.0.as_ptr(),
                indirect.as_ptr() as *mut _,
                hw_ptr,
            ) as u64
        }
    }
}

/// An owned `struct snd_pcm_indirect` (the hw_ptr tracker). `#[repr(transparent)]` so a `*mut
/// snd_pcm_indirect` from the C trampoline casts to `&mut PcmIndirect`.
#[repr(transparent)]
pub struct PcmIndirect(bindings::snd_pcm_indirect);

impl PcmIndirect {
    pub fn zeroed() -> Self {
        // SAFETY: `snd_pcm_indirect` is POD (all scalar fields); zeroed is valid.
        Self(unsafe { core::mem::zeroed() })
    }
    pub fn sw_data(&self) -> u32 {
        self.0.sw_data
    }
    pub fn set_hw_buffer_size(&mut self, v: u32) {
        self.0.hw_buffer_size = v;
    }
    pub fn as_mut_ptr(&mut self) -> *mut bindings::snd_pcm_indirect {
        &mut self.0
    }
    pub fn as_ptr(&self) -> *const bindings::snd_pcm_indirect {
        &self.0
    }
}

/// The per-chunk copy callback for `snd_pcm_indirect_playback_transfer` — the driver fills +
/// submits a PCM message for `bytes` at the indirect's current position. Implement on the
/// per-substream chip (set via `PcmSubstream::set_chip`).
pub trait PcmCopyOps {
    fn copy(ss: &PcmSubstream, indirect: &mut PcmIndirect, bytes: usize);
}

/// `snd_pcm_indirect_copy_t` trampoline. Recovers the chip `T` from `substream->private_data`
/// (set by `set_chip`) + dispatches to `T::copy`. Generic in `T` ⇒ monomorphizes into the driver
/// module; the `unsafe` (extern "C" + raw-pointer recovery) lives here, so the driver writes no
/// `unsafe extern "C"` callback.
unsafe extern "C" fn copy_trampoline<T: PcmCopyOps>(
    ss: *mut bindings::snd_pcm_substream,
    rec: *mut bindings::snd_pcm_indirect,
    bytes: usize,
) {
    // SAFETY: the framework passes a valid `substream` + the `indirect` passed to
    // `playback_transfer`. `T::copy` recovers driver state via its own (global) handle.
    let indirect = unsafe { &mut *(rec as *mut PcmIndirect) };
    T::copy(&PcmSubstream::from_raw(ss), indirect, bytes);
}
