// SPDX-License-Identifier: GPL-2.0

//! Completion support.
//!
//! Reference: <https://docs.kernel.org/scheduler/completion.html>
//!
//! C header: [`include/linux/completion.h`](srctree/include/linux/completion.h)

use crate::{bindings, error::to_result, prelude::*, time::Jiffies, types::Opaque};

/// Result of waiting for a completion with a timeout.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionTimeoutResult {
    /// The completion fired before expiry, with this many jiffies remaining.
    Completed(Jiffies),
    /// The timeout expired before a matching completion.
    TimedOut,
}

/// Synchronization primitive to signal when a certain task has been completed.
///
/// The [`Completion`] synchronization primitive signals when a certain task has been completed by
/// waking up other tasks that have been queued up to wait for the [`Completion`] to be completed.
///
/// # Examples
///
/// ```
/// use kernel::sync::{Arc, Completion};
/// use kernel::workqueue::{self, impl_has_work, new_work, Work, WorkItem};
///
/// #[pin_data]
/// struct MyTask {
///     #[pin]
///     work: Work<MyTask>,
///     #[pin]
///     done: Completion,
/// }
///
/// impl_has_work! {
///     impl HasWork<Self> for MyTask { self.work }
/// }
///
/// impl MyTask {
///     fn new() -> Result<Arc<Self>> {
///         let this = Arc::pin_init(pin_init!(MyTask {
///             work <- new_work!("MyTask::work"),
///             done <- Completion::new(),
///         }), GFP_KERNEL)?;
///
///         let _ = workqueue::system().enqueue(this.clone());
///
///         Ok(this)
///     }
///
///     fn wait_for_completion(&self) {
///         self.done.wait_for_completion();
///
///         pr_info!("Completion: task complete\n");
///     }
/// }
///
/// impl WorkItem for MyTask {
///     type Pointer = Arc<MyTask>;
///
///     fn run(this: Arc<MyTask>) {
///         // process this task
///         this.done.complete_all();
///     }
/// }
///
/// let task = MyTask::new()?;
/// task.wait_for_completion();
/// # Ok::<(), Error>(())
/// ```
#[pin_data]
pub struct Completion {
    #[pin]
    inner: Opaque<bindings::completion>,
}

// SAFETY: `Completion` is safe to be send to any task.
unsafe impl Send for Completion {}

// SAFETY: `Completion` is safe to be accessed concurrently.
unsafe impl Sync for Completion {}

impl Completion {
    /// Create an initializer for a new [`Completion`].
    pub fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            inner <- Opaque::ffi_init(|slot: *mut bindings::completion| {
                // SAFETY: `slot` is a valid pointer to an uninitialized `struct completion`.
                unsafe { bindings::init_completion(slot) };
            }),
        })
    }

    fn as_raw(&self) -> *mut bindings::completion {
        self.inner.get()
    }

    /// Signal all tasks waiting on this completion.
    ///
    /// This method wakes up all tasks waiting on this completion; after this operation the
    /// completion is permanently done, i.e. signals all current and future waiters.
    pub fn complete_all(&self) {
        // SAFETY: `self.as_raw()` is a pointer to a valid `struct completion`.
        unsafe { bindings::complete_all(self.as_raw()) };
    }

    /// Signal a single task waiting on this completion.
    ///
    /// This method wakes up at most one task waiting on this completion; unlike
    /// [`Completion::complete_all`], the completion is not permanently done and may be reused after
    /// a call to [`Completion::reinit`].
    #[inline(always)]
    pub fn complete(&self) {
        // SAFETY: `self.as_raw()` is a pointer to a valid `struct completion`.
        unsafe { bindings::complete(self.as_raw()) };
    }

    /// Wait for completion of a task.
    ///
    /// This method waits for the completion of a task; it is not interruptible and there is no
    /// timeout.
    ///
    /// See also [`Completion::complete_all`].
    pub fn wait_for_completion(&self) {
        // SAFETY: `self.as_raw()` is a pointer to a valid `struct completion`.
        unsafe { bindings::wait_for_completion(self.as_raw()) };
    }

    /// Wait for completion of a task, interruptible by fatal signals.
    ///
    /// Mirrors C's `wait_for_completion_killable()`. Blocks until the completion is signalled (by
    /// [`Completion::complete`] or [`Completion::complete_all`]) or a fatal signal is received.
    /// Returns `Ok(0)` on completion; `Err(ERESTARTSYS)` if interrupted.
    #[inline(always)]
    pub fn wait_for_completion_killable(&self) -> Result {
        // SAFETY: `self.as_raw()` is a pointer to a valid `struct completion`.
        to_result(unsafe { bindings::wait_for_completion_killable(self.as_raw()) })
    }

    /// Wait with I/O accounting for at most `timeout` jiffies.
    ///
    /// This may sleep and must not be called from atomic context.
    pub fn wait_for_completion_io_timeout(&self, timeout: Jiffies) -> CompletionTimeoutResult {
        // SAFETY: `self` is a fully initialized completion whose pinned
        // allocation remains live for the entire blocking call.
        let remaining = unsafe { bindings::wait_for_completion_io_timeout(self.as_raw(), timeout) };
        if remaining == 0 {
            CompletionTimeoutResult::TimedOut
        } else {
            CompletionTimeoutResult::Completed(remaining)
        }
    }

    /// Return a synchronized snapshot of whether a completion is pending.
    pub fn is_done(&self) -> bool {
        // SAFETY: `self.as_raw()` points to a valid initialized completion.
        unsafe { bindings::completion_done(self.as_raw()) }
    }

    /// Reinitialize the completion so it can be reused.
    ///
    /// Mirrors C's `reinit_completion()`: resets the completion to the unsignalled state so a
    /// subsequent [`Completion::wait_for_completion_killable`] blocks until the next
    /// [`Completion::complete`]. Required when a completion is reused across requests (e.g. a
    /// virtqueue request/response cycle), since [`Completion::complete`] only releases one waiter.
    #[inline(always)]
    pub fn reinit(&self) {
        // Mirrors C's `reinit_completion()`, which is `x->done = 0` (a plain write; the wait queue
        // is untouched). Done as a direct field write so the driver `.ko` needs no extra helper
        // symbol. SAFETY: `self.as_raw()` is a valid `struct completion`; `done` is a plain
        // `unsigned int` and an aligned 4-byte write is atomic on this arch (matching C).
        unsafe {
            core::ptr::addr_of_mut!((*self.as_raw()).done).write(0);
        }
    }
}
