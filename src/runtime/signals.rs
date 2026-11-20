//! Install scoped signal handlers and record the first interruption.

use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::Result;

use super::checked;

pub(super) const SIGNALS: [i32; 5] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTSTP,
];
static SIGNAL: AtomicI32 = AtomicI32::new(0);

pub(super) extern "C" fn remember_signal(signal: i32) {
    let _ = SIGNAL.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

pub(super) fn pending_signal() -> i32 {
    SIGNAL.load(Ordering::Relaxed)
}

pub struct SessionSignals {
    previous: Vec<(i32, libc::sigaction)>,
    previous_mask: Option<libc::sigset_t>,
}

impl SessionSignals {
    pub fn install() -> Result<Self> {
        let mut guard = Self {
            previous: Vec::with_capacity(SIGNALS.len() + 2),
            previous_mask: None,
        };
        SIGNAL.store(0, Ordering::Relaxed);

        for signal in SIGNALS.into_iter().chain([libc::SIGIO, libc::SIGCHLD]) {
            // A zeroed action has no flags. The handler only sets a lock-free atomic.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            // The filesystem worker checks for lease breaks with F_GETLEASE.
            // SIGIO must not terminate or cancel the supervisor.
            action.sa_sigaction = match signal {
                libc::SIGIO => libc::SIG_IGN,
                // A launcher can ignore SIGCHLD. Linux then auto-reaps the probe
                // or work command before the supervisor can collect its status.
                libc::SIGCHLD => libc::SIG_DFL,
                _ => remember_signal as *const () as usize,
            };

            let mut old = action;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                checked(libc::sigaction(signal, &action, &mut old))?;
            }
            guard.previous.push((signal, old));
        }

        // exec preserves the launcher's signal mask. Install all handlers
        // before unblocking a pending interrupt in this single-threaded CLI.
        unsafe {
            let mut watched = std::mem::zeroed();
            let mut old = std::mem::zeroed();
            checked(libc::sigemptyset(&mut watched))?;
            for signal in SIGNALS {
                checked(libc::sigaddset(&mut watched, signal))?;
            }
            checked(libc::sigprocmask(libc::SIG_UNBLOCK, &watched, &mut old))?;
            guard.previous_mask = Some(old);
        }
        Ok(guard)
    }

    pub fn interrupted(&self) -> bool {
        pending_signal() != 0
    }
}

impl Drop for SessionSignals {
    fn drop(&mut self) {
        if let Some(mask) = &self.previous_mask {
            unsafe {
                libc::sigprocmask(libc::SIG_SETMASK, mask, std::ptr::null_mut());
            }
        }

        for (signal, action) in self.previous.iter().rev() {
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
    }
}
