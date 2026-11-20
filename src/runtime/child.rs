//! Shared process setup and wait primitives for commands and access probes.

use std::io;
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use rustix::process::{self, Pid, WaitOptions, WaitStatus};

use super::{User, checked, signals::SIGNALS, terminal::set_foreground};

// Prepare only async-signal-safe operations for the fork-to-exec interval.
pub(super) fn child_setup(
    user: &User,
    tty: Option<RawFd>,
    inherited: &[RawFd],
    supervisor: i32,
) -> io::Result<()> {
    unsafe {
        checked(libc::setpgid(0, 0))?;
        if let Some(fd) = tty {
            set_foreground(fd, libc::getpgrp())?;
        }

        for signal in
            SIGNALS
                .into_iter()
                .chain([libc::SIGTTIN, libc::SIGTTOU, libc::SIGPIPE, libc::SIGIO])
        {
            if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
        }
        let mut empty = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        checked(libc::sigprocmask(
            libc::SIG_SETMASK,
            &empty,
            std::ptr::null_mut(),
        ))?;

        for &fd in inherited {
            let rc = libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            if rc == -1 && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
                return Err(io::Error::last_os_error());
            }
        }

        checked(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        checked(libc::setgroups(user.groups.len(), user.groups.as_ptr()))?;
        checked(libc::setresgid(user.gid, user.gid, user.gid))?;
        checked(libc::setresuid(user.uid, user.uid, user.uid))?;
        checked(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0))?;

        // Clear even inherited capabilities kept across a UID change by securebits.
        // Linux capability ABI version 3: header {version,pid}, then two
        // {effective,permitted,inheritable} words sets.
        let header = [0x2008_0522u32, 0];
        let sets = [0u32; 6];
        checked(libc::syscall(libc::SYS_capset, header.as_ptr(), sets.as_ptr()) as i32)?;

        // Check the parent after arming the signal in case it exited during setup.
        checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0))?;
        if libc::getppid() != supervisor {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
    }
    Ok(())
}

pub(super) fn inherited_descriptors() -> Result<Vec<RawFd>> {
    std::fs::read_dir("/proc/self/fd")?
        .map(|entry| -> Result<RawFd> {
            Ok(entry?
                .file_name()
                .to_str()
                .context("invalid proc fd")?
                .parse()?)
        })
        .collect()
}

pub(super) fn child_status(pid: Pid) -> io::Result<Option<WaitStatus>> {
    let status = rustix::io::retry_on_intr(|| {
        process::waitpid(Some(pid), WaitOptions::NOHANG | WaitOptions::UNTRACED)
    })?;
    Ok(status.map(|(_, status)| status))
}
