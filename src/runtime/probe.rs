//! Verify file traversal and access in a child running as the ordinary account.
use super::child::{child_setup, child_status, inherited_descriptors};
use super::{User, checked, signals::pending_signal};
use crate::tree::FileAccess;
use anyhow::{Context, Result, ensure};
use rustix::fs::{self, Access, AtFlags, Mode, OFlags, ResolveFlags};
use rustix::process::{self, Pid, Signal};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::{ffi::OsStrExt, process::ExitStatusExt};
use std::path::PathBuf;
use std::process::ExitStatus;

fn probe_file(
    path: &CStr,
    expected: &FileAccess,
    access: Access,
    slot: RawFd,
    slot_path: &CStr,
) -> io::Result<()> {
    let pinned = fs::openat2(
        fs::CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )?;
    let stat = fs::fstat(&pinned)?;
    if (stat.st_dev, stat.st_ino) != (expected.dev, expected.ino) {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    if access != Access::EXISTS {
        // Probe the pinned inode without opening its contents or affecting file leases.
        // The procfd path also works on Linux 5.6, before faccessat2(AT_EMPTY_PATH).
        checked(unsafe { libc::dup2(pinned.as_raw_fd(), slot) })?;
        fs::accessat(fs::CWD, slot_path, access, AtFlags::empty())?;
    }
    Ok(())
}

pub fn check_file_access(
    user: &User,
    files: &BTreeMap<PathBuf, FileAccess>,
    access: Access,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let targets = files
        .iter()
        .map(|(path, expected)| Ok((CString::new(path.as_os_str().as_bytes())?, expected)))
        .collect::<Result<Vec<_>>>()?;
    let (mut reader, mut writer) = io::pipe()?;
    let slot = reader.as_raw_fd();
    let slot_path = CString::new(format!("/proc/self/fd/{slot}"))?;
    let descriptors = inherited_descriptors()?;
    let supervisor = unsafe { libc::getpid() };
    // Prepare paths before fork. The child uses only syscalls and the error pipe,
    // and exits without running parent destructors or executing external code.
    let pid = unsafe { libc::fork() };
    checked(pid).context("start file access check")?;
    if pid == 0 {
        for &fd in &descriptors {
            if fd != slot && fd != writer.as_raw_fd() {
                unsafe { libc::close(fd) };
            }
        }
        let mut index = targets.len();
        let result = child_setup(user, None, &[], supervisor).and_then(|()| {
            for (i, (path, expected)) in targets.iter().enumerate() {
                index = i;
                probe_file(path, expected, access, slot, &slot_path)?;
            }
            Ok(())
        });
        if let Err(error) = result {
            let errno = error.raw_os_error().unwrap_or(libc::EIO);
            let _ = writer.write_all(&index.to_ne_bytes());
            let _ = writer.write_all(&errno.to_ne_bytes());
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::_exit(0) };
    }
    drop(writer);
    let pid = Pid::from_raw(pid).context("missing access check process")?;
    let status = wait_for_probe(pid, &reader).context("wait for file access check")?;
    if status.success() {
        return Ok(());
    }
    ensure!(
        status.code() == Some(1),
        "file access check ended with {status}"
    );
    let mut index = [0; size_of::<usize>()];
    let mut errno = [0; size_of::<i32>()];
    reader.read_exact(&mut index)?;
    reader.read_exact(&mut errno)?;
    let error = io::Error::from_raw_os_error(i32::from_ne_bytes(errno));
    let Some(path) = files.keys().nth(usize::from_ne_bytes(index)) else {
        return Err(error).with_context(|| format!("check access as UID {}", user.uid));
    };
    let permission = if access == Access::EXISTS {
        "traverse the path to"
    } else {
        "read and write"
    };
    Err(error).with_context(|| format!("UID {} could not {permission} {path:?}", user.uid))
}

fn wait_for_probe(pid: Pid, reader: &io::PipeReader) -> io::Result<ExitStatus> {
    // The worker closes its error pipe on exit. Its hangup wakes us promptly,
    // while a bounded timeout covers cancellation just before poll and SIGSTOP.
    let mut exit_pipe = libc::pollfd {
        fd: reader.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    loop {
        if pending_signal() != 0 {
            let _ = process::kill_process(pid, Signal::KILL);
        }
        if let Some(status) = child_status(pid)? {
            if status.stopped() {
                let _ = process::kill_process(pid, Signal::KILL);
            } else {
                return Ok(ExitStatus::from_raw(status.as_raw()));
            }
        }
        match checked(unsafe { libc::poll(&mut exit_pipe, 1, 100) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::SessionSignals;
    use std::env;
    use std::process::{Command, Stdio};

    #[test]
    fn cancels_probe_if_signal_arrived_before_wait() -> Result<()> {
        // The signal flag is process-wide. Exercise it in a fresh test process
        // so concurrent terminal tests see their own normal signal state.
        const CHILD: &str = "SECRET_GUARD_TEST_PROBE_WAIT";
        if env::var_os(CHILD).is_none() {
            let result = Command::new(env::current_exe()?)
                .args([
                    "--exact",
                    "runtime::probe::tests::cancels_probe_if_signal_arrived_before_wait",
                ])
                .env(CHILD, "1")
                .output()?;
            let summary = String::from_utf8_lossy(&result.stdout);
            assert!(
                result.status.success() && summary.contains("1 passed;"),
                "{summary}"
            );
            return Ok(());
        }

        // Model an exec from a launcher whose calling thread blocked SIGTERM.
        unsafe {
            let mut blocked = std::mem::zeroed();
            checked(libc::sigemptyset(&mut blocked))?;
            checked(libc::sigaddset(&mut blocked, libc::SIGTERM))?;
            checked(libc::sigprocmask(
                libc::SIG_BLOCK,
                &blocked,
                std::ptr::null_mut(),
            ))?;
        }
        let signals = SessionSignals::install()?;
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert!(signals.interrupted());
        let (reader, writer) = io::pipe()?;
        let child = Command::new("sleep")
            .arg("5")
            .stdout(Stdio::from(writer))
            .spawn()?;
        let status = wait_for_probe(Pid::from_child(&child), &reader)?;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        drop(signals);
        unsafe {
            let mut mask = std::mem::zeroed();
            checked(libc::sigprocmask(
                libc::SIG_BLOCK,
                std::ptr::null(),
                &mut mask,
            ))?;
            assert_eq!(libc::sigismember(&mask, libc::SIGTERM), 1);
        }
        Ok(())
    }
}
