use crate::tree::FileAccess;
use anyhow::{Context, Result, ensure};
use nix::unistd::{Uid, User as Account, getgrouplist};
use rustix::fs::{self, Access, AtFlags, Mode, OFlags, ResolveFlags};
use rustix::process::{self, Pid, Signal, WaitOptions, WaitStatus};
use std::collections::BTreeMap;
use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

pub(crate) const COMMAND_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/run/current-system/sw/bin";

#[derive(Clone)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    shell: PathBuf,
    groups: Vec<libc::gid_t>,
}

fn account_user(account: Account) -> Result<User> {
    ensure!(
        !account.uid.is_root(),
        "the session user must have a non-zero UID"
    );
    let groups = getgrouplist(&CString::new(account.name.as_bytes())?, account.gid)?
        .into_iter()
        .map(|gid| gid.as_raw())
        .collect();
    Ok(User {
        name: account.name,
        uid: account.uid.as_raw(),
        gid: account.gid.as_raw(),
        home: account.dir,
        shell: account.shell,
        groups,
    })
}

pub fn resolve_uid(uid: u32) -> Result<User> {
    account_user(
        Account::from_uid(Uid::from_raw(uid))?.context("session UID has no local account")?,
    )
}

pub fn resolve_user(selected: Option<&str>) -> Result<User> {
    let caller: Option<u32> = env::var_os("SUDO_UID")
        .map(|s| {
            s.to_str()
                .context("invalid SUDO_UID")?
                .parse()
                .context("invalid SUDO_UID")
        })
        .transpose()?;
    if let Some(name) = selected {
        let account = Account::from_name(name)?.context("selected user does not exist")?;
        ensure!(
            caller.is_none_or(|id| id == 0 || id == account.uid.as_raw()),
            "--user must match the ordinary sudo caller"
        );
        account_user(account)
    } else {
        resolve_uid(caller.filter(|&uid| uid != 0).context("invoke through sudo as an ordinary user, or specify --user USER when running directly as root")?)
    }
}

fn checked(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

const SIGNALS: [i32; 5] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTSTP,
];
static SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn remember_signal(signal: i32) {
    let _ = SIGNAL.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
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
        SIGNAL.load(Ordering::Relaxed) != 0
    }

    pub fn run(&self, user: &User, command: &[OsString]) -> Result<i32> {
        if self.interrupted() {
            return Ok(128 + SIGNAL.load(Ordering::Relaxed));
        }
        if command.is_empty() {
            let mut tty =
                foreground_terminal()?.context("a foreground controlling terminal is required")?;
            writeln!(tty, "Press Enter to lock.")?;
            let _ = read_enter(&mut tty)?;
            return Ok(if self.interrupted() {
                128 + SIGNAL.load(Ordering::Relaxed)
            } else {
                0
            });
        }
        let tty = foreground_terminal()?;
        let mut child = Command::new(&command[0]);
        child.args(&command[1..]);
        run_command(user, child, tty.as_ref())
    }

    pub fn run_editor(&self, user: &User, editor: &OsStr, draft: &Path) -> Result<i32> {
        ensure!(
            !self.interrupted(),
            "edit interrupted before starting the editor"
        );
        let tty = foreground_terminal()?.context("editing requires a foreground terminal")?;
        let mut child = Command::new(editor);
        child
            .arg(draft)
            .stdin(tty.try_clone()?)
            .stdout(tty.try_clone()?)
            .stderr(tty.try_clone()?);
        run_command(user, child, Some(&tty))
    }

    pub fn wait_for_retry(&self, busy: &[PathBuf]) -> Result<()> {
        fn list(out: &mut impl Write, busy: &[PathBuf]) -> io::Result<()> {
            writeln!(out, "Files still in use:")?;
            for path in busy {
                writeln!(out, "  {path:?}")?;
            }
            Ok(())
        }
        let Some(mut tty) = foreground_terminal()? else {
            list(&mut io::stderr().lock(), busy)?;
            anyhow::bail!("close the listed files and run 'sudo secret-guard lock' again");
        };
        list(&mut tty, busy)?;
        ensure!(
            !self.interrupted(),
            "retry interrupted; close the listed files before recovery"
        );
        writeln!(tty, "Close the listed files, then press Enter to retry.")?;
        ensure!(
            read_enter(&mut tty)?,
            "retry ended before Enter; the remaining files still need locking"
        );
        Ok(())
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

pub fn check_interactive() -> Result<()> {
    foreground_terminal()?.context("this command requires a foreground controlling terminal")?;
    Ok(())
}

fn foreground_terminal() -> Result<Option<File>> {
    let tty = match OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => tty,
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    // A background command with redirected standard streams must not take
    // the terminal away from its foreground process group.
    let group = unsafe { libc::tcgetpgrp(tty.as_raw_fd()) };
    checked(group)?;
    Ok((group == unsafe { libc::getpgrp() }).then_some(tty))
}

fn read_enter(tty: &mut File) -> Result<bool> {
    let mut input = [0u8; 256];
    while tty_ready(tty.as_raw_fd())? {
        match tty.read(&mut input) {
            Ok(0) => return Ok(false),
            Ok(n) if input[..n].contains(&b'\n') => return Ok(true),
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

// The bounded poll also covers a signal arriving immediately before poll().
fn tty_ready(fd: RawFd) -> io::Result<bool> {
    let mut entry = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    while SIGNAL.load(Ordering::Relaxed) == 0 {
        let rc = unsafe { libc::poll(&mut entry, 1, 100) };
        if rc > 0 {
            return Ok(SIGNAL.load(Ordering::Relaxed) == 0);
        }
        if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(false)
}

fn termios(fd: RawFd) -> io::Result<libc::termios> {
    let mut settings = unsafe { std::mem::zeroed() };
    checked(unsafe { libc::tcgetattr(fd, &mut settings) })?;
    Ok(settings)
}

fn change_termios(fd: RawFd, value: &libc::termios) -> io::Result<()> {
    loop {
        match checked(unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, value) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

// The parent can be in the background when it reclaims the child's terminal.
fn set_foreground(fd: RawFd, group: i32) -> io::Result<()> {
    unsafe {
        let mut blocked = std::mem::zeroed();
        let mut old = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        checked(libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut old))?;
        let result = checked(libc::tcsetpgrp(fd, group));
        checked(libc::sigprocmask(
            libc::SIG_SETMASK,
            &old,
            std::ptr::null_mut(),
        ))?;
        result
    }
}
struct Foreground(RawFd, i32, libc::termios);
impl Drop for Foreground {
    fn drop(&mut self) {
        if set_foreground(self.0, self.1).is_ok() {
            // A killed editor may have left the TTY raw or echo disabled.
            let _ = change_termios(self.0, &self.2);
        }
    }
}

// Prepare only async-signal-safe operations for the fork-to-exec interval.
fn child_setup(
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
        checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0))?;
        if libc::getppid() != supervisor {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
    }
    Ok(())
}

fn inherited_descriptors() -> Result<Vec<RawFd>> {
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

fn child_status(pid: Pid) -> io::Result<Option<WaitStatus>> {
    let status = rustix::io::retry_on_intr(|| {
        process::waitpid(Some(pid), WaitOptions::NOHANG | WaitOptions::UNTRACED)
    })?;
    Ok(status.map(|(_, status)| status))
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
        if SIGNAL.load(Ordering::Relaxed) != 0 {
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

fn run_command(user: &User, mut cmd: Command, tty: Option<&File>) -> Result<i32> {
    cmd.env_clear()
        .env("HOME", &user.home)
        .env("SHELL", &user.shell)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("PATH", COMMAND_PATH);
    for (key, value) in env::vars_os() {
        if key
            .to_str()
            .is_some_and(|s| matches!(s, "TERM" | "COLORTERM" | "LANG") || s.starts_with("LC_"))
        {
            cmd.env(key, value);
        }
    }
    // Handle descriptors inherited from sudo as well as files opened by this process.
    // Rust marks the exec-error pipe it creates later close-on-exec itself.
    let inherited = inherited_descriptors()?
        .into_iter()
        .filter(|fd| *fd >= 3)
        .collect::<Vec<_>>();
    let tty_fd = tty.map(AsRawFd::as_raw_fd);
    let _foreground = tty_fd
        .map(|fd| termios(fd).map(|mode| Foreground(fd, unsafe { libc::getpgrp() }, mode)))
        .transpose()?;
    let supervisor = unsafe { libc::getpid() };
    let target_user = user.clone();
    unsafe {
        cmd.pre_exec(move || child_setup(&target_user, tty_fd, &inherited, supervisor));
    }
    let child = cmd
        .spawn()
        .context("start working command as the session user")?;
    wait_for_command(Pid::from_child(&child))
}

fn signal_command(pid: Pid, signal: Signal) {
    let _ = process::kill_process_group(pid, signal);

    // A work command is free to change its own process group. It is still our
    // unreaped child, so its PID remains valid even if the original group is gone.
    if process::getpgid(Some(pid)).is_ok_and(|group| group != pid) {
        let _ = process::kill_process(pid, signal);
    }
}

fn wait_for_command(pid: Pid) -> Result<i32> {
    let mut terminating = None;
    let mut stopped = false;

    loop {
        if let Some(status) = child_status(pid).context("wait for working command")? {
            if let Some(signal) = status.stopping_signal() {
                stopped = true;
                remember_signal(signal);
                // A suspended job has to finish before its files can be relocked.
                signal_command(pid, Signal::CONT);
            } else {
                // Terminal-generated signals usually reach the foreground child directly.
                if let Some(signal) = status.terminating_signal() {
                    remember_signal(signal);
                }

                let signal = SIGNAL.load(Ordering::Relaxed);
                return if signal == 0 {
                    status
                        .exit_status()
                        .context("missing work command exit status")
                } else {
                    Ok(128 + signal)
                };
            }
        }

        let signal = SIGNAL.load(Ordering::Relaxed);
        if terminating.is_none() && signal != 0 {
            let forward = if stopped || signal == libc::SIGTSTP {
                Signal::TERM
            } else {
                Signal::from_named_raw(signal).context("invalid session signal")?
            };
            signal_command(pid, forward);
            terminating = Some(Instant::now());
        } else if terminating.is_some_and(|start| start.elapsed() >= Duration::from_secs(3)) {
            signal_command(pid, Signal::KILL);
        }

        std::thread::sleep(Duration::from_millis(40));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_is_never_a_working_user() {
        assert!(resolve_uid(0).is_err());
    }

    #[test]
    fn cancels_probe_if_signal_arrived_before_wait() -> Result<()> {
        // The signal flag is process-wide. Exercise it in a fresh test process
        // so concurrent terminal tests see their own normal signal state.
        const CHILD: &str = "SECRET_GUARD_TEST_PROBE_WAIT";
        if env::var_os(CHILD).is_none() {
            let result = Command::new(env::current_exe()?)
                .args([
                    "--exact",
                    "runtime::tests::cancels_probe_if_signal_arrived_before_wait",
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
            .stdout(std::process::Stdio::from(writer))
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
