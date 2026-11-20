use anyhow::{Context, Result, anyhow, ensure};
use nix::unistd::{Uid, User as Account, getgrouplist};
use std::env;
use std::ffi::{CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    home: PathBuf,
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
}

impl SessionSignals {
    pub fn install() -> Result<Self> {
        let mut guard = Self {
            previous: Vec::with_capacity(SIGNALS.len() + 1),
        };
        SIGNAL.store(0, Ordering::Relaxed);
        for signal in SIGNALS.into_iter().chain([libc::SIGIO]) {
            // A zeroed action has no flags. The handler only sets a lock-free atomic.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            // The filesystem worker checks for lease breaks with F_GETLEASE.
            // SIGIO must not terminate or cancel the supervisor.
            action.sa_sigaction = if signal == libc::SIGIO {
                libc::SIG_IGN
            } else {
                remember_signal as *const () as usize
            };
            let mut old = action;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                checked(libc::sigaction(signal, &action, &mut old))?;
            }
            guard.previous.push((signal, old));
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
        run_command(user, command, tty.as_ref())
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
        for (signal, action) in self.previous.iter().rev() {
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
    }
}

pub fn check_interactive() -> Result<()> {
    foreground_terminal()?
        .context("interactive sessions require a foreground controlling terminal")?;
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

fn run_command(user: &User, args: &[OsString], tty: Option<&File>) -> Result<i32> {
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..])
        .env_clear()
        .env("HOME", &user.home)
        .env("SHELL", &user.shell)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env(
            "PATH",
            "/usr/local/bin:/usr/bin:/bin:/run/current-system/sw/bin",
        );
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
    let inherited = std::fs::read_dir("/proc/self/fd")?
        .map(|entry| -> Result<i32> {
            Ok(entry?
                .file_name()
                .to_str()
                .context("invalid proc fd")?
                .parse()?)
        })
        .collect::<Result<Vec<_>>>()?
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
    let pid = child.id() as i32;
    let mut terminating = None;
    let mut stop_signal = 0;
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
        if waited == pid {
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                // Terminal-generated signals normally reach the foreground child
                // group directly. Tell the transaction that this exit was interrupted.
                if libc::WIFSIGNALED(status) {
                    remember_signal(libc::WTERMSIG(status));
                }
                let signal = SIGNAL.load(Ordering::Relaxed);
                return Ok(if signal != 0 {
                    128 + signal
                } else {
                    libc::WEXITSTATUS(status)
                });
            }
            if libc::WIFSTOPPED(status) {
                stop_signal = libc::WSTOPSIG(status);
                remember_signal(stop_signal);
                // A suspended job has to finish before its files can be relocked.
                unsafe {
                    libc::kill(-pid, libc::SIGCONT);
                }
            }
        } else if waited < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(anyhow!(
                "wait for working command: {}",
                io::Error::last_os_error()
            ));
        }
        let signal = SIGNAL.load(Ordering::Relaxed);
        if terminating.is_none() && (signal != 0 || stop_signal != 0) {
            let forward = if stop_signal != 0 || signal == libc::SIGTSTP {
                libc::SIGTERM
            } else {
                signal
            };
            unsafe {
                libc::kill(-pid, forward);
            }
            terminating = Some(Instant::now());
        } else if terminating.is_some_and(|start| start.elapsed() >= Duration::from_secs(3)) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
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
}
