//! Start and supervise a work command or terminal editor as the selected user.
use super::User;
use super::child::{child_setup, child_status, inherited_descriptors};
use super::signals::{SessionSignals, pending_signal, remember_signal};
use super::terminal::{Foreground, foreground_terminal, read_enter};
use anyhow::{Context, Result, ensure};
use rustix::process::{self, Pid, Signal};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

pub(crate) const COMMAND_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/run/current-system/sw/bin";

impl SessionSignals {
    pub fn run(&self, user: &User, command: &[OsString]) -> Result<i32> {
        if self.interrupted() {
            return Ok(128 + pending_signal());
        }
        if command.is_empty() {
            let mut tty =
                foreground_terminal()?.context("a foreground controlling terminal is required")?;
            writeln!(tty, "Press Enter to lock.")?;
            let _ = read_enter(&mut tty)?;
            return Ok(if self.interrupted() {
                128 + pending_signal()
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
    let _foreground = tty.map(Foreground::capture).transpose()?;
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
                let signal = pending_signal();
                return if signal == 0 {
                    status
                        .exit_status()
                        .context("missing work command exit status")
                } else {
                    Ok(128 + signal)
                };
            }
        }
        let signal = pending_signal();
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
