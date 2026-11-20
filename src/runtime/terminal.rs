//! Controlling terminal input and foreground ownership.
use super::{SessionSignals, checked, signals::pending_signal};
use crate::output::{Palette, Tone};
use anyhow::{Context, Result, ensure};
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;

pub fn check_interactive() -> Result<()> {
    foreground_terminal()?.context("this command requires a foreground controlling terminal")?;
    Ok(())
}

pub fn confirm_session_reset(label: &str, kind: &str, roots: &[PathBuf]) -> Result<bool> {
    let Some(mut tty) = foreground_terminal()? else {
        return Ok(false);
    };
    let palette = Palette::for_stream(&tty);
    writeln!(tty, "{label} is {}.", palette.paint(Tone::Warning, kind))?;
    for root in roots {
        writeln!(tty, "  {root:?}")?;
    }
    writeln!(
        tty,
        "Enter keeps this session open and cancels the new request."
    )?;
    write!(
        tty,
        "Reset this session by locking its files, then continue? {} ",
        palette.paint(Tone::Action, "[y/N]")
    )?;
    tty.flush()?;
    read_confirmation(&mut tty)
}

impl SessionSignals {
    pub fn wait_for_retry(&self, busy: &[PathBuf]) -> Result<()> {
        fn list(out: &mut (impl Write + IsTerminal), busy: &[PathBuf]) -> io::Result<()> {
            let palette = Palette::for_stream(out);
            writeln!(
                out,
                "{}",
                palette.paint(Tone::Warning, "Files still in use:")
            )?;
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
        let palette = Palette::for_stream(&tty);
        writeln!(
            tty,
            "{}",
            palette.paint(
                Tone::Action,
                "Close the listed files, then press Enter to retry."
            )
        )?;
        ensure!(
            read_enter(&mut tty)?,
            "retry ended before Enter; the remaining files still need locking"
        );
        Ok(())
    }
}

fn read_confirmation(tty: &mut File) -> Result<bool> {
    Ok(read_answer(tty)?.is_some_and(|answer| {
        answer.eq_ignore_ascii_case(b"y") || answer.eq_ignore_ascii_case(b"yes")
    }))
}

pub(super) fn foreground_terminal() -> Result<Option<File>> {
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

pub(super) fn read_enter(tty: &mut File) -> Result<bool> {
    Ok(read_answer(tty)?.is_some())
}

fn read_answer(tty: &mut File) -> io::Result<Option<Vec<u8>>> {
    // Consume exactly one line, even on a noncanonical TTY. Four bytes suffice
    // to distinguish an overlong answer from "yes"; discard the rest of that line.
    let mut answer = Vec::with_capacity(4);
    let mut byte = [0];
    while tty_ready(tty.as_raw_fd())? {
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => {
                return Ok((pending_signal() == 0).then_some(answer));
            }
            Ok(_) if answer.len() < 4 => answer.push(byte[0]),
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

// The bounded poll also covers a signal arriving immediately before poll().
fn tty_ready(fd: RawFd) -> io::Result<bool> {
    let mut entry = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    while pending_signal() == 0 {
        let rc = unsafe { libc::poll(&mut entry, 1, 100) };
        if rc > 0 {
            return Ok(pending_signal() == 0);
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
pub(super) fn set_foreground(fd: RawFd, group: i32) -> io::Result<()> {
    unsafe {
        let mut blocked = std::mem::zeroed();
        let mut old = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        checked(libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut old))?;
        let result = loop {
            match checked(libc::tcsetpgrp(fd, group)) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => break result,
            }
        };
        checked(libc::sigprocmask(
            libc::SIG_SETMASK,
            &old,
            std::ptr::null_mut(),
        ))?;
        result
    }
}
pub(super) struct Foreground<'a> {
    tty: &'a File,
    group: libc::pid_t,
    settings: libc::termios,
}

impl<'a> Foreground<'a> {
    pub(super) fn capture(tty: &'a File) -> io::Result<Self> {
        Ok(Self {
            tty,
            group: unsafe { libc::getpgrp() },
            settings: termios(tty.as_raw_fd())?,
        })
    }
}

impl Drop for Foreground<'_> {
    fn drop(&mut self) {
        let fd = self.tty.as_raw_fd();
        if set_foreground(fd, self.group).is_ok() {
            // A killed editor may have left the TTY raw or echo disabled.
            let _ = change_termios(fd, &self.settings);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    #[test]
    fn reset_requires_an_explicit_complete_answer() -> Result<()> {
        for (input, expected) in [
            ("YES\n", true),
            ("y\n", true),
            ("\n", false),
            ("n\n", false),
            ("yes please\n", false),
            ("yes", false),
            ("", false),
        ] {
            let mut file = tempfile::tempfile()?;
            file.write_all(input.as_bytes())?;
            file.rewind()?;
            assert_eq!(read_confirmation(&mut file)?, expected, "{input:?}");
        }
        Ok(())
    }

    #[test]
    fn reset_reads_only_its_own_answer() -> Result<()> {
        let mut file = tempfile::tempfile()?;
        file.write_all(b"yes\n\n\n")?;
        file.rewind()?;
        assert!(read_confirmation(&mut file)?);
        assert!(read_enter(&mut file)?);
        assert!(read_enter(&mut file)?);
        assert!(!read_enter(&mut file)?);
        Ok(())
    }
}
