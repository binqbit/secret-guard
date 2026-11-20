//! Render session progress and file status for terminals and scripts.
use super::selection::Slot;
use crate::{journal::Session, runtime::User, tree::FileAccess};
use anyhow::Result;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

pub(super) enum AccessMessage {
    Unlocked,
    Locked,
}

impl AccessMessage {
    pub(super) fn write(self, out: &mut (impl Write + IsTerminal)) -> Result<()> {
        let (label, color) = match self {
            Self::Unlocked => ("UNLOCKED", 32),
            Self::Locked => ("LOCKED", 31),
        };
        if out.is_terminal() {
            writeln!(out, "\x1b[{color}m{label}\x1b[0m")?;
        } else {
            writeln!(out, "{label}")?;
        }
        out.flush()?;
        Ok(())
    }

    pub(super) fn session(self, interactive: bool) -> Result<()> {
        if interactive {
            self.write(&mut OpenOptions::new().write(true).open("/dev/tty")?)
        } else {
            self.write(&mut std::io::stderr().lock())
        }
    }
}

pub(super) fn session_heading(
    out: &mut impl Write,
    slot: &Slot,
    root: Option<&Path>,
) -> io::Result<()> {
    let heading = match (slot, root) {
        (Slot::Default, _) => slot.title(),
        (Slot::Named(name), Some(path)) => format!("Session {name} ({path:?})"),
        _ => format!("Session {}", slot.label(root)),
    };
    writeln!(out, "{heading}")
}

pub(super) fn describe(
    out: &mut impl Write,
    session: Option<&Session>,
    idle: bool,
    hint: &str,
) -> io::Result<()> {
    if let Some(s) = session {
        if s.is_manual_open() {
            writeln!(out, "OPEN / manual (user {:?}, UID {})", s.user, s.uid)?;
            return Ok(());
        }
        let activity = if idle {
            "OPEN / recovery required"
        } else {
            "OPEN / active"
        };
        writeln!(
            out,
            "{activity} ({:?}, user {:?}, UID {}, supervisor PID {})",
            s.phase, s.user, s.uid, s.pid
        )?;
        if idle {
            writeln!(out, "{hint}")?;
        }
    } else if idle {
        writeln!(out, "No open session.")?;
    } else {
        writeln!(out, "Another operation holds the lock.")?;
    }
    Ok(())
}

pub(super) fn show_files(
    files: BTreeMap<PathBuf, FileAccess>,
    user: &User,
    paths: bool,
) -> io::Result<()> {
    let mut out = io::stdout().lock();
    for (path, access) in files {
        if paths {
            writeln!(out, "{path:?}")?;
        } else {
            let label = if access.is_locked(user.uid) {
                "locked"
            } else if access.is_open(user.uid, user.gid) {
                "owner-only mode"
            } else if access.is_public(user.uid, user.gid) {
                "public-read mode"
            } else {
                "unmanaged or changed"
            };
            writeln!(
                out,
                "{label}  {}:{} {:04o}  {path:?}",
                access.uid, access.gid, access.mode
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_a_closed_output_pipe_without_panicking() {
        let (reader, mut writer) = io::pipe().unwrap();
        drop(reader);
        let heading = session_heading(&mut writer, &Slot::Default, None).unwrap_err();
        let status = describe(&mut writer, None, true, "").unwrap_err();
        assert_eq!(heading.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(status.kind(), io::ErrorKind::BrokenPipe);
    }
}
