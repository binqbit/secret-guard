//! Render session progress and file status for terminals and scripts.
use super::selection::Slot;
use crate::{
    config::Scope,
    journal::Session,
    output::{Palette, Tone},
    runtime::User,
    tree::FileAccess,
};
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
        let (label, tone) = match self {
            Self::Unlocked => ("UNLOCKED", Tone::Open),
            Self::Locked => ("LOCKED", Tone::Locked),
        };
        writeln!(out, "{}", Palette::for_stream(out).paint(tone, label))?;
        out.flush()?;
        Ok(())
    }

    pub(super) fn session(self, interactive: bool, slot: &Slot, scope: &Scope) -> Result<()> {
        if interactive {
            let mut tty = OpenOptions::new().write(true).open("/dev/tty")?;
            if matches!(self, Self::Unlocked) {
                let palette = Palette::for_stream(&tty);
                writeln!(tty, "{}", palette.paint(Tone::Heading, slot.title()))?;
                for root in &scope.roots {
                    writeln!(tty, "  {root:?}")?;
                }
            }
            self.write(&mut tty)
        } else {
            self.write(&mut io::stderr().lock())
        }
    }
}

pub(super) fn session_heading(
    out: &mut impl Write,
    slot: &Slot,
    root: Option<&Path>,
    palette: &Palette,
) -> io::Result<()> {
    let heading = match (slot, root) {
        (Slot::Default, _) => "Default session".into(),
        (Slot::Named(name), Some(path)) => format!("Session {name} ({path:?})"),
        _ => format!("Session {}", slot.label(root)),
    };
    writeln!(out, "{}", palette.paint(Tone::Heading, heading))
}

pub(super) fn describe(
    out: &mut impl Write,
    session: Option<&Session>,
    idle: bool,
    hint: &str,
    palette: &Palette,
) -> io::Result<()> {
    let Some(s) = session else {
        return if idle {
            writeln!(out, "No open session.")
        } else {
            writeln!(
                out,
                "{}",
                palette.paint(Tone::Warning, "Another operation holds the lock.")
            )
        };
    };
    if s.is_manual_open() {
        return writeln!(
            out,
            "{} (user {:?}, UID {})",
            palette.paint(Tone::Open, "OPEN / manual"),
            s.user,
            s.uid
        );
    }
    let (activity, tone) = if idle {
        ("OPEN / recovery required", Tone::Warning)
    } else {
        ("OPEN / active", Tone::Open)
    };
    writeln!(
        out,
        "{} ({:?}, user {:?}, UID {}, supervisor PID {})",
        palette.paint(tone, activity),
        s.phase,
        s.user,
        s.uid,
        s.pid
    )?;
    if idle {
        writeln!(out, "{}", palette.paint(Tone::Action, hint))?;
    }
    Ok(())
}

pub(super) fn show_files(
    files: BTreeMap<PathBuf, FileAccess>,
    user: &User,
    paths: bool,
) -> io::Result<()> {
    let mut out = io::stdout().lock();
    if paths {
        for path in files.keys() {
            writeln!(out, "{path:?}")?;
        }
        return Ok(());
    }
    let palette = Palette::for_stream(&out);
    let mut owner_width = "UID:GID".len();
    if palette.is_terminal() {
        if files.is_empty() {
            writeln!(out, "\nNo files match the selected rules.")?;
            return Ok(());
        }
        for access in files.values() {
            owner_width = owner_width.max(format!("{}:{}", access.uid, access.gid).len());
        }
        writeln!(
            out,
            "\n{}",
            palette.paint(
                Tone::Heading,
                format_args!("Matching files ({})", files.len())
            )
        )?;
        writeln!(
            out,
            "{:<20}  {:<owner_width$}  MODE  PATH",
            "ACCESS", "UID:GID"
        )?;
    }
    for (path, access) in files {
        let (label, tone) = if access.is_locked(user.uid) {
            ("locked", Tone::Locked)
        } else if access.is_open(user.uid, user.gid) {
            ("owner-only mode", Tone::Open)
        } else if access.is_public(user.uid, user.gid) {
            ("public-read mode", Tone::Warning)
        } else {
            ("unmanaged or changed", Tone::Warning)
        };
        let owner = format!("{}:{}", access.uid, access.gid);
        if palette.is_terminal() {
            writeln!(
                out,
                "{:<20}  {owner:<owner_width$}  {:04o}  {path:?}",
                palette.paint(tone, label),
                access.mode
            )?;
        } else {
            writeln!(out, "{label}  {owner} {:04o}  {path:?}", access.mode)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn status_reports_a_closed_output_pipe_without_panicking() {
        let (reader, mut writer) = io::pipe().unwrap();
        drop(reader);
        let palette = Palette::for_stream(&writer.as_fd());
        let heading = session_heading(&mut writer, &Slot::Default, None, &palette).unwrap_err();
        let status = describe(&mut writer, None, true, "", &palette).unwrap_err();
        assert_eq!(heading.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(status.kind(), io::ErrorKind::BrokenPipe);
    }
}
