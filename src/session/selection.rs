//! Interpret the optional session name or directory and select its registry slot.
use std::{
    ffi::OsString,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use rustix::fs::{self, Mode, OFlags, ResolveFlags};

use super::admission::Entry;
use crate::journal::{JournalStore, validate_session_name};

#[derive(Args, Default)]
pub(crate) struct Selection {
    /// Saved session name, or a directory path (e.g. ./api).
    #[arg(value_name = "NAME_OR_PATH")]
    selector: Option<OsString>,
    /// Directory to associate with a name on first use.
    #[arg(long, value_name = "DIR")]
    path: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Slot {
    Default,
    Named(String),
    Direct((u64, u64)),
}

impl Slot {
    pub(super) fn open(
        &self,
        registry: &JournalStore,
        create: bool,
    ) -> Result<Option<JournalStore>> {
        match self {
            Self::Default => registry.reopen().map(Some),
            Self::Named(name) => registry.named(name, create),
            Self::Direct(id) => registry.direct(*id, create),
        }
    }

    pub(crate) fn title(&self) -> String {
        match self {
            Self::Default => "Default session".into(),
            Self::Named(name) => format!("Session {name}"),
            Self::Direct(_) => "Directory session".into(),
        }
    }

    pub(crate) fn label(&self, root: Option<&Path>) -> String {
        match self {
            Self::Default => "default".into(),
            Self::Named(name) => name.clone(),
            Self::Direct(_) => format!("directory {:?}", root.unwrap_or(Path::new("?"))),
        }
    }

    pub(crate) fn close_hint(&self, root: Option<&Path>) -> String {
        match self {
            Self::Default => {
                "Run 'sudo secret-guard lock' to rescan the roots and close access.".into()
            }
            Self::Named(name) => {
                format!("Run 'sudo secret-guard lock {name}' to close this session.")
            }
            Self::Direct(_) => format!(
                "Run 'sudo secret-guard lock' with the original directory as its argument: {:?}.",
                root.unwrap_or(Path::new("?"))
            ),
        }
    }
}

fn absolute_root(path: &Path) -> Result<PathBuf> {
    ensure!(
        !path.as_os_str().is_empty() && !path.components().any(|c| c == Component::ParentDir),
        "use a directory path without '..'"
    );
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let normal: PathBuf = absolute.components().collect();
    ensure!(
        normal.parent().is_some(),
        "the filesystem root cannot be a session directory"
    );
    Ok(normal)
}

impl Selection {
    pub(super) fn for_slot(slot: &Slot, root: Option<&Path>) -> Self {
        match slot {
            Slot::Default => Self::default(),
            Slot::Named(name) => Self {
                selector: Some(name.into()),
                path: None,
            },
            Slot::Direct(_) => Self {
                selector: None,
                path: root.map(Path::to_owned),
            },
        }
    }

    pub(super) fn resolve(&self, entries: &[Entry]) -> Result<(Slot, Option<PathBuf>)> {
        let root = self.path.as_deref().map(absolute_root).transpose()?;
        let direct = match self.selector.as_deref() {
            None => match root {
                Some(path) => path,
                None => return Ok((Slot::Default, None)),
            },
            Some(value) if value.as_bytes().contains(&b'/') || value == "." || value == ".." => {
                ensure!(root.is_none(), "supply one directory path");
                absolute_root(Path::new(value))?
            }
            Some(value) => {
                let name = value.to_str().context("session name must be ASCII")?;
                validate_session_name(name)?;
                return Ok((Slot::Named(name.to_owned()), root));
            }
        };
        // Prefer an open record at this exact location even after replacement.
        // Recovery then reports the original inode mismatch instead of creating a new slot.
        if let Some(entry) = entries
            .iter()
            .find(|e| matches!(e.slot, Slot::Direct(_)) && e.root() == Some(&direct))
        {
            return Ok((entry.slot.clone(), Some(direct)));
        }
        let fd = std::fs::File::from(
            fs::openat2(
                fs::CWD,
                &direct,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
            .with_context(|| format!("open session directory {direct:?}"))?,
        );
        let m = fd.metadata()?;
        let slot = Slot::Direct((m.dev(), m.ino()));
        if let Some(entry) = entries.iter().find(|e| e.slot == slot)
            && let Some(original) = entry.root()
        {
            ensure!(
                original == direct,
                "directory session is open at its original path {original:?}"
            );
        }
        Ok((slot, Some(direct)))
    }
}
