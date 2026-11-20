//! Session selectors and admission checks shared by all file operations.
use std::{
    ffi::OsString,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use rustix::fs::{self, Mode, OFlags, ResolveFlags};

use crate::{
    journal::{Binding, JournalStore, validate_session_name},
    overlap,
    state::Session,
    tree::Tree,
};

#[derive(Args, Default)]
pub struct Selection {
    /// Saved session name, or a directory path (e.g. ./api).
    #[arg(value_name = "NAME_OR_PATH")]
    selector: Option<OsString>,
    /// Directory to associate with a name on first use.
    #[arg(long, value_name = "DIR")]
    path: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Slot {
    Default,
    Named(String),
    Direct((u64, u64)),
}

impl Slot {
    pub fn open(&self, registry: &JournalStore, create: bool) -> Result<Option<JournalStore>> {
        match self {
            Self::Default => Ok(Some(JournalStore::open()?)),
            Self::Named(name) => registry.named(name, create),
            Self::Direct(id) => registry.direct(*id, create),
        }
    }

    pub fn print_heading(&self, root: Option<&Path>) {
        match (self, root) {
            (Self::Named(name), Some(path)) => println!("Session {name} ({path:?})"),
            _ => println!("Session {}", self.label(root)),
        }
    }

    pub fn label(&self, root: Option<&Path>) -> String {
        match self {
            Self::Default => "default".into(),
            Self::Named(name) => name.clone(),
            Self::Direct(_) => format!("directory {:?}", root.unwrap_or(Path::new("?"))),
        }
    }
}

pub struct Entry {
    pub slot: Slot,
    pub session: Option<Session>,
    pub idle: bool,
}

impl Entry {
    pub fn root(&self) -> Option<&Path> {
        self.session
            .as_ref()?
            .scope()
            .roots
            .first()
            .map(PathBuf::as_path)
    }
}

// Caller holds the admission lock. A short-lived, independent flock probe
// distinguishes a running supervisor from a durable manual or recovery journal.
pub fn operations(registry: &JournalStore) -> Result<Vec<Entry>> {
    let mut slots = vec![Slot::Default];
    slots.extend(registry.names()?.into_iter().map(Slot::Named));
    slots.extend(registry.direct_ids()?.into_iter().map(Slot::Direct));
    let mut entries = Vec::new();
    for slot in slots {
        let store = slot
            .open(registry, false)?
            .context("session state disappeared")?;
        let idle = store.try_exclusive()?;
        let session = store.load()?;
        if !idle || session.is_some() {
            entries.push(Entry {
                slot,
                idle,
                session,
            });
        }
    }
    Ok(entries)
}

pub fn check_other_roots(entries: &[Entry], selected: &Slot, tree: &Tree) -> Result<()> {
    for other in entries.iter().filter(|other| other.slot != *selected) {
        let label = other.slot.label(other.root());
        let session = other.session.as_ref().with_context(|| {
            format!("session {label} is busy; retry after its operation finishes")
        })?;
        overlap::check_disjoint(tree, session)
            .with_context(|| format!("conflict with open session {label}"))?;
    }
    Ok(())
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
    pub fn resolve(&self, entries: &[Entry]) -> Result<(Slot, Option<PathBuf>)> {
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

pub fn named_root(
    name: &str,
    binding: Option<Binding>,
    supplied: Option<PathBuf>,
    uid: u32,
    mutate: bool,
) -> Result<PathBuf> {
    if let Some(binding) = binding {
        ensure!(
            !mutate || binding.uid == uid,
            "session {name} belongs to UID {}",
            binding.uid
        );
        if let Some(path) = supplied {
            ensure!(
                path == binding.path,
                "session {name} is already associated with {:?}",
                binding.path
            );
        }
        Ok(binding.path)
    } else {
        supplied.with_context(|| format!("unknown session {name}; supply --path DIR on first use"))
    }
}

pub fn close_hint(slot: &Slot, root: Option<&Path>) -> String {
    match slot {
        Slot::Default => {
            "Run 'sudo secret-guard lock' to rescan the roots and close access.".into()
        }
        Slot::Named(name) => format!("Run 'sudo secret-guard lock {name}' to close this session."),
        Slot::Direct(_) => format!(
            "Run 'sudo secret-guard lock' with the original directory as its argument: {:?}.",
            root.unwrap_or(Path::new("?"))
        ),
    }
}
