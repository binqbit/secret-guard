//! Inspect open sessions under the admission lock and detect conflicting requests.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::selection::Slot;
use crate::{
    journal::{JournalStore, Session},
    tree::{Tree, overlap},
};

pub(crate) struct Entry {
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
pub(crate) fn operations(registry: &JournalStore) -> Result<Vec<Entry>> {
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

pub(super) fn check_other_roots(entries: &[Entry], selected: &Slot, tree: &Tree) -> Result<()> {
    for other in entries.iter().filter(|other| other.slot != *selected) {
        let label = other.slot.label(other.root());
        let session = other.session.as_ref().with_context(|| {
            format!("session {label} is busy; retry after its operation finishes")
        })?;
        if let Some((requested, open)) =
            overlap::overlapping_roots(tree, &session.scope().roots, session.root_ids())
                .with_context(|| format!("check roots of open session {label}"))?
        {
            bail!(
                "conflict with open session {label}: session roots overlap: {requested:?} and {open:?}"
            );
        }
    }
    Ok(())
}
