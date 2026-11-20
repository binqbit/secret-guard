//! Inspect open sessions under the admission lock and detect conflicting requests.
use std::{
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use super::selection::{Selection, Slot};
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

struct Conflict<'a> {
    entry: &'a Entry,
    session: &'a Session,
    reason: String,
}

fn conflicts<'a>(
    entries: &'a [Entry],
    selected: &Slot,
    tree: &Tree,
    starting_session: bool,
) -> Result<Vec<Conflict<'a>>> {
    let mut conflicts = Vec::new();
    for entry in entries
        .iter()
        .filter(|entry| starting_session || entry.slot != *selected)
    {
        let label = entry.slot.label(entry.root());
        let session = entry.session.as_ref().with_context(|| {
            format!("session {label} is busy; retry after its operation finishes")
        })?;
        let reason = if entry.slot == *selected {
            if session.is_manual_open() {
                "files are manually unlocked".into()
            } else {
                "an unfinished operation was found".into()
            }
        } else {
            let Some((requested, open)) =
                overlap::overlapping_roots(tree, &session.scope().roots, session.root_ids())
                    .with_context(|| format!("check roots of open session {label}"))?
            else {
                continue;
            };
            format!(
                "conflict with open session {label}: session roots overlap: {requested:?} and {open:?}"
            )
        };
        conflicts.push(Conflict {
            entry,
            session,
            reason,
        });
    }
    Ok(conflicts)
}

pub(super) fn check_other_roots(entries: &[Entry], selected: &Slot, tree: &Tree) -> Result<()> {
    if let Some(conflict) = conflicts(entries, selected, tree, false)?.first() {
        anyhow::bail!("{}", conflict.reason);
    }
    Ok(())
}

pub(super) struct ResetOffer {
    pub selection: Selection,
    pub journal: File,
    pub label: String,
    pub roots: Vec<PathBuf>,
    pub kind: &'static str,
    pub close_hint: String,
}

pub(super) fn reset_offer(
    registry: &JournalStore,
    entries: &[Entry],
    selected: &Slot,
    tree: &Tree,
    uid: u32,
    command: Option<&[OsString]>,
) -> Result<Option<ResetOffer>> {
    let conflicts = conflicts(entries, selected, tree, command.is_some())?;
    // Check all blockers before offering to close any of them. A live or foreign
    // session still prevents the request even if a different journal is recoverable.
    for conflict in &conflicts {
        let entry = conflict.entry;
        ensure!(
            entry.idle,
            "{}; finish the active session in its own terminal",
            conflict.reason
        );
        ensure!(
            conflict.session.uid == uid,
            "{}; the session belongs to UID {}",
            conflict.reason,
            conflict.session.uid
        );
        ensure!(
            command.is_some_and(<[OsString]>::is_empty),
            "{}. {}",
            conflict.reason,
            entry.slot.close_hint(entry.root())
        );
    }
    let Some(conflict) = conflicts.first() else {
        return Ok(None);
    };
    let entry = conflict.entry;
    let store = entry
        .slot
        .open(registry, false)?
        .context("session has already closed")?;
    Ok(Some(ResetOffer {
        selection: Selection::for_slot(&entry.slot, entry.root()),
        label: entry.slot.title(),
        roots: conflict.session.scope().roots.clone(),
        journal: store.pin_session()?,
        kind: if conflict.session.is_manual_open() {
            "manually unlocked"
        } else {
            "awaiting recovery"
        },
        close_hint: entry.slot.close_hint(entry.root()),
    }))
}
