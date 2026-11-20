//! Inspect open sessions under the admission lock and detect conflicting requests.

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use super::{
    operation::Mutation,
    selection::{Selection, Slot},
};
use crate::{
    journal::{JournalStore, Session},
    tree::{Tree, overlap},
};

pub(crate) struct Entry {
    pub slot: Slot,
    pub session: Option<Session>,
    pub receipts: Vec<Session>,
    pub idle: bool,
}

impl Entry {
    pub fn occupies_slot(&self) -> bool {
        !self.idle || self.session.is_some()
    }

    pub fn root(&self) -> Option<&Path> {
        self.session
            .as_ref()
            .or_else(|| self.receipts.last())?
            .scope()
            .roots
            .first()
            .map(PathBuf::as_path)
    }

    pub fn has_receipt_at(&self, path: &Path) -> bool {
        self.receipts
            .iter()
            .any(|r| r.scope().roots.iter().any(|root| root == path))
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
        let mut session = store.load::<Session>()?;
        let mut receipts = store.receipts()?;
        // Version 1.0.0 stored a completed unlock in session.json. Reading
        // status must also work before any command migrates that slot.
        if idle && let Some(completed) = session.take_if(|s| s.is_manual_open()) {
            completed.validate_receipt()?;
            receipts.retain(|r| !r.same_selection(&completed));
            receipts.push(completed);
        }

        if !idle || session.is_some() || !receipts.is_empty() {
            entries.push(Entry {
                slot,
                idle,
                session,
                receipts,
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
        .filter(|entry| entry.occupies_slot() && (starting_session || entry.slot != *selected))
    {
        let label = entry.slot.label(entry.root());
        let session = entry.session.as_ref().with_context(|| {
            format!("session {label} is busy; retry after its operation finishes")
        })?;

        let reason = if entry.slot == *selected {
            "an unfinished operation was found".into()
        } else {
            let Some((requested, open)) = overlap::overlapping_roots(
                tree,
                &session.scope().roots,
                session.root_ids(),
                &session.scope().ignores,
            )
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
    pub close_hint: String,
}

pub(super) fn reset_offer(
    registry: &JournalStore,
    entries: &[Entry],
    selected: &Slot,
    tree: &Tree,
    uid: u32,
    request: Mutation<'_>,
    approved: bool,
) -> Result<Option<ResetOffer>> {
    let include_selected = !approved && !matches!(request, Mutation::Lock);
    let conflicts = conflicts(entries, selected, tree, include_selected)?;

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
            matches!(request, Mutation::Session([]))
                || (matches!(request, Mutation::Unlock) && entry.slot == *selected),
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
        close_hint: entry.slot.close_hint(entry.root()),
    }))
}
