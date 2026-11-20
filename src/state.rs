//! Only operation metadata is persisted. The filesystem is the source of truth for file access.
use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    Scope,
    journal::JournalStore,
    runtime::{SessionSignals, User},
    tree::{Change, FileAccess, Tree},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Opening,
    Running,
    Closing,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    version: u32,
    pub phase: Phase,
    pub user: String,
    pub uid: u32,
    pub pid: u32,
    scope: Scope,
    roots: Vec<(u64, u64)>,
}

impl Session {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn start(
        store: &JournalStore,
        tree: &Tree,
        user: &User,
        scope: &Scope,
        phase: Phase,
    ) -> Result<Self> {
        let session = Self {
            version: 3,
            phase,
            user: user.name.clone(),
            uid: user.uid,
            pid: std::process::id(),
            scope: scope.clone(),
            roots: tree.root_ids()?,
        };
        store.save(&session)?;
        Ok(session)
    }

    pub fn validate(&self, tree: &Tree, uid: u32, scope: &Scope) -> Result<()> {
        ensure!(self.version == 3, "unsupported session journal version");
        ensure!(
            self.uid == uid && self.scope == *scope,
            "restore the original session user, roots and selection rules before recovery"
        );
        ensure!(
            self.roots == tree.root_ids()?,
            "restore the original root directories before recovery"
        );
        Ok(())
    }

    pub fn phase(&mut self, store: &JournalStore, phase: Phase) -> Result<()> {
        self.phase = phase;
        self.pid = std::process::id();
        store.save(self)
    }
}

pub fn preflight(tree: &Tree, user: &User) -> Result<BTreeMap<PathBuf, FileAccess>> {
    let files = tree.scan()?;
    for (path, access) in &files {
        access
            .validate_open(user.uid)
            .with_context(|| format!("cannot open {path:?}"))?;
        tree.check_public_parents(path)?;
    }
    Ok(files)
}

pub fn open_files(
    tree: &Tree,
    user: &User,
    files: &BTreeMap<PathBuf, FileAccess>,
    interrupted: impl Fn() -> bool,
) -> Result<()> {
    for (path, access) in files {
        ensure!(!interrupted(), "session opening interrupted");
        let change = tree
            .set_access(path, access, true, user.gid)
            .with_context(|| format!("cannot open {path:?}"))?;
        ensure!(
            matches!(change, Change::Done),
            "file is in use and could not be opened: {path:?}"
        );
    }
    let current = tree.scan()?;
    for (path, access) in &current {
        ensure!(
            access.is_public(user.uid, user.gid),
            "file appeared or changed during session opening: {path:?}"
        );
        tree.check_public_parents(path)?;
    }
    Ok(())
}

/// Closing starts with a fresh scan so new files and editor replacements get locked too.
pub fn close(
    store: &JournalStore,
    tree: &Tree,
    user: &User,
    signals: &SessionSignals,
) -> Result<()> {
    loop {
        let pending = close_pass(tree, user)?;
        if pending.is_empty() {
            return store.finish();
        }
        signals.wait_for_retry(&pending)?;
    }
}

fn close_pass(tree: &Tree, user: &User) -> Result<Vec<PathBuf>> {
    let mut busy = std::collections::BTreeSet::new();
    let mut failures = Vec::new();
    for (path, access) in tree.scan()? {
        match tree.set_access(&path, &access, false, user.gid) {
            Ok(Change::Done) => (),
            Ok(Change::Busy) => {
                busy.insert(path);
            }
            Err(e) => failures.push(format!("{path:?}: {e:#}")),
        }
    }
    if !failures.is_empty() {
        failures.extend(busy.iter().map(|path| format!("{path:?}: still in use")));
        bail!("could not lock all files:\n{}", failures.join("\n"));
    }

    let mut pending = Vec::new();
    for (path, access) in tree.scan()? {
        if busy.contains(&path) {
            pending.push(path);
        } else {
            ensure!(
                access.is_locked(user.uid),
                "file appeared or changed during closing: {path:?}; retry lock"
            );
        }
    }
    Ok(pending)
}
