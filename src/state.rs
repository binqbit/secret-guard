//! Only operation metadata is persisted. The filesystem is the source of truth for file access.
use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::Access;
use serde::{Deserialize, Serialize};

use crate::{
    Scope,
    journal::JournalStore,
    runtime::{self, SessionSignals, User},
    tree::{Change, FileAccess, Tree},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Opening,
    Running,
    Closing,
    ManualOpening,
    Manual,
    ManualClosing,
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

    pub fn manual_scope(&self) -> Option<&Scope> {
        match self.phase {
            Phase::ManualOpening | Phase::Manual | Phase::ManualClosing => Some(self.scope()),
            Phase::Opening | Phase::Running | Phase::Closing => None,
        }
    }

    pub fn is_manual_open(&self) -> bool {
        matches!(self.phase, Phase::Manual)
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
        if let Err(error) = store.save(self) {
            // save may fail before rename or during the subsequent directory sync.
            // Consult the visible journal before deciding how to roll back.
            if let Ok(Some(committed)) = store.load::<Self>() {
                *self = committed;
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn begin_close(&mut self, store: &JournalStore) -> Result<()> {
        let was_manually_open = self.is_manual_open();
        let closing = if self.manual_scope().is_some() {
            Phase::ManualClosing
        } else {
            Phase::Closing
        };
        if let Err(error) = self.phase(store, closing) {
            // A committed manual opening permits subsequent unlocks. Invalidate that
            // permission to reopen before beginning any partial closing transition.
            if was_manually_open {
                return Err(error).context("record closing of manually unlocked files");
            }
            // All other journal phases already require recovery if the owner exits.
            eprintln!("Could not update the closing phase before locking: {error:#}");
        }
        Ok(())
    }
}

pub fn preflight(tree: &Tree, user: &User) -> Result<BTreeMap<PathBuf, FileAccess>> {
    let files = tree.scan()?;
    for (path, access) in &files {
        access
            .validate(user.uid)
            .with_context(|| format!("cannot open {path:?}"))?;
    }
    runtime::check_file_access(user, &files, Access::EXISTS)?;
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
            access.is_open(user.uid, user.gid),
            "file appeared or changed during session opening: {path:?}"
        );
    }
    runtime::check_file_access(user, &current, Access::READ_OK | Access::WRITE_OK)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn historical_v3_sessions_and_manual_recovery_keep_their_scope() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let store = JournalStore::open_test(&workspace.path().join("state"))?;
        assert!(store.try_exclusive()?);
        let root = workspace.path().join("project");
        std::fs::create_dir(&root)?;
        let scope = Scope {
            roots: vec![root.clone()],
            patterns: vec![".secrets/".into()],
            ignores: vec![],
        };
        let uid = 1000;
        let tree = Tree::new(&scope.roots, &scope.patterns, &scope.ignores, uid)?;
        let original = json!({
            "version": 3, "phase": "running", "user": "editor", "uid": uid, "pid": 123,
            "scope": &scope, "roots": tree.root_ids()?
        });
        for phase in ["opening", "running", "closing"] {
            let mut v3 = original.clone();
            v3["phase"] = json!(phase);
            store.save(&v3)?;
            let session: Session = store.load()?.unwrap();
            session.validate(&tree, uid, &scope)?;
            assert!(session.manual_scope().is_none());
            assert!(!session.is_manual_open());
        }
        let mut session: Session = store.load()?.unwrap();
        for phase in [Phase::ManualOpening, Phase::Manual, Phase::ManualClosing] {
            session.phase(&store, phase)?;
            let saved: Session = store.load()?.unwrap();
            saved.validate(&tree, uid, &scope)?;
            assert!(saved.manual_scope() == Some(&scope));
            assert_eq!(saved.is_manual_open(), matches!(phase, Phase::Manual));
        }
        session.phase(&store, Phase::Manual)?;
        session.begin_close(&store)?;
        let closing: Session = store.load()?.unwrap();
        assert!(matches!(closing.phase, Phase::ManualClosing));
        assert!(closing.validate(&tree, uid + 1, &scope).is_err());

        // A journal write refused before publication must leave the saved phase
        // in charge. Rollback can close an incomplete opening even if updating
        // the journal still fails. A deliberately open manual state requires a
        // durable transition before the first file may be relocked.
        let reader = JournalStore::open_test(&workspace.path().join("state"))?;
        session.phase(&store, Phase::ManualOpening)?;
        assert!(session.phase(&reader, Phase::Manual).is_err());
        assert!(matches!(session.phase, Phase::ManualOpening));
        session.begin_close(&reader)?;
        session.phase(&store, Phase::Manual)?;
        assert!(session.begin_close(&reader).is_err());
        assert!(session.is_manual_open());

        std::fs::rename(&root, workspace.path().join("original"))?;
        std::fs::create_dir(&root)?;
        let replacement = Tree::new(&scope.roots, &scope.patterns, &scope.ignores, uid)?;
        assert!(closing.validate(&replacement, uid, &scope).is_err());
        Ok(())
    }
}
