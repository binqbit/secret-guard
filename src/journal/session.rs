//! Versioned session metadata and durable phase transitions.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::JournalStore;
use crate::{config::Scope, runtime::User, tree::Tree};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Phase {
    Opening,
    Running,
    Closing,
    ManualOpening,
    Manual,
    ManualClosing,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Session {
    version: u32,
    pub(crate) phase: Phase,
    pub(crate) user: String,
    pub(crate) uid: u32,
    pub(crate) pid: u32,
    scope: Scope,
    roots: Vec<(u64, u64)>,
}

impl Session {
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    pub(crate) fn root_ids(&self) -> &[(u64, u64)] {
        &self.roots
    }

    pub(crate) fn manual_scope(&self) -> Option<&Scope> {
        match self.phase {
            Phase::ManualOpening | Phase::Manual | Phase::ManualClosing => Some(self.scope()),
            Phase::Opening | Phase::Running | Phase::Closing => None,
        }
    }

    pub(crate) fn is_manual_open(&self) -> bool {
        matches!(self.phase, Phase::Manual)
    }

    pub(crate) fn start(
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

    pub(crate) fn validate(&self, tree: &Tree, uid: u32, scope: &Scope) -> Result<()> {
        ensure!(self.version == 3, "unsupported session journal version");
        ensure!(
            self.uid == uid,
            "session belongs to UID {}; recover it as the original user",
            self.uid
        );
        ensure!(
            self.scope == *scope,
            "restore the original session user, roots and selection rules before recovery"
        );
        ensure!(
            self.roots == tree.root_ids()?,
            "restore the original root directories before recovery"
        );
        Ok(())
    }

    pub(crate) fn phase(&mut self, store: &JournalStore, phase: Phase) -> Result<()> {
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

    /// Record the closing phase. `Ok(Some(error))` allows relocking when the
    /// preceding phase already requires recovery and the new write failed.
    pub(crate) fn begin_close(&mut self, store: &JournalStore) -> Result<Option<anyhow::Error>> {
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
            return Ok(Some(error));
        }
        Ok(None)
    }
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
        assert!(session.begin_close(&store)?.is_none());
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
        let warning = session
            .begin_close(&reader)?
            .expect("report the failed phase write");
        assert!(warning.to_string().contains("exclusive state lock"));
        assert!(matches!(session.phase, Phase::ManualOpening));
        session.phase(&store, Phase::Manual)?;
        let error = session
            .begin_close(&reader)
            .expect_err("a manual session needs a durable closing phase");
        assert_eq!(
            error.to_string(),
            "record closing of manually unlocked files"
        );
        assert!(session.is_manual_open());

        std::fs::rename(&root, workspace.path().join("original"))?;
        std::fs::create_dir(&root)?;
        let replacement = Tree::new(&scope.roots, &scope.patterns, &scope.ignores, uid)?;
        assert!(closing.validate(&replacement, uid, &scope).is_err());
        Ok(())
    }
}
