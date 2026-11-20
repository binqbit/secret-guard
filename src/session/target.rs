//! Resolve a selected slot to its binding, verified tree and journal.

use std::{fs::File, path::PathBuf};

use anyhow::{Context, Result, ensure};

use super::{
    admission::Entry,
    selection::{Selection, Slot},
};
use crate::{
    config::{self, Scope},
    journal::{Binding, JournalStore, Session},
    runtime::User,
    tree::{Tree, overlap},
};

pub(super) struct Target {
    pub(super) slot: Slot,
    pub(super) root: Option<PathBuf>,
    store: Option<JournalStore>,
    pub(super) binding_uid: Option<u32>,
}

impl Target {
    pub(super) fn resolve(
        registry: &JournalStore,
        entries: &[Entry],
        selection: &Selection,
        uid: u32,
        mutate: bool,
    ) -> Result<Self> {
        let (slot, supplied) = selection.resolve(entries)?;
        let store = slot.open(registry, false)?;

        let (root, binding_uid) = if let Slot::Named(name) = &slot {
            let binding = store
                .as_ref()
                .map(JournalStore::binding)
                .transpose()?
                .flatten();
            let owner = binding.as_ref().map(|binding| binding.uid);
            (
                Some(named_root(name, binding, supplied, uid, mutate)?),
                owner,
            )
        } else {
            (supplied, None)
        };

        Ok(Self {
            slot,
            root,
            store,
            binding_uid,
        })
    }

    pub(super) fn hint(&self) -> String {
        self.slot.close_hint(self.root.as_deref())
    }

    pub(super) fn tree(
        &self,
        caller: &User,
        owner_uid: u32,
        saved: Option<&Scope>,
        session: Option<&Session>,
    ) -> Result<(Scope, Tree)> {
        let scope = match saved {
            Some(scope) => scope.clone(),
            None => {
                config::initialize_if_needed(&caller.home)?;
                config::read_config(self.root.as_deref())?
            }
        };

        let tree = Tree::new(&scope.roots, &scope.patterns, &scope.ignores, owner_uid)?;
        if let Slot::Direct(id) = self.slot {
            ensure!(
                tree.root_ids()?.as_slice() == [id],
                "restore the original directory for this session"
            );
        }

        if let Some(session) = session {
            session.validate(&tree, owner_uid, &scope)?;
            overlap::check_protected_roots(&tree)?;
        } else {
            overlap::check_selection(&tree)?;
        }

        Ok((scope, tree))
    }

    pub(super) fn lock_existing(&self, approved: Option<&File>) -> Result<Option<Session>> {
        let Some(store) = &self.store else {
            ensure!(
                approved.is_none(),
                "the confirmed session has already closed; run session again"
            );
            return Ok(None);
        };

        ensure!(
            store.try_exclusive()?,
            "session {} is already active; inspect it with status",
            self.slot.label(self.root.as_deref())
        );
        if let Some(snapshot) = approved {
            store.verify_session(snapshot)?;
        }

        store.load()
    }

    pub(super) fn claim(&mut self, registry: &JournalStore, uid: u32) -> Result<JournalStore> {
        let store = match self.store.take() {
            Some(store) => store, // lock_existing already holds this flock
            None => {
                let store = self
                    .slot
                    .open(registry, true)?
                    .context("create session state")?;
                ensure!(store.try_exclusive()?, "session is busy");
                store
            }
        };

        if matches!(self.slot, Slot::Named(_)) && self.binding_uid.is_none() {
            let path = self
                .root
                .clone()
                .context("missing directory for named session")?;
            store.bind_if_absent(&Binding { uid, path })?;
        }
        Ok(store)
    }
}

fn named_root(
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
