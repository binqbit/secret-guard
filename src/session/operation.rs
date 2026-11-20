//! Admit a mutation, supervise file access, and release its journal and locks.
use std::{ffi::OsString, fs::File, io::Write};

use anyhow::{Context, Result, bail, ensure};

use super::{
    access, admission,
    display::AccessMessage,
    selection::{Selection, Slot},
    target::Target,
};
use crate::{
    config::Scope,
    journal::{JournalStore, Phase, Session},
    runtime::{self, SessionSignals, User},
    tree::Tree,
};

pub(crate) enum Mutation<'a> {
    Lock,
    Unlock,
    Session(&'a [OsString]),
}

impl Mutation<'_> {
    fn command(&self) -> Option<&[OsString]> {
        match self {
            Self::Session(command) => Some(command),
            _ => None,
        }
    }
}

pub(crate) fn run(
    registry: &JournalStore,
    user: &User,
    selection: &Selection,
    request: Mutation<'_>,
) -> Result<i32> {
    let admission = registry.admission()?;
    let entries = admission::operations(registry)?;
    let mut target = Target::resolve(registry, &entries, selection, user.uid, true)?;
    let existing = target.lock_existing()?;
    let saved = existing.as_ref().and_then(|s| match target.slot {
        Slot::Default => s.manual_scope(),
        _ => Some(s.scope()),
    });
    let (scope, tree) = target.tree(user, user.uid, saved, existing.as_ref())?;
    admission::check_other_roots(&entries, &target.slot, &tree)?;
    let hint = target.hint();
    if let Some(s) = &existing {
        match &request {
            Mutation::Session(_) if s.is_manual_open() => {
                bail!("files are manually unlocked. {hint}")
            }
            Mutation::Session(_) => bail!("an unfinished operation was found. {hint}"),
            Mutation::Unlock if !s.is_manual_open() => {
                bail!("an unfinished operation was found. {hint}")
            }
            _ => (),
        }
    }
    if request.command().is_some_and(<[OsString]>::is_empty) {
        runtime::check_interactive()?;
    }
    let signals = SessionSignals::install()?;
    let store = target.claim(registry, user.uid)?;
    let op = Operation {
        registry,
        store,
        slot: target.slot,
        scope,
        tree,
        user,
        signals: &signals,
    };
    let mut admission = Some(admission);
    let result = match request {
        Mutation::Lock => op.lock(existing, &mut admission),
        Mutation::Unlock => op.open(None, existing, &mut admission),
        Mutation::Session(command) => op.open(Some(command), existing, &mut admission),
    };
    op.release_after(result, admission, &hint)
}

struct Operation<'a> {
    registry: &'a JournalStore,
    store: JournalStore,
    slot: Slot,
    scope: Scope,
    tree: Tree,
    user: &'a User,
    signals: &'a SessionSignals,
}

impl Operation<'_> {
    fn release_empty_slot(&self) -> Result<()> {
        if let Slot::Direct(id) = self.slot {
            self.registry.remove_direct(id, &self.store)?;
        }
        self.store.release()
    }

    fn finish(&self) -> Result<()> {
        // End the journal and release the slot flock as one admission decision.
        let _guard = self.registry.admission()?;
        self.store.finish()?;
        self.release_empty_slot()
    }

    fn close(&self) -> Result<()> {
        access::close(&self.tree, self.user, self.signals, || {
            let _guard = self.registry.admission()?;
            admission::check_other_roots(
                &admission::operations(self.registry)?,
                &self.slot,
                &self.tree,
            )
        })?;
        self.finish()
    }

    fn release_after(
        &self,
        result: Result<i32>,
        admission: Option<File>,
        hint: &str,
    ) -> Result<i32> {
        if !self.store.holds_lock() {
            return result;
        }
        let remaining = (|| -> Result<bool> {
            let _guard = match admission {
                Some(guard) => guard,
                None => self.registry.admission()?,
            };
            let session = self.store.load::<Session>()?;
            if session.is_some() {
                self.store.release()?;
            } else {
                self.release_empty_slot()?;
            }
            Ok(session.is_some())
        })();
        let stderr = std::io::stderr();
        match remaining {
            Ok(true) if result.is_err() => {
                let _ = writeln!(stderr.lock(), "Operation remains OPEN. {hint}");
            }
            Err(cleanup) => {
                let _ = writeln!(
                    stderr.lock(),
                    "Cannot confirm a locked state. Inspect it with status."
                );
                return Err(cleanup).with_context(|| match result {
                    Err(e) => {
                        format!("operation failed ({e:#}); releasing session state also failed")
                    }
                    Ok(_) => "release session state".into(),
                });
            }
            _ => (),
        }
        result
    }

    fn begin_close(&self, session: &mut Session) -> Result<()> {
        if let Some(error) = session.begin_close(&self.store)? {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(
                err,
                "Could not update the closing phase before locking: {error:#}"
            );
        }
        Ok(())
    }

    fn lock(&self, session: Option<Session>, admission: &mut Option<File>) -> Result<i32> {
        match session {
            Some(mut s) => self.begin_close(&mut s)?,
            None => {
                Session::start(
                    &self.store,
                    &self.tree,
                    self.user,
                    &self.scope,
                    Phase::Closing,
                )?;
            }
        }
        drop(admission.take());
        self.close()?;
        AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
        Ok(0)
    }

    fn open(
        &self,
        command: Option<&[OsString]>,
        existing: Option<Session>,
        admission: &mut Option<File>,
    ) -> Result<i32> {
        let phase = if command.is_some() {
            Phase::Opening
        } else {
            Phase::ManualOpening
        };
        let fresh = existing.is_none();
        let mut session = match existing {
            Some(s) => s,
            None => Session::start(&self.store, &self.tree, self.user, &self.scope, phase)?,
        };
        // The durable scope now excludes competing operations during the file scan.
        drop(admission.take());
        let preflight = access::preflight(&self.tree, self.user).and_then(|files| {
            ensure!(
                !self.signals.interrupted(),
                "interrupted before opening the session"
            );
            Ok(files)
        });
        let files = match preflight {
            Ok(files) => files,
            Err(e) => {
                if fresh {
                    self.finish()
                        .with_context(|| format!("{e:#}; release unopened session"))?;
                }
                return Err(e);
            }
        };
        if !fresh {
            session.phase(&self.store, phase)?;
        }
        let interactive = command.is_some_and(<[OsString]>::is_empty);
        let result = (|| -> Result<i32> {
            access::open_files(&self.tree, self.user, &files, || self.signals.interrupted())?;
            if let Some(command) = command {
                session.phase(&self.store, Phase::Running)?;
                AccessMessage::Unlocked.session(interactive)?;
                self.signals.run(self.user, command)
            } else {
                ensure!(!self.signals.interrupted(), "manual unlock interrupted");
                session.phase(&self.store, Phase::Manual)?;
                AccessMessage::Unlocked.write(&mut std::io::stdout().lock())?;
                Ok(0)
            }
        })();
        if command.is_none() && result.is_ok() {
            return result;
        }

        self.begin_close(&mut session)
            .and_then(|()| self.close())
            .with_context(|| match &result {
                Err(e) => format!("operation failed ({e:#}); closing also failed"),
                Ok(_) => "closing the session failed".to_string(),
            })?;
        if command.is_some() {
            AccessMessage::Locked.session(interactive)?;
        } else {
            AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
        }
        result
    }
}
