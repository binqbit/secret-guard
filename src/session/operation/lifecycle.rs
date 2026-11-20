//! Supervise permission changes and release the session journal and locks.

use std::{ffi::OsString, fs::File, io::Write};

use anyhow::{Context, Result, ensure};

use crate::{
    config::Scope,
    journal::{JournalStore, Phase, Session},
    output::{Palette, Tone},
    runtime::{SessionSignals, User},
    session::{access, admission, display::AccessMessage, selection::Slot, target::saved_tree},
    tree::Tree,
};

pub(super) struct Operation<'a> {
    pub(super) registry: &'a JournalStore,
    pub(super) store: JournalStore,
    pub(super) slot: Slot,
    pub(super) scope: Scope,
    pub(super) tree: Tree,
    pub(super) user: &'a User,
    pub(super) signals: &'a SessionSignals,
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

    fn close_files(&self) -> Result<()> {
        access::close(&self.tree, self.user, self.signals, || {
            let _guard = self.registry.admission()?;
            admission::check_other_roots(
                &admission::operations(self.registry)?,
                &self.slot,
                &self.tree,
            )
        })
    }

    pub(super) fn release_after(
        &self,
        result: Result<i32>,
        admission: Option<File>,
        hint: &str,
    ) -> Result<i32> {
        if !self.store.holds_lock() {
            return result;
        }

        let remaining = (|| -> Result<Option<Session>> {
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
            Ok(session)
        })();

        let stderr = std::io::stderr();
        let palette = Palette::for_stream(&stderr);
        match remaining {
            Ok(Some(session)) if result.is_err() => {
                let state = if session.is_manual_open() {
                    "Files remain unlocked."
                } else {
                    "Operation remains OPEN."
                };
                let _ = writeln!(
                    stderr.lock(),
                    "{} {hint}",
                    palette.paint(Tone::Warning, state)
                );
            }
            Err(cleanup) => {
                let _ = writeln!(
                    stderr.lock(),
                    "{} Inspect it with status.",
                    palette.paint(Tone::Warning, "Cannot confirm a locked state.")
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
            let palette = Palette::for_stream(&err);
            let _ = writeln!(
                err,
                "{}: {error:#}",
                palette.paint(
                    Tone::Warning,
                    "Could not update the closing phase before locking"
                )
            );
        }
        Ok(())
    }

    pub(super) fn lock(
        &mut self,
        existing: Option<Session>,
        manual: bool,
        others: &[&Session],
        admission: &mut Option<File>,
    ) -> Result<i32> {
        let mut session = match existing {
            Some(mut session) => {
                self.begin_close(&mut session)?;
                session
            }
            None => Session::start(
                &self.store,
                &self.tree,
                self.user,
                &self.scope,
                if manual {
                    Phase::ManualClosing
                } else {
                    Phase::Closing
                },
            )?,
        };

        let mut remaining = others.iter();
        loop {
            drop(admission.take());
            self.close_files()?;

            *admission = Some(self.registry.admission()?);
            self.store.clear_receipt(&session)?;
            self.store.finish()?;
            let Some(next) = remaining.next() else { break };
            self.scope = next.scope().clone();
            self.tree = saved_tree(next, self.user.uid)?;
            admission::check_other_roots(
                &admission::operations(self.registry)?,
                &self.slot,
                &self.tree,
            )?;
            session = Session::start(
                &self.store,
                &self.tree,
                self.user,
                &self.scope,
                Phase::ManualClosing,
            )?;
        }

        self.release_empty_slot()?;
        drop(admission.take());
        AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
        Ok(0)
    }

    pub(super) fn open(
        &self,
        command: Option<&[OsString]>,
        existing: Option<Session>,
        keep_open_on_error: bool,
        admission: &mut Option<File>,
    ) -> Result<i32> {
        let phase = if command.is_some() {
            Phase::Opening
        } else {
            Phase::ManualOpening
        };
        let fresh = existing.is_none();
        let mut session = match existing {
            Some(session) => session,
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
                AccessMessage::Unlocked.session(interactive, &self.slot, &self.scope)?;
                self.signals.run(self.user, command)
            } else {
                ensure!(!self.signals.interrupted(), "manual unlock interrupted");
                Ok(0)
            }
        })();

        if command.is_none() && result.is_ok() {
            {
                let _guard = self.registry.admission()?;
                session.phase(&self.store, Phase::Manual)?;
                self.store.archive_unlock()?;
                self.store.release()?;
            }
            // Once access is committed, an output failure cannot undo it.
            AccessMessage::Unlocked.write(&mut std::io::stdout().lock())?;
            return Ok(0);
        }
        if keep_open_on_error
            || (command.is_none() && files.values().any(|file| file.uid == self.user.uid))
        {
            // A different selector can cover files already open to this user.
            // Keep the journal for recovery instead of revoking their access.
            return result;
        }

        self.begin_close(&mut session)
            .and_then(|()| self.close_files())
            .and_then(|()| {
                let _guard = self.registry.admission()?;
                self.store.clear_receipt(&session)?;
                self.store.finish()?;
                self.release_empty_slot()
            })
            .with_context(|| match &result {
                Err(e) => format!("operation failed ({e:#}); closing also failed"),
                Ok(_) => "closing the session failed".to_string(),
            })?;

        if command.is_some() {
            AccessMessage::Locked.session(interactive, &self.slot, &self.scope)?;
        } else {
            AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
        }
        result
    }
}
