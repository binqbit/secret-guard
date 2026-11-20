//! Admit a mutation, supervise file access, and release its journal and locks.
use std::{ffi::OsString, fs::File, io::Write};

use anyhow::{Context, Result, ensure};

use super::{
    access,
    admission::{self, ResetOffer},
    display::AccessMessage,
    selection::{Selection, Slot},
    target::Target,
};
use crate::{
    config::Scope,
    journal::{JournalStore, Phase, Session},
    output::{Palette, Tone},
    runtime::{self, SessionSignals, User},
    tree::Tree,
};

#[derive(Clone, Copy)]
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

enum Outcome {
    Done(i32),
    NeedsConfirmation(ResetOffer),
}

pub(crate) fn run(
    registry: &JournalStore,
    user: &User,
    selection: &Selection,
    request: Mutation<'_>,
) -> Result<i32> {
    let mut reset: Option<ResetOffer> = None;
    loop {
        let result = match &reset {
            Some(offer) => attempt(
                registry,
                user,
                &offer.selection,
                Mutation::Lock,
                Some(&offer.journal),
            ),
            None => attempt(registry, user, selection, request, None),
        }?;
        match result {
            Outcome::Done(code) => {
                if reset.take().is_none() || code != 0 {
                    return Ok(code);
                }
                // Confirmed closure succeeded. Recheck the original selection.
            }
            Outcome::NeedsConfirmation(offer) => {
                ensure!(
                    runtime::confirm_session_reset(&offer.label, offer.kind, &offer.roots)?,
                    "new session cancelled. {}",
                    offer.close_hint
                );
                reset = Some(offer);
            }
        }
    }
}

fn attempt(
    registry: &JournalStore,
    user: &User,
    selection: &Selection,
    request: Mutation<'_>,
    approved: Option<&File>,
) -> Result<Outcome> {
    let admission = registry.admission()?;
    let entries = admission::operations(registry)?;
    let mut target = Target::resolve(registry, &entries, selection, user.uid, true)?;
    let existing = target.lock_existing(approved)?;
    let saved = existing.as_ref().and_then(|s| match target.slot {
        Slot::Default => s.manual_scope(),
        _ => Some(s.scope()),
    });
    let (scope, tree) = target.tree(user, user.uid, saved, existing.as_ref())?;
    if let Some(offer) = admission::reset_offer(
        registry,
        &entries,
        &target.slot,
        &tree,
        user.uid,
        request.command(),
    )? {
        return Ok(Outcome::NeedsConfirmation(offer));
    }
    let hint = target.hint();
    if let Some(s) = &existing {
        ensure!(
            !matches!(request, Mutation::Unlock) || s.is_manual_open(),
            "an unfinished operation was found. {hint}"
        );
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
    let code = op.release_after(result, admission, &hint)?;
    ensure!(
        approved.is_none() || !signals.interrupted(),
        "reset was interrupted; the previous session is locked"
    );
    Ok(Outcome::Done(code))
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
        let palette = Palette::for_stream(&stderr);
        match remaining {
            Ok(true) if result.is_err() => {
                let _ = writeln!(
                    stderr.lock(),
                    "{} {hint}",
                    palette.paint(Tone::Warning, "Operation remains OPEN.")
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
                AccessMessage::Unlocked.session(interactive, &self.slot, &self.scope)?;
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
            AccessMessage::Locked.session(interactive, &self.slot, &self.scope)?;
        } else {
            AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
        }
        result
    }
}
