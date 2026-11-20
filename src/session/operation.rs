//! Resolve mutation requests, check admission, and confirm recovery.

mod lifecycle;

use std::{ffi::OsString, fs::File};

use anyhow::{Context, Result, ensure};

use super::{
    admission::{self, ResetOffer},
    selection::{Selection, Slot},
    target::Target,
};
use crate::{
    journal::JournalStore,
    runtime::{self, SessionSignals, User},
};
use lifecycle::Operation;

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
    loop {
        let offer = match attempt(registry, user, selection, request, None)? {
            Outcome::Done(code) => return Ok(code),
            Outcome::NeedsConfirmation(offer) => offer,
        };
        let (action, question) = if matches!(request, Mutation::Unlock) {
            (
                Mutation::Unlock,
                "Reset this session and leave its files unlocked?",
            )
        } else {
            (
                Mutation::Lock,
                "Reset this session by locking its files, then continue?",
            )
        };
        let confirmed = runtime::confirm_session_reset(&offer.label, &offer.roots, question)
            .with_context(|| format!("{}. {}", offer.label, offer.close_hint))?;
        ensure!(confirmed, "request cancelled. {}", offer.close_hint);

        let Outcome::Done(code) = attempt(
            registry,
            user,
            &offer.selection,
            action,
            Some(&offer.journal),
        )?
        else {
            anyhow::bail!("the conflicting sessions changed; retry the command");
        };
        if matches!(action, Mutation::Unlock) || code != 0 {
            return Ok(code);
        }
        // The indicated scope is now closed. Admit the requested session afresh.
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
    let mut target = Target::resolve(
        registry,
        &entries,
        selection,
        user.uid,
        true,
        request.command().is_none(),
    )?;
    let existing = target.lock_existing(approved)?;

    let receipts = entries
        .iter()
        .find(|e| e.slot == target.slot)
        .map_or(&[][..], |e| e.receipts.as_slice());
    let receipt = match request {
        Mutation::Session(_) => None,
        _ => receipts.iter().rfind(|r| r.uid == user.uid),
    };
    let snapshot = existing.as_ref().or(receipt);
    if target.slot == Slot::Default
        && existing
            .as_ref()
            .is_some_and(|s| s.manual_scope().is_none())
    {
        // Keep the installed configuration trust checks for default-session
        // recovery. Edited lists must not redirect the saved operation.
        crate::config::read_config(None)?;
    }
    let (scope, tree) = target.tree(user, user.uid, snapshot)?;

    if let Some(offer) = admission::reset_offer(
        registry,
        &entries,
        &target.slot,
        &tree,
        user.uid,
        request,
        approved.is_some(),
    )? {
        return Ok(Outcome::NeedsConfirmation(offer));
    }

    let hint = target.hint();
    if request.command().is_some_and(<[OsString]>::is_empty) {
        runtime::check_interactive()?;
    }

    let signals = SessionSignals::install()?;
    let store = target.claim(registry, user.uid)?;
    let mut operation = Operation {
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
        Mutation::Lock => {
            // A confirmed reset for a new session closes only the journal shown
            // at the prompt. An explicit lock also closes earlier manual scopes.
            let others = receipts
                .iter()
                .filter(|r| {
                    approved.is_none()
                        && r.uid == user.uid
                        && snapshot.is_none_or(|s| !r.same_selection(s))
                })
                .collect::<Vec<_>>();
            let manual = existing.is_none() && receipt.is_some();
            operation.lock(existing, manual, &others, &mut admission)
        }
        Mutation::Unlock => operation.open(
            None,
            existing,
            receipt.is_some() || approved.is_some(),
            &mut admission,
        ),
        Mutation::Session(command) => {
            operation.open(Some(command), existing, false, &mut admission)
        }
    };

    let code = operation.release_after(result, admission, &hint)?;
    ensure!(
        approved.is_none() || !signals.interrupted(),
        "reset was interrupted; inspect the selected scope with status"
    );
    Ok(Outcome::Done(code))
}
