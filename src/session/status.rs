//! Snapshot session state and report the files in the requested scope.

use std::io::Write;

use anyhow::Result;

use super::{
    admission::{self, Entry},
    display,
    selection::{Selection, Slot},
    target::Target,
};
use crate::{
    journal::{JournalStore, Session},
    output::Palette,
    runtime::{self, User},
};

pub(crate) fn status(
    registry: &JournalStore,
    caller: &User,
    selection: &Selection,
    paths: bool,
) -> Result<i32> {
    // Snapshot the registry. Slow scans or output must never hold up another session.
    let (entries, target) = {
        let _guard = registry.admission()?;
        let entries = admission::operations(registry)?;
        let target = Target::resolve(registry, &entries, selection, caller.uid, false, !paths)?;
        (entries, target)
    };

    let entry = entries.iter().find(|entry| entry.slot == target.slot);
    let session = entry.and_then(|entry| entry.session.as_ref());
    if !paths {
        describe_status(&target, &entries, entry)?;
    }

    let owner = match session.map(|session| session.uid).or(target.binding_uid) {
        Some(uid) if uid != caller.uid => Some(runtime::resolve_uid(uid)?),
        _ => None,
    };
    let user = owner.as_ref().unwrap_or(caller);

    // Status reports observed permissions, including files covered by a saved
    // manual unlock. --paths always previews the current configuration.
    let mut scopes: Vec<&Session> = Vec::new();
    if !paths {
        scopes.extend(session);
        if let Some(entry) = entry {
            scopes.extend(
                entry
                    .receipts
                    .iter()
                    .filter(|r| r.uid == user.uid && session.is_none_or(|s| !s.same_selection(r))),
            );
        }
    }
    let files = if scopes.is_empty() {
        target.tree(caller, user.uid, None)?.1.scan()?
    } else {
        let mut files = std::collections::BTreeMap::new();
        for scope in scopes {
            let (_, tree) = target.tree(caller, user.uid, Some(scope))?;
            files.extend(tree.scan()?);
        }
        files
    };
    display::show_files(files, user, paths)?;
    Ok(0)
}

fn describe_status(target: &Target, entries: &[Entry], selected: Option<&Entry>) -> Result<()> {
    let mut out = std::io::stdout().lock();
    let palette = Palette::for_stream(&out);

    if target.slot == Slot::Default {
        let mut peers = entries
            .iter()
            .filter(|entry| entry.slot != Slot::Default && entry.occupies_slot())
            .peekable();
        let show_default = peers.peek().is_some() || palette.is_terminal();

        for peer in peers {
            display::session_heading(&mut out, &peer.slot, peer.root(), &palette)?;
            display::describe(
                &mut out,
                peer.session.as_ref(),
                peer.idle,
                &peer.slot.close_hint(peer.root()),
                &palette,
            )?;
            if palette.is_terminal() {
                writeln!(out)?;
            }
        }

        if show_default {
            display::session_heading(&mut out, &target.slot, None, &palette)?;
        }
    } else {
        display::session_heading(&mut out, &target.slot, target.root.as_deref(), &palette)?;
    }

    display::describe(
        &mut out,
        selected.and_then(|e| e.session.as_ref()),
        selected.is_none_or(|e| e.idle),
        &target.hint(),
        &palette,
    )?;
    Ok(())
}
