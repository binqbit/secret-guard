//! Snapshot session state and report the files in the requested scope.
use anyhow::Result;

use super::{
    admission::{self, Entry},
    display,
    selection::{Selection, Slot},
    target::Target,
};
use crate::{
    journal::{JournalStore, Session},
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
        let target = Target::resolve(registry, &entries, selection, caller.uid, false)?;
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
    let saved = session.filter(|_| !paths);
    let (_, tree) = target.tree(caller, user.uid, saved.map(Session::scope), saved)?;
    display::show_files(tree.scan()?, user, paths)?;
    Ok(0)
}

fn describe_status(target: &Target, entries: &[Entry], selected: Option<&Entry>) -> Result<()> {
    let mut out = std::io::stdout().lock();
    if target.slot == Slot::Default {
        let mut peers = entries
            .iter()
            .filter(|entry| entry.slot != Slot::Default)
            .peekable();
        let show_default = peers.peek().is_some();
        for peer in peers {
            display::session_heading(&mut out, &peer.slot, peer.root())?;
            display::describe(
                &mut out,
                peer.session.as_ref(),
                peer.idle,
                &peer.slot.close_hint(peer.root()),
            )?;
        }
        if show_default {
            display::session_heading(&mut out, &target.slot, None)?;
        }
    } else {
        display::session_heading(&mut out, &target.slot, target.root.as_deref())?;
    }
    display::describe(
        &mut out,
        selected.and_then(|e| e.session.as_ref()),
        selected.is_none_or(|e| e.idle),
        &target.hint(),
    )?;
    Ok(())
}
