//! Apply the configured file permissions and verify each complete pass.

use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::Access;

use crate::{
    runtime::{self, SessionSignals, User},
    tree::{Change, FileAccess, Tree},
};

pub(super) fn preflight(tree: &Tree, user: &User) -> Result<BTreeMap<PathBuf, FileAccess>> {
    let files = tree.scan()?;
    for (path, access) in &files {
        access
            .validate(user.uid)
            .with_context(|| format!("cannot open {path:?}"))?;
    }

    runtime::check_file_access(user, &files, Access::EXISTS)?;
    Ok(files)
}

pub(super) fn open_files(
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
pub(super) fn close(
    tree: &Tree,
    user: &User,
    signals: &SessionSignals,
    check_other_sessions: impl Fn() -> Result<()>,
) -> Result<()> {
    loop {
        check_other_sessions()?;
        let pending = close_pass(tree, user)?;
        if pending.is_empty() {
            return Ok(());
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
