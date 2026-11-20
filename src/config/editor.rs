//! Edit rule lists in a private draft owned by the ordinary user.
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use rustix::fs::{self as linux, AtFlags, Dir, Gid, Mode, OFlags, ResolveFlags, Uid};
use rustix::io::Errno;
use tempfile::TempDir;

use crate::runtime::{self, SessionSignals, User};

fn select_editor(preferred: Option<&str>) -> Result<OsString> {
    if let Some(editor) = preferred {
        ensure!(!editor.is_empty(), "specify an editor executable");
        return Ok(editor.into());
    }
    for name in ["vim", "nano", "vi"] {
        for dir in env::split_paths(OsStr::new(runtime::COMMAND_PATH)) {
            let path = dir.join(name);
            if path
                .metadata()
                .is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
            {
                return Ok(path.into_os_string());
            }
        }
    }
    anyhow::bail!("no terminal editor found; install Vim or Nano, or specify --editor")
}

// Editors can replace the draft by rename. Pin and inspect the final inode before
// acquiring a data descriptor so a replacement device, link or mount cannot redirect root.
fn read_draft(directory: &File, name: &str, uid: u32) -> Result<String> {
    let pinned = File::from(linux::openat2(
        directory,
        name,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    let meta = pinned.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == uid && meta.nlink() == 1,
        "the edited draft must be a regular file owned by the editor user with a single link"
    );
    let mut contents = String::new();
    File::open(crate::tree::descriptor_path(&pinned))?
        .read_to_string(&mut contents)
        .context("read the edited rule list as UTF-8")?;
    Ok(contents)
}

// Only unlink entries directly in the scratch directory. An editor can create
// subdirectories or mount filesystems, which a root cleanup must never traverse.
fn remove_drafts(outer: &TempDir, directory: &File) -> Result<()> {
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        match linux::unlinkat(directory, name, AtFlags::empty()) {
            Err(Errno::ISDIR) => linux::unlinkat(directory, name, AtFlags::REMOVEDIR)?,
            Err(Errno::NOENT) => (),
            result => result?,
        }
    }
    fs::remove_dir(outer.path().join("draft"))?;
    fs::remove_dir(outer.path())?;
    Ok(())
}

pub(super) fn edit_text(
    user: &User,
    list_name: &str,
    contents: &str,
    preferred_editor: Option<&str>,
) -> Result<Option<String>> {
    ensure!(
        Path::new(list_name).file_name() == Some(OsStr::new(list_name)),
        "expected a single rule filename"
    );
    let editor = select_editor(preferred_editor)?;
    let temp = fs::symlink_metadata("/tmp")?;
    ensure!(
        temp.is_dir() && temp.uid() == 0 && (temp.mode() & 0o022 == 0 || temp.mode() & 0o1000 != 0),
        "/tmp must be a root-owned directory with protected root entries"
    );
    let mut outer = tempfile::Builder::new()
        .prefix("secret-guard-edit-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let draft_dir = outer.path().join("draft");
    fs::create_dir(&draft_dir)?;
    let directory = File::open(&draft_dir)?;
    let path = draft_dir.join(list_name);
    let uid = Some(Uid::from_raw(user.uid));
    let gid = Some(Gid::from_raw(user.gid));
    {
        let mut draft = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        draft.write_all(contents.as_bytes())?;
        linux::fchown(&draft, uid, gid)?;
        linux::fchmod(&draft, Mode::RUSR | Mode::WUSR)?;
    }
    linux::fchmod(&directory, Mode::RWXU)?;
    // The outer directory remains root-owned under sticky /tmp. After handoff
    // the editor can save atomically inside draft, but cannot replace draft itself.
    outer.disable_cleanup(true);
    let result = (|| -> Result<Option<String>> {
        linux::fchown(&directory, uid, gid)?;
        fs::set_permissions(outer.path(), Permissions::from_mode(0o711))?;
        let signals = SessionSignals::install()?;
        let code = signals
            .run_editor(user, &editor, &path)
            .with_context(|| format!("start editor {editor:?} as {}", user.name))?;
        ensure!(
            code == 0,
            "editor {editor:?} exited with status {code}; rules were not saved"
        );
        let edited = read_draft(&directory, list_name, user.uid)?;
        ensure!(!signals.interrupted(), "edit interrupted before saving");
        Ok((edited != contents).then_some(edited))
    })();
    if let Err(error) = remove_drafts(&outer, &directory) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "Could not clean up editor scratch directory {:?}: {error:#}",
            outer.path()
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn accepts_editor_rename_and_rejects_substituted_drafts() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let directory = File::open(tmp.path())?;
        let uid = directory.metadata()?.uid();
        let name = ".indexingfolders";
        let path = tmp.path().join(name);
        let saved = tmp.path().join("saved");
        fs::write(&path, "/old\n")?;
        fs::write(&saved, "/new\n")?;
        fs::rename(&saved, &path)?;
        assert_eq!(read_draft(&directory, name, uid)?, "/new\n");
        fs::hard_link(&path, &saved)?;
        assert!(read_draft(&directory, name, uid).is_err());
        fs::remove_file(&path)?;
        symlink(&saved, &path)?;
        assert!(read_draft(&directory, name, uid).is_err());
        fs::remove_file(&path)?;
        linux::mkfifoat(&directory, name, Mode::RUSR | Mode::WUSR)?;
        assert!(read_draft(&directory, name, uid).is_err());
        Ok(())
    }
}
