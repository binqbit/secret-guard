//! Read and atomically edit rule lists beneath a verified installation directory.

mod defaults;

pub(crate) use defaults::initialize_if_needed;
pub(super) use defaults::{is_uninitialized, reset_config};

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, AtFlags, FlockOperation, Gid, Mode, Uid};
use rustix::io::Errno;

use super::CONFIG_DIR;
use super::rules::{RuleList, Scope};
use crate::storage::{Visibility, checked_file, directory_flags, trusted_directory};
use crate::tree::{acl_allows_public_read, descriptor_path};

const RESET_PENDING: &str = ".secret-guard-reset.pending";

pub(super) struct ConfigFiles {
    directory: File,
    uid: u32,
    gid: u32,
}

impl ConfigFiles {
    pub(super) fn open() -> Result<Self> {
        let directory =
            trusted_directory(Path::new(CONFIG_DIR), Visibility::Public).context(CONFIG_DIR)?;
        Self::from_directory(directory, 0, 0)
    }

    fn from_directory(directory: File, uid: u32, gid: u32) -> Result<Self> {
        let meta = directory.metadata()?;
        ensure!(
            meta.uid() == uid && meta.gid() == gid && meta.mode() & 0o7777 == 0o755,
            "{CONFIG_DIR} must be owned by {uid}:{gid} with mode 0755"
        );
        ensure!(
            acl_allows_public_read(&directory)?,
            "{CONFIG_DIR} has an access ACL entry without read permission"
        );

        Ok(Self {
            directory,
            uid,
            gid,
        })
    }

    fn write_lock(&self) -> Result<File> {
        let fd = File::from(fs::openat(
            &self.directory,
            ".",
            directory_flags(),
            Mode::empty(),
        )?);
        fs::flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .context("configuration is busy; retry the command")?;
        Ok(fd)
    }

    fn reset_pending(&self) -> Result<bool> {
        match fs::statat(&self.directory, RESET_PENDING, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(e).context("inspect configuration reset marker"),
        }
    }

    fn check_ready(&self) -> Result<()> {
        ensure!(
            !self.reset_pending()?,
            "configuration reset is incomplete; run 'sudo secret-guard config reset' again"
        );
        Ok(())
    }

    fn capture(&self, list: RuleList) -> Result<(File, String)> {
        let name = list.filename();
        let mut file = checked_file(
            &self.directory,
            name,
            self.uid,
            self.gid,
            Visibility::Public,
        )?
        .with_context(|| format!("missing required configuration file {CONFIG_DIR}/{name}"))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("read {CONFIG_DIR}/{name}"))?;
        Ok((file, contents))
    }

    pub(super) fn read(&self, list: RuleList) -> Result<String> {
        self.check_ready()?;
        let (_, text) = self.capture(list)?;
        self.check_ready()?;
        Ok(text)
    }

    pub(super) fn read_all(&self) -> Result<Vec<(RuleList, String)>> {
        self.read_lists(&RuleList::ALL)
    }

    fn read_lists(&self, lists: &[RuleList]) -> Result<Vec<(RuleList, String)>> {
        self.check_ready()?;

        let mut held = Vec::with_capacity(lists.len());
        for &list in lists {
            let (file, contents) = self.capture(list)?;
            held.push((list, file, contents));
        }

        // Writers publish by rename. Verify all names after pinning the whole set,
        // so a completed reset between two opens cannot produce a mixed scope.
        // Readers need no flock on this publicly accessible directory.
        let mut contents = Vec::with_capacity(held.len());
        for (list, file, text) in held {
            let identity = file.metadata()?;
            let live = fs::statat(&self.directory, list.filename(), AtFlags::SYMLINK_NOFOLLOW)?;
            ensure!(
                live.st_dev == identity.dev() && live.st_ino == identity.ino(),
                "configuration changed while reading; retry the command"
            );
            contents.push((list, text));
        }

        self.check_ready()?;
        Ok(contents)
    }

    fn scope(&self, root: Option<&Path>) -> Result<Scope> {
        let lists = match root {
            Some(_) => &[RuleList::Secrets, RuleList::Ignore][..],
            None => &RuleList::ALL,
        };
        Scope::from_lists(root, self.read_lists(lists)?)
    }

    pub(super) fn replace(&self, list: RuleList, original: &str, edited: &str) -> Result<()> {
        if original == edited {
            return Ok(());
        }
        list.validate_edit(edited)?;

        let dir_path = descriptor_path(&self.directory);
        let name = list.filename();
        let mut pending =
            tempfile::NamedTempFile::new_in(&dir_path).context("create replacement rule file")?;
        pending
            .write_all(edited.as_bytes())
            .context("write replacement rule file")?;
        fs::fchown(
            &pending,
            Some(Uid::from_raw(self.uid)),
            Some(Gid::from_raw(self.gid)),
        )
        .context("set rule file owner and group")?;

        // A separate open-file description releases the lock on every return.
        // Check for concurrent changes while the uncommitted draft is still private.
        let _lock = self.write_lock()?;
        ensure!(
            self.read(list)? == original,
            "{CONFIG_DIR}/{name} changed while editing; reopen it to apply your changes"
        );

        fs::fchmod(&pending, Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH)
            .context("set rule file permissions")?;
        ensure!(
            acl_allows_public_read(pending.as_file())?,
            "replacement for {name} has an access ACL entry without read permission"
        );
        pending
            .as_file()
            .sync_all()
            .context("sync replacement rule file")?;

        pending
            .persist(dir_path.join(name))
            .context("publish replacement rule file")?;
        self.directory
            .sync_all()
            .context("sync configuration directory")
    }
}

pub(crate) fn read_config(root: Option<&Path>) -> Result<Scope> {
    ConfigFiles::open()?.scope(root)
}

#[cfg(test)]
fn editable_config(dir: &Path) -> Result<ConfigFiles> {
    use std::fs as disk;
    use std::os::unix::fs::PermissionsExt;

    disk::set_permissions(dir, disk::Permissions::from_mode(0o755))?;
    let directory = File::open(dir)?;
    let meta = directory.metadata()?;
    ConfigFiles::from_directory(directory, meta.uid(), meta.gid())
}

#[cfg(test)]
mod tests {
    use std::fs as disk;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn configuration_uses_three_editable_lists() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let directory = File::open(tmp.path())?;
        let uid = directory.metadata()?.uid();
        let gid = directory.metadata()?.gid();
        disk::set_permissions(tmp.path(), disk::Permissions::from_mode(0o755))?;
        let read_lists =
            || ConfigFiles::from_directory(directory.try_clone()?, uid, gid)?.scope(None);
        let write = |name: &str, text: &str| -> Result<()> {
            let path = tmp.path().join(name);
            disk::write(&path, text)?;
            disk::set_permissions(path, disk::Permissions::from_mode(0o644))?;
            Ok(())
        };

        write(
            ".indexingfolders",
            "# Projects\n/srv/first project\n/srv/second\n",
        )?;
        write(".indexingsecrets", " .env \n\n.secrets/\n")?;
        assert!(read_lists().is_err());
        write(".indexingignore", "# No exclusions\n")?;
        let scope = read_lists()?;
        assert_eq!(
            scope.roots,
            [Path::new("/srv/first project"), Path::new("/srv/second")]
        );
        assert_eq!(scope.patterns, [".env", ".secrets/"]);
        assert!(scope.ignores.is_empty());

        for mode in [0o700, 0o750, 0o775, 0o777] {
            disk::set_permissions(tmp.path(), disk::Permissions::from_mode(mode))?;
            assert!(read_lists().is_err());
        }
        disk::set_permissions(tmp.path(), disk::Permissions::from_mode(0o755))?;

        write(".indexingignore", "target/\n.env.example\n")?;
        assert_eq!(read_lists()?.ignores, ["target/", ".env.example"]);
        write(".indexingsecrets", "# No selection\n")?;
        assert!(read_lists().is_err());
        write(".indexingsecrets", ".env\n")?;
        write(".indexingfolders", "\n")?;
        assert!(read_lists().is_err());
        Ok(())
    }

    #[test]
    fn edit_repairs_one_list_and_publishes_its_exact_text() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let config = editable_config(tmp.path())?;
        let list = RuleList::Secrets;
        let path = tmp.path().join(list.filename());
        let original = "# Incomplete list\n";
        let edited = "# Local keys\n\n  .env.*\n.secrets/";
        disk::write(&path, original)?;
        disk::set_permissions(&path, disk::Permissions::from_mode(0o644))?;
        let mut old = File::open(&path)?;
        let old_meta = old.metadata()?;

        // Reading and repairing the selected list does not depend on the other two.
        assert_eq!(config.read(list)?, original);
        assert!(config.scope(None).is_err());

        let writer = File::open(tmp.path())?;
        fs::flock(&writer, FlockOperation::NonBlockingLockExclusive)?;
        assert!(config.replace(list, original, edited).is_err());
        assert_eq!(config.read(list)?, original);
        assert_eq!(disk::read_dir(tmp.path())?.count(), 1);
        drop(writer);

        config.replace(list, original, edited)?;
        assert_eq!(config.read(list)?, edited);
        let current = disk::metadata(&path)?;
        assert_ne!(current.ino(), old_meta.ino());
        assert_eq!(
            (current.uid(), current.gid()),
            (old_meta.uid(), old_meta.gid())
        );
        assert_eq!(current.mode() & 0o7777, 0o644);
        let mut old_contents = String::new();
        old.read_to_string(&mut old_contents)?;
        assert_eq!(old_contents, original);

        config.replace(list, edited, edited)?;
        assert_eq!(disk::metadata(&path)?.ino(), current.ino());
        assert!(config.replace(list, original, ".env\n").is_err());
        assert_eq!(config.read(list)?, edited);
        assert_eq!(disk::read_dir(tmp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn invalid_edits_preserve_installed_rules_and_ignore_may_be_empty() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let config = editable_config(tmp.path())?;
        let valid_root = tmp.path().to_str().unwrap();
        for (list, before, rejected) in [
            (RuleList::Folders, valid_root, "../foo"),
            (RuleList::Folders, valid_root, " # comment \n "),
            (RuleList::Secrets, ".env", " # comment\n"),
            (RuleList::Secrets, ".env", "../keys/"),
            (RuleList::Ignore, "target/", "broken["),
        ] {
            let path = tmp.path().join(list.filename());
            disk::write(&path, before)?;
            disk::set_permissions(&path, disk::Permissions::from_mode(0o644))?;
            assert!(config.replace(list, before, rejected).is_err());
            assert_eq!(config.read(list)?, before);
        }

        config.replace(RuleList::Ignore, "target/", "")?;
        assert_eq!(config.read(RuleList::Ignore)?, "");
        Ok(())
    }
}
