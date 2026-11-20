//! Publish packaged defaults on first use and durably replace them on reset.
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, AtFlags, Dir, Gid, Mode, OFlags, Uid};
use rustix::io::Errno;

use super::{ConfigFiles, RESET_PENDING};
use crate::config::CONFIG_DIR;
use crate::config::rules::RuleList;
use crate::storage::{
    Visibility, checked_file, directory_flags, stage_directory, trusted_directory, trusted_path,
};
use crate::tree::{check_directory_search, descriptor_path};

const RESET_SIGNATURE: &[u8] = b"Secret Guard configuration reset v1\n";

fn uninitialized_at(parent: &File, uid: u32, gid: u32) -> Result<bool> {
    let directory = match fs::openat(parent, "secret-guard", directory_flags(), Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(true),
        Err(e) => return Err(e).context(CONFIG_DIR),
    };
    check_directory_search(&directory, Path::new(CONFIG_DIR))?;
    let files = ConfigFiles::from_directory(directory, uid, gid)?;
    for entry in Dir::read_from(&files.directory)? {
        if !matches!(entry?.file_name().to_bytes(), b"." | b"..") {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(in crate::config) fn is_uninitialized() -> Result<bool> {
    let parent = trusted_path(Path::new("/etc"), Visibility::Public)?;
    uninitialized_at(&parent, 0, 0)
}

pub(crate) fn initialize_if_needed(home: &Path) -> Result<()> {
    let parent = trusted_directory(Path::new("/etc"), Visibility::Public)?;
    initialize_at(&parent, home, 0, 0).context("initialize /etc/secret-guard")
}

pub(in crate::config) fn reset_config(home: &Path) -> Result<()> {
    initialize_if_needed(home)?;
    ConfigFiles::open()?
        .reset(home)
        .context("reset /etc/secret-guard")
}

fn stage_defaults(
    parent: &File,
    home: &Path,
    uid: u32,
    gid: u32,
) -> Result<(tempfile::TempDir, File)> {
    let (staged, directory) = stage_directory(parent, ".secret-guard-init-", uid, gid)?;
    let owner = Some(Uid::from_raw(uid));
    let group = Some(Gid::from_raw(gid));
    // Published rules use public read access even when /etc has a restrictive default ACL.
    // Change only our new objects. Remove the inherited default before creating any files.
    for acl in ["system.posix_acl_access", "system.posix_acl_default"] {
        match fs::fremovexattr(&directory, acl) {
            Ok(()) | Err(Errno::NODATA | Errno::OPNOTSUPP) => (),
            Err(e) => {
                return Err(e).context("clear inherited ACL from new configuration directory");
            }
        }
    }
    for list in RuleList::ALL {
        let mut file = File::from(fs::openat(
            &directory,
            list.filename(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        file.write_all(list.defaults(home)?.as_bytes())?;
        fs::fchown(&file, owner, group)?;
        fs::fchmod(&file, Mode::from_bits_retain(0o644))?;
        file.sync_all()?;
    }
    Ok((staged, directory))
}

fn initialize_at(parent: &File, home: &Path, uid: u32, gid: u32) -> Result<()> {
    if !uninitialized_at(parent, uid, gid)? {
        return Ok(());
    }
    let (staged, directory) = stage_defaults(parent, home, uid, gid)?;
    fs::fchmod(&directory, Mode::from_bits_retain(0o755))?;
    directory.sync_all()?;
    // Linux rename installs a complete directory at an absent or empty destination.
    // A competing publisher or administrator who populated it first keeps their files.
    let name = staged
        .path()
        .file_name()
        .context("missing staged directory name")?;
    match fs::renameat(parent, name, parent, "secret-guard") {
        Ok(()) => (),
        Err(Errno::EXIST | Errno::NOTEMPTY) if !uninitialized_at(parent, uid, gid)? => (),
        Err(e) => return Err(e).context("publish default configuration directory"),
    }
    parent.sync_all().context("sync default configuration")
}

impl ConfigFiles {
    fn reset(&self, home: &Path) -> Result<()> {
        let _lock = self.write_lock()?;
        for list in RuleList::ALL {
            // Reset can repair a missing, unreadable or malformed list. It may
            // replace only independent regular files belonging to the administrator.
            match fs::statat(&self.directory, list.filename(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => ensure!(
                    fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::RegularFile
                        && stat.st_nlink == 1
                        && stat.st_uid == self.uid
                        && stat.st_gid == self.gid,
                    "unsafe reset target {:?}",
                    list.filename()
                ),
                Err(Errno::NOENT) => (),
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("inspect reset target {:?}", list.filename()));
                }
            }
        }

        let (_stage, staged_dir) = stage_defaults(&self.directory, home, self.uid, self.gid)?;
        if self.reset_pending()? {
            let marker = checked_file(
                &self.directory,
                RESET_PENDING,
                self.uid,
                self.gid,
                Visibility::Private,
            )?
            .context("missing configuration reset marker")?;
            let mut bytes = Vec::new();
            marker
                .take(RESET_SIGNATURE.len() as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes == RESET_SIGNATURE,
                "unrecognized file at {CONFIG_DIR}/{RESET_PENDING}"
            );
        } else {
            let path = descriptor_path(&self.directory);
            let mut marker = tempfile::NamedTempFile::new_in(&path)?;
            marker.write_all(RESET_SIGNATURE)?;
            fs::fchown(
                &marker,
                Some(Uid::from_raw(self.uid)),
                Some(Gid::from_raw(self.gid)),
            )?;
            fs::fchmod(&marker, Mode::RUSR | Mode::WUSR)?;
            marker.as_file().sync_all()?;
            marker.persist_noclobber(path.join(RESET_PENDING))?;
        }
        // Make interruption visible before the first rename. Readers refuse a
        // marked snapshot until all three defaults are durable.
        self.directory.sync_all()?;
        for list in RuleList::ALL {
            fs::renameat(
                &staged_dir,
                list.filename(),
                &self.directory,
                list.filename(),
            )?;
        }
        self.directory.sync_all()?;
        fs::unlinkat(&self.directory, RESET_PENDING, AtFlags::empty())?;
        self.directory.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::editable_config;
    use super::*;
    use rustix::fs::FlockOperation;
    use std::fs as disk;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[test]
    fn competing_first_runs_publish_one_complete_default_configuration() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let parent = File::open(tmp.path())?;
        let meta = parent.metadata()?;
        let (uid, gid) = (meta.uid(), meta.gid());
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|s| -> Result<()> {
            let first = s.spawn(|| {
                barrier.wait();
                initialize_at(&parent, Path::new("/srv/alice"), uid, gid)
            });
            barrier.wait();
            let second = initialize_at(&parent, Path::new("/workspace/bob"), uid, gid);
            first.join().unwrap()?;
            second
        })?;
        let config =
            ConfigFiles::from_directory(File::open(tmp.path().join("secret-guard"))?, uid, gid)?;
        let folders = config.read(RuleList::Folders)?;
        assert!(
            folders == RuleList::Folders.defaults(Path::new("/srv/alice"))?
                || folders == RuleList::Folders.defaults(Path::new("/workspace/bob"))?
        );
        for list in [RuleList::Secrets, RuleList::Ignore] {
            assert_eq!(config.read(list)?, list.defaults(Path::new("/"))?);
        }
        let rules = tmp.path().join("secret-guard/.indexingignore");
        disk::write(rules, "local-only/\n")?;
        initialize_at(&parent, Path::new("/"), uid, gid)?;
        assert_eq!(config.read(RuleList::Ignore)?, "local-only/\n");
        assert_eq!(disk::read_dir(tmp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn only_absent_or_verified_empty_configuration_can_be_initialized() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let parent = File::open(tmp.path())?;
        let meta = parent.metadata()?;
        let (uid, gid) = (meta.uid(), meta.gid());
        let path = tmp.path().join("secret-guard");
        assert!(initialize_at(&parent, Path::new("/"), uid, gid).is_err());
        assert_eq!(disk::read_dir(tmp.path())?.count(), 0);

        let outside = tempfile::tempdir()?;
        symlink(outside.path(), &path)?;
        assert!(initialize_at(&parent, Path::new("/srv/alice"), uid, gid).is_err());
        assert_eq!(disk::read_dir(outside.path())?.count(), 0);
        disk::remove_file(&path)?;
        disk::create_dir(&path)?;
        disk::set_permissions(&path, disk::Permissions::from_mode(0o777))?;
        assert!(initialize_at(&parent, Path::new("/srv/alice"), uid, gid).is_err());
        disk::set_permissions(&path, disk::Permissions::from_mode(0o755))?;
        for file in ["config.toml", ".indexingsecrets"] {
            let existing = path.join(file);
            disk::write(&existing, "original")?;
            initialize_at(&parent, Path::new("/srv/alice"), uid, gid)?;
            assert_eq!(disk::read(&existing)?, b"original");
            assert_eq!(disk::read_dir(&path)?.count(), 1);
            disk::remove_file(&existing)?;
        }
        initialize_at(&parent, Path::new("/srv/alice"), uid, gid)?;
        assert_eq!(disk::read_dir(&path)?.count(), 3);
        Ok(())
    }

    #[test]
    fn interrupted_reset_blocks_mixed_reads_and_can_restore_defaults() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let config = editable_config(tmp.path())?;
        let folders = tmp.path().join(RuleList::Folders.filename());
        disk::write(&folders, "wrong\n")?;
        disk::set_permissions(&folders, disk::Permissions::from_mode(0o644))?;
        let secrets = tmp.path().join(RuleList::Secrets.filename());
        disk::write(&secrets, [0xff])?;
        disk::set_permissions(&secrets, disk::Permissions::from_mode(0o600))?;
        let extra = tmp.path().join("site-settings");
        disk::write(&extra, "keep")?;
        let marker = tmp.path().join(RESET_PENDING);
        disk::write(&marker, RESET_SIGNATURE)?;
        disk::set_permissions(&marker, disk::Permissions::from_mode(0o600))?;
        assert!(config.scope(None).is_err());
        assert!(config.read_all().is_err());
        assert!(config.read(RuleList::Folders).is_err());
        assert!(
            config
                .replace(RuleList::Folders, "wrong\n", "/tmp")
                .is_err()
        );

        let home = Path::new("/srv/ordinary user");
        config.reset(home)?;
        for (list, raw) in config.read_all()? {
            assert_eq!(raw, list.defaults(home)?);
            assert_eq!(
                disk::metadata(tmp.path().join(list.filename()))?.mode() & 0o7777,
                0o644
            );
        }
        // An ordinary reader can flock the directory. It cannot obstruct scanning
        // or session recovery, which both rely on the aggregate snapshot.
        let reader = File::open(tmp.path())?;
        fs::flock(&reader, FlockOperation::NonBlockingLockExclusive)?;
        assert!(config.reset(home).is_err());
        config.scope(None)?;
        assert!(!marker.exists());
        assert_eq!(disk::read(&extra)?, b"keep");
        assert_eq!(disk::read_dir(tmp.path())?.count(), 4);
        Ok(())
    }

    #[test]
    fn reset_preserves_unsafe_objects_and_unrecognized_markers() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let config = editable_config(tmp.path())?;
        let home = Path::new("/home/alice");
        let first = tmp.path().join(RuleList::Folders.filename());
        disk::write(&first, "/custom")?;
        let extra = tmp.path().join("keep");
        disk::write(&extra, "original")?;
        let ignore = tmp.path().join(RuleList::Ignore.filename());
        symlink(&extra, &ignore)?;
        assert!(config.reset(home).is_err());
        assert!(ignore.is_symlink());
        disk::remove_file(&ignore)?;
        disk::hard_link(&extra, &ignore)?;
        assert!(config.reset(home).is_err());
        disk::remove_file(&ignore)?;
        let marker = tmp.path().join(RESET_PENDING);
        disk::write(&marker, "unrelated")?;
        disk::set_permissions(&marker, disk::Permissions::from_mode(0o600))?;
        assert!(config.reset(home).is_err());
        assert_eq!(disk::read(&marker)?, b"unrelated");
        assert_eq!(disk::read(&first)?, b"/custom");
        assert_eq!(disk::read(&extra)?, b"original");
        assert_eq!(disk::read_dir(tmp.path())?.count(), 3);
        Ok(())
    }
}
