//! Pin and validate private state directories and serialize work in each slot.
use std::cell::Cell;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, Dir, FlockOperation, Mode, RenameFlags};
use rustix::io::Errno;

use crate::storage::{
    Visibility, checked_file, directory_flags, stage_directory, trusted_directory,
};

const STATE: &str = "/var/lib/secret-guard";

pub(crate) struct JournalStore {
    pub(super) directory: File,
    pub(super) uid: u32,
    pub(super) gid: u32,
    locked: Cell<bool>,
}

impl JournalStore {
    pub(crate) fn open() -> Result<Self> {
        let parent = trusted_directory(Path::new("/var/lib"), Visibility::Private)?;
        Self::open_at(&parent, OsStr::new("secret-guard"), 0, 0).context(STATE)
    }

    /// A separate open file description keeps this probe's flock independent
    /// while anchoring it to the caller's already verified registry directory.
    pub(crate) fn reopen(&self) -> Result<Self> {
        let directory = fs::openat(&self.directory, ".", directory_flags(), Mode::empty())?;
        Self::from_directory(File::from(directory), self.uid, self.gid)
    }

    #[cfg(test)]
    pub(super) fn open_test(path: &Path) -> Result<Self> {
        let parent = File::from(fs::open(
            path.parent().context("missing test parent")?,
            directory_flags(),
            Mode::empty(),
        )?);
        Self::open_at(
            &parent,
            path.file_name().context("missing test directory name")?,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    pub(super) fn open_at(parent: &File, name: &OsStr, uid: u32, gid: u32) -> Result<Self> {
        let open = || fs::openat(parent, name, directory_flags(), Mode::empty());
        let directory = match open() {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => {
                Self::create_directory(parent, name, uid, gid)?;
                File::from(open().context("open new private state directory")?)
            }
            Err(e) => return Err(e).context("open private state directory"),
        };
        // Covers a racing first open which observed the just-created directory.
        parent.sync_all()?;
        Self::from_directory(directory, uid, gid)
    }

    fn create_directory(parent: &File, name: &OsStr, uid: u32, gid: u32) -> Result<()> {
        let (stage, staged) = stage_directory(parent, ".secret-guard-state-", uid, gid)?;
        staged.sync_all()?;
        let source = stage
            .path()
            .file_name()
            .context("missing staged directory name")?;
        match fs::renameat_with(parent, source, parent, name, RenameFlags::NOREPLACE) {
            Ok(()) | Err(Errno::EXIST) => Ok(()),
            Err(e) => Err(e).context("publish private state directory"),
        }
    }

    pub(super) fn from_directory(directory: File, uid: u32, gid: u32) -> Result<Self> {
        let m = directory.metadata()?;
        ensure!(
            m.uid() == uid && m.gid() == gid && m.mode() & 0o7777 == 0o700,
            "state directory must be owned by {uid}:{gid} with mode 0700"
        );
        let store = Self {
            directory,
            uid,
            gid,
            locked: Cell::new(false),
        };
        store.check_layout()?;
        Ok(store)
    }

    pub(crate) fn try_exclusive(&self) -> Result<bool> {
        loop {
            match fs::flock(&self.directory, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    self.locked.set(true);
                    return Ok(true);
                }
                Err(Errno::INTR) => continue,
                Err(Errno::WOULDBLOCK) => return Ok(false),
                Err(e) => return Err(e).context("lock private state directory"),
            }
        }
    }

    pub(crate) fn holds_lock(&self) -> bool {
        self.locked.get()
    }

    pub(crate) fn release(&self) -> Result<()> {
        self.require_lock()?;
        loop {
            match fs::flock(&self.directory, FlockOperation::Unlock) {
                Ok(()) => {
                    self.locked.set(false);
                    return Ok(());
                }
                Err(Errno::INTR) => continue,
                Err(e) => return Err(e).context("unlock private state directory"),
            }
        }
    }

    pub(super) fn require_lock(&self) -> Result<()> {
        ensure!(self.holds_lock(), "operation requires exclusive state lock");
        Ok(())
    }

    pub(super) fn file(&self, name: &str) -> Result<Option<File>> {
        checked_file(
            &self.directory,
            name,
            self.uid,
            self.gid,
            Visibility::Private,
        )
    }

    pub(super) fn check_layout(&self) -> Result<()> {
        for entry in Dir::read_from(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            ensure!(
                !matches!(name, b"manifest.json" | b"key-header")
                    && ![
                        b"file-".as_slice(),
                        b"blob-",
                        b".sg-write-",
                        b".sg-v2-write-"
                    ]
                    .iter()
                    .any(|prefix| name.starts_with(prefix)),
                "found an earlier Secret Guard archive in {STATE}; restore its files with the matching version, then move the old state directory aside before starting this version"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as disk;

    #[test]
    fn concurrent_first_opens_share_the_same_lock() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("state");
        let barrier = std::sync::Barrier::new(4);
        let stores = std::thread::scope(|threads| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    threads.spawn(|| {
                        barrier.wait();
                        JournalStore::open_test(&path)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Result<Vec<_>>>()
        })?;
        assert!(stores[0].try_exclusive()?);
        for contender in &stores[1..] {
            assert!(!contender.try_exclusive()?);
        }
        assert_eq!(disk::read_dir(tmp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn refuse_old_archives_without_touching_their_contents() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("state");
        let store = JournalStore::open_test(&path)?;
        assert!(store.try_exclusive()?);
        for name in [
            "manifest.json",
            "file-123",
            ".sg-v2-write-123",
            "key-header",
            "blob-123",
            ".sg-write-123",
        ] {
            let legacy = path.join(name);
            disk::write(&legacy, b"old-state")?;
            assert!(JournalStore::open_test(&path).is_err());
            assert!(store.load::<u32>().is_err());
            assert!(store.save(&5).is_err());
            assert!(store.finish().is_err());
            assert!(!path.join("session.json").exists());
            assert_eq!(disk::read(&legacy)?, b"old-state");
            disk::remove_file(legacy)?;
        }
        Ok(())
    }

    #[test]
    fn released_store_can_be_reacquired_by_another_descriptor() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("state");
        let first = JournalStore::open_test(&path)?;
        let second = JournalStore::open_test(&path)?;
        assert!(first.try_exclusive()?);
        assert!(first.holds_lock());
        assert!(!second.try_exclusive()?);
        assert!(!second.holds_lock());
        first.release()?;
        assert!(!first.holds_lock());
        assert!(second.try_exclusive()?);
        assert!(first.save(&0).is_err());
        second.release()?;
        assert!(first.try_exclusive()?);
        Ok(())
    }

    #[test]
    fn read_only_snapshot_and_lock_stay_bound_to_directory() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state = tmp.path().join("state");
        let writer = JournalStore::open_test(&state)?;
        let reader = writer.reopen()?;
        assert!(writer.try_exclusive()?);
        assert!(!reader.try_exclusive()?);
        assert!(reader.save(&0).is_err());
        writer.save(&42)?;
        assert_eq!(reader.load::<u32>()?, Some(42));
        let moved = tmp.path().join("moved");
        disk::rename(&state, &moved)?;
        disk::create_dir(&state)?;
        let reopened = writer.reopen()?;
        assert!(!reopened.try_exclusive()?);
        writer.save(&73)?;
        assert_eq!(reopened.load::<u32>()?, Some(73));
        assert_eq!(reader.load::<u32>()?, Some(73));
        assert!(!state.join("session.json").exists());
        drop(writer);
        assert!(reader.try_exclusive()?);
        Ok(())
    }
}
