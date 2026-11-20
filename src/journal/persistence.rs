//! Atomically publish session.json and recover interrupted writes under the slot lock.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Serialize, de::DeserializeOwned};

use super::JournalStore;

const SESSION: &str = "session.json";
const PENDING: &str = ".session.pending";

impl JournalStore {
    pub(crate) fn pin_session(&self) -> Result<File> {
        self.file(SESSION)?.context("session has already closed")
    }

    // Journal updates atomically replace the file. Keeping the approved inode
    // open across the prompt also prevents its inode number from being reused.
    pub(crate) fn verify_session(&self, expected: &File) -> Result<()> {
        self.require_lock()?;

        let current = self.pin_session()?.metadata()?;
        let approved = expected.metadata()?;
        ensure!(
            (current.dev(), current.ino()) == (approved.dev(), approved.ino()),
            "the session changed while awaiting confirmation; run session again"
        );
        Ok(())
    }

    pub(crate) fn load<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        self.check_layout()?;
        match self.file(SESSION)? {
            Some(file) => serde_json::from_reader(file)
                .map(Some)
                .context("read session journal"),
            None => Ok(None),
        }
    }

    // Only the exclusive lock holder uses the reserved pending filename. A
    // killed writer can leave it here without replacing the committed journal.
    fn discard_pending(&self) -> Result<()> {
        let stat = match fs::statat(&self.directory, PENDING, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => return Err(e).context("inspect pending session journal"),
        };

        // A crash between create and fchmod may leave owner bits cleared by umask.
        ensure!(
            fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::RegularFile
                && stat.st_nlink == 1
                && stat.st_uid == self.uid
                && stat.st_gid == self.gid
                && (stat.st_mode & 0o7777) & !0o600 == 0,
            "unsafe pending session journal"
        );

        fs::unlinkat(&self.directory, PENDING, AtFlags::empty()).context("remove pending journal")
    }

    pub(super) fn save<T: Serialize>(&self, session: &T) -> Result<()> {
        self.require_lock()?;
        self.check_layout()?;
        self.file(SESSION)?;
        self.discard_pending()?;

        let mut pending = File::from(
            fs::openat(
                &self.directory,
                PENDING,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .context("create pending session journal")?,
        );

        let result = (|| -> Result<()> {
            fs::fchmod(&pending, Mode::RUSR | Mode::WUSR)?;
            serde_json::to_writer(&mut pending, session)?;
            pending.sync_all()?;

            fs::renameat(&self.directory, PENDING, &self.directory, SESSION)?;
            self.directory.sync_all()?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::unlinkat(&self.directory, PENDING, AtFlags::empty());
        }
        result.context("commit session journal")
    }

    pub(crate) fn finish(&self) -> Result<()> {
        self.require_lock()?;
        self.check_layout()?;
        self.discard_pending()?;

        if self.file(SESSION)?.is_some() {
            fs::unlinkat(&self.directory, SESSION, AtFlags::empty())?;
        }
        self.directory.sync_all().context("commit session end")
    }
}

#[cfg(test)]
mod tests {
    use std::fs as disk;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    #[test]
    fn commit_and_recover_only_session_metadata() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("state");
        let first = JournalStore::open_test(&path)?;
        assert_eq!(first.load::<u32>()?, None);
        assert!(first.try_exclusive()?);

        first.save(&41)?;
        let session = path.join(SESSION);
        assert_eq!(disk::metadata(&session)?.mode() & 0o7777, 0o600);
        assert_eq!(disk::metadata(&path)?.mode() & 0o7777, 0o700);

        let pending = path.join(PENDING);
        disk::write(&pending, b"half-written")?;
        disk::set_permissions(&pending, disk::Permissions::from_mode(0o000))?;
        drop(first);

        let next = JournalStore::open_test(&path)?;
        assert!(next.try_exclusive()?);
        assert_eq!(next.load::<u32>()?, Some(41));
        next.save(&99)?;
        assert_eq!(next.load::<u32>()?, Some(99));
        assert!(!pending.exists());

        next.finish()?;
        next.finish()?;
        assert_eq!(next.load::<u32>()?, None);
        assert_eq!(disk::read_dir(&path)?.count(), 0);
        Ok(())
    }

    #[test]
    fn rejects_unsafe_private_objects() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state = tmp.path().join("state");
        let store = JournalStore::open_test(&state)?;
        assert!(store.try_exclusive()?);
        store.save(&7)?;

        let pending = state.join(PENDING);
        disk::write(&pending, b"incomplete")?;
        disk::set_permissions(&pending, disk::Permissions::from_mode(0o644))?;
        assert!(store.finish().is_err());
        assert_eq!(store.load::<u32>()?, Some(7));
        disk::remove_file(&pending)?;

        let journal = state.join(SESSION);
        disk::set_permissions(&journal, disk::Permissions::from_mode(0o644))?;
        assert!(store.load::<u32>().is_err());
        disk::set_permissions(&journal, disk::Permissions::from_mode(0o600))?;

        let other = state.join("other");
        disk::hard_link(&journal, &other)?;
        assert!(store.load::<u32>().is_err());
        disk::remove_file(&journal)?;
        symlink(other, &journal)?;
        assert!(store.load::<u32>().is_err());

        disk::set_permissions(&state, disk::Permissions::from_mode(0o755))?;
        assert!(JournalStore::open_test(&state).is_err());
        Ok(())
    }
}
