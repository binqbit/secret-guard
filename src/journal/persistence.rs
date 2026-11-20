//! Atomically publish an operation journal and retain its scope after manual unlock.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Serialize, de::DeserializeOwned};

use super::{JournalStore, Session};

const SESSION: &str = "session.json";
const RECEIPT: &str = "unlocked.json";
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
            "the session changed while awaiting confirmation; retry the command"
        );
        Ok(())
    }

    pub(crate) fn load<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        self.read_record(SESSION)
    }

    fn read_record<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        self.check_layout()?;
        match self.file(name)? {
            Some(file) => serde_json::from_reader(file)
                .map(Some)
                .with_context(|| format!("read {name}")),
            None => Ok(None),
        }
    }

    pub(crate) fn receipts(&self) -> Result<Vec<Session>> {
        let receipts: Vec<Session> = self.read_record(RECEIPT)?.unwrap_or_default();
        for record in &receipts {
            record.validate_receipt()?;
        }
        Ok(receipts)
    }

    /// The caller holds admission and the slot lock. Make the scope durable
    /// before removing its active journal. An interrupted handoff (or an old
    /// Manual journal) can be replayed without adding the same scope twice.
    pub(crate) fn archive_unlock(&self) -> Result<()> {
        self.require_lock()?;
        let session: Session = self.load()?.context("missing completed unlock journal")?;
        session.validate_receipt()?;
        let mut receipts = self.receipts()?;
        if receipts
            .last()
            .is_some_and(|last| last.same_selection(&session))
        {
            // A prior publisher may have installed the list and failed its fsync.
            self.directory
                .sync_all()
                .context("sync manual unlock scopes")?;
        } else {
            // The last entry is the most recently unlocked scope for this slot.
            receipts.retain(|previous| !previous.same_selection(&session));
            receipts.push(session);
            self.save_record(RECEIPT, &receipts)?;
        }
        self.finish()
    }

    /// After verified closure, remove the passive scope before ending the
    /// closing journal so a crash still leaves enough state to retry.
    pub(crate) fn clear_receipt(&self, closed: &Session) -> Result<()> {
        self.require_lock()?;
        let mut receipts = self.receipts()?;
        let before = receipts.len();
        receipts.retain(|receipt| !receipt.same_selection(closed));
        if receipts.len() == before {
            return Ok(());
        }
        if receipts.is_empty() {
            fs::unlinkat(&self.directory, RECEIPT, AtFlags::empty())
                .context("remove the last manual unlock scope")?;
            return self.directory.sync_all().context("commit receipt removal");
        }
        self.save_record(RECEIPT, &receipts)
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
        self.save_record(SESSION, session)
    }

    // The exclusive slot lock serializes writes to both records. After a crash
    // only the atomically published destination can authorize an operation.
    fn save_record<T: Serialize>(&self, name: &str, record: &T) -> Result<()> {
        self.require_lock()?;
        self.check_layout()?;
        self.file(name)?;
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
            serde_json::to_writer(&mut pending, record)?;
            pending.sync_all()?;

            fs::renameat(&self.directory, PENDING, &self.directory, name)?;
            self.directory.sync_all()?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::unlinkat(&self.directory, PENDING, AtFlags::empty());
        }
        result.with_context(|| format!("commit {name}"))
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

    use serde_json::json;

    use super::*;

    #[test]
    fn legacy_manual_handoff_is_retryable_and_retains_every_outstanding_scope() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let registry = JournalStore::open_test(&tmp.path().join("state"))?;
        let _admission = registry.admission()?;
        let id = (12, 34);
        let slot = registry.direct(id, true)?.unwrap();
        assert!(slot.try_exclusive()?);

        let mut old = json!({
            "version": 3, "phase": "manual", "user": "editor", "uid": 1000, "pid": 2,
            "scope": {"roots": ["/srv/api"], "patterns": [".env"], "ignores": []},
            "roots": [id]
        });
        slot.save(&old)?;
        assert!(slot.reopen()?.archive_unlock().is_err());
        slot.archive_unlock()?;
        assert!(slot.load::<Session>()?.is_none());
        assert_eq!(slot.receipts()?[0].root_ids(), &[id]);
        let first: Session = serde_json::from_value(old.clone())?;
        assert_eq!(
            slot.file(RECEIPT)?.unwrap().metadata()?.mode() & 0o7777,
            0o600
        );
        registry.remove_direct(id, &slot)?;
        assert_eq!(registry.direct_ids()?, [id]);

        for phase in [
            "opening",
            "running",
            "closing",
            "manualopening",
            "manualclosing",
        ] {
            old["phase"] = json!(phase);
            slot.save(&old)?;
            assert!(slot.archive_unlock().is_err(), "{phase}");
            assert!(slot.load::<Session>()?.is_some());
            slot.finish()?;
            assert_eq!(slot.receipts()?.len(), 1);
        }

        old["phase"] = json!("manual");
        old["version"] = json!(4);
        slot.save(&old)?;
        assert!(slot.archive_unlock().is_err());

        // Both files can be visible after a crash between publishing the
        // receipt and retiring the active journal. Replaying adds no duplicate.
        old["version"] = json!(3);
        old["pid"] = json!(172);
        slot.save(&old)?;
        slot.archive_unlock()?;
        assert_eq!(slot.receipts()?.len(), 1);
        old["scope"]["patterns"] = json!([".secrets/"]);
        slot.save(&old)?;
        slot.archive_unlock()?;
        let second: Session = serde_json::from_value(old.clone())?;
        old["uid"] = json!(2000);
        slot.save(&old)?;
        slot.archive_unlock()?;
        let third: Session = serde_json::from_value(old)?;
        assert_eq!(slot.receipts()?.len(), 3);
        slot.save(&first)?;
        slot.archive_unlock()?;
        assert_eq!(slot.receipts()?.len(), 3);
        assert!(slot.receipts()?.last().unwrap().same_selection(&first));
        assert!(slot.reopen()?.clear_receipt(&first).is_err());
        slot.clear_receipt(&second)?;
        slot.clear_receipt(&second)?;
        let remaining = slot.receipts()?;
        assert_eq!(remaining.len(), 2);
        assert!(remaining[0].same_selection(&third));
        assert!(remaining[1].same_selection(&first));
        slot.clear_receipt(&first)?;
        slot.clear_receipt(&third)?;
        assert!(slot.file(RECEIPT)?.is_none());
        registry.remove_direct(id, &slot)?;
        assert!(registry.direct_ids()?.is_empty());
        Ok(())
    }

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
