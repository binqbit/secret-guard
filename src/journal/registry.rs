use std::ffi::OsStr;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, PathBuf};

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, AtFlags, Dir, FlockOperation, Gid, Mode, Uid};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use super::{JournalStore, directory_flags};
use crate::tree::descriptor_path;

const ADMISSION: &str = ".admission.lock";
const NAMED_PREFIX: &str = "named-";
const DIRECT_PREFIX: &str = "path-";
const BINDING: &str = "binding.json";

fn direct_entry((dev, ino): (u64, u64)) -> String {
    format!("{DIRECT_PREFIX}{dev:016x}-{ino:016x}")
}

pub fn validate_session_name(name: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
        "session names use 1 to 64 ASCII letters, digits, underscores or hyphens"
    );
    ensure!(
        name != "default",
        "the name 'default' is reserved; omit the name for the default session"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub uid: u32,
    pub path: PathBuf,
}

impl Binding {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.uid != 0 && self.uid != u32::MAX,
            "invalid account in session binding"
        );
        ensure!(
            self.path.is_absolute()
                && self.path.parent().is_some()
                && !self
                    .path
                    .components()
                    .any(|part| part == Component::ParentDir),
            "invalid folder in session binding: {:?}",
            self.path
        );
        Ok(())
    }
}

impl JournalStore {
    // Both the admission lock and the binding have stable names and are published
    // exactly once. An incomplete temporary file never serves as a lock or binding.
    fn publish_once(&self, name: &str, contents: &[u8]) -> Result<()> {
        let dir = descriptor_path(&self.directory);
        let mut pending = tempfile::NamedTempFile::new_in(&dir)?;
        pending.write_all(contents)?;
        fs::fchown(
            &pending,
            Some(Uid::from_raw(self.uid)),
            Some(Gid::from_raw(self.gid)),
        )?;
        fs::fchmod(&pending, Mode::RUSR | Mode::WUSR)?;
        pending.as_file().sync_all()?;
        match pending.persist_noclobber(dir.join(name)) {
            Ok(_) => (),
            Err(e) if e.error.kind() == ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e).with_context(|| format!("publish {name}")),
        }
        self.directory
            .sync_all()
            .with_context(|| format!("sync {name}"))
    }

    /// Serializes conflict checks and publication of each operation's first journal.
    /// Each caller opens the same inode with a separate open file description.
    pub fn admission(&self) -> Result<File> {
        let guard = match self.file(ADMISSION)? {
            Some(file) => file,
            None => {
                self.publish_once(ADMISSION, &[])?;
                self.file(ADMISSION)?
                    .context("missing session admission lock")?
            }
        };
        let meta = guard.metadata()?;
        ensure!(
            meta.nlink() == 1 && meta.len() == 0,
            "invalid session admission lock"
        );
        loop {
            match fs::flock(&guard, FlockOperation::LockExclusive) {
                Ok(()) => return Ok(guard),
                Err(Errno::INTR) => continue,
                Err(e) => return Err(e).context("lock session registry"),
            }
        }
    }

    pub fn named(&self, name: &str, create: bool) -> Result<Option<Self>> {
        validate_session_name(name)?;
        self.slot(&format!("{NAMED_PREFIX}{name}"), create)
    }

    pub fn direct(&self, root_id: (u64, u64), create: bool) -> Result<Option<Self>> {
        self.slot(&direct_entry(root_id), create)
    }

    fn slot(&self, entry: &str, create: bool) -> Result<Option<Self>> {
        if create {
            return Self::open_at(&self.directory, OsStr::new(entry), self.uid, self.gid)
                .with_context(|| format!("create or open session state {entry:?}"))
                .map(Some);
        }
        match fs::openat(&self.directory, entry, directory_flags(), Mode::empty()) {
            Ok(fd) => Self::from_directory(File::from(fd), self.uid, self.gid).map(Some),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("open session state {entry:?}")),
        }
    }

    fn entries(&self, prefix: &str) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in Dir::read_from(&self.directory)? {
            let entry = entry?;
            if let Some(suffix) = entry.file_name().to_bytes().strip_prefix(prefix.as_bytes()) {
                let name = std::str::from_utf8(suffix).context("invalid session registry entry")?;
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn names(&self) -> Result<Vec<String>> {
        let names = self.entries(NAMED_PREFIX)?;
        for name in &names {
            validate_session_name(name)?;
        }
        Ok(names)
    }

    pub fn direct_ids(&self) -> Result<Vec<(u64, u64)>> {
        self.entries(DIRECT_PREFIX)?
            .into_iter()
            .map(|suffix| {
                let (dev, ino) = suffix
                    .split_once('-')
                    .context("invalid path session identity")?;
                let id = (u64::from_str_radix(dev, 16)?, u64::from_str_radix(ino, 16)?);
                ensure!(
                    direct_entry(id) == format!("{DIRECT_PREFIX}{suffix}"),
                    "invalid path session identity"
                );
                Ok(id)
            })
            .collect()
    }

    /// After an operation finishes, the caller holds admission and the same slot
    /// lock. rmdir also fails safely if any journal or pending write remains.
    pub fn remove_direct(&self, root_id: (u64, u64), store: &Self) -> Result<()> {
        store.require_lock()?;
        let entry = direct_entry(root_id);
        let actual = fs::statat(&self.directory, entry.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        let held = store.directory.metadata()?;
        ensure!(
            (actual.st_dev, actual.st_ino) == (held.dev(), held.ino()),
            "path session state directory was replaced"
        );
        fs::unlinkat(&self.directory, entry.as_str(), AtFlags::REMOVEDIR)
            .context("remove empty path session state")?;
        self.directory
            .sync_all()
            .context("sync path session removal")
    }

    pub fn binding(&self) -> Result<Option<Binding>> {
        let Some(file) = self.file(BINDING)? else {
            return Ok(None);
        };
        let binding: Binding = serde_json::from_reader(file).context("read session binding")?;
        binding.validate()?;
        Ok(Some(binding))
    }

    pub fn bind_if_absent(&self, binding: &Binding) -> Result<()> {
        self.require_lock()?;
        binding.validate()?;
        if self.binding()?.is_none() {
            self.publish_once(BINDING, &serde_json::to_vec(binding)?)?;
        }
        let saved = self.binding()?.context("missing session binding")?;
        ensure!(
            saved == *binding,
            "this name is bound to {:?} for UID {}",
            saved.path,
            saved.uid
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn admission_guard_is_shared_across_names_and_independent_of_slot_locks() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = JournalStore::open_test(&temp.path().join("state"))?;
        let guard = root.admission()?;
        let contender = root.file(ADMISSION)?.unwrap();
        assert!(matches!(
            rustix::fs::flock(&contender, FlockOperation::NonBlockingLockExclusive),
            Err(Errno::WOULDBLOCK)
        ));
        assert!(root.try_exclusive()?);
        let api = root.named("api", true)?.unwrap();
        let web = root.named("web", true)?.unwrap();
        assert!(api.try_exclusive()?);
        assert!(web.try_exclusive()?);
        assert!(!root.named("api", false)?.unwrap().try_exclusive()?);
        drop(guard);
        rustix::fs::flock(&contender, FlockOperation::NonBlockingLockExclusive)?;
        assert_eq!(contender.metadata()?.mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn finishing_a_named_slot_preserves_its_binding_and_other_journals() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("state");
        let root = JournalStore::open_test(&path)?;
        let _guard = root.admission()?;
        assert!(root.named("api", false)?.is_none());
        assert!(root.names()?.is_empty());
        let api = root.named("api", true)?.unwrap();
        let web = root.named("web", true)?.unwrap();
        assert_eq!(root.names()?, ["api", "web"]);
        assert_eq!(fs::metadata(path.join("named-api"))?.mode() & 0o777, 0o700);
        let binding = Binding {
            uid: 1000,
            path: "/srv/api".into(),
        };
        assert!(api.bind_if_absent(&binding).is_err());
        assert!(api.try_exclusive()?);
        assert!(web.try_exclusive()?);
        assert!(root.try_exclusive()?);
        api.bind_if_absent(&binding)?;
        api.bind_if_absent(&binding)?;
        assert!(
            api.bind_if_absent(&Binding {
                uid: 1001,
                ..binding.clone()
            })
            .is_err()
        );
        assert!(
            api.bind_if_absent(&Binding {
                path: "/srv/web".into(),
                ..binding.clone()
            })
            .is_err()
        );
        api.save(&1u32)?;
        web.save(&2u32)?;
        root.save(&3u32)?;
        api.finish()?;
        assert_eq!(api.load::<u32>()?, None);
        assert_eq!(web.load::<u32>()?, Some(2));
        assert_eq!(root.load::<u32>()?, Some(3));
        assert_eq!(root.named("api", false)?.unwrap().binding()?, Some(binding));
        assert_eq!(
            fs::metadata(path.join("named-api/binding.json"))?.mode() & 0o777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn direct_slots_are_separate_from_names_and_only_removed_when_empty() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("state");
        let root = JournalStore::open_test(&path)?;
        let _guard = root.admission()?;
        let id = (u64::MAX, 42);
        assert!(root.direct(id, false)?.is_none());
        let direct = root.direct(id, true)?.unwrap();
        let named = root.named("path-42", true)?.unwrap();
        assert_eq!(root.direct_ids()?, vec![id]);
        assert_eq!(root.names()?, ["path-42"]);
        assert!(direct.try_exclusive()?);
        assert!(named.try_exclusive()?);
        assert!(root.remove_direct(id, &named).is_err());
        direct.save(&1u32)?;
        assert!(root.remove_direct(id, &direct).is_err());
        assert_eq!(direct.load::<u32>()?, Some(1));
        direct.finish()?;
        root.remove_direct(id, &direct)?;
        assert!(root.direct_ids()?.is_empty());
        assert!(root.direct(id, false)?.is_none());
        assert_eq!(root.names()?, ["path-42"]);
        fs::create_dir(path.join("path-01-02"))?;
        assert!(root.direct_ids().is_err());
        Ok(())
    }

    #[test]
    fn registry_rejects_unsafe_names_and_filesystem_objects() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("state");
        let root = JournalStore::open_test(&path)?;
        for name in [
            "",
            "default",
            "../outside",
            "name/child",
            ".hidden",
            "a b",
            "a\0b",
        ] {
            assert!(root.named(name, true).is_err(), "{name:?}");
        }
        assert!(root.named(&"a".repeat(65), true).is_err());
        let other = temp.path().join("outside");
        fs::create_dir(&other)?;
        symlink(&other, path.join("named-link"))?;
        assert!(root.named("link", false).is_err());
        assert!(root.named("link", true).is_err());
        symlink(temp.path().join("new-file"), path.join(ADMISSION))?;
        assert!(root.admission().is_err());
        fs::remove_file(path.join(ADMISSION))?;
        let _guard = root.admission()?;
        let broken = root.named("broken", true)?.unwrap();
        let record = path.join("named-broken/binding.json");
        fs::write(&record, b"{}")?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))?;
        assert!(broken.binding().is_err());
        fs::remove_file(&record)?;
        symlink(temp.path().join("new-file"), &record)?;
        assert!(broken.binding().is_err());
        Ok(())
    }
}
