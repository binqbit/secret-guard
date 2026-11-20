use std::cell::Cell;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, AtFlags, Dir, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Serialize, de::DeserializeOwned};

use crate::tree::{acl_allows_public_read, check_directory_search};

const CONFIG_DIR: &str = "/etc/secret-guard";
const STATE: &str = "/var/lib/secret-guard";
const SESSION: &str = "session.json";
const PENDING: &str = ".session.pending";

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[derive(Clone, Copy)]
enum Storage {
    Rules,
    Journal,
}

// Open each component relative to the checked parent. Keep the final descriptor pinned.
fn trusted_directory(path: &Path, storage: Storage) -> Result<File> {
    // An ordinary config reader needs search access, but need not be able to
    // list every ancestor. Only the final directory requires a readable handle.
    let lookup = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(fs::open("/", lookup, Mode::empty())?);
    for component in path.components() {
        if let Component::Normal(name) = component {
            directory = fs::openat(&directory, name, lookup, Mode::empty())
                .with_context(|| format!("open trusted directory component {name:?}"))?
                .into();
        } else {
            ensure!(
                component == Component::RootDir,
                "expected absolute trusted directory"
            );
        }
        let meta = directory.metadata()?;
        ensure!(
            meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "{component:?} must be owned by root and disallow group and other writes"
        );
        if matches!(storage, Storage::Rules) {
            check_directory_search(&directory, Path::new(component.as_os_str()))?;
        }
    }
    Ok(fs::openat(&directory, ".", directory_flags(), Mode::empty())?.into())
}

fn checked_file(
    directory: &File,
    name: &str,
    uid: u32,
    gid: u32,
    storage: Storage,
) -> Result<Option<File>> {
    ensure!(
        !name.is_empty()
            && !matches!(name, "." | "..")
            && !name.as_bytes().contains(&b'/')
            && !name.as_bytes().contains(&0),
        "expected a single plain filename"
    );
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = match fs::openat(directory, name, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open {name:?}")),
    };
    let meta = file.metadata()?;
    let mode = match storage {
        Storage::Rules => 0o644,
        Storage::Journal => 0o600,
    };
    // Atomic journal replacement can unlink an already-open status reader's inode.
    ensure!(
        meta.is_file()
            && meta.nlink() <= 1
            && meta.mode() & 0o7777 == mode
            && meta.uid() == uid
            && meta.gid() == gid,
        "{name:?} must be a regular file owned by {uid}:{gid} with mode {mode:04o} and no additional hard links"
    );
    if matches!(storage, Storage::Rules) {
        ensure!(
            acl_allows_public_read(&file)?,
            "{name:?} has an access ACL entry without read permission"
        );
    }
    Ok(Some(file))
}

#[derive(Clone, Copy)]
pub enum RuleList {
    Folders,
    Secrets,
    Ignore,
}

impl RuleList {
    pub const ALL: [Self; 3] = [Self::Folders, Self::Secrets, Self::Ignore];

    pub fn filename(self) -> &'static str {
        match self {
            Self::Folders => ".indexingfolders",
            Self::Secrets => ".indexingsecrets",
            Self::Ignore => ".indexingignore",
        }
    }

    pub fn name(self) -> &'static str {
        self.filename().trim_start_matches(".indexing")
    }

    fn entries(self, contents: &str) -> Result<Vec<String>> {
        let entries: Vec<_> = contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect();
        let required = match self {
            Self::Folders => Some("absolute search directory"),
            Self::Secrets => Some("file or directory pattern"),
            Self::Ignore => None,
        };
        if let Some(required) = required {
            ensure!(
                !entries.is_empty(),
                "list at least one {required} in {CONFIG_DIR}/{}",
                self.filename()
            );
        }
        Ok(entries)
    }
}

pub struct ConfigFiles {
    directory: File,
    uid: u32,
    gid: u32,
}

impl ConfigFiles {
    pub fn open() -> Result<Self> {
        let directory =
            trusted_directory(Path::new(CONFIG_DIR), Storage::Rules).context(CONFIG_DIR)?;
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

    pub fn read(&self, list: RuleList) -> Result<String> {
        let name = list.filename();
        let mut file = checked_file(&self.directory, name, self.uid, self.gid, Storage::Rules)?
            .with_context(|| format!("missing required configuration file {CONFIG_DIR}/{name}"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("read {CONFIG_DIR}/{name}"))?;
        Ok(contents)
    }

    fn scope(&self) -> Result<crate::Scope> {
        let entries = |list: RuleList| list.entries(&self.read(list)?);
        Ok(crate::Scope {
            roots: entries(RuleList::Folders)?
                .into_iter()
                .map(Into::into)
                .collect(),
            patterns: entries(RuleList::Secrets)?,
            ignores: entries(RuleList::Ignore)?,
        })
    }
}

pub fn read_config() -> Result<crate::Scope> {
    ConfigFiles::open()?.scope()
}

pub struct JournalStore {
    directory: File,
    uid: u32,
    gid: u32,
    locked: Cell<bool>,
}

impl JournalStore {
    pub fn open() -> Result<Self> {
        let parent = trusted_directory(Path::new("/var/lib"), Storage::Journal)?;
        Self::open_at(&parent, std::ffi::OsStr::new("secret-guard"), 0, 0).context(STATE)
    }

    #[cfg(test)]
    pub fn open_test(path: &Path) -> Result<Self> {
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

    fn open_at(parent: &File, name: &std::ffi::OsStr, uid: u32, gid: u32) -> Result<Self> {
        match fs::mkdirat(parent, name, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => (),
            Err(e) => return Err(e).context("create private state directory"),
        }
        let directory = File::from(
            fs::openat(parent, name, directory_flags(), Mode::empty())
                .context("open private state directory")?,
        );
        let m = directory.metadata()?;
        ensure!(
            m.uid() == uid && m.gid() == gid && m.mode() & 0o7777 == 0o700,
            "state directory must be owned by {uid}:{gid} with mode 0700"
        );
        // Covers a racing first open which observed the just-created directory.
        parent.sync_all()?;
        let store = Self {
            directory,
            uid,
            gid,
            locked: Cell::new(false),
        };
        store.check_layout()?;
        Ok(store)
    }

    pub fn try_exclusive(&self) -> Result<bool> {
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

    fn require_lock(&self) -> Result<()> {
        ensure!(self.locked.get(), "operation requires exclusive state lock");
        Ok(())
    }

    fn file(&self, name: &str) -> Result<Option<File>> {
        checked_file(&self.directory, name, self.uid, self.gid, Storage::Journal)
    }

    fn check_layout(&self) -> Result<()> {
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

    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<T>> {
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
        if self.file(PENDING)?.is_some() {
            fs::unlinkat(&self.directory, PENDING, AtFlags::empty())?;
        }
        Ok(())
    }

    pub fn save<T: Serialize>(&self, session: &T) -> Result<()> {
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

    pub fn finish(&self) -> Result<()> {
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
    use super::*;
    use std::fs as disk;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn configuration_uses_three_editable_lists() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let directory = File::open(tmp.path())?;
        let uid = directory.metadata()?.uid();
        let gid = directory.metadata()?.gid();
        disk::set_permissions(tmp.path(), disk::Permissions::from_mode(0o755))?;
        let read_lists = || ConfigFiles::from_directory(directory.try_clone()?, uid, gid)?.scope();
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
            assert!(!path.join(SESSION).exists());
            assert_eq!(disk::read(&legacy)?, b"old-state");
            disk::remove_file(legacy)?;
        }
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
        disk::set_permissions(&pending, disk::Permissions::from_mode(0o600))?;
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
    fn read_only_snapshot_and_lock_stay_bound_to_directory() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state = tmp.path().join("state");
        let writer = JournalStore::open_test(&state)?;
        let reader = JournalStore::open_test(&state)?;
        assert!(writer.try_exclusive()?);
        assert!(!reader.try_exclusive()?);
        assert!(reader.save(&0).is_err());
        writer.save(&42)?;
        assert_eq!(reader.load::<u32>()?, Some(42));
        let moved = tmp.path().join("moved");
        disk::rename(&state, &moved)?;
        disk::create_dir(&state)?;
        writer.save(&73)?;
        assert_eq!(reader.load::<u32>()?, Some(73));
        assert!(!state.join(SESSION).exists());
        drop(writer);
        assert!(reader.try_exclusive()?);
        Ok(())
    }

    #[test]
    fn rule_files_must_be_public_readable_regular_siblings() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let parent = File::open(tmp.path())?;
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        for name in [
            "",
            ".",
            "..",
            "foo/bar",
            "/etc/passwd",
            "./.indexingsecrets",
            ".indexingsecrets/",
            "foo\0bar",
        ] {
            assert!(
                checked_file(&parent, name, uid, gid, Storage::Rules).is_err(),
                "{name:?}"
            );
        }
        let rules = tmp.path().join(".indexingsecrets");
        disk::write(&rules, b".env\n")?;
        disk::set_permissions(&rules, disk::Permissions::from_mode(0o644))?;
        assert!(checked_file(&parent, ".indexingsecrets", uid, gid, Storage::Rules)?.is_some());
        symlink(&rules, tmp.path().join(".indexingignore"))?;
        assert!(checked_file(&parent, ".indexingignore", uid, gid, Storage::Rules).is_err());
        for mode in [0o600, 0o640, 0o664, 0o646, 0o666] {
            disk::set_permissions(&rules, disk::Permissions::from_mode(mode))?;
            assert!(checked_file(&parent, ".indexingsecrets", uid, gid, Storage::Rules).is_err());
        }
        disk::set_permissions(&rules, disk::Permissions::from_mode(0o644))?;
        disk::hard_link(&rules, tmp.path().join("another-link"))?;
        assert!(checked_file(&parent, ".indexingsecrets", uid, gid, Storage::Rules).is_err());
        Ok(())
    }

    #[test]
    fn rejects_unsafe_private_objects() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state = tmp.path().join("state");
        let store = JournalStore::open_test(&state)?;
        assert!(store.try_exclusive()?);
        store.save(&7)?;
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
