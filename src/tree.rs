use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::os::fd::AsRawFd;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use globset::{GlobBuilder, GlobMatcher};
use rustix::fs::{self, Gid, Mode, OFlags, ResolveFlags, Uid, XattrFlags};
use rustix::io::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Done,
    Busy,
}

const LEGACY_STAGE: &str = ".secret-guard-stage";
const MARKER: &str = "trusted.secret_guard";
const ACL: &str = "system.posix_acl_access";
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const WITHIN: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccess {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    marker_uid: Option<u32>,
    acl_allows_public_read: bool,
    problem: Option<String>,
}

impl FileAccess {
    fn inspect(pinned: &File) -> Result<Self> {
        let m = pinned.metadata()?;
        let mut info = Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
            marker_uid: None,
            acl_allows_public_read: true,
            problem: None,
        };
        if !m.is_file() || m.nlink() != 1 {
            info.problem = Some(
                if m.is_file() {
                    "file has additional hard links"
                } else {
                    "matched object is not a regular file"
                }
                .into(),
            );
            return Ok(info);
        }
        let details = (|| -> Result<()> {
            let proc_path = descriptor_path(pinned);
            let mut marker = [0u8; 5];
            match fs::getxattr(&proc_path, MARKER, &mut marker[..]) {
                Ok(5) if marker[0] == 1 => {
                    info.marker_uid = Some(u32::from_be_bytes(marker[1..].try_into().unwrap()));
                }
                Ok(_) | Err(Errno::RANGE) => anyhow::bail!("invalid Secret Guard ownership marker"),
                Err(Errno::NODATA) => (),
                Err(e) => {
                    return Err(e)
                        .context("read trusted ownership marker; trusted xattrs are required");
                }
            }
            info.acl_allows_public_read = acl_allows_public_read(pinned)?;
            Ok(())
        })();
        if let Err(error) = details {
            info.problem = Some(format!("{error:#}"));
        }
        Ok(info)
    }

    pub fn validate(&self, uid: u32) -> Result<()> {
        if let Some(issue) = &self.problem {
            anyhow::bail!("{issue}");
        }
        ensure!(
            self.marker_uid.is_none_or(|original| original == uid),
            "ownership marker belongs to a different user"
        );
        ensure!(
            self.uid == uid || (self.uid == 0 && self.marker_uid == Some(uid)),
            "file must belong to the session user or have its protected ownership marker"
        );
        Ok(())
    }

    pub fn is_locked(&self, uid: u32) -> bool {
        self.problem.is_none()
            && self.uid == 0
            && self.gid == 0
            && self.mode == 0o600
            && self.marker_uid == Some(uid)
    }

    pub fn is_open(&self, uid: u32, gid: u32) -> bool {
        self.validate(uid).is_ok() && self.uid == uid && self.gid == gid && self.mode == 0o600
    }

    pub fn is_public(&self, uid: u32, gid: u32) -> bool {
        self.validate(uid).is_ok()
            && self.uid == uid
            && self.gid == gid
            && self.mode == 0o644
            && self.acl_allows_public_read
    }
}

struct AclPermissions {
    all_can_search: bool,
    read_after_chmod: bool,
}

fn access_acl(fd: &File) -> Result<Option<AclPermissions>> {
    let proc_path = descriptor_path(fd);
    let size = match fs::getxattr_query(&proc_path, ACL) {
        Ok(size) => size,
        Err(Errno::NODATA | Errno::OPNOTSUPP) => return Ok(None),
        Err(e) => return Err(e).context("inspect access ACL"),
    };
    let mut bytes = vec![0; size];
    let used = fs::getxattr(&proc_path, ACL, &mut bytes[..]).context("read access ACL")?;
    parse_acl(&bytes[..used]).map(Some)
}

/// Given readable owner, group and other mode bits, can every ACL entry read?
pub(crate) fn acl_allows_public_read(fd: &File) -> Result<bool> {
    Ok(access_acl(fd)?.is_none_or(|acl| acl.read_after_chmod))
}

pub(crate) fn check_directory_search(fd: &File, dir: &Path) -> Result<()> {
    ensure!(
        fd.metadata()?.mode() & 0o111 == 0o111,
        "directory {dir:?} needs search permission for owner, group, and others to make the configuration lists publicly readable"
    );
    ensure!(
        access_acl(fd)?.is_none_or(|acl| acl.all_can_search),
        "directory {dir:?} has an access ACL entry without search permission"
    );
    Ok(())
}

// Linux UAPI posix_acl_xattr version 2 has a little-endian header and eight-byte
// entries. chmod changes owner, mask (or owning group when unmasked), and other.
fn parse_acl(bytes: &[u8]) -> Result<AclPermissions> {
    const OWNER: u16 = 1;
    const USER: u16 = 2;
    const OWNING_GROUP: u16 = 4;
    const GROUP: u16 = 8;
    const MASK: u16 = 16;
    const OTHER: u16 = 32;

    let entries = bytes
        .strip_prefix(&2u32.to_le_bytes())
        .context("invalid access ACL version")?;
    let (entries, remainder) = entries.as_chunks::<8>();
    ensure!(remainder.is_empty(), "truncated access ACL");
    let mut kinds = 0;
    let mut previous_tag = 0;
    let mut named = BTreeSet::new();
    let mut all_can_search = true;
    let mut group_class_can_read = true;
    for entry in entries {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let perm = u16::from_le_bytes([entry[2], entry[3]]);
        let id = u32::from_le_bytes(entry[4..].try_into().unwrap());
        ensure!(tag >= previous_tag && perm <= 7, "invalid access ACL entry");
        previous_tag = tag;
        match tag {
            USER | GROUP => ensure!(
                id != u32::MAX && named.insert((tag, id)),
                "invalid named ACL entry"
            ),
            OWNER | OWNING_GROUP | MASK | OTHER => {
                ensure!(id == u32::MAX && kinds & tag == 0, "invalid base ACL entry")
            }
            _ => anyhow::bail!("unknown access ACL entry"),
        }
        kinds |= tag;
        all_can_search &= perm & 1 != 0;
        if matches!(tag, USER | GROUP | OWNING_GROUP) {
            group_class_can_read &= perm & 4 != 0;
        }
    }
    let base = OWNER | OWNING_GROUP | OTHER;
    ensure!(
        kinds & base == base && (named.is_empty() || kinds & MASK != 0),
        "incomplete access ACL"
    );
    // With a mask, named entries and the owning group's underlying permission
    // bits survive chmod. They must independently allow read under the new mask.
    Ok(AclPermissions {
        all_can_search,
        read_after_chmod: kinds & MASK == 0 || group_class_can_read,
    })
}

// getxattr on the procfs magic link inspects the pinned inode without acquiring
// a data descriptor or interrupting a lease held by another application.
pub(crate) fn descriptor_path(fd: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn metadata_fd(pinned: &File) -> rustix::io::Result<File> {
    // Called only after the selected inode has passed FileAccess::validate.
    fs::open(
        descriptor_path(pinned),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
}

// An exclusive Linux lease checks existing read/write opens, including file
// mappings that outlive the original descriptor. Dropping fd releases the lease.
fn take_exclusive_lease(fd: &File) -> Result<bool> {
    // SAFETY: the descriptor is live and F_SETLEASE takes the indicated integer.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLEASE, libc::F_WRLCK) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    Err(error).context("cannot check active use; Linux file leases must be enabled and supported on this filesystem, and sudo must grant CAP_LEASE")
}

fn lease_is_exclusive(fd: &File) -> Result<bool> {
    // Once a competing open requests a break, F_GETLEASE reports its target type.
    // SAFETY: F_GETLEASE takes only the command and a live descriptor.
    let kind = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETLEASE) };
    if kind == -1 {
        return Err(std::io::Error::last_os_error()).context("inspect file lease");
    }
    Ok(kind == libc::F_WRLCK)
}

pub(crate) struct Root {
    pub(crate) path: PathBuf,
    pub(crate) fd: File,
}

impl Root {
    pub(crate) fn open_list(paths: &[PathBuf]) -> Result<Vec<Self>> {
        let mut roots: Vec<Root> = Vec::new();
        for path in paths {
            ensure!(
                path.is_absolute()
                    && path.parent().is_some()
                    && !path.components().any(|part| part == Component::ParentDir),
                "specify an absolute, non-filesystem-root directory without '..': {path:?}"
            );
            for reserved in [
                Path::new("/var/lib/secret-guard"),
                Path::new("/etc/secret-guard"),
            ] {
                ensure!(
                    !path.starts_with(reserved) && !reserved.starts_with(path),
                    "root overlaps Secret Guard configuration or state: {path:?}"
                );
            }
            ensure!(
                !roots
                    .iter()
                    .any(|r| path.starts_with(&r.path) || r.path.starts_with(path)),
                "overlapping roots: {path:?}"
            );
            let fd = fs::openat2(fs::CWD, path, DIR, Mode::empty(), ResolveFlags::NO_SYMLINKS)
                .with_context(|| format!("open configured root {path:?}"))?;
            roots.push(Root {
                path: path.components().collect(),
                fd: fd.into(),
            });
        }
        Ok(roots)
    }
}

pub(crate) struct Rule {
    matcher: GlobMatcher,
    basename: bool,
    directory: bool,
}

impl Rule {
    pub(crate) fn compile(pattern: &str) -> Result<Self> {
        let directory = pattern.ends_with('/');
        let glob = pattern.strip_suffix('/').unwrap_or(pattern);
        ensure!(
            !glob
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == ".."),
            "invalid relative pattern {pattern:?}"
        );
        let matcher = GlobBuilder::new(glob)
            .literal_separator(true)
            .build()
            .with_context(|| format!("invalid pattern {pattern:?}"))?
            .compile_matcher();
        Ok(Self {
            matcher,
            basename: !glob.contains('/'),
            directory,
        })
    }

    fn covers_file(&self, relative: &Path) -> bool {
        if self.directory {
            relative
                .ancestors()
                .skip(1)
                .filter(|p| !p.as_os_str().is_empty())
                .any(|p| self.matches(p))
        } else {
            self.matches(relative)
        }
    }

    fn matches(&self, path: &Path) -> bool {
        if self.basename {
            path.file_name()
                .is_some_and(|name| self.matcher.is_match(Path::new(name)))
        } else {
            self.matcher.is_match(path)
        }
    }
}

pub(crate) enum IgnoreRule {
    Exact { path: PathBuf, directory_only: bool },
    Pattern(Rule),
}

impl IgnoreRule {
    pub(crate) fn compile(entry: &str) -> Result<Self> {
        ensure!(!entry.contains('\0'), "invalid ignore entry {entry:?}");
        let path = Path::new(entry);
        if path.is_absolute() || entry.starts_with("./") {
            ensure!(
                !path.components().any(|part| part == Component::ParentDir),
                "ignore path must not contain '..': {entry:?}"
            );
            return Ok(Self::Exact {
                path: path
                    .components()
                    .filter(|part| *part != Component::CurDir)
                    .collect(),
                directory_only: entry.ends_with('/'),
            });
        }
        Ok(Self::Pattern(Rule::compile(entry)?))
    }

    pub(crate) fn excludes_root(&self, root: &Path) -> bool {
        self.excludes(root, Path::new(""), true)
    }

    fn excludes(&self, absolute: &Path, relative: &Path, is_directory: bool) -> bool {
        match self {
            Self::Exact {
                path,
                directory_only,
            } => {
                let candidate = if path.is_absolute() {
                    absolute
                } else {
                    relative
                };
                candidate.starts_with(path)
                    && (candidate != path || is_directory || !directory_only)
            }
            Self::Pattern(rule) if is_directory => {
                rule.directory && !relative.as_os_str().is_empty() && rule.matches(relative)
            }
            Self::Pattern(rule) => rule.covers_file(relative),
        }
    }
}

pub struct Tree {
    roots: Vec<Root>,
    rules: Vec<Rule>,
    ignores: Vec<IgnoreRule>,
    uid: u32,
}

fn open_beneath(fd: &File, path: &Path, flags: OFlags) -> rustix::io::Result<File> {
    fs::openat2(fd, path, flags | OFlags::CLOEXEC, Mode::empty(), WITHIN).map(File::from)
}

pub(crate) fn check_root(root: &Root) -> Result<()> {
    let current = File::from(
        fs::openat2(
            fs::CWD,
            &root.path,
            DIR,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )
        .with_context(|| format!("reopen configured root {:?}", root.path))?,
    );
    ensure!(
        same_inode(&current.metadata()?, &root.fd.metadata()?),
        "configured root was replaced: {:?}",
        root.path
    );
    Ok(())
}

fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

impl Tree {
    pub(crate) fn roots(&self) -> &[Root] {
        &self.roots
    }

    pub fn new(
        paths: &[PathBuf],
        patterns: &[String],
        ignores: &[String],
        uid: u32,
    ) -> Result<Self> {
        ensure!(
            !paths.is_empty() && !patterns.is_empty(),
            "configure at least one root and pattern"
        );
        let roots = Root::open_list(paths)?;
        let rules = patterns
            .iter()
            .map(|p| Rule::compile(p))
            .collect::<Result<_>>()?;
        let ignores = ignores
            .iter()
            .map(|p| IgnoreRule::compile(p))
            .collect::<Result<_>>()?;
        Ok(Self {
            roots,
            rules,
            ignores,
            uid,
        })
    }

    fn excluded(&self, absolute: &Path, relative: &Path, is_directory: bool) -> bool {
        self.ignores
            .iter()
            .any(|rule| rule.excludes(absolute, relative, is_directory))
    }

    fn matches_file(&self, absolute: &Path, relative: &Path) -> bool {
        if relative.as_os_str().is_empty()
            || relative.starts_with(LEGACY_STAGE)
            || relative
                .components()
                .any(|p| !matches!(p, Component::Normal(_)))
        {
            return false;
        }
        self.rules.iter().any(|rule| rule.covers_file(relative))
            && !self.excluded(absolute, relative, false)
    }

    fn locate<'a>(&self, path: &'a Path) -> Result<(&Root, &'a Path)> {
        self.roots
            .iter()
            .find_map(|root| {
                let relative = path.strip_prefix(&root.path).ok()?;
                self.matches_file(path, relative)
                    .then_some((root, relative))
            })
            .with_context(|| format!("path outside configured selection: {path:?}"))
    }

    pub fn root_ids(&self) -> Result<Vec<(u64, u64)>> {
        self.roots
            .iter()
            .map(|root| {
                check_root(root)?;
                let m = root.fd.metadata()?;
                Ok((m.dev(), m.ino()))
            })
            .collect()
    }

    pub fn scan(&self) -> Result<BTreeMap<PathBuf, FileAccess>> {
        let mut result = BTreeMap::new();
        for root in &self.roots {
            check_root(root)?;
            if self
                .ignores
                .iter()
                .any(|rule| rule.excludes_root(&root.path))
            {
                continue;
            }
            let mut dirs = vec![PathBuf::new()];
            while let Some(dir) = dirs.pop() {
                let relative = if dir.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    &dir
                };
                let fd = open_beneath(&root.fd, relative, DIR)
                    .with_context(|| format!("scan directory {:?}", root.path.join(&dir)))?;
                for entry in fs::Dir::read_from(&fd)? {
                    let entry = entry?;
                    let name = OsStr::from_bytes(entry.file_name().to_bytes());
                    if name == "." || name == ".." {
                        continue;
                    }
                    let child = dir.join(name);
                    if child == Path::new(LEGACY_STAGE) {
                        continue;
                    }
                    let pinned =
                        match open_beneath(&root.fd, &child, OFlags::PATH | OFlags::NOFOLLOW) {
                            Ok(fd) => fd,
                            Err(Errno::XDEV | Errno::LOOP | Errno::NOENT) => continue,
                            Err(e) => {
                                return Err(e).with_context(|| {
                                    format!("inspect {:?}", root.path.join(&child))
                                });
                            }
                        };
                    let meta = pinned.metadata()?;
                    let absolute = root.path.join(&child);
                    if meta.is_dir() {
                        if !self.excluded(&absolute, &child, true) {
                            dirs.push(child);
                        }
                    } else if !meta.is_symlink() && self.matches_file(&absolute, &child) {
                        result.insert(absolute, FileAccess::inspect(&pinned)?);
                    }
                }
            }
            check_root(root)?;
        }
        Ok(result)
    }

    pub fn set_access(
        &self,
        path: &Path,
        expected: &FileAccess,
        open: bool,
        gid: u32,
    ) -> Result<Change> {
        let (root, relative) = self.locate(path)?;
        ensure!(
            self.uid != 0 && self.uid != u32::MAX && gid != u32::MAX,
            "invalid session identity"
        );
        check_root(root)?;
        let pinned = open_beneath(&root.fd, relative, OFlags::PATH | OFlags::NOFOLLOW)?;
        let before = FileAccess::inspect(&pinned)?;
        ensure!(
            before == *expected,
            "file identity or permissions changed after scanning"
        );
        before.validate(self.uid)?;
        let verify_name = |expected_uid: u32| -> Result<()> {
            check_root(root)?;
            let current =
                open_beneath(&root.fd, relative, OFlags::PATH | OFlags::NOFOLLOW)?.metadata()?;
            ensure!(
                current.dev() == before.dev
                    && current.ino() == before.ino
                    && current.nlink() == 1
                    && current.uid() == expected_uid,
                "file path, link count, or owner changed during the permission change"
            );
            Ok(())
        };
        verify_name(before.uid)?;
        // Narrowing a previously shared file also requires the old readers to release it.
        let require_lease = !open || before.mode & 0o077 != 0;
        let fd = match metadata_fd(&pinned) {
            Ok(fd) => fd,
            Err(Errno::AGAIN) if require_lease => return Ok(Change::Busy),
            Err(e) => return Err(e).context("open the verified file for metadata changes"),
        };
        if require_lease && (!take_exclusive_lease(&fd)? || !lease_is_exclusive(&fd)?) {
            return Ok(Change::Busy);
        }
        if !open && before.is_locked(self.uid) {
            return Ok(Change::Done);
        }
        if before.marker_uid.is_none() {
            let mut value = [1u8; 5];
            value[1..].copy_from_slice(&self.uid.to_be_bytes());
            fs::fsetxattr(&fd, MARKER, &value, XattrFlags::CREATE).context(
                "record the verified file owner (trusted xattrs and CAP_SYS_ADMIN required)",
            )?;
            // A root-owned inode must never survive a crash without its enrollment.
            fd.sync_all()?;
        }

        let restricted = Mode::RUSR | Mode::WUSR;
        let (wanted_uid, wanted_gid) = if open { (self.uid, gid) } else { (0, 0) };
        if before.uid != wanted_uid || before.gid != wanted_gid {
            // Finish the ownership transition in a restrictive mode. fchown also clears
            // executable privilege bits and file capabilities as specified by Linux.
            if require_lease && !lease_is_exclusive(&fd)? {
                return Ok(Change::Busy);
            }
            fs::fchmod(&fd, restricted)?;
            verify_name(before.uid)?;
            if require_lease && !lease_is_exclusive(&fd)? {
                return Ok(Change::Busy);
            }
            fs::fchown(
                &fd,
                Some(Uid::from_raw(wanted_uid)),
                Some(Gid::from_raw(wanted_gid)),
            )?;
        }
        verify_name(wanted_uid)?;
        if fd.metadata()?.mode() & 0o7777 != restricted.bits() {
            if require_lease && !lease_is_exclusive(&fd)? {
                return Ok(Change::Busy);
            }
            fs::fchmod(&fd, restricted)?;
        }
        fd.sync_all()?;
        let parent = relative
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        open_beneath(&root.fd, parent, DIR)?.sync_all()?;
        verify_name(wanted_uid)?;
        let after = FileAccess::inspect(&pinned)?;
        ensure!(
            if open {
                after.is_open(self.uid, gid)
            } else {
                after.is_locked(self.uid)
            },
            "file permissions did not reach the requested state"
        );
        if require_lease && !lease_is_exclusive(&fd)? {
            return Ok(Change::Busy);
        }
        Ok(Change::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as disk;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn tree(root: &Path) -> Tree {
        Tree::new(
            &[root.into()],
            &[".env".into(), ".env.*".into(), ".secrets/".into()],
            &["target/".into(), ".env.example".into()],
            rustix::process::geteuid().as_raw(),
        )
        .unwrap()
    }

    #[test]
    fn scans_nested_rules_bytewise_and_skips_symlinks_and_exclusions() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let root = workspace.path().join("project");
        disk::create_dir_all(root.join("app/.secrets/keys"))?;
        disk::create_dir_all(root.join("target"))?;
        disk::write(root.join("target/.env"), b"ignored")?;
        disk::write(root.join(".env.example"), b"public")?;
        let a = root.join(".env");
        let b = root
            .join("app/.secrets/keys")
            .join(std::ffi::OsString::from_vec(vec![0xff]));
        let outside = workspace.path().join(".env");
        for path in [&a, &b, &outside] {
            disk::write(path, b"fixture")?;
        }
        symlink(&outside, root.join(".env.link"))?;
        symlink(workspace.path(), root.join("link"))?;
        let t = tree(&root.join("./"));
        let files = t.scan()?;
        assert_eq!(files.keys().collect::<Vec<_>>(), vec![&a, &b]);
        assert!(t.locate(&outside).is_err());
        assert!(t.locate(&root.join("dir/../../.env")).is_err());
        assert!(t.locate(&root.join("target/.env")).is_err());
        assert!(t.locate(&root.join(".secret-guard-stage/.env")).is_err());
        assert!(Tree::new(&[root], &["../.env".into()], &[], 1000).is_err());
        Ok(())
    }

    #[test]
    fn absolute_ignores_match_exact_paths_across_search_roots() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let first = workspace.path().join("first");
        let second = workspace.path().join("second");
        let excluded_root = workspace.path().join("excluded/project");
        let entries = [
            "dir[1]/deep/key",
            "dir1/deep/key",
            "key*",
            "key-extra",
            "regular",
        ];
        for root in [&first, &second, &excluded_root] {
            for entry in entries {
                let file = root.join(entry);
                disk::create_dir_all(file.parent().unwrap())?;
                disk::write(file, b"fixture")?;
            }
        }
        let mut ignores = vec![
            first.join("dir[1]").display().to_string(),
            second.join("dir1/").display().to_string(),
            first.join("key*").display().to_string(),
            first.join("regular/").display().to_string(),
            workspace
                .path()
                .join("outside/absent")
                .display()
                .to_string(),
            workspace.path().join("excluded").display().to_string(),
        ];
        let roots = [first.clone(), second.clone(), excluded_root.clone()];
        let make_tree = |ignores: &[String]| Tree::new(&roots, &["*".into()], ignores, 1000);
        let tree = make_tree(&ignores)?;
        let visible: BTreeSet<_> = tree.scan()?.into_keys().collect();
        let expected = [
            first.join("dir1/deep/key"),
            first.join("key-extra"),
            first.join("regular"),
            second.join("dir[1]/deep/key"),
            second.join("key*"),
            second.join("key-extra"),
            second.join("regular"),
        ];
        assert_eq!(visible, expected.into_iter().collect());
        for hidden in [
            first.join("dir[1]/deep/key"),
            first.join("key*"),
            excluded_root.join("regular"),
        ] {
            assert!(tree.locate(&hidden).is_err());
        }
        ignores.push(first.display().to_string());
        assert!(
            make_tree(&ignores)?
                .scan()?
                .keys()
                .all(|p| p.starts_with(&second))
        );
        assert!(IgnoreRule::compile("/where/../else").is_err());
        assert!(Rule::compile("/where/key").is_err());
        Ok(())
    }

    #[test]
    fn relative_ignore_paths_prune_named_directories() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        for entry in [
            "cache/key",
            "nested/cache/key",
            "skip/key",
            "nested/skip/key",
            "app/generated/deep/key",
            "nested/app/generated/key",
            "build.tmp/key",
            "key.tmp",
            "legacy/key",
            "nested/legacy",
            "folder[1]/key",
            "folder1/key",
        ] {
            let file = root.join(entry);
            disk::create_dir_all(file.parent().unwrap())?;
            disk::write(file, b"fixture")?;
        }
        let tree = Tree::new(
            &[root.into()],
            &["*".into()],
            &[
                "./cache".into(),
                "skip/".into(),
                "app/generated/".into(),
                "legacy".into(),
                "./folder[1]".into(),
                "*.tmp".into(),
            ],
            1000,
        )?;
        let expected = [
            "nested/cache/key",
            "nested/app/generated/key",
            "build.tmp/key",
            "legacy/key",
            "folder1/key",
        ];
        assert_eq!(
            tree.scan()?.into_keys().collect::<BTreeSet<_>>(),
            expected.map(|name| root.join(name)).into_iter().collect()
        );
        for hidden in [
            "cache/key",
            "nested/skip/key",
            "app/generated/deep/key",
            "key.tmp",
            "nested/legacy",
            "folder[1]/key",
        ] {
            assert!(tree.locate(&root.join(hidden)).is_err());
        }
        Ok(())
    }

    #[test]
    fn scan_reports_an_unsafe_file_without_hiding_the_others() -> Result<()> {
        let root = tempfile::tempdir()?;
        let a = root.path().join(".env");
        let b = root.path().join(".env.extra");
        let fifo = root.path().join(".env.pipe");
        disk::write(&a, b"a")?;
        disk::write(&b, b"b")?;
        disk::hard_link(&a, root.path().join("alias"))?;
        fs::mkfifoat(fs::CWD, &fifo, Mode::RUSR | Mode::WUSR)?;
        let t = tree(root.path());
        let files = t.scan()?;
        assert!(files[&a].validate(t.uid).is_err());
        assert!(files[&fifo].validate(t.uid).is_err());
        files[&b].validate(t.uid)?;
        Ok(())
    }

    #[test]
    fn public_configuration_requires_searchable_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        let private = root.path().join("private");
        disk::create_dir(&private)?;
        disk::set_permissions(&private, disk::Permissions::from_mode(0o700))?;
        let error = check_directory_search(&File::open(&private)?, &private).unwrap_err();
        assert!(error.to_string().contains("private"));
        assert_eq!(disk::metadata(private)?.mode() & 0o777, 0o700);
        Ok(())
    }

    fn fixture_acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in entries {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&permissions.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn owner_only_mode_masks_named_acl_entries_and_preserves_them() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join(".env");
        let fd = File::create(&path)?;
        let base = u32::MAX;
        let mut entries = [
            (1, 6, base),
            (2, 4, rustix::process::geteuid().as_raw()),
            (4, 4, base),
            (8, 4, rustix::process::getegid().as_raw()),
            (16, 4, base),
            (32, 4, base),
        ];
        fs::fsetxattr(&fd, ACL, &fixture_acl(&entries), XattrFlags::empty())?;
        let info = FileAccess::inspect(&fd)?;
        assert!(info.is_public(info.uid, info.gid));
        assert!(!info.is_open(info.uid, info.gid));
        entries[1].1 = 0;
        fs::fsetxattr(&fd, ACL, &fixture_acl(&entries), XattrFlags::empty())?;
        assert!(!FileAccess::inspect(&fd)?.is_public(info.uid, info.gid));
        fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)?;
        let private = FileAccess::inspect(&fd)?;
        assert!(private.is_open(info.uid, info.gid));
        assert!(!private.is_public(info.uid, info.gid));
        // chmod preserved named read grants and denials, and masked every grant.
        entries[4].1 = 0;
        entries[5].1 = 0;
        let mut actual = vec![0; fs::fgetxattr_query(&fd, ACL)?];
        fs::fgetxattr(&fd, ACL, &mut actual[..])?;
        assert_eq!(actual, fixture_acl(&entries));
        Ok(())
    }

    #[test]
    fn directory_search_uses_all_entries_and_the_mask() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let fd = File::open(dir.path())?;
        let base = u32::MAX;
        let mut entries = [
            (1, 7, base),
            (2, 1, rustix::process::geteuid().as_raw()),
            (4, 5, base),
            (16, 5, base),
            (32, 1, base),
        ];
        fs::fsetxattr(&fd, ACL, &fixture_acl(&entries), XattrFlags::empty())?;
        assert!(access_acl(&fd)?.unwrap().all_can_search);
        entries[1].1 = 4;
        fs::fsetxattr(&fd, ACL, &fixture_acl(&entries), XattrFlags::empty())?;
        assert!(!access_acl(&fd)?.unwrap().all_can_search);
        entries[1].1 = 1;
        entries[3].1 = 4;
        fs::fsetxattr(&fd, ACL, &fixture_acl(&entries), XattrFlags::empty())?;
        assert!(!access_acl(&fd)?.unwrap().all_can_search);
        Ok(())
    }

    #[test]
    fn malformed_acl_entries_are_rejected() {
        let base = u32::MAX;
        assert!(parse_acl(&[]).is_err());
        assert!(parse_acl(&[2, 0, 0, 0, 1]).is_err());
        let missing_mask = [(1, 7, base), (2, 4, 55), (4, 7, base), (32, 5, base)];
        assert!(parse_acl(&fixture_acl(&missing_mask)).is_err());
        let duplicate = [
            (1, 7, base),
            (2, 4, 55),
            (2, 0, 55),
            (4, 7, base),
            (16, 7, base),
            (32, 5, base),
        ];
        assert!(parse_acl(&fixture_acl(&duplicate)).is_err());
    }

    #[test]
    fn release_requires_protected_provenance_and_the_requested_identity() {
        let mut info = FileAccess {
            dev: 1,
            ino: 2,
            uid: 0,
            gid: 0,
            mode: 0o600,
            marker_uid: None,
            acl_allows_public_read: true,
            problem: None,
        };
        assert!(info.validate(1000).is_err());
        info.marker_uid = Some(2000);
        assert!(info.validate(1000).is_err());
        info.marker_uid = Some(1000);
        info.validate(1000).unwrap();
        assert!(info.is_locked(1000));
        assert!(!info.is_open(1000, 1000));
        info.uid = 1000;
        info.gid = 1000;
        info.acl_allows_public_read = false;
        assert!(info.is_open(1000, 1000));
        assert!(!info.is_open(1000, 2000));
        assert!(!info.is_open(2000, 1000));
        assert!(!info.is_locked(1000));
    }

    #[test]
    fn active_reader_writer_and_mapping_block_an_exclusive_lease() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join(".env");
        disk::write(&path, b"fixture")?;
        let pinned = File::from(fs::open(
            &path,
            OFlags::PATH | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        let fd = metadata_fd(&pinned)?;
        let reader = File::open(&path)?;
        assert!(!take_exclusive_lease(&fd)?);
        drop(reader);
        let writer = disk::OpenOptions::new().write(true).open(&path)?;
        assert!(!take_exclusive_lease(&fd)?);
        drop(writer);
        let reader = File::open(&path)?;
        // SAFETY: map one existing byte read-only. The mapping outlives reader and
        // is released below without constructing references into the mapped region.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                1,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                reader.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        drop(reader);
        let held = take_exclusive_lease(&fd)?;
        // SAFETY: mapping is the successful mmap result above, of length one.
        assert_eq!(unsafe { libc::munmap(mapping, 1) }, 0);
        assert!(!held);
        assert!(take_exclusive_lease(&fd)?);
        // Scanning metadata must not open another data descriptor or break our lease.
        assert!(FileAccess::inspect(&pinned)?.problem.is_none());
        assert!(lease_is_exclusive(&fd)?);
        Ok(())
    }

    #[test]
    fn busy_file_is_skipped_before_any_changes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join(".env");
        disk::write(&path, b"fixture")?;
        let reader = File::open(&path)?;
        fs::fchmod(&reader, Mode::from_bits_retain(0o644))?;
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let uid = if uid == 0 {
            fs::fchown(&reader, Some(Uid::from_raw(1000)), None)?;
            1000
        } else {
            uid
        };
        let tree = Tree::new(&[root.path().into()], &[".env".into()], &[], uid)?;
        let before = tree.scan()?;
        let original = reader.metadata()?;
        assert_eq!(
            tree.set_access(&path, &before[&path], false, gid)?,
            Change::Busy
        );
        assert_eq!(
            tree.set_access(&path, &before[&path], true, gid)?,
            Change::Busy
        );
        assert_eq!(tree.scan()?, before);
        let current = reader.metadata()?;
        assert_eq!(
            (current.ctime(), current.ctime_nsec()),
            (original.ctime(), original.ctime_nsec())
        );
        Ok(())
    }

    #[test]
    fn replacement_is_rejected_before_metadata_changes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join(".env");
        disk::write(&path, b"before")?;
        let uid = rustix::process::geteuid().as_raw();
        let t = Tree::new(
            &[root.path().into()],
            &[".env".into()],
            &[],
            if uid == 0 { 1000 } else { uid },
        )?;
        let files = t.scan()?;
        disk::rename(&path, root.path().join("old"))?;
        disk::write(&path, b"after")?;
        let original_mode = disk::metadata(&path)?.mode();
        assert!(t.set_access(&path, &files[&path], false, 1000).is_err());
        assert_eq!(disk::metadata(&path)?.mode(), original_mode);
        Ok(())
    }
}
