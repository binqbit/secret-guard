//! Pin search roots and resolve their descendants within filesystem boundaries.
use anyhow::{Context, Result, ensure};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

pub(super) const RESERVED_ROOTS: [&str; 2] = ["/etc/secret-guard", "/var/lib/secret-guard"];
pub(super) const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const WITHIN: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

// getxattr on the procfs magic link inspects the pinned inode without acquiring
// a data descriptor or interrupting a lease held by another application.
pub(crate) fn descriptor_path(fd: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

pub(crate) struct Root {
    pub(super) path: PathBuf,
    pub(super) fd: File,
}

impl Root {
    pub(super) fn open(path: &Path) -> rustix::io::Result<Self> {
        let fd = fs::openat2(fs::CWD, path, DIR, Mode::empty(), ResolveFlags::NO_SYMLINKS)?;
        Ok(Self {
            path: path.components().collect(),
            fd: fd.into(),
        })
    }

    /// Resolve a descendant without following symlinks or crossing a mount.
    pub(super) fn open_beneath(&self, path: &Path, flags: OFlags) -> rustix::io::Result<File> {
        fs::openat2(
            &self.fd,
            path,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            WITHIN,
        )
        .map(File::from)
    }

    /// Verify the configured name still reaches the pinned directory.
    pub(super) fn verified_id(&self) -> Result<(u64, u64)> {
        let current = Self::open(&self.path)
            .with_context(|| format!("reopen configured root {:?}", self.path))?;
        let current = current.fd.metadata()?;
        let pinned = self.fd.metadata()?;
        let id = (pinned.dev(), pinned.ino());
        ensure!(
            id == (current.dev(), current.ino()),
            "configured root was replaced: {:?}",
            self.path
        );
        Ok(id)
    }

    pub(crate) fn open_list(paths: &[PathBuf]) -> Result<Vec<Self>> {
        let mut roots: Vec<Root> = Vec::new();
        for path in paths {
            ensure!(
                path.is_absolute()
                    && path.parent().is_some()
                    && !path.components().any(|part| part == Component::ParentDir),
                "specify an absolute, non-filesystem-root directory without '..': {path:?}"
            );
            for reserved in RESERVED_ROOTS.map(Path::new) {
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
            roots.push(Self::open(path).with_context(|| format!("open configured root {path:?}"))?);
        }
        Ok(roots)
    }
}
