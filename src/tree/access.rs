//! Inspect a pinned file and change its ownership and mode under a file lease.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, Gid, Mode, OFlags, Uid, XattrFlags};
use rustix::io::Errno;

use super::{Tree, acl_allows_public_read, descriptor_path, root::DIR};

const MARKER: &str = "trusted.secret_guard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Done,
    Busy,
}

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
    pub(super) fn inspect(pinned: &File) -> Result<Self> {
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

impl Tree {
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

        root.verified_id()?;
        let pinned = root.open_beneath(relative, OFlags::PATH | OFlags::NOFOLLOW)?;
        let before = FileAccess::inspect(&pinned)?;
        if before != *expected {
            // A legacy scope can reach one inode through two bind mounts. The
            // first path may already have completed the requested transition.
            // Only accept the same enrolled inode in its exact target state.
            expected.validate(self.uid)?;
            let completed = if open {
                before.marker_uid == Some(self.uid) && before.is_open(self.uid, gid)
            } else {
                before.is_locked(self.uid)
            };
            ensure!(
                (before.dev, before.ino) == (expected.dev, expected.ino) && completed,
                "file identity or permissions changed after scanning"
            );
        }
        before.validate(self.uid)?;

        let verify_name = |expected_uid: u32| -> Result<()> {
            root.verified_id()?;
            let current = root
                .open_beneath(relative, OFlags::PATH | OFlags::NOFOLLOW)?
                .metadata()?;
            ensure!(
                current.dev() == before.dev
                    && current.ino() == before.ino
                    && current.nlink() == 1
                    && current.uid() == expected_uid,
                "file path, link count, or owner changed during the permission change"
            );
            Ok(())
        };

        // Narrowing a previously shared file also requires the old readers to release it.
        let require_lease = !open || (expected.mode | before.mode) & 0o077 != 0;
        let fd = match metadata_fd(&pinned) {
            Ok(fd) => fd,
            Err(Errno::AGAIN) => return Ok(Change::Busy),
            Err(e) => return Err(e).context("open the verified file for metadata changes"),
        };
        if require_lease && (!take_exclusive_lease(&fd)? || !lease_is_exclusive(&fd)?) {
            return Ok(Change::Busy);
        }
        verify_name(before.uid)?;

        let enrolling = before.marker_uid.is_none();
        if enrolling {
            let mut value = [1u8; 5];
            value[1..].copy_from_slice(&self.uid.to_be_bytes());
            fs::fsetxattr(&fd, MARKER, &value, XattrFlags::CREATE).context(
                "record the verified file owner (trusted xattrs and CAP_SYS_ADMIN required)",
            )?;
        }
        if enrolling || (!open && before.uid != 0) {
            // A failed sync can leave the marker visible. Retry it before giving
            // the inode to root, so the enrollment survives a crash as well.
            fd.sync_all().context("sync the secret ownership marker")?;
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

        // Even an already-locked inode may be here because an earlier sync failed.
        fd.sync_all()
            .context("sync file ownership and permissions")?;
        let parent = relative
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        root.open_beneath(parent, DIR)?
            .sync_all()
            .context("sync the parent directory of the managed file")?;

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
    use std::fs as disk;

    use super::*;

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
