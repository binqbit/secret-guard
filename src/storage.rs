//! Open trusted configuration and journal objects through verified directory descriptors.

use std::fs::File;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, Gid, Mode, OFlags, Uid};
use rustix::io::Errno;

use crate::tree::{acl_allows_public_read, check_directory_search, descriptor_path};

pub(crate) fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Prepare a private directory under a pinned trusted parent before publishing it by rename.
pub(crate) fn stage_directory(
    parent: &File,
    prefix: &str,
    uid: u32,
    gid: u32,
) -> Result<(tempfile::TempDir, File)> {
    let mode = std::fs::Permissions::from_mode(0o700);
    let stage = tempfile::Builder::new()
        .prefix(prefix)
        .permissions(mode.clone())
        .tempdir_in(descriptor_path(parent))?;

    // Restore owner access after mkdir's umask, then clear any inherited setgid group.
    std::fs::set_permissions(stage.path(), mode)?;
    let directory = File::open(stage.path())?;
    fs::fchown(
        &directory,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )?;
    fs::fchmod(&directory, Mode::RWXU)?;
    Ok((stage, directory))
}

#[derive(Clone, Copy)]
pub(crate) enum Visibility {
    Public,
    Private,
}

// Open each component relative to the checked parent. Keep the final descriptor pinned.
pub(crate) fn trusted_path(path: &Path, visibility: Visibility) -> Result<File> {
    // An ordinary config reader needs search access, but need not be able to
    // list every ancestor. Only the final directory requires a readable handle.
    ensure!(path.is_absolute(), "expected absolute trusted directory");
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
        if matches!(visibility, Visibility::Public) {
            check_directory_search(&directory, Path::new(component.as_os_str()))?;
        }
    }
    Ok(directory)
}

pub(crate) fn trusted_directory(path: &Path, visibility: Visibility) -> Result<File> {
    let directory = trusted_path(path, visibility)?;
    Ok(fs::openat(&directory, ".", directory_flags(), Mode::empty())?.into())
}

pub(crate) fn checked_file(
    directory: &File,
    name: &str,
    uid: u32,
    gid: u32,
    visibility: Visibility,
) -> Result<Option<File>> {
    ensure!(
        !name.is_empty()
            && !matches!(name, "." | "..")
            && !name.as_bytes().contains(&b'/')
            && !name.as_bytes().contains(&0),
        "expected a single plain filename"
    );

    // Pin and verify the object's type before acquiring a data descriptor.
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = match fs::openat(directory, name, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open {name:?}")),
    };

    let meta = file.metadata()?;
    let mode = match visibility {
        Visibility::Public => 0o644,
        Visibility::Private => 0o600,
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
    if matches!(visibility, Visibility::Public) {
        ensure!(
            acl_allows_public_read(&file)?,
            "{name:?} has an access ACL entry without read permission"
        );
    }

    Ok(Some(File::open(descriptor_path(&file))?))
}

#[cfg(test)]
mod tests {
    use std::fs as disk;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

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
                checked_file(&parent, name, uid, gid, Visibility::Public).is_err(),
                "{name:?}"
            );
        }

        let rules = tmp.path().join(".indexingsecrets");
        disk::write(&rules, b".env\n")?;
        disk::set_permissions(&rules, disk::Permissions::from_mode(0o644))?;
        assert!(checked_file(&parent, ".indexingsecrets", uid, gid, Visibility::Public)?.is_some());

        symlink(&rules, tmp.path().join(".indexingignore"))?;
        assert!(checked_file(&parent, ".indexingignore", uid, gid, Visibility::Public).is_err());

        for mode in [0o600, 0o640, 0o664, 0o646, 0o666] {
            disk::set_permissions(&rules, disk::Permissions::from_mode(mode))?;
            assert!(
                checked_file(&parent, ".indexingsecrets", uid, gid, Visibility::Public).is_err()
            );
        }

        disk::set_permissions(&rules, disk::Permissions::from_mode(0o644))?;
        disk::hard_link(&rules, tmp.path().join("another-link"))?;
        assert!(checked_file(&parent, ".indexingsecrets", uid, gid, Visibility::Public).is_err());
        Ok(())
    }
}
