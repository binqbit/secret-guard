//! Validate Linux access ACLs for public configuration and file status.

use std::collections::BTreeSet;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use rustix::fs;
use rustix::io::Errno;

use super::descriptor_path;

const ACL: &str = "system.posix_acl_access";

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

#[cfg(test)]
mod tests {
    use std::fs as disk;
    use std::os::unix::fs::PermissionsExt;

    use rustix::fs::{Mode, XattrFlags};

    use super::super::FileAccess;
    use super::*;

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
}
