//! A bind mount gives a directory a second pathname. Compare roots both in the
//! mount namespace and at their locations inside the underlying filesystem.
use std::ffi::OsString;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::{Root, Tree, descriptor_path, root::RESERVED_ROOTS};

const MOUNTINFO: &str = "/proc/self/mountinfo";

fn decode_path(field: &[u8]) -> Result<PathBuf> {
    let mut parts = field.split(|&b| b == b'\\');
    let mut path = parts.next().unwrap_or_default().to_vec();
    for part in parts {
        let (octal, rest) = part
            .split_at_checked(3)
            .context("truncated mount path escape")?;
        ensure!(
            matches!(octal, [b'0'..=b'3', b'0'..=b'7', b'0'..=b'7']),
            "invalid mount path escape"
        );
        path.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
        path.extend_from_slice(rest);
    }
    ensure!(!path.contains(&0), "invalid NUL in mount path");
    let path = PathBuf::from(OsString::from_vec(path));
    ensure!(
        path.is_absolute() && !path.components().any(|c| c == Component::ParentDir),
        "invalid mount path {path:?}"
    );
    Ok(path)
}

struct Location {
    filesystem: u64,
    within_filesystem: PathBuf,
}

impl Location {
    fn from_mount_info(table: &[u8], mount_id: u64, visible_path: &Path) -> Result<Self> {
        let prefix = format!("{mount_id} ");
        let line = table
            .split(|&b| b == b'\n')
            .find_map(|line| line.strip_prefix(prefix.as_bytes()))
            .context("mount of pinned search root is missing from this mount namespace")?;
        // Fields after the ID: parent ID, major:minor, root on filesystem, mount point.
        let mut fields = line.split(|&b| b == b' ').skip(1);
        let device = std::str::from_utf8(fields.next().context("missing mount device")?)?;
        let (major, minor) = device.split_once(':').context("invalid mount device")?;
        let root = decode_path(fields.next().context("missing filesystem root")?)?;
        let mount_point = decode_path(fields.next().context("missing mount point")?)?;
        let relative = visible_path.strip_prefix(&mount_point).with_context(|| {
            format!("pinned path {visible_path:?} is outside mount point {mount_point:?}")
        })?;
        Ok(Self {
            filesystem: rustix::fs::makedev(major.parse()?, minor.parse()?),
            within_filesystem: root.join(relative),
        })
    }

    fn pinned(root: &Root, table: &[u8]) -> Result<Self> {
        let visible_path = fs::read_link(descriptor_path(&root.fd))?;
        ensure!(
            visible_path == root.path,
            "search root moved: {:?}",
            root.path
        );
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", root.fd.as_raw_fd()))?;
        let mount_id = info
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:"))
            .context("missing mount ID for pinned search root")?
            .trim()
            .parse()?;
        Self::from_mount_info(table, mount_id, &visible_path)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.filesystem == other.filesystem
            && nested(&self.within_filesystem, &other.within_filesystem)
    }

    fn reserved(path: &Path, table: &[u8]) -> Result<Self> {
        // Config editing can precede state initialization. Locate the eventual
        // directory inside its parent's filesystem without creating it.
        match Root::open(path) {
            Ok(root) => Self::pinned(&root, table),
            Err(rustix::io::Errno::NOENT) => {
                let parent = path.parent().context("missing filesystem root")?;
                let mut location = Self::reserved(parent, table)?;
                location
                    .within_filesystem
                    .push(path.file_name().context("missing directory name")?);
                Ok(location)
            }
            Err(error) => Err(error).with_context(|| format!("open reserved directory {path:?}")),
        }
    }
}

fn nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

struct LocatedRoot<'a> {
    root: &'a Root,
    id: (u64, u64),
    location: Location,
}

impl<'a> LocatedRoot<'a> {
    fn new(root: &'a Root, table: &[u8]) -> Result<Self> {
        Ok(Self {
            root,
            id: root.verified_id()?,
            location: Location::pinned(root, table)?,
        })
    }

    fn overlaps(&self, other: &Self) -> bool {
        nested(&self.root.path, &other.root.path)
            || self.id == other.id
            || self.location.overlaps(&other.location)
    }
}

fn locate<'a>(roots: &'a [Root], table: &[u8]) -> Result<Vec<LocatedRoot<'a>>> {
    roots
        .iter()
        .map(|root| LocatedRoot::new(root, table))
        .collect()
}

fn read_mounts() -> Result<Vec<u8>> {
    fs::read(MOUNTINFO).context("read mount table for root overlap check")
}

fn verify_mounts(table: &[u8]) -> Result<()> {
    ensure!(
        read_mounts()? == table,
        "mounts changed during root overlap check; retry the command"
    );
    Ok(())
}

fn validate_roots(roots: &[Root], require_disjoint: bool) -> Result<()> {
    let table = read_mounts()?;
    let candidates = locate(roots, &table)?;
    for reserved in RESERVED_ROOTS.map(Path::new) {
        let area = Location::reserved(reserved, &table)?;
        for candidate in &candidates {
            ensure!(
                !candidate.location.overlaps(&area),
                "root {:?} overlaps Secret Guard configuration or state: {reserved:?}",
                candidate.root.path
            );
        }
    }
    if require_disjoint {
        for (i, candidate) in candidates.iter().enumerate() {
            for peer in &candidates[..i] {
                ensure!(
                    !candidate.overlaps(peer),
                    "overlapping roots: {:?} and {:?}",
                    candidate.root.path,
                    peer.root.path
                );
            }
        }
    }
    for root in roots {
        root.verified_id()?;
    }
    verify_mounts(&table)
}

pub(crate) fn check_configured_roots(roots: &[Root]) -> Result<()> {
    validate_roots(roots, true)
}

pub(crate) fn check_selection(tree: &Tree) -> Result<()> {
    check_configured_roots(tree.roots())
}

pub(crate) fn check_protected_roots(tree: &Tree) -> Result<()> {
    // An older journal can contain aliases of its own roots. Let it recover
    // its files while enforcing the config/state boundary on every saved root.
    validate_roots(tree.roots(), false)
}

pub(crate) fn overlapping_roots(
    tree: &Tree,
    paths: &[PathBuf],
    ids: &[(u64, u64)],
) -> Result<Option<(PathBuf, PathBuf)>> {
    let saved = Root::open_list(paths).context("reopen the other session's original roots")?;
    ensure!(saved.len() == ids.len(), "invalid saved session root count");
    let table = read_mounts()?;
    let candidates = locate(tree.roots(), &table)?;
    let mut overlap = None;
    for (peer, &id) in saved.iter().zip(ids) {
        let located = LocatedRoot::new(peer, &table)?;
        ensure!(
            located.id == id,
            "restore the other session's original root directory: {:?}",
            peer.path
        );
        for candidate in &candidates {
            if candidate.overlaps(&located) {
                overlap.get_or_insert_with(|| (candidate.root.path.clone(), peer.path.clone()));
            }
        }
    }
    for root in saved.iter().chain(tree.roots()) {
        root.verified_id()?;
    }
    verify_mounts(&table)?;
    Ok(overlap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disjoint_check_verifies_current_and_saved_root_identities() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let project = temp.path().join("api");
        let sibling = temp.path().join("api-tools");
        fs::create_dir_all(project.join("sub"))?;
        fs::create_dir(&sibling)?;
        let tree = |path: &Path| Tree::new(&[path.into()], &[".env".into()], &[], 1000);
        let enrolled = tree(&project)?;
        let paths = std::slice::from_ref(&project);
        let ids = enrolled.root_ids()?;
        assert!(overlapping_roots(&tree(&sibling)?, paths, &ids)?.is_none());
        assert!(overlapping_roots(&tree(&project.join("sub"))?, paths, &ids)?.is_some());
        assert!(overlapping_roots(&tree(temp.path())?, paths, &ids)?.is_some());
        fs::rename(&project, temp.path().join("moved"))?;
        fs::create_dir(&project)?;
        assert!(overlapping_roots(&tree(&sibling)?, paths, &ids).is_err());
        Ok(())
    }

    #[test]
    fn bind_aliases_compare_filesystem_paths_by_component() -> Result<()> {
        let table = b"23 1 8:5 / / rw - ext4 /dev/sda rw\n57 23 8:5 /work/a\\040b/project /mnt/view rw - ext4 /dev/sda rw\n61 23 8:6 / /different rw - ext4 /dev/sdb rw\n";
        let parent = Location::from_mount_info(table, 23, Path::new("/work/a b"))?;
        let alias_child = Location::from_mount_info(table, 57, Path::new("/mnt/view/sub"))?;
        assert!(parent.overlaps(&alias_child));
        let sibling = Location::from_mount_info(table, 23, Path::new("/work/a bc"))?;
        assert!(!sibling.overlaps(&alias_child));
        let separate = Location::from_mount_info(table, 61, Path::new("/different/work/a b"))?;
        assert!(!parent.overlaps(&separate));
        assert!(Location::from_mount_info(table, 57, Path::new("/mnt/elsewhere")).is_err());
        Ok(())
    }

    #[test]
    fn reserved_location_exists_before_state_initialization() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("missing-parent/state");
        let table = read_mounts()?;
        let expected = Location::reserved(&path, &table)?;
        assert!(!path.exists());
        fs::create_dir_all(&path)?;
        let actual = Location::pinned(&Root::open(&path)?, &table)?;
        assert_eq!(actual.filesystem, expected.filesystem);
        assert_eq!(actual.within_filesystem, expected.within_filesystem);
        Ok(())
    }

    #[test]
    fn mount_path_decoding_preserves_arbitrary_filename_bytes() -> Result<()> {
        assert_eq!(
            decode_path(b"/a\\134b\\011c\\012\xff")?,
            PathBuf::from(OsString::from_vec(b"/a\\b\tc\n\xff".to_vec()))
        );
        for invalid in [
            b"/bad\\99".as_slice(),
            b"/bad\\400",
            b"/bad\\000",
            b"/bad/../name",
        ] {
            assert!(decode_path(invalid).is_err());
        }
        Ok(())
    }
}
