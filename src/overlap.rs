//! A bind mount gives a directory a second pathname. Compare roots both in the
//! mount namespace and at their locations inside the underlying filesystem.
use std::ffi::OsString;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::state::Session;
use crate::tree::{Root, Tree, check_root, descriptor_path};

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
}

fn nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

pub fn check_disjoint(tree: &Tree, other: &Session) -> Result<()> {
    let saved = Root::open_list(&other.scope().roots)
        .context("reopen the other session's original roots")?;
    ensure!(
        saved.len() == other.root_ids().len(),
        "invalid saved session root count"
    );
    let candidate_ids = tree.root_ids()?;
    let table = fs::read(MOUNTINFO).context("read mount table for session overlap check")?;
    let candidates = tree
        .roots()
        .iter()
        .map(|root| Location::pinned(root, &table))
        .collect::<Result<Vec<_>>>()?;
    for (peer, &id) in saved.iter().zip(other.root_ids()) {
        let metadata = peer.fd.metadata()?;
        ensure!(
            (metadata.dev(), metadata.ino()) == id,
            "restore the other session's original root directory: {:?}",
            peer.path
        );
        let location = Location::pinned(peer, &table)?;
        for ((root, candidate_id), candidate) in
            tree.roots().iter().zip(&candidate_ids).zip(&candidates)
        {
            ensure!(
                !nested(&peer.path, &root.path)
                    && id != *candidate_id
                    && !location.overlaps(candidate),
                "session roots overlap: {:?} and {:?}",
                root.path,
                peer.path
            );
        }
    }
    for root in saved.iter().chain(tree.roots()) {
        check_root(root)?;
    }
    ensure!(
        fs::read(MOUNTINFO)? == table,
        "mounts changed during session overlap check; retry the command"
    );
    Ok(())
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
        let operation: Session = serde_json::from_value(serde_json::json!({
            "version": 3, "phase": "manual", "uid": 1000, "user": "editor", "pid": 1,
            "scope": { "roots": [&project], "patterns": [".env"], "ignores": [] },
            "roots": enrolled.root_ids()?,
        }))?;
        check_disjoint(&tree(&sibling)?, &operation)?;
        assert!(check_disjoint(&tree(&project.join("sub"))?, &operation).is_err());
        assert!(check_disjoint(&tree(temp.path())?, &operation).is_err());
        fs::rename(&project, temp.path().join("moved"))?;
        fs::create_dir(&project)?;
        assert!(check_disjoint(&tree(&sibling)?, &operation).is_err());
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
