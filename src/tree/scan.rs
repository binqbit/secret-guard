//! Enumerate files selected by the rules beneath pinned root directories.
use anyhow::{Context, Result, ensure};
use rustix::{
    fs::{self, OFlags},
    io::Errno,
};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use super::{FileAccess, IgnoreRule, Root, Rule, root::DIR};

const LEGACY_STAGE: &str = ".secret-guard-stage";

pub(crate) struct Tree {
    roots: Vec<Root>,
    rules: Vec<Rule>,
    ignores: Vec<IgnoreRule>,
    pub(super) uid: u32,
}

impl Tree {
    pub(super) fn roots(&self) -> &[Root] {
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

    pub(super) fn locate<'a>(&self, path: &'a Path) -> Result<(&Root, &'a Path)> {
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
        self.roots.iter().map(Root::verified_id).collect()
    }

    pub fn scan(&self) -> Result<BTreeMap<PathBuf, FileAccess>> {
        let mut result = BTreeMap::new();
        for root in &self.roots {
            root.verified_id()?;
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
                let fd = match root.open_beneath(relative, DIR) {
                    Ok(fd) => fd,
                    // A discovered directory can be removed or replaced before its turn.
                    Err(Errno::XDEV | Errno::LOOP | Errno::NOENT | Errno::NOTDIR) => continue,
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("scan directory {:?}", root.path.join(&dir)));
                    }
                };
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
                    let pinned = match root.open_beneath(&child, OFlags::PATH | OFlags::NOFOLLOW) {
                        Ok(fd) => fd,
                        Err(Errno::XDEV | Errno::LOOP | Errno::NOENT | Errno::NOTDIR) => {
                            continue;
                        }
                        Err(e) => {
                            return Err(e)
                                .with_context(|| format!("inspect {:?}", root.path.join(&child)));
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
            root.verified_id()?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::Mode;
    use std::collections::BTreeSet;
    use std::fs as disk;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;

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
        assert!(Rule::compile("secret\0key").is_err());
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
}
