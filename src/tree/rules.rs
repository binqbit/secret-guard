//! Compile path globs and explicit file or directory exclusions.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use globset::{GlobBuilder, GlobMatcher};

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
            !glob.contains('\0')
                && !glob
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

    pub(super) fn covers_file(&self, relative: &Path) -> bool {
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
    pub(super) fn compile_list(entries: &[String]) -> Result<Vec<Self>> {
        entries.iter().map(|entry| Self::compile(entry)).collect()
    }

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

    pub(super) fn excludes(&self, absolute: &Path, relative: &Path, is_directory: bool) -> bool {
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
