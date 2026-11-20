//! Names, syntax and packaged contents of the three rule lists.
use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::CONFIG_DIR;
use crate::tree::{IgnoreRule, Root, Rule};

/// The effective selection recorded verbatim in a session journal.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Scope {
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) patterns: Vec<String>,
    pub(crate) ignores: Vec<String>,
}

impl Scope {
    pub(super) fn from_lists(root: Option<&Path>, lists: Vec<(RuleList, String)>) -> Result<Self> {
        let mut scope = Self {
            roots: root.into_iter().map(Path::to_path_buf).collect(),
            patterns: Vec::new(),
            ignores: Vec::new(),
        };
        for (list, raw) in lists {
            let entries = list.entries(&raw)?;
            match list {
                RuleList::Folders => scope.roots = entries.into_iter().map(Into::into).collect(),
                RuleList::Secrets => scope.patterns = entries,
                RuleList::Ignore => {
                    if let Some(root) = root {
                        // Save the effective rules so closing this session reuses the
                        // selection it opened, even after an upgrade or configuration edit.
                        for entry in entries {
                            if !IgnoreRule::compile(&entry)?.excludes_root(root) {
                                scope.ignores.push(entry);
                            }
                        }
                    } else {
                        scope.ignores = entries;
                    }
                }
            }
        }
        Ok(scope)
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum RuleList {
    Folders,
    Secrets,
    Ignore,
}

impl RuleList {
    pub(super) const ALL: [Self; 3] = [Self::Folders, Self::Secrets, Self::Ignore];

    pub(super) fn filename(self) -> &'static str {
        match self {
            Self::Folders => ".indexingfolders",
            Self::Secrets => ".indexingsecrets",
            Self::Ignore => ".indexingignore",
        }
    }

    pub(super) fn name(self) -> &'static str {
        self.filename().trim_start_matches(".indexing")
    }

    pub(super) fn defaults(self, home: &Path) -> Result<Cow<'static, str>> {
        match self {
            Self::Folders => {
                Ok(render_folders(include_str!("../../.indexingfolders"), home)?.into())
            }
            Self::Secrets => Ok(include_str!("../../.indexingsecrets").into()),
            Self::Ignore => Ok(include_str!("../../.indexingignore").into()),
        }
    }

    pub(super) fn entries(self, contents: &str) -> Result<Vec<String>> {
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

    pub(super) fn validate_edit(self, edited: &str) -> Result<()> {
        let entries = self.entries(edited)?;
        match self {
            Self::Folders => {
                let paths: Vec<_> = entries.into_iter().map(Into::into).collect();
                crate::tree::overlap::check_configured_roots(&Root::open_list(&paths)?)?;
            }
            Self::Secrets => {
                for pattern in entries {
                    Rule::compile(&pattern)?;
                }
            }
            Self::Ignore => {
                for pattern in entries {
                    IgnoreRule::compile(&pattern)?;
                }
            }
        }
        Ok(())
    }
}

fn render_folders(template: &str, home: &Path) -> Result<String> {
    let mut output = String::with_capacity(template.len());
    for line in template.split_inclusive('\n') {
        let entry = line.trim();
        if entry == "/home/user" || entry.starts_with("/home/user/") {
            let text = home
                .to_str()
                .context("account home cannot be represented in a UTF-8 rule list")?
                .trim_end_matches('/');
            ensure!(
                home.is_absolute()
                    && home.parent().is_some()
                    && !home.components().any(|part| part == Component::ParentDir)
                    && text.trim() == text
                    && !text.contains(['\r', '\n', '\0']),
                "account home {home:?} cannot be used as a search root"
            );
            output.push_str(&line.replacen("/home/user", text, 1));
        } else {
            output.push_str(line);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_home_placeholders_as_complete_path_components() -> Result<()> {
        let template = "# /home/user\n  /home/user/projects  \r\n/home/users\n/home/user";
        let expected = "# /home/user\n  /srv/Local User/projects  \r\n/home/users\n/srv/Local User";
        assert_eq!(
            render_folders(template, Path::new("/srv/Local User/"))?,
            expected
        );
        for invalid in [
            "/",
            "relative",
            " ",
            "/srv/../..",
            "/srv/name\n/extra",
            "/srv/end ",
            "/srv/end /",
        ] {
            assert!(render_folders(template, Path::new(invalid)).is_err());
        }
        Ok(())
    }
}
