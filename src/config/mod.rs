//! Installed rule lists, their effective session scope and the `config` command.
mod commands;
mod editor;
mod files;
mod rules;

pub(crate) use commands::{Action, run};
pub(crate) use files::{initialize_if_needed, read_config};
pub(crate) use rules::Scope;

const CONFIG_DIR: &str = "/etc/secret-guard";
