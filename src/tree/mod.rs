//! Select, inspect and change access to files inside verified Linux directory trees.
mod access;
mod acl;
pub(crate) mod overlap;
mod root;
mod rules;
mod scan;

pub(crate) use access::{Change, FileAccess};
pub(crate) use acl::{acl_allows_public_read, check_directory_search};
pub(crate) use root::{Root, descriptor_path};
pub(crate) use rules::{IgnoreRule, Rule};
pub(crate) use scan::Tree;
