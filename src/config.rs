use std::io::{self, Write};

use anyhow::Result;
use clap::Subcommand;

use crate::journal::{ConfigFiles, RuleList};

#[derive(Subcommand)]
pub enum Action {
    /// Show all three installed lists, including comments.
    Show,
}

pub fn show() -> Result<()> {
    let files = ConfigFiles::open()?;
    let mut output = String::new();
    for list in RuleList::ALL {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&format!("[{}]\n", list.name()));
        output.push_str(&files.read(list)?);
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }
    io::stdout().lock().write_all(output.as_bytes())?;
    Ok(())
}
