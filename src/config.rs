use std::env;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result};
use clap::Subcommand;

use crate::journal::{self, ConfigFiles, RuleList};
use crate::{editor, runtime};

#[derive(Subcommand)]
pub enum Action {
    /// Show all three lists, initializing the installed defaults on first use.
    Show,
    /// Open one installed list in a terminal editor.
    Edit {
        #[arg(value_enum)]
        list: RuleList,
        /// Editor executable (for example, vim or nano). Defaults to VISUAL or EDITOR.
        #[arg(long, value_name = "PROGRAM", value_parser = clap::builder::NonEmptyStringValueParser::new())]
        editor: Option<String>,
    },
}

fn show() -> Result<()> {
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

fn run_with_sudo(selected_user: Option<&str>, args: &[&str]) -> Result<i32> {
    // Keep the caller's terminal and let sudo apply the host's normal policy.
    let mut sudo = Command::new("sudo");
    sudo.arg("--").arg(env::current_exe()?);
    if let Some(user) = selected_user {
        sudo.args(["--user", user]);
    }
    Err(sudo.arg("config").args(args).exec()).context("start sudo for Secret Guard configuration")
}

pub fn run(action: Action, selected_user: Option<&str>) -> Result<i32> {
    let (list, editor) = match action {
        Action::Show => {
            if journal::is_uninitialized()? {
                if !rustix::process::geteuid().is_root() {
                    return run_with_sudo(selected_user, &["show"]);
                }
                let user = runtime::resolve_user(selected_user)?;
                journal::initialize_if_needed(&user.home)?;
            }
            show()?;
            return Ok(0);
        }
        Action::Edit { list, editor } => (list, editor),
    };
    runtime::check_interactive().context("config edit requires a foreground terminal")?;
    let preferred = editor.or_else(|| {
        ["VISUAL", "EDITOR"]
            .iter()
            .filter_map(|key| env::var(key).ok())
            .find(|value| !value.is_empty())
    });
    if !rustix::process::geteuid().is_root() {
        let mut args = vec!["edit", list.name()];
        if let Some(program) = preferred.as_deref() {
            args.extend(["--editor", program]);
        }
        return run_with_sudo(selected_user, &args);
    }
    let user = runtime::resolve_user(selected_user)?;
    journal::initialize_if_needed(&user.home)?;
    let original = ConfigFiles::open()?.read(list)?;
    if let Some(edited) =
        editor::edit_text(&user, list.filename(), &original, preferred.as_deref())?
    {
        ConfigFiles::open()?.replace(list, &original, &edited)?;
        println!("Saved {}.", list.filename());
    } else {
        println!("No changes to {}.", list.filename());
    }
    Ok(0)
}
