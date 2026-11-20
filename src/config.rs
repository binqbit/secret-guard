use std::env;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Subcommand;

use crate::journal::{ConfigFiles, RuleList};
use crate::{editor, runtime};

#[derive(Subcommand)]
pub enum Action {
    /// Show all three installed lists, including comments.
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

pub fn run(action: Action, selected_user: Option<&str>) -> Result<i32> {
    let Action::Edit { list, editor } = action else {
        show()?;
        return Ok(0);
    };
    ensure!(
        rustix::process::getuid() == rustix::process::geteuid(),
        "use a regular installation of secret-guard and invoke it through sudo"
    );
    runtime::check_interactive().context("config edit requires a foreground terminal")?;
    let preferred = editor.or_else(|| {
        ["VISUAL", "EDITOR"]
            .iter()
            .filter_map(|key| env::var(key).ok())
            .find(|value| !value.is_empty())
    });
    if !rustix::process::geteuid().is_root() {
        // Keep the caller's terminal and let sudo apply the host's normal policy.
        let mut sudo = Command::new("sudo");
        sudo.arg("--").arg(env::current_exe()?);
        if let Some(user) = selected_user {
            sudo.args(["--user", user]);
        }
        sudo.args(["config", "edit", list.name()]);
        if let Some(program) = &preferred {
            sudo.arg("--editor").arg(program);
        }
        return Err(sudo.exec()).context("start sudo for config edit");
    }
    let user = runtime::resolve_user(selected_user)?;
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
