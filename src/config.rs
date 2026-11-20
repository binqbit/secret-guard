use std::env;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;

use crate::journal::{self, ConfigFiles, RuleList};
use crate::sessions;
use crate::{editor, runtime};

#[derive(Subcommand)]
pub enum Action {
    /// Show all three lists, initializing the installed defaults on first use.
    Show,
    /// Replace all three installed lists with the packaged defaults for your account.
    Reset,
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
    for (list, contents) in files.read_all()? {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&format!("[{}]\n", list.name()));
        output.push_str(&contents);
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

fn reset(selected_user: Option<&str>) -> Result<i32> {
    if !rustix::process::geteuid().is_root() {
        return run_with_sudo(selected_user, &["reset"]);
    }
    let user = runtime::resolve_user(selected_user)?;
    let store = journal::JournalStore::open()?;
    let _admission = store.admission()?;
    if let Some(entry) = sessions::operations(&store)?.first() {
        let label = entry.slot.label(entry.root());
        ensure!(
            entry.idle,
            "session {label} is active; finish it before resetting the configuration"
        );
        let session = entry.session.as_ref().context("missing session state")?;
        let state = if session.is_manual_open() {
            "files are manually unlocked"
        } else {
            "an unfinished operation needs recovery"
        };
        let hint = sessions::close_hint(&entry.slot, entry.root());
        bail!("session {label}: {state}. {hint}");
    }
    journal::reset_config(&user.home)?;
    println!("Restored the three installed rule lists to their packaged defaults.");
    Ok(0)
}

pub fn run(action: Action, selected_user: Option<&str>) -> Result<i32> {
    let (list, editor) = match action {
        Action::Reset => return reset(selected_user),
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
