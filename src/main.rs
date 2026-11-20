#[cfg(not(target_os = "linux"))]
compile_error!("Secret Guard requires Linux.");

mod config;
mod journal;
mod output;
mod runtime;
mod session;
mod storage;
mod tree;

use std::{ffi::OsString, process::ExitCode};

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};

use session::{Mutation, Selection};

#[derive(Parser)]
#[command(
    version,
    disable_help_subcommand = true,
    styles = output::cli_styles(),
    about = "Switch selected files between owner-only and root-only access"
)]
struct Cli {
    /// Select the ordinary account when invoking directly as root.
    #[arg(long, global = true, value_name = "USER")]
    user: Option<String>,
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Display, edit or reset the installed configuration lists.
    Config {
        #[command(subcommand)]
        command: config::Action,
    },
    #[command(flatten)]
    Files(FileCommand),
}

#[derive(Subcommand)]
enum FileCommand {
    /// Show current file permissions and any open session.
    Status {
        #[command(flatten)]
        selection: Selection,
        /// List only paths matching the current configuration.
        #[arg(long)]
        paths: bool,
    },
    /// Lock matching files, or safely finish an interrupted session.
    Lock(Selection),
    /// Open matching files and leave access open until a separate lock.
    Unlock(Selection),
    /// Open the files until Enter, or run a command as the session user.
    Session {
        #[command(flatten)]
        selection: Selection,
        #[arg(last = true, value_name = "COMMAND", num_args = 0..)]
        command: Vec<OsString>,
    },
}

fn run(cli: Cli) -> Result<i32> {
    let uid = rustix::process::getuid();
    ensure!(
        uid == rustix::process::geteuid(),
        "use a regular installation of secret-guard and invoke it through sudo"
    );

    let files = match cli.action {
        Action::Config { command } => return config::run(command, cli.user.as_deref()),
        Action::Files(files) => files,
    };

    ensure!(uid.is_root(), "run Secret Guard through sudo");
    let user = runtime::resolve_user(cli.user.as_deref())?;
    let registry = journal::JournalStore::open()?;

    match files {
        FileCommand::Status { selection, paths } => {
            session::status(&registry, &user, &selection, paths)
        }
        FileCommand::Lock(selection) => session::run(&registry, &user, &selection, Mutation::Lock),
        FileCommand::Unlock(selection) => {
            session::run(&registry, &user, &selection, Mutation::Unlock)
        }
        FileCommand::Session { selection, command } => {
            session::run(&registry, &user, &selection, Mutation::Session(&command))
        }
    }
}

fn main() -> ExitCode {
    // Colorize otherwise uses stdout to decide even for stderr or /dev/tty.
    // Each output site selects a style only for its own color-capable stream.
    colored::control::set_override(true);

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            output::print_cli_message(&error);
            return ExitCode::from(error.exit_code() as u8);
        }
    };

    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            output::report_error(&err);
            ExitCode::FAILURE
        }
    }
}
