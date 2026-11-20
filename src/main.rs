#[cfg(not(target_os = "linux"))]
compile_error!("Secret Guard requires Linux.");

mod config;
mod editor;
mod journal;
mod runtime;
mod state;
mod tree;

use std::{ffi::OsString, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use journal::JournalStore;
use runtime::{SessionSignals, User};
use serde::{Deserialize, Serialize};
use state::{Phase, Session};
use tree::Tree;

#[derive(Parser)]
#[command(
    version,
    about = "Switch local files between public-read and root-only permissions"
)]
struct Cli {
    /// Select the ordinary account for sessions and editing when invoking directly as root.
    #[arg(long, global = true, value_name = "USER")]
    user: Option<String>,
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Display or edit the installed configuration lists.
    Config {
        #[command(subcommand)]
        command: config::Action,
    },
    /// List matching working files under the configured roots.
    Scan,
    /// Show current file permissions and any open session.
    Status,
    /// Lock matching files, or safely finish an interrupted session.
    Lock,
    /// Open the files until Enter, or run a command as the session user.
    Session {
        #[arg(last = true, value_name = "COMMAND", num_args = 0..)]
        command: Vec<OsString>,
    },
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Scope {
    roots: Vec<PathBuf>,
    patterns: Vec<String>,
    ignores: Vec<String>,
}

const RECOVERY: &str = "Run 'sudo secret-guard lock' to rescan the roots and close access.";

fn describe(session: Option<&Session>, idle: bool) {
    if let Some(s) = session {
        let activity = if idle {
            "OPEN / recovery required"
        } else {
            "OPEN / active"
        };
        println!(
            "{activity} ({:?}, user {:?}, UID {}, supervisor PID {})",
            s.phase, s.user, s.uid, s.pid
        );
        if idle {
            println!("{RECOVERY}");
        }
    } else if idle {
        println!("No open session.");
    } else {
        println!("Another operation holds the lock.");
    }
}

enum AccessMessage {
    Unlocked,
    Locked,
}

impl AccessMessage {
    fn write(self, out: &mut (impl std::io::Write + std::io::IsTerminal)) -> Result<()> {
        let (label, color) = match self {
            Self::Unlocked => ("UNLOCKED", 32),
            Self::Locked => ("LOCKED", 31),
        };
        if out.is_terminal() {
            writeln!(out, "\x1b[{color}m{label}\x1b[0m")?;
        } else {
            writeln!(out, "{label}")?;
        }
        out.flush()?;
        Ok(())
    }

    fn session(self, interactive: bool) -> Result<()> {
        if interactive {
            self.write(&mut std::fs::OpenOptions::new().write(true).open("/dev/tty")?)
        } else {
            self.write(&mut std::io::stderr().lock())
        }
    }
}

fn mutate(
    action: Action,
    store: &JournalStore,
    session: Option<Session>,
    tree: &Tree,
    user: &User,
    scope: &Scope,
) -> Result<i32> {
    if let Some(s) = &session {
        s.validate(tree, user.uid, scope)?;
    }
    let signals = SessionSignals::install()?;
    if matches!(action, Action::Lock) {
        if let Some(mut interrupted) = session {
            // The original journal remains sufficient to retry if space is exhausted.
            if let Err(e) = interrupted.phase(store, Phase::Closing) {
                eprintln!("Could not update the recovery phase: {e:#}");
            }
        } else {
            Session::start(store, tree, user, scope, Phase::Closing)?;
        }
        state::close(store, tree, user, &signals)?;
        AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
        return Ok(0);
    }
    let Action::Session { command } = action else {
        unreachable!()
    };
    ensure!(
        session.is_none(),
        "an unfinished operation was found. {RECOVERY}"
    );
    let interactive = command.is_empty();
    if interactive {
        runtime::check_interactive()?;
    }
    let files = state::preflight(tree, user)?;
    ensure!(
        !signals.interrupted(),
        "interrupted before opening the session"
    );
    let mut active = Session::start(store, tree, user, scope, Phase::Opening)?;
    // Even a partial opening or a failed child launch goes through the same close path.
    let result = state::open_files(tree, user, &files, || signals.interrupted())
        .and_then(|()| active.phase(store, Phase::Running))
        .and_then(|()| AccessMessage::Unlocked.session(interactive))
        .and_then(|()| signals.run(user, &command));
    // The existing durable journal is sufficient for recovery if updating its phase fails.
    let phase_update = active.phase(store, Phase::Closing);
    state::close(store, tree, user, &signals).with_context(|| match &result {
        Err(e) => format!("session failed ({e:#}); closing also failed"),
        Ok(_) => "closing the session failed".to_string(),
    })?;
    AccessMessage::Locked.session(interactive)?;
    if let Err(error) = phase_update {
        eprintln!("Could not update the closing phase before locking: {error:#}");
    }
    result
}

fn run(cli: Cli) -> Result<i32> {
    let Cli { action, user } = cli;
    if let Action::Config { command } = action {
        return config::run(command, user.as_deref());
    }
    ensure!(
        unsafe { libc::geteuid() == 0 && libc::getuid() == 0 },
        "run Secret Guard through sudo"
    );
    let store = JournalStore::open()?;
    let idle = store.try_exclusive()?;
    if !idle && matches!(action, Action::Lock | Action::Session { .. }) {
        bail!(
            "another Secret Guard operation is active; inspect it with 'sudo secret-guard status'"
        );
    }
    let session: Option<Session> = store.load()?;
    if matches!(action, Action::Status) {
        describe(session.as_ref(), idle);
    } else if session.is_some() && idle {
        eprintln!("Unfinished operation found. {RECOVERY}");
    }
    let scope = journal::read_config()?;
    let user = runtime::resolve_user(user.as_deref())?;
    let tree = Tree::new(&scope.roots, &scope.patterns, &scope.ignores, user.uid)?;
    match action {
        Action::Config { .. } => unreachable!(),
        Action::Scan => {
            for path in tree.scan()?.keys() {
                println!("{path:?}");
            }
            Ok(0)
        }
        Action::Status => {
            for (path, access) in tree.scan()? {
                let label = if access.is_locked(user.uid) {
                    "locked"
                } else if access.is_public(user.uid, user.gid) {
                    "public-read mode"
                } else {
                    "unmanaged or changed"
                };
                println!(
                    "{label}  {}:{} {:04o}  {path:?}",
                    access.uid, access.gid, access.mode
                );
            }
            Ok(0)
        }
        Action::Lock | Action::Session { .. } => {
            let result = mutate(action, &store, session, &tree, &user, &scope);
            if result.is_err() {
                match store.load::<Session>() {
                    Ok(Some(_)) => eprintln!("Operation remains OPEN. {RECOVERY}"),
                    Err(_) => {
                        eprintln!("Cannot confirm a locked state. Run 'sudo secret-guard status'.")
                    }
                    Ok(None) => (),
                }
            }
            result
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("secret-guard: {err:#}");
            ExitCode::FAILURE
        }
    }
}
