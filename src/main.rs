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
    disable_help_subcommand = true,
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
    /// Show current file permissions and any open session.
    Status {
        /// List only paths matching the current configuration.
        #[arg(long)]
        paths: bool,
    },
    /// Lock matching files, or safely finish an interrupted session.
    Lock,
    /// Open matching files and leave access open until a separate lock.
    Unlock,
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
        if s.is_manual_open() {
            println!("OPEN / manual (user {:?}, UID {})", s.user, s.uid);
            return;
        }
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
        match &action {
            Action::Session { .. } if s.is_manual_open() => {
                bail!(
                    "files are manually unlocked; run 'sudo secret-guard lock' before starting a session"
                );
            }
            Action::Session { .. } => bail!("an unfinished operation was found. {RECOVERY}"),
            Action::Unlock if !s.is_manual_open() => {
                bail!("an unfinished operation was found. {RECOVERY}");
            }
            _ => (),
        }
        s.validate(tree, user.uid, scope)?;
    }
    let signals = SessionSignals::install()?;
    if matches!(action, Action::Lock) {
        if let Some(mut interrupted) = session {
            interrupted.begin_close(store)?;
        } else {
            Session::start(store, tree, user, scope, Phase::Closing)?;
        }
        state::close(store, tree, user, &signals)?;
        AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
        return Ok(0);
    }
    let command = match action {
        Action::Session { command } => Some(command),
        Action::Unlock => None,
        _ => unreachable!(),
    };
    let interactive = command.as_ref().is_some_and(Vec::is_empty);
    if interactive {
        runtime::check_interactive()?;
    }
    let files = state::preflight(tree, user)?;
    ensure!(
        !signals.interrupted(),
        "interrupted before opening the session"
    );
    let opening = if command.is_some() {
        Phase::Opening
    } else {
        Phase::ManualOpening
    };
    let mut active = match session {
        Some(mut manual) => {
            manual.phase(store, opening)?;
            manual
        }
        None => Session::start(store, tree, user, scope, opening)?,
    };
    let opened = state::open_files(tree, user, &files, || signals.interrupted());
    let result = if let Some(command) = &command {
        opened
            .and_then(|()| active.phase(store, Phase::Running))
            .and_then(|()| AccessMessage::Unlocked.session(interactive))
            .and_then(|()| signals.run(user, command))
    } else {
        match opened.and_then(|()| {
            ensure!(!signals.interrupted(), "manual unlock interrupted");
            active.phase(store, Phase::Manual)?;
            AccessMessage::Unlocked.write(&mut std::io::stdout().lock())
        }) {
            Ok(()) => return Ok(0),
            Err(error) => Err(error),
        }
    };
    // A partial open, failed command launch or interrupted unlock also takes this path.
    active
        .begin_close(store)
        .and_then(|()| state::close(store, tree, user, &signals))
        .with_context(|| match &result {
            Err(e) => format!("operation failed ({e:#}); closing also failed"),
            Ok(_) => "closing the session failed".to_string(),
        })?;
    if command.is_some() {
        AccessMessage::Locked.session(interactive)?;
    } else {
        AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
    }
    result
}

fn run(cli: Cli) -> Result<i32> {
    let Cli { action, user } = cli;
    let uid = rustix::process::getuid();
    ensure!(
        uid == rustix::process::geteuid(),
        "use a regular installation of secret-guard and invoke it through sudo"
    );
    if let Action::Config { command } = action {
        return config::run(command, user.as_deref());
    }
    ensure!(uid.is_root(), "run Secret Guard through sudo");
    let user = runtime::resolve_user(user.as_deref())?;
    let store = JournalStore::open()?;
    let idle = store.try_exclusive()?;
    if !idle
        && matches!(
            action,
            Action::Lock | Action::Unlock | Action::Session { .. }
        )
    {
        bail!(
            "another Secret Guard operation is active; inspect it with 'sudo secret-guard status'"
        );
    }
    let session: Option<Session> = store.load()?;
    if matches!(action, Action::Status { paths: false }) {
        describe(session.as_ref(), idle);
    } else if idle && session.as_ref().is_some_and(|s| !s.is_manual_open()) {
        eprintln!("Unfinished operation found. {RECOVERY}");
    }
    // A manual opening outlives this process. Close exactly the selection that was
    // opened, even if an administrator subsequently changes the installed lists.
    let saved_scope = match &action {
        Action::Status { paths: true } => None,
        Action::Status { paths: false } => session.as_ref().map(Session::scope),
        _ => session.as_ref().and_then(Session::manual_scope),
    };
    let scope = if let Some(scope) = saved_scope {
        scope.clone()
    } else {
        journal::initialize_if_needed(&user.home)?;
        journal::read_config()?
    };
    // A different sudo caller can inspect the recorded owner's file state.
    let user = match (&action, &session) {
        (Action::Status { paths: false }, Some(s)) if s.uid != user.uid => {
            runtime::resolve_uid(s.uid)?
        }
        _ => user,
    };
    let tree = Tree::new(&scope.roots, &scope.patterns, &scope.ignores, user.uid)?;
    match action {
        Action::Config { .. } => unreachable!(),
        Action::Status { paths: true } => {
            for path in tree.scan()?.keys() {
                println!("{path:?}");
            }
            Ok(0)
        }
        Action::Status { paths: false } => {
            if let Some(s) = &session {
                s.validate(&tree, user.uid, &scope)?;
            }
            for (path, access) in tree.scan()? {
                let label = if access.is_locked(user.uid) {
                    "locked"
                } else if access.is_open(user.uid, user.gid) {
                    "owner-only mode"
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
        Action::Lock | Action::Unlock | Action::Session { .. } => {
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
