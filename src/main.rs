#[cfg(not(target_os = "linux"))]
compile_error!("Secret Guard requires Linux.");

mod config;
mod editor;
mod journal;
mod overlap;
mod runtime;
mod sessions;
mod state;
mod tree;

use std::{ffi::OsString, fs::File, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use journal::{Binding, JournalStore};
use runtime::{SessionSignals, User};
use serde::{Deserialize, Serialize};
use sessions::{Selection, Slot};
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

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Scope {
    roots: Vec<PathBuf>,
    patterns: Vec<String>,
    ignores: Vec<String>,
}

fn describe(session: Option<&Session>, idle: bool, hint: &str) {
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
            println!("{hint}");
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

struct Operation<'a> {
    registry: &'a JournalStore,
    store: &'a JournalStore,
    slot: &'a Slot,
    tree: &'a Tree,
    user: &'a User,
    scope: &'a Scope,
    hint: &'a str,
}

impl Operation<'_> {
    // Remove the reservation and release its flock as one admission decision.
    // A disjoint close never observes a live supervisor with a missing journal.
    fn finish(&self) -> Result<()> {
        let _admission = self.registry.admission()?;
        self.store.finish()?;
        self.release_empty_slot()
    }

    fn release_empty_slot(&self) -> Result<()> {
        if let Slot::Direct(id) = self.slot {
            self.registry.remove_direct(*id, self.store)?;
        }
        self.store.release()
    }

    fn close(&self, signals: &SessionSignals) -> Result<()> {
        state::close(self.tree, self.user, signals, || {
            let _admission = self.registry.admission()?;
            sessions::check_other_roots(&sessions::operations(self.registry)?, self.slot, self.tree)
        })?;
        self.finish()
    }

    fn mutate(
        &self,
        action: Action,
        session: Option<Session>,
        admission: &mut Option<File>,
    ) -> Result<i32> {
        let (store, tree, user, scope, hint) =
            (self.store, self.tree, self.user, self.scope, self.hint);
        if let Some(s) = &session {
            match &action {
                Action::Session { .. } if s.is_manual_open() => {
                    bail!("files are manually unlocked. {hint}")
                }
                Action::Session { .. } => bail!("an unfinished operation was found. {hint}"),
                Action::Unlock(_) if !s.is_manual_open() => {
                    bail!("an unfinished operation was found. {hint}")
                }
                _ => (),
            }
            s.validate(tree, user.uid, scope)?;
        }
        let signals = SessionSignals::install()?;
        if matches!(action, Action::Lock(_)) {
            if let Some(mut active) = session {
                active.begin_close(store)?;
            } else {
                Session::start(store, tree, user, scope, Phase::Closing)?;
            }
            drop(admission.take());
            self.close(&signals)?;
            AccessMessage::Locked.write(&mut std::io::stdout().lock())?;
            return Ok(0);
        }
        let command = match action {
            Action::Session { command, .. } => Some(command),
            Action::Unlock(_) => None,
            _ => unreachable!(),
        };
        let interactive = command.as_ref().is_some_and(Vec::is_empty);
        if interactive {
            runtime::check_interactive()?;
        }
        let opening = if command.is_some() {
            Phase::Opening
        } else {
            Phase::ManualOpening
        };
        let new = session.is_none();
        // Publish this scope while all admissions are serialized. The filesystem scan
        // and the user's command then run with only this slot's supervisor lock.
        let mut active = match session {
            Some(manual) => manual,
            None => Session::start(store, tree, user, scope, opening)?,
        };
        drop(admission.take());
        let files = state::preflight(tree, user).and_then(|files| {
            ensure!(
                !signals.interrupted(),
                "interrupted before opening the session"
            );
            Ok(files)
        });
        let files = match files {
            Ok(files) => files,
            Err(e) => {
                if new {
                    self.finish()
                        .with_context(|| format!("{e:#}; release unopened session"))?;
                }
                return Err(e);
            }
        };
        if !new {
            active.phase(store, opening)?;
        }
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
        active
            .begin_close(store)
            .and_then(|()| self.close(&signals))
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
}

fn show_files(tree: &Tree, user: &User, paths: bool) -> Result<i32> {
    for (path, access) in tree.scan()? {
        if paths {
            println!("{path:?}");
        } else {
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
    }
    Ok(0)
}

fn run(cli: Cli) -> Result<i32> {
    let Cli { action, user } = cli;
    let uid = rustix::process::getuid();
    ensure!(
        uid == rustix::process::geteuid(),
        "use a regular installation of secret-guard and invoke it through sudo"
    );
    let selection = match &action {
        Action::Status { selection, .. }
        | Action::Session { selection, .. }
        | Action::Lock(selection)
        | Action::Unlock(selection) => selection,
        Action::Config { .. } => {
            let Action::Config { command } = action else {
                unreachable!()
            };
            return config::run(command, user.as_deref());
        }
    };
    ensure!(uid.is_root(), "run Secret Guard through sudo");
    let mut user = runtime::resolve_user(user.as_deref())?;
    let registry = JournalStore::open()?;
    let mut admission = Some(registry.admission()?);
    let entries = sessions::operations(&registry)?;
    let (slot, supplied) = selection.resolve(&entries)?;
    let status = matches!(action, Action::Status { .. });
    let preview = matches!(action, Action::Status { paths: true, .. });
    let existing = slot.open(&registry, false)?;
    let binding = if matches!(slot, Slot::Named(_)) {
        existing
            .as_ref()
            .map(JournalStore::binding)
            .transpose()?
            .flatten()
    } else {
        None
    };
    let profile_uid = binding.as_ref().map(|b| b.uid);
    let root = match &slot {
        Slot::Named(name) => Some(sessions::named_root(
            name, binding, supplied, user.uid, !status,
        )?),
        _ => supplied,
    };
    let hint = sessions::close_hint(&slot, root.as_deref());
    let idle = existing
        .as_ref()
        .map(JournalStore::try_exclusive)
        .transpose()?
        .unwrap_or(true);
    ensure!(
        status || idle,
        "session {} is already active; inspect it with status",
        slot.label(root.as_deref())
    );
    let session: Option<Session> = existing
        .as_ref()
        .map(JournalStore::load)
        .transpose()?
        .flatten();
    if status {
        if idle && let Some(store) = &existing {
            store.release()?;
        }
        drop(admission.take());
        if !preview {
            if slot == Slot::Default {
                for e in entries.iter().filter(|e| e.slot != Slot::Default) {
                    e.slot.print_heading(e.root());
                    describe(
                        e.session.as_ref(),
                        e.idle,
                        &sessions::close_hint(&e.slot, e.root()),
                    );
                }
                if entries.iter().any(|e| e.slot != Slot::Default) {
                    println!("Default session");
                }
            } else {
                slot.print_heading(root.as_deref());
            }
            describe(session.as_ref(), idle, &hint);
        }
    }
    let saved_scope = session.as_ref().and_then(|s| {
        if preview {
            None
        } else if status || slot != Slot::Default {
            Some(s.scope())
        } else {
            s.manual_scope()
        }
    });
    let scope = if let Some(scope) = saved_scope {
        scope.clone()
    } else {
        journal::initialize_if_needed(&user.home)?;
        journal::read_config(root.as_deref())?
    };
    if status
        && let Some(owner) = session.as_ref().map(|s| s.uid).or(profile_uid)
        && owner != user.uid
    {
        user = runtime::resolve_uid(owner)?;
    }
    let tree = Tree::new(&scope.roots, &scope.patterns, &scope.ignores, user.uid)?;
    if let Slot::Direct(id) = slot {
        ensure!(
            tree.root_ids()?.as_slice() == [id],
            "restore the original directory for this session"
        );
    }
    if status {
        if !preview && let Some(s) = &session {
            s.validate(&tree, user.uid, &scope)?;
        }
        return show_files(&tree, &user, preview);
    }
    sessions::check_other_roots(&entries, &slot, &tree)?;
    let store = match existing {
        Some(store) => store,
        None => {
            let store = slot
                .open(&registry, true)?
                .context("create session state")?;
            ensure!(store.try_exclusive()?, "session is busy");
            store
        }
    };
    if matches!(slot, Slot::Named(_)) && profile_uid.is_none() {
        store.bind_if_absent(&Binding {
            uid: user.uid,
            path: root.as_ref().unwrap().clone(),
        })?;
    }
    let op = Operation {
        registry: &registry,
        store: &store,
        slot: &slot,
        tree: &tree,
        user: &user,
        scope: &scope,
        hint: &hint,
    };
    let result = op.mutate(action, session, &mut admission);
    if store.holds_lock() {
        let _guard = match admission.take() {
            Some(guard) => guard,
            None => registry.admission()?,
        };
        let remaining = store.load::<Session>();
        if matches!(remaining, Ok(None)) {
            op.release_empty_slot()?;
        } else {
            store.release()?;
        }
        drop(_guard);
        if result.is_err() {
            match remaining {
                Ok(Some(_)) => eprintln!("Operation remains OPEN. {hint}"),
                Err(_) => eprintln!("Cannot confirm a locked state. Inspect it with status."),
                Ok(None) => (),
            }
        }
    }
    result
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
