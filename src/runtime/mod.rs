//! Resolve the working user and supervise an interactive session or user command.
mod account;
mod child;
mod command;
mod probe;
mod signals;
mod terminal;

pub(crate) use account::{User, resolve_uid, resolve_user};
pub(crate) use command::COMMAND_PATH;
pub(crate) use probe::check_file_access;
pub(crate) use signals::SessionSignals;
pub(crate) use terminal::check_interactive;

use std::io;

fn checked(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
