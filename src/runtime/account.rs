//! Resolve the ordinary account and its supplementary groups.
use anyhow::{Context, Result, ensure};
use nix::unistd::{Uid, User as Account, getgrouplist};
use std::{env, ffi::CString, path::PathBuf};

#[derive(Clone)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub(super) shell: PathBuf,
    pub(super) groups: Vec<libc::gid_t>,
}

fn account_user(account: Account) -> Result<User> {
    ensure!(
        !account.uid.is_root(),
        "the session user must have a non-zero UID"
    );
    let groups = getgrouplist(&CString::new(account.name.as_bytes())?, account.gid)?
        .into_iter()
        .map(|gid| gid.as_raw())
        .collect();
    Ok(User {
        name: account.name,
        uid: account.uid.as_raw(),
        gid: account.gid.as_raw(),
        home: account.dir,
        shell: account.shell,
        groups,
    })
}

pub fn resolve_uid(uid: u32) -> Result<User> {
    account_user(
        Account::from_uid(Uid::from_raw(uid))?.context("session UID has no local account")?,
    )
}

pub fn resolve_user(selected: Option<&str>) -> Result<User> {
    let caller: Option<u32> = env::var_os("SUDO_UID")
        .map(|s| {
            s.to_str()
                .context("invalid SUDO_UID")?
                .parse()
                .context("invalid SUDO_UID")
        })
        .transpose()?;
    if let Some(name) = selected {
        let account = Account::from_name(name)?.context("selected user does not exist")?;
        ensure!(
            caller.is_none_or(|id| id == 0 || id == account.uid.as_raw()),
            "--user must match the ordinary sudo caller"
        );
        account_user(account)
    } else {
        let uid = caller.filter(|&uid| uid != 0).context(
            "invoke through sudo as an ordinary user, or specify --user USER when running directly as root"
        )?;
        resolve_uid(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_never_a_working_user() {
        assert!(resolve_uid(0).is_err());
    }
}
