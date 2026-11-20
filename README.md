# Secret Guard

Secret Guard is a Linux command-line tool that locks local project files between work sessions. Store real credentials in `.secrets/` and keep public settings in `.env`. The default rules manage both. Use `unlock` and `lock` to control access manually, or use `session` to lock the files when you press Enter or a work command exits.

Secret Guard changes the owner and permissions of matching files in place. Their contents stay on disk in plaintext throughout. Directories keep their existing permissions.

| State | Owner and group | Mode | Who can open the file |
| --- | --- | --- | --- |
| Locked | `root:root` | `0600` | Root can read and write. |
| Unlocked | Opening user and their primary group | `0600` | The opening user can read and edit without sudo. Root can also read and write. |

## First-time setup

### 1. Install the CLI

On Linux 5.6 or later, use a recent stable Rust toolchain with Cargo. Build as your ordinary user from the repository root. The binary includes the three `.indexing*` files from that build as its configuration defaults.

```sh
cargo build --release --locked
sudo install -D -o root -g root -m 0755 target/release/secret-guard /usr/local/bin/secret-guard
```

If sudo cannot find `secret-guard`, use `/usr/local/bin/secret-guard` in its place.

### 2. Initialize and review the rules

From the ordinary account that owns your secrets, display the rules. On first use, Secret Guard creates the three lists under **`/etc/secret-guard/`** from its embedded defaults. Running `config show` as an ordinary user requests sudo for this initial setup. Afterward, anyone can read the installed lists without sudo, including while secrets are locked.

```sh
secret-guard config show
```

The default search root is **the whole home directory of the ordinary user who first invokes sudo for setup**. Secret Guard replaces `/home/user` in the folder template with the home recorded for that UID in the system account database. For a user whose home is `/srv/users/alice`, the installed list contains `/srv/users/alice`. From a root shell, select the intended account explicitly with `secret-guard --user alice config show`.

The installed lists are system-wide. Normal use and binary upgrades preserve your edits. If an installed list is missing, restore it or explicitly reset all three lists to the packaged defaults. Only root can change the lists. Their paths, patterns and comments are public, so keep credential values in `.secrets/`.

For example, with `/home/alice` as the search root, the default rules manage `/home/alice/project/.secrets/service-token` and skip `/home/alice/project/notes.txt`. Alice can unlock her token beneath her private `0700` home. A root-owned shared directory such as `/srv/projects` can also be a search root. Alice can manage her own `/srv/projects/api/.env` if she can traverse every parent directory. In either location the unlocked file's `0600` mode denies access to other ordinary UIDs. To narrow the search to one project, set its absolute path with `secret-guard config edit folders`. The walkthrough below uses `/srv/work/api`.

| Installed list | What to put in it | Example entries, one per line |
| --- | --- | --- |
| [.indexingfolders](.indexingfolders) | Absolute directories to scan. File operations cover all listed roots, regardless of your working directory. | `/srv/work/api`, `/srv/work/web` |
| [.indexingsecrets](.indexingsecrets) | Names or glob patterns of files to protect. A directory rule protects its contents recursively. | `.env`, `.env.*`, `.secrets/` |
| [.indexingignore](.indexingignore) | Files to skip and directories to skip entirely. An ignore rule wins over a secret rule. | `.git/`, `target/`, `node_modules/`, `.env.example`, `.env.*.example` |

To choose your editor for one edit, pass `--editor`. For example, either command opens the selected list in the same terminal.

```sh
secret-guard config edit secrets --editor vim
secret-guard config edit ignore --editor nano
```

`config edit` requests sudo access and runs the editor as your ordinary account. With `sudo secret-guard config edit`, use `--editor` if sudo filters your editor preference. By default the CLI uses `VISUAL`, then `EDITOR`, then the first installed of Vim, Nano and vi. Specify an executable name or path. In Vim, use `:wq` to save and exit. In Nano, press Ctrl+O, Enter, then Ctrl+X. Secret Guard checks the edited list before replacing the installed file. If another edit has already changed it, reopen the list to apply your changes to the current version.

Keep the directory owned by `root:root` with mode `0755` and each list owned by `root:root` with mode `0644`. Blank lines and whole-line `#` comments are ignored. Enter paths with spaces without quotes. Supply at least one root and one secret rule. The ignore list may be empty.

Roots cannot overlap each other or the configuration and state directories. Use absolute paths without symlinks or `..`. The filesystem root (`/`) is refused. A name such as `.env` matches at any depth. A pattern such as `config/*.key` matches relative to each root. Scans skip symlinks and nested mounts. To scan a mounted project, list its mount point as a separate, non-overlapping root.

The entries below illustrate how to exclude files and directory trees in `.indexingignore`. Each relative entry is interpreted from **each selected search root**. Paths starting with `./` or `/` are literal, so characters such as `*` and `[` in those paths refer to the filename itself. An absolute exclusion never adds a directory to the search.

| Ignore entry | What Secret Guard skips |
| --- | --- |
| `build/` | Every directory named `build` and its contents. |
| `services/*/generated/` | The matching generated trees relative to each root. |
| `./fixtures/.env` | The exact `fixtures/.env` immediately beneath each root. |
| `./fixtures/sample data` | The literal file or entire directory at that relative path. |
| `/srv/work/api/.env.local` | That exact file when it falls within the selected roots. |
| `/srv/work/api/fixtures` | That directory and its contents. A trailing slash limits the exclusion to a directory. |

### 3. Preview the selection, then lock it

Run these commands from the ordinary account that owns the project secrets. `status --paths` always lists matches for the currently installed rules. Full `status` reports access and permissions. While any operation is open, it scans using the roots and rules saved when that operation began, even if the installed lists have since changed.

For a project with `.env`, `.secrets/service.key`, `.env.example` and `target/.env`, the example rules select two files. **Review the paths before the first lock.**

```console
$ sudo secret-guard status --paths
"/srv/work/api/.env"
"/srv/work/api/.secrets/service.key"

$ sudo secret-guard lock
LOCKED

$ sudo secret-guard status
No open session.
locked  0:0 0600  "/srv/work/api/.env"
locked  0:0 0600  "/srv/work/api/.secrets/service.key"
```

The first status line describes the operation. Each file line shows an access label, owner ID, group ID and mode. `locked` marks a root-protected file. `owner-only mode` identifies an eligible file owned by the working user at `0600`. A file already at `0644`, including one opened by an older release, can appear as `public-read mode`. Other mismatches appear as `unmanaged or changed`.

### Reset the configuration

Run `secret-guard config reset` to **overwrite all three installed lists** with the defaults embedded in the current binary. The command requests sudo and sets the search root to the calling user's home. From a root shell, select the ordinary account with `secret-guard --user alice config reset`.

Reset requires closed access. Finish an active session, or run `sudo secret-guard lock` to close a manual unlock or recover an interrupted session. The reset changes only the three rule lists. Existing secrets keep their contents and permissions. Save any rules you want to reuse. A locked file outside the new selection stays root-only until you include it again.

```sh
secret-guard config reset
secret-guard config show
```

If the reset is interrupted, run it again from the same account and review the resulting lists.

## Everyday use

**To unlock manually**, run `unlock`. It prints `UNLOCKED` and returns you to the shell. You can read and edit the matching files without sudo until you run `lock`, even if you close the terminal. Use the same account to close access before starting a session or resetting the configuration.

```console
$ sudo secret-guard unlock
UNLOCKED
$ sudo secret-guard lock
LOCKED
```

Closing a manual unlock uses its saved rules, even if you edited the installed lists or the operation was interrupted.

**To lock on Enter**, start a session in a foreground terminal.

```console
$ sudo secret-guard session
UNLOCKED
Press Enter to lock.
```

The green **UNLOCKED** means you can now run your application or edit the files in another terminal. When finished, return to the first terminal and press **Enter**. Secret Guard scans again, locks the matches and verifies their permissions. A red **LOCKED** confirms closure and the CLI exits. The closing scan includes new matching files and replacements made by an editor. Your edits stay in the working files. Files you deleted stay deleted.

**To run one command**, put it and its arguments after `--`. Try this from your ordinary account to see which user runs the command.

```console
$ sudo secret-guard session -- id -un
UNLOCKED
alice
LOCKED
```

Here `alice` stands for your login name. For a project with an executable test script, run `sudo secret-guard session -- ./scripts/test` from the project directory. The child runs with your ordinary privileges, working directory, and standard streams. It gets a fresh environment with your account settings, a system search path, and terminal and locale settings. Your application loads its own `.env` if it needs those variables. After the command exits, Secret Guard locks the files and returns the command's exit status if closure succeeds. Session messages go to stderr in command mode, so stdout can be piped.

## If a file is busy or the session stops

Before converting a file with broader permissions, such as an existing `0644` `.env`, to owner-only access, Secret Guard checks for open handles and memory mappings. If a process holds the file, release it, finish any pending close and then retry the opening command. When closing access, Secret Guard locks the files it can and lists the paths still in use.

```text
Files still in use:
  "/srv/work/api/.env"
Close the listed files, then press Enter to retry.
```

Close the listed file in the process using it, or stop that process. Return to the waiting terminal and press Enter. Each retry scans again. A second `session` or `lock` cannot take over while the first is active. You can run `sudo secret-guard status` from another terminal.

| What you see | What to do |
| --- | --- |
| `OPEN / manual` | The `unlock` command completed. When finished, run `sudo secret-guard lock` from the account that opened access. |
| `OPEN / active` | Return to the session terminal, or let its work command finish. Ctrl+C requests an orderly close. |
| `OPEN / recovery required` | The supervisor has exited. Resolve the reported problem and run `sudo secret-guard lock` as the original user. Check `status` afterward. |
| Busy paths in a job without a foreground terminal | The job exits with an error and leaves the operation open. Release the files and run `sudo secret-guard lock` again. |

A crash or power loss can leave files unlocked. Secret Guard records the opening user, phase and selection rules in `/var/lib/secret-guard/session.json`, inside a root-only directory (`0700`). A successful close removes the journal. To recover an interrupted `session`, run `lock` with its original root directories and list entries in their original order. Restore them first if they have changed.

## Security model

- **Who can unlock a file.** The ordinary sudo caller is the session user. On first use, a file must belong to that user. Secret Guard records their UID in a root-protected `trusted.secret_guard` attribute so it can recognize the file after taking ownership. It refuses unrelated root-owned files, files belonging to another user, hard-linked files and matching special files. From a root shell, specify the original ordinary account, for example `secret-guard --user alice lock`. [Linux extended attributes](https://man7.org/linux/man-pages/man7/xattr.7.html)
- **What locking covers.** Secret Guard checks each file's identity beneath its search root and takes an exclusive lease when locking it. Someone who can write to a parent directory may rename, replace or delete a locked file. Moving a file outside the selection takes it beyond the next scan. New and replacement files keep the permissions chosen by their creator until Secret Guard next applies a permission change. Create credential files with mode `0600` (for example, set `umask 077` before creating them). [Linux path resolution](https://man7.org/linux/man-pages/man2/openat2.2.html) · [Linux file leases](https://man7.org/linux/man-pages/man2/F_SETLEASE.2const.html)
- **What happens to the data.** The opening user owns the unlocked file and can change its permissions or share its contents. Any process running under that UID can read and copy it. Root retains access in both states. Secret Guard provides no encryption, backups or secure erasure. Offline disk access, snapshots, backups and copies made while the files are open may expose the contents.

The CLI needs procfs and a local filesystem with trusted extended attributes, enabled file leases, and support for syncing files and directories. The root process needs permission to change ownership, write trusted attributes (`CAP_SYS_ADMIN`) and acquire leases (`CAP_LEASE`).

## Install the Codex skill

The [Secret Guard skill](skills/secret-guard/SKILL.md) teaches Codex to read the installed rules, check whether a credential path is covered and wait for the access its task needs. It also explains where to store credentials and how to keep them out of Git. From this repository, install it for your ordinary account.

```sh
install -D -m 0644 skills/secret-guard/SKILL.md "${CODEX_HOME:-$HOME/.codex}/skills/secret-guard/SKILL.md"
```

Start a new Codex session. The skill is available for credential and environment configuration tasks. You can also invoke it explicitly, for example, `$secret-guard Configure the client to read its service token from a file.`

## Development and workspace indexing

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

For the privileged integration test, use a disposable Linux VM with util-linux, GNU coreutils and findutils. The test mounts temporary filesystems in a private mount namespace and exercises two ordinary UIDs.

```sh
cargo build --release --locked
sudo sh tests/session.sh ./target/release/secret-guard
```

Git-aware workspace indexers skip build output, real environment files and `.secrets/`. Source, tests, documentation, `Cargo.lock`, the three list templates and sanitized environment examples remain visible. Use only dummy values in examples. For an indexer with its own exclusions, mirror the repository's [Git ignore rules](.gitignore).

Secret Guard selects files using the three installed lists. A real `.env` can therefore stay out of your workspace index and still appear in `sudo secret-guard status --paths`.

<details>
<summary>Upgrading from an older access mode, configuration or storage format</summary>

If your previous release opened secrets at `0644`, finish any supervised session and run `sudo secret-guard lock` as the account that opened them before upgrading. Reopen with `unlock` or `session` after installing this release. The files will then belong to the opening user at `0600`.

If your installed lists use the old private permissions, finish any open session with the installed binary first. Review the lists for paths, patterns and public comments, then update their permissions in place before replacing the binary.

```sh
sudo chmod 0644 /etc/secret-guard/.indexingfolders /etc/secret-guard/.indexingsecrets /etc/secret-guard/.indexingignore
sudo chmod 0755 /etc/secret-guard
```

If the CLI reports an access ACL error after the upgrade, check the named file or directory. An ACL entry can still deny a particular user read access to a list or traversal through its parent. [Linux access control lists](https://man7.org/linux/man-pages/man5/acl.5.html)

Finish any open session with the previously installed version. For a TOML configuration, put each former `roots` entry on its own line in `.indexingfolders`. Transfer `patterns` or the contents of `patterns_file` to `.indexingsecrets`, and the entries from `ignore_file` to `.indexingignore`. If the old `user` setting restricted callers, apply that restriction in your sudo policy. Run `sudo secret-guard status --paths` from the account that originally owned the files to check the migrated selection.

For a copy-based installation, recover the stored files with that version and retain its old state directory separately before installing this release. Secret Guard detects the old archive layout and stops before changing it.

</details>
