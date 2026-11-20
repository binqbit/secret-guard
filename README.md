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
| [.indexingfolders](.indexingfolders) | Absolute directories for the default session. A named or directory session selects one directory of its own. | `/srv/work/api`, `/srv/work/web` |
| [.indexingsecrets](.indexingsecrets) | Names or glob patterns of files to protect. A directory rule protects its contents recursively. | `.env`, `.env.*`, `.secrets/` |
| [.indexingignore](.indexingignore) | Files to skip and directories to skip entirely. Within a scanned root, exclusions take precedence over secret rules. | `.git/`, `target/`, `node_modules/`, `.env.example`, `.env.*.example` |

To choose your editor for one edit, pass `--editor`. For example, either command opens the selected list in the same terminal.

```sh
secret-guard config edit secrets --editor vim
secret-guard config edit ignore --editor nano
```

`config edit` requests sudo access and runs the editor as your ordinary account. With `sudo secret-guard config edit`, use `--editor` if sudo filters your editor preference. By default the CLI uses `VISUAL`, then `EDITOR`, then the first installed of Vim, Nano and vi. Specify an executable name or path. In Vim, use `:wq` to save and exit. In Nano, press Ctrl+O, Enter, then Ctrl+X. Secret Guard checks the edited list before replacing the installed file. If another edit has already changed it, reopen the list to apply your changes to the current version.

Keep the directory owned by `root:root` with mode `0755` and each list owned by `root:root` with mode `0644`. Blank lines and whole-line `#` comments are ignored. Enter paths with spaces without quotes. Supply at least one root and one secret rule. The ignore list may be empty.

Roots listed together in `.indexingfolders` must be disjoint. Every root must also be disjoint from the configuration and state directories, including through bind mounts. Use absolute paths without symlinks or `..`. The filesystem root (`/`) is refused. A name such as `.env` matches at any depth. A pattern such as `config/*.key` matches relative to each root. Scans skip symlinks and nested mounts. To scan a mounted project, list its mount point as a separate, non-overlapping root.

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

Run these commands from the ordinary account that owns the project secrets. `status --paths` previews the currently installed rules. Full `status` reports the selected operation and the actual file permissions, including files covered by its saved manual unlock rules. With no selector it also summarizes active and interrupted operations for other names and directories.

For a project with `.env`, `.secrets/service.key`, `.env.example` and `target/.env`, the example rules select two files. **Review the paths before the first lock.**

```console
$ sudo secret-guard status --paths
"/srv/work/api/.env"
"/srv/work/api/.secrets/service.key"

$ sudo secret-guard lock
LOCKED

$ sudo secret-guard status | cat
No open session.
locked  0:0 0600  "/srv/work/api/.env"
locked  0:0 0600  "/srv/work/api/.secrets/service.key"
```

The piped example shows the plain status format. Each file line shows an access label, owner ID, group ID and mode. `locked` marks a root-protected file. `owner-only mode` identifies an eligible file owned by the working user at `0600`. A file already at `0644`, including one opened by an older release, can appear as `public-read mode`. Other mismatches appear as `unmanaged or changed`.

Run `sudo secret-guard status` directly to see the session name and a table of file permissions. Cyan headings group the output. Green marks open access, red marks locked files, and yellow draws attention to states such as required recovery. Every state has a text label. Set `NO_COLOR=1` or `TERM=dumb` to disable colors, for example `sudo NO_COLOR=1 secret-guard status`. Pipes and redirected streams use plain text. For a script that needs only paths, use `sudo secret-guard status --paths`.

### Reset the configuration

Run `secret-guard config reset` to **overwrite all three installed lists** with the defaults embedded in the current binary. The command requests sudo and sets the search root to the calling user's home. From a root shell, select the ordinary account with `secret-guard --user alice config reset`.

Finish active operations and recover interrupted ones before resetting. A completed manual `unlock` allows a reset. Its saved rules let you close access afterward with the same selector, even if the new configuration selects different files. Save any custom rules you want to reuse. Resetting changes the installed lists and preserves file permissions and saved name bindings.

```sh
secret-guard config reset
secret-guard config show
```

If the reset is interrupted, run it again from the same account and review the resulting lists.

## Everyday use

**To unlock manually**, run `unlock`. It gives your account access to the matching files, prints `UNLOCKED` and exits. The files stay accessible after you close the terminal. A successful manual unlock releases the session slot. Full `status` then reports `No open session.` and shows the file permissions.

```console
$ sudo secret-guard unlock
UNLOCKED
$ sudo secret-guard lock
LOCKED
```

Use the same account and selector for a repeat `unlock` or a later `lock`. A repeat unlock uses the saved rules. Lock rescans every outstanding selection for that selector and includes new files that match those rules. A fresh `session` uses the current configuration and locks its own selection on exit, including files previously unlocked manually that match it.

**To lock on Enter**, start a session in a foreground terminal.

```console
$ sudo secret-guard session
Default session
  "/srv/work/api"
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

### Named and directory sessions

`session`, `unlock`, `lock` and `status` accept the same optional selector. Omitting it operates on the default roots in `.indexingfolders`. A name or a directory selects one project and applies the installed `.indexingsecrets` and `.indexingignore` to it. The project may lie outside the default roots.

An explicitly selected directory takes precedence over an exclusion of that directory or one of its parents. For example, if `.indexingignore` lists both `/srv/work/` and `/srv/work/api/fixtures/`, a default scan skips `/srv/work/`. Running `sudo secret-guard session /srv/work/api` selects matching secrets in `api` and still skips `api/fixtures/`. A saved session name for `/srv/work/api` uses the same selection. Preview it with `sudo secret-guard status /srv/work/api --paths`.

This also applies when a directory name repeats. With `target/` in the ignore list, `session /srv/work/target` can select `/srv/work/target/src/.env`. It still skips `/srv/work/target/target/.env` because the inner `target/` matches the rule.

To save a name, give the directory on the first `session`, `unlock` or `lock`. The example below previews the selection, opens an interactive session, then reuses the name for manual access after that session closes.

```sh
sudo secret-guard status api --path /srv/work/api --paths
sudo secret-guard session api --path /srv/work/api
sudo secret-guard unlock api
sudo secret-guard status api
sudo secret-guard lock api
```

The preview does not register the name. Once registered, a name identifies the same directory and opening UID system-wide, including after closure. Use 1–64 ASCII letters, digits, underscores or hyphens. The name `default` is reserved. To run a work command, use `sudo secret-guard session api -- id -un`. The command inherits your current working directory.

For a one-off session, supply the path directly, for example `sudo secret-guard session /srv/work/web`. From `/srv/work`, `sudo secret-guard session ./web` selects the same directory. A bare word such as `web` selects a saved name. You can also supply `--path DIR` without a name. After a manual `unlock ./web`, close it with `sudo secret-guard lock ./web` from the same working directory, or pass its absolute path.

Active and interrupted operations reserve their selector and the directories they scan. Two operations can run together if their roots are disjoint or the parent scan skips the entire nested project. For example, with `/srv/work` as the default root and `./api/` in its ignore list, `session` and `session /srv/work/api` can run concurrently. Closing the default session skips `api`, including new files there. Ignoring only `./api/fixtures/` still leaves an overlap. The check uses the rules each operation opened with and detects bind aliases. Two active operations cannot select the same physical directory.

After `unlock /srv/work/api` completes, you can start a default session using the current default rules. If they exclude `api`, the project files remain accessible after the default session exits. Use `lock /srv/work/api` to close manual access to that project.

### When an earlier session blocks a new one

If your earlier process stopped before it finished, choose the command that gives you the access you need.

| Command in a foreground terminal | What confirming the reset does |
| --- | --- |
| `sudo secret-guard unlock /srv/work/api` | Reopens an interrupted operation under this exact selector and your UID using its saved rules. Files already unlocked stay accessible during the reset. On success the interrupted session is gone. |
| `sudo secret-guard session /srv/work/api` | Closes your indicated interrupted operation, verifies its files are locked and retries the requested session. This also works for an interrupted operation whose scan overlaps the requested project. |

Read the displayed selector and roots before typing `y` or `yes`. Press Enter at `[y/N]` to cancel and preserve the earlier state. To close an interrupted operation directly, use `lock` with its original name or directory. An `unlock` blocked by an interrupted operation under a different selector requires that targeted recovery first. A running session must finish in its own terminal. Another UID's interrupted operation must be recovered by its original user. Command sessions and processes without a foreground terminal report conflicts without prompting.

## If a file is busy or the session stops

Before converting a file with broader permissions, such as an existing `0644` `.env`, to owner-only access, Secret Guard checks for open handles and memory mappings. If a process holds the file, release it, finish any pending close and then retry the opening command. When closing access, Secret Guard locks the files it can and lists the paths still in use.

```text
Files still in use:
  "/srv/work/api/.env"
Close the listed files, then press Enter to retry.
```

Close the listed file in the process using it, or stop that process. Return to the waiting terminal and press Enter. Each retry scans that session's roots again. A second operation cannot take over those roots while the first is active. You can run `sudo secret-guard status` from another terminal and inspect a specific project with its name or path.

| What you see | What to do |
| --- | --- |
| `No open session.` and `owner-only mode` | The account can access the indicated file. After a manual unlock, run `lock` with that selector when you finish. |
| `OPEN / active` | Return to the session terminal, or let its work command finish. Ctrl+C requests an orderly close. |
| `OPEN / recovery required` | Resolve the reported problem. Run `lock` as the original user to close access, or use interactive `unlock` with the same selector to restore manual access. Check `status` afterward. |
| Busy paths in a job without a foreground terminal | The job exits with an error and leaves the operation open. Release the files and retry `lock` with the same selector. |

A crash or power loss can leave files unlocked. Secret Guard stores the user, operation phase, directory identities and selection rules under `/var/lib/secret-guard/`. An interrupted operation retains a recovery journal. A completed manual unlock keeps its rules separately for later locking. If a saved root has moved or been replaced, restore the original directory before recovery.

If a manual unlock fails partway through a scope that already contained user-owned files, Secret Guard preserves existing access and reports the operation as open. Inspect the paths with `status`, then use the same selector with `unlock` to resume or `lock` to close access.

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

| Rust module | Where to make a change |
| --- | --- |
| [config](src/config/mod.rs) | Installed rule lists, packaged defaults and the `config` commands. |
| [session](src/session/mod.rs) | Session selection, conflict handling, status and the open/close lifecycle. |
| [journal](src/journal/mod.rs) | Session records, atomic writes, directory locks and saved name bindings. |
| [tree](src/tree/mod.rs) | Search roots, rule matching, mount boundaries, ACLs and file permissions. |
| [runtime](src/runtime/mod.rs) | User lookup, privilege changes, command execution, signals and terminal interaction. |

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

For the privileged integration test, use a disposable Linux VM with util-linux, GNU coreutils and findutils. The test mounts temporary filesystems in a private mount namespace and exercises two ordinary UIDs. Install `setfacl` to include ACL scenarios and `strace` to test recovery from file and directory sync errors.

```sh
cargo build --release --locked
sudo sh tests/session.sh ./target/release/secret-guard
```

Git-aware workspace indexers skip build output, real environment files and `.secrets/`. Source, tests, documentation, `Cargo.lock`, the three list templates and sanitized environment examples remain visible. Use only dummy values in examples. For an indexer with its own exclusions, mirror the repository's [Git ignore rules](.gitignore).

Secret Guard selects files using the three installed lists. A real `.env` can therefore stay out of your workspace index and still appear in `sudo secret-guard status --paths`.

<details>
<summary>Upgrading from an older access mode, configuration or storage format</summary>

Finish running operations before replacing the binary. Use one installed version for all concurrent file operations. This release recognizes a completed manual unlock recorded in the older version 3 journal format. Its saved selection remains available to `lock`, and fresh sessions can start without resetting it. An interrupted opening or closing still requires recovery. If you are upgrading from a release that predates per-project journals, close its sessions with the original binary first.

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
