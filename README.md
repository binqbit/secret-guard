# Secret Guard

Secret Guard is a Linux command-line tool for projects that read secrets from local files such as `.env` or `.secrets/service.key`. Between work sessions, only root can open those files. Run `sudo secret-guard session` to make them readable, work with them in their usual locations, then press Enter to lock them again. You can also open a session for the lifetime of one command.

Secret Guard changes the owner and permissions of each file in place. Its contents stay on disk in plaintext throughout.

| State | Owner and group | Mode | Who can open the file |
| --- | --- | --- | --- |
| Locked | `root:root` | `0600` | Root can read and write. |
| Unlocked | Session user and their primary group | `0644` | **Every local user can read.** The session user can also edit. |

## First-time setup

### 1. Install the CLI

On Linux 5.6 or later, use a recent stable Rust toolchain with Cargo. From the repository root, build as your ordinary user and install the binary. On a **first install**, also install the three example lists.

```sh
cargo build --release --locked
sudo install -D -o root -g root -m 0755 target/release/secret-guard /usr/local/bin/secret-guard
sudo install -d -o root -g root -m 0700 /etc/secret-guard
sudo install -o root -g root -m 0600 .indexingfolders .indexingsecrets .indexingignore /etc/secret-guard/
```

For a binary update, run just the build and binary installation commands. If sudo cannot find `secret-guard`, use `/usr/local/bin/secret-guard` in its place.

### 2. Choose where to look and what to protect

Secret Guard reads three lists from **`/etc/secret-guard/`**. The files in this repository are templates. Edit the installed folder list first.

```sh
sudoedit /etc/secret-guard/.indexingfolders
```

Replace `/home/alice/work` with the absolute path of an existing project. The walkthrough below uses `/srv/work/api`. Every directory on the way to a managed file must let all users traverse it. For example, a home directory with mode `0700` blocks public access even if the file inside is `0644`. Secret Guard reports the blocking directory before unlocking. Choose a project location suitable for shared reading.

| Installed list | What to put in it | Example entries, one per line |
| --- | --- | --- |
| [.indexingfolders](.indexingfolders) | Absolute directories to scan. Each command scans all listed roots, regardless of your working directory. | `/srv/work/api`, `/srv/work/web` |
| [.indexingsecrets](.indexingsecrets) | Names or glob patterns of files to protect. A directory rule protects its contents recursively. | `.env`, `.env.*`, `.secrets/` |
| [.indexingignore](.indexingignore) | Files to skip and directories to skip entirely. An ignore rule wins over a secret rule. | `.git/`, `target/`, `node_modules/`, `.env.example`, `.env.*.example` |

Use `sudoedit` to change any of these lists. Keep them owned by `root:root` with mode `0600`. Blank lines and whole-line `#` comments are ignored. Enter paths with spaces without quotes. Supply at least one root and one secret rule. The ignore list may be empty.

Roots cannot overlap each other or the configuration and state directories. Use absolute paths without symlinks or `..`. The filesystem root (`/`) is refused. A name such as `.env` matches at any depth. A pattern such as `config/*.key` matches relative to each root. Scans skip symlinks and nested mounts. To scan a mounted project, list its mount point as a separate, non-overlapping root.

### 3. Preview the selection, then lock it

Run these commands from the ordinary account that owns the project secrets. For a project with `.env`, `.secrets/service.key`, `.env.example` and `target/.env`, the example rules select two files. **Review the paths before the first lock.** Scanning leaves permissions as they are.

```console
$ sudo secret-guard scan
"/srv/work/api/.env"
"/srv/work/api/.secrets/service.key"

$ sudo secret-guard lock
LOCKED

$ sudo secret-guard status
No open session.
locked  0:0 0600  "/srv/work/api/.env"
locked  0:0 0600  "/srv/work/api/.secrets/service.key"
```

The first status line describes the session. Each file then gets a label (`locked`, `public-read mode` or `unmanaged or changed`), followed by its owner ID, group ID and mode. A new file can be publicly readable while the first line says `No open session.`

## Everyday use

**To work interactively**, start a session in a foreground terminal.

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

If a process still has a matching file open or memory-mapped, Secret Guard locks the files it can and lists the paths still in use.

```text
Files still in use:
  "/srv/work/api/.env"
Close the listed files, then press Enter to retry.
```

Close the listed file in the process using it, or stop that process. Return to the waiting terminal and press Enter. Each retry scans again. A second `session` or `lock` cannot take over while the first is active. You can run `sudo secret-guard status` from another terminal.

| What you see | What to do |
| --- | --- |
| `OPEN / active` | Return to the session terminal, or let its work command finish. Ctrl+C requests an orderly close. |
| `OPEN / recovery required` | The supervisor has exited. Resolve the reported problem and run `sudo secret-guard lock` as the original user. Check `status` afterward. |
| Busy paths in a job without a foreground terminal | The job exits with an error and leaves the operation open. Release the files and run `sudo secret-guard lock` again. |

A crash or power loss can leave files publicly readable. Secret Guard records the session user, phase and scan scope in `/var/lib/secret-guard/session.json`, inside a root-only directory (`0700`). A successful close removes the journal. An active session uses the lists it read when it started. For recovery, use those same entries in their original order and the same root directories.

## Security model

- **Who can unlock a file.** The ordinary sudo caller is the session user. On first use, a file must belong to that user. Secret Guard records their UID in a root-protected `trusted.secret_guard` attribute so it can recognize the file after taking ownership. It refuses unrelated root-owned files, files belonging to another user, hard-linked files and matching special files. From a root shell, specify the original ordinary account, for example `secret-guard --user alice lock`. [Linux extended attributes](https://man7.org/linux/man-pages/man7/xattr.7.html)
- **What locking covers.** Secret Guard checks the file's identity beneath the configured root and takes an exclusive file lease when locking it. Someone who can write to a parent directory may still rename, replace or delete a locked file. Moving a file outside the selection takes it beyond the next scan. Files created after closure keep their creator's permissions until another lock. [Linux path resolution](https://man7.org/linux/man-pages/man2/openat2.2.html) · [Linux file leases](https://man7.org/linux/man-pages/man2/F_SETLEASE.2const.html)
- **What happens to the data.** During either kind of session, other local processes can read and copy the files. Secret Guard provides no encryption, backups or secure erasure. Anyone with privileged or offline disk access can read the contents, and snapshots, backups or copies made during a session may retain them.

The CLI needs procfs and a local filesystem with trusted extended attributes, enabled file leases, and support for syncing files and directories. The root process needs permission to change ownership, write trusted attributes (`CAP_SYS_ADMIN`) and acquire leases (`CAP_LEASE`).

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

Secret Guard's own scan uses the three installed lists. A real `.env` can therefore stay out of your workspace index and still appear in `sudo secret-guard scan`.

<details>
<summary>Upgrading from an older configuration or storage format</summary>

Finish any open session with the previously installed version. For a TOML configuration, put each former `roots` entry on its own line in `.indexingfolders`. Transfer `patterns` or the contents of `patterns_file` to `.indexingsecrets`, and the entries from `ignore_file` to `.indexingignore`. If the old `user` setting restricted callers, apply that restriction in your sudo policy. Run `scan` from the account that originally owned the files to check the migrated rules.

For a copy-based installation, recover the stored files with that version and retain its old state directory separately before installing this release. Secret Guard detects the old archive layout and stops before changing it.

</details>
