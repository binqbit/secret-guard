---
name: secret-guard
description: Use when storing local credentials, wiring applications to secret files, or checking which files an agent can read or edit under Secret Guard.
---

# Local project secrets

- Store API keys, tokens, passwords and private keys under the project root’s `.secrets/`. Create credential files with mode `0600`.
- Keep `.env`, `.env.*` and environment variables public-only. With `SERVICE_TOKEN_FILE=.secrets/service-token`, have the application read the file relative to the project root.
- Add `.secrets/` to the root `.gitignore` before creating secrets. Verify with `git check-ignore -- .secrets/service-token`. Exclude it from workspace indexers too. If a credential was committed, recommend rotation.
- Use dummy values in examples and tests. Keep real values out of source code, command arguments, logs and chat.

## Working with Secret Guard

Read the installed rules in `/etc/secret-guard/` without sudo. Repository copies are templates. The path must lie under a root in `.indexingfolders` and match `.indexingsecrets` (typically `.secrets/`). Exclusions in `.indexingignore` win, including absolute file or directory paths and exact root-relative paths beginning with `./`. A search root can be shared. On first use, the file must belong to the opening user, who must be able to traverse the path. Scans skip symlinks and nested mounts. Report missing rules or uncovered paths before relying on Secret Guard.

| File | Can read | Can write |
| --- | --- | --- |
| Installed rule list (`root:root 0644`) | All local users | Root |
| Locked (`root:root 0600`) | Root | Root |
| Unlocked (opening user's UID and primary group, `0600`) | Opening user and root | Opening user and root |

Wait for `UNLOCKED` from an authorized `session` or manual `unlock`. Work as the opening user without sudo. Processes under that UID share access. Unlock preserves directory permissions, including `0700` on the opening user's home. Check `test -r "$path"` for reads or `test -w "$path"` for edits without printing the value. Release your file handles when finished. Close a manual unlock with `sudo secret-guard lock` as the opening user and confirm `LOCKED`.
