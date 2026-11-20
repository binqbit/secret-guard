---
name: secret-guard
description: Use when choosing a protected credential path or wiring an application to a local secret file.
---

# Use project credentials

Read the installed lists in `/etc/secret-guard/` without sudo. Repository copies are templates. Skip blank lines and `#` comment lines.

| List | How to interpret it |
| --- | --- |
| `.indexingfolders` | Default session roots. For a named or path session, use its selected directory. |
| `.indexingsecrets` | `.env.*` matches names at any depth. `config/*.key` matches relative to each root. `.secrets/` covers its contents recursively. |
| `.indexingignore` | An explicit session root wins over an exclusion covering that root or its parent. Within the selected root, exclusions win over secret patterns. The same glob rules apply. Entries starting with `./` or `/` are literal paths. For example, `./fixtures/` skips that tree under each root and `/srv/api/fixtures/` skips that absolute tree. |

If the lists changed during an open session, check that session’s `status` for its active selection.

1. Store real keys, tokens and passwords in a covered regular file under the project's `.secrets/`, owned by the project user with mode `0600`. Avoid symlinks and nested mounts. If no path qualifies, ask for a covered location.
2. Add `.secrets/` to `.gitignore`. Verify with `git check-ignore -- .secrets/service-token`. If the workspace indexer uses separate rules, exclude `.secrets/` there too.
3. Keep `.env`, `.env.*` and exported variables public-only. For example, set `SERVICE_TOKEN_FILE=.secrets/service-token`. Have the application resolve the path from the project root and read the token at runtime.
4. As the ordinary user, check `test -r "$path"` before reading or `test -w "$path"` before editing. If access is missing, tell the operator which path you need and wait. Keep credential values out of command arguments, logs, chat and Git. Use dummy values in examples and tests.
