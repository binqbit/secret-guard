#!/bin/sh
# Run in a disposable Linux VM: sudo sh tests/session.sh ./target/release/secret-guard
set -eu

if [ "$#" != 1 ] || [ "$(id -u)" != 0 ]; then
    echo "Usage: sudo sh tests/session.sh /path/to/secret-guard" >&2
    exit 2
fi
binary=$(realpath "$1")
templates=$(realpath "$(dirname "$0")/..")
[ -x "$binary" ] || { echo "Missing executable: $binary" >&2; exit 2; }
case "$binary" in
    /etc/*|/var/lib/*) echo "Place the test executable outside /etc and /var/lib." >&2; exit 2 ;;
esac

# No fixtures are created until both private mounts succeed. Their contents
# disappear with this mount namespace. Requires util-linux and GNU coreutils.
exec unshare --mount --propagation private sh -eu -s -- "$binary" "$templates" <<'GUEST'
guard=$1
templates=$2
mount -n -t tmpfs -o mode=0755,nodev,nosuid tmpfs /etc
mount -n -t tmpfs -o mode=0755,nodev,nosuid tmpfs /var/lib
export SUDO_UID=1000
cat > /etc/passwd <<'ACCOUNTS'
root:x:0:0:Root:/root:/bin/sh
editor:x:1000:1000:Editor:/var/lib/editor home:/bin/sh
reader:x:2000:2000:Reader:/var/lib/reader home:/bin/sh
ACCOUNTS
printf '%s\n' 'root:x:0:' 'editor:x:1000:' 'reader:x:2000:' 'shared:x:3000:editor' > /etc/group
printf '%s\n' 'passwd: files' 'group: files' > /etc/nsswitch.conf

work=/var/lib/sg-test-work
rules=/etc/secret-guard
as_reader() { setpriv --reuid=2000 --regid=2000 --clear-groups "$@"; }
as_editor() { setpriv --reuid=1000 --regid=1000 --groups=3000 "$@"; }
locked() { [ "$(stat -c '%u:%g:%a' "$1")" = '0:0:600' ]; }
# Hold a real descriptor as the selected test account until the caller releases it.
hold_file() {
    holder_dir=$3
    "$1" sh -eu -c '
        exec 3<"$1"
        : > "$2/reader-ready"
        for attempt in $(seq 1 150); do
            [ -e "$2/reader-release" ] && exit 0
            sleep 0.1
        done
        exit 1
    ' sh "$2" "$holder_dir" &
    holder=$!
    trap 'touch "$holder_dir/reader-release"; wait "$holder" || :' 0
    for attempt in $(seq 1 100); do
        [ -e "$holder_dir/reader-ready" ] && return 0
        kill -0 "$holder" || return 1
        sleep 0.1
    done
    return 1
}
release_file() {
    touch "$holder_dir/reader-release"
    wait "$holder"
    trap - 0
}
editor_home='/var/lib/editor home'
reader_home='/var/lib/reader home'
install -d -o 1000 -g 1000 -m 0700 "$editor_home"
install -d -o 2000 -g 2000 -m 0755 "$reader_home"
# Give both ordinary accounts access to the binary even if the build directory is private.
install -m 0755 "$guard" /var/lib/sg-test-cli
guard=/var/lib/sg-test-cli

# First use from outside the checkout gets the packaged defaults and the NSS home.
cd /var/lib
if (unset SUDO_UID; "$guard" config show) > no-user.log 2>&1; then
    echo 'Root without a caller initialized rules for an arbitrary account' >&2; exit 1
fi
[ ! -e "$rules" ]
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m d:u:2000:--- /etc
fi
(umask 0077; HOME=/root USER=root LOGNAME=root "$guard" config show) > first-show.out
[ "$(stat -c '%u:%g:%a' "$rules")" = '0:0:755' ]
grep -Fx "$editor_home" "$rules/.indexingfolders" >/dev/null
cmp "$templates/.indexingsecrets" "$rules/.indexingsecrets"
cmp "$templates/.indexingignore" "$rules/.indexingignore"
[ ! -e /var/lib/secret-guard ]
for name in .indexingfolders .indexingsecrets .indexingignore; do
    file="$rules/$name"
    [ "$(stat -c '%u:%g:%a' "$file")" = '0:0:644' ]
    as_reader cat "$file" >/dev/null
    if as_reader sh -c ': >> "$1"' sh "$file" 2>/dev/null; then echo "Reader can write $name" >&2; exit 1; fi
    if as_reader rm "$file" 2>/dev/null; then echo "Reader can remove $name" >&2; exit 1; fi
done
if command -v setfacl >/dev/null 2>&1; then
    setfacl -k /etc
    echo 'PASS: public bootstrap rules with restrictive inherited ACL'
fi

# A precreated empty directory also supports setup for an explicitly selected account.
mv "$rules" /etc/editor-defaults
install -d -m 0755 "$rules"
(unset SUDO_UID; "$guard" --user reader config show) > reader-show.out
grep -Fx "$reader_home" "$rules/.indexingfolders" >/dev/null
mv "$rules" /etc/reader-defaults

# Status can be the first command, showing the session and current file permissions.
printf '%s\n' 'bootstrap fixture' > "$editor_home/.env"
chown 1000:1000 "$editor_home/.env"
chmod 0644 "$editor_home/.env"
HOME=/root "$guard" status > first-status.out
grep -Fx 'No open session.' first-status.out >/dev/null
grep -Fx "public-read mode  1000:1000 0644  \"$editor_home/.env\"" first-status.out >/dev/null
"$guard" status --paths > first-paths.out
printf '"%s"\n' "$editor_home/.env" | cmp - first-paths.out
cmp /etc/editor-defaults/.indexingfolders "$rules/.indexingfolders"

# The top-level commands have distinct roles.
"$guard" --help | sed -n '/^Commands:/,/^Options:/{s/^  \([a-z][a-z]*\)  *.*/\1/p;}' > commands.out
[ "$(wc -l < commands.out)" -eq 5 ]
for name in config status lock unlock session; do grep -Fx "$name" commands.out >/dev/null; done
if "$guard" scan > invalid-command.log 2>&1; then echo 'Accepted a top-level scan' >&2; exit 1; fi
grep -F "unrecognized subcommand 'scan'" invalid-command.log >/dev/null

# Reset rewrites exactly the three rules for the selected account.
if "$guard" reset config > invalid-command.log 2>&1; then echo 'Accepted a top-level reset' >&2; exit 1; fi
grep -F "unrecognized subcommand 'reset'" invalid-command.log >/dev/null
before_reset=$(stat -c '%d:%i:%u:%g:%a' "$editor_home/.env")
printf '%s\n' 'keep admin note' > "$rules/admin-note"
mkdir "$rules/local-settings"
printf '%s\n' 'keep this too' > "$rules/local-settings/note"
printf '%s\n' "$reader_home" > "$rules/.indexingfolders"
printf '%s\n' 'custom.key' > "$rules/.indexingsecrets"
printf '%s\n' 'custom/' > "$rules/.indexingignore"
"$guard" config reset
for name in .indexingfolders .indexingsecrets .indexingignore; do
    cmp "/etc/editor-defaults/$name" "$rules/$name"
    [ "$(stat -c '%u:%g:%a' "$rules/$name")" = '0:0:644' ]
    as_reader cat "$rules/$name" >/dev/null
done
# A bad target aborts the entire reset, including lists before it in the write order.
printf '%s\n' 'custom.key' > "$rules/.indexingsecrets"
rm "$rules/.indexingignore"
ln -s "$rules/admin-note" "$rules/.indexingignore"
if "$guard" config reset > unsafe-reset.log 2>&1; then echo 'Reset a symlinked list' >&2; exit 1; fi
[ -L "$rules/.indexingignore" ]
[ "$(cat "$rules/.indexingsecrets")" = 'custom.key' ]
rm "$rules/.indexingignore"
ln "$rules/admin-note" "$rules/.indexingignore"
if "$guard" config reset > unsafe-reset.log 2>&1; then echo 'Reset a hard-linked list' >&2; exit 1; fi
[ "$(stat -c %h "$rules/admin-note")" = 2 ]
[ "$(cat "$rules/.indexingsecrets")" = 'custom.key' ]
rm "$rules/.indexingignore"
(unset SUDO_UID; "$guard" --user reader config reset)
cmp /etc/reader-defaults/.indexingfolders "$rules/.indexingfolders"
cmp "$templates/.indexingsecrets" "$rules/.indexingsecrets"
cmp "$templates/.indexingignore" "$rules/.indexingignore"
# Make the last list temporarily unreplaceable after the reset has begun.
# Readers must refuse the interrupted snapshot until the same reset succeeds.
mount -n --bind "$rules/admin-note" "$rules/.indexingignore"
if "$guard" config reset > interrupted-reset.log 2>&1; then echo 'Replaced a mounted rule file' >&2; exit 1; fi
if as_reader "$guard" config show > interrupted-show.log 2>&1; then echo 'Read interrupted reset as complete' >&2; exit 1; fi
grep -F 'reset' interrupted-show.log >/dev/null
umount -n "$rules/.indexingignore"
"$guard" config reset
as_reader "$guard" config show > reset-show.out
for name in .indexingfolders .indexingsecrets .indexingignore; do
    cmp "/etc/editor-defaults/$name" "$rules/$name"
done
[ "$(cat "$rules/admin-note")" = 'keep admin note' ]
[ "$(cat "$rules/local-settings/note")" = 'keep this too' ]
[ "$(stat -c '%d:%i:%u:%g:%a' "$editor_home/.env")" = "$before_reset" ]
[ "$(cat "$editor_home/.env")" = 'bootstrap fixture' ]

# Opening the default home keeps its existing traversal restrictions.
home_env="$editor_home/.env"
"$guard" lock
(
    for attempt in $(seq 1 100); do
        if grep -F 'Press Enter to lock.' private-tty.log >/dev/null 2>&1; then
            [ "$(as_editor cat "$home_env")" = 'bootstrap fixture' ] || exit 1
            touch private-tty-enter
            printf '\n'
            exit 0
        fi
        sleep 0.1
    done
    exit 1
) | SHELL=/bin/sh timeout 15 script -eqfc "$guard session" /dev/null > private-tty.log
[ -e private-tty-enter ]
grep -F "$(printf '\033[32mUNLOCKED\033[0m')" private-tty.log >/dev/null
grep -F "$(printf '\033[31mLOCKED\033[0m')" private-tty.log >/dev/null
locked "$home_env"
"$guard" session -- /bin/sh -eu -c '
    [ "$(stat -c %a "$HOME")" = 700 ]
    [ "$(stat -c "%u:%g:%a" "$HOME/.env")" = 1000:1000:600 ]
    [ "$(cat "$HOME/.env")" = "bootstrap fixture" ]
    printf "%s\n" "private session edit" > "$HOME/.env"
'
locked "$home_env"
if as_editor cat "$home_env" >/dev/null 2>&1; then echo 'Home secret still readable after session' >&2; exit 1; fi
"$guard" unlock
[ "$(as_editor cat "$home_env")" = 'private session edit' ]
[ "$(stat -c '%u:%g:%a' "$home_env")" = '1000:1000:600' ]
[ "$(stat -c '%u:%g:%a' "$editor_home")" = '1000:1000:700' ]
if as_reader cat "$home_env" >/dev/null 2>&1; then echo 'Another UID traversed the private home' >&2; exit 1; fi
# Keep the caller's private descriptor open while the CLI refreshes manual access.
hold_file as_editor "$home_env" "$editor_home"
"$guard" unlock
release_file
"$guard" lock
locked "$home_env"
if as_editor cat "$home_env" >/dev/null 2>&1; then echo 'Home secret still readable after manual lock' >&2; exit 1; fi
[ "$(stat -c '%u:%g:%a' "$editor_home")" = '1000:1000:700' ]

# File ownership alone does not grant traversal. Preflight must leave even an
# eligible, unenrolled sibling unchanged when the selected user cannot enter.
foreign_dir="$editor_home/other-owner"
install -d -o 2000 -g 3000 -m 0700 "$foreign_dir"
printf '%s\n' 'traversal fixture' > "$foreign_dir/.env"
touch "$editor_home/.env.sibling"
chown 1000:1000 "$foreign_dir/.env" "$editor_home/.env.sibling"
chmod 0600 "$foreign_dir/.env" "$editor_home/.env.sibling"
if "$guard" unlock > traversal.log 2>&1; then echo 'Unlocked through an inaccessible directory' >&2; exit 1; fi
grep -F "$foreign_dir" traversal.log >/dev/null
[ ! -e /var/lib/secret-guard/session.json ]
[ "$(stat -c '%u:%g:%a' "$editor_home/.env.sibling")" = '1000:1000:600' ]
[ "$(stat -c '%u:%g:%a' "$foreign_dir/.env")" = '1000:1000:600' ]
locked "$home_env"

# A supplementary group can grant search permission without directory listing.
chmod 0710 "$foreign_dir"
"$guard" session -- grep -Fx 'traversal fixture' "$foreign_dir/.env" >/dev/null
locked "$foreign_dir/.env"
if command -v setfacl >/dev/null 2>&1; then
    # A named user denial takes precedence over group search permission.
    setfacl -m u:1000:--- "$foreign_dir"
    if "$guard" unlock > traversal.log 2>&1; then echo 'Ignored a named ACL denial' >&2; exit 1; fi
    grep -F "$foreign_dir" traversal.log >/dev/null
    [ ! -e /var/lib/secret-guard/session.json ]
    locked "$foreign_dir/.env"
    setfacl -m u:1000:--x,g::--- "$foreign_dir"
    "$guard" session -- grep -Fx 'traversal fixture' "$foreign_dir/.env" >/dev/null
    locked "$foreign_dir/.env"
fi
echo 'PASS: private home, user-specific traversal, and root-only closure'
mv /var/lib/secret-guard /var/lib/first-status-state

printf '%s\n' "$work" > "$rules/.indexingfolders"
printf '%s\n' 'target/' > "$rules/.indexingignore"
install -d -m 0755 -o 1000 -g 1000 "$work" "$work/.secrets" "$work/target"
cd "$work"
printf 'before\n' > .env
printf 'recursive\n' > .secrets/key
printf 'ignored\n' > target/.env
chown 1000:1000 .env .secrets/key target/.env
chmod 0640 target/.env
inode=$(stat -c '%d:%i' .env)

# Public configuration commands read the installed lists, even before the first scan.
# Keep an empty rule list and a comment visible so an operator can diagnose them.
printf '%s\n' '# review the paths before the first scan' "$work" > "$rules/.indexingfolders"
: > "$rules/.indexingignore"
chmod 0711 /etc
as_reader env PATH=/no-sudo "$guard" config show > show.out
chmod 0755 /etc
for entry in '[folders]' '[secrets]' '[ignore]' '# review the paths before the first scan' "$work" '.secrets/'; do
    grep -Fx "$entry" show.out >/dev/null
done
[ ! -e /var/lib/secret-guard ]
printf '%s\n' 'target/' > "$rules/.indexingignore"
cp "$rules/.indexingignore" before-edit
if setsid --fork --wait "$guard" config edit ignore --editor vim </dev/null > no-tty.log 2>&1; then
    echo 'Opened the configuration editor without a controlling terminal' >&2
    exit 1
fi
if "$guard" config edit "$work/.env" > invalid-edit.log 2>&1; then
    echo 'Accepted a configuration edit outside the three lists' >&2
    exit 1
fi
grep -F 'invalid value' invalid-edit.log >/dev/null
cmp before-edit "$rules/.indexingignore"
[ ! -e /var/lib/secret-guard ]

# Exercise the same terminal handoff as a full-screen editor with a predictable
# test program. The ordinary editor can replace its draft but cannot write the list.
cat > /var/lib/sg-test-editor <<'EDITOR'
#!/bin/sh
set -eu
[ "$(id -u)" = 1000 ] && [ -t 0 ] && [ -t 1 ] || exit 2
[ -w "$1" ] && [ ! -w /etc/secret-guard/.indexingignore ] || exit 2
printf '%s\n' 'target/' '# edited in the terminal' > "$1.new"
mv "$1.new" "$1"
[ ! -e fail-editor ]
EDITOR
chmod 0755 /var/lib/sg-test-editor
run_config_editor() {
    SHELL=/bin/sh script -eqc "$guard config edit ignore --editor /var/lib/sg-test-editor" /dev/null </dev/null
}
touch fail-editor
if run_config_editor > editor.log 2>&1; then echo 'Failed editor published changes' >&2; exit 1; fi
cmp before-edit "$rules/.indexingignore"
rm fail-editor
run_config_editor > editor.log
grep -Fx '# edited in the terminal' "$rules/.indexingignore" >/dev/null
[ "$(stat -c '%u:%g:%a' "$rules/.indexingignore")" = '0:0:644' ]
as_reader cat "$rules/.indexingignore" >/dev/null
[ ! -e /var/lib/secret-guard ]

# Each invocation reads the current three lists. A root path may contain spaces.
extra='/var/lib/sg extra root'
install -d -m 0755 -o 1000 -g 1000 "$extra"
touch "$extra/new.token"
chown 1000:1000 "$extra/new.token"
"$guard" status --paths > paths.out
grep -Fx "\"$work/.secrets/key\"" paths.out >/dev/null
if grep -F 'new.token' paths.out >/dev/null; then echo 'Scanned outside configured roots' >&2; exit 1; fi
printf '%s\n' "$extra" >> "$rules/.indexingfolders"
printf '%s\n' '*.token' >> "$rules/.indexingsecrets"
printf '%s\n' '.secrets/key' >> "$rules/.indexingignore"
"$guard" status --paths > paths.out
grep -Fx "\"$extra/new.token\"" paths.out >/dev/null
if grep -F '.secrets/key' paths.out >/dev/null; then echo 'Updated exclusion was ignored' >&2; exit 1; fi
(unset SUDO_UID; "$guard" --user editor status --paths) > direct.out
cmp paths.out direct.out
printf '%s\n' "$work" > "$rules/.indexingfolders"
printf '%s\n' 'target/' > "$rules/.indexingignore"

# Bad configuration must stop a lock before it changes any working file.
original_access=$(stat -c '%u:%g:%a' .env)
reject_lock() {
    if "$guard" lock > invalid.log 2>&1; then echo "Accepted $1" >&2; exit 1; fi
    [ "$(stat -c '%u:%g:%a' .env)" = "$original_access" ]
}
for name in .indexingfolders .indexingsecrets .indexingignore; do
    file="$rules/$name"
    mv "$file" "$file.saved"
    reject_lock "missing list $name"
    ln -s "$file.saved" "$file"
    reject_lock "symlinked list $name"
    rm "$file"
    mv "$file.saved" "$file"
done
file="$rules/.indexingsecrets"
for mode in 0600 0664 0646; do
    chmod "$mode" "$file"
    reject_lock "rule file with mode $mode"
done
chmod 0644 "$file"
chown 1000:1000 "$file"
reject_lock "rule file owned by the session user"
chown 0:0 "$file"
for mode in 0700 0775; do
    chmod "$mode" "$rules"
    reject_lock "configuration directory with mode $mode"
done
chmod 0755 "$rules"
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:2000:--- "$file"
    reject_lock "rule file with a named ACL denying read"
    setfacl -b "$file"
    setfacl -m u:2000:r-- "$rules"
    reject_lock "configuration directory with a named ACL denying traversal"
    setfacl -b "$rules"
    setfacl -m u:2000:r-- /etc
    reject_lock "configuration ancestor with a named ACL denying traversal"
    setfacl -b /etc
    echo 'PASS: rule file, directory and ancestor ACL checks'
fi

if command -v setfacl >/dev/null 2>&1; then
    # An existing named read grant must be ineffective throughout an opening.
    setfacl -m u:2000:r--,u:3000:--- .secrets/key
    [ "$(as_reader cat "$work/.secrets/key")" = recursive ]
fi
# A reader can retain a descriptor to an older 0644 file even after chmod.
legacy_file="$work/.env.legacy"
reader_sync=/var/lib/sg-held-reader
install -d -o 2000 -g 2000 -m 0700 "$reader_sync"
printf '%s\n' 'legacy fixture' > "$legacy_file"
chown 1000:1000 "$legacy_file"
chmod 0644 "$legacy_file"
hold_file as_reader "$legacy_file" "$reader_sync"
if setsid --fork --wait "$guard" unlock </dev/null > held-unlock.log 2>&1; then
    echo 'Unlocked a formerly public file while another user still held it open' >&2; exit 1
fi
grep -F "$legacy_file" held-unlock.log >/dev/null
if grep -Fx UNLOCKED held-unlock.log >/dev/null; then echo 'Claimed owner-only access before closing existing handles' >&2; exit 1; fi
release_file
"$guard" lock
locked "$legacy_file"
locked .env && locked .secrets/key || exit 1
if as_reader cat .env >/dev/null 2>&1; then echo 'Locked file is readable' >&2; exit 1; fi
[ "$(stat -c '%u:%g:%a' target/.env)" = '1000:1000:640' ]
"$guard" status > locked-status.out
grep -Fx "locked  0:0 0600  \"$work/.env\"" locked-status.out >/dev/null

# Manual unlock exits without a terminal; access persists until a separate lock.
setsid --fork --wait "$guard" unlock </dev/null > unlock.out
grep -Fx 'UNLOCKED' unlock.out >/dev/null
"$guard" status > manual-status.out
grep -F 'OPEN / manual' manual-status.out >/dev/null
grep -Fx "owner-only mode  1000:1000 0600  \"$work/.env\"" manual-status.out >/dev/null
if grep -F 'recovery required' manual-status.out >/dev/null; then echo 'Manual unlock reported as a crash' >&2; exit 1; fi
[ "$(as_editor cat "$work/.env")" = before ]
[ "$(as_editor cat "$legacy_file")" = 'legacy fixture' ]
if as_reader cat "$legacy_file" >/dev/null 2>&1; then echo 'Legacy fixture stayed readable after recovery' >&2; exit 1; fi
if as_reader cat "$work/.env" >/dev/null 2>&1; then echo 'Reader can read after manual unlock' >&2; exit 1; fi
if as_reader cat "$work/.secrets/key" >/dev/null 2>&1; then echo 'Named ACL grants read after unlock' >&2; exit 1; fi
if as_reader sh -c ': >> .env' 2>/dev/null; then echo 'Reader can write after manual unlock' >&2; exit 1; fi
if "$guard" session -- touch unexpected-session > rejected-session.log 2>&1; then echo 'Session took over manual unlock' >&2; exit 1; fi
[ ! -e unexpected-session ]
if "$guard" config reset > reset-manual.log 2>&1; then echo 'Reset manually unlocked rules' >&2; exit 1; fi
if (unset SUDO_UID; "$guard" --user reader unlock) > wrong-user.log 2>&1; then
    echo 'A different account took over manually unlocked files' >&2; exit 1
fi
setpriv --reuid=1000 --regid=1000 --clear-groups sh -ec '
    printf "manual edit\n" > .env
    printf "created while unlocked\n" > .env.manual
    chmod 0600 .env.manual
'
# Installed rules may be edited while files are open. Status and closing must remember
# the open scope; --paths previews the next selection under today's installed rules.
touch "$extra/.env"
chown 1000:1000 "$extra/.env"
chmod 0600 "$extra/.env"
cp "$rules/.indexingfolders" before-manual-scope
printf '%s\n' "$extra" > "$rules/.indexingfolders"
"$guard" unlock >/dev/null
[ "$(stat -c '%u:%g:%a' .env.manual)" = '1000:1000:600' ]
"$guard" status > manual-scope.out
grep -F "\"$work/.env\"" manual-scope.out >/dev/null
if grep -F "\"$extra/.env\"" manual-scope.out >/dev/null; then echo 'Manual status lost original scope' >&2; exit 1; fi
"$guard" status --paths > installed-paths.out
grep -Fx "\"$extra/.env\"" installed-paths.out >/dev/null
if grep -F "\"$work/.env\"" installed-paths.out >/dev/null; then echo 'Path preview ignored installed rules' >&2; exit 1; fi
exec 3<.env.manual
if setsid --fork --wait "$guard" lock 3<&- </dev/null > manual-busy.log 2>&1; then
    echo 'Manual lock reported success while a reader held .env.manual' >&2; exit 1
fi
grep -F "$work/.env.manual" manual-busy.log >/dev/null
locked .env
"$guard" status > manual-recovery.out
grep -F 'OPEN / recovery required' manual-recovery.out >/dev/null
if "$guard" unlock > manual-reopen.log 2>&1; then echo 'Unlock took over partial manual close' >&2; exit 1; fi
exec 3<&-
"$guard" lock
locked .env && locked .secrets/key && locked .env.manual || exit 1
[ "$(stat -c '%u:%g:%a' "$extra/.env")" = '1000:1000:600' ]
cp before-manual-scope "$rules/.indexingfolders"
[ "$(cat .env)" = 'manual edit' ]
[ "$(cat .env.manual)" = 'created while unlocked' ]
[ "$(stat -c '%d:%i' .env)" = "$inode" ]
"$guard" status > closed-status.out
grep -Fx 'No open session.' closed-status.out >/dev/null

"$guard" session -- /bin/sh -eu -c '
    [ "$(id -u)" = 1000 ]
    [ "$(cat .env)" = "manual edit" ]
    printf "edited\n" > .env
    printf "new\n" > .env.new
    touch ready
    for attempt in $(seq 1 100); do [ -e finish ] && exit 0; sleep 0.1; done
    echo "Timed out waiting for the reader test" >&2
    exit 1
' &
supervisor=$!
trap 'kill "$supervisor" 2>/dev/null || :; wait "$supervisor" 2>/dev/null || :' 0
for attempt in $(seq 1 100); do
    [ -e ready ] && break
    kill -0 "$supervisor" 2>/dev/null || { wait "$supervisor"; exit 1; }
    sleep 0.1
done
[ -e ready ] || { echo 'Timed out waiting for the session' >&2; exit 1; }
if "$guard" unlock > unlock-active.log 2>&1; then echo 'Unlock took over an active session' >&2; exit 1; fi
if "$guard" config reset > reset-open.log 2>&1; then echo 'Reset an active session' >&2; exit 1; fi
grep -Fx "$work" "$rules/.indexingfolders" >/dev/null
[ "$(stat -c '%u:%g:%a' /var/lib/secret-guard)" = '0:0:700' ]
locked /var/lib/secret-guard/session.json
if as_reader cat /var/lib/secret-guard/session.json >/dev/null 2>&1; then echo 'Reader can read private journal' >&2; exit 1; fi
[ "$(stat -c '%u:%g:%a' .env)" = '1000:1000:600' ]
[ "$(as_editor cat "$work/.env")" = edited ]
[ "$(as_editor cat "$work/.secrets/key")" = recursive ]
if as_reader cat "$work/.env" >/dev/null 2>&1; then echo 'Reader can read during session' >&2; exit 1; fi
if as_reader cat "$work/.secrets/key" >/dev/null 2>&1; then echo 'Named ACL grants read during session' >&2; exit 1; fi
if as_reader sh -c 'echo changed >> .env' 2>/dev/null; then echo 'Reader can write' >&2; exit 1; fi
touch finish
wait "$supervisor"
trap - 0

locked .env && locked .env.new && locked .secrets/key || exit 1
[ "$(stat -c '%d:%i' .env)" = "$inode" ]
[ "$(cat .env)" = edited ] && [ "$(cat .env.new)" = new ] || exit 1
[ "$(stat -c '%u:%g:%a' target/.env)" = '1000:1000:640' ]
if as_reader cat .env >/dev/null 2>&1; then echo 'Closed file is still readable' >&2; exit 1; fi
[ -z "$(find /var/lib/secret-guard -mindepth 1 ! -path /var/lib/secret-guard/.admission.lock -print -quit)" ]
# Keep a Linux file description open in the parent shell. A headless close
# must report that file, finish the independent file and leave recovery possible.
printf 'held reader fixture\n' > .env.busy
printf 'available fixture\n' > .env.available
chown 1000:1000 .env.busy .env.available
chmod 0644 .env.busy .env.available
exec 3<.env.busy
if setsid --fork --wait "$guard" lock 3<&- </dev/null > busy.log 2>&1; then
    echo 'Headless lock reported success while a reader still held .env.busy' >&2
    exit 1
fi
grep -F "$work/.env.busy" busy.log >/dev/null
grep -F 'sudo secret-guard lock' busy.log >/dev/null
[ "$(stat -c '%u:%g:%a' .env.busy)" = '1000:1000:644' ]
locked .env.available
if "$guard" unlock > unlock-recovery.log 2>&1; then echo 'Unlock took over an unfinished recovery' >&2; exit 1; fi
if "$guard" config reset > reset-recovery.log 2>&1; then echo 'Reset with unfinished recovery' >&2; exit 1; fi
grep -Fx "$work" "$rules/.indexingfolders" >/dev/null
exec 3<&-
# A permissions-only upgrade preserves both the operator's rules and recovery.
chmod 0700 "$rules"
chmod 0600 "$rules/.indexingfolders" "$rules/.indexingsecrets" "$rules/.indexingignore"
if "$guard" lock > invalid.log 2>&1; then echo 'Old private configuration was accepted' >&2; exit 1; fi
locked /var/lib/secret-guard/session.json
chmod 0644 "$rules/.indexingfolders" "$rules/.indexingsecrets" "$rules/.indexingignore"
chmod 0755 "$rules"
"$guard" lock
locked .env.busy
[ "$(cat .env.busy)" = 'held reader fixture' ]
[ -z "$(find /var/lib/secret-guard -mindepth 1 ! -path /var/lib/secret-guard/.admission.lock -print -quit)" ]
printf '%s\n' 'PASS: owner-only reads, public configuration, private journal, root-only locking, stable inode, edits, closing rescan, exclusions and busy-file recovery'

# Named sessions use their own root and inherit the installed secret/ignore rules.
projects='/var/lib/scoped projects'
api="$projects/api"
web="$projects/api-extra"
alias_dir="$projects/alias"
install -d -o 1000 -g 1000 -m 0755 "$projects" "$api" "$api/child" "$api/cache[1]" \
    "$web" "$web/cache[1]" "$web/local" "$web/deep/local" "$alias_dir"
for file in "$api/.env" "$api/child/.env" "$api/.env.[key]" "$api/cache[1]/.env" \
    "$web/.env" "$web/.env.[key]" "$web/cache[1]/.env" "$web/local/.env" "$web/deep/local/.env"; do
    printf 'scoped fixture\n' > "$file"
    chown 1000:1000 "$file"
    chmod 0640 "$file"
done
printf '%s\n' '.env' '.env.*' > "$rules/.indexingsecrets"
printf '%s\n' "$api/.env.[key]" "$api/cache[1]" './local/' > "$rules/.indexingignore"
opened() { [ "$(stat -c '%u:%g:%a' "$1")" = '1000:1000:600' ]; }
untouched() { [ "$(stat -c '%u:%g:%a' "$1")" = '1000:1000:640' ]; }
reject_scope() {
    if "$guard" "$@" > scope-rejected.log 2>&1; then
        echo "Unexpected success for $*" >&2
        exit 1
    fi
}
# The explicit root only needs the secret and ignore lists.
mv "$rules/.indexingfolders" named-unused-folders
"$guard" lock service-api --path "$api"
"$guard" status service-api --paths > api-paths.out
mv named-unused-folders "$rules/.indexingfolders"
"$guard" lock service-web --path "$web"
locked "$api/.env" && locked "$api/child/.env" && locked "$web/.env" || exit 1
untouched "$api/.env.[key]" && untouched "$api/cache[1]/.env" && untouched "$web/local/.env" || exit 1
locked "$web/.env.[key]" && locked "$web/cache[1]/.env" && locked "$web/deep/local/.env" || exit 1
printf '"%s"\n' "$api/.env" "$api/child/.env" | cmp - api-paths.out

"$guard" session service-api -- /bin/sh -eu -c '
    [ "$(id -u)" = 1000 ]
    printf "edited under api\n" > "$1/.env"
    touch "$1/ready"
    for attempt in $(seq 1 400); do sleep 0.1; done
    exit 1
' sh "$api" > named-session.log 2>&1 &
supervisor=$!
trap 'kill "$supervisor" 2>/dev/null || :; wait "$supervisor" 2>/dev/null || :' 0
for attempt in $(seq 1 100); do
    [ -e "$api/ready" ] && break
    kill -0 "$supervisor" 2>/dev/null || { wait "$supervisor"; exit 1; }
    sleep 0.1
done
[ -e "$api/ready" ] && opened "$api/.env" && opened "$api/child/.env" || exit 1
reject_scope session service-api -- touch "$api/taken-over"
reject_scope lock service-api
reject_scope lock "$api"
reject_scope unlock "$api/child"
reject_scope unlock service-api --path "$web"
reject_scope lock another --path "$api"
reject_scope lock nested --path "$api/child"
reject_scope lock outer --path "$projects"
mount -n --bind "$api/child" "$alias_dir"
reject_scope lock alias --path "$alias_dir"
umount -n "$alias_dir"
printf '%s\n' "$api" > "$rules/.indexingfolders"
reject_scope lock
reject_scope config reset
[ ! -e "$api/taken-over" ] && opened "$api/.env" && opened "$api/child/.env" || exit 1
printf '%s\n' "$work" > "$rules/.indexingfolders"
"$guard" lock
"$guard" session service-web -- /bin/sh -ec 'test -w "$1"' sh "$web/.env"
locked "$web/.env" && opened "$api/.env" || exit 1
"$guard" unlock service-web
opened "$web/.env" && opened "$api/.env" || exit 1
# A peer's root can move inside this root after both have been admitted.
mv "$api" "$web/moved-api"
reject_scope lock service-web
opened "$web/.env" && opened "$web/moved-api/.env" || exit 1
mv "$web/moved-api" "$api"
"$guard" status > all-open.out
grep -F 'service-api' all-open.out >/dev/null
grep -F 'service-web' all-open.out >/dev/null
"$guard" status service-web > web-open.out
grep -F 'OPEN / manual' web-open.out >/dev/null
if grep -F "$api/.env" web-open.out >/dev/null; then echo 'Named status included another operation' >&2; exit 1; fi

# Recovery must secure the original scope even after rule edits, beside a live peer.
kill -KILL "$supervisor"
if wait "$supervisor"; then echo 'Killed session reported success' >&2; exit 1; fi
trap - 0
"$guard" status service-api > named-recovery.out
grep -F 'OPEN / recovery required' named-recovery.out >/dev/null
reject_scope unlock service-api
reject_scope unlock nested-recovery --path "$api/child"
printf '%s\n' 'unused.fixture' > "$rules/.indexingsecrets"
"$guard" lock service-api
locked "$api/.env" && locked "$api/child/.env" && opened "$web/.env" || exit 1
[ "$(cat "$api/.env")" = 'edited under api' ]
if SUDO_UID=2000 "$guard" lock service-web > wrong-user.log 2>&1; then echo 'A different UID closed named manual access' >&2; exit 1; fi
"$guard" lock service-web
locked "$web/.env" && untouched "$web/local/.env" || exit 1
printf '%s\n' '.env' '.env.*' > "$rules/.indexingsecrets"

# Two admissions that race for the same scope cannot both leave manual access open.
"$guard" unlock race-a --path "$web" > race-a.log 2>&1 &
first=$!
"$guard" unlock race-b --path "$web" > race-b.log 2>&1 &
second=$!
wins=0
if wait "$first"; then wins=1; winner=race-a; fi
if wait "$second"; then wins=$((wins+1)); winner=race-b; fi
[ "$wins" = 1 ] && opened "$web/.env" || { echo "Overlapping admissions produced $wins winners" >&2; exit 1; }
"$guard" lock "$winner"
locked "$web/.env" && locked "$api/.env" || exit 1

# An explicit path has its own operation identity. Absolute and relative spellings
# of that same path select it, even if a named profile also points to the directory.
(cd "$projects"; "$guard" unlock ./api-extra)
opened "$web/.env" && locked "$api/.env" && untouched "$web/local/.env" || exit 1
"$guard" status "$web" > direct-status.out
grep -F 'OPEN / manual' direct-status.out >/dev/null
reject_scope lock service-web
reject_scope unlock another-web --path "$web"
exec 3<"$web/.env"
if setsid --fork --wait "$guard" lock "$web" 3<&- </dev/null > direct-busy.log 2>&1; then
    echo 'Direct path lock ignored an open descriptor' >&2; exit 1
fi
grep -F "$web/.env" direct-busy.log >/dev/null
exec 3<&-
"$guard" status "$web" > direct-recovery.out
grep -F 'OPEN / recovery required' direct-recovery.out >/dev/null
reject_scope lock service-web
(cd "$projects"; "$guard" lock ./api-extra)
locked "$web/.env" && locked "$api/.env" || exit 1
"$guard" session "$api" -- /bin/sh -ec 'test -w "$1"' sh "$api/.env"
locked "$api/.env" && untouched "$api/.env.[key]" || exit 1

# Once a session's close is durable, a stalled terminal write must not obstruct
# a disjoint session attempting its own close. Hold both command sessions open.
gate_command='
    touch "$1/close-ready"
    for attempt in $(seq 1 300); do [ -e "$1/close-go" ] && exit 0; sleep 0.1; done
    exit 1
'
pipe="$projects/slow-output"
mkfifo "$pipe"
exec 4<>"$pipe"
"$guard" session service-api -- /bin/sh -eu -c "$gate_command" sh "$api" 2>"$pipe" &
slow=$!
"$guard" session service-web -- /bin/sh -eu -c "$gate_command" sh "$web" > closing-peer.log 2>&1 &
peer=$!
trap 'kill -KILL "$slow" "$peer" 2>/dev/null || :; wait "$slow" || :; wait "$peer" || :' 0
for attempt in $(seq 1 100); do
    [ -f "$api/close-ready" ] && [ -f "$web/close-ready" ] && break
    kill -0 "$slow" && kill -0 "$peer" || exit 1
    sleep 0.1
done
[ -f "$api/close-ready" ] && [ -f "$web/close-ready" ] || exit 1
if dd if=/dev/zero of="$pipe" bs=1 count=2097152 oflag=nonblock status=none 2> full-pipe.log; then
    echo 'Did not fill the supervisor output pipe' >&2; exit 1
fi
touch "$api/close-go"
for attempt in $(seq 1 100); do
    [ ! -e /var/lib/secret-guard/named-service-api/session.json ] && locked "$api/.env" && break
    sleep 0.1
done
[ ! -e /var/lib/secret-guard/named-service-api/session.json ] && locked "$api/.env" || exit 1
kill -0 "$slow"
touch "$web/close-go"
peer_result=0
wait "$peer" || peer_result=$?
dd if="$pipe" of=/dev/null bs=4096 count=1 status=none
wait "$slow"
exec 4>&-
trap - 0
if [ "$peer_result" != 0 ]; then cat closing-peer.log >&2; exit "$peer_result"; fi
locked "$web/.env"
echo 'PASS: absolute and relative excludes, concurrent named and direct sessions, overlap rejection and targeted crash recovery'
GUEST
