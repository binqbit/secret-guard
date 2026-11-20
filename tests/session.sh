#!/bin/sh
# Run in a disposable Linux VM: sudo sh tests/session.sh ./target/release/secret-guard
set -eu

if [ "$#" != 1 ] || [ "$(id -u)" != 0 ]; then
    echo "Usage: sudo sh tests/session.sh /path/to/secret-guard" >&2
    exit 2
fi
binary=$(realpath "$1")
[ -x "$binary" ] || { echo "Missing executable: $binary" >&2; exit 2; }
case "$binary" in
    /etc/*|/var/lib/*) echo "Place the test executable outside /etc and /var/lib." >&2; exit 2 ;;
esac

# No fixtures are created until both private mounts succeed. Their contents
# disappear with this mount namespace. Requires util-linux and GNU coreutils.
exec unshare --mount --propagation private sh -eu -s -- "$binary" <<'GUEST'
guard=$1
mount -n -t tmpfs -o mode=0755,nodev,nosuid tmpfs /etc
mount -n -t tmpfs -o mode=0755,nodev,nosuid tmpfs /var/lib
export SUDO_UID=1000
cat > /etc/passwd <<'ACCOUNTS'
root:x:0:0:Root:/root:/bin/sh
editor:x:1000:1000:Editor:/:/bin/sh
reader:x:2000:2000:Reader:/:/bin/sh
ACCOUNTS
printf '%s\n' 'root:x:0:' 'editor:x:1000:' 'reader:x:2000:' > /etc/group
printf '%s\n' 'passwd: files' 'group: files' > /etc/nsswitch.conf

work=/var/lib/sg-test-work
rules=/etc/secret-guard
as_reader() { setpriv --reuid=2000 --regid=2000 --clear-groups "$@"; }
install -d -m 0755 "$rules"
printf '%s\n' "$work" > "$rules/.indexingfolders"
printf '%s\n' '.env' '.env.*' '.secrets/' > "$rules/.indexingsecrets"
printf '%s\n' 'target/' > "$rules/.indexingignore"
chmod 0644 "$rules/.indexingfolders" "$rules/.indexingsecrets" "$rules/.indexingignore"
# Give both ordinary accounts access to the binary even if the build directory is private.
install -m 0755 "$guard" /var/lib/sg-test-cli
guard=/var/lib/sg-test-cli
for name in .indexingfolders .indexingsecrets .indexingignore; do
    file="$rules/$name"
    as_reader cat "$file" >/dev/null
    if as_reader sh -c ': >> "$1"' sh "$file" 2>/dev/null; then echo "Reader can write $name" >&2; exit 1; fi
    if as_reader rm "$file" 2>/dev/null; then echo "Reader can remove $name" >&2; exit 1; fi
done
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
as_reader "$guard" config show > show.out
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
"$guard" scan > scan.out
grep -Fx "\"$work/.secrets/key\"" scan.out >/dev/null
if grep -F 'new.token' scan.out >/dev/null; then echo 'Scanned outside configured roots' >&2; exit 1; fi
printf '%s\n' "$extra" >> "$rules/.indexingfolders"
printf '%s\n' '*.token' >> "$rules/.indexingsecrets"
printf '%s\n' '.secrets/key' >> "$rules/.indexingignore"
"$guard" scan > scan.out
grep -Fx "\"$extra/new.token\"" scan.out >/dev/null
if grep -F '.secrets/key' scan.out >/dev/null; then echo 'Updated exclusion was ignored' >&2; exit 1; fi
(unset SUDO_UID; "$guard" --user editor scan) > direct.out
cmp scan.out direct.out
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

locked() { [ "$(stat -c '%u:%g:%a' "$1")" = '0:0:600' ]; }
"$guard" lock
locked .env && locked .secrets/key || exit 1
if as_reader cat .env >/dev/null 2>&1; then echo 'Locked file is readable' >&2; exit 1; fi
[ "$(stat -c '%u:%g:%a' target/.env)" = '1000:1000:640' ]

"$guard" session -- /bin/sh -eu -c '
    [ "$(id -u)" = 1000 ]
    [ "$(cat .env)" = before ]
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
[ "$(stat -c '%u:%g:%a' /var/lib/secret-guard)" = '0:0:700' ]
locked /var/lib/secret-guard/session.json
if as_reader cat /var/lib/secret-guard/session.json >/dev/null 2>&1; then echo 'Reader can read private journal' >&2; exit 1; fi
[ "$(stat -c '%u:%g:%a' .env)" = '1000:1000:644' ]
[ "$(as_reader cat .env)" = edited ]
[ "$(as_reader cat .secrets/key)" = recursive ]
if as_reader sh -c 'echo changed >> .env' 2>/dev/null; then echo 'Reader can write' >&2; exit 1; fi
touch finish
wait "$supervisor"
trap - 0

locked .env && locked .env.new && locked .secrets/key || exit 1
[ "$(stat -c '%d:%i' .env)" = "$inode" ]
[ "$(cat .env)" = edited ] && [ "$(cat .env.new)" = new ] || exit 1
[ "$(stat -c '%u:%g:%a' target/.env)" = '1000:1000:640' ]
if as_reader cat .env >/dev/null 2>&1; then echo 'Closed file is still readable' >&2; exit 1; fi
[ -z "$(find /var/lib/secret-guard -mindepth 1 -print -quit)" ]
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
[ -z "$(find /var/lib/secret-guard -mindepth 1 -print -quit)" ]
printf '%s\n' 'PASS: public reads, root-written rules, private journal, root-only locking, stable inode, edits, closing rescan, exclusions and busy-file recovery'
GUEST
