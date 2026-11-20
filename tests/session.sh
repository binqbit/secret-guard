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
install -d -m 0700 "$rules"
printf '%s\n' "$work" > "$rules/.indexingfolders"
printf '%s\n' '.env' '.env.*' '.secrets/' > "$rules/.indexingsecrets"
printf '%s\n' 'target/' > "$rules/.indexingignore"
chmod 0600 "$rules/.indexingfolders" "$rules/.indexingsecrets" "$rules/.indexingignore"
install -d -m 0755 -o 1000 -g 1000 "$work" "$work/.secrets" "$work/target"
cd "$work"
printf 'before\n' > .env
printf 'recursive\n' > .secrets/key
printf 'ignored\n' > target/.env
chown 1000:1000 .env .secrets/key target/.env
chmod 0640 target/.env
inode=$(stat -c '%d:%i' .env)

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

# An absent or symlinked list must stop a lock before it changes any file.
original_access=$(stat -c '%u:%g:%a' .env)
for name in .indexingfolders .indexingsecrets .indexingignore; do
    file="$rules/$name"
    mv "$file" "$file.saved"
    if "$guard" lock > invalid.log 2>&1; then echo "Missing list accepted: $name" >&2; exit 1; fi
    ln -s "$file.saved" "$file"
    if "$guard" lock > invalid.log 2>&1; then echo "Symlinked list accepted: $name" >&2; exit 1; fi
    rm "$file"
    mv "$file.saved" "$file"
    [ "$(stat -c '%u:%g:%a' .env)" = "$original_access" ]
done

as_reader() { setpriv --reuid=2000 --regid=2000 --clear-groups "$@"; }
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
"$guard" lock
locked .env.busy
[ "$(cat .env.busy)" = 'held reader fixture' ]
[ -z "$(find /var/lib/secret-guard -mindepth 1 -print -quit)" ]
printf '%s\n' 'PASS: public reads, root-only locking, stable inode, edits, closing rescan, exclusions and busy-file recovery'
GUEST
