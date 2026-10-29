#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run this check as root in a test environment.' >&2; exit 1; }
binary=${1:?Pass the published Linux pnt binary}
test_dir=$(mktemp -d /tmp/pnt-access-check.XXXXXX)
had_group=0
getent group pnt >/dev/null && had_group=1
cleanup() {
    case "$test_dir" in /tmp/pnt-access-check.*) rm -rf -- "$test_dir" ;; esac
    [ "$had_group" -eq 1 ] || groupdel pnt
}
trap cleanup EXIT
chmod 755 "$test_dir"
cp "$binary" "$test_dir/pnt"; chmod 755 "$test_dir/pnt"
mkdir "$test_dir/config" "$test_dir/nonmember-bundle" "$test_dir/member-bundle" "$test_dir/root-bundle"
chmod 777 "$test_dir/nonmember-bundle" "$test_dir/member-bundle" "$test_dir/root-bundle"
printf '/test/source\n' > "$test_dir/config/source-dir";chmod 600 "$test_dir/config/source-dir"
export PNT_DATA_DIR="$test_dir/data" PNT_CONFIG_DIR="$test_dir/config" DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
export DOTNET_BUNDLE_EXTRACT_BASE_DIR="$test_dir/root-bundle"
"$test_dir/pnt" _prepare-access
"$test_dir/pnt" create cluster test >/dev/null
chmod 600 "$test_dir/data/node.pfx" "$test_dir/data/pnt.db"
"$test_dir/pnt" _prepare-access
[ "$(stat -c %a "$test_dir/data")" = 2770 ]
[ "$(stat -c %a "$test_dir/data/node.pfx")" = 660 ]
[ "$(stat -c %a "$test_dir/config/source-dir")" = 640 ]
uid=$(id -u nobody);base_gid=$(id -g nobody);pnt_gid=$(getent group pnt | cut -d: -f3)
[ "$base_gid" != "$pnt_gid" ]
export DOTNET_BUNDLE_EXTRACT_BASE_DIR="$test_dir/nonmember-bundle"
set +e
setpriv --reuid "$uid" --regid "$base_gid" --clear-groups "$test_dir/pnt" --help >"$test_dir/denied" 2>&1
status=$?
set -e
[ "$status" -ne 0 ]
grep -q 'pnt:' "$test_dir/denied"
export DOTNET_BUNDLE_EXTRACT_BASE_DIR="$test_dir/member-bundle"
setpriv --reuid "$uid" --regid "$base_gid" --groups "$pnt_gid" "$test_dir/pnt" name group-member
setpriv --reuid "$uid" --regid "$pnt_gid" --clear-groups "$test_dir/pnt" nodes >"$test_dir/nodes"
grep -q group-member "$test_dir/nodes"
set +e
setpriv --reuid "$uid" --regid "$pnt_gid" --clear-groups "$test_dir/pnt" _prepare-access >"$test_dir/prepare-denied" 2>&1
status=$?
set -e
[ "$status" -ne 0 ]
echo 'PASS: root, denied nonmember, primary/supplementary pnt membership, old data migration, shared SQLite/certificate access, privileged migration guard'
