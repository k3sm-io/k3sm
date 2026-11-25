#!/bin/bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Exercise the real archive, manifest and download path against a file-backed registry.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=hack/app-bundle.sh
source "$here/app-bundle.sh"

if [[ ${1:-} == read-fixture ]]; then
    fixture=$2
    parse_ref "$3"
    connect_registry() { :; }
    fetch() {
        case $1 in
            manifests/*) cp "$fixture/manifest" "$3" ;;
            blobs/*)
                echo blob >> "$fixture/requests"
                cp "$fixture/blob" "$3"
                ;;
            *) die "unexpected registry request: $1" ;;
        esac
    }
    download "$fixture/fetched.zip"
    exit
fi

fixture=$(mktemp -d "${TMPDIR:-/tmp}/app-bundle-test.XXXXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/Example.app/Contents/MacOS"
cp /usr/bin/true "$fixture/Example.app/Contents/MacOS/Example"
cat > "$fixture/Example.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.k3sm.fixture.app</string>
<key>CFBundleExecutable</key><string>Example</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PLIST
ln -s Example "$fixture/Example.app/Contents/MacOS/alias"
/usr/bin/codesign --force --sign - "$fixture/Example.app"
(
    k3sm() {
        [[ $1 == image && $2 == push && $4 == registry-k3sm:6450/apps/example:dev ]]
        cp -R "$3" "$fixture/layout"
    }
    parse_ref apps/example:dev
    publish "$fixture/Example.app"
)
blobs="$fixture/layout/blobs/sha256"
pin=$(/usr/bin/jq -er '.manifests[0].digest' "$fixture/layout/index.json")
cp "$blobs/${pin#sha256:}" "$fixture/manifest"
layer=$(/usr/bin/jq -er '.layers[0].digest' "$fixture/manifest")
cp "$blobs/${layer#sha256:}" "$fixture/blob"
read_fixture() { /bin/bash "$0" read-fixture "$fixture" "$1"; }
mkdir "$fixture/shared"
chmod 0777 "$fixture/shared"
if "$here/app-bundle.sh" pull apps/example:dev "$fixture/shared/unsafe.zip"; then die "accepted a shared directory"; fi
ln -s "$fixture/good.zip" "$fixture/link.zip"
if "$here/app-bundle.sh" pull apps/example:dev "$fixture/link.zip"; then die "accepted a symlink destination"; fi
read_fixture "apps/example@$pin"
read_fixture apps/example:dev
[[ $(wc -l < "$fixture/requests") -eq 1 ]] || die "unchanged archive was downloaded twice"
ditto -x -k "$fixture/fetched.zip" "$fixture/unpacked"
codesign --verify --deep --strict "$fixture/unpacked/Example.app"
[[ $(readlink "$fixture/unpacked/Example.app/Contents/MacOS/alias") == Example ]] || die "lost symlink"
[[ -x $fixture/unpacked/Example.app/Contents/MacOS/Example ]] || die "lost executable mode"
cp "$fixture/fetched.zip" "$fixture/good.zip"
reject() {
    if read_fixture "$1"; then die "accepted invalid fixture: $1"; fi
    cmp "$fixture/fetched.zip" "$fixture/good.zip"
}
reject "apps/example@sha256:0000000000000000000000000000000000000000000000000000000000000000"
reject '../apps:dev'
/usr/bin/jq '.artifactType = "application/example"' "$blobs/${pin#sha256:}" > "$fixture/manifest"
reject apps/example:dev
/usr/bin/jq '.layers[0].digest = "sha256:../../outside"' "$blobs/${pin#sha256:}" > "$fixture/manifest"
reject apps/example:dev
printf 'updated valid bytes' > "$fixture/blob"
updated=$(sha "$fixture/blob")
/usr/bin/jq --arg d "$updated" --argjson size "$(size "$fixture/blob")" \
    '.layers[0].digest=$d | .layers[0].size=$size' "$blobs/${pin#sha256:}" > "$fixture/manifest"
printf 'corrupt valid bytes' > "$fixture/blob"
reject apps/example:dev
printf 'x' > "$fixture/blob"
reject apps/example:dev
printf 'updated valid bytes' > "$fixture/blob"
read_fixture apps/example:dev
cmp "$fixture/blob" "$fixture/fetched.zip"
echo "app-bundle: archive round trip, unchanged pull, update and rejection checks passed"

# Drive the watch loop without sleeping or contacting the registry. The first
# poll fails, the second succeeds, and the watcher must schedule both intervals.
(
    polls=0
    locked_pull() {
        [[ $2 == apps/example:dev && $3 == "$(physical_file "$fixture/fetched.zip")" ]] || exit 1
        polls=$((polls + 1))
        echo "$polls" >> "$fixture/polls"
        [[ $polls -gt 1 ]]
    }
    sleep() {
        [[ $1 == 7 ]] || exit 1
        if [[ $polls == 2 ]]; then exit 0; fi
    }
    main watch apps/example:dev "$fixture/fetched.zip" 7
)
[[ $(cat "$fixture/polls") == $'1\n2' ]] || die "watch did not retry"
if "$here/app-bundle.sh" watch "apps/example@$pin" "$fixture/fetched.zip"; then die "watched a pinned reference"; fi
if "$here/app-bundle.sh" watch apps/example:dev "$fixture/fetched.zip" 0; then die "allowed a busy poll"; fi
echo "app-bundle: watch retries and input checks passed"
