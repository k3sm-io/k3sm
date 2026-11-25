#!/bin/bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Exercise the real archive, manifest and download path against a file-backed registry.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=hack/app-bundle.sh
source "$here/app-bundle.sh"

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
[[ $(sha "$fixture/manifest") == "$pin" && $(sha "$fixture/blob") == "$layer" ]]
ditto -x -k "$fixture/blob" "$fixture/unpacked"
codesign --verify --deep --strict "$fixture/unpacked/Example.app"
[[ $(readlink "$fixture/unpacked/Example.app/Contents/MacOS/alias") == Example ]]
[[ -x $fixture/unpacked/Example.app/Contents/MacOS/Example ]]
echo "app-bundle: signed OCI archive round trip passed"
