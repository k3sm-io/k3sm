#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry store reads and writes the layout zot leaves.
#
# --check runs, in pkg/ociregistry/store:
#   TestStoreReadsZotLayout       the store reads a store the pinned zot wrote
#                                 (testdata, captured by hack/capture-zot-layout.sh)
#                                 and writes into it without touching cache.db or meta.db
#   TestStoreRoundTripMatchesZot  the same pushes through the store give zot's
#                                 tree: modes, hardlinks, byte-identical index.json
# and the ref validator's tests with their fuzz seed corpora, all under -race.
#
# --zot <path> additionally has that zot serve a store the round trip wrote
# (hack/capture-zot-layout.sh --serve-check): the store's output read by zot itself.
#
# Usage: hack/acceptance/B1017.sh --check [--zot <path>]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

check=0
zot=""
while [ $# -gt 0 ]; do
	case "$1" in
	--check) check=1; shift ;;
	--zot) zot="$2"; shift 2 ;;
	*) echo "usage: $0 --check [--zot <path>]" >&2; exit 2 ;;
	esac
done
[ "$check" = 1 ] || { echo "usage: $0 --check [--zot <path>]" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
for f in pkg/ociregistry/store/testdata/zot-v2.1.22.tar.gz hack/capture-zot-layout.sh; do
	[ -e "$f" ] || { echo "B1017: FAIL: $f is missing"; exit 1; }
done

out="$(go test -race -count=1 -v -run '^(TestStoreReadsZotLayout|TestStoreRoundTripMatchesZot)$' ./pkg/ociregistry/store/ 2>&1)" || {
	printf '%s\n' "$out"; echo "B1017: FAIL: store tests"; exit 1; }
printf '%s\n' "$out" | grep -E '^(--- |ok|PASS)'
# A test that does not run is not a pass.
for t in TestStoreReadsZotLayout TestStoreRoundTripMatchesZot; do
	printf '%s\n' "$out" | grep -q -- "--- PASS: $t " || { echo "B1017: FAIL: $t did not run"; exit 1; }
done
go test -race -count=1 ./pkg/ociregistry/ref/ ./pkg/ociregistry/store/ || { echo "B1017: FAIL: package tests"; exit 1; }

if [ -n "$zot" ]; then
	tmp="$(mktemp -d "${TMPDIR:-/tmp}/b1017.XXXXXX")"
	trap 'rm -rf "$tmp"' EXIT
	K3SM_STORE_ROUNDTRIP_OUT="$tmp/work" go test -count=1 -run '^TestStoreRoundTripMatchesZot$' ./pkg/ociregistry/store/ >/dev/null ||
		{ echo "B1017: FAIL: round trip"; exit 1; }
	hack/capture-zot-layout.sh --zot "$zot" --serve-check "$tmp/work/registry" || { echo "B1017: FAIL: zot did not serve the store"; exit 1; }
fi
echo "B1017: PASS"
