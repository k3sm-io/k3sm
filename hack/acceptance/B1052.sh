#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# A blob a client HEADs and then names in a manifest PUT is not reaped by the
# registry's online garbage collector in between.
#
# --check runs, by name, with the race detector on:
#   TestBlobHeadKeepsTheBlobForTheManifestPut  in pkg/ociregistry/api: blobs past
#                                              the grace and named by no manifest
#                                              are HEADed, a deleting sweep runs,
#                                              then the manifest PUT must answer 201
#                                              with every blob kept; without the
#                                              HEAD the same sweep reaps them and
#                                              the PUT must be refused with
#                                              MANIFEST_BLOB_UNKNOWN, so the test
#                                              is not vacuous
#   TestTouchBlob                              in pkg/ociregistry/store: the touch
#                                              sets the mtime from the store clock,
#                                              and a probe of an absent blob is
#                                              unknown and creates no lock file
# then the api, store and gc packages, also under -race.
#
# Usage: hack/acceptance/B1052.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
# named <package> <test>...: run the tests by name and require each to pass.
named() {
	local pkg="$1"; shift
	local re out t
	re="^($(IFS='|'; echo "$*"))\$"
	out="$(go test -race -count=1 -v -run "$re" "$pkg" 2>&1)" || {
		printf '%s\n' "$out"; echo "B1052: FAIL: $pkg named tests"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |ok|PASS)'
	# A test that does not run is not a pass.
	for t in "$@"; do
		printf '%s\n' "$out" | grep -q -- "^--- PASS: $t " || { echo "B1052: FAIL: $t did not run"; exit 1; }
	done
	NAMED_OUT="$out"
}

named ./pkg/ociregistry/api/ TestBlobHeadKeepsTheBlobForTheManifestPut
# Both halves of the contract must run.
n="$(printf '%s\n' "$NAMED_OUT" | grep -c -- "^    --- PASS: TestBlobHeadKeepsTheBlobForTheManifestPut/" || true)"
[ "$n" -eq 2 ] || { echo "B1052: FAIL: TestBlobHeadKeepsTheBlobForTheManifestPut ran $n cases, want 2"; exit 1; }
named ./pkg/ociregistry/store/ TestTouchBlob
go test -race -count=1 ./pkg/ociregistry/api/ ./pkg/ociregistry/store/ ./pkg/ociregistry/gc/ || { echo "B1052: FAIL: package tests"; exit 1; }
echo "B1052: PASS"
