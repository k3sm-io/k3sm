#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# An untagged child manifest a client HEADs by digest and then names in an
# index PUT is not reaped by the registry's online garbage collector in
# between.
#
# --check runs, by name, with the race detector on:
#   TestManifestHeadKeepsTheChildForTheIndexPut  in pkg/ociregistry/api: an
#                                                untagged child manifest past the
#                                                grace is HEADed by digest, a
#                                                deleting sweep runs, then the
#                                                index PUT naming it must answer
#                                                201 with the child and its blobs
#                                                kept; without the HEAD the same
#                                                sweep reaps the child, so the
#                                                test is not vacuous
#   TestManifestReadsThatWriteNothing            in pkg/ociregistry/api: a HEAD by
#                                                tag and a GET by tag or digest
#                                                leave the manifest's mtime alone;
#                                                only a HEAD by digest touches it
# then the api, store and gc packages, also under -race.
#
# Usage: hack/acceptance/B1065.sh --check
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
		printf '%s\n' "$out"; echo "B1065: FAIL: $pkg named tests"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |ok|PASS)'
	# A test that does not run is not a pass.
	for t in "$@"; do
		printf '%s\n' "$out" | grep -q -- "^--- PASS: $t " || { echo "B1065: FAIL: $t did not run"; exit 1; }
	done
	NAMED_OUT="$out"
}
# cases <test> <want>: require <want> passing subtests of <test>.
cases() {
	local n
	n="$(printf '%s\n' "$NAMED_OUT" | grep -c -- "^    --- PASS: $1/" || true)"
	[ "$n" -eq "$2" ] || { echo "B1065: FAIL: $1 ran $n cases, want $2"; exit 1; }
}

named ./pkg/ociregistry/api/ TestManifestHeadKeepsTheChildForTheIndexPut TestManifestReadsThatWriteNothing
# Both halves of the contract, and every read, must run.
cases TestManifestHeadKeepsTheChildForTheIndexPut 2
cases TestManifestReadsThatWriteNothing 4
go test -race -count=1 ./pkg/ociregistry/api/ ./pkg/ociregistry/store/ ./pkg/ociregistry/gc/ || { echo "B1065: FAIL: package tests"; exit 1; }
echo "B1065: PASS"
