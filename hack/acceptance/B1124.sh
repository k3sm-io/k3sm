#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The write a registry HEAD makes to restart an object's garbage-collection
# grace is bounded: only an untagged manifest or a blob with less than half
# the grace left is touched, a younger object is answered with no repository
# lock and no write, and a touch that fails for a reason other than the object
# being gone is logged while the HEAD still answers 200.
#
# --check runs, by name, with the race detector on:
#   TestManifestHeadTouchIsBounded  in pkg/ociregistry/api: repeated manifest
#                                   and blob HEADs inside the half-grace take
#                                   no lock (the test holds it) and write
#                                   nothing; a HEAD by digest of a tagged row
#                                   writes nothing; an untagged row and a blob
#                                   past the half-grace are touched; a HEAD
#                                   answers 200 when the store's Futimes seam
#                                   fails; an untagged child HEADed and then
#                                   named by an index PUT survives a sweep
#
# Usage: hack/acceptance/B1124.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
test=TestManifestHeadTouchIsBounded
out="$(go test -race -count=1 -v -run "^${test}\$" ./pkg/ociregistry/api/ 2>&1)" || {
	printf '%s\n' "$out"; echo "B1124: FAIL: $test"; exit 1; }
printf '%s\n' "$out" | grep -E '^(--- |    --- |ok|PASS)'
# A test that does not run is not a pass, and every case must run.
printf '%s\n' "$out" | grep -q -- "^--- PASS: $test " || { echo "B1124: FAIL: $test did not run"; exit 1; }
n="$(printf '%s\n' "$out" | grep -c -- "^    --- PASS: $test/" || true)"
[ "$n" -eq 5 ] || { echo "B1124: FAIL: $test ran $n cases, want 5"; exit 1; }
echo "B1124: PASS"
