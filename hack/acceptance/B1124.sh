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
#                                   past the half-grace are touched; HEADs on
#                                   a store whose Futimes seam fails answer
#                                   200, take the lock once per object and log
#                                   once; a HEAD that gives up waiting for the
#                                   lock is suppressed the same way; New
#                                   refuses a zero or negative grace; a digest
#                                   with a tagged and an untagged row writes
#                                   nothing; an untagged child HEADed and then
#                                   named by an index PUT survives a sweep
#   TestTouchFailsIsBounded         in pkg/ociregistry/api: the suppression
#                                   map evicts the entry whose window ends
#                                   first and forgets a closed window
#
# Usage: hack/acceptance/B1124.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
test=TestManifestHeadTouchIsBounded
out="$(go test -race -count=1 -v -run "^(${test}|TestTouchFailsIsBounded)\$" ./pkg/ociregistry/api/ 2>&1)" || {
	printf '%s\n' "$out"; echo "B1124: FAIL: named tests"; exit 1; }
printf '%s\n' "$out" | grep -E '^(--- |    --- |ok|PASS)'
# A test that does not run is not a pass, and every case must run.
for t in "$test" TestTouchFailsIsBounded; do
	printf '%s\n' "$out" | grep -q -- "^--- PASS: $t " || { echo "B1124: FAIL: $t did not run"; exit 1; }
done
n="$(printf '%s\n' "$out" | grep -c -- "^    --- PASS: $test/" || true)"
[ "$n" -eq 8 ] || { echo "B1124: FAIL: $test ran $n cases, want 8"; exit 1; }
echo "B1124: PASS"
