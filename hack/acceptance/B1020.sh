#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's online garbage collector never deletes what a push in flight
# still needs.
#
# --check runs, in pkg/ociregistry/gc, under -race:
#   TestGCNeverRacesAPush                      four interleavings of a push with a
#                                              sweep (mount then sweep, upload during
#                                              the sweep, manifest PUT racing a delete,
#                                              a restart while a mounted blob is older
#                                              than the grace), on an injected clock
#                                              with a hook between mark and delete
#   TestGCNeverRacesAPushIsRedWithoutTheGuard  the same interleavings against a
#                                              variant without the on-disk guard
#                                              (no mtime touch, no locked re-read and
#                                              re-stat, no start delay) must each lose
#                                              something: the test is not vacuous
# then the whole gc and store packages: the report-only first sweep, the start
# delay, the half-repository stop, zot's retention rules, and the reaping of
# committed-but-not-removed upload sessions and .tmp-<uuid> links.
#
# Usage: hack/acceptance/B1020.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
tests=(TestGCNeverRacesAPush TestGCNeverRacesAPushIsRedWithoutTheGuard)
re="^($(IFS='|'; echo "${tests[*]}"))\$"
out="$(go test -race -count=1 -v -run "$re" ./pkg/ociregistry/gc/ 2>&1)" || {
	printf '%s\n' "$out"; echo "B1020: FAIL: gc race tests"; exit 1; }
printf '%s\n' "$out" | grep -E '^(\s*--- |ok|PASS)'
# A test that does not run is not a pass, and every interleaving must run in both.
for t in "${tests[@]}"; do
	printf '%s\n' "$out" | grep -q -- "^--- PASS: $t " || { echo "B1020: FAIL: $t did not run"; exit 1; }
	n="$(printf '%s\n' "$out" | grep -c -- "^    --- PASS: $t/" || true)"
	[ "$n" -eq 4 ] || { echo "B1020: FAIL: $t ran $n interleavings, want 4"; exit 1; }
done
go test -race -count=1 ./pkg/ociregistry/gc/ ./pkg/ociregistry/store/ || { echo "B1020: FAIL: package tests"; exit 1; }
echo "B1020: PASS"
