#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's online garbage collector never deletes what a push in flight
# still needs.
#
# --check runs, by name, with the race detector on:
#   TestGCNeverRacesAPush                      four interleavings of a push with a
#                                              sweep (mount then sweep, upload during
#                                              the sweep, manifest PUT racing a delete,
#                                              a restart while a mounted blob is older
#                                              than the grace), on an injected clock
#                                              with a hook between mark and delete.
#                                              These are scripted in one goroutine, so
#                                              the race detector has nothing to see in
#                                              them; the hook fixes the order.
#   TestGCNeverRacesAPushIsRedWithoutTheGuard  the same interleavings against a
#                                              variant without the on-disk guard
#                                              (no mtime touch, no locked re-read and
#                                              re-stat, no start delay) must each lose
#                                              something: the test is not vacuous
#   TestConcurrentPushesAndSweeps              pushes from two Store instances on one
#                                              root (uploads, re-uploads, mounts, tags)
#                                              in goroutines while sweeps run in
#                                              another; this is where -race has work
#   TestRemoveLayoutRacesAPush                 an empty layout's removal racing a
#                                              session start, a commit and a mount
#   TestSweepConvergesAfterACrash              a sweep stopped after its row write or
#                                              after a blob removal, then a second one
#   TestSweepConvergesAfterAHalfRemovedLayout  the layout index.json-less after a stop
#   TestEmptying, TestBrakeBoundary,           the half brake and its emptying rule,
#   TestSweepsExactlyHalf, TestBrakeHolds,     and a mutation check that the brake's
#   TestBrakeHoldsIsRedWhenEmptyingAlwaysHolds tests fail when the rule always holds
#   TestEmptyingSharedBlob                     an emptying sweep of a shared blob
# and in pkg/ociregistry/store:
#   TestWithLock, TestReapSession, TestRemoveTemp, TestContents, TestRemoveLayout,
#   TestRemoveLayoutStoppedAfterTheIndex, TestSweepStoppedInsideRemoveLayout
# then the whole gc and store packages, also under -race: the report-only first
# sweep, the start delay, zot's retention rules, and the reaping of
# committed-but-not-removed upload sessions and .tmp-<uuid> links.
#
# Usage: hack/acceptance/B1020.sh --check
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
		printf '%s\n' "$out"; echo "B1020: FAIL: $pkg named tests"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |ok|PASS)'
	# A test that does not run is not a pass.
	for t in "$@"; do
		grep -q -- "^--- PASS: $t " <<<"$out" || { echo "B1020: FAIL: $t did not run"; exit 1; }
	done
	NAMED_OUT="$out"
}

race=(TestGCNeverRacesAPush TestGCNeverRacesAPushIsRedWithoutTheGuard)
named ./pkg/ociregistry/gc/ "${race[@]}" \
	TestConcurrentPushesAndSweeps TestRemoveLayoutRacesAPush \
	TestSweepConvergesAfterACrash TestSweepConvergesAfterAHalfRemovedLayout \
	TestEmptying TestBrakeBoundary TestSweepsExactlyHalf TestBrakeHolds \
	TestBrakeHoldsIsRedWhenEmptyingAlwaysHolds TestEmptyingSharedBlob
# Every interleaving must run in both race tests.
for t in "${race[@]}"; do
	n="$(printf '%s\n' "$NAMED_OUT" | grep -c -- "^    --- PASS: $t/" || true)"
	[ "$n" -eq 4 ] || { echo "B1020: FAIL: $t ran $n interleavings, want 4"; exit 1; }
done
named ./pkg/ociregistry/store/ TestWithLock TestReapSession TestRemoveTemp TestContents \
	TestRemoveLayout TestRemoveLayoutStoppedAfterTheIndex TestSweepStoppedInsideRemoveLayout
go test -race -count=1 ./pkg/ociregistry/gc/ ./pkg/ociregistry/store/ || { echo "B1020: FAIL: package tests"; exit 1; }
echo "B1020: PASS"
