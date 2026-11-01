#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's online garbage collector reads manifests without the
# repository lock, does not let one unreadable repository hold the whole
# store at its report-only first sweep, and binds its gc-ran marker to the
# store root. It frees an abandoned first push from the half brake once the
# repository has gone unwritten for the abandon horizon, and treats any body
# with a Docker schema1 fsLayers field as unreadable, which the server never
# stores.
#
# --check runs, by name, with the race detector on, in pkg/ociregistry/gc:
#   TestPushProceedsWhileTheSweepReadsManifests     the sweep pauses at every
#                                                   manifest read and a push into
#                                                   the same repository must
#                                                   complete there; the sweep
#                                                   still reaps what it should
#   TestLockedPassAnswersOnlyFromAnUnchangedRead    the locked pass plans only
#                                                   from a manifest read that is
#                                                   unchanged under the lock, and
#                                                   is stale otherwise
#   TestOneUnreadableRepositoryStillWritesTheMarker one bad repository among good
#                                                   ones is reported, the marker
#                                                   is written, and the next sweep
#                                                   reaps only in the good ones
#   TestRelocatedStoreReportsOnlyAgain              a copy of the store at a new
#                                                   root sweeps report-only again,
#                                                   the original deletes
#   TestAbandoned                                   the abandoned predicate: no
#                                                   rows, and nothing written
#                                                   since the horizon
#   TestAbandonedFirstPushIsFreed                   a first push with no manifest
#                                                   is braked inside the horizon
#                                                   and reaped past it
#   TestRecentFirstPushStaysBraked                  a first push inside the horizon,
#                                                   or one a push wrote to again,
#                                                   stays under the brake
#   TestAbandonOption                               the horizon's default, bounds
#                                                   and a configured value
#   TestParseRefsFailsClosed                        every unreadable body, schema1
#                                                   fsLayers at schemaVersion 2
#                                                   included, is ErrUnreadable
# then, in pkg/ociregistry/api:
#   TestPutManifestRejectsDockerSchema1             the server stores no schema1
#                                                   manifest under any media type
# then the gc package, also under -race.
#
# Usage: hack/acceptance/B1036.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
LABEL="registry gc"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
TESTS=(
	TestPushProceedsWhileTheSweepReadsManifests
	TestLockedPassAnswersOnlyFromAnUnchangedRead
	TestOneUnreadableRepositoryStillWritesTheMarker
	TestRelocatedStoreReportsOnlyAgain
	TestAbandoned
	TestAbandonedFirstPushIsFreed
	TestRecentFirstPushStaysBraked
	TestAbandonOption
	TestParseRefsFailsClosed
)
API_TESTS=(
	TestPutManifestRejectsDockerSchema1
)
re="^($(IFS='|'; echo "${TESTS[*]}"))\$"
out="$(go test -race -count=1 -v -run "$re" ./pkg/ociregistry/gc/ 2>&1)" || {
	printf '%s\n' "$out"; echo "$LABEL: FAIL: named tests"; exit 1; }
grep -E '^(--- |ok|PASS)' <<<"$out"
# A test that does not run is not a pass.
for t in "${TESTS[@]}"; do
	grep -q -- "^--- PASS: $t " <<<"$out" || { echo "$LABEL: FAIL: $t did not run"; exit 1; }
done
re="^($(IFS='|'; echo "${API_TESTS[*]}"))\$"
out="$(go test -race -count=1 -v -run "$re" ./pkg/ociregistry/api/ 2>&1)" || {
	printf '%s\n' "$out"; echo "$LABEL: FAIL: named api tests"; exit 1; }
grep -E '^(--- |ok|PASS)' <<<"$out"
for t in "${API_TESTS[@]}"; do
	grep -q -- "^--- PASS: $t " <<<"$out" || { echo "$LABEL: FAIL: $t did not run"; exit 1; }
done
go test -race -count=1 ./pkg/ociregistry/gc/ || { echo "$LABEL: FAIL: package tests"; exit 1; }
echo "$LABEL: PASS"
