#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's online garbage collector reads manifests without the
# repository lock, reviews each repository in its own report-only sweep, so
# one that fails holds no other, names in its gc-ran marker only the repositories
# reviewed, and binds the marker to a random store id kept in the store root.
# It frees an abandoned first push from the half brake once the
# repository has gone unwritten for the abandon horizon, and treats any body
# with a Docker schema1 fsLayers field as unreadable, which the server
# refuses at PUT. The marker names each reviewed repository, a pusher-named
# child blob within the size cap does not stop a sweep, and the server stores
# only what the collector reads.
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
#   TestFailureThatMayPassLeavesItsRepositoryUnreviewed
#                                                   a repository failed for a reason
#                                                   that may pass is not reviewed, and
#                                                   the next sweep deletes elsewhere
#   TestFailureThatMayPassHoldsOnlyItsRepository    a failure that persists holds no
#                                                   other repository, and its own
#                                                   repository reports after repair
#   TestUnreadableAtTheFirstSweepIsReviewedAfterRepair
#                                                   nothing unreviewed deletes once
#                                                   the body is readable again
#   TestBrakedFirstSweepListsAndWaits               a braked first sweep lists what
#                                                   it would reap; the abandon horizon
#                                                   reports before it deletes
#   TestReviewedSetIsNotBoundedBySize               repositories cannot outgrow the
#                                                   marker and turn the collector off
#   TestMergeRestoreFollowsTheDocumentedRule        the restore rule docs/user/registry.md
#                                                   gives, and its recovery
#   TestBadStoreIDSaysHowToRecover                  a corrupt id file deletes nothing,
#                                                   and removing it recovers
#   TestUnwritableStoreIDSaysWhyNothingDeletes      a root that refuses the id file
#                                                   says so on every sweep
#   TestIndexChildThatIsNoManifestDoesNotStopTheSweep
#                                                   a blob named as a child, with no
#                                                   row, is kept and stops nothing
#   TestScanFoundManifestIsFollowed                 a digest found in an unreadable child
#                                                   is followed through a stored body, a
#                                                   body it cannot verify stops nothing,
#                                                   and a cycle ends
#   TestChildDigestThatNamesNoBlobDoesNotStopTheSweep
#                                                   a child digest no blob can have
#                                                   does not fail the plan
#   TestChildWithARowStaysFailClosed                a child with a row that cannot be
#                                                   read still stops the sweep
#   TestRowlessChildThatParsesIsStillFollowed       a readable child keeps what it names
#   TestRestoredRootReportsOnlyAgain                a backup without the store id
#                                                   restored into the same root
#                                                   directory sweeps report-only
#   TestEmptyFirstSweepThenRestoreReportsOnly       a sweep over an empty store
#                                                   writes no marker, so restored
#                                                   content sweeps report-only
#   TestCopiedStoreFollowsItsStoreID                a copy with the store id deletes,
#                                                   one without it reports only
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
# then, in pkg/ociregistry/store:
#   TestEnsureIDWritesOnceAndKeepsIt                the store id is written once,
#                                                   atomically, and a malformed one
#                                                   is an error
# then, in pkg/ociregistry/api:
#   TestPutManifestRejectsDockerSchema1             the server stores no schema1
#                                                   manifest under any media type
#   TestPutManifestRejectsFSLayersAtSchemaVersion2  nor any body with an fsLayers
#                                                   field, at schemaVersion 2 too
#   TestPutAcceptsOnlyWhatTheCollectorReads         the server stores no body the
#                                                   collector cannot read, an index
#                                                   with no manifests array included
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
	TestFailureThatMayPassLeavesItsRepositoryUnreviewed
	TestFailureThatMayPassHoldsOnlyItsRepository
	TestUnreadableAtTheFirstSweepIsReviewedAfterRepair
	TestBrakedFirstSweepListsAndWaits
	TestReviewedSetIsNotBoundedBySize
	TestMergeRestoreFollowsTheDocumentedRule
	TestBadStoreIDSaysHowToRecover
	TestUnwritableStoreIDSaysWhyNothingDeletes
	TestIndexChildThatIsNoManifestDoesNotStopTheSweep
	TestScanFoundManifestIsFollowed
	TestChildDigestThatNamesNoBlobDoesNotStopTheSweep
	TestChildWithARowStaysFailClosed
	TestRowlessChildThatParsesIsStillFollowed
	TestRestoredRootReportsOnlyAgain
	TestEmptyFirstSweepThenRestoreReportsOnly
	TestCopiedStoreFollowsItsStoreID
	TestAbandoned
	TestAbandonedFirstPushIsFreed
	TestRecentFirstPushStaysBraked
	TestAbandonOption
	TestParseRefsFailsClosed
)
STORE_TESTS=(
	TestEnsureIDWritesOnceAndKeepsIt
)
API_TESTS=(
	TestPutManifestRejectsDockerSchema1
	TestPutManifestRejectsFSLayersAtSchemaVersion2
	TestPutAcceptsOnlyWhatTheCollectorReads
)
re="^($(IFS='|'; echo "${TESTS[*]}"))\$"
out="$(go test -race -count=1 -v -run "$re" ./pkg/ociregistry/gc/ 2>&1)" || {
	printf '%s\n' "$out"; echo "$LABEL: FAIL: named tests"; exit 1; }
grep -E '^(--- |ok|PASS)' <<<"$out"
# A test that does not run is not a pass.
for t in "${TESTS[@]}"; do
	grep -q -- "^--- PASS: $t " <<<"$out" || { echo "$LABEL: FAIL: $t did not run"; exit 1; }
done
re="^($(IFS='|'; echo "${STORE_TESTS[*]}"))\$"
out="$(go test -race -count=1 -v -run "$re" ./pkg/ociregistry/store/ 2>&1)" || {
	printf '%s\n' "$out"; echo "$LABEL: FAIL: named store tests"; exit 1; }
grep -E '^(--- |ok|PASS)' <<<"$out"
for t in "${STORE_TESTS[@]}"; do
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
