#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's distribution API server over the on-disk store.
#
# --check runs, under -race:
#   TestDistributionAPI   (pkg/ociregistry/api) every delete rule, the manifest
#                         accept and reject table (testdata/manifest-put), the
#                         blob Range, upload, paging and referrers behaviour,
#                         the session cap, the low-space refusal, panic
#                         recovery and the client-compat cases
#   the chunk-range and session-state tests with their committed fuzz seeds
#   the store's linked-session and checked-delete tests
#   TestClientAgainstTheRegistryServer          (pkg/registryclient)
#   TestImageVerbsAgainstTheRegistryServer      (cmd/k3sm)
# and one iteration of the 2,000-row index benchmark.
#
# Usage: hack/acceptance/B1018.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
for f in pkg/ociregistry/api/testdata/manifest-put/cases.json \
	pkg/ociregistry/api/testdata/fuzz/FuzzParseChunkRange \
	pkg/ociregistry/api/testdata/fuzz/FuzzSessionHashState; do
	[ -e "$f" ] || { echo "B1018: FAIL: $f is missing"; exit 1; }
done

# run <package> <regexp> <test>... runs the tests and requires each to pass by name.
run() {
	local pkg="$1" re="$2"
	shift 2
	local out
	out="$(go test -race -count=1 -v -run "$re" "$pkg" 2>&1)" || {
		printf '%s\n' "$out"; echo "B1018: FAIL: $pkg"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |ok)'
	# A test that does not run is not a pass.
	local t
	for t in "$@"; do
		printf '%s\n' "$out" | grep -q -- "--- PASS: $t " || { echo "B1018: FAIL: $t did not run"; exit 1; }
	done
}

run ./pkg/ociregistry/api/ '^(TestDistributionAPI|TestParseChunkRange|TestSessionHashState|TestSessionTable|FuzzParseChunkRange|FuzzSessionHashState)$' \
	TestDistributionAPI TestParseChunkRange TestSessionHashState TestSessionTable FuzzParseChunkRange FuzzSessionHashState
out="$(go test -count=1 -v -run '^TestDistributionAPI$' ./pkg/ociregistry/api/ 2>&1)"
n="$(printf '%s\n' "$out" | grep -c -- '--- PASS: TestDistributionAPI/')"
[ "$n" -ge 50 ] || { echo "B1018: FAIL: only $n TestDistributionAPI subtests passed"; exit 1; }
for sub in 'delete/a_tag_DELETE' 'delete/a_digest_DELETE_removes' 'delete/a_digest_DELETE_is_refused' 'delete/upload_cancel_needs' \
	'client/the_mount_fallback' 'client/a_Docker_v2_manifest_missing' 'client/the_4_MiB' 'client/ggcr_push_and_pull' \
	'limits/the_session_cap' 'limits/under_2_GiB' 'limits/a_panicking_handler' 'manifest/a_blob_deleted_after'; do
	printf '%s\n' "$out" | grep -q -- "--- PASS: TestDistributionAPI/$sub" || { echo "B1018: FAIL: subtest $sub did not pass"; exit 1; }
done
run ./pkg/ociregistry/store/ '^(TestLinkedSessionCanFinish|TestHashedCommitFallsBackToRehash|TestDeleteDigestChecked|TestLateChunkNeverReachesPublishedBlob)$' \
	TestLinkedSessionCanFinish TestHashedCommitFallsBackToRehash TestDeleteDigestChecked TestLateChunkNeverReachesPublishedBlob
run ./pkg/registryclient/ '^TestClientAgainstTheRegistryServer$' TestClientAgainstTheRegistryServer
run ./cmd/k3sm/ '^TestImageVerbsAgainstTheRegistryServer$' TestImageVerbsAgainstTheRegistryServer
go test -count=1 -run '^$' -bench '^BenchmarkIndex2000Rows$' -benchtime 1x ./pkg/ociregistry/api/ >/dev/null ||
	{ echo "B1018: FAIL: the 2,000-row benchmark"; exit 1; }
echo "B1018: PASS"
