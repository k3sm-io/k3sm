#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's read listings are bounded, its handlers are fuzzed, and its
# upload, blob GET and delete limits hold as documented.
#
# --check runs, under -race:
#   TestListingBounds     (pkg/ociregistry/api) the catalog's default page and
#                         n cap over 2,000 repositories with Link paging, and
#                         its visit budget with a readable cursor for a caller
#                         denied on most repositories; the referrers view over
#                         2,000 manifests: the per-request row and byte
#                         budgets, one read per manifest, the rebuild on an
#                         index.json change, the page bounds, the cache bound,
#                         the artifactType cap, progress kept while 1,100 other
#                         repositories are touched, negative entries, busy on
#                         a retryable error, the build slots, and one-request
#                         reads of 4,096 manifests or sixteen of 4 MiB
#   TestDistributionAPI   (pkg/ociregistry/api) the response shapes, paging
#                         and referrers behaviour the bounds must keep
#   FuzzHandlers          (pkg/ociregistry/api) every committed seed: no 5xx
#                         but 507, no panic, nothing created outside the store
#                         and nothing in it the layout does not name, no symlink
#   TestStrayEntries      (pkg/ociregistry/api) that layout check is not vacuous
#   TestWalkRepositories, TestIndexVersion (pkg/ociregistry/store) the lexical
#                         walk that stops at the page and the index version
#   FuzzConditionalDelete (pkg/ociregistry/api) every committed seed: any
#                         If-Match on a DELETE, by digest above all: no 5xx, no
#                         panic, nothing outside the store, no tagged or
#                         index-named row removed
#   TestSpaceSharePerPrincipal (pkg/ociregistry/api) one principal cannot hold
#                         the whole shared space reservation
#   TestCatalogAsksOncePerVisit (pkg/ociregistry/api) the Authorizer hook needs
#                         no list form: the visit budget bounds its calls
#   TestSessionShare      (pkg/ociregistry/auth) one principal cannot take the
#                         upload slots another needs
#   TestBlobFloor, TestFloorWriter (pkg/ociregistry/api) a blob GET that stalls
#                         is cut within ResponseTimeout over a real socket, and
#                         the floor keeps the sendfile path
#   TestBodyFloorWindow   (pkg/ociregistry/api) a lock wait is not charged to
#                         the body floor; the floor's slack is what the doc says
#   TestUploadSpaceIsHeldInAggregate (pkg/ociregistry/api) bodies in flight
#                         reserve free space together
#   TestCommitForgetsTheSessionOnAPanic (pkg/ociregistry/api) a panic after a
#                         commit holds no session slot
#   TestConditionalDelete (pkg/ociregistry/api) a conditional digest DELETE
#                         refuses a digest a row tags
#   TestPruneThroughTheStore (pkg/registrysvc) prune concurrent with a push,
#                         against the real API server and access check
#   TestImagePruneReportsRecheckSkips (cmd/k3sm) a re-check that cannot read a
#                         repository lists it as unreadable in the report
#
# Usage: hack/acceptance/B1038.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
corpus=pkg/ociregistry/api/testdata/fuzz/FuzzHandlers
[ -d "$corpus" ] || { echo "B1038: FAIL: $corpus is missing"; exit 1; }
seeds="$(find "$corpus" -type f -name 'seed-*' | wc -l | tr -d ' ')"
[ "$seeds" -ge 30 ] || { echo "B1038: FAIL: only $seeds committed FuzzHandlers seeds"; exit 1; }
delcorpus=pkg/ociregistry/api/testdata/fuzz/FuzzConditionalDelete
[ -d "$delcorpus" ] || { echo "B1038: FAIL: $delcorpus is missing"; exit 1; }
delseeds="$(find "$delcorpus" -type f -name 'seed-*' | wc -l | tr -d ' ')"
[ "$delseeds" -ge 20 ] || { echo "B1038: FAIL: only $delseeds committed FuzzConditionalDelete seeds"; exit 1; }

# run <package> <regexp> <test>... runs the tests and requires each to pass by name.
out=""
run() {
	local pkg="$1" re="$2"
	shift 2
	out="$(go test -race -count=1 -v -run "$re" "$pkg" 2>&1)" || {
		printf '%s\n' "$out"; echo "B1038: FAIL: $pkg"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |ok)'
	# A test that does not run is not a pass.
	local t
	for t in "$@"; do
		printf '%s\n' "$out" | grep -q -- "--- PASS: $t " || { echo "B1038: FAIL: $t did not run"; exit 1; }
	done
}

run ./pkg/ociregistry/store/ '^(TestWalkRepositories|TestIndexVersion)$' TestWalkRepositories TestIndexVersion
for sub in 'lexical_order_matches_Repositories' 'a_page_of_2,000_repositories_reads_only_its_path'; do
	printf '%s\n' "$out" | grep -q -- "--- PASS: TestWalkRepositories/$sub" || { echo "B1038: FAIL: subtest $sub did not pass"; exit 1; }
done
run ./pkg/ociregistry/api/ '^(TestListingBounds|TestDistributionAPI|FuzzHandlers|TestStrayEntries)$' TestListingBounds TestDistributionAPI FuzzHandlers TestStrayEntries
for sub in 'catalog/2,000_repositories' 'catalog/denied_repositories' 'referrers/2,000_manifests' 'referrers/the_byte_budget' \
	'referrers/the_cache_drops' 'referrers/more_than_8_artifactType' 'referrers/touching_1,100_other' 'referrers/an_unreadable_manifest' \
	'referrers/a_build_needs_a_free_slot' 'referrers/4,096_manifests'; do
	printf '%s\n' "$out" | grep -q -- "--- PASS: TestListingBounds/$sub" || { echo "B1038: FAIL: subtest $sub did not pass"; exit 1; }
done
ran="$(printf '%s\n' "$out" | grep -c -- '--- PASS: FuzzHandlers/seed-')"
[ "$ran" -eq "$seeds" ] || { echo "B1038: FAIL: $ran of $seeds FuzzHandlers seeds ran"; exit 1; }

run ./pkg/ociregistry/api/ '^(FuzzConditionalDelete|TestSpaceSharePerPrincipal|TestCatalogAsksOncePerVisit|TestBlobFloor|TestFloorWriter|TestBodyFloorWindow|TestUploadSpaceIsHeldInAggregate|TestCommitForgetsTheSessionOnAPanic|TestConditionalDelete)$' \
	FuzzConditionalDelete TestSpaceSharePerPrincipal TestCatalogAsksOncePerVisit TestBlobFloor TestFloorWriter TestBodyFloorWindow TestUploadSpaceIsHeldInAggregate TestCommitForgetsTheSessionOnAPanic TestConditionalDelete
printf '%s\n' "$out" | grep -q -- '--- PASS: TestConditionalDelete/a_conditional_digest_DELETE_refuses_a_digest_a_row_tags' || { echo "B1038: FAIL: the tagged-digest refusal did not pass"; exit 1; }
ran="$(printf '%s\n' "$out" | grep -c -- '--- PASS: FuzzConditionalDelete/seed-')"
[ "$ran" -eq "$delseeds" ] || { echo "B1038: FAIL: $ran of $delseeds FuzzConditionalDelete seeds ran"; exit 1; }
run ./pkg/ociregistry/auth/ '^TestSessionShare$' TestSessionShare
run ./pkg/registrysvc/ '^TestPruneThroughTheStore$' TestPruneThroughTheStore
printf '%s\n' "$out" | grep -q -- '--- PASS: TestPruneThroughTheStore/a_prune_concurrent_with_a_push_does_not_lose_the_pushed_tag' || { echo "B1038: FAIL: the concurrent prune did not pass"; exit 1; }
run ./cmd/k3sm/ '^TestImagePruneReportsRecheckSkips$' TestImagePruneReportsRecheckSkips
echo "B1038: PASS"
