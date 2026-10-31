#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's read listings are bounded, and its handlers are fuzzed.
#
# --check runs, under -race:
#   TestListingBounds     (pkg/ociregistry/api) the catalog's default page and
#                         n cap over 2,000 repositories with Link paging; the
#                         referrers view over 2,000 manifests: the per-request
#                         row and byte budgets, one read per manifest, the
#                         rebuild on an index.json change, the page bounds and
#                         the cache bound
#   TestDistributionAPI   (pkg/ociregistry/api) the response shapes, paging
#                         and referrers behaviour the bounds must keep
#   FuzzHandlers          (pkg/ociregistry/api) every committed seed: no 5xx
#                         but 507, no panic, nothing created outside the store
#   TestWalkRepositories, TestIndexVersion (pkg/ociregistry/store) the lexical
#                         walk that stops at the page and the index version
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
[ "$seeds" -ge 20 ] || { echo "B1038: FAIL: only $seeds committed FuzzHandlers seeds"; exit 1; }

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
run ./pkg/ociregistry/api/ '^(TestListingBounds|TestDistributionAPI|FuzzHandlers)$' TestListingBounds TestDistributionAPI FuzzHandlers
for sub in 'catalog/2,000_repositories' 'referrers/2,000_manifests' 'referrers/the_byte_budget' 'referrers/the_cache_drops'; do
	printf '%s\n' "$out" | grep -q -- "--- PASS: TestListingBounds/$sub" || { echo "B1038: FAIL: subtest $sub did not pass"; exit 1; }
done
ran="$(printf '%s\n' "$out" | grep -c -- '--- PASS: FuzzHandlers/seed-')"
[ "$ran" -eq "$seeds" ] || { echo "B1038: FAIL: $ran of $seeds FuzzHandlers seeds ran"; exit 1; }
echo "B1038: PASS"
