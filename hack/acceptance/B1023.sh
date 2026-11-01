#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Image prune reads the registry through the store and deletes through the server.
#
# --check runs, in pkg/registrysvc:
#   TestPruneThroughTheStore  the plan reads the layout only through
#                             pkg/ociregistry/store, read-only: a tagged digest is
#                             never deleted, an untagged index is deleted before the
#                             manifests it names, planning writes nothing, a planned
#                             digest a push tags or re-pushes before its delete is
#                             re-checked out of it, and prune rounds run concurrently
#                             with a push without losing the pushed tag; the deletes
#                             there go to a fake DELETE handler backed by the store,
#                             not to the real registry server
# then, in cmd/k3sm:
#   TestImagePruneRechecksEachPlannedDigestBeforeItsDelete  the command's delete loop
#                             skips a planned digest tagged between plan and DELETE
# then the registrysvc and store package tests, all under -race, and asserts
# prune.go opens no layout file itself.
#
# Usage: hack/acceptance/B1023.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1

# One parser: prune.go reads through the store, never the filesystem.
if grep -nE '"(os|io/fs|path/filepath|regexp)"|index\.json"|"blobs"' pkg/registrysvc/prune.go; then
	echo "B1023: FAIL: prune.go reads the layout itself"; exit 1
fi
grep -q 'store.OpenReader' pkg/registrysvc/prune.go || { echo "B1023: FAIL: prune.go does not read through the store"; exit 1; }

out="$(go test -race -count=1 -v -run '^TestPruneThroughTheStore$' ./pkg/registrysvc/ 2>&1)" || {
	printf '%s\n' "$out"; echo "B1023: FAIL: prune tests"; exit 1; }
printf '%s\n' "$out" | grep -E '^(--- |    --- |ok|PASS)'
# A test that does not run is not a pass.
for t in 'TestPruneThroughTheStore' \
	'TestPruneThroughTheStore/a_tagged_digest_is_never_deleted' \
	'TestPruneThroughTheStore/an_untagged_index_is_deleted_before_the_manifests_it_names' \
	'TestPruneThroughTheStore/planning_writes_nothing' \
	'TestPruneThroughTheStore/a_planned_digest_tagged_or_re-pushed_before_its_delete_is_re-checked_out' \
	'TestPruneThroughTheStore/a_prune_concurrent_with_a_push_does_not_lose_the_pushed_tag'; do
	grep -q -- "--- PASS: $t" <<<"$out" || { echo "B1023: FAIL: $t did not run"; exit 1; }
done
out="$(go test -race -count=1 -v -run '^TestImagePruneRechecksEachPlannedDigestBeforeItsDelete$' ./cmd/k3sm/ 2>&1)" || {
	printf '%s\n' "$out"; echo "B1023: FAIL: prune re-check test"; exit 1; }
grep -q -- '--- PASS: TestImagePruneRechecksEachPlannedDigestBeforeItsDelete' <<<"$out" || {
	echo "B1023: FAIL: TestImagePruneRechecksEachPlannedDigestBeforeItsDelete did not run"; exit 1; }
go test -race -count=1 ./pkg/registrysvc/ ./pkg/ociregistry/store/ || { echo "B1023: FAIL: package tests"; exit 1; }
echo "B1023: PASS"
