#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Garbage collection, quota and node eviction keyed by artifactType.
#
#   .1  pkg/ociregistry/gc: a retention class per artifactType keeps an
#       untagged manifest of its type longer, and only longer.
#   .2  pkg/ociregistry/api: a manifest PUT over its type's quota is refused
#       with DENIED and writes no row.
#   .3  pkg/ociregistry/api: a blob two manifests share counts once.
#   .4  runtimed pkg/image: reclaim under pressure evicts unreferenced
#       artifacts before unreferenced images.
#   .5  runtimed pkg/image: the store reports its bytes per class.
#
# Unit tests only, under -race: no cluster, no network, no privilege. A
# listed test that does not exist yet is PENDING, not a pass. The runtimed
# rows run in the sibling checkout the k3sm module resolves through go.work.
#
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING (everything present passed, and at
# least one listed test does not exist yet).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/$(basename "$0")"
GATE="$(basename "$0" .sh)"
export CGO_ENABLED=1

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

PASS=0; FAIL=0; PENDING=0
ladder() {
	case "$1" in
	ok) echo "PASS     $2"; PASS=$((PASS+1)) ;;
	pending) echo "PENDING  $2"; PENDING=$((PENDING+1)) ;;
	*) echo "FAIL     $2"; FAIL=$((FAIL+1)) ;;
	esac
}

# run DIR PKG NAME...: pending when any named test is not in PKG yet, else the
# result of running exactly those tests under -race. DIR is the module root
# the package path is relative to.
run() {
	local dir="$1" pkg="$2"; shift 2
	local listed n re
	listed="$(cd "$dir" && go test -list '.*' "$pkg" 2>/dev/null)" || { echo no; return; }
	for n in "$@"; do grep -qx "$n" <<<"$listed" || { echo pending; return; }; done
	re="^($(IFS='|'; echo "$*"))\$"
	( cd "$dir" && go test -race -count=1 -run "$re" "$pkg" >/dev/null 2>&1 ) && echo ok || echo no
}

# sibling_dir FROM MODULE: the directory MODULE resolves to from the module at
# FROM, which is the workspace checkout when go.work names it. A resolution
# into the module cache is refused: the cache holds the pinned release, not the
# sibling's working tree, so its missing tests would read as PENDING forever.
sibling_dir() {
	local from="$1" module="$2" dir cache
	dir="$(cd "$from" && go list -m -f '{{.Dir}}' "$module" 2>/dev/null)" || return 1
	[ -n "$dir" ] || return 1
	cache="$(go env GOMODCACHE)"
	case "$dir" in "$cache"/*) return 1 ;; esac
	printf '%s\n' "$dir"
}

echo "==> $GATE acceptance (gc, quota and eviction by artifactType)"

b0=ok
bash -n "$SELF" || b0=no
for f in pkg/ociregistry/gc/gc.go pkg/ociregistry/api/manifests.go pkg/registrysvc/serveconfig.go; do
	[ -f "$K3SM_ROOT/$f" ] || b0=no
done
runtimed="$(sibling_dir "$K3SM_ROOT" k3sm.io/runtimed)" || {
	echo "    k3sm.io/runtimed does not resolve to a workspace checkout; run with GOWORK naming a go.work that uses ../runtimed" >&2
	b0=no
}
ladder "$b0" "$GATE.0  gate parses (bash -n), the registry packages exist, runtimed resolves through go.work${runtimed:+ ($runtimed)}"
if [ "$b0" != ok ]; then
	echo "$GATE: $PASS passed, $FAIL failed, $PENDING pending" >&2
	exit 1
fi

ladder "$(run "$K3SM_ROOT" ./pkg/ociregistry/gc/ TestRetentionByArtifactType)" "$GATE.1  gc: a retention class per artifactType"
ladder "$(run "$K3SM_ROOT" ./pkg/ociregistry/api/ TestQuotaRefusesPushOverLimit)" "$GATE.2  api: a push over the quota is refused with DENIED"
ladder "$(run "$K3SM_ROOT" ./pkg/ociregistry/api/ TestQuotaCountsDedupedBlobOnce)" "$GATE.3  api: a deduped blob counts once"
ladder "$(run "$runtimed" ./pkg/image/ TestReclaimEvictsUnreferencedArtifactsFirst)" "$GATE.4  runtimed image: unreferenced artifacts are evicted first"
ladder "$(run "$runtimed" ./pkg/image/ TestStoreBytesByClass)" "$GATE.5  runtimed image: store bytes by class"

echo "----------------------------------------"
echo "$GATE: $PASS passed, $FAIL failed, $PENDING pending"
[ "$FAIL" = 0 ] || exit 1
[ "$PENDING" = 0 ] || { echo "$GATE: PENDING: not a pass" >&2; exit 3; }
