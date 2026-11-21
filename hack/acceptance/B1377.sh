#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Guest kernel and initramfs from the cluster store: the server publishes
# its verified pair to its own registry, and a worker fetches it from there
# by the pin's digests, never from the release host.
#
#   .1  runtimed pkg/guestartifacts: the pair is ensured from the cluster
#       store by the pinned digests.
#   .2  runtimed pkg/guestartifacts: a blob from the store whose digest is
#       not the pin's is refused.
#   .3  pkg/registrysvc: the server publishes the pair as the guest
#       repository's pin tag, with the guest artifactType and the pin's digests
#       as its layers, and a re-publish uploads nothing and rewrites no tag.
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

echo "==> $GATE acceptance (guest artifacts from the cluster store)"

b0=ok
bash -n "$SELF" || b0=no
for f in pkg/registrysvc/guestpublish.go pkg/provider/guestartifacts.go; do
	[ -f "$K3SM_ROOT/$f" ] || b0=no
done
runtimed="$(sibling_dir "$K3SM_ROOT" k3sm.io/runtimed)" || {
	echo "    k3sm.io/runtimed does not resolve to a workspace checkout; run with GOWORK naming a go.work that uses ../runtimed" >&2
	b0=no
}
ladder "$b0" "$GATE.0  gate parses (bash -n), the publisher exists, runtimed resolves through go.work${runtimed:+ ($runtimed)}"
if [ "$b0" != ok ]; then
	echo "$GATE: $PASS passed, $FAIL failed, $PENDING pending" >&2
	exit 1
fi

ladder "$(run "$runtimed" ./pkg/guestartifacts/ TestEnsureFromClusterStoreByPinnedDigest)" "$GATE.1  runtimed guestartifacts: ensured from the cluster store by the pinned digests"
ladder "$(run "$runtimed" ./pkg/guestartifacts/ TestWrongDigestFromStoreRefused)" "$GATE.2  runtimed guestartifacts: a wrong digest from the store is refused"
ladder "$(run "$K3SM_ROOT" ./pkg/registrysvc/ TestServerPublishesGuestArtifacts)" "$GATE.3  registrysvc: the server publishes the pair, idempotently"
ladder "$(run "$runtimed" ./pkg/runtime/ TestGuestClusterStorePullsThroughTheRuntimeCache)" "$GATE.4  runtimed runtime: the guest store pulls through the runtime's own cache"
ladder "$(run "$K3SM_ROOT" ./pkg/provider/ TestEnsureGuestArtifactsFromClusterStore)" "$GATE.5  provider: a worker ensures the pair from the cluster store, no release-host fetch"
ladder "$(run "$K3SM_ROOT" ./pkg/provider/ TestNewRuntimedGuestFromClusterStore)" "$GATE.6  provider: the real runtime takes the store's pair after start"

echo "----------------------------------------"
echo "$GATE: $PASS passed, $FAIL failed, $PENDING pending"
[ "$FAIL" = 0 ] || exit 1
[ "$PENDING" = 0 ] || { echo "$GATE: PENDING: not a pass" >&2; exit 3; }
