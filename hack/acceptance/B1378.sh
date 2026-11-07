#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Image pulls on the server node clone blobs from the cluster registry's own
# store when it sits on the same volume as the runtime's cache, and fetch
# them otherwise. The cache never trusts the registry's file: it clones the
# descriptor and re-hashes its own clone.
#
#   .1  runtimed pkg/image: a blob in the local store is cloned into the
#       cache and re-hashed before it is committed.
#   .2  runtimed pkg/image: a local copy whose bytes contradict the
#       digest is refused.
#   .3  runtimed pkg/image: a local store on another volume falls back
#       to the normal pull.
#   .4  runtimed pkg/runtime: Config.LocalBlobSource reaches the puller.
#   .5  pkg/ociregistry/store: the store's local blob source opens a
#       blob read-only, through the store's layout, without a lock.
#   .6  pkg/ociregistry/store: an invalid digest, a symlink and a
#       non-regular file are refused; a missing blob or store is "not
#       local".
#   .7  pkg/provider: a server's runtime config carries the source; one
#       that names no registry store (an agent) carries none.
#   .8  cmd/k3sm: the started registry's store root reaches only the
#       server's runtime config, never an agent's.
#   .9  pkg/install: the state tree creates the image cache's clone staging
#       dir for the service user at 0700, which the runtime cannot create
#       under the root-owned data root and refuses at any other mode.
#
# Unit tests only, under -race: no cluster, no network, no privilege. A
# listed test that does not exist yet is PENDING, not a pass. The runtimed
# rows run in the sibling checkout the k3sm module resolves through go.work.
#
# Usage: <this script> --check | --self-test
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING (everything present passed, and at
# least one listed test does not exist yet).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/$(basename "$0")"
GATE="$(basename "$0" .sh)"
export CGO_ENABLED=1

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

# verdict PASS FAIL PENDING: the exit code the ladder ends on.
verdict() {
	if [ "$2" != 0 ]; then echo 1
	elif [ "$3" != 0 ]; then echo 3
	else echo 0
	fi
}

check() {
	echo "==> $GATE acceptance (server pulls clone blobs from the local registry store)"

	local b0=ok runtimed
	bash -n "$SELF" || b0=no
	for f in pkg/ociregistry/store/localblob.go pkg/provider/runtimed.go; do
		[ -f "$K3SM_ROOT/$f" ] || b0=no
	done
	runtimed="$(sibling_dir "$K3SM_ROOT" k3sm.io/runtimed)" || { echo "    k3sm.io/runtimed does not resolve to a workspace checkout; run with GOWORK naming a go.work that uses ../runtimed" >&2; b0=no; }
	ladder "$b0" "$GATE.0  gate parses (bash -n), the source exists, runtimed resolves through go.work${runtimed:+ ($runtimed)}"
	if [ "$b0" != ok ]; then
		echo "$GATE: $PASS passed, $FAIL failed, $PENDING pending" >&2
		exit 1
	fi

	ladder "$(run "$runtimed" ./pkg/image/ TestCommitFromLocalStoreClonesAndRehashes)" "$GATE.1  runtimed image: a local-store blob is cloned and re-hashed"
	ladder "$(run "$runtimed" ./pkg/image/ TestLocalStoreTamperedBlobRefused)" "$GATE.2  runtimed image: a tampered local copy is refused"
	ladder "$(run "$runtimed" ./pkg/image/ TestCrossVolumeFallsBackToPull)" "$GATE.3  runtimed image: another volume falls back to the pull"
	ladder "$(run "$runtimed" ./pkg/runtime/ TestConfigLocalBlobSourceReachesThePuller)" "$GATE.4  runtimed runtime: Config.LocalBlobSource reaches the puller"
	ladder "$(run "$K3SM_ROOT" ./pkg/ociregistry/store/ TestLocalBlobSourceOpensStoreBlob)" "$GATE.5  store: the blob is opened read-only through the layout, no lock taken"
	ladder "$(run "$K3SM_ROOT" ./pkg/ociregistry/store/ TestLocalBlobSourceRefusesBadDigestAndSymlink TestLocalBlobSourceMissingIsNotLocal)" "$GATE.6  store: bad digest, symlink, non-regular refused; missing is not local"
	ladder "$(run "$K3SM_ROOT" ./pkg/provider/ TestServerRuntimedConfigCarriesLocalBlobSource TestAgentRuntimedConfigHasNoLocalBlobSource)" "$GATE.7  provider: the server config carries the source, an agent's does not"
	ladder "$(run "$K3SM_ROOT" ./cmd/k3sm/ TestRegistryStoreRootReachesOnlyTheServerRuntime)" "$GATE.8  cmd/k3sm: the store root reaches only the server's runtime"
	ladder "$(run "$K3SM_ROOT" ./pkg/install/ TestStateTreeCoversRuntimedTrees TestStateTreeRuntimeTreeModes)" "$GATE.9  install: the clone staging dir is a service-user 0700 state-tree row"

	echo "----------------------------------------"
	echo "$GATE: $PASS passed, $FAIL failed, $PENDING pending"
	local rc
	rc="$(verdict "$PASS" "$FAIL" "$PENDING")"
	[ "$rc" != 3 ] || echo "$GATE: PENDING: not a pass" >&2
	exit "$rc"
}

# self_test proves the helpers over a throwaway workspace of two stub modules:
# run's ok, no and pending answers, sibling_dir through go.work and its refusal
# without one, and the exit-code mapping. Offline: the stubs import nothing.
self_test() {
	echo "==> $GATE self-test"
	local tmp ws bad=0 gover sib
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' RETURN
	gover="$(go env GOVERSION)"; gover="${gover#go}"; gover="${gover%%[!0-9.]*}"
	export GOTOOLCHAIN=local
	mkdir -p "$tmp/k3sm/pkg/a" "$tmp/k3sm/pkg/broken" "$tmp/runtimed/pkg/b"
	printf 'module k3sm.io/k3sm\n\ngo %s\n' "$gover" >"$tmp/k3sm/go.mod"
	printf 'module k3sm.io/runtimed\n\ngo %s\n' "$gover" >"$tmp/runtimed/go.mod"
	printf 'go %s\n\nuse (\n\t./k3sm\n\t./runtimed\n)\n' "$gover" >"$tmp/go.work"
	cat >"$tmp/k3sm/pkg/a/a_test.go" <<'GO'
package a

import "testing"

func TestGreen(t *testing.T) {}

func TestRed(t *testing.T) { t.Fatal("red") }
GO
	printf 'package broken\n\nfunc F() int { return "x" }\n' >"$tmp/k3sm/pkg/broken/broken.go"
	printf 'package broken\n\nimport "testing"\n\nfunc TestGreen(t *testing.T) {}\n' >"$tmp/k3sm/pkg/broken/broken_test.go"
	printf 'package b\n\nimport "testing"\n\nfunc TestSibling(t *testing.T) {}\n' >"$tmp/runtimed/pkg/b/b_test.go"

	expect() {
		if [ "$2" = "$3" ]; then echo "ok    $1"; else echo "FAIL  $1: got '$2', want '$3'"; bad=1; fi
	}
	ws="$tmp/go.work"
	expect "run: a present passing test is ok" "$(GOWORK="$ws" run "$tmp/k3sm" ./pkg/a/ TestGreen)" ok
	expect "run: a present failing test is no" "$(GOWORK="$ws" run "$tmp/k3sm" ./pkg/a/ TestRed)" no
	expect "run: an absent test is pending" "$(GOWORK="$ws" run "$tmp/k3sm" ./pkg/a/ TestAbsent)" pending
	expect "run: one absent among present is pending" "$(GOWORK="$ws" run "$tmp/k3sm" ./pkg/a/ TestGreen TestAbsent)" pending
	expect "run: a passing and a failing test together is no" "$(GOWORK="$ws" run "$tmp/k3sm" ./pkg/a/ TestGreen TestRed)" no
	expect "run: a package that does not build is no" "$(GOWORK="$ws" run "$tmp/k3sm" ./pkg/broken/ TestGreen)" no
	expect "run: an absent package is no" "$(GOWORK="$ws" run "$tmp/k3sm" ./pkg/missing/ TestGreen)" no
	sib="$(GOWORK="$ws" sibling_dir "$tmp/k3sm" k3sm.io/runtimed || echo REFUSED)"
	expect "sibling_dir: go.work resolves the sibling checkout" "$(cd "$sib" 2>/dev/null && pwd -P)" "$(cd "$tmp/runtimed" && pwd -P)"
	expect "run: a sibling test runs in the sibling module" "$(GOWORK="$ws" run "$sib" ./pkg/b/ TestSibling)" ok
	expect "sibling_dir: no go.work, no sibling: refused" "$(GOWORK=off sibling_dir "$tmp/k3sm" k3sm.io/runtimed || echo REFUSED)" REFUSED
	expect "verdict: all passed is 0" "$(verdict 3 0 0)" 0
	expect "verdict: any failure is 1, even beside pending" "$(verdict 1 1 2)" 1
	expect "verdict: pending with no failure is 3" "$(verdict 3 0 3)" 3

	if [ "$bad" = 0 ]; then echo "$GATE self-test: green"; else echo "$GATE self-test: RED"; exit 1; fi
}

case "${1:-}:$#" in
--check:1) check ;;
--self-test:1) self_test ;;
*) echo "usage: $0 --check | --self-test" >&2; exit 2 ;;
esac
