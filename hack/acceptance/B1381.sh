#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Wasm modules as artifacts: the CNCF wasm OCI artifact (config
# application/vnd.wasm.config.v0+json, layer application/wasm) is fetched
# through runtimed's PullArtifact, and a wasm artifact carrying any other
# layer type is refused.
#
#   b1381.1  runtimed pkg/artifact: a wasm module is accepted, with or without
#            an artifactType, and recorded under the wasm config type; the
#            model allow-set is unchanged beside it.
#   b1381.2  runtimed pkg/artifact: a non-wasm layer in a wasm artifact,
#            alone or beside a module, is refused with a typed error before
#            any blob is fetched; a wasm manifest with no layer is refused.
#
# Unit tests only, under -race: no cluster, no network, no privilege. A
# listed test that does not exist yet is PENDING, not a pass. The runtimed
# rows run in the sibling checkout the k3sm module resolves through go.work.
#
# Usage: B1381.sh --check
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING (everything present passed, and at
# least one listed test does not exist yet).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B1381.sh"
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

echo "==> B1381 acceptance (wasm modules as artifacts)"

b0=ok
runtimed=""
bash -n "$SELF" || b0=no
runtimed="$(sibling_dir "$K3SM_ROOT" k3sm.io/runtimed)" || { echo "    k3sm.io/runtimed does not resolve to a workspace checkout; run with GOWORK naming a go.work that uses ../runtimed" >&2; b0=no; }
[ -z "$runtimed" ] || [ -f "$runtimed/pkg/artifact/artifact.go" ] || b0=no
ladder "$b0" "b1381.0  gate parses (bash -n), runtimed resolves through go.work, pkg/artifact exists${runtimed:+ ($runtimed)}"
if [ "$b0" != ok ]; then
	echo "B1381: $PASS passed, $FAIL failed, $PENDING pending" >&2
	exit 1
fi

ladder "$(run "$runtimed" ./pkg/artifact/ TestPullArtifactAcceptsWasmModule)" "b1381.1  runtimed artifact: a wasm module is accepted; the model allow-set is unchanged"
ladder "$(run "$runtimed" ./pkg/artifact/ TestWasmArtifactRefusesNonWasmLayer)" "b1381.2  runtimed artifact: a non-wasm layer in a wasm artifact is refused, typed"

echo "----------------------------------------"
echo "B1381: $PASS passed, $FAIL failed, $PENDING pending"
if [ "$FAIL" != 0 ]; then exit 1; fi
if [ "$PENDING" != 0 ]; then echo "B1381: PENDING: not a pass" >&2; exit 3; fi
exit 0
