#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Model variants: quantizations of one model are separate artifact manifests
# joined by an OCI image index, each entry annotated io.k3sm.model.variant,
# and an MLXModel's spec.quantization selects one.
#
#   b1380.1  runtimed pkg/artifact: a pull with a variant selects the matching
#            index entry.
#   b1380.2  runtimed pkg/artifact: zero or two matching entries are refused.
#   b1380.3  apis config/crd: spec.quantization is admitted with
#            spec.artifact.
#   b1380.4  pkg/modelpack: a variant push adds or replaces its index entry
#            and keeps the others; a plain manifest at the tag is refused.
#   b1380.5  pkg/mlx/operator: spec.quantization records the selected
#            manifest's digest; zero or two matches, a single manifest with
#            quantization and an index without it are InvalidSpec.
#
# Unit tests only, under -race: no cluster, no network, no privilege. A
# listed test that does not exist yet is PENDING, not a pass. The runtimed
# and apis rows run in the sibling checkouts the k3sm module resolves through
# go.work.
#
# Usage: B1380.sh --check | --self-test
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING (everything present passed, and at
# least one listed test does not exist yet).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B1380.sh"
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
	echo "==> B1380 acceptance (model variants)"

	local b0=ok runtimed apis
	bash -n "$SELF" || b0=no
	[ -f "$K3SM_ROOT/pkg/modelpack/variant.go" ] || b0=no
	runtimed="$(sibling_dir "$K3SM_ROOT" k3sm.io/runtimed)" || { echo "    k3sm.io/runtimed does not resolve to a workspace checkout; run with GOWORK naming a go.work that uses ../runtimed" >&2; b0=no; }
	apis="$(sibling_dir "$K3SM_ROOT" k3sm.io/apis)" || { echo "    k3sm.io/apis does not resolve to a workspace checkout; run with GOWORK naming a go.work that uses ../apis" >&2; b0=no; }
	ladder "$b0" "b1380.0  gate parses (bash -n), pkg/modelpack/variant.go exists, runtimed and apis resolve through go.work"
	if [ "$b0" != ok ]; then
		echo "B1380: $PASS passed, $FAIL failed, $PENDING pending" >&2
		exit 1
	fi

	ladder "$(run "$runtimed" ./pkg/artifact/ TestPullArtifactSelectsVariant)" "b1380.1  runtimed artifact: a variant pull selects the matching index entry"
	ladder "$(run "$runtimed" ./pkg/artifact/ TestVariantSelectorZeroOrTwoMatchesRefused)" "b1380.2  runtimed artifact: zero or two matching entries are refused"
	ladder "$(run "$apis" ./config/crd/ TestQuantizationAllowedWithArtifact)" "b1380.3  apis crd: spec.quantization is admitted with spec.artifact"
	ladder "$(run "$K3SM_ROOT" ./pkg/modelpack/ TestPushVariantUpdatesIndex)" "b1380.4  modelpack: a variant push updates the index; a plain manifest is refused"
	ladder "$(run "$K3SM_ROOT" ./pkg/mlx/operator/ TestResolveArtifactVariant)" "b1380.5  mlx operator: spec.quantization records the selected manifest; refusals are InvalidSpec"

	echo "----------------------------------------"
	echo "B1380: $PASS passed, $FAIL failed, $PENDING pending"
	local rc
	rc="$(verdict "$PASS" "$FAIL" "$PENDING")"
	[ "$rc" != 3 ] || echo "B1380: PENDING: not a pass" >&2
	exit "$rc"
}

# self_test proves the helpers over a throwaway workspace of two stub modules:
# run's ok, no and pending answers, sibling_dir through go.work and its refusal
# without one, and the exit-code mapping. Offline: the stubs import nothing.
self_test() {
	echo "==> B1380 self-test"
	local tmp ws bad=0 gover sib
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' RETURN
	gover="$(go env GOVERSION)"; gover="${gover#go}"; gover="${gover%%[!0-9.]*}"
	export GOTOOLCHAIN=local
	mkdir -p "$tmp/k3sm/pkg/a" "$tmp/k3sm/pkg/broken" "$tmp/runtimed/pkg/b" "$tmp/apis/config/crd"
	printf 'module k3sm.io/k3sm\n\ngo %s\n' "$gover" >"$tmp/k3sm/go.mod"
	printf 'module k3sm.io/runtimed\n\ngo %s\n' "$gover" >"$tmp/runtimed/go.mod"
	printf 'module k3sm.io/apis\n\ngo %s\n' "$gover" >"$tmp/apis/go.mod"
	printf 'go %s\n\nuse (\n\t./apis\n\t./k3sm\n\t./runtimed\n)\n' "$gover" >"$tmp/go.work"
	cat >"$tmp/k3sm/pkg/a/a_test.go" <<'GO'
package a

import "testing"

func TestGreen(t *testing.T) {}

func TestRed(t *testing.T) { t.Fatal("red") }
GO
	printf 'package broken\n\nfunc F() int { return "x" }\n' >"$tmp/k3sm/pkg/broken/broken.go"
	printf 'package broken\n\nimport "testing"\n\nfunc TestGreen(t *testing.T) {}\n' >"$tmp/k3sm/pkg/broken/broken_test.go"
	printf 'package b\n\nimport "testing"\n\nfunc TestSibling(t *testing.T) {}\n' >"$tmp/runtimed/pkg/b/b_test.go"
	printf 'package crd\n\nimport "testing"\n\nfunc TestCRD(t *testing.T) {}\n' >"$tmp/apis/config/crd/crd_test.go"

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
	sib="$(GOWORK="$ws" sibling_dir "$tmp/k3sm" k3sm.io/apis || echo REFUSED)"
	expect "sibling_dir: go.work resolves a second sibling (apis)" "$(cd "$sib" 2>/dev/null && pwd -P)" "$(cd "$tmp/apis" && pwd -P)"
	expect "run: a test in the second sibling runs there" "$(GOWORK="$ws" run "$sib" ./config/crd/ TestCRD)" ok
	expect "sibling_dir: a module go.work does not use: refused" "$(GOWORK="$ws" sibling_dir "$tmp/k3sm" k3sm.io/absent || echo REFUSED)" REFUSED
	expect "sibling_dir: no go.work, no sibling: refused" "$(GOWORK=off sibling_dir "$tmp/k3sm" k3sm.io/runtimed || echo REFUSED)" REFUSED
	expect "verdict: all passed is 0" "$(verdict 3 0 0)" 0
	expect "verdict: any failure is 1, even beside pending" "$(verdict 1 1 2)" 1
	expect "verdict: pending with no failure is 3" "$(verdict 3 0 3)" 3

	if [ "$bad" = 0 ]; then echo "B1380 self-test: green"; else echo "B1380 self-test: RED"; exit 1; fi
}

case "${1:-}:$#" in
--check:1) check ;;
--self-test:1) self_test ;;
*) echo "usage: $0 --check | --self-test" >&2; exit 2 ;;
esac
