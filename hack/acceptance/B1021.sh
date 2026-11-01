#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The k3sm registry server passes the OCI distribution-spec conformance suite.
#
# --run (needs the module proxy or a warm module cache for the build; the run
# itself has no network):
#   b1021.run.1  hack/ociconformance.sh builds the pinned suite and the server
#                launcher, then runs all four areas (pull, push, content
#                discovery, content management) against a fresh server, as the
#                k3sm principal with a credential minted for the run, in an
#                empty environment. Network confinement is proved before the
#                run: with sandbox-exec usable, connects to two public
#                addresses and the LAN gateway are refused (EPERM) under the
#                loopback-only profile and a DNS lookup fails; where
#                sandbox-exec cannot nest, the same probes must be refused by
#                the enclosing sandbox, and an unreachable network is not
#                accepted in place of a denied one. The logs are scanned for
#                the credential, its Basic form and any Authorization header
#                before anything is printed or kept
#   b1021.run.2  no spec failed and the suite exited zero
#   b1021.run.3  the skipped specs are exactly EXPECTED_SKIPS, the five this
#                server produces, and each one's either-or partner passed in
#                the same run; any other skip set is red
#   b1021.run.4  each area passed at least its floor of specs (MIN_* below)
#
# --check (offline):
#   b1021.1  hack/deps-ociconformance.lock exists, names the suite at the pin
#            hack/ociconformance.sh builds, and lists exactly the modules
#            hack/ociconformance/go.sum.txt hashes the source of
#   b1021.2  hack/verify-deps.sh screens that go.sum through that lock (its
#            WRAPPERS table)
#   b1021.3  the scripts are sane: both parse, the pin in hack/ociconformance.sh
#            is the one go.mod.txt requires, neither of those two names
#            @latest, and neither script sets
#            GOSUMDB, GOPROXY, GONOSUMDB, GOPRIVATE, GOINSECURE or GOFLAGS
#   b1021.4  the shipped binaries link no Ginkgo, Gomega, reggie or conformance
#            package (`go list -deps` of every cmd/ main); a self-check plants a
#            Ginkgo package in a dependency list and requires the matcher to red
#   b1021.5  no release-built binary links the conformance launcher
#            (k3sm.io/k3sm/hack/ociconformance/...): `go list -deps` of every
#            main hack/release/stage.sh builds, which must include ./cmd/k3sm;
#            a self-check plants the launcher and requires the matcher to red
#   b1021.6  every EXPECTED_SKIPS entry is the skipped branch of an EITHER_OR
#            pair, and every pair's skipped branch is in EXPECTED_SKIPS
#
# Usage: hack/acceptance/B1021.sh --check | --run [--report <dir>]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
cd "$K3SM_ROOT"
export CGO_ENABLED=1

LOCK=hack/deps-ociconformance.lock
SUM=hack/ociconformance/go.sum.txt
GOMOD=hack/ociconformance/go.mod.txt
TOOL=hack/ociconformance.sh
MODULE=github.com/opencontainers/distribution-spec/conformance

# The passed-spec floors per area: exactly what the pinned suite runs with
# every area enabled (74 of its 79 specs; the other 5 are EXPECTED_SKIPS). A
# pin bump re-derives them from a green run.
MIN_PULL=23
MIN_PUSH=27
MIN_DISCOVERY=15
MIN_MANAGEMENT=9

# The either-or branches: "<skipped spec>|<partner that must have passed>".
# The suite decides each pair at run time, so one side always skips.
EITHER_OR='Pull Setup Get tag name from environment|Pull Setup Populate registry with test manifest
Push Cross-Repository Blob Mount Cross-mounting of nonexistent blob should yield session id|Push Cross-Repository Blob Mount POST request to mount another repository'"'"'s blob should return 201 or 202
Push Cross-Repository Blob Mount Cross-mounting without from, and automatic content discovery enabled should return a 201|Push Cross-Repository Blob Mount Cross-mounting without from, and automatic content discovery disabled should return a 202
Content Discovery Setup Populate registry with test tags (no push)|Content Discovery Setup Populate registry with test tags
Content Management Blob delete GET request to deleted blob URL should yield 404 response|Content Management Blob delete DELETE request to blob URL should yield 202 response'

# EXPECTED_SKIPS is the exact skip set this server produces with the run's
# settings. The partner check alone is not enough: the suite's blob DELETE
# spec passes on 202, 404 or 405 (04_management_test.go:160-174), and only a
# 405 skips the GET after it, so a passed partner does not say which branch
# the server took. This server answers 405 (blobs are removed by garbage
# collection), so the GET skip is pinned here, and a server that started
# answering 202 or 404 changes the set and reds. The same holds for the
# cross-mount pairs, decided by OCI_AUTOMATIC_CROSSMOUNT=0 and the mount's
# 201 or 202. A pin bump or a server change re-derives this from a green run.
EXPECTED_SKIPS='Content Discovery Setup Populate registry with test tags (no push)
Content Management Blob delete GET request to deleted blob URL should yield 404 response
Pull Setup Get tag name from environment
Push Cross-Repository Blob Mount Cross-mounting of nonexistent blob should yield session id
Push Cross-Repository Blob Mount Cross-mounting without from, and automatic content discovery enabled should return a 201'

# RELEASE_BUILDS is where the release mains are read from.
RELEASE_BUILDS=hack/release/stage.sh

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
finish() {
	echo "B1021: $PASS passed, $FAIL failed"
	[ "$FAIL" = 0 ]
}

usage() { echo "usage: $0 --check | --run [--report <dir>]" >&2; exit 2; }

# forbidden_deps: read a dependency list on stdin, print each package the
# shipped binaries must not link.
forbidden_deps() {
	grep -E '^(github\.com/onsi/(ginkgo|gomega)(/|$)|github\.com/bloodorangeio/reggie(/|$)|github\.com/opencontainers/distribution-spec/conformance(/|$))' || true
}

# launcher_deps: read a dependency list on stdin, print each package of the
# conformance launcher tree.
launcher_deps() {
	grep -E '^k3sm\.io/k3sm/hack/ociconformance(/|$)' || true
}

# release_mains: the main packages hack/release/stage.sh passes to go build,
# one per line, ./cmd/<x> or k3sm.io/<repo>/cmd/<x>.
release_mains() {
	sed -nE 's/^[[:space:]]*\( cd "[^"]*" && go build .* (\.\/cmd\/[A-Za-z0-9_-]+|k3sm\.io\/[a-z-]+\/cmd\/[A-Za-z0-9_-]+) \)[[:space:]]*$/\1/p' "$RELEASE_BUILDS" | LC_ALL=C sort -u
}

check() {
	# b1021.1
	local pin
	pin="$(sed -n 's/^PIN=//p' "$TOOL")"
	if [ -s "$LOCK" ] && [ -s "$SUM" ] && [ -n "$pin" ] &&
		grep -qE "^${MODULE//./\\.} ${pin//./\\.} # " "$LOCK" &&
		diff <(grep -v '^#' "$LOCK" | awk '{print $1, $2}' | LC_ALL=C sort -u) \
			<(awk '$2 !~ /\/go\.mod$/ {print $1, $2}' "$SUM" | LC_ALL=C sort -u) >/dev/null; then
		ladder ok "b1021.1 $LOCK names $MODULE $pin and every module $SUM hashes ($(grep -vc '^#' "$LOCK") lines)"
	else
		ladder fail "b1021.1 $LOCK is missing, lacks $MODULE ${pin:-<no PIN>}, or differs from $SUM's modules"
	fi
	# b1021.2
	if grep -qE "^ociconformance $SUM $LOCK(\"|$)" hack/verify-deps.sh; then
		ladder ok "b1021.2 hack/verify-deps.sh screens $SUM through $LOCK"
	else
		ladder fail "b1021.2 hack/verify-deps.sh WRAPPERS does not name ociconformance $SUM $LOCK"
	fi
	# b1021.3
	local why=""
	bash -n "$TOOL" || why="$why $TOOL does not parse;"
	bash -n "$0" || why="$why $0 does not parse;"
	grep -qE "^require ${MODULE//./\\.} ${pin//./\\.}\$" "$GOMOD" || why="$why $GOMOD does not require $MODULE ${pin:-<no PIN>};"
	! grep -qE '@latest' "$TOOL" "$GOMOD" || why="$why $TOOL or $GOMOD names @latest;"
	! grep -nE '(^|[^A-Za-z_])(export[[:space:]]+)?(GOSUMDB|GOPROXY|GONOSUMDB|GONOSUMCHECK|GOPRIVATE|GOINSECURE|GOFLAGS)=' "$TOOL" "$0" >/dev/null ||
		why="$why a script sets a Go verification variable;"
	if [ -z "$why" ]; then
		ladder ok "b1021.3 $TOOL and this script parse, pin $pin, no @latest, no verification override"
	else
		ladder fail "b1021.3$why"
	fi
	# b1021.4
	local planted mains deps bad
	planted="$(printf 'k3sm.io/k3sm/pkg/ociregistry/api\ngithub.com/onsi/ginkgo/v2/types\n' | forbidden_deps)"
	mains="$(go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./cmd/... 2>/dev/null)" || mains=""
	if [ -z "$planted" ]; then
		ladder fail "b1021.4 self-check: the matcher missed a planted Ginkgo package"
	elif [ -z "$mains" ]; then
		ladder fail "b1021.4 go list found no cmd/ main package"
	elif ! deps="$(go list -deps $mains)"; then
		ladder fail "b1021.4 go list -deps of the shipped binaries failed"
	else
		bad="$(forbidden_deps <<<"$deps")"
		if [ -z "$bad" ]; then
			ladder ok "b1021.4 the shipped binaries ($(wc -w <<<"$mains" | tr -d ' ') cmd/ mains) link no Ginkgo, Gomega, reggie or conformance package (self-check reds)"
		else
			ladder fail "b1021.4 a shipped binary links: $(paste -sd ' ' - <<<"$bad")"
		fi
	fi
	# b1021.5
	local rmains rdeps rbad
	planted="$(printf 'k3sm.io/k3sm/pkg/ociregistry/api\nk3sm.io/k3sm/hack/ociconformance/serve\n' | launcher_deps)"
	rmains="$(release_mains)"
	if [ -z "$planted" ]; then
		ladder fail "b1021.5 self-check: the matcher missed a planted launcher package"
	elif ! grep -qx '\./cmd/k3sm' <<<"$rmains"; then
		ladder fail "b1021.5 $RELEASE_BUILDS builds no ./cmd/k3sm that this check can read (found: $(paste -sd ' ' - <<<"$rmains"))"
	elif ! rdeps="$(go list -deps $rmains)"; then
		ladder fail "b1021.5 go list -deps of the release mains failed"
	else
		rbad="$(launcher_deps <<<"$rdeps")"
		if [ -z "$rbad" ]; then
			ladder ok "b1021.5 the release mains ($(paste -sd ' ' - <<<"$rmains")) link no hack/ociconformance package (self-check reds)"
		else
			ladder fail "b1021.5 a release main links: $(paste -sd ' ' - <<<"$rbad")"
		fi
	fi
	# b1021.6
	local lefts
	lefts="$(cut -d'|' -f1 <<<"$EITHER_OR" | LC_ALL=C sort)"
	if [ "$lefts" = "$(LC_ALL=C sort <<<"$EXPECTED_SKIPS")" ]; then
		ladder ok "b1021.6 EXPECTED_SKIPS ($(wc -l <<<"$EXPECTED_SKIPS" | tr -d ' ')) is exactly the skipped branches of EITHER_OR"
	else
		ladder fail "b1021.6 EXPECTED_SKIPS and the skipped branches of EITHER_OR differ"
	fi
	finish
}

# tally <junit.xml>: one line per spec, "<status>\t<name>", the suite prefix
# stripped and the reporter nodes dropped.
tally() {
	/usr/bin/python3 -I - "$1" <<'PYEOF'
import sys
import xml.etree.ElementTree as ET
PREFIX = "OCI Distribution Conformance Tests "
for tc in ET.parse(sys.argv[1]).getroot().iter("testcase"):
    name = tc.get("name", "")
    if not name.startswith(PREFIX):
        continue
    status = tc.get("status", "")
    if tc.find("failure") is not None or tc.find("error") is not None:
        status = "failed"
    print(status + "\t" + name[len(PREFIX):])
PYEOF
}

area_of() {
	case "$1" in
	"Pull "*) echo pull ;;
	"Push "*) echo push ;;
	"Content Discovery "*) echo discovery ;;
	"Content Management "*) echo management ;;
	*) echo other ;;
	esac
}

run_suite() {
	local report="$1"
	mkdir -p "$report"
	report="$(cd "$report" && pwd)"
	local bin="$K3SM_ROOT/hack/.ociconformance/bin" rc=0
	bash "$TOOL" build "$bin" || { ladder fail "b1021.run.1 the suite or the launcher did not build"; finish; return; }
	bash "$TOOL" run "$bin" "$report" || rc=$?
	if [ ! -s "$report/junit.xml" ]; then
		ladder fail "b1021.run.1 the run wrote no junit.xml (exit $rc)"
		finish
		return
	fi
	ladder ok "b1021.run.1 the suite ran all four areas against the server as k3sm, loopback only"
	local specs
	specs="$(tally "$report/junit.xml")"
	# b1021.run.2
	local failed
	failed="$(grep -c '^failed' <<<"$specs" || true)"
	if [ "$rc" = 0 ] && [ "$failed" = 0 ]; then
		ladder ok "b1021.run.2 no spec failed, suite exit 0"
	else
		ladder fail "b1021.run.2 $failed specs failed, suite exit $rc:"
		grep '^failed' <<<"$specs" | sed 's/^failed\t/        /' || true
	fi
	# b1021.run.3
	local bad="" name partner pair skipset line
	skipset="$(grep '^skipped' <<<"$specs" | cut -f2- | LC_ALL=C sort || true)"
	if [ "$skipset" != "$(LC_ALL=C sort <<<"$EXPECTED_SKIPS")" ]; then
		bad="$bad"$'\n'"        the skip set is not EXPECTED_SKIPS:"
		while IFS= read -r line; do
			case "$line" in
			"< "*) bad="$bad"$'\n'"        expected, not skipped: ${line#< }" ;;
			"> "*) bad="$bad"$'\n'"        skipped, not expected: ${line#> }" ;;
			esac
		done < <(diff <(LC_ALL=C sort <<<"$EXPECTED_SKIPS") <(printf '%s\n' "$skipset") || true)
	fi
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		partner=""
		while IFS= read -r pair; do
			[ "${pair%%|*}" != "$name" ] || partner="${pair#*|}"
		done <<<"$EITHER_OR"
		if [ -z "$partner" ]; then
			bad="$bad"$'\n'"        skipped: $name"
		elif ! grep -qxF "passed	$partner" <<<"$specs"; then
			bad="$bad"$'\n'"        skipped: $name (its partner did not pass: $partner)"
		fi
	done < <(grep '^skipped' <<<"$specs" | cut -f2-)
	local nskip
	nskip="$(grep -c '^skipped' <<<"$specs" || true)"
	if [ -z "$bad" ]; then
		ladder ok "b1021.run.3 $nskip skips, exactly EXPECTED_SKIPS, each the other branch of an either-or pair whose partner passed"
		sed 's/^/        skipped: /' <<<"$skipset"
	else
		ladder fail "b1021.run.3 unexpected skips:$bad"
	fi
	# b1021.run.4
	local area passed skipped floor line summary="" under=""
	for area in pull push discovery management; do
		passed=0 skipped=0
		while IFS= read -r line; do
			[ -n "$line" ] || continue
			[ "$(area_of "${line#*	}")" = "$area" ] || continue
			case "$line" in
			skipped*) skipped=$((skipped + 1)) ;;
			passed*) passed=$((passed + 1)) ;;
			esac
		done <<<"$specs"
		case "$area" in
		pull) floor=$MIN_PULL ;; push) floor=$MIN_PUSH ;;
		discovery) floor=$MIN_DISCOVERY ;; management) floor=$MIN_MANAGEMENT ;;
		esac
		summary="$summary $area=$passed/${skipped}s"
		[ "$passed" -ge "$floor" ] || under="$under $area $passed<$floor"
	done
	if [ -z "$under" ]; then
		ladder ok "b1021.run.4 passed/skipped per area:$summary (floors $MIN_PULL $MIN_PUSH $MIN_DISCOVERY $MIN_MANAGEMENT)"
	else
		ladder fail "b1021.run.4 under the floor:$under (passed/skipped:$summary)"
	fi
	finish
}

mode="" report="$K3SM_ROOT/hack/.ociconformance/report"
while [ $# -gt 0 ]; do
	case "$1" in
	--check) mode=check; shift ;;
	--run) mode=run; shift ;;
	--report) [ $# -ge 2 ] || usage; report="$2"; shift 2 ;;
	*) usage ;;
	esac
done
case "$mode" in
check) check ;;
run) run_suite "$report" ;;
*) usage ;;
esac
