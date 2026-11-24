#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The keystore's acceptance gate: docs/design/keystore.md § "Acceptance gate",
# rows G1 to G23, the user-scope rows U1 to U137 (U15, U39 and U117 are unused),
# the typed-credential rows U138 to U191, the floor's tombstone row U192, the
# rebuild rows U193 and U194, the rows U195 to U206, and the rig legs E1 to E36. Every row
# is listed, on exactly one line. A row runs
# the tests that deliver it and passes only if each named test ran and passed
# in its own package; a row whose change has not landed yet prints PENDING,
# never PASS. A row delivered in part prints PENDING when its delivered part
# passes, and FAIL when it does not.
#
# A row names its tests as <repo>/<package>::<Test>, a bare name taking the
# package before it (the first defaults to k3sm/pkg/keystore). The repo is k3sm
# itself or a sibling checkout beside it: ../apis, ../runtimed, ../darwin-net.
# Each package runs once, verbose; a named test counts only if its "--- PASS:"
# line appears in that package's output. Rows in runtimed and k3sm run with
# CGO_ENABLED=1 and under -race; rows in ../apis and ../darwin-net run with
# CGO_ENABLED=0 and so without -race (-race needs cgo on darwin), and the run
# prints that it did. CGO is set per package run, never exported. A sibling runs
# through the go.work beside the k3sm root when that file exists; k3sm runs as
# it is. A sibling that is not checked out fails its rows, never skips them.
#
# Exit status: 0 every row passed; 1 a row failed; 3 no row failed but at
# least one is pending. Only --lab judges the rig legs: --check prints each as
# a RIG line and leaves it out of the count and the exit status, so a unit run
# exits 0 without the rig. Phase A is complete when --check exits 0.
#
# Modes. Neither --check nor a unit mode calls sudo.
#   --check         every G and U row; the E rows print as RIG (run --lab). It
#                   runs every package a row names, whole: the keystore package's
#                   tests, the delivery's in ./pkg/keystore/deliver/ (G18 to G20),
#                   and for the CLI rows (G7, G10, G16 to G21) the keys verbs'
#                   tests in ./cmd/k3sm/, named k3sm/cmd/k3sm::<Test> below.
#   --rewrap        Rewrap's rows: G3, G12, G13, G14 and U5.
#   --verbs         the keys verbs: G16, G17, G21, U1.
#   --delivery      the system delivery: G18 to G20.
#   --sandbox       the pod denies and the shared path names: U16, U17, U49, U116.
#   --api           the KeyDelivery API types: U18, U19.
#   --scope         user scopes: U6 to U11, U47, U58, U64, U66, U108, U127, U129, U132.
#   --scope-store   the user-scope store: U12 to U14, U63, U97, U101, U128.
#   --files         the append-only files: U20, U21, U23 to U25, U50, U52, U60, U61,
#                   U68, U80, U88, U90, U91, U105, U118, U119, U193 to U206, and in the helper
#                   variant
#                   only U70, U71.
#   --socket        the socket listener: U26 to U31, U46, U48, U54, U82, U99, U104, U113,
#                   U120, U121, U122, U131, U137.
#   --socket-ops    the socket operations: U32 to U35, U45, U51, U67, U84, U112, U136.
#   --exec          the non-root CLI and exec: U36 to U38, U69, U92.
#   --kd-author     KeyDelivery authoring: U40, U41, U74, U76, U87, U94, U135.
#   --kd-reconcile  the KeyDelivery reconciler: U42, U43, U59, U73, U78, U81, U111.
#   --kd-lifecycle  the KeyDelivery lifecycle: U22, U44, U53, U55, U56, U62, U65,
#                   U72, U75, U77, U79, U83, U85, U86, U89, U93, U95, U96, U98, U100, U102, U103, U106, U107, U109, U110, U114, U115,
#                   U123 to U126, U130, U133, U134, U136.
#   --grammar       the entry grammar in apis: U57.
#   --credential    the typed KeyDelivery API and credential names in apis: U18, U19,
#                   U139 to U142.
#   --typed         the typed store: U143 to U154.
#   --typed-cli     the typed verbs: U155 to U159.
#   --projection    typed projection: U160 to U164.
#   --expiry        expiry and revocation: U165 to U168.
#   --mount-audit   the mount audit: U169 to U174.
#   --refresh-profiles  refresh profiles: U175 to U181.
#   --refresh       the refresher: U182 to U190.
#   --typed-docs    the typed-credential docs: U191.
#   --docs          the user docs: no row yet, so it exits 3.
# A unit mode runs only its rows and only their tests, with the same exit
# status: it exits 0 only when every row it names passes.
#
# --lab runs the rig legs E1 to E36, and nothing else, as an explicit, recorded
# step. --<unit mode> --lab runs that mode's unit rows and then only the legs
# mapped to that mode (the leg's last feature to land, see the leg table); a
# leg mapped to no mode runs only under plain --lab. Each leg's description
# ends "(fails without: <feature>)". It refuses (exit 2) unless K3SM_LAB=1 and
# K3SM_LAB_EVIDENCE names an existing directory. It writes a record file into
# that directory: the date, the mode, the head sha and dirty flag of k3sm and of
# each sibling checkout, the evidence directory, each leg's verdict and the
# final exit status. A leg with no implementation is PENDING.
#
# --listed is a row-presence lint, not proof. It checks that every U and E row
# in EXPECTED_ROWS below exists here, and that every test a row names exists,
# found with go test -list in its package (the same CGO and GOWORK rules as a
# run; grep of the _test.go files only when go test -list cannot build the
# package, marked "(grep fallback)" on that row). A test that does not exist yet
# is MISSING (pending row), which is not a failure while its row is pending; it
# fails a row that is checked. Row L1 holds the security-relevant claims in
# CLAIMS below against the design: each phrase must appear in that row's line
# of the design's gate table and in this script's description of the row, and
# a phrase missing from either fails L1. L1 also holds the test names: for each
# U row, the Test and Fuzz names in the design table's "Validated by" column
# must be exactly the names this script's row runs. Row L2 is the duplicate-id
# lint (U138): it fails on any U or E id that appears twice among this script's
# rows, in EXPECTED_ROWS, in one mode's row list, or among the design's gate and
# leg table rows. Exit status: 0 every row present and
# every named test exists; 3 every row present, some named tests do not exist yet; 1 a row
# is missing or a checked row's test is missing.
#
# --root runs row R1: the package's tests as root, in the deployment's
# shape (root runs the verbs and owns the data root, the service user owns the
# store; the tests take the service user from K3SM_KEYSTORE_TEST_UID and
# K3SM_KEYSTORE_TEST_GID, or the local user _k3sm). It builds the test binary
# as the invoking user and runs only that binary under sudo -n, from the
# package's source directory as go test does, so the tests that read the
# source tree find it; root builds nothing. It passes when
# no test failed and the binary exited 0. It then runs the root-run rows
# (declared with rootpend or rootcheck): each by name, in its own k3sm
# package's binary, built the same way and run the same way. A checked
# root-run row passes only if each named test printed PASS: a SKIP fails it,
# and so does a test that did not run. A pending one prints PENDING. Neither
# --check nor a unit mode runs a root-run row: each prints it as ROOT and
# leaves it out of the count, as pending. Exit status: 0 pass; 1 fail; 3 sudo
# -n is unavailable (run sudo -v first, or run as a user sudo lets run it), or
# nothing failed and a root-run row is pending; 2 the source tree is dirty
# (git status shows any change or untracked file), so it does not start.
#
# G1 diffs go.mod and go.sum against KEYSTORE_BASE (default: the merge base
# with origin/main). KEYSTORE_SKIP_G22=1 marks G22 PENDING instead of running
# hack/ci.sh, for a run inside a sandbox that cannot run it.
#
# Usage: hack/acceptance/keystore.sh --check|--<unit mode> [--lab]|--lab|--listed|--root
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

# The U and E rows the design's gate table lists; --listed checks each is here.
# The design doc is the human reference; this list is what the lint reads.
EXPECTED_ROWS="U1 U2 U3 U4 U5 U6 U7 U8 U9 U10 U11 U12 U13 U14 U16 U17 U18 U19 U20"
EXPECTED_ROWS="$EXPECTED_ROWS U21 U22 U23 U24 U25 U26 U27 U28 U29 U30 U31 U32 U33 U34 U35"
EXPECTED_ROWS="$EXPECTED_ROWS U36 U37 U38 U40 U41 U42 U43 U44 U45 U46 U47 U48"
EXPECTED_ROWS="$EXPECTED_ROWS U49 U50 U51 U52 U53 U54 U55 U56 U57"
EXPECTED_ROWS="$EXPECTED_ROWS U58 U59 U60 U61 U62 U63"
EXPECTED_ROWS="$EXPECTED_ROWS U64 U65 U66 U67 U68 U69 U70 U71"
EXPECTED_ROWS="$EXPECTED_ROWS U72 U73 U74 U75 U76"
EXPECTED_ROWS="$EXPECTED_ROWS U77 U78 U79 U80 U81 U82 U83 U84"
EXPECTED_ROWS="$EXPECTED_ROWS U85 U86 U87 U88 U89 U90 U91 U92 U93 U94 U95 U96 U97"
EXPECTED_ROWS="$EXPECTED_ROWS U98"
EXPECTED_ROWS="$EXPECTED_ROWS U99"
EXPECTED_ROWS="$EXPECTED_ROWS U100"
EXPECTED_ROWS="$EXPECTED_ROWS U101"
EXPECTED_ROWS="$EXPECTED_ROWS U102"
EXPECTED_ROWS="$EXPECTED_ROWS U103"
EXPECTED_ROWS="$EXPECTED_ROWS U104"
EXPECTED_ROWS="$EXPECTED_ROWS U105"
EXPECTED_ROWS="$EXPECTED_ROWS U106"
EXPECTED_ROWS="$EXPECTED_ROWS U107"
EXPECTED_ROWS="$EXPECTED_ROWS U108"
EXPECTED_ROWS="$EXPECTED_ROWS U109"
EXPECTED_ROWS="$EXPECTED_ROWS U110"
EXPECTED_ROWS="$EXPECTED_ROWS U111"
EXPECTED_ROWS="$EXPECTED_ROWS U112"
EXPECTED_ROWS="$EXPECTED_ROWS U113"
EXPECTED_ROWS="$EXPECTED_ROWS U114"
EXPECTED_ROWS="$EXPECTED_ROWS U115"
EXPECTED_ROWS="$EXPECTED_ROWS U116"
EXPECTED_ROWS="$EXPECTED_ROWS U118 U119 U120 U121 U122 U123 U124 U125 U126 U127"
EXPECTED_ROWS="$EXPECTED_ROWS U128 U129 U130 U131 U132 U133 U134 U135 U136 U137"
EXPECTED_ROWS="$EXPECTED_ROWS U138 U139 U140 U141 U142 U143 U144 U145 U146 U147 U148 U149"
EXPECTED_ROWS="$EXPECTED_ROWS U150 U151 U152 U153 U154 U155 U156 U157 U158 U159 U160 U161"
EXPECTED_ROWS="$EXPECTED_ROWS U162 U163 U164 U165 U166 U167 U168 U169 U170 U171 U172 U173"
EXPECTED_ROWS="$EXPECTED_ROWS U174 U175 U176 U177 U178 U179 U180 U181 U182 U183 U184 U185"
EXPECTED_ROWS="$EXPECTED_ROWS U186 U187 U188 U189 U190 U191"
EXPECTED_ROWS="$EXPECTED_ROWS U192"
EXPECTED_ROWS="$EXPECTED_ROWS U193 U194"
EXPECTED_ROWS="$EXPECTED_ROWS U195"
EXPECTED_ROWS="$EXPECTED_ROWS U196 U197 U198 U199 U200 U201 U202 U203 U204 U205 U206"
# >>> ADD NEW U ROWS (U200 upward) HERE <<<
EXPECTED_ROWS="$EXPECTED_ROWS E1 E2 E3 E4 E5 E6 E7 E8 E9 E10 E11 E12 E13 E14 E15 E16 E17 E18 E19 E20"
EXPECTED_ROWS="$EXPECTED_ROWS E21 E22 E23 E24 E25 E26 E27"
EXPECTED_ROWS="$EXPECTED_ROWS E28 E29 E30 E31 E32 E33 E34 E35 E36"
# >>> ADD NEW E LEGS (E37 upward) HERE <<<

MODES="check rewrap verbs delivery sandbox api scope scope-store files socket socket-ops exec"
MODES="$MODES kd-author kd-reconcile kd-lifecycle grammar credential typed typed-cli projection"
MODES="$MODES expiry mount-audit refresh-profiles refresh typed-docs docs lab listed root"

usage() {
	echo "usage: $0 --check|--rewrap|--verbs|--delivery|--sandbox|--api|--scope|--scope-store|--files|--socket|--socket-ops|--exec|--kd-author|--kd-reconcile|--kd-lifecycle|--grammar|--credential|--typed|--typed-cli|--projection|--expiry|--mount-audit|--refresh-profiles|--refresh|--typed-docs|--docs|--lab|--listed|--root" >&2
	echo "       $0 --<unit mode> --lab   (a unit mode's rows, then only its rig legs)" >&2
	exit 2
}
[ $# -ge 1 ] && [ $# -le 2 ] || usage
mode=""
for m in $MODES; do
	if [ "$1" = "--$m" ]; then mode="$m"; fi
done
[ -n "$mode" ] || usage

# mode_rows prints the rows a unit mode runs.
mode_rows() {
	case "$1" in
	rewrap) echo "G3 G12 G13 G14 U5" ;;
	verbs) echo "G16 G17 G21 U1" ;;
	delivery) echo "G18 G19 G20" ;;
	sandbox) echo "U16 U17 U49 U116" ;;
	api) echo "U18 U19" ;;
	scope) echo "U6 U7 U8 U9 U10 U11 U47 U58 U64 U66 U108 U127 U129 U132" ;;
	scope-store) echo "U12 U13 U14 U63 U97 U101 U128" ;;
	files) echo "U20 U21 U23 U24 U25 U50 U52 U60 U61 U68 U70 U71 U80 U88 U90 U91 U105 U118 U119 U193 U194 U195 U196 U197 U198 U199 U200 U201 U202 U203 U204 U205 U206" ;;
	socket) echo "U26 U27 U28 U29 U30 U31 U46 U48 U54 U82 U99 U104 U113 U120 U121 U122 U131 U137" ;;
	socket-ops) echo "U32 U33 U34 U35 U45 U51 U67 U84 U112 U136" ;;
	exec) echo "U36 U37 U38 U69 U92" ;;
	kd-author) echo "U40 U41 U74 U76 U87 U94 U135" ;;
	kd-reconcile) echo "U42 U43 U59 U73 U78 U81 U111" ;;
	kd-lifecycle) echo "U22 U44 U53 U55 U56 U62 U65 U72 U75 U77 U79 U83 U85 U86 U89 U93 U95 U96 U98 U100 U102 U103 U106 U107 U109 U110 U114 U115 U123 U124 U125 U126 U130 U133 U134 U136" ;;
	grammar) echo "U57" ;;
	credential) echo "U18 U19 U139 U140 U141 U142" ;;
	typed) echo "U143 U144 U145 U146 U147 U148 U149 U150 U151 U152 U153 U154" ;;
	typed-cli) echo "U155 U156 U157 U158 U159" ;;
	projection) echo "U160 U161 U162 U163 U164" ;;
	expiry) echo "U165 U166 U167 U168" ;;
	mount-audit) echo "U169 U170 U171 U172 U173 U174" ;;
	refresh-profiles) echo "U175 U176 U177 U178 U179 U180 U181" ;;
	refresh) echo "U182 U183 U184 U185 U186 U187 U188 U189 U190" ;;
	typed-docs) echo "U191" ;;
	*) echo "" ;;
	esac
}

# lab is 1 when the rig legs run: plain --lab, or a unit mode followed by --lab.
lab=0
if [ "$mode" = lab ]; then lab=1; fi
if [ $# -eq 2 ]; then
	[ "$2" = --lab ] || usage
	[ -n "$(mode_rows "$mode")" ] || usage
	lab=1
fi

if [ "$lab" = 1 ]; then
	if [ "${K3SM_LAB:-}" != 1 ]; then
		echo "keystore: --lab is the recorded rig step; it runs only with K3SM_LAB=1" >&2
		exit 2
	fi
	if [ -z "${K3SM_LAB_EVIDENCE:-}" ] || [ ! -d "$K3SM_LAB_EVIDENCE" ]; then
		echo "keystore: --lab needs K3SM_LAB_EVIDENCE, an existing evidence directory" >&2
		exit 2
	fi
fi

cd "$K3SM_ROOT"

# run_root is --root: row R1. Only the test binary runs under sudo; the build,
# the counting and the cleanup run as the invoking user. It is called where set
# -e does not apply, so every step checks its own status.
root_tmp=""
root_t=""
root_ids=()

# tree_state prints the k3sm checkout's git status, untracked files listed
# one by one, sorted. Root runs the test binaries in the source tree, so each
# run is bracketed by two of these.
tree_state() {
	git -C "$K3SM_ROOT" status --porcelain --untracked-files=all | LC_ALL=C sort
}

# tree_dirtied prints each status line in tree_state now that is not in $1,
# a tree_state taken before a root run, and fails if any is (or if git
# fails): a root run that leaves anything new in the source tree fails.
tree_dirtied() {
	local now new line
	now="$(tree_state)" || { echo "  git status of $K3SM_ROOT failed"; return 1; }
	new="$(LC_ALL=C comm -13 <(printf '%s\n' "$1") <(printf '%s\n' "$now") | grep -v '^$' || true)"
	if [ -n "$new" ]; then
		while IFS= read -r line; do echo "  left in the source tree: $line"; done <<<"$new"
		return 1
	fi
}

run_root() {
	local t out rc=0 n m f before
	t="$(mktemp -d "${TMPDIR:-/tmp}/keystore-root.XXXXXX")" || { echo "R1 FAIL as root: mktemp -d failed"; return 1; }
	root_tmp="$t"
	# The store refuses an unclean DataRoot, and macOS's TMPDIR ends in a
	# slash, so the tests' temp dirs are under the canonical path.
	t="$(cd "$t" && pwd -P)" || { echo "R1 FAIL as root: cannot resolve $root_tmp"; return 1; }
	root_t="$t"
	trap 'rm -rf "$root_tmp" 2>/dev/null || echo "keystore: could not remove $root_tmp (a root-owned leftover)" >&2' EXIT
	if ! out="$(CGO_ENABLED=1 go test -race -c -o "$t/keystore.test" ./pkg/keystore/ 2>&1)"; then
		printf '%s\n' "$out"
		echo "R1 FAIL as root: the test binary did not build"
		return 1
	fi
	if ! mkdir "$t/tmp"; then
		echo "R1 FAIL as root: could not lay out $t"
		return 1
	fi
	if ! command -v sudo >/dev/null 2>&1; then
		echo "R1 PENDING as root: sudo is not on PATH"
		return 3
	fi
	# sudo resets the environment, so the service user's ids are passed on.
	root_ids=()
	if [ -n "${K3SM_KEYSTORE_TEST_UID+set}" ]; then root_ids+=("K3SM_KEYSTORE_TEST_UID=$K3SM_KEYSTORE_TEST_UID"); fi
	if [ -n "${K3SM_KEYSTORE_TEST_GID+set}" ]; then root_ids+=("K3SM_KEYSTORE_TEST_GID=$K3SM_KEYSTORE_TEST_GID"); fi
	# The binary runs in the package's source directory, as go test runs it,
	# so the tests that read the source tree (and the committed fuzz corpus
	# in ./testdata) find it. Root only runs the binary built above, and a
	# run that leaves anything new in the tree fails.
	before="$(tree_state)" || { echo "R1 FAIL as root: git status of $K3SM_ROOT failed"; return 1; }
	out="$(cd "$K3SM_ROOT/pkg/keystore" && sudo -n env TMPDIR="$t/tmp" ${root_ids[@]+"${root_ids[@]}"} "$t/keystore.test" -test.count=1 -test.v 2>&1)" || rc=$?
	# sudo -n that cannot run the binary prints only its own refusal.
	if [ "$rc" -ne 0 ] && ! grep -q -- '^=== RUN' <<<"$out" && grep -q '^sudo: ' <<<"$out"; then
		printf '%s\n' "$out"
		echo "R1 PENDING as root: sudo -n is unavailable"
		return 3
	fi
	n="$(grep -c -- '^--- PASS: ' <<<"$out" || true)"
	m="$(grep -c -- '^--- SKIP: ' <<<"$out" || true)"
	f="$(grep -c -- '--- FAIL: ' <<<"$out" || true)"
	if ! tree_dirtied "$before"; then
		echo "R1 FAIL as root: the run changed the source tree ($n tests passed, $m skipped)"
		return 1
	fi
	if [ "$rc" -eq 0 ] && [ "$f" -eq 0 ]; then
		echo "R1 PASS as root: $n tests passed, $m skipped"
		return 0
	fi
	printf '%s\n' "$out" | grep -E -- '^ *(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
	echo "R1 FAIL as root: $n tests passed, $m skipped"
	return 1
}

# root_build sets RB to a fresh directory under root_t holding package $1's
# test binary, pkg.test, built as the invoking user, and RS to that
# package's source directory, where the binary runs, as go test runs it.
RB=""
RS=""
root_bin_n=0
root_build() {
	local rel d
	case "$1" in
	k3sm/*) ;;
	*) echo "keystore: a root-run row runs k3sm packages only, not $1"; return 1 ;;
	esac
	rel="$(pkg_rel "$1")"
	root_bin_n=$((root_bin_n + 1))
	d="$root_t/b$root_bin_n"
	mkdir -p "$d/tmp" || return 1
	if ! CGO_ENABLED=1 go test -race -c -o "$d/pkg.test" "$rel" >"$d/build.out" 2>&1; then
		cat "$d/build.out"
		return 1
	fi
	[ -f "$d/pkg.test" ] || { echo "keystore: $1 has no test binary"; return 1; }
	RB="$d"
	RS="$K3SM_ROOT/${rel#./}"
}

# judge_root_row runs root-run row $1's named tests by name under sudo -n, one
# binary per package, and fails it unless each printed PASS: a SKIP fails.
judge_root_row() {
	local i="$1" id="${R_ID[$1]}" spec p pkgs="" names t out rc bad=0 before
	for spec in ${R_TESTS[$i]}; do
		case " $pkgs " in *" ${spec%%::*} "*) ;; *) pkgs="$pkgs ${spec%%::*}" ;; esac
	done
	for p in $pkgs; do
		names=""
		for spec in ${R_TESTS[$i]}; do
			if [ "${spec%%::*}" = "$p" ]; then names="${names:+$names|}${spec#*::}"; fi
		done
		if ! root_build "$p"; then
			echo "$id FAIL as root: the test binary of $p did not build"
			return 1
		fi
		rc=0
		before="$(tree_state)" || { echo "$id FAIL as root: git status of $K3SM_ROOT failed"; return 1; }
		out="$(cd "$RS" && sudo -n env TMPDIR="$RB/tmp" ${root_ids[@]+"${root_ids[@]}"} "$RB/pkg.test" -test.count=1 -test.v -test.run "^($names)\$" 2>&1)" || rc=$?
		if ! tree_dirtied "$before"; then
			echo "$id FAIL as root: the run of $p changed the source tree"
			bad=1
		fi
		for t in ${names//|/ }; do
			if grep -q -- "--- SKIP: $t " <<<"$out"; then
				echo "$id FAIL as root: $t ($p) skipped, and a root-run row fails on SKIP"
				bad=1
			elif ! grep -q -- "--- PASS: $t " <<<"$out"; then
				echo "$id FAIL as root: $t ($p) did not pass"
				bad=1
			fi
		done
		if [ "$rc" -ne 0 ]; then
			printf '%s\n' "$out" | grep -E -- '^ *(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
			bad=1
		fi
	done
	if [ "$bad" -ne 0 ]; then return 1; fi
	echo "$id PASS as root: ${R_DESC[$i]}"
}

# run_root_mode is --root: R1, then every root-run row.
run_root_mode() {
	local rc=0 i=0 dirty
	# Root runs the test binaries in the source tree, and a run that leaves
	# anything new there fails. In a tree already dirty a root-owned leftover
	# could hide among the changes, or be committed with them, so a root run
	# starts only from a clean tree.
	dirty="$(tree_state)" || { echo "keystore: --root: git status of $K3SM_ROOT failed" >&2; return 2; }
	if [ -n "$dirty" ]; then
		printf '%s\n' "$dirty" >&2
		echo "keystore: --root refuses a dirty source tree: root runs the tests in it and fails a run that leaves anything new, so start from a clean checkout (commit or remove the changes above)" >&2
		return 2
	fi
	run_root || rc=$?
	if [ "$rc" -eq 3 ] || [ -z "$root_t" ]; then return "$rc"; fi
	while [ "$i" -lt "$nrows" ]; do
		case "${R_KIND[$i]}" in
		rootpend)
			echo "${R_ID[$i]} PENDING as root: ${R_DESC[$i]}"
			if [ "$rc" -eq 0 ]; then rc=3; fi
			;;
		rootcheck) judge_root_row "$i" || rc=1 ;;
		esac
		i=$((i + 1))
	done
	return "$rc"
}

# The row table. Each row is declared here and judged after its packages ran,
# in declaration order. The arrays are parallel, indexed by row; bash 3.2 has
# no associative arrays.
R_ID=()
R_KIND=()
R_DESC=()
R_TODO=()
R_TESTS=()
# add kind id desc todo tests... records a row, its tests as <pkg>::<Test>.
add() {
	local kind="$1" id="$2" desc="$3" todo="$4" pkg="k3sm/pkg/keystore" t specs=""
	shift 4
	for t in "$@"; do
		case "$t" in
		*::*) pkg="${t%%::*}" t="${t#*::}" ;;
		esac
		specs="$specs $pkg::$t"
	done
	R_ID+=("$id")
	R_KIND+=("$kind")
	R_DESC+=("$desc")
	R_TODO+=("$todo")
	R_TESTS+=("${specs# }")
}
check() { local id="$1" desc="$2"; shift 2; add check "$id" "$desc" "" "$@"; }   # row, description, tests...
partial() { local id="$1" d="$2" t="$3"; shift 3; add partial "$id" "$d" "$t" "$@"; } # row, delivered part, pending part, tests...
pend() { local id="$1" desc="$2"; shift 2; add pend "$id" "$desc" "" "$@"; }    # row, description (its change), tests...
# rig leg, the unit mode that delivers its last feature ("" for none), description, fails-without feature
leg() { add leg "$1" "$3 (fails without: $4)" "$2"; }
special() { add "$1" "$2" "" ""; }                                               # G1 or G22, judged inline
# root-run rows: --root runs them by name; --check prints them as ROOT, uncounted
rootcheck() { local id="$1" desc="$2"; shift 2; add rootcheck "$id" "$desc" "" "$@"; } # row, description, tests...
rootpend() { local id="$1" desc="$2"; shift 2; add rootpend "$id" "$desc" "" "$@"; }   # row, description (its change), tests...
# a row of the floor variant K0 did not pick: printed N/A, never run, and
# counted neither as pending nor as passed (K0 amendment 2026-11-21: the
# flag variant, so the helper rows do not apply)
notapplicable() { local id="$1" desc="$2"; shift 2; add na "$id" "$desc" "" "$@"; } # row, description, tests...

special g1 G1
check G2 "AAD is length-prefixed and binds format, scope, kind, name, version, generation" \
	TestAADLayout TestAADBindsEveryField TestRecordMovedBetweenEntries TestScopeBindsRecords
check G3 "every seal draws a fresh nonce, Rewrap included, which changes every nonce" TestSealNonceIsFresh TestRewrapChangesEveryNonce
check G4 "Delete then Put does not reopen the old v1" TestDeleteThenPutRefusesReplayedRecord
check G5 "a copied-back current is refused against the floor, with its own message; nothing recorded for the name accepts it" \
	TestFloorRefusesCopiedBackPointer TestFloorCheck
check G6 "the floor and the data root are root-owned and not shared, judged on the descriptor; the floor is the system scope's, parsed strictly; a caller that cannot write it changes nothing; no non-test file sets the floor's owner" \
	TestFloorTrust TestFloorScope FuzzParseFloor TestFloorNotWritableChangesNothing TestFloorOwnerUnsetOutsideTests
check G7 "the floor is raised by Put, Rotate, RaiseFloor and Delete when the master opens, and by list and show before they read; one behind is accepted; each write re-reads it under the data-root lock, with a bounded wait; a verb that takes both locks, a maintenance verb included, takes keystore-lock before keystore/.lock" \
	TestFloorRaised TestFloorWriteRereads TestFloorLockBoundedWait TestMaintenanceTakesFloorLockFirst k3sm/cmd/k3sm::TestKeysReadVerbsRaiseFloor
check G8 "Rotate flips the pointer last; a crash before the flip leaves the old version current" \
	TestRotateCrashAtEveryStep TestRotate
check G9 "a Rotate retry never promotes an orphan: a failed Rotate removes its own, a sealed one a crash left is refused, an unauthenticated one is discarded, and the retry seals the value it was given; only an attended adopt promotes one" \
	TestRotateRetryDiscardsOrphan TestParseVersionName TestRotateVersionSyncFailureRemovesVersion \
	TestOAuthCrashOrphanAdopted TestOrphanRefusalTellsCasesApart TestAdoptRefuses \
	TestAdoptRefusesReplacedOrphan TestOAuthPreFlipFailureKeepsVersion TestReadsReportOrphanEveryKind TestReadsRefuseFilesAboveNextByName \
	k3sm/cmd/k3sm::TestKeysAdopt TestKeysCommittedExitCode
check G10 "the master is minted only by the first put, never over entries; rewrap --key-in accepts only a key an interrupted rewrap recorded or sealed records under" \
	TestMasterMint TestMintCountsReservedUserName \
	k3sm/cmd/k3sm::TestKeysRewrapKeyInRecoveryOnly TestKeysRewrapKeyInRecoversReplacedNext
check G11 "the master is judged on the open descriptor" TestMasterTrust
check G12 "Rewrap resumes after a crash at every step, old key then new, nothing unreadable; a bad master.next is discarded only with no .new file" \
	TestRewrapCrashAtEveryStep TestRewrapKeyReuse TestRewrapRefusesStalePointer TestRewrapVerifiesCommit TestRewrapGuards \
	TestRewrapRefusesLiveMasterFirst TestRewrapRecoversReplacedNext \
	TestRewrapRemovesStaleNew TestRewrapOverFullFloor TestRewrapCommitChecksMetadata \
	TestInterruptedRewrap TestRecordsSealedUnder TestRewrapNotStarted TestRewrapRefusesOrphan
check G13 "a crash between the master renames leaves a trusted master, and the next verb completes the swap" \
	TestRewrapMasterRenameCompleted TestFinishSwapLeavesUnmatchedFingerprint
check G14 "one lock with a bounded wait serializes Rewrap, Rotate, Put, Delete and the reads, and no read blocks" \
	TestLockBoundedWait TestLockExcludes TestConcurrentOperations TestFIFORefused TestReadDirNamesBound
check G15 "files a root verb writes are the service user's, at the layout's modes, inside the store" \
	TestOwnership TestCredSymlinkRefused TestRefusesSymlinks TestMkdirRefusesSwappedDirectory \
	TestCreateEntryRefusesSwappedDirectory TestConfigRefused
check G16 "List marks an unreadable entry with Err, and Delete still removes it; an entry directory with no current is an interrupted put only in the shape a crashed Put leaves and with its generation not in the floor, and Delete removes it too; list exits 1 on a corrupt entry" \
	TestListMarksCorruptEntry TestDeleteCorruptEntry TestEntryWithNoPointer TestCommittedBeforeDecodesGeneration \
	TestDeletePlantedNonDirectory TestDeleteDirectoryAtCurrent TestPointerVersionBound TestPutCrashAtEveryStep \
	TestMkdirSyncsParent \
	k3sm/cmd/k3sm::TestKeysListCorruptExitsOne TestKeysRmCorruptEntry
check G17 "show prints a value only with --reveal, byte-exact for an opaque value and 32- and 64-byte Ed25519 values; no verb takes a value as an argument" \
	k3sm/cmd/k3sm::TestKeysShowRevealByteExact TestKeysShowMetadataOnly TestKeysRefusals
check G18 "delivery is refused while encryption is off, before any apiserver call, logged once per target; the server's override flag allows it; a target delivered under the override stays when it is removed; deliver prints the refusal" \
	k3sm/pkg/keystore/deliver::TestDeliveryRefusedWhileEncryptionOff TestDeliveryOverrideAllowsPlaintext TestDeliveredTargetStaysWhenOverrideRemoved \
	k3sm/cmd/k3sm::TestKeysDeliveryServerFlag TestKeysDeliveryServerConfig TestKeysDeliverEncryptionOffNote TestKeysDeliveryServerGate
check G19 "the delivery declaration is root-owned and not group- or other-writable, opened O_NOFOLLOW and judged on the descriptor, size- and count-capped and parsed strictly, each entry system/<name>; anything else is refused whole, by the reconciler and by the verbs; the verbs serialize on a root-owned lock file judged the same way; the data root holding them is root's and not shared-writable, judged on its descriptor; the state file is the server euid's, in a directory of that euid, root or (for a root server) the service user" \
	k3sm/pkg/keystore/deliver::TestDeclarationRootOwned TestDeclarationOpenedWithNoFollow TestLockRefusesUntrustedFile TestLockBoundedWait \
	TestNewDefaultsBindRoot TestDataRootDirectoryChecked TestStateFileOtherOwnerRefused TestStateDirServiceUserOwner \
	TestDeclarationEntryField TestStateFileMalformedDeliversNothing \
	k3sm/cmd/k3sm::TestKeysDeliverRefusals TestKeysDeliverWritersSerialize TestKeysEnvDefaultsBindRoot TestKeysUndeliverSecret
check G20 "the reconciler only gets, creates and updates the Opaque Secrets it created, proven by the UID it recorded, not the label: an unlabelled, foreign, pre-created or recreated Secret is untouched, and no list is ever made, and no delete but an owned immutable Secret's under a UID precondition; content drift is re-applied; one hung call cannot stall the sweep; rm of a declared entry warns that its Secret keeps the value; no stored value reaches the log or the verbs' output" \
	k3sm/pkg/keystore/deliver::TestReconcilerTouchesOnlyLabelledSecrets TestReconcilerRedeliversOnRotation \
	TestReconcilerSkipsLabelledNonOpaque TestReconcilerContinuesAfterTargetFailure \
	TestReconcilerRedeliversAfterRmPut TestReconcilerReappliesChangedDataKey \
	TestReconcilerNeverWritesTenantPrecreated TestReconcilerDoesNotAdoptRecreated \
	TestReconcilerRecordsCreatedUID TestReconcilerReappliesDrift TestReconcilerImmutableOwned \
	TestReconcilerLogsNoValue TestReconcilerTargetTimeout TestNewTargetTimeout TestWatchLogsErrors \
	TestStateStockInstallShape TestMissingDeclarationKeepsRecords \
	TestReconcilerRepointsOwnedSecret TestReconcilerRelabelledOwnedSecret \
	TestReconcilerImmutableDeleteConflict TestStateWriteFailureCreatesNothing \
	TestReconcilerUpdateCarriesUIDAndResourceVersion TestStateWriteFailureDeletesNothing \
	TestReconcilerImmutableMetadataOnly TestReconcilerTerminatingNotDeleted \
	TestMissingDeclarationWarnsOnce TestReconcilerImmutableDeleteNotFound \
	k3sm/cmd/k3sm::TestKeysRmWarnsDeclared TestKeysDeliveryPrintsNoValue
check G21 "the rollback recipe is a byte-exact round trip: show --reveal into rotate --in -, the new version compared with version N byte for byte (bytes.Equal, as cmp), opaque and Ed25519" \
	k3sm/cmd/k3sm::TestKeysRollbackRoundTrip
special g22 G22
check G23 "a deleted entry's directory put back before a new Put of the name is refused by every reader and verb, never recorded in the floor, and removed by rm, which keeps the tombstone" \
	TestTombstoneRefusesPutBack TestTombstoneSurvivesPlantedGeneration TestTombstonesKeptAcrossRecreate TestDeleteBuriesFloorGeneration TestDeleteBuriesWithDirectoryGone TestDeleteFaultAfterBurial TestDeleteBuriesPastPlantedNames TestDeleteClearsUserFlags TestBuriedErrorPointsToRestore TestRefusalLeadsWithSafeAction TestDeleteBuriesAuthenticatedDirectoryGeneration TestDeleteBuriesUnderHeldEntryLock TestDeleteBuriesUnderReplacedEntryLock TestDeleteKeepsHardLinkedFlags TestDeleteClearsKeystoreDirFlag

pend U1 "rotate --from-version N writes version N's bytes as a new version server side; no value leaves the store (keys verbs)" \
	k3sm/cmd/k3sm::TestKeysRotateFromVersionNoValueOut
partial U2 "AAD scope: a record moved between scopes fails to open, and two users derive different keys" "a record opened as another user is refused (user scopes)" \
	TestScopeBindsRecords TestDerivedKeysDifferByScope
check U3 "KDF labels take the scope; checkScope accepts only system and user/<decimal uid>; kinds 0xFE and 0xFD are reserved" \
	TestDerivedKeysDifferByScope TestCheckScope TestParseRecordRefusesMalformed
check U4 "the first-Put mint refuses with .user present and the master missing" \
	TestMintCountsReservedUserName
check U5 "replaced by U12: Rewrap no longer refuses with ErrScopeUnsupported while .user exists; a .user that is a file or a symlink refuses with ErrCorrupt, writing nothing" \
	TestRewrapRefusesDamagedUserScopes
check U6 "scope.key is sealed under W, bound to the GeneratedUID; a mismatch is ErrScopeOwnerChanged" \
	TestScopeKeyGeneratedUIDMismatch
check U7 "the GeneratedUID lookup past its deadline, 250 ms everywhere, or in error fails closed; mbr_uid_to_uuid is in the symbol canary" \
	TestGeneratedUIDLookupDeadlineFailsClosed k3sm/internal/hostacl::TestMbrUIDToUUIDSymbolCanary
check U8 "a scope's records open only under its K_u; a copied .user/<uid>/ without the master opens nothing" \
	TestScopeCopyWithoutMasterOpensNothing
check U9 "per-scope fingerprints differ for equal values in two scopes" \
	TestFingerprintsDifferAcrossScopes
check U10 "user/<other>/... is ErrNotFound, same text as an absent entry; a short name resolves to the uid and is printed" \
	TestOtherUserIsNotFound TestShortNameResolvesToUID
check U11 "the Go resolver and Phase A's checkName pass the shared entry-grammar vectors; pkg/keystore imports no Kubernetes package" \
	TestEntryGrammarVectorsResolver TestEntryGrammarVectorsCheckName TestCheckScopeRefusesUserZero TestAllDigitSegmentIsAlwaysUID TestKeystoreIsKubernetesFree
check U12 "master Rewrap re-wraps every scope.key and leaves user records byte-identical; resumable at every step, by fault injection as G12" \
	TestRewrapRewrapsScopeKeysResumable TestRewrapRefusesDamagedScopeTree TestRewrapVerifiesScopeKeysBeforeSwap TestRewrapRefusesStrayScopeDirs TestRewrapPinsScopeKeyFromPlan
check U13 "quotas: the 257th entry and the byte budget answer ErrQuota, and so does the 65th live delivery; rm and withdraw still work" \
	TestUserScopeQuota TestUserScopeQuotaCountsDeliveriesAndGeneration TestDeliveryRecordQuota TestRevocationIsUnconditional TestWithdrawFloorFaults TestWithdrawRepeatAppendsNoFloorLine TestWithdrawRefusesRollbackBelowSeen TestWithdrawRefusesRollbackAfterFloorLineFailed TestRepeatWithdrawCatchUpIsRevocation TestWithdrawAuditRevokeFlag TestDeliveriesCatchUpSurvivesRestart TestDeliverCatchesUpFloor TestCatchUpUserAtStartSurvivesRestart TestUserScopeRefusedBeforeStart TestStartUserScopesChecksBoundsFirst TestCheckLogBoundsFailsClosed TestCheckLogBoundsReportsDamage TestExportPrereqsChecked TestWithdrawBelowReadableFloorRefused TestDeleteOwnerChanged TestRmLookupRefusalKinds TestDeliveriesSeenIsProcessWide
check U14 "the delivery record stores UID, the full target tuple under its seal, and target digest; add, look up and withdraw round-trip under the floor; the digest covers entry, namespace, secretName and the key-sorted items, a reorder leaving it unchanged" \
	TestDeliveryRecordDigestRoundTrip TestDeliveryRecordVersionByteAndDigestLabel TestDeliveryDigestCoversTargetAndItems TestDeliveryFieldGrammarAtAdd TestDeliveryFieldGrammarAtParse
check U101 "rewrap prints a warning whenever .user/ exists, before it starts and when it finishes, saying Rewrap does not re-key K_u and naming the procedure: each user re-puts their values after a suspected master exposure; with no .user/ it prints none" \
	k3sm/cmd/k3sm::TestRewrapWarnsWhenUserScopesExist
check U16 "every pod profile variant (native, vm, container-vm, xcode, expose-paths, wasm, the profile an exec-session process runs under, a custom pod root distinct from the data root) denies every keystore path, the keystore-sock/ tree included, the protected-prefix validator refusing any re-allow onto one, since the order of denies and allows protects nothing; a hostPath or expose path onto the data root is refused; an empty data root fails closed; over the whole rendered profile, a pod root equal to or a parent of the data root included, no emitted allow matches a keystore path; the keystore stanza is the profile's last rule, in the /var, /private/var and /System/Volumes/Data spellings, with a case-folded regex keystore- prefix deny; a caller path naming a keystore path is refused with ErrProtectedPath; a write, create, unlink, rename and network-bind on keystore-sock/, keys.sock and every keystore-* name are refused; each also through /System/Volumes/Data/private/var/lib/k3sm and the data volume's mount path; rig leg E10 (sandbox denies)" \
	runtimed/pkg/sandbox::TestDataRootDeniesKeystorePathsEveryProfile TestShimProfileKeepsTheKeystoreDeniesLast TestKeystoreDenyStanzaShape TestDataRootRefusesPodRootUnderKeystoreName TestValidateRefusesKeystoreExtraPaths TestEmptyDataRootFailsClosed TestDataRootRefusesWhatCannotHoldTheDeny TestKeystoreDeniesUnderSandboxExec
check U17 "runtimed refuses a pod identity it may not hold through Credential.CheckPodIdentity (pkg/supervisor/privdrop.go), not in resolveCredential: at startContainer, at Exec (an exec session), at the resident shim's dropShim and in RunLaunchSequence; a drop target uid is refused if it is 0, negative, 501 or above, or the service uid; groups are refused if they are 0, 20, 80, the privileged system groups (wheel, daemon, kmem, sys, tty, operator, procview, procmod, _developer), the service gid, negative or out of range, and a gid of 501 or above unless it is an admitted fsGroup; a missing group defaults to nobody; a gid-only drop that leaves uid 0 is refused; an inherited uid with no drop is allowed; a gid in 1..500 is refused for a pod drop, as the primary or a supplemental group, when the host assigns it (an unassigned gid is allowed, and so is nobody; the never-list is always refused, a lookup error refuses, and an operator-admitted fsGroup the host assigns is still refused); the service identity (the _k3sm lookup and the owners of the installed directories) is resolved again on every drop check; a symlink at an installed path refuses every drop; the system gids (1, 2, 3, 4, 5, 8, 9, 204) are refused as the primary gid and as a supplemental gid; when the account lookup returns not-found, a drop to the owner of the installed work dir or the keystore socket dir is refused (the installed service-uid fallback); the live check is strict, a denial is an EPERM and planting is included; rig legs E21, E22 (sandbox denies)" \
	runtimed/pkg/runtime::TestStartContainerRefusesAPodIdentity TestExecRefusesAPodIdentity TestPodUIDInLoginRangeRefused TestPodGroupsRefused TestServiceUIDFromInstalledDirs TestStartContainerResolvesTheServiceOwnerEachStart TestSymlinkedWorkDirRefusesDrops \
	runtimed/internal/execshim::TestDropShim \
	runtimed/pkg/supervisor::TestRunLaunchSequenceRefusesPodUID TestRunLaunchSequenceRefusesPodGroups TestFSGroupGidAllowList TestResolveServiceIdentityInstalledOwner TestPodGroupsHostAssigned \
	runtimed/pkg/sandbox::TestKeystoreDeniesUnderSandboxExec TestShimProfileKeepsTheKeystoreDeniesLast
pend U18 "CRD: entry, secretName, items, requestedBy required with no default and immutable by CEL transition rules (items as a map); status subresource on; reasons listed; a system/ entry is refused (KeyDelivery API)" \
	apis/config/crd::TestKeyDeliveryCRDMatchesTheGoTypes TestKeyDeliveryImmutableFields TestKeyDeliveryRequiredFields TestKeyDeliveryRequestedByMatchesEntryUID TestKeyDeliveryConditionsListMap TestKeyDeliveryRefusesSystemEntry
pend U19 "the CRD pattern, its maxLength, the uid range rule and the 253-byte name-length rule pass the shared entry-grammar vectors (KeyDelivery API)" \
	apis/config/crd::TestEntryGrammarVectors
check U20 "a user entry tree copied back after rm is refused as deleted against the floor log's tombstone (real, not synthetic), a later put of the name is served, and an rm whose removal fails still leaves the entry refused; an rm buries every generation it can name (the floor's live ones, the generation file's, the pointer header's and each v<N> record header's), so a swapped generation file, or a generation file and pointer both rewritten, does not let the original tree back, and it reports the mismatch after the commit; whatever stands at the name it buries the floor's live generations first: a file or a symlink there is buried, removed and reported after the commit, and an rm of an absent tree with live generations buries them and succeeds, so a retry after a failed burial closes the window; an absent floor refuses an rm, which removes nothing, a withdraw over a floor that is absent, unflagged or unreadable seals nothing and is refused naming the Secret's deletion, so a restored record is never re-sealed, a floor line that does not parse, or a torn tail, is skipped and counted as damage (root reads the count), so an rm and a withdraw of two uids after garbage each succeed while a grant is refused before its first write naming CheckLogBounds and the root acknowledgement (a skipped line can be a tombstone, so damage writes no live line for a key it could name, a line torn inside its name or scope covering every key that starts with it, and unattributable damage keeps the floor-wide rule until root acknowledges it, while a taint past the taint set's cap overflows it, refusing every key's grants and reads, which no acknowledgement lifts, and the acknowledgement is a compare-and-set that refuses a floor changed since root reviewed it, its unrecovered count included, and the review gives each unrecovered line's offset, and a withdraw under a delivery-record taint seals every delivery withdrawn and audits each one it withdrew, admitting every audit line on the audit log before it seals and attempting each one past a failure; every floor line carries a CRC-32C checksum, so a truncated or flipped line never parses, a truncated one taints its key or counts as unattributable, and a damaged line that could be a tear, a prefix of a line in the grammar, taints by that prefix, and any other is corrected to the keys it taints, a flipped-away newline's two lines included, or, with no unique single-bit correction, refuses every known generation until the acknowledgement; a scope whose catch-up is refused is quarantined alone, its grants and reads refused while its rm and withdraw still run, and a full volume quarantines nothing), every append writes a newline first, so a foreign fragment landing just before the server's write is one damaged line and every server line parses, and a torn tail is frozen where first read, so a foreign append that completes it stays damage that keeps its key tainted, an empty line is benign, a burial's free-space preflight also holds its audit line's after the burial's block-rounded reservation, an rm whose burial fsync fails is committed, durability uncertain, and audited as a revocation when its tombstones are visible, found from the file's real end, and refused with nothing removed when none is, and the tombstones read before the garbage still refuse their copies; an rm over a torn floor tail buries and removes; a floor past the reader's bound refuses a withdraw with ErrCorrupt naming the matched-set restore, which brings back every entry deleted since the backup, and a read I/O error is not damage; a grant over a floor that is absent, unflagged, unreadable or past its bound is refused before its first write, with no ok line; a current below a floor line is refused with the user-scope floor message, which names the matched-set restore, not removing keystore-floor.json, proved against a synthetic later floor line until user rotate exists; rig leg E9" \
	TestUserFloorRefusesCopyBackAfterRm TestUserPutAfterRmServed TestUserRmBuriesBeforeRemoval TestUserRmAbsentFloorRemovesNothing TestUserRmSwappedGenerationStillBuries TestUserRmNonDirectoryBuries TestUserRmRetryAfterTreeGoneBuries TestUserRmBuriesVersionHeaderGeneration TestUserRmOpenFailureBuriesFirst TestUserRmOpenFailureRefusedWithoutTombstone TestUserRmMissingEntriesBuriesFirst TestUserRmRemovalFailureIsCommitted TestUserRmChargesEveryTombstone TestRmBurialReservedBeforeFirstTombstone TestRmBurialIsOneWrite TestRmBurialWriteFailureRefuses TestRmBurialShortWriteAfterWholeLineCommits TestRmBurialServedPointerFirstWithoutKu TestRmBurialPartialNamesLandedWithoutServed TestServerPathsLeaveOneLiveGeneration TestRmBurialSyncFailureRefuses TestRmBurialSyncFailureVisibleCommits TestRmBurialForeignAppendBeforeShortWriteCommits TestForeignFragmentBeforeWriteIsOwnLine TestRmPartialBurialIsCommitted TestUserRmUnreadableScopeKeyBuriesNothing TestUserRmNoGenerationRefusesFirst TestUserRmCapsTreeGenerations TestUserFloorRefusesCopiedBackCurrent TestWithdrawAbsentFloorProceeds TestWithdrawUnverifiedFloorSealsNothing TestRmOverTornFloorTailBuries TestFloorGarbageTailIsSkippedDamage TestFloorDamageDegradesLiveLines TestTornBurialTaintsOnlyItsKey TestTornBurialEveryCutRefusesKnownGeneration TestSkippedScopePrefixTaintsItsScopes TestTornWithdrawLineTaintsDeliveryRecord TestUnattributableDamageKeepsFloorWideRefusal TestTornPutLineQuarantinesOnlyItsScope TestQuarantinedScopeRevokes TestFullVolumeAtStartDoesNotQuarantine TestWithdrawRunsUnderDeliveryRecordTaint TestFloorLineCarriesChecksum TestEveryTruncationAndFlipNeverParses TestClosedTearRefusesKnownGeneration TestDeliveryTearClosedKeepsTaint TestFlippedGenerationDigitTaintsName TestCorruptTombstoneOfKnownGenerationRefused TestFloorDamageAckLiftsOnlyUnattributable TestFloorTaintOverflowRefusesEveryKey TestFloorDamageAckRefusesChangedFloor TestFloorDamageAckRefusesStaleUnrecovered TestFloorAckViewGivesUnrecoveredOffsets TestFloorDamageAckCatchUpSkipsAttributable TestRuntimeCatchUpRestoresLostEntryLine TestWithdrawUnderTaintNeverRevivesLostWithdraw TestFloorTornMiddleLineIsSkipped TestWithdrawMalformedFloorRefused TestFloorReadErrorIsNotDamage TestGrantRefusesUntrustedFloorFirst TestEveryTombstoneFlipRefusesKnownGeneration TestFlippedTombstoneScopeRefusesCopyBack TestUnrecoveredFlipRefusesKnownGenerations TestForeignCompletionOfTornTailStaysTainted TestForeignGrowthOfTornTailKeepsTaint TestWithdrawUnderTaintAuditsEverySealed TestWithdrawMassSealAuditsEveryDeliveryAtBudgetEdge TestAuditSealedKeepsGoingPastFailure TestRmBurialNeverLosesItsAuditLine TestRmBurialFreeSpaceCoversItsAuditLine TestDeliveryCatchUpPathsCheckLiveRefused FuzzParseFloorLine TestEveryBurialBufferFlipRefusesEveryBuried TestEveryTwoBitTombstoneFlipTaintsTrueKeyOrUnrecovered TestCouldBeTearMatchesOracle TestReadBurialEverySingleFlip FuzzCouldBeTear FuzzBurialFlips
check U21 "install creates each missing log with its own directory, as the maintenance verbs build one: the directory is built in the root-only keystore-staging/, the log created root's 0600 with O_EXCL|O_NOFOLLOW and nothing written, handed to the service user, set 0600 and flagged SF_APPEND on its descriptor and judged, all before the directory is placed in keystore-logs/ with RENAME_EXCL, so the log is flagged before it is reachable; a log that passes the judge is left alone, and an unflagged one is refused and left as found; it judges the data root's flags and ACL as the keystore does, refuses, changing nothing, while a maintenance verb runs, and removes a stale keystore-maintenance marker once the live set is ensured; the listener refuses to start when a flag is clear or a log is not the service user's; rig leg E1 (append-only files)" \
	k3sm/pkg/install::TestKeystoreAppendOnlyFilesAtInstall TestKeystoreFilesRefuseDuringMaintenance TestKeystoreFilesJudgeDataRootFlags k3sm/pkg/keystore::TestFlagCheckRefusesUnflagged
pend U22 "floor --rebuild and audit --rotate take keystore-lock and the store lock, then write the marker keystore-maintenance in the root-owned data root, which stops the listener; they build the replacement log directory in the root-only keystore-staging/, its new log handed to the service user, set 0600 and flagged SF_APPEND on its held descriptor before it is reachable, record its inode and the report in the marker, and swap the directory in with one RENAME_SWAP; the old log's flag is cleared only after the swap, in staging, and the retired directory is removed unread; a crash before the report removes the marker and changes nothing, and from the report on keeps it, so the listener stays down until a rerun cleans staging and prints the committed swap's saved report or runs again; every audit and floor append takes the store lock, so a reconciler append during audit --rotate waits; after maintenance, under the exclusive lock, the server reopens its audit and floor append descriptors and recounts the per-uid shares before releasing it, and the counts reset; rig leg E17 (append-only files, socket listener, KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestKeysFloorRebuildCrashOrder TestKeysAuditRotateCrashOrder k3sm/pkg/keystore/reconcile::TestReconcilerAppendWaitsForAuditRotate \
	k3sm/pkg/keystore/socket::TestMaintenanceReopensLogsAndResetsShares TestFailedReopenRetriedAtMarkerPoll
check U23 "every audited operation writes one v:1 line; no line carries a value or its length; readers ignore unknown fields; an append after a torn tail writes a newline first, so the torn bytes are a dropped line of their own and the new line parses; a change committed whole is audited ok and one committed in part committed; a partial commit whose audit line fails keeps both failures and logs the scope and verb at Warn" \
	TestAuditLineNeverCarriesValue TestAuditReaderIgnoresUnknownFields TestAuditTornTailAppendParses FuzzParseAuditLine TestAuditLineChargedStrictly TestAuditResultCommitted TestCommittedChangeKeepsAuditFailure
check U24 "the logs' sizes and soft cap are exposed for doctor (LogSizes); past the hard cap every mutating user op is ErrLogFull, except the revocation class, which draws on its uid's revocation budget; a line over 1 KiB is refused, and one found past the hard cap in the audit log is skipped and charged to no uid, while in the floor it is damage; the reader is bounded in size and floor keys, and the writer never appends past either bound: a floor line adding a key past the key bound is ErrLogFull, a grant without room for its keys is refused before its first write naming doctor, and a revocation of a key the floor holds still goes through, so put/rm churn never makes the floor damage; the reader reads through a line straddling the cap, and never blocks on a FIFO; a log or data root carrying a file flag beside SF_APPEND or a non-empty extended ACL is refused as untrusted; an append preflights free space and refuses, retryably, below 1 MiB plus the line, except a revocation's line, which keeps only a minimal check of the line plus 9 KiB; a put whose floor line would be refused after its commit (at the key bound, at a cap straddle where a minting put's second line would start past the hard cap, or below the free-space margin) is refused before its first write; an append reserves its line's blocks on the log's descriptor before it writes, and a refused reservation is refused for space with the log byte-identical; a configuration under which a uid's lines past the hard cap already exceed its revocation budget is refused at store open naming the remedy, a budget under two lines is refused, and the default budget holds one scope's full revocation" \
	TestLogHardCapRefusesMutations TestAuditLineBoundedAtOneKiB TestLogReaderSizeBound TestLogReadBoundAuditCarriesPreFrameBudget TestFloorKeyBound TestFloorKeyBoundChurnRefusesGrants TestFloorWriterRefusesKeyPastBound TestFloorKeyBoundDerivedFromCaps TestAuditStraddlingLineCharged TestLogOpenFIFORefused TestLogAppendPreflightsFreeSpace TestRevocationLinesSkipFreeMargin TestRevocationLineAtKeyBound TestLogRefusesExtraFlags TestLogDataRootRefusesExtraFlags TestLogRefusesExtendedACL TestAuditOverlongLineSkipped TestPutRefusedFirstBelowFloorMargin TestPutRefusedFirstAtKeyBound TestPutRefusedFirstAtCapStraddle TestDeliverRefusedFirstBelowFloorMargin TestPutFloorLineSurvivesVolumeFiller TestPutPreflightReservesValueRoom TestFloorLineBudgetFollowsClass TestLogFullTextNamesNoNumbers TestLogErrorsNameNoFigures TestFloorSeqZeroLineIsPresent TestFloorKeyShareRefusesOneUID TestFloorKeyShareChargesBuriedKeys TestFloorKeyShareLifetimeArithmetic TestFloorDeliverRoomExistingKeyPastBound TestFloorTombstoneLandsInHeadroom TestFloorReaderAcceptsHeadroom TestCheckLogBoundsRefusesShrunkCaps TestCheckLogBoundsRefusesKeysPastBound TestCheckConfigBoundsCapsAbove TestLogMissingWithScopesNamesRestore TestLogAppendReservesBlocks TestReserveLogBlocksRounds TestCheckLogBoundsRefusesSpentRevocationBudget TestCheckLogBoundsRefusesAtSpent TestSpentRevocationBudgetIsPerUID TestCheckConfigRevocationBudgetFloor TestDefaultRevocationBudgetHoldsFullRevocation
check U25 "backup and restore round trip: a restored tree with cleared flags is refused until floor --rebuild, which takes the restored root-owned unflagged floor as input, then opens; the rebuild writes a line for every entry directory holding a generation file, an authenticated pointer's sequence or, with none, sequence 0, so a damaged entry stays ErrCorrupt and never becomes ErrNotFound; the maintenance verbs take the locks, keystore-lock then the store lock, before they write the marker, build the replacement directory in a root-only 0700 keystore-staging/, swap it in with RENAME_SWAP, and leave the live set one complete set at every step; they take a log with a second link as input, which the steady-state check refuses naming the verb, leaving a fresh canonical log with one link, and refuse an unflagged old log the service user owns; past the 30 s wait they name the service-user holder and k3sm stop; rig leg E17 (append-only files)" \
	TestBackupRestoreRoundTripRebuild TestRebuildKeepsDamagedEntryCorrupt TestSwapCallOrder TestSwapRerunFromEachStep TestMaintenanceRepairsHardLinkedLog TestMaintenanceStagingDirIsRootOnly TestMaintenanceLocksBeforeMarker TestOldLogUnflaggedServiceOwnedRefused
check U26 "peers uid 0, the service uid and uid < 501 are refused before any frame is read (socket listener)" \
	k3sm/pkg/keystore/socket::TestPeerEligibility
check U27 "framing: an oversize frame, unknown type or missing HELLO closes; an unknown header field is ignored; HELLO picks the highest common version; a known request header field of the wrong type is refused (socket listener)" \
	k3sm/pkg/keystore/socket::FuzzFrameReader FuzzRequestHeader TestFramingBounds TestSubLengthsWithinFrame TestHelloReadDeadline TestUnknownHeaderFieldsIgnored TestHelloVersionRange TestHelloReplyCarriesVersionAndMaxFrame TestHelloNoOverlapSendsUnsupportedVersion TestUnknownOpKeepsConnection TestFrameCapCoversMaxValue
check U28 "64 connections in all, 2 per uid; a request past 10 s is cut; a connection idle 30 s after HELLO or between requests is closed (socket listener)" \
	k3sm/pkg/keystore/socket::TestConnectionCapsPerUID TestRequestTimeout TestIdleTimeoutAfterHelloAndBetweenRequests
check U29 "a listener panic is recovered and restarted; the apiserver is untouched; a stale socket is unlinked only if a service-user socket; a lock wait past 2 s fails the request (socket listener)" \
	k3sm/pkg/keystore/socket::TestListenerRecoversPanic TestStaleSocketUnlinkChecksOwner TestBoundedLockWait TestAbandonedLockWaitsBounded TestLockWaitSlotsReservedUpFront TestCheckBackoffResetsOnPassingChecks k3sm/cmd/k3sm::TestKeystoreSocketWiring TestKeystoreSocketRecoversSupervisorPanic
check U30 "with two servers registered, the listener does not start and doctor says why (socket listener)" \
	k3sm/pkg/keystore/socket::TestUserScopeRefusedWithTwoServers TestSecondServerStopsServingListener k3sm/cmd/k3sm::TestDoctorKeystoreUserScopeRow TestKeystoreServerCountNames
check U31 "a missing or unflagged file logs the install Warn at start and on each retry; doctor reports user scope off (socket listener)" \
	k3sm/pkg/keystore/socket::TestListenerWarnsOnEveryRetry TestInstallMissingLogNamesInstall TestPreconditionsCheck k3sm/cmd/k3sm::TestDoctorKeystoreUserScopeRow TestDoctorKeystoreSocketLstat TestDoctorKeystoreKubeconfigPermission TestDoctorKeystoreReopenJudgement
check U32 "a grant (put, deliver) appends its audit line before its first write, and every other operation's order is commit, append, reply, so the audit line is written before the reply; a failed append refuses user mutations and reads, except the revocation class (socket operations)" \
	k3sm/pkg/keystore/socket::TestAuditBeforeReply TestAuditFailureRefusesOps k3sm/pkg/keystore::TestExecReadRefusedWhenAuditFails TestUserRotateCrashOrder
check U33 "refused lines are rate-limited per uid with a summary of the dropped count (socket operations)" \
	k3sm/pkg/keystore/socket::TestRefusedLinesRateLimited
check U34 "5 mutating ops a second per uid; 30 read-for-exec a minute per uid, each audited exec-read (socket operations)" \
	k3sm/pkg/keystore/socket::TestMutationRateLimit TestExecReadCapPerUID k3sm/pkg/keystore::TestExecReadAudited
check U35 "the socket server's store interface has no reveal, show or rewrap method (socket operations)" \
	k3sm/pkg/keystore/socket::TestStoreInterfaceHasNoRevealMethod
pend U36 "the client refuses a socket whose connected peer uid is not the service uid, whatever the path checks said (non-root CLI and exec)" \
	k3sm/cmd/k3sm::TestClientRefusesForeignServerUID
pend U37 "exec sets the variable only in the child; nothing on stdout, nothing on disk; the value never enters argv; no non-root verb writes a value to stdout (non-root CLI and exec)" \
	k3sm/cmd/k3sm::TestKeysExecEnvOnlyInChild TestNoNonRootVerbWritesValue
pend U38 "an unknown error code prints the code; a connect failure names sudo k3sm install (non-root CLI and exec)" \
	k3sm/cmd/k3sm::TestUnknownErrorCodeFallback TestConnectErrorNamesInstall
pend U40 "the VAP checks requestedBy against the requester and refuses a ServiceAccount creator; its CEL passes the shared grammar vectors (KeyDelivery authoring)" \
	k3sm/pkg/policy::TestKeyDeliveryPolicyChecksRequestedBy TestEntryGrammarVectorsCEL
pend U41 "deliver creates impersonating only k3sm:local:<uid> and k3sm:local-users, refusing any other impersonation; it writes the UID and digest; withdraw deletes the object; undeliver prints the hint (KeyDelivery authoring)" \
	k3sm/pkg/keystore/socket::TestDeliverImpersonatesUIDPrincipalOnly TestDeliverImpersonatesPeerUIDNotOwner TestImpersonationSendsNoUidOrExtra TestDeliverWritesDigestRecord \
	k3sm/cmd/k3sm::TestUndeliverPrintsRotationHint
pend U42 "an unrecorded UID, a digest mismatch, or a failed name-scoped SAR (create keydeliveries; create, update, delete secrets with resourceNames) gets no Secret; encryption off refuses, G18 for KeyDelivery; each SAR carries the impersonated create's user and groups, so a group-bound grant is honoured consistently (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestUnrecordedOrRetargetedDeliveryGetsNoSecret TestSARCreateUnnamedUpdateDeleteNamed \
	TestEncryptionOffRefusesKeyDelivery TestSARCarriesImpersonatedUserAndGroups TestGroupBoundGrantHonouredConsistently
pend U43 "reasons are the closed set; absent and not yours both read EntryUnavailable; a pre-existing Secret not claimed by a KeyDelivery (unlabelled, or Phase A's) is SecretExists; a second declaration is SecretClaimed; observedGeneration tracks; Ready=False carries NotAuthorized for any authority failure; Ready=Unknown, Pending initially and while Authorized is Unknown; each Authorized=False reason is tied to deleting or retaining the Secret, and a kept Secret sets SecretRetained=True (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestConditionReasonsClosedSet TestReasonConditionTable TestOneDeclarationPerSecret TestReadyFalseCarriesNotAuthorized TestReadyUnknownPending TestAuthorizedFalseReasonActionMap TestSecretRetainedWhenKept
pend U44 "losing authority deletes exactly the owned Secret; the crash order is Secret, record, finalizer at every interruption point; ownership is the label, the owner annotation and that UID in the sealed record, not the ownerReference; the Secret's namespace and name must equal the record's target for that UID, and the record's entry must match the owner annotation; the orphan sweep removes a labelled Secret only when its owner annotation names a UID the sealed record holds, it is that UID's recorded target, and that object is gone or withdrawn, never on the label and owner annotation alone, never an unlabelled or foreign one; a forged label and a real UID on another Secret are left alone, charged to no share, one refused line under the reconciler, against the reconciler budget (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestLostAuthorityDeletesOnlyOwnedSecret TestFinalizerCrashOrder TestOrphanSweep TestForgedOwnerAnnotationOnOtherSecretIsLeftAlone
pend U45 "cross-user refusal with a fake peer-credential seam: a peer with uid B asks for list, read-for-exec, rotate, rm, deliver, withdraw and deliveries of uid A's entries and objects, and for any system/... name; every call is ErrNotFound with text identical to an absent entry of B's own, and the refused audit lines carry uid B (socket operations)" \
	k3sm/pkg/keystore/socket::TestCrossUserRefusedFakePeerCred TestCrossUserRefusedShareSpent TestNonRootCannotNameSystemEntries k3sm/pkg/keystore::TestUserRotateNotFoundIsNoOp TestExecReadAudited
check U46 "baseSocketDenies derives keys.sock from runtimed's keystorepaths.SocketPath(dataRoot), <dataRoot>/keystore-sock/keys.sock (socket listener)" \
	k3sm/pkg/provider::TestBaseSocketDeniesKeystoreSocket TestBaseSocketDeniesResolvesDataRoot runtimed/pkg/keystorepaths::TestNames
pend U47 "seam guard: the real primitives the keystore's tests replace are unreachable from a test build (user scopes)" \
	k3sm/pkg/keystore::TestRealPrimitivesUnreachable
check U48 "seam guard: the real primitives the socket listener's tests replace are unreachable from a test build; the peer-credential source is a constructor parameter of the listener, nil refused (socket listener)" \
	k3sm/pkg/keystore/socket::TestRealPrimitivesUnreachable TestListenerRequiresPeerCredSource

pend U49 "the shared keystore path names build with CGO_ENABLED=0 and import only the standard library; pkg/keystore never imports the sandbox package (sandbox change)" \
	runtimed/pkg/keystorepaths::TestLeafImportsOnlyTheStandardLibrary k3sm/pkg/keystore::TestKeystoreImportsNoSandbox
rootcheck U50 "root-run: the defeat list run as the service user against both flagged logs, by name under --root, a SKIP failing it, in a root-owned 0755 directory (a name operation refused by the flag or by the directory, EPERM or EACCES) and a service-owned 0700 one (refused by the flag, EPERM), then an owner chflags uchg beside sappnd and an owner chmod +a ACL write, each refused or, if it lands, refused by judgeLog: each defeat fails, F_SETFL clearing O_APPEND included, bytes and flag unchanged, O_APPEND still succeeds and a seek-then-write appends at the end" \
	k3sm/pkg/keystore::TestAppendOnlyDefeatListAsServiceUser
partial U51 "per-uid log fairness: the share is a fixed byte count, at most 1/16 of the hard cap; every line, reads included, is charged to its uid; a uid past its share has its mutations and reads refused with ErrLogFull while another uid's succeed, never as the global append failure; it cannot get another uid's mutations, reads or revocations refused, though it can delay them through the store lock; list and deliveries are rate-limited per uid (socket operations); delivered: all of it but the deliveries rate limit, through the socket's store bridge" "deliveries rate-limited per uid (the deliveries operation)" \
	k3sm/pkg/keystore/socket::TestLogSharePerUIDRefusesOnlyThatUID TestLogShareAtMostOneSixteenthOfHardCap TestShareRefusalIsNotGlobalAppendFailure TestReadRateLimitPerUID TestReadsChargedToShare TestShareExhaustionIsolatedPerUID k3sm/pkg/keystore::TestShareRefusalNotGlobalAppendFailureInStore TestExecReadPastShareRefused
check U52 "every root verb writes one audit line with via root once the log exists, and none before it; adopt, floor merge and its dry run included, a change made with exit 4 or 5 audited committed, a put, rotate or adopt whose later step failed (ErrCommitted) included, and an rm-scope whose removed-scopes record was renamed into place but whose data-root fsync failed (rm-scope's exit 4: this run changed something, or the record's durability is uncertain) (append-only files)" \
	k3sm/cmd/k3sm::TestEveryRootVerbWritesAuditLine TestAdoptWritesAuditLine TestFloorMergeWritesAuditLine TestKeysAuditResult TestKeysRmScopePartialExitsFour k3sm/pkg/keystore::TestRmScopeRecordFsyncFailureIsCommitted
pend U53 "every reconciler Secret write and delete, and every record withdrawal, writes one audit line with via reconciler, except drift repairs, coalesced to one line per delivery per 10 minutes (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestEveryReconcilerWriteAndDeleteAudited
check U54 "a pre-frame refusal writes a refused line with the peer uid, rate-limited per uid, drawing on the reconciler budget with its once-a-minute dropped-count summary; a dropped count is persisted in .preframe-dropped in the store directory, not kept only in memory, survives a reopen, is emptied once in the audit log, folds uids past 256 into others, is reported unreadable rather than reset, is shown by doctor, and is written by the next audit --rotate (socket listener)" \
	k3sm/pkg/keystore/socket::TestPreFrameRefusalsAudited TestPreFrameRefusalLinesRateLimited TestPreFrameReservedClassLimits k3sm/pkg/keystore::TestPreFrameFsyncFailureIsWrittenNotDropped TestPreFrameDroppedSurvivesReopen TestPreFrameDroppedClearedOnceWritten TestPreFrameDroppedCoalesced TestPreFrameDroppedFoldsOthers TestPreFrameDroppedCorruptFile TestPreFrameDroppedParseStrict TestPreFrameDroppedEncodeFits TestPreFrameDroppedRoundTrip TestRotateAuditWritesDroppedCounts TestRotateAuditKeepsDroppedOnRefusal TestRotateAuditIgnoresHostileDropped k3sm/cmd/k3sm::TestDoctorKeystorePreFrameDropped
pend U55 "a transient lookup, SAR or apiserver error leaves the Secret, the record entry and the finalizer, sets Authorized=Unknown with reason Indeterminate, and retries with backoff; a SAR with allowed=false and no evaluation error is a definitive denial whatever denied says, and an evaluation error or a failed call is Indeterminate; no sweep before readyz and the RBAC, KeyDelivery and Secret informers sync; every deleting outcome deletes only on two consecutive sweeps; only the allow-list of definitive outcomes deletes (ErrNotFound in a scope that opened among them), and every other sentinel, ErrScopeAbsent and, until a K7a amendment (U127), ErrScopeOwnerChanged included, is Indeterminate; against the real store, on ErrScopeOwnerChanged the reconciler reads the deliveries record under W without the GeneratedUID check only to find recorded targets for a lifecycle delete, deletes them by the target-matching rule, and never delivers, rotates or opens an entry (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestTransientErrorLeavesSecretSetsUnknown TestSAREvaluationErrorIsIndeterminate TestSARAllowedFalseWithoutErrorIsDenial TestNoSweepBeforeReady TestDenialNeedsTwoSweeps TestEverySentinelBesidesNotFoundIsIndeterminate \
	TestOwnerChangedRecordReadFindsTargetsAgainstRealStore
pend U56 "a delivery record with an unknown format version is refused by the store and read by the reconciler as Indeterminate, never as a denial (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore::TestDeliveryRecordUnknownVersionRefused k3sm/pkg/keystore/reconcile::TestUnknownRecordVersionIsIndeterminate
pend U57 "the entry grammar package imports only the standard library, exports the pattern, the maxLength and the parse, and passes the shared vector table (entry grammar)" \
	apis/keystore/entry::TestGrammarVectors TestImportsStdlibOnly
pend U58 "seam guard, repo level: every package on the closed seam-package list has its TestMain stubs and its TestRealPrimitivesUnreachable, and no package off the list declares a seam (user scopes)" \
	k3sm/pkg/keystore::TestEverySeamPackageHasAGuard
pend U59 "seam guard: pkg/keystore/reconcile's TestMain stubs its clock seam (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestRealPrimitivesUnreachable
partial U60 "seam guard: cmd/k3sm's TestMain stubs each of its seams: clock, uid resolver, client-side peer credentials, server code identity, exec, euid source, file-attribute writer (append-only files); delivered: euid source, uid resolver, exec, file-attribute writer (floor --rebuild and audit --rotate)" "client-side peer credentials and server code identity (the non-root CLI and exec); the clock when a keystore path in cmd/k3sm first reads it" \
	k3sm/cmd/k3sm::TestRealPrimitivesUnreachable
check U61 "seam guard: pkg/install's TestMain stubs its euid source and file-attribute writer (append-only files)" \
	k3sm/pkg/install::TestRealPrimitivesUnreachable
pend U62 "reconciler lines are charged to the delivery's owner uid: a deliver-write of a new version past the share is Indeterminate unless it is the rotation write that follows a rotate; a deliver-delete, a withdrawal's lines and the rotation write are never refused for the share and past it draw on the owner's 256 KiB reconciler allowance, never on its socket margin (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestReconcilerLinesChargedToOwner TestDeliverWritePastShareIsIndeterminate TestDeliverDeleteNeverRefusedForShare
pend U63 "entries live under .user/<uid>/entries/: entries named deliveries and scope.key are ordinary and touch neither scope file (user-scope store)" \
	k3sm/pkg/keystore::TestEntriesNamedDeliveriesAndScopeKeyAreOrdinary
pend U64 "a missing .user/<uid>/ or scope.key answers ErrScopeAbsent, never ErrNotFound; inside a scope whose scope.key opens, a missing entries/ directory or a missing deliveries record is ErrScopeAbsent too; ErrNotFound only for an entry missing from an entries/ that exists and opened; a read on a uid with no scope creates no directory and mints no K_u; the first mutating op does (user scopes)" \
	k3sm/pkg/keystore::TestReadDoesNotMintScope TestMissingScopeIsScopeAbsent TestMissingEntriesDirIsScopeAbsent TestMissingDeliveriesRecordIsScopeAbsent
pend U65 "ErrScopeAbsent is Indeterminate and deletes nothing; every allow-list outcome, not only a SAR denial, deletes only on two consecutive sweeps; single-server is re-checked from a fresh List before every sweep (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestAbsentScopeIsIndeterminate TestEveryDeletingOutcomeNeedsTwoSweeps TestSingleServerRecheckedBeforeEverySweep
pend U66 "a synthesized GeneratedUID (prefix FFFFEEEE-DDDD-CCCC-BBBB-AAAA) is ErrScopeOwnerUnknown and never bound; ErrScopeOwnerChanged only for a real GeneratedUID that differs (user scopes)" \
	k3sm/pkg/keystore::TestSynthesizedGeneratedUIDIsUnknown
check U67 "the revocation class (withdraw, rm, rotate, the withdrawal's floor line, the reconciler's deliver-delete, its deliver-write of a withdrawal and its rotation write) bypasses the share past it and draws on its uid's own budgets per log above the hard cap: a 256 KiB reconciler allowance and a separate 720 KiB socket margin; neither budget can draw on the other; refused only when the budget it draws on runs out, so one uid's revocations are never refused because of another uid; a no-op revocation is charged to the share; a uid whose budget is spent to under one line is counted per uid and never refuses the store start; a log passes the hard cap by at most 976 KiB per user scope (its 720 KiB socket margin and 256 KiB reconciler allowance), plus the 1 MiB reconciler budget (socket operations)" \
	k3sm/pkg/keystore::TestRevocationBypassesShareUsesReserve TestNoOpRevocationChargedToShare TestReserveKeepsReconcilerPart TestRevocationAllowanceIsPerUID \
	TestSocketMarginSeparateFromReconcilerAllowance TestShareLimitRefusesOnlyThatUID TestShareLimitInTheFloor TestShareRunningCountIsTheRecount \
	TestShareResetAfterAuditRotate TestShareConfigAtMostOneSixteenthOfHardCap TestLogReadBoundHoldsBothBudgets TestSpentRevocationBudgetIsPerUID TestUserRotateNoOpChargedToShare
rootcheck U68 "root-run: floor --rebuild and audit --rotate meet a symlink, a FIFO and a swapped directory at the marker, at keystore-staging/ and at their log's directory in keystore-logs/, and refuse before anything changes; a symlink, FIFO or directory inside keystore-staging/ is removed unread and the verb finishes; the verb never follows a planted name, the decoy it points at does not change, and no log byte changes on a refusal (append-only files)" \
	k3sm/cmd/k3sm::TestMaintenanceRefusesPlantedNames
pend U69 "the client pins the server: the peer's audit token (LOCAL_PEERTOKEN) must resolve to the cdhash of the installed /Library/k3sm/k3sm, or nothing is written; another service-user binary, a reused pid, a lookup error, an old server after an upgrade and a listener inherited or passed to another process are refused (non-root CLI and exec)" \
	k3sm/cmd/k3sm::TestClientPinsServerByInstalledCDHash TestClientRefusesServiceUIDPeerOfOtherCode TestClientRefusesReusedPeerPID TestClientCDHashMismatchNamesRestart TestClientPinWithInheritedOrPassedListener
notapplicable U70 "helper variant only: the floor helper admits only a service-uid peer whose audit token resolves to the installed binary's cdhash, the server pins the helper as root and that binary, and only append and read are served (K0 amendment, helper variant only)" \
	k3sm/pkg/keystore/floorhelper::TestFloorHelperPeerPinned TestFloorHelperRefusesOtherRequests
notapplicable U71 "helper variant only: every pod profile variant denies the floor helper's socket for connect, bind and every file operation (K0 amendment, helper variant only)" \
	runtimed/pkg/sandbox::TestFloorHelperSocketPodDenied
pend U72 "an orphan-cascade delete of a KeyDelivery, its Secret's ownerReference stripped, still deletes the Secret, found by label, owner annotation and the sealed record's UID (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestOrphanCascadeStillDeletesSecret
pend U73 "only an honoured, recorded KeyDelivery can claim a target for SecretClaimed; an older unrecorded object claims nothing; precedence comes only from honoured records plus creationTimestamp, then name; an Indeterminate object counts as honoured and keeps the claim until a definitive deleting outcome, so an indeterminate sweep keeps the claim; the owner annotation never decides (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestUnrecordedObjectDoesNotClaimTarget TestIndeterminateOwnerKeepsClaim
pend U74 "withdraw by namespace and name deletes the caller's own unrecorded object after checking requestedBy against the peer uid, with a UID precondition; another uid's object is not-found, worded as for an absent object (KeyDelivery authoring)" \
	k3sm/pkg/keystore/socket::TestWithdrawRemovesOwnUnrecordedObject TestWithdrawOtherUIDsObjectIsNotFound
pend U75 "the finalizer counts a scope unopenable for an owner change, or removed by rm-scope, as withdrawn and drops after the Secret is gone; a transient error keeps it (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestFinalizerDropsWhenScopeUnopenable
pend U76 "k3sm's CA refuses CN k3sm:local:* and O k3sm:local-users in issueLeaf, so every issuer and CSR path; the controller-manager has no cluster-signing key (KeyDelivery authoring)" \
	k3sm/pkg/certs::TestReservedLocalPrincipalsRefusedInCSR TestReservedLocalPrincipalsRefusedEveryIssuer k3sm/pkg/executor::TestControllerManagerHasNoClusterSigningKey
pend U77 "rm-scope revokes first: under the exclusive store lock it reads the sealed deliveries record, deletes each recorded delivery's Secret by the target-matching rule, and only then removes the scope; with the API server unreachable it refuses and changes nothing; with the record unopenable it refuses unless --orphan-secrets, which lists and leaves the labelled Secrets, each marked unauthenticated (annotation only) (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRmScopeDeletesDeliveredSecretsFirst TestRmScopeRefusesWithoutAPI TestRmScopeOrphanSecretsListsAndLeaves
pend U78 "SecretRetained is True whenever a labelled Secret stays while Authorized is Unknown or False: under Unknown with reason Indeterminate; NoneRetained only when none stays or Authorized is True (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestSecretRetainedTrueUnderUnknown
pend U79 "the rotation write that follows a rotate is in the revocation class: past the owner's share it draws on the owner's reconciler allowance, once per live delivery per log; the reconciler's need for one uid, 64 deliveries x 4 lines x 1 KiB, is 256 KiB, the whole allowance (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestRotationWriteUsesReserve
partial U80 "root-run: rm-scope, floor --rebuild and Rewrap of each scope.key (U128) walk .user/<uid>/ by descriptor with openat, unlinkat and O_NOFOLLOW; floor --rebuild refuses a planted symlink, FIFO or other non-regular file, and rm-scope removes each without following it; read with a bounded size, re-check SameFile after each open and never follow a swapped directory (append-only files); delivered: rm-scope and floor --rebuild, by a test that runs here and, as root, in --root's R1" "Rewrap of each scope.key (U128)" \
	k3sm/pkg/keystore::TestRootWalksRefusePlantedNames TestRemoveScopeWalksJudgedRoot
pend U81 "a KeyDelivery never touches a Phase A Secret: the label value is the constant keydelivery and the entry is in the annotation k3sm.io/keystore-entry; a target present and not claimed by a KeyDelivery is SecretExists, never overwritten or deleted (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestKeyDeliveryNeverTouchesPhaseASecret
check U82 "eligible peer uids are 501 to 2147483647: nobody (4294967294) and every uid at 2^31 or above are refused before any frame, with a refused line; 501 and 2147483647 are admitted; no scope is minted outside the range (socket listener)" \
	k3sm/pkg/keystore/socket::TestPeerUIDRangeRefusesNobodyAndHighUIDs
pend U83 "the reconciler checks the user-scope floor log: a missing or unflagged floor log is Indeterminate for writes, so no deliver-write runs until floor --rebuild; the floor holds writes and absence-driven deletes: an ErrNotFound delete is Indeterminate while the floor is missing or unflagged, a revocation-driven delete still deletes the Secret without the floor, and only the record withdrawal waits for it (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestReconcilerHoldsWritesWithoutFloor
check U84 "when a log's size is past the hard cap, doctor shows a Warn with the overshoot in bytes and the rotate or rebuild hint, and none at or below it; the overshoot is at most 976 KiB per user scope (its 720 KiB socket margin and 256 KiB reconciler allowance), plus the 1 MiB reconciler budget (socket operations)" \
	k3sm/cmd/k3sm::TestDoctorWarnsOnLogOvershoot
pend U85 "a reconciler line charged to no uid (a forged-Secret refused line, a drift repair, their summaries) draws on the reconciler budget, 1 MiB per log, separate from every uid and excluded from the hard-cap test; forged Secrets are counted in a bounded LRU of 1024 (namespace, name) pairs with no per-resourceVersion set, new pairs' lines at most 10 a minute and at most one summary refused line a minute carrying the dropped count; past the budget the lines are dropped and counted and doctor warns; N forged updates leave every uid able to read and mutate (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestForgedSecretFloodLeavesEveryUIDServed TestUnchargedLinesHaveOwnBudget
pend U86 "a drift repair (the reconciler re-creating or repairing a delivered Secret that someone other than the reconciler edited or deleted, at the version already delivered) is reconciler-class: it draws on the reconciler budget and is never charged to the owner's share or budgets; repairs are coalesced to one audit line per delivery per 10 minutes with a count, and rate-limited per delivery with exponential backoff capped at 10 minutes; a write of a new version after the owner's own rotate or put stays charged to the owner; Ready=Delivered compares k3sm.io/keystore-digest, the sha256 of the Secret's data, each sweep, so a substituted data under an intact version annotation is drift (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestDriftRepairNotChargedToOwner TestSubstitutedDataIsDrift
pend U87 "the admission policy also matches UPDATE and DELETE of keydeliveries and admits one only when the requester equals oldObject.spec.requestedBy, is the k3sm server's identity, or is in system:masters (and, for DELETE only, the namespace controller's ServiceAccount); a finalizer edit is an UPDATE, so another author can neither delete the object nor strip its finalizer; the reconciler's and withdraw's own writes pass; on a DELETE object is null and only oldObject is read; failurePolicy is Fail; rig leg E23 (KeyDelivery authoring)" \
	k3sm/pkg/policy::TestVAPRefusesDeleteByOtherAuthor TestVAPRefusesFinalizerStripByOtherAuthor
check U88 "floor --rebuild never lowers: it reads every scope whose scope.key opens under W without the GeneratedUID check, so an owner change or a departed account is rebuilt from its pointers (U129); if any scope's scope.key does not open under W or any other error stops it (ErrBusy included), it refuses to finish, names the scope and changes nothing; the deliveries record's AAD is scope, kind 0xFD, name deliveries, generation and sequence, its floor key is (user/<uid>, .deliveries, generation, seq), and the rebuild writes that key's line; a copied-back older deliveries record is refused against the floor, before and after a rebuild (append-only files)" \
	k3sm/pkg/keystore::TestRebuildRefusesOnUnopenableScope TestCopiedBackDeliveriesRecordRefused
partial U89 "reads take the store lock shared and mutations exclusive, through a writer-preferring in-process lock; a server exclusive hold targets at most 50 ms of work per operation, larger work chunked, no hold across an API call (the target measured in K7a, not checked); a reconciler revocation that gets ErrBusy retries up to 3 times with jitter in the same sweep before it is Indeterminate; under a sustained read load from other uids a revocation completes (KeyDelivery lifecycle); delivered: lock handoff checked, and no walk in a put or rotate hold but U108's named fallback (pkg/keystore, on synctest's clock); the work bound measured, not checked; rm pending" "the per-uid hold bound for an rm of a large entry (U108's pending part), the reconciler's retries, and its revocation under other uids' read load, TestRevocationCompletesUnderOtherUIDReadLoad (KeyDelivery lifecycle)" \
	TestWriterPreferringLock TestPrefLockWriterTimeoutAdmitsReaders TestPrefLockAdmitsReaderUnderWriterStream TestRotateHoldServesOtherUIDWithinLockWait
rootcheck U90 "root-run: the directory swap. A process running as the service user holds, from before floor --rebuild, audit --rotate or install's log creation, an O_APPEND descriptor on the old log, a descriptor on the log's live directory and one on keystore-logs/. Before every step and after, by path on the canonical log its open(O_WRONLY), open(O_WRONLY|O_TRUNC) and link() into its own directory each fail EPERM, and through the held descriptors F_SETFL clearing O_APPEND, pwrite and ftruncate fail EPERM while the file is flagged and openat for write fails EPERM, or ENOENT once the name is gone; at every hook the canonical log by path is a complete judged log, the whole old content or the whole new content, flags exactly SF_APPEND, the service user's, 0600, one link; at the end the new log holds what the verb wrote and the service user's O_APPEND lines, nothing the held descriptors did reaches the new log, and staging and the retired directory are empty. A crash at every step and a rerun of the same verb end valid, a rebuild that dropped lines exiting 4 with the same counts; the other verb run first harms nothing, and the first verb's rerun still finishes; the maintenance wait is the exclusive .lock, bounded at 30 s (append-only files)" \
	k3sm/cmd/k3sm::TestMaintenanceSwapRefusesServiceUser TestMaintenanceCrashAtEverySwapStepReruns k3sm/pkg/install::TestKeystoreLogCreationRefusesServiceUserAtEveryStep k3sm/pkg/keystore::TestStoreReadsSwappedLogDirAsRoot
check U91 "audit --rotate keeps four archives, .1 to .4, and refuses, changing nothing, when .4 exists unless --discard-oldest; the replacement directory holds an empty flagged log, a fresh root 0600 unflagged .1 holding the old log's bytes up to its size at open, made by cloning the old log, removing every extended attribute and any ACL from the clone (when one cannot be removed the clone is discarded and the archive is a copy), judging it with the logs' flags-and-ACL judge and truncating it to that size, or, when the volume refuses the clone, by a copy that first checks the volume's free space and refuses up front, changing nothing, short of the log's size plus the larger of 1 GiB and 2% of the volume's size, and the older archives carried by hard link as .2 to .4; every archive is root's 0600, unflagged, with no ACL, in keystore-logs/audit/archives/, root's 0700 (a 0755 one refuses), and an old log with an ACL is a Warn, never a refusal (the swap copies no ACL, and chmod -N fails on a flagged log), as a second link on one is; a marker with a second link is read, with a Warn, and a stale staging file is cleaned; a rerun after a crash past the swap prints the crashed run's report and does not rotate twice, and while the marker stands a missing audit log is never skipped; the doctor hint says to export first, as root, from archives/; rotation resets the shares, bounded by the archive count (append-only files)" \
	k3sm/cmd/k3sm::TestAuditRotateKeepsFourArchives k3sm/pkg/keystore::TestMaintenanceJudgesMarkerAndStale TestSwapRerunFromEachStep TestAuditRootRefusesMissingLogInMaintenance TestRotateAuditClonesArchive TestCloneArchiveTruncatesToSnapshot TestRotateAuditCopyChecksFreeSpace TestCopyArchiveMarginScalesWithVolume TestCloneArchiveStripsXattrsAndACL TestCloneArchiveProtectedXattr TestCloneArchiveRefusesRemainingACL TestJudgeArchiveRefusesACL TestOldLogUnflaggedServiceOwnedRefused
pend U92 "a rotate whose delivery will stall (owner past share, the delivery's rotation write used) is stored and answered stored; delivery pending: past your log share; the CLI prints the warning line and exits 0 (non-root CLI and exec)" \
	k3sm/cmd/k3sm::TestRotateReportsDeliveryStall
pend U93 "the sweep period is 30 s by default; two consecutive deleting observations count only when at least 60 s apart on the clock seam, however many sweeps run between them (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestDeletingObservationsSpacedOnClock
pend U94 "withdraw opens the caller's scope and so runs the GeneratedUID check: a reused uid with a changed GeneratedUID gets scope-owner-changed and deletes nothing (KeyDelivery authoring)" \
	k3sm/pkg/keystore/socket::TestWithdrawChecksGeneratedUID
pend U95 "rm-scope lists every RoleBinding and ClusterRoleBinding with the subject k3sm:local:<uid> and refuses, changing nothing, unless none exist or --keep-bindings is given (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRmScopeRefusesWithBindings
pend U96 "the deliveries record is exempt from the 64 KiB value cap and bounded at 64 live entries plus 256 withdrawn tombstones, 3,328 bytes an entry (8 items), 1,056 KiB sealed; at the bound deliver answers quota and a withdrawal still succeeds, in place; a tombstone is pruned only after its Secret is seen gone (Get not found) on two sweeps at least 60 s apart (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestDeliveriesRecordBoundAndPrune TestRevocationNeverRefusedAtRecordBound
pend U97 "when rotate answers ErrQuota, rm then put recovers: rm frees every version and put stores the value as version 1 of a new generation; no quota text recommends that recovery (user-scope store)" \
	k3sm/pkg/keystore::TestRotateQuotaRecoveredByRmThenPut
pend U98 "the sealed deliveries record stores each delivery's KeyDelivery metadata.name; the orphan sweep checks the object with a live Get by that name sent to the API server, never an informer cache and never a List; not found, or another UID, deletes only on two consecutive observations at least 60 s apart, any other answer resetting the count; no sweep before the KeyDelivery and Secret informers sync (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestOrphanSweepUsesLiveGetByName TestOrphanSweepNeedsTwoObservations
check U99 "under the store lock, before every audit or floor append, the server compares its descriptor's (dev, ino) with the canonical name's and reopens on a mismatch, recounting the shares; audit --rotate and floor --rebuild each complete while the server never saw the marker, and every later line lands in the new canonical file (socket listener)" \
	k3sm/pkg/keystore/socket::TestAppendReopensOnInodeMismatch
pend U100 "a departed account with an unreused uid is reported, not acted on: doctor lists every scope whose uid has no directory record (a synthesized GeneratedUID); each of that scope's deliveries gets SecretRetained=True with reason OwnerUnresolvable, and no Secret is deleted (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestDoctorListsUnresolvableScopes k3sm/pkg/keystore/reconcile::TestOwnerUnresolvableRetainedCondition
pend U102 "the sealed record stores the last delivered version per delivery, raised after the Secret write succeeds; the repair-versus-owner classifier uses only that recorded version: a rewritten version annotation and a rewritten status.deliveredVersion each leave the charge unchanged (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestChargingIgnoresTamperedVersionAnnotationAndStatus
pend U103 "a Secret at a recorded target whose label or owner annotation was removed is never overwritten or deleted, under a revocation, the object's deletion and rm-scope alike; the KeyDelivery gets SecretRetained=True with reason LabelRemoved, and doctor names the Secret and the KeyDelivery (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestStrippedLabelReportedNotDeleted
rootpend U104 "root-run: install creates keystore-sock/ root:wheel 0755 and the server plist carries a Sockets listener for keystore-sock/keys.sock; a process running as the service uid cannot unlink, replace or bind keys.sock, whether or not the server runs, and gets EACCES; rig leg E24 (socket listener)" \
	k3sm/pkg/install::TestSocketDirRootOwnedServiceUIDCannotBind
rootpend U105 "root-run: every root path walks the keystore trees by descriptor: install over an existing tree, uninstall --purge and doctor each refuse a planted symlink, FIFO or swapped directory, with openat, O_NOFOLLOW, bounded reads and a SameFile re-check (append-only files)" \
	k3sm/pkg/install::TestInstallOverExistingTreeWalksByDescriptor TestPurgeWalksKeystoreByDescriptor k3sm/cmd/k3sm::TestDoctorWalksKeystoreByDescriptor
pend U106 "every root verb refuses a non-root caller: one table test runs rm-scope, floor --rebuild, audit --rotate, rewrap and deliver system/... with a non-root euid through the euid source; each is refused, changing nothing (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRootVerbsRefuseNonRootEUID
pend U107 "with the user floor missing or unflagged, an absence-driven delete (ErrNotFound) is Indeterminate and deletes nothing, while a revocation-driven delete (a withdrawn record, a digest mismatch, a SAR denial) deletes the Secret after its two spaced observations (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestNotFoundDeleteWaitsForFloor TestRevocationDeleteProceedsWithoutFloor
partial U108 "the exclusive hold bound on a fake clock: no server exclusive hold spans any fake time, so no wait the clock sees runs inside a hold; the GeneratedUID lookup runs before the lock is taken and is cached for the hold (user scopes); delivered: no lookup or wait inside a hold, the quota judged on the usage figure with no scope walk under the lock but the fallback walk when the figure is still absent or stale at the lock (the walk before it failed, a root rm-scope and a new mint or a Rewrap landed between that walk and the lock, or the put minted the scope), rotate's orphan check reading only the version above the pointer, and list authenticating only the current version" "an rm hold bounded however many versions its entry keeps (its burial's header reads and unlinks chunked)" \
	k3sm/pkg/keystore::TestExclusiveHoldBound TestRotateAtQuotaNoFullWalk TestUsageFigureMatchesWalk TestUsagePanicAtWriteDropsFigure TestUsageRefusalKeepsFigure TestUserListOpensOnlyCurrentVersion TestUserRotateOrphanCheckReadsOnlyNextVersion TestDoneCtxAfterPreWalkTakesNoHold
pend U109 "with every audit append failing (a full disk), revocation deletes go ahead, their lines dropped and counted in memory and shown by doctor, while user mutations and reads stay refused (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestRevocationDeleteProceedsOnAppendFailure
pend U110 "when a second server registers at runtime, the next single-server check stops the listener and each KeyDelivery gets SecretRetained=True with reason UserScopeOff; the delivered Secrets stay and doctor says they must be deleted by hand (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestSecondServerAtRuntimeStopsListenerAndReports
pend U111 "the owner annotation never decides precedence: a Secret whose owner annotation is rewritten to name another recorded UID stays with the object that holds the claim by honoured record, creationTimestamp and name; an Indeterminate object counts as honoured (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestAnnotationRewriteCannotTakeOverTarget
check U112 "outside a grant (put, deliver), which appends before its first write, the order is commit, then append, then reply: an append that fails after the commit answers ok with the warning committed; audit failed, the server then refuses user mutations except the revocation class, and doctor counts the unaudited operations (socket operations)" \
	k3sm/pkg/keystore/socket::TestAuditFailureAfterCommitRepliesCommittedAuditFailed k3sm/cmd/k3sm::TestDoctorCountsUnauditedOps k3sm/pkg/keystore::TestUnauditedOpsCountsCommittedRevocations TestUserRotateCrashOrder
check U113 "the listener refuses to start unless the server's effective uid is the service uid: a rootless k3sm server runs no listener, and the server log and doctor say user scope needs the installed server (socket listener)" \
	k3sm/pkg/keystore/socket::TestListenerRefusesUnlessServiceUID
pend U114 "rm-scope writes keystore-removed-scopes.json in the data root, root-owned, through the data-root descriptor rules, before it removes the scope; only a scope listed there counts as removed for the finalizer, and a plain ErrScopeAbsent stays non-definitive and keeps the finalizer (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRmScopeRecordsRemovedScope k3sm/pkg/keystore/reconcile::TestOnlyRecordedRemovalCountsAsWithdrawn
pend U115 "rm-scope names each blocking binding, a RoleBinding with its namespace; --remove-bindings deletes each listed binding through the admin client before anything else changes, and a failed delete stops the verb (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRmScopeNamesBindingsAndRemovesThem
check U116 "the Pod uid refusal applies to native Pods only: a vm Pod with runAsUser: 1000 is allowed, since a guest uid has no host meaning, while a native Pod with the same drop target is refused, and a vm Pod's guest groups skip the host group rules the same way (sandbox change)" \
	runtimed/pkg/runtime::TestVMPodGuestUIDNotRefused
rootcheck U118 "root-run: the old log is retired, never re-owned: in audit --rotate and floor --rebuild the new log gets, in staging, its fchown to the service user, its fchmod 0600 and then its flag, between the build and report steps; the old log's one attribute call is its flag clear, made after the swap has made it unreachable by path, in the retired directory in keystore-staging/, which is then removed unread; it is never chowned or chmodded, ends unlinked with its owner, mode and bytes unchanged; rotate's archives, in archives/, are fresh root-owned unflagged copies, 0600 with one link, and the older archives carried by link are the same inodes and bytes (append-only files)" \
	k3sm/cmd/k3sm::TestMaintenanceOldLogRetiredNeverReowned
rootcheck U119 "root-run: the floor lock is keystore-lock, a root 0600 file in the data root that only root can open, taken by every root verb that writes the floor or a keystore file in the data root, rm-scope, floor --rebuild and audit --rotate included; a non-root process other than the service user holding the old data-root flock blocks none of them (append-only files)" \
	k3sm/pkg/keystore::TestNonRootDataRootFlockBlocksNoRootVerb
pend U120 "the activated listening descriptor reaches no child (integration): an exec.Command child, the runtimed helper and a Pod through the exec shim each list their open descriptors, and the listening socket is among none of them (socket listener)" \
	k3sm/pkg/keystore/socket::TestActivatedListenerReachesNoChild
pend U121 "under activation, a client whose connected peer reads as uid 0 or as launchd's code refuses and writes nothing; U36 is never relaxed to accept uid 0, and if K7a finds the client-side peer names launchd the self-bind form ships (socket listener)" \
	k3sm/cmd/k3sm::TestClientRefusesLaunchdAsPeer
pend U122 "when K7a finds that a Pod can obtain the server's listener from launchd, the self-bind form ships and every rendered Pod profile denies the launchd socket-activation lookup; rig leg E27 (socket listener)" \
	k3sm/pkg/provider::TestPodProfileDeniesLaunchdSocketActivation
pend U123 "same-target cross-record deletion: the orphan sweep, a lost-authority delete and rm-scope never delete a Secret that another honoured record claims at the same (namespace, secretName); a forged owner annotation naming one uid's tombstone on another uid's live Secret deletes nothing; the owner annotation never selects which record's tombstone governs a delete; nothing is charged to the victim (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestForgedTombstoneAnnotationOnOtherUsersLiveSecretIsNotDeleted
pend U124 "a tombstone is pruned when its target is not this UID's owned Secret on two observations at least 60 s apart, not only on a Get that answers not found: a target occupied by another Secret still prunes; a failed Get keeps it (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestTombstonePrunesWhenTargetOccupied
pend U125 "every reconciler Secret delete or update and every rm-scope delete passes Preconditions{UID, ResourceVersion} from the ownership read: a fake client swaps the Secret between the read and the delete, the delete is refused, and the outcome is Indeterminate (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestDeleteRefusedWhenSecretSwappedAfterRead
pend U126 "the reconciler budget is split by source, 384 KiB for forged-Secret lines, 384 KiB for repairs, 256 KiB for pre-frame refusals, the forged and repair parts capped at 64 KiB per namespace; one source or namespace spending its part leaves every other part whole; the dropped count is persisted in the next summary line written for that source, not kept only in memory (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestReconcilerBudgetSplitBySource TestDroppedCountPersistedInNextSummary
pend U127 "ErrScopeOwnerChanged is Indeterminate plus a doctor report, not a deleting outcome, until a K7a amendment records GeneratedUID stability across Migration Assistant, a macOS upgrade and a directory rebind: no Secret is deleted on it, and doctor names the scope (user scopes)" \
	k3sm/pkg/keystore/reconcile::TestScopeOwnerChangedIsIndeterminate k3sm/cmd/k3sm::TestDoctorReportsOwnerChangedScope
rootpend U128 "root-run: Rewrap of each scope.key, and every root write under server/keystore/, walks by descriptor: a planted symlink, FIFO or swapped directory under .user/ refuses Rewrap and changes no record (user-scope store)" \
	k3sm/pkg/keystore::TestRewrapWalksScopeKeysByDescriptor
pend U129 "floor --rebuild reads every scope whose scope.key opens under W without the GeneratedUID check: a departed account (ErrScopeOwnerUnknown) and an owner change each get their lines and block nothing (user scopes)" \
	k3sm/cmd/k3sm::TestRebuildReadsScopeWithoutOwnerCheck
pend U130 "a scope listed in keystore-removed-scopes.json for its bound GeneratedUID is definitive for claims, so its stale objects lose their claim; rm-scope deletes that scope's KeyDeliveries, each by its recorded namespace and name with a UID precondition (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestRemovedScopeLosesClaim k3sm/cmd/k3sm::TestRmScopeDeletesScopeKeyDeliveries
check U131 "the listener refuses to start on a data root mounted with MNT_IGNORE_OWNERSHIP, read with fstatfs on the data-root descriptor (socket listener)" \
	k3sm/pkg/keystore/socket::TestStartRefusesIgnoreOwnershipMount k3sm/cmd/k3sm::TestKeystoreSocketDataRootPerPass
pend U132 ".user/<uid>/ is 0700 and scope.key and deliveries are 0600, all the service user's; a scope whose directory or files have another owner or a wider mode is refused (user scopes)" \
	k3sm/pkg/keystore::TestUserScopeFileModes
pend U133 "keystore-removed-scopes.json is root-owned 0644, under the keystore- prefix the Pod denies cover; a file that is not root's or is group- or other-writable is refused, and the parse is strict, a refused file counting as no listing (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRemovedScopesFileRootOwnedAndMode TestRemovedScopesFileStrictParse
pend U134 "the reconciler's store interface reads a value only for an authorised delivery: its value read takes the authorisation the checks produced, and no other method returns a value (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestStoreInterfaceReadsValueOnlyForAuthorisedDelivery
pend U135 "the KeyDelivery admission policy's failurePolicy is Fail, and the namespace-controller exemption admits DELETE only: the namespace controller's UPDATE of another author's object is refused (KeyDelivery authoring)" \
	k3sm/pkg/policy::TestKeyDeliveryVAPFailurePolicyFail TestNamespaceControllerExemptOnlyForDelete
pend U136 "every root verb and doctor line that prints annotation text strips control characters first: an owner or entry annotation carrying terminal escapes prints without them (socket operations, KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRootVerbsStripAnnotationControlChars
check U137 "the listener refuses a sandboxed peer before the first frame: it calls sandbox_check on the peer's audit token through the peer-sandbox source, a constructor parameter that refuses nil, so a Pod process is refused whatever its uid; rig leg E26 (socket listener)" \
	k3sm/pkg/keystore/socket::TestListenerRefusesSandboxedPeer TestSandboxSelfCheckKeepsListenerOff
pend U138 "--listed fails on a duplicated U or E id: in the script's rows, its expected-row list, one mode's row list, or the design's gate and leg tables (the typed-credential design)"
pend U139 "items required, no default, 1 to 8, unique keys, the key pattern with . and a .. prefix refused, both maxLengths, immutable as a map (a reorder accepted, a change refused), CEL cost within budget; no dataKey (the typed KeyDelivery API)" \
	apis/config/crd::TestKeyDeliveryItemsSchema TestItemKeyMatchesIsConfigMapKey TestKeyDeliveryHasNoDataKey TestItemsReorderAcceptedChangeRefused TestItemsCELCostWithinBudget
pend U140 "the field enum equals the credential table's union; a KeyDelivery naming refreshToken is refused by the schema; rig leg E31 (the typed KeyDelivery API)" \
	apis/config/crd::TestFieldEnumEqualsCredentialTable TestSchemaRefusesRefreshTokenField
check U141 "the credential leaf: kind names, field table vectors, no refresh field, the item type, the refresh-owner vectors, closed validity, Event and refresh_state sets, the metadata keys; stdlib only" \
	apis/keystore/credential::TestFieldTableVectors TestNoRefreshField TestRefreshOwnerGrammarVectors TestNameSetsClosed TestImportsStdlibOnly
pend U142 "the CRD descriptions list the CredentialValid reasons and ProjectionInvalid, say Ready means delivered and that Valid, Expiring and RefreshFailing share True; every condition has observedGeneration (the typed KeyDelivery API)" \
	apis/config/crd::TestKeyDeliveryReasonDescriptions TestConditionsCarryObservedGeneration
check U143 "the envelope matches committed per-kind golden vectors; unknown tag, duplicate, disorder, missing field or out-of-bound field is ErrCorrupt; the fuzz invariants hold" \
	k3sm/pkg/keystore/typed::TestEnvelopeGoldenVectors TestEnvelopeRejectsUnknownTagDuplicateAndOrder TestFieldTablesSortedByTag FuzzEnvelopeParse
check U144 "token and oauth require a sealed issuedAt/accessIssuedAt stamped from the clock seam; editing the created header changes no typed time" \
	k3sm/pkg/keystore::TestTypedIssuedAtStampedAndSealed TestCreatedHeaderEditChangesNoTypedTime TestExpiryCheckedOnSealedSeconds k3sm/pkg/keystore/typed::TestExpiryOrderEnforced
check U145 "a relabelled typed record fails to open; kind-byte table: 6 to 0xFC and an unknown envelope version are ErrKindUnsupported, 0xFD and 0xFE ErrCorrupt; list shows unsupported" \
	k3sm/pkg/keystore::TestTypedKindRelabelFailsOpen TestKindByteTable TestListShowsUnsupportedKind
check U146 "rotate and put over an existing entry cannot change its kind (ErrKindMismatch), nor can rotate --from-version from a version of another kind" \
	k3sm/pkg/keystore::TestRotateAndPutCannotChangeKind TestRotateFromRefusesOtherKind
check U147 "token needs expiresAt; oauth needs access token, access expiry, refresh token and an owner in the grammar" \
	k3sm/pkg/keystore::TestTypedPutValidation
check U148 "SSH generate uses the random seam; import accepts unencrypted OpenSSH ed25519 only; the fingerprint equals a committed ssh-keygen -l vector" \
	k3sm/pkg/keystore/typed::TestSSHGenerateAndImport TestSSHFingerprintMatchesOpenSSH TestSSHImportRefusesMalformed k3sm/pkg/keystore::TestStoreGenerateSSHUsesRandomSeam
partial U149 "write-only, structurally: a planted refresh token appears in no result of any exported method of pkg/keystore, raw, hex, base64 or URL-encoded; a typed entry reads back only as a typed.Credential (CurrentCredential, GetCredential), and Current and Get refuse it" "the consumer interfaces and only refresh (and the installing pkg/keystore) imports internal/refreshopen (the refresher)" \
	k3sm/pkg/keystore::TestPlantedRefreshTokenNeverReturned TestGetReturnsRedactedCredential k3sm/pkg/keystore/typed::TestEnvelopeRefusalsNeverCarryRefreshToken TestShortSecretNeverInRefusals TestSecretTypesRedactWhenFormatted TestNoUnexportedSecretField TestDecodeRefusalClearsClones k3sm/pkg/keystore::TestTypedPlaintextZeroedAfterSeal
check U150 "RotateIf refuses a stale version, and a version read from an entry since deleted and put again; a rotation never changes an oauth entry's refresh owner" \
	k3sm/pkg/keystore::TestRotateIfStaleVersionRefused TestRotateIfRefusesRecreatedEntry TestRotateIfRefusesVersionBuiltOutside TestRefreshOwnerFixedPerEntry TestRotateIfRefusesSameNumberDifferentRecord
check U151 "oauth keeps current and one previous; the low-water mark is in the sealed pointer (24 bytes only after a prune, 16 means low = 1); crash-safe at every step, prune included (the prune cases of the crash test); a failure after the pointer flip reports the commit" \
	k3sm/pkg/keystore::TestOAuthPruneKeepsTwo TestPointerLowWaterMark TestRotateCrashAtEveryStep TestRotateReportsCommitAfterFlip TestCommitPointReported TestFloorLagNeverDeletesCommittedVersion TestPointerCanonicalForm TestOAuthRetentionWindowOnRead FuzzPointerPlaintext TestOAuthVersionCeiling
check U152 "a pruned oauth entry: List shows it healthy, Rewrap re-seals low..current, Delete removes leftovers, a gap inside the range is damage, a copied-back pointer is caught" \
	k3sm/pkg/keystore::TestListPrunedOAuthEntryNotCorrupt TestRewrapHandlesPrunedOAuth TestDeletePrunedOAuthEntry TestGapInsideCommittedRangeIsCorrupt TestCopyBackAcrossPruneCaught
check U153 "--from-version is refused for oauth" \
	k3sm/pkg/keystore::TestFromVersionRefusedForOAuth
check U154 "every Fuzz* target in the keystore packages has a non-empty committed seed directory" \
	k3sm/pkg/keystore::TestEveryFuzzTargetHasSeeds
pend U155 "HELLO lists capabilities; mutating ops refuse an unknown header (unknown-header), non-mutating ops tolerate it; the CLI refuses a typed request to a daemon without the capability (the typed verbs)" \
	k3sm/pkg/keystore/socket::TestHelloListsCapabilities TestMutatingOpRefusesUnknownHeader TestNonMutatingOpToleratesUnknownHeader k3sm/cmd/k3sm::TestCLIRefusesTypedAgainstOldDaemon
pend U156 "an oauth put takes an RFC 6749 response, stamps times from the clock, drops id_token and unknown fields; an error response is refused printing only the code (the typed verbs)" \
	k3sm/pkg/keystore/socket::TestPutOAuthTokenResponse TestTokenResponseWithErrorRefused FuzzTokenResponseParse
pend U157 "generate returns only the public key; pubkey prints only the public line (the typed verbs)" \
	k3sm/pkg/keystore/socket::TestGenerateReturnsPublicKeyOnly k3sm/cmd/k3sm::TestKeysPubkeyPrintsOnlyPublicKey
pend U158 "the kind flags; per-kind exec field defaults, ssh needs a field; show --field and exec --field refuse refreshToken; kind-mismatch on the wire (the typed verbs)" \
	k3sm/cmd/k3sm::TestKeysPutKindFlags TestKeysExecFieldDefaults TestFieldSelectionRefusesRefreshToken k3sm/pkg/keystore/socket::TestRotateKindMismatch
pend U159 "list -o json and the socket list carry the typed metadata (snake_case) and no token bytes (planted) (the typed verbs)" \
	k3sm/cmd/k3sm::TestKeysListJSONTypedMetadata
pend U160 "typed.Project is exact per kind and supports exactly the apis table's fields; a planted refresh token is in no projection for any item set (typed projection)" \
	k3sm/pkg/keystore/typed::TestProjectFieldsPerKind TestProjectSupportsExactlyCredentialTable TestProjectNeverEmitsRefreshToken
pend U161 "the Secret's data keys equal items; a field wrong for the kind gives ProjectionInvalid with the Secret unchanged; digest golden vectors over entry, namespace, secretName and key-sorted items, order-insensitive (typed projection)" \
	k3sm/pkg/keystore/reconcile::TestItemsProjectExactKeys TestProjectionInvalidLeavesSecret TestDigestGoldenVectors
pend U162 "root-file items are parsed strictly and use the same projection (typed projection)" \
	k3sm/pkg/keystore/reconcile::TestRootFileItemsStrictAndProjected
pend U163 "--item, --data-key shorthand, per-kind defaults; an ssh delivery without items is refused (typed projection)" \
	k3sm/cmd/k3sm::TestDeliverItemDefaultsPerKind TestDeliverSSHWithoutItemsRefused
pend U164 "ErrKindUnsupported and ErrCorrupt on a typed entry are Indeterminate; encryption off refuses every typed kind (G18) (typed projection)" \
	k3sm/pkg/keystore/reconcile::TestTypedEntryErrorsAreIndeterminate TestEncryptionOffRefusesTypedKinds
pend U165 "the CredentialValid table on a fake clock, thresholds from issuedAt, the oauth rules, the nil-RefreshStatus fallback, observedGeneration set (expiry and revocation)" \
	k3sm/pkg/keystore/reconcile::TestCredentialValidConditionTable TestExpiringThresholdUsesIssuedAt TestNilRefreshStatusUsesStoredExpiry
pend U166 "Events: events.k8s.io, related the Secret, Warning or Normal per reason, once per real transition with hysteresis; prior state from persisted status, so a restart re-emits none (expiry and revocation)" \
	k3sm/pkg/keystore/reconcile::TestCredentialEventsOncePerTransition TestCredentialEventTypesAndRelated TestRestartReemitsNoCredentialEvent
pend U167 "messages carry names, times and a closed cause only (planted token and error body absent) (expiry and revocation)" \
	k3sm/pkg/keystore/reconcile::TestCredentialEventsCarryNamesOnly
pend U168 "expiry never deletes the Secret and never changes Ready; requeue at the next threshold (expiry and revocation)" \
	k3sm/pkg/keystore/reconcile::TestExpiredKeepsSecret TestRequeueAtNextThreshold
pend U169 "the mount observer is level-based: one baseline line at start, a relist emits nothing, tombstones and terminal pods unmount (the mount audit)" \
	k3sm/pkg/keystore/mountaudit::TestStartupBaselineOneLine TestRelistEmitsNothing TestTombstoneAndTerminalPodsUnmount
pend U170 "pod-refresh only for volume and projected refs without subPath; env, envFrom and subPath get refreshes: false and never pod-refresh (the mount audit)" \
	k3sm/pkg/keystore/mountaudit::TestPodRefreshOnlyForRefreshingRefs
pend U171 "the mount-line field set is closed; lines are built from metadata only, on the error path too (planted token) (the mount audit)" \
	k3sm/pkg/keystore/mountaudit::TestMountLineFieldsClosed TestMountLinesMetadataOnly
pend U172 "a first-seen pair is never rate-limited; repeats are limited per namespace and globally, with a summary; all stop at the soft cap; never ErrLogFull; an append failure fails nothing; server class (the mount audit)" \
	k3sm/pkg/keystore/mountaudit::TestFirstSeenNeverDropped TestRepeatsRateLimitedAndGlobalCap TestMountLinesStopAtSoftCap TestMountLinesNotCharged
pend U173 "the provider's MountObserver: at the caller of Secret(), metadata from the lister, once per pod per version, labelled Secrets only, bounded per pod track, no re-emit after a restart, no value in the Event (the mount audit)" \
	k3sm/pkg/provider::TestKeystoreSecretMountedOncePerVersion TestMountObserverReadsListerNotData TestMountObserverRestartReplay TestKeystoreMountEventCarriesNoValue
pend U174 "a doctor row and a server Warn at 80% of the soft cap (the mount audit)" \
	k3sm/cmd/k3sm::TestDoctorAuditSoftCapWarnAt80
pend U175 "the profile file is strict and fuzzed; owner and mode 0640 root:_k3sm through the floor helper's stat seam; --client-secret-entry checks; revokedErrorCodes default (refresh profiles)" \
	k3sm/pkg/keystore/refresh::TestProfileFileStrict TestProfileFileOwnerAndMode FuzzProfileFile TestRevokedErrorCodesDefault
pend U176 "refresh-profile add validates the URL: https, no userinfo, no fragment, no IP literal without --allow-private (refresh profiles)" \
	k3sm/cmd/k3sm::TestRefreshProfileAddValidatesURL
pend U177 "Proxy is nil; a redirect is response-invalid; 64 KiB cap; timeout; a 200 with an error field is an error (fake RoundTripper) (refresh profiles)" \
	k3sm/pkg/keystore/refresh::TestRefreshClientProxyNil TestRefreshClientRefusesRedirect TestRefreshResponseCap TestHTTP200WithErrorIsError
pend U178 "the dial guard's deny table on synthetic addresses, the --allow-private override, and a rebind to 169.254.169.254 through a fake resolver; rig leg E36 (refresh profiles)" \
	k3sm/pkg/keystore/refresh::TestDialGuardDenyTable TestDialGuardAllowPrivate TestDialGuardRefusesRebindToLinkLocal
pend U179 "error mapping against golden response fixtures; the cause set is closed (dns, clock-skew included); a RetrieveError body never reaches a log or error (refresh profiles)" \
	k3sm/pkg/keystore/refresh::TestErrorMappingGoldenFixtures TestRefreshCausesClosedSet TestRetrieveErrorBodyNeverSurfaces
pend U180 "the refresh package's TestMain stubs its RoundTripper factory, resolver, Control and clock seams; refresh and mountaudit are on U58's seam-package list (refresh profiles)" \
	k3sm/pkg/keystore/refresh::TestRealPrimitivesUnreachable k3sm/pkg/keystore::TestEverySeamPackageHasAGuard
pend U181 "refresh-profile test sends a random refresh token, never a stored one, and passes only on a revoked-code answer (refresh profiles)" \
	k3sm/cmd/k3sm::TestRefreshProfileTestSendsNoStoredToken
pend U182 "schedule at half of accessExpiresAt − accessIssuedAt, lead, jitter, minimum interval, nearest-expiry first, backoff bound, retry at the maximum past access expiry (synctest, in-bubble fake RoundTripper) (the refresher)" \
	k3sm/pkg/keystore/refresh::TestRefreshSchedule TestRetriesPastAccessExpiry
pend U183 "success rotates via RotateIf and prunes; a missing refresh_token keeps the old one; one compacted summary line per entry per UTC day, at most 512 bytes, charged to no uid (the refresher)" \
	k3sm/pkg/keystore/refresh::TestRefreshRotatesEntry TestRefreshKeepsRefreshTokenWhenNotReturned TestRefreshOkCompactedPerDay TestRefresherLinesServerClass
pend U184 "a revoked code parks; unpark by a new version at most once per 10 minutes; refresh-state.json holds names and states only; losing it costs one retry (the refresher)" \
	k3sm/pkg/keystore/refresh::TestRevokedCodeParks TestUnparkRateLimited TestRefreshStateFileHoldsNoSecret TestLostRefreshStateCostsOneRetry
pend U185 "an owner's rotate during a refresh wins (the refresher)" \
	k3sm/pkg/keystore/refresh::TestOwnerRotateDuringRefreshWins
pend U186 "local is never server-refreshed; per-uid-per-profile fairness; global and per-user caps (the refresher)" \
	k3sm/pkg/keystore/refresh::TestLocalOwnerNeverServerRefreshed TestRefreshFairnessPerUIDPerProfile TestRefreshCaps
pend U187 "a second server joining mid-run pauses the refresher before its next refresh; removing it resumes with no restart (the refresher)" \
	k3sm/pkg/keystore/refresh::TestSecondServerPausesAndRemovalResumes
pend U188 "SIGTERM stops new refreshes and drains in-flight ones within 10 s; no refresh starts under the maintenance marker or exclusive lock; the lock order holds (the refresher)" \
	k3sm/pkg/keystore/refresh::TestShutdownDrainsWithin10s TestNoRefreshUnderMaintenance TestLockOrderLeaseThenLock
pend U189 "refresh-now is owner-only, rate-limited, refresh-not-owned for local, sends nothing for a parked pair (the refresher)" \
	k3sm/pkg/keystore/socket::TestRefreshNowOwnerOnly
pend U190 "the refresher doctor rows; every state change logs at Warn or Error under io.k3sm.keystore, names and causes only (the refresher)" \
	k3sm/cmd/k3sm::TestDoctorRefresherRows k3sm/pkg/keystore/refresh::TestStateChangesLogAtWarn
pend U191 "examples/keydelivery-github.yaml validates against the apis CRD schema; limitations.md lists the typed-credential residuals (the typed-credential docs)" \
	k3sm/examples::TestKeyDeliveryExamplesValidateAgainstCRD TestLimitationsListTypedResiduals
check U192 "the floor's tombstones: a completed Delete buries the floor's live generation for the name (with no live record, the directory's only when its pointer authenticates under it with the master, so a planted generation buries nothing) with a delete sequence, without the master too; a later Put keeps the buried set; at most 64 buried generations a name; tombstones use at most 1 MiB of the 4 MiB floor and are pruned oldest first, never a live entry, each prune logged at Warn; a floor with no tombstones field parses, and a burial is parsed as strictly as an entry; keys floor merge carries every burial of the moved-aside floor into a restored one, burying a generation it holds live and each moved-aside live generation it does not hold live (--keep spares only the restored generation; an unmatched --keep refuses), fencing a restored generation, and recording a kept one the restored floor does not record, with a high-water mark one past the higher of the moved-aside sequence and mark (+1) that readers and the raise honour and Rotate seals above, under keystore-lock alone, reading only the data root's keystore-floor.json.pre-restore (no path; a guard file replaced during the merge refuses it), reading the restored pointers only from the root-only pre-restore.d/restored the recipe stages (pre-restore.d refused with an extended ACL; anything at the keystore directory, a symlink counted, is moved aside into pre-restore.d/planted-<unix> through directory descriptors with RENAME_EXCL and reported, a dry run moving nothing; with nothing staged a merge that would change the floor refuses), fencing above the moved-aside tree's authenticated pointer too (pre-restore.d/keystore), refusing a staged tree holding anything the store does not write (a name outside the entry-file allowlist, a non-regular file, a second link, a setuid, setgid or sticky bit, a flag, an ACL, a file over its cap, an owner but the service user or the unknown owner), dry run included, handing it to the service user through descriptors (openat O_NOFOLLOW, fstat, fchmod, fchown, fstat again; a link gained refuses it) and fsyncing every file and directory of it before the rename and moving it into place with renameatx_np RENAME_EXCL after the floor write (a failed move exits 5 and a rerun completes it; a rerun that finds the floor written words a refusal of the staged tree or of the move aside as committed and exits 5, dry run included), raising a restored record to its authenticated pointer by at most one sequence (a higher pointer is unverified and fenced), refusing an absent live floor, the live floor itself and a merge that would retire every moved-aside live record, renaming its input to keystore-floor.json.merged-<unix> (a rerun after a failed rename writes nothing and renames it; that failure exits 5), pruned and reported, refusing a write that would drop any burial, the restored floor's own included (rm's under the guard numbered above guardEraSeq, kept newer than the merged ones, the band kept at the sequence limit and renumbered back by a Delete with no guard), naming keys rm only when the floor size binds and --accept-drops (which writes it, prints each drop and exits 4) when the tombstone budget or the per-name cap does, never dropping a buried-live burial even with --accept-drops (that refusal names keys rm), removing the staged directory of each entry whose staged generation the merged floor buries or whose burial the write drops, recording before the floor write, as its commit marker, the input's and the written floor's sha256 and what it retired, buried live, kept and dropped in a root-owned keystore-floor.json.pre-restore.retired renamed with the input to keystore-floor.json.merged-<unix>.retired (a rerun finding that record and that floor, or that floor with only burials added since, never plans the floor again and reports from the record, keeping those burials and removing their staged directories, any other floor fails closed, and rm runs while the record is pending, first recording each burial its write drops in a root-owned keystore-floor.json.pre-restore.rm-dropped bound to the record, which a rerun accepts gone; a rerun after the record's rename and before the input's renames only the input), refusing --keep of an entry rm deleted after the restore, that --undo reads only when its input is the live floor to report a version the restore retired apart from one deleted since (refusing --keep on the latter, and refusing with no matching record), refusing pre-restore.d on another device than the keystore's directory, exiting 4 too when it keeps an entry, leaves one unverified (with pre-restore.d/keystore absent, each moved-aside live entry) or moves a planted target aside, and 5 when a directory fsync after the tree's rename fails (a restored pointer, or a moved-aside one that does not authenticate or has no master to load), --dry-run writing nothing and exiting as the merge would; while keystore-floor.json.pre-restore is in the data root Put, Rotate and Rewrap refuse, Delete refuses with no live floor, RaiseFloor raises nothing and the delivery reconciler delivers nothing (guarded delivery); a committed change whose floor write evicted a burial exits 4, and list and show warn of it and exit 0 (the floor's tombstone)" \
	TestTombstoneKeptByPut TestDeleteWithoutMasterTombstones TestTombstonePrune TestTombstoneNeverRefusesPut TestPruneLogsAtWarn TestParseFloorTombstones TestFloorOpsProperty TestDeleteSequenceNeverWraps TestDeleteIgnoresPlantedGeneration TestPerNameCapIsBackstop TestDeleteWithoutMasterWarnsUnrecorded TestDeleteReportsEvictedTombstone TestDeleteWarnsUnrecordedWithMaster TestFloorMergeSemantics TestFloorMergeCapsAndPrune TestFloorMergeRefusesUntrusted TestFloorMergeBuriesRevokedLive TestMergeFloorKeep TestFloorMergeRetiresAsideLive TestFloorMergeRefusesUntrustedPlace TestDeleteReportsAnyEvictedTombstone TestFloorHighWaterEncoding TestFloorHighWaterCheckRaise TestFloorMergeFencesAbandonedHistory TestMergeFloorIgnoresEntryLock TestMergeFloorRefusesWrongInput TestPendingMergeGuard TestEvictionReportedCommitted TestMergeFloorRefusesUnmatchedKeep TestMergeFloorRefusesDroppingItsOwnBurials TestFloorMergeKeepRecordsAsideLive TestDeleteNotFoundReportsEviction FuzzParseFloor FuzzMergeFloor TestMergeFloorReadsOnlyTheGuardFile TestFloorMergeBoundsRestoredRaise TestGuardEraBurialSurvivesPressuredMerge TestGuardEraTombstoneBudget TestGuardEraBurialPerNameCap TestPendingMergeDeleteNeedsLiveFloor TestMergeFloorRefusesRetiringEverything TestFloorMergeRefusesExistingTarget TestFloorMergeFencesAboveAsidePointer TestFloorMergeMovesStagedTree TestFloorMergeNeedsStagedTree TestMergeFloorNeverDropsBuriedLive TestMergeFloorRefusesDroppingRestoredBurials FuzzPlanMerge TestPlanMergeKeepTwiceWritesNothing TestFuzzRmReportsCapEviction TestPlanMergeUnmatchedKeepRefusedFirst FuzzDeleteUnderGuardAtLimit TestDeleteRenormalisesStaleBand TestFloorMergeRemovesGuardBuriedStaged TestChownStagedRefusesShape TestChownStagedRefusesACL TestChownStagedRefusesForeignOwner TestChownStagedRecheckSeam TestChownStagedNameBound TestChownStagedSetsModes TestFloorMergeShapeDryRunParity FuzzStagedChild TestFloorMergeRemovesBuriedLiveStaged TestParseRetired TestFloorMergeRerunCommittedWording TestFloorMergeAsideUnverified TestFloorMergeSyncsStagedTree TestOpenStagingRefusesACL TestFloorMergeRerunAfterAcceptDrops TestFloorMergeKeptOnlyWritesRecord TestFloorMergePointerOnlyRefusalNotCommitted TestFloorMergeRerunKeepsRetiredSets TestFloorMergeRerunFloorChanged TestFloorMergeUndoRecord TestFloorMergeAbsentAsideTree TestFloorMergeRerunAfterMoveNotUnverified TestFloorMergeRemovedStagedNamed TestFloorMergeMoveSyncCommitted TestFloorMergeRemovesAsideBuriedStaged TestFloorMergeRemovesDroppedStaged TestFloorMergeRefusesTwoDevices TestFloorMergeRerunAfterDelete TestFloorMergeDeleteBeforeFloorWrite TestFloorMergeRerunNonMonotone TestFloorMergeRerunAfterRmPrune TestPendingSinceReadFloorNotCommitted TestFloorMergeCrashBetweenRenames TestFloorMergeCrashBetweenRenamesClearsRmDropped TestFloorMergeFirstRunRemovesRmDroppedStaged TestDeleteUnderGuardNeverRefusedBySidecar TestParseRmDroppedMark TestMergeFloorRefusesKeepAfterRm TestClassifyUndoDeletedSince FuzzRerunPredicates TestBuriedSinceFence TestFloorMergeBoundsAsidePointer TestFloorMergeStagedNodeBudget TestStagedHoldsUserScopes TestStagedPreFrameDroppedAccepted TestStagedPreFrameDroppedRefused TestStagedPreFrameDroppedUnknownOwner TestStagedPreFrameDroppedTempNotParsed k3sm/cmd/k3sm::TestKeysEvictionExitsCommitted TestKeysPendingMergeGuard TestKeysReadVerbsWarnEviction TestKeysFloorMergeTakesNoFile TestKeysFloorMergeAcceptDrops TestKeysFloorMergeDryRun TestKeysFloorMergeReportCodes TestKeysFloorMergeMovesPlantedAside TestKeysFloorMergeCommittedRerunRefused
check U193 "floor --rebuild carries the old floor forward: over an old floor holding tombstones, sequence lines and a torn last line (which the reader already skips as counted damage, so the floor served throughout), it keeps every tombstone and every key's highest sequence that parses, writes the higher of that and the sequence on disk, drops the lines that do not parse and names their count (U196 holds the other classes it drops); a tree copied back after an rm, a crash and a rebuild is refused as deleted, and a copied-back older record is refused; a floor that cannot be read refuses the rebuild, changing nothing (append-only files: the rebuild verb)" \
	k3sm/pkg/keystore::TestRebuildCarriesTombstonesForward
check U194 "once root removes a user scope (rm-scope), floor --rebuild drops every key of that scope, live or buried, by position: the uid's lines before the floor size rm-scope recorded, keeping every line after it, so a re-minted scope whose directory is later deleted by hand keeps its tombstones and a copy-back of it is refused; a re-minted scope gets a fresh K_u, and rm-scope's record refuses the old scope key (U197); the rebuild frees the uid's lifetime key share and its keys in the global key bound (append-only files: the rebuild verb, after rm-scope)" \
	k3sm/pkg/keystore::TestRebuildDropsRemovedScopeKeys TestRebuildKeepsReMintedScopeTombstones
rootcheck U195 "root-run: the SF_APPEND facts measured on 2026-11-23: on a flagged file root's fchown, fchmod, rename, link, unlink and O_TRUNC open are each EPERM; chown then flag works, and root's fchown back is then EPERM; a descriptor opened without O_APPEND before the flag can neither pwrite nor ftruncate once it is set; the service user's link() of a root-owned 0600 unflagged file into its own directory succeeds, and of a file flagged UF_IMMUTABLE, UF_APPEND or SF_APPEND fails with EPERM, whether root or the service user owns it. The second probe: root's rename and RENAME_SWAP of directories holding flagged files work; once the retired log is unflagged a descriptor held from before can clear O_APPEND, pwrite and ftruncate it, and a held directory descriptor can openat it; the new canonical log refuses non-append and O_TRUNC opens with EPERM and takes an O_APPEND write; staging is EACCES; root's fclonefileat of the service user's flagged file into a root-only directory works, and the clone is root's (CLONE_NOOWNERCOPY), 0600, whole and flagged, refusing a read-write open and fchown until fchflags clears it on a read-only descriptor, after which fchown, a read-write open and ftruncate work and the source is unchanged; root's setattrlistat of ATTR_CMN_FLAGS with FSOPT_NOFOLLOW by directory descriptor and name clears uchg on the service user's FIFO and socket, and at a symlink changes the link, not its target; root's fclonefileat of the service user's flagged file carrying an extended attribute and an ACL carries the attribute and not the ACL, and cloneArchive leaves the archive with neither; and rm-scope's premise: a service-user thread cannot rename a root-owned 0700 directory into another parent it owns, can rename it within the same parent, and, with an inheritable add_subdirectory entry on the parent at creation, can move a root-created directory out, while the directory mkdirAt makes there carries no ACL (append-only files)" \
	k3sm/pkg/keystore::TestSappndMeasuredFacts TestSappndDirectorySwap TestRmScopeMeasuredPremiseAsRoot
check U196 "floor --rebuild reads a flooded floor: it streams the old floor with no size bound and memory bounded by the reader's key bound and one line, so a floor past the steady-state reader's size bound, which the service user can reach at will, rebuilds; over-long and unparseable lines are dropped and counted, every real tombstone is kept; a present scope's lines are admitted all for keys on disk and every tombstone, whatever the share (a revocation's tombstone past the share survives), and its other live lines oldest first up to the uid's key share (excess counted past the share); an absent, unrecorded scope's tombstones per uid up to the share, uids in first-appearance order, and its live lines only once every absent tombstone is in, per uid up to the share (rest counted as absent scopes); the room the present scopes' keys on disk and tombstones leave under the key bound is split evenly between the absent scopes' tombstones and the present scopes' other live lines, a class needing less than its half giving the rest to the other, so a flood of forged lines of either class never evicts the other's lines within its half; so forged tombstones for uids with no scope, or a forged live flood for one real uid, never wedge it and every real line is kept; only the present scopes' keys on disk and tombstones past the reader's key bound (the key bound plus the revocation headroom, the bound the steady-state reader enforces) refuse, naming the scopes with the most keys and rm-scope, so real tombstones a revocation wrote into the headroom rebuild and are all kept, and the new floor never passes the reader's key bound, and rm-scope of the named scope lets the rebuild run; each removal's floor offset is bound to the floor log's device, inode and birth time it was recorded against, so rebuild never rewrites the record: a refused rebuild leaves it byte-identical and a later rebuild still drops the removed scope's lines, while a committed rebuild's new floor (a new file) gets no stale drop; a record without that whole identity drops nothing (the append-only files (the rebuild verb))" \
	k3sm/pkg/keystore::TestRebuildStreamsFloorPastReadBound TestRebuildDropsForgedLiveFlood TestOldFloorReaderMemoryBounded TestOldFloorReaderRefusesTombstonesPastBound TestRebuildForgedAbsentTombstoneFlood TestRebuildForgedLiveFloodOneRealUIDTrimmed TestOldFloorReaderAbsentFirstAppearanceOrder TestOldFloorReaderAbsentLiveAfterTombstones TestOldFloorReaderPresentLiveFloodKeepsAbsentTombstones TestOldFloorReaderAbsentTombFloodKeepsPresentLive TestOldFloorReaderPresentLiveFloodKeepsAbsentTombsHalf TestRebuildKeepsRevocationTombstonePastShare TestRebuildForgedTombstoneFloodPresentUIDRefusesThenRmScope TestOldFloorReaderRefusesRealScopesPastBound TestRebuildRefusedLeavesRecordAndStillDrops TestRebuildKeepsTombstonesInHeadroom TestRebuildRefusesPastReadKeyBound TestOldFloorReaderAdmitsAtMostReadBound
check U197 "rm-scope lists the removed scope key's identity in keystore-removed-scopes.json in the data root, with the floor log's device, inode, birth time and byte size at the removal (root's, by temp, fsync and rename, parsed strictly, bounded), so the old scope directory copied back is refused at every open (read, put, the start step, rebuild) while a re-minted scope opens; a full record still removes the scope and rebuild keeps its floor keys; a record that does not read fails closed; a scope whose delivery record is damaged is still removed and listed, exit 4, saying its deliveries were not checked, while a transient failure to read it refuses, changing nothing; the delivery record is read against the floor, so a rolled-back authentic copy is damage, and a floor that cannot be read leaves a record naming no delivery unverified, exit 4, deliveries not confirmed; the no-key and untrusted paths, which never read it, say the scope's deliveries were not checked; a repair text names the record's mode, 0644; every name from the service user's tree in an error prints quoted with control bytes removed and labelled as not for pasting, and no text offers an action by hand: the only commands rm-scope's output holds are its own rerun line built from the integer uid, the floor --rebuild follow-up on success, and what the shared store-lock and root-file helpers print; it never prints a name from the service user's tree in a command; a system flag it leaves and a multiply-linked flagged entry it does not clear are named, with the flag and the owner, and left, and a run past its flag budget says to run rm-scope again; a refusal of a copied-back removed scope names sudo k3sm keys rm-scope user/<uid> --yes; a locking flag is cleared on any entry with one link and no system flag, whoever owns it; a flagged FIFO, socket or device is written exactly 0 by name without an open, so a name swapped for a hard link to another file never gains a flag, and the re-stat leaves a changed name for the rescan; each directory, the scope directory first, is taken from the service user (fchmod 0700, fchown to root, fchmod 0700 again, its ACL removed, then an fstat that must show root's at 0700, on the held descriptor) before any of its entries is listed, so a service-user process's create and rename in there then fail with EACCES (on macOS an entry carrying an ACL entry that allows its deletion can still be renamed out); a subdirectory another user owns, or root at another mode than 0700, or on another device, is left in place with its contents, and the removal fails naming it for reading only and its owner, stopping once it has left 16 such directories, none entered; a directory nested more than 32 below the scope directory stops it, named relative to the scope directory for reading only, nothing below it removed, no command offered; a directory is emptied a bounded batch at a time, so a huge one is removed with no count refused; an rm-scope stopped part-way names the state it left and a rerun finishes it, root-owned 0700 directories included; one that stopped after it changed something (added a key to the record, removed an ACL, unlinked an entry, took a directory or cleared a flag) exits 4, audited committed, and one that changed nothing refuses, a rewrite of a record that already listed the key counting as no change; a stop after this run added a key to the record is never a refusal; the tree is removed only while the directory held at the scope's name is root's taken leftover at 0700, or holds, read by descriptor, the scope.key rm-scope judged and listed, so another service-user scope directory renamed onto the name is refused with nothing in it taken or listed; the final rmdir keeps the emptied directory's descriptor and checks it is the directory removed, and a name moved away or holding another directory, empty or not, is reported, never as removed; a probe that fails for another cause than ENOENT is reported as a removal rm-scope could not confirm, exit 4, never as moved, and a probe it could not remove again is said; a record renamed into place whose data-root fsync fails exits 4, saying the record lists the scope but its durability is unknown, and one that fails before its rename refuses; a stop after rm-scope cleared a flag on .user still carries that note; a stop a rerun would meet the same way (a scope directory moved from its name, a planted name, another user's flag on .user, a system flag on .user, a directory that is not the judged scope, a foreign or too-deep directory, a system flag or a multiply-linked flagged entry rm-scope leaves, a take the file system does not keep, an rmdir it could not confirm) offers no rerun and no command, a scope directory absent before the walk is found absent with no advice, a directory the judge refuses is named for reading with no command and no rerun line, no text rm-scope builds says to restore a file of the service user's tree, the errors about the root-owned record keep the shared reader's wording and name nothing from the service user's tree, and a flag set again on an entry rm-scope cleared stops it saying to rerun once nothing sets the flag, with the rerun line (the append-only files (rm-scope))" \
	k3sm/pkg/keystore::TestRemovedScopeCopiedBackRefused TestRemovedScopesFullKeepsFloorKeys TestRemovedScopesMalformedFailsClosed TestRemovedScopesFloorSizeParse TestRemoveScopeRerunFinishesPartialRemoval TestRemoveScopeUnreadableDeliveryRecord TestRemoveScopeTransientDeliveryReadRefuses TestRemovedScopesBadNamesAcceptedMode TestRmScopeHostileNameInert TestRmScopeOffersNoCommand TestRemoveScopeClearsUserFlags TestRemoveScopeClearsForeignFlags TestRemoveScopeSwappedNameGetsZero TestClearScopeFlagsSocketTypeUnopened TestRemoveScopeTakesEachDirBeforeListing TestRemoveScopeLeavesForeignDir TestRemoveScopeBatchesHugeDir TestReadBatchBounded TestRmScopePartialRemovalIsCommitted TestRemoveScopeForeignDirCap TestRemoveScopeDepthLimit TestRemoveScopeFlagBudget TestRemoveScopeRefusesSwappedScope TestRemoveScopeDirMovedBeforeRmdir TestRemoveScopeSharedDirFlags TestRmScopeRecordFsyncFailureIsCommitted TestRmScopeErrorTextsOfferNoCommand TestRemoveScopeFlagResetThenRerunFinishes TestRemoveScopeRmdirProbeFailures TestRmScopeFailureAfterWriteIsCommitted TestRmScopeRecordErrorsNameNoServiceUserPath TestRmScopeRolledBackDeliveriesIsNotExitZero TestRmScopeUnverifiedDeliveriesIsNotExitZero TestRmScopeKeylessPathsSayDeliveriesUnchecked TestRmScopeCommandSet
check U198 "the log reader charges at most maxRevokeUIDs plus 64 distinct uids past the hard cap; forged lines of more distinct uids are sticky damage, with no growth of its per-uid map (the append-only files (the reader))" \
	k3sm/pkg/keystore::TestAuditReaderBoundsChargedUIDs
check U199 "floor --rebuild that dropped any line or key exits 4, lists the counts by class and audits committed; doctor's keystore-floor row warns of floor damage naming floor --rebuild (the append-only files (the rebuild verb, doctor))" \
	k3sm/cmd/k3sm::TestKeysMaintenanceVerbs TestDoctorChecksTable
check U200 "a second link on a root-written data-root file (the removed-scopes record, the maintenance marker, the floor acknowledgement) is a Warn, never a refusal: each still reads, judged on type, owner, mode, flags and ACL, so a link any local user can make blocks no scope open, verb or acknowledgement; a flag on one is refused with, as the first repair, sudo chflags 0 on that exact root-owned path, and restoring from a backup (or install, for the marker) only second (the append-only files (root-written files))" \
	k3sm/pkg/keystore::TestRemovedScopesSecondLinkReads TestMarkerSecondLinkReads TestFloorAckSecondLinkReads TestRootFileModeStillJudged TestRootFileFlagNamesChflags TestMaintenanceJudgesMarkerAndStale
rootcheck U201 "root-run: the service user link(2)s root's removed-scopes record and floor acknowledgement into its own directory; the record still reads and rm-scope still writes it, and the acknowledgement still lifts the damage it acknowledged (the append-only files (root-written files))" \
	k3sm/pkg/keystore::TestRootFileServiceLinkReadsAsRoot
check U202 "a maintenance verb that fails after its RENAME_SWAP is committed, never refused: it exits 4, audits committed and still prints its report (a rebuild's drop counts); a later run of the other verb, or install, that finds a marker recording a committed run prints its saved report to stderr as an earlier committed run that was not reported and audits it (op that verb, result committed) before it replaces or removes the marker; when that report shows drops the text says the earlier run dropped N lines and the verb exits at least 4, except install, which keeps its exit codes and adds to the line that the drop counts are kept in keystore-maintenance-runs, which doctor reads, or, when that record does not read or write, that they are in that line only and why, the audit log holding a committed line for that run, and to copy the line down; a same-verb rerun that only prints the saved report says the earlier run committed and this run did not rebuild; doctor WARNs on a standing marker, naming its verb; a marker whose swap never committed reports nothing; a committed run whose report drops any line or key, its own or a saved one a rerun, the other verb or install reports, appends one record (run id, verb, UTC time, the drop counts by reason, the new log's inode) to keystore-maintenance-runs in the data root before the marker goes, root's 0644 through the data-root descriptor, the newest 64 kept, parsed strictly, and a record that does not read is reported and left as found; doctor's keystore-maintenance-runs row counts the lossy runs (the append-only files (the swap))" \
	k3sm/pkg/keystore::TestSwapFailureAfterCommitIsCommitted TestEarlierCommittedRunReported TestStandingMaintenanceNamesVerb TestSwapRerunFromEachStep k3sm/cmd/k3sm::TestKeysMaintenanceCommittedAfterSwap TestKeysRebuildRerunSaysEarlierRun TestDoctorKeystoreMaintenanceNamesVerb k3sm/pkg/install::TestKeystoreFilesReportsCommittedMarker k3sm/pkg/keystore::TestMaintenanceReportDurable k3sm/cmd/k3sm::TestDoctorKeystoreMaintenanceRow k3sm/pkg/install::TestInstallRecordsLossyEarlierRun TestEarlierRunDropHint
check U203 "rm-scope of a scope directory with no scope.key, for a uid the record does not list, removes the tree but exits 4, audited committed, saying it was removed without being listed because its key file was absent, so a copy of its directory put back by the service user opens again, held only to the scope's floor lines, which are kept; it never says the record is full; a scope.key the judge refuses only for a second link or a mode wider than 0600 that still authenticates under the master is listed, exit 4 noting the link count or mode, and a copy put back is refused; one whose content does not parse is removed unlisted, saying its key file could not be trusted, and floor --rebuild then runs; a full record also exits 4, with its own text; a scope directory already gone when rm-scope opens it is reported as found absent, not removed, exit 4 when this run added a key to the record and a refusal otherwise, also when the fsync of .user that follows fails; a directory root owns at 0700 at the name (another uid's leftover an earlier run took and renamed within .user, or a root-owned directory an ACL entry granting add_subdirectory let the service user move there from another parent; never served) is always removed, whatever scope.key it holds, its ACL removed first: one that opens as this uid's is listed first, or the record rewritten for durability, and the result says listed (exit 0) only when the key read in the held directory is in the record, the directory carried no ACL and its key was listed before this run, and never on the judged path, where it says the directory rm-scope judged was not at its name and never that the scope's directory was removed; otherwise exit 4 saying how many keys the record lists for the uid; mkdirAt removes an inherited ACL from a directory a root verb makes; on the judged path exit 0 needs the judged key in the record and scope.key read again after the take as the same key; rm-scope's judge reads through the mode of .user and of the scope directory, so the principal being revoked cannot veto it with a mode; a service user's directory is accepted on these paths only when it holds what its path judged (no scope.key, or one that cannot be trusted) or a key already listed for the uid, never a valid unlisted scope.key; scope.key goes last on every path, and a take stopped at any step, its first fchmod included, leaves a directory a rerun finishes, its text carrying the rerun line; every exit 0 also needs the newest-scope rule: the user-scope floor, read through rebuild's root-judged reader, holds no line of the uid written after the listing of the key that proves the run (a floor rebuilt since counts every line of the uid, and one that cannot be judged is never exit 0), so a directory holding a kept copy of a listed key, or a parked leftover, put at the name with the live scope renamed away is exit 4 with the live scope untouched, while a genuine rerun still exits 0; more than one sequence-1 delivery-record line of the uid in the floor since its last listing before the run (its scope created more than once) is exit 4 too, saying so, the scope at the name removed and listed and a scope moved away untouched, while exactly one such line, also after an earlier listed removal, still exits 0, and a torn or over-long line before a mint's line does not hide it; on the no-key and untrusted paths the directory held at the name must be the one the judge opened (device and inode), else it is refused with nothing taken; rm-scope reads through the mode of keystore/ too; a stop after it removed the ACL of a root-owned leftover is committed (the append-only files (rm-scope))" \
	k3sm/pkg/keystore::TestRemoveScopeMissingKeyUnlistedCommitted TestRemoveScopeUntrustedKeyUnlisted TestRemoveScopeRerunFinishesPartialRemoval TestRemovedScopesFullKeepsFloorKeys TestRemoveScopeRerunAcceptsOwnLeftover TestRemoveScopeRerunFinishesAnyTakenLeftover TestRemoveScopeRerunRefusesServiceUserLeftover TestRmScopeListedNeedsThisKey TestRmScopeAbsentAtOpenIsNotRemoved TestRemoveScopeTakeStopAtEachStepRerunFinishes TestRmScopeErrorTextsOfferNoCommand TestRemoveScopeRootLeftoverWithACLIsUnproven TestRemoveScopeRootLeftoverUnlistedKeyIsNotExitZero TestRmScopeDirectoryModeCannotVeto TestRmScopeJudgedProofNeedsJudgedKey TestMkdirAtStripsInheritedACL TestRmScopeDecoyOfListedKeyIsNotExitZero TestRmScopeParkedLeftoverIsNotExitZero TestRmScopeGenuineRerunStillExitsZero TestRmScopeRebuiltFloorCountsEveryLine TestRmScopeUnjudgedFloorIsNotExitZero TestRmScopeTwoMintsSinceListingIsNotExitZero TestRmScopeOneMintSinceListingExitsZero TestRmScopeTwoMintsAfterListedRemovalIsNotExitZero TestRmScopeHostileLineBeforeMintDoesNotHideIt TestRmScopePinsJudgedDirectory TestRemoveScopeACLStrippedThenStopIsCommitted k3sm/cmd/k3sm::TestKeysRmScopeUnlistedExitsCommitted
check U204 "floor --rebuild bounds what it collects from disk: it checks the keys and entry names of the scopes on disk against the key bound while collecting, stops once they pass it and refuses before reading the old floor, naming the scopes with the most entries and rm-scope, changing nothing; the scope walk is bounded by the listing bound (the append-only files (the rebuild verb))" \
	k3sm/pkg/keystore::TestRebuildRefusesDiskPastBound
check U205 "install clears a user flag on keystore-run/ on its judged descriptor before any chmod or chown, and makes the chmod and chown only when the mode or owner is not already right, so the service user cannot wedge install with uchg on the directory it owns (the append-only files (install))" \
	k3sm/pkg/install::TestKeystoreRunDirClearsUserFlag
rootcheck U206 "root-run: the service user sets uchg on keystore-run/, which makes root's chmod fail EPERM; install clears the flag first and finishes, leaving the directory the service user's 0700 with no user flag (the append-only files (install))" \
	k3sm/pkg/install::TestKeystoreRunDirUserFlagAsRoot
# >>> ADD NEW U ROWS (U200 upward) HERE, and add each to EXPECTED_ROWS and to mode_rows <<<

leg E1 "files" "preconditions: secrets encryption on; one server; keystore-sock/ root:wheel 0755 with keys.sock from launchd, and both logs present, service-user 0600, SF_APPEND set; the doctor user-scope row on; keystore.sh --check exits 0 on the build" "the append-only files"
leg E2 "socket-ops" "the user, no sudo, puts user/<me>/e2e-token (short-name form): exit 0; the CLI prints the resolved user/<uid>; k3sm keys list shows it; the audit log has a put line with no value" "the socket operations"
leg E3 "kd-reconcile" "an admin binds k3sm:keystore-delivery-author and the built-in edit ClusterRole for k3sm:local:<uid> in ks-e2e and the user delivers the entry to Secret e2e-token: KeyDelivery Ready, reason Delivered, observedGeneration current; requestedBy is k3sm:local:<uid>; a pod mounting the Secret reads exactly the stored bytes" "the KeyDelivery reconciler"
leg E4 "verbs" "the user rotates (rotate --in -), then rotate --from-version 1: the pod's mounted file moves to v2, then to v1's bytes as v3, within one sweep each" "the k3sm keys verbs"
leg E5 "exec" "k3sm keys exec user/<uid>/e2e-token --env TOKEN -- /usr/bin/env: the child sees TOKEN; the CLI wrote nothing else; ps during the run shows no value in argv; one exec-read audit line" "the non-root CLI and exec"
leg E6 "socket-ops" "as the one login user: list, exec, rotate, rm and deliver of an unused other uid's entry and of system/e2e-sys, then a connect as root and as the service user: not found each time, text identical to an absent entry of the user's own, refused audit lines carry the user's uid; root and the service user are refused at accept" "the socket operations; the socket listener"
leg E7 "kd-reconcile" "an admin copies E3's KeyDelivery into ks-e2e-2, where the user also has the role: Authorized=False, reason NotRecorded, no Secret" "the KeyDelivery reconciler"
leg E8 "kd-reconcile" "an admin strips the CRD's transition rules (restored at the end) and edits E3's spec.secretName: Authorized=False, NotRecorded (digest mismatch); the original Secret deleted; no Secret under the new name" "the target digest"
leg E9 "files" "sudo cp saves current, the user rotates, sudo cp puts the old current back, then the same for a system/ entry: both lists mark the entry corrupt with the floor message" "the append-only files"
leg E10 "sandbox" "a pod pinned to the darwin node tries connect(2) to keys.sock and to read server/keystore, keystore-sock/, both logs and Phase A's two files, then a write, create, unlink, rename and network-bind on keystore-sock/, keys.sock and every keystore-* file, each also through /System/Volumes/Data/private/var/lib/k3sm and the data volume's mount path: EPERM for each; then a vm Pod on the node tries keys.sock and the data root from the guest: no path to either" "runtimed's sandbox change"
leg E11 "kd-lifecycle" "an admin removes the user's RoleBinding in ks-e2e: the Secret is deleted after two spaced observations, the leg waiting at least 90 s before it judges; Authorized=False, NotAuthorized" "the KeyDelivery reconciler (lifecycle)"
leg E12 "socket-ops" "root puts and delivers system/e2e-sys; then the user, with no sudo, tries deliver, list and exec on it: root's Secret is delivered and stays; each of the user's attempts answers not found and nothing reaches ks-e2e-2" "root delivery; the socket operations"
leg E13 "kd-author" "a ServiceAccount token creates a KeyDelivery: refused at admission" "KeyDelivery authoring"
leg E14 "kd-lifecycle" "k3sm keys undeliver on E3's object, then kubectl delete of a second one: each Secret deleted before its object goes; the hint printed; no orphan Secret once the leg has waited at least 90 s" "the KeyDelivery reconciler (lifecycle)"
leg E15 "" "upgrade from the previous release's install tree, then sudo k3sm install: system scope intact; user scope comes on after the install, off with the Warn and doctor row before it" "upgrade visibility"
leg E16 "" "rollback to the previous release, then forward again: the old build runs with the keystore files unused; after rolling forward the user's entries, records and Secrets are intact and re-adopted" "the rollback guard"
leg E17 "files" "backup and restore round trip with cp, then floor --rebuild and audit --rotate: before the rebuild the listener refuses (flags clear); after it every entry opens and both logs are flagged" "the flag check"
leg E18 "socket" "an old worker on the previous release joins this server: worker Ready; pods there mount delivered Secrets; no keystore listener or reconciler on the worker" "server-only listener"
leg E19 "socket" "launchctl kickstart -k of the server while a client is connected mid-request: a clean error, not a hang; the listener back within its backoff; kine and the apiserver back; no partial record" "the listener lifecycle"
leg E20 "files" "reboot of the server node, operator-attended (--attended reboot): after boot the flags are still set, the listener starts, E2's entry opens, E3's Secret is still current" "the flag check"
leg E21 "sandbox" "a native pod with runAsUser 501 is refused at spawn: the container never starts, and its status carries the uid refusal" "runtimed's sandbox change"
leg E22 "socket" "a native pod with runAsUser 0 on a root runtimed runs (no drop, an inherited uid is allowed); a root connect to keys.sock is refused before any frame" "none: a guard that the uid refusal does not reach an inherited uid"
leg E23 "kd-reconcile" "against the real authorizer, a role with create on secrets and update and delete on one named secret: delivery as that name is Ready, Delivered; delivery as another name is Authorized=False, NotAuthorized, with no Secret; then another principal (kubectl --as, with edit in the namespace) deletes the KeyDelivery and patches its finalizer away: each refused at admission, the object, its finalizer and the Secret stay" "the KeyDelivery reconciler; KeyDelivery authoring"
leg E24 "exec" "with the server running, a non-k3sm program run as the service user tries to unlink keystore-sock/keys.sock and bind that path: EACCES for each, keys.sock still launchd's; with the listener stopped by the maintenance marker, the real installed k3sm binary, exec'd inside a native pod, tries the same bind and gets EPERM; in the deny-plus-pin fallback only, the service-user program binds keys.sock and the user's k3sm keys list and put refuse before any frame, naming the server pin; the real server is accepted afterwards" "the root-owned socket directory; the server pin; the pod bind deny"
leg E25 "files" "helper variant only: a native pod tries connect(2) to the floor helper's socket, and the login user and a non-k3sm service-user program each send it an append: EPERM for the pod, both refused, no line appended" "the helper pin"
leg E26 "socket" "a native pod on a test build whose pod profile omits the keystore deny stanza (restored at the end) tries connect(2) to keys.sock: the listener refuses it before any frame, since the peer is sandboxed, and writes a refused line" "the sandboxed-peer refusal"
leg E27 "socket" "a native pod calls launch_activate_socket for the server's socket name: no descriptor is returned, and nothing in the pod can accept on keys.sock" "the launchd lookup deny"
leg E28 "" "the typed-credential tracer (\"Rig credentials and custody\"): a generated deploy key and a server-refreshed oauth pair delivered into one pod, which pushes over ssh and opens a pull request; then k3sm keys refresh: push and pull request succeed; the access-token file's hash changes in the same pod with restartCount 0; mount lines; the positive-controlled scans find nothing they should not; PENDING (exit 3) if the oauth pair is missing or not ok" "typed projection, the mount audit or the refresher"
leg E29 "expiry" "a synthetic token put with --expires-at now+8 m, delivered: Valid, then Expiring after about 6 m, then Expired at 8 m; one Warning Event each, related the Secret; the Secret kept; Ready unchanged" "expiry and revocation"
leg E30 "projection" "generate --kind ssh; deliver --item privateKey=id_ed25519 --item publicKey=id_ed25519.pub (defaultMode 0400); the pod runs ssh-keygen -y -f id_ed25519; a delivery without items is refused: the output equals k3sm keys pubkey; the fingerprint matches" "typed projection"
leg E31 "projection" "a synthetic oauth pair (local, planted access and refresh tokens) put from a token-response JSON, then delivered with the CLI default: positive control: the planted access token is found base64-encoded in the Secret; then every Secret, Event, pod log and keystore-audit.log holds no planted refresh-token bytes (raw, base64, URL-encoded); a KeyDelivery naming refreshToken is refused by the schema" "typed projection"
leg E32 "refresh" "on the real server/github-e2e pair, k3sm keys refresh (recorded during E28): the pod's access_token hash changes without a restart; one refresh-now and one refresher line; refresh_state ok; CredentialValid=True Valid; PENDING (exit 3) if the pair is missing or not ok" "the refresher"
leg E33 "refresh" "a separate entry holding a planted random refresh token against the real token endpoint, delivered; k3sm keys refresh: Revoked through the profile's revokedErrorCodes (the endpoint answers HTTP 200 with an error field); one CredentialRevoked Warning Event; parked: a second refresh-now sends nothing; a positive-controlled scan as E31" "the refresher"
leg E34 "mount-audit" "two pods mount a delivered Secret; delete one; churn 200 short pods; rotate the entry 40 times in a minute: pod-mount for every first-seen pod, pod-unmounts, pod-refresh lines with one rate summary; no ErrLogFull; put still works" "the mount audit"
leg E35 "sandbox" "precondition: refresh-profile list shows a profile; a pod reads a sibling non-keystore file in the same directory (positive control), then keystore-refresh-profiles.json and keystore-run/refresh-state.json: the sibling read succeeds; both keystore reads are EPERM; a regression guard, which cannot fail before refresh profiles land" "the keystore-* prefix deny"
leg E36 "refresh-profiles" "a profile with https://localhost:<port>/token, a loopback listener on that port counting accepted connections, a pair naming it, k3sm keys refresh: RefreshFailing with cause dial-refused; the listener counted 0 connections; the redirect case is unit-only (U177)" "refresh profiles"
# >>> ADD NEW E LEGS (E37 upward) HERE, with the unit mode that delivers the last feature <<<

nrows=${#R_ID[@]}

# row_index prints the index of row $1, or nothing.
row_index() {
	local i=0
	while [ "$i" -lt "$nrows" ]; do
		if [ "${R_ID[$i]}" = "$1" ]; then echo "$i"; return 0; fi
		i=$((i + 1))
	done
}

# repo_dir prints the checkout that holds package $1 (<repo>/<path>).
repo_dir() {
	case "${1%%/*}" in
	k3sm) echo "$K3SM_ROOT" ;;
	*) echo "$(dirname "$K3SM_ROOT")/${1%%/*}" ;;
	esac
}
# pkg_rel prints package $1's path inside its repo, as go test takes it.
pkg_rel() {
	case "$1" in
	*/*) echo "./${1#*/}/" ;;
	*) echo "./" ;;
	esac
}

# --root: R1 and the root-run rows. It needs the row table and pkg_rel above.
if [ "$mode" = root ]; then
	rc=0
	run_root_mode || rc=$?
	exit "$rc"
fi

# nocgo reports whether package $1 runs with CGO_ENABLED=0, and so without
# -race: the repos that import no cgo-backed code.
nocgo() {
	case "${1%%/*}" in
	apis | darwin-net) return 0 ;;
	esac
	return 1
}
work=""
if [ -f "$(dirname "$K3SM_ROOT")/go.work" ]; then work="$(dirname "$K3SM_ROOT")/go.work"; fi
# gotest pkg args... runs go test in package pkg's repo, CGO and GOWORK set for
# this run only: -race under cgo, none without; k3sm runs as it is, a sibling
# through the go.work beside the root when there is one.
gotest() {
	local pkg="$1" dir cgo=1 race=-race
	shift
	dir="$(repo_dir "$pkg")"
	if nocgo "$pkg"; then cgo=0 race=""; fi
	if [ "$dir" = "$K3SM_ROOT" ]; then
		(cd "$dir" && CGO_ENABLED="$cgo" go test ${race:+"$race"} "$@")
	elif [ -n "$work" ]; then
		(cd "$dir" && CGO_ENABLED="$cgo" GOWORK="$work" go test ${race:+"$race"} "$@")
	else
		(cd "$dir" && CGO_ENABLED="$cgo" go test ${race:+"$race"} "$@")
	fi
}

failed=0
pending=0
pend_missing=0
row() { printf '%-4s %-8s %s\n' "$1" "$2" "$3"; }
pass() { row "$1" PASS "$2"; }
fail() { row "$1" FAIL "$2"; failed=$((failed + 1)); }
pending_row() { row "$1" PENDING "$2"; pending=$((pending + 1)); }

# CLAIMS are the security-relevant claims --listed holds against the design:
# each "<row>|<phrase>" line needs the phrase in that row's line of the
# design's gate table (backticks removed) and in this script's description of
# the row, so the two cannot drift apart on these points unnoticed (row L1).
CLAIMS="U16|no emitted allow matches
U16|network-bind
U16|/System/Volumes/Data/private/var/lib/k3sm
U44|owner annotation
U44|sealed record
U44|not the ownerReference
U44|namespace and name must equal the record's target for that UID
U44|a forged label and a real UID on another Secret are left alone
U51|reads
U51|ErrLogFull
U55|two consecutive sweeps
U55|ErrScopeAbsent
U64|ErrScopeAbsent
U64|a missing entries/ directory or a missing deliveries record is ErrScopeAbsent too
U66|FFFFEEEE-DDDD-CCCC-BBBB-AAAA
U67|256 KiB reconciler allowance
U67|720 KiB socket margin
U67|neither budget can draw on the other
U67|at most 976 KiB per user scope
U84|overshoot
U67|one uid's revocations are never refused because of another uid
U73|an indeterminate sweep keeps the claim
U25|a damaged entry stays ErrCorrupt
U193|it keeps every tombstone and every key's highest sequence that parses
U194|drops every key of that scope, live or buried
U194|a re-minted scope gets a fresh K_u
U81|keydelivery
U81|k3sm.io/keystore-entry
U77|only then removes the scope
U77|refuses and changes nothing
U68|never follows a planted name
U69|LOCAL_PEERTOKEN
U69|cdhash
U72|orphan-cascade
U76|k3sm:local-users
E3|built-in edit ClusterRole
U82|2147483647
U82|nobody (4294967294)
U83|Indeterminate for writes
E10|vm Pod
E10|network-bind
E10|EPERM
E24|EPERM
U85|reconciler budget, 1 MiB per log
U85|excluded from the hard-cap test
U85|bounded LRU of 1024
U85|every uid able to read and mutate
U67|plus the 1 MiB reconciler budget
U86|never charged to the owner's share or budgets
U86|exponential backoff capped at 10 minutes
U86|stays charged to the owner
U87|oldObject.spec.requestedBy
U87|a finalizer edit is an UPDATE
U87|on a DELETE object is null
E23|refused at admission
U55|without the GeneratedUID check only to find recorded targets
U55|never delivers, rotates or opens an entry
U88|never lowers
U88|refuses to finish, names the scope and changes nothing
U88|(user/<uid>, .deliveries, generation, seq)
U88|a copied-back older deliveries record is refused
U83|the floor holds writes and absence-driven deletes
U89|retries up to 3 times with jitter
U89|a revocation completes
U90|the canonical log by path is a complete judged log
U90|nothing the held descriptors did reaches the new log
U91|refuses, changing nothing, when .4 exists unless --discard-oldest
U92|stored; delivery pending: past your log share
U93|at least 60 s apart on the clock seam
U94|runs the GeneratedUID check
U95|refuses, changing nothing, unless none exist or --keep-bindings is given
U96|a withdrawal still succeeds
U96|seen gone (Get not found) on two sweeps
U45|withdraw and deliveries
U7|250 ms everywhere
U20|names the matched-set restore, not removing keystore-floor.json
U77|unauthenticated (annotation only)
U86|k3sm.io/keystore-digest
U86|a substituted data under an intact version annotation is drift
U98|live Get by that name
U98|never an informer cache and never a List
U98|two consecutive observations at least 60 s apart
U99|before every audit or floor append
U99|reopens on a mismatch
U99|never saw the marker
U100|no directory record
U100|OwnerUnresolvable
U100|no Secret is deleted
U101|does not re-key K_u
U101|each user re-puts their values after a suspected master exposure
U102|last delivered version per delivery
U102|uses only that recorded version
U103|never overwritten or deleted
U103|LabelRemoved
U104|keystore-sock/ root:wheel 0755
U104|cannot unlink, replace or bind keys.sock
U105|install over an existing tree, uninstall --purge and doctor
U106|refuses a non-root caller
U106|through the euid source
U107|an absence-driven delete (ErrNotFound) is Indeterminate
U107|a revocation-driven delete
U108|no server exclusive hold spans any fake time
U108|runs before the lock is taken
U109|revocation deletes go ahead
U109|user mutations and reads stay refused
U110|stops the listener
U110|must be deleted by hand
U111|the owner annotation never decides precedence
U111|an Indeterminate object counts as honoured
U112|commit, then append, then reply
U112|committed; audit failed
U113|unless the server's effective uid is the service uid
U113|user scope needs the installed server
U17|drop target uid is refused if it is 0, negative, 501 or above, or the service uid
U17|a gid-only drop that leaves uid 0 is refused
U17|an inherited uid
U114|keystore-removed-scopes.json
U114|a plain ErrScopeAbsent stays non-definitive
U115|--remove-bindings deletes each listed binding through the admin client
U116|a vm Pod with runAsUser: 1000 is allowed
U97|rm then put
U118|the old log's one attribute call is its flag clear
U118|fresh root-owned unflagged copies
U195|each EPERM
U119|keystore-lock
U119|blocks none of them
U119|other than the service user
U120|among none of them
U121|never relaxed to accept uid 0
U123|another honoured record claims at the same (namespace, secretName)
U124|a target occupied by another Secret still prunes
U125|Preconditions{UID, ResourceVersion}
U126|persisted in the next summary line
U127|not a deleting outcome
U129|without the GeneratedUID check
U133|the parse is strict
U135|admits DELETE only
U137|sandbox_check
U14|key-sorted items
U140|refused by the schema
U149|a planted refresh token appears in no result
U161|key-sorted items
U172|a first-seen pair is never rate-limited
U178|169.254.169.254"

# --listed: the row-presence lint.
if [ "$mode" = listed ]; then
	echo "keystore --listed: a row-presence lint, not proof: no test runs"
	list_dir="$(mktemp -d "${TMPDIR:-/tmp}/keystore-list.XXXXXX")"
	trap 'rm -rf "$list_dir"' EXIT
	# L_PKG and L_HOW are parallel: how package L_PKG's tests were found, in
	# the file $list_dir/<n>.list: go (go test -list), grep, or none (no checkout).
	L_PKG=()
	L_HOW=()
	# list_pkg sets LK to the index of package $1's test list, making it on
	# first use (not in a subshell: the arrays must persist).
	LK=0
	list_pkg() {
		local k=0 dir how n
		while [ "$k" -lt "${#L_PKG[@]}" ]; do
			if [ "${L_PKG[$k]}" = "$1" ]; then LK=$k; return 0; fi
			k=$((k + 1))
		done
		n=${#L_PKG[@]}
		dir="$(repo_dir "$1")/$(pkg_rel "$1")"
		: >"$list_dir/$n.list"
		if [ ! -d "$dir" ]; then
			how=none
		elif gotest "$1" -list '.*' "$(pkg_rel "$1")" >"$list_dir/$n.list" 2>/dev/null; then
			how=go
		else
			how="grep"
			grep -h -o -E '^func (Test|Fuzz|Benchmark|Example)[A-Za-z0-9_]*' "$dir"*_test.go 2>/dev/null | sed 's/^func //' >"$list_dir/$n.list" || true
		fi
		L_PKG+=("$1")
		L_HOW+=("$how")
		LK=$n
	}
	# lint_unique_ids appends to dups each U or E id that list $2 (words) holds
	# more than once, naming the list $1.
	lint_unique_ids() {
		local d
		d="$(printf '%s\n' $2 | grep -E '^[UE][0-9]+$' | sort | uniq -d | tr '\n' ' ' || true)"
		if [ -n "$d" ]; then dups="$dups; $1: ${d% }"; fi
	}
	for id in $EXPECTED_ROWS; do
		if [ -z "$(row_index "$id")" ]; then fail "$id" "in the design's gate table, not in this script"; fi
	done
	i=0
	while [ "$i" -lt "$nrows" ]; do
		id="${R_ID[$i]}"
		case "$id" in
		U* | E*)
			case " $EXPECTED_ROWS " in
			*" $id "*) ;;
			*) fail "$id" "in this script, not in EXPECTED_ROWS" ;;
			esac
			;;
		esac
		if [ "${R_KIND[$i]}" = na ]; then
			row "$id" N/A "not applicable under the flag variant; its tests are not looked for"
			i=$((i + 1))
			continue
		fi
		missing=""
		found=0
		fb=""
		for spec in ${R_TESTS[$i]}; do
			pkg="${spec%%::*}" t="${spec#*::}"
			list_pkg "$pkg"
			k=$LK
			if [ "${L_HOW[$k]}" = grep ]; then fb=" (grep fallback)"; fi
			if grep -q -x -- "$t" "$list_dir/$k.list"; then
				found=$((found + 1))
			else
				missing="$missing $t ($pkg)"
			fi
		done
		if [ -z "${R_TESTS[$i]}" ]; then
			case "${R_KIND[$i]}" in
			leg) row "$id" LISTED "rig leg, no named test" ;;
			*) row "$id" LISTED "no named test" ;;
			esac
		elif [ -z "$missing" ]; then
			row "$id" LISTED "$found named test(s) found$fb"
		elif [ "${R_KIND[$i]}" = pend ] || [ "${R_KIND[$i]}" = rootpend ]; then
			row "$id" "MISSING (pending row)" "${missing# }$fb"
			pend_missing=$((pend_missing + 1))
		else
			fail "$id" "named test(s) not found:$missing$fb"
		fi
		i=$((i + 1))
	done
	# L1: each claim's phrase in the design's table row and in this script's row.
	doc="$K3SM_ROOT/docs/design/keystore.md"
	nclaims=0
	drift=""
	while IFS='|' read -r cid phrase; do
		[ -n "$cid" ] || continue
		nclaims=$((nclaims + 1))
		drow="$(grep -E -- "^\| $cid \| " "$doc" | head -n 1 | tr -d '`' || true)"
		k="$(row_index "$cid")"
		sdesc=""
		if [ -n "$k" ]; then sdesc="${R_DESC[$k]}"; fi
		case "$drow" in *"$phrase"*) ;; *) drift="$drift; $cid design lacks \"$phrase\"" ;; esac
		case "$sdesc" in *"$phrase"*) ;; *) drift="$drift; $cid script lacks \"$phrase\"" ;; esac
	done <<<"$CLAIMS"
	# The test names: the design's "Validated by" column (its third; an escaped
	# \| inside a cell is not a column break) against the names the row runs.
	nnamed=0
	for cid in $EXPECTED_ROWS; do
		case "$cid" in U*) ;; *) continue ;; esac
		k="$(row_index "$cid")"
		[ -n "$k" ] || continue
		drow="$(grep -E -- "^\| $cid \| " "$doc" | head -n 1 || true)"
		if [ -z "$drow" ]; then
			drift="$drift; $cid has no row in the design's table"
			continue
		fi
		dnames="$(printf '%s\n' "$drow" | sed 's/\\|/ /g' | awk -F'|' '{print $4}' | grep -o -E '(Test|Fuzz)[A-Za-z0-9_]+' | sort -u | tr '\n' ' ' || true)"
		snames="$(for spec in ${R_TESTS[$k]}; do echo "${spec#*::}"; done | sort -u | tr '\n' ' ')"
		nnamed=$((nnamed + 1))
		if [ "$dnames" != "$snames" ]; then
			drift="$drift; $cid test names differ: design [${dnames% }], script [${snames% }]"
		fi
	done
	if [ -n "$drift" ]; then
		fail L1 "the design's table and this script drifted:${drift#;}"
	else
		row L1 LISTED "$nclaims security claims and $nnamed rows' test names match the design's table and this script"
	fi
	# L2 (U138): no U or E id twice in any list that names rows.
	dups=""
	lint_unique_ids "this script's rows" "$(printf '%s\n' "${R_ID[@]}")"
	lint_unique_ids "EXPECTED_ROWS" "$EXPECTED_ROWS"
	for m in $MODES; do lint_unique_ids "mode --$m" "$(mode_rows "$m")"; done
	lint_unique_ids "the design's tables" "$(grep -o -E '^\| [UE][0-9]+ \|' "$doc" | tr -d '| ' || true)"
	if [ -n "$dups" ]; then
		fail L2 "duplicated row ids:${dups#;}"
	else
		row L2 LISTED "no U or E id is duplicated in this script's rows, EXPECTED_ROWS, any mode or the design's tables"
	fi
	if [ "$failed" -gt 0 ]; then echo "keystore --listed: FAIL ($failed) (not proof)"; exit 1; fi
	if [ "$pend_missing" -gt 0 ]; then
		echo "keystore --listed: every row present, $pend_missing pending row(s) name tests that do not exist yet (not proof)"
		exit 3
	fi
	echo "keystore --listed: every row present, every named test exists (not proof)"
	exit 0
fi

# wanted reports whether row $1 runs in this mode.
# A leg's unit mode is in R_TODO; under a unit mode with --lab only the legs
# mapped to that mode run.
wanted() {
	local k
	case "$1" in
	E*)
		if [ "$lab" = 1 ]; then
			if [ "$mode" = lab ]; then return 0; fi
			k="$(row_index "$1")"
			if [ -n "$k" ] && [ "${R_TODO[$k]}" = "$mode" ]; then return 0; fi
			return 1
		fi
		if [ "$mode" = check ]; then return 0; fi
		return 1
		;;
	esac
	if [ "$mode" = check ]; then return 0; fi
	if [ "$mode" = lab ]; then return 1; fi
	case " $(mode_rows "$mode") " in *" $1 "*) return 0 ;; esac
	return 1
}

# The packages the wanted rows' tests are in, each run once. P_PKG, P_TESTS
# and P_RC are parallel; P_RC is the go test status, or "absent" for a repo
# that is not checked out. Pending rows name tests but run none.
P_PKG=()
P_TESTS=()
P_RC=()
pkg_index() {
	local j=0
	while [ "$j" -lt "${#P_PKG[@]}" ]; do
		if [ "${P_PKG[$j]}" = "$1" ]; then echo "$j"; return 0; fi
		j=$((j + 1))
	done
}
i=0
while [ "$i" -lt "$nrows" ]; do
	case "${R_KIND[$i]}" in
	check | partial)
		if wanted "${R_ID[$i]}"; then
			for spec in ${R_TESTS[$i]}; do
				pkg="${spec%%::*}" t="${spec#*::}"
				j="$(pkg_index "$pkg")"
				if [ -z "$j" ]; then
					j=${#P_PKG[@]}
					P_PKG+=("$pkg")
					P_TESTS+=("")
					P_RC+=("")
				fi
				case " ${P_TESTS[$j]} " in *" $t "*) ;; *) P_TESTS[j]="${P_TESTS[$j]:+${P_TESTS[$j]} }$t" ;; esac
			done
		fi
		;;
	esac
	i=$((i + 1))
done

out_dir=""
if [ "${#P_PKG[@]}" -gt 0 ]; then
	out_dir="$(mktemp -d "${TMPDIR:-/tmp}/keystore-gate.XXXXXX")"
	trap 'rm -rf "$out_dir"' EXIT
fi
# One run of each package's tests (under --check, the whole package; under a
# unit mode, the mode's tests only), verbose so each named test can be checked:
# a test that does not run is not a pass. Under -race unless the package runs
# with CGO_ENABLED=0, which the run says.
j=0
while [ "$j" -lt "${#P_PKG[@]}" ]; do
	pkg="${P_PKG[$j]}"
	dir="$(repo_dir "$pkg")"
	: >"$out_dir/$j.out"
	run=()
	if [ "$mode" != check ]; then run=(-run "^($(tr ' ' '|' <<<"${P_TESTS[$j]}"))\$"); fi
	rc=0
	if [ ! -d "$dir" ]; then
		rc=absent
	else
		if nocgo "$pkg"; then echo "keystore: $pkg: CGO_ENABLED=0, run without -race"; fi
		gotest "$pkg" -count=1 -v ${run[@]+"${run[@]}"} "$(pkg_rel "$pkg")" >"$out_dir/$j.out" 2>&1 || rc=$?
	fi
	P_RC[j]="$rc"
	j=$((j + 1))
done

# ran reports whether every test row $1 names passed, its package green; on
# a missing checkout it sets why.
why=""
ran() {
	local spec pkg t j
	why=""
	for spec in ${R_TESTS[$1]}; do
		pkg="${spec%%::*}" t="${spec#*::}"
		j="$(pkg_index "$pkg")"
		[ -n "$j" ] || return 1
		if [ "${P_RC[$j]}" = absent ]; then
			why=" (../${pkg%%/*} is not checked out beside k3sm)"
			return 1
		fi
		[ "${P_RC[$j]}" = 0 ] || return 1
		grep -q -- "--- PASS: $t " "$out_dir/$j.out" || return 1
	done
}

# A failing merge-base must not end the run under set -e, so its status is
# discarded and an empty base is the failure; a base that is not a commit is
# the same failure, never a diff that reads as a change.
judge_g1() {
	local base="${KEYSTORE_BASE:-}"
	if [ -z "$base" ]; then base="$(git merge-base HEAD origin/main 2>/dev/null || true)"; fi
	if [ -z "$base" ] || ! git rev-parse -q --verify "$base^{commit}" >/dev/null 2>&1; then
		fail G1 "no base to diff go.mod and go.sum against: fetch origin/main or set KEYSTORE_BASE to a commit"
	elif git diff --quiet "$base" -- go.mod go.sum; then
		pass G1 "go.mod and go.sum unchanged since $(git rev-parse --short "$base")"
	else
		fail G1 "go.mod or go.sum changed since $(git rev-parse --short "$base")"
	fi
}
# hack/ci.sh does not run this script, so G22 cannot recurse into it.
judge_g22() {
	if [ "${KEYSTORE_SKIP_G22:-}" = 1 ]; then
		pending_row G22 "hack/ci.sh is green (not run: KEYSTORE_SKIP_G22=1)"
	elif hack/ci.sh >/dev/null 2>&1; then
		pass G22 "hack/ci.sh is green"
	else
		fail G22 "hack/ci.sh is not green (rerun it for the reason)"
	fi
}

# A rig leg runs as the function leg_<id> when one is defined, and returns 0
# pass, 1 fail; none is defined yet, so every leg is PENDING.
lab_verdicts=()
judge_leg() {
	local i="$1" id="${R_ID[$1]}" rc=0
	if [ "$lab" != 1 ]; then
		row "$id" RIG "${R_DESC[$i]} (rig leg: run --lab)"
		return 0
	fi
	if ! declare -F "leg_$id" >/dev/null; then
		pending_row "$id" "${R_DESC[$i]} (rig leg: no implementation yet)"
		lab_verdicts+=("$id PENDING")
		return 0
	fi
	"leg_$id" || rc=$?
	if [ "$rc" -eq 0 ]; then
		pass "$id" "${R_DESC[$i]}"
		lab_verdicts+=("$id PASS")
	else
		fail "$id" "${R_DESC[$i]}"
		lab_verdicts+=("$id FAIL")
	fi
}

if [ "$mode" = docs ]; then
	echo "keystore: --docs names no row yet"
	pending=$((pending + 1))
fi

i=0
while [ "$i" -lt "$nrows" ]; do
	id="${R_ID[$i]}"
	if wanted "$id"; then
		case "${R_KIND[$i]}" in
		g1) judge_g1 ;;
		g22) judge_g22 ;;
		check) if ran "$i"; then pass "$id" "${R_DESC[$i]}"; else fail "$id" "${R_DESC[$i]}$why"; fi ;;
		partial)
			if ran "$i"; then
				pending_row "$id" "${R_DESC[$i]}: checked; pending: ${R_TODO[$i]}"
			else
				fail "$id" "${R_DESC[$i]}: failed; pending: ${R_TODO[$i]}$why"
			fi
			;;
		pend) pending_row "$id" "${R_DESC[$i]}" ;;
		na) row "$id" N/A "${R_DESC[$i]} (not applicable: the flag variant was built; not counted)" ;;
		rootpend | rootcheck) row "$id" ROOT "${R_DESC[$i]} (root-run row: --root runs it; pending here, not counted)" ;;
		leg) judge_leg "$i" ;;
		esac
	fi
	i=$((i + 1))
done

j=0
while [ "$j" -lt "${#P_PKG[@]}" ]; do
	case "${P_RC[$j]}" in
	0) ;;
	absent) echo "keystore: ${P_PKG[$j]}: ../${P_PKG[$j]%%/*} is not checked out beside k3sm" ;;
	*)
		echo "keystore: ${P_PKG[$j]} failed:"
		grep -E -- '^(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' "$out_dir/$j.out" || true
		;;
	esac
	j=$((j + 1))
done

# The final status is decided before the lab record, so the record carries it.
final=0
if [ "$failed" -gt 0 ]; then
	final=1
	msg="keystore: FAIL ($failed failed, $pending pending)"
elif [ "$pending" -gt 0 ]; then
	final=3
	msg="keystore: PENDING ($pending pending, none failed)"
else
	msg="keystore: PASS"
fi

# sibling_state prints "<sha> clean|dirty" for the checkout at $1, or "absent".
sibling_state() {
	local sha dirty=clean
	if ! sha="$(git -C "$1" rev-parse HEAD 2>/dev/null)"; then echo absent; return 0; fi
	if [ -n "$(git -C "$1" status --porcelain 2>/dev/null)" ]; then dirty=dirty; fi
	echo "$sha $dirty"
}

if [ "$lab" = 1 ]; then
	record="$K3SM_LAB_EVIDENCE/keystore-lab-$(date -u +%Y%m%dT%H%M%SZ).txt"
	lab_mode="lab"
	if [ "$mode" != lab ]; then lab_mode="$mode --lab"; fi
	{
		echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "mode: $lab_mode"
		echo "head: $(git rev-parse HEAD)"
		echo "k3sm: $(sibling_state "$K3SM_ROOT")"
		for r in apis runtimed darwin-net; do
			echo "$r: $(sibling_state "$(dirname "$K3SM_ROOT")/$r")"
		done
		echo "evidence: $K3SM_LAB_EVIDENCE"
		for v in ${lab_verdicts[@]+"${lab_verdicts[@]}"}; do echo "$v"; done
		echo "exit: $final"
	} >"$record"
	echo "keystore: lab record $record"
fi

echo "$msg"
exit "$final"
