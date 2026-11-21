#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The keystore's acceptance gate: docs/design/keystore.md § "Acceptance gate",
# rows G1 to G22, the user-scope rows U1 to U103 (U15 and U39 are unused) and
# the rig legs E1 to E25. Every row is listed, on exactly one line. A row runs
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
#   --check         every G and U row; the E rows print as RIG (run --lab).
#   --rewrap        Rewrap's rows: G3, G12, G13, G14 and U5.
#   --verbs         the keys verbs: G16, G17, G21, U1.
#   --delivery      the system delivery: G18 to G20.
#   --sandbox       the pod denies and the shared path names: U16, U17, U49.
#   --api           the KeyDelivery API types: U18, U19.
#   --scope         user scopes: U6 to U11, U47, U58, U64, U66.
#   --scope-store   the user-scope store: U12 to U14, U63, U97, U101.
#   --files         the append-only files: U20 to U25, U50, U52, U60, U61, U68,
#                   U80, U88, U90, U91, U99, and in the helper variant only U70, U71.
#   --socket        the socket listener: U26 to U31, U46, U48, U54, U82.
#   --socket-ops    the socket operations: U32 to U35, U45, U51, U67, U84.
#   --exec          the non-root CLI and exec: U36 to U38, U69, U92.
#   --kd-author     KeyDelivery authoring: U40, U41, U74, U76, U87, U94.
#   --kd-reconcile  the KeyDelivery reconciler: U42, U43, U59, U73, U78, U81.
#   --kd-lifecycle  the KeyDelivery lifecycle: U44, U53, U55, U56, U62, U65,
#                   U72, U75, U77, U79, U83, U85, U86, U89, U93, U95, U96, U98, U100, U102, U103.
#   --grammar       the entry grammar in apis: U57.
#   --docs          the user docs: no row yet, so it exits 3.
# A unit mode runs only its rows and only their tests, with the same exit
# status: it exits 0 only when every row it names passes.
#
# --lab runs the rig legs E1 to E25, and nothing else, as an explicit, recorded
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
# must be exactly the names this script's row runs. Exit status: 0 every row present and
# every named test exists; 3 every row present, some named tests do not exist yet; 1 a row
# is missing or a checked row's test is missing.
#
# --root runs row R1: the package's tests as root, in the deployment's
# shape (root runs the verbs and owns the data root, the service user owns the
# store; the tests take the service user from K3SM_KEYSTORE_TEST_UID and
# K3SM_KEYSTORE_TEST_GID, or the local user _k3sm). It builds the test binary
# as the invoking user and runs only that binary under sudo -n. It passes when
# no test failed and the binary exited 0. It then runs the root-run rows
# (declared with rootpend or rootcheck): each by name, in its own k3sm
# package's binary, built the same way and run the same way. A checked
# root-run row passes only if each named test printed PASS: a SKIP fails it,
# and so does a test that did not run. A pending one prints PENDING. Neither
# --check nor a unit mode runs a root-run row: each prints it as ROOT and
# leaves it out of the count, as pending. Exit status: 0 pass; 1 fail; 3 sudo
# -n is unavailable (run sudo -v first, or run as a user sudo lets run it), or
# nothing failed and a root-run row is pending.
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
# >>> ADD NEW U ROWS (U64 upward) HERE <<<
EXPECTED_ROWS="$EXPECTED_ROWS E1 E2 E3 E4 E5 E6 E7 E8 E9 E10 E11 E12 E13 E14 E15 E16 E17 E18 E19 E20"
EXPECTED_ROWS="$EXPECTED_ROWS E21 E22 E23 E24 E25"
# >>> ADD NEW E LEGS (E24 upward) HERE <<<

MODES="check rewrap verbs delivery sandbox api scope scope-store files socket socket-ops exec"
MODES="$MODES kd-author kd-reconcile kd-lifecycle grammar docs lab listed root"

usage() {
	echo "usage: $0 --check|--rewrap|--verbs|--delivery|--sandbox|--api|--scope|--scope-store|--files|--socket|--socket-ops|--exec|--kd-author|--kd-reconcile|--kd-lifecycle|--grammar|--docs|--lab|--listed|--root" >&2
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
	sandbox) echo "U16 U17 U49" ;;
	api) echo "U18 U19" ;;
	scope) echo "U6 U7 U8 U9 U10 U11 U47 U58 U64 U66" ;;
	scope-store) echo "U12 U13 U14 U63 U97 U101" ;;
	files) echo "U20 U21 U22 U23 U24 U25 U50 U52 U60 U61 U68 U70 U71 U80 U88 U90 U91 U99" ;;
	socket) echo "U26 U27 U28 U29 U30 U31 U46 U48 U54 U82" ;;
	socket-ops) echo "U32 U33 U34 U35 U45 U51 U67 U84" ;;
	exec) echo "U36 U37 U38 U69 U92" ;;
	kd-author) echo "U40 U41 U74 U76 U87 U94" ;;
	kd-reconcile) echo "U42 U43 U59 U73 U78 U81" ;;
	kd-lifecycle) echo "U44 U53 U55 U56 U62 U65 U72 U75 U77 U79 U83 U85 U86 U89 U93 U95 U96 U98 U100 U102 U103" ;;
	grammar) echo "U57" ;;
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
run_root() {
	local t out rc=0 n m f
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
	# The committed fuzz corpus is read from ./testdata, beside the binary.
	if ! cp -R pkg/keystore/testdata "$t/testdata" || ! mkdir "$t/tmp"; then
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
	out="$(cd "$t" && sudo -n env TMPDIR="$t/tmp" ${root_ids[@]+"${root_ids[@]}"} ./keystore.test -test.count=1 -test.v 2>&1)" || rc=$?
	# sudo -n that cannot run the binary prints only its own refusal.
	if [ "$rc" -ne 0 ] && ! grep -q -- '^=== RUN' <<<"$out" && grep -q '^sudo: ' <<<"$out"; then
		printf '%s\n' "$out"
		echo "R1 PENDING as root: sudo -n is unavailable"
		return 3
	fi
	n="$(grep -c -- '^--- PASS: ' <<<"$out" || true)"
	m="$(grep -c -- '^--- SKIP: ' <<<"$out" || true)"
	f="$(grep -c -- '--- FAIL: ' <<<"$out" || true)"
	if [ "$rc" -eq 0 ] && [ "$f" -eq 0 ]; then
		echo "R1 PASS as root: $n tests passed, $m skipped"
		return 0
	fi
	printf '%s\n' "$out" | grep -E -- '^ *(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
	echo "R1 FAIL as root: $n tests passed, $m skipped"
	return 1
}

# root_build sets RB to a fresh directory under root_t holding package $1's
# test binary, pkg.test, built as the invoking user, and its testdata.
RB=""
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
	if [ -d "${rel}testdata" ]; then cp -R "${rel}testdata" "$d/testdata" || return 1; fi
	RB="$d"
}

# judge_root_row runs root-run row $1's named tests by name under sudo -n, one
# binary per package, and fails it unless each printed PASS: a SKIP fails.
judge_root_row() {
	local i="$1" id="${R_ID[$1]}" spec p pkgs="" names t out rc bad=0
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
		out="$(cd "$RB" && sudo -n env TMPDIR="$RB/tmp" ${root_ids[@]+"${root_ids[@]}"} ./pkg.test -test.count=1 -test.v -test.run "^($names)\$" 2>&1)" || rc=$?
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
	local rc=0 i=0
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

special g1 G1
check G2 "AAD is length-prefixed and binds format, scope, kind, name, version, generation" \
	TestAADLayout TestAADBindsEveryField TestRecordMovedBetweenEntries TestScopeBindsRecords
check G3 "every seal draws a fresh nonce, Rewrap included, which changes every nonce" TestSealNonceIsFresh TestRewrapChangesEveryNonce
check G4 "Delete then Put does not reopen the old v1" TestDeleteThenPutRefusesReplayedRecord
check G5 "a copied-back current is refused against the floor, with its own message; nothing recorded for the name accepts it" \
	TestFloorRefusesCopiedBackPointer TestFloorCheck
check G6 "the floor and the data root are root-owned and not shared, judged on the descriptor; the floor is the system scope's, parsed strictly; a caller that cannot write it changes nothing" \
	TestFloorTrust TestFloorScope FuzzParseFloor TestFloorNotWritableChangesNothing
partial G7 "the floor is raised by Put, Rotate, RaiseFloor and Delete when the master opens; one behind is accepted; each write re-reads it under the data-root lock, with a bounded wait (library)" \
	"list/show call RaiseFloor (PR 4: k3sm keys)" \
	TestFloorRaised TestFloorWriteRereads TestFloorLockBoundedWait
check G8 "Rotate flips the pointer last; a crash before the flip leaves the old version current" \
	TestRotateCrashAtEveryStep TestRotate
check G9 "a Rotate retry discards the orphan and seals the value it was given" TestRotateRetryDiscardsOrphan TestParseVersionName
check G10 "the master is minted only by the first put, never over entries" TestMasterMint TestMintCountsReservedUserName
check G11 "the master is judged on the open descriptor" TestMasterTrust
check G12 "Rewrap resumes after a crash at every step, old key then new, nothing unreadable; a bad master.next is discarded only with no .new file" \
	TestRewrapCrashAtEveryStep TestRewrapKeyReuse TestRewrapRefusesStalePointer TestRewrapVerifiesCommit TestRewrapGuards \
	TestRewrapRefusesLiveMasterFirst TestRewrapUserScopesBeforeSwap TestRewrapRecoversReplacedNext \
	TestRewrapRemovesStaleNew TestRewrapOverFullFloor TestRewrapCommitChecksMetadata TestRewrapUserScopesUnderLock
check G13 "a crash between the master renames leaves a trusted master, and the next verb completes the swap" \
	TestRewrapMasterRenameCompleted TestFinishSwapLeavesUnmatchedFingerprint
check G14 "one lock with a bounded wait serializes Rewrap, Rotate, Put, Delete and the reads, and no read blocks" \
	TestLockBoundedWait TestLockExcludes TestConcurrentOperations TestFIFORefused TestReadDirNamesBound
check G15 "files a root verb writes are the service user's, at the layout's modes, inside the store" \
	TestOwnership TestCredSymlinkRefused TestRefusesSymlinks TestMkdirRefusesSwappedDirectory \
	TestCreateEntryRefusesSwappedDirectory TestConfigRefused
partial G16 "List marks an unreadable entry with Err, and Delete still removes it; an entry directory with no current is an interrupted put only in the shape a crashed Put leaves and with its generation not in the floor, and Delete removes it too (library)" \
	"list exits 1 on a corrupt entry (PR 4: k3sm keys)" \
	TestListMarksCorruptEntry TestDeleteCorruptEntry TestEntryWithNoPointer TestCommittedBeforeDecodesGeneration \
	TestDeletePlantedNonDirectory TestDeleteDirectoryAtCurrent TestPointerVersionBound TestPutCrashAtEveryStep \
	TestMkdirSyncsParent
pend G17 "show prints a value only with --reveal, byte-exact (PR 4)"
pend G18 "delivery refused while encryption is off (PR 5)"
pend G19 "the delivery declaration is root-owned (PR 5)"
pend G20 "the reconciler touches only its labelled Secrets (PR 5)"
pend G21 "the rollback recipe is a byte-exact round trip (PR 4)"
special g22 G22

pend U1 "rotate --from-version N writes version N's bytes as a new version server side; no value leaves the store (keys verbs)" \
	k3sm/cmd/k3sm::TestKeysRotateFromVersionNoValueOut
partial U2 "AAD scope: a record moved between scopes fails to open, and two users derive different keys" "a record opened as another user is refused (user scopes)" \
	TestScopeBindsRecords TestDerivedKeysDifferByScope
check U3 "KDF labels take the scope; checkScope accepts only system and user/<decimal uid>; kinds 0xFE and 0xFD are reserved" \
	TestDerivedKeysDifferByScope TestCheckScope TestParseRecordRefusesMalformed
check U4 "the first-Put mint refuses with .user present and the master missing" \
	TestMintCountsReservedUserName
check U5 "Rewrap refuses with ErrScopeUnsupported, writing nothing, while .user exists as a directory, a file or a symlink" \
	TestRewrapRefusesWhileUserScopesExist
pend U6 "scope.key is sealed under W, bound to the GeneratedUID; a mismatch is ErrScopeOwnerChanged (user scopes)" \
	TestScopeKeyGeneratedUIDMismatch
pend U7 "the GeneratedUID lookup past its deadline, 250 ms everywhere, or in error fails closed; mbr_uid_to_uuid is in the symbol canary (user scopes)" \
	TestGeneratedUIDLookupDeadlineFailsClosed k3sm/internal/hostacl::TestMbrUIDToUUIDSymbolCanary
pend U8 "a scope's records open only under its K_u; a copied .user/<uid>/ without the master opens nothing (user scopes)" \
	TestScopeCopyWithoutMasterOpensNothing
pend U9 "per-scope fingerprints differ for equal values in two scopes (user scopes)" \
	TestFingerprintsDifferAcrossScopes
pend U10 "user/<other>/... is ErrNotFound, same text as an absent entry; a short name resolves to the uid and is printed (user scopes)" \
	TestOtherUserIsNotFound TestShortNameResolvesToUID
pend U11 "the Go resolver and Phase A's checkName pass the shared entry-grammar vectors; pkg/keystore imports no Kubernetes package (user scopes)" \
	TestEntryGrammarVectorsResolver TestEntryGrammarVectorsCheckName TestCheckScopeRefusesUserZero TestAllDigitSegmentIsAlwaysUID TestKeystoreIsKubernetesFree
pend U12 "master Rewrap re-wraps every scope.key and leaves user records byte-identical; resumable at every step, by fault injection as G12 (user-scope store)" \
	TestRewrapRewrapsScopeKeysResumable
pend U13 "quotas: the 257th entry and the byte budget answer ErrQuota, and so does the 65th live delivery; rm and withdraw still work (user-scope store)" \
	TestUserScopeQuota TestDeliveryRecordQuota
pend U14 "the delivery record stores UID, the full target tuple under its seal, and target digest; add, look up and withdraw round-trip under the floor; the digest covers entry, namespace, secretName, dataKey and requestedBy (user-scope store)" \
	TestDeliveryRecordDigestRoundTrip TestDeliveryRecordVersionByteAndDigestLabel TestDeliveryDigestCoversRequestedBy
pend U16 "every pod profile variant (native, vm, container-vm, xcode, expose-paths, wasm, the profile an exec-session process runs under, a custom pod root distinct from the data root) denies every keystore path, the protected-prefix validator refusing any re-allow onto one, since the order of denies and allows protects nothing; a hostPath or expose path onto the data root is refused; an empty data root fails closed; over the whole rendered profile, a pod root equal to or a parent of the data root included, no emitted allow matches a keystore path; canonical /private/var/lib/k3sm denies and a regex keystore- prefix deny; a write, create, unlink, rename and network-bind on keystore-run/, keys.sock and every keystore-* name are refused; each also through /System/Volumes/Data/private/var/lib/k3sm and the data volume's mount path; rig leg E10 (sandbox denies)" \
	runtimed/pkg/sandbox::TestDataRootDeniesKeystorePathsEveryProfile TestNoEmittedAllowCoversKeystorePath TestDataRootDeniesCanonicalPathAndPrefixRegex TestProtectedPrefixesRefuseKeystoreReallow TestEmptyDataRootFailsClosed TestVMGuestGetsNoDataRootShare TestKeystoreDenyCoversWritesAndBind TestKeystoreDeniesCoverPathAliases
pend U17 "runtimed refuses a pod process uid of 501 or above, and uid 0 without a drop, at credential resolution and at spawn, on the final effective uid after any drop; rig legs E21, E22 (sandbox denies)" \
	runtimed/pkg/runtime::TestResolveCredentialRefusesLoginRangeUID TestResolveCredentialRefusesRootWithoutDrop \
	runtimed/pkg/supervisor::TestSpawnRefusesLoginRangeUID TestSpawnRefusesRootUIDWithoutDrop TestSpawnChecksFinalEffectiveUID
pend U18 "CRD: entry, secretName, dataKey, requestedBy immutable by CEL transition rules; status subresource on; reasons listed; a system/ entry is refused (KeyDelivery API)" \
	apis/config/crd::TestKeyDeliveryCRDMatchesTheGoTypes TestKeyDeliveryImmutableFields TestKeyDeliveryRequiredFields TestKeyDeliveryRequestedByMatchesEntryUID TestKeyDeliveryConditionsListMap TestKeyDeliveryRefusesSystemEntry
pend U19 "the CRD pattern, its maxLength, the uid range rule and the 253-byte name-length rule pass the shared entry-grammar vectors (KeyDelivery API)" \
	apis/config/crd::TestEntryGrammarVectors
pend U20 "a user-scope current copied back is refused against the floor log, with the user-scope floor message, which names floor --rebuild, not removing keystore-floor.json; rig leg E9 (append-only files)" \
	TestUserFloorRefusesCopiedBackCurrent
pend U21 "install creates both logs service-user-owned 0600 and flagged; the listener refuses to start when a flag is clear or a log is not the service user's; rig leg E1 (append-only files)" \
	k3sm/pkg/install::TestKeystoreAppendOnlyFilesAtInstall k3sm/pkg/keystore::TestFlagCheckRefusesUnflagged
pend U22 "floor --rebuild and audit --rotate mark and stage under keystore- names in the root-owned data root, stop the listener, hold the lock, write the new file before touching the old, clear the old flag before any rename, flag the new file after the rename; a crash at each step leaves the marker, and a rerun leaves a flagged file; every audit and floor append takes the store lock, so a reconciler append during audit --rotate waits; after maintenance, under the exclusive lock, the server reopens its audit and floor append descriptors and recounts the per-uid shares before releasing it, and the counts reset; rig leg E17 (append-only files)" \
	k3sm/cmd/k3sm::TestKeysFloorRebuildCrashOrder TestKeysAuditRotateCrashOrder k3sm/pkg/keystore/reconcile::TestReconcilerAppendWaitsForAuditRotate \
	k3sm/pkg/keystore/socket::TestMaintenanceReopensLogsAndResetsShares
pend U23 "every audited operation writes one v:1 line; no line carries a value or its length; readers ignore unknown fields (append-only files)" \
	TestAuditLineNeverCarriesValue TestAuditReaderIgnoresUnknownFields
pend U24 "soft cap shows in doctor; past the hard cap every mutating user op is ErrLogFull, except the revocation class, which draws on its uid's revocation budgets; a line over 1 KiB is refused (append-only files)" \
	TestLogHardCapRefusesMutations TestAuditLineBoundedAtOneKiB
pend U25 "backup and restore round trip: a restored tree with cleared flags is refused until floor --rebuild, then opens; the rebuild writes a line for every entry directory holding a generation file, sequence 0 without an authenticated pointer, so a damaged entry stays ErrCorrupt and never becomes ErrNotFound; rig leg E17 (append-only files)" \
	TestBackupRestoreRoundTripRebuild TestRebuildKeepsDamagedEntryCorrupt
pend U26 "peers uid 0, the service uid and uid < 501 are refused before any frame is read (socket listener)" \
	k3sm/pkg/keystore/socket::TestPeerEligibility
pend U27 "framing: an oversize frame, unknown type or missing HELLO closes; an unknown header field is ignored; HELLO picks the highest common version (socket listener)" \
	k3sm/pkg/keystore/socket::FuzzFrameReader TestFramingBounds TestSubLengthsWithinFrame TestHelloReadDeadline TestUnknownHeaderFieldsIgnored TestHelloVersionRange TestHelloReplyCarriesVersionAndMaxFrame TestHelloNoOverlapSendsUnsupportedVersion TestUnknownOpKeepsConnection TestFrameCapCoversMaxValue
pend U28 "16 connections in all, 2 per uid; a request past 10 s is cut; a connection idle 30 s after HELLO or between requests is closed (socket listener)" \
	k3sm/pkg/keystore/socket::TestConnectionCapsPerUID TestRequestTimeout TestIdleTimeoutAfterHelloAndBetweenRequests
pend U29 "a listener panic is recovered and restarted; the apiserver is untouched; a stale socket is unlinked only if a service-user socket; a lock wait past 2 s fails the request (socket listener)" \
	k3sm/pkg/keystore/socket::TestListenerRecoversPanic TestStaleSocketUnlinkChecksOwner TestBoundedLockWait
pend U30 "with two servers registered, the listener does not start and doctor says why (socket listener)" \
	k3sm/pkg/keystore/socket::TestUserScopeRefusedWithTwoServers
pend U31 "a missing or unflagged file logs the install Warn at start and on each retry; doctor reports user scope off (socket listener)" \
	k3sm/pkg/keystore/socket::TestListenerWarnsOnEveryRetry k3sm/cmd/k3sm::TestDoctorKeystoreUserScopeRow
pend U32 "the audit line is written before the reply; a failed append refuses mutating ops and reads (socket operations)" \
	k3sm/pkg/keystore/socket::TestAuditBeforeReply TestAuditFailureRefusesOps
pend U33 "refused lines are rate-limited per uid with a summary of the dropped count (socket operations)" \
	k3sm/pkg/keystore/socket::TestRefusedLinesRateLimited
pend U34 "5 mutating ops a second per uid; 30 read-for-exec a minute per uid, each audited exec-read (socket operations)" \
	k3sm/pkg/keystore/socket::TestMutationRateLimit TestExecReadCapPerUID
pend U35 "the socket server's store interface has no reveal, show or rewrap method (socket operations)" \
	k3sm/pkg/keystore/socket::TestStoreInterfaceHasNoRevealMethod
pend U36 "the client refuses a socket whose connected peer uid is not the owner of keystore-run/, whatever the path checks said (non-root CLI and exec)" \
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
	k3sm/pkg/keystore/socket::TestCrossUserRefusedFakePeerCred TestNonRootCannotNameSystemEntries
pend U46 "baseSocketDenies derives keys.sock from runtimed's names (socket listener)" \
	k3sm/pkg/provider::TestBaseSocketDeniesKeystoreSocket
pend U47 "seam guard: the real primitives the keystore's tests replace are unreachable from a test build (user scopes)" \
	k3sm/pkg/keystore::TestRealPrimitivesUnreachable
pend U48 "seam guard: the real primitives the socket listener's tests replace are unreachable from a test build; the peer-credential source is a constructor parameter of the listener, nil refused (socket listener)" \
	k3sm/pkg/keystore/socket::TestRealPrimitivesUnreachable TestListenerRequiresPeerCredSource

pend U49 "the shared keystore path names build with CGO_ENABLED=0 and import only the standard library; pkg/keystore never imports the sandbox package (sandbox change)" \
	runtimed/pkg/keystorepaths::TestLeafImportsStdlibOnly k3sm/pkg/keystore::TestKeystoreImportsNoSandbox
rootpend U50 "root-run: the defeat list run as the service user against both flagged logs, by name under --root, a SKIP failing it: each defeat fails, bytes and flag unchanged, O_APPEND still succeeds (append-only files)" \
	k3sm/pkg/keystore::TestAppendOnlyDefeatListAsServiceUser
pend U51 "per-uid log fairness: the share is a fixed byte count, at most 1/16 of the hard cap; every line, reads included, is charged to its uid; a uid past its share has its mutations and reads refused with ErrLogFull while another uid's succeed, never as the global append failure; it cannot get another uid's mutations, reads or revocations refused, though it can delay them through the store lock; list and deliveries are rate-limited per uid (socket operations)" \
	k3sm/pkg/keystore/socket::TestLogSharePerUIDRefusesOnlyThatUID TestLogShareAtMostOneSixteenthOfHardCap TestShareRefusalIsNotGlobalAppendFailure TestReadRateLimitPerUID TestReadsChargedToShare TestShareExhaustionIsolatedPerUID
pend U52 "every root verb writes one audit line with via root once the log exists, and none before it (append-only files)" \
	k3sm/cmd/k3sm::TestEveryRootVerbWritesAuditLine
pend U53 "every reconciler Secret write and delete, and every record withdrawal, writes one audit line with via reconciler, except drift repairs, coalesced to one line per delivery per 10 minutes (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestEveryReconcilerWriteAndDeleteAudited
pend U54 "a pre-frame refusal writes a refused line with the peer uid, rate-limited per uid with a dropped-count summary (socket listener)" \
	k3sm/pkg/keystore/socket::TestPreFrameRefusalsAudited TestPreFrameRefusalLinesRateLimited
pend U55 "a transient lookup, SAR or apiserver error leaves the Secret, the record entry and the finalizer, sets Authorized=Unknown with reason Indeterminate, and retries with backoff; a SAR with allowed=false and no evaluation error is a definitive denial whatever denied says, and an evaluation error or a failed call is Indeterminate; no sweep before readyz and the RBAC, KeyDelivery and Secret informers sync; every deleting outcome deletes only on two consecutive sweeps; only the allow-list of definitive outcomes deletes (ErrNotFound in a scope that opened and ErrScopeOwnerChanged among them), and every other sentinel, ErrScopeAbsent included, is Indeterminate; against the real store, on ErrScopeOwnerChanged the reconciler reads the deliveries record under W without the GeneratedUID check only to find recorded targets, deletes them by the target-matching rule, and never delivers, rotates or opens an entry (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestTransientErrorLeavesSecretSetsUnknown TestSAREvaluationErrorIsIndeterminate TestSARAllowedFalseWithoutErrorIsDenial TestNoSweepBeforeReady TestDenialNeedsTwoSweeps TestScopeOwnerChangedDeletes TestEverySentinelBesidesNotFoundAndOwnerChangedIsIndeterminate \
	TestScopeOwnerChangedDeletesAgainstRealStore
pend U56 "a delivery record with an unknown format version is refused by the store and read by the reconciler as Indeterminate, never as a denial (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore::TestDeliveryRecordUnknownVersionRefused k3sm/pkg/keystore/reconcile::TestUnknownRecordVersionIsIndeterminate
pend U57 "the entry grammar package imports only the standard library, exports the pattern, the maxLength and the parse, and passes the shared vector table (entry grammar)" \
	apis/keystore/entry::TestGrammarVectors TestImportsStdlibOnly
pend U58 "seam guard, repo level: every package on the closed seam-package list has its TestMain stubs and its TestRealPrimitivesUnreachable, and no package off the list declares a seam (user scopes)" \
	k3sm/pkg/keystore::TestEverySeamPackageHasAGuard
pend U59 "seam guard: pkg/keystore/reconcile's TestMain stubs its clock seam (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestRealPrimitivesUnreachable
pend U60 "seam guard: cmd/k3sm's TestMain stubs each of its seams: clock, uid resolver, client-side peer credentials, server code identity, exec, euid source, file-attribute writer (append-only files)" \
	k3sm/cmd/k3sm::TestRealPrimitivesUnreachable
pend U61 "seam guard: pkg/install's TestMain stubs its euid source and file-attribute writer (append-only files)" \
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
pend U67 "the revocation class (withdraw, rm, rotate, the withdrawal's floor line, the reconciler's deliver-delete, its deliver-write of a withdrawal and its rotation write) bypasses the share past it and draws on its uid's own budgets per log above the hard cap: a 256 KiB reconciler allowance and a separate 64 KiB socket margin; neither budget can draw on the other; refused only when the budget it draws on runs out, so one uid's revocations are never refused because of another uid; a no-op revocation is charged to the share; a log passes the hard cap by at most 320 KiB per user scope, plus the 1 MiB reconciler budget (socket operations)" \
	k3sm/pkg/keystore/socket::TestRevocationBypassesShareUsesReserve TestNoOpRevocationChargedToShare TestReserveKeepsReconcilerPart TestRevocationAllowanceIsPerUID \
	TestSocketMarginSeparateFromReconcilerAllowance
rootpend U68 "root-run: the maintenance verbs refuse a symlink or swapped file planted at the marker, a staging name or the old log; creates are O_EXCL|O_NOFOLLOW through one data-root descriptor, fchflags on the held descriptor after renameat and fchown to the service user only after the flag, never renaming a flagged file or over one; no log byte changes on a refusal (append-only files)" \
	k3sm/cmd/k3sm::TestMaintenanceRefusesPlantedSymlinkAndSwap
pend U69 "the client pins the server: the peer's audit token (LOCAL_PEERTOKEN) must resolve to the cdhash of the installed /Library/k3sm/k3sm, or nothing is written; another service-user binary, a reused pid, a lookup error and an old server after an upgrade are refused (non-root CLI and exec)" \
	k3sm/cmd/k3sm::TestClientPinsServerByInstalledCDHash TestClientRefusesServiceUIDPeerOfOtherCode TestClientRefusesReusedPeerPID TestClientCDHashMismatchNamesRestart
pend U70 "helper variant only: the floor helper admits only a service-uid peer whose audit token resolves to the installed binary's cdhash, the server pins the helper as root and that binary, and only append and read are served (K0 amendment, helper variant only)" \
	k3sm/pkg/keystore/floorhelper::TestFloorHelperPeerPinned TestFloorHelperRefusesOtherRequests
pend U71 "helper variant only: every pod profile variant denies the floor helper's socket for connect, bind and every file operation (K0 amendment, helper variant only)" \
	runtimed/pkg/sandbox::TestFloorHelperSocketPodDenied
pend U72 "an orphan-cascade delete of a KeyDelivery, its Secret's ownerReference stripped, still deletes the Secret, found by label, owner annotation and the sealed record's UID (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestOrphanCascadeStillDeletesSecret
pend U73 "only an honoured, recorded KeyDelivery can claim a target for SecretClaimed; an older unrecorded object claims nothing; precedence follows the last honoured owner, which keeps the claim until a definitive deleting outcome, and an indeterminate sweep keeps the claim (KeyDelivery reconciler)" \
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
rootpend U80 "root-run: rm-scope and floor --rebuild walk .user/<uid>/ by descriptor with openat, unlinkat and O_NOFOLLOW, refuse a planted symlink, FIFO or other non-regular file, read with a bounded size, re-check SameFile after each open and never follow a swapped directory (append-only files)" \
	k3sm/cmd/k3sm::TestRootWalksRefusePlantedNames
pend U81 "a KeyDelivery never touches a Phase A Secret: the label value is the constant keydelivery and the entry is in the annotation k3sm.io/keystore-entry; a target present and not claimed by a KeyDelivery is SecretExists, never overwritten or deleted (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestKeyDeliveryNeverTouchesPhaseASecret
pend U82 "eligible peer uids are 501 to 2147483647: nobody (4294967294) and every uid at 2^31 or above are refused before any frame, with a refused line; 501 and 2147483647 are admitted; no scope is minted outside the range (socket listener)" \
	k3sm/pkg/keystore/socket::TestPeerUIDRangeRefusesNobodyAndHighUIDs
pend U83 "the reconciler checks the user-scope floor log: a missing or unflagged floor log is Indeterminate for writes, so no deliver-write runs until floor --rebuild; the floor holds writes only, so a deleting outcome still deletes the Secret without the floor and only the record withdrawal waits for it (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestReconcilerHoldsWritesWithoutFloor TestDeleteProceedsWithoutFloor
pend U84 "when a log's size is past the hard cap, doctor shows a Warn with the overshoot in bytes and the rotate or rebuild hint, and none at or below it; the overshoot is at most 320 KiB per user scope, plus the 1 MiB reconciler budget (socket operations)" \
	k3sm/cmd/k3sm::TestDoctorWarnsOnLogOvershoot
pend U85 "a reconciler line charged to no uid (a forged-Secret refused line, a drift repair, their summaries) draws on the reconciler budget, 1 MiB per log, separate from every uid and excluded from the hard-cap test; forged Secrets are counted in a bounded LRU of 1024 (namespace, name) pairs with no per-resourceVersion set, new pairs' lines at most 10 a minute and at most one summary refused line a minute carrying the dropped count; past the budget the lines are dropped and counted and doctor warns; N forged updates leave every uid able to read and mutate (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestForgedSecretFloodLeavesEveryUIDServed TestUnchargedLinesHaveOwnBudget
pend U86 "a drift repair (the reconciler re-creating or repairing a delivered Secret that someone other than the reconciler edited or deleted, at the version already delivered) is reconciler-class: it draws on the reconciler budget and is never charged to the owner's share or budgets; repairs are coalesced to one audit line per delivery per 10 minutes with a count, and rate-limited per delivery with exponential backoff capped at 10 minutes; a write of a new version after the owner's own rotate or put stays charged to the owner; Ready=Delivered compares k3sm.io/keystore-digest, the sha256 of the Secret's data, each sweep, so a substituted data under an intact version annotation is drift (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestDriftRepairNotChargedToOwner TestSubstitutedDataIsDrift
pend U87 "the admission policy also matches UPDATE and DELETE of keydeliveries and admits one only when the requester equals oldObject.spec.requestedBy, is the k3sm server's identity, or is in system:masters (and, for DELETE only, the namespace controller's ServiceAccount); a finalizer edit is an UPDATE, so another author can neither delete the object nor strip its finalizer; the reconciler's and withdraw's own writes pass; on a DELETE object is null and only oldObject is read; failurePolicy is Fail; rig leg E23 (KeyDelivery authoring)" \
	k3sm/pkg/policy::TestVAPRefusesDeleteByOtherAuthor TestVAPRefusesFinalizerStripByOtherAuthor
pend U88 "floor --rebuild never lowers: if any scope fails to open for a non-definitive reason (ErrScopeOwnerUnknown, a lookup past its deadline, ErrBusy) or any error but an owner change, it refuses to finish, names the scope and changes nothing; an owner-changed scope is rebuilt from its pointers read under W without the GeneratedUID check; the deliveries record's AAD is scope, kind 0xFD, name deliveries, generation and sequence, its floor key is (user/<uid>, .deliveries, generation, seq), and the rebuild writes that key's line; a copied-back older deliveries record is refused against the floor, before and after a rebuild (append-only files)" \
	k3sm/cmd/k3sm::TestRebuildRefusesOnUnopenableScope k3sm/pkg/keystore::TestCopiedBackDeliveriesRecordRefused
pend U89 "reads take the store lock shared and mutations exclusive, through a writer-preferring in-process lock; a server exclusive hold does at most 50 ms of work per operation, larger work chunked, no hold across an API call (the bound measured in K7a); a reconciler revocation that gets ErrBusy retries up to 3 times with jitter in the same sweep before it is Indeterminate; under a sustained read load from other uids a revocation completes (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestRevocationCompletesUnderOtherUIDReadLoad
rootpend U90 "root-run: no unflagged window for the new file: it stays root-owned 0600 while written, and the order is write, fsync, clear the old file's flag, rename, set sappnd on the held descriptor, then fchown to the service user, so the service user never holds a descriptor from before the flag; a crash that leaves the canonical file unflagged or root-owned keeps the listener refused until the verb is rerun; the maintenance wait is the exclusive .lock, bounded at 30 s (append-only files)" \
	k3sm/cmd/k3sm::TestMaintenanceHandsOverOnlyAfterFlag
pend U91 "audit --rotate keeps four archives, .1 to .4, and refuses, changing nothing, when .4 exists unless --discard-oldest; each shifted archive is re-flagged on its own descriptor; the doctor hint says to export first; rotation resets the shares, bounded by the archive count (append-only files)" \
	k3sm/cmd/k3sm::TestAuditRotateKeepsFourArchives
pend U92 "a rotate whose delivery will stall (owner past share, the delivery's rotation write used) is stored and answered stored; delivery pending: past your log share; the CLI prints the warning line and exits 0 (non-root CLI and exec)" \
	k3sm/cmd/k3sm::TestRotateReportsDeliveryStall
pend U93 "the sweep period is 30 s by default; two consecutive deleting observations count only when at least 60 s apart on the clock seam, however many sweeps run between them (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestDeletingObservationsSpacedOnClock
pend U94 "withdraw opens the caller's scope and so runs the GeneratedUID check: a reused uid with a changed GeneratedUID gets scope-owner-changed and deletes nothing (KeyDelivery authoring)" \
	k3sm/pkg/keystore/socket::TestWithdrawChecksGeneratedUID
pend U95 "rm-scope lists every RoleBinding and ClusterRoleBinding with the subject k3sm:local:<uid> and refuses, changing nothing, unless none exist or --keep-bindings is given (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestRmScopeRefusesWithBindings
pend U96 "the deliveries record is exempt from the 64 KiB value cap and bounded at 64 live entries plus 256 withdrawn tombstones, 1,280 bytes an entry, 416 KiB sealed; at the bound deliver answers quota and a withdrawal still succeeds, in place; a tombstone is pruned only after its Secret is seen gone (Get not found) on two sweeps at least 60 s apart (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestDeliveriesRecordBoundAndPrune TestRevocationNeverRefusedAtRecordBound
pend U97 "when rotate answers ErrQuota, rm then put recovers: rm frees every version and put stores the value as version 1 of a new generation; the quota error names that recovery (user-scope store)" \
	k3sm/pkg/keystore::TestRotateQuotaRecoveredByRmThenPut
pend U98 "the sealed deliveries record stores each delivery's KeyDelivery metadata.name; the orphan sweep checks the object with a live Get by that name sent to the API server, never an informer cache and never a List; not found, or another UID, deletes only on two consecutive observations at least 60 s apart, any other answer resetting the count; no sweep before the KeyDelivery and Secret informers sync (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestOrphanSweepUsesLiveGetByName TestOrphanSweepNeedsTwoObservations
pend U99 "under the store lock, before every audit or floor append, the server compares its descriptor's (dev, ino) with the canonical name's and reopens on a mismatch, recounting the shares; audit --rotate and floor --rebuild each complete while the server never saw the marker, and every later line lands in the new canonical file (append-only files)" \
	k3sm/pkg/keystore/socket::TestAppendReopensOnInodeMismatch
pend U100 "a departed account with an unreused uid is reported, not acted on: doctor lists every scope whose uid has no directory record (a synthesized GeneratedUID); each of that scope's deliveries gets SecretRetained=True with reason OwnerUnresolvable, and no Secret is deleted (KeyDelivery lifecycle)" \
	k3sm/cmd/k3sm::TestDoctorListsUnresolvableScopes k3sm/pkg/keystore/reconcile::TestOwnerUnresolvableRetainedCondition
pend U101 "rewrap prints a warning whenever .user/ exists, before it starts and when it finishes, saying Rewrap does not re-key K_u and naming the procedure: each user re-puts their values after a suspected master exposure; with no .user/ it prints none (user-scope quotas, scope-key Rewrap and the delivery record)" \
	k3sm/cmd/k3sm::TestRewrapWarnsWhenUserScopesExist
pend U102 "the sealed record stores the last delivered version per delivery, raised after the Secret write succeeds; the repair-versus-owner classifier uses only that recorded version: a rewritten version annotation and a rewritten status.deliveredVersion each leave the charge unchanged (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestChargingIgnoresTamperedVersionAnnotationAndStatus
pend U103 "a Secret at a recorded target whose label or owner annotation was removed is never overwritten or deleted, under a revocation, the object's deletion and rm-scope alike; the KeyDelivery gets SecretRetained=True with reason LabelRemoved, and doctor names the Secret and the KeyDelivery (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestStrippedLabelReportedNotDeleted
# >>> ADD NEW U ROWS (U64 upward) HERE, and add each to EXPECTED_ROWS and to mode_rows <<<

leg E1 "files" "preconditions: secrets encryption on; one server; keystore-run/ and both logs present, service-user 0600, SF_APPEND set; the doctor user-scope row on; keystore.sh --check exits 0 on the build" "the append-only files"
leg E2 "socket-ops" "the user, no sudo, puts user/<me>/e2e-token (short-name form): exit 0; the CLI prints the resolved user/<uid>; k3sm keys list shows it; the audit log has a put line with no value" "the socket operations"
leg E3 "kd-reconcile" "an admin binds k3sm:keystore-delivery-author and the built-in edit ClusterRole for k3sm:local:<uid> in ks-e2e and the user delivers the entry to Secret e2e-token: KeyDelivery Ready, reason Delivered, observedGeneration current; requestedBy is k3sm:local:<uid>; a pod mounting the Secret reads exactly the stored bytes" "the KeyDelivery reconciler"
leg E4 "verbs" "the user rotates (rotate --in -), then rotate --from-version 1: the pod's mounted file moves to v2, then to v1's bytes as v3, within one sweep each" "the k3sm keys verbs"
leg E5 "exec" "k3sm keys exec user/<uid>/e2e-token --env TOKEN -- /usr/bin/env: the child sees TOKEN; the CLI wrote nothing else; ps during the run shows no value in argv; one exec-read audit line" "the non-root CLI and exec"
leg E6 "socket-ops" "as the one login user: list, exec, rotate, rm and deliver of an unused other uid's entry and of system/e2e-sys, then a connect as root and as the service user: not found each time, text identical to an absent entry of the user's own, refused audit lines carry the user's uid; root and the service user are refused at accept" "the socket operations; the socket listener"
leg E7 "kd-reconcile" "an admin copies E3's KeyDelivery into ks-e2e-2, where the user also has the role: Authorized=False, reason NotRecorded, no Secret" "the KeyDelivery reconciler"
leg E8 "kd-reconcile" "an admin strips the CRD's transition rules (restored at the end) and edits E3's spec.secretName: Authorized=False, NotRecorded (digest mismatch); the original Secret deleted; no Secret under the new name" "the target digest"
leg E9 "files" "sudo cp saves current, the user rotates, sudo cp puts the old current back, then the same for a system/ entry: both lists mark the entry corrupt with the floor message" "the append-only files"
leg E10 "sandbox" "a pod pinned to the darwin node tries connect(2) to keys.sock and to read server/keystore, keystore-run/, both logs and Phase A's two files, then a write, create, unlink, rename and network-bind on keystore-run/, keys.sock and every keystore-* file, each also through /System/Volumes/Data/private/var/lib/k3sm and the data volume's mount path: EPERM for each; then a vm Pod on the node tries keys.sock and the data root from the guest: no path to either" "runtimed's sandbox change"
leg E11 "kd-lifecycle" "an admin removes the user's RoleBinding in ks-e2e: within two sweeps the Secret is deleted; Authorized=False, NotAuthorized" "the KeyDelivery reconciler (lifecycle)"
leg E12 "socket-ops" "root puts and delivers system/e2e-sys; then the user, with no sudo, tries deliver, list and exec on it: root's Secret is delivered and stays; each of the user's attempts answers not found and nothing reaches ks-e2e-2" "root delivery; the socket operations"
leg E13 "kd-author" "a ServiceAccount token creates a KeyDelivery: refused at admission" "KeyDelivery authoring"
leg E14 "kd-lifecycle" "k3sm keys undeliver on E3's object, then kubectl delete of a second one: each Secret deleted before its object goes; the hint printed; no orphan Secret after one sweep" "the KeyDelivery reconciler (lifecycle)"
leg E15 "" "upgrade from the previous release's install tree, then sudo k3sm install: system scope intact; user scope comes on after the install, off with the Warn and doctor row before it" "upgrade visibility"
leg E16 "" "rollback to the previous release, then forward again: the old build runs with the keystore files unused; after rolling forward the user's entries, records and Secrets are intact and re-adopted" "the rollback guard"
leg E17 "files" "backup and restore round trip with cp, then floor --rebuild and audit --rotate: before the rebuild the listener refuses (flags clear); after it every entry opens and both logs are flagged" "the flag check"
leg E18 "socket" "an old worker on the previous release joins this server: worker Ready; pods there mount delivered Secrets; no keystore listener or reconciler on the worker" "server-only listener"
leg E19 "socket" "launchctl kickstart -k of the server while a client is connected mid-request: a clean error, not a hang; the listener back within its backoff; kine and the apiserver back; no partial record" "the listener lifecycle"
leg E20 "files" "reboot of the server node, operator-attended (--attended reboot): after boot the flags are still set, the listener starts, E2's entry opens, E3's Secret is still current" "the flag check"
leg E21 "sandbox" "a native pod with runAsUser 501 is refused at spawn: the container never starts, and its status carries the uid refusal" "runtimed's sandbox change"
leg E22 "sandbox" "a native pod with runAsUser 0 is refused at spawn: the container never starts as root, and its status carries the uid refusal" "runtimed's sandbox change"
leg E23 "kd-reconcile" "against the real authorizer, a role with create on secrets and update and delete on one named secret: delivery as that name is Ready, Delivered; delivery as another name is Authorized=False, NotAuthorized, with no Secret; then another principal (kubectl --as, with edit in the namespace) deletes the KeyDelivery and patches its finalizer away: each refused at admission, the object, its finalizer and the Secret stay" "the KeyDelivery reconciler; KeyDelivery authoring"
leg E24 "exec" "with the listener stopped by the maintenance marker, a non-k3sm program run as the service user binds keys.sock; the user's k3sm keys list and put refuse before any frame, naming the server pin; then the real installed k3sm binary, exec'd inside a native pod, tries to bind keys.sock and gets EPERM; the real server is accepted afterwards" "the server pin; the pod bind deny"
leg E25 "files" "helper variant only: a native pod tries connect(2) to the floor helper's socket, and the login user and a non-k3sm service-user program each send it an append: EPERM for the pod, both refused, no line appended" "the helper pin"
# >>> ADD NEW E LEGS (E24 upward) HERE, with the unit mode that delivers the last feature <<<

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
U67|64 KiB socket margin
U67|neither budget can draw on the other
U67|at most 320 KiB per user scope
U84|overshoot
U67|one uid's revocations are never refused because of another uid
U73|an indeterminate sweep keeps the claim
U25|a damaged entry stays ErrCorrupt
U81|keydelivery
U81|k3sm.io/keystore-entry
U77|only then removes the scope
U77|refuses and changes nothing
U68|O_EXCL
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
U83|the floor holds writes only
U89|retries up to 3 times with jitter
U89|a revocation completes
U90|root-owned 0600 while written
U90|never holds a descriptor from before the flag
U91|refuses, changing nothing, when .4 exists unless --discard-oldest
U92|stored; delivery pending: past your log share
U93|at least 60 s apart on the clock seam
U94|runs the GeneratedUID check
U95|refuses, changing nothing, unless none exist or --keep-bindings is given
U96|a withdrawal still succeeds
U96|seen gone (Get not found) on two sweeps
U45|withdraw and deliveries
U7|250 ms everywhere
U20|names floor --rebuild, not removing keystore-floor.json
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
U97|rm then put"

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
