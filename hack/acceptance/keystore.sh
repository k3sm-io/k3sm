#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The keystore's acceptance gate: docs/design/keystore.md § "Acceptance gate",
# rows G1 to G22, and U5 (Rewrap refuses while user scopes exist). Every row is
# listed, on exactly one line. A row runs the tests that deliver it and passes
# only if each named test ran and passed; a row whose pull request has not
# landed yet prints PENDING, never PASS. A row delivered in part prints PENDING
# when its delivered part passes, and FAIL when it does not.
#
# Exit status: 0 every row passed; 1 a row failed; 3 no row failed but at
# least one is pending. Phase A is complete when --check exits 0.
#
# --check runs every row: the package's tests, the delivery reconciler's in
# ./pkg/keystore/deliver/ (named deliver:<Test> below), and for the CLI rows
# (G7, G10, G16 to G19, G21) the keys verbs' tests in ./cmd/k3sm/, named
# cmd:<Test>. --rewrap runs only Rewrap's rows, G3, G12, G13, G14 and U5, and
# only their tests; --delivery runs only the delivery rows, G18, G19 and G20,
# and only their tests; both with the same exit status. None calls sudo.
#
# KEYSTORE_SKIP_G22=1 prints G22 as SKIP instead of running hack/ci.sh, for a
# caller that runs the repo gate itself; a skipped row is neither a pass nor
# pending.
#
# --root runs row R1 alone: the package's tests as root, in the deployment's
# shape (root runs the verbs and owns the data root, the service user owns the
# store; the tests take the service user from K3SM_KEYSTORE_TEST_UID and
# K3SM_KEYSTORE_TEST_GID, or the local user _k3sm). It builds the test binary
# as the invoking user and runs only that binary under sudo -n. It passes when
# no test failed and the binary exited 0. Exit status: 0 pass; 1 fail; 3 sudo
# -n is unavailable (run sudo -v first, or run as a user sudo lets run it).
#
# G1 diffs go.mod and go.sum against KEYSTORE_BASE (default: the merge base
# with origin/main).
#
# Usage: hack/acceptance/keystore.sh --check|--rewrap|--delivery|--root
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

usage() { echo "usage: $0 --check|--rewrap|--delivery|--root" >&2; exit 2; }
[ $# -eq 1 ] || usage
case "$1" in
--check) mode=check ;;
--rewrap) mode=rewrap ;;
--delivery) mode=delivery ;;
--root) mode=root ;;
*) usage ;;
esac

cd "$K3SM_ROOT"
export CGO_ENABLED=1

# run_root is --root: row R1. Only the test binary runs under sudo; the build,
# the counting and the cleanup run as the invoking user. It is called where set
# -e does not apply, so every step checks its own status.
root_tmp=""
run_root() {
	local t out rc=0 n m f
	t="$(mktemp -d "${TMPDIR:-/tmp}/keystore-root.XXXXXX")" || { echo "R1 FAIL as root: mktemp -d failed"; return 1; }
	root_tmp="$t"
	# The store refuses an unclean DataRoot, and macOS's TMPDIR ends in a
	# slash, so the tests' temp dirs are under the canonical path.
	t="$(cd "$t" && pwd -P)" || { echo "R1 FAIL as root: cannot resolve $root_tmp"; return 1; }
	trap 'rm -rf "$root_tmp" 2>/dev/null || echo "keystore: could not remove $root_tmp (a root-owned leftover)" >&2' EXIT
	if ! out="$(go test -race -c -o "$t/keystore.test" ./pkg/keystore/ 2>&1)"; then
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
	local ids=()
	if [ -n "${K3SM_KEYSTORE_TEST_UID+set}" ]; then ids+=("K3SM_KEYSTORE_TEST_UID=$K3SM_KEYSTORE_TEST_UID"); fi
	if [ -n "${K3SM_KEYSTORE_TEST_GID+set}" ]; then ids+=("K3SM_KEYSTORE_TEST_GID=$K3SM_KEYSTORE_TEST_GID"); fi
	out="$(cd "$t" && sudo -n env TMPDIR="$t/tmp" ${ids[@]+"${ids[@]}"} ./keystore.test -test.count=1 -test.v 2>&1)" || rc=$?
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
if [ "$mode" = root ]; then
	rc=0
	run_root || rc=$?
	exit "$rc"
fi

# The tests Rewrap's rows name; --rewrap runs only these.
rewrap_tests="TestSealNonceIsFresh TestRewrapChangesEveryNonce TestRewrapCrashAtEveryStep TestRewrapMasterRenameCompleted"
rewrap_tests="$rewrap_tests TestLockBoundedWait TestLockExcludes TestConcurrentOperations TestFIFORefused TestReadDirNamesBound"
rewrap_tests="$rewrap_tests TestRewrapRefusesWhileUserScopesExist"
rewrap_tests="$rewrap_tests TestRewrapKeyReuse TestRewrapRefusesStalePointer TestRewrapVerifiesCommit TestRewrapGuards"
rewrap_tests="$rewrap_tests TestRewrapRefusesLiveMasterFirst TestRewrapUserScopesBeforeSwap TestRewrapRecoversReplacedNext"
rewrap_tests="$rewrap_tests TestRewrapRemovesStaleNew TestRewrapOverFullFloor TestRewrapCommitChecksMetadata TestRewrapUserScopesUnderLock"
rewrap_tests="$rewrap_tests TestFinishSwapLeavesUnmatchedFingerprint"
rewrap_tests="$rewrap_tests TestInterruptedRewrap TestRecordsSealedUnder TestRewrapNotStarted"

# wanted reports whether row $1 runs in this mode.
wanted() {
	[ "$mode" = check ] && return 0
	if [ "$mode" = delivery ]; then
		case "$1" in G18 | G19 | G20) return 0 ;; esac
		return 1
	fi
	case "$1" in G3 | G12 | G13 | G14 | U5) return 0 ;; esac
	return 1
}

failed=0
pending=0
row() { printf '%-4s %-8s %s\n' "$1" "$2" "$3"; }
pass() { row "$1" PASS "$2"; }
fail() { row "$1" FAIL "$2"; failed=$((failed + 1)); }
pend() { wanted "$1" || return 0; row "$1" PENDING "$2"; pending=$((pending + 1)); }
skip() { row "$1" SKIP "$2"; }

# One run of the package's tests (under --rewrap, of Rewrap's tests only),
# under -race, verbose so each named test can be checked: a test that does not
# run is not a pass.
# --delivery names no package test, so it only builds the package's.
run=()
if [ "$mode" = rewrap ]; then run=(-run "^($(tr ' ' '|' <<<"$rewrap_tests"))\$"); fi
if [ "$mode" = delivery ]; then run=(-run '^$'); fi
out="$(go test -race -count=1 -v ${run[@]+"${run[@]}"} ./pkg/keystore/ 2>&1)" && pkg_ok=1 || pkg_ok=0
# The keys verbs' tests, which only the CLI rows name, so --rewrap skips them
# and --delivery runs only the deliver verbs' and the server flag's.
cmd_out=""
cmd_ok=0
cmd_run=""
case "$mode" in
check) cmd_run='^TestKeys' ;;
delivery) cmd_run='^TestKeysDeliver' ;;
esac
if [ -n "$cmd_run" ]; then
	cmd_out="$(go test -race -count=1 -v -run "$cmd_run" ./cmd/k3sm/ 2>&1)" && cmd_ok=1 || cmd_ok=0
fi
# The delivery reconciler's tests, which only the delivery rows name.
del_out=""
del_ok=0
if [ "$mode" = check ] || [ "$mode" = delivery ]; then
	del_out="$(go test -race -count=1 -v ./pkg/keystore/deliver/ 2>&1)" && del_ok=1 || del_ok=0
fi
# ran passes when every named test ran and passed: a cmd:<Test> in the keys
# verbs' run and a deliver:<Test> in the reconciler's, each run having itself
# passed, any other in the package's run.
ran() {
	local t
	for t in "$@"; do
		case "$t" in
		cmd:*)
			[ "$cmd_ok" = 1 ] || return 1
			grep -q -- "--- PASS: ${t#cmd:} " <<<"$cmd_out" || return 1
			;;
		deliver:*)
			[ "$del_ok" = 1 ] || return 1
			grep -q -- "--- PASS: ${t#deliver:} " <<<"$del_out" || return 1
			;;
		*) grep -q -- "--- PASS: $t " <<<"$out" || return 1 ;;
		esac
	done
}
check() { # row, description, tests...
	local id="$1" desc="$2"
	shift 2
	wanted "$id" || return 0
	if [ "$pkg_ok" = 1 ] && ran "$@"; then pass "$id" "$desc"; else fail "$id" "$desc"; fi
}
partial() { # row, description of the delivered part, of the pending part, tests...
	local id="$1" done_desc="$2" todo="$3"
	shift 3
	wanted "$id" || return 0
	if [ "$pkg_ok" = 1 ] && ran "$@"; then
		pend "$id" "$done_desc: checked; pending: $todo"
	else
		fail "$id" "$done_desc: failed; pending: $todo"
	fi
}

# A failing merge-base must not end the run under set -e, so its status is
# discarded and an empty base is the failure; a base that is not a commit is
# the same failure, never a diff that reads as a change.
if wanted G1; then
	base="${KEYSTORE_BASE:-}"
	if [ -z "$base" ]; then base="$(git merge-base HEAD origin/main 2>/dev/null || true)"; fi
	if [ -z "$base" ] || ! git rev-parse -q --verify "$base^{commit}" >/dev/null 2>&1; then
		fail G1 "no base to diff go.mod and go.sum against: fetch origin/main or set KEYSTORE_BASE to a commit"
	elif git diff --quiet "$base" -- go.mod go.sum; then
		pass G1 "go.mod and go.sum unchanged since $(git rev-parse --short "$base")"
	else
		fail G1 "go.mod or go.sum changed since $(git rev-parse --short "$base")"
	fi
fi
check G2 "AAD is length-prefixed and binds format, scope, kind, name, version, generation" \
	TestAADLayout TestAADBindsEveryField TestRecordMovedBetweenEntries TestScopeBindsRecords
check G3 "every seal draws a fresh nonce, Rewrap included, which changes every nonce" TestSealNonceIsFresh TestRewrapChangesEveryNonce
check G4 "Delete then Put does not reopen the old v1" TestDeleteThenPutRefusesReplayedRecord
check G5 "a copied-back current is refused against the floor, with its own message; nothing recorded for the name accepts it" \
	TestFloorRefusesCopiedBackPointer TestFloorCheck
check G6 "the floor and the data root are root-owned and not shared, judged on the descriptor; the floor is the system scope's, parsed strictly; a caller that cannot write it changes nothing; no non-test file sets the floor's owner" \
	TestFloorTrust TestFloorScope FuzzParseFloor TestFloorNotWritableChangesNothing TestFloorOwnerUnsetOutsideTests
check G7 "the floor is raised by Put, Rotate, RaiseFloor and Delete when the master opens, and by list and show before they read; one behind is accepted; each write re-reads it under the data-root lock, with a bounded wait" \
	TestFloorRaised TestFloorWriteRereads TestFloorLockBoundedWait cmd:TestKeysReadVerbsRaiseFloor
check G8 "Rotate flips the pointer last; a crash before the flip leaves the old version current" \
	TestRotateCrashAtEveryStep TestRotate
check G9 "a Rotate retry discards the orphan and seals the value it was given" TestRotateRetryDiscardsOrphan TestParseVersionName
check G10 "the master is minted only by the first put, never over entries; rewrap --key-in accepts only a key an interrupted rewrap recorded or sealed records under" \
	TestMasterMint TestMintCountsReservedUserName cmd:TestKeysRewrapKeyInRecoveryOnly cmd:TestKeysRewrapKeyInRecoversReplacedNext
check G11 "the master is judged on the open descriptor" TestMasterTrust
check G12 "Rewrap resumes after a crash at every step, old key then new, nothing unreadable; a bad master.next is discarded only with no .new file" \
	TestRewrapCrashAtEveryStep TestRewrapKeyReuse TestRewrapRefusesStalePointer TestRewrapVerifiesCommit TestRewrapGuards \
	TestRewrapRefusesLiveMasterFirst TestRewrapUserScopesBeforeSwap TestRewrapRecoversReplacedNext \
	TestRewrapRemovesStaleNew TestRewrapOverFullFloor TestRewrapCommitChecksMetadata TestRewrapUserScopesUnderLock \
	TestInterruptedRewrap TestRecordsSealedUnder TestRewrapNotStarted
check G13 "a crash between the master renames leaves a trusted master, and the next verb completes the swap" \
	TestRewrapMasterRenameCompleted TestFinishSwapLeavesUnmatchedFingerprint
check G14 "one lock with a bounded wait serializes Rewrap, Rotate, Put, Delete and the reads, and no read blocks" \
	TestLockBoundedWait TestLockExcludes TestConcurrentOperations TestFIFORefused TestReadDirNamesBound
check G15 "files a root verb writes are the service user's, at the layout's modes, inside the store" \
	TestOwnership TestCredSymlinkRefused TestRefusesSymlinks TestMkdirRefusesSwappedDirectory \
	TestCreateEntryRefusesSwappedDirectory TestConfigRefused
check G16 "List marks an unreadable entry with Err, and Delete still removes it; an entry directory with no current is an interrupted put only in the shape a crashed Put leaves and with its generation not in the floor, and Delete removes it too; list exits 1 on a corrupt entry" \
	cmd:TestKeysListCorruptExitsOne cmd:TestKeysRmCorruptEntry TestListMarksCorruptEntry TestDeleteCorruptEntry TestEntryWithNoPointer TestCommittedBeforeDecodesGeneration \
	TestDeletePlantedNonDirectory TestDeleteDirectoryAtCurrent TestPointerVersionBound TestPutCrashAtEveryStep \
	TestMkdirSyncsParent
check G17 "show prints a value only with --reveal, byte-exact for an opaque value and 32- and 64-byte Ed25519 values; no verb takes a value as an argument" \
	cmd:TestKeysShowRevealByteExact cmd:TestKeysShowMetadataOnly cmd:TestKeysRefusals
check G18 "delivery is refused while encryption is off, before any apiserver call, logged once per target; the server's override flag allows it; a target delivered under the override stays when it is removed; deliver prints the refusal" \
	deliver:TestDeliveryRefusedWhileEncryptionOff deliver:TestDeliveryOverrideAllowsPlaintext deliver:TestDeliveredTargetStaysWhenOverrideRemoved \
	cmd:TestKeysDeliveryServerFlag cmd:TestKeysDeliveryServerConfig cmd:TestKeysDeliverEncryptionOffNote \
	cmd:TestKeysDeliveryServerGate
check G19 "the delivery declaration is root-owned and not group- or other-writable, opened O_NOFOLLOW and judged on the descriptor, size- and count-capped and parsed strictly; anything else is refused whole, by the reconciler and by the verbs; the verbs serialize on a root-owned lock file judged the same way" \
	deliver:TestDeclarationRootOwned deliver:TestDeclarationOpenedWithNoFollow cmd:TestKeysDeliverRefusals \
	deliver:TestLockRefusesUntrustedFile deliver:TestLockBoundedWait cmd:TestKeysDeliverWritersSerialize \
	deliver:TestNewDefaultsBindRoot cmd:TestKeysEnvDefaultsBindRoot
check G20 "the reconciler only gets, creates and updates the Opaque Secrets it created, proven by the UID it recorded, not the label: an unlabelled, foreign, pre-created or recreated Secret is untouched, and no list or delete is ever made; rm of a declared entry warns that its Secret keeps the value; no stored value reaches the log or the verbs' output" \
	deliver:TestReconcilerTouchesOnlyLabelledSecrets deliver:TestReconcilerRedeliversOnRotation \
	deliver:TestReconcilerSkipsLabelledNonOpaque deliver:TestReconcilerContinuesAfterTargetFailure \
	deliver:TestReconcilerRedeliversAfterRmPut deliver:TestReconcilerReappliesChangedDataKey \
	deliver:TestReconcilerNeverWritesTenantPrecreated deliver:TestReconcilerDoesNotAdoptRecreated \
	deliver:TestReconcilerRecordsCreatedUID deliver:TestReconcilerReappliesDrift deliver:TestReconcilerImmutableOwned \
	cmd:TestKeysRmWarnsDeclared deliver:TestReconcilerLogsNoValue cmd:TestKeysDeliveryPrintsNoValue
check G21 "the rollback recipe is a byte-exact round trip: show --reveal into rotate --in -, the new version compared with version N byte for byte (bytes.Equal, as cmp), opaque and Ed25519" \
	cmd:TestKeysRollbackRoundTrip
# hack/ci.sh does not run this script, so G22 cannot recurse into it.
if wanted G22 && [ "${KEYSTORE_SKIP_G22:-}" = 1 ]; then
	skip G22 "KEYSTORE_SKIP_G22=1: hack/ci.sh not run here"
elif wanted G22; then
	if hack/ci.sh >/dev/null 2>&1; then pass G22 "hack/ci.sh is green"; else fail G22 "hack/ci.sh is not green (rerun it for the reason)"; fi
fi
check U5 "Rewrap refuses with ErrScopeUnsupported, writing nothing, while .user exists as a directory, a file or a symlink" \
	TestRewrapRefusesWhileUserScopesExist

if [ "$pkg_ok" != 1 ]; then
	printf '%s\n' "$out" | grep -E -- '^(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
fi
if [ -n "$cmd_run" ] && [ "$cmd_ok" != 1 ]; then
	printf '%s\n' "$cmd_out" | grep -E -- '^(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
fi
if [ -n "$del_out" ] && [ "$del_ok" != 1 ]; then
	printf '%s\n' "$del_out" | grep -E -- '^(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
fi
if [ "$failed" -gt 0 ]; then echo "keystore: FAIL ($failed failed, $pending pending)"; exit 1; fi
if [ "$pending" -gt 0 ]; then echo "keystore: PENDING ($pending pending, none failed)"; exit 3; fi
echo "keystore: PASS"
