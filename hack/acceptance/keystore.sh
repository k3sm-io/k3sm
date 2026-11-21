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
# --check runs every row. --rewrap runs only Rewrap's rows, G3, G12, G13, G14
# and U5, and only their tests, with the same exit status.
#
# G1 diffs go.mod and go.sum against KEYSTORE_BASE (default: the merge base
# with origin/main).
#
# Usage: hack/acceptance/keystore.sh --check|--rewrap
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

usage() { echo "usage: $0 --check|--rewrap" >&2; exit 2; }
[ $# -eq 1 ] || usage
case "$1" in
--check) mode=check ;;
--rewrap) mode=rewrap ;;
*) usage ;;
esac

cd "$K3SM_ROOT"
export CGO_ENABLED=1

# The tests Rewrap's rows name; --rewrap runs only these.
rewrap_tests="TestSealNonceIsFresh TestRewrapChangesEveryNonce TestRewrapCrashAtEveryStep TestRewrapMasterRenameCompleted"
rewrap_tests="$rewrap_tests TestLockBoundedWait TestLockExcludes TestConcurrentOperations TestFIFORefused TestReadDirNamesBound"
rewrap_tests="$rewrap_tests TestRewrapRefusesWhileUserScopesExist"
rewrap_tests="$rewrap_tests TestRewrapKeyReuse TestRewrapRefusesStalePointer TestRewrapVerifiesCommit TestRewrapGuards"
rewrap_tests="$rewrap_tests TestRewrapRefusesLiveMasterFirst TestRewrapUserScopesBeforeSwap TestRewrapRecoversReplacedNext"

# wanted reports whether row $1 runs in this mode.
wanted() {
	[ "$mode" = check ] && return 0
	case "$1" in G3 | G12 | G13 | G14 | U5) return 0 ;; esac
	return 1
}

failed=0
pending=0
row() { printf '%-4s %-8s %s\n' "$1" "$2" "$3"; }
pass() { row "$1" PASS "$2"; }
fail() { row "$1" FAIL "$2"; failed=$((failed + 1)); }
pend() { wanted "$1" || return 0; row "$1" PENDING "$2"; pending=$((pending + 1)); }

# One run of the package's tests (under --rewrap, of Rewrap's tests only),
# under -race, verbose so each named test can be checked: a test that does not
# run is not a pass.
run=()
if [ "$mode" = rewrap ]; then run=(-run "^($(tr ' ' '|' <<<"$rewrap_tests"))\$"); fi
out="$(go test -race -count=1 -v "${run[@]}" ./pkg/keystore/ 2>&1)" && pkg_ok=1 || pkg_ok=0
ran() {
	local t
	for t in "$@"; do
		grep -q -- "--- PASS: $t " <<<"$out" || return 1
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
	TestRewrapRefusesLiveMasterFirst TestRewrapUserScopesBeforeSwap TestRewrapRecoversReplacedNext
check G13 "a crash between the master renames leaves a trusted master, and the next verb completes the swap" \
	TestRewrapMasterRenameCompleted
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
# hack/ci.sh does not run this script, so G22 cannot recurse into it.
if wanted G22; then
	if hack/ci.sh >/dev/null 2>&1; then pass G22 "hack/ci.sh is green"; else fail G22 "hack/ci.sh is not green (rerun it for the reason)"; fi
fi
check U5 "Rewrap refuses with ErrScopeUnsupported, writing nothing, while .user exists as a directory, a file or a symlink" \
	TestRewrapRefusesWhileUserScopesExist

if [ "$pkg_ok" != 1 ]; then
	printf '%s\n' "$out" | grep -E -- '^(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
fi
if [ "$failed" -gt 0 ]; then echo "keystore: FAIL ($failed failed, $pending pending)"; exit 1; fi
if [ "$pending" -gt 0 ]; then echo "keystore: PENDING ($pending pending, none failed)"; exit 3; fi
echo "keystore: PASS"
