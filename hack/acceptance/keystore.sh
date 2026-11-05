#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The keystore's acceptance gate: docs/design/keystore.md § "Acceptance gate",
# rows G1 to G22. Every row is listed. A row runs the tests that deliver it
# and passes only if each named test ran and passed; a row whose pull request
# has not landed yet prints PENDING, never PASS.
#
# Exit status: 0 every row passed; 1 a row failed; 3 no row failed but at
# least one is pending. Phase A is complete when this exits 0.
#
# G1 diffs go.mod and go.sum against KEYSTORE_BASE (default: the merge base
# with origin/main).
#
# Usage: hack/acceptance/keystore.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1

failed=0
pending=0
row() { printf '%-4s %-8s %s\n' "$1" "$2" "$3"; }
pass() { row "$1" PASS "$2"; }
fail() { row "$1" FAIL "$2"; failed=$((failed + 1)); }
pend() { row "$1" PENDING "$2"; pending=$((pending + 1)); }

# One run of the package's tests, under -race, verbose so each named test can
# be checked: a test that does not run is not a pass.
out="$(go test -race -count=1 -v ./pkg/keystore/ 2>&1)" && pkg_ok=1 || pkg_ok=0
ran() {
	local t
	for t in "$@"; do
		grep -q -- "--- PASS: $t " <<<"$out" || return 1
	done
}
check() { # row, description, tests...
	local id="$1" desc="$2"
	shift 2
	if [ "$pkg_ok" = 1 ] && ran "$@"; then pass "$id" "$desc"; else fail "$id" "$desc"; fi
}

base="${KEYSTORE_BASE:-$(git merge-base HEAD origin/main)}"
if git diff --quiet "$base" -- go.mod go.sum; then
	pass G1 "go.mod and go.sum unchanged since $(git rev-parse --short "$base")"
else
	fail G1 "go.mod or go.sum changed since $(git rev-parse --short "$base")"
fi
check G2 "AAD is length-prefixed and binds format, kind, name, version, generation" \
	TestAADLayout TestAADBindsEveryField TestRecordMovedBetweenEntries
check G3 "every seal draws a fresh nonce (library)" TestSealNonceIsFresh
pend G3 "Rewrap changes every nonce (PR 3: Rewrap)"
check G4 "Delete then Put does not reopen the old v1" TestDeleteThenPutRefusesReplayedRecord
pend G5 "a copied-back current is refused against the floor (PR 2)"
pend G6 "the floor is root-owned and checked on the descriptor (PR 2)"
pend G7 "the floor is raised by every root verb (PR 2)"
pend G8 "Rotate flips the pointer last under fault injection (PR 2)"
pend G9 "a Rotate retry discards the orphan (PR 2)"
check G10 "the master is minted only by the first put, never over entries" TestMasterMint
check G11 "the master is judged on the open descriptor" TestMasterTrust
pend G12 "Rewrap resumes after a crash at every step (PR 3)"
pend G13 "a crash between the master renames is completed (PR 3)"
check G14 "one lock with a bounded wait" TestLockBoundedWait TestConcurrentOperations
check G15 "files a root verb writes are the service user's, at the layout's modes" TestOwnership
check G16 "List marks an unreadable entry with Err (library)" TestListMarksCorruptEntry
pend G16 "list exits 1 on a corrupt entry (PR 4: k3sm keys)"
pend G17 "show prints a value only with --reveal, byte-exact (PR 4)"
pend G18 "delivery refused while encryption is off (PR 5)"
pend G19 "the delivery declaration is root-owned (PR 5)"
pend G20 "the reconciler touches only its labelled Secrets (PR 5)"
pend G21 "the rollback recipe is a byte-exact round trip (PR 4)"
if hack/ci.sh >/dev/null 2>&1; then pass G22 "hack/ci.sh is green"; else fail G22 "hack/ci.sh is not green (rerun it for the reason)"; fi

if [ "$pkg_ok" != 1 ]; then
	printf '%s\n' "$out" | grep -E -- '^(--- FAIL|FAIL|panic:)|_test\.go:[0-9]+:' || true
fi
if [ "$failed" -gt 0 ]; then echo "keystore: FAIL ($failed failed, $pending pending)"; exit 1; fi
if [ "$pending" -gt 0 ]; then echo "keystore: PENDING ($pending pending, none failed)"; exit 3; fi
echo "keystore: PASS"
