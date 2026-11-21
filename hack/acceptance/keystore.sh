#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The keystore's acceptance gate: docs/design/keystore.md § "Acceptance gate",
# rows G1 to G22, the user-scope rows U1 to U45 (U15 and U39 are unused) and
# the rig legs E1 to E20. Every row is listed, on exactly one line. A row runs
# the tests that deliver it and passes only if each named test ran and passed
# in its own package; a row whose change has not landed yet prints PENDING,
# never PASS. A row delivered in part prints PENDING when its delivered part
# passes, and FAIL when it does not.
#
# A row names its tests as <repo>/<package>::<Test>, a bare name taking the
# package before it (the first defaults to k3sm/pkg/keystore). The repo is k3sm
# itself or a sibling checkout beside it: ../apis, ../runtimed, ../darwin-net.
# Each package runs once, under -race, verbose; a named test counts only if its
# "--- PASS:" line appears in that package's output. A sibling runs through the
# go.work beside the k3sm root when that file exists; k3sm runs as it is. A
# sibling that is not checked out fails its rows, never skips them.
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
#   --sandbox       the pod denies: U16, U17.
#   --api           the KeyDelivery API types: U18, U19.
#   --scope         user scopes: U6 to U11.
#   --scope-store   the user-scope store: U12 to U14.
#   --files         the append-only files: U20 to U25.
#   --socket        the socket listener: U17, U26 to U31.
#   --socket-ops    the socket operations: U32 to U35, U45.
#   --exec          the non-root CLI and exec: U36 to U38.
#   --kd-author     KeyDelivery authoring: U40, U41.
#   --kd-reconcile  the KeyDelivery reconciler: U42, U43.
#   --kd-lifecycle  the KeyDelivery lifecycle: U44.
#   --docs          the user docs: no row yet, so it exits 3.
# A unit mode runs only its rows and only their tests, with the same exit
# status: it exits 0 only when every row it names passes.
#
# --lab runs the rig legs E1 to E20, and nothing else, as an explicit, recorded
# step. It refuses (exit 2) unless K3SM_LAB=1 and K3SM_LAB_EVIDENCE names an
# existing directory. It writes a record file into that directory: the date,
# the head sha, the evidence directory and each leg's verdict. A leg with no
# implementation is PENDING.
#
# --listed is a row-presence lint, not proof. It checks that every U and E row
# in EXPECTED_ROWS below exists here, and that every test a row names is a func
# in its package's _test.go files, by grep. A test that does not exist yet is
# MISSING (pending row), which is not a failure while its row is pending; it
# fails a row that is checked. Exit status: 0 every row present; 1 otherwise.
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
# with origin/main). KEYSTORE_SKIP_G22=1 marks G22 PENDING instead of running
# hack/ci.sh, for a run inside a sandbox that cannot run it.
#
# Usage: hack/acceptance/keystore.sh --check|--<unit mode>|--lab|--listed|--root
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

# The U and E rows the design's gate table lists; --listed checks each is here.
# The design doc is the human reference; this list is what the lint reads.
EXPECTED_ROWS="U1 U2 U3 U4 U5 U6 U7 U8 U9 U10 U11 U12 U13 U14 U16 U17 U18 U19 U20"
EXPECTED_ROWS="$EXPECTED_ROWS U21 U22 U23 U24 U25 U26 U27 U28 U29 U30 U31 U32 U33 U34 U35"
EXPECTED_ROWS="$EXPECTED_ROWS U36 U37 U38 U40 U41 U42 U43 U44 U45"
EXPECTED_ROWS="$EXPECTED_ROWS E1 E2 E3 E4 E5 E6 E7 E8 E9 E10 E11 E12 E13 E14 E15 E16 E17 E18 E19 E20"

MODES="check rewrap verbs delivery sandbox api scope scope-store files socket socket-ops exec"
MODES="$MODES kd-author kd-reconcile kd-lifecycle docs lab listed root"

usage() {
	echo "usage: $0 --check|--rewrap|--verbs|--delivery|--sandbox|--api|--scope|--scope-store|--files|--socket|--socket-ops|--exec|--kd-author|--kd-reconcile|--kd-lifecycle|--docs|--lab|--listed|--root" >&2
	exit 2
}
[ $# -eq 1 ] || usage
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
	sandbox) echo "U16 U17" ;;
	api) echo "U18 U19" ;;
	scope) echo "U6 U7 U8 U9 U10 U11" ;;
	scope-store) echo "U12 U13 U14" ;;
	files) echo "U20 U21 U22 U23 U24 U25" ;;
	socket) echo "U17 U26 U27 U28 U29 U30 U31" ;;
	socket-ops) echo "U32 U33 U34 U35 U45" ;;
	exec) echo "U36 U37 U38" ;;
	kd-author) echo "U40 U41" ;;
	kd-reconcile) echo "U42 U43" ;;
	kd-lifecycle) echo "U44" ;;
	*) echo "" ;;
	esac
}

if [ "$mode" = lab ]; then
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
leg() { add leg "$1" "$2" ""; }                                                  # rig leg, description
special() { add "$1" "$2" "" ""; }                                               # G1 or G22, judged inline

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
check U2 "AAD scope: a record moved between scopes, or between two users, fails to open" \
	TestScopeBindsRecords TestDerivedKeysDifferByScope
check U3 "KDF labels take the scope; checkScope accepts only system and user/<decimal uid>; kinds 0xFE and 0xFD are reserved" \
	TestDerivedKeysDifferByScope TestCheckScope TestParseRecordRefusesMalformed
check U4 "the first-Put mint refuses with .user present and the master missing" \
	TestMintCountsReservedUserName
check U5 "Rewrap refuses with ErrScopeUnsupported, writing nothing, while .user exists as a directory, a file or a symlink" \
	TestRewrapRefusesWhileUserScopesExist
pend U6 "scope.key is sealed under W, bound to the GeneratedUID; a mismatch is ErrScopeOwnerChanged (user scopes)" \
	TestScopeKeyGeneratedUIDMismatch
pend U7 "the GeneratedUID lookup past its deadline or in error fails closed; mbr_uid_to_uuid is in the symbol canary (user scopes)" \
	TestGeneratedUIDLookupDeadlineFailsClosed k3sm/internal/hostacl::TestMbrUIDToUUIDSymbolCanary
pend U8 "a scope's records open only under its K_u; a copied .user/<uid>/ without the master opens nothing (user scopes)" \
	TestScopeCopyWithoutMasterOpensNothing
pend U9 "per-scope fingerprints differ for equal values in two scopes (user scopes)" \
	TestFingerprintsDifferAcrossScopes
pend U10 "user/<other>/... is ErrNotFound, same text as an absent entry; a short name resolves to the uid and is printed (user scopes)" \
	TestOtherUserIsNotFound TestShortNameResolvesToUID
pend U11 "the Go resolver passes the shared entry-grammar vectors; pkg/keystore imports no Kubernetes package (user scopes)" \
	TestEntryGrammarVectorsResolver TestKeystoreIsKubernetesFree
pend U12 "master Rewrap re-wraps every scope.key and leaves user records byte-identical; resumable at every step, by fault injection as G12 (user-scope store)" \
	TestRewrapRewrapsScopeKeysResumable
pend U13 "quotas: the 257th entry and the byte budget answer ErrQuota; rm still works (user-scope store)" \
	TestUserScopeQuota
pend U14 "the delivery record stores UID and target digest; add, look up and withdraw round-trip under the floor (user-scope store)" \
	TestDeliveryRecordDigestRoundTrip
pend U16 "every pod profile variant (native, vm, container-vm, xcode, expose-paths, a custom pod root distinct from the data root) denies every keystore path, each deny after every allow; rig leg E10 (sandbox denies)" \
	runtimed/pkg/sandbox::TestDataRootDeniesKeystorePathsEveryProfile
pend U17 "runtimed refuses a pod process uid >= 501 (or proves no path to one); baseSocketDenies derives keys.sock from runtimed's names (sandbox denies; socket listener)" \
	runtimed/pkg/supervisor::TestSpawnRefusesLoginRangeUID k3sm/pkg/provider::TestBaseSocketDeniesKeystoreSocket
pend U18 "CRD: entry, secretName, dataKey, requestedBy immutable by CEL transition rules; status subresource on; reasons listed (KeyDelivery API)" \
	apis/config/crd::TestKeyDeliveryCRDMatchesTheGoTypes TestKeyDeliveryImmutableFields
pend U19 "the CRD pattern passes the shared entry-grammar vectors (KeyDelivery API)" \
	apis/config/crd::TestEntryGrammarVectors
pend U20 "a user-scope current copied back is refused against the floor log, with Phase A's floor message; rig leg E9 (append-only files)" \
	TestUserFloorRefusesCopiedBackCurrent
pend U21 "install creates both logs service-user-owned 0600 and flagged; the listener refuses to start when a flag is clear; rig leg E1 (append-only files)" \
	k3sm/pkg/install::TestKeystoreAppendOnlyFilesAtInstall k3sm/pkg/keystore::TestFlagCheckRefusesUnflagged
pend U22 "floor --rebuild and audit --rotate stop the listener, hold the lock, flag the new file before touching the old; a crash at each step leaves a flagged file; rig leg E17 (append-only files)" \
	k3sm/cmd/k3sm::TestKeysFloorRebuildCrashOrder TestKeysAuditRotateCrashOrder
pend U23 "every audited operation writes one v:1 line; no line carries a value or its length; readers ignore unknown fields (append-only files)" \
	TestAuditLineNeverCarriesValue TestAuditReaderIgnoresUnknownFields
pend U24 "soft cap shows in doctor; past the hard cap every mutating user op is ErrLogFull (append-only files)" \
	TestLogHardCapRefusesMutations
pend U25 "backup and restore round trip: a restored tree with cleared flags is refused until floor --rebuild, then opens; rig leg E17 (append-only files)" \
	TestBackupRestoreRoundTripRebuild
pend U26 "peers uid 0, the service uid and uid < 501 are refused before any frame is read (socket listener)" \
	k3sm/pkg/keystore/socket::TestPeerEligibility
pend U27 "framing: an oversize frame, unknown type or missing HELLO closes; an unknown header field is ignored; HELLO picks the highest common version (socket listener)" \
	k3sm/pkg/keystore/socket::FuzzFrameReader TestFramingBounds TestUnknownHeaderFieldsIgnored TestHelloVersionRange
pend U28 "16 connections in all, 2 per uid; a request past 10 s is cut (socket listener)" \
	k3sm/pkg/keystore/socket::TestConnectionCapsPerUID TestRequestTimeout
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
pend U40 "the VAP stamps requestedBy and refuses a ServiceAccount creator; its CEL passes the shared grammar vectors (KeyDelivery authoring)" \
	k3sm/pkg/policy::TestKeyDeliveryPolicyStampsRequestedBy TestEntryGrammarVectorsCEL
pend U41 "deliver creates impersonating only k3sm:local:<uid> and k3sm:local-users, refusing any other impersonation; it writes the UID and digest; withdraw deletes the object; undeliver prints the hint (KeyDelivery authoring)" \
	k3sm/pkg/keystore/socket::TestDeliverImpersonatesUIDPrincipalOnly TestDeliverWritesDigestRecord \
	k3sm/cmd/k3sm::TestUndeliverPrintsRotationHint
pend U42 "an unrecorded UID, a digest mismatch, or a failed name-scoped SAR (create keydeliveries; create, update, delete secrets with resourceNames) gets no Secret; encryption off refuses, G18 for KeyDelivery (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestUnrecordedOrRetargetedDeliveryGetsNoSecret TestSARsAreNameScopedAndIncludeDelete \
	TestEncryptionOffRefusesKeyDelivery
pend U43 "reasons are the closed set; absent and not yours both read EntryUnavailable; a pre-existing unlabelled Secret is SecretExists; a second declaration is SecretClaimed; observedGeneration tracks (KeyDelivery reconciler)" \
	k3sm/pkg/keystore/reconcile::TestConditionReasonsClosedSet TestOneDeclarationPerSecret
pend U44 "losing authority deletes exactly the owned Secret; the crash order is Secret, record, finalizer at every interruption point; the orphan sweep removes labelled, owner-annotated Secrets with no live object and never an unlabelled or foreign one (KeyDelivery lifecycle)" \
	k3sm/pkg/keystore/reconcile::TestLostAuthorityDeletesOnlyOwnedSecret TestFinalizerCrashOrder TestOrphanSweep
pend U45 "cross-user refusal with a fake peer-credential seam: a peer with uid B asks for list, read-for-exec, rotate, rm and deliver of uid A's entries, and for any system/... name; every call is ErrNotFound with text identical to an absent entry of B's own, and the refused audit lines carry uid B (socket operations)" \
	k3sm/pkg/keystore/socket::TestCrossUserRefusedFakePeerCred TestNonRootCannotNameSystemEntries

leg E1 "preconditions: secrets encryption on; one server; keystore-run/ and both logs present, service-user 0600, SF_APPEND set; the doctor user-scope row on; keystore.sh --check exits 0 on the build"
leg E2 "the user, no sudo, puts user/<me>/e2e-token (short-name form): exit 0; the CLI prints the resolved user/<uid>; k3sm keys list shows it; the audit log has a put line with no value"
leg E3 "an admin binds k3sm:keystore-delivery-author for k3sm:local:<uid> in ks-e2e and the user delivers the entry to Secret e2e-token: KeyDelivery Ready, reason Delivered, observedGeneration current; requestedBy is k3sm:local:<uid>; a pod mounting the Secret reads exactly the stored bytes"
leg E4 "the user rotates (rotate --in -), then rotate --from-version 1: the pod's mounted file moves to v2, then to v1's bytes as v3, within one sweep each"
leg E5 "k3sm keys exec user/<uid>/e2e-token --env TOKEN -- /usr/bin/env: the child sees TOKEN; the CLI wrote nothing else; ps during the run shows no value in argv; one exec-read audit line"
leg E6 "as the one login user: list, exec, rotate, rm and deliver of an unused other uid's entry and of system/e2e-sys, then a connect as root and as the service user: not found each time, text identical to an absent entry of the user's own, refused audit lines carry the user's uid; root and the service user are refused at accept"
leg E7 "an admin copies E3's KeyDelivery into ks-e2e-2, where the user also has the role: Authorized=False, reason NotRecorded, no Secret"
leg E8 "an admin strips the CRD's transition rules (restored at the end) and edits E3's spec.secretName: Authorized=False, NotRecorded (digest mismatch); the original Secret deleted; no Secret under the new name"
leg E9 "sudo cp saves current, the user rotates, sudo cp puts the old current back, then the same for a system/ entry: both lists mark the entry corrupt with the floor message"
leg E10 "a pod pinned to the darwin node tries connect(2) to keys.sock and to read server/keystore, keystore-run/, both logs and Phase A's two files: EPERM for each"
leg E11 "an admin removes the user's RoleBinding in ks-e2e: within one sweep the Secret is deleted; Authorized=False, NotAuthorized"
leg E12 "root puts and delivers system/e2e-sys; then the user, with no sudo, tries deliver, list and exec on it: root's Secret is delivered and stays; each of the user's attempts answers not found and nothing reaches ks-e2e-2"
leg E13 "a ServiceAccount token creates a KeyDelivery: refused at admission"
leg E14 "k3sm keys undeliver on E3's object, then kubectl delete of a second one: each Secret deleted before its object goes; the hint printed; no orphan Secret after one sweep"
leg E15 "upgrade from the previous release's install tree, then sudo k3sm install: system scope intact; user scope comes on after the install, off with the Warn and doctor row before it"
leg E16 "rollback to the previous release, then forward again: the old build runs with the keystore files unused; after rolling forward the user's entries, records and Secrets are intact and re-adopted"
leg E17 "backup and restore round trip with cp, then floor --rebuild and audit --rotate: before the rebuild the listener refuses (flags clear); after it every entry opens and both logs are flagged"
leg E18 "an old worker on the previous release joins this server: worker Ready; pods there mount delivered Secrets; no keystore listener or reconciler on the worker"
leg E19 "launchctl kickstart -k of the server while a client is connected mid-request: a clean error, not a hang; the listener back within its backoff; kine and the apiserver back; no partial record"
leg E20 "reboot of the server node, operator-attended (--attended reboot): after boot the flags are still set, the listener starts, E2's entry opens, E3's Secret is still current"

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

failed=0
pending=0
row() { printf '%-4s %-8s %s\n' "$1" "$2" "$3"; }
pass() { row "$1" PASS "$2"; }
fail() { row "$1" FAIL "$2"; failed=$((failed + 1)); }
pending_row() { row "$1" PENDING "$2"; pending=$((pending + 1)); }

# --listed: the row-presence lint.
if [ "$mode" = listed ]; then
	echo "keystore --listed: a row-presence lint, not proof: no test runs"
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
		for spec in ${R_TESTS[$i]}; do
			pkg="${spec%%::*}" t="${spec#*::}"
			dir="$(repo_dir "$pkg")/$(pkg_rel "$pkg")"
			if [ -d "$dir" ] && grep -q -E "^func $t\(" "$dir"*_test.go 2>/dev/null; then
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
			row "$id" LISTED "$found named test(s) found"
		elif [ "${R_KIND[$i]}" = pend ]; then
			row "$id" "MISSING (pending row)" "${missing# }"
		else
			fail "$id" "named test(s) not found:$missing"
		fi
		i=$((i + 1))
	done
	if [ "$failed" -gt 0 ]; then echo "keystore --listed: FAIL ($failed) (not proof)"; exit 1; fi
	echo "keystore --listed: every row present (not proof)"
	exit 0
fi

# wanted reports whether row $1 runs in this mode.
wanted() {
	case "$mode" in
	check) return 0 ;;
	lab) case "$1" in E*) return 0 ;; esac; return 1 ;;
	esac
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

work=""
if [ -f "$(dirname "$K3SM_ROOT")/go.work" ]; then work="$(dirname "$K3SM_ROOT")/go.work"; fi
out_dir=""
if [ "${#P_PKG[@]}" -gt 0 ]; then
	out_dir="$(mktemp -d "${TMPDIR:-/tmp}/keystore-gate.XXXXXX")"
	trap 'rm -rf "$out_dir"' EXIT
fi
# One run of each package's tests (under --check, the whole package; under a
# unit mode, the mode's tests only), under -race, verbose so each named test
# can be checked: a test that does not run is not a pass.
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
	elif [ "$dir" = "$K3SM_ROOT" ]; then
		go test -race -count=1 -v ${run[@]+"${run[@]}"} "$(pkg_rel "$pkg")" >"$out_dir/$j.out" 2>&1 || rc=$?
	elif [ -n "$work" ]; then
		(cd "$dir" && GOWORK="$work" go test -race -count=1 -v ${run[@]+"${run[@]}"} "$(pkg_rel "$pkg")") >"$out_dir/$j.out" 2>&1 || rc=$?
	else
		(cd "$dir" && go test -race -count=1 -v ${run[@]+"${run[@]}"} "$(pkg_rel "$pkg")") >"$out_dir/$j.out" 2>&1 || rc=$?
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
	if [ "$mode" != lab ]; then
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

if [ "$mode" = lab ]; then
	record="$K3SM_LAB_EVIDENCE/keystore-lab-$(date -u +%Y%m%dT%H%M%SZ).txt"
	{
		echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "head: $(git rev-parse HEAD)"
		echo "evidence: $K3SM_LAB_EVIDENCE"
		for v in ${lab_verdicts[@]+"${lab_verdicts[@]}"}; do echo "$v"; done
	} >"$record"
	echo "keystore: lab record $record"
fi

if [ "$failed" -gt 0 ]; then echo "keystore: FAIL ($failed failed, $pending pending)"; exit 1; fi
if [ "$pending" -gt 0 ]; then echo "keystore: PENDING ($pending pending, none failed)"; exit 3; fi
echo "keystore: PASS"
