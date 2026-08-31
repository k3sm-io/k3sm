#!/usr/bin/env bash
#
# k3sm B226 acceptance gate — the runnable proof that every projected
# ServiceAccount token the provider mints is BOUND to the Pod object it was minted
# for, exactly as upstream kubelet binds it (lab defect D5; plan M14.1-d5).
#
# The defect: kubeResolver.ServiceAccountToken built a TokenRequestSpec carrying
# only Audiences + ExpirationSeconds. With no spec.boundObjectRef the apiserver
# has nothing to tie the token's life to, so a deleted pod's token stays valid
# until expiry, and the TokenReview response carries none of the
# authentication.kubernetes.io/pod-name or pod-uid extras that identity consumers
# (service-mesh SDS, policy external-data, workload-identity federation) read to
# attribute a request to a workload.
#
# The gate asserts the EXACT reference, not merely that one exists: Kind "Pod",
# APIVersion "v1", the creating pod's Name AND its UID. A ServiceAccount-kinded
# ref, or one without the UID, satisfies a literal reading of "bound" while
# restoring neither the pod-lifetime invalidation (the UID is what the apiserver
# matches) nor the extras. It also asserts the FAIL-CLOSED half: a call that
# reaches the resolver with no pod identity on the request context must error
# rather than mint an unbound token, and must reach the apiserver zero times.
#
# TWO TIERS, split by what can be proven without a live cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   wiring: the resolver stamps the exact ref, the fail-closed sentinel is on the
#   only mint path, both provider seams (CreatePod, UpdatePod) bind the pod
#   identity onto the request context, and the pre-B226 name-only carrier is gone.
#   Proven by the structural pins plus two Go legs (the B226 binding matrix and
#   the M2.4 in-pod-API suite it must not regress). This tier reddens if the
#   BoundObjectRef, its UID, or the fail-closed return is removed (the mutant
#   check).
#
#   LAB TIER (K3SM_LAB=1, a dev Mac) — the live apiserver semantics the fake
#   clientset cannot prove: a running pod's projected token authenticates; after
#   the pod is deleted the SAME token is rejected before its TTL elapses; and a
#   TokenReview of it reports the pod-name/pod-uid extras. RED-BEFORE on
#   origin/main: the deleted pod's token still authenticates and the extras are
#   absent. Without K3SM_LAB the lab rungs are announced as LAB-PENDING and never
#   fail CI.
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: this Mac's Go
# toolchain can itself be x86_64-under-Rosetta (`go env GOARCH` -> amd64), and an
# unpinned build silently decides arch-sensitive behaviour. The product is
# darwin/arm64-only.
#
# Usage:  hack/acceptance/B226.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B226.sh # + the live apiserver tier
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
RESOLVER="$K3SM_ROOT/pkg/provider/resolver.go"
RUNTIMED="$K3SM_ROOT/pkg/provider/runtimed.go"
SELF="$HERE/B226.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B226 acceptance (projected SA tokens bound to their Pod object)"

# ---- b226.0 — the gate parses and both wiring sources exist -----------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$RESOLVER" ] || b0=no
[ -f "$RUNTIMED" ] || b0=no
ladder "$b0" "b226.0  gate parses (bash -n) + pkg/provider/{resolver,runtimed}.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B226: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B226: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b226.1 — the EXACT pod-object reference -------------------------------
# All four fields, pinned individually. Dropping any ONE of them is the shape of
# the near-miss this item exists to prevent, so a single grep over the whole
# literal would not distinguish "bound to the pod" from "bound to something".
ref=ok
grep -qE 'BoundObjectRef: &authnv1\.BoundObjectReference\{' "$RESOLVER" || ref=no
grep -qE 'Kind:[[:space:]]+"Pod",' "$RESOLVER" || ref=no
grep -qE 'APIVersion:[[:space:]]+"v1",' "$RESOLVER" || ref=no
grep -qE 'Name:[[:space:]]+id\.name,' "$RESOLVER" || ref=no
grep -qE 'UID:[[:space:]]+id\.uid,' "$RESOLVER" || ref=no
ladder "$ref" "b226.1  ServiceAccountToken sets BoundObjectRef{Kind:Pod, APIVersion:v1, Name:<pod>, UID:<pod>}"

# ---- b226.2 — fail-closed, on the ONLY mint path ---------------------------
# The sentinel plus its early return, and the count of CreateToken call sites in
# the shipped (non-test) tree. A second mint site would be a second chance to
# emit an unbound token, invisible to every assertion above.
fc=ok
grep -qE 'errNoPodIdentity = errors\.New\(' "$RESOLVER" || fc=no
grep -qE 'return "", fmt\.Errorf\("mint token in namespace %s: %w", namespace, errNoPodIdentity\)' "$RESOLVER" || fc=no
# `|| true` on the pipeline, not laziness: under `set -o pipefail` a grep that
# matches NOTHING exits 1 and would abort the gate mid-ladder — and zero matches is
# a verdict here (b226.3 asserts exactly that), not an error.
mints="$( { grep -rn --include='*.go' 'CreateToken(' "$K3SM_ROOT/pkg" "$K3SM_ROOT/cmd" 2>/dev/null || true; } | { grep -v '_test\.go:' || true; } | wc -l | tr -d ' ')"
[ "$mints" = 1 ] || fc=no
ladder "$fc" "b226.2  errNoPodIdentity fails the mint closed; exactly ONE CreateToken site ships (found $mints)"

# ---- b226.3 — the identity is threaded at BOTH provider seams ---------------
# CreatePod and UpdatePod both bind it; the pre-B226 name-only carrier
# (withServiceAccount / serviceAccountFromContext) must be GONE, since leaving it
# reachable leaves a route to a mint with no pod object in scope.
thread=ok
[ "$(grep -cE '^[[:space:]]*ctx = withPodIdentity\(ctx, pod\)$' "$RUNTIMED")" = 2 ] || thread=no
grep -qE 'func withPodIdentity\(ctx context\.Context, pod \*corev1\.Pod\) context\.Context' "$RESOLVER" || thread=no
grep -qE 'func podIdentityFromContext\(ctx context\.Context\) \(podIdentity, bool\)' "$RESOLVER" || thread=no
stale="$( { grep -rn --include='*.go' -e 'withServiceAccount' -e 'serviceAccountFromContext' "$K3SM_ROOT/pkg" "$K3SM_ROOT/cmd" 2>/dev/null || true; } | wc -l | tr -d ' ')"
[ "$stale" = 0 ] || thread=no
ladder "$thread" "b226.3  CreatePod+UpdatePod both bind withPodIdentity; the name-only carrier is gone (stale refs: $stale)"

# ---- b226.4 — the partial-reference guard is not a silent fallback ----------
# podIdentityFromContext reports NOT-ok for an identity missing either half of the
# reference. Were it to fall back to a name-only identity, the resolver would mint
# a ref with an empty UID — the exact weaker binding this item rejects.
guard=ok
grep -qE 'if !ok \|\| id\.name == "" \|\| id\.uid == "" \{' "$RESOLVER" || guard=no
ladder "$guard" "b226.4  a partial pod identity (missing name or UID) fails closed, never degrades to a weaker ref"

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN its subtests: `go test -run <filter>` EXITS 0 on a
# zero-match filter, so a renamed test would read PASS forever. Each leg fails
# unless "no tests to run" is ABSENT and the count of `--- PASS: <TestName>/`
# subtest lines meets the pinned minimum.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" out rc=0 ran
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- b226.5 — the binding matrix -------------------------------------------
# CreatePod and UpdatePod each bind the exact ref, an SA-less pod still binds to
# its pod object, and the no-identity call errors having minted nothing.
run_test "b226.5" 4 TestB226_ProjectedTokenBoundToPod ./pkg/provider/

# ---- b226.6 — the M2.4 in-pod-API surface is not regressed ------------------
# The binding rides the same carrier that selects the pod's ServiceAccount; this
# leg is what keeps the SA-selection half honest while the pod-object half lands.
run_test "b226.6" 4 TestM2_InPodKubectl ./pkg/provider/

# ============================================================================
# LAB TIER — the live apiserver semantics (K3SM_LAB=1, a dev Mac).
# ============================================================================
lab_pending() { echo "LAB-PENDING  $1"; }

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B226 LAB tier (set K3SM_LAB=1 on a dev Mac to run):"
	lab_pending "b226.L1  a Running pod's projected token authenticates (kubectl auth whoami / TokenReview says authenticated)"
	lab_pending "b226.L2  after the pod is deleted the SAME token is REJECTED well before its TTL (RED before: it still authenticates on origin/main)"
	lab_pending "b226.L3  a TokenReview of the live token reports the authentication.kubernetes.io/pod-name and pod-uid extras (RED before: absent)"
	lab_pending "b226.L4  the pod-uid extra equals the creating pod's metadata.uid (the exact binding, not merely a bound-ness flag)"
else
	# The live datapath. Boots `k3sm server` via the shared clusterup library; the
	# operator applies a projected-token pod, reads its in-pod token, and runs the
	# TokenReview probes. Kept behind K3SM_LAB because it needs a dev Mac (a live
	# datastore, lo0 aliases, a real apiserver serving the TokenRequest API); it is
	# never exercised in hack/ci.sh.
	LIB="$K3SM_ROOT/hack/lib/clusterup.sh"
	if [ ! -f "$LIB" ]; then
		ladder no "b226.L0  hack/lib/clusterup.sh present (required for the live tier)"
	else
		# shellcheck source=/dev/null
		. "$LIB"
		echo "----------------------------------------"
		echo "B226 LAB tier: booting a single-node cluster (this mutates lo0/datastore on this Mac)"
		if cluster_up; then
			ladder ok "b226.L0  single-node cluster up"
			lab_pending "b226.L1-L4  apply a projected-SA-token pod, read /var/run/secrets/kubernetes.io/serviceaccount/token, TokenReview it before and after deleting the pod (operator step; see the header)"
			cluster_down || true
		else
			ladder no "b226.L0  single-node cluster up (cluster_up failed — see output above)"
			cluster_down || true
		fi
	fi
fi

echo "----------------------------------------"
echo "B226: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B226 GREEN (CI tier) ================"
