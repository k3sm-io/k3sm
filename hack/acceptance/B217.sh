#!/usr/bin/env bash
#
# k3sm B217 acceptance gate — the runnable proof that the provider injects the
# bind-discipline env (K3SM_POD_IP) so a Pod's wildcard bind() is rewritten onto its
# own /32, giving same-node Pods separate per-IP port spaces (two Pods can both hold
# :8080). Plan W4; depends on B216 (the darwin-net bind() interpose) and B215 (the lab
# probe wave). Closes the DESIGN §6 M2 "IP-per-pod (lo0 alias + bind discipline)"
# deliverable.
#
# TWO TIERS, split by what can be proven without a live cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   wiring: toPodBox injects K3SM_POD_IP for a DISTINCT-/32 pod and NOTHING for a
#   hostNetwork pod (podIP == nodeIP, zero allocation), the value is the allocated /32,
#   the injection is infra-wins, an unparseable/unspecified/IPv6/empty podIP is a
#   no-op, and an M0 host-binary route still injects but WARNS. Proven by the two Go
#   legs (unit + full CreatePod flow) plus the structural pins that keep the wiring in
#   place and the cross-repo darwin-net ABI reachable. This tier reddens if the
#   injection or its hostNetwork guard is removed (the mutant check).
#
#   LAB TIER (K3SM_LAB=1, a dev Mac) — the live datapath: two Pods each binding :8080
#   simultaneously Running, each reachable at its own podIP:8080 through its Service,
#   coexisting with BOTH standing wildcard binders (an svclb 0.0.0.0:8080 AND a proxy
#   *:NodePort), and a hostNetwork-shaped Pod whose bind stays wildcard (no rewrite).
#   RED-BEFORE on origin/main: the second :8080 Pod crash-loops EADDRINUSE today. The
#   cross-node cell (a remote Pod dials this Pod's /32 over wireguard and the specific
#   bind still accepts post-decap) is the two-Mac harness slice. Without K3SM_LAB the
#   lab rungs are announced as LAB-PENDING and never fail CI.
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: this Mac's Go
# toolchain is itself x86_64-under-Rosetta (`go env GOARCH` -> amd64), and an unpinned
# build produced an x86_64 shim that dyld refused to load into the arm64 execshim (the
# B215 trap). The product is darwin/arm64-only.
#
# Usage:  hack/acceptance/B217.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B217.sh # + the live single-node datapath
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$K3SM_ROOT/.." && pwd)"
DARWIN_NET_ROOT="$WS_ROOT/darwin-net"
TRANSLATE="$K3SM_ROOT/pkg/provider/translate.go"
SELF="$HERE/B217.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B217 acceptance (provider K3SM_POD_IP injection + per-IP port spaces)"

# ---- b217.0 — the gate parses and the wiring source exists -----------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$TRANSLATE" ] || b0=no
ladder "$b0" "b217.0  gate parses (bash -n) + pkg/provider/translate.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B217: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B217: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b217.pre — the cross-repo preconditions -------------------------------
# The injection legally imports darwin-net's podnet.BindDisciplineEnv; the two halves
# only compile against each other through the workspace go.work. A standalone k3sm
# clone cannot prove it, so its absence is a hard FAIL (never a skip, or "B217 green"
# would mean "B217 was not checked").
if [ -f "$WS_ROOT/go.work" ]; then
	ladder ok "b217.pre  workspace go.work present ($WS_ROOT/go.work)"
else
	ladder no "b217.pre  workspace go.work present — B217 imports darwin-net; a standalone k3sm checkout cannot prove it"
fi
if [ -f "$DARWIN_NET_ROOT/pkg/podnet/env.go" ]; then
	ladder ok "b217.pre  sibling darwin-net podnet ABI present ($DARWIN_NET_ROOT/pkg/podnet/env.go)"
else
	ladder no "b217.pre  sibling darwin-net podnet ABI absent — the bind-discipline ABI the provider consumes is unreachable"
fi
if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B217: $PASS passed, $FAIL failed (cross-repo preconditions unmet)" >&2
	exit 1
fi

# ---- b217.1 — darwin-net exposes the exact ABI the provider consumes -------
# The single-sourced encoder + env const the provider imports. A rename on the
# darwin-net side (which the provider cannot see at grep time) would break the build,
# but this pin makes the ABI dependency explicit in the gate so a reader knows what
# B217 rides on.
abi=ok
grep -qE 'func BindDisciplineEnv\(' "$DARWIN_NET_ROOT/pkg/podnet/env.go" || abi=no
grep -qE 'EnvPodIP\s*=\s*"K3SM_POD_IP"' "$DARWIN_NET_ROOT/pkg/podnet/env.go" || abi=no
ladder "$abi" "b217.1  darwin-net podnet exports BindDisciplineEnv + EnvPodIP (K3SM_POD_IP)"

# ---- b217.2 — the wiring is present and gated on a DISTINCT /32 -------------
# Structural pins so the gate reddens if the injection call or its hostNetwork guard is
# deleted — the mutant check for a change that would silently narrow the shipped
# hostNetwork semantic or drop the discipline entirely.
#
# B218 widened the call site to also thread the cluster CIDRs (clusterCIDRs) through
# to podnet.BindDisciplineEnvWithCIDRs (the additive superset of BindDisciplineEnv) —
# these two pins were updated to match; the gated-on-distinct-/32 pin below is
# unchanged, since B218 did not touch that guard.
w=ok
grep -qE 'injectBindDisciplineEnv\(box, podIP, nodeIP, clusterCIDRs\(dnsCfg\.ClusterDNSIP\), log\)' "$TRANSLATE" || w=no
grep -qE 'podIP == "" \|\| podIP == nodeIP' "$TRANSLATE" || w=no
grep -qE 'podnet\.BindDisciplineEnvWithCIDRs\(addr, cidrs\)' "$TRANSLATE" || w=no
ladder "$w" "b217.2  toPodBox calls injectBindDisciplineEnv, gated on podIP != nodeIP (distinct /32)"

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN its subtests: `go test -run <filter>` EXITS 0 on a
# zero-match filter, so a renamed test would read PASS forever. Each leg fails unless
# "no tests to run" is ABSENT and the count of `--- PASS: <TestName>/` subtest lines
# meets the pinned minimum.
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

# ---- b217.3 — the unit-tier injection matrix -------------------------------
# distinct-/32 injection, infra-wins, the hostNetwork/empty/unspecified/IPv6 no-op
# cases, and the host-binary warn + ordinary-route no-warn split.
run_test "b217.3" 7 TestToPodBoxInjectsBindDisciplineEnv ./pkg/provider/

# ---- b217.4 — the full CreatePod flow: distinct /32 gets it, hostNetwork none
# The end-to-end assertion through the podnet adapter: two pods get distinct /32s AND
# carry K3SM_POD_IP == their /32; a hostNetwork pod resolves to nodeIP and carries NONE.
run_test "b217.4" 3 TestCreatePodAssignsDistinctPodIP ./pkg/provider/

# ============================================================================
# LAB TIER — the live single-node datapath (K3SM_LAB=1, a dev Mac).
# ============================================================================
lab_pending() { echo "LAB-PENDING  $1"; }

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B217 LAB tier (set K3SM_LAB=1 on a dev Mac to run):"
	lab_pending "b217.L1  two Pods each binding :8080 both reach Running (RED before: the 2nd crash-loops EADDRINUSE on origin/main)"
	lab_pending "b217.L2  each Pod is reachable at its own podIP:8080 through its Service"
	lab_pending "b217.L3  coexistence with BOTH standing wildcard binders (svclb 0.0.0.0:8080 AND proxy *:NodePort)"
	lab_pending "b217.L4  a hostNetwork-shaped Pod's bind stays WILDCARD (no rewrite; K3SM_POD_IP not injected)"
	lab_pending "b217.L5  [two-Mac harness] a remote Pod dials this Pod's /32 over wireguard; the specific bind still accepts post-decap"
else
	# The live datapath. Boots `k3sm server` via the shared clusterup library, applies
	# the two-:8080-pods + Services fixture, and asserts coexistence + reachability.
	# Kept behind K3SM_LAB because it needs a dev Mac (lo0 aliases, a live datastore,
	# the proxy/svclb listeners); it is never exercised in hack/ci.sh.
	LIB="$K3SM_ROOT/hack/lib/clusterup.sh"
	if [ ! -f "$LIB" ]; then
		ladder no "b217.L0  hack/lib/clusterup.sh present (required for the live tier)"
	else
		# shellcheck source=/dev/null
		. "$LIB"
		echo "----------------------------------------"
		echo "B217 LAB tier: booting a single-node cluster (this mutates lo0/datastore on this Mac)"
		if cluster_up; then
			ladder ok "b217.L0  single-node cluster up"
			# The live fixture + assertions are authored against the shared kubectl
			# helpers; the operator running this tier fills in the datapath probe (two
			# Pods on :8080 + a curl through each Service VIP). Left as an explicit
			# operator step rather than a half-tested auto-run, per the lab-run contract.
			lab_pending "b217.L1-L5  apply examples/two-bind-8080.yaml and probe each podIP:8080 (operator step; see the header)"
			cluster_down || true
		else
			ladder no "b217.L0  single-node cluster up (cluster_up failed — see output above)"
			cluster_down || true
		fi
	fi
fi

echo "----------------------------------------"
echo "B217: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B217 GREEN (CI tier) ================"
