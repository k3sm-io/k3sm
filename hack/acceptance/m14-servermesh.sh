#!/usr/bin/env bash
#
# k3sm M14.2 acceptance gate — the runnable proof that `k3sm server --mesh-ip`
# JOINS THE MESH IT HOSTS, and that wiring its mesh-egress source into the Service
# proxy does not break the backend dials the old unconditional bind would have.
#
# The defect: `k3sm server` brokered other nodes into a wireguard mesh it was not
# itself a peer of. Nothing wrote a MeshPeer for the control-plane node, so no
# worker had an AllowedIPs route to its /24, and the server's own Service proxy was
# left with MeshEgressIP deliberately EMPTY — because the proxy bound that source
# on EVERY dial, and a non-local value there broke all backend dials, including
# same-node loopback. M14.2 fixes both halves: the server enrolls itself at index 0
# (k3sm, this gate) and the source bind becomes destination-scoped (darwin-net).
#
# WHY THIS GATE EXISTS SEPARATELY FROM m3.sh (plan R4): hack/acceptance/m3.sh boots
# WITHOUT --mesh-ip. It therefore cannot exercise a single line of this change, and
# citing it as regression evidence for the hazard would be vacuous. The hazard proof
# has to live in a gate that sets --mesh-ip, which is this one.
#
# TWO TIERS, split by what can be proven without a live control plane:
#
#   CI TIER (always runs, CGO_ENABLED=1) — the unit-provable half: the index-0 pin
#   and its fail-closed foreign-claim handling, the list-back verification, the
#   lowest-free-index allocator table, the persistent wireguard identity, the
#   underlay endpoint derivation, and — the legs that catch this repo's recurring
#   defect class of a well-tested helper bring-up never calls — the structural
#   ORDERING pins read out of cmd/k3sm/server.go. Plus the two-actor race test that
#   pins the d4 happens-before, run under -race.
#   RED BEFORE: on the unmodified tree EnrollSelf, lowestFreeNodeIndex,
#   loadOrCreateServerMeshKey and enrollSelfAndBringUpMesh do not exist, so the Go
#   legs fail to build and every structural pin fails.
#
#   ROOT/INTEGRATION TIER (K3SM_LAB=1 AND root, a single Mac) — a live
#   `k3sm server --mesh-ip 127.0.0.1 --network direct`, built WITH -race, asserting
#   the index-0 MeshPeer object, the wireguard device artifacts, and the
#   HAZARD-REGRESSION round trip. Root is required for --network direct (the utun,
#   the lo0 aliases, the pf anchor); K3SM_LAB gates it because it boots a real
#   control plane and takes over host network state. Under K3SM_LAB=1 WITHOUT root
#   the tier FAILS rather than skipping: this row is manual:true in
#   hack/acceptance/phases.json, so the release process trusts its exit 0 under
#   K3SM_LAB=1 as "proven", and a silent skip there would green a milestone whose
#   proof was never run.
#
# WHAT THIS GATE DOES NOT PROVE: a cross-node datapath. One Mac has no second
# machine to route between, so the actual wireguard egress path — the one this
# defect class has historically hidden in — is the two-Mac hack/lab/m3.sh slice,
# which M14.2 unblocks and M14.3/M14.4 run. Announced as LAB-PENDING below, never
# counted as a pass.
#
# Usage:  hack/acceptance/m14-servermesh.sh                 # CI tier only
#         sudo K3SM_LAB=1 hack/acceptance/m14-servermesh.sh # + the live root tier
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$K3SM_ROOT/.." && pwd)"
SERVER_GO="$K3SM_ROOT/cmd/k3sm/server.go"
AGENT_GO="$K3SM_ROOT/cmd/k3sm/agent.go"
ENROLL_GO="$K3SM_ROOT/cmd/k3sm/enroll.go"
SERVERMESH_GO="$K3SM_ROOT/cmd/k3sm/servermesh.go"
DESIGN_MD="$K3SM_ROOT/docs/DESIGN.md"
SELF="$HERE/m14-servermesh.sh"

# The pinned index-0 identity every leg below asserts against. These are NOT knobs:
# they are podnet.NodeCIDR(ClusterPodCIDR, 0) and its mesh-egress .1, the same two
# values defaultNodePodCIDR() and EnrollSelf derive independently. Writing them out
# here is the point — if either derivation moves, this gate says so.
SELF_POD_CIDR="100.64.0.0/24"
SELF_MESH_IP="100.64.0.1"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
lab_pending() { echo "LAB-PENDING  $1"; }

echo "==> k3sm M14.2 acceptance (the server joins its own mesh; scoped mesh-egress does not break backend dials)"

# ---- m14.0 — the gate parses and its wiring sources exist -------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$SERVER_GO" "$AGENT_GO" "$ENROLL_GO" "$SERVERMESH_GO"; do
	[ -f "$f" ] || b0=no
done
ladder "$b0" "m14.0  gate parses (bash -n) + cmd/k3sm/{server,agent,enroll,servermesh}.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "M14.2: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "M14.2: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- m14.pre — the cross-repo precondition ---------------------------------
# The hazard this gate exists to contain is HALF in darwin-net: the server's
# mesh-egress source is only safe to wire because the proxy's dial-source bind is
# DESTINATION-SCOPED there. The two halves meet only through the workspace go.work,
# so a standalone k3sm clone cannot prove this gate — its absence is a hard FAIL,
# never a skip, or "M14.2 green" would mean "M14.2 was not checked".
if [ -f "$WS_ROOT/go.work" ] && [ -d "$WS_ROOT/darwin-net/pkg/proxy" ]; then
	ladder ok "m14.pre  workspace go.work + sibling darwin-net/pkg/proxy present"
else
	ladder no "m14.pre  workspace go.work + sibling darwin-net/pkg/proxy present — the scoped-bind half lives there; a standalone k3sm checkout cannot prove this gate"
fi
if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "M14.2: $PASS passed, $FAIL failed (cross-repo preconditions unmet)" >&2
	exit 1
fi

# ---- m14.1 — the wiring, read straight out of the source -------------------
# Structural pins, so the gate reddens if a call is deleted or re-implemented as a
# second path. The Go AST legs below assert the same invariants more precisely;
# these stay readable in a gate log.
w=ok
grep -qE 'func \(e \*meshEnroller\) EnrollSelf\(' "$ENROLL_GO" || w=no
grep -qE 'func lowestFreeNodeIndex\(' "$ENROLL_GO" || w=no
# The retired counter, matched as CODE (the replacement's doc comment names it, so
# a bare `len(existing)+1` grep matches the explanation rather than the defect).
grep -qE 'NodeCIDR\(e\.clusterPod, len\(existing\)\+1\)' "$ENROLL_GO" && w=no
ladder "$w" "m14.1  the enroller pins index 0 (EnrollSelf) and allocates workers by lowest free index (the len(existing)+1 counter is gone)"

k=ok
grep -qE 'func loadOrCreateServerMeshKey\(' "$SERVERMESH_GO" || k=no
grep -qE '0o600' "$SERVERMESH_GO" || k=no
grep -qE 'enrollSelfAndBringUpMesh\(ctx, enroller' "$SERVER_GO" || k=no
ladder "$k" "m14.1  the server persists a 0600 wireguard identity and self-enrolls during bring-up"

# The ORDER, by line number as well as by AST: the enroll must precede BOTH the
# proxy construction (mesh.Start plumbs the lo0 alias the proxy sources from) and
# the join listener (the index-0 claim must be durable before a worker can be
# assigned an index).
crd_ln="$(grep -n 'ensureMeshPeerCRD(ctx, opts\.meshIP,' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
enr_ln="$(grep -n 'enrollSelfAndBringUpMesh(ctx, enroller' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
net_ln="$(grep -n 'netserve\.New(netserve\.Config{' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
sup_ln="$(grep -n 'startBootstrapServer(ctx, deps' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
if [ -n "$crd_ln" ] && [ -n "$enr_ln" ] && [ -n "$net_ln" ] && [ -n "$sup_ln" ] &&
	[ "$crd_ln" -lt "$enr_ln" ] && [ "$enr_ln" -lt "$net_ln" ] && [ "$net_ln" -lt "$sup_ln" ]; then
	ladder ok "m14.1  ensureMeshPeerCRD(:$crd_ln) < enrollSelfAndBringUpMesh(:$enr_ln) < netserve.New(:$net_ln) < startBootstrapServer(:$sup_ln)"
else
	ladder no "m14.1  ordering: ensureMeshPeerCRD(:${crd_ln:-none}) < enrollSelfAndBringUpMesh(:${enr_ln:-none}) < netserve.New(:${net_ln:-none}) < startBootstrapServer(:${sup_ln:-none})"
fi

# d8 — the doc deliverable, and the retirement of the claim it replaces.
d=ok
grep -q 'destination-scoped' "$DESIGN_MD" || d=no
grep -q 'The server is a peer, not only a broker' "$DESIGN_MD" || d=no
grep -q 'does not bring up its own wireguard mesh' "$SERVER_GO" && d=no
ladder "$d" "m14.1  DESIGN §5b records server-mesh participation + the destination-scoped egress rule, and server.go's 'no server mesh' claim is gone"

# ---- Go leg runner (CGO_ENABLED=1) -----------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-Rosetta
# would otherwise build the wrong arch for a product that is darwin/arm64-only.
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg> [extra go test flags...]
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever. Each leg fails unless the
# top-level `--- PASS: <TestName>` line is present and the subtest count meets the
# pinned minimum (0 for a leg with no subtests).
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4"; shift 4
	local out rc=0 ran
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v "$@" -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name}( |\$)"; then
		ladder no "$id  $name ($pkg) actually RAN — no top-level --- PASS line"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- m14.2 — the index-0 pin and the allocator (d3) -------------------------
run_test "m14.2" 9 TestNodeIndexOf                                  ./cmd/k3sm/
run_test "m14.2" 10 TestLowestFreeNodeIndex                         ./cmd/k3sm/
run_test "m14.2" 0 TestLowestFreeNodeIndexExhaustsClosed            ./cmd/k3sm/
run_test "m14.2" 0 TestEnrollAssignsLowestFreeIndexAboveZero        ./cmd/k3sm/
run_test "m14.2" 0 TestEnrollSelfPinsIndexZero                      ./cmd/k3sm/
run_test "m14.2" 0 TestEnrollSelfFailsClosedOnAForeignIndexZeroClaim ./cmd/k3sm/
run_test "m14.2" 0 TestEnrollSelfRequiresTheWriteToReadBack         ./cmd/k3sm/

# ---- m14.3 — the d4 happens-before, under -race ----------------------------
# The two-actor race: the server's own enroll against a burst of simulated worker
# joins through ONE enroller. -race is not decoration here — the property being
# proven is that two entry points sharing an allocator never hand out one /24, and
# an unsynchronized read is exactly how that would regress.
run_test "m14.3" 0 TestSelfEnrollRacesConcurrentJoinsWithoutSharingAnIndex ./cmd/k3sm/ -race

# ---- m14.4 — the persistent identity + the bring-up contract (d2/d6) -------
run_test "m14.4" 0 TestServerMeshKeyIsMintedOnceAndReused           ./cmd/k3sm/
run_test "m14.4" 3 TestServerMeshKeyRefusesAnUnusableFile           ./cmd/k3sm/
run_test "m14.4" 0 TestServerMeshKeyRefIsNotTheAgentRef             ./cmd/k3sm/
run_test "m14.4" 0 TestServerMeshEndpointPrefersAnUnderlayAddress   ./cmd/k3sm/
run_test "m14.4" 0 TestBringUpMeshRefusesAMeshIPTheCIDRDoesNotDerive ./cmd/k3sm/

# ---- m14.5 — the bring-up wiring, structurally (d4/d5/d7) ------------------
run_test "m14.5" 0 TestRunServerEnrollsSelfBeforeTheDatapathAndJoinListener ./cmd/k3sm/
run_test "m14.5" 0 TestRunServerSharesOneMeshEnroller               ./cmd/k3sm/
run_test "m14.5" 0 TestServerMeshBringUpIsLogAndContinue            ./cmd/k3sm/
run_test "m14.5" 0 TestServerNetserveWiresTheMeshEgressSource       ./cmd/k3sm/

# ---- m14.6 — the darwin-net half, under -race ------------------------------
# The scoping decision tables (foreign /24 ⇒ bound; own /24, loopback, node LAN,
# ClusterIP VIP, LocalityUnknown ⇒ unbound, for BOTH TCP and UDP) are M14.2-d1's
# and live in darwin-net. This gate CITES them by running that package rather than
# re-implementing a copy here: the source-bind decision must have exactly one home,
# and a second table in this repo would drift from the dialer it describes. The
# whole package runs under -race because the containment being proven is a
# per-connection shared-state property — the failure mode the plan names is a
# mutation of the shared dialer's LocalAddr across the per-connection goroutines,
# which only -race and concurrency together can see.
dn_out=""; dn_rc=0
dn_out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -race k3sm.io/darwin-net/pkg/proxy 2>&1)" || dn_rc=$?
if [ "$dn_rc" -eq 0 ]; then
	ladder ok "m14.6  darwin-net/pkg/proxy passes under -race (the destination-scoped dial-source tables, M14.2-d1)"
else
	printf '%s\n' "$dn_out" | tail -30
	ladder no "m14.6  darwin-net/pkg/proxy passes under -race — M14.2-d1 (the scoped dial source) is the other half of this sub-phase; the server's mesh-egress wiring is only safe with it"
fi

# ============================================================================
# ROOT / INTEGRATION TIER — a live single-Mac mesh-path control plane.
# Requires K3SM_LAB=1 AND root: --network direct owns the utun, the lo0 aliases
# and the pf anchor.
# ============================================================================
if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "M14.2 ROOT tier (run: sudo K3SM_LAB=1 $0):"
	lab_pending "m14.L0  \`k3sm server --mesh-ip 127.0.0.1 --network direct\` (built -race) reaches a healthy apiserver"
	lab_pending "m14.L1  the index-0 MeshPeer exists: name=<node>, podCIDR=$SELF_POD_CIDR, meshIP=$SELF_MESH_IP, non-empty publicKey (RED before: no such object at all)"
	lab_pending "m14.L2  the mesh-egress lo0 alias $SELF_MESH_IP is plumbed and the io.k3sm.mesh pf anchor names a utun (the device is up)"
	lab_pending "m14.L3  wireguard is listening on UDP :51820 — the endpoint the index-0 MeshPeer advertises"
	lab_pending "m14.L4  HAZARD REGRESSION: a same-node ClusterIP round trip completes with MeshEgressIP wired, with remote-destination dials concurrently in flight"
	lab_pending "m14.L5  the -race build reports no DATA RACE across the concurrent local/remote dials"
	lab_pending "m14.L6  [two-Mac harness] cross-node pod traffic actually traverses the mesh — hack/lab/m3.sh, NOT proven on one Mac"
	echo "----------------------------------------"
	echo "M14.2: $PASS passed, $FAIL failed"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "================ M14.2 GREEN (CI tier; the root tier is owed) ================"
	exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "----------------------------------------"
	echo "M14.2 ROOT tier requires root for --network direct (utun + lo0 aliases + the pf anchor) — run: sudo K3SM_LAB=1 $0" >&2
	echo "Refusing to report a K3SM_LAB run green without it: this row is manual:true in phases.json, so exit 0 here would be read as PROVEN." >&2
	echo "M14.2: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# Every port is off-default so this tier can run beside another gate's cluster.
M14_WORK="${M14_WORK:-/tmp/k3sm-m14-servermesh}"
K3SM_WORKDIR="$M14_WORK"
SERVER_WORKDIR="$M14_WORK/server"
M14_API_PORT=6447
M14_KINE_PORT=2382
M14_KUBELET_PORT=10256
M14_SCHED_PORT=10270
M14_CM_PORT=10268
M14_NODE=m14-servermesh
APISERVER_PORT="$M14_API_PORT"
KINE_PORT="$M14_KINE_PORT"
SERVER_PID=""
LIB="$K3SM_ROOT/hack/lib/clusterup.sh"
if [ ! -f "$LIB" ]; then
	ladder no "m14.L0  hack/lib/clusterup.sh present (required for the root tier)"
	echo "M14.2: $PASS passed, $FAIL failed" >&2
	exit 1
fi
# clusterup.sh is sourced for RESET and TEARDOWN only — never for bring-up, because
# server_up cannot pass --network direct together with --mesh-ip on a hostprocess
# runtime, and M14.2 is exactly about that combination.
# shellcheck source=/dev/null
. "$LIB"

m14_down() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
	# Give the server its shutdown window so it removes the lo0 alias and the pf
	# anchor itself; sweep what it left behind either way.
	sleep 3
	for port in "$M14_KUBELET_PORT" "$M14_SCHED_PORT" "$M14_CM_PORT" "$APISERVER_PORT" "$KINE_PORT"; do
		reap_port "$port" warn || true
	done
	ifconfig lo0 -alias "$SELF_MESH_IP" 2>/dev/null || true
	pfctl -a io.k3sm.mesh -F rules 2>/dev/null || true
}
trap m14_down EXIT

if ! cluster_reset; then
	ladder no "m14.L0  cluster_reset (free this gate's ports + drop the previous datastore)"
	echo "M14.2: $PASS passed, $FAIL failed" >&2
	exit 1
fi
rm -f "$SERVER_WORKDIR/bin"/*.cstemp
mkdir -p "$M14_WORK"

echo "----------------------------------------"
echo "M14.2 ROOT tier: building the -race server binary"
# -race, deliberately. The hazard being contained is a per-connection shared-state
# property (a mutated shared dialer LocalAddr across the proxy's handle()
# goroutines), and a functional round trip cannot see it. Under -race, with local-
# and remote-destination dials concurrently in flight, it is detected.
RACE_BIN="$M14_WORK/k3sm-race"
if ! ( cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go build -race -o "$RACE_BIN" ./cmd/k3sm ); then
	ladder no "m14.L0  build a -race k3sm binary"
	echo "M14.2: $PASS passed, $FAIL failed" >&2
	exit 1
fi

echo "M14.2 ROOT tier: booting a mesh-path control plane in $M14_WORK"
# --mesh-ip 127.0.0.1: the apiserver and the join supervisor bind it, so it has to
# be an address the host ALREADY answers on — the mesh-egress /32 does not exist
# until mesh.Start plumbs it, which is after the executor starts. A loopback mesh
# is a legitimate single-host cluster; the CROSS-node address is the two-Mac slice.
# The ingress listeners are disabled so the tier does not contend for :80/:443.
nohup env CGO_ENABLED=1 "$RACE_BIN" server \
	--work-dir "$SERVER_WORKDIR" --node-name "$M14_NODE" \
	--mesh-ip 127.0.0.1 --network direct --runtime hostprocess \
	--pod-root "$M14_WORK/pods" \
	--api-port "$M14_API_PORT" --kine-port "$M14_KINE_PORT" \
	--kubelet-port "$M14_KUBELET_PORT" \
	--scheduler-port "$M14_SCHED_PORT" --controller-manager-port "$M14_CM_PORT" \
	--ingress-http-port 0 --ingress-https-port 0 \
	> "$M14_WORK/server.log" 2>&1 &
SERVER_PID=$!

KCFG="$SERVER_WORKDIR/k3sm.kubeconfig"
KUBECTL="$SERVER_WORKDIR/bin/kubectl"
# The SUPERVISOR-ALIVE check is re-checked after healthz, never as an alternative
# to it: a `k3sm server` that dies mid-bring-up can leave its apiserver child
# listening, and that orphan answers /healthz with "ok" — so a healthz-only wait
# reports a healthy cluster over a corpse.
n=0; up=no
while [ $n -lt 900 ]; do
	if [ -f "$KCFG" ] && [ -x "$KUBECTL" ] &&
		[ "$("$KUBECTL" --kubeconfig "$KCFG" get --raw /healthz 2>/dev/null)" = "ok" ]; then
		if kill -0 "$SERVER_PID" 2>/dev/null; then up=ok; break; fi
		echo "/healthz answered but \`k3sm server\` is gone — that is an ORPHANED apiserver, not a healthy cluster" >&2
		break
	fi
	kill -0 "$SERVER_PID" 2>/dev/null || { echo "k3sm server exited during bring-up:" >&2; break; }
	sleep 1; n=$((n+1))
done
ladder "$up" "m14.L0  \`k3sm server --mesh-ip 127.0.0.1 --network direct\` (-race build) reached a healthy apiserver"
if [ "$up" != ok ]; then
	tail -40 "$M14_WORK/server.log" >&2
	echo "----------------------------------------"
	echo "M14.2: $PASS passed, $FAIL failed" >&2
	exit 1
fi

kc14() { "$KUBECTL" --kubeconfig "$KCFG" "$@"; }

# ---- m14.L1 — the index-0 MeshPeer object ----------------------------------
# POLLED, not sampled: /healthz goes ok several bring-up steps before the enroll
# runs (the admission policies, the RBAC graph and the add-on converge sit between).
# A single read here races bring-up and reports the pre-fix symptom on a fixed
# binary. RED BEFORE: no MeshPeer named after this node exists at all.
n=0; got_cidr=""; got_mesh=""; got_key=""
while [ $n -lt 180 ]; do
	got_cidr="$(kc14 get meshpeer "$M14_NODE" -o jsonpath='{.spec.podCIDR}' 2>/dev/null || true)"
	[ -n "$got_cidr" ] && break
	kill -0 "$SERVER_PID" 2>/dev/null || break
	sleep 1; n=$((n+1))
done
got_mesh="$(kc14 get meshpeer "$M14_NODE" -o jsonpath='{.spec.meshIP}' 2>/dev/null || true)"
got_key="$(kc14 get meshpeer "$M14_NODE" -o jsonpath='{.spec.publicKey}' 2>/dev/null || true)"
got_allowed="$(kc14 get meshpeer "$M14_NODE" -o jsonpath='{.spec.allowedIPs[0]}' 2>/dev/null || true)"
got_endpoint="$(kc14 get meshpeer "$M14_NODE" -o jsonpath='{.spec.endpoint}' 2>/dev/null || true)"
l1=ok
[ "$got_cidr" = "$SELF_POD_CIDR" ] || l1=no
[ "$got_mesh" = "$SELF_MESH_IP" ] || l1=no
[ "$got_allowed" = "$SELF_POD_CIDR" ] || l1=no
[ -n "$got_key" ] || l1=no
[ -n "$got_endpoint" ] || l1=no
ladder "$l1" "m14.L1  index-0 MeshPeer $M14_NODE: podCIDR=${got_cidr:-<absent>} meshIP=${got_mesh:-<absent>} allowedIPs[0]=${got_allowed:-<absent>} endpoint=${got_endpoint:-<absent>} publicKey=${got_key:+present}${got_key:-<absent>} (after ${n}s)"

# The endpoint must be an UNDERLAY address, not the mesh /32 — a worker has no mesh
# until the handshake completes, so an in-mesh endpoint is unreachable exactly when
# it is needed.
case "$got_endpoint" in
"$SELF_MESH_IP":*) ladder no "m14.L1  the advertised endpoint $got_endpoint is the MESH address; a joining worker cannot reach it before the mesh exists" ;;
*:*) ladder ok "m14.L1  the advertised endpoint $got_endpoint is an underlay address" ;;
*) ladder no "m14.L1  the advertised endpoint ${got_endpoint:-<absent>} is not a host:port" ;;
esac

# ---- m14.L2/L3 — the wireguard device artifacts ----------------------------
if ifconfig lo0 | grep -qE "inet ${SELF_MESH_IP}( |$|/)"; then
	ladder ok "m14.L2  the mesh-egress lo0 alias $SELF_MESH_IP is plumbed (the source the proxy binds for foreign pod destinations)"
else
	ladder no "m14.L2  the mesh-egress lo0 alias $SELF_MESH_IP is plumbed"
fi
# The pf anchor names the utun the device created. Asserting the ANCHOR rather than
# `ifconfig | grep utun` matters: a Mac with a VPN already has utun interfaces, so
# a bare utun grep would pass without k3sm having created anything.
if pfctl -a io.k3sm.mesh -s rules 2>/dev/null | grep -q 'on utun'; then
	ladder ok "m14.L2  the io.k3sm.mesh pf anchor names a utun (the mesh device is up, MSS-clamped)"
else
	ladder no "m14.L2  the io.k3sm.mesh pf anchor names a utun — the mesh device did not come up"
fi
if lsof -nP -iUDP:51820 2>/dev/null | grep -q k3sm; then
	ladder ok "m14.L3  wireguard is listening on UDP :51820 — the port the index-0 MeshPeer's endpoint advertises"
else
	ladder no "m14.L3  wireguard is listening on UDP :51820"
fi

# ---- m14.L4 — THE HAZARD REGRESSION ----------------------------------------
# The containment being proven: with MeshEgressIP wired, a SAME-NODE ClusterIP
# round trip still completes. Under the old unconditional bind it could not — every
# dial, loopback included, was sourced from a mesh /32 the destination would never
# reply to.
#
# It is driven with REMOTE-destination dials concurrently in flight, because the
# property is per-connection: a sequential local round trip cannot distinguish "the
# source is chosen per dial" from "the source happens to be right for this one".
# The remote service has no selector and a HAND-WRITTEN EndpointSlice pointing into
# a foreign node's /24 — no second Mac and no pod required, and it is exactly the
# destination class that DOES take the bind.
REMOTE_BACKEND="100.64.9.10"
cat > "$M14_WORK/remote.yaml" <<-YAML
	apiVersion: v1
	kind: Service
	metadata:
	  name: m14-remote
	  namespace: default
	spec:
	  ports:
	  - name: http
	    port: 8080
	    protocol: TCP
	    targetPort: 8080
	---
	apiVersion: discovery.k8s.io/v1
	kind: EndpointSlice
	metadata:
	  name: m14-remote-manual
	  namespace: default
	  labels:
	    kubernetes.io/service-name: m14-remote
	addressType: IPv4
	ports:
	- name: http
	  port: 8080
	  protocol: TCP
	endpoints:
	- addresses: ["$REMOTE_BACKEND"]
	  conditions:
	    ready: true
	YAML
if kc14 apply -f "$M14_WORK/remote.yaml" >/dev/null 2>&1; then
	ladder ok "m14.L4  a remote-destination Service (backend $REMOTE_BACKEND, a foreign node /24) is published"
else
	ladder no "m14.L4  a remote-destination Service (backend $REMOTE_BACKEND) is published"
fi
RVIP="$(kc14 get svc m14-remote -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
# Let the proxy's Service/EndpointSlice informers claim the VIP before dialing it.
n=0; while [ $n -lt 60 ] && ! ifconfig lo0 | grep -qE "inet ${RVIP}( |$|/)"; do sleep 1; n=$((n+1)); done

# Remote dials, in flight for the duration of the local round trips. They are
# EXPECTED to fail (there is no second Mac behind that address); what matters is
# that they are concurrently occupying the same proxy and the same dialer.
remote_pids=()
for _ in 1 2 3 4; do
	( for _ in $(seq 1 40); do nc -z -G 1 -w 1 "$RVIP" 8080 >/dev/null 2>&1 || true; done ) &
	remote_pids+=($!)
done

# The local round trip: the `kubernetes` ClusterIP VIP, owned by this same proxy and
# spliced to a SAME-NODE backend. Twenty consecutive successes, with the remote
# dials in flight throughout.
local_ok=0
for _ in $(seq 1 20); do
	if [ "$(kc14 --server "https://10.43.0.1:443" --insecure-skip-tls-verify=true get --raw /healthz 2>/dev/null)" = "ok" ]; then
		local_ok=$((local_ok+1))
	fi
done
for pid in "${remote_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
if [ "$local_ok" -eq 20 ]; then
	ladder ok "m14.L4  HAZARD REGRESSION: 20/20 same-node ClusterIP round trips completed with MeshEgressIP wired and remote dials in flight"
else
	ladder no "m14.L4  HAZARD REGRESSION: only $local_ok/20 same-node ClusterIP round trips completed — wiring the mesh-egress source is blackholing local backend dials"
	tail -40 "$M14_WORK/server.log" >&2
fi

# ---- m14.L5 — the -race verdict --------------------------------------------
if grep -q 'WARNING: DATA RACE' "$M14_WORK/server.log" 2>/dev/null; then
	ladder no "m14.L5  no DATA RACE in the -race server log — the dial-source state is being mutated across the proxy's per-connection goroutines"
	grep -A 25 'WARNING: DATA RACE' "$M14_WORK/server.log" | head -60 >&2
else
	ladder ok "m14.L5  the -race build reported no DATA RACE across the concurrent local/remote dials"
fi

lab_pending "m14.L6  [two-Mac harness] cross-node pod traffic actually traverses the mesh — hack/lab/m3.sh, NOT proven on one Mac"

m14_down
trap - EXIT

echo "----------------------------------------"
echo "M14.2: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M14.2 GREEN (CI + root tiers) ================"
