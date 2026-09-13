#!/usr/bin/env bash
#
# k3sm B283 acceptance gate — the runnable proof that a node REPUBLISHES its
# wireguard endpoint when the address it is reachable at changes.
#
# The defect (observed on the two-Mac lab rig, 2026-09-13): a node's
# MeshPeer.spec.endpoint is derived ONCE — at join for a worker, at self-enroll for
# the control-plane node — and never again. MikoBook joined at 192.168.0.206:51820
# and now lives at .111; the CR still said .206. Wireguard's roaming hides that for
# as long as the node keeps sending (a peer learns the new source address from an
# authenticated packet) and STOPS hiding it at the next full resync on the peer
# (device Up, netd or server restart, a failed IpcSet), which re-programs the dead
# endpoint from the CR and blackholes the node until its next keepalive.
#
# The fix is three pieces, and this gate is their ladder:
#
#   B1  an additive bootstrap verb, POST /v1-k3sm/mesh/endpoint, authenticated by
#       the NODE'S OWN CLIENT CERTIFICATE. Not the join token: that is TTL-bounded
#       (24 h by default), so a refresh gated on it would stop working after a day
#       and silently restore the staleness. The listener therefore gains
#       tls.VerifyClientCertIfGiven + the cluster's client-identity CA — OPTIONAL,
#       because /join, /cacert and /server-bootstrap are reached by nodes that hold
#       no certificate yet. Optional mTLS mistaken for enforced mTLS is a recurring
#       vulnerability class, which is why the whole security table is pinned.
#   B2  meshEndpointRefresher: a 30 s loop (darwin-net's meshResyncPeriod) on BOTH
#       roles that re-derives and republishes, DEBOUNCED — two consecutive
#       identical derivations, so an interface flap cannot stomp a good endpoint.
#   B3  serverMeshEndpoint switched to the tunnel-EXCLUDING interface scan. At
#       bring-up the mesh utun does not exist, so the old scan was harmless by
#       accident; re-derived every 30 s with the device up, it would publish this
#       node's own mesh /32 — the one address an un-joined peer cannot route to.
#
#   The two sibling repos carry the rest and are run here because the behaviour is
#   only true if all three hold: apis validates the endpoint as host:port (a
#   malformed value fanned out to every peer fails at wireguard-configuration time
#   on each node), and darwin-net coalesces the resync fan-out and does not stomp a
#   roamed endpoint.
#
# TWO TIERS, split by what can be proven without two Macs:
#
#   CI TIER (always runs, per-repo CGO_ENABLED: k3sm 1, apis/darwin-net 0) — the
#   unit-provable halves: the verb's security table, the refresher's debounce and
#   retry policy, the tunnel-exclusion, the apis syntax rule, the darwin-net watch
#   behaviour. RED BEFORE: on the unmodified tree neither the verb, the refresher
#   nor the tunnel-exclusion exists, so every k3sm leg fails to build.
#
#   INTEGRATION TIER (K3SM_LAB=1, TWO MACS) — the only tier that can prove the
#   thing the defect is about: a real address change on a joined worker reaching
#   every peer. Announced LAB-PENDING when K3SM_LAB is unset; never silently passed.
#
# Usage:  hack/acceptance/B283.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B283.sh # + the two-Mac integration tier
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$K3SM_ROOT/.." && pwd)"
APIS_ROOT="$WS_ROOT/apis"
DNET_ROOT="$WS_ROOT/darwin-net"
SELF="$HERE/B283.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B283 acceptance (a node republishes its mesh endpoint when its address changes)"

# ---- b283.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$K3SM_ROOT/pkg/bootstrap/meshendpoint.go" ] || b0=no
[ -f "$K3SM_ROOT/cmd/k3sm/meshrefresh.go" ] || b0=no
ladder "$b0" "b283.0  gate parses (bash -n) + pkg/bootstrap/meshendpoint.go + cmd/k3sm/meshrefresh.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B283: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B283: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b283.pre — the cross-repo precondition --------------------------------
# The behaviour spans three repos and they only meet through the workspace
# go.work, so a standalone k3sm clone cannot prove it — its absence is a hard FAIL,
# never a skip, or "B283 green" would mean "B283 was not checked".
pre=ok
[ -f "$WS_ROOT/go.work" ] || pre=no
[ -d "$APIS_ROOT" ] || pre=no
[ -d "$DNET_ROOT" ] || pre=no
ladder "$pre" "b283.pre  workspace go.work + sibling apis and darwin-net present ($WS_ROOT)"
if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B283: $PASS passed, $FAIL failed (cross-repo preconditions unmet)" >&2
	exit 1
fi

# ---- b283.1 — the WIRING, read straight out of the source ------------------
# Structural pins for the three properties a later edit would quietly undo: the
# listener verifies client certificates, the handler reads VerifiedChains (never
# PeerCertificates — the difference between enforced and decorative mTLS), and the
# refresher is started for BOTH roles from the one bring-up path.
w=ok
grep -qE 'ClientAuth:\s+tls\.VerifyClientCertIfGiven' "$K3SM_ROOT/pkg/bootstrap/meshendpoint.go" || w=no
grep -qE 'bootstrap\.ListenerTLSConfig\(servingChain, h\.Signing\.CertPEM\)' "$K3SM_ROOT/cmd/k3sm/enroll.go" || w=no
ladder "$w" "b283.1  the bootstrap listener verifies node client certificates against the signing CA"

v=ok
grep -qE 'r\.TLS\.VerifiedChains' "$K3SM_ROOT/pkg/bootstrap/meshendpoint.go" || v=no
if grep -qE 'r\.TLS\.PeerCertificates' "$K3SM_ROOT/pkg/bootstrap/meshendpoint.go"; then v=no; fi
grep -qE 'AuthorizeMeshPeerWrite\(certNode, req\.NodeName\)' "$K3SM_ROOT/pkg/bootstrap/meshendpoint.go" || v=no
ladder "$v" "b283.1  the handler authorizes on VerifiedChains (never PeerCertificates) + AuthorizeMeshPeerWrite"

s=ok
grep -qE 'refresher:\s+newServerEndpointRefresher\(' "$K3SM_ROOT/cmd/k3sm/servermesh.go" || s=no
grep -qE 'newWorkerEndpointRefresher\(' "$K3SM_ROOT/cmd/k3sm/agent.go" || s=no
grep -qE 'in\.refresher\.Run\(ctx\)' "$K3SM_ROOT/cmd/k3sm/agent.go" || s=no
ladder "$s" "b283.1  bringUpMesh starts the endpoint refresher for BOTH roles"

# ---- Go leg runner ---------------------------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-Rosetta
# would otherwise build the wrong arch for a product that is darwin/arm64-only.
#
# run_test <id> <min-subtests> <TestName> <pkg> <dir> <cgo>
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever. Each leg fails unless the
# top-level `--- PASS: <TestName>` line is present and the subtest count meets the
# pinned minimum (0 for a leg with no subtests). CGO is passed per REPO — running
# a mixed-CGO set under one value hides breakage on whichever side disagrees.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" dir="$5" cgo="$6" out rc=0 ran
	out="$(cd "$dir" && env GOARCH=arm64 CGO_ENABLED="$cgo" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
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

# ---- b283.2 — k3sm (CGO_ENABLED=1) -----------------------------------------
# The security table is the leg that matters most: it is the whole authentication
# of a LAN-reachable write path into the object that decides where every peer sends
# a node's pod traffic. The minimum subtest count is pinned at 7 so a row deleted
# from the table reddens the gate rather than shrinking it silently.
run_test "b283.2" 7 TestMeshEndpointVerbAuthAndGuard ./pkg/bootstrap/ "$K3SM_ROOT" 1
run_test "b283.2" 5 TestMeshEndpointRefresherRepublishesOnChange ./cmd/k3sm/ "$K3SM_ROOT" 1
run_test "b283.2" 0 TestServerMeshEndpointNeverPicksATunnel ./cmd/k3sm/ "$K3SM_ROOT" 1

# ---- b283.3 — apis (CGO_ENABLED=0) -----------------------------------------
run_test "b283.3" 0 TestMeshPeerEndpointMustBeHostPort ./net/v1/ "$APIS_ROOT" 0

# ---- b283.4 — darwin-net (CGO_ENABLED=0) -----------------------------------
# The reconcile side needs no change to accept a refreshed endpoint; these two pin
# that it still does not, and that the resync fan-out stays one Reconcile per tick.
run_test "b283.4" 0 TestMeshWatcherCoalescesResync ./pkg/mesh/ "$DNET_ROOT" 0
run_test "b283.4" 0 TestMeshReconcileDoesNotStompRoamedEndpoint ./pkg/mesh/ "$DNET_ROOT" 0

# ============================================================================
# INTEGRATION TIER — TWO MACS (K3SM_LAB=1).
# ============================================================================
lab_pending() { echo "LAB-PENDING  $1"; }

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B283 INTEGRATION tier (TWO MACS; set K3SM_LAB=1 on the control-plane Mac to run):"
	lab_pending "b283.L0  a joined worker is Ready and its MeshPeer names its current LAN address"
	lab_pending "b283.L1  after the worker's LAN address changes, its MeshPeer endpoint follows within 120s"
	lab_pending "b283.L2  \`kubectl logs\` of a pod on that worker succeeds from the control-plane Mac afterwards"
	echo
	echo "  The procedure, run by hand on the two-Mac rig (it needs a real address change,"
	echo "  which no single-host harness can produce):"
	echo "    1. Join the second Mac:  k3sm agent --server <cp-lan-ip> --node-ip <mesh-ip> --token <token>"
	echo "       and confirm:  kubectl get meshpeers <worker> -o jsonpath='{.spec.endpoint}'"
	echo "    2. Schedule a pod onto it and confirm \`kubectl logs\` works from the control-plane Mac."
	echo "    3. Change the worker's LAN address (renew its DHCP lease, or move it between"
	echo "       Wi-Fi and Ethernet). Do NOT restart k3sm: a restart would re-derive the"
	echo "       endpoint through the JOIN path and prove nothing about the refresher."
	echo "    4. Poll for up to 120s (two debounced 30s ticks plus one resync period):"
	echo "         for i in \$(seq 1 24); do kubectl get meshpeers <worker> \\"
	echo "           -o jsonpath='{.spec.endpoint}'; echo; sleep 5; done"
	echo "       PASS when it names the worker's NEW address. RED BEFORE: it stays on the"
	echo "       address the worker joined from, forever."
	echo "    5. \`kubectl logs\` the same pod again from the control-plane Mac. PASS when it"
	echo "       still succeeds — the peer is dialing an address the worker still owns."
	echo "    6. \`kubectl describe node <worker>\` shows a MeshEndpointChanged event naming"
	echo "       the old and new values."
else
	echo "----------------------------------------"
	echo "B283 INTEGRATION tier: this tier is HUMAN-RUN on the two-Mac rig."
	echo "It cannot be automated from one Mac: its stimulus is a real LAN address change on"
	echo "a SECOND machine, and its assertion is that a peer on the FIRST one follows it."
	echo "Run the numbered procedure printed by this gate without K3SM_LAB=1, and record the"
	echo "result on the item. Nothing is asserted here, so nothing is claimed here."
	lab_pending "b283.L0  a joined worker is Ready and its MeshPeer names its current LAN address"
	lab_pending "b283.L1  after the worker's LAN address changes, its MeshPeer endpoint follows within 120s"
	lab_pending "b283.L2  \`kubectl logs\` of a pod on that worker succeeds from the control-plane Mac afterwards"
fi

echo "----------------------------------------"
echo "B283: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B283 GREEN (CI tier; integration tier is two-Mac, human-run) ================"
