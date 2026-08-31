#!/usr/bin/env bash
#
# k3sm B224 acceptance gate — the runnable proof that `k3sm server --mesh-ip`
# ESTABLISHES the MeshPeer CustomResourceDefinition itself, fail-closed, before the
# worker-join supervisor exists.
#
# The defect (lab defect D3): nothing applied the CRD. The manifest shipped in
# k3sm.io/apis, darwin-net watched the resource and pkg/rbac granted read on it, but
# no k3sm code path ever created it — so pkg/bootstrap's enroll write 500'd on EVERY
# worker join until a human ran `kubectl apply` by hand. cmd/k3sm/server.go step 4a
# now ensures it through pkg/crdensure (the same server-side-apply + Established wait
# the MLX operator uses), on the mesh path only, halting bring-up if it cannot.
#
# TWO TIERS, split by what can be proven without a live control plane:
#
#   CI TIER (always runs, CGO_ENABLED=1) — the unit-provable wiring: the ensure runs
#   on the mesh path and builds NO client at all on single-node; the applied object is
#   the apis manifest under the crdensure field manager; a client-construction failure
#   AND an apply rejection both propagate (fail-closed); and — the leg that actually
#   catches this defect class — the ORDERING pin, which parses server.go and asserts
#   runServer calls ensureMeshPeerCRD before newMeshEnroller and startBootstrapServer
#   and RETURNS on its error. Plus the mesh-regression legs below.
#   RED BEFORE: on the unmodified tree ensureMeshPeerCRD does not exist, so the Go
#   legs fail to build and the b224.2 structural pins fail.
#
#   INTEGRATION TIER (K3SM_LAB=1, a dev Mac; NO ROOT REQUIRED) — boots
#   `k3sm server --mesh-ip 127.0.0.1 --network none` on non-default ports and asserts
#   the CRD reaches Established, that `kubectl get meshpeers` succeeds, and that a
#   MeshPeer shaped exactly like the enroller's write is ACCEPTED and reads back
#   intact. RED BEFORE: every one of those is a NotFound on the unmodified tree.
#   It is behind K3SM_LAB because it downloads the control-plane payload and boots a
#   real datastore; without K3SM_LAB the rungs are announced LAB-PENDING and never
#   silently pass.
#
#   KNOWN BLOCKER, recorded 2026-08-30: this tier cannot reach its assertions yet.
#   `--mesh-ip` bring-up dies inside the executor's Start — kube-controller-manager is
#   given --root-ca-file <work-dir>/apiserver-certs/apiserver.crt, but the mesh path
#   writes the apiserver serving cert under <work-dir>/tls/, leaving that dir empty.
#   That is a SEPARATE defect, upstream of everything B224 added (the CRD ensure runs
#   after Start returns), and it is being fixed on its own item. The legs below stay
#   FAILING until it lands — they are never softened into a skip, because "the mesh
#   path cannot boot" is exactly the kind of thing a gate must keep saying out loud.
#   The assertions themselves are NOT speculative: with that cert dir hand-seeded, a
#   2026-08-30 run of exactly this bring-up logged `ensured the MeshPeer CRD` at
#   .330 and `bootstrap supervisor listening` at .352 (the ordering, live), reported
#   the CRD Established=True, and accepted the enroll-shaped MeshPeer below with
#   every field reading back intact.
#
# THE MESH-REGRESSION OBLIGATION (what the apis accessor's doc comment owed). Adopting
# MeshPeer into the applied set had to be shown not to perturb the mesh/enroll path.
# Discharged by three legs, and honest about their reach:
#   PROVES  — the applied schema accepts exactly what the enroller writes (every spec
#             key is a declared property, so nothing is silently PRUNED; every
#             required key is populated), and the enroller's own behaviour (index-1
#             /24 assignment, create, and rejoin-updates-in-place) is unchanged when
#             driven end to end through its real REST client (b224.3);
#           — against a LIVE apiserver, that the enroll-shaped write now lands where
#             it previously 404'd (b224.L2/L3).
#   DOES NOT PROVE — a cross-node join. Two Macs, a live wireguard mesh and a real
#             worker agent are the K3SM_LAB two-Mac slice, unchanged by this item.
#             B224 makes the CRD exist; it brings up no mesh (that is M14.2).
#
# Usage:  hack/acceptance/B224.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B224.sh # + the live single-node integration tier
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$K3SM_ROOT/.." && pwd)"
APIS_CRD="$WS_ROOT/apis/config/crd/embed.go"
SERVER_GO="$K3SM_ROOT/cmd/k3sm/server.go"
SELF="$HERE/B224.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B224 acceptance (server bring-up ensures the MeshPeer CRD, fail-closed)"

# ---- b224.0 — the gate parses and the wiring source exists -----------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$SERVER_GO" ] || b0=no
ladder "$b0" "b224.0  gate parses (bash -n) + cmd/k3sm/server.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B224: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B224: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b224.pre — the cross-repo precondition --------------------------------
# The ensure applies k3sm.io/apis' OWN bytes through its named accessor. The two
# halves only meet through the workspace go.work, so a standalone k3sm clone cannot
# prove this — its absence is a hard FAIL, never a skip, or "B224 green" would mean
# "B224 was not checked".
if [ -f "$WS_ROOT/go.work" ]; then
	ladder ok "b224.pre  workspace go.work present ($WS_ROOT/go.work)"
else
	ladder no "b224.pre  workspace go.work present — B224 applies apis' embedded manifest; a standalone k3sm checkout cannot prove it"
fi
pre=ok
[ -f "$APIS_CRD" ] || pre=no
grep -qE 'MeshPeerCRDName\s*=\s*"meshpeers\.net\.k3sm\.io"' "$APIS_CRD" 2>/dev/null || pre=no
grep -qE 'func MeshPeerCRD\(\) \[\]byte' "$APIS_CRD" 2>/dev/null || pre=no
ladder "$pre" "b224.pre  sibling apis exports MeshPeerCRDName + MeshPeerCRD() (the accessor the ensure consumes)"
if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B224: $PASS passed, $FAIL failed (cross-repo preconditions unmet)" >&2
	exit 1
fi

# ---- b224.1 — the ensure is wired, through the SHARED applier --------------
# Structural pins, so the gate reddens if the call is deleted or re-implemented as a
# second, forked apply path. pkg/crdensure is the one applier (MLX uses it for
# MLXModel); a hand-rolled Create here would skip the Established wait and hand the
# join supervisor a CRD whose REST handler does not exist yet.
w=ok
grep -qE 'ensureMeshPeerCRD\(ctx, opts\.meshIP,' "$SERVER_GO" || w=no
grep -qE 'crdensure\.Ensure\(ctx, c, crdconfig\.MeshPeerCRD\(\)' "$SERVER_GO" || w=no
ladder "$w" "b224.1  runServer calls ensureMeshPeerCRD(opts.meshIP), applying crdconfig.MeshPeerCRD() via pkg/crdensure"

# ---- b224.2 — the ORDER, read straight out of the source -------------------
# The invariant that makes the fix worth anything: the CRD exists before anything can
# write a MeshPeer. startBootstrapServer opens the join listener, so a CRD ensured
# after it would still lose whichever worker won the race. Asserted here by line
# number as well as by the Go AST leg below — this one stays readable in a gate log.
ens_ln="$(grep -n 'ensureMeshPeerCRD(ctx, opts\.meshIP,' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
enr_ln="$(grep -n 'newMeshEnroller(restCfg' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
sup_ln="$(grep -n 'startBootstrapServer(ctx, deps' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
if [ -n "$ens_ln" ] && [ -n "$enr_ln" ] && [ -n "$sup_ln" ] && [ "$ens_ln" -lt "$enr_ln" ] && [ "$enr_ln" -lt "$sup_ln" ]; then
	ladder ok "b224.2  ensure(:$ens_ln) precedes newMeshEnroller(:$enr_ln) precedes startBootstrapServer(:$sup_ln)"
else
	ladder no "b224.2  ensure(:${ens_ln:-none}) must precede newMeshEnroller(:${enr_ln:-none}) and startBootstrapServer(:${sup_ln:-none})"
fi

# ---- Go leg runner (CGO_ENABLED=1) -----------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-Rosetta
# would otherwise build the wrong arch for a product that is darwin/arm64-only.
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever. Each leg fails unless the
# top-level `--- PASS: <TestName>` line is present and the subtest count meets the
# pinned minimum (0 for a leg with no subtests).
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

# ---- b224.3 — the unit tier -------------------------------------------------
# mesh-path-vs-single-node (the client factory is called once / never), fail-closed on
# both failure classes, and the source-level ordering + returns-on-error pin.
run_test "b224.3" 2 TestEnsureMeshPeerCRDProvisionsOnlyOnTheMeshPath ./cmd/k3sm/
run_test "b224.3" 2 TestEnsureMeshPeerCRDFailsClosed ./cmd/k3sm/
run_test "b224.3" 0 TestRunServerEnsuresMeshPeerCRDBeforeTheJoinListener ./cmd/k3sm/

# ---- b224.4 — the MESH-REGRESSION legs -------------------------------------
# Green before AND after the adoption by design: they pin that the enroll path did not
# move. See the header for exactly what they do and do not prove.
run_test "b224.4" 0 TestMeshPeerCRDSchemaAcceptsTheEnrollWrite ./cmd/k3sm/
run_test "b224.4" 0 TestMeshEnrollerCreatesAndRejoinsUnchanged ./cmd/k3sm/

# ============================================================================
# INTEGRATION TIER — a live single-node mesh-path control plane (K3SM_LAB=1).
# Rootless: --network none, no privileged ports, ingress listeners disabled.
# ============================================================================
lab_pending() { echo "LAB-PENDING  $1"; }

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B224 INTEGRATION tier (set K3SM_LAB=1 on a dev Mac to run; no root needed):"
	lab_pending "b224.L0  \`k3sm server --mesh-ip 127.0.0.1 --network none\` reaches a healthy apiserver"
	lab_pending "b224.L1  the MeshPeer CRD reports Established (RED before: NotFound — nothing applied it)"
	lab_pending "b224.L2  \`kubectl get meshpeers\` succeeds (RED before: the server has no such resource)"
	lab_pending "b224.L3  an enroll-shaped MeshPeer is ACCEPTED and reads back intact (the live half of the mesh-regression leg)"
	lab_pending "b224.L4  [two-Mac harness] a real worker join enrolls over the mesh — M14.2, NOT proven here"
else
	# This tier reuses hack/lib/clusterup.sh for RESET and TEARDOWN only — never for
	# bring-up, because server_up cannot pass --mesh-ip and B224 is exactly about the
	# mesh path. cluster_reset is what removes the previous run's datastore and reaps
	# the listeners it left behind (a killed run leaves a live kine holding the
	# datastore port, which the next run then reports as a bind failure); it keeps the
	# bin/ download caches, so only a cold first run pays for the payload.
	#
	# The port variables are set BEFORE sourcing so cluster_reset reaps THIS gate's
	# ports rather than the defaults. Every one of them is off-default so this tier can
	# run beside another gate's cluster, and none is privileged.
	B224_WORK="${B224_WORK:-/tmp/k3sm-b224}"
	K3SM_WORKDIR="$B224_WORK"
	SERVER_WORKDIR="$B224_WORK/server"
	B224_API_PORT=6446
	B224_KINE_PORT=2381
	B224_KUBELET_PORT=10255
	B224_SCHED_PORT=10269
	B224_CM_PORT=10267
	APISERVER_PORT="$B224_API_PORT"
	KINE_PORT="$B224_KINE_PORT"
	SERVER_PID=""
	LIB="$K3SM_ROOT/hack/lib/clusterup.sh"
	if [ ! -f "$LIB" ]; then
		ladder no "b224.L0  hack/lib/clusterup.sh present (required for the integration tier)"
		echo "----------------------------------------"
		echo "B224: $PASS passed, $FAIL failed" >&2
		exit 1
	fi
	# shellcheck source=/dev/null
	. "$LIB"
	b224_down() {
		[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
		for port in "$B224_KUBELET_PORT" "$B224_SCHED_PORT" "$B224_CM_PORT" "$APISERVER_PORT" "$KINE_PORT"; do
			reap_port "$port" warn || true
		done
	}
	trap b224_down EXIT
	if ! cluster_reset; then
		ladder no "b224.L0  cluster_reset (free this gate's ports + drop the previous datastore)"
		echo "----------------------------------------"
		echo "B224: $PASS passed, $FAIL failed" >&2
		exit 1
	fi
	# A codesign interrupted by a previous kill leaves a .cstemp beside its binary,
	# and the next signing pass refuses to overwrite it.
	rm -f "$SERVER_WORKDIR/bin"/*.cstemp
	echo "----------------------------------------"
	echo "B224 INTEGRATION tier: booting a mesh-path control plane in $B224_WORK"
	# The ingress listeners are disabled outright so no privileged bind is attempted
	# and the tier stays rootless; --network none means no datapath and no lo0 alias.
	( cd "$K3SM_ROOT" && nohup env CGO_ENABLED=1 go run ./cmd/k3sm server \
		--work-dir "$SERVER_WORKDIR" --node-name b224-mesh \
		--mesh-ip 127.0.0.1 --network none --runtime hostprocess \
		--pod-root "$B224_WORK/pods" \
		--api-port "$B224_API_PORT" --kine-port "$B224_KINE_PORT" \
		--kubelet-port "$B224_KUBELET_PORT" \
		--scheduler-port "$B224_SCHED_PORT" --controller-manager-port "$B224_CM_PORT" \
		--ingress-http-port 0 --ingress-https-port 0 \
		> "$B224_WORK/server.log" 2>&1 & echo $! > "$B224_WORK/server.pid" )
	SERVER_PID="$(cat "$B224_WORK/server.pid")"

	KCFG="$SERVER_WORKDIR/k3sm.kubeconfig"
	KUBECTL="$SERVER_WORKDIR/bin/kubectl"
	# The bound is generous because a COLD run downloads the whole control-plane
	# payload, ad-hoc-signs it, and builds the pinned kine before the apiserver so much
	# as starts. A warm run (cluster_reset keeps bin/) reaches healthy in seconds.
	#
	# The SUPERVISOR-ALIVE check is checked LAST and re-checked after healthz, not as
	# an alternative to it. A `k3sm server` that dies mid-bring-up can leave its
	# apiserver child listening for a while, and that orphan answers /healthz with
	# "ok" — so a healthz-only wait reports a healthy cluster over a corpse and then
	# blames the fix for the CRD it never got the chance to apply. Observed live.
	n=0; up=no
	while [ $n -lt 900 ]; do
		if [ -f "$KCFG" ] && [ -x "$KUBECTL" ] && \
			[ "$("$KUBECTL" --kubeconfig "$KCFG" get --raw /healthz 2>/dev/null)" = "ok" ]; then
			if kill -0 "$SERVER_PID" 2>/dev/null; then up=ok; break; fi
			echo "/healthz answered but \`k3sm server\` is gone — that is an ORPHANED apiserver, not a healthy cluster" >&2
			break
		fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			echo "k3sm server exited during bring-up; its last log lines:" >&2
			break
		fi
		sleep 1; n=$((n+1))
	done
	ladder "$up" "b224.L0  \`k3sm server --mesh-ip 127.0.0.1 --network none\` reached a healthy apiserver"
	if [ "$up" != ok ]; then
		tail -30 "$B224_WORK/server.log" >&2
		# Name the one known blocker rather than let it read as a B224 failure. It is
		# NOT one: it happens inside the executor's Start, strictly BEFORE any code
		# this item added runs. Observed 2026-08-30 on the mesh path — the apiserver
		# serving cert is written under tls/ while kube-controller-manager is pointed
		# at an empty apiserver-certs/, so KCM exits and takes bring-up with it. The
		# leg still FAILS (a named cause is not a pass); it goes green once the
		# separate mesh-path --root-ca-file fix lands.
		if grep -q 'root-ca-file.*apiserver-certs' "$B224_WORK/server.log" 2>/dev/null; then
			echo "b224.L0: this is the known mesh-path --root-ca-file defect (kube-controller-manager cannot read apiserver-certs/apiserver.crt), NOT a B224 regression — it fails before the CRD ensure is reached" >&2
		fi
	else
		# NOT clusterup.sh's kc(): that one dials a fixed port with a static token.
		bkc() { "$KUBECTL" --kubeconfig "$KCFG" "$@"; }

		# POLLED, not sampled. /healthz goes ok the moment the apiserver serves, which
		# is several bring-up steps BEFORE step 4a runs (the admission policies, the
		# RBAC graph and the add-on converge all sit in between). A single read here
		# races bring-up and reports the pre-fix symptom on a fixed binary.
		n=0; est=""
		while [ $n -lt 180 ]; do
			est="$(bkc get crd meshpeers.net.k3sm.io \
				-o jsonpath='{.status.conditions[?(@.type=="Established")].status}' 2>/dev/null || true)"
			[ "$est" = True ] && break
			kill -0 "$SERVER_PID" 2>/dev/null || break
			sleep 1; n=$((n+1))
		done
		if [ "$est" = True ]; then
			ladder ok "b224.L1  the MeshPeer CRD reports Established (after ${n}s)"
		else
			ladder no "b224.L1  the MeshPeer CRD reports Established (got '${est:-<absent>}' after ${n}s — RED-BEFORE looks exactly like this)"
			tail -30 "$B224_WORK/server.log" >&2
		fi

		if bkc get meshpeers >/dev/null 2>&1; then
			ladder ok "b224.L2  \`kubectl get meshpeers\` succeeds"
		else
			ladder no "b224.L2  \`kubectl get meshpeers\` succeeds"
		fi

		# The live half of the mesh-regression leg: the object below is shaped exactly
		# like bootstrap.BuildMeshPeer's output for node index 1 (schemaVersion +
		# nodeName + publicKey + endpoint + podCIDR + symmetric allowedIPs + meshIP).
		# On the unmodified tree this is the write that 404s.
		cat > "$B224_WORK/peer.yaml" <<-'YAML'
			apiVersion: net.k3sm.io/v1
			kind: MeshPeer
			metadata:
			  name: b224-worker
			spec:
			  schemaVersion: 1
			  nodeName: b224-worker
			  publicKey: dGVzdC1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGVzPT0=
			  endpoint: 192.0.2.10:51820
			  podCIDR: 100.64.1.0/24
			  allowedIPs:
			    - 100.64.1.0/24
			  meshIP: 100.64.1.1
			  persistentKeepaliveSeconds: 25
		YAML
		if bkc create -f "$B224_WORK/peer.yaml" >/dev/null 2>&1 && \
			[ "$(bkc get meshpeer b224-worker -o jsonpath='{.spec.podCIDR}' 2>/dev/null)" = "100.64.1.0/24" ] && \
			[ "$(bkc get meshpeer b224-worker -o jsonpath='{.spec.allowedIPs[0]}' 2>/dev/null)" = "100.64.1.0/24" ] && \
			[ "$(bkc get meshpeer b224-worker -o jsonpath='{.spec.meshIP}' 2>/dev/null)" = "100.64.1.1" ]; then
			ladder ok "b224.L3  an enroll-shaped MeshPeer is accepted and reads back intact (no field pruned)"
		else
			ladder no "b224.L3  an enroll-shaped MeshPeer is accepted and reads back intact"
		fi
		lab_pending "b224.L4  [two-Mac harness] a real worker join enrolls over the mesh — M14.2, NOT proven here"
	fi
	b224_down
	trap - EXIT
fi

echo "----------------------------------------"
echo "B224: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ B224 GREEN (CI + integration tiers) ================"
else
	echo "================ B224 GREEN (CI tier) ================"
fi
