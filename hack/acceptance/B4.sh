#!/usr/bin/env bash
# k3sm B4 acceptance gate — the server's in-process node runs as system:node.
#
# A `k3sm server` runs a Virtual Kubelet node inside its own process. That node
# now authenticates as CN=system:node:<node name>, O=system:nodes (a client cert
# minted in memory from the signing CA on every boot), so the Node authorizer and
# NodeRestriction govern it exactly as they govern a joined worker, and it gets
# only the grants the system:nodes group already has. No role or binding is added.
#
# TWO TIERS:
#
#   INTEGRATION (default; a dev Mac, NO root). Boots a single-node `k3sm server`
#   (hostprocess runtime, --network none) on off-default ports, so it runs beside
#   an installed k3sm node, which holds the defaults (:6444 apiserver, :2379 kine,
#   :10250 kubelet, :10259 scheduler, :10257 controller-manager). It uses
#   apiserver :6454, kine :2394, kubelet :10350, scheduler :10364 and
#   controller-manager :10362 (the B4_*_PORT knobs below override each), the same
#   off-default band B213's lab tier boots in, and taken by no other gate. Then it
#   runs the build-tagged e2e/TestB4_InProcessNodeIdentityScoped against it:
#     leg 1  the node's Lease and nodes/status are written by system:node:<node>
#            (system:nodes), and by nobody else afterwards. RED on a build whose
#            server node still uses the admin identity.
#     leg 2  SubjectAccessReviews and direct requests as the node identity: no
#            cluster-wide secret/configmap list or watch; a Secret referenced by a
#            pod bound to the node is readable (polled). A policy tripwire.
#     leg 3  the audit log holds no cluster-wide secret/configmap list/watch by
#            the node, and no 403 to it on such a request.
#     leg 4  the bindings a node identity is authorized through are exactly the
#            pkg/rbac golden plus the upstream allowlist in e2e/testdata.
#     leg 5  the upgrade case: the gate seeds, as admin, a stale restricted
#            label on the Node (live and in the Virtual Kubelet last-applied
#            annotation) plus an operator label and taint, then restarts the
#            server; the boot clears the stale label, the node's status writes
#            succeed as itself, and the operator's label and taint survive.
#   Without K3SM_LAB=1 the gate then reports LAB-PENDING and exits 3: it never
#   reports full green without the lab tier.
#
#   LAB (K3SM_LAB=1). Runs against the RUNNING cluster in $KUBECONFIG and boots
#   nothing. Required:
#     K3SM_B4_NODES        node names to pin the reference-resolution pods to
#                          (the server's own node, and any worker to check)
#     K3SM_B4_WORKERS      joined worker node names for the can-i tripwire
#     K3SM_B4_AUDIT_CMD    a command that prints the SERVER's audit log (JSON lines)
#                          on stdout
#     K3SM_B4_AUDIT_WINDOW seconds of node traffic to observe (default 600)
#   For each node it runs e2e/TestB4_ServerNodeResolvesReferencedSecret; for each
#   worker it asserts `kubectl auth can-i` answers no to a cluster-wide secret list
#   and configmap watch; then, over the window, every node user must appear in the
#   audit log (positive control) and none may list or watch secrets or configmaps
#   across all namespaces, allowed or denied.
#
# Exit: 0 all green (lab tier), 1 a failure, 3 integration green with the lab tier
# owed.
#
# Usage:  hack/acceptance/B4.sh                # integration tier
#         K3SM_LAB=1 K3SM_B4_NODES=… K3SM_B4_WORKERS=… K3SM_B4_AUDIT_CMD=… hack/acceptance/B4.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Set BEFORE sourcing clusterup.sh, whose defaults (the installed node's ports) apply
# only to a variable that is still unset; server_up, kc and the reset/teardown reaps
# all read these.
APISERVER_PORT="${B4_API_PORT:-6454}"
KINE_PORT="${B4_KINE_PORT:-2394}"
SCHEDULER_PORT="${B4_SCHEDULER_PORT:-10364}"
CONTROLLER_MANAGER_PORT="${B4_CONTROLLER_MANAGER_PORT:-10362}"
. "$HERE/../lib/clusterup.sh"
. "$HERE/../lib/conformance.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
summary() {
	echo "----------------------------------------"
	echo "B4 ($1): $PASS passed, $FAIL failed"
}

if [ "${K3SM_LAB:-}" != 1 ]; then
	# ---- INTEGRATION tier ---------------------------------------------------
	: "${B4_NODE_NAME:=k3sm-b4}"
	: "${B4_KUBELET_PORT:=10350}"
	trap cluster_down EXIT
	echo "==> k3sm B4 integration gate (single-node k3sm server; node $B4_NODE_NAME on :$B4_KUBELET_PORT)"
	server_up "$B4_NODE_NAME" hostprocess none "" "$B4_KUBELET_PORT"

	# The upgrade case (leg 5). A server Node registered while its node ran as the
	# admin identity can carry kubernetes.io/role=agent both as a live label and in
	# the Virtual Kubelet last-applied annotation. Reproduce that Node as admin,
	# with an operator control-plane label and taint beside it, then restart the
	# server on the SAME work dir (cluster_reset fires once per run, so the
	# datastore survives): the boot under test must clear the stale label it can no
	# longer remove as a node, and keep the operator's.
	ann_key='virtual-kubelet.io/last-applied-object-meta'
	ann="$(kc get node "$B4_NODE_NAME" -o jsonpath='{.metadata.annotations.virtual-kubelet\.io/last-applied-object-meta}')"
	if [ -z "$ann" ]; then
		echo "B4: node $B4_NODE_NAME carries no $ann_key annotation; cannot seed the upgrade state" >&2
		exit 1
	fi
	ann="$(python3 -c 'import json,sys; m=json.loads(sys.argv[1]); m.setdefault("labels",{})["kubernetes.io/role"]="agent"; print(json.dumps(m,separators=(",",":")))' "$ann")"
	kc annotate node "$B4_NODE_NAME" --overwrite "$ann_key=$ann" >/dev/null
	kc label node "$B4_NODE_NAME" --overwrite kubernetes.io/role=agent node-role.kubernetes.io/control-plane= >/dev/null
	kc taint node "$B4_NODE_NAME" --overwrite k3sm.io/b4-operator=seeded:NoSchedule >/dev/null
	echo "B4: seeded the upgrade state on $B4_NODE_NAME; restarting the server on the same work dir"
	cluster_down
	# The second boot must not race the first one's listeners (cluster_reset, which
	# would reap them, runs only once per gate).
	for port in "$KINE_PORT" "$APISERVER_PORT" "$B4_KUBELET_PORT"; do
		reap_port "$port" fatal || { echo "B4: :$port still held after the first server stopped" >&2; exit 1; }
	done
	SERVER_PID=""
	# Every boot mints a new admin token and rewrites the kubeconfig; remove the old
	# one so server_up waits for (and reads its token from) the new boot's file.
	rm -f "$SERVER_WORKDIR/k3sm.kubeconfig"
	K3SM_B4_BOOTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	export K3SM_B4_BOOTED_AT
	server_up "$B4_NODE_NAME" hostprocess none "" "$B4_KUBELET_PORT"

	# The legs read this cluster's audit log and sign a node identity with this
	# cluster's signing CA, both under the server work dir.
	export K3SM_WORK_DIR="$SERVER_WORKDIR"
	export K3SM_B4_NODE="$B4_NODE_NAME"
	if run_conformance_slice "$REPO_ROOT" '^TestB4_InProcessNodeIdentityScoped$' 900s B4_InProcessNodeIdentityScoped; then
		ladder ok "b4.I  the in-process server node runs as system:node:$B4_NODE_NAME, scoped by the Node authorizer (legs 1-5)"
	else
		ladder no "b4.I  the in-process server node runs as system:node:$B4_NODE_NAME, scoped by the Node authorizer (legs 1-5)"
	fi
	summary integration
	[ "$FAIL" -eq 0 ] || exit 1
	echo "B4 integration tier GREEN"
	echo "LAB-PENDING: rig legs not run (set K3SM_LAB=1)"
	exit 3
fi

# ---- LAB tier -----------------------------------------------------------------
missing=""
[ -n "${KUBECONFIG:-}" ] || missing="$missing KUBECONFIG"
[ -n "${K3SM_B4_NODES:-}" ] || missing="$missing K3SM_B4_NODES"
[ -n "${K3SM_B4_WORKERS:-}" ] || missing="$missing K3SM_B4_WORKERS"
[ -n "${K3SM_B4_AUDIT_CMD:-}" ] || missing="$missing K3SM_B4_AUDIT_CMD"
if [ -n "$missing" ]; then
	echo "B4 lab tier: required variable(s) unset:$missing (see the header of $0)" >&2
	exit 1
fi
: "${K3SM_B4_AUDIT_WINDOW:=600}"
KUBECTL="${KUBECTL:-kubectl}"
"$KUBECTL" get --raw /healthz >/dev/null || { echo "the cluster at \$KUBECONFIG is not serving" >&2; exit 1; }
echo "==> k3sm B4 lab tier (nodes: $K3SM_B4_NODES; workers: $K3SM_B4_WORKERS)"

for n in $K3SM_B4_NODES; do
	if K3SM_B4_NODE="$n" run_conformance_slice "$REPO_ROOT" '^TestB4_ServerNodeResolvesReferencedSecret$' 900s B4_ServerNodeResolvesReferencedSecret; then
		ladder ok "b4.L1  pods pinned to $n resolve secretKeyRef env + Secret and ConfigMap volumes; a Never pod Succeeds; a Secret update lands within two ticks"
	else
		ladder no "b4.L1  pods pinned to $n resolve secretKeyRef env + Secret and ConfigMap volumes; a Never pod Succeeds; a Secret update lands within two ticks"
	fi
done

for w in $K3SM_B4_WORKERS; do
	for check in "list secrets" "watch configmaps"; do
		# shellcheck disable=SC2086 # the verb and resource are two words on purpose
		got="$("$KUBECTL" auth can-i $check --all-namespaces --as="system:node:$w" --as-group=system:nodes 2>/dev/null || true)"
		# kubectl appends the authorizer's reason ("no - can only read namespaced
		# object of this type"); the verdict is the first word.
		if [ "${got%% *}" = no ]; then
			ladder ok "b4.L2  can-i $check --all-namespaces as system:node:$w: no"
		else
			ladder no "b4.L2  can-i $check --all-namespaces as system:node:$w: ${got:-<no answer>} (want no)"
		fi
	done
done

window_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "B4 lab tier: observing $K3SM_B4_AUDIT_WINDOW s of node traffic from $window_start"
sleep "$K3SM_B4_AUDIT_WINDOW"
audit="$(mktemp -t b4-audit)"
if ! bash -c "$K3SM_B4_AUDIT_CMD" > "$audit"; then
	ladder no "b4.L3  K3SM_B4_AUDIT_CMD printed the server's audit log"
else
	for n in $K3SM_B4_NODES $K3SM_B4_WORKERS; do
		verdict="$(python3 - "$audit" "$window_start" "system:node:$n" <<'PY'
import json, sys
from datetime import datetime, timezone

def ts(s):
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac, _, tz = rest.partition("+")
        s = head + "." + frac[:6].ljust(6, "0") + "+" + tz
    return datetime.fromisoformat(s)

path, start, user = sys.argv[1], ts(sys.argv[2]), sys.argv[3]
seen = bad = 0
with open(path) as f:
    for line in f:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("user", {}).get("username") != user:
            continue
        t = ev.get("stageTimestamp") or ev.get("requestReceivedTimestamp")
        if not t or ts(t) < start:
            continue
        seen += 1
        ref = ev.get("objectRef") or {}
        if (ev.get("verb") in ("list", "watch") and ref.get("resource") in ("secrets", "configmaps")
                and not ref.get("apiGroup") and not ref.get("namespace")):
            bad += 1
print(seen, bad)
PY
)"
		seen="${verdict% *}"; bad="${verdict#* }"
		if [ "$seen" -ge 1 ] 2>/dev/null; then
			ladder ok "b4.L3  system:node:$n made $seen requests in the window (positive control)"
		else
			ladder no "b4.L3  system:node:$n made no request in the window — the audit command or the window is wrong (positive control)"
		fi
		if [ "$bad" = 0 ]; then
			ladder ok "b4.L3  system:node:$n made no cluster-wide secret/configmap list or watch"
		else
			ladder no "b4.L3  system:node:$n made $bad cluster-wide secret/configmap list/watch requests"
		fi
	done
fi
rm -f "$audit"

summary lab
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B4 GREEN (lab tier) ================"
