#!/usr/bin/env bash
# k3sm M3 lab gate — the runnable proof of multi-node, mesh, NodePort & persistent
# storage (DESIGN §9 M3) on a TWO-MAC rig. Unlike the single-host m0/m1/m2 gates,
# M3 needs two machines (a control-plane Mac + a joined worker Mac), so this gate
# is manual: true / requires two-macs in hack/acceptance/phases.json and runs ONLY
# under K3SM_LAB=1. The orchestrator reports it "pending lab" (never auto-green)
# when K3SM_LAB is unset; a direct run without it is a no-op skip.
#
# It asserts the three M3 exit behaviors, from a host with the admin KUBECONFIG:
#   (a) M3.1 — a NodePort Service is reachable on *:nodePort,
#   (b) M3.2 — a StatefulSet+PVC writes data, the pod restarts, the SAME data is
#       present (persistence across restart, ReclaimPolicy Retain),
#   (c) M3.3 — in-pod kubectl AND cluster DNS work from a pod on the JOINED
#       (non-control-plane) node: the pod resolves kubernetes.default.svc to the
#       node-local API VIP (10.43.0.1, proxy-owned + mesh-forwarded) and a Service
#       name to its ClusterIP via the per-node CoreDNS on 10.43.0.10, and reaches
#       /healthz — proving the infra VIPs are answered node-locally and never
#       blackholed over the wireguard mesh.
#
# The cross-host data path (a NodePort reached from the worker, a cross-node dial
# sourced from the mesh-egress /32, in-pod resolution on the worker) is exercised
# by the typed TestM3 e2e suite (./e2e, build tag e2e), which this gate runs with
# the worker node pinned via $K3SM_WORKER. The vacuous green is GUARDED: an
# absent/empty TestM3 (no tests matched) FAILS the gate rather than false-greening.
#
# Prerequisites (manual two-Mac setup, NOT done here):
#   - control-plane Mac:  sudo k3sm install server --mesh-ip <cp-mesh-ip>
#   - worker Mac:         sudo k3sm install agent --server <cp-mesh-ip> \
#                             --token <join-token> --node-ip <worker-mesh-ip>
#   - this host has the admin kubeconfig exported as $KUBECONFIG.
#
# Tier: lab (two-macs). Exit 0 iff every check passes (or skipped pending lab).
#
# Usage: K3SM_LAB=1 KUBECONFIG=~/.kube/config [K3SM_WORKER=<node>] hack/lab/m3.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/../lib/conformance.sh"

# ── Lab guard: only run under K3SM_LAB=1 (a real two-Mac rig). ────────────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M3 lab gate: PENDING (two-macs). Set K3SM_LAB=1 on a two-Mac rig to run; this is NOT a pass."
	exit 0
fi

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"
export KUBECONFIG="$KUBECONFIG_PATH"

if ! command -v kubectl >/dev/null 2>&1; then
	echo "M3 lab gate requires kubectl on PATH (the admin client for the running cluster)" >&2
	exit 1
fi

echo "==> k3sm M3 lab gate (two Macs: control plane + joined worker; KUBECONFIG=$KUBECONFIG_PATH)"

# m3.0 — the cluster is multi-node: at least two Ready nodes (control plane + a
# joined worker). Identify the worker (the node to pin the M3.3 pod onto): an
# explicit $K3SM_WORKER wins; else pick a Ready node whose name differs from this
# host's k3sm node name (the control plane runs `k3sm server` here).
ready_nodes="$(kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{print $1}')"
node_count="$(printf '%s\n' "$ready_nodes" | grep -c . || true)"
if [ "$node_count" -ge 2 ]; then
	ladder ok "m3.0  multi-node cluster ($node_count Ready nodes)"
else
	ladder no "m3.0  multi-node cluster (need >=2 Ready nodes, got $node_count) — join a worker Mac first"
	echo "M3: no worker joined — aborting"; echo "M3: $PASS passed, $FAIL failed"; exit 1
fi

WORKER="${K3SM_WORKER:-}"
if [ -z "$WORKER" ]; then
	cp_node="k3sm-$(hostname -s | tr '[:upper:]' '[:lower:]')"
	WORKER="$(printf '%s\n' "$ready_nodes" | grep -v -x "$cp_node" | head -n1 || true)"
fi
if [ -n "$WORKER" ] && printf '%s\n' "$ready_nodes" | grep -qx "$WORKER"; then
	ladder ok "m3.0  joined worker identified: $WORKER (pass K3SM_WORKER to override)"
else
	ladder no "m3.0  could not identify a joined worker node (set K3SM_WORKER=<node>)"
	echo "M3: $PASS passed, $FAIL failed"; exit 1
fi
export K3SM_WORKER="$WORKER"

# m3.A — the full M3 conformance suite, pinned to the joined worker via $K3SM_WORKER.
# REQUIRED criteria (the non-vacuous guard turns a missing/failed/skipped one RED):
#   TestM3_NodePort                   (a) Deployment behind a NodePort reachable on *:nodePort
#   TestM3_PVCPersistsAcrossRestart   (b) StatefulSet+PVC: write -> restart -> same data
#   TestM3_InPodKubectlAndDNSOnWorker (c) on the WORKER: cluster DNS + in-pod kubectl to the node-local API VIP
# (a)+(b) also run single-node in hack/acceptance/m3.sh; (c) is two-Mac-only here.
#
# The conformance helper binaries (e2e/testdata/cmd) are built+ad-hoc-signed by the
# suite's TestMain into $K3SM_CONFORMANCE_BIN on THIS host. NOTE: native pods exec a
# host binary path, so the WORKER criterion requires the SAME helper binary to be
# pre-staged on the worker Mac at the same $K3SM_CONFORMANCE_BIN path (there is no
# image distribution); stage it before running this gate.
export K3SM_CONFORMANCE_BIN="${K3SM_CONFORMANCE_BIN:-/tmp/k3sm-conformance-bin}"
mkdir -p "$K3SM_CONFORMANCE_BIN"; chmod 755 "$K3SM_CONFORMANCE_BIN"
M3_CRITERIA=(M3_NodePort M3_PVCPersistsAcrossRestart M3_InPodKubectlAndDNSOnWorker)
if run_conformance_slice "$REPO_ROOT" "TestM3" 900s "${M3_CRITERIA[@]}"; then
	ladder ok "m3.A  M3 conformance suite (NodePort, PVC persistence, in-pod kubectl + cluster DNS on the joined worker)"
else
	ladder no "m3.A  M3 conformance suite (a required criterion missing, failed, or skipped)"
fi

echo "----------------------------------------"
echo "M3: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M3 GREEN ================"
