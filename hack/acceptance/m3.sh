#!/usr/bin/env bash
# k3sm M3 INTEGRATION gate (single node) — the CI-runnable slice of M3: a NodePort
# Service is reachable on *:nodePort, and a StatefulSet+PVC's data survives a pod
# restart. Both are single-node-testable, so unlike the two-Mac mesh/DNS criteria
# they run here (not only in the lab).
#
# This is DISTINCT from hack/lab/m3.sh, which owns the CROSS-NODE criteria
# (in-pod kubectl + cluster DNS from a pod on the JOINED worker) and runs only on a
# two-Mac rig under K3SM_LAB=1. Splitting them gives the single-node-testable M3
# assertions a home that actually executes in CI rather than skip-greening.
#
# Bring-up: a single-node `k3sm server` with the runtimed runtime + the DIRECT
# host-network datapath (`server_up <node> runtimed direct`). NodePort needs a real
# datapath: the userspace Service proxy binds the wildcard *:nodePort listener
# directly (>=1024; NOT via the netd helper, which rejects wildcards) and pods get
# routable lo0 IPs so EndpointSlices populate — neither happens under
# `--network none`. The direct datapath is root-gated, so this gate requires root
# (like hack/acceptance/m2.sh); the helper path (`sudo k3sm install`) is the other
# datapath posture but the direct path keeps the gate self-contained.
#
# Tier: integration (dev Mac + root). Exit 0 iff every check passes.
#
# Usage: sudo hack/acceptance/m3.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../lib/clusterup.sh"
. "$HERE/../lib/conformance.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
cleanup() { cluster_down; }
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
	echo "M3 integration gate requires root for the --network direct datapath (NodePort + routable pod IPs) — run: sudo $0" >&2
	exit 1
fi

echo "==> k3sm M3 integration gate (single node: k3sm server --runtime runtimed --network direct)"
server_up k3sm-m3 runtimed direct

# m3.1 — the control plane the executor brought up is serving.
if [ "$(kc get --raw /healthz 2>/dev/null)" = "ok" ]; then
	ladder ok "m3.1  k3sm server control plane healthy (/healthz ok)"
else
	ladder no "m3.1  k3sm server control plane healthy (/healthz ok)"
fi

# m3.A — the single-node-testable M3 conformance criteria, scoped by -run so the
# cross-node worker criterion (TestM3_InPodKubectlAndDNSOnWorker) is NOT required
# here (it is lab-only and would skip without $K3SM_WORKER — the lab gate runs it).
# The non-vacuous guard turns a missing/failed/skipped required criterion RED.
#
# The conformance helper binaries (e2e/testdata/cmd) are built+ad-hoc-signed by the
# suite's TestMain into $K3SM_CONFORMANCE_BIN; it must be world-readable and on a
# path the default-deny Seatbelt profile admits for exec. OPEN INTEGRATION ITEM:
# the profile-admitted path is validated on a dev Mac; /tmp is the default.
export K3SM_CONFORMANCE_BIN="/tmp/k3sm-conformance-bin"
mkdir -p "$K3SM_CONFORMANCE_BIN"; chmod 755 "$K3SM_CONFORMANCE_BIN"
M3_CRITERIA=(M3_NodePort M3_PVCPersistsAcrossRestart)
if run_conformance_slice "$REPO_ROOT" 'TestM3_(NodePort|PVCPersistsAcrossRestart)$' 900s "${M3_CRITERIA[@]}"; then
	ladder ok "m3.A  M3 single-node conformance (NodePort reachable + PVC persists across restart)"
else
	ladder no "m3.A  M3 single-node conformance (a required criterion missing, failed, or skipped)"
fi

echo "----------------------------------------"
echo "M3 (integration): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "============ M3 INTEGRATION GREEN ============"
