#!/usr/bin/env bash
# k3sm M4 INTEGRATION gate — the live RBAC-enforcement flip (M4.1). It brings up a
# single-node `k3sm server`, whose apiserver defaults to
# --authorization-mode=Node,RBAC + NodeRestriction since M4.1, and whose
# pkg/rbac.Provision laid down the node-datapath ClusterRole + the in-pod-reader
# RoleBinding fail-closed at start. It then runs the build-tagged
# e2e/TestM4_RBACEnforced criterion, proving live authorization:
#   - a restricted ServiceAccount (the in-pod-reader SA) is AUTHORIZED its granted
#     read yet DENIED what it was not granted (secrets);
#   - the joined-worker system:node leg runs only on a multi-node bring-up with the
#     signing CA on disk (it SKIPS single-node here — covered by hack/lab/m3.sh).
#
# This is the RBAC/conformance INTEGRATION slice, split out from the packaging /
# launchd lab gate (hack/lab/m4.sh, the M4-lab row in phases.json) so M4.1's live
# authz assertion has a CI-runnable home rather than riding the two-Mac lab. It
# needs NO root: TestM4_RBACEnforced is SelfSubjectAccessReviews + a token mint +
# API calls, no pods/datapath. The full M4.1-a1 verdict (incl. the system:node leg)
# is the multi-node lab; this gate proves the SA half live in CI.
#
# Tier: integration (dev Mac, no root). Exit 0 iff every check passes.
#
# Usage: hack/acceptance/m4.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../lib/clusterup.sh"
. "$HERE/../lib/conformance.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
cleanup() { cluster_down; }
trap cleanup EXIT

echo "==> k3sm M4 integration gate (k3sm server, --authorization-mode=Node,RBAC default since M4.1)"
server_up k3sm-m4 hostprocess

# m4.1 — the control plane (Node,RBAC authorizer) is serving and pkg/rbac.Provision
# ran fail-closed before the node started, so the RBAC graph already exists.
if [ "$(kc get --raw /healthz 2>/dev/null)" = "ok" ]; then
	ladder ok "m4.1  k3sm server control plane healthy under Node,RBAC (/healthz ok)"
else
	ladder no "m4.1  k3sm server control plane healthy under Node,RBAC (/healthz ok)"
fi

# m4.A — the live RBAC-enforcement criterion. The non-vacuous guard turns a missing
# or failed criterion RED; the system:node subtest skips single-node (covered by
# the lab gate) without failing the parent.
M4_CRITERIA=(M4_RBACEnforced)
if run_conformance_slice "$REPO_ROOT" "TestM4_RBACEnforced" 300s "${M4_CRITERIA[@]}"; then
	ladder ok "m4.A  RBAC enforced live (restricted SA: granted read allowed, secrets denied)"
else
	ladder no "m4.A  RBAC enforced live (TestM4_RBACEnforced missing or failed)"
fi

echo "----------------------------------------"
echo "M4 (integration): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "============ M4 INTEGRATION GREEN ============"
