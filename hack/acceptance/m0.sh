#!/usr/bin/env bash
# k3sm M0 acceptance gate — the runnable proof of the walking skeleton (DESIGN §9 M0,
# docs/M0-node.md): a kubectl-applied Pod runs as a native macOS process on a real
# Virtual Kubelet node, and `kubectl delete` kills the process group. Exit 0 iff every
# check passes. This is what /orchestrate runs to confirm M0 (already done — re-greens it).
#
# Usage: hack/acceptance/m0.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../lib/clusterup.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
cleanup() { kc delete pod hello-native -n default --ignore-not-found --wait=false >/dev/null 2>&1 || true; cluster_down; }
trap cleanup EXIT

echo "==> k3sm M0 acceptance"
cluster_up
node_up k3sm-m0

# Core pod assertions live in the typed e2e suite (apply -> Running -> native process -> delete).
if ( cd "$REPO_ROOT" && CGO_ENABLED=0 go test -tags e2e -run TestM0 ./e2e/... ); then
	ladder ok "m0.A  native pod runs + deletes (e2e TestM0)"
else
	ladder no "m0.A  native pod runs + deletes (e2e TestM0)"
fi

# The node stayed Ready through it all.
if [ "$(kc get node k3sm-m0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "True" ]; then
	ladder ok "m0.B  node stays Ready"
else
	ladder no "m0.B  node stays Ready"
fi

echo "----------------------------------------"
echo "M0: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M0 GREEN ================"
