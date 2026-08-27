#!/usr/bin/env bash
# k3sm M1 acceptance gate — the runnable proof of `k3sm server` + images +
# Services + DNS (DESIGN §9 M1). It brings the FULL stack up via the M1 path
# (`go run ./cmd/k3sm server` — the child-process control-plane executor + the
# Virtual Kubelet node in one process), then asserts the three M1 exit criteria:
#
#   1. a native image runs (image -> Running),
#   2. kubectl expose -> a ClusterIP Service (allocated + EndpointSlice populated
#      by the KEPT endpointslice controller, reconciled by the Service proxy),
#   3. the cluster DNS Service is provisioned for CoreDNS to resolve.
#
# Exit 0 iff every check passes. Mirrors hack/acceptance/m0.sh.
#
# Usage: hack/acceptance/m1.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../lib/clusterup.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
cleanup() {
	kc delete pod m1-web -n default --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kc delete svc m1-web -n default --ignore-not-found --wait=false >/dev/null 2>&1 || true
	cluster_down
}
trap cleanup EXIT

echo "==> k3sm M1 acceptance (k3sm server: embedded-by-supervision control plane + node)"
server_up k3sm-m1 hostprocess

# M1.1 — the control plane the executor brought up is serving.
if [ "$(kc get --raw /healthz 2>/dev/null)" = "ok" ]; then
	ladder ok "m1.1  k3sm server control plane healthy (/healthz ok)"
else
	ladder no "m1.1  k3sm server control plane healthy (/healthz ok)"
fi

# KCM scoping — the endpointslice controller is enabled (M1.4 depends on it),
# node-side controllers dropped. We verify behaviorally via the e2e endpoint
# assertion below; here we just confirm the controller-manager is alive.
if pgrep -f "$SERVER_WORKDIR/bin/kube-controller-manager" >/dev/null 2>&1; then
	ladder ok "m1.1  controller-manager running (scoped --controllers)"
else
	ladder no "m1.1  controller-manager running (scoped --controllers)"
fi

# M1.2/M1.3/M1.4 — the typed e2e suite drives image->Running, expose->ClusterIP
# (+EndpointSlice), and the DNS Service check against the live `k3sm server`.
# The -run pattern is ANCHORED. `-run TestM1` is a REGEX, not a prefix match, so it
# also selects every TestM10_* test in the suite -- which is how this gate came to
# fail on M10 audit/PSA criteria it does not own and cannot satisfy (they need a
# default ServiceAccount this bring-up has not created). Anchor any gate's -run.
if ( cd "$REPO_ROOT" && CGO_ENABLED=1 go test -tags e2e -run '^TestM1$' -timeout 300s ./e2e/... ); then
	ladder ok "m1.A  image->Running + expose->ClusterIP + DNS Service (e2e TestM1)"
else
	ladder no "m1.A  image->Running + expose->ClusterIP + DNS Service (e2e TestM1)"
fi

# M1.2 — the os=darwin admission policy rejects a non-darwin pod (intent guard).
if kc apply -f - >/dev/null 2>&1 <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: m1-linux-reject, namespace: default}
spec:
  tolerations: [{operator: Exists}]
  containers: [{name: c, image: native, command: ["/usr/bin/true"]}]
EOF
then
	kc delete pod m1-linux-reject -n default --ignore-not-found --wait=false >/dev/null 2>&1 || true
	ladder no "m1.2  non-os=darwin pod rejected by admission"
else
	ladder ok "m1.2  non-os=darwin pod rejected by admission"
fi

echo "----------------------------------------"
echo "M1: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M1 GREEN ================"
