#!/usr/bin/env bash
# k3sm M10.3 ingress acceptance — Ingress hosting + IngressClass + LoadBalancer
# status (klipper-lite svclb, B32) against a RUNNING cluster.
#
# This gate BOOTS NOTHING itself: $KUBECONFIG must point at a live `k3sm server`
# that was started with the HIGH-PORT ingress listener — the integration tier:
#
#   k3sm server ... --ingress-http-port ${INGRESS_HTTP_PORT:-8080} \
#                   --ingress-https-port ${INGRESS_HTTPS_PORT:-8443}
#
# The privileged :80/:443 leg — the netd-authorized bind on the node InternalIP,
# granted because the canonical kube-system/k3sm-ingress LoadBalancer Service
# declares those ports — is the LAB slice (unprivileged _k3sm + root helper rig)
# and is deliberately NOT asserted here.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. the IngressClass k3sm (controller k3sm.io/ingress) is provisioned,
#   2. the canonical kube-system/k3sm-ingress LoadBalancer Service declares 80+443,
#   3. host+path routing: an Ingress (class k3sm) fronting a hello-http backend
#      answers on http://<nodeIP>:<port> with Host-header routing (+ a wrong-host
#      404 negative),
#   4. the Ingress status.loadBalancer.ingress carries the node InternalIP
#      (written only AFTER the listener is live — bind-then-advertise),
#   5. a plain type=LoadBalancer Service gets its status IP from svclb.
#
# Requires: kubectl, curl, go (builds the hello-http fixture), codesign (macOS).
# Usage: KUBECONFIG=/path/to/kubeconfig hack/acceptance/m10-ingress.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

INGRESS_HTTP_PORT="${INGRESS_HTTP_PORT:-8080}"
NS=default
HOST=ingress.test

if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at a RUNNING k3sm cluster started with --ingress-http-port $INGRESS_HTTP_PORT (this gate boots nothing itself)" >&2
	exit 1
fi
kc() { kubectl "$@"; }
kc get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
cleanup() {
	kc delete ingress m10-ing -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kc delete svc m10-ing-backend m10-lb -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kc delete pod m10-ing-backend -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

NODE_IP="$(kc get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
[ -n "$NODE_IP" ] || { echo "could not resolve the node InternalIP" >&2; exit 1; }
echo "==> k3sm M10.3 ingress acceptance (node $NODE_IP, http :$INGRESS_HTTP_PORT)"

# 1. The IngressClass k3sm is provisioned with the k3sm controller.
if [ "$(kc get ingressclass k3sm -o jsonpath='{.spec.controller}' 2>/dev/null)" = "k3sm.io/ingress" ]; then
	ladder ok "m10.3-1  IngressClass k3sm provisioned (controller k3sm.io/ingress)"
else
	ladder no "m10.3-1  IngressClass k3sm provisioned (controller k3sm.io/ingress)"
fi

# 2. The canonical LoadBalancer Service — the declaring subject for the
#    privileged 80/443 node-address bind — exists and declares both ports.
LB_PORTS="$(kc get svc k3sm-ingress -n kube-system -o jsonpath='{.spec.type} {.spec.ports[*].port}' 2>/dev/null || true)"
if [ "$LB_PORTS" = "LoadBalancer 80 443" ]; then
	ladder ok "m10.3-2  canonical kube-system/k3sm-ingress LoadBalancer declares 80+443"
else
	ladder no "m10.3-2  canonical kube-system/k3sm-ingress LoadBalancer declares 80+443 (got: ${LB_PORTS:-absent})"
fi

# 3. Host+path routing through the high-port listener. The backend is the e2e
#    hello-http fixture run as a native pod (built + ad-hoc-signed onto a
#    Seatbelt-admitted path, the m3.sh convention).
FIXTURE_BIN="${K3SM_CONFORMANCE_BIN:-/tmp/k3sm-conformance-bin}"
mkdir -p "$FIXTURE_BIN"; chmod 755 "$FIXTURE_BIN"
(cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$FIXTURE_BIN/hello-http" ./e2e/testdata/cmd/hello-http)
codesign -s - -f "$FIXTURE_BIN/hello-http" >/dev/null 2>&1 || true

kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: m10-ing-backend
  namespace: $NS
  labels: {app: m10-ing-backend}
spec:
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{operator: Exists}]
  containers:
  - name: web
    image: native
    command: ["$FIXTURE_BIN/hello-http", "--id", "m10-ingress-backend", "--addr", ":8080"]
    ports: [{containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: m10-ing-backend, namespace: $NS}
spec:
  selector: {app: m10-ing-backend}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: m10-ing, namespace: $NS}
spec:
  ingressClassName: k3sm
  rules:
  - host: $HOST
    http:
      paths:
      - path: /
        pathType: Prefix
        backend: {service: {name: m10-ing-backend, port: {number: 80}}}
EOF
kc wait --for=condition=Ready "pod/m10-ing-backend" -n "$NS" --timeout=120s >/dev/null

ROUTED=no
for _ in $(seq 1 30); do
	if [ "$(curl -fsS -m 5 -H "Host: $HOST" "http://$NODE_IP:$INGRESS_HTTP_PORT/" 2>/dev/null)" = "m10-ingress-backend" ]; then
		ROUTED=yes; break
	fi
	sleep 2
done
if [ "$ROUTED" = yes ]; then
	ladder ok "m10.3-3a host+path routing on :$INGRESS_HTTP_PORT (Host: $HOST -> backend identity)"
else
	ladder no "m10.3-3a host+path routing on :$INGRESS_HTTP_PORT (Host: $HOST -> backend identity)"
fi
# Negative: a host no Ingress rule claims must 404 at the router, not route.
WRONG_CODE="$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "Host: nobody.test" "http://$NODE_IP:$INGRESS_HTTP_PORT/" 2>/dev/null || true)"
if [ "$WRONG_CODE" = "404" ]; then
	ladder ok "m10.3-3b unclaimed host answers 404 (no default backend invented)"
else
	ladder no "m10.3-3b unclaimed host answers 404 (got HTTP ${WRONG_CODE:-none})"
fi

# 4. The Ingress status carries the node InternalIP (bind-then-advertise: it is
#    written only once the listener is live, which 3a just proved).
ING_IP=""
for _ in $(seq 1 15); do
	ING_IP="$(kc get ingress m10-ing -n "$NS" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
	[ -n "$ING_IP" ] && break
	sleep 2
done
if [ "$ING_IP" = "$NODE_IP" ]; then
	ladder ok "m10.3-4  Ingress status.loadBalancer.ingress = node InternalIP"
else
	ladder no "m10.3-4  Ingress status.loadBalancer.ingress = node InternalIP (got '${ING_IP:-}')"
fi

# 5. svclb: a plain type=LoadBalancer Service gets its status IP once the
#    nodeIP:port listener is bound (klipper-lite honesty: bind THEN advertise).
kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: m10-lb, namespace: $NS}
spec:
  type: LoadBalancer
  selector: {app: m10-ing-backend}
  ports: [{port: 18080, targetPort: 8080}]
EOF
LB_IP=""
for _ in $(seq 1 15); do
	LB_IP="$(kc get svc m10-lb -n "$NS" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
	[ -n "$LB_IP" ] && break
	sleep 2
done
if [ "$LB_IP" = "$NODE_IP" ]; then
	ladder ok "m10.3-5a LoadBalancer Service status IP set by svclb"
else
	ladder no "m10.3-5a LoadBalancer Service status IP set by svclb (got '${LB_IP:-}')"
fi
if [ "$(curl -fsS -m 5 "http://$NODE_IP:18080/" 2>/dev/null)" = "m10-ingress-backend" ]; then
	ladder ok "m10.3-5b svclb splice nodeIP:18080 -> ClusterIP VIP -> backend"
else
	ladder no "m10.3-5b svclb splice nodeIP:18080 -> ClusterIP VIP -> backend"
fi

echo "----------------------------------------"
echo "M10.3 ingress: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "=========== M10.3 INGRESS GREEN ==========="
