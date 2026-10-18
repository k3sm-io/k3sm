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
# declares those ports — is asserted when the gate runs at the privileged ports
# on the rig (INGRESS_HTTP_PORT=80 INGRESS_HTTPS_PORT=443, the server started
# without the high-port flags). The address probed is the node that serves the
# ingress listener: the one the k3sm-ingress LoadBalancer status names, else the
# control-plane node.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. the IngressClass k3sm (controller k3sm.io/ingress) is provisioned,
#   2. the canonical kube-system/k3sm-ingress LoadBalancer Service declares 80+443,
#   3. host+path routing: an Ingress (class k3sm) fronting a hello-http backend
#      answers on http://<nodeIP>:<port> with Host-header routing (+ a wrong-host
#      404 negative),
#   4. the Ingress status.loadBalancer.ingress carries the node InternalIP
#      (written only AFTER the listener is live — bind-then-advertise),
#   5. a plain type=LoadBalancer Service gets its status IP from svclb,
#   6. TLS-from-Secret terminates on :$INGRESS_HTTPS_PORT (throwaway self-signed
#      cert in a kubernetes.io/tls Secret named by the Ingress tls[] entry).
#
# The backend is the shell responder the M10 e2e tests use (a /usr/bin/nc loop
# in a native pod, no fixture binary), pinned to the serving node.
#
# Requires: kubectl, curl, openssl.
# Usage: KUBECONFIG=/path/to/kubeconfig hack/acceptance/m10-ingress.sh
#        hack/acceptance/m10-ingress.sh --self-test   # render + check the backend pod, no cluster
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

INGRESS_HTTP_PORT="${INGRESS_HTTP_PORT:-8080}"
INGRESS_HTTPS_PORT="${INGRESS_HTTPS_PORT:-8443}"
NS=default
HOST=ingress.test
BACKEND_ID=m10-ingress-backend

# shellcheck source=../lab/lib/tolerations.sh
. "$HERE/../lab/lib/tolerations.sh"

# backend_pod <node> - the backend pod: the e2e shell responder, pinned to the
# node, the darwin nodeSelector, and the helper's tolerations (never Exists-only).
backend_pod() {
	local tols
	tols="$(lab_tolerations_yaml NoSchedule)" || return 1
	cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: m10-ing-backend
  namespace: $NS
  labels: {app: m10-ing-backend}
spec:
  nodeName: $1
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$tols]
  containers:
  - name: web
    image: native
    command:
    - /bin/sh
    - -c
    - |
      while :; do printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: ${#BACKEND_ID}\\r\\nConnection: close\\r\\n\\r\\n$BACKEND_ID' | /usr/bin/nc -l "\$K3SM_POD_IP" 8080 >/dev/null 2>&1 || sleep 1; done
    ports: [{containerPort: 8080}]
EOF
}

if [ "${1:-}" = "--self-test" ]; then
	st=0
	chk() { if [ "$1" = ok ]; then echo "ok   $2"; else echo "FAIL $2"; st=1; fi; }
	out="$(K3SM_LAB_TOLERATE_KEYS="example.com/estate-off" backend_pod node-x)"
	echo "$out" | grep -q '^  nodeName: node-x$' && chk ok "nodeName pinned" || chk no "nodeName pinned"
	echo "$out" | grep -q '^  nodeSelector: {kubernetes.io/os: darwin}$' && chk ok "darwin nodeSelector" || chk no "darwin nodeSelector"
	echo "$out" | grep -q 'key: k3sm.io/provider, operator: Exists, effect: NoSchedule' && chk ok "helper provider toleration" || chk no "helper provider toleration"
	echo "$out" | grep -q 'key: example.com/estate-off, operator: Exists' && chk ok "helper extra-key toleration" || chk no "helper extra-key toleration"
	if echo "$out" | grep -E '^  tolerations:' | grep -Eq '\[\{operator: Exists\}|, \{operator: Exists\}'; then chk no "no Exists-only toleration"; else chk ok "no Exists-only toleration"; fi
	echo "$out" | grep -q 'nc -l "\$K3SM_POD_IP" 8080' && chk ok "responder binds the pod IP" || chk no "responder binds the pod IP"
	if echo "$out" | grep -q '/tmp'; then chk no "no /tmp path"; else chk ok "no /tmp path"; fi
	exit "$st"
fi

if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at a RUNNING k3sm cluster started with --ingress-http-port $INGRESS_HTTP_PORT (this gate boots nothing itself)" >&2
	exit 1
fi
kc() { kubectl "$@"; }
kc get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
TLS_DIR=""
cleanup() {
	[ -z "$TLS_DIR" ] || rm -rf "$TLS_DIR"
	kc delete secret m10-ing-tls -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kc delete ingress m10-ing -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kc delete svc m10-ing-backend m10-lb -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kc delete pod m10-ing-backend -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The node serving the ingress listener: the one the canonical LoadBalancer
# status names, else the control-plane node. Never .items[0].
LB_STATUS_IP="$(kc get svc k3sm-ingress -n kube-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
NODE_NAME=""
if [ -n "$LB_STATUS_IP" ]; then
	NODE_NAME="$(kc get nodes -o jsonpath="{range .items[?(@.status.addresses[*].address==\"$LB_STATUS_IP\")]}{.metadata.name}{end}" 2>/dev/null || true)"
fi
if [ -z "$NODE_NAME" ]; then
	NODE_NAME="$(kc get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
fi
[ -n "$NODE_NAME" ] || { echo "could not resolve the node serving the ingress listener" >&2; exit 1; }
NODE_IP="$(kc get node "$NODE_NAME" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
[ -n "$NODE_IP" ] || { echo "could not resolve the InternalIP of node $NODE_NAME" >&2; exit 1; }
echo "==> k3sm M10.3 ingress acceptance (node $NODE_NAME $NODE_IP, http :$INGRESS_HTTP_PORT, https :$INGRESS_HTTPS_PORT)"

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

# 3. Host+path routing through the ingress listener. The backend is the e2e
#    shell responder run as a native pod pinned to the serving node.
backend_pod "$NODE_NAME" | kc apply -f - >/dev/null
kc apply -f - >/dev/null <<EOF
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
	if [ "$(curl -fsS -m 5 -H "Host: $HOST" "http://$NODE_IP:$INGRESS_HTTP_PORT/" 2>/dev/null)" = "$BACKEND_ID" ]; then
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
if [ "$(curl -fsS -m 5 "http://$NODE_IP:18080/" 2>/dev/null)" = "$BACKEND_ID" ]; then
	ladder ok "m10.3-5b svclb splice nodeIP:18080 -> ClusterIP VIP -> backend"
else
	ladder no "m10.3-5b svclb splice nodeIP:18080 -> ClusterIP VIP -> backend"
fi

# 6. TLS from a Secret terminates (M10.3-a1): a throwaway self-signed pair for
#    the test host in a kubernetes.io/tls Secret, named by the Ingress tls[]
#    entry; SNI on the https port must serve exactly that certificate and route
#    to the backend. The ingress terminates TLS only for hosts a tls[] entry names.
TLS_DIR="$(mktemp -d)"
cat >"$TLS_DIR/req.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $HOST
[ext]
subjectAltName = DNS:$HOST
EOF
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
	-config "$TLS_DIR/req.cnf" -keyout "$TLS_DIR/tls.key" -out "$TLS_DIR/tls.crt" >/dev/null 2>&1
kc create secret tls m10-ing-tls -n "$NS" --cert="$TLS_DIR/tls.crt" --key="$TLS_DIR/tls.key" >/dev/null
kc patch ingress m10-ing -n "$NS" --type merge \
	-p "{\"spec\":{\"tls\":[{\"hosts\":[\"$HOST\"],\"secretName\":\"m10-ing-tls\"}]}}" >/dev/null
TLS_BODY=""
for _ in $(seq 1 30); do
	TLS_BODY="$(curl -fsS -m 5 --cacert "$TLS_DIR/tls.crt" --resolve "$HOST:$INGRESS_HTTPS_PORT:$NODE_IP" "https://$HOST:$INGRESS_HTTPS_PORT/" 2>/dev/null || true)"
	[ "$TLS_BODY" = "$BACKEND_ID" ] && break
	sleep 2
done
TLS_SUBJECT="$(echo | openssl s_client -connect "$NODE_IP:$INGRESS_HTTPS_PORT" -servername "$HOST" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)"
if [ "$TLS_BODY" = "$BACKEND_ID" ] && printf '%s' "$TLS_SUBJECT" | grep -q "CN *= *$HOST"; then
	ladder ok "m10.3-6  TLS from Secret terminates on :$INGRESS_HTTPS_PORT (SNI $HOST serves the Secret's cert, backend identity)"
else
	ladder no "m10.3-6  TLS from Secret terminates on :$INGRESS_HTTPS_PORT (body '${TLS_BODY:-}', subject '${TLS_SUBJECT:-none}')"
fi

echo "----------------------------------------"
echo "M10.3 ingress: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "=========== M10.3 INGRESS GREEN ==========="
