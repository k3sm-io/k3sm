#!/usr/bin/env bash
# k3sm gate: multi-node ServiceLB with node pools.
#
# TWO TIERS:
#
#   INTEGRATION (default; a dev Mac, NO root). Boots a single-node `k3sm server`
#   (hostprocess runtime, --network none, so no svclb hoster runs) on off-default
#   ports, so it can run beside an installed node: apiserver :6458, kine :2398,
#   kubelet :10356, scheduler :10368, controller-manager :10366 (the B416_*_PORT
#   knobs override each). Then it runs e2e/TestNodePoolSelection, the report
#   channel proof against a real apiserver (Node,RBAC + NodeRestriction):
#     i.1  system:node:<X> may merge-patch svclb.k3sm.io/bound on Node X;
#     i.2  the same identity is denied that patch on another Node, and denied
#          any write to a Service (stamp or status);
#     i.3  the node's own status heartbeat leaves the annotation intact.
#   Without K3SM_LAB=1 the gate then reports LAB-PENDING and exits 3.
#
#   LAB (K3SM_LAB=1). Runs against the RUNNING two-node cluster in $KUBECONFIG and
#   boots nothing. The driver has already installed the build under test
#   AGENT FIRST, SERVER LAST (the deploy contract's order), polled the join port
#   before the agent rejoin, and re-copied the kubeconfig. Required:
#     K3SM_B416_SERVER_NODE   the server's node name
#     K3SM_B416_WORKER_NODE   the joined worker's node name
#     K3SM_B416_SERVER_SSH    ssh destination of the server Mac
#     K3SM_B416_WORKER_SSH    ssh destination of the worker Mac
#   Optional:
#     K3SM_B416_EVIDENCE      evidence directory (default: a new mktemp dir)
#     KUBECTL                 kubectl binary (default kubectl)
#     K3SM_LAB_TOLERATE_KEYS  extra taint keys every lab pod tolerates, space-separated
#                             (hack/lab/lib/tolerations.sh)
#     K3SM_LAB_PRINT_MANIFESTS=1  print the pod manifests and exit; contacts nothing
#   Legs (every Service in namespace default, every label removed at the end):
#     l.3  Service lb-a (port 18080, no labels): ingress lists both nodes' mesh
#          addresses, and each address serves the backend from the OTHER Mac;
#     l.4  server labelled svclb.k3sm.io/enablelb=true: ingress drops to the
#          server, and the worker holds no wildcard (LoadBalancer) listener on
#          18080 (its ClusterIP listener on the Service VIP is not counted);
#     l.5  server in pool blue (multi-pool form), worker in pool green (single
#          form): lb-blue and lb-green, both on 18081, are each hosted on one Mac;
#     l.6  a plain process holds 18082 on the worker: lb-c (18082) lists the
#          server only, the worker's svclb.k3sm.io/bound lacks lb-c, and a
#          HostNotBound Event names the worker;
#     l.7  two unlabelled Services on 18083: no node is listed for both;
#     l.8  `kubectl auth can-i patch services/status` as the worker's node
#          identity answers no (no grant was widened).
#
# Exit: 0 all green (lab tier), 1 a failure, 2 a lab precondition refused the
# run, 3 integration green with the lab tier owed.
#
# Usage:  hack/lab/b416.sh                       # integration tier
#         K3SM_LAB=1 K3SM_B416_SERVER_NODE=node-a K3SM_B416_WORKER_NODE=node-b \
#           K3SM_B416_SERVER_SSH=node-a.example K3SM_B416_WORKER_SSH=node-b.example \
#           hack/lab/b416.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/tolerations.sh
. "$HERE/lib/tolerations.sh"
# The backend tolerates the provider taint of every effect (no effect: field).
LAB_TOLERATIONS="$(lab_tolerations_yaml "")" || exit 2

# backend_pod <namespace> <node>: the backend's manifest. A native pod pinned to
# the server, answering "b416" on 8080; the responder ships inline (a native pod
# cannot read files under /tmp).
backend_pod() {
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: b416-backend, namespace: $1, labels: {app: b416-backend}}
spec:
  nodeName: $2
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$LAB_TOLERATIONS]
  containers:
  - name: web
    image: native
    command: ["/bin/sh", "-c", "while true; do printf 'HTTP/1.0 200 OK\\\\r\\\\nContent-Length: 5\\\\r\\\\n\\\\r\\\\nb416\\\\n' | /usr/bin/nc -l 8080 >/dev/null; done"]
    ports: [{containerPort: 8080}]
EOF
}

if [ "${K3SM_LAB_PRINT_MANIFESTS:-}" = 1 ]; then
	lab_tolerations_header
	backend_pod default "<server-node>"
	exit 0
fi

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
summary() {
	echo "----------------------------------------"
	echo "multi-node ServiceLB ($1): $PASS passed, $FAIL failed"
}

if [ "${K3SM_LAB:-}" != 1 ]; then
	# ---- INTEGRATION tier ---------------------------------------------------
	APISERVER_PORT="${B416_API_PORT:-6458}"
	KINE_PORT="${B416_KINE_PORT:-2398}"
	SCHEDULER_PORT="${B416_SCHEDULER_PORT:-10368}"
	CONTROLLER_MANAGER_PORT="${B416_CONTROLLER_MANAGER_PORT:-10366}"
	: "${K3SM_WORKDIR:=/tmp/k3sm-b416}"
	. "$HERE/../lib/clusterup.sh"
	. "$HERE/../lib/conformance.sh"
	: "${B416_NODE_NAME:=k3sm-b416}"
	: "${B416_KUBELET_PORT:=10356}"
	trap cluster_down EXIT
	echo "==> k3sm integration gate (single-node k3sm server; node $B416_NODE_NAME on :$B416_KUBELET_PORT)"
	server_up "$B416_NODE_NAME" hostprocess none "" "$B416_KUBELET_PORT"
	# The leg mints the node identity from this cluster's signing CA.
	export K3SM_WORK_DIR="$SERVER_WORKDIR"
	export K3SM_B416_NODE="$B416_NODE_NAME"
	if run_conformance_slice "$REPO_ROOT" '^TestNodePoolSelection$' 600s NodePoolSelection; then
		ladder ok "b416.I  report channel: own Node patch allowed, other Node and Services denied, intact across the heartbeat (i.1-i.3)"
	else
		ladder no "b416.I  report channel: own Node patch allowed, other Node and Services denied, intact across the heartbeat (i.1-i.3)"
	fi
	summary integration
	[ "$FAIL" -eq 0 ] || exit 1
	echo "integration tier GREEN"
	echo "LAB-PENDING: lab legs not run (set K3SM_LAB=1)"
	exit 3
fi

# ---- LAB tier -----------------------------------------------------------------
missing=""
for v in KUBECONFIG K3SM_B416_SERVER_NODE K3SM_B416_WORKER_NODE K3SM_B416_SERVER_SSH K3SM_B416_WORKER_SSH; do
	[ -n "${!v:-}" ] || missing="$missing $v"
done
if [ -n "$missing" ]; then
	echo "lab tier: required variable(s) unset:$missing (see the header of $0)" >&2
	exit 2
fi
KUBECTL="${KUBECTL:-kubectl}"
SERVER="$K3SM_B416_SERVER_NODE"
WORKER="$K3SM_B416_WORKER_NODE"
EVIDENCE="${K3SM_B416_EVIDENCE:-$(mktemp -d -t b416-evidence)}"
mkdir -p "$EVIDENCE"
NS=default
kc() { "$KUBECTL" "$@"; }
# Remote commands need a login shell on the lab Macs.
on() { local host="$1"; shift; ssh -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"; }

kc get --raw /healthz >/dev/null || { echo "the cluster at \$KUBECONFIG is not serving" >&2; exit 2; }
for n in "$SERVER" "$WORKER"; do
	ready="$(kc get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
	[ "$ready" = True ] || { echo "lab tier: node $n is not Ready (got '${ready:-absent}')" >&2; exit 2; }
done
mesh_ip() { kc get meshpeers.net.k3sm.io "$1" -o jsonpath='{.spec.meshIP}'; }
SERVER_IP="$(mesh_ip "$SERVER")"
WORKER_IP="$(mesh_ip "$WORKER")"
[ -n "$SERVER_IP" ] && [ -n "$WORKER_IP" ] || { echo "lab tier: a MeshPeer mesh address is missing (server '$SERVER_IP', worker '$WORKER_IP')" >&2; exit 2; }
echo "==> k3sm lab tier (server $SERVER @ $SERVER_IP, worker $WORKER @ $WORKER_IP; evidence $EVIDENCE)"
lab_tolerations_header

PORT_HOLDER_PID=""
cleanup() {
	set +e
	kc delete svc -n "$NS" lb-a lb-blue lb-green lb-c lb-d1 lb-d2 --ignore-not-found >/dev/null 2>&1
	kc delete pod -n "$NS" b416-backend --ignore-not-found >/dev/null 2>&1
	kc label node "$SERVER" svclb.k3sm.io/enablelb- lbpool.svclb.k3sm.io/blue- >/dev/null 2>&1
	kc label node "$WORKER" svclb.k3sm.io/lbpool- >/dev/null 2>&1
	[ -n "$PORT_HOLDER_PID" ] && on "$K3SM_B416_WORKER_SSH" "kill $PORT_HOLDER_PID" >/dev/null 2>&1
	kc get svc,events -n "$NS" -o wide > "$EVIDENCE/final-state.txt" 2>&1
}
trap cleanup EXIT

# The backend (backend_pod above).
backend_pod "$NS" "$SERVER" | kc apply -f - >/dev/null
kc wait --for=condition=Ready pod/b416-backend -n "$NS" --timeout=180s >/dev/null

lb_service() { # name port [label=value]
	local name="$1" port="$2" label="${3:-}" labels="{}"
	if [ -n "$label" ]; then labels="{${label%%=*}: ${label#*=}}"; fi
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: $name, namespace: $NS, labels: $labels}
spec:
  type: LoadBalancer
  selector: {app: b416-backend}
  ports: [{port: $port, targetPort: 8080}]
EOF
}
ingress_of() { kc get svc "$1" -n "$NS" -o jsonpath='{range .status.loadBalancer.ingress[*]}{.ip}{" "}{end}' | xargs -n1 2>/dev/null | sort | xargs; }
# wait_ingress <svc> <want> [seconds]: poll until the sorted ingress equals want.
wait_ingress() {
	local svc="$1" want="$2" n=0 limit="${3:-90}" got=""
	while [ "$n" -lt "$limit" ]; do
		got="$(ingress_of "$svc")"
		[ "$got" = "$want" ] && return 0
		sleep 2; n=$((n+2))
	done
	echo "    $svc ingress = '$got', want '$want'" >&2
	return 1
}
sorted() { printf '%s\n' "$@" | sort | xargs; }
# listening <ssh> <port>: how many WILDCARD TCP listeners <ssh> holds on <port>,
# the shape a LoadBalancer listener takes (lsof -nP NAME `*:<port>` or
# `[::]:<port>`). A specific-address listener is not counted, so the Service
# proxy's ClusterIP listener, which every node holds on the VIP, never reads as
# the LoadBalancer listener.
listening() { on "$1" "sudo -n lsof -nP -iTCP:$2 -sTCP:LISTEN 2>/dev/null | awk -v a='*:$2' -v b='[::]:$2' '{for (i = 1; i <= NF; i++) if (\$i == a || \$i == b) { n++; break }} END { print n + 0 }'"; }

# l.3 -------------------------------------------------------------------------
lb_service lb-a 18080
if wait_ingress lb-a "$(sorted "$SERVER_IP" "$WORKER_IP")"; then
	ladder ok "b416.l3a lb-a ingress lists both nodes' mesh addresses"
else
	ladder no "b416.l3a lb-a ingress lists both nodes' mesh addresses"
fi
a="$(on "$K3SM_B416_WORKER_SSH" "curl -fsS -m 5 http://$SERVER_IP:18080/" 2>/dev/null || true)"
b="$(on "$K3SM_B416_SERVER_SSH" "curl -fsS -m 5 http://$WORKER_IP:18080/" 2>/dev/null || true)"
if [ "$a" = b416 ] && [ "$b" = b416 ]; then
	ladder ok "b416.l3b each address serves the backend from the other Mac"
else
	ladder no "b416.l3b each address serves the backend from the other Mac (worker->server '$a', server->worker '$b')"
fi
kc get svc lb-a -n "$NS" -o yaml > "$EVIDENCE/l3-lb-a.yaml"

# l.4 -------------------------------------------------------------------------
kc label node "$SERVER" svclb.k3sm.io/enablelb=true --overwrite >/dev/null
if wait_ingress lb-a "$SERVER_IP"; then
	ladder ok "b416.l4a allow-list mode: lb-a ingress drops to the server"
else
	ladder no "b416.l4a allow-list mode: lb-a ingress drops to the server"
fi
if [ "$(listening "$K3SM_B416_WORKER_SSH" 18080)" = 0 ]; then
	ladder ok "b416.l4b the worker holds no wildcard LoadBalancer listener on 18080"
else
	ladder no "b416.l4b the worker holds no wildcard LoadBalancer listener on 18080"
fi
kc label node "$SERVER" svclb.k3sm.io/enablelb- >/dev/null

# l.5 -------------------------------------------------------------------------
kc label node "$SERVER" lbpool.svclb.k3sm.io/blue=true --overwrite >/dev/null
kc label node "$WORKER" svclb.k3sm.io/lbpool=green --overwrite >/dev/null
lb_service lb-blue 18081 svclb.k3sm.io/lbpool=blue
lb_service lb-green 18081 svclb.k3sm.io/lbpool=green
if wait_ingress lb-blue "$SERVER_IP" && wait_ingress lb-green "$WORKER_IP"; then
	ladder ok "b416.l5  one port, two pools: lb-blue on the server, lb-green on the worker"
else
	ladder no "b416.l5  one port, two pools: lb-blue on the server, lb-green on the worker"
fi
kc label node "$SERVER" lbpool.svclb.k3sm.io/blue- >/dev/null
kc label node "$WORKER" svclb.k3sm.io/lbpool- >/dev/null
kc delete svc -n "$NS" lb-blue lb-green >/dev/null

# l.6 -------------------------------------------------------------------------
PORT_HOLDER_PID="$(on "$K3SM_B416_WORKER_SSH" "nohup /usr/bin/nc -lk 18082 >/dev/null 2>&1 & echo \$!")"
sleep 2
lb_service lb-c 18082
if wait_ingress lb-c "$SERVER_IP"; then
	ladder ok "b416.l6a a held port keeps the worker out of lb-c's status"
else
	ladder no "b416.l6a a held port keeps the worker out of lb-c's status"
fi
uid="$(kc get svc lb-c -n "$NS" -o jsonpath='{.metadata.uid}')"
bound="$(kc get node "$WORKER" -o jsonpath='{.metadata.annotations.svclb\.k3sm\.io/bound}')"
echo "$bound" > "$EVIDENCE/l6-worker-bound.txt"
case "$bound" in
*"$NS/lb-c:$uid"*) ladder no "b416.l6b the worker's bound report lacks lb-c" ;;
*) ladder ok "b416.l6b the worker's bound report lacks lb-c" ;;
esac
ev=""
for _ in $(seq 1 45); do
	ev="$(kc get events -n "$NS" --field-selector "involvedObject.uid=$uid,reason=HostNotBound" -o jsonpath='{.items[*].message}' 2>/dev/null || true)"
	case "$ev" in *"$WORKER"*) break ;; esac
	sleep 2
done
case "$ev" in
*"$WORKER"*) ladder ok "b416.l6c a HostNotBound Event names the worker" ;;
*) ladder no "b416.l6c a HostNotBound Event names the worker (got '${ev:-none}')" ;;
esac

# l.7 -------------------------------------------------------------------------
lb_service lb-d1 18083
lb_service lb-d2 18083
sleep 45
d1="$(ingress_of lb-d1)"; d2="$(ingress_of lb-d2)"
dup=""
for ip in $d1; do case " $d2 " in *" $ip "*) dup="$dup $ip" ;; esac; done
if [ -z "$dup" ] && [ -n "$d1$d2" ]; then
	ladder ok "b416.l7  same port on one pool: no node is listed for both Services (lb-d1 '$d1', lb-d2 '$d2')"
else
	ladder no "b416.l7  same port on one pool: no node is listed for both Services (lb-d1 '$d1', lb-d2 '$d2')"
fi

# l.8 -------------------------------------------------------------------------
got="$(kc auth can-i patch services/status --as="system:node:$WORKER" --as-group=system:nodes 2>/dev/null || true)"
if [ "${got%% *}" = no ]; then
	ladder ok "b416.l8  can-i patch services/status as system:node:$WORKER: no"
else
	ladder no "b416.l8  can-i patch services/status as system:node:$WORKER: ${got:-<no answer>} (want no)"
fi

summary lab
[ "$FAIL" -eq 0 ] || exit 1
echo "lab tier GREEN"
