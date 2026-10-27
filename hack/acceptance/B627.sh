#!/usr/bin/env bash
#
# k3sm console probes acceptance gate: the lab host probes behind the app console's per-tab
# actions. Each probe runs one action against a running two-Mac cluster and
# prints what the cluster did, as `probe <n>: <answer>`. The answers are the
# evidence the console's sheet wording and enabled states cite; a probe never
# passes or fails on its answer.
#
#   probe 1  `kubectl scale` on an MLXModel: whether the CRD serves a scale
#            subresource, what `kubectl scale --replicas=0` returns, and
#            whether `kubectl patch --type=merge` of spec.replicas is admitted
#            (a server dry-run to 1, then a real patch to 0), and the replicas
#            of the workload the operator renders. The model is
#            created with replicas 0, so no serving pod ever starts.
#   probe 2  `kubectl port-forward` to a native pod and a `vm` RuntimeClass pod
#            on the peer node, and to a native pod on this node, issued from
#            this Mac; then to the peer's native and vm pods issued from the
#            peer Mac. Each forward is bounded to 20 s.
#   probe 3  the local-path lifecycle on this node: a PVC on the default storage
#            class (the only class when none is marked default), a pod writing a file, the pod deleted, the PVC deleted; the
#            PV phase and whether its host directory survives, then the same
#            after `kubectl delete pv`. `sudo -n` is used only to read.
#   probe 4  a NodePort Service for a native pod on this node: `curl` to each
#            Mac's LAN address and to 127.0.0.1, from this Mac and from the peer
#            (the reachability of the console's Open in browser).
#   probe 5  writes from this Mac with its kubeconfig: who it authenticates as,
#            its install role, `kubectl delete pod` and `kubectl scale` of a
#            Deployment.
#
# Every object lives in one namespace (default rig-b627) that the script creates,
# refuses to reuse, and deletes on exit, together with the PV probe 3 leaves.
# Pods are pinned with nodeName AND nodeSelector kubernetes.io/os: darwin and
# tolerate only what hack/lab/lib/tolerations.sh renders. Native pods use the
# `native` image; the vm pod uses B627_VM_IMAGE, which must already be on the
# peer node (imagePullPolicy Never). Nothing is installed or restarted.
#
# Run it from the WORKER Mac (so probe 5 is the worker-role answer) with the
# server as the peer. Exit: 0 every probe ran (whatever it answered), 1 a setup
# or cleanup failure, 3 K3SM_LAB unset (LAB-PENDING: not a pass).
#
# Environment:
#   K3SM_LAB=1          required to touch the cluster
#   B627_LOCAL_NODE     this Mac's node name (required)
#   B627_PEER_NODE      the other Mac's node name (required)
#   B627_PEER_SSH       ssh destination of the other Mac (required; BatchMode)
#   B627_CONTEXT        kubeconfig context (default k3sm)
#   B627_NAMESPACE      the test namespace (default rig-b627)
#   B627_VM_IMAGE       a linux image present on the peer node with sh and nc
#                       (default docker.io/library/postgres:16-alpine)
#   B627_STORAGE_CLASS  the class probe 3 uses (default: the default class, else
#                       the only class)
#   B627_LOCAL_LAN / B627_PEER_LAN  LAN addresses (default: the address on each
#                       Mac's default-route interface)
#   B627_EVIDENCE       evidence directory (default: a mktemp dir)
#   K3SM_LAB_TOLERATE_KEYS  extra taint keys to tolerate (the tolerations helper)
#
# Usage:  hack/acceptance/B627.sh [--help]
#         K3SM_LAB=1 B627_LOCAL_NODE=<worker> B627_PEER_NODE=<server> \
#           B627_PEER_SSH=<server-address> hack/acceptance/B627.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SELF="$HERE/B627.sh"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

case "${1:-}" in
-h | --help)
	sed -n '2,/^set -euo pipefail$/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'
	exit 0 ;;
"") ;;
*) echo "usage: $0 [--help]" >&2; exit 2 ;;
esac

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "LAB-PENDING  not a pass: needs K3SM_LAB=1 and a running two-Mac cluster (see --help)"
	exit 3
fi

# shellcheck source-path=SCRIPTDIR source=../lab/lib/tolerations.sh
. "$K3SM_ROOT/hack/lab/lib/tolerations.sh"
LAB_TOLERATIONS="$(lab_tolerations_yaml NoSchedule)" || exit 1

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

setup_fail() { echo "SETUP FAILURE  $*" >&2; exit 1; }

LOCAL_NODE="${B627_LOCAL_NODE:-}"
PEER_NODE="${B627_PEER_NODE:-}"
PEER_SSH="${B627_PEER_SSH:-}"
CTX="${B627_CONTEXT:-k3sm}"
NS="${B627_NAMESPACE:-rig-b627}"
VM_IMAGE="${B627_VM_IMAGE:-docker.io/library/postgres:16-alpine}"
EV="${B627_EVIDENCE:-}"
[ -n "$LOCAL_NODE" ] || setup_fail "B627_LOCAL_NODE is required"
[ -n "$PEER_NODE" ] || setup_fail "B627_PEER_NODE is required"
[ -n "$PEER_SSH" ] || setup_fail "B627_PEER_SSH is required"
for tool in kubectl jq curl ssh; do
	command -v "$tool" >/dev/null 2>&1 || setup_fail "$tool is not on PATH"
done
[ -n "$EV" ] || EV="$(mktemp -d "${TMPDIR:-/tmp}/k3sm-b627-evidence.XXXXXX")"
mkdir -p "$EV" || setup_fail "cannot create $EV"
ANSWERS="$EV/answers.txt"
: >"$ANSWERS"

k() { kubectl --context "$CTX" "$@"; }

# peer <script>: run a bash script on the peer Mac (PATH carries kubectl there).
peer() {
	ssh -o BatchMode=yes -o ConnectTimeout=10 "$PEER_SSH" \
		'PATH=/opt/homebrew/bin:/usr/local/bin:$PATH bash -s' <<<"$1"
}

answer() {
	echo "probe $1: $2" | tee -a "$ANSWERS"
}

log() { echo "      $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
ssh -o BatchMode=yes -o ConnectTimeout=10 "$PEER_SSH" true || setup_fail "ssh $PEER_SSH failed"
peer "kubectl --context '$CTX' get --raw /readyz >/dev/null" || setup_fail "the peer's kubectl cannot reach the cluster"
for n in "$LOCAL_NODE" "$PEER_NODE"; do
	ready="$(k get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" ||
		setup_fail "node $n not found"
	[ "$ready" = True ] || setup_fail "node $n is not Ready ($ready)"
done
if k get namespace "$NS" >/dev/null 2>&1; then
	setup_fail "namespace $NS already exists; delete it or set B627_NAMESPACE"
fi
# The LAN address is the one on the default route's interface (en0 or en1).
# shellcheck disable=SC2016 # expanded by the shell that runs it, on each Mac
LAN_CMD='ipconfig getifaddr "$(route -n get default 2>/dev/null | awk '"'"'/interface:/ {print $2}'"'"')"'
LOCAL_LAN="${B627_LOCAL_LAN:-$(bash -c "$LAN_CMD" 2>/dev/null || true)}"
PEER_LAN="${B627_PEER_LAN:-$(peer "$LAN_CMD" 2>/dev/null || true)}"
[ -n "$LOCAL_LAN" ] || setup_fail "no LAN address for this Mac (set B627_LOCAL_LAN)"
[ -n "$PEER_LAN" ] || setup_fail "no LAN address for the peer (set B627_PEER_LAN)"

# ── Evidence: header and the before transcripts ───────────────────────────────
{
	echo "run $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "local_node: $LOCAL_NODE ($LOCAL_LAN)  peer_node: $PEER_NODE ($PEER_LAN)"
	echo "context: $CTX  namespace: $NS  vm_image: $VM_IMAGE"
	echo "k3sm_sha: $(git -C "$K3SM_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
	lab_tolerations_header
} >"$EV/header.txt"
cat "$EV/header.txt"
cp "$SELF" "$EV/B627.sh.as-run"

snapshot() {
	local tag="$1"
	k get nodes -o wide >"$EV/nodes-$tag.txt" 2>&1 || true
	k get pv -o wide >"$EV/pv-$tag.txt" 2>&1 || true
	k get ds -A -o json 2>/dev/null |
		jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name) generation=\(.metadata.generation) desired=\(.status.desiredNumberScheduled) ready=\(.status.numberReady) updated=\(.status.updatedNumberScheduled)"' \
			>"$EV/daemonsets-$tag.txt" 2>&1 || true
	k get pods -A -o json 2>/dev/null |
		jq -r '.items[] | select(.metadata.ownerReferences[0].kind? == "DaemonSet") | "\(.metadata.namespace)/\(.metadata.name) uid=\(.metadata.uid) node=\(.spec.nodeName) phase=\(.status.phase)"' |
		sort >"$EV/daemonset-pods-$tag.txt" 2>&1 || true
	k get mlxmodels.mlx.k3sm.io -A >"$EV/mlxmodels-$tag.txt" 2>&1 || true
}
snapshot before

# ── Cleanup (trap) ────────────────────────────────────────────────────────────
PF_PIDS=""
PROBE3_PV=""
PROBE3_DIR=""
CLEANUP_RC=0
cleanup() {
	local rc=$?
	set +e
	for p in $PF_PIDS; do kill "$p" 2>/dev/null; done
	k delete namespace "$NS" --ignore-not-found --wait=true --timeout=180s >"$EV/cleanup.txt" 2>&1 ||
		{ echo "CLEANUP FAILURE  namespace $NS was not deleted (see $EV/cleanup.txt)" >&2; CLEANUP_RC=1; }
	if [ -n "$PROBE3_PV" ]; then
		k delete pv "$PROBE3_PV" --ignore-not-found --wait=true --timeout=60s >>"$EV/cleanup.txt" 2>&1 ||
			{ echo "CLEANUP FAILURE  PV $PROBE3_PV was not deleted" >&2; CLEANUP_RC=1; }
	fi
	# A PV the operator's weights claim produced (probe 1) carries the namespace in its claimRef.
	for pv in $(k get pv -o json 2>/dev/null | jq -r --arg ns "$NS" '.items[] | select(.spec.claimRef.namespace == $ns) | .metadata.name'); do
		k delete pv "$pv" --ignore-not-found --wait=true --timeout=60s >>"$EV/cleanup.txt" 2>&1 || CLEANUP_RC=1
	done
	snapshot after
	if k get namespace "$NS" >/dev/null 2>&1; then
		echo "CLEANUP FAILURE  namespace $NS still exists" >&2; CLEANUP_RC=1
	fi
	for n in "$LOCAL_NODE" "$PEER_NODE"; do
		ready="$(k get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
		if [ "$ready" != True ]; then echo "CLEANUP FAILURE  node $n is not Ready at the end ($ready)" >&2; CLEANUP_RC=1; fi
	done
	if ! diff "$EV/daemonsets-before.txt" "$EV/daemonsets-after.txt" >"$EV/daemonsets.diff" 2>&1 ||
		! diff "$EV/daemonset-pods-before.txt" "$EV/daemonset-pods-after.txt" >>"$EV/daemonsets.diff" 2>&1; then
		echo "NOTE  a DaemonSet or its pods changed during the run (see $EV/daemonsets.diff)" >&2
	fi
	if [ -n "$PROBE3_DIR" ]; then
		if sudo -n test -e "$PROBE3_DIR" 2>/dev/null; then
			echo "LEFT BEHIND  $PROBE3_DIR (the local-path directory survives PV deletion; this script only reads with sudo)" | tee -a "$EV/left-behind.txt"
		fi
	fi
	echo "----------------------------------------"
	echo "answers:"
	cat "$ANSWERS"
	echo "evidence: $EV"
	if [ "$rc" -ne 0 ]; then exit "$rc"; fi
	exit "$CLEANUP_RC"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

k create namespace "$NS" >/dev/null || setup_fail "cannot create namespace $NS"
k label namespace "$NS" k3sm.io/lab=b627 >/dev/null

# ── Manifests ─────────────────────────────────────────────────────────────────
# http_loop <body> <port>: a shell loop answering one HTTP request per nc accept
# with <body>. nc keeps the socket open after its stdin ends, so the response
# carries a Content-Length and the client closes. http_loop_busybox is the same
# for busybox nc (-p names the port).
http_response() {
	printf 'HTTP/1.0 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s\\n' "$((${#1} + 1))" "$1"
}
http_loop() {
	printf 'while :; do printf "%s" | nc -l %s; done' "$(http_response "$1")" "$2"
}
http_loop_busybox() {
	printf 'while :; do printf "%s" | nc -l -p %s; done' "$(http_response "$1")" "$2"
}

# native_pod <name> <node> <label> <body> <port>: native pods share the host's
# port space, so each probe pod listens on its own port.
native_pod() {
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS, labels: {k3sm.io/lab: b627, b627: $3}}
spec:
  nodeName: $2
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$LAB_TOLERATIONS]
  restartPolicy: Never
  activeDeadlineSeconds: 900
  terminationGracePeriodSeconds: 2
  containers:
  - name: main
    image: native
    command: ["/bin/sh", "-c", $(printf '%s' "$4" | jq -Rs .)]
    ports: [{containerPort: ${5:-28670}}]
EOF
}

vm_pod() {
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS, labels: {k3sm.io/lab: b627, b627: $3}}
spec:
  nodeName: $2
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$LAB_TOLERATIONS]
  runtimeClassName: vm
  restartPolicy: Never
  activeDeadlineSeconds: 900
  terminationGracePeriodSeconds: 2
  containers:
  - name: main
    image: $VM_IMAGE
    imagePullPolicy: Never
    command: ["/bin/sh", "-c", $(printf '%s' "$4" | jq -Rs .)]
    ports: [{containerPort: 28672}]
EOF
}

# wait_ready <pod> <seconds>: 0 when Ready; the pod's state goes to the evidence.
wait_ready() {
	if k -n "$NS" wait --for=condition=Ready "pod/$1" --timeout="${2}s" >/dev/null 2>&1; then
		return 0
	fi
	k -n "$NS" get pod "$1" -o wide >"$EV/pod-$1-notready.txt" 2>&1
	k -n "$NS" describe pod "$1" >>"$EV/pod-$1-notready.txt" 2>&1
	return 1
}

# curl_try <url> <seconds>: up to three GETs a second apart, each bounded to
# <seconds>, because the nc backends answer one connection at a time and are
# briefly not listening between two. Prints "ok <body> (attempt <n>)" or
# "fail <the last error>". The peer runs the same function (declare -f).
curl_try() {
	local n=1 out
	while [ "$n" -le 3 ]; do
		if out="$(curl -sS -m "$2" "$1" 2>&1)"; then
			echo "ok $(printf '%s' "$out" | tr -d '\r\n') (attempt $n)"
			return 0
		fi
		n=$((n + 1)); sleep 1
	done
	echo "fail $(printf '%s' "$out" | tail -1 | tr -d '\r' | cut -c1-120)"
}

# forward_local <pod> <local-port> <pod-port>: port-forward from this Mac, bounded
# to 20 s; prints "ok <body>" or "fail <reason>".
forward_local() {
	local pod="$1" lport="$2" pport="$3" pflog="$EV/pf-$1-local.log" pid body i=0
	# kubectl itself goes to the background (not the k wrapper), so $! is the
	# process the kill below reaches.
	kubectl --context "$CTX" -n "$NS" port-forward --address 127.0.0.1 "pod/$pod" "$lport:$pport" >"$pflog" 2>&1 &
	pid=$!
	PF_PIDS="$PF_PIDS $pid"
	while [ $i -lt 20 ]; do
		if grep -q '^Forwarding from' "$pflog" 2>/dev/null; then break; fi
		if ! kill -0 "$pid" 2>/dev/null; then break; fi
		sleep 1; i=$((i + 1))
	done
	if grep -q '^Forwarding from' "$pflog" 2>/dev/null; then
		body="$(curl_try "http://127.0.0.1:$lport/" 4)"
		echo "$body" >>"$pflog"
		echo "$body"
	else
		echo "fail $(grep -v '^Forwarding from' "$pflog" | tail -1 | tr -d '\r' | cut -c1-160)"
	fi
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

# ── probe 1: kubectl scale on an MLXModel ─────────────────────────────────────
probe1() {
	local sub scale_out scale_rc dry_out dry_rc patch_out patch_rc replicas deploy ready
	if ! k get crd mlxmodels.mlx.k3sm.io >/dev/null 2>&1; then
		answer 1 "the mlxmodels.mlx.k3sm.io CRD is not installed; nothing to scale"
		return
	fi
	sub="$(k get crd mlxmodels.mlx.k3sm.io -o json | jq -c '[.spec.versions[] | {(.name): (.subresources // {} | keys)}] | add')"
	k get crd mlxmodels.mlx.k3sm.io -o json | jq '.spec.versions[] | {name, subresources}' >"$EV/probe1-crd-subresources.json"
	if ! k apply -f - >"$EV/probe1-create.txt" 2>&1 <<EOF
apiVersion: mlx.k3sm.io/v1alpha1
kind: MLXModel
metadata: {name: b627-model, namespace: $NS, labels: {k3sm.io/lab: b627}}
spec:
  model: b627-probe/no-such-model
  memory: 16Gi
  replicas: 0
  port: 28676
  runtime: {image: b627.invalid/no-such-image:0}
EOF
	then
		answer 1 "subresources $sub; creating a minimal MLXModel was refused: $(tail -1 "$EV/probe1-create.txt")"
		return
	fi
	sleep 5
	set +e
	scale_out="$(k -n "$NS" scale --replicas=0 mlxmodel/b627-model 2>&1)"; scale_rc=$?
	dry_out="$(k -n "$NS" patch mlxmodel/b627-model --type=merge -p '{"spec":{"replicas":1}}' --dry-run=server 2>&1)"; dry_rc=$?
	patch_out="$(k -n "$NS" patch mlxmodel/b627-model --type=merge -p '{"spec":{"replicas":0}}' 2>&1)"; patch_rc=$?
	set -e
	sleep 5
	replicas="$(k -n "$NS" get mlxmodel/b627-model -o jsonpath='{.spec.replicas}' 2>/dev/null)"
	deploy="$(k -n "$NS" get statefulsets,deployments -o json 2>/dev/null | jq -r '[.items[] | "\(.kind)/\(.metadata.name) replicas=\(.spec.replicas)"] | join(", ")')"
	ready="$(k -n "$NS" get mlxmodel/b627-model -o json 2>/dev/null | jq -r '[.status.conditions[]? | select(.type == "Ready") | "\(.status)/\(.reason)"][0] // "none"')"
	{
		echo "## kubectl scale --replicas=0 mlxmodel/b627-model  (rc=$scale_rc)"; echo "$scale_out"
		echo "## kubectl patch --type=merge spec.replicas=1 --dry-run=server  (rc=$dry_rc)"; echo "$dry_out"
		echo "## kubectl patch --type=merge spec.replicas=0  (rc=$patch_rc)"; echo "$patch_out"
		echo "## the model and what the operator rendered"
		k -n "$NS" get mlxmodel/b627-model -o yaml 2>&1
		k -n "$NS" get statefulsets,deployments,svc,pvc,pods -o wide 2>&1
	} >"$EV/probe1.txt"
	answer 1 "CRD subresources $sub (no scale subresource means the API answers 404 on /scale); kubectl scale rc=$scale_rc ($(printf '%s' "$scale_out" | tail -1 | cut -c1-160)); patch merge spec.replicas dry-run=server to 1 rc=$dry_rc, real patch to 0 rc=$patch_rc ($(printf '%s' "$patch_out" | tail -1)); spec.replicas now ${replicas:-unset}; model Ready=$ready; operator workload: ${deploy:-none}"
}

# ── probe 2: port-forward ─────────────────────────────────────────────────────
probe2() {
	local r_nat_peer r_vm_peer r_nat_local remote
	native_pod b627-pf-native-peer "$PEER_NODE" pf-native-peer "$(http_loop b627-native-peer 28671)" 28671 | k apply -f - >/dev/null
	vm_pod b627-pf-vm-peer "$PEER_NODE" pf-vm-peer "$(http_loop_busybox b627-vm-peer 28672)" | k apply -f - >/dev/null
	native_pod b627-pf-native-local "$LOCAL_NODE" pf-native-local "$(http_loop b627-native-local 28673)" 28673 | k apply -f - >/dev/null
	if wait_ready b627-pf-native-peer 90; then r_nat_peer="$(forward_local b627-pf-native-peer 18627 28671)"; else r_nat_peer="fail pod never Ready"; fi
	if wait_ready b627-pf-vm-peer 180; then r_vm_peer="$(forward_local b627-pf-vm-peer 18628 28672)"; else r_vm_peer="fail pod never Ready"; fi
	if wait_ready b627-pf-native-local 90; then r_nat_local="$(forward_local b627-pf-native-local 18629 28673)"; else r_nat_local="fail pod never Ready"; fi
	# The same two peer pods, forwarded by the peer Mac's own kubectl.
	remote="$(peer "$(declare -f curl_try)
ctx='$CTX'; ns='$NS'
fwd() {
	pod=\$1; lport=\$2; pport=\$3; log=\$(mktemp); i=0
	kubectl --context \"\$ctx\" -n \"\$ns\" port-forward --address 127.0.0.1 pod/\$pod \$lport:\$pport >\"\$log\" 2>&1 &
	pid=\$!
	while [ \$i -lt 20 ]; do grep -q '^Forwarding from' \"\$log\" && break; kill -0 \$pid 2>/dev/null || break; sleep 1; i=\$((i+1)); done
	if grep -q '^Forwarding from' \"\$log\"; then
		echo \"\$pod \$(curl_try http://127.0.0.1:\$lport/ 4)\"
	else
		echo \"\$pod fail \$(grep -v '^Forwarding from' \"\$log\" | tail -1 | tr -d '\r' | cut -c1-160)\"
	fi
	kill \$pid 2>/dev/null; wait \$pid 2>/dev/null; rm -f \"\$log\"
}
fwd b627-pf-native-peer 18637 28671
fwd b627-pf-vm-peer 18638 28672
" 2>&1 || true)"
	{
		echo "from this Mac: native on peer: $r_nat_peer"
		echo "from this Mac: vm on peer: $r_vm_peer"
		echo "from this Mac: native on this node: $r_nat_local"
		echo "from the peer Mac:"; echo "$remote"
		k -n "$NS" get pods -o wide
	} >"$EV/probe2.txt" 2>&1
	answer 2 "from the worker Mac: native pod on the server node -> $r_nat_peer; vm pod on the server node -> $r_vm_peer; native pod on the worker node -> $r_nat_local; from the server Mac: $(printf '%s' "$remote" | tr '\n' ';' | sed 's/;$//')"
	k -n "$NS" delete pod b627-pf-native-peer b627-pf-vm-peer b627-pf-native-local --wait=false >/dev/null 2>&1 || true
}

# ── probe 3: the local-path PV lifecycle ──────────────────────────────────────
probe3() {
	local sc defsc nclasses pv reclaim path phase1 phase2 dir1 dir2 dir0 list0
	# A run-unique claim name: the host directory of an earlier run's claim may
	# survive (this probe's question), and a reused name would find it.
	local CLAIM
	CLAIM="b627-pvc-$(date -u +%H%M%S)"
	# The default class, else the only class (named in the answer either way).
	defsc="$(k get sc -o json | jq -r '[.items[] | select(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true") | .metadata.name][0] // empty')"
	nclasses="$(k get sc -o json | jq -r '.items | length')"
	sc="${B627_STORAGE_CLASS:-$defsc}"
	if [ -z "$sc" ] && [ "$nclasses" = 1 ]; then sc="$(k get sc -o jsonpath='{.items[0].metadata.name}')"; fi
	if [ -z "$sc" ]; then
		answer 3 "no default storage class and $nclasses classes; set B627_STORAGE_CLASS"
		return
	fi
	# The writer pod is pinned by nodeName, which bypasses the scheduler, so a
	# WaitForFirstConsumer claim never gets the selected-node annotation the
	# scheduler would write; the claim carries it from the start instead.
	k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $CLAIM
  namespace: $NS
  labels: {k3sm.io/lab: b627}
  annotations: {volume.kubernetes.io/selected-node: $LOCAL_NODE}
spec:
  storageClassName: $sc
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 16Mi}}
EOF
	local j=0
	while [ $j -lt 60 ]; do
		[ "$(k -n "$NS" get pvc "$CLAIM" -o jsonpath='{.status.phase}' 2>/dev/null)" = Bound ] && break
		sleep 2; j=$((j + 2))
	done
	cat <<EOF | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: b627-pv-writer, namespace: $NS, labels: {k3sm.io/lab: b627}}
spec:
  nodeName: $LOCAL_NODE
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$LAB_TOLERATIONS]
  restartPolicy: Never
  activeDeadlineSeconds: 300
  terminationGracePeriodSeconds: 2
  containers:
  - name: main
    image: native
    command: ["/bin/sh", "-c", "echo b627 > /data/b627.txt && cat /data/b627.txt"]
    volumeMounts: [{name: data, mountPath: /data}]
  volumes:
  - name: data
    persistentVolumeClaim: {claimName: $CLAIM}
EOF
	local i=0 podphase=""
	while [ $i -lt 90 ]; do
		podphase="$(k -n "$NS" get pod b627-pv-writer -o jsonpath='{.status.phase}' 2>/dev/null || true)"
		case "$podphase" in Succeeded | Failed) break ;; esac
		sleep 2; i=$((i + 2))
	done
	pv="$(k -n "$NS" get pvc "$CLAIM" -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)"
	{
		echo "## default storage class: ${defsc:-none annotated}; used: $sc"
		k get sc -o wide
		echo "## writer pod phase: $podphase"
		k -n "$NS" logs b627-pv-writer 2>&1 | tail -5
		k -n "$NS" get pvc "$CLAIM" -o wide
	} >"$EV/probe3.txt" 2>&1
	if [ -z "$pv" ]; then
		k -n "$NS" describe pvc "$CLAIM" >>"$EV/probe3.txt" 2>&1
		answer 3 "the PVC never bound on class $sc (default: ${defsc:-none annotated}); writer pod phase ${podphase:-none}"
		return
	fi
	PROBE3_PV="$pv"
	k get pv "$pv" -o yaml >>"$EV/probe3.txt" 2>&1
	reclaim="$(k get pv "$pv" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}')"
	path="$(k get pv "$pv" -o json | jq -r '.spec.hostPath.path // .spec.local.path // empty')"
	PROBE3_DIR="$path"
	dirstate() {
		if [ -z "$path" ]; then echo "no host path in the PV spec"; return; fi
		if sudo -n test -d "$path" 2>/dev/null; then echo "exists"
		elif sudo -n true 2>/dev/null; then echo "gone"
		else echo "unknown (sudo -n unavailable)"; fi
	}
	dir0="$(dirstate)"
	list0="$(sudo -n ls -la "$path" 2>&1 | tr '\n' ';' | cut -c1-200)"
	k -n "$NS" delete pod b627-pv-writer --wait=true --timeout=60s >/dev/null 2>&1 || true
	k -n "$NS" delete pvc "$CLAIM" --wait=true --timeout=60s >/dev/null 2>&1 || true
	sleep 8
	phase1="$(k get pv "$pv" -o jsonpath='{.status.phase}' 2>/dev/null || echo gone)"
	dir1="$(dirstate)"
	{
		echo "## dir before deletes: $dir0 ($list0)"
		echo "## after pod+PVC delete: pv phase=$phase1 dir=$dir1"
		sudo -n ls -la "$path" 2>&1
	} >>"$EV/probe3.txt"
	if [ "$phase1" != gone ]; then
		k delete pv "$pv" --wait=true --timeout=60s >/dev/null 2>&1 || true
		sleep 8
	fi
	phase2="$(k get pv "$pv" -o jsonpath='{.status.phase}' 2>/dev/null || echo gone)"
	dir2="$(dirstate)"
	echo "## after kubectl delete pv: pv=$phase2 dir=$dir2" >>"$EV/probe3.txt"
	[ "$phase2" = gone ] && PROBE3_PV=""
	[ "$dir2" = exists ] || PROBE3_DIR=""
	answer 3 "class $sc (default: ${defsc:-none annotated}), reclaimPolicy $reclaim, writer pod $podphase; host path ${path:-none} ($dir0 after the write); after the pod and PVC are deleted the PV is $phase1 and the directory $dir1; after kubectl delete pv the PV is $phase2 and the directory $dir2"
}

# ── probe 4: NodePort reachability ────────────────────────────────────────────
probe4() {
	local np results="" target body remote
	native_pod b627-np "$LOCAL_NODE" np "$(http_loop b627-nodeport 28674)" 28674 | k apply -f - >/dev/null
	k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: b627-np, namespace: $NS, labels: {k3sm.io/lab: b627}}
spec:
  type: NodePort
  selector: {b627: np}
  ports: [{name: http, port: 8080, targetPort: 28674}]
EOF
	np="$(k -n "$NS" get svc b627-np -o jsonpath='{.spec.ports[0].nodePort}')"
	if ! wait_ready b627-np 90; then
		answer 4 "the NodePort backend pod never became Ready (nodePort $np)"
		return
	fi
	sleep 3
	for target in "worker-LAN=$LOCAL_LAN" "server-LAN=$PEER_LAN" "loopback=127.0.0.1"; do
		body="$(curl_try "http://${target#*=}:$np/" 5)"
		results="$results from-worker->${target%%=*}: $body;"
		sleep 1
	done
	remote="$(peer "$(declare -f curl_try)
for t in worker-LAN=$LOCAL_LAN server-LAN=$PEER_LAN loopback=127.0.0.1; do
	printf ' from-server->%s: %s;' \"\${t%%=*}\" \"\$(curl_try http://\${t#*=}:$np/ 5)\"
	sleep 1
done
" 2>&1 || true)"
	{
		echo "nodePort $np, backend on $LOCAL_NODE"
		echo "$results"
		echo "$remote"
		k -n "$NS" get svc,endpointslices -o wide
	} >"$EV/probe4.txt" 2>&1
	answer 4 "NodePort $np, backend native pod on the worker node:$results$remote"
}

# ── probe 5: writes from this Mac ─────────────────────────────────────────────
probe5() {
	local who role del_out del_rc scale_out scale_rc ready
	who="$(k auth whoami -o json 2>/dev/null | jq -r '.status.userInfo | "\(.username) groups=\(.groups | join(","))"' || echo unknown)"
	role="$(k3sm status -o json 2>/dev/null | jq -r '.role // "unknown"' || echo unknown)"
	native_pod b627-del "$LOCAL_NODE" del "sleep 600" 28675 | k apply -f - >/dev/null
	cat <<EOF | k apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: b627-deploy, namespace: $NS, labels: {k3sm.io/lab: b627}}
spec:
  replicas: 1
  selector: {matchLabels: {b627: deploy}}
  template:
    metadata: {labels: {k3sm.io/lab: b627, b627: deploy}}
    spec:
      nodeName: $LOCAL_NODE
      nodeSelector: {kubernetes.io/os: darwin}
      tolerations: [$LAB_TOLERATIONS]
      terminationGracePeriodSeconds: 2
      containers:
      - name: main
        image: native
        command: ["/bin/sh", "-c", "sleep 600"]
EOF
	wait_ready b627-del 90 || true
	set +e
	del_out="$(k -n "$NS" delete pod b627-del --wait=true --timeout=60s 2>&1)"; del_rc=$?
	k -n "$NS" rollout status deploy/b627-deploy --timeout=90s >/dev/null 2>&1
	scale_out="$(k -n "$NS" scale deploy/b627-deploy --replicas=0 2>&1)"; scale_rc=$?
	set -e
	sleep 5
	ready="$(k -n "$NS" get deploy b627-deploy -o json 2>/dev/null | jq -r '"spec \(.spec.replicas) status \(.status.replicas // 0)"')"
	{
		echo "identity: $who"; echo "role: $role"
		echo "## delete pod (rc=$del_rc)"; echo "$del_out"
		echo "## scale deploy to 0 (rc=$scale_rc)"; echo "$scale_out"
		k -n "$NS" get deploy,pods -o wide
	} >"$EV/probe5.txt" 2>&1
	answer 5 "from a role=$role Mac as $who: kubectl delete pod rc=$del_rc ($(printf '%s' "$del_out" | tail -1)); kubectl scale deploy --replicas=0 rc=$scale_rc ($(printf '%s' "$scale_out" | tail -1)); deployment replicas $ready"
}

for p in probe1 probe2 probe3 probe4 probe5; do
	echo "== $p"
	"$p" || answer "${p#probe}" "the probe stopped with an error (rc=$?); see $EV"
done
