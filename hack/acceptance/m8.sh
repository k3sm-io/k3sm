#!/usr/bin/env bash
#
# k3sm M8 gate — MLX native Apple-Silicon ML serving, end to end.
#
# This is the M8 row in hack/acceptance/phases.json (tier integration, requires
# dev-mac + apple-gpu + network, manual: false). There is deliberately NO M8-lab
# row: a GPU dev-mac covers the whole proof.
#
# It BOOTS NOTHING. $KUBECONFIG must point at a running `k3sm server` on a Mac
# whose node advertises the mlx.k3sm.io/gpu extended resource, and the serving
# image must be pullable from that node (see hack/images/mlx-serve/README.md —
# publishing is a human lab step and the digest it prints is what K3SM_MLX_IMAGE
# should carry).
#
# The ladder, and why each rung is here:
#
#   m8.0  preflight — GPU node, MLXModel CRD established, the example on disk.
#   m8.1  pre-seed  — nothing is staged on the host: the weights are seeded on the
#                     cluster at m8.3-b, the way an operator without host root does.
#   m8.2  apply     — examples/mlxmodel.yaml, the shipped manifest itself.
#   m8.3  volume    — the cache PVC binds, and the seed lands in its local path.
#   m8.4  ready     — via CONDITIONS. status.phase is a derived printer column and
#                     is explicitly NOT the assertion: a consumer that branches on
#                     it reads a projection, and observedGeneration is what proves
#                     the condition describes THIS spec rather than the last one.
#   m8.5  endpoint  — the ClusterIP Service and the published status.endpoint.
#   m8.5-c served id— GET /v1/models, asserted singular, IS the id every
#                     completion below posts. The engine registers whatever it
#                     decided to call the served snapshot (often a resolved
#                     on-disk PATH, not examples/mlxmodel.yaml's repo id), so
#                     posting the spec's repo id 404s a Ready pod.
#                     m8.0-b's pin check is untouched: it pins the SPEC, not
#                     the served name.
#   m8.6  completion— one OpenAI chat completion through the ClusterIP returns
#                     actual tokens.
#   m8.7  CONCURRENT— N simultaneous completions, ALL of which must succeed.
#                     THIS IS THE RUNG A SINGLE-REQUEST SMOKE TEST CANNOT REPLACE.
#                     Without --continuous-batching the engine serves exactly one
#                     request at a time and answers HTTP 503 to every other
#                     concurrent client, while /health stays green and the
#                     readiness probe stays green — so the pod presents as a
#                     healthy backend that is a broken load balancer, and m8.6
#                     passes anyway. Spike S5 measured 1 of 8 requests served with
#                     `waiters=0` in the 503 body: a rejection, not a queue.
#                     See hack/spike/m8/findings-s5.md and pkg/mlx/sizing.go.
#   m8.8  latency   — TTFT and tokens/sec, ClusterIP path vs the pod directly, so
#                     the Service-proxy hop is a measured number and not a guess.
#                     RECORDED, not thresholded: there is no committed budget to
#                     hold this to yet, and inventing one here would either be
#                     vacuous or flaky. Both paths must answer; the numbers print.
#   m8.9  deletion  — delete the MLXModel, then poll every operator-owned object
#                     to ABSENT. The PVC disposition is asserted EXACTLY per the
#                     StatefulSet's whenDeleted:Delete policy, and the PV is
#                     asserted to SURVIVE, because the local-path class reclaims
#                     Retain — weights are removed by hand, deliberately.
#
# Every wait is bounded and every network call carries -m. A hang is a FAIL with a
# named rung, never a gate that runs until someone kills it.
#
# Usage:
#   KUBECONFIG=/path/to/kubeconfig hack/acceptance/m8.sh
#   hack/acceptance/m8.sh --plan     # print the ladder and the pins; touch nothing
#   hack/acceptance/m8.sh --self-test  # render the manifest and the seed Job; no cluster
#   hack/acceptance/m8.sh --render-seed-job <namespace> <node> <pvc>
#                                    # print the m8.3-b seed Job for another driver
#
# Knobs (all optional):
#   K3SM_MLX_IMAGE        serving image override, ideally the @sha256 digest pin
#   K3SM_MLX_NAMESPACE    namespace to run in (default: the example's own); it is
#                         rendered into the gate's copy of the example
#   K3SM_MLX_CONCURRENCY  m8.7 concurrent requests (default 4, the engine's
#                         --max-num-seqs ceiling; below 4 the rung proves less)
#   K3SM_MLX_READY_TIMEOUT   seconds to wait for Ready (default 1800)
#   K3SM_MLX_DELETE_TIMEOUT  seconds to wait for GC (default 300)
#   K3SM_LAB_TOLERATE_KEYS  extra taint keys the seed Job tolerates (hack/lab/lib/tolerations.sh)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
EXAMPLE="$REPO_ROOT/examples/mlxmodel.yaml"
# shellcheck source=../lab/lib/tolerations.sh
. "$REPO_ROOT/hack/lab/lib/tolerations.sh"

# The pins. These MUST agree with examples/mlxmodel.yaml — m8.0 asserts it rather
# than trusting it, so an edit to either file that forgets the other goes red here
# instead of silently gating a different model than the one that ships.
MODEL_NAME="qwen3-06b"
MODEL_REPO="mlx-community/Qwen3-0.6B-4bit"
MODEL_REV="73e3e38d981303bc594367cd910ea6eb48349da8"
SERVING_PORT="8000"

# Where the serving pod mounts the cache and what it sets HF_HOME to. These MUST
# equal pkg/mlx/render.go (CacheMountPath, hfHomePath); --self-test asserts it, so
# the seed Job writes where the server reads.
CACHE_MOUNT="/var/lib/mlx/cache"
HF_HOME_PATH="$CACHE_MOUNT/huggingface"

CONCURRENCY="${K3SM_MLX_CONCURRENCY:-4}"
READY_TIMEOUT="${K3SM_MLX_READY_TIMEOUT:-1800}"
DELETE_TIMEOUT="${K3SM_MLX_DELETE_TIMEOUT:-300}"
REQ_TIMEOUT=120

PASS=0; FAIL=0; SKIP=0
ladder() {
	case "$1" in
	ok)   echo "PASS  $2"; PASS=$((PASS + 1)) ;;
	skip) echo "SKIP  $2"; SKIP=$((SKIP + 1)) ;;
	*)    echo "FAIL  $2"; FAIL=$((FAIL + 1)) ;;
	esac
}
note() { echo "      $*"; }

# render_manifest <namespace> — the gate's copy of the example on stdout, with
# metadata.namespace set to <namespace> (the example hard-codes `default`, which
# kubectl apply -n refuses against any other namespace) and, when K3SM_MLX_IMAGE
# is set, the image line replaced. The shipped file itself is never rewritten.
render_manifest() {
	local ns="$1"
	sed -E "s#^(  namespace:).*#\1 ${ns}#" "$EXAMPLE" |
		if [ -n "${K3SM_MLX_IMAGE:-}" ]; then
			sed -E "s#^([[:space:]]*image:).*#\1 ${K3SM_MLX_IMAGE}#"
		else
			cat
		fi
}

# seed_image — the image the seed Job runs: the serving image (its interpreter
# carries huggingface_hub, a dependency of the engine), as the gate will apply it.
seed_image() {
	render_manifest "$1" | grep -E '^[[:space:]]*image:' | head -1 | sed -E 's#^[[:space:]]*image:[[:space:]]*##'
}

# render_seed_job <namespace> <node> <image> <pvc> — a Job that downloads the
# pinned snapshot into the model's cache PVC under HF_HOME, the layout the engine
# reads (pkg/mlx modelReference). It is what an operator does on k3sm with no host
# root: the pod writes the volume as the unprivileged pod user, so ownership is
# already right. Pinned with nodeName (the PV is node-local) and the darwin
# selector; tolerations come from the lab helper.
render_seed_job() {
	local ns="$1" node="$2" image="$3" pvc="$4"
	# A pod's mount at an absolute path is a path-rebase shim over opens and mkdir,
	# not a mount namespace, and huggingface_hub resolves HF_HOME through /var ->
	# /private/var before it creates directories, which leaves the shim's prefix
	# (docs/user/limitations.md, "Volume Mounts Resolve for Native Workloads"). So
	# the mount and HF_HOME are the serving pod's exactly, and the download is
	# pointed at the same directory by a RELATIVE cache_dir: the pod's working
	# directory is the pod data volume, where the mount is materialized at ./<path>.
	local SEED_PY
	SEED_PY="import os,sys; from huggingface_hub import snapshot_download; c='.'+os.environ['HF_HOME']+'/hub'; print(os.getcwd(), c); print(snapshot_download(sys.argv[1], revision=sys.argv[2], cache_dir=c))"
	cat <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: m8-seed-$MODEL_NAME
  namespace: $ns
spec:
  backoffLimit: 2
  template:
    spec:
      restartPolicy: Never
      nodeName: $node
      nodeSelector: {kubernetes.io/os: darwin}
      tolerations: [$(lab_tolerations_yaml)]
      containers:
      - name: seed
        image: $image
        command: ["/bin/python3.12", "-c", "$SEED_PY", "$MODEL_REPO", "$MODEL_REV"]
        env:
        - {name: HF_HOME, value: $HF_HOME_PATH}
        volumeMounts:
        - {name: cache, mountPath: $CACHE_MOUNT}
      volumes:
      - name: cache
        persistentVolumeClaim: {claimName: $pvc}
EOF
}

# delete_seed_job — delete the seed Job in the foreground and wait until no pod of
# it remains (bounded), so nothing but the replica references the cache claim.
delete_seed_job() {
	kubectl delete job "m8-seed-$MODEL_NAME" -n "$NS" --ignore-not-found --cascade=foreground --wait=true --timeout=120s >/dev/null 2>&1 || true
	local d=$((SECONDS + 120))
	while [ "$SECONDS" -lt "$d" ]; do
		[ -z "$(kubectl get pods -n "$NS" -l "job-name=m8-seed-$MODEL_NAME" -o name 2>/dev/null || true)" ] && return 0
		sleep 2
	done
	note "seed Job pods still present after 120s"
}

# --------------------------------------------------------------------------------
# --self-test: render the manifest and the seed Job and assert their shape. No
# cluster, no network. The live legs are run on the lab host.
# --------------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
	st_fail=0
	st() { if [ "$1" = ok ]; then echo "ok    $2"; else echo "FAIL  $2"; st_fail=1; fi; }
	m="$(render_manifest lab-ns)"
	grep -qx '  namespace: lab-ns' <<<"$m" && ! grep -q 'namespace: default' <<<"$m" &&
		st ok "namespace rendered into the example copy" || st no "namespace rendered into the example copy"
	[ "$(printf '%s\n' "$m" | grep -c 'namespace:')" = 1 ] && st ok "exactly one namespace line" || st no "exactly one namespace line"
	[ "$(render_manifest default)" = "$(cat "$EXAMPLE")" ] && st ok "default namespace leaves the example byte-identical" || st no "default namespace leaves the example byte-identical"
	m="$(K3SM_MLX_IMAGE=example.invalid/img@sha256:abc render_manifest lab-ns)"
	grep -q 'image: example.invalid/img@sha256:abc' <<<"$m" && st ok "image override still applies" || st no "image override still applies"
	j="$(K3SM_LAB_TOLERATE_KEYS='estate.example.com/off' render_seed_job lab-ns node-a img:1 cache-$MODEL_NAME-0)"
	for want in 'kind: Job' 'namespace: lab-ns' 'nodeName: node-a' 'kubernetes.io/os: darwin' \
		'claimName: cache-qwen3-06b-0' 'image: img:1' "$MODEL_REPO" "$MODEL_REV" \
		'value: /var/lib/mlx/cache/huggingface' '{key: estate.example.com/off, operator: Exists}'; do
		grep -qF -- "$want" <<<"$j" && st ok "seed Job carries $want" || st no "seed Job carries $want"
	done
	[ "$(printf '%s\n' "$j" | grep -c 'k3sm.io/provider')" = 1 ] && st ok "seed Job tolerates k3sm.io/provider once" || st no "seed Job tolerates k3sm.io/provider once"
	[ "$(printf '%s\n' "$j" | grep -c 'tolerations:')" = 1 ] && ! grep -q 'operator: Exists}, {key: [^e]' <<<"$j" &&
		st ok "seed Job tolerates only the provider key and the named extras" || st no "seed Job tolerates only the provider key and the named extras"
	grep -qF -- "mountPath: $CACHE_MOUNT" <<<"$j" && st ok "seed Job mounts the cache at $CACHE_MOUNT" || st no "seed Job mounts the cache at $CACHE_MOUNT"
	go_mount="$(sed -nE 's/^[[:space:]]*CacheMountPath = "([^"]+)".*/\1/p' "$REPO_ROOT/pkg/mlx/render.go")"
	go_home="$(sed -nE 's/^[[:space:]]*hfHomePath = CacheMountPath \+ "([^"]+)".*/\1/p' "$REPO_ROOT/pkg/mlx/render.go")"
	[ -n "$go_mount" ] && [ "$CACHE_MOUNT" = "$go_mount" ] && st ok "gate cache mount equals the serving pod's ($go_mount)" || st no "gate cache mount equals the serving pod's (${go_mount:-unparsed})"
	[ -n "$go_home" ] && [ "$HF_HOME_PATH" = "$go_mount$go_home" ] && grep -qF -- "value: $go_mount$go_home" <<<"$j" &&
		st ok "seed Job HF_HOME equals the serving pod's ($go_mount$go_home)" || st no "seed Job HF_HOME equals the serving pod's"
	grep -qF "cache_dir=c" <<<"$j" && grep -qF "c='.'+os.environ['HF_HOME']" <<<"$j" &&
		st ok "seed download targets a relative cache_dir under the mount" || st no "seed download targets a relative cache_dir under the mount"
	body="$(cat "$0")"
	del_line="$(printf '%s\n' "$body" | grep -n '^delete_seed_job$' | head -1 | cut -d: -f1)"
	seed_line="$(printf '%s\n' "$body" | grep -n 'render_seed_job "\$NS"' | head -1 | cut -d: -f1)"
	ready_line="$(printf '%s\n' "$body" | grep -n '^# m8.4 Ready' | head -1 | cut -d: -f1)"
	[ -n "$del_line" ] && [ -n "$seed_line" ] && [ -n "$ready_line" ] && [ "$seed_line" -lt "$del_line" ] && [ "$del_line" -lt "$ready_line" ] &&
		st ok "seed Job is deleted after m8.3-b and before m8.4" || st no "seed Job is deleted after m8.3-b and before m8.4"
	grep -q 'cascade=foreground' <<<"$body" && st ok "seed Job delete is foreground" || st no "seed Job delete is foreground"
	[ "$(seed_image lab-ns)" = "$(grep -E '^[[:space:]]*image:' "$EXAMPLE" | head -1 | sed -E 's#^[[:space:]]*image:[[:space:]]*##')" ] &&
		st ok "seed image is the example's serving image" || st no "seed image is the example's serving image"
	[ "$("$0" --render-seed-job lab-ns node-a "cache-$MODEL_NAME-0")" = "$(render_seed_job lab-ns node-a "$(seed_image lab-ns)" "cache-$MODEL_NAME-0")" ] &&
		st ok "--render-seed-job prints the m8.3-b seed Job for the example's image" || st no "--render-seed-job prints the m8.3-b seed Job for the example's image"
	if "$0" --render-seed-job lab-ns >/dev/null 2>&1; then st no "--render-seed-job refuses a short argument list"; else
		[ $? -eq 2 ] && st ok "--render-seed-job refuses a short argument list" || st no "--render-seed-job refuses a short argument list"; fi
	exit "$st_fail"
fi

# --------------------------------------------------------------------------------
# --render-seed-job <namespace> <node> <pvc>: print the seed Job for the shipped
# example's pinned revision, so another driver that applies examples/mlxmodel.yaml
# (the release gate's demo tier) seeds the cache volume the way m8.3-b does, from
# this one rendering, rather than carrying a copy of it. A pinned revision is
# loaded from the cache and never fetched into it (pkg/mlx modelReference), so a
# driver that skips this step waits on a replica that crash-loops for as long as
# the cache stays empty.
# --------------------------------------------------------------------------------
if [ "${1:-}" = "--render-seed-job" ]; then
	[ $# -eq 4 ] || { echo "m8.sh: --render-seed-job <namespace> <node> <pvc>" >&2; exit 2; }
	render_seed_job "$2" "$3" "$(seed_image "$2")" "$4"
	exit 0
fi

# --------------------------------------------------------------------------------
# --plan: the ladder, the pins, and nothing else. No cluster, no network, no files
# written. It exists so the gate's SHAPE is reviewable on a machine that has no GPU
# and no cluster — which is every machine that reviews the PR that adds it.
# --------------------------------------------------------------------------------
if [ "${1:-}" = "--plan" ] || [ "${1:-}" = "--dry-run" ]; then
	echo "==> k3sm M8 gate — PLAN ONLY (nothing is contacted, nothing is written)"
	echo
	echo "pins"
	echo "  example       examples/mlxmodel.yaml"
	echo "  MLXModel      $MODEL_NAME"
	echo "  model repo    $MODEL_REPO"
	echo "  revision      $MODEL_REV"
	echo "  serving port  $SERVING_PORT"
	echo "  image         ${K3SM_MLX_IMAGE:-<from the example; override with K3SM_MLX_IMAGE>}"
	echo
	echo "bounds"
	echo "  ready timeout    ${READY_TIMEOUT}s"
	echo "  delete timeout   ${DELETE_TIMEOUT}s"
	echo "  per-request      ${REQ_TIMEOUT}s"
	echo "  concurrency      $CONCURRENCY (engine --max-num-seqs ceiling is 4)"
	echo
	echo "ladder"
	echo "  m8.0  preflight   GPU node + MLXModel CRD established + example present"
	echo "  m8.1  pre-seed    nothing staged on the host; the seed runs on the cluster"
	echo "  m8.2  apply       kubectl apply -f examples/mlxmodel.yaml"
	echo "  m8.3  volume      cache PVC Bound; a seed Job writes the pinned snapshot into it"
	echo "  m8.4  ready       status.conditions[Ready]=True AND observedGeneration current"
	echo "  m8.5  endpoint    ClusterIP allocated; status.endpoint published"
	echo "  m8.5-c served id  GET /v1/models (singular) — the id every completion posts"
	echo "  m8.6  completion  POST /v1/chat/completions via the ClusterIP returns tokens"
	echo "  m8.7  concurrent  $CONCURRENCY simultaneous completions ALL succeed (see hack/spike/m8/findings-s5.md)"
	echo "  m8.8  latency     TTFT + tokens/sec, ClusterIP vs direct pod (recorded)"
	echo "  m8.9  deletion    every operator-owned object absent; PVC deleted; PV retained"
	echo
	echo "requires: dev-mac, apple-gpu, network   (phases.json M8 row)"
	exit 0
fi

if [ $# -gt 0 ]; then
	echo "m8.sh: unknown argument: $1 (try --plan, --self-test or --render-seed-job)" >&2
	exit 2
fi

if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at a RUNNING k3sm cluster on an apple-gpu Mac (this gate boots nothing itself)" >&2
	exit 1
fi
command -v kubectl >/dev/null 2>&1 || { echo "kubectl not on PATH" >&2; exit 1; }
kubectl --request-timeout=10s get --raw /healthz >/dev/null || {
	echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1
}

NS="${K3SM_MLX_NAMESPACE:-$(grep -E '^  namespace:' "$EXAMPLE" | head -1 | awk '{print $2}')}"
NS="${NS:-default}"

MANIFEST=""
cleanup() {
	kubectl delete mlxmodel "$MODEL_NAME" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kubectl delete job "m8-seed-$MODEL_NAME" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	[ -n "$MANIFEST" ] && rm -f "$MANIFEST"
	return 0
}
trap cleanup EXIT

echo "==> k3sm M8 gate — MLX serving ($MODEL_REPO @ ${MODEL_REV:0:12}, ns $NS)"

# --------------------------------------------------------------------------------
# m8.0 preflight
# --------------------------------------------------------------------------------
if [ -f "$EXAMPLE" ]; then
	ladder ok "m8.0-a  examples/mlxmodel.yaml present"
else
	ladder no "m8.0-a  examples/mlxmodel.yaml MISSING — the gate applies the shipped example, not an inline copy"
	echo "----------------------------------------"; echo "M8: $PASS passed, $FAIL failed, $SKIP skipped"; exit 1
fi

# The pins above are the gate's contract with the example. Assert, do not assume.
pins_ok=1
grep -q "name: $MODEL_NAME\$" "$EXAMPLE" || { pins_ok=0; note "example does not name $MODEL_NAME"; }
grep -q "model: $MODEL_REPO\$" "$EXAMPLE" || { pins_ok=0; note "example does not pin $MODEL_REPO"; }
grep -q "revision: $MODEL_REV\$" "$EXAMPLE" || { pins_ok=0; note "example does not pin revision $MODEL_REV"; }
grep -q "port: $SERVING_PORT\$" "$EXAMPLE" || { pins_ok=0; note "example does not set port $SERVING_PORT"; }
if [ "$pins_ok" -eq 1 ]; then
	ladder ok "m8.0-b  gate pins agree with the example (name/model/revision/port)"
else
	ladder no "m8.0-b  gate pins DISAGREE with the example — one of the two was edited alone"
fi

GPU_CAP="$(kubectl get nodes -o jsonpath='{.items[*].status.allocatable.mlx\.k3sm\.io/gpu}' 2>/dev/null || true)"
if grep -qE '[1-9]' <<<"$GPU_CAP"; then
	ladder ok "m8.0-c  a node advertises the mlx.k3sm.io/gpu extended resource (allocatable: $GPU_CAP)"
else
	ladder no "m8.0-c  NO node advertises mlx.k3sm.io/gpu — this gate requires apple-gpu (got: '${GPU_CAP:-none}')"
fi

CRD_EST="$(kubectl get crd mlxmodels.mlx.k3sm.io -o jsonpath='{.status.conditions[?(@.type=="Established")].status}' 2>/dev/null || true)"
if [ "$CRD_EST" = "True" ]; then
	ladder ok "m8.0-d  the MLXModel CRD is Established"
else
	ladder no "m8.0-d  the MLXModel CRD is not Established (got '${CRD_EST:-absent}') — the operator ensures it at start-up"
fi

if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "M8: $PASS passed, $FAIL failed, $SKIP skipped — preflight failed, not running the serving legs"
	exit 1
fi

# --------------------------------------------------------------------------------
# m8.1 pre-seed. Nothing is staged on the host: the volume lives under a root-owned
# tree, and an operator on k3sm does not copy into it by hand. The weights are
# seeded by a Job on the cluster at m8.3-b.
# --------------------------------------------------------------------------------
ladder ok "m8.1  pre-seed — no host staging; the seed Job writes the volume at m8.3-b"

# --------------------------------------------------------------------------------
# m8.2 apply the shipped example.
#
# The example is applied as-is except for the namespace (rendered to $NS) and, when
# K3SM_MLX_IMAGE is set, the image. Both are line-level substitutions on a COPY: the
# point of this gate is to prove the manifest users are handed, so the file itself
# is never rewritten.
# --------------------------------------------------------------------------------
MANIFEST="$(mktemp -t m8-mlxmodel).yaml"
render_manifest "$NS" > "$MANIFEST"
[ -z "${K3SM_MLX_IMAGE:-}" ] || note "image overridden: $K3SM_MLX_IMAGE"
if [ -n "${K3SM_MLX_NAMESPACE:-}" ]; then
	kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null
fi

kubectl delete mlxmodel "$MODEL_NAME" -n "$NS" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true
if kubectl apply -n "$NS" -f "$MANIFEST" >/dev/null; then
	ladder ok "m8.2  examples/mlxmodel.yaml applied (admitted by the real admission chain)"
else
	ladder no "m8.2  examples/mlxmodel.yaml REJECTED at apply"
	echo "----------------------------------------"; echo "M8: $PASS passed, $FAIL failed, $SKIP skipped"; exit 1
fi

STS="$MODEL_NAME"
SVC="$MODEL_NAME"
HEADLESS="$MODEL_NAME-headless"
PVC="cache-$MODEL_NAME-0"

# --------------------------------------------------------------------------------
# m8.3 the cache PVC binds, and the seed is copied into its local path.
#
# local-path binds WaitForFirstConsumer, so the PV does not exist until the
# scheduler has placed the pod. That is also what makes the copy possible at all:
# by the time the path exists the replica is still pulling the serving image.
# --------------------------------------------------------------------------------
PV=""
deadline=$((SECONDS + 300))
while [ "$SECONDS" -lt "$deadline" ]; do
	PV="$(kubectl get pvc "$PVC" -n "$NS" -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)"
	[ -n "$PV" ] && break
	sleep 3
done
if [ -n "$PV" ]; then
	ladder ok "m8.3-a  cache PVC $PVC bound to $PV"
else
	ladder no "m8.3-a  cache PVC $PVC did not bind within 300s"
fi

# m8.3-b: a Job writes the pinned snapshot into the PVC. The replica pod places the
# PV on a node, so the Job is pinned to that pod's node.
SEED_NODE=""
deadline=$((SECONDS + 300))
while [ "$SECONDS" -lt "$deadline" ]; do
	SEED_NODE="$(kubectl get pod "$STS-0" -n "$NS" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
	[ -n "$SEED_NODE" ] && break
	sleep 3
done
SEED_JOB="m8-seed-$MODEL_NAME"
if [ -z "$SEED_NODE" ]; then
	ladder no "m8.3-b  pod $STS-0 was not scheduled within 300s; no node to seed on"
elif render_seed_job "$NS" "$SEED_NODE" "$(seed_image "$NS")" "$PVC" | kubectl apply -f - >/dev/null &&
	kubectl wait --for=condition=complete "job/$SEED_JOB" -n "$NS" --timeout=900s >/dev/null 2>&1; then
	ladder ok "m8.3-b  seed Job wrote $MODEL_REPO @ ${MODEL_REV:0:12} into $PVC on $SEED_NODE"
else
	ladder no "m8.3-b  seed Job did not complete"
	kubectl logs -n "$NS" "job/$SEED_JOB" --tail=20 2>&1 | sed 's/^/      /' || true
fi
# Remove the seed Job and wait for its pods to go: a completed pod still references
# the claim, and the pvc-protection finalizer would then keep the PVC after the
# StatefulSet's whenDeleted:Delete fires (m8.9-pvc). The EXIT trap is the backstop.
delete_seed_job
# The pod crash-looped on the empty cache until now; restart it onto the snapshot.
kubectl delete pod "$STS-0" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true

# --------------------------------------------------------------------------------
# m8.4 Ready — via CONDITIONS, with observedGeneration.
# --------------------------------------------------------------------------------
ready=0
deadline=$((SECONDS + READY_TIMEOUT))
last=""
while [ "$SECONDS" -lt "$deadline" ]; do
	cond="$(kubectl get mlxmodel "$MODEL_NAME" -n "$NS" \
		-o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
	obs="$(kubectl get mlxmodel "$MODEL_NAME" -n "$NS" -o jsonpath='{.status.observedGeneration}' 2>/dev/null || true)"
	gen="$(kubectl get mlxmodel "$MODEL_NAME" -n "$NS" -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"
	if [ "$cond" = "True" ] && [ -n "$obs" ] && [ "$obs" = "$gen" ]; then
		ready=1
		break
	fi
	reason="$(kubectl get mlxmodel "$MODEL_NAME" -n "$NS" \
		-o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)"
	if [ "$reason" != "$last" ]; then
		note "Ready=${cond:-?} reason=${reason:-?} observedGeneration=${obs:-?}/${gen:-?} (${SECONDS}s)"
		last="$reason"
	fi
	sleep 10
done
if [ "$ready" -eq 1 ]; then
	ladder ok "m8.4  Ready condition True with observedGeneration == metadata.generation"
else
	ladder no "m8.4  not Ready within ${READY_TIMEOUT}s (last reason: ${last:-none})"
	kubectl get pods -n "$NS" -l "app.kubernetes.io/instance=$MODEL_NAME" 2>&1 | sed 's/^/      /' || true
	kubectl logs -n "$NS" "$STS-0" --tail=40 2>&1 | sed 's/^/      /' || true
	echo "----------------------------------------"; echo "M8: $PASS passed, $FAIL failed, $SKIP skipped"; exit 1
fi

# --------------------------------------------------------------------------------
# m8.5 the ClusterIP Service and the published endpoint.
# --------------------------------------------------------------------------------
CLUSTER_IP="$(kubectl get svc "$SVC" -n "$NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
if [ -n "$CLUSTER_IP" ] && [ "$CLUSTER_IP" != "None" ]; then
	ladder ok "m8.5-a  ClusterIP Service $SVC allocated $CLUSTER_IP"
else
	ladder no "m8.5-a  ClusterIP Service $SVC has no VIP (got '${CLUSTER_IP:-absent}')"
fi
ENDPOINT="$(kubectl get mlxmodel "$MODEL_NAME" -n "$NS" -o jsonpath='{.status.endpoint}' 2>/dev/null || true)"
if [ -n "$ENDPOINT" ]; then
	ladder ok "m8.5-b  status.endpoint published: $ENDPOINT"
else
	ladder no "m8.5-b  status.endpoint is empty while Ready — clients have no address to use"
fi
POD_IP="$(kubectl get pod "$STS-0" -n "$NS" -o jsonpath='{.status.podIP}' 2>/dev/null || true)"

VIP="$CLUSTER_IP:$SERVING_PORT"

# --------------------------------------------------------------------------------
# m8.5-c the served model id — GET /v1/models, never assumed from the spec.
#
# The engine registers whatever it decided to call the served snapshot — often
# a resolved on-disk PATH, not examples/mlxmodel.yaml's repo id — so a
# completion posted against MODEL_REPO 404s a Ready pod. Ask the
# serving surface directly, require EXACTLY one model listed (a plural listing
# would make "the" served id ambiguous), and use THAT id for every completion
# below. m8.0-b's pin check is a different assertion (the SPEC matches the
# gate's pins) and is untouched by this rung.
# --------------------------------------------------------------------------------
models_body="$(mktemp)"
models_code="$(curl -sS -m "$REQ_TIMEOUT" -o "$models_body" -w '%{http_code}' "http://$VIP/v1/models" 2>/dev/null || echo 000)"
SERVED_MODEL_ID="$(python3 - "$models_body" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    data = d.get("data", [])
    if len(data) == 1:
        print(data[0]["id"])
except Exception:
    pass
PY
)"
rm -f "$models_body"
if [ "$models_code" = "200" ] && [ -n "$SERVED_MODEL_ID" ]; then
	ladder ok "m8.5-c  /v1/models lists exactly one model — served id: $SERVED_MODEL_ID"
else
	ladder no "m8.5-c  /v1/models did not list exactly one model (http $models_code) — cannot derive the served id"
	echo "----------------------------------------"; echo "M8: $PASS passed, $FAIL failed, $SKIP skipped"; exit 1
fi

# completion <addr> <max_tokens> <outfile> -> prints "<http_code> <ttfb> <total>"
# The body is written to outfile so the caller can assert on content; only the
# timing triple comes back on stdout. Posts SERVED_MODEL_ID (m8.5-c), never
# MODEL_REPO — the served id is what the engine actually answers to.
completion() {
	curl -sS -m "$REQ_TIMEOUT" -o "$3" -w '%{http_code} %{time_starttransfer} %{time_total}' \
		-H 'Content-Type: application/json' \
		-d "{\"model\":\"$SERVED_MODEL_ID\",\"messages\":[{\"role\":\"user\",\"content\":\"Name three primary colours.\"}],\"max_tokens\":$2,\"temperature\":0}" \
		"http://$1/v1/chat/completions" 2>/dev/null || echo "000 0 0"
}

# tokens_of <file> -> the completion's text, empty when the response is not a
# well-formed OpenAI chat completion.
tokens_of() {
	python3 - "$1" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d["choices"][0]["message"]["content"].strip())
except Exception:
    pass
PY
}

# completion_tokens_of <file> -> usage.completion_tokens, or 0.
completion_tokens_of() {
	python3 - "$1" <<'PY' 2>/dev/null || echo 0
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(int(d.get("usage", {}).get("completion_tokens", 0)))
except Exception:
    print(0)
PY
}

# --------------------------------------------------------------------------------
# m8.6 one chat completion through the ClusterIP returns tokens.
# --------------------------------------------------------------------------------
body="$(mktemp)"
read -r code _ _ <<<"$(completion "$VIP" 64 "$body")"
text="$(tokens_of "$body")"
if [ "$code" = "200" ] && [ -n "$text" ]; then
	ladder ok "m8.6  OpenAI chat completion through the ClusterIP returned tokens"
	note "reply: $(printf '%s' "$text" | head -c 120)"
else
	ladder no "m8.6  chat completion through the ClusterIP returned no tokens (http $code)"
	head -c 400 "$body" | sed 's/^/      /' || true
fi
rm -f "$body"

# --------------------------------------------------------------------------------
# m8.7 THE CONCURRENCY RUNG (see hack/spike/m8/findings-s5.md). See the header.
# --------------------------------------------------------------------------------
cdir="$(mktemp -d)"
pids=""
i=1
while [ "$i" -le "$CONCURRENCY" ]; do
	( completion "$VIP" 48 "$cdir/body.$i" > "$cdir/meta.$i" ) &
	pids="$pids $!"
	i=$((i + 1))
done
for p in $pids; do wait "$p" || true; done

ok_n=0; got503=0
i=1
while [ "$i" -le "$CONCURRENCY" ]; do
	c="$(awk '{print $1}' "$cdir/meta.$i" 2>/dev/null || echo 000)"
	t="$(tokens_of "$cdir/body.$i")"
	if [ "$c" = "200" ] && [ -n "$t" ]; then
		ok_n=$((ok_n + 1))
	else
		note "request $i: http $c $(head -c 160 "$cdir/body.$i" 2>/dev/null | tr '\n' ' ')"
		[ "$c" = "503" ] && got503=1
	fi
	i=$((i + 1))
done
rm -rf "$cdir"

if [ "$ok_n" -eq "$CONCURRENCY" ]; then
	ladder ok "m8.7  all $CONCURRENCY concurrent completions succeeded (continuous batching is live)"
else
	ladder no "m8.7  only $ok_n of $CONCURRENCY concurrent completions succeeded"
	if [ "$got503" -eq 1 ]; then
		note "HTTP 503 under concurrency is the S5 signature of a MISSING --continuous-batching"
		note "in the engine argv: one request served, the rest rejected, /health still green."
		note "Check the rendered args (kubectl get sts $STS -n $NS -o jsonpath='{.spec.template.spec.containers[0].args}')"
	fi
fi

# --------------------------------------------------------------------------------
# m8.8 TTFT + tokens/sec, ClusterIP vs the pod directly. Recorded, not thresholded.
# --------------------------------------------------------------------------------
measure() { # measure <label> <addr>
	local_body="$(mktemp)"
	read -r c f t <<<"$(completion "$2" 128 "$local_body")"
	n="$(completion_tokens_of "$local_body")"
	rm -f "$local_body"
	case "$n" in ''|*[!0-9]*) n=0 ;; esac
	if [ "$c" != "200" ] || [ "$n" -eq 0 ]; then
		echo "$1|FAIL|$c|0|0"
		return
	fi
	rate="$(python3 -c "print(f'{$n/max($t,1e-6):.1f}')" 2>/dev/null || echo 0)"
	echo "$1|OK|$f|$t|$rate"
}

vip_m="$(measure clusterip "$VIP")"
IFS='|' read -r _ vstate vttfb vtotal vrate <<<"$vip_m"
if [ -n "$POD_IP" ]; then
	pod_m="$(measure direct "$POD_IP:$SERVING_PORT")"
else
	pod_m="direct|FAIL|0|0|0"
fi
IFS='|' read -r _ pstate pttfb ptotal prate <<<"$pod_m"

if [ "$vstate" = "OK" ] && [ "$pstate" = "OK" ]; then
	ladder ok "m8.8  both paths answered; TTFT and tokens/sec recorded"
else
	ladder no "m8.8  a measurement path did not answer (clusterip=$vstate direct=$pstate)"
fi
note "path       TTFT(s)  total(s)  tok/s"
note "clusterip  ${vttfb}  ${vtotal}  ${vrate}"
note "direct     ${pttfb}  ${ptotal}  ${prate}"
note "(TTFT here is time-to-first-byte of a non-streamed reply, so it includes"
note " generation; the ClusterIP-vs-direct DELTA is the Service-proxy hop.)"

# --------------------------------------------------------------------------------
# m8.9 deletion — poll every operator-owned object to ABSENT.
# --------------------------------------------------------------------------------
kubectl delete mlxmodel "$MODEL_NAME" -n "$NS" --wait=false >/dev/null 2>&1 || true

# gone <kind> <name> -> 0 once the object is absent, bounded by DELETE_TIMEOUT.
gone() {
	d=$((SECONDS + DELETE_TIMEOUT))
	while [ "$SECONDS" -lt "$d" ]; do
		kubectl get "$1" "$2" -n "$NS" </dev/null >/dev/null 2>&1 || return 0
		sleep 3
	done
	return 1
}
while read -r kind name; do
	[ -n "$kind" ] || continue
	if gone "$kind" "$name"; then
		ladder ok "m8.9-gc  $kind/$name gone"
	else
		ladder no "m8.9-gc  $kind/$name still present after ${DELETE_TIMEOUT}s — the ownerReference cascade did not reach it"
	fi
done <<EOF
mlxmodel $MODEL_NAME
statefulset $STS
service $SVC
service $HEADLESS
pod $STS-0
EOF

# The PVC is NOT owner-referenced: ownerReferences do not cascade through a
# StatefulSet's volumeClaimTemplates, which is exactly why the render sets
# whenDeleted:Delete. This rung asserts that policy actually fired.
if gone pvc "$PVC"; then
	ladder ok "m8.9-pvc  cache PVC $PVC deleted per whenDeleted:Delete"
else
	ladder no "m8.9-pvc  cache PVC $PVC survived — whenDeleted:Delete did not fire"
fi

# ...and that the PV did NOT go with it. local-path reclaims Retain, so the
# weights on disk outlive the PVC and are removed by hand. A PV that vanished
# here would mean data was deleted by a policy nobody asked for.
if [ -n "$PV" ]; then
	PVPHASE="$(kubectl get pv "$PV" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
	if [ -n "$PVPHASE" ]; then
		ladder ok "m8.9-pv   PV $PV retained (phase $PVPHASE) — local-path reclaims Retain"
	else
		ladder no "m8.9-pv   PV $PV is gone — local-path must RETAIN, weights are reclaimed by hand"
	fi
else
	ladder skip "m8.9-pv   no PV was bound; nothing to assert about retention"
fi

echo "----------------------------------------"
echo "M8: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M8 GREEN ================"
