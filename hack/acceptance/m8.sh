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
#   m8.1  pre-seed  — stage the pinned weights on the host. BEST EFFORT: it only
#                     shortens the first-ready wait, never decides the verdict.
#   m8.2  apply     — examples/mlxmodel.yaml, the shipped manifest itself.
#   m8.3  volume    — the cache PVC binds, and the seed lands in its local path.
#   m8.4  ready     — via CONDITIONS. status.phase is a derived printer column and
#                     is explicitly NOT the assertion: a consumer that branches on
#                     it reads a projection, and observedGeneration is what proves
#                     the condition describes THIS spec rather than the last one.
#   m8.5  endpoint  — the ClusterIP Service and the published status.endpoint.
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
#
# Knobs (all optional):
#   K3SM_MLX_IMAGE        serving image override, ideally the @sha256 digest pin
#   K3SM_MLX_NAMESPACE    namespace to run in (default: the example's own)
#   K3SM_MLX_CONCURRENCY  m8.7 concurrent requests (default 4, the engine's
#                         --max-num-seqs ceiling; below 4 the rung proves less)
#   K3SM_MLX_READY_TIMEOUT   seconds to wait for Ready (default 1800)
#   K3SM_MLX_DELETE_TIMEOUT  seconds to wait for GC (default 300)
#   K3SM_MLX_STAGE        host weight-stage dir (default ~/.cache/k3sm/m8/hf)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
EXAMPLE="$REPO_ROOT/examples/mlxmodel.yaml"

# The pins. These MUST agree with examples/mlxmodel.yaml — m8.0 asserts it rather
# than trusting it, so an edit to either file that forgets the other goes red here
# instead of silently gating a different model than the one that ships.
MODEL_NAME="qwen3-06b"
MODEL_REPO="mlx-community/Qwen3-0.6B-4bit"
MODEL_REV="73e3e38d981303bc594367cd910ea6eb48349da8"
SERVING_PORT="8000"

CONCURRENCY="${K3SM_MLX_CONCURRENCY:-4}"
READY_TIMEOUT="${K3SM_MLX_READY_TIMEOUT:-1800}"
DELETE_TIMEOUT="${K3SM_MLX_DELETE_TIMEOUT:-300}"
STAGE="${K3SM_MLX_STAGE:-$HOME/.cache/k3sm/m8/hf}"
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
	echo "  m8.1  pre-seed    stage the pinned revision on the host (best effort)"
	echo "  m8.2  apply       kubectl apply -f examples/mlxmodel.yaml"
	echo "  m8.3  volume      cache PVC Bound; seed copied into the PV local path"
	echo "  m8.4  ready       status.conditions[Ready]=True AND observedGeneration current"
	echo "  m8.5  endpoint    ClusterIP allocated; status.endpoint published"
	echo "  m8.6  completion  POST /v1/chat/completions via the ClusterIP returns tokens"
	echo "  m8.7  concurrent  $CONCURRENCY simultaneous completions ALL succeed (S5-binding)"
	echo "  m8.8  latency     TTFT + tokens/sec, ClusterIP vs direct pod (recorded)"
	echo "  m8.9  deletion    every operator-owned object absent; PVC deleted; PV retained"
	echo
	echo "requires: dev-mac, apple-gpu, network   (phases.json M8 row)"
	exit 0
fi

if [ $# -gt 0 ]; then
	echo "m8.sh: unknown argument: $1 (try --plan)" >&2
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
if printf '%s' "$GPU_CAP" | grep -qE '[1-9]'; then
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
# m8.1 pre-seed the pinned weights on the host.
#
# BEST EFFORT BY CONSTRUCTION. It never fails the gate and never skips a rung: if
# the stage cannot be built or cannot be copied in, the engine downloads the
# weights itself and the only cost is a longer m8.4. Making it fatal would turn a
# Hugging Face outage or a missing CLI into an M8 verdict, which it is not.
# --------------------------------------------------------------------------------
HF_CLI=""
if command -v hf >/dev/null 2>&1; then HF_CLI="hf"
elif command -v huggingface-cli >/dev/null 2>&1; then HF_CLI="huggingface-cli"
fi
SEEDED=0
if [ -z "$HF_CLI" ]; then
	ladder skip "m8.1  pre-seed — no hf/huggingface-cli on PATH; the engine will download in-pod"
elif HF_HOME="$STAGE" "$HF_CLI" download "$MODEL_REPO" --revision "$MODEL_REV" >/dev/null 2>&1; then
	SEEDED=1
	ladder ok "m8.1  pre-seed — pinned revision staged at $STAGE"
else
	ladder skip "m8.1  pre-seed — $HF_CLI download failed; the engine will download in-pod"
fi

# --------------------------------------------------------------------------------
# m8.2 apply the shipped example.
#
# The example is applied as-is unless K3SM_MLX_IMAGE overrides the image. The
# override is a line-level substitution on a COPY: the point of this gate is to
# prove the manifest users are handed, so the file itself is never rewritten.
# --------------------------------------------------------------------------------
MANIFEST="$(mktemp -t m8-mlxmodel).yaml"
if [ -n "${K3SM_MLX_IMAGE:-}" ]; then
	sed -E "s#^([[:space:]]*image:).*#\1 ${K3SM_MLX_IMAGE}#" "$EXAMPLE" > "$MANIFEST"
	note "image overridden: $K3SM_MLX_IMAGE"
else
	cp "$EXAMPLE" "$MANIFEST"
fi
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

PVPATH="$(kubectl get pv "$PV" -o jsonpath='{.spec.local.path}' 2>/dev/null || true)"
if [ "$SEEDED" -eq 1 ] && [ -n "$PVPATH" ] && [ -d "$PVPATH" ]; then
	# HF_HOME is set by the operator to <mount>/huggingface, so that subdirectory
	# is exactly what the stage must become. Ownership is restored to whatever owns
	# the PV directory (the unprivileged _k3sm user), or the pod cannot write the
	# cache it is about to use.
	owner="$(stat -f '%Su:%Sg' "$PVPATH" 2>/dev/null || true)"
	if mkdir -p "$PVPATH/huggingface" 2>/dev/null &&
		cp -R "$STAGE/." "$PVPATH/huggingface/" 2>/dev/null &&
		{ [ -z "$owner" ] || chown -R "$owner" "$PVPATH/huggingface" 2>/dev/null; }; then
		ladder ok "m8.3-b  staged weights copied into $PVPATH/huggingface (owner $owner)"
	else
		ladder skip "m8.3-b  could not write $PVPATH/huggingface (permissions); the engine downloads in-pod"
	fi
else
	ladder skip "m8.3-b  no staged weights to copy; the engine downloads in-pod"
fi

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

# completion <addr> <max_tokens> <outfile> -> prints "<http_code> <ttfb> <total>"
# The body is written to outfile so the caller can assert on content; only the
# timing triple comes back on stdout.
completion() {
	curl -sS -m "$REQ_TIMEOUT" -o "$3" -w '%{http_code} %{time_starttransfer} %{time_total}' \
		-H 'Content-Type: application/json' \
		-d "{\"model\":\"$MODEL_REPO\",\"messages\":[{\"role\":\"user\",\"content\":\"Name three primary colours.\"}],\"max_tokens\":$2,\"temperature\":0}" \
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
# m8.7 THE CONCURRENCY RUNG (S5-binding). See the header.
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
