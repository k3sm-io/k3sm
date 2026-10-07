#!/usr/bin/env bash
# M17.0 / S5 — two mlx-lm ranks over the ring backend, between pods on the two Macs.
#
#   (1) Two native pods (one per Mac) from the mlx-serve image, each holding one GPU
#       slot; the ranks are started by `kubectl exec` with a hostfile of the two POD
#       IPs, so each rank binds its own pod IP and dials the other's, under the pod
#       network shim. An all_sum across the pair proves both directions.
#   (2) The pinned tiny model is loaded sharded (mlx_lm's sharded_load, tensor
#       parallel, as the sharded MLXModel's entrypoint does) and a fixed prompt is
#       generated; rank 0's tokens/s is recorded per path: ring over the direct
#       /25s, ring over wireguard-over-cable (K3SM_M17_WG_CABLE_ROUTE=1), ring over
#       Wi-Fi (the mesh on the LAN), and the same model on one Mac, each Mac — so a
#       negative result is published as such (R15: figures before claims).
# The laptop has 8 GiB, so the model is the smallest the M16 spike pins, and each
# rank asks for K3SM_M17_RANK_MEMORY (default 3Gi).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$HERE/lib.sh"

RUNG="S5"
QUESTION="Do two mlx-lm ranks in pods on the two Macs bind and dial each other's pod IPs over the ring backend, and
what tokens/s does a sharded tiny model reach over the direct path, wireguard over the cable and Wi-Fi, against the
same model on one Mac?"
CRITERIA="s5.1 over the direct path both ranks initialise the ring with size 2 and an all_sum across them returns 2
s5.2 over the direct path rank 0 generates the fixed prompt from the sharded model (tokens/s > 0)
RECORDED: tokens/s (median, p99) for ring-over-direct, ring-over-wg-cable, ring-over-Wi-Fi, single-Mac on each Mac;
the image digest the tag resolved to; the sharded_load parallelism used"
METHOD="Two pods (restartPolicy Never, pinned by nodeName, the MLX guardrail stanza: darwin + GPU-present selectors,
the provider toleration, one mlx.k3sm.io/gpu in requests and limits) from $MLX_IMAGE, idle until exec'd; a ConfigMap
carries rank.py. Per path the driver configures the cable (the S2 configuration, restore trap held), then execs
rank.py in both pods at once with the pod-IP hostfile; the model is $MODEL_REPO at $MODEL_REV, fixed prompt,
max_tokens 128, K3SM_M17_S5_RUNS (default 3) generations per path."
HALT="s5.1/s5.2 fail with the 8 GiB worker's rank out of memory -> R8: the rung moves the model to the workstation.
s5.1/s5.2 fail otherwise (the ranks cannot bind or dial pod IPs) -> no substitution is pre-decided: the sharded
  path of the M17 plan §5 does not hold under the pod network, and the spike stops for a re-plan."

spike_args "$RUNG" "$QUESTION" "$CRITERIA" "$METHOD" "$HALT" "$@"
spike_begin "$RUNG"

S5_RUNS="${K3SM_M17_S5_RUNS:-3}"
R8_S5="halt (R8): the rung moves the model to the workstation"

spike_cleanup() {
	kc delete namespace "$NS" --ignore-not-found --wait=false </dev/null >/dev/null 2>&1 || true
}

# kexec <pod> <seconds> <args...> — kubectl exec in a pod with a local bound (no
# request timeout: a generation streams for minutes).
kexec() {
	local pod="$1" secs="$2" pid w rc=0
	shift 2
	on server "k3sm kubectl exec -n $NS $pod -- $(printf '%q ' "$@")" </dev/null &
	pid=$!
	(
		sleep "$secs"
		kill -TERM "$pid" 2>/dev/null
	) &
	w=$!
	wait "$pid" || rc=$?
	kill "$w" 2>/dev/null
	return "$rc"
}

# ---------------------------------------------------------------------------------
note "S5 setup — the namespace, rank.py, two rank pods"
# ---------------------------------------------------------------------------------
for n in "$SRV_NODE" "$WRK_NODE"; do
	g="$(kc get node "$n" -o 'jsonpath={.metadata.labels.mlx\.k3sm\.io/gpu\.present}' </dev/null 2>/dev/null)"
	[ "$g" = true ] || fail "s5 setup: node $n does not advertise mlx.k3sm.io/gpu.present=true (got '$g')"
done
if [ "$FAILS" -gt 0 ]; then spike_end "$RUNG"; fi

# Indented to sit under the ConfigMap's `rank.py: |` key.
RANK_PY="$(sed 's/^/    /' <<'PY'
import json, os, sys, time
mode, rank, world, hostfile, repo, rev, runs = sys.argv[1:8]
os.environ.setdefault("MLX_METAL_FAST_SYNCH", "1")
def say(**kv):
    print(json.dumps(kv), flush=True)
from huggingface_hub import snapshot_download
path = snapshot_download(repo, revision=rev)
say(event="downloaded", rank=int(rank))
import mlx.core as mx
from mlx_lm import load, stream_generate
group = None
if mode == "ring":
    hf = os.path.join(os.environ.get("HF_HOME", "/cache"), "..", f"hostfile-{rank}.json")
    with open(hf, "w") as f:
        f.write(hostfile)
    os.environ.update(MLX_RANK=rank, MLX_WORLD_SIZE=world, MLX_HOSTFILE=hf)
    group = mx.distributed.init(backend="ring", strict=True)
    say(event="init", rank=group.rank(), size=group.size())
    s = mx.distributed.all_sum(mx.ones(1), group=group)
    mx.eval(s)
    say(event="all_sum", rank=group.rank(), value=float(s.item()))
    from mlx_lm.utils import sharded_load
    try:
        model, tok = sharded_load(path, tensor_group=group)
        say(event="loaded", parallelism="tensor")
    except TypeError:
        model, tok = sharded_load(path, pipeline_group=group)
        say(event="loaded", parallelism="pipeline")
else:
    model, tok = load(path)
    say(event="loaded", parallelism="none")
prompt = "Count from one to twenty in words."
if hasattr(tok, "apply_chat_template"):
    prompt = tok.apply_chat_template([{"role": "user", "content": prompt}], add_generation_prompt=True, tokenize=False)
for i in range(int(runs)):
    last = None
    for last in stream_generate(model, tok, prompt, max_tokens=128):
        pass
    if group is None or group.rank() == 0:
        say(event="gen", run=i, tps=last.generation_tps, tokens=last.generation_tokens)
PY
)"

pod_yaml() { # pod_yaml <name> <node>
	cat <<EOF
---
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: $NS
  labels:
    app.kubernetes.io/name: k3sm-m17-spike
spec:
  nodeName: $2
  restartPolicy: Never
  nodeSelector:
    kubernetes.io/os: darwin
    mlx.k3sm.io/gpu.present: "true"
  # The provider taint by key, in the exact shape k3sm's admission policy checks on
  # a GPU pod (pkg/mlx providerTolerations); never a key-less toleration.
  tolerations:
  - key: k3sm.io/provider
    operator: Exists
    effect: NoSchedule
  containers:
  - name: rank
    image: $MLX_IMAGE
    command: ["/bin/python3.12", "-c", "import time; time.sleep(86400)"]
    env:
    - name: HF_HOME
      value: /cache/hf
    ports:
    - name: collective
      containerPort: $COLLECTIVE_PORT
    resources:
      requests:
        mlx.k3sm.io/gpu: "1"
        memory: $RANK_MEMORY
      limits:
        mlx.k3sm.io/gpu: "1"
        memory: $RANK_MEMORY
    volumeMounts:
    - name: cache
      mountPath: /cache
    - name: spike
      mountPath: /spike
  volumes:
  - name: cache
    emptyDir: {}
  - name: spike
    configMap:
      name: m17-rank
EOF
}

{
	cat <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: m17-rank
  namespace: $NS
data:
  rank.py: |
$RANK_PY
EOF
	pod_yaml m17-rank0 "$SRV_NODE"
	pod_yaml m17-rank1 "$WRK_NODE"
} >"$RUNG_DIR/s5.yaml"
kc apply -f - <"$RUNG_DIR/s5.yaml" >"$RUNG_DIR/s5-apply.txt" 2>&1 || fail "s5 setup: the rank pods were not admitted (see $RUNG_DIR/s5-apply.txt)"
if [ "$FAILS" -gt 0 ]; then spike_end "$RUNG"; fi
if ! on server "k3sm kubectl wait -n $NS --for=condition=Ready pod/m17-rank0 pod/m17-rank1 --timeout=20m" </dev/null >"$RUNG_DIR/s5-wait.txt" 2>&1; then
	kc get pods -n "$NS" -o wide </dev/null >>"$RUNG_DIR/s5-wait.txt" 2>&1
	kc get events -n "$NS" </dev/null >>"$RUNG_DIR/s5-wait.txt" 2>&1
	fail "s5 setup: the rank pods did not become Ready in 20 minutes (see $RUNG_DIR/s5-wait.txt)"
	spike_end "$RUNG"
fi
IP0="$(kc get pod m17-rank0 -n "$NS" -o 'jsonpath={.status.podIP}' </dev/null)"
IP1="$(kc get pod m17-rank1 -n "$NS" -o 'jsonpath={.status.podIP}' </dev/null)"
record "s5 image $MLX_IMAGE resolved to $(kc get pod m17-rank0 -n "$NS" -o 'jsonpath={.status.containerStatuses[0].imageID}' </dev/null)"
record "s5 rank pods: rank0 $IP0 on the server, rank1 $IP1 on the worker; model $MODEL_REPO@$MODEL_REV"
HOSTFILE="[[\"$IP0:$COLLECTIVE_PORT\"],[\"$IP1:$COLLECTIVE_PORT\"]]"

# ring <path> — both ranks at once; rank logs in the evidence directory.
ring() {
	local path="$1" l0="$RUNG_DIR/ring-$1-rank0.jsonl" l1="$RUNG_DIR/ring-$1-rank1.jsonl" p1
	kexec m17-rank1 1800 /bin/python3.12 /spike/rank.py ring 1 2 "$HOSTFILE" "$MODEL_REPO" "$MODEL_REV" "$S5_RUNS" >"$l1" 2>&1 &
	p1=$!
	kexec m17-rank0 1800 /bin/python3.12 /spike/rank.py ring 0 2 "$HOSTFILE" "$MODEL_REPO" "$MODEL_REV" "$S5_RUNS" >"$l0" 2>&1
	wait "$p1" 2>/dev/null || true
	{
		echo "CMD tps-ring-$path python3.12 rank.py ring <rank> 2 <hostfile: rank0-pod-ip:$COLLECTIVE_PORT, rank1-pod-ip:$COLLECTIVE_PORT> $MODEL_REPO $MODEL_REV (max_tokens 128)"
		sed -n 's/.*"event": "gen".*"tps": \([0-9.e+-]*\).*/FIG tps-ring-'"$path"' \1/p' "$l0"
	} >"$RUNG_DIR/ring-$path.fig"
	figures_from_log "ring-$path" "$RUNG_DIR/ring-$path.fig"
}

oom_on_worker() {
	kc get pod m17-rank1 -n "$NS" -o 'jsonpath={.status.containerStatuses[0].state.terminated.reason}{.status.containerStatuses[0].lastState.terminated.reason}' </dev/null 2>/dev/null | grep -q OOMKilled ||
		grep -qiE 'killed|out of memory|MemoryError|exit code 137' "$RUNG_DIR/ring-direct-rank1.jsonl"
}

# ---------------------------------------------------------------------------------
note "S5(1,2) — ring over the direct path (the S2 configuration, /25s on)"
# ---------------------------------------------------------------------------------
spike_configure_link server routes
spike_configure_link worker routes
ring direct
sums="$(cat "$RUNG_DIR/ring-direct-rank0.jsonl" "$RUNG_DIR/ring-direct-rank1.jsonl" | grep -c '"event": "all_sum".*"value": 2.0' || true)"
inits="$(cat "$RUNG_DIR/ring-direct-rank0.jsonl" "$RUNG_DIR/ring-direct-rank1.jsonl" | grep -c '"event": "init".*"size": 2' || true)"
if [ "$inits" = 2 ] && [ "$sums" = 2 ]; then
	pass "s5.1 both ranks bound and dialled their pod IPs over the ring ($IP0 <-> $IP1): size 2, all_sum = 2 on each"
elif oom_on_worker; then
	fail "s5.1 the worker's rank ran out of memory before the ring formed (inits $inits, all_sums $sums) — $R8_S5"
else
	fail "s5.1 the ring did not form between the pod IPs (inits $inits/2, all_sums $sums/2; see $RUNG_DIR/ring-direct-rank*.jsonl) — halt: no substitution is pre-decided"
fi
par="$(sed -n 's/.*"parallelism": "\([a-z]*\)".*/\1/p' "$RUNG_DIR/ring-direct-rank0.jsonl" | head -1)"
[ -n "$par" ] && record "s5 sharded_load parallelism: $par"
if grep -q '"event": "gen"' "$RUNG_DIR/ring-direct-rank0.jsonl"; then
	pass "s5.2 rank 0 generated the fixed prompt from the sharded model over the direct path"
elif oom_on_worker; then
	fail "s5.2 the worker's rank ran out of memory during the sharded load or generation — $R8_S5"
else
	fail "s5.2 rank 0 produced no generation over the direct path (see $RUNG_DIR/ring-direct-rank0.jsonl) — halt: no substitution is pre-decided"
fi

# ---------------------------------------------------------------------------------
note "S5 — ring over wireguard on the cable, and over Wi-Fi"
# ---------------------------------------------------------------------------------
spike_restore_both
if [ "${K3SM_M17_WG_CABLE_ROUTE:-}" != 1 ]; then
	record "s5 ring-over-wg-cable: not measured — it needs K3SM_M17_WG_CABLE_ROUTE=1"
else
	kc get meshpeers -o json </dev/null >"$RUNG_DIR/meshpeers.json" 2>/dev/null || true
	ep="$(python3 - "$RUNG_DIR/meshpeers.json" "$SRV_NODE" <<'PY'
import json, sys
try:
    items = json.load(open(sys.argv[1]))["items"]
except Exception:
    items = []
for m in items:
    if m["spec"].get("nodeName") == sys.argv[2]:
        print(m["spec"].get("endpoint", "").rsplit(":", 1)[0].strip("[]"))
PY
)"
	if [ -z "$ep" ]; then
		record "s5 ring-over-wg-cable: not measured — the server's MeshPeer endpoint could not be read"
	else
		spike_configure_link server
		spike_configure_link worker
		remote_sudo worker "s5-wg-on" SPIKE_HOLD=1 EP="$ep" GW="$SRV_LINK" <<'EOF'
spike_route -host "$EP" "$GW" || verdict FAIL "s5 wg-cable: the host route to the server's wireguard endpoint was refused"
ping -c 5 -q "$EP" >/dev/null 2>&1
EOF
		sleep 15
		ring wg-cable
		spike_restore_both
	fi
fi
sleep 15
ring wifi

# ---------------------------------------------------------------------------------
note "S5 — the same model on one Mac, each Mac"
# ---------------------------------------------------------------------------------
for pair in server:m17-rank0 worker:m17-rank1; do
	side="${pair%%:*}" pod="${pair##*:}"
	l="$RUNG_DIR/single-$side.jsonl"
	kexec "$pod" 1800 /bin/python3.12 /spike/rank.py single 0 1 "" "$MODEL_REPO" "$MODEL_REV" "$S5_RUNS" >"$l" 2>&1
	{
		echo "CMD tps-single-$side python3.12 rank.py single 0 1 - $MODEL_REPO $MODEL_REV (max_tokens 128)"
		sed -n 's/.*"event": "gen".*"tps": \([0-9.e+-]*\).*/FIG tps-single-'"$side"' \1/p' "$l"
	} >"$RUNG_DIR/single-$side.fig"
	figures_from_log "single-$side" "$RUNG_DIR/single-$side.fig"
done

spike_end "$RUNG"
