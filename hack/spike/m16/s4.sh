#!/usr/bin/env bash
# M16.0-d5 / S4 — the worker, end to end.
#
# S0 proved the platform, S1 the build, S2 the control plane, S3 the engine. S4 is
# the one rung that puts all four in a line, and it is the shape M16.3 productizes:
# nothing S4 leaves undecided gets decided later by a build wave.
#
#   s4.1  the backend contract  an MLXEngine implementing the documented contract
#         (start -> config, generate -> stream, cleanup) over S3's in-process core.
#   s4.2  the conformance kit   the upstream kit's assertions, green. The kit exists
#         precisely because the contract is young and no production backend has
#         migrated to it yet, so running it is worth more here than anywhere.
#   s4.3  end to end            frontend -> worker -> tokens, first with file
#         discovery (the minimum deployment: two processes and a directory), then
#         through the frontend's ClusterIP if S2's control plane is up.
#   s4.4  the extended resource a Pod requesting mlx.k3sm.io/gpu: 1. This needs an
#         IMAGE, and M16.3 is what builds it — so the leg runs here only when the
#         operator points K3SM_M16_WORKER_IMAGE at a published one, and is otherwise
#         RECORDED as discharged by the gate's worker rung. It is never quietly
#         skipped: a recorded owed leg is the point of the exit contract's third code.
#   s4.5  warm-prefix routing   the stretch, recorded here and REQUIRED later by the
#         gate: the router preferring the worker that already holds the prefix.
#
# No halt of its own: S4 inherits S3's, because a worker that cannot be built on the
# in-process core is the sidecar shape, which is the same substitution.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

RUNG="S4"
QUESTION="Does a worker built on the M8 engine, behind the upstream backend contract, pass the conformance kit and serve tokens end to end through a frontend, including as a Pod requesting mlx.k3sm.io/gpu?"
METHOD="Rig-side over ssh: an MLXEngine implementing the documented backend contract over S3's in-process core, the upstream conformance kit run against it, then a frontend plus that worker with file discovery serving a completion, then the same through S2's frontend ClusterIP, and the extended-resource leg run only against a published worker image (otherwise recorded as owed to the gate's worker rung)."
HALT="none of its own: a worker that cannot be built on the in-process core is R3's sidecar shape, the same substitution S3 already names."

case "${1:-}" in
--plan | --dry-run) spike_plan "$RUNG" "$QUESTION" "$METHOD" "$HALT" ;;
"") ;;
*)
	echo "s4.sh: unknown argument: $1 (try --plan)" >&2
	exit 2
	;;
esac

spike_host

note "S4 — the backend contract, the conformance kit, and tokens end to end"
lab <<'EOF'
set -uo pipefail
W="$PREFIX/s4"; mkdir -p "$W/discovery"
export UV_CACHE_DIR="$PREFIX/cache" UV_PYTHON_INSTALL_DIR="$PREFIX/pyinstall" HF_HOME="$PREFIX/hf"
export PATH="$PREFIX/bin:$PATH"
V="$PREFIX/venv-s1/bin/python"
[ -x "$V" ] || { verdict FAIL "s4.0 setup  no build venv at $PREFIX/venv-s1 — run s1.sh first (it builds and installs the darwin runtime wheel)"; exit 0; }
MP=$(ls -d "$PREFIX"/hf/hub/models--*/snapshots/* 2>/dev/null | head -1)
[ -n "$MP" ] || { verdict FAIL "s4.0 setup  no model snapshot under $PREFIX/hf — run s0.sh first"; exit 0; }

# The worker's engine lives in its own package, exactly as the contract's own
# documentation says a backend may: it does not need to be part of the upstream
# repository, and M16.3 ships this file's descendant as hack/images/mlx-worker/src/.
cat > "$W/mlx_engine.py" <<'PY'
"""An MLX backend for the upstream serving contract, in the shape M16.3 productizes.

It resolves the contract's base class and the engine core at import time and reports
what it found, because both are young APIs: the contract is documented as
experimental, and a spike that guesses a symbol name proves nothing.
"""
import importlib, inspect, os

MODEL = os.environ["MODEL_PATH"]
MAX_KV = int(os.environ.get("MAX_KV_SIZE", "4096"))
MAX_SEQS = int(os.environ.get("MAX_NUM_SEQS", "4"))


def _resolve(paths, names, what):
    last = None
    for mod in paths:
        try:
            m = importlib.import_module(mod)
        except Exception as exc:
            last = exc
            continue
        for n in names:
            if hasattr(m, n):
                return getattr(m, n), mod + "." + n
    raise RuntimeError("could not resolve %s (tried %s; last import error: %r)" % (what, paths, last))


Base, BASE_WHERE = _resolve(
    ("dynamo.llm", "dynamo.llm.engine", "dynamo.runtime"),
    ("LLMEngine",), "the backend contract's base class")
Core, CORE_WHERE = _resolve(
    ("vllm_mlx.engine.async_engine_core", "vllm_mlx.engine", "vllm_mlx"),
    ("AsyncEngineCore", "AsyncLLMEngine", "EngineCore"), "the MLX engine core")


class MLXEngine(Base):
    """The M8 engine, in-process, behind the documented backend contract."""

    def __init__(self, model=MODEL):
        self._model = model
        self._core = None

    async def start(self, worker_id=None):
        kwargs = {}
        sig = inspect.signature(Core.__init__)
        for name, value in (("max_kv_size", MAX_KV), ("max_num_seqs", MAX_SEQS),
                            ("continuous_batching", True)):
            if name in sig.parameters:
                kwargs[name] = value
        self._core = Core(self._model, **kwargs)
        start = getattr(self._core, "start", None)
        if start:
            maybe = start()
            if inspect.isawaitable(maybe):
                await maybe
        # kv_cache_block_size is what makes the router prefix-aware rather than
        # round-robin; None is the documented round-robin contract, so it is
        # reported truthfully rather than defaulted.
        cache = getattr(self._core, "prefix_cache", None)
        block = getattr(cache, "block_size", None) if cache else None
        return {"model": self._model, "kv_cache_block_size": block}

    async def generate(self, request, context=None):
        tok = self._core.tokenizer
        prompt = request.get("prompt") if isinstance(request, dict) else request
        ids = prompt if isinstance(prompt, list) else list(tok.encode(str(prompt)))
        rid = (context or {}).get("id", "s4") if isinstance(context, dict) else "s4"
        maybe = self._core.add_request(rid, ids)
        if inspect.isawaitable(maybe):
            await maybe
        async for out in self._core.stream_outputs():
            yield out

    async def cleanup(self):
        close = getattr(self._core, "cleanup", None) or getattr(self._core, "close", None)
        if close:
            maybe = close()
            if inspect.isawaitable(maybe):
                await maybe
PY

cat > "$W/conformance.py" <<'PY'
import asyncio, importlib, sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import mlx_engine

print("RECORD s4.1 contract base: %s | engine core: %s" % (mlx_engine.BASE_WHERE, mlx_engine.CORE_WHERE))

run = None
where = None
for mod in ("dynamo.llm.conformance", "dynamo.llm.testing", "dynamo.llm"):
    try:
        m = importlib.import_module(mod)
    except Exception:
        continue
    if hasattr(m, "run_conformance"):
        run, where = m.run_conformance, mod + ".run_conformance"
        break

if run is None:
    print("VERDICT FAIL s4.2 conformance  the upstream conformance kit is not importable at this pin — the contract's own assertions are what make a young API safe to build on")
    sys.exit(1)

print("RECORD s4.2 conformance kit: %s" % where)
try:
    result = run(mlx_engine.MLXEngine())
    if asyncio.iscoroutine(result):
        result = asyncio.run(result)
    print("VERDICT PASS s4.2 conformance  the kit's assertions passed against MLXEngine: %s" % (result,))
except Exception as exc:
    print("VERDICT FAIL s4.2 conformance  the kit failed against MLXEngine: %r" % (exc,))
    sys.exit(1)
PY

MODEL_PATH="$MP" "$V" "$W/conformance.py" 2>&1 | tee "$W/conformance.log"

# ---- s4.3 end to end, file discovery first ---------------------------------------
nohup env MODEL_PATH="$MP" "$V" -m dynamo.frontend --discovery-backend file \
  --discovery-path "$W/discovery" --http-port 8121 > "$W/frontend.log" 2>&1 &
FE=$!
nohup env MODEL_PATH="$MP" PYTHONPATH="$W" "$V" -m dynamo.worker --discovery-backend file \
  --discovery-path "$W/discovery" --engine mlx_engine:MLXEngine --model mlx-worker \
  > "$W/worker.log" 2>&1 &
WK=$!
UP=no
for i in $(seq 1 90); do
  curl -fsS -m 3 http://127.0.0.1:8121/v1/models 2>/dev/null | grep -q mlx && { UP=yes; break; }
  sleep 5
done
if [ "$UP" = yes ]; then
  OUT=$(curl -fsS -m 300 http://127.0.0.1:8121/v1/chat/completions -H 'content-type: application/json' \
    -d '{"model":"mlx-worker","max_tokens":32,"messages":[{"role":"user","content":"Name three primary colors."}]}' 2>&1)
  case "$OUT" in
    *choices*) verdict PASS "s4.3 end-to-end  frontend -> MLX worker -> tokens, through the documented backend contract on the in-process engine" ;;
    *)         verdict FAIL "s4.3 end-to-end  the worker registered but the completion failed: $(printf '%s' "$OUT" | head -c 200)" ;;
  esac
else
  verdict FAIL "s4.3 end-to-end  the worker never appeared in the frontend's model list (see $W/frontend.log, $W/worker.log)"
  tail -20 "$W/worker.log"
fi

# ---- s4.4 the extended-resource leg ----------------------------------------------
if [ -n "${WORKER_IMAGE:-}" ]; then
  kc -n "$NS" delete pod m16-worker --ignore-not-found --wait=false >/dev/null 2>&1
  kc apply -f - <<YAML >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: m16-worker, namespace: $NS}
spec:
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  restartPolicy: Never
  containers:
    - name: worker
      image: $WORKER_IMAGE
      resources:
        requests: {mlx.k3sm.io/gpu: "1", memory: 1536Mi}
        limits: {mlx.k3sm.io/gpu: "1", memory: 1536Mi}
YAML
  if kc -n "$NS" wait --for=condition=Ready pod/m16-worker --timeout=600s >/dev/null 2>&1; then
    verdict PASS "s4.4 extended resource  a worker Pod requesting mlx.k3sm.io/gpu: 1 was admitted, scheduled and became Ready"
  else
    verdict FAIL "s4.4 extended resource  the worker Pod requesting mlx.k3sm.io/gpu: 1 never became Ready: $(kc -n "$NS" get pod m16-worker -o jsonpath='{.status.phase}: {.status.conditions[*].message}' 2>/dev/null | head -c 200)"
  fi
  kc -n "$NS" delete pod m16-worker --ignore-not-found --wait=false >/dev/null 2>&1
else
  recorded "s4.4 extended resource  OWED, not skipped: a Pod requesting mlx.k3sm.io/gpu needs a published worker image, which M16.3 builds. Set K3SM_M16_WORKER_IMAGE to run this leg here; otherwise the gate's worker rung discharges it."
fi

# ---- s4.5 the routing stretch ----------------------------------------------------
recorded "s4.5 warm-prefix routing  STRETCH here, REQUIRED by the gate: two workers, a repeated prefix steered to the warm one, asserted from router metrics AND a measured TTFT gap. This rung proves one worker end to end; the second worker and the routing assertion are the gate's routing rung."
kill "$FE" "$WK" 2>/dev/null
EOF

spike_verdict "$RUNG"
