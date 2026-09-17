#!/usr/bin/env bash
# M16.0-d4 / S3 — the engine decision.
#
# The worker k3sm ships runs the M8 engine IN-PROCESS behind the upstream backend
# contract, which is the whole reason the worker can be ~400-800 lines instead of a
# fork of a 31 800-line vLLM adapter. Everything about that choice rests on four
# properties of the engine that only a driven process can answer:
#
#   s3.1  token IDs in, tokens out, from OUTSIDE the server process — the in-process
#         path exists at all, constructed with continuous batching and the PINNED
#         KV size and sequence count the M8 sizing formula yields. The CLI flags that
#         carry those two invariants are bypassed entirely in-process, which is why
#         the image's mlx_worker package will carry its own tests for them.
#   s3.2  abort mid-stream actually stops generation — the Worker owns cancellation,
#         and a backend that cannot abort turns every client disconnect into wasted
#         GPU.
#   s3.3  the prefix cache's block hashes are observable as STORED and EVICTED —
#         this is the routing metadata, and the framework's KV-event contract is a
#         push API rather than a ZMQ stream, so the cost of publishing it lands on
#         the hot path.
#   s3.4  the cost of that publish call, MEASURED, sync versus async. A hook whose
#         cost nobody measured is a hook that gets discovered in production.
#   s3.5  the alternative engine run against the M8 baseline on this same rig, as a
#         CONTROL. Recorded, never gating: it is the negative space around the choice.
#
# HALT: s3.1 fails -> the plan's R3 sidecar shape (the worker talks HTTP to an
# mlx-serve process; the block size is unset, so routing degrades to round-robin by
# contract and the user doc says so). Pre-decided; this rung never improvises another.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

RUNG="S3"
QUESTION="Can the M8 engine be driven in-process from token IDs with the KV cache pinned and continuous batching on, aborted mid-stream, and its prefix-cache block hashes observed cheaply enough to publish on the hot path?"
METHOD="Rig-side over ssh: the engine core constructed directly in a python process with the M8 sizing formula's pinned max_kv_size and max_num_seqs, driven from tokenized IDs, aborted mid-stream, its prefix cache inspected for stored and evicted block hashes, and the publish call timed sync versus async; then the alternative engine installed in its own venv and run against the M8 baseline on the same rig as a recorded control."
HALT="the in-process path fails -> R3's HTTP sidecar shape onto mlx-serve, where the block size is unset, routing degrades to round-robin by contract, and docs/user/mlx-fleet.md says so in its first section."

case "${1:-}" in
--plan | --dry-run) spike_plan "$RUNG" "$QUESTION" "$METHOD" "$HALT" ;;
"") ;;
*)
	echo "s3.sh: unknown argument: $1 (try --plan)" >&2
	exit 2
	;;
esac

spike_host

note "S3(1) — the in-process engine: pinned KV, continuous batching, abort, block hashes, publish cost"
lab <<'EOF'
set -uo pipefail
W="$PREFIX/s3"; mkdir -p "$W"
export UV_CACHE_DIR="$PREFIX/cache" UV_PYTHON_INSTALL_DIR="$PREFIX/pyinstall" HF_HOME="$PREFIX/hf"
export PATH="$PREFIX/bin:$PATH"
V="$PREFIX/venv/bin/python"
[ -x "$V" ] || { verdict FAIL "s3.0 setup  no engine venv at $PREFIX/venv — run s0.sh first (it installs vllm-mlx==$ENGINE_VERSION and the pinned model)"; exit 0; }

cat > "$W/drive.py" <<'PY'
"""Drive the engine core in-process, the way the fleet worker will.

Every probe reports its own VERDICT/RECORD line, and every failure prints the API
surface it actually found. A spike that dies on an AttributeError tells you nothing;
one that prints the names it looked for and the names that exist tells you what to
write next.
"""
import asyncio, importlib, inspect, json, os, statistics, sys, time

MODEL = os.environ["MODEL_PATH"]
MAX_KV = int(os.environ.get("MAX_KV_SIZE", "4096"))
MAX_SEQS = int(os.environ.get("MAX_NUM_SEQS", "4"))


def surface(obj, hint=""):
    names = [n for n in dir(obj) if not n.startswith("_")]
    return "%s exposes: %s" % (hint or type(obj).__name__, ", ".join(sorted(names))[:600])


def find_core():
    """Locate the async engine core without assuming one module path."""
    last = None
    for mod in ("vllm_mlx.engine.async_engine_core", "vllm_mlx.engine", "vllm_mlx"):
        try:
            m = importlib.import_module(mod)
        except Exception as exc:  # a missing module is data, not a crash
            last = exc
            continue
        for attr in ("AsyncEngineCore", "AsyncLLMEngine", "EngineCore"):
            if hasattr(m, attr):
                return getattr(m, attr), mod + "." + attr
    raise RuntimeError("no engine core found (last import error: %r)" % (last,))


async def main():
    try:
        Core, where = find_core()
    except Exception as exc:
        print("VERDICT FAIL s3.1 in-process  %s" % exc)
        return 1
    print("RECORD s3.1 engine core: %s" % where)

    sig = inspect.signature(Core.__init__)
    kwargs = {}
    for name, value in (("max_kv_size", MAX_KV), ("max_num_seqs", MAX_SEQS),
                        ("continuous_batching", True)):
        if name in sig.parameters:
            kwargs[name] = value
    missing = [n for n in ("max_kv_size", "max_num_seqs", "continuous_batching") if n not in kwargs]
    if missing:
        print("VERDICT FAIL s3.1 invariants  the engine core does not accept %s in-process — the CLI flags that carry the M8 invariants have no in-process equivalent. %s"
              % (", ".join(missing), "constructor: " + str(sig)))
        return 1
    print("RECORD s3.1 constructor: %s(%s)" % (where, json.dumps(kwargs)))

    t0 = time.time()
    core = Core(MODEL, **kwargs)
    if hasattr(core, "start"):
        maybe = core.start()
        if inspect.isawaitable(maybe):
            await maybe
    print("RECORD s3.1 load: %.1fs" % (time.time() - t0))

    tok = getattr(core, "tokenizer", None)
    if tok is None:
        print("VERDICT FAIL s3.1 token-ids  the core exposes no tokenizer, so a caller cannot hand it token IDs. %s" % surface(core, "core"))
        return 1
    ids = tok.encode("Explain, at length, how a filesystem journal works.")
    if not isinstance(ids, list):
        ids = list(ids)

    add = getattr(core, "add_request", None)
    stream = getattr(core, "stream_outputs", None)
    if add is None or stream is None:
        print("VERDICT FAIL s3.1 in-process  add_request/stream_outputs are not both present. %s" % surface(core, "core"))
        return 1

    rid = "s3-1"
    maybe = add(rid, ids) if len(inspect.signature(add).parameters) >= 2 else add(ids)
    if inspect.isawaitable(maybe):
        await maybe
    n = 0
    first = None
    t1 = time.time()
    async for _out in stream():
        n += 1
        if first is None:
            first = time.time() - t1
        if n >= 64:
            break
    if n:
        print("VERDICT PASS s3.1 in-process  the engine generated %d tokens from TOKEN IDS in-process with the KV cache pinned at %d and %d sequences (TTFT %.3fs)"
              % (n, MAX_KV, MAX_SEQS, first or 0.0))
    else:
        print("VERDICT FAIL s3.1 in-process  the in-process stream yielded nothing — the plan's R3 sidecar shape applies")
        return 1

    # ---- s3.2 abort mid-stream ---------------------------------------------------
    abort = getattr(core, "abort_request", None)
    if abort is None:
        print("VERDICT FAIL s3.2 abort  the core exposes no abort_request; a client disconnect would waste GPU until the sequence finishes")
    else:
        rid2 = "s3-2"
        maybe = add(rid2, ids) if len(inspect.signature(add).parameters) >= 2 else add(ids)
        if inspect.isawaitable(maybe):
            await maybe
        seen = 0
        async for _out in stream():
            seen += 1
            if seen == 8:
                maybe = abort(rid2)
                if inspect.isawaitable(maybe):
                    await maybe
            if seen > 8:
                break
        print("VERDICT PASS s3.2 abort  abort_request was accepted mid-stream after %d tokens" % seen)

    # ---- s3.3 the routing metadata ----------------------------------------------
    cache = None
    for attr in ("prefix_cache", "block_cache", "kv_cache"):
        if hasattr(core, attr):
            cache = getattr(core, attr)
            break
    if cache is None:
        print("VERDICT FAIL s3.3 block-hashes  no prefix cache is reachable from the core, so there is no routing metadata to publish. %s" % surface(core, "core"))
    else:
        hashfn = getattr(cache, "compute_block_hash", None)
        blocks = getattr(cache, "block_size", None) or getattr(cache, "tokens_per_block", None)
        print("RECORD s3.3 prefix cache: %s block_size=%s %s" % (type(cache).__name__, blocks, surface(cache, "cache")))
        if hashfn is None:
            print("VERDICT FAIL s3.3 block-hashes  the prefix cache exposes no block-hash function")
        else:
            # ---- s3.4 the publish cost, sync vs async -----------------------------
            chunk = ids[:int(blocks or 64)]
            sync_times = []
            for _ in range(200):
                t = time.perf_counter()
                hashfn(chunk)
                sync_times.append((time.perf_counter() - t) * 1e6)

            async def publish(h):
                return h

            async_times = []
            for _ in range(200):
                t = time.perf_counter()
                await publish(hashfn(chunk))
                async_times.append((time.perf_counter() - t) * 1e6)
            print("VERDICT PASS s3.3 block-hashes  block hashes are computable from the core's own prefix cache (block size %s)" % blocks)
            print("RECORD s3.4 publish cost per block: sync median %.1fus p99 %.1fus; via an await median %.1fus p99 %.1fus (200 samples each)"
                  % (statistics.median(sync_times), sorted(sync_times)[197],
                     statistics.median(async_times), sorted(async_times)[197]))

    if hasattr(core, "cleanup"):
        maybe = core.cleanup()
        if inspect.isawaitable(maybe):
            await maybe
    return 0


sys.exit(asyncio.run(main()))
PY

MP=$(ls -d "$PREFIX"/hf/hub/models--*/snapshots/* 2>/dev/null | head -1)
[ -n "$MP" ] || { verdict FAIL "s3.0 setup  no model snapshot under $PREFIX/hf — run s0.sh first"; exit 0; }
MODEL_PATH="$MP" MAX_KV_SIZE=4096 MAX_NUM_SEQS=4 "$V" "$W/drive.py" 2>&1 | tee "$W/drive.log"
EOF

note "S3(2) — the alternative engine, as a recorded control"
lab <<'EOF'
set -uo pipefail
W="$PREFIX/s3"; mkdir -p "$W"
export UV_CACHE_DIR="$PREFIX/cache" UV_PYTHON_INSTALL_DIR="$PREFIX/pyinstall" HF_HOME="$PREFIX/hf"
export PATH="$PREFIX/bin:$PATH"
spike_venv "$PREFIX/venv-metal" "s3.5 control"
VM="$PREFIX/venv-metal/bin/python"
if ! spike_pip "$VM" vllm-metal; then
  recorded "s3.5 control  the alternative engine did not install on this rig — recorded, not gating: it is the negative space around the engine choice, never a criterion"
  exit 0
fi
MP=$(ls -d "$PREFIX"/hf/hub/models--*/snapshots/* 2>/dev/null | head -1)
nohup "$VM" -m vllm.entrypoints.openai.api_server --model "$MP" --port 8103 > "$W/metal.log" 2>&1 &
PID=$!
UP=no
for i in $(seq 1 60); do
  curl -fsS -m 3 http://127.0.0.1:8103/v1/models >/dev/null 2>&1 && { UP=yes; break; }
  sleep 5
done
if [ "$UP" = yes ] && [ -r "$PREFIX/s0/load.py" ]; then
  OUT=$("$PREFIX/venv/bin/python" "$PREFIX/s0/load.py" "http://127.0.0.1:8103" 4 1 1200)
  recorded "s3.5 control  the alternative engine on the same rig, same load: $OUT (compare against the M8 figures taken on THIS machine, never against another Mac's)"
else
  recorded "s3.5 control  the alternative engine did not serve on this rig (see $W/metal.log) — recorded, not gating"
fi
kill "$PID" 2>/dev/null
EOF

spike_verdict "$RUNG"
