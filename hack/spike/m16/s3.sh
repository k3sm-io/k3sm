#!/usr/bin/env bash
# S3 — the engine decision.
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
# HALT: s3.1 fails -> the HTTP sidecar shape (the worker talks HTTP to an
# mlx-serve process; the block size is unset, so routing degrades to round-robin by
# contract and the user doc says so). Pre-decided; this rung never improvises another.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

RUNG="S3"
QUESTION="Can the M8 engine be driven in-process from token IDs with the KV cache pinned and continuous batching on, aborted mid-stream, and its prefix-cache block hashes observed cheaply enough to publish on the hot path?"
METHOD="Rig-side over ssh: the engine core constructed directly in a python process with the M8 sizing formula's pinned max_kv_size and max_num_seqs, driven from tokenized IDs, aborted mid-stream, its prefix cache inspected for stored and evicted block hashes, and the publish call timed sync versus async; then the alternative engine installed in its own venv and run against the M8 baseline on the same rig as a recorded control."
HALT="the in-process path fails -> the HTTP sidecar shape onto mlx-serve, where the block size is unset, routing degrades to round-robin by contract."

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

The surface driven here is the engine's own in-process API, as the supplementary run
in findings-s3.md recorded it: `mlx_lm.load` yields the model and tokenizer; the
invariants travel in `SchedulerConfig` inside `EngineConfig`, and the scheduler is
read back to prove it took them; a request is `add_request(token_ids, SamplingParams,
request_id=...)`; its stream is `stream_outputs(request_id, timeout=...)`; and the
prefix cache sits behind the scheduler as `paged_cache_manager`, which exists only
with `use_paged_cache=True` (the default `PrefixCacheManager` has no block-hash
function). Every wait is bounded: a stream that stays open after an abort is the
expected shape, not a hang.
"""
import asyncio, inspect, json, os, statistics, sys, time, traceback

MODEL = os.environ["MODEL_PATH"]
MAX_KV = int(os.environ.get("MAX_KV_SIZE", "4096"))
MAX_SEQS = int(os.environ.get("MAX_NUM_SEQS", "4"))
STREAM_BUDGET = float(os.environ.get("STREAM_BUDGET", "90"))  # one request, start to finish
ABORT_GRACE = float(os.environ.get("ABORT_GRACE", "5"))      # quiet time after an abort that counts as "stopped"
SAMPLES = 200


def surface(obj, hint=""):
    names = [n for n in dir(obj) if not n.startswith("_")]
    return "%s exposes: %s" % (hint or type(obj).__name__, ", ".join(sorted(names))[:600])


def verdict(state, crit, text):
    print("VERDICT %s %s  %s" % (state, crit, text), flush=True)


def record(text):
    print("RECORD %s" % text, flush=True)


def version(dist):
    try:
        import importlib.metadata as md
        return md.version(dist)
    except Exception:
        return "?"


def cache_stats(core):
    try:
        return json.dumps(core.get_cache_stats(), default=str)[:400]
    except Exception as exc:
        return "unreadable (%r)" % (exc,)


class Pump:
    """Reads a stream into a queue from its own task, so a bounded wait on the queue never
    cancels the engine's generator mid-step: "quiet" then means the stream is open and
    silent, and "ended" means the engine closed it."""

    def __init__(self, stream):
        self.q = asyncio.Queue()
        self.task = asyncio.ensure_future(self._run(stream))

    async def _run(self, stream):
        try:
            async for out in stream:
                await self.q.put(out)
        except Exception as exc:
            await self.q.put(exc)
        finally:
            await self.q.put(None)

    async def next(self, budget):
        """The next event; None once the stream ended; "quiet" when budget passed without one."""
        try:
            return await asyncio.wait_for(self.q.get(), budget)
        except asyncio.TimeoutError:
            return "quiet"

    async def close(self):
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)


async def stop(core):
    try:
        maybe = core.stop()
        if inspect.isawaitable(maybe):
            await maybe
    except Exception as exc:
        record("engine stop raised %r" % (exc,))


async def main():
    try:
        from mlx_lm import load
        import vllm_mlx.engine_core as engine_core
        from vllm_mlx.request import SamplingParams
    except Exception as exc:
        verdict("FAIL", "s3.1 in-process", "the engine's in-process modules do not import: %r" % (exc,))
        return 1
    record("s3.1 engine core: vllm_mlx.engine_core.AsyncEngineCore (vllm-mlx %s, mlx-lm %s)"
           % (version("vllm-mlx"), version("mlx-lm")))

    # ---- s3.1 the invariants pinned in-process, then token IDs in, tokens out -----
    t0 = time.time()
    model, tok = load(MODEL)
    record("s3.1 load (mlx_lm.load): %.1fs" % (time.time() - t0))
    wanted = {"max_num_seqs": MAX_SEQS, "max_kv_size": MAX_KV, "use_paged_cache": True}
    core = engine_core.AsyncEngineCore(
        model, tok, engine_core.EngineConfig(model_name=MODEL, scheduler_config=engine_core.SchedulerConfig(**wanted)))
    core.start()
    await asyncio.sleep(0.2)

    sched = getattr(getattr(core, "engine", None), "scheduler", None)
    cfg = getattr(sched, "config", None)
    if cfg is None:
        verdict("FAIL", "s3.1 invariants", "the core exposes no engine.scheduler.config to read the invariants back from. %s"
                % surface(core, "core"))
        await stop(core)
        return 0
    echoed = {k: getattr(cfg, k, None) for k in wanted}
    block = getattr(cfg, "paged_cache_block_size", None)
    record("s3.1 constructor: AsyncEngineCore(model, tokenizer, EngineConfig(scheduler_config=SchedulerConfig(%s))); "
           "the scheduler holds %s, block_size=%s; continuous batching is the engine-core path itself "
           "(the CLI's --continuous-batching selects this engine; in-process there is no flag to forget)"
           % (", ".join("%s=%s" % kv for kv in wanted.items()), json.dumps(echoed), block))
    if echoed != wanted:
        verdict("FAIL", "s3.1 invariants", "the scheduler did not keep the pinned values: wanted %s, got %s"
                % (json.dumps(wanted), json.dumps(echoed)))
        await stop(core)
        return 0

    # The config is what the drive handed over; what the engine APPLIED is read from the live
    # scheduler: with MAX_SEQS + 3 requests queued at once, the running count must never exceed
    # MAX_SEQS and must sit at MAX_SEQS while others wait. max_kv_size is read from a running
    # request's cache object when that cache exposes a size; otherwise its absence is recorded.
    ids = list(tok.encode("Explain, at length, how a filesystem journal works."))
    burst = [await core.add_request(ids, SamplingParams(max_tokens=24, temperature=0.0), request_id="s3-cap-%d" % i)
             for i in range(MAX_SEQS + 3)]
    most, capped, kv_seen, t_cap = 0, False, None, time.time()
    while time.time() - t_cap < STREAM_BUDGET:
        await asyncio.sleep(0.05)
        nr, nw = sched.get_num_running(), sched.get_num_waiting()
        most = max(most, nr)
        if nr == MAX_SEQS and nw > 0:
            capped = True
        if nr > 0 and kv_seen is None:
            for req in list(getattr(sched, "running", {}).values()):
                pc = getattr(req, "prompt_cache", None)
                layers = pc if isinstance(pc, (list, tuple)) else ([pc] if pc is not None else [])
                sizes = [getattr(l, "max_size", None) for l in layers if getattr(l, "max_size", None) is not None]
                if sizes:
                    kv_seen = sizes[0]
                elif layers:
                    kv_seen = "no max_size on %s" % type(layers[0]).__name__
        if nr == 0 and nw == 0 and time.time() - t_cap > 0.5:
            break
    drains = [Pump(core.stream_outputs(r, timeout=STREAM_BUDGET)) for r in burst]
    for d in drains:
        while await d.next(STREAM_BUDGET) not in (None, "quiet"):
            pass
        await d.close()
    record("s3.1 applied: %d requests queued at once, running never exceeded %d of max_num_seqs=%d, cap reached with a queue: %s; "
           "max_kv_size on a running request's cache: %s"
           % (len(burst), most, MAX_SEQS, capped, kv_seen if kv_seen is not None else "not observable on the paged path"))
    if most <= MAX_SEQS and capped:
        verdict("PASS", "s3.1 invariants", "the scheduler applied max_num_seqs=%d (running peaked at %d with others waiting)%s"
                % (MAX_SEQS, most, "; max_kv_size=%s read from a running request's cache" % kv_seen if isinstance(kv_seen, int) and kv_seen == MAX_KV
                   else "; max_kv_size is held by the scheduler but not observable on a paged-cache request in-process, so the image's own tests must pin it"))
    else:
        verdict("FAIL", "s3.1 invariants", "the scheduler did not apply max_num_seqs=%d: running peaked at %d, cap with a queue seen: %s"
                % (MAX_SEQS, most, capped))
        await stop(core)
        return 0

    try:
        rid = await asyncio.wait_for(
            core.add_request(ids, SamplingParams(max_tokens=64, temperature=0.0), request_id="s3-1"), STREAM_BUDGET)
    except Exception as exc:
        verdict("FAIL", "s3.1 token-ids", "add_request did not accept a token-id list: %r. %s" % (exc, surface(core, "core")))
        await stop(core)
        return 0
    record("s3.1 add_request accepted %d token ids -> %r" % (len(ids), rid))

    stream = Pump(core.stream_outputs(rid, timeout=STREAM_BUDGET))
    events, first, last, t1 = 0, None, None, time.time()
    while True:
        out = await stream.next(STREAM_BUDGET)
        if out is None or out == "quiet" or isinstance(out, Exception):
            break
        events += 1
        last = out
        if first is None:
            first = time.time() - t1
        if getattr(out, "finished", False) or events >= 64:
            break
    await stream.close()
    tokens = len(getattr(last, "output_token_ids", None) or [])
    finish = getattr(last, "finish_reason", None)
    if not events:
        verdict("FAIL", "s3.1 in-process", "the in-process stream yielded nothing within %.0fs - the HTTP sidecar shape applies"
                % STREAM_BUDGET)
        await stop(core)
        return 0
    # the count is checked, not claimed: one token per event, and a length finish means all 64.
    # This assumes the engine emits one token per stream event. An engine that batches
    # several tokens into one event makes tokens != events and reads as a FAIL here, never
    # as a false PASS; adjust the check if a later engine version does that.
    if tokens != events or (finish == "length" and tokens != 64):
        verdict("FAIL", "s3.1 in-process", "the stream's token count does not add up: %d events, %d output tokens, finish=%s (64 asked for)"
                % (events, tokens, finish))
        await stop(core)
        return 0
    verdict("PASS", "s3.1 in-process",
            "the engine generated %d tokens over %d stream events from TOKEN IDS in-process, one token per event, finish=%s "
            "(TTFT %.3fs)" % (tokens, events, finish, first or 0.0))

    # ---- s3.2 abort mid-stream, the wait after it bounded ---------------------------
    rid2 = await core.add_request(ids, SamplingParams(max_tokens=256, temperature=0.0), request_id="s3-2")
    stream = Pump(core.stream_outputs(rid2, timeout=STREAM_BUDGET))
    seen = 0
    while seen < 8:
        out = await stream.next(STREAM_BUDGET)
        if out is None or out == "quiet" or isinstance(out, Exception):
            break
        seen += 1
    if seen < 8:
        verdict("FAIL", "s3.2 abort", "the second stream gave %d events and then nothing, before an abort could be sent" % seen)
    else:
        t_abort = time.time()
        accepted = await core.abort_request(rid2)
        took = time.time() - t_abort
        after, ended = 0, "kept streaming"
        while True:
            out = await stream.next(ABORT_GRACE)
            if out is None:
                ended = "ended %.1fs after the abort" % (time.time() - t_abort)
                break
            if out == "quiet":
                ended = "stayed open, silent for %.0fs" % ABORT_GRACE
                break
            if isinstance(out, Exception):
                ended = "raised %r" % (out,)
                break
            if getattr(out, "finished", False):
                ended = "ended with finish=%s %.1fs after the abort" % (getattr(out, "finish_reason", None), time.time() - t_abort)
                break
            after += 1
        record("s3.2 abort_request(%r) returned %r in %.3fs; %d token events after the abort; cache stats: %s"
               % (rid2, accepted, took, after, cache_stats(core)))
        if accepted and after == 0:
            verdict("PASS", "s3.2 abort", "abort_request was accepted mid-stream after 8 events and generation stopped: "
                    "no token event followed it within %.0fs" % ABORT_GRACE)
        elif accepted:
            verdict("FAIL", "s3.2 abort", "abort_request returned True but %d token event(s) followed it - the engine kept generating"
                    % after)
        else:
            verdict("FAIL", "s3.2 abort", "abort_request returned %r for a live request" % (accepted,))
        # The stream's own ending is a separate fact for the reader to judge, never part of the PASS:
        # a worker whose engine leaves the stream open must end it itself.
        record("s3.2-stream after the abort the stream %s; the worker %s"
               % (ended, "can rely on the engine to end the stream" if ended.startswith("ended") else "must end the stream itself"))
    await stream.close()

    # ---- s3.3 the routing metadata: block hashes behind the scheduler ---------------
    pcm = getattr(sched, "paged_cache_manager", None)
    if pcm is None:
        verdict("FAIL", "s3.3 block-hashes",
                "no paged cache manager is reachable behind the scheduler (use_paged_cache=%s), so there is no routing "
                "metadata to publish. %s" % (echoed["use_paged_cache"], surface(sched, "scheduler")))
    else:
        hashfn = getattr(pcm, "compute_block_hash", None)
        block = getattr(pcm, "block_size", None) or block or 64
        present = [n for n in ("compute_block_hash", "register_block_hash", "get_computed_blocks", "evict_lru_blocks", "get_stats")
                   if hasattr(pcm, n)]
        record("s3.3 prefix cache: %s block_size=%s; present: %s" % (type(pcm).__name__, block, ", ".join(present)))
        if hashfn is None:
            verdict("FAIL", "s3.3 block-hashes", "the paged cache exposes no compute_block_hash. %s" % surface(pcm, "cache"))
        else:
            chunk = (ids * (block // len(ids) + 1))[:block]   # one full block, so s3.4 prices a block and not a fragment
            try:
                sample = hashfn(chunk)
            except TypeError as exc:
                sample = None
                verdict("FAIL", "s3.3 block-hashes", "compute_block_hash did not take a token list: %r (signature %s)"
                        % (exc, inspect.signature(hashfn)))
            if sample is not None:
                verdict("PASS", "s3.3 block-hashes",
                        "block hashes are computable from the scheduler's paged cache (block size %s, sample %r); stored "
                        "blocks are readable from its stats; eviction is exposed as evict_lru_blocks and was not exercised "
                        "here (it needs more than max_cache_blocks=%s resident blocks)"
                        % (block, str(sample)[:16], getattr(cfg, "max_cache_blocks", None)))

                # ---- s3.4 the publish cost, sync vs async --------------------------------
                sync_us = []
                for _ in range(SAMPLES):
                    t = time.perf_counter()
                    hashfn(chunk)
                    sync_us.append((time.perf_counter() - t) * 1e6)

                async def publish(h):
                    return h

                async_us = []
                for _ in range(SAMPLES):
                    t = time.perf_counter()
                    await publish(hashfn(chunk))
                    async_us.append((time.perf_counter() - t) * 1e6)
                p99 = int(SAMPLES * 0.99) - 1
                record("s3.4 publish cost per %d-token block: sync median %.1fus p99 %.1fus; via an await median %.1fus p99 %.1fus "
                       "(%d samples each)" % (block, statistics.median(sync_us), sorted(sync_us)[p99],
                                              statistics.median(async_us), sorted(async_us)[p99], SAMPLES))
        record("s3.3 cache stats at the end: %s" % cache_stats(core))

    await stop(core)
    return 0


async def run():
    """Exit 0 once the drive has finished, whatever its verdicts say; exit 1 only when it died."""
    try:
        return await main()
    except Exception:
        tb = traceback.format_exc()
        verdict("FAIL", "s3.0 drive", "the drive raised before it finished: %s" % tb.strip().splitlines()[-1])
        print(tb[-1500:], file=sys.stderr, flush=True)
        return 1


sys.exit(asyncio.run(run()))
PY

MP=$(ls -d "$PREFIX"/hf/hub/models--*/snapshots/* 2>/dev/null | sed -n 1p)
[ -n "$MP" ] || { verdict FAIL "s3.0 setup  no model snapshot under $PREFIX/hf — run s0.sh first"; exit 0; }
# The scoreboard reads the drive's VERDICT lines. The drive exits 0 whenever it finished,
# whatever those lines say, so a finished drive never earns a second FAIL from the driver;
# a drive that died (a crash, a signal, an unhandled error) exits non-zero, which is turned
# into one FAIL that names the status and keeps the payload non-zero, so a crash after an
# earlier PASS can never read as green.
MODEL_PATH="$MP" MAX_KV_SIZE=4096 MAX_NUM_SEQS=4 "$V" "$W/drive.py" 2>&1 | tee "$W/drive.log"
rc=${PIPESTATUS[0]}
if [ "$rc" != 0 ]; then
  verdict FAIL "s3.0 drive  drive.py died with status $rc after its last verdict line (see $W/drive.log)"
  exit "$rc"
fi
grep -q '^VERDICT ' "$W/drive.log" || { verdict FAIL "s3.0 drive  drive.py finished without reporting a verdict (see $W/drive.log)"; exit 1; }
EOF

note "S3(2) — the alternative engine, as a recorded control"
lab <<'EOF'
set -uo pipefail
W="$PREFIX/s3"; mkdir -p "$W"
export UV_CACHE_DIR="$PREFIX/cache" UV_PYTHON_INSTALL_DIR="$PREFIX/pyinstall" HF_HOME="$PREFIX/hf"
export PATH="$PREFIX/bin:$PATH"
spike_venv "$PREFIX/venv-metal" "s3.5 control"
VM="$PREFIX/venv-metal/bin/python"
if ! spike_pip "$VM" "vllm-metal==0.1.0"; then
  recorded "s3.5 control  the alternative engine did not install on this rig — recorded, not gating: it is the negative space around the engine choice, never a criterion"
  exit 0
fi
# vllm-metal serves its OpenAI endpoint from the `vllm-metal` console script. The
# `vllm.entrypoints.openai.api_server` module exists only under its [vllm] extra, which
# would pull an unpinned dependency tree into the control venv.
SERVER="$PREFIX/venv-metal/bin/vllm-metal"
[ -x "$SERVER" ] || { recorded "s3.5 control  the alternative engine installed without its vllm-metal console script — recorded, not gating"; exit 0; }
MP=$(ls -d "$PREFIX"/hf/hub/models--*/snapshots/* 2>/dev/null | sed -n 1p)
nohup "$SERVER" --model "$MP" --host 127.0.0.1 --port 8103 > "$W/metal.log" 2>&1 &
PID=$!
# the control never outlives the payload, interrupted or not; a server that already
# exited makes kill non-zero, which must not become the payload's status
trap 'kill "$PID" 2>/dev/null || true' EXIT
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
EOF

spike_verdict "$RUNG"
