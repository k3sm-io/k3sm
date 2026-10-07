# S3 findings — the engine decision (M16.0-d4)

> **Status: RUN 2026-10-02 02:37Z, one run of `s3.sh` at `main` dba9ee6 on an outside
> machine (Apple M4 Max, 64 GiB), not the M16 rig, through the local-payload shim. Per
> the #446 ruling the canonical run is the rig's and this record is advisory.** The payload exited at its
> first criterion: `s3.1` **FAIL** on the invariants check, so `s3.2`–`s3.4` were never
> reached and `s3.5` recorded that the control did not serve. The payload's own API
> dump, quoted on the verdict line, shows **what** failed: the probe asks the core's
> constructor for `max_kv_size`, `max_num_seqs` and `continuous_batching` by keyword,
> and the constructor is `(model, tokenizer, config: EngineConfig)`. The invariants are
> fields of `SchedulerConfig`, carried inside that `EngineConfig`. Driven that way,
> outside the ladder and recorded below as supplementary, the in-process path accepted
> token IDs with the invariants pinned, accepted an abort mid-stream, exposed a block-hash
> function, and timed the publish call. Eviction was not exercised, and the stream did not
> end after the abort. Re-running the script overwrites rig state under `$PREFIX`;
> it does not rewrite this file.

> **Rig substitution.** The host under Rig is not the sanctioned M16 rig (the laptop
> dev Mac: Apple M2, 8 CPU, 8 GiB): it is an outside machine with roughly 8x that
> memory (Apple M4 Max, 64 GiB). Per the #446 ruling the canonical run is the rig's
> and this record is advisory. S3's criteria are API shape, not budget, so the
> substitution bears on `s3.4`'s absolute timings and the `s3.5` control only.

> **The halt is not landed here.** Per #446 a run off the rig does not discharge the
> rung, so neither this run's FAIL nor the halt's substitution can land on its strength.
> Context for the rig re-run: the verdict line says the core's constructor does not take
> three keywords, while the supplementary records below show the same invariants carried
> in `SchedulerConfig`, so the FAIL may be a miss of the probe rather than of the path.
> Whether the rung re-runs on the rig with a corrected probe (Harness notes) or R3 lands
> as the ladder says is the maintainers' call, not decided here.

## Question

Can the M8 engine be driven **in-process** from token IDs with the KV cache pinned
and continuous batching on, aborted mid-stream, and its prefix-cache block hashes
observed cheaply enough to publish on the hot path? The worker's whole shape rests on
this: in-process is ~400–800 lines, and the alternative is an HTTP sidecar whose
routing degrades to round-robin by contract.

## Method

Rig-side over ssh: the engine core constructed directly in a python process with the
M8 sizing formula's pinned `max_kv_size` and `max_num_seqs`, driven from tokenized
IDs, aborted mid-stream, its prefix cache inspected for stored and evicted block
hashes, and the publish call **timed** sync versus async. Then the alternative engine
in its own venv, run against the M8 baseline **on this same rig**, recorded and never
gating.

## Halt (binding, substitution pre-decided)

The in-process path fails → **R3's HTTP sidecar shape** onto `mlx-serve`, where the
block size is unset, routing degrades to round-robin by contract, and
`docs/user/mlx-fleet.md` says so in its first section.

## Scoreboard

Verdicts are the payload's own lines, verbatim. The driver's scoreboard read
`0 passed, 3 failed, 2 recorded`: one failed criterion plus two `FAIL` lines the
driver adds whenever a payload's shell exits non-zero (Harness notes, third item).

| criterion | verdict | evidence |
|---|---|---|
| s3.1 token IDs in, tokens out, in-process, invariants pinned | **FAIL** | `RECORD s3.1 engine core: vllm_mlx.engine.AsyncEngineCore` then `VERDICT FAIL s3.1 invariants  the engine core does not accept max_kv_size, max_num_seqs, continuous_batching in-process — the CLI flags that carry the M8 invariants have no in-process equivalent. constructor: (self, model: Any, tokenizer: Any, config: Optional[vllm_mlx.engine_core.EngineConfig] = None)` |
| s3.2 abort mid-stream accepted | not reached | the payload returns at the s3.1 failure |
| s3.3 block hashes observable (stored / evicted, block size) | not reached | as above |
| s3.4 publish cost per block, sync vs async (median, p99) | not reached | as above |
| s3.5 the alternative engine as a control (recorded) | RECORDED | `RECORD s3.5 control  the alternative engine did not serve on this rig (see $PREFIX/s3/metal.log) — recorded, not gating`; `metal.log` is one line: `Error while finding module specification for 'vllm.entrypoints.openai.api_server' (ModuleNotFoundError: No module named 'vllm')`. `vllm-metal==0.1.0` installed (`pip-venv-metal-vllm-metal.log`); it ships no `vllm` module without its `[vllm]` extra, and its console script is `vllm-metal` (Harness notes, second item). |

## Prerequisites prepared by hand (S0 not run on this machine)

S0 as a whole needs the vm cluster and the two-engine budget this machine cannot
represent, so only what `s3.sh` reads from S0 was prepared, with S0's own pins and
S0's own lines:

| what `s3.sh` reads | prepared as | pin |
|---|---|---|
| `$PREFIX/venv/bin/python` | `uv venv --python cpython-3.12-macos-aarch64-none` (arm64 asserted), `uv pip install vllm-mlx==0.4.1` | `ENGINE_VERSION` 0.4.1; resolved mlx 0.32.3, mlx-lm 0.32.0 |
| `$PREFIX/hf/hub/models--*/snapshots/*` | `huggingface_hub.snapshot_download` of the ladder's model at the ladder's revision | `mlx-community/Qwen3-0.6B-4bit` @ `73e3e38d981303bc594367cd910ea6eb48349da8`, 335 MB on disk |
| `$PREFIX/s0/load.py` | the heredoc in `s0.sh`, extracted verbatim | — |

S0(1), S0(2) and S0(3) are not claimed.

## Supplementary records (outside the ladder; the verdict above stands)

The same five questions, asked the way the engine's API expects: `model, tokenizer =
mlx_lm.load(path)`, the invariants in `SchedulerConfig`, the core started on the
running loop. One run, `use_paged_cache=True` (the default `False` selects
`PrefixCacheManager`, which has no block-hash function). The lines carry a `SUPP` prefix
so they are never read as ladder output. The driver that produced them is not in the
tree, and the figures cannot be reproduced from the repo.

```
SUPP load mlx_lm.load: 0.3s
SUPP construct: AsyncEngineCore(model, tokenizer, EngineConfig(scheduler_config=SchedulerConfig(max_num_seqs=4, max_kv_size=4096, use_paged_cache=True))); scheduler sees max_num_seqs=4 max_kv_size=4096 use_paged_cache=True block_size=64
SUPP add_request accepted token ids (12) -> 's3-1'
SUPP s3.1-shape 64 output tokens over 64 stream events, TTFT 0.428s, finish=length
SUPP s3.2-shape abort_request returned True after 8 events; 0 events after the abort; finish=None
SUPP s3.3-shape PagedCacheManager.compute_block_hash(tokens: 'List[int]') -> 'str' block_size=64; evict_lru_blocks/register_block_hash/get_computed_blocks present
SUPP block hash sample args=['tokens'] -> '4e4c04d8c9fbcecf'
SUPP s3.4-shape publish cost per block: sync median 2.8us p99 3.6us; via an await median 2.6us p99 3.4us (200 samples each)
SUPP get_cache_stats: {"hits": 0, "misses": 2, "hit_rate": 0.0, "tokens_saved": 0, "active_requests": 0, "block_size": 64, "max_blocks": 1000, "allocated_blocks": 1, "free_blocks": 999, "shared_blocks": 0, "total_tokens_cached": 0, "utilization": 0.001, "cache_hit_rate": 0}
```

Two things the lines do not say on their own. After `abort_request` returned `True`
no further output arrived, but `stream_outputs` did not terminate either: the iterator
sat until its own 90 s timeout. A worker that aborts on client disconnect must close the
client stream itself; the core stops generating but does not end the stream. And the
eviction half of s3.3 was not exercised: one 12-token request fills one block of 1000,
so `evictions=0` is an idle counter, not an observation.

**The control and a baseline, on this machine, S0's `load.py` with the ladder's
arguments (`4 1 1200`).** The control was started through its own console script
rather than the module the payload names. It answered non-streamed: `load.py` counts
SSE events, so `0` tokens and `0` TTFT mean no event stream, not no tokens. The
baseline is one `vllm-mlx serve` process with the M8 invariants on the CLI, the
single-engine half of S0(2) and nothing more.

| server | requests ok | wall | latency p50 / p99 | aggregate tok/s | TTFT p50 |
|---|---|---|---|---|---|
| `vllm-metal --model <pin> --port 8103` (0.1.0) | 4/4 | 10.83 s | 8.33 / 10.82 s | not measurable (non-streamed) | not measurable |
| `vllm-mlx serve <pin> --continuous-batching --max-num-seqs 4 --max-kv-size 4096` (0.4.1) | 4/4 | 5.25 s | 5.24 / 5.24 s | 915 | 0.012 s |

These are two numbers from one machine with no M8 figures taken on it; they are the
negative space the ladder asks for, never a criterion.

## What this run observed

- **The in-process construction, verbatim:**
  `model, tokenizer = mlx_lm.load(path)`;
  `AsyncEngineCore(model, tokenizer, EngineConfig(model_name=path, scheduler_config=SchedulerConfig(max_num_seqs=N, max_kv_size=K, use_paged_cache=True)))`;
  `core.start()` on the running loop; `await core.add_request(token_ids, SamplingParams(...), request_id=...)`;
  `async for out in core.stream_outputs(request_id, timeout=...)`; `await core.abort_request(request_id)`.
  Continuous batching is the `EngineCore` path itself: the CLI's `--continuous-batching`
  chooses `BatchedEngine` over `SimpleEngine`, and in-process there is no flag to forget.
  `use_paged_cache=True` is not the default and is the one setting without which there
  are no block hashes to publish. This run observed these values; whether the image's
  `mlx_worker` tests pin them follows from the rig re-run, not from this record.
- **The publish call was cheap enough to ride the request path on this machine:** 2.8 µs
  median, 3.6 µs p99 per block, identical through an `await`. The cost is the hash, not
  the hook.
- **The stream did not end after the abort here**, so a worker would own stream
  termination on abort, not only the abort call.

## Harness notes (file:line, fix shape; not changed in this write-back)

1. `s3.sh:103` tests the invariants as constructor keywords; the engine carries them in
   `EngineConfig.scheduler_config`. Correcting that check is not enough: the probe would
   then fail at `s3.sh:115`, which constructs the core from a path with no tokenizer, and
   the calls after it do not match the API the supplementary run used. The request id and
   token ids are passed in a different order, `stream_outputs` is called without a
   request id, and the probe looks for the prefix cache on the core rather than behind
   the scheduler. The drive needs rewriting against that API: `mlx_lm.load`, then
   `SchedulerConfig`/`EngineConfig` with the pinned values, asserting
   `core.engine.scheduler.config` echoes them.
2. `s3.sh:240` starts the control as `python -m vllm.entrypoints.openai.api_server`;
   `vllm-metal` 0.1.0 ships that module only under its `[vllm]` extra, and its own entry
   point is the `vllm-metal` console script. Fix shape: `"$PREFIX/venv-metal/bin/vllm-metal" --model "$MP" --port 8103`.
   Installing the `[vllm]` extra instead would pull an unpinned dependency tree into the
   control venv.
3. `s3.sh:224` pipes the drive through `tee` under `pipefail`, so the drive's exit code is
   the payload's; `s3.sh:253`'s trailing `kill` returns non-zero when the server has
   already exited. Each non-zero payload earns a `FAIL` from `lib.sh:250`, which is how one
   failed criterion read as three. Fix shape: end the drive payload with `exit 0` once a
   `VERDICT` line has been written, and `kill "$PID" 2>/dev/null || true`.
4. `s3.sh:165-173`, the s3.2 loop, breaks only on a ninth event after the abort at the
   eighth. The stream stays open after an abort and sends nothing more (Supplementary
   records), so the loop would wait with no timeout. Fix shape: bound the wait with the
   stream's own timeout and treat its expiry after the abort as the expected end.

## Rig

| | |
|---|---|
| host | an outside machine, reached through the local-payload shim in place of `K3SM_M16_HOST` |
| SoC / memory | Apple M4 Max, 64 GiB (Mac16,6) |
| macOS | 26.6.2 |
| tree | k3sm `main` dba9ee6, `s3.sh` unmodified |
| engine | vllm-mlx 0.4.1 (mlx 0.32.3, mlx-lm 0.32.0) in `$PREFIX/venv`; control vllm-metal 0.1.0 in `$PREFIX/venv-metal` |
| model | `mlx-community/Qwen3-0.6B-4bit` @ `73e3e38d…`, under `$PREFIX/hf` |
| dates (UTC) | 2026-10-02 02:37Z, one ladder run; supplementary runs within the following hour |
