# S3 findings — the engine decision (M16.0-d4)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m16/s3.sh`.

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

| criterion | verdict | evidence |
|---|---|---|
| s3.1 token IDs in, tokens out, in-process, invariants pinned | | |
| s3.2 abort mid-stream accepted | | |
| s3.3 block hashes observable (stored / evicted, block size) | | |
| s3.4 publish cost per block, sync vs async (median, p99) | | |
| s3.5 the alternative engine as a control (recorded) | | |

## Consequences recorded here

- The in-process construction kwargs the worker must use, verbatim — the CLI flags
  that carry the continuous-batching and pinned-KV invariants are **bypassed
  entirely** in-process, which is why the image's `mlx_worker` package carries its
  own tests for them.
- Whether the publish call can ride the request path, from s3.4's numbers.
