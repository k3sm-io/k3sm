# S4 findings — the worker, end to end (M16.0-d5)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m16/s4.sh`.

## Question

Does a worker built on the M8 engine, behind the upstream backend contract, pass the
conformance kit and serve tokens end to end through a frontend — including as a Pod
requesting `mlx.k3sm.io/gpu`? This is the shape M16.3 productizes, so nothing left
undecided here gets decided later by a build wave.

## Method

Rig-side over ssh: an `MLXEngine` implementing the documented contract
(`start` → config, `generate` → stream, `cleanup`) over S3's in-process core; the
upstream conformance kit run against it; a frontend plus that worker with file
discovery serving a completion; then the same through S2's frontend ClusterIP. The
extended-resource leg runs here only against a **published** worker image
(`K3SM_M16_WORKER_IMAGE`), because a Pod needs one and M16.3 is what builds it;
otherwise it is **recorded as owed** to the gate's worker rung, never silently
skipped.

## Halt

None of its own. A worker that cannot be built on the in-process core is R3's
sidecar shape — the same substitution S3 already names.

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s4.1 the backend contract resolves (base class, engine core) | | |
| s4.2 the conformance kit's assertions | | |
| s4.3 frontend → worker → tokens (file discovery) | | |
| s4.3 the same through the frontend's ClusterIP | | |
| s4.4 a Pod requesting `mlx.k3sm.io/gpu: 1` (or: owed, and to whom) | | |
| s4.5 warm-prefix routing (stretch here, required by the gate) | | |

## What M16.3 inherits from this rung

- The engine module's final shape, which becomes
  `hack/images/mlx-worker/src/mlx_worker/`.
- The `kv_cache_block_size` the worker reports at registration — the value that
  decides whether the router is prefix-aware or round-robin.
