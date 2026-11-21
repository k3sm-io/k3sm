# Node budget design

## P0 calibration results

This table records the verdict of each M21 P0 calibration question and the rule k3sm adopts from it.

| Q | verdict | result and the rule adopted |
|---|---|---|
| (a) | PASS | `kern.memorystatus_vm_pressure_level` (1/2/4) and `kern.memorystatus_level` (percent) read without privilege as `_k3sm` and inside a generated pod SBPL. The macOS level sits at warning for a large share of ordinary use, far above the 5% warn rule, which supports a design decision: it stays information only |
| (b1) `memory.available` | PASS | the warn rung holds below 5% of the time at quiet load; under heavy load max(1Gi, 12% mem) does not and max(1Gi, 11% mem) does (ruled by the operator). On a small-memory Mac the 1Gi floor sets the rung |
| (b2) `memory.compressor` | PASS | the warn rung holds below 5% at quiet load; under heavy load 50% does not and 56% does |
| (b3) `memory.swap` | PASS | the growth rungs of the earlier ruling (warn on a 256Mi rise in 60 s, gated on used >= max(1Gi, memsize/4)) hold below 5% at quiet load; under heavy load a 512Mi warn is needed. The first-pass FAIL was the level rungs, already replaced |
| (b4) `swapfs.available` | FAIL | on a small-memory Mac, swap-volume free space falls below 3x floor often in ordinary use even while the compressor is low, because the shared APFS container fills. No threshold fixes it as a memory signal; it is a disk signal, not a memory one, and is carried by separate follow-up work |
| (b5) `nodefs.available`, `pid.available` | N/A | not sampled by the spike; the threshold rows unchanged |
| (b6) the extended sample run | PASS | an extended run on each of two machines answered (b1) to (b4). The samples carry no load column, so "quiet" and "heavy" are split by a memory-churn proxy (mean gross compressions per second over 10 minutes) |
| (c) | PASS | shared `os_sync_wait_on_address` on `notifyEpoch` and the kqueue doorbell wake a sandboxed reader across processes and uids; non-opted-in pods get EPERM, opted-in pods read only |
| (d) | PASS | an annotation write costs the same apiserver latency as a Lease renew but about 64x the kine bytes, so writes are rate-limited; the Node annotation stays the channel; annotation-only updates requeue no pending pod; the rate changed to edge-triggered quantized writes at most one per 60 s, Lease fallback dropped |
| (e) | PASS | negative confirmed: a guest never sees host updates to an open virtiofs file through mmap or `pread`; `PublishBudget` stands |
| (f) | N/A | resolved by a design decision; nothing to measure |
| (g1) fill rate inside the 75-98% band | PASS | measured; in-band fills are slow enough that the tier-1 rungs and the 5 s hold have time to act, and the fastest fills are tier 2's by construction |
| (g2) worst-case fill-rate bound | FAIL | the earlier, lower bound of the prior ruling is exceeded. The design bound becomes 2.533% of the segment limit per second. At that rate the kernel's 98% point is 7.1 s from 80% and 3.2 s from 90% (to 100%: 8 s and 4 s). The tier-2 numbers are re-sized, ruled by the operator (85% instant trip) |
| (h) | FAIL | from source, no live test: with only batch pods marked the kernel can find no victim; resolved by an operator ruling (batch and standard marked) |
| (i) eviction teardown latency | PASS | delete call to process gone and footprint returned is under 1 s for native and vm pods, and the tier-2 teardown allowance is 0.8 s. It also found grace 0 resolving to the pod's 30 s grace; follow-up fixes (done) make wire grace 0 the immediate SIGKILL, so the 0.8 s allowance is the tier-2 teardown |
