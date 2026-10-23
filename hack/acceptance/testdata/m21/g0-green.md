## P0 calibration results

The calibration run measured the pressure signals and channels on two Macs before any of the
design's thresholds were fixed: the server (64 GiB, runs the control plane) and the worker (8 GiB).
Both ran macOS 27.0.1. Nothing was installed or restarted for the run, and no pressure was induced on
the server.

Each row answers one calibration question. The verdict is exactly one of PASS (the design holds as
written), FAIL (the design had to change, and the answer says how) or N/A (no verdict yet, and the
answer says what is still owed). The evidence column names each evidence file with the first 16 hex
characters of its sha256. Question (f) is not a measurement, since a design decision settled it, so it
has no row. The gate `hack/acceptance/m21.sh --g0` parses this table.

| Q | verdict | answer | evidence (sha256 prefix) |
|---|---|---|---|
| (a) | PASS | `kern.memorystatus_vm_pressure_level` (1, 2, 4) and `kern.memorystatus_level` (percent) read without privilege as `_k3sm` and inside a generated pod sandbox profile on both Macs, with no profile change; the macOS level sat at warning in 8.2% of samples on the worker at ordinary load, so it is reported as information only and carries no threshold | `a-server-sysctl-unprivileged.txt` `c51323f82eff6a73`, `a-worker-sysctl-unprivileged.txt` `9ea9c6bf0f8343b6`, `c-server-probe.txt` `f6b635690b3215d0`, `c-worker-probe.txt` `cad80a9c57a417f9` |
| (b) | N/A | time at the warn rung over 0.95 h of samples: `memory.available` 0% and `memory.compressor` 0% (max 18.7%) on both Macs, so those defaults stand; `memory.swap` and `swapfs.available` sat at warn 100% of the time on the worker at idle (5.1 to 5.5 GiB of swap used, 26 to 29 GiB free), so swap is re-derived as growth rungs and the swap-volume floor as 3x, 2x, 1.5x and 1x; `nodefs.available` and `pid.available` were not measured. Still owed: the full week of samples (168 h), until which these values are provisional | `b-g-analysis-partial.txt` `53d90ea9090a13bb` |
| (c) | PASS | a shared `os_sync_wait_on_address` on the `notifyEpoch` word and a kqueue doorbell both wake a sandboxed `_k3sm` reader across processes and across uids; a pod that has not opted in gets EPERM, and an opted-in pod can only read | `c-server-probe.txt` `f6b635690b3215d0`, `c-worker-probe.txt` `cad80a9c57a417f9` |
| (d) | PASS | the Node annotation stays the channel: an annotation write costs the same apiserver latency as a Lease renew (the difference is about 64x the datastore bytes), and annotation-only Node updates requeue no pending pod; writes become edge-triggered on a quantized change, at most one per 60 s, and the Lease fallback is dropped | `d-write-cost.txt` `a31962683b8bf0db`, `d-scheduler-metrics-t3.txt` `c4465c916a564ac2`, `d-scheduler-metrics-t4.txt` `02b98dbed79684c9`, `d-node-watch-180s.txt` `8a6237a562acea16` |
| (e) | PASS | negative confirmed: a guest never sees host updates to a virtiofs file it holds open, through mmap or `pread`, even after a host `msync` or `pwrite`; a fresh open sees the latest value, so `vm` pods keep the `PublishBudget` path into a guest-local page | `e-virtiofs-mmap.txt` `1a2f36f0b5236fc0` |
| (g) | N/A | the fill rate inside the 75-98% band was not measured: on the worker the swap volume fills before the band is reached, and inducing that pressure on the server was out of scope. The worst-case bound measured is 1.15% of the compressor segment limit per second, from an induced 1.28 GiB burst on the worker (passive maxima 0.139%/s on the server and 0.118%/s on the worker), which supports a tier-2 trip at 80% held 5 s and an instant trip at 90%. Still owed: the pod eviction teardown latency, which sets the tier-2 hold | `g-induced-worker.txt` `16a2888010a63f1e`, `samples-worker-burst.csv` `46ac67e17632d733`, `b-g-analysis-partial.txt` `53d90ea9090a13bb` |
| (h) | FAIL | read from the kernel source, not tested live: with only batch-band pods carrying the kill mark, the kernel's no-paging-space action finds a victim only if a marked process holds compressed pages or one unmarked process holds over half of them, and otherwise kills nothing and retries every 5 s; resolved by marking both the batch and the standard bands | `h-xnu-excerpts.txt` `30473e3be051488f` |
