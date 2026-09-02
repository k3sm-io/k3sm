# S3 — memory visibility & growth (M8.0-d3) — **PASS, with one binding consequence**

> **Verdict: PASS.** `ri_phys_footprint` — the OOM watcher's input in
> `runtimed/pkg/supervisor/sampler.go` — sees the Metal/unified working set
> **exactly**, so the accounting source needs no redesign (the M8 plan Res. 17 S3 is
> terminal-or-redesign; neither consequence fires). **One binding consequence
> does fire**: the sampler's leader-PID-only walk under-counts a forking engine
> by the entire child working set, so Res. 18's contingency is **required**
> unless M8.4 pins the S5 winner single-process.

Run: 2026-08-29 on the S1 rig (Apple M1-family, 64 GiB, macOS 26.5.2).
Re-run with `hack/spike/m8/s3.sh`. Model: `mlx-community/Llama-3.2-3B-Instruct-4bit`
(1.7 GB, under the 2 GB cap). Sampler: `s3mem`, whose cgo call is
`proc_pid_rusage(pid, RUSAGE_INFO_V2).ri_phys_footprint` — the *same* call
`rusage_darwin.go` makes, so a divergence here would be a divergence in
production.

## (1) Visibility — **YES, and RSS is useless**

The single most important number in this spike. Under the S1 profile, holding
**24 GiB** of pure `MTLBuffer` allocations with no file backing:

```
  t=0      fp=  4112.9MB rss=    31.1MB
  t=3009   fp= 10257.0MB rss=    31.2MB
  t=7019   fp= 16401.1MB rss=    31.3MB
  t=11031  fp= 24593.1MB rss=    31.3MB      <- 24 GiB allocated
```

- **`ri_phys_footprint` tracks Metal allocations 1:1** — 24 593 MB of footprint
  for 24 GiB of MLX arrays, ~500 MB of which is the interpreter. It is not an
  approximation; each 2 GiB step moves it by exactly 2048 MB.
- **`ri_resident_size` (RSS) stays flat at 31 MB** across the entire 24 GiB ramp.
  RSS is **blind** to the unified-memory working set.

**Consequence:** the OOM watcher's existing input is correct and needs no change.
Had `sampler.go` metered RSS instead, an MLX pod would have appeared to use
31 MB while holding 24 GiB, and every limit would have been unenforceable. The
`ri_phys_footprint` choice — already documented in `rusage_darwin.go` as "NOT
RSS" — is load-bearing for M8 specifically. **Do not "simplify" it to RSS.**

At model load the two agree closely, which is the mmap-weights case:
`fp=1960.6MB` vs `rss=2088.6MB` for a 1.7 GB model whose weights are
file-backed. The split is therefore: **mmap'd weights show in both; MTLBuffer
allocations show only in footprint.**

## (2) Sustained-generation growth — ~0.15 MB/token

1200 tokens of continuous generation, 3B-4bit, sampled at 500 ms:

```
  PHASE loaded  mlx_active=1807441224   fp=1960.6MB
  TOK  200      mlx_active=1839666298   fp≈1985MB
  TOK  600      mlx_active=1898386554   fp≈2037MB
  TOK 1000      mlx_active=1977331106   fp≈2143MB
  TOK 1200      mlx_active=1977339298   fp≈2132MB   peak observed 2190.6MB
  DONE tokens=1200  mlx_peak=2012890478
```

- Steady-state growth **1960.6 → ~2132 MB over 1200 tokens ≈ 0.145 MB/token**
  of KV cache for this model. Linear, as expected.
- **Transient peaks exceed the steady state by ~60-130 MB** (2190.6 MB observed
  against a ~2100 MB floor), and the footprint *oscillates downward* between
  samples — MLX's buffer cache (`mlx_cache` spiked to 131 MB at TOK 1000, then
  fell to 2.8 MB) is returned and re-taken.

**Consequence for the M8.5 sizing formula:** a limit set at the steady-state
footprint will be tripped by the allocator's own cache churn. The formula needs
**headroom above the transient peak**, not above the mean — here that is ~6% on
a 2 GB working set, and the KV term is `tokens × ~0.15 MB` for a 3B-4bit model
(scale by model KV geometry). A sampler that kills on a single over-limit sample
will produce spurious kills; **require N consecutive samples over limit.**

## (3) The mmap-weights vs MTLBuffer split

Covered by (1): weights are file-backed and appear in both footprint and RSS;
GPU-side buffers appear only in footprint. The 24 GiB ramp is the clean
MTLBuffer-only case (RSS 31 MB), the model-load figure is the mixed case.

## (4) Killer order past the wired limit — **nothing fires; the wired limit is not a limit**

Bounded probe: `mx.set_wired_limit(1 GiB)`, then allocate **8 GiB** past it.

```
  WIRED_LIMIT_SET 1.0GB
  STEP 2GB mlx_active=2.00GB level=90
  STEP 4GB mlx_active=4.00GB level=90
  STEP 6GB mlx_active=6.00GB level=87
  STEP 8GB mlx_active=8.00GB level=91
  HOLD_DONE held=8GB level=91
      fp=8209.0MB rss=31.2MB
  jetsam events in window: (none — only unrelated runningboardd noise)
```

- **The Metal wired limit is a residency hint, not a cap.** Allocation 8× past it
  succeeded, no exception, no eviction visible to the process.
- **No jetsam event fired**, at 8 GiB or at 24 GiB. `kern.memorystatus_level`
  never left the 87–91 band on a 64 GiB machine.

**Consequence: k3sm's own sampler is the operative killer for MLX pods.** There
is no Metal-side backstop to defer to, and jetsam does not engage until real
system pressure. The M8.5 limit and the `sampler.go` OOM path are the *only*
thing standing between an over-sized `MLXModel` and the whole node.

**FLAGGED — the bounded-probe honesty clause.** The M8.0 guardrails forbid
destabilizing the lab, so this probe was hard-capped (8 GiB / 24 GiB) with an
abort guard at `kern.memorystatus_level < 20`. **It therefore does NOT determine
the sampler-vs-jetsam ordering under genuine system pressure** — it establishes
the weaker, sufficient fact that *nothing* fires before ~24 GiB on a 64 GiB rig,
so the sampler owns the decision in the whole range M8 cares about. A true
killer-order determination needs a machine that may be driven to OOM (the
`hack/lab-vm.sh` disposable-guest class), not the shared lab rig. Do not read
this section as proving the sampler wins a race against jetsam.

## (5) Process-group coverage — **leader-PID-only UNDER-COUNTS 3.9×**

Leader holds 200 MB; two forked children hold 300 MB each.

```
  leader=3268 children=3269 3270
  t=0     fp=207.3MB  rss=215.9MB  pgrp_n=6  pgrp_sum=817.3MB
  t=1503  fp=207.3MB  rss=215.9MB  pgrp_n=6  pgrp_sum=817.3MB
  t=3005  fp=207.3MB  rss=215.9MB  pgrp_n=6  pgrp_sum=817.3MB
```

- **Leader-PID-only sees 207.3 MB. The true group working set is 817.3 MB.** The
  leader's `ri_phys_footprint` is blind to forked children — a **3.9×
  under-count** here, and the ratio grows with the number of workers.
- **`proc_listpids(PROC_PGRP_ONLY, getpgid(pid))` fixes it**, exactly as Res. 18
  pre-authorizes: it enumerated the group and summing per-member footprints
  recovered 200 + 300 + 300 MB plus ~17 MB of shell overhead.

**Consequence — one of these two MUST ship, and the choice is M8.4's:**

- **Either** M8.4 **pins the S5 winner single-process** (the Res. 18 default), in
  which case leader-PID-only is exact and nothing changes in `sampler.go`;
- **or** M8.2 lands the pgid-enumeration deliverable. The mechanism is proven
  here on public libproc, in the `rusage_darwin.go` cgo pattern, and needs a
  `spicanary` row like its siblings.

Silently keeping leader-PID-only against a forking engine is the one outcome
that must not happen: the pod would appear to fit its limit while the node ran
out of memory, and the OOM watcher would never fire.

**Measurement caveat, recorded for honesty:** `pgrp_n=6` counts the shell's
whole job group, not only our three processes — the harness ran from an
interactive shell. Under runtimed this is not a source of error: the daemon
already places each pod's containers in their own process group (the
`PodReapSubdir` store is keyed `<podID>/<pgid>.json`), so `PROC_PGRP_ONLY` over
that pgid is exactly the pod and nothing else. The sum reconciles
(207 + 300 + 300 ≈ 807 of the 817 MB reported).

## What W4's builder must know

1. **Keep `ri_phys_footprint`.** It is the only accounting source that sees the
   GPU working set; RSS reports 31 MB for a 24 GiB pod.
2. **Size with headroom over the transient peak**, ~6% here, plus a
   `tokens × 0.15 MB` KV term for a 3B-4bit model. Require N consecutive
   over-limit samples before killing, or MLX's buffer-cache churn will cause
   spurious kills.
3. **The sampler is the only killer.** No Metal or jetsam backstop engages in the
   range M8 operates in.
4. **Decide the process-model question explicitly at M8.4** — pin the engine
   single-process, or land the pgid walk. Do not leave it implicit.
