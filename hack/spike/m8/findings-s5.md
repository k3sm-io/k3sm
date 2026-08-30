# S5 — serving-engine bake-off (M8.0-d5) — **PASS: the working hypothesis is RATIFIED, with a binding configuration amendment**

> **M8.4 ENGINE DECISION: `vllm-mlx==0.4.1`, served with `--continuous-batching`.**
>
> The M8 plan's working hypothesis (vllm-mlx) survives — but **only with that
> flag**, which is **not** the default. At its defaults vllm-mlx serves exactly
> one request at a time and returns **HTTP 503 to every other concurrent
> client**: 1 of 4 and 1 of 8 requests succeeded. With the flag it wins every
> throughput axis outright (**775 tok/s aggregate at N=8**, 1.7× the runner-up)
> and its single-stream rate goes *up*, not down. `--continuous-batching` is
> therefore a **binding part of the M8.4 image contract**, not a tuning knob.
>
> **oMLX is ELIMINATED on packageability, not on merit.** M8.4-d1 requires
> `uv pip install --require-hashes` against a checked-in lockfile; oMLX's
> dependency closure contains **four `git+` direct-URL requirements** that
> cannot carry a hash, and the install fails in hash-enforcing mode. It is also
> not published on PyPI at all.
>
> **S3's open process-model question is CLOSED: all three engines are
> single-process.** Res. 18's DEFAULT branch holds — pin the winner
> single-process at M8.4 — and **the M8.2 pgid-enumeration deliverable is NOT
> required**.
>
> The stated minimum bar is cleared by more than one candidate, so the "S5
> terminal" halt condition does not fire.

Run: 2026-08-29 on the S1 rig (Apple M1 Ultra, 64 GiB, macOS 26.5.2 / (redacted)),
agent-driven over ssh. Re-run with `hack/spike/m8/s5.sh`
(`--reinstall`, `--only <engine>`). Model: `Qwen2.5-0.5B-Instruct-4bit` for all
candidates; each engine in its **own** venv under the spike prefix so footprints
do not share and process trees cannot be confused.

## The candidates, and how each was pinned

| candidate | pinned as | distribution |
|---|---|---|
| **mlx-lm** (the "current dev" baseline) | `mlx-lm==0.31.3` | PyPI |
| **vllm-mlx** (the working hypothesis) | `vllm-mlx==0.4.1` | PyPI |
| **oMLX** | `github.com/jundot/omlx` @ `e008a66b4703bc77404dab30f8f898a117d49dfe` (self-versioned 0.6.4) | **not on PyPI** — `pip install` from a clone, a brew tap, or a `.dmg` |

A note on identifying oMLX: the plan names it only as "oMLX (two-tier KV
cache)". There is no `omlx` distribution on PyPI (404). The project measured is
`jundot/omlx`, whose README describes exactly the two-tier hot-RAM/cold-SSD KV
cache the plan's parenthetical names. That identification is recorded here so a
later reader can check it rather than inherit it.

## The scoreboard

Same rig, same model, same prompt, same `max_tokens=128`, `temperature=0`.
Throughput rows are 3 runs after 2 discarded warm-ups; concurrency rows fire N
identical requests from N threads simultaneously and report **every** outcome.

| axis | mlx-lm 0.31.3 | vllm-mlx 0.4.1 *(defaults)* | **vllm-mlx 0.4.1 `--continuous-batching`** | oMLX 0.6.4 |
|---|---|---|---|---|
| single-stream tok/s | 184.5 | 219.1 | **279.0** | 236.6 |
| aggregate tok/s, N=1 | 152.4 | 220.0 | **281.1** | 237.1 |
| aggregate tok/s, N=4 | 224.0 | 219.9 | **720.9** | 421.2 |
| aggregate tok/s, N=8 | 460.8 | 219.7 | **775.1** | 471.8 |
| **requests served, N=8** | **8/8** | **1/8** (7 × HTTP 503) | **8/8** | **8/8** |
| TTFB, streaming | 0.12 s | 0.07 s | 0.07 s | **0.06 s** |
| startup → serving | **1.1 s** | 3.1 s | 3.1 s | 1.7 s |
| process model | **single**, 33 threads | **single**, 33 | **single**, 33 | **single**, 38 |
| venv footprint | **0.31 GB** | 1.21 GB | 1.21 GB | 1.02 GB |
| packages / files / Mach-O | 34 / 6 165 / **30** | 97 / 34 201 / 342 | same | 114 / 16 016 / 383 |
| license | MIT | **Apache-2.0** | Apache-2.0 | Apache-2.0 |
| `--require-hashes` | **OK** | **OK** | **OK** | **FAIL** |
| on PyPI | yes | yes | yes | **no** |

## 1 · Packageability — the axis that decides one candidate outright

M8.4-d1's requirement is not negotiable: *"`uv pip install --require-hashes`
against a checked-in, hash-pinned lockfile"*. So the first question asked of each
engine was whether its closure can be **expressed** that way, before any
performance number was allowed to matter.

```
  mlxlm    compiled: 34 packages, 555 hashes  |  git+ direct-URL requirements: 0
  mlxlm    REQUIRE_HASHES=OK
  vllmmlx  compiled: 97 packages, 1835 hashes |  git+ direct-URL requirements: 0
  vllmmlx  REQUIRE_HASHES=OK
  omlx     compiled: 113 packages, 2982 hashes|  git+ direct-URL requirements: 4
      dflash-mlx     @ git+https://github.com/jundot/dflash-mlx@c55324c8…
      mlx-embeddings @ git+https://github.com/Blaizzy/mlx-embeddings@32981fa4…
      mlx-lm         @ git+https://github.com/ml-explore/mlx-lm@ab1806e8…
      mlx-vlm        @ git+https://github.com/Blaizzy/mlx-vlm@78b96eb5…
  omlx     REQUIRE_HASHES=FAIL
      error: In `--require-hashes` mode, all requirements must have a hash,
      but none were provided for: dflash-mlx @ git+https://…
```

**This is a rule-out, not a preference.** A PEP 508 direct-URL VCS requirement
has no artifact hash by construction, so the resolver cannot produce one and the
installer refuses. Four of oMLX's transitive dependencies — including its own
`dflash-mlx` — are of that shape. Note also that **its `mlx` pin (0.32.0)
disagrees with the wheel set S1/S2/S4 measured (0.32.2)**, and its ABI comment
says the bundled custom kernels are coupled to that exact version, so it cannot
simply be floated forward.

Recorded for fairness, since this is elimination on a supply-chain rule rather
than on capability: **oMLX is the second-fastest candidate**, beats vllm-mlx's
*defaults* everywhere, has the richest `/health`, and is Apache-2.0. If M8.4's
hash-pinning requirement were ever relaxed — it should not be — oMLX would be a
live candidate again, and the commit above is where to restart.

## 2 · Concurrency — the axis the hypothesis actually rests on, and the trap in it

"Continuous batching" is a claim about what happens when requests **overlap**. A
single-stream tok/s number cannot test it, and — the trap — neither can an
aggregate token count: *"the engine batched 8 requests"* and *"7 of the 8
failed"* produce similar-looking aggregates. So the probe reports every
request's HTTP status and its own token count.

That distinction is not academic here. It is the whole finding:

```
  vllm-mlx, DEFAULTS
      N=4    0.47s  1/4 ok    103 tokens   219.9 tok/s aggregate
        x1  http=200
        x3  http=503
      N=8    0.47s  1/8 ok    103 tokens   219.7 tok/s aggregate
        x1  http=200
        x7  http=503
```

The 503 body is explicit about what is happening:

```json
{"detail":{"error":"text_generation_busy",
 "message":"SimpleEngine serialized route is busy; request_id=simple-11722ecc0;
            active=simple-116793740:running:blocking_serialized:…; waiters=0; retry later"}}
```

**`waiters=0`.** There is no queue: a second concurrent request is *rejected*,
not delayed. Under k8s that is a Service in front of one replica returning 503 to
every client but one, immediately, with a healthy `/health` and a green readiness
probe. It would present as a load-balancer or app bug, not as an engine setting.

The cause is a flag, and it is opt-in:

```
  --continuous-batching   Enable continuous batching for multiple concurrent
                          users (slower for single user)
```

With it, on the same binary and the same model:

```
  vllm-mlx, --continuous-batching
      N=1    0.37s  1/1 ok    104 tokens   281.1 tok/s
      N=4    0.58s  4/4 ok    416 tokens   720.9 tok/s
      N=8    1.07s  8/8 ok    832 tokens   775.1 tok/s
```

Two things worth stating plainly:

1. **The flag's own help text is wrong on this rig.** It warns "slower for single
   user"; measured, single-stream went **219 → 279 tok/s (+27 %)** and TTFB was
   unchanged. Do not skip the flag on the strength of that warning.
2. **N=8 at 775 tok/s is 2.8× its own single-stream rate**, and 1.6× the best
   any other candidate reaches at N=8. That is what the hypothesis promised.

For comparison, the other two batch correctly at their defaults but scale less
well: mlx-lm 8/8 at 460.8 tok/s (2.5× its single stream — it has
`--decode-concurrency`), oMLX 8/8 at 471.8 tok/s (2.0×). Neither ever 503s.

**BINDING for M8.4-d1: `--continuous-batching` is part of the image's argv, not
an operator tuning knob**, and the M8.6 gate should assert N-concurrent success —
an S4-style single-request smoke test passes against the broken configuration.

## 3 · `/health` — three surfaces, and only two are usable as a readiness probe

| engine | `GET /health` |
|---|---|
| mlx-lm | `{"status": "ok"}` — **static** |
| vllm-mlx | `{"status":"healthy","model_loaded":true,"model_name":"…","available_models":[…]}` |
| oMLX | `{"status":"healthy","default_model":"qwen05b","engine_pool":{"model_count":3,"loaded_count":0,"final_ceiling":53438350008,"current_model_memory":0,…}}` |

`/healthz` is 404 on all three; `/metrics` is 404 on all three, but vllm-mlx
answers `{"detail":"Metrics endpoint is disabled"}` — it **has** a Prometheus
endpoint (`prometheus-client` is a base dependency) behind configuration, which
the other two do not.

**Consequence for M8.5's readiness probe.** mlx-lm's `/health` reports `ok`
before any weights are loaded — it serves the model list from the HF cache and
loads lazily on first request. A readiness probe pointed at it marks the pod
Ready while the first real request still pays the full model load. vllm-mlx's
`model_loaded: true` is the field an honest readiness probe wants;
oMLX's `loaded_count` is richer still but reports **0** while ready, so it is a
pool-occupancy gauge, not a readiness signal — do not wire a probe to it
expecting `>0`.

## 4 · OpenAI-surface fidelity — where the differences are behavioural, not cosmetic

| probe | mlx-lm | vllm-mlx | oMLX |
|---|---|---|---|
| `POST /v1/completions` | 200 | 200 | 200 |
| `POST /v1/chat/completions` non-stream | 200 | 200 | 200 |
| SSE stream + `[DONE]` | yes | yes | yes |
| `stream_options.include_usage` | 1 usage chunk | **2** usage chunks | 1 usage chunk |
| `usage` keys | `completion_tokens, prompt_tokens, prompt_tokens_details, total_tokens` | `completion_tokens, prompt_tokens, total_tokens` | `+ input_tokens, output_tokens, total_time` |
| `/v1/models` entry keys | `id, object, created` | `+ owned_by` | `+ owned_by, max_model_len` |
| unknown model | **404 with an HF-cache error string** | 404, `The model \`x\` does not exist. Available model: …` | 404, structured `error.message` |

Two of these matter beyond cosmetics:

- **mlx-lm's unknown-model path reaches for the network.** Its 404 body is
  *"Cannot find an appropriate cached snapshot folder for the specified
  revision on the local disk and outgoing traffic has been disabled"* — i.e. it
  attempted a Hub fetch and was stopped only by `HF_HUB_OFFLINE=1`. Inside a
  pod without that variable it would try to **download a model named by an
  untrusted request body**. Under the k3sm egress model that is either a hang (no
  egress) or an unintended fetch (egress allowed). vllm-mlx and oMLX both refuse
  from a served-model list without touching the network.
- **`/v1/models` is not a fixed advertisement for two of the three.** mlx-lm and
  oMLX both enumerate **whatever they can see** — mlx-lm listed both models in
  the HF cache; oMLX reported `model_count: 3` and returned the *3B Llama* as the
  first entry despite being started with a `--model-dir` containing exactly one
  model, because its HF-cache discovery is on by default. vllm-mlx advertises
  exactly the one model named on argv. For an `MLXModel` CRD whose contract is
  "this resource serves this model", a `/v1/models` that varies with the
  contents of a mounted PVC is a fidelity problem in M8.5's render.

## 5 · Process model — S3(5)'s open question, CLOSED

```
  mlx-lm        1 process in the group, 33 threads
  vllm-mlx      1 process in the group, 33 threads
  vllm-mlx --cb 1 process in the group, 33 threads
  oMLX          1 process in the group, 38 threads  (comm: omlx-server)
```

**No candidate forks.** All three are single-process, multi-**threaded** servers,
and threads share the task's `ri_phys_footprint` — so the sampler's
leader-PID-only walk (`pod.go` `containerPIDs`) is **exact** for any of them.

- Res. 18's **default** branch is the one that fires: **pin the winner
  single-process at M8.4**. It is already single-process, so "pinning" means
  *asserting* it, not changing it.
- **The M8.2 `proc_listpids(PROC_PGRP_ONLY,…)` pgid-enumeration deliverable is
  NOT required for M8.** S3 proved the mechanism works and pre-authorized it; S5
  establishes it is not needed. It should be recorded as available-but-unbuilt,
  not silently dropped — S3's 3.9× under-count is real for any future forking
  engine.

**FLAGGED — the scope of that verdict.** It holds for the **single-model serving
configuration measured here**. Every candidate has a multi-model mode
(vllm-mlx `--models-config`, oMLX's engine pool and `cluster` subcommand) that
was not exercised. If M8.5 ever renders a multi-model pod, the process model must
be re-measured before the leader-PID-only assumption is carried over.
The M8.6 gate should assert a **single-process** pod so a future engine bump that
starts forking fails loudly instead of silently under-accounting memory.

## 6 · Footprint — the one axis the winner loses, and what it costs downstream

```
  mlxlm       324 541 KB (0.31 GB)   34 packages    6 165 files    30 Mach-O
  vllmmlx   1 265 301 KB (1.21 GB)   97 packages   34 201 files   342 Mach-O
  omlx      1 067 692 KB (1.02 GB)  114 packages   16 016 files   383 Mach-O
```

vllm-mlx costs **3.9× mlx-lm's footprint** because its *base* dependencies (not
extras) include `torch`, `torchvision`, `opencv-python`, `gradio`, `scipy`,
`pandas` and `mcp` — the vision/audio/UI surface of a project whose scope is
wider than text serving.

**Composed with S4's measured numbers, the mlx-serve image becomes:**

| | S4 as measured (mlx-lm) | projected with vllm-mlx |
|---|---|---|
| unpacked | 0.37 GB | **~1.3 GB** (still **PASS** vs the >2 GB threshold, ~0.7 GB headroom) |
| entries | 9 069 | ~36 000 |
| Mach-Os | 41 | **~353** |
| clonefile / pod | 1.2 s | **~4.7 s** *(extrapolated at S4's measured ~130 µs/entry)* |
| ad-hoc tree-sign | 0.67 s | **~5.8 s** *(extrapolated at S4's measured ~16 ms/Mach-O)* |
| Mach-O discovery walk | 8.4 s | **~38 s** *(extrapolated at S4's `file(1)`-per-file rate)* |

The two extrapolated columns are labelled as such: they are S4's **measured
per-unit rates** applied to S5's **measured** entry and Mach-O counts, not
re-measured end to end. They do not change any threshold verdict — 1.3 GB is
still comfortably under 2 GB — but they do change two engineering conclusions:

1. **S4's "budget the walk, not the signature" recommendation gets sharper.** A
   ~38 s `file(1)` walk on every image arrival is not acceptable; reading the
   Mach-O magic in Go is now required rather than merely tidy.
2. **The per-pod materialize budget roughly triples** (1.2 s → ~4.7 s clone).
   Still small against a 3.2 s first token, but M8.5's probe timings should be
   sized against the composed number, not S4's mlx-lm-only one.

One more margin worth naming: `pkg/oci`'s build-context budget
(`MaxContextBytes`) is **2 GiB**, and a ~1.3 GB vllm-mlx tree consumes 65 % of it.
Two more dependencies of `torch`'s size and `k3sm build` refuses the image with
`ErrContextTooLarge`. That is a **build-time** ceiling distinct from the S4
pruning threshold, and it is the one that will bind first.

**The pruning menu, if it ever binds.** The Res.-17 "S4 remediable" branch does
not fire today, but should it later: `gradio`, `opencv-python`, `torchvision`,
`mlx-audio` and `mcp` are all base dependencies that a **text-only** serving image
does not execute. Whether vllm-mlx tolerates their absence was **not tested here**
and must not be assumed — the honest statement is that a pruning path plausibly
exists, not that one is known to work.

## 7 · License

All three are permissive and machine-readable from the installed artifact:
**mlx-lm MIT**, **vllm-mlx Apache-2.0**, **oMLX Apache-2.0**. mlx-lm declares its
license only in the `License` metadata field and carries **no license
classifier**; the other two carry both. Anything generating `NOTICE` from
installed metadata must read `License`/`License-Expression`, not classifiers
alone.

## The decision, and why

**`vllm-mlx==0.4.1` with `--continuous-batching`.** In order of how the
candidates fell out:

1. **oMLX fails a hard M8.4 requirement** — no hash-pinnable lockfile, no PyPI
   distribution. Eliminated regardless of its (good) numbers.
2. **Between the two survivors, vllm-mlx wins throughput at every concurrency**
   (279 vs 185 single-stream; 775 vs 461 at N=8), has the only `/health` that
   reports model readiness, has a Prometheus endpoint available, refuses unknown
   models without touching the network, and advertises a **fixed** `/v1/models`.
3. **mlx-lm wins footprint by 3.9×** and is the documented fallback if the image
   budget or the 2 GiB build-context ceiling ever binds. It is a real fallback,
   not a formality: it batches correctly, it is MIT, and it is already the
   dependency S1–S4 measured.

### The pinned wheel set (M8.4-d1 input)

```
vllm-mlx==0.4.1
```
resolves to a **97-package, 1 835-hash** lockfile via
`uv pip compile --generate-hashes`, installable with
`uv pip install --require-hashes`. Two constraints inherited from S4 apply to
generating it:

- **compile it natively on macOS 14+ arm64** — `--python-platform macos`
  defaults to macOS 13.0, for which no `mlx` wheel exists;
- the lockfile is **not** checked in by this spike. It is regenerated by
  `s5.sh` at `<prefix>/engines/vllmmlx/req-hashed.txt`; M8.4-d1 owns the
  checked-in copy, so that it is reviewed as product supply chain rather than
  inherited from a spike's scratch directory.

## What W4's builder must do differently

1. **Ship `--continuous-batching` in the image's argv.** Without it the pod
   serves one request at a time and 503s the rest — with a green `/health` and a
   green readiness probe, so nothing else catches it.
2. **Make the M8.6 gate concurrent.** Assert N≥4 simultaneous completions all
   return 200. A single-request smoke test passes against the broken config.
3. **Point M8.5's readiness probe at `/health` and require `model_loaded`** —
   not the mere 200, and not oMLX-style `loaded_count`.
4. **Pin the pod single-process and assert it**, per Res. 18's default branch.
   **Do not build the M8.2 pgid-enumeration deliverable for M8** — record it as
   available-but-unbuilt, with S3's 3.9× under-count as the reason it must come
   back if any future engine forks.
5. **Re-check the image against the 2 GiB `MaxContextBytes` build-context
   ceiling**, not only the 2 GB unpacked threshold. vllm-mlx's tree uses 65 % of it.
6. **Implement the Mach-O walk in Go**, reading the magic. At ~353 Mach-Os over
   ~36 000 files, a `file(1)`-per-file walk costs ~38 s per image arrival.
7. **Regenerate and check in the hashed lockfile as a product artifact.** Do not
   copy this spike's scratch copy.
8. **If the footprint ever binds, fall back to mlx-lm** (0.31 GB, MIT, batches
   correctly) — but then set `HF_HUB_OFFLINE=1` in the image, because mlx-lm
   tries to fetch a model named by an untrusted request body.
