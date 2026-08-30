# S1 — Metal under Seatbelt (M8.0-d1) — **PARTIAL / GO**

> **Verdict: criterion 1 PASS (the M8 go/no-go), criterion 2 SPLIT — SBPL half
> PASS, production-datapath half ATTEMPTED-BLOCKED.** Per the M8 plan Res. 17 S1 is
> the terminal spike; criterion 1 passing means **M8 proceeds**. Criterion 2's
> blocked half is a *structural* block with an exact cause (below), not an
> unfinished attempt, and it does not gate the M8.2-d1 encoding.

Run: 2026-08-29, agent-driven over ssh. Re-run with `hack/spike/m8/s1.sh`
(`--setup` first on a clean rig).

## Rig

| | |
|---|---|
| host | `miko-studio.blackmesalab.com` (the bare name does not resolve) |
| SoC | **Apple M1 Ultra**, 20-core, 64 GiB unified — *not* the M1 Max the M8.0 ledger row records; the row should be corrected |
| macOS | **26.5.2**, build **25F84** |
| GPU | `AGXAcceleratorG13X` (IOKit service class); MLX reports `architecture: applegpu_g13d`, `max_recommended_working_set_size: 55662788608` |
| toolchain | uv 0.12.7 → CPython 3.12.14 (python-build-standalone) |
| pins | `mlx==0.32.2`, `mlx-metal==0.32.2`, `mlx-lm==0.31.3`, `transformers==5.16.1`, `tokenizers==0.23.1`, `numpy==2.5.2`, `safetensors==0.8.0`, `huggingface-hub==1.29.0` (full set: `$PREFIX/logs/pip-freeze.txt`) |
| model | `mlx-community/Qwen2.5-0.5B-Instruct-4bit`, 276 MB |
| prefix | `~/k3sm-spike-m8` — every write confined here; no sudo, no `/Library/Sandbox/Profiles`, no TCC/Gatekeeper/SIP/LaunchDaemon touch |

## THE ADOPTED ALLOW-SET

The entire Metal delta over the existing `sbpl.go` default-deny profile is **one
rule**:

```lisp
(allow iokit-open
  (iokit-registry-entry-class "AGXDeviceUserClient")
  (iokit-registry-entry-class "IOSurfaceRootUserClient"))
```

Nothing else. No `mach-lookup`, no `iokit-get-properties`, no `/private/var/db/CVMS`
read, **no shader-cache write**. Under it a full `mlx_lm` round-trip generates
tokens and a cold JIT Metal-kernel compile succeeds.

## Criterion 1 — tokens generated under the profile: **PASS**

The profile mirrors `runtimed/pkg/sandbox/sbpl.go` `Generate()` rule-for-rule and
in order — `(version 1)` → `(deny default)` → `(import "system.sb")` → allows →
protected denies (`/Users`, `/private/var/db`, the cryptex write-deny) → narrow
re-allows. `$PREFIX` lives under `/Users`, so the rootfs and data-volume
analogues are re-allowed *after* the `/Users` deny, exactly as production
re-allows the pod data volume after the protected denies.

```
  minimal-gen => TOKENS_OK
  minimal-jit => JIT_OK k3sm_s1_5f8399366fe4 22.0
```

Full generation output, unsandboxed control vs profile:

```
Three primary colors are red, blue, and yellow.
Prompt: 34 tokens, 16.952 tokens-per-sec
Generation: 12 tokens, 284.241 tokens-per-sec
Peak memory: 0.336 GB
LOAD_S=0.28 GEN_S=2.14
TOKENS_OK
```

`minimal-jit` uses a **UUID-suffixed kernel name every run**, so it is a
genuinely cold `MTLLibrary` compile, not a cache hit — without that the
"no shader-cache write is needed" finding below would be a warm-cache artifact.

### The raw denial evidence

`probe0` — the same profile with **no** GPU rules at all. This is what the
allow-set is derived from; nothing here was guessed:

```
  probe0 => ImportError: [metal::load_device] No Metal device available.
      DENY iokit-open-user-client AGXDeviceUserClient
      DENY iokit-open-user-client IOSurfaceRootUserClient
      DENY mach-lookup com.apple.tccd.system
      DENY mach-lookup com.apple.windowserver.active
      DENY file-read-data <home>/.CFUserTextEncoding
      DENY file-read-metadata /private/var/db/timezone/zoneinfo
```

`tccd.system` and `windowserver.active` stay **denied** in the adopted set and
generation works anyway — they are probes, not requirements. Allowing either
would be an unforced widening.

## R22 — the prefix rule: **it does NOT hold as written; the fallback is NOT needed either**

R22's primary job was to validate `(iokit-registry-entry-class-prefix "AGXAcceleratorG")`.
Measured, on the real rig:

| candidate | result |
|---|---|
| `(allow iokit-open (iokit-registry-entry-class-prefix "AGXAcceleratorG"))` | **FAILS** — `No Metal device available`; both user-client opens still denied |
| `(allow iokit-open (iokit-registry-entry-class-prefix "AGXDeviceUserClient"))` | partial — AGX granted, then `Failed to create Metal shared event`; `IOSurfaceRootUserClient` still denied |
| `(allow iokit-open (iokit-registry-entry-class "AGXDeviceUserClient") (iokit-registry-entry-class "IOSurfaceRootUserClient"))` | **PASS** — `JIT_OK`, `TOKENS_OK` |
| `(allow iokit-open)` bare | PASS, but grossly over-scoped — rejected |

**Why it fails.** The `iokit-registry-entry-class*` filter matches the class of
the **user client being opened**, not the class of the accelerator IOService
behind it. On this rig the service is `AGXAcceleratorG13X` but the user client is
`AGXDeviceUserClient`; `"AGXAcceleratorG"` therefore matches nothing MLX opens.
R22's string was derived from the *service* name and is simply the wrong axis.

**What this means for M8.2-d1, and it is good news:**

1. **The prefix rule's SHAPE is vindicated — its STRING is not.** R22's real
   goal was "no per-chip-family table". That goal is *met*, and more strongly
   than R22 hoped: `AGXDeviceUserClient` and `IOSurfaceRootUserClient` are
   **family-independent class names** — they carry no `G13X`/`G14`/`G16` suffix
   at all. Two **exact** class names cover every family by construction.
2. **The per-family fallback table is not merely unnecessary — it is
   unimplementable on this axis.** A table of `AGXAcceleratorG13X`-style names
   cannot be written as an SBPL `iokit-registry-entry-class` filter, because
   those names are never the ones checked. **Do not encode the fallback.**
3. **Prefer exact classes over a prefix.** `(iokit-registry-entry-class-prefix "AGX")`
   also passes but admits every future `AGX*` user client sight-unseen. Two exact
   names are tighter and cost nothing, since neither varies by family.
4. **Res. 14's fail-closed control is unaffected and remains THE gate.** R22
   already says the SBPL rule is "a static ceiling, not a family approximation";
   this result makes that literally true — the rule contains no family
   information whatsoever. `metal.go`'s Go-side data and the
   `sandbox_gpu_supported` advertisement stay the sole family gate, keyed (per
   R22's prefix-rule branch) on the **functional probe**.

**FLAGGED — the one honest scope caveat.** Only **M1-family hardware (G13X /
`applegpu_g13d`)** was available. The claim "these two class names are
family-independent" rests on their *form* (no family suffix) plus Apple's own
practice, not on an M3/M4 measurement. M8.3's `sandbox_gpu_supported` functional
probe is what makes this safe: on a family where the two names are wrong, the
probe fails and the node never advertises `mlx.k3sm.io/gpu`. That is the
fail-closed path Res. 14 requires, and it is why this residual is acceptable
rather than blocking.

## Ablation — every candidate rule that is NOT load-bearing

Each was added to the passing minimal set and its necessity tested by removal:

| candidate rule | needed? | evidence |
|---|---|---|
| `(allow mach-lookup (global-name "com.apple.MTLCompilerService"))` | **NO** | cold JIT compile → `JIT_OK` with it absent. **Over-scope; do not ship.** The Metal front-end compiles in-process on macOS 26; the research hint is stale. |
| `(allow iokit-get-properties)` | **NO** | `TOKENS_OK` with it absent. **Over-scope; do not ship.** |
| `(allow file-read* (subpath "/private/var/db/CVMS"))` | **NO** | absent from the adopted set; no CVMS denial ever appeared. **Over-scope; do not ship.** |
| shader-cache write scope | **NO** | see below |

Three of the four research hints were **over-scope on macOS 26.5.2**. This is
exactly the widening Res. 11 and the M8.0 guardrails require be flagged rather
than silently adopted — so they are flagged, and dropped.

## Shader cache — Res. 11 resolves the GOOD way: **no write allow, no cross-pod channel**

Res. 11 required S1 to show either that the shader cache is steerable per-pod or
that the allow is an enumerated narrow subpath, **and** that `limitations.md`
names the cross-pod shared-cache channel it creates. Measured: **neither branch
is needed, because no write allow is needed at all.**

```
  cacheprobe => WRITE_DENIED com.apple.metal PermissionError
      DENY file-read-data     .../C/com.apple.metal
      DENY file-read-data     .../C/com.apple.metalfe
      DENY file-write-create  .../C/com.apple.metal/k3sm_s1_probe.txt
      DENY file-write-create  .../C/com.apple.metalfe/k3sm_s1_probe.txt
```

The confined pod can neither list nor write `DARWIN_USER_CACHE_DIR/com.apple.metal`
or `com.apple.metalfe` — and generation and cold JIT compile both succeed anyway.
A before/after `stat` + file-count over `com.apple.metalfe` across a sandboxed JIT
run **and** an unsandboxed control showed **zero change in either case**: MLX's
`metal_kernel` path does not write an on-disk shader cache at all.

**Consequence for M8.2-d1 and `limitations.md`:** there is **no cross-pod
shared-cache channel to disclose**, because the shared cache is unreachable from
a confined pod. `file-write*` outside the pod data volume stays absent — the
profile's core invariant is intact, undiluted. This is strictly better than
either branch Res. 11 anticipated, and M8.2-d1 should encode **no write rule**.

**FLAGGED as a re-check, not a widening:** should a future MLX/engine version
(or the S5 winner) begin using an on-disk `MTLBinaryArchive`, this conclusion
changes. The M8.6 gate should keep a `WRITE_DENIED` assertion so the regression
is caught rather than silently papered over with a write allow.

## Criterion 2 — HF weight download through the production datapath: **SPLIT**

### (a) SBPL half — **PASS**

The 289.6 MB model was downloaded end-to-end (DNS, TLS, HTTP) from a pod-shaped
process under the R21 `allow_internet_egress` stanza — emitted **byte-identical**
to `sbpl.go`'s `AllowNetwork` stanza (`sbpl.go:382-411`), comment lines included,
which is the artifact R21's re-scoped `Validate` check will compare against:

```
  egress => DOWNLOAD_OK 7.3s 289.6MB
      DENY mach-lookup com.apple.SystemConfiguration.configd
      DENY system-socket domain:32 type:2 protocol:2
      DENY file-read-data /private/etc/ssl/openssl.cnf
```

All residual denials are non-fatal — `configd` and the `PF_SYSTEM` route socket
are optional network-configuration probes, and Python's TLS uses the system trust
store, not `openssl.cnf`. **No additional network rule is required beyond the
existing stanza**, which confirms R21's "same unfiltered-but-compilable stanza as
`allow_network`" is sufficient for the MLX weight-pull path.

### (b) Production-datapath half — **ATTEMPTED-BLOCKED (structural)**

Not run. The exact cause, from `k3sm/cmd/k3sm/dev.go:47-49`:

```
  rootless (default): runtimed + network=none — real apiserver + CRD/SSA/CEL + real pod lifecycle +
                      Seatbelt, NO root. Datapath is INERT (Service traffic needs --datapath).
  --datapath (root):  runtimed + network=direct — real Service/ClusterIP/DNS/pod-IP. Requires euid 0.
```

The DNS shim → Service-proxy dialer → egress chain criterion 2 names **exists
only in the `--datapath` tier**, and that tier **requires euid 0**. The M8.0
ledger guardrails and this dispatch both forbid root/sudo on the lab. So the
criterion is not "we ran out of time" — it is unreachable from a rootless
session by construction. Standing it up needs a *privileged* lab slice.

**Owed slice.** Run the HF download from inside a real pod on a
`k3sm dev up --datapath` cluster (euid 0) and confirm it resolves through the
DNS shim and dials through the Service proxy. This is the machine check on
the M8 plan's "darwin-net has no planned work" claim, and it is **still owed** —
recommend filing it as an M8.6-gate row or a `human_gate: true` backlog item,
since it needs root.

**What criterion 2(a) does and does not license.** It proves the *Seatbelt* layer
does not obstruct egress. It does **not** prove the darwin-net datapath carries
it. Do not read (a) as discharging the "no darwin-net work" claim.

## Non-fatal residual denials (adopted set, recorded for completeness)

`file-issue-extension target:/`, `file-read-data <home>/.CFUserTextEncoding`,
`file-read-metadata /private/var/db/timezone/zoneinfo`, `file-read-metadata`
on `DARWIN_USER_CACHE_DIR`, `/Users`, `<home>`, `mach-lookup
com.apple.CoreServices.coreservicesd`, `mach-lookup
com.apple.DiskArbitration.diskarbitrationd`, `mach-lookup com.apple.tccd.system`,
`mach-lookup com.apple.windowserver.active`. **All left denied.** Every one is a
probe whose failure MLX and CPython tolerate; none was widened.

## What W4's builder must do differently

1. **Encode the two exact user-client class names.** Not R22's
   `"AGXAcceleratorG"` prefix — it does not match. Not a per-family table — it
   cannot be expressed on this filter axis.
2. **Emit no `mach-lookup`, no `iokit-get-properties`, no CVMS read, no
   shader-cache write.** Each was measured unnecessary.
3. **`limitations.md` gets no cross-pod shader-cache disclosure** — there is no
   such channel. It should instead record that the Metal allow-set is a
   *fixed two-class ceiling*, family-independent, with `sandbox_gpu_supported`'s
   functional probe as the only family gate.
4. **The pod's cwd must be inside its data volume.** A pod whose cwd is a denied
   path dies in `import rich` on `os.getcwd()` → `PermissionError`, long before
   any GPU rule matters. Cost one debugging cycle here; it will cost M8.4 one too
   if `mlx-serve`'s entrypoint does not chdir.
5. **The lab rig is an M1 Ultra, not an M1 Max** — correct the M8.0 ledger row.
