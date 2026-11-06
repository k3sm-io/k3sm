# llama.cpp under the GPU sandbox profile: findings

Run on 2026-11-06 against two Macs, called here the server (M1-family, macOS
27.0) and the worker (M2-family, macOS 27.0), both joined to one cluster. A
hand-delivered `llama-server` was run as a pod under the shipped profile, and
under variants of that profile started with `sandbox-exec` as the same
unprivileged user the pods run as, because a pod cannot be given a variant
profile. The part of this that needs no cluster is reproduced by
`hack/acceptance/llamacpp-measure.sh --measure`; what it does not reproduce is
listed at the end.

## Verdict

- Metal works under the shipped stanza, unchanged. The engine puts all 29 of 29
  layers on the GPU and answers completions on both machines.
- Of the two `iokit-open` classes, `AGXDeviceUserClient` is required and
  `IOSurfaceRootUserClient` is not, for this engine.
- None of the four candidate additions changes anything.
- The denied `mach-lookup`s are non-fatal. The engine does nothing different
  because of them.
- The shipped GPU grant is unchanged by this work, so no widening is proposed.
- Two results that were not expected: a Metal out-of-memory arrives as an HTTP
  500 from a running server rather than as a load failure, and the Go verifier
  succeeded against the Hub under the profile.

## Method

- **Engine.** `llama-server`, built from the pinned commit below with the
  embedded Metal library, one request at a time, bound to loopback.
- **Model.** The pinned GGUF below, for every run. Prompt: one short user turn
  asking for three primary colours, 16 completion tokens.
- **Profile.** The profile the node renders for a GPU pod, taken from a running
  holder pod. Each variant is that text with one rule removed or one rule added
  at the end, the unmodified text run twice as a control. The edit tool refuses a
  removal that matches nothing, so "not required" is never recorded for a
  rule that was not removed.
- **Denials.** Read from the system log by engine process id, both the sandbox
  reports and the launchd lookup refusals, after each run.
- **Memory.** `proc_pid_rusage` `ri_phys_footprint` beside the resident size,
  sampled every 100 ms, the same figure a memory limit is judged on.
- **Throughput.** Each completion is 16 tokens, so tokens per second varies
  from about 49 to about 190 between runs of the same profile on the server.
  Nothing below is read from those figures.

## Pins

| | |
|---|---|
| Release tag | `b11829`, a pre-release, published 2026-10-22 |
| Commit | `184f6536024668e8908ab8c86033d56708e62b40` (the tag resolves to it; the commit shows as verified) |
| Age when pinned | 14 days 6 hours, past a 14-day cooldown |
| Model | `unsloth/Qwen3-0.6B-GGUF`, file `Qwen3-0.6B-Q4_K_M.gguf` |
| Model revision | `50968a4468ef4233ed78cd7c3de230dd1d61a56b` |
| Model sha256 | `ac2d97712095a558e31573f62f466a3f9d93990898b0ec79d7c974c1780d524a` |
| Model size | 396,705,472 bytes (378 MiB), Apache-2.0, not gated, `qwen3`, context length 40960, carries a chat template |
| Toolchain | Apple clang 21.0.0, cmake 3.28.1, SDK 27.0, deployment target 26.0 |
| Configure options | Release, `GGML_METAL=ON`, `GGML_METAL_EMBED_LIBRARY=ON`, `BUILD_SHARED_LIBS=OFF`, `GGML_BACKEND_DL=OFF`, `GGML_NATIVE=OFF`, `LLAMA_CURL=OFF`, `LLAMA_OPENSSL=OFF`, tests and examples off, tools and server on, `FETCHCONTENT_FULLY_DISCONNECTED=ON` |

The Hub's redirect for the pinned file carried `x-linked-etag` equal to the
sha256 above and `x-repo-commit` equal to the revision.

## The seventeen questions

### 1. Does Metal initialise, compile and offload under the two-rule grant? Is each rule required?

- **Expected.** Unknown. The profile's Metal rules were measured for a different
  engine's precompiled library and JIT, not for the embedded-source path.
- **Measured.**
  - Shipped profile, both machines: the device is listed, the engine reports
    `offloaded 29/29 layers to GPU`, becomes ready in 5 to 8 seconds and
    answers with HTTP 200 and the expected text.
  - Without `AGXDeviceUserClient`, with `IOSurfaceRootUserClient` kept: the
    device list is empty, the engine logs `failed to create command queue` and
    exits. Both machines.
  - Without `IOSurfaceRootUserClient`, with `AGXDeviceUserClient` kept: ready,
    29/29 layers, HTTP 200, no difference. Both machines.
  - Without the whole `iokit-open` stanza: identical to the first removal.
  - Removing the network-bind, POSIX-semaphore and mDNS rules, and adding a
    write-deny over the pod's own directories, each left the engine serving.
  - The four candidate additions (below, question 2) each left it serving with
    no change in layers or output.
- **How.** One variant per run, the control run twice, `--list-devices` run
  first under each variant as its own process, then a served completion.
- **Inferred.** Removing network-bind changed nothing most likely because the
  profile also allows network-inbound and network-outbound; this was not tested
  by removing those.
- **Shipping note.** `IOSurfaceRootUserClient` not being needed here is a
  record, not a proposal. Removing it from the shipped stanza would affect the
  other engine that stanza was measured for, and is a separate decision.

The rendered profile was compared with the golden profile with `diff`. No hunk
touches the `iokit-open` stanza; every difference is pod-specific (paths,
network allowances, the DNS lookups, the semaphore prefix, socket denials). So
the shipped stanza is identical to the golden's, as read from that diff.

### 2. What is the full denial list over cold load, first token, second slot and idle? Does any stop or degrade the engine?

- **Expected.** Possibly a refused `sem_open`-style call that a partial grant
  would hide.
- **Measured.** In a real pod on each machine the denials were four lookups,
  all at cold load, none afterwards:
  - `com.apple.CoreServices.coreservicesd`
  - `com.apple.DiskArbitration.diskarbitrationd`
  - `com.apple.tccd.system`
  - `com.apple.windowserver.active`

  No denial appeared at first token, with a second concurrent request, or while
  idle. Across 46 engine processes on the server and 49 on the worker in the
  variant runs, the same four names were the only lookups refused. The sandbox
  reported a subset of them in any one run (zero to two names per run). Two
  other single reports: a `file-read-metadata` on the per-user cache directory
  on the worker, and `system-info vfs.disk-space` on the server with mapping
  turned off.
  - No semaphore denial was seen under the shipped profile, and removing the
    semaphore rule changed nothing.
  - In every run with these denials the engine answered correctly and its log
    shows no error line tied to them.
  - Idle: the pod stayed up and `/health` stayed 200 for the 11.5 minutes
    (server) and 12.8 minutes (worker) the pod had been running when sampled,
    footprint unchanged at about 985 to 990 MiB.
- **Candidate additions, one at a time:** `iokit-get-properties`, the
  `MTLCompilerService` `mach-lookup`, a read of the `CVMS` directory, and read
  plus write on the per-user shader cache directory. Each: ready, 29/29 layers,
  HTTP 200, no change in the denials beyond the list above.
- **How.** Real pods with the log read per phase by timestamp, plus every
  `sandbox-exec` run summarised by process id.
- **Inferred.** The "idle" phase is the time between the first completion and
  the sample, about ten minutes; it was not timed separately.

### 3. Does `cmake` plus `clang++` work in a confined stage job, on a Command Line Tools node and on full Xcode?

- **Expected.** Unknown.
- **Measured.**
  - Command Line Tools (worker), confined: the package-manager `cmake` cannot
    be executed in place (`Operation not permitted`, exit 126). A copy placed
    inside the working directory runs. `clang++` runs. `xcrun` prints errors
    that it cannot create its cache file and still resolves the SDK. Configure
    2 s, build 139 s with 4 jobs, binary produced.
  - Full Xcode (server), confined: configure 42 s, build 196 s, binary produced.
    `xcodebuild` prints file-event-stream warnings that do not affect the result.
  - Unconfined on the server, 16 jobs: build 48 s.
  - The three binaries have three different sha256 values. A pin has to be on
    the source, not on the binary.
- **How.** A job in each node's confined environment with the working directory
  on the pod volume.

### 4. How do weights count in `ri_phys_footprint`, mapped versus not, and what happens at the limit?

- **Expected.** A mapped file is not counted.
- **Measured.** Footprint at ready, context 4096, one slot:

  | Weights | Server footprint | Server resident | Worker footprint |
  |---|---|---|---|
  | mapped (default, or `-lm mmap`) | 520 MiB | 945 MiB | 517 to 531 MiB |
  | not mapped (`-lm none`) | 1166 MiB | 1012 MiB | 1156 MiB |

  The mapped file is in the resident size and not in the footprint. Without
  mapping the footprint is about 650 MiB higher, more than the 378 MiB file;
  the extra was not traced.
- **At a limit,** as a pod with a memory limit (the node enforces the limit by
  sampling the footprint and killing, so a kill is not instant):

  | Limit | Arguments | Server | Worker |
  |---|---|---|---|
  | 800 Mi | context 4096, not mapped | OOMKilled (exit 137) before ready | answered one request, then OOMKilled |
  | 800 Mi | context 4096, mapped | running, answered, 523 MiB | running, answered, 518 MiB |
  | 600 Mi | context 4096 | running, answered, 520 MiB | running, answered, 518 MiB |
  | 500 Mi | context 4096 | OOMKilled before ready | OOMKilled before ready |
  | 2 Gi | context 32768 | OOMKilled | answered one request, then OOMKilled |
  | 2 Gi | context 8192, two slots, not mapped | not run | running, answered, 1607 MiB |

  For this model at context 4096 the working limit sits between 500 and 600 MiB.
- **How.** The sampler in `hack/spike/m25/sampler.c`, then pods with limits and
  the pod's state and events read after each.

### 5. Is KV allocated up front? Is `--ctx-size` a total or per slot?

- **Expected.** Up front, and a total.
- **Measured.** Footprint at ready is 126 MiB at context 512, 520 MiB at 4096 and
  3678 MiB at 32768 (server; the worker is within 15 MiB of each), and does not
  grow by more than 4 MiB over two completions on the server (up to 21 MiB on the
  worker, with mapped weights). So the KV is allocated at load.
  `-c 4096 -np 2` logs `n_ctx_slot = 2048`, and `-c 8192 -np 2` logs
  `n_ctx_slot = 4096`: the context is a total, divided among the slots. Footprint
  with two slots equals that with one. With no `-c`, the context comes from the
  model (40960) and the footprint is 4.5 GiB on the server and 3.9 GiB on the
  worker. With no `--parallel`, the engine picks 4 slots with a unified KV
  cache.
- **How.** The footprint sampler across load and two completions; the engine's
  own log for slot size.

### 6. What does no GPU do: exit or CPU? Which flag refuses?

- **Expected.** Exit, with a flag that selects CPU.
- **Measured.** With the GPU grant removed (a stand-in for no GPU):
  - `--list-devices` returns exit 0 and an empty `Available devices:` list.
  - The engine exits with status 1 (`failed to create command queue`) under
    the default flags, `-ngl 99`, `-ngl 0`, `--device MTL0 -ngl 99` and
    `--fit off`. `-ngl 0` does not avoid it.
  - Only `--device none` serves, on CPU: 139 tokens per second on the worker
    and 1.8 on the server. The server figure is far below the worker's and was
    not investigated.
  - A real pod that did not request the GPU resource was rendered a profile with
    no `iokit-open` rule at all and exited with status 1 within a second, with
    the same error.
- **How.** Variant without the stanza, each flag set started in turn; a pod
  without the GPU resource.
- **Not verified.** A machine with no GPU at all; the grant's absence is the
  stand-in.

### 7. The full `--help`, every network- or file-reaching route, classified

- **Expected.** A new golden to commit.
- **Measured.** 264 flags in 740 lines of `--help`, captured from the pinned
  build (the script regenerates it as `help.txt`; it is not committed here).
  - 17 reach the network: `--rpc`, `--model-url`, `--docker-repo`, `--hf-repo`,
    `--hf-file`, `--hf-token`, the speculative-draft Hub flags, `--mmproj-url`,
    `--host`, `--port`, `--reuse-port`, the MCP proxy flag, `--tools`,
    `--tools-runtime`, `--mcp-servers-config`, `--mcp-servers-json`, `--agent`.
  - 23 reach files: model, LoRA and control-vector files, `--log-file`, grammar
    and schema files, lookup caches, `--mmproj`, `--video-ffmpeg-dir`, `--path`,
    the UI config, the API-key, TLS key and certificate files,
    `--slot-save-path`, `--media-path`, `--models-dir`, `--models-preset`,
    `--chat-template-file`, `--log-prompts-dir`.
  - Of 38 spellings checked against a draft deny list, all exist except
    `--spec-draft-hf-repo`; the draft-model Hub flag is spelled `--spec-draft-hf`
    (with `-hfd` and `-hfrd`).
  - HTTP surface: 33 routes. Besides health, models, props, slots and the
    completion endpoints there are `models/load`, `models/unload`, `slots/:id`,
    `cors-proxy`, `tools`, `apply-template`, `lora-adapters` and `props` (POST,
    answered 501 by default).
- **How.** The `--help` text parsed for flag lines and for path and URL
  placeholders.

### 8. With no projector, is a remote `image_url` refused with no outbound request?

- **Expected.** Refused.
- **Measured.** Both a loopback `http://` URL and an `https://` URL return HTTP
  500 with `image input is not supported - hint: if this is unexpected, you may
  need to provide the mmproj`. A listener on the loopback URL received zero
  requests. The status is 500, not a 4xx.
- **How.** A request with an `image_url` part to a server started without
  `--mmproj`; a logging listener as the target.
- **Inferred.** The source fetches `http` URLs when it handles media, so the
  refusal that was observed is the missing projector, ahead of the fetch. A
  server started with a projector was not tried.

### 9. Does a prompt over the window get an error or silent truncation?

- **Expected.** An error.
- **Measured.** At context 512, a prompt of about 2000 tokens returns HTTP 400,
  type `exceed_context_size_error`, naming the prompt tokens (2009 for chat, 2001
  for completion) and the window (512). No truncation. Both machines.
- **How.** One over-length request to each of the chat and completion routes.

### 10. `/health` during load; `/v1/models` under `--alias`; is the file path in `/props`?

- **Expected.** 503 while loading, the alias as the model name, the path shown.
- **Measured.** `/health` is a connection error for the first moments, then 503
  `Loading model` for the 5 to 8 seconds of load, then 200 `{"status":"ok"}`.
  With `--alias`, the model list carries the alias as `name` and `model`.
  `/props` returns `model_path` exactly as given to `-m` (a relative path stays
  relative), `total_slots`, `modalities` (all false here), `build_info`, and the
  chat template. `POST /props` is 501. `/metrics` is 501 unless the flag is set.
  `/slots` is 200 by default and carries slot state.
- **How.** Polling `/health` from process start; a `GET` of each route.

### 11. Concurrency at `parallel` N: do all N succeed?

- **Expected.** All succeed.
- **Measured.** Two concurrent requests with `-np 2`, and four with `-np 4`, all
  return 200 on both machines, and in a pod with two slots. Per-request speed
  falls with the count (about 145 tokens per second each with two, 53 to 86 with
  four on the server).
- **How.** N threads each posting a completion at the same moment.

### 12. What does `-hf` do about TLS, revision and hash under this profile?

- **Expected.** Not known.
- **Measured.**
  - The build without TLS refuses an `https` URL at the first
    request: `HTTPS is not supported`, and exits on a model load error.
  - A second build with TLS (a package-manager OpenSSL, built only for this
    test) under the profile logs `SSL server verification failed` and exits
    the same way. Under the profile it could not verify the Hub's certificate.
  - The source builds the file URL from the repo, the resolved commit and the
    path, and checks a `sha256:<64 hex>` digest when one is given. The default
    revision is the moving `main`, resolved at run time.
- **How.** `-hf` runs under the profile with each build; the relevant source
  read.
- **Inferred.** The failure under the profile is the engine's TLS library not
  reaching the system trust store; not isolated.

### 13. Does Go's default verifier fail under the profile? Is a Hub download a plain `GET`, and what is the LFS metadata route?

- **Expected.** The default verifier fails under the profile.
- **Measured.** It succeeded. A small Go client run as a pod, once with the
  default roots and once with a PEM bundle appended, issued a ranged `GET` on the
  pinned `resolve` URL. The Hub answered a redirect to its CDN host and the CDN
  returned 206 with the first 1024 bytes and the `GGUF` magic. No denials in either pod. The same client rejected a
  certificate from an untrusted root and an expired certificate with the
  expected x509 errors, so verification was real, not skipped.
  - A download is a plain `GET` on `/<repo>/resolve/<revision>/<file>`. The
    revision can be the commit.
  - Metadata: the redirect carries `x-linked-size`, `x-linked-etag` (the file's
    sha256) and `x-repo-commit`; the engine's source reads `lfs.oid` from the
    tree listing for each LFS file (that route was not called here).
- **How.** The client against the real Hub from a pod with the shipped profile;
  two negative controls.
- **Not included.** The Go client itself is not part of this change.

### 14. Which small GGUF: licence, size under 700 MB, a chat template, a commit to pin?

- **Measured.** The model in the pin table: Apache-2.0, 378 MiB, a chat template
  present, a commit to pin, and the digest matched the Hub's own after download.

### 15. Submodules, `FetchContent` or configure-time downloads? What does the configure trace show?

- **Expected.** None.
- **Measured.**
  - The tree has 3881 entries and no gitlinks. `.gitmodules` exists as a
    zero-length file. The tree digest was identical before and after the build.
  - With `FETCHCONTENT_FULLY_DISCONNECTED=ON` there is no `_deps` directory, no
    `FetchContent` or `ExternalProject` call and no `file(DOWNLOAD ...)` in the
    trace of the configure.
  - The configure does run commands: compiler probes (`c++`, `cc`), `sw_vers`,
    `sysctl`, `uname`, `xcode-select`, `xcrun`, and `git` calls inside the
    source tree (version, `describe`, `log`, `rev-parse`, `rev-list`,
    `diff-index`). `git` therefore has to be present in the stage job.
  - In the JSON trace format the command and its arguments are separate fields,
    so a check written as the literal text `file(DOWNLOAD` never matches. The
    working check is: command equals `file` and first argument equals
    `DOWNLOAD`.
- **How.** `cmake --trace-format=json-v1 --trace-expand`, the trace parsed for
  command names; a walk of the source tree before and after the build.

### 16. Does the binary need any entitlement? Is dynamic backend loading off?

- **Expected.** None needed.
- **Measured.** The binary is ad-hoc and linker-signed, no team identifier, and
  `codesign` printed no entitlements. It ran as an unprivileged user under the
  profile with none. It links only system frameworks and libraries
  (Accelerate, Foundation, Metal, MetalKit, CoreFoundation, libc++, libobjc,
  libSystem). `GGML_BACKEND_DL` is `OFF` in the build cache, and the binary links no backend library.
- **Inferred.** "Needs no entitlement" rests on the binary running without one
  and on the empty `codesign` output.

### 17. How much memory does the GGUF need to serve? What are the two ceilings?

- **Measured.**
  - Mapped, context 4096, one slot: about 520 MiB; a pod limit of 600 MiB served,
    500 MiB did not.
  - A pod with context 8192 and two slots: about 990 MiB on each machine.
  - Not mapped: 1.16 GiB at 4096; 1.6 GiB at 8192 with two slots.
  - Context 32768: 3.7 GiB.
  - GPU ceiling (the engine's device list and the node figure agree): 51.84 GiB
    on the server and 5.33 GiB on the worker; the GPU wired limit is at its
    default (0) on both.
  - Metal out-of-memory arrives as a request failure, not a load failure. On
    the worker, context 32768 (3.7 GiB footprint) and the model's own 40960
    (3.9 GiB) load, `/health` is 200, and the first completion returns HTTP 500
    `Compute error.`, with `Insufficient Memory (kIOGPUCommandBufferCallbackErrorOutOfMemory)`
    in the engine's log. The process stays up and answers a second request the
    same way. The same arguments serve on the server. A readiness probe on
    `/health` passes while every request fails.
- **How.** The footprint sampler, pods with limits, and the engine's own device
  report.

## A shader compile at every start

- The engine compiles its embedded shader source at each start under the
  sandbox. Time to ready is 5 to 7 seconds on the server and 7 to 8 on the
  worker. An unsandboxed start on the server was ready in 0.83 s. The worker's
  engine log times one library at 4.4 s.
- Granting read and write on the per-user shader cache directory did not shorten
  it: two consecutive starts took 6.9 s and 6.3 s, and a third under the shipped
  profile 5.6 s.
- **Inferred.** The cost is the runtime shader compile that the sandbox does not
  let cache. Whether the cache was written was not established.

## Denied lookups, in one place

The four refused lookups in question 2 are non-fatal and unchanged by the four
candidate additions. Granting `MTLCompilerService` changed neither the
denial list nor the start time.

## What was not verified

- A machine with no GPU. The grant's absence stands in for one.
- A run with every `deny` set to report-only, to prove the denial list is
  complete. The attempt did not become ready and was not repeated.
- Any macOS release other than 27.0, any chip other than the two here, any model
  other than the pinned one, and any larger quantisation.
- The Command Line Tools path on the server and the full Xcode path on the
  worker.
- Throughput differences between variants (16-token samples are noise).
- A server started with a projector; the `-hf` path to a successful download;
  the Go client against anything but the Hub; the Hub's tree route.
- Idle denials beyond roughly twelve minutes.
- Why unmapped weights add about 650 MiB, and why CPU-only serving is slow on
  the server.

## What the script reproduces

`hack/acceptance/llamacpp-measure.sh --measure` needs `K3SM_LAB=1` and verifies
the pinned commit and model digest first, failing closed on either. It then
reproduces questions 1, 2 (the `sandbox-exec` runs), 4 and 5 (the footprint
columns), 6, 8, 9, 10 and 11, the tree and configure checks of question 15 and
the signing and link checks of question 16, and captures the `--help` for
question 7. It does not reproduce the pod-level memory limits (question 4's
second half), the confined builds (question 3), real-pod denials by phase,
the Go verifier (question 13), `-hf` (question 12), or the machine ceilings
(question 17).
