# mlx-serve — the k3sm MLX serving image

`ghcr.io/k3sm-io/mlx-serve` is the runtime image behind `MLXModel`: an
OpenAI-compatible MLX inference server that runs as a native Darwin process on
Apple silicon.

The image is `FROM scratch` and COPY-only. It holds a
[python-build-standalone](https://github.com/astral-sh/python-build-standalone)
CPython dist plus the serving engine's wheel closure, and nothing else — no
shell, no package manager, and **no model weights**. Weights are a volume
concern: `HF_HOME` points at `/models`, which the operator mounts.

| | |
|---|---|
| engine | `vllm-mlx==0.5.0` (Apache-2.0), pinned in `requirements.in` |
| interpreter | CPython 3.12.14, python-build-standalone, macos-aarch64 |
| entrypoint | `/bin/python3.12 -m k3sm_serve serve --continuous-batching --host 0.0.0.0 --port 8000` (the engine's own CLI, run in-process with the context guard below) |
| args | the model — a repo id or a path under `/models` — supplied by the pod |
| port | 8000; readiness at `GET /health`, which reports `model_loaded` |
| platform | `darwin/arm64` only |

`--continuous-batching` is part of the image, not a tuning knob. At the engine's
defaults it serves one request at a time and answers **HTTP 503** to every other
concurrent client, while `/health` stays green and a readiness probe stays
green — so nothing else catches it. Measurements:
[`hack/spike/m8/findings-s5.md`](../../spike/m8/findings-s5.md).

## Context length

The engine has no `--max-model-len` and checks no prompt length. Its only
per-sequence bound is `--max-kv-size`, which k3sm renders from the model's
derived context and which selects a rotating KV cache: a sequence that outgrows
it loses its first tokens, and the engine answers HTTP 200 with text built on
the context it has left. `k3sm_serve` closes that gap the way vLLM enforces
`max_model_len`. It runs `vllm_mlx.cli` in the same process with the same
arguments, after hooking the server so that, on `/v1/completions`,
`/v1/chat/completions`, `/v1/messages` and `/v1/responses` (streaming or not),
a request is checked before a response starts. With the window W taken from
the engine's `--max-kv-size` (the last one in argv wins, as it does for the
cache) and the prompt counted with the model's tokenizer after the chat
template:

- a prompt of W tokens or more is refused;
- a prompt plus a client `max_tokens` over W is refused;
- an omitted `max_tokens` runs as the rest of the window.

A refusal is HTTP 400 with vLLM's error object
(`{"error": {"message": "This model's maximum context length is W tokens. ...",
"type": "BadRequestError", "param": null, "code": 400}}`). The guard hooks
engine functions by name and the process exits at start if one has moved, so
an engine bump fails loudly rather than serving unguarded; selftest rung 9
checks the hooks against a staged tree. Image and audio tokens a multimodal
processor adds after the template are not counted.

`k3sm_serve` also patches the prefill mask of mlx-lm's `RotatingKVCache`. The
cache keeps its first four tokens as attention sinks, but mlx-lm 0.32.0 builds
the multi-token mask as a plain sliding window, so after a chunked prefill
trims the cache the sinks are masked out and recall inside the window drops
while decode looks fine. The patched mask keeps the sinks attended and the
recent band at the window minus the sinks, as proposed upstream in
[ml-explore/mlx-lm#1978](https://github.com/ml-explore/mlx-lm/pull/1978). In
this image the cache with sinks is the one the multimodal scheduler builds; the
text scheduler's caches have none, and their mask is unchanged.

Before the engine starts, `k3sm_serve` clamps `--max-kv-size` to the model's
KV geometry. k3sm sizes W from a fixed 157286 bytes of KV cache per token
(`kvBytesPerToken` in `pkg/mlx/sizing.go`, measured on a 3B model), because the
model's `config.json` is only on disk inside the pod. The real fp16 cost is
4 x `num_hidden_layers` x `num_key_value_heads` x `head_dim` bytes per token
(262144 for Qwen2.5-32B, 327680 for Llama-3.3-70B), so `k3sm_serve` reads
`config.json` (from a local model directory, or only that file from the Hub
into the cache the weight download then reuses; a nested `text_config` wins)
and, when the real cost is higher, lowers W to W x 157286 / cost, never below
1024, logging one line. A config it cannot read leaves W as given. The assumed
figure is `K3SM_KV_BYTES_PER_TOKEN`, `K3SM_MODEL_CONFIG_DIR` names a directory
to read `config.json` from instead, and `K3SM_KV_GEOMETRY_CLAMP=off` disables
the clamp. Selftest rung 8 checks it against fake configs.

A pinned revision reaches the engine as its snapshot path in the cache volume,
`<HF_HOME>/hub/models--<org>--<name>/snapshots/<revision>`, because the engine
has no revision option, and the engine only loads that path. So before the
clamp, `k3sm_serve` reads the repository and revision back out of the path and
fetches that revision into the same hub cache with
`huggingface_hub.snapshot_download`, on every start: a complete snapshot moves
no weights, and a half-written one is finished. A failed fetch serves the
snapshot if the volume already holds it, and otherwise exits 2 naming the
revision; a revision the Hub resolves to another commit (a branch or tag name)
exits 2 too. A model reference that is not such a path is left to the engine.
`TestRenderSeedsPinnedRevision` in `pkg/mlx` runs the rendered argv through it.

## Files

| file | what it is |
|---|---|
| `build.sh` | stages the tree with uv and packages it with `k3sm build` |
| `stage-job.sh` | runs the stage step as a native Job on the cluster |
| `requirements.in` | the engine pin — the only direct requirement |
| `requirements.lock` | the resolved closure, one hash per artifact; do not hand-edit |
| `walk-verify.sh` | asserts every Mach-O in the payload is validly signed |
| `k3sm_serve.py` | the single-node entrypoint: the engine's CLI plus the context guard (above) |
| `k3sm_shard.py` | the entrypoint of one rank of a sharded `MLXModel` (see below) |
| `selftest.sh` | the checks that do not need a build (see below) |

## Sharded models

A sharded `MLXModel` (one that sets `spec.distributed`) runs one Pod per rank,
and every rank runs this same image with a different command:

```
/bin/python3.12 -m k3sm_shard --model <ref> --served-model-name <spec.model> [spec.runtime.args...]
```

The sharded engine is **`mlx-lm`'s server** (`mlx_lm.server`), which the
engine closure already carries. **`vllm-mlx` is not used for sharded models**: it
has no multi-node support, so the image's `ENTRYPOINT` stays the single-node
server and only the operator's sharded render overrides the command. A sharded
model is one logical replica; rank 0 alone serves HTTP.

`k3sm_shard` does name resolution, then runs the engine in its own process. It reads the
environment the operator renders (`MLX_RANK`, `MLX_WORLD_SIZE`,
`MLX_METAL_FAST_SYNCH`, `K3SM_MLX_BACKEND`, `K3SM_MLX_PARALLELISM`,
`K3SM_MLX_RANKS`, `K3SM_MLX_PORT`, `K3SM_MLX_SERVE_PORT`, for `jaccl`
`K3SM_MLX_IBV_DEVICES_JSON`, and on the Thunderbolt path `K3SM_MLX_HOSTS`). On
the network path it resolves every rank's per-pod name under the model's
headless Service (retrying, bounded), taking its own address from
`K3SM_POD_IP` when the runtime set it. On the Thunderbolt path nothing is
resolved: `K3SM_MLX_HOSTS` already names every rank's interconnect address and
port in rank order, and the rank refuses to start unless its own entry is
`K3SM_INTERCONNECT_IP`, the address the runtime attached to it. Either way it
writes MLX's rendezvous file into the pod data volume (`$TMPDIR`, the one
writable path under the pod's sandbox profile):

| backend | file | also set |
|---|---|---|
| `ring` | `MLX_HOSTFILE`: `[["<podIP>:<port>"], ...]`, one entry per rank | |
| `jaccl` | `MLX_IBV_DEVICES`: the per-rank RDMA device matrix, `null` for self | `MLX_JACCL_COORDINATOR=<rank 0 podIP>:<port>` |

It then runs `mlx_lm.server --host 0.0.0.0 --port <serve port>` in the same
process, adding `--pipeline` for pipeline parallelism, with its own arguments
last.

`mlx_lm.server` has no `--served-model-name`, so `k3sm_shard` takes that option
itself and does not pass it on. Without it a pinned model, whose `--model` is
the snapshot path in the cache volume, would list that path on `/v1/models`,
and a request naming `spec.model` would make every rank load the model again
from the Hub cache. With it, `/v1/models` lists `spec.model` alone and a request
naming `spec.model` is served by the model already loaded. This hooks four
`mlx_lm.server` internals (`ModelProvider.load`,
`APIHandler.handle_models_request`, `run` and `_run_http_server`). The rank
checks each one against the shape mlx-lm 0.32.0 gives it and exits, naming the
hook, if one is missing or has changed. The selftest checks the same hooks on a
staged tree.

`k3sm_shard --probe` is the rank-0 liveness probe: a one-token completion
against the local server every 60 seconds, to catch a collective that hung
while the listener stayed up. A server that is not listening yet passes, so a
long first download is never killed. The probe costs one forward pass of the
whole sharded model per minute; that cost is measured on the lab Macs beside
the serving figure.

Rank ports are unauthenticated and reachable by every pod in the cluster, so
sharded serving is for trusted tenants only.

## Build

The build runs on k3sm. The stage step (fetch the pinned interpreter and the
hash-pinned closure, precompile) runs as a native Job on the cluster, and the
host only packages the staged tree and pushes it, as the operator's own user:

```sh
# 1. stage on the cluster, onto a local volume of the named node
hack/images/mlx-serve/stage-job.sh apply --node <node>

# 2. on that node, package the volume's stage (no uv, no network)
CGO_ENABLED=1 go build -o /tmp/k3sm ./cmd/k3sm
K3SM_BIN=/tmp/k3sm hack/images/mlx-serve/build.sh \
    --from-stage "$(hack/images/mlx-serve/stage-job.sh path)"
```

`stage-job.sh render --node <node>` prints the manifests without applying them:
a Namespace (`mlx-serve-build`), a `local-path` claim for the stage, a ConfigMap
carrying `build.sh`, `requirements.lock`, `k3sm_shard.py` and `k3sm_serve.py`
verbatim, and the Job. The Job's pod is a native pod that:

- checks the ConfigMap's `requirements.lock` against the sha256 rendered into
  the Job;
- downloads uv at the exact version that generated the lockfile and checks it
  against the sha256 its release publishes, failing closed on a mismatch;
- runs `build.sh --stage-only`, which is every check and step below up to the
  context ceiling, into the claim.

It carries **no credential**: no Secret, no service-account token, no pull
secret. The registry credential never leaves the operator's user on the host.
The node is chosen with a `nodeSelector`, so the scheduler places the pod and
binds the claim (a `WaitForFirstConsumer` claim stays `Pending` under a
`nodeName` pod). The staged tree lands at
`/var/lib/k3sm/storage/<namespace>/<claim>/stage` on that node, owned by the
runtime user and readable by the operator.

`build.sh --from-stage` refuses a stage that was not made from the checkout's
pins (it compares the stamp the stage step writes beside the tree), that lacks
the interpreter, whose entrypoint modules differ from the checkout's, or that holds
a file the packaging user cannot read. Then it packages and walk-verifies as
below.

### Building on the host

Staging on the host is the fallback. It needs a Mac on Apple silicon, in a
**native arm64 shell** (a Rosetta-translated shell would stage x86_64 wheels
into an arm64 image, so the script refuses one), with
[uv](https://docs.astral.sh/uv/), `python3`, and a `k3sm` binary.

```sh
CGO_ENABLED=1 go build -o /tmp/k3sm ./cmd/k3sm
K3SM_BIN=/tmp/k3sm hack/images/mlx-serve/build.sh
```

It runs as your own user with no `sudo`: it packages with
`k3sm build --no-record`, which writes the OCI layout and never records the image
in this node's image store (recording needs root, because it goes through the
runtime daemon's socket). To run the image on the build Mac, tar the layout and
import it as a separate root step:

```sh
tar -cf ~/.cache/k3sm/mlx-serve/oci.tar -C ~/.cache/k3sm/mlx-serve/oci .
sudo k3sm image import ~/.cache/k3sm/mlx-serve/oci.tar
```

It stages into `~/.cache/k3sm/mlx-serve` (override with `K3SM_MLX_WORK`, or
`--stage` / `--output` individually), and re-running is cheap: the staged tree is
reused unless the lockfile or the interpreter pin changed, or `--restage` is
given. Expect roughly 1.3 GB unpacked and a couple of minutes on a cold cache.

What the script does, on either path, and why each step is there:

1. **Refuses a lockfile that is not fully pinned** — every requirement must be an
   exact `==` with at least one hash, and no direct (`git+`) URL, which cannot
   carry a hash at all. Checked before the network is touched.
2. **Installs the pinned interpreter and asserts the artifact URL.** The uv
   version key alone is not a pin: a later uv ships a newer
   python-build-standalone build of the same CPython patch release. `build.sh`
   compares uv's resolved URL against `PY_URL` and stops if they differ. The
   listing is parsed by the interpreter just installed, run with `-I -B` so it
   leaves no bytecode in the tree it is about to stage.
3. **Stages the resolved versioned directory.** uv keeps a version-alias symlink
   beside the dist whose target is an absolute path; the builder accepts
   relative, resolvable, in-context symlinks and nothing else, so the alias is
   never staged. The script also names any absolute or dangling symlink in the
   tree itself, because the builder's own error names only the context root.
4. **Removes the `EXTERNALLY-MANAGED` marker** uv stamps on its interpreters,
   rather than defeating it with `--break-system-packages`, which would also
   silence a genuine misconfiguration.
5. **Installs the closure with `--require-hashes`.**
6. **Precompiles bytecode** (`unchecked-hash`, with in-image source paths).
   Without it every pod writes its own `__pycache__` into its copy-on-write
   clone of the rootfs — breaking sharing for exactly the model-architecture
   modules the lockfile could not know would be imported. It runs serially:
   a parallel `compileall` needs a POSIX semaphore, which a pod's sandbox
   refuses. The build then fails if more than five modules have no `.pyc`, on
   both paths, so a precompile that did not run cannot pass quietly.
7. **Checks the staged tree against the builder's 2 GiB context ceiling**, which
   binds well before any image-size budget does.
8. **Writes the Dockerfile outside the context** (`COPY . /` would otherwise
   absorb it) and runs `k3sm build --no-record --format oci`.
9. **Runs `walk-verify.sh`** on the result, unless `--no-verify`.

## Verify

```sh
hack/images/mlx-serve/walk-verify.sh --layout ~/.cache/k3sm/mlx-serve/oci
```

It verifies every blob against the digest that names it, checks that each
layer's declared media type matches the bytes it actually holds, unpacks the
payload, finds every Mach-O by reading its magic in a single pass, and verifies
each one **per architecture**. Exit 1 on any invalid signature.

Per-architecture matters: universal wheels ship a valid arm64 slice and an
unsigned x86_64 slice, and a whole-file `codesign -v` calls those "not signed at
all". The foreign slice never executes on a darwin/arm64 pod, so verifying it
would fail a perfectly good file — and re-signing it would break the
copy-on-write sharing the runtime depends on. Evidence:
[`hack/spike/m8/findings-s2.md`](../../spike/m8/findings-s2.md).

## Publish

Push the layout with the registry token from the environment, as your own user:

```sh
K3SM_REGISTRY_TOKEN=<ghcr-token> \
  k3sm image push ~/.cache/k3sm/mlx-serve/oci ghcr.io/k3sm-io/mlx-serve:0.5.0-k3sm.2
```

The credential is read from the environment or the docker config chain — never
from argv — and is not stored. `push` prints the digest and the pin:

```
pushed ghcr.io/k3sm-io/mlx-serve:0.5.0-k3sm.2
  digest: sha256:…
  pin:    ghcr.io/k3sm-io/mlx-serve@sha256:…
```

The tag is the engine version, with a `-k3sm.N` suffix when k3sm rebuilds the same engine with changes of its own (the context-length guard is `0.5.0-k3sm.1`; the attention-sink mask fix and the guard on `/v1/messages` and `/v1/responses` are `0.5.0-k3sm.2`), so a tag never changes what it names.

Record that pin. The operator resolves the image **by digest**; the tag is
display-only and the next push moves it.

## Selftest

```sh
hack/images/mlx-serve/selftest.sh
```

Runs in seconds on any Mac and needs neither uv nor a `k3sm` binary: it checks
that the scripts are shellcheck-clean, that `build.sh` packages with
`k3sm build --no-record --output`, that the emitted Dockerfile is COPY-only
and carries the serving argv, that the lockfile is exactly pinned with a hash
per artifact, that `build.sh` refuses a lockfile that is not and refuses to run
without uv, and that `walk-verify.sh` goes red on an invalid signature, on a
mislabelled layer, on a blob that does not match its digest, and on a
non-Mach-O entrypoint. It checks the stage Job `stage-job.sh` renders (the uv
version and sha256, the lockfile digest, the files carried verbatim, no
credential, the placement and toleration) and that its entry script stops on a
digest mismatch before downloading anything, and it drives
`build.sh --from-stage` against a fake stage and a fake `k3sm`, including every
refusal. It also drives `k3sm_shard` with fake name resolution
(no model, no GPU): the ring hostfile and the `jaccl` device matrix land in the
pod data volume, resolution retries and gives up on time, and the liveness
probe answers correctly. It drives the `k3sm_serve` context guard against
fakes, the `--max-kv-size` clamp against fake `config.json` files, and, when a staged tree exists (`K3SM_MLX_STAGE`, default the build's
work dir), against the real engine's HTTP app, and checks the attention-sink
mask on the real mlx-lm cache. It prints what it does **not** cover; the stage Job on a cluster, the live build,
the real payload walk, the push, and a sharded model on two Macs are the lab
run.

## Regenerating the lockfile

Change `requirements.in`, then regenerate in the same commit — on a Mac,
**natively**:

```sh
uv python install cpython-3.12.14-macos-aarch64-none
uv pip compile --generate-hashes --no-header \
    --exclude-newer "$(date -u -v-14d +%Y-%m-%dT00:00:00Z)" \
    --python "${UV_PYTHON_INSTALL_DIR:-$HOME/.local/share/uv/python}/cpython-3.12.14-macos-aarch64-none/bin/python3.12" \
    requirements.in -o requirements.lock
```

`--exclude-newer` is the 14-day dependency cooldown: the resolver ignores every
artifact uploaded after midnight UTC 14 days before the run, so a version
published inside the cooldown never enters the closure. The current lockfile
was compiled with `--exclude-newer 2026-10-04T00:00:00Z`.

Keep the comment header at the top of `requirements.lock` (it records the uv
version, the interpreter the closure was resolved against, and the upload
cutoff) and update its generated-on and cutoff lines.

Do **not** pass `--python-platform macos`: it defaults to macOS 13.0, for which
no `mlx` wheel exists — mlx ships `macosx_14_0_arm64` and newer — so the
lockfile comes out unsatisfiable.

Then re-run `selftest.sh`, rebuild, and re-run `walk-verify.sh`: a new closure
can add Mach-Os, and the image size and the signing verdict are both properties
of the payload, not of the recipe.

## Bumping the interpreter

Edit `PY_KEY` **and** `PY_URL` in `build.sh` together — the URL is what actually
pins the build — then `--restage`, rebuild, and regenerate the lockfile against
the new interpreter.

## Limits

- The interpreter is pinned by artifact URL, not by a checksum in this repo; uv
  verifies the archive it downloads against its own manifest.
- Two builds of the same context on the same machine produce the same digest.
  That has not been shown to hold across Go toolchain versions, so do not treat
  a digest as reproducible across build hosts.
- The staged tree depends on where it was staged, so a stage made by the Job and
  one made on the host package to different digests. uv writes the stage's
  absolute interpreter path into the console-script shebangs under `bin/` and
  their `RECORD` entries, the interpreter's install directory into
  `libpython3.12.dylib` and its sysconfig data, and the handful of modules the
  staging interpreter imports carry timestamp `.pyc` files. The file set is the
  same; the image runs its entrypoint through `-m`, never a `bin/` script.
- `selftest.sh`'s invalid-signature fixture is an *unsigned* hand-written Mach-O.
  A signed-then-tampered binary is rejected for a different reason; only the
  live payload walk exercises that.
- Pruning the payload (the engine's base dependencies include a vision/audio/UI
  surface a text-only server never executes) has not been tested and must not be
  assumed to work.
