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
| engine | `vllm-mlx==0.4.1` (Apache-2.0), pinned in `requirements.in` |
| interpreter | CPython 3.12.14, python-build-standalone, macos-aarch64 |
| entrypoint | `/bin/python3.12 -m vllm_mlx.cli serve --continuous-batching --host 0.0.0.0 --port 8000` |
| args | the model — a repo id or a path under `/models` — supplied by the pod |
| port | 8000; readiness at `GET /health`, which reports `model_loaded` |
| platform | `darwin/arm64` only |

`--continuous-batching` is part of the image, not a tuning knob. At the engine's
defaults it serves one request at a time and answers **HTTP 503** to every other
concurrent client, while `/health` stays green and a readiness probe stays
green — so nothing else catches it. Measurements:
[`hack/spike/m8/findings-s5.md`](../../spike/m8/findings-s5.md).

## Files

| file | what it is |
|---|---|
| `build.sh` | stages the tree with uv and packages it with `k3sm build` |
| `requirements.in` | the engine pin — the only direct requirement |
| `requirements.lock` | the resolved closure, one hash per artifact; do not hand-edit |
| `walk-verify.sh` | asserts every Mach-O in the payload is validly signed |
| `selftest.sh` | the checks that do not need a build (see below) |

## Build

Needs a Mac on Apple silicon, in a **native arm64 shell** (a Rosetta-translated
shell would stage x86_64 wheels into an arm64 image, so the script refuses one),
with [uv](https://docs.astral.sh/uv/), `python3`, and a `k3sm` binary.

```sh
CGO_ENABLED=1 go build -o /tmp/k3sm ./cmd/k3sm
K3SM_BIN=/tmp/k3sm hack/images/mlx-serve/build.sh
```

It stages into `~/.cache/k3sm/mlx-serve` (override with `K3SM_MLX_WORK`, or
`--stage` / `--output` individually), and re-running is cheap: the staged tree is
reused unless the lockfile or the interpreter pin changed, or `--restage` is
given. Expect roughly 1.3 GB unpacked and a couple of minutes on a cold cache.

What the script does, and why each step is there:

1. **Refuses a lockfile that is not fully pinned** — every requirement must be an
   exact `==` with at least one hash, and no direct (`git+`) URL, which cannot
   carry a hash at all. Checked before the network is touched.
2. **Installs the pinned interpreter and asserts the artifact URL.** The uv
   version key alone is not a pin: a later uv ships a newer
   python-build-standalone build of the same CPython patch release. `build.sh`
   compares uv's resolved URL against `PY_URL` and stops if they differ.
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
   modules the lockfile could not know would be imported.
7. **Checks the staged tree against the builder's 2 GiB context ceiling**, which
   binds well before any image-size budget does.
8. **Writes the Dockerfile outside the context** (`COPY . /` would otherwise
   absorb it) and runs `k3sm build --format oci`.
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

Publishing is a **human-run lab step**. There is no automated registry workflow
and none is planned before the public release; the image is published from a Mac
by hand, and the digest is recorded.

```sh
K3SM_REGISTRY_TOKEN=<ghcr-token> \
  k3sm image push ~/.cache/k3sm/mlx-serve/oci ghcr.io/k3sm-io/mlx-serve:0.4.1
```

The credential is read from the environment or the docker config chain — never
from argv — and is not stored. `push` prints the digest and the pin:

```
pushed ghcr.io/k3sm-io/mlx-serve:0.4.1
  digest: sha256:…
  pin:    ghcr.io/k3sm-io/mlx-serve@sha256:…
```

Record that pin. The operator resolves the image **by digest**; the tag is
display-only and the next push moves it.

## Selftest

```sh
hack/images/mlx-serve/selftest.sh
```

Runs in seconds on any Mac and needs neither uv nor a `k3sm` binary: it checks
that the scripts are shellcheck-clean, that the emitted Dockerfile is COPY-only
and carries the serving argv, that the lockfile is exactly pinned with a hash
per artifact, that `build.sh` refuses a lockfile that is not and refuses to run
without uv, and that `walk-verify.sh` goes red on an invalid signature, on a
mislabelled layer, on a blob that does not match its digest, and on a
non-Mach-O entrypoint. It prints what it does **not** cover; the live build,
the real payload walk and the push are the lab run.

## Regenerating the lockfile

Change `requirements.in`, then regenerate in the same commit — on a Mac,
**natively**:

```sh
uv python install cpython-3.12.14-macos-aarch64-none
uv pip compile --generate-hashes --no-header \
    --python "${UV_PYTHON_INSTALL_DIR:-$HOME/.local/share/uv/python}/cpython-3.12.14-macos-aarch64-none/bin/python3.12" \
    requirements.in -o requirements.lock
```

Keep the comment header at the top of `requirements.lock` (it records the uv
version and the interpreter the closure was resolved against) and update its
generated-on line.

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
- `selftest.sh`'s invalid-signature fixture is an *unsigned* hand-written Mach-O.
  A signed-then-tampered binary is rejected for a different reason; only the
  live payload walk exercises that.
- Pruning the payload (the engine's base dependencies include a vision/audio/UI
  surface a text-only server never executes) has not been tested and must not be
  assumed to work.
