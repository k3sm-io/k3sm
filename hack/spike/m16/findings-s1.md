# S1 findings — the Darwin build and an infrastructure-free smoke (M16.0-d2)

> **Status: RUN 2026-09-24** on the M16 rig named under Rig, at the plan's default
> pins (upstream `ref=main`), exit 1 (3 passed, 1 failed, 4 recorded). s1.1 to s1.3
> and the frontend `--help` hold, and file discovery connects the frontend to the
> mocker, but the frontend never materializes the mocker's model, so no completion is
> served. The binding halt (a `nixl-sys` link failure) does NOT apply: `nixl-sys` and
> the memory crate built. Two earlier runs the same day stopped on harness defects
> written against an older upstream CLI (the smoke resolved the top-level package from
> the index, whose runtime has no darwin wheel; then it passed a discovery-path flag
> and an ambiguous model flag the resolved commit does not accept); both are fixed in
> the script that produced this run. Re-running the script overwrites rig state under
> `$PREFIX`; it does not rewrite this file.

## Question

Does the upstream serving framework (Apache-2.0) build from source on darwin/arm64
with the CUDA-bearing default features off, and does a frontend plus the in-tree
mocker serve a completion with **no etcd, no NATS and no Kubernetes**? macOS is a
maintained in-tree build target, but there is no published darwin wheel and no macOS
CI, so the memory crate's `nixl-sys` link is the one risk reading cannot settle.

## Method

Rig-side over ssh in the spike prefix: a **pinned** Rust toolchain and maturin; a
clone at the requested ref with the **resolved sha recorded** (that sha is the pin
R2 promotes); a release wheel built from the python bindings; the wheel's sha256 and
the extension's signature state recorded; then `python3 -m dynamo.frontend --help`
and a frontend plus mocker with `--discovery-backend file` answering one completion.

## Halt (binding, substitution pre-decided)

The memory crate / `nixl-sys` does not build on darwin/arm64 → the worker re-plans on
the **Rust backend contract**, which does not pull that crate, **before** any build
wave starts.

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s1.1 toolchain pinned (rustc, maturin, interpreter) | PASS | rustc 1.90.0 (1159e78c4 2025-09-14) is the rustup default; maturin 1.15.0; CPython 3.12.14 (arm64). See Findings: upstream's `rust-toolchain.toml` selected 1.96.1 for the actual build |
| s1.2 build completes; resolved commit recorded | PASS | the python bindings built from source on darwin/arm64 with the CUDA-bearing defaults off, at `2be370d1510979953e7447796ffafc3f87fed3a0` (`v1.4.0-inkling-dev.1-1366-g2be370d15`); `nixl-sys` and the memory crate compiled and linked |
| s1.3 wheel sha256; extension signature state | RECORDED | `ai_dynamo_runtime-1.6.0-cp310-abi3-macosx_11_0_arm64.whl` sha256 `d52f058dcf83973f6cae466a072cae9f67344de5fd575d2f4ced1aa73e36d352`; `dynamo/_core.abi3.so` arrives `adhoc,linker-signed` (flags 0x20002), which is what `hack/images/*/walk-verify.sh` assumes |
| s1.4 `dynamo.frontend --help` | PASS | answers from the top-level package installed from the clone against the locally built wheel |
| s1.4 frontend + mocker, file discovery, one completion | FAIL | both processes started with `--discovery-backend file` and the root in `DYN_FILE_KV`, and the frontend discovered the mocker's `mock-model` endpoint through the file store, but every materialization attempt failed with `chat pipeline requires preprocessed routing` (8 attempts over two minutes), so `/v1/models` never listed the model and no completion was attempted. The mocker was started with `--model-name` only and no `--model-path`, so it offers no tokenizer to preprocess against; that is the likely cause, not established here |

## Pins this rung sets

| pin | value |
|---|---|
| upstream commit (R2 promotes it to the first tag containing it) | `2be370d1510979953e7447796ffafc3f87fed3a0` |
| chart version built from that commit | not built by this rung (S2 installs the chart) |
| runtime wheel sha256 (a **reproducibility record**, not provenance) | `d52f058dcf83973f6cae466a072cae9f67344de5fd575d2f4ced1aa73e36d352` (see Findings: not stable across rebuilds) |
| Rust toolchain / maturin | rustc 1.90.0 asserted, 1.96.1 built (see Findings) / maturin 1.15.0 |

## Rig

| | |
|---|---|
| host | the M16 rig, reached over the harness's ssh path (`K3SM_M16_HOST`) |
| SoC / memory | Apple M2, 8 GiB (Mac14,2) |
| macOS | 26.6.2 |
| date (UTC) | 2026-09-24 |
| cluster | none touched: S1 is infrastructure-free |

## Findings

- **Toolchain pin vs the toolchain that built.** s1.1 asserts that `rustc --version`
  reports the pinned 1.90.0, and it does, as the rustup default. But the upstream
  checkout carries a `rust-toolchain.toml` (`channel = "1.96.1"`), and rustup honours it
  inside the tree: the release build of the bindings ran under rustc 1.96.1. The pin
  check therefore passes against a compiler that did not produce the wheel. Recorded,
  not changed here: whether the pin should follow upstream's file or override it is a
  decision for the image build (M16.3), which asserts the same pin.
- **The wheel is not byte-reproducible across rebuilds.** Two builds of the same
  commit on the same rig the same day produced different sha256s
  (`91116f57007b59fcc1dcfffc6804abc40cbcffa3c419c578b815e91d5fb25e73`, then
  `8c99585d323f26fbb7a84283702ae286d899d66e38db5c35788231268d9631ec`). The sha256 is a
  record of one artifact, not a value a rebuild can be checked against.
- **The final run's wheel differs again.** The build that produced this run's
  scoreboard gave `d52f058dcf83973f6cae466a072cae9f67344de5fd575d2f4ced1aa73e36d352`, a
  third sha256 for the same commit on the same rig.
- **File discovery works; model materialization does not.** At the resolved commit
  the file backend takes its root from `DYN_FILE_KV` (there is no path flag), and with
  it set the frontend found the mocker's endpoint in the store. It then refused to
  build a chat pipeline for the model (`chat pipeline requires preprocessed routing`).
  The infrastructure-free question is therefore half-answered: two processes and a
  directory do discover each other with no etcd and no NATS, but no completion has
  been served. Closing it needs a mocker started with a model path the frontend can
  preprocess against, which is a further change to the smoke and is not made here.
