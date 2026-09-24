# S1 findings — the Darwin build and an infrastructure-free smoke (M16.0-d2)

> **Status: RUN 2026-09-24** on the M16 rig named under Rig, at the plan's default
> pins (upstream `ref=main`). s1.1 to s1.3 and the frontend `--help` hold; the
> infrastructure-free smoke fails on a harness defect, not on the darwin build, so the
> binding halt (a `nixl-sys` link failure) does NOT apply: `nixl-sys` and the memory
> crate built. An earlier attempt the same day failed s1.4 `--help` because the smoke
> resolved the top-level package from the index, whose runtime has no darwin wheel;
> that is fixed in the script that produced this run. Re-running the script overwrites
> rig state under `$PREFIX`; it does not rewrite this file.

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
| s1.3 wheel sha256; extension signature state | RECORDED | `ai_dynamo_runtime-1.6.0-cp310-abi3-macosx_11_0_arm64.whl` sha256 `8c99585d323f26fbb7a84283702ae286d899d66e38db5c35788231268d9631ec`; `dynamo/_core.abi3.so` arrives `adhoc,linker-signed` (flags 0x20002), which is what `hack/images/*/walk-verify.sh` assumes |
| s1.4 `dynamo.frontend --help` | PASS | answers from the top-level package installed from the clone against the locally built wheel |
| s1.4 frontend + mocker, file discovery, one completion | FAIL (harness) | neither process started: the frontend rejected `--discovery-path` as an unknown argument, and the mocker rejected `--model` as ambiguous (`--model-path`, `--model-name`). At this commit both take `--discovery-backend file` but not the rung's path flag, so the smoke's invocation has drifted from upstream. No completion was attempted |

## Pins this rung sets

| pin | value |
|---|---|
| upstream commit (R2 promotes it to the first tag containing it) | `2be370d1510979953e7447796ffafc3f87fed3a0` |
| chart version built from that commit | not built by this rung (S2 installs the chart) |
| runtime wheel sha256 (a **reproducibility record**, not provenance) | `8c99585d323f26fbb7a84283702ae286d899d66e38db5c35788231268d9631ec` (see Findings: not stable across rebuilds) |
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
- **The smoke's invocation has drifted from upstream.** At this commit the frontend
  takes no `--discovery-path`, and the mocker's `--model` is an ambiguous prefix. The
  file-discovery smoke cannot run until the rung's flags match the checkout; that is a
  harness fix, and the infrastructure-free question stays open until it lands.
