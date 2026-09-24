# S1 findings — the Darwin build and an infrastructure-free smoke (M16.0-d2)

> **Status: RUN 2026-09-21** on the single-node dev Mac named under Rig, three times
> the same day. The build holds (s1.1–s1.3, s1.4 `--help`); the infrastructure-free
> smoke (s1.4) is **recorded, not passed**: the frontend lists the mocker's model and
> accepts the request, and the completion then waits on the response stream until the
> 30 s client timeout. The dial that fails is a loopback plumbing question on this rig
> (below), not a build question, and the halt's substitution does **not** apply since
> the memory crate linked. Re-running the script overwrites rig state under `$PREFIX`;
> it does not rewrite this file.

> **Rig substitution.** The host named under Rig below is not the sanctioned M16 rig
> (the laptop dev Mac: Apple M2, 8 CPU, 8 GiB): it is an
> outside machine with roughly **8x** that memory budget (Apple M4 Max, 64 GiB), the
> exact constraint the sanctioned rig's second rung exists to exercise. Whether these
> runs stand as recorded on that substitute, or must be re-run on the sanctioned rig
> before acceptance, is a question for the maintainers, not decided here.

> **Sanctioned-rig run at a different pin, 2026-09-24 (recorded separately before this
> file merged).** The maintainers ran the rung on the sanctioned rig at the plan's
> default upstream ref (main, resolved to 2be370d15, v1.4.0-inkling-dev.1-1366), not
> this file's tagged v1.5.0 pin. Exit 1: the toolchain, build and frontend --help
> held (nixl-sys and the memory crate linked, so the binding halt did not apply; the
> build's rust-toolchain.toml selected rustc 1.96.1; wheel 1.6.0, sha256 d52f058dcf83
> 973f6cae466a072cae9f67344de5fd575d2f4ced1aa73e36d352), and file discovery connected
> the frontend to the mocker, but the frontend never materialized the mocker's model,
> so no completion was served. A different pin answers a different question; the two
> records stand side by side.

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
| s1.1 toolchain pinned (rustc, maturin, interpreter) | PASS | rustc 1.90.0 (1159e78c4 2025-09-14), maturin 1.15.0, CPython 3.12.12 (arm64 venv); floor `MATURIN_MIN=1.7.0`; cmake and protobuf from Homebrew |
| s1.2 build completes; resolved commit recorded | PASS | `v1.5.0` resolved to b83b1d9304ebfc624709ac46db32b1b6f1ff1615 (`git describe` = v1.5.0); `maturin build --release` of `lib/bindings/python` linked the memory crate / `nixl-sys` on darwin/arm64 without a patch |
| s1.3 wheel sha256; extension signature state | RECORDED | `ai_dynamo_runtime-1.5.0-cp310-abi3-macosx_11_0_arm64.whl`; three builds from the same sha gave three sha256s (2080b0b2…, 972db793…, 0dc014e9…), so the wheel is a **reproducibility record per build, not a reproducible artifact**; `dynamo/_core.abi3.so` carries a linker ad-hoc signature (`flags=0x20002(adhoc,linker-signed)`), which is what `walk-verify.sh` assumes |
| s1.4 `dynamo.frontend --help` | PASS | answers from the darwin build |
| s1.4 frontend + mocker, file discovery, one completion | RECORDED (halt: loopback plumbing on the rig) | `/v1/models` lists `mock-model` and the completion request is accepted; the response never arrives on the TCP response stream and the client times out at 30 s. Details under Findings |

## Pins this rung sets

| pin | value |
|---|---|
| upstream commit (R2 promotes it to the first tag containing it) | b83b1d9304ebfc624709ac46db32b1b6f1ff1615 = tag `v1.5.0` |
| chart version built from that commit | `dynamo-platform` 1.5.0 (appVersion 1.5.0), pulled by digest in S2 |
| runtime wheel sha256 (a **reproducibility record**, not provenance) | 0dc014e9e5e8aa68e18e8fd14671b8d897096b0ae83be94013389f313c1dec52 (third build; each build differs, see s1.3) |
| Rust toolchain / maturin | rustc 1.90.0 / maturin 1.15.0 / CPython 3.12.12 |

## Rig

| | |
|---|---|
| host | the M16 rig, reached over the harness's ssh path (`K3SM_M16_HOST`) |
| SoC / memory | Apple M4 Max, 64 GiB (Mac16,6) |
| macOS | 26.6.2 |
| date (UTC) | 2026-09-21 |

## Findings

- **The script's flags predate the pin.** At v1.5.0 the frontend rejects
  `--discovery-path`; the file backend reads its directory from `DYN_FILE_KV`. The
  mocker's `--model` is ambiguous between a name and a path; `--model-name` names the
  served model and `--model-path` supplies the tokenizer. Both fixed in `s1.sh`.
- **Where the smoke stops.** With both processes advertising the rig's LAN address
  (the default), the frontend never lists the model: macOS's application firewall
  refuses the ad-hoc-signed python's inbound dial to that address. With
  `DYN_TCP_RPC_HOST=127.0.0.1` on both, the model lists and the request is accepted;
  the completion then waits on the response stream. `DYN_TCP_RESPONSE_STREAM_HOST`
  takes an **interface name**, and with `lo0` the listing survives but the stream
  still never delivers within 30 s. Whether that is the firewall, the interface
  resolution, or the mocker is not settled here; a firewall exception for the venv's
  python is the next probe, and that is an operator decision, not a script change.
- **Not the halt.** The halt was written for the memory crate failing to link on
  darwin/arm64; it linked. The Rust backend contract re-plan does **not** apply.
- **Three shas from one commit.** The wheel embeds build-time state, so R2 cannot
  promote the wheel sha as a pin; it pins the source sha and records the wheel sha
  the image build produced.
