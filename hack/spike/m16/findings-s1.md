# S1 findings — the Darwin build and an infrastructure-free smoke (M16.0-d2)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m16/s1.sh`.

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
| s1.1 toolchain pinned (rustc, maturin, interpreter) | | |
| s1.2 build completes; resolved commit recorded | | |
| s1.3 wheel sha256; extension signature state | | |
| s1.4 `dynamo.frontend --help` | | |
| s1.4 frontend + mocker, file discovery, one completion | | |

## Pins this rung sets

| pin | value |
|---|---|
| upstream commit (R2 promotes it to the first tag containing it) | |
| chart version built from that commit | |
| runtime wheel sha256 (a **reproducibility record**, not provenance) | |
| Rust toolchain / maturin | |
