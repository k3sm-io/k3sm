# k3sm — distribution & assembly

Module **`k3sm.io/k3sm`** (≈ k3s): the single-binary distribution. `cmd/k3sm` (server | agent | node |
install | token | kubectl | doctor | dev | build | image | …; `image` is
load|import|push|pull|tag|untag|inspect|save|prune|ls|df, a client of runtimed's Images service — the
daemon is the store's only writer. `build` runs Dockerfile `RUN` steps through the build engine and
records the image to the store unless `--no-record` is given (`--output` additionally writes a file); OCI plumbing lives in `pkg/oci` — see docs/user/images.md),
`pkg/provider` (the Virtual Kubelet Darwin provider — the HostProcess runtime), control-plane
embedding, launchd/packaging. Imports `k3sm.io/{apis,runtimed,darwin-net}`.

> Product design: `docs/DESIGN.md`. Milestones: `docs/M0-spike.md`, `docs/M0-node.md`. Spike: `hack/spike/run.sh`.
> Roadmap & current phase: `docs/PHASES.md`. Acceptance gates: `hack/acceptance/`.
> Public roadmap: `ROADMAP.md`, grouped by minor version.

## Build / test
```sh
gofmt -l .
go vet ./...
CGO_ENABLED=1 go build ./...
go test ./...
go mod tidy
```
- **`CGO_ENABLED=1`** (imports runtimed's cgo-backed capability probes). kine is **not**
  embedded — the executor runs it as a pinned child process built on demand
  (`go install`, out-of-module); `mattn/go-sqlite3` is in no `k3sm.io` go.mod.
- Keep the `replace google.golang.org/genproto` in `go.mod` — it resolves the monolith-vs-split
  ambiguous import. Don't remove it.

## Run the node
```sh
go run ./cmd/k3sm node --kubeconfig <spike-kubeconfig> --node-name k3sm-m0
kubectl apply -f examples/hello-native.yaml
```

## Containers only, and no CI on GitHub

- **Containers only.** Nothing is installed on the host Mac, for supply-chain safety: no `brew`, no global
  `go install`/`cargo install`/`pip install`/`npm -g` of a tool, no `curl | sh`, no `sudo` installs. Toolchains
  and services run in k3sm pods; a tool the gate needs runs in a pod image pinned to an exact version and
  checksum. When a gate names a missing tool, it gives the pinned command to run in the pod, not on the host.
- **No CI on GitHub: no GitHub Actions workflows, ever, in any project, and Actions stays disabled; all gates
  run locally in k3sm pods**, through Yureisha CI (the `yureisha/ci` commit status) or this repo's own gate
  script, `hack/ci.sh`. No file may exist under `.github/workflows/`, commented out or not. `hack/ci.sh`
  checks the DCO sign-off on every commit a branch adds.

## Standards
@docs/GO-STANDARDS.md
