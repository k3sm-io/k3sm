# k3sm — distribution & assembly

Module **`k3sm.io/k3sm`** (≈ k3s): the single-binary distribution. `cmd/k3sm` (server | agent | node |
install | token | kubectl | doctor | dev | build | …; `image` is planned — see docs/user/images.md.
`build` is COPY-only and writes to a file, not to the shared store; OCI plumbing lives in `pkg/oci`),
`pkg/provider` (the Virtual Kubelet Darwin provider — the M0 HostProcess runtime), control-plane
embedding (M1), launchd/packaging. Imports `k3sm.io/{apis,runtimed,darwin-net}`.

> Product design: `docs/DESIGN.md`. Milestones: `docs/M0-spike.md`, `docs/M0-node.md`. Spike: `hack/spike/run.sh`.
> Roadmap & current phase: `docs/PHASES.md`. Acceptance gates: `hack/acceptance/`.
> Public roadmap narrative: `ROADMAP.md` (hand-written).

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

## Run the node (M0)
```sh
go run ./cmd/k3sm node --kubeconfig <spike-kubeconfig> --node-name k3sm-m0
kubectl apply -f examples/hello-native.yaml
```

## Standards
@docs/GO-STANDARDS.md
