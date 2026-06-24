# k3sm — distribution & assembly

Module **`k3sm.io/k3sm`** (≈ k3s): the single-binary distribution. `cmd/k3sm` (server | agent | node |
install | token | build | …), `pkg/provider` (the Virtual Kubelet Darwin provider — the M0 HostProcess
runtime), control-plane embedding (M1), launchd/packaging. Imports `k3sm.io/{apis,runtimed,darwin-net}`.

> Product design: `docs/DESIGN.md`. Milestones: `docs/M0-spike.md`, `docs/M0-node.md`. Spike: `hack/spike/run.sh`.

## Build / test
```sh
gofmt -l .
go vet ./...
go build ./...        # pure Go today
go test ./...
go mod tidy
```
- **`CGO_ENABLED=1` from M1** (embeds kine → `mattn/go-sqlite3`).
- Keep the `replace google.golang.org/genproto` in `go.mod` — it resolves the monolith-vs-split
  ambiguous import. Don't remove it.

## Run the node (M0)
```sh
go run ./cmd/k3sm node --kubeconfig <spike-kubeconfig> --node-name k3sm-m0
kubectl apply -f examples/hello-native.yaml
```

## Standards
@docs/GO-STANDARDS.md
