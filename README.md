# k3sm — Kubernetes for macOS, natively

`k3sm` is the macOS / Apple-Silicon analog of [k3s](https://github.com/k3s-io/k3s): a lightweight,
single-binary Kubernetes distribution that runs **truly native Darwin workloads** — native arm64
Mach-O processes, **zero Linux, no VM in the default path** — using macOS's own primitives
(Seatbelt, `lo0`/vmnet, wireguard-go, launchd, APFS) instead of Linux's (cgroups, namespaces,
iptables, systemd, OverlayFS).

> Target install UX: `brew install k3sm-io/tap/k3sm` → `sudo k3sm install server`.

## Repositories (one Go workspace under `k3sm-io/`)
| Repo | Module | Role (k3s analog) |
|---|---|---|
| **k3sm** (this repo) | `k3sm.io/k3sm` | distribution — embeds the control plane, builds the single binary |
| [runtimed](https://github.com/k3sm-io/runtimed) | `k3sm.io/runtimed` | native runtime daemon — Seatbelt + APFS + posix_spawn (≈ containerd) |
| [darwin-net](https://github.com/k3sm-io/darwin-net) | `k3sm.io/darwin-net` | pod networking — lo0 IPAM, Service proxy, wireguard mesh (≈ flannel + kube-proxy) |
| [apis](https://github.com/k3sm-io/apis) | `k3sm.io/apis` | shared gRPC / CRD / Go contracts |

## Status
**Pre-M0 scaffold.** The full architecture, the macOS-26 adversarial red-team findings that shaped
it, and the milestone roadmap live in **[docs/DESIGN.md](docs/DESIGN.md)**.

## Planned layout
```
cmd/k3sm/            single-binary entrypoint (server | agent | install | token | build | …)
pkg/executor/embed/  in-process apiserver/scheduler/controller-manager (k3s pattern)
pkg/datastore/       kine + SQLite
pkg/bootstrap/ cert/ token, node-password, HTTP-CSR, cluster CA
pkg/provider/        Virtual Kubelet Darwin provider (logs/exec/top)
pkg/launchd/         LaunchDaemon + app-bundle packaging
pkg/image/           OCI artifact build/pull (oras)
pkg/deploy/          embedded addons (CoreDNS, CRDs, RBAC)
```

## Develop
```sh
# from the workspace root /Users/miko/Code/k3sm-io
go build ./k3sm/cmd/k3sm   # builds the (stub) binary
```
