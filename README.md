# k3sm — Kubernetes for macOS, natively

`k3sm` is the macOS / Apple-Silicon analog of [k3s](https://github.com/k3s-io/k3s): a lightweight,
single-binary Kubernetes distribution that runs **truly native Darwin workloads** — native arm64
Mach-O processes, **zero Linux, no VM in the default path** — using macOS's own primitives
(Seatbelt, `lo0`/vmnet, wireguard-go, launchd, APFS) instead of Linux's (cgroups, namespaces,
iptables, systemd, OverlayFS).

> Install, once the first release is tagged: `curl -fsSL https://k3sm.io/install.sh | sh`, which
> downloads, sha256-verifies, and runs `sudo k3sm install` for you. A Homebrew tap
> (`brew install k3sm-io/tap/k3sm`, then `sudo k3sm install`) and a notarized `.pkg` follow it.
> **No release is published yet** — neither command works today. See
> [docs/user/install.md](docs/user/install.md).

## Repositories (one Go workspace under `k3sm-io/`)
| Repo | Module | Role (k3s analog) |
|---|---|---|
| **k3sm** (this repo) | `k3sm.io/k3sm` | distribution — embeds the control plane, builds the single binary |
| [runtimed](https://github.com/k3sm-io/runtimed) | `k3sm.io/runtimed` | native runtime daemon — Seatbelt + APFS + posix_spawn (≈ containerd) |
| [darwin-net](https://github.com/k3sm-io/darwin-net) | `k3sm.io/darwin-net` | pod networking — lo0 IPAM, Service proxy, wireguard mesh (≈ flannel + kube-proxy) |
| [apis](https://github.com/k3sm-io/apis) | `k3sm.io/apis` | shared gRPC / CRD / Go contracts |

## Status

**Pre-release.** The engine (**M0–M6**) is code-complete and workspace-integration-green: native
Seatbelt-isolated pods, a single `k3sm server` embedding the upstream control plane over kine, lo0
IP-per-pod + a userspace Service proxy, a wireguard mesh for multi-node, local-path storage, and
RBAC. **M0, M1 and M2 are validated end to end on Apple-Silicon hardware** — M2's gate passed all 13
required conformance criteria plus the install/uninstall lifecycle against a real root install. The
remaining live-hardware and two-Mac acceptance gates, the packaging/signing pipeline, and the `vm`
RuntimeClass / HA lab validation are burned down in **M7 (public release)** and **M8 (MLX — native
Apple-Silicon ML serving)**.

See the hand-written [**ROADMAP.md**](ROADMAP.md) for the Shipped / Next / Future narrative, and
[**docs/DESIGN.md**](docs/DESIGN.md) for the full architecture and the macOS-26 red-team findings
that shaped it.

## Layout
```
cmd/k3sm/         single-binary entrypoint (server | agent | node | install | uninstall | token |
                  certificate | build | image | kubectl | kubeconfig | doctor | netd | version)
pkg/executor/     in-process apiserver/scheduler/controller-manager + kine datastore
pkg/provider/     Virtual Kubelet Darwin provider (logs/exec/top/port-forward)
pkg/bootstrap/    token / node-password / HTTP-CSR / cluster CA
pkg/certs/        certificate authorities and issuance
pkg/netserve/     worker-node network bringup
pkg/netdsvc/      the root k3sm-netd helper client (lo0 / utun / pf / <1024 bind)
pkg/hostnet/      host networking primitives
pkg/policy/       admission (darwin nodeSelector, Warn policies)
pkg/rbac/         fail-closed RBAC provisioner (node-datapath ClusterRole)
pkg/provisioner/  local-path storage provisioner
pkg/runtimeclass/ RuntimeClass provisioning (incl. the vm class)
pkg/install/      LaunchDaemon install/uninstall
pkg/loadbalancer/ client-side apiserver load balancer (HA)
```

## Develop
```sh
# from the workspace root where the four repos are cloned as siblings (go.work spans all four modules)
go build ./...
go test ./...
cd k3sm && CGO_ENABLED=1 go build ./...   # cgo: runtimed capability probes
```

## License

[Apache License 2.0](LICENSE) — © The k3sm Authors. Contributions require a Developer Certificate of
Origin sign-off (`git commit -s`); see [CONTRIBUTING.md](CONTRIBUTING.md),
[GOVERNANCE.md](GOVERNANCE.md), and [SECURITY.md](SECURITY.md).
