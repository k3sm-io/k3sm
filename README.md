# k3sm

k3sm is a macOS-native Kubernetes distribution for Apple Silicon — the macOS/arm64 analog of
[k3s](https://github.com/k3s-io/k3s). Pods run as native Darwin processes: real arm64 Mach-O
executables, isolated with a Seatbelt sandbox, on the same Mac as the control plane. There is
no Linux, no container runtime, and no VM in the default path. Linux container images can run
too, in a per-pod Virtualization.framework micro-VM, through an opt-in RuntimeClass
(`runtimeClassName: vm`), not the default.

## What's in the binary

k3sm ships as a single binary. Its subcommands:

| Command | What it does |
|---|---|
| `server` | Run the control plane (apiserver, scheduler, controller-manager, kine datastore) plus a node, on this Mac |
| `agent` | Join this Mac to an existing cluster as a worker node |
| `node` | Run a Virtual Kubelet node against an existing control plane |
| `install` / `uninstall` | Install or remove the netd and server launchd daemons (run as root) |
| `token` | Mint cluster join tokens |
| `certificate` | Re-issue the control-plane leaf certificates over the existing CA |
| `snapshot` | Back up and restore the kine SQLite datastore |
| `build` | Package a native darwin/arm64 image from a COPY-only Dockerfile |
| `image` | Load, import, push, prune, list and inspect this node's images |
| `kubectl` | Run the bundled kubectl against this cluster, with `KUBECONFIG` preset |
| `kubeconfig` | Print the admin kubeconfig, or write/merge it into `~/.kube/config` |
| `doctor` | Run preflight environment and datastore-posture checks |
| `netd` | Run the root-privileged network helper (launched by its own daemon) |
| `dev` | Bring up a disposable single-node cluster for local development |
| `version` | Print the k3sm version and the Kubernetes version it embeds |

Underneath, a few packages carry most of the weight: `pkg/provider` is the Virtual Kubelet
Darwin provider that turns a Pod spec into a running process; `pkg/executor` brings up and
supervises the embedded control plane; `pkg/bootstrap` and `pkg/certs` handle join tokens, node
identity and the certificate hierarchy; `pkg/install` manages the launchd daemons; and `pkg/oci`
is the one place in the repo that reads or writes OCI image bytes. k3sm also imports
`k3sm.io/runtimed` (the native runtime daemon) and `k3sm.io/darwin-net` (pod networking) to do
the actual work of running and connecting pods.

## Quick start

Install the latest release (pre-releases included until the first stable one):

```sh
curl -fsSL https://k3sm.io/install.sh | sh
```

Or build from source:

k3sm's `go.mod` resolves its sibling modules (`k3sm.io/apis`, `k3sm.io/runtimed`,
`k3sm.io/darwin-net`) as relative paths, so clone all four repos side by side:

```sh
mkdir k3sm-io && cd k3sm-io
git clone https://github.com/k3sm-io/apis
git clone https://github.com/k3sm-io/runtimed
git clone https://github.com/k3sm-io/darwin-net
git clone https://github.com/k3sm-io/k3sm
cd k3sm
```

Build (this repo imports runtimed's cgo-backed capability probes, so `CGO_ENABLED=1` is
required):

```sh
CGO_ENABLED=1 go build -o k3sm ./cmd/k3sm
```

Install runs once, as root, and sets up an unprivileged `_k3sm` user and daemon that everything
else runs under — no `sudo` is needed for day-to-day use after this:

```sh
sudo ./k3sm install
./k3sm kubectl get nodes
```

See [docs/user/install.md](docs/user/install.md) for what the install step does and
[docs/user/quickstart.md](docs/user/quickstart.md) for running a first Pod.

## What it does not do

k3sm is not a drop-in replacement for a Linux Kubernetes cluster. It cannot pass CNCF
`[Conformance]` (Sonobuoy assumes Linux containers, cgroups, CNI and network namespaces, none of
which exist on Darwin). CPU `limits` are not enforced — there is no CFS equivalent, so CPU-based
autoscaling is unservable and resource management is best-effort. A Linux container image does
not run on the default path at all; it is rejected at pull. Read
[docs/user/limitations.md](docs/user/limitations.md) for the full inventory, including the
resource model, NetworkPolicy's reduced scope, and the per-pod isolation boundary.

## How the pieces fit together

k3sm is one of four repositories under the `k3sm-io` GitHub organization. `apis` defines the
shared contracts; `runtimed` and `darwin-net` implement the node-level primitives; this repo
assembles all three into the single binary a user installs.

| Repo | Role | k3s analog |
|---|---|---|
| [apis](https://github.com/k3sm-io/apis) | Shared gRPC, CRD and Go contracts | — |
| [runtimed](https://github.com/k3sm-io/runtimed) | Native runtime daemon: Seatbelt confinement, APFS image layers, process supervision | containerd |
| [darwin-net](https://github.com/k3sm-io/darwin-net) | Pod networking: loopback IP-per-pod, Service proxy, wireguard mesh | flannel + kube-proxy |
| k3sm (this repo) | Distribution: the Virtual Kubelet node, the embedded control plane, the CLI | k3s |

## Documentation

The full user documentation lives in this repository, starting at
[docs/user/README.md](docs/user/README.md). It covers installation, concepts, kubectl access,
images, storage, upgrades, certificates, backup and restore, multi-node and high-availability
setups, and the current limitations.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow. Contributions require a
Developer Certificate of Origin sign-off (`git commit -s`); see [DCO](DCO). Project governance is
in [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md); security reports go
through [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE) — © The k3sm Authors.
