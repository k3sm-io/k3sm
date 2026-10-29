# k3sm

k3sm is a macOS-native Kubernetes distribution for Apple Silicon, the macOS/arm64 analog of
[k3s](https://github.com/k3s-io/k3s). Pods run as native Darwin processes: real arm64 Mach-O
executables, isolated with a Seatbelt sandbox, on the same Mac as the control plane. There is
no Linux, no container runtime, and no VM in the default path. Linux container images can run
too, in a per-pod Virtualization.framework micro-VM, through an opt-in RuntimeClass
(`runtimeClassName: vm`). The `vm` path runs `linux/arm64` images; `linux/amd64` images do not
run on any path yet.

The latest release is v0.2.3 (2026-10-29). The control plane on `main` embeds
Kubernetes v1.37.1. Multi-node clusters, two Macs joined over a wireguard mesh, and a control plane shared by
two servers are experimental; both graduate in a later release. Models served on
the Mac's GPU with MLX have their own resource and CRD (`mlx.k3sm.io/gpu` and `MLXModel`). The
[roadmap](ROADMAP.md) says what has shipped and what comes next.

## What's in the binary

k3sm ships as a single binary. Its subcommands:

| Command | What it does |
|---|---|
| `server` | Run the control plane (apiserver, scheduler, controller-manager, kine datastore) plus a node, on this Mac |
| `agent` | Join this Mac to an existing cluster as a worker node |
| `node` | Run a Virtual Kubelet node against an existing control plane |
| `install` / `uninstall` | Install or remove the k3sm launchd daemons (run as root) |
| `stop` / `start` / `restart` | Stop the node fully and keep it stopped across reboots, start it again, or restart the daemons with pods kept running |
| `network` | Choose whether NodePort, LoadBalancer and ingress listeners answer on the LAN (`network lan on\|off\|status`) |
| `datavol` | Manage the APFS volume the data root can live on (`datavol mount\|status\|delete`) |
| `token` | Mint cluster join tokens |
| `certificate` | Re-issue the control-plane leaf certificates over the existing CA |
| `snapshot` | Save, restore, list and prune datastore snapshots |
| `secrets-encrypt` | Report the state of secrets encryption at rest |
| `interconnect` | Arm or disarm a Thunderbolt cable between Macs as an opt-in network (alpha) |
| `build` | Build a Dockerfile into an image: natively for copy-only recipes, on the cluster's build engine for `RUN` |
| `builder` | Manage the in-cluster buildkitd build engine and its bundled buildx |
| `image` | Load, import, pull, tag, untag, push, save, prune, list (`ls`, `df`) and inspect images in the cluster registry and this node's pull cache, and migrate a node's older images into the registry |
| `registry` | Mint the cluster registry's push token for any OCI tool, through your kubeconfig (`registry token\|login`) |
| `payload` | Stage the control-plane binaries an install copies into place |
| `kubectl` | Run the bundled kubectl against this cluster, with `KUBECONFIG` preset |
| `kubeconfig` | Print the admin kubeconfig, or write/merge it into `~/.kube/config` |
| `status` | Show what is running (daemons, apiserver, node, workloads, data root), with a one-line verdict and the fix for whatever is down |
| `alerts` | List only what needs attention, each with its cause, the evidence, numbered fix steps and the docs page (`-o json` for scripts and tools) |
| `update` | Check for a newer release, or roll the whole cluster to one, workers first and the server last (`update check\|apply\|status\|cancel\|abort`) |
| `doctor` | Run preflight environment and datastore-posture checks |
| `netd` | Run the root-privileged network helper (launched by its own daemon) |
| `dev` | Bring up a disposable single-node cluster for local development |
| `version` | Print the k3sm version and the Kubernetes version it embeds |

Underneath, a few packages carry most of the weight: `pkg/provider` is the Virtual Kubelet
Darwin provider that turns a Pod spec into a running process; `pkg/executor` brings up and
supervises the embedded control plane; `pkg/bootstrap` and `pkg/certs` handle join tokens, node
identity and the certificate hierarchy; `pkg/install` manages the launchd daemons; `pkg/mlx`
renders an `MLXModel` into the objects that serve it; `pkg/addons` carries the add-on reconcilers: the embedded metrics-server
add-on, which every server applies once its node has minted its kubelet serving certificate, and the operator's root-owned manifest directory; `pkg/update` and `pkg/updatectl` back `k3sm update`, the release check and the server-driven roll of
the cluster to a release, workers first and the server last; `pkg/interconnect` is the opt-in
Thunderbolt cable network between Macs, beside the wireguard mesh; and
`pkg/oci` is the one place in the repo that reads or writes OCI image bytes. k3sm imports
`k3sm.io/runtimed` (the native runtime daemon) and `k3sm.io/darwin-net` (pod networking) to do
the actual work of running and connecting pods.

## Quick start

Install the latest release:

```sh
curl -fsSL https://k3sm.io/install.sh | sh
```

Or build from source:

k3sm's `go.mod` resolves its sibling modules (`k3sm.io/apis`, `k3sm.io/runtimed`,
`k3sm.io/darwin-net`) as relative paths, so clone the four Go repos side by side and tie them
together with a `go.work`:

```sh
mkdir k3sm-io && cd k3sm-io
git clone https://github.com/k3sm-io/apis
git clone https://github.com/k3sm-io/runtimed
git clone https://github.com/k3sm-io/darwin-net
git clone https://github.com/k3sm-io/k3sm
go work init ./apis ./runtimed ./darwin-net ./k3sm
cd k3sm
```

Build the binary (this repo imports runtimed's cgo-backed capability probes, so `CGO_ENABLED=1`
is required):

```sh
CGO_ENABLED=1 go build -o k3sm ./cmd/k3sm
```

An install needs more than the binary: the Seatbelt exec helper, two DYLD shims, the VM host
helper and the control-plane payload sit beside it. `hack/release/stage.sh` builds the binary
again and assembles that whole set, ad-hoc signed, into the folder you name. It needs the Command
Line Tools, a signed-in GitHub CLI (`gh`), and the exact Go release the script pins
(`PAYLOAD_GO_VERSION` in `hack/release/lib/gochild.sh`, which the script sources) first on your `PATH`, and the staged folder comes to about
700 MB.

Before it signs anything, the staging script scans the bundled Go binaries for known
vulnerabilities: every Go binary in the control-plane payload (the Kubernetes binaries, kine,
etcd, etcdutl, zot and helm), with `govulncheck -mode=binary` at the version `hack/ci.sh` pins. It
needs that govulncheck installed and the Go vulnerability database reachable. A finding whose
trace reaches a vulnerable symbol in a binary stops the staging unless
`hack/release/govulncheck.allow` names it by vulnerability id, child and the child's pinned
version, with a reason and an expiry date. Allow entries expire, and an expired entry turns the
repo gate (`hack/ci.sh`) red until it is re-reviewed. An expired entry stops the staging, and so
does an entry that matches no finding, so an exemption ends when its finding or its pin goes away.
A finding with no vulnerable symbol in the binary is printed and does not stop it. A missing or
mismatched govulncheck, an unreachable or stale database or an incomplete scan output stops the
staging with the failure named.

Install runs once, as root, and sets up an unprivileged `_k3sm` user and daemon that everything
else runs under. Day-to-day use after that needs no `sudo`:

```sh
hack/release/stage.sh ../stage
sudo ../stage/k3sm install
k3sm kubectl get nodes
```

To install from the k3sm app instead, see
[Installing From k3sm.app](docs/user/install.md#installing-from-k3smapp). The app is a separate
SwiftPM package with its own repository, [k3sm-io/app](https://github.com/k3sm-io/app).

See [docs/user/install.md](docs/user/install.md) for what the install step does and
[docs/user/quickstart.md](docs/user/quickstart.md) for running a first Pod.

## What it does not do

k3sm is not a drop-in replacement for a Linux Kubernetes cluster. It cannot pass CNCF
`[Conformance]` (the suite assumes Linux containers, cgroups, CNI and network namespaces, none of
which exist on Darwin). CPU `limits` are not enforced, because there is no CFS equivalent. That
makes CPU-based autoscaling unservable and resource management best-effort. A Linux container image does
not run on the default path at all; it is rejected at pull, and so is an `amd64`-only image on
either path. Read [docs/user/limitations.md](docs/user/limitations.md) for the full inventory,
including the resource model, NetworkPolicy's reduced scope, and the per-pod isolation boundary.

## How the pieces fit together

k3sm is one of seven code repositories under the `k3sm-io` GitHub organization (`apis`, `runtimed`,
`darwin-net`, `k3sm`, `app` and the C++ and Swift SDKs), beside a separate release repository that
publishes the Linux guest the `vm` RuntimeClass boots. `apis` defines the shared contracts;
`runtimed` and `darwin-net` implement the node-level primitives; this repo assembles all three
into the single binary a user installs; `app` is the macOS app on top of it.

| Repo | Role | k3s analog |
|---|---|---|
| [apis](https://github.com/k3sm-io/apis) | Shared gRPC, CRD and Go contracts | none |
| [runtimed](https://github.com/k3sm-io/runtimed) | Native runtime daemon: Seatbelt confinement, APFS image layers, process supervision | containerd |
| [darwin-net](https://github.com/k3sm-io/darwin-net) | Pod networking: loopback IP-per-pod, Service proxy, wireguard mesh | flannel + kube-proxy |
| k3sm (this repo) | Distribution: the Virtual Kubelet node, the embedded control plane, the CLI | k3s |
| [app](https://github.com/k3sm-io/app) | The macOS app: a menu bar status item and a window with the cluster, this Mac, the nodes and a workloads console; it reads `k3sm status -o json` | none |
| [linux-guest](https://github.com/k3sm-io/linux-guest) | The pinned guest kernel and initramfs releases the `vm` RuntimeClass boots | none |
| [k3sm-sdk-cpp](https://github.com/k3sm-io/k3sm-sdk-cpp) | A C++ SDK for applications that read node pressure and headroom from k3sm (header-only, CMake; the API is being designed) | none |
| [k3sm-sdk-swift](https://github.com/k3sm-io/k3sm-sdk-swift) | A Swift SDK for applications that read node pressure and headroom from k3sm (SwiftPM; the API is being designed) | none |

## Documentation

The full user documentation lives in this repository, starting at
[docs/user/README.md](docs/user/README.md). It covers installation, concepts, kubectl access,
images and the build engine, storage, upgrades, certificates, backup and restore, stopping and
starting a node, multi-node and high-availability setups, Linux images under `vm`, MLX serving,
and the current limitations. [CHANGELOG.md](CHANGELOG.md) lists what each release changed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow. Contributions require a
Developer Certificate of Origin sign-off (`git commit -s`); see [DCO](DCO). Project governance is
in [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md); security reports go
through [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE), © The k3sm Authors.
