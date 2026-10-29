# Quickstart

Bring up a single-node k3sm cluster on your Mac and run your first native Pod. This is the fastest
path; [Install](install.md) explains what happens underneath.

> **Requirements:** Apple Silicon (arm64), macOS 26+. k3sm runs Pods as native Darwin processes; see
> [Concepts](concepts.md).

## 1. Install

```sh
curl -fsSL https://k3sm.io/install.sh | sh
```

The script checks that this is an Apple silicon Mac on macOS 26+, downloads the release tarball and
its checksums from GitHub Releases, verifies the sha256, prints exactly what it is about to do, and
then runs `sudo k3sm install`. It installs the newest published release. To pin a particular one (the example names the release you are on today, so change it to the
version you want), put the variable after
the pipe so it reaches `sh`:

```sh
curl -fsSL https://k3sm.io/install.sh | K3SM_INSTALL_VERSION=v0.2.3 sh
```

Set `K3SM_INSTALL_DOWNLOAD_ONLY=1` the same way to download and verify into the current directory
without running anything as root.

Two alternatives:

- **The k3sm app,** a signed, notarized download from k3sm.io. See [Installing From k3sm.app](install.md#installing-from-k3smapp).
- **From source**, if you would rather build it yourself: clone `apis`, `runtimed`, `darwin-net`
  and `k3sm` side by side, run `go work init ./apis ./runtimed ./darwin-net ./k3sm`, build with
  `CGO_ENABLED=1 go build -o k3sm ./cmd/k3sm` inside `k3sm`, assemble the install set with
  `hack/release/stage.sh ../stage`, then run `sudo ../stage/k3sm install`. The staging script
  needs the Command Line Tools, a signed-in `gh` and the Go release it pins. The full steps are
  in the [repository README](https://github.com/k3sm-io/k3sm#quick-start).

The one-time admin step (`sudo k3sm install`, which the script runs for you after printing what it
is about to do) creates the unprivileged `_k3sm` user, installs the LaunchDaemons, and writes an
admin kubeconfig to your home directory. After that, day-to-day use needs **no `sudo`**. See
[Install](install.md) for the install-channel generations and the script's options.

## 2. Confirm the Cluster Is Up

**Do not run `k3sm server` yourself.** The install step registered the `io.k3sm.server` LaunchDaemon
with `RunAtLoad` and `KeepAlive`, so the control plane and the node are **already running** and will
come back after a reboot. A second, foreground `k3sm server` would contend with it for the work
directory and the apiserver port.

```sh
k3sm status         # one screen: daemons, apiserver, node, workloads, data root
kubectl get nodes   # one Ready darwin node
```

In that output, the `install` row of `k3sm status` names the two LaunchDaemons. They are what makes
the cluster survive a reboot, and `k3sm status` is how you check they came back. Its exit code is the verdict, so a script can branch
on it; `k3sm status --help` lists the codes.

Install merged an admin context into your `~/.kube/config`, so your own `kubectl` reaches the cluster
with no further setup. See [kubectl access](kubectl-access.md) for the details, and
[Install](install.md) for what the daemons do.

> Running a **foreground** cluster instead (no daemons, for a throwaway experiment)? Then skip step 1
> entirely and run `k3sm server` in a terminal. Never run both.

## 3. Run a Native Binary as a Pod

k3sm workloads are native Darwin executables, not OCI Linux images; see [Images](images.md).
The `image: native` sentinel runs an absolute host binary as a confined pod. Every k3sm Pod must
declare the darwin node selector and tolerate the node's provider taint, so use a manifest rather
than `kubectl run`:

```sh
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  restartPolicy: Never
  containers:
    - name: hello
      image: native
      command: ["/usr/bin/sw_vers"]
EOF

kubectl get pods
kubectl logs hello
```

Drop the `nodeSelector` and the cluster rejects the Pod at admission. That guardrail keeps
Linux-assuming workloads off these nodes. `examples/hello-native.yaml` in the repo is the same shape.

For your own workload, build a darwin/arm64 binary with your normal toolchain and point
`command[0]` at its absolute path (or set `image: /abs/path` with no command).

## Before You Go Further

k3sm is not a drop-in Linux Kubernetes. Before building anything you depend on, read
[Limitations](limitations.md), especially the notes on DNS, `restartPolicy` per runtime path, and
the resource model.

## Next

- [Install](install.md) covers the install model and the `_k3sm` posture.
- [Concepts](concepts.md) explains how Kubernetes maps onto Darwin processes.
- [Troubleshooting](troubleshooting.md) helps when something does not come up.
