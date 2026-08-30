# Quickstart

Bring up a single-node k3sm cluster on your Mac and run your first native Pod. This is the fastest
path; [install.md](install.md) explains what happens underneath.

> **Requirements:** Apple Silicon (arm64), macOS 26+. k3sm runs Pods as native Darwin processes — see
> [concepts.md](concepts.md).

## 1. Install

```sh
curl -fsSL https://k3sm.io/install.sh | sh   # downloads, sha256-verifies, runs sudo k3sm install
# or, once the tap ships:
#   brew install k3sm-io/tap/k3sm && sudo k3sm install
```

The one-time admin step (`sudo k3sm install`, which the script runs for you after printing what it
is about to do) creates the unprivileged `_k3sm` user, installs the LaunchDaemons, and writes an
admin kubeconfig to your home directory. After that, day-to-day use needs **no `sudo`**. See
[install.md](install.md) for the install-channel generations and the script's options.

## 2. Confirm the cluster is up

**Do not run `k3sm server` yourself.** The install step registered the `io.k3sm.server` LaunchDaemon
with `RunAtLoad` and `KeepAlive`, so the control plane and the node are **already running** and will
come back after a reboot. A second, foreground `k3sm server` would contend with it for the work
directory and the apiserver port.

```sh
launchctl print system/io.k3sm.server | head -5   # the daemon launchd is running
kubectl get nodes                                 # one Ready darwin node
```

Install merged an admin context into your `~/.kube/config`, so your own `kubectl` reaches the cluster
with no further setup. See [kubectl-access.md](kubectl-access.md) for the details, and
[install.md](install.md) for what the daemons do.

> Running a **foreground** cluster instead (no daemons, for a throwaway experiment)? Then skip step 1
> entirely and run `k3sm server` in a terminal — never both.

## 3. Run a native binary as a Pod

k3sm workloads are native Darwin executables, not OCI Linux images — see [images.md](images.md).
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

Drop the `nodeSelector` and the cluster rejects the Pod at admission — that guardrail is what keeps
Linux-assuming workloads off these nodes. `examples/hello-native.yaml` in the repo is the same shape.

For your own workload, build a darwin/arm64 binary with your normal toolchain and point
`command[0]` at its absolute path (or set `image: /abs/path` with no command).

## Before you go further

k3sm is not a drop-in Linux Kubernetes. Read [limitations.md](limitations.md) — especially the notes on
DNS, `restartPolicy` per runtime path, and the resource model — before building anything you depend on.

## Next

- [install.md](install.md) — the install model and the `_k3sm` posture.
- [concepts.md](concepts.md) — how Kubernetes maps onto Darwin processes.
- [troubleshooting.md](troubleshooting.md) — when something does not come up.
