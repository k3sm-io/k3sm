# Quickstart

Bring up a single-node k3sm cluster on your Mac and run your first native Pod. This is the fastest
path; [install.md](install.md) explains what happens underneath.

> **Requirements:** Apple Silicon (arm64), macOS 26+. k3sm runs Pods as native Darwin processes — see
> [concepts.md](concepts.md).

## 1. Install

```sh
brew install k3sm-io/tap/k3sm      # or download a notarized release binary
sudo k3sm install                  # one-time admin step (see install.md)
```

The one-time `sudo k3sm install` creates the unprivileged `_k3sm` user, installs the LaunchDaemons,
and writes an admin kubeconfig to your home directory. After that, day-to-day use needs **no `sudo`**.

## 2. Start the control plane + node

```sh
k3sm server
```

This brings up the embedded control plane (apiserver + controller-manager + scheduler over kine/SQLite)
and the Virtual Kubelet node in one process.

## 3. Talk to the cluster

```sh
k3sm kubectl get nodes
```

See [kubectl-access.md](kubectl-access.md) for using a standalone `kubectl` with the generated
kubeconfig.

## 4. Build a native image and run it

k3sm images are native Darwin process bundles, not OCI Linux images — see [images.md](images.md).

```sh
k3sm build -t hello .
k3sm kubectl run hello --image=hello --restart=Never
k3sm kubectl get pods
```

## Before you go further

k3sm is not a drop-in Linux Kubernetes. Read [limitations.md](limitations.md) — especially the notes on
`restartPolicy`, DNS, and the resource model — before building anything you depend on.

## Next

- [install.md](install.md) — the install model and the `_k3sm` posture.
- [concepts.md](concepts.md) — how Kubernetes maps onto Darwin processes.
- [troubleshooting.md](troubleshooting.md) — when something does not come up.
