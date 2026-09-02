# Running Temporal on k3sm

[Temporal](https://temporal.io) is a durable-execution service: a gRPC frontend, a history and
matching engine, a worker service and a Web UI over a SQL store. It ships as `linux/arm64` container
images, so on k3sm it runs under the **`vm` RuntimeClass** — each Pod in its own micro-VM on
Virtualization.framework — while the node stays an ordinary Mac.

That combination is the point of this example. The **server** is a Linux system running on your Mac,
and the **client** is the native macOS `temporal` binary from Homebrew, talking to it over a Service.

> **Requirements:** Apple Silicon, macOS 26+, a running k3sm cluster ([quickstart.md](quickstart.md)),
> a node that advertises `k3sm.io/virtualization`, and network access to pull images from Docker Hub.
>
> The `vm` RuntimeClass runs unmodified `linux/arm64` images in a per-Pod micro-VM. Read
> [vm-runtimeclass.md](vm-runtimeclass.md) and [limitations.md](limitations.md) for what it supports
> today.

## What it stands up

| Object | What it is |
|---|---|
| Pod `temporal` | `temporalio/temporal`, running `temporal server start-dev` — the Temporal Server, SQLite persistence and the Web UI in one process |
| Service `temporal-frontend` | NodePort: gRPC `7233` on node port `30733`, Web UI `8233` on node port `30823` |
| Pod `temporal-ui` (optional) | `temporalio/ui`, the standalone Web UI server, reaching the frontend through its Service |
| Service `temporal-ui` (optional) | NodePort: `8080` on node port `30808` |

Both manifests are in [`examples/temporal/`](../../examples/temporal/). The optional pair is a second
file you can skip: the dev server already serves a Web UI.

**One image per Pod.** Every container in a `vm` Pod shares one root filesystem, so a Pod naming two
images runs the second container's command against the first container's image. Temporal's production
shape — server, datastore and UI as separate images — must therefore be separate Pods here. The dev
server collapses the service into a single image, which is why the one-Pod form is both the simplest
and the honest one.

## 1. Check the node can run a micro-VM

```sh
kubectl get nodes -L k3sm.io/virtualization
```

A node without that label cannot run a `vm` Pod, and the Pod stays Pending. If the Mac is capable but
the label is missing, the capability was probed at daemon start — see
[vm-runtimeclass.md](vm-runtimeclass.md).

## 2. Apply the server

```sh
kubectl apply -f examples/temporal/temporal-dev-server.yaml
kubectl get pod temporal -o wide
kubectl wait --for=condition=Ready pod/temporal --timeout=10m
```

The first start pulls a multi-arch image and boots a guest; later starts reuse the cached image. Watch
the server come up with:

```sh
kubectl logs -f temporal
```

## 3. Drive it from inside the cluster

The image ships the `temporal` CLI as its entrypoint, so the fastest check needs no networking at all:

```sh
kubectl exec -it temporal -- temporal operator cluster health
kubectl exec -it temporal -- temporal operator namespace list
```

`kubectl exec` reaches into the guest directly. Use it whenever you want to separate "is the server
healthy?" from "can I reach the server?".

## 4. Connect the macOS-native `temporal` CLI

Install the CLI as a native arm64 binary and point it at the node port:

```sh
brew install temporal

temporal --address 127.0.0.1:30733 operator cluster health
temporal --address 127.0.0.1:30733 operator namespace list
```

Set it once for the shell instead of repeating the flag:

```sh
export TEMPORAL_ADDRESS=127.0.0.1:30733
temporal workflow list
```

**Dial the Service, never the Pod.** A NodePort answers on every interface the Mac has, and k3sm's
userspace Service proxy is what carries the connection into the guest. A `vm` Pod's pod IP is its
published cluster identity rather than a live address, so `kubectl get pod -o wide` gives you an
address that nothing answers on — as do headless Services and per-Pod DNS names. From inside the
cluster, use the Service's DNS name instead, fully qualified:

```
temporal-frontend.default.svc.cluster.local:7233
```

Fully qualified matters inside a `vm` Pod: a guest's resolver may ignore the search list.

## 5. Open the Web UI

The dev server serves the UI itself:

```sh
open http://127.0.0.1:30823
```

For the multi-Pod shape — a separate UI server image reaching the frontend over the network, the way a
production deployment is arranged — apply the optional manifest as well:

```sh
kubectl apply -f examples/temporal/temporal-web-ui.yaml
kubectl wait --for=condition=Ready pod/temporal-ui --timeout=10m
open http://127.0.0.1:30808
```

That Pod is a second Linux guest consuming the first one through cluster DNS and a Service, which is
the interesting part of applying it.

## 6. Run a workflow

A workflow needs a **worker** — your own code, using a Temporal SDK. Run it as a native macOS process
against the same address the CLI uses:

```sh
export TEMPORAL_ADDRESS=127.0.0.1:30733
```

Every SDK takes that host and port when it builds a client (the Go SDK's `client.Dial` with
`HostPort`, the Python and TypeScript SDKs' `address`/`target_host`). Start from Temporal's own
[samples](https://github.com/temporalio/samples-go) and change only the address. Once a worker is
polling a task queue, start a workflow from the CLI:

```sh
temporal workflow start --type YourWorkflow --task-queue YourTaskQueue --workflow-id demo-1
temporal workflow list
temporal workflow describe --workflow-id demo-1
```

Nothing about the worker is k3sm-specific: it is a normal macOS process talking to a normal Temporal
frontend that happens to be a Linux Pod on the same machine.

## 7. Tear it down

```sh
kubectl delete -f examples/temporal/temporal-web-ui.yaml --ignore-not-found
kubectl delete -f examples/temporal/temporal-dev-server.yaml
```

Deleting the Pod destroys its guest, and with it the workflow history — the example keeps state in
memory. Nothing is left on disk beyond the cached image.

## Things to know

- **This is a development server.** `temporal server start-dev` relaxes checks that a production
  Temporal deployment enforces, and it is a single instance with no replication. It is the right shape
  for a demo, a local integration test or a CI job — not for production traffic.
- **Persisting workflow state** means adding `--db-filename /data/temporal.db` and mounting a
  PersistentVolumeClaim at `/data`. PVC storage works on the `vm` path, with ceilings worth reading
  first: a foreign `runAsUser` or `fsGroup` is refused at admission, `hostPath` is refused outright,
  the host volume is case-insensitive, and an unprivileged `k3sm server` needs `--pod-root` before any
  PVC binds. See [storage.md](storage.md) and [limitations.md](limitations.md).
- **Probes must be `exec` probes.** `httpGet`, `tcpSocket` and gRPC probes are dialed at the published
  pod IP, which a `vm` Pod does not answer; only `exec` reaches into the guest.
- **A container restart recreates the whole VM.** There is no in-guest supervisor: the container *is*
  the guest. The recreate is fast, and a crash-loop behaves as it would anywhere else.
- **Resources size the guest.** The containers' memory limits are summed into the guest's RAM ceiling,
  and their CPU limits are summed and rounded up to whole vCPUs. Raising the limits gives Temporal a
  bigger machine.
- **NetworkPolicy will not isolate this.** It is enforced only on Service-mediated ingress and cannot
  yet name a `vm` Pod as an allowed traffic *source*. Treat it as a hint, not a boundary
  ([limitations.md](limitations.md)).
- **Single node.** Cross-node traffic to or from a `vm` Pod is out of scope for this release, so run
  the server and anything in-cluster that talks to it on the same Mac.

## Next

- [vm-runtimeclass.md](vm-runtimeclass.md) — the RuntimeClass this example runs on.
- [limitations.md](limitations.md) — the measured ceilings referenced throughout.
- [what-runs.md](what-runs.md) — which workloads run natively and which need a guest.
- [images.md](images.md) — how images are pulled, cached and selected per platform.
