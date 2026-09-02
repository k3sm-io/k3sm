# The node-local registry

k3sm can run a small **OCI registry on the node's loopback interface**, so you can push a locally
built image and have a Pod pull it back through the ordinary Kubernetes image path — including
`imagePullPolicy: Always`, the digest index, and real pull failures.

It is **off by default**. Turn it on with `--registry-port`:

```sh
k3sm server --registry-port 6450
```

`k3sm dev` clusters enable it automatically on a per-instance port, so a disposable dev cluster is
always a push target.

## Why It Exists

`k3sm image load` puts an image straight into the node's store. That is the fastest way to try
something, but it steps around every image semantic Kubernetes defines: the node already has the
content, so `imagePullPolicy: Always` pulls nothing, a moved tag is never noticed, and a broken
reference fails at a different place than it would in a real cluster.

A registry on loopback puts those semantics back. The image travels the same way it would from a
public registry — it is just a registry that lives on your Mac and that nothing outside your Mac
can reach.

## Finding the Port

The cluster publishes its own address, so you never have to remember the port. k3sm writes the
standard `local-registry-hosting` ConfigMap into `kube-public`:

```sh
kubectl get configmap local-registry-hosting -n kube-public \
  -o jsonpath='{.data.localRegistryHosting\.v1}'
```

```yaml
help: https://k3sm.io/docs/user/registry/
host: localhost:6450
hostFromContainerRuntime: localhost:6450
```

`hostFromClusterNetwork` is deliberately **absent**, and its absence is a truthful statement rather
than an oversight. That field means "an address a workload inside the cluster network can pull
from". A native Pod is a Darwin process on this host, so its `localhost` is the host's and
`hostFromContainerRuntime` already covers it. A Pod running under the Linux `RuntimeClass` is a
guest with its **own** loopback, on which the registry is not listening — so there is no address
k3sm could publish there that a guest could actually use.

That is the one ceiling worth knowing about: **a Linux-guest Pod cannot pull from the node-local
registry.** Use a reachable registry for those images, or load them into the node's store directly.

## Pushing

Build an OCI layout and push it. No credential is needed on the command line — `k3sm image push`
finds the node's own push credential when, and only when, the target is this node's registry:

```sh
k3sm build --tag localhost:6450/myapp:v1 --format oci --output ./myapp-layout .
k3sm image push ./myapp-layout localhost:6450/myapp:v1
```

Then reference it like any other image:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: localhost:6450/myapp:v1
      imagePullPolicy: Always
```

If the control plane runs as a different user than the one you are pushing from — the packaged
install runs it as its own service account — point push at that control plane's state directory:

```sh
k3sm image push --work-dir /var/lib/k3sm/server ./myapp-layout localhost:6450/myapp:v1
```

The credential itself lives at:

```
<work-dir>/registry/push-credential.json     mode 0600
```

It is regenerated on every server start, so a credential that leaked out of a previous run is
already worthless, and it is never copied anywhere else. `k3sm` presents it only to a loopback
target on exactly the port recorded inside it, so it is never offered to a public registry or to a
second cluster's registry on the same Mac.

You can also push with any OCI tool, using that file's `username` and `password`.

## Pulling

**Pulls are anonymous.** The node's runtime pulls with no credential at all, which is what lets a
Pod reference `localhost:<port>/…` with nothing configured.

**Pushes are authenticated.** Together those two are the whole access model: anyone who can reach
the port can read the images this cluster runs, and only the holder of the current push credential
can put a new one there.

## Storage

Image content lives under the control plane's state directory:

```
<work-dir>/registry/
```

Garbage collection is on. Blobs that no manifest references are collected on a periodic sweep,
with a delay long enough that a slow push is never collected out from under itself. Deleting the
directory while the server is stopped resets the registry to empty; nothing else in the cluster
depends on its contents.

## Security Posture

- **Loopback only.** The listener binds `127.0.0.1` and that is not configurable — a non-loopback
  bind is rejected at startup rather than served. Nothing off your Mac can reach it.
- **Plain HTTP, no TLS.** A certificate would buy nothing against an attacker who is already
  running code on the host, and it would mean every client had to be taught a new trust anchor.
- **Anonymous read.** Any process on the machine can list and pull the images the cluster runs.
  Do not treat the node-local registry as a private store for content the host's other users
  should not see.
- **Authenticated write.** A push needs the per-boot credential, so a process that merely reached
  the port cannot plant an image the cluster will then run.

## Turning It Off

Drop the flag — or set `--registry-port 0` — and restart the server. The registry stops, and its
directory is left where it is; delete `<work-dir>/registry/` to reclaim the space.

## See Also

- [Images](images.md) — the full image reference: `k3sm build`, `image load`/`import`/`push`, and
  the deliberate differences from the Docker tool of the same name.
- [What runs](what-runs.md) — the path from a Dockerfile to a running Pod.
- [Linux images](vm-runtimeclass.md) — the guest path, and why it cannot reach this registry.
