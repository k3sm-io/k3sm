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
help: https://k3sm.io/docs/user/registry/ — the in-cluster address serves plain HTTP,
  not TLS
host: localhost:6450
hostFromClusterNetwork: registry-k3sm-mystudio.k3sm-registry.svc.cluster.local:6450
hostFromContainerRuntime: localhost:6450
```

`host` and `hostFromContainerRuntime` are for tools running **on the Mac**.
`hostFromClusterNetwork` is the address for something running **inside the cluster** — see
[Pulling From Inside a Pod](#pulling-from-inside-a-pod).

`hostFromClusterNetwork` is absent on a single Mac that hosts no Linux guests. There is nothing
listening off loopback on such a node, so there is no in-cluster address to publish.

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

## Using Images Across the Cluster

Every node runs its own registry, so `localhost:6450/myapp:v1` names a **different** registry on
every Mac in the cluster. Push on one machine, let the scheduler place the Pod on another, and the
pull fails — the reference is right, and the node it landed on was simply never fed.

k3sm closes that without asking you to do anything differently. Each node publishes where its own
registry can be reached from inside the cluster, and a node that cannot find a `localhost:<port>/…`
image in its own registry asks the other nodes for it. The image is stored under the name your Pod
asked for, so nothing downstream can tell which machine the bytes came from, and every layer is
verified against its digest exactly as it is on a pull from a public registry.

Two things are worth knowing about how it behaves.

**The direction matters.** The node running the Pod dials the node that has the image. So the
machine you pushed to has to be up and on the cluster network at the moment the pull happens — this
is a fallback between running nodes, not a copy made in advance. If that machine is off, the pull
fails the same way it would have before, and the Pod reports the same image-pull error.

**Reading is open inside the cluster; writing is not.** A pull between nodes is anonymous, which is
what lets a Pod reference `localhost:<port>/…` with nothing configured. Pushing still needs the
per-boot credential, and that credential never leaves the machine that minted it — so another node
can read the images this cluster runs and cannot put a new one there.

Each node publishes where its registry can be reached as a ConfigMap in the **`k3sm-registry`**
namespace, which k3sm creates for exactly this. Nodes are granted read on that one namespace and
nothing more — `kubectl get configmaps -n k3sm-registry` shows what they see.

Nothing about the registry's own listener changes: it still binds loopback and refuses anything
else. What is reachable from the rest of the cluster is a separate, narrow forwarder that carries
connections to it, on the cluster network address and nowhere else.

On a single-machine cluster none of this is in play: there are no other nodes, nothing is published,
and no forwarder is started.

## Pulling From Inside a Pod

A process running **inside** a Pod — a build running in the cluster, say — cannot use
`localhost:6450`. A native Pod's `localhost` is the host's, so that one happens to work; a Linux
guest's `localhost` is its own, and nothing is listening on it.

Each node publishes one address that works for both, and for the Mac itself: an ordinary
Kubernetes Service, named after the node, in the `k3sm-registry` namespace.

```sh
kubectl get svc,endpointslice -n k3sm-registry
```

Dial it the way you would any Service:

```
registry-<node>.k3sm-registry.svc.cluster.local:6450
```

Substitute your node's name — `kubectl get nodes` — or read the address straight out of the
discovery ConfigMap's `hostFromClusterNetwork`, which is what it is there for. The name is
per-node because every node's registry holds different content, so one shared name would resolve
to whichever machine answered first.

Three things to know before you use it:

**It speaks plain HTTP.** The `localhost` spelling gets an insecure-registry exemption from the
docker/OCI toolchain automatically; a Service name does not. Tell your client to use HTTP —
`--plain-http`, `--insecure`, or whatever the tool calls it. The discovery ConfigMap's `help`
line says so too.

**It is a pull address.** Pushing from inside a Pod is not supported: `k3sm image push` finds the
node's credential only for a loopback target, and that credential never leaves the machine that
minted it. Push from the Mac.

**A vm Pod needs the node to be running guests.** The address a caller is sent to is the node's
cluster-network address — the mesh address on a multi-machine cluster, otherwise the guest
network's gateway. A single Mac with neither publishes no Service at all.

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
  bind is rejected at startup rather than served. On a single-machine cluster, nothing off your Mac
  can reach it.
- **Reachable from the rest of the cluster, and only from there.** On a multi-machine cluster a
  separate forwarder carries connections from the cluster network to that loopback listener, so
  another node can pull an image this machine holds. It adds exactly two addresses — the cluster
  network address and the guest network's gateway — and never a wildcard bind, so it does not
  expose the registry to any other network your Mac is on. See
  [Using Images Across the Cluster](#using-images-across-the-cluster).
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
- [Linux images](vm-runtimeclass.md) — the guest path.
