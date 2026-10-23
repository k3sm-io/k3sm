# The node-local registry

k3sm can run a small **OCI registry on the node's loopback interface**, so you can push a locally
built image and have a Pod pull it back through the ordinary Kubernetes image path, including
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
public registry. This one happens to live on your Mac, and nothing outside your Mac can reach it.

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
`hostFromClusterNetwork` is the address for something running **inside the cluster**; see
[Pulling From Inside a Pod](#pulling-from-inside-a-pod).

`hostFromClusterNetwork` is absent on a single Mac that hosts no Linux guests. There is nothing
listening off loopback on such a node, so there is no in-cluster address to publish.

## Pushing

`k3sm build --push` builds and uploads in one command. You need no credential on the command line,
because the build finds the node's own push credential when, and only when, the target is this
node's registry:

```sh
k3sm build --tag localhost:6450/myapp:v1 --push .
k3sm build --tag myapp:v1 --push .          # a bare tag goes here too, on the port above
```

A bare tag is the short form of the same thing. It resolves to `localhost:<registry-port>`, which is
also where a bare `image: myapp:v1` in a Pod spec is served from. The store keeps the name you gave,
so the tag in your Pod spec is the tag you typed.

For an image that already exists, such as a layout you built earlier or one someone handed you,
push it on its own:

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

The packaged install runs the control plane as its own service account. If the control plane runs as
a different user than the one you are pushing from, point push at that control plane's state
directory:

```sh
k3sm image push --work-dir /var/lib/k3sm/server ./myapp-layout localhost:6450/myapp:v1
```

`k3sm build --push` reads the same file, from the work dir it resolves for the current user or from
`K3SM_WORK_DIR` when that is set.

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

Pulls are anonymous. The node's runtime pulls with no credential at all, which is what lets a Pod
reference `localhost:<port>/…` with nothing configured.

Pushes are authenticated. Together those two are the whole access model. Anyone who can reach the
port can read the images this cluster runs, and only the holder of the current push credential, or a
Pod the cluster's RBAC allows to push (see [Pushing From Inside a Pod](#pushing-from-inside-a-pod)),
can put a new one there.

## Using Images Across the Cluster

The registry runs on the **server**, when the server is started with `--registry-port`. On a
multi-machine cluster `localhost:6450/myapp:v1` therefore names the registry on the server Mac, and
on any other Mac `localhost:6450` is a different, empty address. Push to the server, let the
scheduler place the Pod on another Mac, and a plain `localhost` pull would fail even though the
reference is right.

k3sm closes that without asking you to do anything differently. The node that runs the registry
publishes where it can be reached from inside the cluster, and a node that cannot find a
`localhost:<port>/…` image locally pulls it from there through a fallback. The image is stored under
the name your Pod asked for, so nothing downstream can tell which machine the bytes came from, and
every layer is verified against its digest exactly as it is on a pull from a public registry.

Two things are worth knowing about how it behaves.

The direction matters. The node running the Pod dials the node that runs the registry, so that
machine has to be up and on the cluster network at the moment the pull happens. This is a
fallback between running nodes, not a copy made in advance. If that machine is off, the pull fails
the same way it would have before, and the Pod reports the same image-pull error.

Reading is open inside the cluster; writing is not. A pull between nodes is anonymous, which is what
lets a Pod reference `localhost:<port>/…` with nothing configured. Pushing still needs the per-boot
credential, which never leaves the machine that minted it, or a Pod's own ServiceAccount token that
the cluster authorizes for that one repository. Another node can read the images this cluster runs
and cannot put a new one there on its own authority.

The node that runs the registry publishes where it can be reached as a ConfigMap in the
**`k3sm-registry`** namespace, which k3sm creates for this. Nodes are granted read on that one
namespace and nothing more; `kubectl get configmaps -n k3sm-registry` shows what they see.

Nothing about the registry's own listener changes. It still binds loopback and refuses anything
else. What is reachable from the rest of the cluster is a separate, narrow front that passes reads
through and checks every write, on the cluster network address and nowhere else.

On a single-machine cluster none of this is in play. There are no other nodes, nothing is published,
and no forwarder is started.

## Pulling From Inside a Pod

A process running **inside** a Pod, say a build running in the cluster, cannot use
`localhost:6450`. A native Pod's `localhost` is the host's, so that one happens to work; a Linux
guest's `localhost` is its own, and nothing is listening on it.

The node that runs the registry publishes one address that works for both, and for the Mac itself.
It is an ordinary Kubernetes Service, named after the node, in the `k3sm-registry` namespace.

```sh
kubectl get svc,endpointslice -n k3sm-registry
```

Dial it the way you would any Service. All four of these name it:

```
registry-<node>.k3sm-registry.svc.cluster.local:6450
registry-<node>.k3sm-registry.svc:6450
registry-<node>.k3sm-registry:6450
<the Service's ClusterIP>:6450
```

Substitute the name of the node that runs the registry (`kubectl get nodes`), or read the fully
qualified form straight out of the discovery ConfigMap's `hostFromClusterNetwork`, which is what it
is there for. The name carries the node because the content lives on that one machine.

Some things to know before you use it.

It speaks plain HTTP. The `localhost` spelling gets an insecure-registry exemption from the
docker/OCI toolchain automatically; a Service name does not. Tell your client to use HTTP, with
`--plain-http`, `--insecure`, or whatever the tool calls it. The discovery ConfigMap's `help`
line says so too.

It is for tools inside the Pod, not for `image:`. Keep writing `localhost:6450/myapp:v1` in
a Pod spec. Kubernetes image references are resolved by the node's runtime, which runs on the
Mac and does not use the cluster's DNS, so a Service name in `spec.containers[].image` has
nothing to resolve it. The addresses above are for a process inside the Pod that is fetching or
inspecting images itself.

It is also a push address, for a Pod that has been allowed to push. See
[Pushing From Inside a Pod](#pushing-from-inside-a-pod).

Reads are anonymous, here as everywhere. Anything that can reach the address can list and pull the
images this cluster runs. The loopback listener allows the same thing; this extends it to the
cluster network and no further.

A vm Pod needs the node to be running guests. The address a caller is sent to is the node's
cluster-network address, which is the mesh address on a multi-machine cluster and otherwise the
guest network's gateway. A single Mac with neither publishes no Service at all.

## Pushing From Inside a Pod

A Pod can push to the registry with its own ServiceAccount token. No shared password is handed out:
the Pod presents a token the cluster minted for it, and the registry asks the cluster whether that
ServiceAccount may push that repository. Reads stay anonymous, as everywhere else.

A push is allowed only when all of these hold:

- The token is a projected ServiceAccount token minted for the audience `k3sm-registry`. The Pod's
  default API token is refused.
- The Pod's namespace carries the label `k3sm.io/registry-push`, whose value is a repository prefix.
- The repository sits under that prefix, at least one level down. With the prefix `team`,
  `team/app` and `team/tools/app` are allowed, and `team`, `teamx/app` and `other/app` are not.
- The ServiceAccount is bound to the `k3sm:registry-pusher` ClusterRole in that namespace.

Deleting is never allowed from a Pod, whatever the grant. Delete images from the Mac.

Opting a namespace in is two steps. Labelling a namespace is a cluster-admin act, and the prefix
should be unique per namespace: two namespaces given the same prefix can overwrite each other's
images.

```sh
kubectl label namespace team k3sm.io/registry-push=team
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: registry-pusher
  namespace: team
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k3sm:registry-pusher
subjects:
  - kind: ServiceAccount
    name: builder
    namespace: team
```

k3sm ships the `k3sm:registry-pusher` ClusterRole and no binding to it, so nothing can push until a
namespace binds it.

Give the Pod a token for the registry with a projected volume:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: build
  namespace: team
spec:
  serviceAccountName: builder
  containers:
    - name: build
      image: localhost:6450/team/buildtools:v1
      volumeMounts:
        - name: registry-token
          mountPath: /var/run/secrets/registry
          readOnly: true
  volumes:
    - name: registry-token
      projected:
        sources:
          - serviceAccountToken:
              audience: k3sm-registry
              expirationSeconds: 3600
              path: token
```

A native Pod's token file is re-minted once less than a fifth of its lifetime is left, and the check
runs about once a minute, so read the file again before each push. A Linux (`vm`) Pod's token is
written once at start and is never re-minted, so the job must finish its pushes within
`expirationSeconds`.

Log in with HTTP Basic: the password is the token and the username is ignored. Push to the
`registry-<node>` Service of the node that runs the registry; the discovery ConfigMap's
`hostFromClusterNetwork` names it. The image lands on that node, and other nodes pull it from there
through the fallback described in [Using Images Across the Cluster](#using-images-across-the-cluster).
The address speaks plain HTTP, so tell each tool so. See
[What the token is exposed to](#what-the-token-is-exposed-to) before you rely on it.

```sh
REG=registry-mynode.k3sm-registry.svc:6450
TOKEN=$(cat /var/run/secrets/registry/token)

# crane
crane auth login "$REG" -u pod -p "$TOKEN"
crane push --insecure ./app.tar "$REG/team/app:v1"

# oras
oras push --plain-http -u pod -p "$TOKEN" "$REG/team/app:v1" ./artifact.txt

# buildctl reads the Docker config file for credentials
mkdir -p ~/.docker
printf '{"auths":{"%s":{"auth":"%s"}}}' "$REG" "$(printf 'pod:%s' "$TOKEN" | base64 | tr -d '\n')" \
  > ~/.docker/config.json
buildctl build --frontend dockerfile.v0 --local context=. --local dockerfile=. \
  --output "type=image,name=$REG/team/app:v1,push=true,registry.insecure=true"
```

### What the token is exposed to

The in-cluster address is plain HTTP, so the token travels in cleartext. On a multi-machine cluster
the hop between Macs is encrypted by the mesh. On the `vm` guest network, though, the guests on a
Mac share one segment, so a hostile `vm` Pod on the same Mac could capture a sibling's push token
and push into that namespace's prefix until the token expires. Ask for the shortest
`expirationSeconds` the job allows, and keep untrusted workloads out of namespaces that can push.

### Refusals

A refused push says why, in an OCI error body. Every status a push can get:

| Status | Meaning |
|---|---|
| `400` | The request path, query or request target is malformed. |
| `401` | No token, a malformed token, an expired or otherwise invalid token, or a token minted for another audience. The response carries a Basic `WWW-Authenticate` challenge. |
| `403` | The caller is authenticated but refused: the token is not a ServiceAccount's, the namespace has not opted in (no label, or an invalid prefix), the repository is outside the prefix, or RBAC denies the push. |
| `405` | A delete, or any other write shape the registry never takes from a Pod. |
| `429` | Token checks are rate-limited; wait for the `Retry-After` interval and retry. |
| `502` | The registry behind the gate is unreachable. |
| `503` | The cluster API is unreachable, or the gate has no identity to ask it with. Retry. |

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

- Loopback only. The listener binds `127.0.0.1` and that is not configurable; a non-loopback bind is
  rejected at startup rather than served. On a single-machine cluster, nothing off your Mac can
  reach it.
- Reachable from the rest of the cluster, and only from there. On a multi-machine cluster a separate
  forwarder carries connections from the cluster network to that loopback listener, so another node
  can pull an image this machine holds. It adds exactly two addresses (the cluster network address
  and the guest network's gateway) and never a wildcard bind, so it does not expose the registry to
  any other network your Mac is on. See
  [Using Images Across the Cluster](#using-images-across-the-cluster).
- Plain HTTP, no TLS. A certificate would buy nothing against an attacker who is already running
  code on the host, and it would mean every client had to be taught a new trust anchor. A push
  token sent over the in-cluster address is exposed on the `vm` guest network; see
  [What the token is exposed to](#what-the-token-is-exposed-to).
- Anonymous read. Any process on the machine can list and pull the images the cluster runs. Do not
  treat the node-local registry as a private store for content the host's other users should not
  see.
- Authenticated write. A push needs the per-boot credential, so a process that merely reached the
  port cannot plant an image the cluster will then run. From inside the cluster, a Pod can push only
  with its own ServiceAccount token, in a namespace that opted in, under that namespace's prefix,
  with an RBAC grant to push, and it can never delete.

## Turning It Off

Drop the flag, or set `--registry-port 0`, and restart the server. The registry stops, and its
directory is left where it is; delete `<work-dir>/registry/` to reclaim the space.

## See Also

- [Images](images.md) is the full image reference: `k3sm build`, `image load`/`import`/`push`, and
  the deliberate differences from the `docker` verb of the same name.
- [What runs](what-runs.md) traces the path from a Dockerfile to a running Pod.
- [Linux images](vm-runtimeclass.md) covers the guest path.
