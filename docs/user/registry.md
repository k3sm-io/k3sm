# The cluster registry

Every k3sm server runs a small **OCI registry**, the cluster's one image store. You push a locally
built image to it and a Pod pulls it back through the ordinary Kubernetes image path, including
`imagePullPolicy: Always`, the digest index, and real pull failures.

Inside the cluster it has one name, on every node and in every namespace:

```
registry-k3sm:6450
```

That address serves **HTTPS**, under a certificate issued by the cluster's own CA, the same CA
every Pod already trusts for the Kubernetes API. On the Mac you keep using `localhost:6450`.

It is **on by default** on port 6450. Choose another loopback port with `--registry-port`, or turn
it off with `--registry-port 0`:

```sh
k3sm server --registry-port 0
```

`k3sm dev` clusters run it on a per-instance port, so a disposable dev cluster is always a push
target.

## Why It Exists

Putting an image straight into a node's store is the fastest way to try something, but it steps
around every image semantic Kubernetes defines: the node already has the
content, so `imagePullPolicy: Always` pulls nothing, a moved tag is never noticed, and a broken
reference fails at a different place than it would in a real cluster.

A registry puts those semantics back. The image travels the same way it would from a public
registry. This one happens to live on your server Mac, and `k3sm build`, `k3sm image load` and
`k3sm image import` record there for that reason.

## Finding It

The cluster publishes its own address. k3sm writes the standard `local-registry-hosting` ConfigMap
into `kube-public`:

```sh
kubectl get configmap local-registry-hosting -n kube-public \
  -o jsonpath='{.data.localRegistryHosting\.v1}'
```

```yaml
help: https://k3sm.io/docs/user/registry/ (the in-cluster name serves HTTPS; trust
  the cluster CA, a Pod's service-account ca.crt)
host: registry-k3sm:6450
hostFromClusterNetwork: registry-k3sm:6450
hostFromContainerRuntime: localhost:6450
```

`host` and `hostFromClusterNetwork` are the address for anything running **inside the cluster**.
`hostFromContainerRuntime` is the address the node's runtime pulls from on the server.

On a single Mac that hosts no Linux guests there is nothing listening off loopback, so no in-cluster
name is published: `host` is `localhost:6450` and `hostFromClusterNetwork` is absent.

`k3sm status` shows the registry's row: the loopback port, the in-cluster name, that it serves
HTTPS, and when the serving certificate expires.

## The Name Must Carry the Port

Write `registry-k3sm:6450/app:v1`, never `registry-k3sm/app:v1`. An image reference whose first part
has no port and no dot is a Docker Hub repository by the OCI rule, so `registry-k3sm/app` is pulled
from Docker Hub, not from this cluster.

## Pushing From the Mac

`k3sm build`, `k3sm image load`, `k3sm image import` and `k3sm image push` write to the cluster
registry with a push token for the `builder` ServiceAccount, minted through your kubeconfig for each
command (see [Who can mint a token](#who-can-mint-a-token)). You need no credential on the command
line:

```sh
k3sm build --tag myapp:v1 .                               # recorded as registry-k3sm:6450/myapp:v1
k3sm build --tag myapp:v1 --format oci --output ./myapp-layout .
k3sm image push ./myapp-layout registry-k3sm:6450/myapp:v1
```

A bare tag, `registry-k3sm:6450/...` and `localhost:6451/...` all name the cluster registry. Where
the upload goes depends on the Mac:

- On the server it goes to the push gate on loopback, `localhost:6451`. The gate checks the token
  and hands the write to the registry. It always runs, with or without workers or Linux guests.
- On a worker it goes to the server's cluster address on port 6450, the endpoint of the
  `registry-k3sm` Service.

Both serve HTTPS under a certificate from the cluster CA that names `registry-k3sm`, and k3sm
verifies it against the CA in your kubeconfig. The gate's port is the registry port plus one: 6451
with the default `--registry-port 6450`.

A Mac with no kubeconfig stops with an error that names the fix (see [On a worker](#on-a-worker)).

Reference the image like any other:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: registry-k3sm:6450/myapp:v1
      imagePullPolicy: Always
```

The Mac does not resolve `registry-k3sm`, and does not need to: every node maps that name to the
registry itself.
From another Mac, see [Reaching It From Another Mac](#reaching-it-from-another-mac).

`k3sm image tag` writes as you, through the push gate with your builder token, like a push.
`inspect` and `save` read the registry's own loopback listener anonymously, so they run on the
server, as any account. `untag` deletes, and the push gate never forwards a delete, so it needs the
server's per-boot credential, `<work-dir>/registry/push-credential.json` (mode `0600`): run it on the
server as root, `sudo k3sm image --work-dir /var/lib/k3sm/server untag <tag>`. That credential is
regenerated on every server start. An account that can read it uses it for all four verbs.

## Pulling

Pulls are anonymous. The node's runtime pulls with no credential at all, which is what lets a Pod
reference an image here with nothing configured.

The registry also holds copies of public images. `k3sm image pull docker.io/library/nginx:1`
copies the image to `registry-k3sm:6450/docker.io/library/nginx:1`, and a node whose pull of the
public name cannot reach that registry at all (a DNS failure, a refused connection, a timeout)
pulls the copy instead. An answer from the public registry, such as a 404 or a certificate the
node does not trust, is never replaced by the copy. See
[Naming and Reading Images](images.md#naming-and-reading-images-tag-untag-inspect-save-pull).

Pushes are authenticated. Together those two are the whole access model. Anyone who can reach the
registry can read the images this cluster runs, and only a user holding a builder token (see
[Pushing With Other Tools](#pushing-with-other-tools)), or a Pod the cluster's RBAC allows to push (see [Pushing From Inside a Pod](#pushing-from-inside-a-pod)),
can put a new one there.

## One Store for the Cluster

The registry runs on the **server**. With several servers, the first server, the one the others
joined, publishes `registry-k3sm`; the others run their own registry for local pushes and publish
nothing. Their own Pods pull `registry-k3sm:6450` from the first server's registry, like every
agent's do, never from the local one. Every node in the cluster reaches the same store under the same name, so an image pushed
once is pullable from any Mac, and every layer is verified against its digest exactly as it is on a
pull from a public registry.

Each node learns where that store is from the `registry-k3sm` EndpointSlice in `k3sm-registry`: the
first server's address and the port its registry listens on. A server started with another
`--registry-port` therefore still serves every reference to `registry-k3sm:6450`, because the port
in a reference never changes. A node reads the EndpointSlice when it starts, waiting up to 30 seconds
for a server that is restarting; a node that started while the server was down for longer maps the
name only after it restarts too.

The direction matters. The node running the Pod pulls from the server, so the server has to be up
and on the cluster network at the moment the pull happens. If it is off, the pull fails, and the Pod
reports the usual image-pull error.

## Using It From Inside a Pod

A process running **inside** a Pod, say a build running in the cluster, uses `registry-k3sm:6450`.
It is an ordinary Kubernetes Service in the `k3sm-registry` namespace:

```sh
kubectl get svc,endpointslice -n k3sm-registry
```

Cluster DNS answers the short name from every namespace, and each of these names the same Service:

```
registry-k3sm:6450
registry-k3sm.k3sm-registry:6450
registry-k3sm.k3sm-registry.svc:6450
registry-k3sm.k3sm-registry.svc.cluster.local:6450
<the Service's ClusterIP>:6450
```

The registry's certificate carries every one of those names and addresses, so a client verifies it
whichever spelling it dialled.

Trust the cluster CA. It is the Pod's service-account `ca.crt`, mounted at
`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` in a Pod that mounts its token (the
default), and the `ca.crt` key of the `kube-root-ca.crt` ConfigMap in every namespace. Each tool
takes it differently:

```sh
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# crane reads the system trust store, which Go takes from SSL_CERT_FILE on Linux,
# so this works in a Linux (vm) Pod
SSL_CERT_FILE=$CA crane ls registry-k3sm:6450/team/app

# oras takes the CA as a flag
oras pull --ca-file "$CA" registry-k3sm:6450/team/app:v1
```

For buildkit, the push is made by `buildkitd`, so the CA goes in its configuration file
(`buildkitd.toml`):

```toml
[registry."registry-k3sm:6450"]
  ca = ["/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"]
```

Plain HTTP is refused. A client told to use HTTP (`--plain-http`, `--insecure`, or a `localhost`
special case) gets `400 Bad Request`; drop those flags.

A vm Pod needs the server to be running guests or to be on a mesh. The address the Service sends a
caller to is the server's cluster-network address, which is the mesh address on a multi-machine
cluster and otherwise the guest network's gateway. A single Mac with neither publishes no Service
at all.

## Pushing From Inside a Pod

A Pod can push to the registry with its own ServiceAccount token. No shared password is handed out:
the Pod presents a token the cluster minted for it, and the registry asks the cluster whether that
ServiceAccount may push that repository. Reads stay anonymous, as everywhere else.

A push is allowed only when all of these hold:

- The token is a projected ServiceAccount token minted for the audience `k3sm-registry`. The Pod's
  default API token is refused.
- The Pod's namespace carries the label `k3sm.io/registry-push`, whose value is the namespace's own
  name. That name is the namespace's repository prefix, so each prefix belongs to one namespace.
- The repository sits under that prefix, at least one level down. In the namespace `team`,
  `team/app` and `team/tools/app` are allowed, and `team`, `teamx/app` and `other/app` are not.
- The ServiceAccount is bound to the `k3sm:registry-pusher` ClusterRole in that namespace.

Deleting is never allowed from a Pod, whatever the grant. Delete images from the Mac.

Opting a namespace in is two steps. Labelling a namespace is a cluster-admin act. Any value other
than the namespace's own name is refused, so two namespaces can never share a prefix and overwrite
each other's images. To fix a namespace labelled with another value, relabel it:
`kubectl label namespace <ns> k3sm.io/registry-push=<ns> --overwrite`.

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

Log in with HTTP Basic: the password is the token and the username is ignored. Push to
`registry-k3sm:6450`, trusting the cluster CA as shown above. See
[What the token is exposed to](#what-the-token-is-exposed-to) before you rely on it.

```sh
REG=registry-k3sm:6450
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
TOKEN=$(cat /var/run/secrets/registry/token)

# crane (a Linux Pod: Go reads SSL_CERT_FILE there)
export SSL_CERT_FILE=$CA
crane auth login "$REG" -u pod -p "$TOKEN"
crane push ./app.tar "$REG/team/app:v1"

# oras
oras push --ca-file "$CA" -u pod -p "$TOKEN" "$REG/team/app:v1" ./artifact.txt

# buildctl: credentials from the Docker config file, the CA from buildkitd.toml (above)
mkdir -p ~/.docker
printf '{"auths":{"%s":{"auth":"%s"}}}' "$REG" "$(printf 'pod:%s' "$TOKEN" | base64 | tr -d '\n')" \
  > ~/.docker/config.json
buildctl build --frontend dockerfile.v0 --local context=. --local dockerfile=. \
  --output "type=image,name=$REG/team/app:v1,push=true"
```

### What the token is exposed to

The token is encrypted on every hop. The registry's in-cluster address terminates TLS, so a token
sent to `registry-k3sm:6450` is never on the wire in cleartext, on the guest network, on the mesh,
or through the Service proxy, and a client that verifies the certificate against the cluster CA
cannot be handed to an impostor that lacks a certificate from that CA. What remains is the token's
lifetime: anything that reads the token file inside the Pod can push into that namespace's prefix
until the token expires. Ask for the shortest `expirationSeconds` the job allows, and keep untrusted
workloads out of namespaces that can push.

### Refusals

A refused push says why, in an OCI error body. Every status a push can get:

| Status | Meaning |
|---|---|
| `400` | The request path, query or request target is malformed, or the request was plain HTTP. |
| `401` | No token, a malformed token, an expired or otherwise invalid token, or a token minted for another audience. The response carries a Basic `WWW-Authenticate` challenge. |
| `403` | The caller is authenticated but refused: the token is not a ServiceAccount's, the namespace has not opted in (no label, or a label value other than the namespace's own name; the message gives the `kubectl label` command that fixes it), the repository is outside the prefix, or RBAC denies the push. |
| `405` | A delete, or any other write shape the registry never takes from a Pod. |
| `429` | Token checks are rate-limited, and each client address has its own share of connections, requests and pushes, so one busy client slows itself rather than every other caller; wait for the `Retry-After` interval and retry. |
| `502` | The registry behind the gate is unreachable. |
| `503` | The cluster API is unreachable, or the gate has no identity to ask it with. Retry. |

## Pushing With Other Tools

The cluster has one push identity for people: the `builder` ServiceAccount in the `k3sm-registry`
namespace. Every server creates it on start and binds it, cluster-wide, to `k3sm:registry-pusher`,
so a token for it may push any repository. You do not share a password. Each push token is minted
through your own kubeconfig, and you can mint one only if your kubeconfig may create tokens for
that ServiceAccount.

Print a token, valid for an hour unless you ask for another lifetime:

```sh
k3sm registry token
k3sm registry token --duration 20m
```

The lifetime is at least 10 minutes and at most 24 hours; a lifetime outside that range is refused
rather than adjusted. The command makes the same call as:

```sh
kubectl create token builder -n k3sm-registry --audience k3sm-registry
```

To let docker, buildx, crane and oras push with nothing else in the loop, write the token into your
docker config:

```sh
k3sm registry login
```

That writes the entry for the address a tool on this Mac reaches the registry at: `localhost:6451`
on the server, or the server's cluster address with port 6450 on a worker. It goes in
`$DOCKER_CONFIG/config.json`, or `~/.docker/config.json`, with mode `0600`, and everything else in
the file is kept. `login` also writes the cluster CA to `certs.d/<host:port>/ca.crt` beside that
file (mode `0644`), where docker and buildx look for a registry's CA, and prints each path it wrote.
Run it again when the token expires.

```sh
crane copy alpine:3.20 localhost:6451/alpine:3.20     # on the server
```

If your docker config keeps credentials in a credential store (Docker Desktop does), `login` stops
and tells you to feed the store instead:

```sh
k3sm registry token | docker login localhost:6451 -u builder --password-stdin
```

A tool that does not read `certs.d` needs the cluster CA another way. It is the CA your kubeconfig
embeds:

```sh
kubectl config view --raw --minify \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > k3sm-ca.crt
```

### Who can mint a token

- The admin kubeconfig can. `sudo k3sm install` merges it into the installing user's
  `~/.kube/config` on the server, so `k3sm registry token` works there right after the install.
- Anyone else needs a grant. k3sm ships the `k3sm:registry-builder-token` Role in `k3sm-registry`,
  which allows only `create` on `serviceaccounts/token` for the name `builder` and `get` on the
  `registry-k3sm` EndpointSlice, and binds it to nobody. Bind it with a RoleBinding in `k3sm-registry`. Because it is a namespaced Role, no binding
  can make it reach a ServiceAccount named `builder` in another namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: registry-builder-token
  namespace: k3sm-registry
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: k3sm:registry-builder-token
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: alice
```

A token is a push credential for the whole cluster registry until it expires. Keep it out of shell
history and logs, and ask for the shortest lifetime the job allows.

Treat the `k3sm-registry` namespace as part of the push credential. Anyone who can create pods there,
or create `serviceaccounts/token` there, can act as the `builder` ServiceAccount and push any
repository. The built-in `edit` and `admin` roles both allow that, so a RoleBinding of either in
`k3sm-registry` is a push grant for the whole registry. Grant nothing in that namespace beyond the
`k3sm:registry-builder-token` binding above.

On the server, `k3sm registry login` stores the token for `localhost:6451`. On a Mac that other
users also log in to, a process of theirs could listen on that port while the server is stopped,
and a tool that does not verify the cluster CA would send it the token. On a shared Mac, skip
`login` and pipe `k3sm registry token` into the tool's `--password-stdin` when you push.

### On a worker

A worker writes no user kubeconfig, so `k3sm build`, `image load`, `import` and `push`, and
`registry token` and `login`, stop there with an error that names the fix. Copy the admin
kubeconfig from the server and write one:

```sh
k3sm kubeconfig --server https://<server>:6444 --certificate-authority <ca> --write
```

The worker finds the server's registry address by getting the `registry-k3sm` EndpointSlice in
`k3sm-registry` by name. The admin kubeconfig may, and so may a user bound to the
`k3sm:registry-builder-token` Role, which grants `get` on that one slice and no `list`, so such a
user can log in and push from a worker with no other grant.

## Reaching It From Another Mac

The in-cluster name does not resolve on a Mac, and k3sm does not make it resolve. A tool running on
a Mac that is not the server can reach the registry through a NodePort instead. It is off by
default. Turn it on with `--registry-node-port` on the server, choosing a port in the NodePort range
(30000 to 32767), and restart the server:

```sh
k3sm server --registry-node-port 30650
```

On an installed server, add the flag to the server daemon's arguments; every later install carries
it over (see [Server flags across a reinstall](install.md#server-flags-across-a-reinstall)).

The `registry-k3sm` Service then becomes a NodePort Service, and the registry answers at that port
on every node:

```
<node-address>:30650
```

It is the same registry behind the same front. It serves HTTPS under the cluster CA, a plain-HTTP
request is refused, and every write goes through the same checks as a push from a Pod. On a single
Mac with no mesh and no Linux guests no Service is published, so there is no NodePort either; use
`localhost:6450` there.

Dial the **server** by its name:

```
https://<server hostname>:30650
```

With the NodePort on, the registry's certificate also names the server as another Mac knows it: the
host's name, its `.local` name (both `<name>.local` and `<name>` for a Mac that calls itself
`<name>.local`), and the InternalIP addresses on the server's Node object. A tool that trusts the
cluster CA then verifies the registry with no extra flags. Take the CA from the cluster:

```sh
kubectl get configmap kube-root-ca.crt -n default -o jsonpath='{.data.ca\.crt}' > k3sm-ca.crt
curl --cacert k3sm-ca.crt https://<name>.local:30650/v2/_catalog
```

The server's InternalIP is its mesh address on a mesh server, so a bare LAN address is not in the
certificate; use the hostname or `.local` name, which resolve to the LAN address. Dial the server
rather than another node: the other nodes forward the port too, but their names are not in the
certificate. When the server's address or name changes, the certificate is re-issued within five
minutes.

What this changes:

- Reads become anonymous to everything that can reach a node on that port. With LAN access on
  (`k3sm network lan on`), that is every network the Mac is on, so anyone there can list and pull
  every image the cluster runs. With LAN access off, NodePorts bind only this Mac and the mesh.
- Writes still need a token. A push needs a ServiceAccount token for the audience `k3sm-registry`,
  which `k3sm registry token` prints, under the same rules as
  [a push from a Pod](#pushing-from-inside-a-pod). An anonymous push is answered `401`.
- Every client that comes in through the NodePort reaches the registry from the node's own address:
  the Service proxy does not keep the client's source address, and `externalTrafficPolicy: Local`
  does not change that. So all of them share one client's share of the [rate limits](#refusals),
  and one LAN client sending many requests can make every other one get `429`s. Turn the flag on
  only on a LAN you trust.

If another Service already holds the port, the server logs an error, publishes the Service with
its cluster address only, and tries the NodePort again every five minutes until the port is free.

Drop the flag and restart the server to close the port again; the Service goes back to a cluster
address only. Do this before you install an earlier k3sm release on the server: an earlier server
does not change the Service back, so the port would stay open.

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

- The registry binds loopback only. Its own listener binds `127.0.0.1`, serves plain HTTP there, and
  that is not configurable; a non-loopback bind is rejected at startup rather than served.
- The cluster reaches it through one front, over HTTPS only. A separate listener on the server's
  cluster network address and its guest network's gateway, and never a wildcard bind, terminates
  TLS and passes reads through and checks every write. The same front also listens on
  `127.0.0.1:6451` for the server's own Mac. It does not expose the registry to any other
  network your Mac is on, and a plain-HTTP request to it is refused.
- The certificate comes from the cluster CA. It is minted in the server's memory at start, its key
  is never written to disk, and it is replaced before it expires. No new trust anchor is involved:
  every Pod already holds the CA as its service-account `ca.crt`.
- Reads are anonymous. Anything that can reach the registry can list and pull the images the
  cluster runs. Do not treat it as a private store for content the host's other users or the
  cluster's other workloads should not see.
- Writes are authenticated. A push from a Mac needs a token for the `builder` ServiceAccount
  minted through a kubeconfig allowed to (see [Pushing With Other Tools](#pushing-with-other-tools)),
  so a process that merely reached the port cannot plant an image the cluster will then run. From inside the cluster,
  a Pod can push only with its own ServiceAccount token, in a namespace that opted in, under that
  namespace's prefix, with an RBAC grant to push, and it can never delete. The token is encrypted on
  every hop; see [What the token is exposed to](#what-the-token-is-exposed-to).

## Turning It Off

Set `--registry-port 0` and restart the server. The registry stops, the `registry-k3sm` Service is
removed, and the registry's directory is left where it is; delete `<work-dir>/registry/` to reclaim
the space.

## See Also

- [Images](images.md) is the full image reference: `k3sm build`, `image load`/`import`/`push`, and
  the deliberate differences from the `docker` verb of the same name.
- [What runs](what-runs.md) traces the path from a Dockerfile to a running Pod.
- [Linux images](vm-runtimeclass.md) covers the guest path.
