# Building images

`k3sm build` builds any Dockerfile:

```sh
k3sm build -t myapp:dev .
```

The image lands in this node's image store under that tag, ready for a Pod to
name it.

## What happens under the hood

Nothing here changes what you type. It is worth knowing where the time goes.

A Dockerfile that only copies files in — `FROM`, `COPY`, `ENV`, `ENTRYPOINT` and
friends — is packaged natively, in about a second, with no cluster involved.

A Dockerfile with `RUN` steps executes Linux commands, and that needs a Linux
builder. `k3sm build` hands those builds to the cluster's build engine, starting
it on first use with one line of progress while it boots. The engine stays up
afterwards, so the next such build goes straight to it.

Same command, same tag, same store, either way.

## The engine

The engine is a long-lived [BuildKit](https://github.com/moby/buildkit) daemon
running in a Linux micro-VM.

It runs in a VM because k3sm pods are native macOS processes, and there is no
Linux there to run a Linux `RUN` step. So the engine runs under the `vm`
RuntimeClass — a Linux guest booted by Virtualization.framework. BuildKit runs as
root **inside that guest**, which is exactly where a build needs root, to mount
cgroups and create build containers. The VM is the isolation boundary, so this
costs no extra privilege on the host.

Starting it creates three objects in the `k3sm-builder` namespace: a build-cache
PersistentVolumeClaim, the engine Pod, and a ClusterIP Service.

Because it is a VM guest, the engine is only schedulable on a node that can boot
one. On a Mac that cannot, the engine Pod stays Pending and a `RUN`-containing
build cannot proceed — `k3sm builder status` says so.

## Managing the engine

`k3sm builder` is the engine's management surface. An ordinary build needs none
of it.

```sh
k3sm builder status     # engine state and, when ready, its buildx dial endpoint
k3sm builder up         # start it now, rather than on the first build that needs it
k3sm builder down       # stop it, keeping the build cache
k3sm builder delete     # stop it and remove the build cache — a full reset
```

`k3sm builder up` waits until a BuildKit worker registers, then prints:

```
builder engine ready: 1 worker(s), endpoint tcp://<cluster-ip>:1234
```

Pre-warming that way is worth it before a demo or a batch of builds. Otherwise
the first build that needs the engine starts it.

`down` stops the engine and keeps the cache, so the next start is warm. `delete`
removes everything the engine created — the cache PersistentVolumeClaim and the
`k3sm-builder` namespace included — and the next start rebuilds the cache from
scratch. Reach for `delete` when the cache is corrupt or you want to reclaim its
disk, and for `down` for the everyday stop.

## The build cache

The engine keeps its layer cache and BuildKit state on the `k3sm-builder`
PersistentVolumeClaim (40Gi by default; `k3sm builder up --cache-size <size>`).
`k3sm builder down` keeps it, so an incremental rebuild after a restart is fast.
For a cold cache, `k3sm builder delete` removes the PVC (and the namespace) for
you — the next start rebuilds the cache from scratch.

The cache lives on an ext4 image the guest loop-mounts on the claim, because
BuildKit's overlay snapshotter needs a real Linux filesystem and the host storage
cannot provide that shape directly.

## The builder image

By default the engine pulls the pinned upstream `moby/buildkit` image directly,
with no credentials. If you mirror it into your own registry, point at the mirror
instead:

```sh
k3sm builder up --mirror                  # k3sm's published mirror
k3sm builder up --mirror --pull-secret <name>   # a private mirror
```

The pinned reference is a digest, so the pulled image is byte-identical whichever
source serves it.

## Raw buildx against the engine

For a build `k3sm build` does not express — a multi-platform manifest, an exotic
exporter, a cache-import flag — `k3sm builder buildx` passes its arguments
straight through to [buildx](https://github.com/docker/buildx), already pointed
at the running engine:

```sh
k3sm builder buildx build -t myapp:dev -o type=oci,dest=out.oci .
```

Everything after `buildx` is buildx's own command line.

The engine also exposes BuildKit on a ClusterIP the Mac can dial directly (k3sm
makes Service ClusterIPs reachable from the host), so your own `buildx` remote
driver can point at the endpoint `k3sm builder status` prints:

```sh
buildx create --name k3sm --driver remote tcp://<cluster-ip>:1234 --use
buildx build --builder k3sm -o type=oci,dest=out.oci .
```

Either way, hand the exported OCI layout to `k3sm image` rather than using
`buildx --push` — k3sm's image tooling speaks to the node's own registry
credential and store:

```sh
k3sm image push out.oci localhost:<registry-port>/myapp:v1
```

## Limitations

- **`RUN` needs a VM-capable node.** A Dockerfile that only copies files in
  builds anywhere k3sm runs. One with `RUN` needs the engine, and the engine
  needs a Mac that can boot a Linux guest.
- **The engine is a single pod.** It is not replicated, and a build in flight
  does not survive the node going away.
- **buildx is a separate tool.** k3sm bundles the pieces it builds; `buildx`
  itself is the upstream release, pinned by version and checksum.
- **No port-forward driver.** Your own `buildx` reaches the engine over its
  Service ClusterIP, not a `kubectl port-forward` tunnel. If the ClusterIP is not
  host-reachable in your setup, that dial fails — check `k3sm builder status` for
  the endpoint it advertises.

## Next

- [Images](images.md) — the image store, and moving images between nodes and registries.
- [What runs](what-runs.md) — the whole path from Dockerfile to running Pod.
- [`vm` RuntimeClass](vm-runtimeclass.md) — the Linux-guest path the engine runs on.
