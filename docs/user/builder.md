# The build engine

`k3sm build` packages a **COPY-only** image natively — no daemon, no cluster. That
covers a large class of images: a compiled binary plus its assets, a static site,
a config bundle. If a Dockerfile only assembles files, use `k3sm build` and stop
reading here — see [Images](images.md).

A Dockerfile that **runs** commands (`RUN apt-get …`, `RUN cargo build …`) needs a
real builder. k3sm provides one **in the cluster**: a long-lived
[BuildKit](https://github.com/moby/buildkit) daemon in a Linux micro-VM, driven by
`buildx`. This page is about that engine.

## Why it runs in a VM

k3sm pods are native macOS processes; there is no Linux there to run a Linux
`RUN` step. The build engine therefore runs under the `vm` RuntimeClass — a Linux
guest booted by Virtualization.framework. BuildKit runs as root **inside that
guest**, which is exactly where a build needs root (to mount cgroups and create
build containers). The VM is the isolation boundary, so this is safe without any
extra privilege on the host.

Because it is a VM guest, the engine is only schedulable on a node that can boot
one. On a Mac that cannot, `k3sm builder up` will leave the pod Pending — check
`k3sm builder status`.

## Enable it

```sh
k3sm builder up
```

This creates three objects in the `k3sm-builder` namespace — a build-cache
PersistentVolumeClaim, the engine Pod, and a ClusterIP Service — and waits until a
BuildKit worker registers. When it is ready:

```
builder engine ready: 1 worker(s), endpoint tcp://<cluster-ip>:1234
```

Check on it any time:

```sh
k3sm builder status
```

Stop it (the **cache is kept**, so the next `up` starts warm):

```sh
k3sm builder down
```

For a **full reset** — remove the engine *and* the build cache (and the
`k3sm-builder` namespace) — use `delete`. The next `up` rebuilds the cache from
scratch:

```sh
k3sm builder delete
```

The distinction is deliberate: `down` **stops** the engine and keeps the cache for
a fast warm rebuild; `delete` is the **full reset** — everything the engine
created is gone. Reach for `delete` when the cache is corrupt or you want to
reclaim its disk; reach for `down` for the everyday stop.

## The buildx driver

The engine exposes BuildKit on a ClusterIP the Mac can dial directly (k3sm makes
Service ClusterIPs reachable from the host). A `buildx` remote driver points at
the endpoint `k3sm builder status` prints:

```sh
buildx create --name k3sm --driver remote tcp://<cluster-ip>:1234 --use
buildx build --builder k3sm -o type=oci,dest=out.oci .
```

Export an **OCI layout** and load or push it with `k3sm image` rather than using
`buildx --push` — k3sm's image tooling speaks to the node's own registry
credential and store:

```sh
k3sm image push out.oci localhost:<registry-port>/myapp:v1
```

> Driving `k3sm build` end to end against the engine for a RUN-containing
> Dockerfile is landing as a follow-up. Until then, use the `buildx` driver above
> against the endpoint; COPY-only `k3sm build` is unaffected and needs no engine.

## The build cache

The engine keeps its layer cache and BuildKit state on the `k3sm-builder`
PersistentVolumeClaim (40Gi by default; `k3sm builder up --cache-size <size>`).
`k3sm builder down` keeps it, so an incremental rebuild after a restart is fast.
For a cold cache, `k3sm builder delete` removes the PVC (and the namespace) for
you — the next `up` rebuilds the cache from scratch.

The cache lives on an ext4 image the guest loop-mounts on the claim — a real Linux
filesystem is what BuildKit's overlay snapshotter needs, and the host storage
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

## Limitations

- **RUN needs the engine.** Only COPY-only Dockerfiles build with no cluster.
  Anything with `RUN` needs `k3sm builder up` first.
- **The engine needs a VM-capable node.** A Mac that cannot boot a Linux guest
  cannot host the engine.
- **No port-forward driver.** The engine is reached over its Service ClusterIP,
  not a `kubectl port-forward` tunnel. If the ClusterIP is not host-reachable in
  your setup, the `buildx` dial will fail — check `k3sm builder status` for the
  endpoint it advertises.
- **buildx is a separate tool.** k3sm bundles the pieces it builds; `buildx`
  itself is the upstream release, pinned by version and checksum.
- **The engine is a single pod.** It is not replicated; a build in flight does not
  survive the node going away.
