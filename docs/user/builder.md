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

## Choosing the platform

Unset, `--platform` follows the Dockerfile: a COPY-only one is packaged as a
`darwin/arm64` image, and one the engine builds produces `linux/arm64`.

Naming a Linux target builds a Linux image from any Dockerfile:

```sh
k3sm build -t myapp:v1 --platform linux/arm64 .
```

That goes to the engine even for a Dockerfile that only copies files in, because
the native packager copies host files into a darwin image and produces no other
kind. Run it with `runtimeClassName: vm` — see
[`vm` RuntimeClass](vm-runtimeclass.md).

Several targets at once build an index:

```sh
k3sm build -t myapp:v1 --platform linux/arm64,linux/amd64 --format oci -o out .
```

`--output` (as `oci`) and `--push` carry every platform. This node's image store
holds one image per name, so it records the `linux/arm64` one — what the node's
own guests run — and the summary says so.

The engine's guest is `arm64` and registers no emulator, so `RUN` steps for
another architecture are refused by name before the engine starts. Copy a
cross-compiled binary in instead, which is how a `linux/amd64` image is built
here:

```dockerfile
FROM scratch
COPY dist/myapp-amd64 /usr/local/bin/myapp
ENTRYPOINT ["/usr/local/bin/myapp"]
```

That image is one you build for other clusters: k3sm nodes run no `amd64`
payload today, on either path. See [What runs](what-runs.md).

## Getting the image out

The image is in this node's store when the build finishes, which is everything a
Pod on this node needs. `--push` sends it on to a registry in the same command:

```sh
k3sm build -t myapp:v1 --push .               # this node's own registry
k3sm build -t ghcr.io/org/myapp:v1 --push .   # a registry you name
```

A tag that names a registry goes to that registry. A bare tag goes to this node's
registry on `localhost:<registry-port>` — the same place a bare `image: myapp:v1`
in a Pod spec resolves from — and the store keeps your original bare name either
way. The node's registry is started with `--registry-port`
([Node-local registry](registry.md)); with none running, a bare tag and `--push`
is an error naming both ways forward.

The store recording happens first. When the upload then fails — a refused
credential, an unreachable host — the build exits non-zero and says the image is
in the store, so what you retry is the push.

The two-step form is still there, and is what you want for an image you built
earlier or received as a layout:

```sh
k3sm build -t myapp:v1 --output ./layout --format oci .
k3sm image push ./layout localhost:6450/myapp:v1
```

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

A build you drive through `k3sm build` needs neither step: `--push` uploads it
through that same credential, and the store recording is already done.

## Limitations

- **`RUN` needs a VM-capable node.** A Dockerfile that only copies files in
  builds anywhere k3sm runs. One with `RUN` needs the engine, and the engine
  needs a Mac that can boot a Linux guest.
- **The engine is a single pod.** It is not replicated, and a build in flight
  does not survive the node going away.
- **`RUN` executes as the guest's architecture, `arm64`.** The engine registers
  no emulator, so a `RUN` step for another architecture is refused by name. A
  foreign-architecture image is built by copying a cross-compiled binary in.
- **buildx is a separate tool.** k3sm bundles the pieces it builds; `buildx`
  itself is the upstream release, pinned by version and checksum.
- **The bundled buildx runs with a k3sm-owned `HOME`,** so it cannot mistake a
  Docker Desktop install for the build backend and end every build with a
  `docker-desktop://` link. Your registry credentials are unaffected — k3sm
  points `DOCKER_CONFIG` at the same config directory buildx would have used —
  but a flag that reads something else out of your home directory (`--cache-to
  type=s3`, which resolves `~/.aws`) needs that tool's own environment variable
  instead.
- **No port-forward driver.** Your own `buildx` reaches the engine over its
  Service ClusterIP, not a `kubectl port-forward` tunnel. If the ClusterIP is not
  host-reachable in your setup, that dial fails — check `k3sm builder status` for
  the endpoint it advertises.

## Next

- [Images](images.md) — the image store, and moving images between nodes and registries.
- [What runs](what-runs.md) — the whole path from Dockerfile to running Pod.
- [`vm` RuntimeClass](vm-runtimeclass.md) — the Linux-guest path the engine runs on.
