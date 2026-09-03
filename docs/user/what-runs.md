# Supported workloads

k3sm runs OCI images two ways, and you pick per Pod:

- **`darwin/arm64` images run as native Mac processes.** This is the default and the fastest path:
  no VM, no kernel to boot, and access to Metal, CoreML, `codesign` and Xcode.
- **`linux/arm64` images run in a Linux micro-VM.** One line in the Pod spec —
  `runtimeClassName: vm` — and an ordinary Linux image runs, unmodified. Any multi-arch image with
  an `arm64` variant qualifies, which is most published images. Validated single-node.

Either way the workflow is the one you already know: build, tag, push, pull, digests,
`imagePullPolicy`, `imagePullSecrets`. `k3sm build` builds both kinds.

The one shape k3sm runs on no path today is **`amd64`**. An `amd64`-only image does not start,
natively or under `vm`: the Linux guest would need in-guest translation, which is held for a later
release.

## Default Path

**An OCI image with a Mac binary inside.** This is the normal path:

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: myapp:v1        # a real image reference: registry, tag or digest
```

k3sm pulls it, verifies the digest, unpacks the layers, merges the image config (`ENV`,
`ENTRYPOINT`, `WORKDIR`, `CMD`) the way Kubernetes does, and executes the entrypoint as a native
Darwin process under a Seatbelt profile.

**A host binary, with no image at all.** For a quick loop, or a binary you do not want to package:

```yaml
      image: native
      command: ["/opt/myapp/bin/myapp", "--flag"]
```

See [Images](images.md) for both conventions in full.

## Linux Path

A stock image from Docker Hub — `nginx`, `postgres`, `redis` — carries a Linux userland and expects a
Linux kernel. k3sm gives it one. Add `runtimeClassName: vm` and the image runs in its own Linux
micro-VM on the same node, under the same Kubernetes semantics:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  runtimeClassName: vm        # <- the whole requirement
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  containers:
    - name: web
      image: nginx:alpine     # linux/arm64
```

The `nodeSelector` and `tolerations` stanza is on every k3sm Pod, `vm` or not — each node carries the
`k3sm.io/provider:NoSchedule` taint. The `vm`-specific part is the one `runtimeClassName` line.

`kubectl logs`, `exec -it` with a real terminal, `attach`, probes, PersistentVolumeClaims, cluster
DNS and ClusterIP Services all work there; [`vm` RuntimeClass](vm-runtimeclass.md) is the full page,
measured on real hardware.

Two facts to plan around. Each Pod gets its own VM, so it costs a boot and a VM's memory where a
native process costs neither — the native path stays the fast one for anything you can compile for
the Mac. And the image must have an `arm64` variant: an `amd64`-only image does not start.

A platform mismatch — a Linux image on the default path, an `amd64`-only image on the `vm` path —
surfaces as a Pod in **`ProviderFailed`** with a `ProviderCreateFailed` event naming both sides:

```
no image manifest matches a runnable platform: want [linux/arm64/v8], image provides [linux/amd64]
```

k3sm decides this before it starts anything. A Linux container runtime handed the wrong architecture
starts the container and lets it die with a format error that names nothing; being told which
platforms the image offers, and which one the node needs, is what you can act on.

## From a Dockerfile to a Running Pod

The whole loop, with nothing left out. Build a `darwin/arm64` binary first — `go build`, `clang`,
whatever you normally use — then:

```sh
# 1. package it
cat > Dockerfile <<'DOCKERFILE'
FROM scratch
COPY dist/myapp /usr/local/bin/myapp
ENV LOG_LEVEL=info
ENTRYPOINT ["/usr/local/bin/myapp"]
DOCKERFILE

# 2. build it — the image is in this node's store when this returns
k3sm build --tag myapp:v1 .

# 3. run it
kubectl run myapp --image=myapp:v1
kubectl logs myapp
```

That is the whole loop on one node. To move the image off it, pick a sink — they compose, and the
store recording happens in every case:

```sh
k3sm build --tag registry.example.com/me/myapp:v1 --push .   # to a registry you name
k3sm build --tag myapp:v1 --push .                           # to this node's own registry
k3sm build --tag myapp:v1 --output myapp.tar .               # to a file, for `k3sm image load`
```

For a Linux workload, name the platform and run it with `runtimeClassName: vm`:

```sh
k3sm build --tag myapp:v1 --platform linux/arm64 .
```

`k3sm build` takes any Dockerfile. One that only copies files in is packaged on the spot, with no
cluster involved; one with `RUN` builds on the cluster's build engine, which starts on first use —
see [Building images](builder.md). `FROM` takes `scratch` or a registry reference; a named base is
fetched for `darwin/arm64` and refused if it declares any other platform. Every deliberate
difference from `docker build` is in [Images](images.md).

Pushing a bare tag needs the node's own registry running — it is off unless you pass
`--registry-port` (or use `k3sm dev`, which turns it on for you). It is worth the extra step when you
want the *real* pull path: a Pod referencing `localhost:<port>/…` honors `imagePullPolicy: Always`,
notices a moved tag, and fails the way a remote registry would, none of which `k3sm image load` can
reproduce. See [Node-local registry](registry.md).

## What Carries Over From Docker and Kubernetes

Almost all of it:

| | |
|---|---|
| Tags and digests | Yes. Pin a digest and you get exactly those bytes. |
| Private registries | Yes — `imagePullSecrets` on the Pod, resolved at pull. |
| `imagePullPolicy` | Yes — `Always`, `IfNotPresent`, `Never`, with upstream meanings. |
| Multi-arch images | The manifest list is read and the entry for the path's platform selected — `darwin/arm64` natively, `linux/arm64` under `runtimeClassName: vm`. Almost no published image carries a `darwin` entry (see below); most carry `linux/arm64`, which is what the `vm` path selects. |
| `docker save` / `docker buildx -o type=oci` | Yes — `k3sm image load` and `k3sm image import` ingest both. |
| `RUN` in a Dockerfile | Yes — `k3sm build` builds it on the cluster's build engine, a Linux builder that starts on first use. See [Building images](builder.md). |
| `FROM <linux image>` | Yes, for a Linux build — `k3sm build --platform linux/arm64` resolves the base on the engine. On the native darwin path the base must be `darwin/arm64`. |
| `linux/arm64` images | Yes — `runtimeClassName: vm`, one line in the Pod spec. |
| `amd64` images | Not yet, on either path. An `amd64`-only image does not start; a multi-arch image with an `arm64` variant runs under `vm` by selecting that variant. |

One footgun worth stating twice, because it is the one people hit: the apiserver defaults a
`:latest` tag to `imagePullPolicy: Always`, so a `:latest` image you loaded locally will still be
fetched from a registry. Tag with something else, or set the policy explicitly.

## Where darwin Images Come From

There is no supply of them. You build them.

That is worth stating plainly, because "k3sm runs OCI images" can otherwise be
read as "k3sm runs the images you can already `docker pull`". Checked against
Docker Hub:

| image | platforms published | `darwin`? |
|---|---|---|
| `alpine`, `nginx`, `postgres`, `redis` | 8 each, every one `linux/*` | none |
| `golang` | 9 — `linux` **and `windows`** | none |

`golang` is the informative row: the OCI `os` field really does carry non-Linux
values in the wild, and Windows containers are published. Darwin ones are not,
anywhere — macOS has no container primitive to build them on, so the ecosystem
never formed.

So the practical shape of this is: the **format, the registries and the tooling**
are the ones you know, and **darwin content** is yours to produce. `k3sm build`
packages a Mac binary into an ordinary OCI image and `--push` puts it in your
registry; nodes pull it the ordinary way. An existing public image is a Linux
image, and that is what `runtimeClassName: vm` is for.

## Summary

The default path runs **Mac-native workloads** — including ones that need Metal, CoreML, `codesign`
or Xcode, which no Linux VM can give you — with Kubernetes semantics and the OCI toolchain around
them. Unmodified **`linux/arm64` images run** on the same cluster, one `runtimeClassName: vm` line
away, at the cost of a VM per Pod — and most published images carry an `arm64` variant. `amd64`
payloads run on no path today; if that is your workload, [Limitations](limitations.md) has the full
picture.
