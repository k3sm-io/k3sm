# What runs on k3sm

The short answer: **OCI container images whose payload is a native `darwin/arm64`
executable**. The workflow around them is the one you already know — build, tag, push, pull,
digests, `imagePullPolicy`, `imagePullSecrets`. What changes is the *contents* of the image, not
how you handle it.

The equally short second answer: **a Linux image does not run on the default path.** Not "runs
slowly", not "runs with a flag" — a `linux/amd64` or `linux/arm64` image is refused when k3sm tries
to pull it. That is the trade this project makes on purpose, and this page is here so you can tell
in a minute whether it is a trade you want.

## What runs

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

See [images.md](images.md) for both conventions in full.

## What does not run, and why

A stock image from Docker Hub — `nginx`, `postgres`, `redis` — carries a Linux userland and expects
a Linux kernel. A k3sm Pod is a Darwin process; there is no Linux kernel under it. So the image is
**refused at pull** with an error naming the platforms the image offers and the one this node needs.

That refusal is deliberate. The alternative, which is what a Linux container runtime does when it is
handed the wrong architecture, is to pull the image, start the container, and let it die at `exec`
with a format error that names nothing. Failing at pull tells you what is wrong while you can still
act on it.

Linux payloads are the job of the [`vm` RuntimeClass](vm-runtimeclass.md), which runs a micro-VM per
Pod. **It does not run a Pod yet** — read that page before planning around it.

## From a Dockerfile to a running Pod

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

k3sm build --tag myapp:v1 --output myapp.tar .

# 2a. put it on this node directly...
k3sm image load myapp.tar
k3sm image ls

# 2b. ...or push it to a registry and let the node pull it
k3sm build --tag registry.example.com/me/myapp:v1 --output ./layout --format oci .
k3sm image push ./layout registry.example.com/me/myapp:v1

# 3. run it
kubectl run myapp --image=myapp:v1
kubectl logs myapp
```

`k3sm build` accepts a COPY-only Dockerfile subset — it packages files, it does not execute them, so
`RUN` is refused. `FROM` takes `scratch` or a registry reference; a named base is fetched for
`darwin/arm64` and refused if it declares any other platform. The full subset, and every deliberate
difference from `docker build`, is in [images.md](images.md).

## What carries over from Docker and Kubernetes

Almost all of it:

| | |
|---|---|
| Tags and digests | Yes. Pin a digest and you get exactly those bytes. |
| Private registries | Yes — `imagePullSecrets` on the Pod, resolved at pull. |
| `imagePullPolicy` | Yes — `Always`, `IfNotPresent`, `Never`, with upstream meanings. |
| Multi-arch images | Yes — the manifest list is read and the `darwin/arm64` entry selected. An image with no such entry is refused. |
| `docker save` / `docker buildx -o type=oci` | Yes — `k3sm image load` and `k3sm image import` ingest both. |
| `RUN` in a Dockerfile | **No.** It needs a Linux builder, which needs the `vm` path. |
| `FROM <linux image>` | **No.** Refused: the base must be `darwin/arm64`. |

One footgun worth stating twice, because it is the one people hit: the apiserver defaults a
`:latest` tag to `imagePullPolicy: Always`, so a `:latest` image you loaded locally will still be
fetched from a registry. Tag with something else, or set the policy explicitly.

## The honest summary

k3sm is not a way to run the containers you already have. It is a way to run **Mac-native
workloads** — including ones that need Metal, CoreML, `codesign` or Xcode, which no Linux VM can
give you — with Kubernetes semantics and the OCI toolchain around them. If your workload is a Linux
binary you cannot rebuild, this is the wrong tool today, and
[limitations.md](limitations.md) says so at greater length.
