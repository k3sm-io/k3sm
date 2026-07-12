# Images

k3sm runs Pods as native Darwin processes, so its workloads are **not OCI Linux container
images** — they are native arm64 executables. This page covers how to reference a workload
**today**, and the OCI image path (registry pull, `k3sm image load`, `k3sm build`) that is on the
[roadmap](../../ROADMAP.md).

## Running a native workload today

Reference the binary directly in the Pod spec — there is no build step:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: native            # sentinel: command[0] is an absolute host binary
      command: ["/opt/myapp/bin/myapp", "--flag"]
```

Two equivalent conventions:

- **`image: native`** plus a `command` whose first element is an **absolute host path** — the
  binary runs in place, confined by the pod's Seatbelt profile like any other pod.
- **`image: /abs/path`** with **no `command`** — the image field itself is the host binary path.

On a disposable dev cluster, `k3sm dev load <path>` stages a binary and prints the matching
`image:` line for you.

Build the binary with your normal toolchain (`go build`, `clang`, …) targeting darwin/arm64. Pods
get the full treatment regardless of packaging: Seatbelt confinement, probes, volume mounts,
resource limits.

## Why not Docker/OCI Linux images

A standard OCI image carries a **Linux** userland and expects a Linux kernel. The native path has
neither, so a Linux image cannot run as a native Darwin process — one of the headline divergences
in [limitations.md](limitations.md). Linux images are the province of the EXPERIMENTAL
[`vm` RuntimeClass](vm-runtimeclass.md).

## On the roadmap: the OCI-native image path

Planned, in order (see the [roadmap](../../ROADMAP.md) for positioning):

- **`k3sm image load` / `k3sm image import`** — ingest docker-save tarballs and OCI layouts (the
  `docker buildx -o type=oci` output) into k3sm's image store.
- **`k3sm build`** — package a native darwin/arm64 binary from a COPY-only Dockerfile subset
  (`FROM scratch` + `COPY` + `ENTRYPOINT`; `RUN` is rejected until the vm-backed builder lands).
- **Registry images natively** — `image: ghcr.io/org/app:tag` pulled, verified, and run with
  kubelet-faithful semantics (imagePullPolicy, pull-failure backoff, multi-arch selection).
- **A full build engine** — `k3sm build` with `RUN` support via a managed BuildKit builder inside
  a `vm`-RuntimeClass micro-VM, so building and running containers needs only k3sm installed.

Until those land, the commands in this section do not exist — the native conventions above are the
supported path.

## Next

- [quickstart.md](quickstart.md) — run your first native Pod.
- [limitations.md](limitations.md) — the adaptation requirement.
- [storage.md](storage.md) — attaching persistent data.
