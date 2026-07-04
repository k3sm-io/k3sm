# Images

k3sm runs Pods as native Darwin processes, so its images are **not OCI Linux container images**. They
are native process bundles built and referenced through k3sm's own image path.

## Building

```sh
k3sm build -t myapp .
```

`k3sm build` produces a native image k3sm can launch as a macOS process (an APFS-cloned root plus the
executable and its entrypoint metadata). The result is referenced by tag in a Pod spec's
`image:` field, the same way you would reference any image.

## Why not OCI / Docker images

A standard OCI image carries a **Linux** userland and expects a Linux kernel, cgroups, and namespaces.
k3sm has none of those. A raw upstream Linux image cannot run as a native Darwin process, so **workloads
must be adapted** to the native image model — this is one of the headline divergences in
[limitations.md](limitations.md).

## Referencing images in a Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: myapp        # a k3sm native image tag
```

## What to expect

- Images are local to the node's image store; there is no assumption of a Linux registry pull path for
  the native model.
- Because there are no containers, image-level Linux features (user namespaces, seccomp profiles baked
  into the image, multi-arch Linux manifests) do not apply — see [concepts.md](concepts.md).

## Next

- [quickstart.md](quickstart.md) — build-and-run in context.
- [limitations.md](limitations.md) — the adaptation requirement.
- [storage.md](storage.md) — attaching persistent data.
