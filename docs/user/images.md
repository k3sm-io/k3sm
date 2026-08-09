# Images

k3sm runs Pods as native Darwin processes, so its workloads are **not OCI Linux container
images** — they are native arm64 executables. This page covers how to reference a workload
**today**, how to **build** an image with `k3sm build`, and the rest of the OCI image path
(registry pull, `k3sm image load`) that is on the [roadmap](../../ROADMAP.md).

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

## Building an image: `k3sm build`

`k3sm build` packages a native darwin/arm64 payload into an OCI image from a COPY-only Dockerfile.
It executes nothing — it copies files and writes metadata.

```sh
k3sm build --tag myapp:v1 --output myapp.tar .
docker load -i myapp.tar          # the tarball is a standard docker-save archive
k3sm build --tag myapp:v1 --output ./layout --format oci .   # or an OCI layout directory
```

```dockerfile
FROM scratch
COPY dist/myapp /usr/local/bin/myapp
ENV LOG_LEVEL=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/myapp"]
```

**Accepted subset:** `FROM scratch`, `COPY`, `ADD`, `ENV`, `ENTRYPOINT`, `CMD`, `WORKDIR`, `LABEL`,
`EXPOSE`. Everything else is refused with an error naming what was rejected — the parser never
guesses and never silently drops an instruction, because a dropped instruction produces an image
that looks built but is not what the recipe described.

> **A built image is not yet runnable on k3sm.** The ingest and materialize path is still on the
> roadmap below, so an `image: myapp:v1` Pod spec will **not** resolve to what you just built. Today
> `k3sm build` produces a portable artifact for registries and other tools; to run a workload on
> k3sm now, use the native conventions above.

### Deliberate differences from `docker build`

Each of these is a refusal or a documented gap, never a silent divergence:

| | k3sm build |
|---|---|
| `RUN` | **Rejected.** This builder packages files; it does not execute them. The RUN-capable path is the vm-backed builder below. |
| `FROM <ref>` | **Rejected** — `FROM scratch` only. Basing on a pulled image arrives with the registry-pull path. |
| `ADD` | An exact alias of `COPY`. It does **not** fetch remote URLs and does **not** auto-extract archives; both are refused rather than silently downgraded. |
| `.dockerignore` | **Not implemented.** `COPY .` therefore includes `.git`, `.env` and anything else in the directory — scope your `COPY` lines, or build from a clean tree. |
| `--platform` | Accepts only `darwin/arm64`. The builder copies host files verbatim and does not cross-compile, so any other value would declare a platform the bytes do not satisfy. |
| Variables (`$VAR`), `ARG` | **Rejected.** No expansion is performed, and a literal `$` in a path would be an invisible divergence. |
| Build output | Written to a path you name (`--output`). There is no default sink and no push; nothing is written to k3sm's shared image store. |
| Timestamps | Fixed, not wall-clock — rebuilding the same context yields the same image digest. |
| File modes | Normalized to `0755` (if any execute bit is set) or `0644`. A `0600` source becomes world-readable in the image, and setuid/setgid/sticky bits are dropped. Preserving source modes would break reproducibility, since git records only the execute bit. |
| Ownership & xattrs | Every entry is `uid 0 / gid 0` with no user or group name, and no extended attributes — the builder's account identity and macOS xattrs (including `com.apple.quarantine`) never reach the image. |
| Special files | Devices, FIFOs and sockets in the context are **refused**, not skipped. Symlinks are preserved as symlinks, but one whose target would escape the image root is refused. |
| `WORKDIR` | Sets the config's working directory but does **not** create it in the image. On `FROM scratch` there is no base filesystem to supply it, so add a `COPY` if the directory must exist. |

## On the roadmap: the rest of the OCI-native image path

Planned, in order (see the [roadmap](../../ROADMAP.md) for positioning):

- **`k3sm image load` / `k3sm image import`** — ingest docker-save tarballs and OCI layouts (the
  `docker buildx -o type=oci` output) into k3sm's image store, so a built image becomes runnable.
- **Registry images natively** — `image: ghcr.io/org/app:tag` pulled, verified, and run with
  kubelet-faithful semantics (imagePullPolicy, pull-failure backoff, multi-arch selection).
- **A full build engine** — `k3sm build` with `RUN` support via a managed BuildKit builder inside
  a `vm`-RuntimeClass micro-VM, so building and running containers needs only k3sm installed.

Until those land, the commands in *this* list do not exist — the native conventions above are the
supported way to run a workload.

## Next

- [quickstart.md](quickstart.md) — run your first native Pod.
- [limitations.md](limitations.md) — the adaptation requirement.
- [storage.md](storage.md) — attaching persistent data.
