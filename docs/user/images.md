# Images

k3sm runs **OCI images** — it pulls them from registries, verifies their digests, unpacks their
layers and honours their config. What it does not run is a **Linux** image: a k3sm Pod is a native
Darwin process, so the payload inside the image must be a `darwin/arm64` executable. A Linux image
is refused at pull rather than started and left to die at `exec`.

If you are here to find out what you can run and how to get there, start with
[What runs](what-runs.md); this page is the reference behind it — the two workload conventions,
`k3sm build` and its accepted Dockerfile subset, `k3sm image load` / `import` / `push`, and every
deliberate difference from the Docker tool of the same name.

## Running a Native Workload Today

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

## Why Not Linux Images

A standard OCI image carries a **Linux** userland and expects a Linux kernel. The native path has
neither, so a Linux image cannot run as a native Darwin process — one of the headline divergences
in [Limitations](limitations.md). k3sm refuses it at pull, naming the platforms the image offers
and the one this node needs, rather than pulling it and failing opaquely at exec.

Note the distinction this section is *not* making: the objection is to **Linux**, not to OCI. The
image format, the registry protocol, tags, digests, pull policy and pull secrets all work normally —
see [What runs](what-runs.md). `linux/arm64` payloads are the province of the
[`vm` RuntimeClass](vm-runtimeclass.md) — see
[Limitations](limitations.md).

## Building an Image: `k3sm build`

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

**Accepted subset:** `FROM` (`scratch` or a registry reference), `COPY`, `ADD`, `ENV`, `ENTRYPOINT`, `CMD`, `WORKDIR`, `LABEL`,
`EXPOSE`. Everything else is refused with an error naming what was rejected — the parser never
guesses and never silently drops an instruction, because a dropped instruction produces an image
that looks built but is not what the recipe described.

> **A built image runs once it is in the store.** `k3sm build` writes a portable artifact to a
> path you name and nothing else — it does not touch the node's image store — so an
> `image: myapp:v1` Pod spec resolves only after you load that artifact (below). The artifact is
> equally usable with registries and other tools.

### Deliberate Differences From `docker build`

Each of these is a refusal or a documented gap, never a silent divergence:

| | k3sm build |
|---|---|
| `RUN` | **Rejected.** This builder packages files; it does not execute them. The RUN-capable path is the vm-backed builder below. |
| `FROM <ref>` | **Supported**, with two caveats. The base is fetched for `darwin/arm64` using the same credential chain as `k3sm image push`, and is **refused if it declares any other platform** — a `darwin/arm64` image built on a `linux/amd64` base is a self-consistent lie whose payload cannot execute. And a **tag**-pinned base is not reproducible: the tag can move, so the build says so and prints the base it used. Pin a digest if you want the guarantee. In practice bases are ones your own organisation published — see [What runs](what-runs.md) on why there is no public supply of `darwin` images. |
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

## Loading an Image Into the Store: `k3sm image load` / `k3sm image import`

`k3sm image load` ingests a `docker save` tarball. `k3sm image import` ingests a **tarred** OCI
image layout — what `docker buildx -o type=oci` writes, and what `k3sm build --format oci`
produces once you tar the directory.

```sh
# a docker-save tar, from k3sm build or from docker itself
k3sm build --tag myapp:v1 --output myapp.tar .
k3sm image load myapp.tar
docker save myapp:v1 -o from-docker.tar && k3sm image load from-docker.tar

# a tarred OCI layout
k3sm build --tag myapp:v1 --output ./layout --format oci .
tar -cf layout.tar -C ./layout .
k3sm image import layout.tar

k3sm image ls                       # what this node has recorded
```

The CLI opens your archive and streams it to the node's runtime daemon, which is the store's only
writer: it re-hashes every byte against the digest it is told to expect and records the reference
only after that check passes. Nothing is written to the store by the command itself.

**Loaded content is runnable.** Once the load succeeds and `k3sm image ls` shows the reference, a
Pod naming that reference runs on the default runtime: the node materializes the stored layers into
the pod's filesystem, so a command that lives inside the image is there to execute. Loading is
therefore both a way to stage content (an airgapped node, a pre-seeded cache) and a way to ship a
workload to a node without a registry.

One caveat, and it is the ordinary Kubernetes one: what a Pod does with a reference is decided by
its `imagePullPolicy`. `IfNotPresent` and `Never` serve the loaded reference with no registry
traffic; `Always` — which is what the apiserver defaults a `:latest` tag to — goes to a registry
regardless of what this node already holds. Tag the images you load with something other than
`latest`, or set the policy explicitly.

### Deliberate Differences From `docker load`

| | `k3sm image load` / `import` |
|---|---|
| Multiple tags on one image | **Rejected.** The store records one reference per loaded image, so a `docker save` of an image tagged twice is refused with both tags named rather than silently keeping one. Re-save with a single tag, or load it once per tag. |
| Multiple images in one archive | **Rejected**, for the same reason — one archive, one image. |
| Naming the image | Taken from the archive: `RepoTags` for docker-save, the `org.opencontainers.image.ref.name` annotation for an OCI layout. `--reference` overrides it, and is **required** for a layout that carries no annotation. |
| Format detection | None — the verb is the declaration. A layout handed to `load` (or a docker-save tar handed to `import`) is refused with an error naming the other verb, never sniffed. |
| Signatures & provenance | Loaded images are provenance-free by design. This path evaluates no signature policy; it is an operator-only surface, and what it stores is exactly what you handed it. |
| Requires a running daemon | Yes. The store is written by the node's runtime daemon over its local socket, so `load` works on an installed, running node and not on a bare directory. Its socket is readable only by the daemon's own account. |
| Deadline | `--timeout` defaults to 30m for these two verbs (they stream a whole archive) and 2m for the metadata verbs. |

### The Daemon Socket

Every subcommand except `push` is a client of the node's runtime daemon, which they reach
over a local unix socket. A running `k3sm server` (or `k3sm agent`) serves that socket as part of
normal bring-up, so on a standard install the commands work with no extra setup and no flags:

```sh
k3sm image ls
k3sm image df
```

The socket lives in the runtime root's `run` directory — `/var/lib/k3sm/run/runtimed.sock` on a
standard install, which is what `--socket` defaults to. A node started with a different runtime
root serves beside its own image store instead, so point the command at it:

```sh
k3sm image ls --socket /path/to/root/run/runtimed.sock
```

**Only the daemon's own account can use it.** The socket is created mode `600` inside a `700`
directory, so a dial from any other user is refused by the operating system before the command
sends anything. Pods are fenced off it separately, by the sandbox profile every Pod carries — they
share the daemon's account, so file permissions alone would not keep them out.

If a command reports that it cannot dial the socket, the node is not running, or it is running with
a different runtime root. `k3sm doctor` reports the former; the latter is a `--socket` away.

## Working With the Store: `pull`, `tag`, `untag`, `inspect`, `save`

These five verbs are the store's day-to-day surface. Each one is a client of the node's runtime
daemon — the daemon is the store's only writer, so nothing here walks the store directly.

```sh
k3sm image pull ghcr.io/org/app:v1            # warm the store ahead of a workload
k3sm image tag ghcr.io/org/app:v1 app:local   # give content a second name
k3sm image inspect app:local                  # digest, platform, config, layer sizes
k3sm image save app:local -o app.tar          # export a tarred OCI layout
k3sm image untag app:local                    # remove that name again
```

| verb | what it does |
|---|---|
| `pull <reference>` | Fetches the reference through the daemon's own puller — the same code path a Pod's pull takes, so every blob is re-hashed against its digest before it is recorded. Prints the digest it resolved to. `--platform os/arch[/variant]` picks which manifest of a multi-platform index to fetch; `--policy always\|if-not-present\|never` carries the ordinary Kubernetes pull-policy meanings. |
| `tag <digest\|reference> <new-reference>` | Records an **additional** name for content the node already holds. Contacts no registry and writes no blob. The target is named by digest — a reference you pass is resolved to one first, and the resolution is printed — because a tag that named another tag could be re-aimed by a concurrent pull. It never re-points an existing name: that is `untag`, then `tag`. |
| `untag <reference>` | Removes **one** name. `--digest` refuses the removal unless the name still resolves to that digest; `--platform` picks the entry when a reference has more than one, and an ambiguous untag is refused rather than guessed. |
| `inspect <reference\|digest>` | Reports the digest, the resolved platform, the creation time, entrypoint/cmd, user, working directory and each layer's size. `-o json` prints the daemon's raw response for scripting. Read-only: it contacts no registry and records nothing. |
| `save <reference> -o <file.tar>` | Streams the image out as a tarred OCI image layout — the `docker save` analog, and the exact inverse of `import`. The archive is checked against the digest and the byte count the daemon reports it sent, and a short one is discarded rather than left on disk. |

**Untag removes a name, not bytes.** No blob is unlinked by `untag`; content is reclaimed only by
`k3sm image prune`, which re-derives what is still reachable first. So untagging a name a running
Pod still uses leaves that Pod unharmed — and, conversely, a name you removed does not free any
space until you prune.

**A pulled image survives a prune.** `pull` and `tag` record the reference as something the node
holds on purpose, so a warmed-but-unused image is not reclaimed behind your back. Untag it when
you no longer want it, then prune.

## Pushing to a Registry: `k3sm image push`

`k3sm image push` uploads the image in an OCI layout directory to a registry reference, so a node
can pull it the ordinary way instead of being loaded one at a time.

```sh
k3sm build --tag registry.example.com/me/myapp:v1 --output ./layout --format oci .
k3sm image push ./layout registry.example.com/me/myapp:v1
```

The first argument is normally that layout directory. A first argument that is **no path on
disk** is taken as a reference in this node's own store instead: k3sm exports it with `save`,
verifies the export, and uploads the result.

```sh
k3sm image push myapp:v1 registry.example.com/me/myapp:v1
```

The credential is read at the moment of the upload and forgotten: from `K3SM_REGISTRY_TOKEN` if it
is set, otherwise from the docker config chain (`docker login`). k3sm writes no credential file and
never takes one on the command line, where it would land in shell history and process listings.

That closes the loop — **build → push → pull → run** — with the node pulling exactly as it would
from any registry: digests verified, `imagePullSecrets` honoured, multi-arch manifest lists read.

## Still on the Roadmap

- **A full build engine** — `k3sm build` with `RUN` support, via a managed BuildKit builder inside
  a `vm`-RuntimeClass micro-VM, so building and running containers needs only k3sm installed. It
  waits on the `vm` path's own release and lab validation — see [Limitations](limitations.md).

Registry pull is **not** on this list: it ships. An `image: ghcr.io/org/app:tag` Pod is pulled,
digest-verified and run with kubelet-faithful semantics — pull policy, pull-failure backoff and
multi-arch selection included. What the image must contain is a `darwin/arm64` payload.

## Next

- [What runs](what-runs.md) — what k3sm can run, and the whole path from Dockerfile to Pod.
- [Quickstart](quickstart.md) — run your first native Pod.
- [Limitations](limitations.md) — the adaptation requirement.
- [Storage](storage.md) — attaching persistent data.
