# Images

k3sm runs **OCI images**. It pulls them from registries, verifies their digests, unpacks their
layers and honours their config. What it does not run is a **Linux** image: a k3sm Pod is a native
Darwin process, so the payload inside the image must be a `darwin/arm64` executable. A Linux image
is refused at pull rather than started and left to die at `exec`.

If you are here to find out what you can run and how to get there, start with
[What runs](what-runs.md). This page is the reference behind it. It covers the two workload
conventions, `k3sm build` and what it does with a Dockerfile, `k3sm image load` / `import` /
`push`, and every deliberate difference from the `docker` verb of the same name.

## Running a Native Workload Today

There is no build step. Reference the binary directly in the Pod spec:

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

- **`image: native`** plus a `command` whose first element is an **absolute host path**. The
  binary runs in place, confined by the pod's Seatbelt profile like any other pod.
- **`image: /abs/path`** with **no `command`**. The image field itself is the host binary path.

On a disposable dev cluster, `k3sm dev load <path>` stages a binary and prints the matching
`image:` line for you.

Build the binary with your normal toolchain (`go build`, `clang`, …) targeting darwin/arm64. Pods
get the full treatment regardless of packaging: Seatbelt confinement, probes, volume mounts,
resource limits.

## Why Not Linux Images

A standard OCI image carries a **Linux** userland and expects a Linux kernel. The native path has
neither, so a Linux image cannot run as a native Darwin process. That is one of the headline
divergences in [Limitations](limitations.md). k3sm refuses it at pull, naming the platforms the
image offers and the one this node needs, rather than pulling it and failing opaquely at exec.

The refusal is about **Linux**, not about OCI. The image format, the registry protocol, tags,
digests, pull policy and pull secrets all work normally; see [What runs](what-runs.md).
`linux/arm64` payloads belong to the [`vm` RuntimeClass](vm-runtimeclass.md), described in
[Limitations](limitations.md).

## Building an Image: `k3sm build`

`k3sm build` builds a Dockerfile into an OCI image carrying a native darwin/arm64 payload. One that
only copies files in is packaged on the spot. Nothing executes; the builder copies files and writes
metadata. One with `RUN` builds on the cluster's build engine, which starts on first use; see
[Building images](builder.md).

```sh
k3sm build --tag myapp:v1 .                                  # into this node's image store
k3sm build --tag myapp:v1 --push .                           # and on to a registry
k3sm build --tag myapp:v1 --output myapp.tar .               # and into a file to carry
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

The native packager handles `FROM` (`scratch` or a registry reference), `COPY`, `ADD`, `ENV`,
`ENTRYPOINT`, `CMD`, `WORKDIR`, `LABEL` and `EXPOSE`. A Dockerfile of only these needs no cluster
and builds in about a second. `RUN` goes to the build engine instead. Anything else is refused with
an error naming what was rejected. The parser never guesses and never silently drops an
instruction, because a dropped instruction produces an image that looks built but is not what the
recipe described.

### Building a Linux Image

`darwin/arm64` is the default target. Name a Linux one and you get a Linux image, from any
Dockerfile:

```sh
k3sm build --tag myapp:v1 --platform linux/arm64 .
```

Run it with `runtimeClassName: vm`; see [`vm` RuntimeClass](vm-runtimeclass.md). A Linux target
always builds on the cluster's build engine, even for a Dockerfile that only copies files in. The
native packager copies host files into a darwin image and produces no other kind.

Several targets at once build an index:

```sh
k3sm build --tag myapp:v1 --platform linux/arm64,linux/amd64 --format oci --output ./layout .
```

`--output` (as `oci`) and `--push` carry every platform. This node's image store holds one image per
name, so it records the `linux/arm64` one, the platform this node's own guests run, and the build
summary says which it took. A multi-platform build with no `linux/arm64` in it is refused rather
than recorded under a name that would not start. `--format docker` is refused for one too, because a
`docker save` tarball holds a single image.

The engine's guest is `arm64` and registers no emulator, so a `RUN` step for another architecture is
refused by name before the engine starts. To get a `linux/amd64` build here, compile elsewhere and
`COPY` the binary in rather than `RUN` the toolchain.

Such an image is one you build **for other clusters**. k3sm nodes run no `amd64` payload today, on
either path; see [What runs](what-runs.md).

> **A built image is in this node's store when the build finishes.** `k3sm build` records it under
> the tag you gave, so an `image: myapp:v1` Pod spec resolves with no further step. `--output` also
> writes a portable artifact to a path you name, which is what you want for moving the image to
> another node or a registry, and it is equally usable with other tools.

### Deliberate Differences From `docker build`

Each of these is a documented difference:

| | k3sm build |
|---|---|
| `RUN` | **Supported, on the cluster.** The native packager copies files; it does not execute them, so a `RUN`-containing Dockerfile builds on the in-cluster engine, which `k3sm build` starts on first use. The image lands in the store under its tag either way; see [Building images](builder.md). |
| `FROM <ref>` | **Supported**, with two caveats. The base is fetched for `darwin/arm64` using the same credential chain as `k3sm image push`, and is **refused if it declares any other platform**, because a `darwin/arm64` image built on a `linux/amd64` base is a self-consistent lie whose payload cannot execute. And a **tag**-pinned base is not reproducible: the tag can move, so the build says so and prints the base it used. Pin a digest if you want the guarantee. In practice bases are ones your own organisation published; see [What runs](what-runs.md) on why there is no public supply of `darwin` images. |
| `ADD` | An exact alias of `COPY`. It does **not** fetch remote URLs and does **not** auto-extract archives; both are refused rather than silently downgraded. |
| `.dockerignore` | **Not implemented.** `COPY .` therefore includes `.git`, `.env` and anything else in the directory, so scope your `COPY` lines, or build from a clean tree. |
| `--platform` | Accepts `darwin/arm64` (the default, packaged natively) and Linux targets, which build on the engine; name several at once for a multi-platform index. Neither builder cross-compiles: a `darwin/arm64` image is refused any other value on the native path, and a `RUN` step for an architecture the engine's `arm64` guest cannot execute is refused by name. |
| Variables (`$VAR`), `ARG` | **Rejected.** No expansion is performed, and a literal `$` in a path would be an invisible divergence. |
| Build output | Recorded in this node's image store under the tag you gave. `--output` additionally writes a portable artifact (a docker-save tar, or an OCI layout with `--format oci`) to a path you name. `--push` additionally uploads it. The store recording happens in every case, including with `--push`, because what a k3sm build produces is an image this node can run. |
| Timestamps | Fixed, not wall-clock, so rebuilding the same context yields the same image digest. |
| File modes | Normalized to `0755` (if any execute bit is set) or `0644`. A `0600` source becomes world-readable in the image, and setuid/setgid/sticky bits are dropped. Preserving source modes would break reproducibility, since git records only the execute bit. |
| Ownership & xattrs | Every entry is `uid 0 / gid 0` with no user or group name, and no extended attributes, so the builder's account identity and macOS xattrs (including `com.apple.quarantine`) never reach the image. |
| Special files | Devices, FIFOs and sockets in the context are **refused**, not skipped. Symlinks are preserved as symlinks, but one whose target would escape the image root is refused. |
| `WORKDIR` | Sets the config's working directory but does **not** create it in the image. On `FROM scratch` there is no base filesystem to supply it, so add a `COPY` if the directory must exist. |

## Loading an Image Into the Store: `k3sm image load` / `k3sm image import`

`k3sm image load` ingests a `docker save` tarball. `k3sm image import` ingests a **tarred** OCI
image layout, which is what `docker buildx -o type=oci` writes and what `k3sm build --format oci`
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

The CLI opens your archive and streams it to the node's runtime daemon. The daemon is the store's
only writer, so nothing reaches the store from the command itself; it re-hashes every byte against
the digest it is told to expect and records the reference only after that check passes.

Loaded content is runnable. Once the load succeeds and `k3sm image ls` shows the reference, a Pod
naming that reference runs on the default runtime. The node materializes the stored layers into the
pod's filesystem, so a command that lives inside the image is there to execute. Loading is
therefore both a way to stage content (an airgapped node, a pre-seeded cache) and a way to ship a
workload to a node without a registry.

One ordinary Kubernetes rule still applies. What a Pod does with a reference is decided by its
`imagePullPolicy`. `IfNotPresent` and `Never` serve the loaded reference with no registry traffic.
`Always`, which is what the apiserver defaults a `:latest` tag to, goes to a registry regardless of
what this node already holds. Tag the images you load with something other than `latest`, or set
the policy explicitly.

### Deliberate Differences From `docker load`

| | `k3sm image load` / `import` |
|---|---|
| Multiple tags on one image | **Rejected.** The store records one reference per loaded image, so a `docker save` of an image tagged twice is refused with both tags named rather than silently keeping one. Re-save with a single tag, or load it once per tag. |
| Multiple images in one archive | **Rejected**, for the same reason. One archive holds one image. |
| Naming the image | Taken from the archive: `RepoTags` for docker-save, the `org.opencontainers.image.ref.name` annotation for an OCI layout. `--reference` overrides it, and is **required** for a layout that carries no annotation. |
| Format detection | None. The verb is the declaration. A layout handed to `load` (or a docker-save tar handed to `import`) is refused with an error naming the other verb, never sniffed. |
| Signatures & provenance | Loaded images carry no provenance. This path evaluates no signature policy, because it is an operator-only surface, and what it stores is exactly what you handed it. |
| Requires a running daemon | Yes. The store is written by the node's runtime daemon over its local socket, so `load` works on an installed, running node and not on a bare directory. Its socket is readable only by the daemon's own account. |
| Deadline | `--timeout` defaults to 30m for these two verbs (they stream a whole archive) and 2m for the metadata verbs. |

### The Daemon Socket

Every subcommand except `push` is a client of the node's runtime daemon, reached over a local unix
socket. A running `k3sm server` (or `k3sm agent`) serves that socket as part of normal bring-up, so
on a standard install the commands work with no extra setup and no flags:

```sh
k3sm image ls
k3sm image df
```

The socket lives in the runtime root's `run` directory, which on a standard install is
`/var/lib/k3sm/run/runtimed.sock`, the default for `--socket`. A node started with a different
runtime root serves beside its own image store instead, so point the command at it:

```sh
k3sm image ls --socket /path/to/root/run/runtimed.sock
```

Only the daemon's own account can use it. The socket is created mode `600` inside a `700`
directory, so a dial from any other user is refused by the operating system before the command
sends anything. Pods are fenced off it separately, by the sandbox profile every Pod carries. They
share the daemon's account, so file permissions alone would not keep them out.

If a command reports that it cannot dial the socket, the node is not running, or it is running with
a different runtime root. `k3sm doctor` reports the former; the latter is a `--socket` away.

## Working With the Store: `pull`, `tag`, `untag`, `inspect`, `save`

These five verbs are the store's day-to-day surface. Each one is a client of the node's runtime
daemon, and the daemon is the store's only writer, so nothing here walks the store directly.

```sh
k3sm image pull ghcr.io/org/app:v1            # warm the store ahead of a workload
k3sm image tag ghcr.io/org/app:v1 app:local   # give content a second name
k3sm image inspect app:local                  # digest, platform, config, layer sizes
k3sm image save app:local -o app.tar          # export a tarred OCI layout
k3sm image untag app:local                    # remove that name again
```

| verb | what it does |
|---|---|
| `pull <reference>` | Fetches the reference through the daemon's own puller, the same code path a Pod's pull takes, so every blob is re-hashed against its digest before it is recorded. Prints the digest it resolved to. `--platform os/arch[/variant]` picks which manifest of a multi-platform index to fetch; `--policy always\|if-not-present\|never` carries the ordinary Kubernetes pull-policy meanings. |
| `tag <digest\|reference> <new-reference>` | Records an **additional** name for content the node already holds. Contacts no registry and writes no blob. The target is named by digest, because a tag that named another tag could be re-aimed by a concurrent pull; a reference you pass is resolved to one first, and the resolution is printed. It never re-points an existing name. To move a name, `untag` it, then `tag` again. |
| `untag <reference>` | Removes **one** name. `--digest` refuses the removal unless the name still resolves to that digest; `--platform` picks the entry when a reference has more than one, and an ambiguous untag is refused rather than guessed. |
| `inspect <reference\|digest>` | Reports the digest, the resolved platform, the creation time, entrypoint/cmd, user, working directory and each layer's size. `-o json` prints the daemon's raw response for scripting. Read-only, so it contacts no registry and records nothing. |
| `save <reference> -o <file.tar>` | Streams the image out as a tarred OCI image layout, the `docker save` analog and the exact inverse of `import`. The archive is checked against the digest and the byte count the daemon reports it sent, and a short one is discarded rather than left on disk. |

Untag removes a name, not bytes. No blob is unlinked by `untag`; content is reclaimed only by
`k3sm image prune`, which re-derives what is still reachable first. Untagging a name a running Pod
still uses leaves that Pod unharmed, and a name you removed frees no space until you prune.

A pulled image survives a prune. `pull` and `tag` record the reference as content the node is meant
to keep, so a warmed-but-unused image is not reclaimed behind your back. Untag it when you no
longer want it, then prune.

## Pushing to a Registry: `k3sm image push`

`k3sm image push` uploads the image in an OCI layout directory to a registry reference, so a node
can pull it the ordinary way instead of being loaded one at a time.

```sh
k3sm build --tag registry.example.com/me/myapp:v1 --output ./layout --format oci .
k3sm image push ./layout registry.example.com/me/myapp:v1
```

A build you are pushing straight away needs neither step. `k3sm build --push` uploads through this
same path, after recording the image in the store:

```sh
k3sm build --tag registry.example.com/me/myapp:v1 --push .
k3sm build --tag myapp:v1 --push .                     # a bare tag: this node's own registry
```

The first argument is normally that layout directory. A first argument that is **no path on
disk** is taken as a reference in this node's own store instead, and k3sm exports it with `save`,
verifies the export, and uploads the result.

```sh
k3sm image push myapp:v1 registry.example.com/me/myapp:v1
```

The credential is read at the moment of the upload and forgotten. It comes from
`K3SM_REGISTRY_TOKEN` if that is set, otherwise from the docker config chain (`docker login`). k3sm
writes no credential file and never takes one on the command line, where it would land in shell
history and process listings.

That closes the loop of **build → push → pull → run**. The node pulls exactly as it would from any
registry: digests verified, `imagePullSecrets` honoured, multi-arch manifest lists read.

Registry pull needs nothing special either. An `image: ghcr.io/org/app:tag` Pod is pulled,
digest-verified and run with kubelet-faithful semantics, including pull policy, pull-failure
backoff and multi-arch selection. What the image must contain is a `darwin/arm64` payload.

## Next

- [Building images](builder.md), building a Dockerfile that runs commands, on the cluster.
- [What runs](what-runs.md), what k3sm can run and the whole path from Dockerfile to Pod.
- [Quickstart](quickstart.md), running your first native Pod.
- [Limitations](limitations.md), the adaptation requirement.
- [Storage](storage.md), attaching persistent data.
