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
k3sm build --tag myapp:v1 .                                  # into the cluster registry
k3sm build --tag ghcr.io/org/myapp:v1 --push .               # or to a registry you name, only
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

The cluster registry, `--output` (as `oci`) and `--push` carry every platform. This node's cache
holds the `linux/arm64` one, the platform this node's own guests run, and the build summary says
so. A multi-platform build with no `linux/arm64` in it is refused rather than recorded under a name
that would not start here. `--format docker` is refused for one too, because a
`docker save` tarball holds a single image.

The engine's guest is `arm64` and registers no emulator, so a `RUN` step for another architecture is
refused by name before the engine starts. To get a `linux/amd64` build here, compile elsewhere and
`COPY` the binary in rather than `RUN` the toolchain.

Such an image is one you build **for other clusters**. k3sm nodes run no `amd64` payload today, on
either path; see [What runs](what-runs.md).

> **A built image is in the cluster registry when the build finishes.** `k3sm build` records it as
> `registry-k3sm:6450/<repository>:<tag>`, so `--tag myapp:v1` becomes
> `registry-k3sm:6450/myapp:v1`, and a Pod on any node can name it with no further step. The build
> then pulls it into this node's cache through the runtime's ordinary pull, so a Pod here with
> `imagePullPolicy: Never` finds it too. `--output` also writes a portable artifact to a path you
> name, and it is equally usable with other tools.

A tag names the cluster registry when it has no registry part (`myapp:v1`), when it spells the flat
name (`registry-k3sm:6450/myapp:v1`), or when it names this node's registry on loopback
(`localhost:<port>/myapp:v1`, on the port the server's registry listens on). A tag that names any
other registry is refused, and the error names both ways forward: tag it
`registry-k3sm:6450/<repository>:<tag>` to keep it in the cluster, or add `--push` to send it to
the registry it names. With `--push` the image goes to that registry only. The cluster registry
keeps no copy of it, so a Pod that names `ghcr.io/org/myapp:v1` pulls it from ghcr.io.

The recording uploads to this server's registry with its push credential, so it needs the
registry running (see [The cluster registry](registry.md)). A node without one fails the build and
names both ways forward.

`--no-record` builds without recording. The build writes `--output`, uploads with `--push`, or
both, and never contacts the node's runtime daemon or the cluster registry for the recording, so it
needs no root. It is refused without `--output` or `--push`. To record the image afterwards, run a
separate step as root: `sudo k3sm image load myapp.tar` for a docker-save tar, or tar an OCI layout
and `sudo k3sm image import` the tar (see "Loading an Image Into the Registry" below).

```sh
k3sm build --tag myapp:v1 --no-record --output myapp.tar .   # a file only, as your own user
sudo k3sm image load myapp.tar                               # into the registry, when you want it
```

### Build History: `k3sm build ls`

Every `k3sm build` is recorded in your build history when it starts and again when it finishes,
whichever path built it. The history keeps the newest 200 builds, in `~/.k3sm/builds`, readable by
you alone.

```sh
k3sm build ls            # a table, newest first
k3sm build ls -o json    # the records as a JSON array, newest first
```

The table shows each build's ID, status (`running`, `succeeded`, `failed` or `cancelled`), tag,
platform, engine (`native` or `engine`), start time and duration. The JSON records add the absolute
Dockerfile and context paths, the finish time, the digest of the image recorded in this node's
store on success, and the error text on failure, clipped to 1 KiB. A build interrupted before it
finished stays `running`. If the history cannot be written, the build prints a warning and goes on.

Each build also keeps its output, the build engine's progress included, beside its record. The log
is capped at 16 MiB and goes when its record goes. It holds plain text: in a terminal the engine's
interactive progress view still draws as usual, and the log keeps the same output with the terminal
control sequences removed, so a build run in a terminal records each redraw of the view one after
another.

```sh
k3sm build logs <id>      # print a build's stored output
k3sm build logs -f <id>   # and keep printing while it runs; returns when it finishes
k3sm build cancel <id>    # stop a running build
k3sm build rm <id>        # remove a finished build and its log from the history
```

`k3sm build cancel` asks the build's own process to stop. On the build engine that interrupts
buildx, which cancels the build's job in BuildKit; buildx that has not exited 30 seconds later is
killed. The build is then recorded `cancelled`, with its finish time, and the build command exits
with an error. A finished build is refused. A record left `running` by a build that was killed
before it could finish has no process to stop, so `cancel` marks it `cancelled`. `k3sm build rm`
refuses a running build: cancel it first. A build is reached by its full ID, as `k3sm build ls`
shows it.

`k3sm build prune` and the `k3sm builder` commands talk to the build engine on the cluster, and
need no `sudo`: as yourself they use your own kubeconfig with the context `sudo k3sm install`
merged into it, the same one `k3sm kubectl` uses. See
[managing the engine](builder.md#managing-the-engine).

### Deliberate Differences From `docker build`

Each of these is a documented difference:

| | k3sm build |
|---|---|
| `RUN` | **Supported, on the cluster.** The native packager copies files; it does not execute them, so a `RUN`-containing Dockerfile builds on the in-cluster engine, which `k3sm build` starts on first use. The image is recorded in the cluster registry either way; see [Building images](builder.md). |
| `FROM <ref>` | **Supported**, with two caveats. The base is fetched for `darwin/arm64` using the same credential chain as `k3sm image push`, and is **refused if it declares any other platform**, because a `darwin/arm64` image built on a `linux/amd64` base is a self-consistent lie whose payload cannot execute. And a **tag**-pinned base is not reproducible: the tag can move, so the build says so and prints the base it used. Pin a digest if you want the guarantee. In practice bases are ones your own organisation published; see [What runs](what-runs.md) on why there is no public supply of `darwin` images. |
| `ADD` | An exact alias of `COPY`. It does **not** fetch remote URLs and does **not** auto-extract archives; both are refused rather than silently downgraded. |
| `.dockerignore` | **Not implemented.** `COPY .` therefore includes `.git`, `.env` and anything else in the directory, so scope your `COPY` lines, or build from a clean tree. |
| `--platform` | Accepts `darwin/arm64` (the default, packaged natively) and Linux targets, which build on the engine; name several at once for a multi-platform index. Neither builder cross-compiles: a `darwin/arm64` image is refused any other value on the native path, and a `RUN` step for an architecture the engine's `arm64` guest cannot execute is refused by name. |
| Variables (`$VAR`), `ARG` | **Rejected.** No expansion is performed, and a literal `$` in a path would be an invisible divergence. |
| Build output | Recorded in the cluster registry as `registry-k3sm:6450/<repository>:<tag>`, then pulled into this node's cache. `--output` additionally writes a portable artifact (a docker-save tar, or an OCI layout with `--format oci`) to a path you name. A tag that names another registry is refused unless `--push` uploads it there, and then it is not recorded in the cluster registry. `--no-record` skips the recording, needs no root, and requires `--output` or `--push`. |
| Timestamps | Fixed, not wall-clock, so rebuilding the same context yields the same image digest. |
| File modes | Normalized to `0755` (if any execute bit is set) or `0644`. A `0600` source becomes world-readable in the image, and setuid/setgid/sticky bits are dropped. Preserving source modes would break reproducibility, since git records only the execute bit. |
| Ownership & xattrs | Every entry is `uid 0 / gid 0` with no user or group name, and no extended attributes, so the builder's account identity and macOS xattrs (including `com.apple.quarantine`) never reach the image. |
| Special files | Devices, FIFOs and sockets in the context are **refused**, not skipped. Symlinks are preserved as symlinks, but one whose target would escape the image root is refused. |
| `WORKDIR` | Sets the config's working directory but does **not** create it in the image. On `FROM scratch` there is no base filesystem to supply it, so add a `COPY` if the directory must exist. |

## Loading an Image Into the Registry: `k3sm image load` / `k3sm image import`

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

k3sm image ls                       # what this node's cache holds
```

Both verbs record the archive's image in the cluster registry, the cluster's one image store, as
`registry-k3sm:6450/<repository>:<tag>`: `myapp:v1` becomes `registry-k3sm:6450/myapp:v1`. A load
overwrites whatever that tag named before. The CLI reads your archive as you and uploads it with this
server's push credential, through the same path as `k3sm image push`; `--work-dir` names the
control plane's state directory when it is not the one your user resolves. A tarred layout whose one
entry is a multi-platform index is recorded as that whole index.

An archive that names another registry, such as a `docker save` of `ghcr.io/org/app:v1`, is
refused. Pass `--reference registry-k3sm:6450/org/app:v1` (or any cluster name) to record it in the
cluster. The two verbs have no `--push`: to send an image to another registry, push it there from an
OCI layout with `k3sm image push`.

The verb then pulls the image into this node's cache through the runtime's ordinary pull, which
re-hashes every blob against its digest before it records anything. A Pod on any node can name the
registry reference, and a Pod on this node with `imagePullPolicy: Never` finds it in the cache.

### Deliberate Differences From `docker load`

| | `k3sm image load` / `import` |
|---|---|
| Multiple tags on one image | **Rejected.** A load records one reference per image, so a `docker save` of an image tagged twice is refused with both tags named rather than silently keeping one. Re-save with a single tag, or load it once per tag. |
| Multiple images in one archive | **Rejected**, for the same reason. One archive holds one image. |
| Naming the image | Taken from the archive: `RepoTags` for docker-save, the `org.opencontainers.image.ref.name` annotation for an OCI layout. `--reference` overrides it, and is **required** for a layout that carries no annotation. |
| Format detection | None. The verb is the declaration. A layout handed to `load` (or a docker-save tar handed to `import`) is refused with an error naming the other verb, never sniffed. |
| Signatures & provenance | Loaded images carry no provenance. This path evaluates no signature policy, because it is an operator-only surface, and what it records is exactly what you handed it. |
| Requires a running node | Yes. The upload needs this server's registry and its push credential, and the cache pull goes through the node's runtime daemon over its local socket, which is readable only by the daemon's own account. |
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
a different runtime root. `k3sm doctor` reports the former in its daemon rows, with the command that
repairs it under `Next:`; the latter is a `--socket` away.

`kubectl get node <name> -o json` lists the node's 50 largest images under `status.images`; anyone who can read nodes can read the names. The node refreshes the list with its status, and keeps the last list it read when its image index cannot be read, so the list can go stale until the index reads again.

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
k3sm build --tag registry.example.com/me/myapp:v1 --no-record --output ./layout --format oci .
k3sm image push ./layout registry.example.com/me/myapp:v1
```

A build you are pushing straight away needs neither step. `k3sm build --push` uploads through this
same path. A tag that names the cluster registry is already there once the build records it, so
`--push` adds nothing for it:

```sh
k3sm build --tag registry.example.com/me/myapp:v1 --push .   # to that registry only
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

`K3SM_REGISTRY_TOKEN` is used the way `docker login` uses a password: k3sm presents it with the
username in `K3SM_REGISTRY_USER` (`token` if that is unset), and a registry that issues
short-lived tokens, as ghcr.io and most hosted public registries do, trades it for a token
scoped to the repository being pushed. The exchange goes to the token realm the registry names,
which can be a different host from the registry itself, so the credential is sent there.

For ghcr.io, use a classic personal access token with the `write:packages` scope, or a
fine-grained token with write access to packages. ghcr ignores the username for a token, so
`K3SM_REGISTRY_USER` can stay unset:

```sh
K3SM_REGISTRY_TOKEN="$(cat ~/.config/ghcr-token)" k3sm image push ./layout ghcr.io/me/myapp:v1
```

Neither the token you set nor the token the registry issues is ever printed or logged.

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
