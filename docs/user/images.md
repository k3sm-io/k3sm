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
> `imagePullPolicy: Never` finds it too. An account that cannot reach this node's runtime (its socket
> is root-only) gets one warning instead, and the first Pod that runs the image pulls it. `--output` also writes a portable artifact to a path you
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
| Timestamps | Fixed, not wall-clock. Rebuilding the same context with the same k3sm release yields the same image digest. Layers are gzip-compressed, and a different Go release can compress the same bytes differently, so a k3sm upgrade can change the digest while the image's content (its config and layer contents) stays the same. |
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

k3sm image ls                       # the registry's images and where each is cached
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
| Deadline | None by default for these two verbs, or for `push`, `pull` and `save`: each registry request is abandoned only after 2m without moving a byte, so a slow transfer that keeps moving is never cut, and Ctrl-C cancels. The pull the node's daemon does itself reports no progress, so it is bounded at 30m. An explicit `--timeout` sets an overall deadline. The metadata verbs default to a 2m deadline. |

### The Daemon Socket

`pull`, `load`, `import`, `prune` and `migrate` are clients of the node's runtime daemon (and so is
`push` when its source is a reference in this node's cache), reached over a local unix socket.
`tag`, `untag`, `inspect`, `save`, `ls` and `df` read or write the cluster registry and never dial
it. A running `k3sm server` (or `k3sm agent`) serves that socket as part of normal bring-up, so
on a standard install the commands work with no extra setup and no flags:

```sh
k3sm image prune
k3sm image pull ghcr.io/org/app:v1
```

The socket lives in the runtime root's `run` directory, which on a standard install is
`/var/lib/k3sm/run/runtimed.sock`, the default for `--socket`. A node started with a different
runtime root serves beside its own image store instead, so point the command at it:

```sh
k3sm image prune --socket /path/to/root/run/runtimed.sock
```

Only the daemon's own account can use it. The socket is created mode `600` inside a `700`
directory, so a dial from any other user is refused by the operating system before the command
sends anything. Pods are fenced off it separately, by the sandbox profile every Pod carries. They
share the daemon's account, so file permissions alone would not keep them out.

If a command reports that it cannot dial the socket, the node is not running, or it is running with
a different runtime root. `k3sm doctor` reports the former in its daemon rows, with the command that
repairs it under `Next:`; the latter is a `--socket` away.

`kubectl get node <name> -o json` lists the node's 50 largest images under `status.images`; anyone who can read nodes can read the names. The node refreshes the list with its status, and keeps the last list it read when its image index cannot be read, so the list can go stale until the index reads again.

## Naming and Reading Images: `tag`, `untag`, `inspect`, `save`, `pull`

`tag`, `untag`, `inspect` and `save` act on the cluster registry, where `build`, `load` and `import`
record images. They never contact the node's runtime daemon, and they run as you, with no `sudo`,
except `untag`:

- `inspect` and `save` read the server's registry anonymously, as every read of it is. They run on
  the server.
- `tag` writes as you, through the push gate with a token minted through your kubeconfig, the same
  identity `k3sm image push` and `k3sm build --push` use, so it also runs from a worker.
- `untag` deletes, and the push gate never forwards a delete, so it needs the server's per-boot
  push credential: run it on the server as root, `sudo k3sm image --work-dir /var/lib/k3sm/server
  untag <tag>`.

An account that can read that credential (root, with `--work-dir` naming the control plane's state
directory) uses it for every verb here. A name may be written bare, as `registry-k3sm:6450/...`, or as
this node's `localhost:<port>/...`; a name that points at another registry is refused. `pull` is the
one verb here that fills this node's cache.

```sh
k3sm image tag myapp:v1 myapp:stable          # a second tag for the same manifest
k3sm image inspect myapp:stable               # digest, platform, config, layer sizes
k3sm image save myapp:stable -o myapp.tar     # export a tarred OCI layout
sudo k3sm image --work-dir /var/lib/k3sm/server untag myapp:stable   # remove that tag again
k3sm image pull ghcr.io/org/app:v1            # warm this node's cache ahead of a workload
```

| verb | what it does |
|---|---|
| `tag <reference\|digest> <new-tag>` | Adds a tag to a manifest the registry already holds. It sends the same manifest bytes under the new tag, so the new tag names the same digest; a source in another repository is copied across with its blobs. The source is a tag, a `<repository>@<digest>`, or a bare digest, which is looked up in the new tag's repository. `--platform` tags one platform's manifest of a multi-platform index. A new tag that already names another manifest is refused unless you pass `--force`; `build`, `load` and `import` overwrite their own tag without asking. |
| `untag <tag>` | Deletes one tag. `--digest` refuses the removal unless the tag still names that digest. A tag names a whole index, so `untag` takes no `--platform`. |
| `inspect <tag\|repository@digest>` | Reads the manifest and config from the registry and reports the digest, the platform, the creation time, entrypoint/cmd, user, working directory and each layer's size. An index lists its platforms; `--platform` inspects one of them. `-o json` prints the registry's manifest and config documents for scripting. Read-only. |
| `save <tag\|repository@digest> -o <file.tar>` | Exports the image as a tarred OCI image layout, the `docker save` analog and the exact inverse of `import`: the layout names the image `registry-k3sm:6450/<repository>:<tag>`, so importing the archive records it under the same name. An index is saved whole unless `--platform` picks one platform. The archive is written beside the target and renamed into place when complete, so a failed save leaves no file behind. |
| `pull <reference>` | Fetches the reference into this node's cache through the daemon's own puller, the same code path a Pod's pull takes, so every blob is re-hashed against its digest before it is recorded. Prints the digest it resolved to. `--platform os/arch[/variant]` picks which manifest of a multi-platform index to fetch; `--policy always\|if-not-present\|never` carries the ordinary Kubernetes pull-policy meanings. |

Untag removes a name, not bytes. The manifest and its blobs stay while another tag or index names
them, and the registry's own garbage collection reclaims what nothing names. A node that already
pulled the image keeps its cached copy, so a running Pod is unharmed.

A pulled image is ordinary cache content: `pull` records no operator root, so `k3sm image prune`
can reclaim it once no Pod uses it.

`pull` of a public image also copies it, the whole index when there is one, into the cluster
registry as `registry-k3sm:6450/<registry>/<repository>:<tag>` (Docker Hub is spelled
`docker.io`). A node uses that copy only when the public registry cannot be reached at all: a
DNS failure, a refused connection or a timeout. Any answer from the public registry, including
a 404 or a certificate it cannot verify, stands. The copy uploads as you through your kubeconfig,
the same way `push` does, and a copy that fails prints a warning naming the cause and does not
fail the pull. A cluster-registry reference, or a registry with a port, gets no copy, and
`--no-mirror` skips it.

## Reclaiming Space: `k3sm image prune`

`k3sm image prune` reclaims space in two places: the cluster registry, and this node's cache.
It is a dry run unless you pass `--force`.

```sh
sudo k3sm image prune                 # report what would go
sudo k3sm image prune --force         # delete it
sudo k3sm image prune -o json         # the same report as one JSON document
```

In the registry it deletes untagged manifests: what is left behind when a tag is pushed again
and now names a newer image. It keeps every tagged manifest, and these untagged ones too:

- a manifest that a kept multi-platform index names;
- a referrer, such as a signature, whose subject is kept;
- a manifest younger than an hour, since a multi-platform push uploads its per-platform
  manifests before the index that names them.

A deleted manifest's layers are reclaimed by the registry's own garbage collection on its next
sweep, so disk usage drops some time after the prune. An untagged manifest that a Pod names by
digest is deleted too, so give anything you run by digest a tag. The registry half runs on the
server that holds the registry, as the control plane's user. It reads the registry's storage
and deletes through the registry's API with that server's own push credential. On a node with
no registry, prune says so and evicts the cache only. Pods cannot delete: the in-cluster push
path refuses every deletion.

In the cache it asks the node's runtime daemon to evict the content no Pod uses. The daemon
keeps everything a Pod uses, and if it cannot list every Pod's images it refuses the whole
prune. This half runs before the registry half, so a refusal there deletes nothing
anywhere.

The `-o json` document has three keys. `dryRun` is true without `--force`. `registry` holds
`name`, `skipped` (set only on a node without a registry), `manifests` (each with `repository`,
`digest`, `mediaType` and `size`, deleted or to be deleted), `kept` (the untagged manifests kept,
each with its `reason`), and, when present, `unreadable` repositories and `failed` deletions.
`cache` holds `blobs`, `reclaimedBytes` and `kept` (counts by reason). The command exits non-zero
when any deletion fails, after printing the report.

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
disk** is taken as a reference in this node's cache instead, and k3sm exports it from the cache
through the runtime daemon, verifies the export, and uploads the result.

```sh
k3sm image push myapp:v1 registry.example.com/me/myapp:v1
```

A reference this node's cache does not hold may also name an image the cluster registry holds,
by any name `k3sm image ls` and `k3sm image inspect` accept: a bare `myapp:v1`, or the same under
`registry-k3sm:6450/`. That is where `k3sm build` records its output, so the image a build just
recorded is pushed on by its tag. k3sm copies it from the cluster registry through the push gate,
with the builder token the build used. Blobs the destination already has are skipped; within the
cluster registry they are mounted from the source repository instead of sent again. A destination
that names the same repository and tag copies nothing and says the image is already there.

```sh
k3sm build --tag myapp:v1 .
k3sm image push myapp:v1 registry-k3sm:6450/team/myapp:v1
```

If neither the cache nor the cluster registry holds the reference, the error names both.

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

## Listing the Registry: `k3sm image ls` / `k3sm image df`

`ls` and `df` describe the cluster's one registry, the one the server runs. They read it
anonymously and need no root and no daemon socket, only a kubeconfig that can read Nodes, Pods and
the `kube-public/local-registry-hosting` ConfigMap. On the server the command reaches the registry
on its loopback port; on any other Mac it reaches the server's address on the port that ConfigMap
publishes.

```sh
k3sm image ls             # every tag, where it is cached, and how many Pods use it
k3sm image ls -o json     # the same, as a versioned document
k3sm image ls -o ndjson   # the same, one JSON line per image as it is read
k3sm image df             # the registry's size and each node's image cache
k3sm image df -o json
```

Each image is shown under its canonical reference, `registry-k3sm:6450/<repository>:<tag>`, with
its digest, its platforms (every platform of a multi-platform index), and its size, which counts
each distinct config and layer once. `PODS` counts the Pods whose container image names that
digest, or that reference under any spelling of the registry's address. `CACHED ON` lists the nodes
whose `status.images` report the digest. A node reports at most its 50 largest images there, so a
node at that cap may cache an image it does not list; the table says so, and `-o json` names such
nodes under `cachedOnIncomplete`.

If the registry does not answer, both commands still exit 0: the table says it is unreachable, and
the JSON document carries `"reachable": false` with the error. `df` then still reports the node
caches.

Both commands keep what each image digest describes (its platforms, size and blobs) in a cache
under your account's cache directory, `~/Library/Caches/k3sm/registry/<registry address>/`, so a
later run reads only each tag's current digest and describes just the digests it has not seen.
Which digest a tag names is read afresh every run; deleting the directory is always safe. A run
as root (under `sudo`) keeps no cache.

### Streaming the list: `-o ndjson`

`k3sm image ls -o ndjson` writes the listing while it runs, one JSON object per line, so a program
can show progress and fill a list before a large registry has been read. Every line has a `type`:

| `type` | When | Fields |
|---|---|---|
| `start` | first | `schemaVersion` (1), `registry` (`name`, `reachable`, and `error` when it is unreachable) |
| `progress` | after each repository's tag list is read, and at most every 250 ms while tags are read | `repositories`, `repositoriesRead`, `tags`, `tagsRead`; `tags` is the running total and grows until every repository's list is read |
| `image` | as each tag is read, in the order the reads finish | the fields of one element of `images` in `-o json`: `repository`, `tag`, `reference`, `digest`, `platforms`, `sizeBytes`, `pods`, `cachedOn` |
| `end` | last | `images` (how many image lines were written), `cachedOnIncomplete`, `migration` |
| `error` | instead of `end`, when the listing fails after the registry answered | `error` |

An unreachable registry is a `start` line with `"reachable": false`, then `end`, and the command
exits 0, as with `-o json`. After an `error` line the command exits non-zero. Image lines arrive in
completion order; sort them yourself.

## Next

- [Building images](builder.md), building a Dockerfile that runs commands, on the cluster.
- [What runs](what-runs.md), what k3sm can run and the whole path from Dockerfile to Pod.
- [Quickstart](quickstart.md), running your first native Pod.
- [Limitations](limitations.md), the adaptation requirement.
- [Storage](storage.md), attaching persistent data.
