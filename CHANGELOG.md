# Changelog

User-visible changes, newest first.

Each released section below is the text published as that version's
[GitHub release](https://github.com/k3sm-io/k3sm/releases) notes, with the version heading
dropped and its subsections promoted one level. The
[releases page](https://k3sm.io/releases/) lists every published build with the version to
pin, its date, and the tarball's sha256.

## v0.1.4 — 2026-09-06

One command that says what is running, and daemons that refuse to write into an unmounted data
root.

### Added

- **`k3sm status`.** One screen that answers "is my cluster up, and if not, which piece is down
  and why": a one-line verdict first, then one row per component — install, netd, server,
  apiserver, node, workloads, data root, datastore, kubeconfig — each with its state, a detail,
  and the command that fixes it. `k3sm status daemons` shows the launchd view (state, pid, runs,
  last exit, plist, log); `k3sm status cluster` the apiserver, node, Pods by phase, control-plane
  children and Linux guest hosts; `k3sm status logs [netd|server]` tails the daemon logs. `-o json`
  emits the same report for scripts, `--wait` blocks until the cluster is running, `--watch`
  re-renders in a terminal. The exit code is the verdict: 0 running, 3 stopped, 4 degraded, 5 not
  installed, 6 unknown (`k3sm status --help` is the reference). Colour and glyphs follow `NO_COLOR`
  and whether stdout is a terminal; the text is never the only signal.
- **Data-root guard.** A data root kept on its own volume is declared in `/etc/fstab`; when that
  volume is not mounted, the netd helper, the server and `sudo k3sm install` now refuse to start
  or install rather than writing a shadow directory into the empty mountpoint — the message names
  the mount command. On a plain-directory data root, the netd helper realigns a root-owned data
  root to the service user on every start, so a wrong owner is repaired by restarting it.

### Fixed

- A data root that was not mounted at boot no longer leaves the server crash-looping on
  `permission denied` behind a root-owned shadow directory, and can no longer receive a fresh,
  empty datastore over the real one. `k3sm status` names the state and the fix.

## v0.1.3 — 2026-09-05

The k3sm command is on PATH after install, and `k3sm kubectl` works without sudo.

### Added

- **A `k3sm` launcher on PATH** — `sudo k3sm install` links `/usr/local/bin/k3sm` to the installed
  binary, so every new terminal finds `k3sm` with no profile edits. The link is a symlink, never a
  copy, so it always runs the same binary the daemons do. The installer refuses to replace a
  non-symlink already at that path and refuses to link into a directory that is not root-owned or
  is group/other-writable, naming the fix in each case; `sudo k3sm uninstall` removes only the link
  it created.

### Fixed

- **`k3sm kubectl` and `k3sm kubeconfig` work as you, not just as root.** Both verbs looked only in
  the control plane's private work directory for the admin kubeconfig and the bundled kubectl, so
  after a normal install they failed for the user who ran it. They now use the `k3sm` context that
  install merges into your `~/.kube/config` (or `$KUBECONFIG`) and the kubectl installed alongside
  k3sm; a user-supplied `--context` still wins, and `K3SM_WORK_DIR` still pins a non-default server
  work directory.
- The installer's closing hint now tells the truth for the current shell: when `k3sm` is not yet on
  PATH it names the launcher and the two ways to reach it (a new terminal, or adding
  `/usr/local/bin` to PATH) instead of suggesting a command that could not work. The pre-escalation
  banner lists the symlink alongside everything else the install lays down.

## v0.1.2 — 2026-09-03

One-command in-cluster image builds, one cluster address for the node registry, and
self-recovering daemons.

### Added

- **One-command builds** — `k3sm build` builds any Dockerfile: a copy-only recipe packages natively
  in about a second, and a recipe with `RUN` steps builds on the cluster's build engine, which
  starts automatically on first use. The image is recorded in the node's image store under its tag
  either way, ready for a Pod to name; `--output` additionally writes a portable artifact.
- **Build and push in one step** — `k3sm build --push` publishes the built image after the store
  recording; a bare tag publishes to the node's own registry, a full reference pushes as written.
- **Linux images as a first-class build target** — `k3sm build --platform linux/arm64` builds a
  Linux image even from a copy-only Dockerfile; multi-platform builds export and push a full OCI
  index.
- **A raw buildx surface for the engine** — `k3sm builder buildx` drives the build engine with the
  bundled, digest-verified buildx; `k3sm builder delete` fully resets the engine, cache included.
- **One cluster address for the node registry** — each node publishes a `registry-<node>` Service
  backed by its relay address, so in-pod tools — Linux guests included — reach the registry at one
  name, and the registry hosting ConfigMap now carries `hostFromClusterNetwork`.
- **Bare image names** — a Pod naming `app:v1` resolves from the node's registry first, then from
  cluster peers, before Docker Hub; no registry prefix required for images you built or pushed
  locally.

### Fixed

- `sudo k3sm install` over a running node now sequences the daemon restart around launchd's
  asynchronous teardown, retries transient bootstrap failures, and verifies both daemons serve
  before reporting success — the in-place upgrade path is exercised by the release suite on every
  cut.
- The installer refuses a `k3sm-vmhost` helper that lacks the virtualization entitlement, naming
  the exact fix, instead of installing it and leaving every `vm` Pod Pending on an opaque
  scheduling message.
- The netd helper exits and restarts cleanly if its control socket is removed or replaced; the
  cluster-DNS listener retries its bind indefinitely instead of giving up; a failed Service-watch
  start no longer leaks a stale retry loop.
- The build engine's output no longer prints a Docker Desktop deep link.

## v0.1.1 — 2026-09-02

Interactive Linux workloads, a node-local image registry, and in-cluster image builds.

### Added

- **Interactive terminals for Linux (`vm`) Pods.** `kubectl exec -it` into a Pod running under the
  `vm` RuntimeClass allocates a real pseudo-terminal in the guest — it was refused outright before.
  Job control, line editing and `stty size` work, resizing your terminal delivers `SIGWINCH`, and
  `tty` names a device that exists **inside** the container, because the terminal is allocated from
  the container's own `devpts` instance rather than the guest's. Exec without a terminal is
  unchanged.
- **A minimal standard `/dev` in every `vm` container.** A container's root filesystem comes from an
  OCI image, whose `/dev` is empty by construction, so a `vm` container previously had no `/dev` at
  all: `echo x > /dev/null` wrote an ordinary file that grew forever, and `/dev/urandom` was missing
  under every language runtime that seeds from it. Each container now gets the OCI runtime-spec
  default character devices (`null`, `zero`, `full`, `random`, `urandom`, `tty`), its own `devpts`
  instance with a `/dev/ptmx` symlink into it, and a private `/dev/shm` bounded at 64 MiB. The set is
  enumerated rather than filtered, and a Pod volume mounted at one of those paths replaces the
  default instead of stacking underneath it — a `Memory` `emptyDir` at `/dev/shm` is how you ask for
  a larger one.
- **`kubectl attach` for `vm` Pods.** A container declaring `tty: true` is started on its own
  terminal (sized 24x80 until a client resizes it, and its session's controlling terminal), and one
  declaring `stdin: true` keeps a writable stdin — so attach has a running process to connect to.
  Detaching never signals the container or closes its stdin, reattaching resumes, and concurrent
  attaches are allowed. Because a terminal merges the two output streams before either leaves the
  container, `kubectl logs` shows one merged stream for a `tty` container, as `docker run -t` does.
  Guests advertise which verbs they can serve, so a Pod booted from an out-of-date guest image
  answers with a message naming the fix rather than a bare "not implemented".
- **A node-local image registry.** `k3sm server --registry-port <port>` runs a small OCI registry on
  the node's loopback interface; `k3sm dev` enables one automatically. Push a locally built image
  with `k3sm image push` (or any OCI tool) and Pods pull `localhost:<port>/name:tag` through the
  ordinary Kubernetes image path — so `imagePullPolicy: Always`, the digest index and real pull
  failures all behave the way they would against a remote registry, which `k3sm image load` cannot
  reproduce. Pulls are anonymous and pushes require a credential regenerated on every server start;
  the listener binds the loopback address and a non-loopback bind is rejected at startup. The
  standard `local-registry-hosting` ConfigMap is published in `kube-public` so tools can discover the
  port. Off unless you ask for it.

- **Image commands work on a stock install.** The server now serves the daemon's control
  socket, so `k3sm image ls`, `df`, `prune`, `load`, and `import` no longer need a separately
  started daemon. The socket is owner-only; the pod sandbox denies it to workloads.
- **The rest of the image verb set.** `k3sm image pull` (warm/pin an image through the same
  verified path a Pod pull takes), `tag` and `untag` (names are edges over digest-pinned
  content — untag removes a name, never bytes; bytes are reclaimed only by reachability-driven
  prune), `inspect`, `save` (verified OCI-layout export), and `push` straight out of the
  node's store.
- **Images travel across the cluster.** A node with the registry enabled advertises it to the
  cluster; when another node's Pod names a `localhost:<port>/...` image it doesn't have, the
  pull falls back to the advertising peers over the encrypted node mesh — content still
  digest-verified on arrival, pushes still credential-gated. Nodes read the advertisements
  through a purpose-made namespace with the narrowest possible grant.
- **Linux-guest Pods can reach the node registry.** The registry is relayed onto the node's
  guest-network gateway address, so a Pod running under the Linux RuntimeClass can pull from —
  and, with the push credential, push to — the node's own registry. This is what lets an
  in-cluster build Pod publish its result without any external registry.

### Known Limitations

- `stdinOnce` is accepted but **not honored** — a container that sets it behaves as though it were
  `false`.
- `kubectl attach` replays a bounded buffer (64 KiB, 4096 writes) before following live, and drops
  bytes for a client too slow to keep up rather than blocking the workload on its own `stdout`.
  Either can leave a full-screen program's first screen garbled; redraw with `Ctrl-L`.
- A Pod under the `vm` RuntimeClass **cannot pull from the node-local registry**: the guest has its
  own loopback, and the registry listens only on the node's. Use a registry the guest can reach, or
  load the image into the node's store directly.
- `kubectl attach` on the **default native path** remains output-only; `-i` / `-t` there is reported
  `Unimplemented`. `kubectl exec -it` works on both paths.

## v0.1.0 — 2026-09-02

The first release of k3sm — a macOS-native Kubernetes distribution for Apple Silicon. Pods run as
native Darwin processes; an experimental `vm` RuntimeClass boots `linux/arm64` images in per-pod
micro-VMs against digest-pinned guest artifacts, verified on every boot.

The archive contains the k3sm binary, the exec shim, both DYLD shims, the entitled `k3sm-vmhost`
helper, and the pre-staged control-plane payload — everything `sudo k3sm install` requires. Ad-hoc
signed, not notarized; the Homebrew tap and notarized package arrive with a later release.
