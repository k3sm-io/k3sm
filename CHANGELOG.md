# Changelog

User-visible changes, newest first.

Each released section below is the text published as that version's
[GitHub release](https://github.com/k3sm-io/k3sm/releases) notes. The
[releases page](https://k3sm.io/releases/) lists every published build with the version to
pin, its date, and the tarball's sha256.

## Unreleased — v0.1.1

**Not yet cut.** This section is the release notes for the next patch release; it gains a date
when the release is published.

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
