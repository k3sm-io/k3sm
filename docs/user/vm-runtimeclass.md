# `vm` RuntimeClass

k3sm runs Pods as native Darwin processes under a **single `_k3sm` user**, so there is **no per-pod uid
isolation** — same-node Pods share one OS trust domain. The **`vm` RuntimeClass** is the intended
answer for **untrusted or multi-tenant** workloads: a real isolation boundary backed by
Virtualization.framework. See the status note below for what it supports today.

> **Status: validated on real hardware.** A Pod that sets
> `runtimeClassName: vm` boots a `linux/arm64` container image in its own micro-VM. Exercised and
> measured on the reference hardware: boot and restart, `kubectl logs` (including `--tail` and
> `-f`), `kubectl exec` with exit-code propagation, `CrashLoopBackOff` and restart backoff,
> PersistentVolumeClaim storage that survives a hard hypervisor kill, per-container CPU and memory
> accounting, and in-guest networking — the guest leases an address on the node's NAT segment,
> resolves cluster DNS, reaches ClusterIP Services, and is itself reachable through its own
> Service's ClusterIP on the same node. See [Limitations](limitations.md) for the full measured
> picture, including what is still not wired.
>
> It ships **`linux/arm64` only** (`linux/amd64` needs in-guest translation
> and is held for a later release); its live lab run is green against the release
> artifact. This path is single-node.

## When to Use It

Use `vm` when a workload must not share the `_k3sm` trust domain with its neighbors — untrusted code,
tenant isolation, or anything you would isolate with a strong boundary on Linux. See
[Limitations](limitations.md) for what is measured and what is not yet wired. This
is the same framing as [Concepts](concepts.md): the default native path is **not** a security
boundary between Pods; `vm` is. The rationale and the trust-domain analysis live in
[the privilege model](../privilege-model.md).

## Using It

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-job
spec:
  runtimeClassName: vm
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  containers:
    - name: app
      image: myapp          # must be linux/arm64
```

The `tolerations` entry is **required**, and is not specific to `vm`: every k3sm node carries the
`k3sm.io/provider:NoSchedule` taint, so a Pod that does not tolerate it stays `Pending` with
`untolerated taint` rather than running. Admission warns about a missing toleration but only injects
one for DaemonSet Pods. The same stanza appears in [Quickstart](quickstart.md).

The image must be `linux/arm64`. An `amd64`-only image is refused at pull with a message naming the
mismatch — it is never started and left to crash:

```
no image manifest matches a runnable platform: want [linux/arm64/v8], image provides [linux/amd64]
```

Pods without `runtimeClassName: vm` use the default native-process runtime and therefore share the
`_k3sm` trust domain with other default Pods on the same node.

## Interactive Sessions

A `vm` Pod answers the interactive `kubectl` verbs, and the guest gives every container a real
terminal to run them on.

### `kubectl exec -it`

```sh
kubectl exec -it untrusted-job -- /bin/sh
```

The guest allocates a pseudo-terminal for the session, so the command really is on a terminal:
`test -t 0` is true, shell job control and line editing work, `stty size` reports a real window, and
resizing your own terminal delivers `SIGWINCH` to the process. `tty` names a device that exists
**inside the container**, because the terminal is allocated from the container's own `devpts`
instance rather than the guest's — so `ps`, `w`, and any program that reopens its controlling
terminal agree with each other instead of naming something that is not there.

Exec **without** a terminal is unchanged: the command runs on pipes, `stdout` and `stderr` stay
separate, and the exit code propagates.

### `kubectl attach`

`kubectl attach` connects to the process the container is **already** running instead of starting a
new one. Declare on the container what stdio it should keep:

```yaml
spec:
  runtimeClassName: vm
  containers:
    - name: app
      image: myapp
      tty: true      # give the container a terminal as its stdio
      stdin: true    # retain a writable stdin
```

A container with `tty: true` is started on its own pseudo-terminal — sized 24x80 until a client
resizes it, held as all three descriptors, and made the session's controlling terminal. That is the
shape `docker run -t` gives you, and it has one visible consequence: the terminal's line discipline
merges `stdout` and `stderr` before either leaves the container, so `kubectl logs` shows **one merged
stream** for a `tty` container, exactly as it already does for a `tty` exec.

A container with `stdin: true` and no terminal keeps a writable pipe instead. A container that
declares neither is started exactly as before.

Then:

```sh
kubectl attach -it untrusted-job
```

- **Detaching is not killing.** Closing the client unsubscribes it and does nothing else — the
  process is never signalled, its stdin is never closed, and its terminal is never hung up.
- **Reattaching resumes.** A new attach replays the recent output the guest still holds, then
  follows live.
- **Concurrent attaches are allowed.** Each client gets its own copy of the output; their keystrokes
  interleave in arrival order, which is left to the people at the keyboards to coordinate.
- **Asking for stdin on a container that kept none fails loudly** — a `FailedPrecondition` naming the
  fix (`stdin: true`), never a silent discard of what you typed.

The two ceilings on this path — `stdinOnce`, and what a replayed screen can look like — are on
[Limitations](limitations.md). So is what the default native runtime does instead.

### Every Container Gets a Minimal `/dev`

A container's root filesystem comes out of an OCI image, whose `/dev` is empty by construction, and
the container is cut off from the guest's own device tree. A container with nothing there is not
merely austere: `echo x > /dev/null` writes an ordinary file that grows forever, `/dev/urandom` is
missing under every language runtime that seeds from it, and no terminal could exist at all. So each
container is given:

| Path | What it is |
|---|---|
| `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty` | the OCI runtime-spec default character devices |
| `/dev/pts`, `/dev/ptmx` | the container's **own** `devpts` instance, and a relative symlink into it |
| `/dev/shm` | a private `tmpfs` bounded at **64 MiB** — the size other runtimes give a container that did not ask for one |

Two properties are deliberate rather than incidental:

- **That table is the whole of it.** The guest's own `/dev` is never re-exposed wholesale, and
  nothing outside the list appears. Enumerating what a container gets — rather than filtering what it
  does not — is what keeps the node that reaches the Pod's guest agent out of every container's
  reach, since that agent can start processes in, and read the logs of, every container in the Pod.
- **Your Pod wins.** Anything the default `/dev` would place where one of your volumes mounts is
  omitted rather than stacked underneath. A `Memory` `emptyDir` at `/dev/shm` therefore *replaces*
  the bounded default outright — that is how you ask for a bigger one. A Pod that mounts over `/dev`
  itself gets its mount and no private `devpts`.

## Trade-Offs

- **Isolation** — a genuine boundary, at the cost of VM startup and overhead versus a native process.
- **Fidelity** — behavior is measured against the reference hardware; see
  [Limitations](limitations.md) for what is covered and what is not yet wired.
- **Fallback posture** — when a Seatbelt SPI symbol-canary trips on the native path, the runtime degrades
  to `vm` or refuse-to-run, never to an unconfined process (see
  [the privilege model](../privilege-model.md)).

## Node Capability Labels

A k3sm node advertises what the **host machine is capable of** as `k3sm.io/*` **node labels**, each
stamped from a probe of the real host at node start. The label is **present with value `"true"` or
absent** — never `"false"` — and it is **removed** when the capability goes away:

| Label | Present when the host can… | Gated by | k3sm honors it today? |
|---|---|---|---|
| `k3sm.io/virtualization` | run the `vm` RuntimeClass (Virtualization.framework) | the `vm` RuntimeClass's own `nodeSelector` | yes — for scheduling |
| `k3sm.io/rosetta` | translate **darwin/amd64** Mach-O payloads via host **Rosetta 2** — natively, no VM | your Pod's `nodeSelector` | **not yet — see "advertised, not yet honored" below** |
| `k3sm.io/rosetta-linux` | translate **linux/amd64** ELF payloads in a Linux guest via **Rosetta for Linux** | your Pod's `nodeSelector` | **not yet — see "advertised, not yet honored" below** |

Inspect them with:

```sh
kubectl get nodes -L k3sm.io/virtualization,k3sm.io/rosetta,k3sm.io/rosetta-linux
```

Two properties are worth internalizing before you build selectors on these:

- **`k3sm.io/rosetta-linux` is a conjunction.** It requires **both** the `vm` backend **and** guest
  Rosetta, because Rosetta for Linux translates *inside a guest* — with no VM there is nothing to
  translate in. So a Mac with Rosetta 2 installed but **no** virtualization capability carries
  `k3sm.io/rosetta` and **not** `k3sm.io/rosetta-linux`. Never treat one as implying the other.
- **Rosetta never changes the node's architecture.** `kubernetes.io/arch` and the node's reported
  `Architecture` stay **`arm64`** — the machine's real ISA — on a Rosetta-capable node, and
  `kubernetes.io/os` stays **`darwin`** even for `rosetta-linux`. Translation is an *additional*
  capability, advertised only through the `k3sm.io/*` keys; nothing in the cluster is told the node
  *is* amd64 or *is* Linux.

### Rosetta Labels, Advertised Only

The `k3sm.io/rosetta` and `k3sm.io/rosetta-linux` labels report what the probe found on the
host — the probe really did find Rosetta — and they do make the node
**selectable**. But **k3sm does not consume them when it pulls your image yet**: the pull still asks only
for the node's native architecture (`darwin/arm64`), so an **amd64-only image is refused at pull time**
with a no-matching-platform error and the Pod lands in `ImagePullBackOff`. A multi-arch image that
includes `darwin/arm64` is unaffected — it runs natively, as it always did.

That refusal is deliberate. Two things must land first:

- **`k3sm.io/rosetta` (host, darwin/amd64)** — spawning a *translated* Mach-O inside the Seatbelt
  sandbox is not wired. Selecting amd64 payloads before that lands would also weaken a
  kernel-level check k3sm relies on: an unsigned **arm64** binary is killed by the OS, while an unsigned
  **x86_64** one is not.
- **`k3sm.io/rosetta-linux` (guest, linux/amd64)** — the Linux-guest payload path (rootfs + guest image
  pull) is not built yet, and translation only happens *inside* a guest, so the Pod must also set
  `runtimeClassName: vm` to have any chance of getting there.

So today these labels answer "**could** this host translate?", not "will k3sm run my amd64 workload
here?". Until the paths above land, ship `arm64` (or multi-arch) images. If you have already selected a
Rosetta label and see `ImagePullBackOff` with a platform error, that is this gap — not a broken node.

### Translated Execution Shares the Node's Trust Domain

One property to know before you plan on translation. Rosetta does not run entirely inside a Pod's
sandbox: translation is served by Apple's `oahd` helper, a **system daemon outside the Pod's Seatbelt
profile running as its own user (`_oahd`)**, and translated code is cached ahead-of-time in a
**node-global directory, `/private/var/db/oah`**, shared by everything on the machine. A Pod's execution
**populates** that cache but cannot read it back, and the Pod's Seatbelt profile **does not mediate**
either the helper or the cache. So a translated Pod stays in the **same-node shared trust domain** as
every other default Pod — translation adds no isolation, and for untrusted workloads the answer remains
the `vm` RuntimeClass above.

### Selecting a Rosetta-Capable Node (Keep the `os` Key)

Because these are plain capability labels with no RuntimeClass behind them, your Pod selects them
itself — and it must **keep `kubernetes.io/os: darwin`** alongside. This is the selector shape to write
**when the paths above land** — as written today the Pod schedules onto a capable node and then fails at
image pull (see the previous section):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: legacy-amd64-job
spec:
  runtimeClassName: vm                # REQUIRED for rosetta-linux — translation happens in a guest
  nodeSelector:
    kubernetes.io/os: darwin          # REQUIRED — do not drop this
    k3sm.io/rosetta-linux: "true"     # the capability you need
  containers:
    - name: app
      image: myapp-linux-amd64
```

Three things about that manifest:

- **`runtimeClassName: vm` is not optional here.** Rosetta for Linux translates *inside* a Linux guest, so
  without it the Pod runs on the native host-process path, where a `linux/amd64` payload has no meaning.
  The `vm` RuntimeClass also merges `k3sm.io/virtualization: "true"` into your `nodeSelector`, which is
  consistent — `k3sm.io/rosetta-linux` already implies a VZ-capable host.
- **Dropping `kubernetes.io/os: darwin`** and writing only the capability key **fails admission with a
  `422`**: k3sm enforces a cluster policy that every Pod declare the darwin node selector (it is what
  keeps Linux-assuming workloads off these nodes). The capability key **adds to** that selector, it does
  not replace it.
- **The host-translation variant** selects `k3sm.io/rosetta: "true"` instead and carries **no**
  `runtimeClassName` (it is the native path, no VM) — with the same not-yet-honored caveat.

For a workload you want to run **today**, drop both the capability key and the RuntimeClass and ship an
`arm64` (or multi-arch) image — the plain native path with `kubernetes.io/os: darwin` in the selector.

### Installing Rosetta After the Node Is Up — Restart Required

Capability probes run **once, at daemon start**. If you install Rosetta 2 (or grant virtualization
capability) on a Mac that is already serving as a k3sm node, the node keeps reporting the **old** answer
until the daemon restarts:

```sh
# 1. install Rosetta 2 (Apple's installer; one-time, per host)
softwareupdate --install-rosetta --agree-to-license

# 2. restart the k3sm daemon so the capability probes re-run
#    (io.k3sm.server is the installed control-plane/node LaunchDaemon; use the label
#     your role installed — see the Troubleshooting page)
sudo launchctl kickstart -k system/io.k3sm.server

# 3. confirm the label appeared
kubectl get nodes -L k3sm.io/rosetta,k3sm.io/rosetta-linux
```

Until step 2, a Pod selecting `k3sm.io/rosetta` stays `Pending` with no node to bind to. The **reverse**
direction — a node that *loses* a capability — has a documented ceiling; see
[Limitations](limitations.md#node-capability-labels-are-probed-once-at-daemon-start).

If the label still does not appear after a restart, `k3sm` logs the reason it withheld each capability
(the runtimed condition's `reason`, e.g. `NotInstalled` / `TranslationFailed` / `NotSupported` /
`VMBackendUnavailable`) at node bring-up. See [Troubleshooting](troubleshooting.md).

## Next

- [Limitations](limitations.md) — the no-per-pod-uid-isolation gap in context.
- [Concepts](concepts.md) — the trust-domain model.
- [Troubleshooting](troubleshooting.md) — a capability label that will not appear.
