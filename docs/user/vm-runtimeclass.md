# The `vm` RuntimeClass

k3sm runs Pods as native Darwin processes under a **single `_k3sm` user**, so there is **no per-pod uid
isolation** — same-node Pods share one OS trust domain. The **`vm` RuntimeClass** is the intended
answer for **untrusted or multi-tenant** workloads: a real isolation boundary backed by
Virtualization.framework. It is the designed answer, not yet an available one — see the status note
below before you depend on it.

> **Status: NOT RUNNING YET.** **No Pod has
> ever booted in a micro-VM.** What exists today is the dispatch half — the RuntimeClass object, the
> fail-closed backend selection, the capability labels, the volume and network plumbing — wrapped
> around a boot path that is not written. A Pod that sets `runtimeClassName: vm` does not start.
>
> It is targeted at the **v0.1.0** public release as documented **EXPERIMENTAL** and
> **`linux/arm64` only** (`linux/amd64` needs in-guest translation and is deliberately held for a
> later release), launch-gated on a live lab proof against the release artifact. The
> de-EXPERIMENTAL graduation, with published performance figures, is the **v0.2** milestone. Until
> the v0.1.0 gate is green, treat every instruction below as *what this will do*, not what it does.
> See [limitations.md](limitations.md).

## When to use it

Use `vm` when a workload must not share the `_k3sm` trust domain with its neighbors — untrusted code,
tenant isolation, or anything you would isolate with a strong boundary on Linux. Today that means:
plan for `vm`, but do not schedule onto it, because it does not boot yet. This is the same
framing as [limitations.md](limitations.md) and [concepts.md](concepts.md): the default native path is
**not** a security boundary between Pods; `vm` is. The rationale and the trust-domain analysis live in
[privilege-model.md](../privilege-model.md).

## Using it

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-job
spec:
  runtimeClassName: vm
  containers:
    - name: app
      image: myapp
```

Pods without `runtimeClassName: vm` use the default native-process runtime and therefore share the
`_k3sm` trust domain with other default Pods on the same node.

## Trade-offs

- **Isolation** — a genuine boundary, at the cost of VM startup and overhead versus a native process.
- **Fidelity** — as an EXPERIMENTAL path, treat behavior as preview-quality and validate your workload.
- **Fallback posture** — when a Seatbelt SPI symbol-canary trips on the native path, the runtime degrades
  to `vm` or refuse-to-run, never to an unconfined process (see
  [privilege-model.md](../privilege-model.md)).

## Node capability labels

A k3sm node advertises what the **host machine is capable of** as `k3sm.io/*` **node labels**, each
stamped from a probe of the real host at node start. The label is **present with value `"true"` or
absent** — never `"false"` — and it is **removed** when the capability goes away:

| Label | Present when the host can… | Gated by | k3sm honors it today? |
|---|---|---|---|
| `k3sm.io/virtualization` | run the `vm` RuntimeClass (Virtualization.framework) | the `vm` RuntimeClass's own `nodeSelector` | yes — for scheduling (the `vm` path itself is EXPERIMENTAL) |
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

### The two Rosetta labels are advertised, not yet honored

The `k3sm.io/rosetta` and `k3sm.io/rosetta-linux` labels are a
**truthful claim about the host** — the probe really did find Rosetta — and they really do make the node
**selectable**. But **k3sm does not consume them when it pulls your image yet**: the pull still asks only
for the node's native architecture (`darwin/arm64`), so an **amd64-only image is refused at pull time**
with a no-matching-platform error and the Pod lands in `ImagePullBackOff`. A multi-arch image that
includes `darwin/arm64` is unaffected — it runs natively, as it always did.

That refusal is deliberate, not an oversight. Two things must land first:

- **`k3sm.io/rosetta` (host, darwin/amd64)** — spawning a *translated* Mach-O inside the Seatbelt sandbox
  is not yet proven end to end. Selecting amd64 payloads before it is would also weaken a
  kernel-level check k3sm relies on: an unsigned **arm64** binary is killed by the OS, while an unsigned
  **x86_64** one is not.
- **`k3sm.io/rosetta-linux` (guest, linux/amd64)** — the Linux-guest payload path (rootfs + guest image
  pull) is not built yet, and translation only happens *inside* a guest, so the Pod must also set
  `runtimeClassName: vm` to have any chance of getting there.

So today these labels answer "**could** this host translate?", not "will k3sm run my amd64 workload
here?". Until the paths above land, ship `arm64` (or multi-arch) images. If you have already selected a
Rosetta label and see `ImagePullBackOff` with a platform error, that is this gap — not a broken node.

### Translated execution shares the node's trust domain

One property to know before you plan on translation. Rosetta does not run entirely inside a Pod's
sandbox: translation is served by Apple's `oahd` helper, a **system daemon outside the Pod's Seatbelt
profile running as its own user (`_oahd`)**, and translated code is cached ahead-of-time in a
**node-global directory, `/private/var/db/oah`**, shared by everything on the machine. A Pod's execution
**populates** that cache but cannot read it back, and the Pod's Seatbelt profile **does not mediate**
either the helper or the cache. So a translated Pod stays in the **same-node shared trust domain** as
every other default Pod — translation adds no isolation, and for untrusted workloads the answer remains
the `vm` RuntimeClass above.

### Selecting a Rosetta-capable node (keep the `os` key)

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

### Installing Rosetta after the node is up — restart required

Capability probes run **once, at daemon start**. If you install Rosetta 2 (or grant virtualization
capability) on a Mac that is already serving as a k3sm node, the node keeps reporting the **old** answer
until the daemon restarts:

```sh
# 1. install Rosetta 2 (Apple's installer; one-time, per host)
softwareupdate --install-rosetta --agree-to-license

# 2. restart the k3sm daemon so the capability probes re-run
#    (io.k3sm.server is the installed control-plane/node LaunchDaemon; use the label
#     your role installed — see troubleshooting.md)
sudo launchctl kickstart -k system/io.k3sm.server

# 3. confirm the label appeared
kubectl get nodes -L k3sm.io/rosetta,k3sm.io/rosetta-linux
```

Until step 2, a Pod selecting `k3sm.io/rosetta` stays `Pending` with no node to bind to. The **reverse**
direction — a node that *loses* a capability — has a documented ceiling; see
[limitations.md](limitations.md#node-capability-labels-are-probed-once-at-daemon-start).

If the label still does not appear after a restart, `k3sm` logs the reason it withheld each capability
(the runtimed condition's `reason`, e.g. `NotInstalled` / `TranslationFailed` / `NotSupported` /
`VMBackendUnavailable`) at node bring-up. See [troubleshooting.md](troubleshooting.md).

## Next

- [limitations.md](limitations.md) — the no-per-pod-uid-isolation gap in context.
- [concepts.md](concepts.md) — the trust-domain model.
- [troubleshooting.md](troubleshooting.md) — a capability label that will not appear.
