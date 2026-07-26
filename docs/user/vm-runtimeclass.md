# The `vm` RuntimeClass

k3sm runs Pods as native Darwin processes under a **single `_k3sm` user**, so there is **no per-pod uid
isolation** — same-node Pods share one OS trust domain. For **untrusted or multi-tenant** workloads, the
**`vm` RuntimeClass** provides a real isolation boundary backed by Virtualization.framework.

> **Status: EXPERIMENTAL.** The `vm` RuntimeClass (M5) ships as documented **EXPERIMENTAL** — a v0.2
> headline, not launch-blocking. See [limitations.md](limitations.md).

## When to use it

Use `vm` when a workload must not share the `_k3sm` trust domain with its neighbors — untrusted code,
tenant isolation, or anything you would isolate with a strong boundary on Linux. This is the same
framing as [limitations.md](limitations.md) and [concepts.md](concepts.md): the default native path is
**not** a security boundary between Pods; `vm` is. The rationale and the trust-domain analysis live in
`docs/privilege-model.md`.

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
  to `vm` or refuse-to-run, never to an unconfined process (see `docs/privilege-model.md`).

## Node capability labels

A k3sm node advertises what it can actually run as `k3sm.io/*` **node labels**, each stamped from a
probe of the real host at node start. The label is **present with value `"true"` or absent** — never
`"false"` — and it is **removed** when the capability goes away:

| Label | Present when the node can run… | Gated by |
|---|---|---|
| `k3sm.io/virtualization` | the `vm` RuntimeClass (Virtualization.framework) | the `vm` RuntimeClass's own `nodeSelector` |
| `k3sm.io/rosetta` | **darwin/amd64** Mach-O payloads via host **Rosetta 2** — natively, no VM | your Pod's `nodeSelector` |
| `k3sm.io/rosetta-linux` | **linux/amd64** ELF payloads in a Linux guest via **Rosetta for Linux** | your Pod's `nodeSelector` |

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

### Selecting a Rosetta-capable node (keep the `os` key)

Because these are plain capability labels with no RuntimeClass behind them, your Pod selects them
itself — and it must **keep `kubernetes.io/os: darwin`** alongside:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: legacy-amd64-job
spec:
  nodeSelector:
    kubernetes.io/os: darwin          # REQUIRED — do not drop this
    k3sm.io/rosetta-linux: "true"     # the capability you need
  containers:
    - name: app
      image: myapp-linux-amd64
```

Dropping `kubernetes.io/os: darwin` and writing only the capability key **fails admission with a
`422`**: k3sm enforces a cluster policy that every Pod declare the darwin node selector (it is what
keeps Linux-assuming workloads off these nodes). The capability key **adds to** that selector, it does
not replace it.

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
