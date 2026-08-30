# The k3sm privilege model — user-space by default, one minimal root helper

How k3sm runs without per-command `sudo`: a **one-time admin install** of a tiny root helper
(`k3sm-netd`) that performs only the irreducibly privileged network operations, with **everything
else** — the control plane, the Virtual Kubelet node, the runtime daemon, the Service proxy, and your
Pods — running as a dedicated **unprivileged `_k3sm`** user. This is the pattern Docker Desktop, lima,
colima and Rancher Desktop all use (`com.docker.vmnetd`, `socket_vmnet`), applied to k3sm. No
networking fidelity is given up for it.

The architecture behind this page is [DESIGN.md](DESIGN.md) §5b (networking) and §5c (control plane,
bootstrap, packaging).

## Why a helper at all — the macOS constraint

A handful of operations are **irreducibly root** on macOS and cannot be done from an unprivileged
process:

| Operation | Used for | Why it needs root |
|---|---|---|
| `lo0` `/32` alias add/remove | per-Pod IPs, ClusterIP VIPs | `ifconfig` / `SIOCAIFADDR` on `lo0` needs root |
| `utun` create + wireguard + routes | the multi-node mesh | interface and routing-table mutation needs root |
| `pf` sub-anchor load | the mesh MSS clamp | `pfctl` / `/dev/pf` needs root |
| bind a `<1024` port on a specific `lo0` VIP | the infra VIPs (`10.43.0.1:443` API, `10.43.0.10:53` DNS) and any `<1024` ClusterIP port | a reserved-port bind on a specific address needs root |

The `com.apple.vm.networking` entitlement that *would* let a user-space `vmnet` client avoid all this
is **Apple-contract-restricted** — even Docker Desktop cannot obtain it, which is exactly why Docker
also ships a one-time-admin root helper. **Zero-root-ever is therefore impossible** for those four
operations. The honest answer is everyone else's answer: do them in a minimal root daemon, installed
once, and run everything else unprivileged.

## The shape

```
   you ──kubectl──▶ apiserver (loopback)          the admin kubeconfig install merged
        │                                          into your own ~/.kube/config
   ┌────┴──────────── unprivileged, runs as _k3sm (LaunchDaemons, boot-surviving) ───────────────┐
   │  control plane (apiserver / datastore / scheduler / controller-manager)   node   runtime    │
   │      │ Seatbelt-confined Pods (also _k3sm) — posix_spawn, clonefile, rusage sampling        │
   └──────┼──────────────────────────────────────────────────────────────────────────────────────┘
          │ unix socket, uid peer-auth, a closed typed-scalar RPC
   ┌──────┴── root, minimal ─────────────────────────────────────────────────────────────────────┐
   │  k3sm-netd:  lo0 /32 alias · utun + wireguard + routes · the io.k3sm.* pf anchor · <1024 bind │
   └──────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **`k3sm-netd` is the same single `k3sm` binary re-exec'd in `netd` mode** — one binary, two launchd
  identities.
- The unprivileged side is a **LaunchDaemon with `UserName=_k3sm`** (`RunAtLoad` + `KeepAlive`), *not*
  a per-user LaunchAgent, so the cluster **survives a reboot** on a headless Mac and never depends on
  a GUI login session.
- **You are a different uid from `_k3sm`**, so Pods (which run as `_k3sm`) cannot read your
  `~/.kube/config` or `~/.ssh` — POSIX permissions and Seatbelt both deny it.

## The helper is the high-risk surface — and its controls

A root daemon taking IPC from user space is the classic local-privilege-escalation surface, the CVE
class `vmnetd` and `socket_vmnet` have lived through. `k3sm-netd` is built to a strict model:

- **Networking and privileged-port binds ONLY.** No Pod spawning, no file operations, no sandbox
  profile application — those stay in user space. The verb set is closed: `EnsureAlias`,
  `RemoveAlias`, `ConfigureMesh`, `RemoveMesh`, `LoadPFAnchor`, `BindPort`.
- **Typed scalars, never text.** The RPC carries an IP, a typed peer (`{public key, endpoint,
  allowedIPs}`), an MSS integer, a `{port, node address}` — never `route`, `pf` or wireguard-UAPI
  *text*. The daemon **renders** the privileged artifact itself and **re-validates** every parameter
  against pinned policy: an alias must be a `/32` inside the pinned aggregate intersected with the
  node's Pod CIDR; a route must pass the route-set predicate; the `pf` rule is the daemon's own
  MSS-clamp template loaded into the `io.k3sm.*` anchor. This is the `socket_vmnet` lesson — never
  pass caller-supplied arguments to a privileged tool.
- **A privileged-port bind is authorized, not merely requested**, and only for **specific `lo0` VIP
  addresses**, never a wildcard. The helper's `<1024` `BindPort` serves the infra VIPs
  (`10.43.0.1:443`, `10.43.0.10:53`) and any `<1024` ClusterIP port; the bind is permitted only when
  the Service-backed authorizer confirms a real Service declares that port, and the daemon binds the
  **specific VIP address**, rejecting a wildcard request. **NodePort is not bound by the helper**: it
  needs all-interfaces reachability including `127.0.0.1`, so the Service proxy binds a wildcard
  `*:nodePort` in-process — the apiserver pins the NodePort range to `30000-32767`, all of which are
  `≥1024` and bindable unprivileged as `_k3sm`. A `<1024` NodePort is unsupported.
  LoadBalancer and Ingress listeners likewise bind the **wildcard**, and on macOS a wildcard
  privileged bind needs no root (a specific-address one does — inverted from Linux), so that datapath
  never reaches the helper at all.
- **Peer authentication.** `LOCAL_PEERCRED` requires the `_k3sm` uid, which keeps *other* local users
  off the socket. A code-identity check (audit token → code-signature validity against the signed
  binary's designated requirement) is a documented defense-in-depth follow-up.
- **Root-owned everything.** The binary and plist live in `/Library/k3sm` (`root:wheel`, `0755`) —
  deliberately *not* a Homebrew, `/usr/local` or `/Applications` prefix that a member of the `admin`
  group could overwrite. The socket lives in a root-owned directory, mode `0660`. On a signed release
  the helper is notarized with a hardened runtime, minimal entitlements, and a designated requirement
  pinned to its identifier and team, so it cannot be downgraded or substituted.
- **Bounded and robust.** The helper emits file descriptors outward only (it never accepts an inbound
  descriptor or path); per-connection resource caps are sized to a node's `/24` Pod capacity; the
  decoder is allocation-bounded, returns errors and never panics; every rejection and lifecycle event
  is logged.
- **Crash recovery.** When the helper restarts, the user-space client invalidates its idempotency
  cache on socket reconnect and re-ensures every live Pod IP, and the mesh reconverges through the
  peer informer's bounded periodic resync (≤30 s), which re-applies the full wireguard state. A
  helper restarted out from under a running cluster therefore reconverges within the resync interval
  rather than stranding Pods.

## Network egress is a contract, not a Seatbelt boundary

The per-Pod internet-egress opt-in (the `k3sm.io/internet-egress` annotation) is an API and admission
contract, surfaced by a warning admission policy. macOS 26 Seatbelt accepts **no per-IP network
filters**, so at the profile layer an egress-enabled Pod gets the same unfiltered-but-compilable
network stanza under `(deny default)` that an ordinary networked Pod gets. No privilege is added or
dropped by the annotation, and network-layer enforcement is future work. **Never describe it as a
network isolation boundary.**

## The one residual limitation — no per-Pod uid isolation

Because the helper is networking-only — minting a per-Pod uid would need root *in the runtime*, which
is exactly the privilege this model removes — every Pod on a node runs as the **same `_k3sm` uid**,
Seatbelt-confined. The consequences, stated plainly:

- Pods share `_k3sm` with the runtime's own helper client, so `LOCAL_PEERCRED` does **not** separate a
  Pod from the helper. The load-bearing barrier keeping a Pod off the helper socket is the **Seatbelt
  AF_UNIX deny** the runtime emits into every Pod's profile; the helper's own request validation
  backstops even a breach, since a socket-reaching Pod could still only ask for operations a
  legitimate client would.
- A Pod requesting a **foreign `runAsUser` / `runAsGroup` / `fsGroup` / `supplementalGroups`** is
  **rejected at admission**, never silently coerced. k3sm does not pretend to honor an isolation it
  cannot provide.
- **Untrusted or multi-tenant workloads belong on the [`vm` RuntimeClass](user/vm-runtimeclass.md)**,
  which is backed by Virtualization.framework — an *entitlement*, not root — and is a real isolation
  boundary. This is consistent with the long-standing design position that same-node Pods are one
  trust domain ([DESIGN.md](DESIGN.md) §3).
- If the runtime's Seatbelt capability probe ever fails, the runtime degrades to **`vm` or
  refuse-to-run** — never to "run the Pod unconfined."

## Install, run, upgrade, uninstall

- **Install — the one privileged step.** `sudo k3sm install` creates `_k3sm`, copies the binary and
  plists into the root-owned `/Library/k3sm`, bootstraps the `io.k3sm.netd` (root) and
  `io.k3sm.server` (`UserName=_k3sm`) LaunchDaemons, and merges an admin kubeconfig into the
  **invoking** user's `~/.kube/config`. It uses the classic `launchctl` path rather than
  `SMAppService`, which requires a GUI `.app` bundle and a System Settings approval and cannot be
  re-registered by a package-manager upgrade — disqualifying for a headless CLI server.
  See [user/install.md](user/install.md).
- **Run — no `sudo`.** Afterwards `kubectl` and the whole Pod lifecycle run as you and as `_k3sm`
  with no `sudo`, and the stack survives a reboot.
- **Networking modes.** `k3sm server --network auto` (the default) uses the direct `lo0` path when
  running as root and the helper plus a startup probe otherwise — the production posture.
  `--network none` is no-op networking for control-plane-only or CI bring-up; it is **not** a
  production fallback.
- **Upgrade.** Re-running the install script, or a Homebrew upgrade once the tap ships, replaces the
  binary and restarts both LaunchDaemons onto it. The helper RPC is version-stamped and additive, so
  a routine upgrade does not break the datapath. Homebrew packaging and the notarized, signed
  installer are the second and third install generations, arriving with and after the first public
  release — see [user/install.md](user/install.md) and [user/upgrade.md](user/upgrade.md).
- **Uninstall.** `sudo k3sm uninstall` boots out both daemons, flushes all privileged state (the `lo0`
  aliases, the `io.k3sm.*` `pf` anchor, the `utun`), and removes `/Library/k3sm`. No orphaned root
  listener survives.

## Explicitly out of scope

- **A fully zero-admin install.** Impossible on macOS for `lo0`, `utun`, `pf` and `<1024` binds, since
  the entitlement that would avoid them is Apple-restricted. The one-time admin step is unavoidable;
  even Docker needs it.
- **Per-Pod uid isolation without a VM.** The helper is networking-only by decision; untrusted
  workloads go to the [`vm` RuntimeClass](user/vm-runtimeclass.md).
- **Rootless multi-node without the helper.** The mesh — `utun` and routes — is irreducibly root.

## Related

- [DESIGN.md](DESIGN.md) — §3 (the trust domain), §5b (networking), §5c (install and packaging),
  §6 (the one-binary doctrine).
- [user/install.md](user/install.md) — the install channels and what each lays down.
- [user/limitations.md](user/limitations.md) — the no-per-Pod-uid-isolation gap in context.
- [user/vm-runtimeclass.md](user/vm-runtimeclass.md) — the isolation boundary for untrusted workloads.
