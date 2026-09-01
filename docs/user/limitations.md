# Limitations — the real gaps

k3sm runs Kubernetes Pods as **native Darwin processes** on Apple Silicon. That design buys a
zero-Linux, zero-VM developer experience, but it also means several standard Kubernetes behaviors
**diverge by design** or are **not yet wired**. This page is the full inventory.

## Where the full truth lives (cite, don't trust this page alone)

The authoritative source of "what k3sm cannot conform to and why" is
[**`docs/conformance-profile.md`**](../conformance-profile.md) — the self-assessment mapping
targeted feature classes to a green synthetic-conformance criterion **or** a documented ceiling. It is
backed by a maintainer-facing full-surface conformance register (one row per standard Kubernetes
feature × verdict, with a canonical §By-design non-conformance summary) kept internal to the project.

That profile is the single source of truth; the summaries below restate the user-visible consequences
so this page stands on its own, but they are deliberately **not** more optimistic than the profile.
When in doubt, the profile wins.

## Headline divergences

- **Pods are native Darwin processes.** There are **no Linux containers, cgroups, CNI, or network
  namespaces**, and no device-plugins or hugepages. Anything that assumes those substrates does not
  apply.
- **Best-effort resource model.** There is **no CFS millicore CPU enforcement** — CPU `limits` are not
  enforced, `HPA`-on-CPU is **unservable**, and `kubectl top` needs an **operator-installed
  metrics-server** (k3sm does not ship one; there is no CPU accounting behind `metrics.k8s.io`). Memory
  is sampled (`proc_pid_rusage`) and can drive OOMKill, but this is best-effort, not cgroup enforcement,
  and there is no node-pressure eviction guarantee.
- **Workloads must be adapted.** A raw upstream `[Conformance]` Pod — one that assumes a Linux image,
  bind mounts, or Linux-only fields — is rejected at admission or stranded. Images are the k3sm native
  image model (see [images.md](images.md)), not arbitrary OCI Linux images.
- **k3sm cannot pass CNCF `[Conformance]` / Sonobuoy.** That suite assumes Linux containers, cgroups,
  CNI, and netns; k3sm has none of them, and k3sm does not claim a
  Certified-Kubernetes badge. See [`conformance-profile.md`](../conformance-profile.md).

## The gaps matrix

### No per-pod uid isolation

All Pods on a node run as the **same unprivileged `_k3sm` OS user**, Seatbelt-confined. There is **no
per-pod uid isolation**, so same-node Pods share a single OS trust domain. Untrusted or multi-tenant
workloads must use the **`vm` RuntimeClass** (Virtualization.framework), which gives a real isolation
boundary. See [vm-runtimeclass.md](vm-runtimeclass.md) for how to opt in. The same framing appears in
[concepts.md](concepts.md).

On the **`k3sm dev --datapath` tier only**, it is worse than that: `--datapath` runs the server as
root, and a Pod that declares no `securityContext.runAsUser` keeps the daemon's identity — so those
Pods run as **uid 0**. They are still Seatbelt-confined, and no installed cluster behaves this way
(the LaunchDaemon runs as `_k3sm`), but `--datapath` is a disposable dev tier: do not run untrusted
workloads on it. `k3sm dev up --datapath` says the same thing in its banner.

### Volume mounts resolve for native workloads, not `/bin/sh`

k3sm pods run at real host paths with **no chroot / mount namespace**, so a volume mounted at an
absolute container path (e.g. `/etc/nats`) is materialized under the pod data volume and made to
resolve there by a **`DYLD_INSERT_LIBRARIES` path-rebase shim** that rewrites the mounted prefixes.
The shim loads into ordinary **native workloads** (Go/C binaries — your app, `nats`, `postgres`), so
their absolute volume mounts work as expected. It **cannot** load into a **SIP platform binary**
(`/bin/sh`, `/usr/bin/*`) — macOS strips `DYLD_INSERT_LIBRARIES` from those — so a shell script that
reads a mounted file at its absolute path won't see it. Ship your workload as a compiled binary (the
native k3sm model), not a `/bin/sh`-driven image, for mounted config/secret/scratch volumes.

Absolute volume-mount paths resolve **only on the root tier**. The path-rebase shim is **euid-gated**:
it must be staged under `/Library` to sit inside the pod Seatbelt read baseline, and only euid 0 can
write there, so an unprivileged (rootless) `k3sm server` never stages it — a rootless pod expecting an
absolute mount path sees the unmounted host path instead. This is why a ladder that depends on
absolute volume mounts (e.g. the MLX acceptance gate's cache PVC) is a root-tier run: rootless stops
at mount resolution by design, not by omission.

### NetworkPolicy is a policy hint, not a security boundary

NetworkPolicy is enforced **only on Service-VIP-mediated ingress** at the userspace proxy, with
per-pod source fidelity for same-node clients. Any direct pod-IP connection — including **all
headless-Service and StatefulSet traffic** — bypasses it completely; **egress rules and `ipBlock`
are never enforced**; and policies against `kube-dns` or the `kubernetes` VIP are unenforceable
(those VIPs bypass the proxy). It is a policy hint, NOT a security boundary — isolate untrusted
workloads with the vm RuntimeClass ([vm-runtimeclass.md](vm-runtimeclass.md)).

### Which addresses your Services actually answer on

Today at `main`, per port class:

- **NodePort** — bound to the **wildcard** `*:30000-32767` in-process. Every interface on the Mac
  answers, including `127.0.0.1` and your LAN address. This has always been the case; it is what
  NodePort means upstream.
- **LoadBalancer / Ingress** — bound to the **wildcard** `*:<port>`, matching Docker Desktop and k3s,
  which both publish LoadBalancer ports on all interfaces.

  **The bind address and the advertised address are different, on purpose.** Read them separately.
  The **port** is reachable on every interface the Mac has, including its LAN address — so treat a
  LoadBalancer Service as publishing to the local network, not to the host alone. The **advertised
  `EXTERNAL-IP`** is the node's InternalIP, an RFC-6598 (`100.64.0.0/10`) alias on `lo0`: reachable
  from this Mac, from local pods, and from mesh peers over WireGuard, but **not routable from your
  LAN**. A LAN client has no route to `100.64/10`, so `curl <EXTERNAL-IP>` from your laptop **hangs
  until timeout** rather than failing fast — dial the Mac's own LAN address and the Service port
  instead. This differs from both analogs: k3s advertises the node's real LAN address, and Docker
  Desktop advertises the literal hostname `localhost`. If you need a LAN-usable value in
  `status.loadBalancer.ingress`, that is not what k3sm publishes today.

  If the derived InternalIP cannot be worked out, k3sm advertises **nothing** — the Service stays
  `<pending>` while the listeners still serve. That is deliberate: an unreachable `EXTERNAL-IP` is
  worse than none. See [troubleshooting.md](troubleshooting.md#a-loadbalancer-service-stays-pending).

- **Same-node Pods get separate per-IP port spaces for ordinary ports.** Each Pod is assigned its own
  `100.64.0.0/10` loopback address, and on the default runtime a Pod's wildcard `bind()` on an
  unprivileged port — **1024 and above, both TCP and UDP** — is transparently rewritten onto that
  address. So two same-node Pods can both hold `:8080`, and a Pod binding `0.0.0.0:8080` no longer
  collides with a LoadBalancer or NodePort wildcard listener on the same port. This heals the
  previous `EADDRINUSE` collision, where a second `:8080` Pod would crash-loop. It is a **correctness
  convenience, not a security boundary** — the rewrite only redirects a Pod's *own* wildcard bind. The
  scope is deliberately narrow, with named residuals:

  - **Ports below 1024 still share one wildcard port space.** On macOS a wildcard bind needs no
    privilege at any port, but a *specific-address* bind below 1024 returns `EACCES` for a non-root
    process, and Pods never run as root — so rewriting a low-port bind would turn a working workload
    into a permission error. A Pod binding `:80` keeps today's shared behaviour and can still collide.
  - **A container that sets its own `DYLD_INSERT_LIBRARIES` opts out.** Its value replaces the one that
    carries the rewrite shim, so that container binds wildcard.
  - **A native host-binary Pod binds wildcard.** A Pod that runs an absolute host path (rather than a
    pulled image) is executed in place and is never re-signed; a hardened-runtime binary then silently
    drops the injected shim, so the rewrite does not apply and the Pod binds the wildcard address. A
    same-node `EADDRINUSE` here will name whichever Pod bound second, not the offender.
  - **Platform and statically linked binaries** the dynamic loader will not inject into also bind
    wildcard.
  - **An explicit bind to another Pod's address still works.** The rewrite touches only wildcard binds;
    the trust domain is unchanged. Same-node Pods share one `_k3sm` OS trust domain — the `vm`
    RuntimeClass is the intended boundary for untrusted workloads, and does not run yet.
  - **A grandchild process that outlives Pod teardown** can keep a socket on the address after it is
    freed (inherited behaviour, not introduced here) — the same leak the old shared wildcard had.

  Pods using the `vm` RuntimeClass will have their own network stack behind VZNAT, unaffected by all
  of the above — see [vm-runtimeclass.md](vm-runtimeclass.md).

- **k3sm reserves some ports, and rejects LoadBalancer Services that claim them.** The NodePort range
  `30000-32767` and the kubelet API port `10250` are k3sm's own wildcard listeners; Go sets no
  `SO_REUSEPORT`, so a second wildcard listener on the same port simply fails. A `type: LoadBalancer`
  Service declaring one of those ports is **rejected at `kubectl apply`** with a message naming the
  port, and the controller additionally refuses to bind it. Plain NodePort Services are unaffected —
  the apiserver allocates their `nodePort` out of that very range. Ordinary duplicate LoadBalancer
  ports are **not** arbitrated: two Services on `8080` are first-come, and the loser stays `<pending>`.

- **A LoadBalancer Service on 80 or 443 can race the ingress host.** Those are legitimate LoadBalancer
  ports, so they are deliberately **not** reserved. The ingress listeners are started *before* the
  LoadBalancer controller, so the ingress host wins in practice — but that is start ordering, not a
  guarantee. If a Service claims 80/443 and wins, the ingress host burns its bounded bind retry
  (~155 s) and then logs `ingress bind retries exhausted`, leaving Ingress disabled until the daemon
  restarts.

`spec.loadBalancerSourceRanges` is **accepted and silently ignored** today — setting it does not
restrict anything. **Planned.** When it lands it is an authorization check at the accept
path, not a firewall: the TCP handshake still completes (so the port answers a scan and a denial
arrives as a connection reset, not a timeout), it matches the immediate peer address so a relay or
NAT presents the relay's address, it applies to TCP only, and an empty range set means allow-all.
Like NetworkPolicy below, it is a hint rather than tenant isolation — every pod runs under one
`_k3sm` uid on a shared `lo0`, so an on-node pod can dial the backend directly and bypass it.

`spec.loadBalancerClass` is honoured: k3sm claims a `type: LoadBalancer` Service only when the field
is unset (the API's "default implementation" case) and ignores a Service that names another class
entirely — it neither binds its ports nor writes its status. k3sm publishes no class of its own, so
there is no value to opt into. `spec.allocateLoadBalancerNodePorts` needs nothing from k3sm: the
apiserver owns allocation, and k3sm's listeners key off whether a nodePort was actually assigned.
Note that setting it to `false` does not deallocate an already-assigned nodePort — that is upstream
behaviour, not a k3sm limitation. A Service's nodePort stays reachable regardless of its class, which
is also upstream behaviour.

Two further consequences of the LB/Ingress datapath: the userspace
splice **discards the client address** when it dials the backend, so a NetworkPolicy denying a pod
does **not** filter traffic that arrives via that pod's LoadBalancer or Ingress (planned work restores this
by carrying the real source into the policy verdict); and a failed listener bind is not visible to
`kubectl` — the Service simply stays `<pending>` and the reason is only in the daemon log, because the
provider has no `EventRecorder` yet; wiring one is planned.

All of this assumes the supported posture: a single operator's Mac with trusted namespaces. Any
principal who can create a Service can claim a host port, and k3sm does not restrict which ports —
that is an accepted risk of the ServiceLB model k3s also ships, not an oversight.

### Per-pod IP is addressing and identity, not isolation

A pod's per-pod IP is **addressing/identity only**: binds are port-scoped on shared interfaces, and
Seatbelt cannot express per-IP network filters on macOS 26. A per-pod IP is therefore **never
network isolation** — any same-node process can dial any pod IP. Untrusted workloads need the vm
RuntimeClass, same as above — and it does not run yet, so today there is no answer for them.

### Ingress TLS keys and Secrets at rest

Ingress TLS private keys are held **in-memory by the server process**, and Secrets are
**plaintext-at-rest in the kine SQLite datastore** (file mode 0600, unreachable from pods). There is
no KMS/envelope encryption: treat read access to the host disk as read access to every Secret.

### Certificate rotation does not revoke

`k3sm certificate rotate` re-issues the control plane's CA-signed leaf certificates (by restarting
the control plane, which re-issues them anyway) and proves the two CAs came through unchanged. It is
**renewal hygiene, not a compromise response**: k3sm publishes no CRL and no OCSP responder, and
`--client-ca-file` trust is CA-wide, so a superseded certificate stays valid until it expires. There
is no way to invalidate a single leaf, no CA-replacement flow, and worker/agent node certs are out of
scope (they re-issue on agent restart, which needs a fresh join token). See
[certificates.md](certificates.md).

### DNS — what resolves, and on which runtime path

k3sm does **not** run CoreDNS. Each node serves an in-process, authoritative cluster resolver on the
DNS VIP and forwards everything else to the host's upstream resolver. What a Pod actually gets
depends on the runtime path it runs on (see the `restartPolicy` section above for the two paths).

**What the resolver answers (all paths — this is the server side):**

- **A records** for `<svc>.<ns>.svc.<domain>`, including `kubernetes.default.svc` → the apiserver VIP.
- **Headless Services** — the all-backends A set for the bare Service name.
- **Per-endpoint identity A records** — `<hostname>.<svc>.<ns>.svc.<domain>` for StatefulSet Pods,
  dashed-IP form otherwise — and stateless pod A names under `<ns>.pod.<domain>`.
- **SRV** records per named port, under the `_<port>._<proto>` owner names.
- **PTR** — the reverse zone for the cluster pod and Service CIDRs is authoritative: a name inside
  either answers locally (a hit or `NXDOMAIN`) and is never forwarded upstream.
- **`ExternalName`** Services resolve, flattened CNAME→A. The one gap: an `ExternalName` whose target
  is itself inside the cluster domain is `NXDOMAIN` (deliberately not re-resolved in-cluster).
- **AAAA is never answered** — k3sm's CIDRs are IPv4.

**In-pod resolution on the default runtime — wired, with one substrate caveat.** A Pod on a
cluster-first `dnsPolicy` (`ClusterFirst`, `ClusterFirstWithHostNet`, or unset) has the cluster DNS
configuration injected into every container, and the `getaddrinfo` shim resolves unqualified Service
names against the DNS VIP with the correct search-list / ndots expansion. Three things to know:

- **The shim cannot load into a SIP platform binary** (`/bin/sh`, `/usr/bin/*`) — macOS strips
  `DYLD_INSERT_LIBRARIES` from those, so a shell script's lookups fall back to the **host** resolver
  and cluster names will not resolve. This is the same constraint as the volume-mount shim above:
  ship a compiled binary.
- **`dnsPolicy: Default` and `dnsPolicy: None` inject nothing** — those Pods use the host resolver.
  For `None` that is a gap: a Pod's own `dnsConfig.nameservers` are not yet honored.
- **Under `ClusterFirst`, `dnsConfig` is merged additively** — extra `searches` are appended and
  `ndots` is overridden. Not yet honored: `dnsConfig.nameservers`, an explicit `ndots: 0`, and
  options other than `ndots`.

**On `--runtime hostprocess`, in-pod cluster DNS is not wired.** No shim, no cluster DNS
configuration — every lookup from inside a Pod goes to the host resolver.

**On the `vm` RuntimeClass, in-pod cluster DNS is not wired either.** A guest owns its own network
stack, and the guest-network path that would carry the cluster resolver into it is not built yet — a
`vm` Pod also reports the **node's** IP as its `podIP` rather than a guest address. Treat in-guest
service discovery as unavailable; see [vm-runtimeclass.md](vm-runtimeclass.md).

### UDP Services (non-DNS) — deferred

Only **cluster DNS on `:53`** uses UDP today (the DNS VIP binds 53 directly). General **UDP Services are
unimplemented** — this covers **both ClusterIP UDP and NodePort UDP**, not just NodePort. If your
workload depends on a UDP ClusterIP or NodePort Service, it will not work yet.

### `restartPolicy` — honored on the default runtime, not on the `hostprocess` opt-out

k3sm has **two pod runtimes**, and this is the first place the difference is user-visible. The
default is the **image runtime** (`k3sm server` / `k3sm node` with no `--runtime` flag), which every
installed cluster uses; `--runtime hostprocess` is an explicit rootless-dev opt-out that runs bare
native processes with no image handling. Pods using the [`vm` RuntimeClass](vm-runtimeclass.md) run
on the default runtime too, so they inherit its behavior here.

**On the default runtime, `restartPolicy` is honored** — the container is restarted **in place**, and
`kubectl` shows the restart count and a `CrashLoopBackOff` waiting reason exactly as upstream does:

- `Always` restarts on any exit, including a clean exit 0; `OnFailure` restarts on a non-zero exit
  code or a non-zero terminating signal (so an OOM kill counts); `Never` does not restart.
- A **native sidecar** (an init container with `restartPolicy: Always`) is restarted under an
  effective `Always` regardless of the Pod's own policy, per upstream sidecar semantics.
- The backoff schedule matches the upstream kubelet: a 10 s base, doubling, capped at 300 s, reset
  once the container has stayed up past the stabilization window. A committed liveness-probe failure
  and a failed `postStart` hook restart the container through the same path.

**The one remaining gap on the default runtime: plain init containers are not restarted.** A regular
(non-sidecar) init container that fails under `Always` / `OnFailure` is not re-run in place — the Pod
does not proceed, and a controller replacing the Pod is what unsticks it.

**On `--runtime hostprocess`, `restartPolicy` is not honored at all.** An exited container is reaped
once and never respawned, whatever the Pod or container policy says. If you are on that opt-out, a
process that exits stays exited until a `Deployment`/`Job` controller replaces the Pod.

### `vm` RuntimeClass and multi-node HA are EXPERIMENTAL

Both ship as documented **EXPERIMENTAL** and should be treated as preview-quality — but they are on
different tracks:

- The **`vm` RuntimeClass** (running Linux images in a per-Pod micro-VM) boots and runs a Pod
  end to end — create-to-Running restarts measure a 165 ms median on the reference hardware
  (the figures below) — but the install-time artifact chain is not wired yet: the guest kernel
  and initramfs it boots are dev-provided, not fetched and verified at install. Treat the whole
  path as preview-quality. It is targeted at the **v0.1.0** public release as
  EXPERIMENTAL and **`linux/arm64` only** (`linux/amd64` needs in-guest translation and is held for
  a later release), and is **launch-gated**: announced only if its live lab proof is green against
  the release artifact. The **de-EXPERIMENTAL graduation** — the branding removed, with published
  performance figures — is the **v0.2** milestone. See [vm-runtimeclass.md](vm-runtimeclass.md).
- **Multi-node and HA** are not launch-blocking; their de-EXPERIMENTAL graduation is the **v0.3**
  milestone. See [multi-node.md](multi-node.md) and [ha.md](ha.md).

### `vm` Pods: node selection and security-context admission

Two admission facts trip people up on the `vm` path specifically.

**The node is still darwin — select it as one.** A `vm` Pod runs a Linux guest, but the *node* it
schedules onto is a Mac, not a Linux node. The natural reflex — reaching for
`kubernetes.io/os: linux` because the container image is Linux — schedules nowhere, because no node
ever carries that label. Write both keys together:

```yaml
spec:
  runtimeClassName: vm
  nodeSelector:
    kubernetes.io/os: darwin   # the node's OS — always darwin, guest or not
```

See [vm-runtimeclass.md](vm-runtimeclass.md) for the full selector shape, including the
`k3sm.io/virtualization` capability the RuntimeClass merges in for you.

**A foreign `runAsUser` or `fsGroup` is rejected at admission, `vm` Pods included.** The cluster-wide
policy that pins every Pod's `securityContext.runAsUser`/`fsGroup` to the node's own identity exists
because the native host-process path has no way to honor a different uid — there is no per-pod uid
isolation to grant it (see [above](#no-per-pod-uid-isolation)). A Linux guest genuinely *can* run as an
arbitrary uid, so carving out an exemption for `vm` Pods is a reasonable target, but it has not shipped:
today the policy applies uniformly, before the runtime is even consulted. Applying a `vm` Pod that sets
a foreign `runAsUser` or `fsGroup` is refused outright (a `422` at `kubectl apply`), not silently
downgraded. Until an exemption ships, either drop the field and accept the node's own identity inside
the guest, or keep that workload on the native path where the same restriction already applies.

### `vm` Pods: a container restart recreates the whole VM

There is no in-guest process supervisor on this path: a `vm` Pod's container **is** the guest, so
`restartPolicy` acting on it means tearing the micro-VM down and creating a new one, not restarting a
process inside a surviving one. Measured on the reference hardware, that recreate is fast — cold boot
(VM create to first console output) came in at a median of **165 ms** (p95 171 ms, N=20), and kernel
start to init exec at a median of **50 ms**. Say it plainly for planning purposes: on this path,
**container restart is pod recreate**, and it is cheap enough that a `CrashLoopBackOff` cycle behaves
the same way it would on the native path.

### `vm` Pods: `linux/arm64` only

The `vm` path runs **`linux/arm64`** guest images. It does not run `linux/amd64` in this release —
in-guest translation for that architecture is a planned follow-up, not something you can opt into
today. What you see depends on how the image is described:

- An image whose manifest names `linux/amd64` **only**, and is annotated as such, is refused **before**
  anything is created — the RuntimeClass's platform check rejects it at admission and records an event
  naming the missing capability. Nothing boots and nothing is left half-started.
- An image with no usable platform annotation at all fails later, at the ordinary image-pull step, the
  same way any unresolvable image reference would.

A multi-arch image that includes a `linux/arm64` variant is unaffected either way — it pulls and runs
that variant normally.

### `vm` Pods: storage — PVCs work; `fsGroup` and a foreign uid do not; `hostPath` is refused

PVC-backed storage works on the `vm` path and is host-visible: what the guest writes lands on the host
filesystem, readable from Finder or `sudo`, same as native pod storage. Two ceilings go with that,
and one of them is now measured rather than assumed:

- **Guest writes land host-side as the pod's own OS identity, and mode bits govern readability** — a
  guest process that `chmod`s its data directory narrow (a database tightening its data directory to
  owner-only, for example) makes that host-side tree unreadable without elevated access, even though it
  sits in an ordinary Finder-visible location.
- **A foreign `runAsUser` or `fsGroup` is refused at admission**, as described [above](#vm-pods-node-selection-and-security-context-admission)
  — and the deeper reason is now measured, not just unimplemented: on the tested macOS build, the
  platform's shared-filesystem device **refuses idmapped mounts** (the kernel mechanism that would let a
  guest present files under a different owning uid without rewriting every file). That is a property of
  the current platform build, not a k3sm gap that a future k3sm release closes on its own — a workload
  that needs to write as a specific uid should run as the guest image's own root instead, which the
  guest genuinely is isolated enough to allow; a `vm` guest is single-tenant, so running as its own root
  is the supported shape for that need.
- **Rootfs writes are RAM, not disk**, backed by a bounded upper layer. A guest that writes past that
  bound sees `ENOSPC` from its own filesystem, not an out-of-memory kill — read an `ENOSPC` inside a
  `vm` guest as "the rootfs filled up," not as a resource-limit surprise.
- **`hostPath` volumes are refused outright** (fail-closed) on the `vm` path today. An allowlisted
  exception is a planned follow-up; until it ships, a `vm` Pod that needs host access has no supported
  route to it — use a PVC instead.

### `vm` Pods: filesystem performance and case-sensitivity, measured

Two things worth knowing before you plan storage-heavy workloads on this path, both measured on the
tested rig and both a property of the shared-filesystem transport, not of PVC storage generally:

- **A synchronous `fsync` costs meaningfully more than an in-guest tmpfs write** — around 0.4 ms on the
  shared filesystem versus roughly 12 µs on guest tmpfs. That is fine for most workloads and is the kind
  of thing to budget for if you are running an `fsync`-heavy database with a tight per-transaction
  latency target.
- **Sequential throughput is solid; it is transport-bound, not disk-bound.** Sequential IO over the
  shared filesystem reached roughly 1.2 GB/s write and 2.8 GB/s read on the tested rig — figures that
  describe the transport's ceiling on that rig, not a durable-media benchmark.
- **The host volume is case-insensitive, and a case-colliding pair of names collapses silently inside
  the guest.** Creating `File` and then `file` inside the guest does not produce two files — it produces
  one, with no error returned to either write. Image layers are checked for this kind of collision when
  they are unpacked, but a workload's own runtime writes are not, so a workload that itself creates
  case-colliding filenames on this path will lose data silently.

### `vm` Pods: networking — same-node Services, not direct pod IPs

A `vm` Pod **consumes** ClusterIP Services on its own node like any other pod — delivery from the guest
to a Service VIP is native on this path, with no extra routes or elevated privileges involved. **Serving**
as a Service backend is not wired yet: the proxy dials a backend at its published address, and a `vm`
Pod's live guest address reaches the proxy through the same planned follow-up as source attribution.
Until that ships, put `vm` workloads behind a Service for *their clients'* sake, but do not expect
traffic to reach them through it.

**Dialing a `vm` Pod's pod IP directly does not work.** The pod IP a `vm` Pod reports is its published
identity, not a live address a peer can connect to — so anything that depends on a direct pod-IP dial,
including headless-Service and per-pod DNS name resolution, does not reach a `vm` Pod. Reach it through
its Service's ClusterIP instead. Cross-node traffic to or from a `vm` Pod is out of scope for this
release.

Two further things worth knowing about the guest network:

- **Guest-to-guest reachability was found to be blocked on the tested rig** — two `vm` Pods on the same
  node could not address each other at all, at the network layer, under the tested configuration. That
  is an *observation* about the platform, not a documented guarantee from it, and it should not be read
  either way: k3sm does not rely on it as an isolation boundary, and it does not promise it as one
  either. Do not build a security model on guest-to-guest reachability being absent.
- **NetworkPolicy cannot yet name a `vm` Pod as an allowed traffic *source*.** Attributing a policy-table
  entry to a specific `vm` Pod's guest-network address is a planned follow-up; until it ships, a policy
  rule that tries to allow traffic *from* a `vm` Pod cannot admit it. In the meantime, on a node hosting
  `vm` Pods, traffic arriving from that guest-network segment that cannot be attributed to a known source
  is **denied**, not silently allowed, at any destination a NetworkPolicy selects — and the resulting
  deny is logged plainly, naming what was denied and why.

### `vm` Pods: isolation posture

The process that constructs and drives a `vm` Pod's guest runs confined under the **same Seatbelt
sandbox profile** as every other pod-hosting process on the node — that was measured working on the
tested rig, in both possible orderings (confine-then-construct and construct-then-confine). The `vm`
RuntimeClass remains the recommended rung for untrusted or multi-tenant workloads; see
[above](#no-per-pod-uid-isolation) for why the default native path cannot offer the same boundary.

### Node capability labels are probed once at daemon start

The `k3sm.io/*` node capability labels — `k3sm.io/virtualization`, `k3sm.io/rosetta`,
`k3sm.io/rosetta-linux` — are stamped from probes that run **once, when the node daemon starts**, and
are not re-evaluated while it runs.

The **gain** direction is merely inconvenient: install Rosetta 2, restart the daemon, the label appears
(see [vm-runtimeclass.md](vm-runtimeclass.md#installing-rosetta-after-the-node-is-up--restart-required)).

The **loss** direction is a real ceiling. A node that **loses** a capability — Rosetta 2 removed, the
virtualization capability withdrawn — **keeps advertising it** until the daemon restarts. In that window
the scheduler keeps binding Pods that select the capability onto a node that can no longer honor them,
and those Pods fail at start rather than staying `Pending` on another node. Remediation, until the
daemon is restarted:

```sh
# stop advertising the capability immediately
kubectl label node <node> k3sm.io/rosetta- k3sm.io/rosetta-linux-

# then restart the daemon so the probes re-run and the labels reflect reality
sudo launchctl kickstart -k system/io.k3sm.server
```

The label removal on restart is itself only proven against the node object k3sm *constructs*; whether a
label **deletion** propagates through Virtual Kubelet's node reconcile to the datastore in every case is
not yet verified in a lab. `k3sm.io/virtualization` has always had the same property. Treat the manual
`kubectl label ... -` above as the reliable way to withdraw a capability claim.

### Unprivileged `server` + PVCs need `--pod-root`

An unprivileged `k3sm server` (no `sudo`) with no `--pod-root` override roots the runtime — image
cache and pod dirs, including PV storage — under `$HOME`, because the default derives from the
control-plane work-dir's parent. The sandbox generator denies `/Users` **unconditionally**: it is a
hard-coded protected prefix with no allowlist knob, and none will be added (closed 2026-08-29). So a
PVC in that default posture is refused with `ErrProtectedPath`. The remedy is `--pod-root`, which
relocates the runtimed on-disk root off `/Users` — `--work-dir` alone only moves control-plane state
(kine DB, certs, kubeconfig) and does not change the pods root.

### Single-node datastore consistency

k3sm embeds **kine** over **SQLite (WAL)**. On a single node the datastore serves a **consistent LIST**;
under churn there is a **potential watch-staleness** posture that is **soak-pending** validation (the
dev-Mac churn soak). Until that soak is signed off, treat heavy-churn watch semantics as
accepted-with-known-issue rather than guaranteed. See [backup-restore.md](backup-restore.md) for the
datastore operational model.

## MLX / Apple-GPU workloads

MLX and Apple-GPU workloads (the `MLXModel` CRD and the `mlx.k3sm.io/gpu` extended resource) have
their own page — see [MLX quickstart](mlx-quickstart.md). They are not covered by these general
user pages; nothing here should be read as describing GPU behavior.
