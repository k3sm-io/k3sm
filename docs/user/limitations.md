# Limitations — the honest gaps

k3sm runs Kubernetes Pods as **native Darwin processes** on Apple Silicon. That design buys a
zero-Linux, zero-VM developer experience, but it also means several standard Kubernetes behaviors
**diverge by design** or are **not yet wired**. This page is the honest inventory. Read it before you
rely on k3sm for anything real.

## Where the full truth lives (cite, don't trust this page alone)

The authoritative source of "what k3sm cannot conform to and why" is
[**`docs/conformance-profile.md`**](../conformance-profile.md) — the honest self-assessment mapping
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
  CNI, and netns; k3sm has none of them. No amount of hardening changes this, and k3sm does not claim a
  Certified-Kubernetes badge. See [`conformance-profile.md`](../conformance-profile.md).

## The honest-gaps matrix

### No per-pod uid isolation

All Pods on a node run as the **same unprivileged `_k3sm` OS user**, Seatbelt-confined. There is **no
per-pod uid isolation**, so same-node Pods share a single OS trust domain. Untrusted or multi-tenant
workloads must use the **`vm` RuntimeClass** (Virtualization.framework), which gives a real isolation
boundary. See [vm-runtimeclass.md](vm-runtimeclass.md) for how to opt in. The same framing appears in
[concepts.md](concepts.md).

### Volume mounts resolve for native workloads, not `/bin/sh`

k3sm pods run at real host paths with **no chroot / mount namespace**, so a volume mounted at an
absolute container path (e.g. `/etc/nats`) is materialized under the pod data volume and made to
resolve there by a **`DYLD_INSERT_LIBRARIES` path-rebase shim** that rewrites the mounted prefixes.
The shim loads into ordinary **native workloads** (Go/C binaries — your app, `nats`, `postgres`), so
their absolute volume mounts work as expected. It **cannot** load into a **SIP platform binary**
(`/bin/sh`, `/usr/bin/*`) — macOS strips `DYLD_INSERT_LIBRARIES` from those — so a shell script that
reads a mounted file at its absolute path won't see it. Ship your workload as a compiled binary (the
native k3sm model), not a `/bin/sh`-driven image, for mounted config/secret/scratch volumes.

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

- **A pod can collide with a LoadBalancer port.** macOS has no network namespaces, so pods share **one
  port space** with the server process (runtimed's sandbox profile emits a bare `(allow network-bind)`
  — per-IP scoping does not compile on macOS 26). Previously a LoadBalancer listener bound a specific
  `lo0` address, so a pod binding `0.0.0.0:8080` never conflicted; now the listener holds
  `0.0.0.0:8080` and the pod's own `listen()` can fail `EADDRINUSE` — or vice versa, leaving the
  Service `<pending>`. Admission cannot catch this: the colliding party is a `containerPort`, not a
  Service field. Pods using the `vm` RuntimeClass are exempt (their own network stack behind VZNAT) —
  see [vm-runtimeclass.md](vm-runtimeclass.md).

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
restrict anything. **Planned (`B131`)**. When it lands it is an authorization check at the accept
path, not a firewall: the TCP handshake still completes (so the port answers a scan and a denial
arrives as a connection reset, not a timeout), it matches the immediate peer address so a relay or
NAT presents the relay's address, it applies to TCP only, and an empty range set means allow-all.
Like NetworkPolicy below, it is a hint rather than tenant isolation — every pod runs under one
`_k3sm` uid on a shared `lo0`, so an on-node pod can dial the backend directly and bypass it.

`spec.loadBalancerClass` is also ignored: k3sm claims **every** `type: LoadBalancer` Service
regardless of class and overwrites its status, so it will fight another LB implementation rather than
defer to it (`B135`).

Two further consequences of the LB/Ingress datapath: the userspace
splice **discards the client address** when it dials the backend, so a NetworkPolicy denying a pod
does **not** filter traffic that arrives via that pod's LoadBalancer or Ingress (`B131` restores this
by carrying the real source into the policy verdict); and a failed listener bind is not visible to
`kubectl` — the Service simply stays `<pending>` and the reason is only in the daemon log, because the
provider has no `EventRecorder` yet (`B75`).

All of this assumes the supported posture: a single operator's Mac with trusted namespaces. Any
principal who can create a Service can claim a host port, and k3sm does not restrict which ports —
that is an accepted risk of the ServiceLB model k3s also ships, not an oversight.

### Per-pod IP is addressing and identity, not isolation

A pod's per-pod IP is **addressing/identity only**: binds are port-scoped on shared interfaces, and
Seatbelt cannot express per-IP network filters on macOS 26. A per-pod IP is therefore **never
network isolation** — any same-node process can dial any pod IP. Untrusted workloads need the vm
RuntimeClass, same as above.

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

### DNS — what works vs what is unwired/planned

The in-process resolver and the `getaddrinfo` shim implement the **search-list / ndots / A-record**
algorithm correctly. However:

- **In-pod cluster-DNS wiring is currently unwired at `main`** — a Pod's resolver still defers to the
  **host resolver** rather than the cluster DNS Service. Wiring this is the keystone item (B18).
- **Headless Services, SRV, PTR, and pod-A records are planned, not present** (B81) — per-pod network
  identity depends on per-pod IP wiring that is not yet plumbed.

Do **not** assume CoreDNS parity. Cluster-DNS-dependent service discovery from inside a Pod is not
something you can rely on today.

### UDP Services (non-DNS) — deferred

Only **cluster DNS on `:53`** uses UDP today (the DNS VIP binds 53 directly). General **UDP Services are
unimplemented** — this covers **both ClusterIP UDP and NodePort UDP**, not just NodePort. If your
workload depends on a UDP ClusterIP or NodePort Service, it will not work yet.

### `restartPolicy` is not honored live

An exited container is **reaped, but never respawned**. The default `restartPolicy: Always` is decided
but **not yet live-wired at `main`**. This is a first-order surprise for `Deployment` and `Job` users: a
process that exits stays exited until the controller replaces the Pod, rather than the container being
restarted in place.

### `vm` RuntimeClass and multi-node HA are EXPERIMENTAL

The **`vm` RuntimeClass** (M5) and **multi-node / HA** (M6) ship as documented **EXPERIMENTAL**. They
are the v0.2 / v0.3 headlines, **not** launch-blocking, and should be treated as preview-quality. See
[vm-runtimeclass.md](vm-runtimeclass.md), [multi-node.md](multi-node.md), and [ha.md](ha.md).

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

### Single-node datastore consistency

k3sm embeds **kine** over **SQLite (WAL)**. On a single node the datastore serves a **consistent LIST**;
under churn there is a **potential watch-staleness** posture that is **soak-pending** validation (the
dev-Mac churn soak). Until that soak is signed off, treat heavy-churn watch semantics as
accepted-with-known-issue rather than guaranteed. See [backup-restore.md](backup-restore.md) for the
datastore operational model.

## MLX / Apple-GPU workloads

MLX and Apple-GPU workloads are a **separate track** (the `MLXModel` CRD and the `mlx.k3sm.io/gpu`
extended resource). They are not covered by these user pages and ship on their own schedule; nothing
here should be read as describing GPU behavior.
