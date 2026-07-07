# Limitations — the honest gaps

k3sm runs Kubernetes Pods as **native Darwin processes** on Apple Silicon. That design buys a
zero-Linux, zero-VM developer experience, but it also means several standard Kubernetes behaviors
**diverge by design** or are **not yet wired**. This page is the honest inventory. Read it before you
rely on k3sm for anything real.

## Where the full truth lives (cite, don't trust this page alone)

The authoritative, maintainer-facing sources of "what k3sm cannot conform to and why" are two
registers in the workspace docs directory:

- **`docs/UPSTREAM-ALIGNMENT.md`** — the full-surface conformance register (one row per standard
  Kubernetes feature × verdict) and the canonical **§By-design non-conformance summary**.
- **`docs/conformance-profile.md`** — the honest self-assessment mapping targeted feature classes to
  a green synthetic-conformance criterion **or** a documented ceiling.

Those two files are the single source of truth; the summaries below restate the user-visible
consequences so this page stands on its own, but they are deliberately **not** more optimistic than
the registers. When in doubt, the register wins.

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
  Certified-Kubernetes badge. See `docs/conformance-profile.md`.

## The honest-gaps matrix

### No per-pod uid isolation

All Pods on a node run as the **same unprivileged `_k3sm` OS user**, Seatbelt-confined. There is **no
per-pod uid isolation**, so same-node Pods share a single OS trust domain. Untrusted or multi-tenant
workloads must use the **`vm` RuntimeClass** (Virtualization.framework), which gives a real isolation
boundary. See [vm-runtimeclass.md](vm-runtimeclass.md) for how to opt in, and `docs/privilege-model.md`
for the full trust-domain rationale. The same framing appears in [concepts.md](concepts.md).

### NetworkPolicy is a policy hint, not a security boundary

NetworkPolicy is enforced **only on Service-VIP-mediated ingress** at the userspace proxy, with
per-pod source fidelity for same-node clients. Any direct pod-IP connection — including **all
headless-Service and StatefulSet traffic** — bypasses it completely; **egress rules and `ipBlock`
are never enforced**; and policies against `kube-dns` or the `kubernetes` VIP are unenforceable
(those VIPs bypass the proxy). It is a policy hint, NOT a security boundary — isolate untrusted
workloads with the vm RuntimeClass ([vm-runtimeclass.md](vm-runtimeclass.md)).

### Per-pod IP is addressing and identity, not isolation

A pod's per-pod IP is **addressing/identity only**: binds are port-scoped on shared interfaces, and
Seatbelt cannot express per-IP network filters on macOS 26. A per-pod IP is therefore **never
network isolation** — any same-node process can dial any pod IP. Untrusted workloads need the vm
RuntimeClass, same as above.

### Ingress TLS keys and Secrets at rest

Ingress TLS private keys are held **in-memory by the server process**, and Secrets are
**plaintext-at-rest in the kine SQLite datastore** (file mode 0600, unreachable from pods). There is
no KMS/envelope encryption: treat read access to the host disk as read access to every Secret.

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
