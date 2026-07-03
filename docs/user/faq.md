# FAQ

Short answers. Follow the links for the full story.

## Is k3sm a certified Kubernetes distribution?

No. k3sm **cannot pass** the CNCF `[Conformance]` / Sonobuoy suite, which assumes Linux containers,
cgroups, CNI, and network namespaces — k3sm has none of them. See [limitations.md](limitations.md).

## Does k3sm use Docker or a VM?

No. By default Pods run as **native Darwin processes** — no Linux, no containers, no VM. A VM path exists
only for the optional [`vm` RuntimeClass](vm-runtimeclass.md) used to isolate untrusted workloads.

## Can I run my existing Docker/OCI Linux images?

No — those carry a Linux userland. Workloads must be **adapted** to the native image model
(`k3sm build`). See [images.md](images.md) and [limitations.md](limitations.md).

## Why did my container exit and not restart?

`restartPolicy` is **not honored live** yet — an exited container is reaped, not respawned. See
[limitations.md](limitations.md).

## Does cluster DNS work inside a Pod?

Partially. The resolver algorithm works, but **in-pod cluster-DNS wiring is unwired at `main`** and
headless/SRV/PTR records are planned. See [limitations.md](limitations.md).

## Do UDP Services work?

Only cluster DNS on `:53`. General UDP Services (ClusterIP and NodePort) are deferred. See
[limitations.md](limitations.md).

## Are pods isolated from each other?

Not by uid — same-node Pods share one `_k3sm` trust domain. Use the [`vm` RuntimeClass](vm-runtimeclass.md)
for untrusted workloads.

## Is multi-node / HA production-ready?

No — both ship **EXPERIMENTAL**. See [multi-node.md](multi-node.md) and [ha.md](ha.md).

## Which Kubernetes version does k3sm track?

See [versions.md](versions.md) — and read the live pin from `k3sm version`.

## How do I upgrade?

`brew upgrade` restarts the daemon via launchd; multi-node is node-by-node. See [upgrade.md](upgrade.md).

## Do I need `sudo` every time?

No — only the one-time `sudo k3sm install`. See [install.md](install.md).
