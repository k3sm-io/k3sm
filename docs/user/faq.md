# FAQ

Short answers. Follow the links for the full story.

## Is k3sm a Certified Kubernetes Distribution?

No. k3sm **cannot pass** the CNCF `[Conformance]` / Sonobuoy suite, which assumes Linux containers,
cgroups, CNI, and network namespaces — k3sm has none of them. See [Limitations](limitations.md).

## Does k3sm Use Docker or a VM?

No. By default Pods run as **native Darwin processes** — no Linux, no containers, no VM. An optional
[`vm` RuntimeClass](vm-runtimeclass.md) runs `linux/arm64` Pods in a per-Pod micro-VM to isolate
untrusted workloads — see [Limitations](limitations.md).

## Can I Run My Existing Docker/OCI Linux Images?

No — those carry a Linux userland, and a k3sm Pod is a Darwin process. A Linux image is refused at
pull, naming the platforms it offers and the one this node needs.

You can still use images, and the usual toolchain around them: build a `darwin/arm64` binary,
package it with `k3sm build`, then `k3sm image load` it or `k3sm image push` it to a registry the
node pulls from. Tags, digests, `imagePullPolicy` and `imagePullSecrets` all behave normally. The
short version is [What runs](what-runs.md); the reference is [Images](images.md).

Unmodified `linux/arm64` images are the province of the [`vm` RuntimeClass](vm-runtimeclass.md)
(`linux/amd64` is not supported yet). See also
[Limitations](limitations.md).

## Why Did My Container Exit and Not Restart?

On the default runtime it should have — `restartPolicy` **is** honored, with an upstream-shaped
`CrashLoopBackOff`. The two cases where it is not: a plain (non-sidecar) **init** container, which is
not re-run in place, and a node started with `--runtime hostprocess`, the rootless-dev opt-out that
reaps an exited container without respawning it. See
[Limitations](limitations.md#restartpolicy--honored-on-the-default-runtime-not-on-the-hostprocess-opt-out).

## Does Cluster DNS Work Inside a Pod?

On the default runtime, yes — cluster Service names, headless Services, StatefulSet per-Pod names,
SRV and PTR all resolve from inside a Pod. Two caveats: the resolver is k3sm's own, not CoreDNS
(IPv4/A only, no AAAA), and the `getaddrinfo` shim that redirects a Pod's lookups **cannot load into
a SIP platform binary** such as `/bin/sh`, so shell-script lookups fall back to the host resolver.
In-pod cluster DNS is **not** wired on `--runtime hostprocess` or on the `vm` RuntimeClass. See
[Limitations](limitations.md#dns--what-resolves-and-on-which-runtime-path).

## Do UDP Services Work?

Only cluster DNS on `:53`. General UDP Services (ClusterIP and NodePort) are deferred. See
[Limitations](limitations.md).

## Are Pods Isolated From Each Other?

Not by uid — same-node Pods share one `_k3sm` trust domain. The [`vm` RuntimeClass](vm-runtimeclass.md)
is the intended boundary for untrusted workloads — see
[Limitations](limitations.md) for what it supports today.

## Is Multi-Node / HA Production-Ready?

No — both ship **EXPERIMENTAL**. See [Multi-node](multi-node.md) and [HA](ha.md).

## Which Kubernetes Version Does k3sm Track?

See [Versions](versions.md) — and read the live pin from `k3sm version`.

## How Do I Upgrade?

Re-run the install script — `curl -fsSL https://k3sm.io/install.sh | sh` — which installs the latest
release and restarts the daemons. Homebrew (`brew upgrade`) is the second install generation and
works once the tap ships. A multi-node cluster rolls node-by-node. See [Upgrade](upgrade.md).

## Do I Need `sudo` Every Time?

No — only the one-time `sudo k3sm install`. See [Install](install.md).
