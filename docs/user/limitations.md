# Limitations

k3sm runs Kubernetes Pods as **native Darwin processes** on Apple Silicon. That design buys a
zero-Linux, zero-VM developer experience, but it also means several standard Kubernetes behaviors
**diverge by design** or are **not yet wired**. This page is the full inventory.

## Where the Full Truth Lives (Cite, Don't Trust This Page Alone)

The authoritative source of "what k3sm cannot conform to and why" is
[**Conformance profile**](../conformance-profile.md), the self-assessment that maps
targeted feature classes to a green synthetic-conformance criterion **or** a documented ceiling. It is
backed by a maintainer-facing full-surface conformance register (one row per standard Kubernetes
feature × verdict, with a canonical §By-design non-conformance summary) kept internal to the project.

That profile is authoritative, and it wins wherever the two disagree. The summaries below restate the
user-visible consequences so this page stands on its own; they are **not** more optimistic than the
profile.

## Headline Divergences

- Pods are native Darwin processes. There are **no Linux containers, cgroups, CNI, or network
  namespaces**, and no device-plugins or hugepages. Anything that assumes those substrates does not
  apply.
- The resource model is best-effort. There is **no CFS millicore CPU enforcement** on the native
  path, so CPU `limits` are not enforced and `HPA`-on-CPU is **unservable**. Memory is sampled
  (`proc_pid_rusage`) and can drive OOMKill, but this is best-effort, not cgroup enforcement, and
  there is no node-pressure eviction guarantee. `kubectl top` always needs an **operator-installed
  metrics-server**, which k3sm does not ship.
  The **`vm` RuntimeClass differs**. A guest is a real Linux kernel, so each container gets a cgroup2
  leaf and the node publishes genuine per-container CPU **and** memory for `vm` Pods on the
  `metrics.k8s.io` scrape target. Native Pods publish neither, because that endpoint emits the
  CPU/memory pair jointly or not at all. A `vm` Pod's memory ceiling is still the guest's whole-VM
  size rather than a per-container limit. See [`vm` RuntimeClass](vm-runtimeclass.md).
- Workloads must be adapted. A raw upstream `[Conformance]` Pod, one that assumes a Linux image,
  bind mounts, or Linux-only fields, is rejected at admission or stranded. Images are the k3sm native
  image model (see [Images](images.md)), not arbitrary OCI Linux images.
- k3sm cannot pass the CNCF `[Conformance]` suite. That suite assumes Linux containers, cgroups,
  CNI, and netns; k3sm has none of them, and k3sm does not claim a
  Certified-Kubernetes badge. See [Conformance profile](../conformance-profile.md).

## Gaps Matrix

### No Per-Pod uid Isolation

All Pods on a node run as the **same unprivileged `_k3sm` OS user**, Seatbelt-confined. There is **no
per-pod uid isolation**, so same-node Pods share a single OS trust domain. Untrusted or multi-tenant
workloads must use the **`vm` RuntimeClass** (Virtualization.framework), which gives an isolation
boundary. See [`vm` RuntimeClass](vm-runtimeclass.md) for how to opt in. The same framing appears in
[Concepts](concepts.md).

On the **`k3sm dev --datapath` tier only**, it is worse than that. `--datapath` runs the server as
root, and a Pod that declares no `securityContext.runAsUser` keeps the daemon's identity, so those
Pods run as **uid 0**. They are still Seatbelt-confined, and no installed cluster behaves this way
(the LaunchDaemon runs as `_k3sm`). Do not run untrusted workloads on `--datapath`; it is a
disposable dev tier, and `k3sm dev up --datapath` says the same thing in its banner.

### Keychain Reads Return Nothing, and Report Success

A Pod reaching the keychain gets an **empty result with a zero exit status**, not an error. The
`security` command talks to the keychain over the `com.apple.SecurityServer` mach service, which the
default-deny Seatbelt profile does not grant, and the framework treats the unreachable service as an
empty search rather than a failure. On a host whose System keychain holds certificates, asking
`security` to list every certificate in it prints them outside a Pod and prints nothing inside one;
both exit `0`. A workload that branches on "did I find a certificate" therefore takes the wrong
branch silently.

Anything built on the keychain inherits this. **Notarization** is out on two counts at once: the
`notarytool` binary lives inside the Xcode application bundle, which the profile does not read, and
its stored credentials live in the keychain. Signing with a Developer ID identity has the same
keychain dependency. Sign and notarize on the host. A `vm` Pod runs Linux, so it cannot run this
tooling either. Network is not the obstacle: every native Pod may open outbound connections on the
host network stack, and k3sm does not filter them (see "NetworkPolicy Is a Policy Hint, Not a
Security Boundary" below).

### Signing Names Files by Relative Path, and SwiftPM Cannot Finish

A Pod compiles. `clang` and `swiftc` build C, Objective-C and Swift against an installed SDK into the
Pod's own data volume, and the binary they produce runs. Ad-hoc signing works as well. `codesign -s -`
succeeds when the file is named by a **relative** path.

Naming that same file by an **absolute** path is refused with `Operation not permitted`. That is what
stops SwiftPM. `swift build` re-signs its product by absolute path as its final step, so the build
does not complete inside a Pod even though every compile and link before it succeeded.

One message on the way is not a failure, and it is worth recognising. Apple's toolchain resolves its
`xcrun` lookup cache through `confstr(_CS_DARWIN_USER_TEMP_DIR)`, which **ignores `TMPDIR`** and names
a path under `/var/folders` that the profile does not grant. Invocations therefore print
`couldn't create cache file … Operation not permitted` on **stderr** and then succeed on stdout. The
clang module cache resolves the same way, and that one would have broken compilation, so k3sm gives
every Pod its own by pointing `CLANG_MODULE_CACHE_PATH` into the Pod's data volume, for every Pod,
with no annotation required.

Signing with a Developer ID identity is a different limit, and it stands. That needs the keychain,
which a Pod cannot read (above). A `vm` Pod is no help for any of this, because it runs Linux and
builds Linux binaries, not Mac ones.

### `k3sm.io/xcode-toolchain` Grants One Node Class, and Says Nothing About the Others

A Pod that carries the `k3sm.io/xcode-toolchain` annotation asks its node for **read** access to the
node's Xcode toolchain, meaning the compilers, linker and SDKs inside the developer directory. The
Pod cannot name the directory; it can only ask for whichever one the node has. Read access is all it
is. The Pod still runs as the same `_k3sm` user with the same sandbox everywhere else.

What the annotation grants depends on what the node has selected, and only one of the three cases is
a grant:

- **A full Xcode developer directory** (`/Applications/Xcode.app/Contents/Developer`) is granted.
  This is the case the annotation exists for.
- **Command Line Tools only** (`/Library/Developer/CommandLineTools`) grants nothing, **and nothing
  needs to be granted**. That tree is already readable from inside a Pod under the default profile,
  so a Pod that wants `clang` or `swiftc` from the Command Line Tools does not need the annotation at
  all. The annotation is accepted and ignored.
- **No developer directory at all** grants nothing either. A Mac with no toolchain is still a normal
  k3sm node; a Pod asking for one is not rejected.

Two things follow that are easy to trip over. The node's developer directory is read **once, when the
node daemon starts**, so running `sudo xcode-select -s …` changes nothing for a running node until
the daemon restarts. And a Pod whose request is not granted **starts and reports healthy**, building
against whatever it can already reach. To see which case a node is in, run
`k3sm doctor` on it and read the `toolchain` row, whose fix is repeated under `Next:` when it warns;
a Pod that asked and got nothing also carries a
`XcodeToolchainUngranted` warning Event in `kubectl describe pod`.

Whichever case you are in, every `xcrun` invocation inside a Pod prints
`couldn't create cache file '/var/folders/…/xcrun_db-…'` on stderr first. It is the lookup-cache
message described above, it is not a failure, and the compile that follows it succeeds. It cannot be
silenced from inside the Pod. `xcrun`'s documented `xcrun_nocache=1` and `--no-cache` both *refresh*
the cache entry rather than skip it, so the write happens anyway, and so does the message.

A tool in `/usr/bin` (`python3`, `git`, `clang` and the other developer-tool shims) run with no
`DEVELOPER_DIR` set prints `xcode-select: error: unable to read data link at
'/var/db/xcode_select_link'` on stderr, with `Operation not permitted`. The sandbox denies that link
on purpose. The tool usually still runs, but `xcrun --find …` and other lookups routed through
`xcrun` fail with exit code 1. Two remedies work: call the Command Line Tools binary by path, for
example `/Library/Developer/CommandLineTools/usr/bin/python3`, which prints nothing extra, or set
`DEVELOPER_DIR=/Library/Developer/CommandLineTools` in the container's `env`, which makes the shims
and `xcrun` work. `DEVELOPER_DIR` only picks which toolchain runs. It changes nothing in the
sandbox profile: the data link and the `xcrun` cache stay denied.

### Volume Mounts Resolve for Native Workloads and Host Shells

k3sm pods run at host paths with **no chroot / mount namespace**, so a volume mounted at an
absolute container path (e.g. `/etc/nats`) is materialized under the pod data volume and made to
resolve there by a **`DYLD_INSERT_LIBRARIES` path-rebase shim** that rewrites the mounted prefixes.
The shim loads into ordinary **native workloads** (Go/C binaries such as your app, `nats`, or
`postgres`), so their absolute volume mounts work as expected.

macOS strips `DYLD_INSERT_LIBRARIES` from a **SIP platform binary**, so on an installed node a Pod's
`/bin/sh`, `bash`, `zsh`, `dash` and `env` run as the re-signed copies `sudo k3sm install` makes
under `/Library/k3sm/shadow`. Those copies keep the path-rebase and DNS shims, so a shell script
that reads a mounted file at its absolute path sees it, and so does whatever the script execs.

The remaining ceiling is any other restricted or hardened main process, such as the system
`python3`, `perl` or `swift`. dyld still strips the shim from those, so their absolute mount paths
resolve to the unmounted host path, and the Pod gets a `ShimInactive` Warning Event saying so. We
still prefer an entrypoint that runs your compiled binary directly when a Pod reads mounted files,
but a shell-driven image now works too.

Absolute volume-mount paths resolve **only on the root tier**. The path-rebase shim is
**euid-gated**. It must be staged under `/Library` to sit inside the pod Seatbelt read baseline, and
only euid 0 can write there, so an unprivileged (rootless) `k3sm server` never stages it, and a
rootless pod expecting an absolute mount path sees the unmounted host path instead. This is why a
ladder that depends on absolute volume mounts (e.g. the MLX acceptance gate's cache PVC) is a
root-tier run. Rootless stops at mount resolution.

### `hostPath` Volumes Are Silently Dropped, Not Refused

`hostPath` is **not modeled on any runtime path**, native or `vm`, and a Pod that declares one is
**not** rejected. `toVolume`
([`pkg/provider/translate.go`](https://github.com/k3sm-io/k3sm/blob/main/pkg/provider/translate.go))
carries no `hostPath` case, so the source falls through its `default` and the volume is skipped.
Admission does not stop it either. k3sm ships PodSecurity `enforce = privileged`, so a `hostPath` Pod
is *admitted* with a PSA **warning**, not a rejection. What you see next depends only on whether a
container mounts it.

- If a container mounts it, the Pod fails with `volume_mount %q references undefined volume`, naming
  the **mount** and never the missing `hostPath` source, so the error does not point at the cause.
- If nothing mounts it, the Pod runs to completion with **no error and no warning at all**. Nothing
  anywhere reports that the host path was ignored.

Treat a `hostPath` in a manifest as "will not be there", and use a PVC instead. An outright refusal at
admission or translation time, and an allowlisted exception after it, are follow-ups.

### `emptyDir` with `medium: Memory` Is Refused, Not Silently Disk-Backed

On the default (native) runtime, a Pod that declares an `emptyDir` with a non-empty `medium` is
**refused at creation**, with a Warning Event whose reason is `FailedEmptyDirMedium` and whose
message names the volume and the medium. Native Pods are ordinary Darwin processes with no mount
namespace and no `tmpfs`, so a `medium: Memory` volume could only ever be an ordinary directory on
disk, and a workload has no way to tell that it got one.

- `medium: Memory`, `medium: HugePages`, and `medium: HugePages-<size>` are all refused. The empty
  (default) medium is the only one this path serves.
- Two ways out: remove the `medium` field and take an ordinary disk-backed directory, or schedule
  the Pod with `runtimeClassName: vm`, whose Linux guest honors `medium: Memory` as a real `tmpfs`
  (see [the `vm` RuntimeClass](vm-runtimeclass.md)).
- `sizeLimit` is **not enforced** on any native `emptyDir`. The directory is disk-backed with no
  quota, so nothing stops a Pod from writing past what it asked for.
- The `hostprocess` opt-out runtime has no volume handling at all, so neither `emptyDir` nor this
  refusal applies there.

### ConfigMap, Secret and Token Volumes Refresh About Once a Minute

On the default (native) runtime, a running Pod's `configMap`, `secret`, `downwardAPI` and `projected`
volumes are re-read from the API server about once a minute, the kubelet's own cadence. Edit a
ConfigMap and a Pod that mounts it sees the new value within roughly a minute, without a restart.

- **Atomic swap.** Each refresh writes a complete new copy of the volume beside the old one and
  switches the volume's `..data` symlink to it in one rename, the kubelet's layout. A reader sees the
  whole old set or the whole new set, never a mix, and a file already open keeps its old contents.
- **`subPath` mounts are never refreshed.** A key mounted with `subPath` keeps the value it had when
  the Pod started. This matches Kubernetes.
- **Environment variables are never updated.** `env` and `envFrom` values are fixed when the
  container starts, as in Kubernetes. Restart the Pod to pick up a changed value.
- **Immutable ConfigMaps and Secrets are not re-read.** A volume whose every source is marked
  `immutable: true` is skipped after its first read, because its data cannot change. Deleting and
  recreating the object under the same name does not reach a running Pod; recreate the Pod.
- **ServiceAccount tokens are re-minted at 80% of their lifetime.** A projected token is replaced
  once less than a fifth of its `expirationSeconds` remains. After a node daemon restart every token
  is re-minted on the first refresh.
- **`vm` Pods are not refreshed.** Their volumes are staged into the guest once, at start. Recreate
  a `vm` Pod to pick up a changed ConfigMap, Secret, or `kube-root-ca.crt`.
- **A failed refresh keeps the old contents.** If a source cannot be read (a ConfigMap deleted
  underneath a running Pod, a permission error), the volume keeps its last good copy and the Pod
  gets a `ProjectedVolumeRefreshFailed` Warning Event naming the volume. If the new contents went
  live but the cleanup after the swap failed, the Pod reads the new data and gets a
  `ProjectedVolumeRefreshWarning` Warning Event naming the volume and the cleanup error instead.
  Each Event is recorded once per volume per kind of failure, and again if the volume recovers and
  then fails.

### NetworkPolicy Is a Policy Hint, Not a Security Boundary

NetworkPolicy is enforced **only on Service-VIP-mediated ingress** at the userspace proxy, with
per-pod source fidelity for same-node clients. Any direct pod-IP connection, including **all
headless-Service and StatefulSet traffic**, bypasses it completely. **Egress rules and `ipBlock`
are never enforced**, and policies against `kube-dns` or the `kubernetes` VIP are unenforceable
because those VIPs bypass the proxy. It is a policy hint, NOT a security boundary. Isolate untrusted
workloads with the [`vm` RuntimeClass](vm-runtimeclass.md).

The `k3sm.io/internet-egress` annotation is the same kind of control. It records that a Pod needs to
reach networks beyond the cluster, and admission surfaces a hand-set one, but leaving it off does not
stop a native Pod from reaching the internet. k3sm does not manage the host's packet filter, and the
sandbox cannot restrict network access by destination address, so nothing filters a connection a
Pod opens on the shared host network stack. Treat egress restriction on the default runtime as
cooperative, and run workloads you do not trust on the [`vm` RuntimeClass](vm-runtimeclass.md).

### Which Addresses Your Services Answer On

Today at `main`, per port class:

- **NodePort** binds the **wildcard** `*:30000-32767` in-process. Every interface on the Mac
  answers, including `127.0.0.1` and your LAN address. This has always been the case; it is what
  NodePort means upstream.
- **LoadBalancer / Ingress** binds the **wildcard** `*:<port>`, matching k3s and the desktop
  container tools, which publish LoadBalancer ports on all interfaces.

  **The bind address and the advertised address are different.** Read them separately.
  The **port** is reachable on every interface the Mac has, including its LAN address, so treat a
  LoadBalancer Service as publishing to the local network rather than to the host alone. The
  **advertised `EXTERNAL-IP`** is the node's InternalIP, an RFC-6598 (`100.64.0.0/10`) alias on
  `lo0`. It is reachable from this Mac, from local pods, and from mesh peers over WireGuard, but
  **not routable from your LAN**. A LAN client has no route to `100.64/10`, so `curl <EXTERNAL-IP>`
  from your laptop **hangs until timeout** rather than failing fast. Dial the Mac's own LAN address
  and the Service port instead. This differs from both analogs. k3s advertises the node's LAN
  address, and the desktop container tools advertise the literal hostname `localhost`. If you need a
  LAN-usable value in `status.loadBalancer.ingress`, that is not what k3sm publishes today.

  If the derived InternalIP cannot be worked out, k3sm advertises **nothing**, because an unreachable
  `EXTERNAL-IP` is worse than none. The Service stays `<pending>` while the listeners still serve.
  See [Troubleshooting](troubleshooting.md#loadbalancer-stuck-pending).

- Same-node Pods get separate per-IP port spaces for ordinary ports. Each Pod is assigned its own
  `100.64.0.0/10` loopback address, and on the default runtime a Pod's wildcard `bind()` on an
  unprivileged port (**1024 and above, both TCP and UDP**) is transparently rewritten onto that
  address. So two same-node Pods can both hold `:8080`, and a Pod binding `0.0.0.0:8080` no longer
  collides with a LoadBalancer or NodePort wildcard listener on the same port. This heals the
  previous `EADDRINUSE` collision, where a second `:8080` Pod would crash-loop. It is a **correctness
  convenience, not a security boundary**, because the rewrite only redirects a Pod's *own* wildcard
  bind. The scope is narrow, and the residuals are named:

  - Ports below 1024 still share one wildcard port space. On macOS a wildcard bind needs no
    privilege at any port, but a *specific-address* bind below 1024 returns `EACCES` for a non-root
    process, and Pods never run as root, so rewriting a low-port bind would turn a working workload
    into a permission error. A Pod binding `:80` keeps today's shared behaviour and can still collide.
  - A container that sets its own `DYLD_INSERT_LIBRARIES` opts out. Its value replaces the one that
    carries the rewrite shim, so that container binds wildcard.
  - A native host-binary Pod binds wildcard. A Pod that runs an absolute host path (rather than a
    pulled image) is executed in place and is never re-signed; a hardened-runtime binary then silently
    drops the injected shim, so the rewrite does not apply and the Pod binds the wildcard address. A
    same-node `EADDRINUSE` here will name whichever Pod bound second, not the offender.
  - Platform and statically linked binaries that the dynamic loader will not inject into also bind
    wildcard.
  - An explicit bind to another Pod's address still works. The rewrite touches only wildcard binds,
    and the trust domain is unchanged. Same-node Pods share one `_k3sm` OS trust domain, and the `vm`
    RuntimeClass is the intended boundary for untrusted workloads (see below).
  - A grandchild process that outlives Pod teardown can keep a socket on the address after it is
    freed. That behaviour is inherited rather than introduced here, and it is the same leak the old
    shared wildcard had.

  Pods using the `vm` RuntimeClass have their own network stack behind VZNAT, unaffected by all of the
  above. See [`vm` RuntimeClass](vm-runtimeclass.md). What a guest can reach was measured rather than
  assumed:

  | from a `vm` Pod's guest to | result |
  |---|---|
  | another `vm` Pod's guest on the same node | **blocked** (TCP refused, ICMP 100% loss) |
  | a ClusterIP Service, including the cluster DNS VIP | reachable (TCP and UDP) |
  | the internet, through the NAT gateway | reachable |
  | another machine on the host's LAN | **blocked** |

  Two consequences follow. Guest-to-guest isolation is **stronger** than a shared L2 segment would
  give, because a `vm` Pod cannot address its neighbour's guest directly, so same-node `vm` traffic
  cannot bypass Services. And a guest reaches the internet but not the host's LAN, so a `vm` Pod is
  not a route onto your local network. Both are properties of the platform's NAT rather than of a
  k3sm policy engine. They are what was measured here, not a guarantee k3sm enforces, and they are
  not a substitute for NetworkPolicy.

- k3sm reserves some ports, and rejects LoadBalancer Services that claim them. The NodePort range
  `30000-32767` and the kubelet API port `10250` are k3sm's own wildcard listeners; Go sets no
  `SO_REUSEPORT`, so a second wildcard listener on the same port simply fails. A `type: LoadBalancer`
  Service declaring one of those ports is **rejected at `kubectl apply`** with a message naming the
  port, and the controller additionally refuses to bind it. Plain NodePort Services are unaffected,
  because the apiserver allocates their `nodePort` out of that very range. Ordinary duplicate
  LoadBalancer ports are **not** arbitrated. Two Services on `8080` are first-come, and the loser
  stays `<pending>`.

- A LoadBalancer Service on 80 or 443 can race the ingress host. Those are legitimate LoadBalancer
  ports, so they are **not** reserved. The ingress listeners are started *before* the
  LoadBalancer controller, so the ingress host wins in practice, but that is start ordering, not a
  guarantee. If a Service claims 80/443 and wins, the ingress host burns its bounded bind retry
  (~155 s) and then logs `ingress bind retries exhausted`, leaving Ingress disabled until the daemon
  restarts.

`spec.loadBalancerSourceRanges` is enforced on LoadBalancer traffic only, the k3s behaviour. The
field wins; when it is empty the legacy `service.beta.kubernetes.io/load-balancer-source-ranges`
annotation applies; when both are empty every client is allowed. It covers the LoadBalancer
listeners and the ingress listeners (through the ranges on `kube-system/k3sm-ingress`). A Service's
nodePort stays unrestricted, as it does under kube-proxy and klipper-lb. Entries are trimmed of
spaces, and one entry that does not parse fails the whole set. On a new Service that means no
listener is opened, it stays `<pending>`, and a `SourceRangesInvalid` Warning Event is recorded on
it. On an edit to a Service that is already serving, the last valid ranges stay in force and the
same Event is recorded. Deleting `kube-system/k3sm-ingress` recreates it with the default spec,
which lifts its ranges; the last ranges stay in force until the recreated Service arrives, and a
`SourceRangesReset` Warning Event on it says they must be set again. The check is an authorization at the accept path, not a firewall: the TCP
handshake still completes (so the port answers a scan and a denial arrives as a closed connection,
not a timeout), it matches the immediate peer address so a relay or NAT presents the relay's
address, it applies to TCP only, and loopback is not exempt. Like NetworkPolicy below, it is a hint
rather than tenant isolation, because every pod runs under one `_k3sm` uid on a shared `lo0`, so an
on-node pod can dial the backend directly and bypass it.

`spec.loadBalancerClass` is honoured. k3sm claims a `type: LoadBalancer` Service only when the field
is unset (the API's "default implementation" case) and ignores a Service that names another class
entirely, neither binding its ports nor writing its status. k3sm publishes no class of its own, so
there is no value to opt into. `spec.allocateLoadBalancerNodePorts` needs nothing from k3sm, because
the apiserver owns allocation and k3sm's listeners key off whether a nodePort was assigned.
Setting it to `false` does not deallocate an already-assigned nodePort, which is upstream
behaviour rather than a k3sm limitation. A Service's nodePort stays reachable regardless of its
class, which is also upstream behaviour.

The LB/Ingress datapath has two further consequences. The userspace splice **discards the client
address** when it dials the backend, so a NetworkPolicy denying a pod does **not** filter traffic
that arrives via that pod's LoadBalancer or Ingress. That client-address gap is a separate tracked
item. Upstream behaves similarly for `externalTrafficPolicy: Cluster`, which SNATs the client, so
only `Local` would preserve the address. And a failed listener bind is not visible to `kubectl`. The
Service simply stays `<pending>` and the reason is only in the daemon log, because the provider has
no `EventRecorder` yet; wiring one is planned.

All of this assumes one operator's Mac with trusted namespaces, which is what k3sm supports. Any
principal who can create a Service can claim a host port, and k3sm does not restrict which ports.
That is an accepted risk of the ServiceLB model k3s also ships.

### Per-Pod IP Is Addressing and Identity, Not Isolation

A pod's per-pod IP is **addressing/identity only**. Binds are port-scoped on shared interfaces, and
Seatbelt cannot express per-IP network filters on macOS 26. A per-pod IP is therefore **never
network isolation**, and any same-node process can dial any pod IP. Untrusted workloads need the
`vm` RuntimeClass, same as above.

### Ingress TLS Keys and Secrets at Rest

Ingress TLS private keys are held **in-memory by the server process**, and Secrets are
**plaintext-at-rest in the kine SQLite datastore** (file mode 0600, unreachable from pods). There is
no KMS/envelope encryption. Treat read access to the host disk as read access to every Secret.

### Certificate Rotation Does Not Revoke

`k3sm certificate rotate` re-issues the control plane's CA-signed leaf certificates (by restarting
the control plane, which re-issues them anyway) and verifies that the two CAs came through unchanged.
It is **renewal hygiene, not a compromise response**. k3sm publishes no CRL and no OCSP responder,
and `--client-ca-file` trust is CA-wide, so a superseded certificate stays valid until it expires.
There is no way to invalidate a single leaf, no CA-replacement flow, and worker/agent node certs are
out of scope (they re-issue on agent restart, which needs a fresh join token). See
[Certificates](certificates.md).

### DNS: What Resolves, and on Which Runtime Path

k3sm does **not** run CoreDNS. Each node serves an in-process, authoritative cluster resolver on the
DNS VIP and forwards everything else to the host's upstream resolver. What a Pod gets
depends on the runtime path it runs on (see the `restartPolicy` section above for the two paths).

**What the resolver answers on every path (this is the server side):**

- **A records** for `<svc>.<ns>.svc.<domain>`, including `kubernetes.default.svc` → the apiserver VIP.
- **Headless Services** get the all-backends A set for the bare Service name.
- **Per-endpoint identity A records**, `<hostname>.<svc>.<ns>.svc.<domain>` for StatefulSet Pods and
  the dashed-IP form otherwise, plus stateless pod A names under `<ns>.pod.<domain>`.
- **SRV** records per named port, under the `_<port>._<proto>` owner names.
- **PTR** records, because the reverse zone for the cluster pod and Service CIDRs is authoritative: a
  name inside either answers locally (a hit or `NXDOMAIN`) and is never forwarded upstream.
- **`ExternalName`** Services resolve, flattened CNAME→A. The one gap is an `ExternalName` whose
  target is itself inside the cluster domain, which is `NXDOMAIN` (not re-resolved in-cluster).
- **AAAA is never answered**, because k3sm's CIDRs are IPv4.

**Every process on an installed node resolves cluster FQDNs.** `k3sm netd` registers one supplemental
DNS entry in the macOS resolver configuration: `svc` and the cluster domain are routed to the DNS VIP,
and nothing else is. mDNSResponder applies it to every process on the Mac, platform binaries
included, the way a Linux container inherits its `resolv.conf`. So any process, in a Pod or on the
host, resolves `<svc>.<ns>.svc.<domain>` and the partial `<svc>.<ns>.svc` (the node resolver
completes it server-side). The entry adds no search domains: host processes do not start completing
bare names, and `/etc/resolv.conf` is unchanged. `scutil --dns` lists it while k3sm is installed;
`k3sm uninstall` removes it, and the `node-resolver` row of `k3sm status` says whether it is there.

While the node DNS is down (the node daemon stopped or restarting), the entry still routes `svc` and
the cluster domain to the DNS VIP. A host lookup of a cluster-shaped name then waits about 5 seconds
and returns the cached answer, or fails. Names outside `svc` and the cluster domain are unaffected.
We measured this on 2026-09-26 on a Mac with the agent stopped.

**Single-label names and per-namespace precedence need the `getaddrinfo` shim.** A Pod on a
cluster-first `dnsPolicy` (`ClusterFirst`, `ClusterFirstWithHostNet`, or unset) gets the cluster DNS
configuration injected into every container, and the shim applies the Pod's search list and ndots, so
a bare `postgres` resolves in the Pod's own namespace first. The node resolver does not do this. A
process without the shim resolves the fully qualified name and `<svc>.<ns>.svc`, but not
`<svc>.<ns>`, `<svc>.svc` or `<svc>` alone. That matches k3s, where a process on the host resolves
no cluster names at all. The shim also carries the
bind/connect discipline that gives a Pod its own source address and port space. What to know:

- **Host shells keep the shim.** macOS strips `DYLD_INSERT_LIBRARIES` from a SIP platform binary, so
  `sudo k3sm install` makes re-signed copies of `/bin/bash`, `/bin/zsh`, `/bin/dash` and `/usr/bin/env`
  under `/Library/k3sm/shadow`, and the runtime runs those in their place: a `/bin/sh -c` entrypoint, a
  script whose shebang names one of them, and one exec'd from inside the Pod. A macOS update replaces
  the host binaries and the copies then lag behind. The `shadow-shells` row of `k3sm status` reports
  the drift, and running `sudo k3sm install` again makes a fresh set.
- **Any other restricted main process loses the shim**, for example `/usr/bin/python3` or a
  hardened-runtime binary. The runtime reads the process's code-signing flags after it starts and the
  Pod gets a `ShimInactive` Warning Event naming what is unavailable. Such a process still resolves
  FQDNs and `<svc>.<ns>.svc` through the node resolver. Use fully qualified names, or a compiled
  binary as the entrypoint.
- **`dnsPolicy: Default` and `dnsPolicy: None` inject nothing**, so those Pods use the host resolver,
  which now answers cluster-shaped names (`*.svc`, `*.<domain>`) from the node resolver entry. For
  `None` that is a gap, because a Pod's own `dnsConfig.nameservers` are not yet honored.
- **Under `ClusterFirst`, `dnsConfig` is merged additively**, so extra `searches` are appended and
  `ndots` is overridden. Not yet honored are `dnsConfig.nameservers`, an explicit `ndots: 0`, and
  options other than `ndots`.

**On `--runtime hostprocess`, in-pod cluster DNS is not wired.** There is no shim and no cluster DNS
configuration, so every lookup from inside a Pod goes to the host resolver.

**On the `vm` RuntimeClass, in-pod cluster DNS works.** The guest brings up its interface, leases an
address on the node's NAT segment, and installs a default route; `/etc/resolv.conf` is written by the
guest with the cluster resolver and search list, and lookups reach the cluster DNS VIP. Resolving a
service FQDN and connecting to the returned ClusterIP both work.

Two caveats remain. A guest's musl resolver may ignore `options ndots`, so prefer a **fully qualified**
service name (`svc.ns.svc.cluster.local`) from inside a `vm` Pod rather than relying on the search
list to complete a short name. And a guest's link MTU is 1500 and the link will not lower it, so
cross-node `vm` traffic is not claimed in this release.

### `externalTrafficPolicy: Local` Is Not Honored

The userspace Service proxy splices each connection, so the client's source address does not survive
to the backend and the node cannot tell a local endpoint apart from a remote one. A Service that sets
`externalTrafficPolicy: Local` is admitted with a warning and then behaves as `Cluster`.

### UDP Services (Non-DNS) Are Deferred

Only **cluster DNS on `:53`** uses UDP today (the DNS VIP binds 53 directly). General **UDP Services are
unimplemented**, and that covers **both ClusterIP UDP and NodePort UDP**, not just NodePort. If your
workload depends on a UDP ClusterIP or NodePort Service, it will not work yet.

### `restartPolicy` Is Honored on the Default Runtime, Not on the `hostprocess` Opt-Out

k3sm has **two pod runtimes**, and this is the first place the difference is user-visible. The
default is the **image runtime** (`k3sm server` / `k3sm node` with no `--runtime` flag), which every
installed cluster uses; `--runtime hostprocess` is an explicit rootless-dev opt-out that runs bare
native processes with no image handling. Pods using the [`vm` RuntimeClass](vm-runtimeclass.md) run
on the default runtime too, so they inherit its behavior here.

**On the default runtime, `restartPolicy` is honored.** The container is restarted **in place**, and
`kubectl` shows the restart count and a `CrashLoopBackOff` waiting reason exactly as upstream does:

- `Always` restarts on any exit, including a clean exit 0; `OnFailure` restarts on a non-zero exit
  code or a non-zero terminating signal (so an OOM kill counts); `Never` does not restart.
- A **native sidecar** (an init container with `restartPolicy: Always`) is restarted under an
  effective `Always` regardless of the Pod's own policy, per upstream sidecar semantics.
- The backoff schedule matches the upstream kubelet: a 10 s base, doubling, capped at 300 s, reset
  once the container has stayed up past the stabilization window. A committed liveness-probe failure
  and a failed `postStart` hook restart the container through the same path.
- Under `Never`, a failed `postStart` hook stops the container, which stays `Terminated`, and the
  Pod goes `Failed`, as upstream. Its `preStop` hook does not run before that stop.
- On a `vm` Pod that stop is not available: the container is held NotReady and keeps running.

**Plain init containers are not restarted**, and that is the one remaining gap on the default
runtime. A regular (non-sidecar) init container that fails under `Always` / `OnFailure` is not re-run
in place, the Pod does not proceed, and a controller replacing the Pod is what unsticks it.

**On `--runtime hostprocess`, `restartPolicy` is not honored at all.** An exited container is reaped
once and never respawned, whatever the Pod or container policy says. If you are on that opt-out, a
process that exits stays exited until a `Deployment`/`Job` controller replaces the Pod.

### What Survives a Node-Daemon Restart

A native Pod's processes outlive the node daemon. When the daemon restarts (`sudo launchctl kickstart
-k system/io.k3sm.server`, or `io.k3sm.agent` on a worker, a crash, an upgrade), the new daemon reads
the Pods bound to its node from the API server and re-attaches to every running Pod whose processes
are still alive, instead of killing them and creating the Pod again. A re-attached Pod keeps its Pod
IP, its listeners and its `restartCount`, and records one `PodReattached` Warning Event. Each
container runs under its own resident shim, which holds the container's output and exit status
across the restart: the container log continues with no gap, exit codes stay real, and
`kubectl exec` works on a re-attached Pod.

What a re-attached Pod does not get back:

- CPU usage restarts from zero at the re-attachment.
- A container whose shim died reports terminated with reason `ExitStatusUnknown` and exit code `-1`
  when it exits, never `0`. Its later output is not logged, `kubectl exec` into it is refused, and
  the Pod carries the `k3sm.io/log-stream-lost` condition with reason `ShimCrashed`. Delete the Pod
  (or let its controller replace it) to get it back.

Some Pods are created again rather than re-attached: `vm` Pods (a guest never outlives its helper),
Pods that were still running an init container, Pods whose processes all exited, and every Pod after
the daemon binary itself changed (an upgrade), because a Pod is only supervised by the exact build
that started it.

A change to a runtimed flag that shapes the sandbox profile (work dir, home, resolver or apiserver
VIP, pod logs dir, shadow bin dir) makes the next daemon start recreate every Pod instead of
re-attaching.

`sudo k3sm uninstall` stops every recorded Pod process group (SIGTERM, then SIGKILL after 10 s) once
the daemons are gone, so nothing k3sm started keeps running and a reinstall starts every Pod fresh. A
group whose original leader process has already exited is left alone and logged, because nothing
proves it still belongs to the Pod.

### `vm` RuntimeClass, Multi-Node, and HA Status

- The **`vm` RuntimeClass** (running Linux images in a per-Pod micro-VM) boots and runs a Pod.
  Create-to-Running restarts measure a 165 ms median (the figures
  below), and one idle Pod with a 512 MiB guest costs about **46 MB of host memory**,
  because the hypervisor allocates guest RAM lazily rather than reserving it. The guest kernel and
  initramfs are digest-pinned and verified on every node start. What is measured is single-node,
  and a multi-image Pod is not supported, because every container in a
  `vm` Pod shares one root filesystem, so a Pod naming two different images runs the second
  container's command against the first container's image. It ships
  **`linux/arm64` only** (`linux/amd64` needs in-guest translation and is held for a later
  release), and it passes against the release build. See
  [`vm` RuntimeClass](vm-runtimeclass.md).
- **Multi-node and HA** ship as documented **EXPERIMENTAL** and are not launch-blocking; their
  de-EXPERIMENTAL graduation is the **v0.3** milestone. See [Multi-node](multi-node.md) and
  [HA](ha.md).

### `vm` Pods: Node Selection and Security-Context Admission

Two admission facts trip people up on the `vm` path specifically.

**The node is still darwin, so select it as one.** A `vm` Pod runs a Linux guest, but the *node* it
schedules onto is a Mac, not a Linux node. The natural reflex, reaching for
`kubernetes.io/os: linux` because the container image is Linux, schedules nowhere, because no node
ever carries that label. Write both keys together:

```yaml
spec:
  runtimeClassName: vm
  nodeSelector:
    kubernetes.io/os: darwin   # the node's OS — always darwin, guest or not
```

See [`vm` RuntimeClass](vm-runtimeclass.md) for the full selector shape, including the
`k3sm.io/virtualization` capability the RuntimeClass merges in for you.

**A foreign `runAsUser` or `fsGroup` is rejected at admission, `vm` Pods included.** The cluster-wide
policy that pins every Pod's `securityContext.runAsUser`/`fsGroup` to the node's own identity exists
because the native host-process path has no way to honor a different uid, and there is no per-pod uid
isolation to grant it (see [above](#no-per-pod-uid-isolation)). A Linux guest *can* run as an
arbitrary uid, so carving out an exemption for `vm` Pods is a reasonable target, but it has not
shipped. Today the policy applies uniformly, before the runtime is even consulted. Applying a `vm`
Pod that sets a foreign `runAsUser` or `fsGroup` is refused outright (a `422` at `kubectl apply`),
not silently downgraded. Until an exemption ships, either drop the field and accept the node's own
identity inside the guest, or keep that workload on the native path where the same restriction
already applies.

### `vm` Pods: A Container Restart Recreates the Whole VM

There is no in-guest process supervisor on this path. A `vm` Pod's container **is** the guest, so
`restartPolicy` acting on it means tearing the micro-VM down and creating a new one, not restarting a
process inside a surviving one. That recreate is fast. Cold boot
(VM create to first console output) came in at a median of **165 ms** (p95 171 ms, N=20), and kernel
start to init exec at a median of **50 ms**, on an M1 Ultra Mac Studio. On this path,
**container restart is pod recreate**, and it is cheap enough that a `CrashLoopBackOff` cycle behaves
the same way it would on the native path.

### `vm` Pods: `linux/arm64` Only

The `vm` path runs **`linux/arm64`** guest images. It does not run `linux/amd64` in this release,
because in-guest translation for that architecture is a planned follow-up rather than something you
can opt into today. What you see depends on how the image is described:

- An image whose manifest names `linux/amd64` **only**, and is annotated as such, is refused
  **before** anything is created. The RuntimeClass's platform check rejects it at admission and
  records an event naming the missing capability. Nothing boots and nothing is left half-started.
- An image with no usable platform annotation at all fails later, at the ordinary image-pull step, the
  same way any unresolvable image reference would.

A multi-arch image that includes a `linux/arm64` variant is unaffected either way, and pulls and runs
that variant normally.

### `vm` Pods: PVCs Work; `fsGroup` and a Foreign uid Do Not

PVC-backed storage works on the `vm` path and is host-visible. What the guest writes lands on the host
filesystem, readable from Finder or `sudo`, same as native pod storage. Three ceilings go with that,
and one of them is now measured rather than assumed:

- **Guest writes land host-side as the pod's own OS identity, and mode bits govern readability.** A
  guest process that `chmod`s its data directory narrow (a database tightening its data directory to
  owner-only, for example) makes that host-side tree unreadable without elevated access, even though it
  sits in an ordinary Finder-visible location.
- **A foreign `runAsUser` or `fsGroup` is refused at admission**, as described [above](#vm-pods-node-selection-and-security-context-admission).
  The underlying reason is now measured rather than merely unimplemented: on the tested macOS build,
  the platform's shared-filesystem device **refuses idmapped mounts** (the kernel mechanism that would
  let a guest present files under a different owning uid without rewriting every file). That is a
  property of the current platform build, not a k3sm gap that a future k3sm release closes on its own.
  A workload that needs to write as a specific uid should run as the guest image's own root instead,
  which the guest is isolated enough to allow; a `vm` guest is single-tenant, so running as its own
  root is the shape k3sm supports for that need.
- **Rootfs writes are RAM, not disk**, backed by a bounded upper layer. A guest that writes past that
  bound sees `ENOSPC` from its own filesystem, not an out-of-memory kill. Read an `ENOSPC` inside a
  `vm` guest as "the rootfs filled up," not as a resource-limit surprise.

### `vm` Pods: Filesystem Performance and Case-Sensitivity, Measured

Two properties matter before you plan storage-heavy workloads on this path, both measured on the
tested rig and both a property of the shared-filesystem transport, not of PVC storage generally:

- **A synchronous `fsync` costs meaningfully more than an in-guest tmpfs write**, around 0.4 ms on the
  shared filesystem versus roughly 12 µs on guest tmpfs. That is fine for most workloads, and it is
  the kind of thing to budget for if you are running an `fsync`-heavy database with a tight
  per-transaction latency target.
- **Sequential throughput is transport-bound, not disk-bound.** Sequential IO over the
  shared filesystem reached roughly 1.2 GB/s write and 2.8 GB/s read on the tested rig. Those figures
  describe the transport's ceiling on that rig, not a durable-media benchmark.
- **The host volume is case-insensitive, and a case-colliding pair of names collapses silently inside
  the guest.** Creating `File` and then `file` inside the guest does not produce two files. It produces
  one, with no error returned to either write. Image layers are checked for this kind of collision when
  they are unpacked, but a workload's own runtime writes are not, so a workload that itself creates
  case-colliding filenames on this path will lose data silently.

### `vm` Pods: Same-Node Services, Not Direct Pod IPs

A `vm` Pod **consumes and serves** ClusterIP Services on its own node like any other pod. Delivery
from the guest to a Service VIP is native on this path, and the proxy routes a Service to a `vm`
Pod backend the same way.

**Dialing a `vm` Pod's pod IP directly does not work.** The pod IP a `vm` Pod reports is its published
identity, not a live address a peer can connect to, so anything that depends on a direct pod-IP dial,
including headless-Service and per-pod DNS name resolution, does not reach a `vm` Pod. Reach it through
its Service's ClusterIP instead, which does work. Cross-node traffic to or from a `vm` Pod is out of
scope for this release.

Three further properties of the guest network:

- **Guest-to-guest reachability was found to be blocked on the tested rig.** Two `vm` Pods on the same
  node could not address each other at all, at the network layer, under the tested configuration. That
  is an *observation* about the platform, not a documented guarantee from it. k3sm does not rely on it
  as an isolation boundary, and it does not promise it as one either. Do not build a security model on
  guest-to-guest reachability being absent.
- **NetworkPolicy cannot yet name a `vm` Pod as an allowed traffic *source*.** Attributing a policy-table
  entry to a specific `vm` Pod's guest-network address is a planned follow-up; until it ships, a policy
  rule that tries to allow traffic *from* a `vm` Pod cannot admit it. In the meantime, on a node hosting
  `vm` Pods, traffic arriving from that guest-network segment that cannot be attributed to a known source
  is **denied**, not silently allowed, at any destination a NetworkPolicy selects, and the resulting
  deny is logged plainly, naming what was denied and why.
- **A `vm` Pod's Service can start accepting connections a few seconds after the Pod reports Ready.**
  The proxy learns the guest's live address from a lease the runtime polls every 5 seconds, and in that
  window a dial to the Service fails just as an unreachable backend does. An admission or conversion
  webhook with `failurePolicy: Fail` backed by a `vm` Pod rejects every matching request in that window.
  Give the backend a readiness probe and wait on it, and prefer `failurePolicy: Ignore` or a longer
  `timeoutSeconds` where the chart allows. Withholding Ready until the lease is live is tracked as a fix.

### `vm` Pods: What Attach Carries, and What It Does Not

`kubectl exec -it` and `kubectl attach` both work on the `vm` path; see
[`vm` RuntimeClass](vm-runtimeclass.md). Three things about attach are worth knowing before you
build a workflow on it.

**`stdinOnce` is not honored.** A container that sets `stdinOnce: true` behaves as though it had set
`false`. Stdin stays open across attaches, and the first client to detach neither closes it nor ends
the container. Kubernetes uses that field to model "one interactive session, then done"; k3sm does
not implement it, and accepts it silently rather than rejecting it at admission. If a workload
depends on stdin reaching EOF when the operator walks away, do not rely on `stdinOnce` to deliver it.

**Attach replays a bounded buffer, so a screen can start out wrong.** Attaching replays the most
recent output the guest still holds, bounded to **64 KiB** and to 4096 separate writes, and then
follows live. Two consequences follow for a full-screen program. The replay can begin in the middle
of an escape sequence, and a client too slow to keep up has bytes dropped, with an in-band
notice saying so; the alternative would block the workload on its
own `stdout` because somebody's terminal is slow. Both render as a garbled line or two. Redraw with
`Ctrl-L`; nothing is wrong with the process.

**An out-of-date guest refuses rather than misbehaves.** A Pod booted from a guest image that
predates these verbs answers `exec -it` and `attach` with a message naming the fix (recreate the Pod
so it boots the guest image this node pins) instead of a bare "not implemented". This only arises
under a development override that points a node at a guest image it does not pin; an ordinary node
pins that image in the binary and cannot reach the mismatch.

### `kubectl attach` on the Default Native Path Is Output-Only

On the default native runtime a container is a Darwin process started with its combined output wired
to the log pipe and **no retained stdin**, so there is no descriptor left to feed input to a process
that is already running. `kubectl attach` there serves the output half faithfully: it replays the
buffered output, follows new output live, and delivers the exit code. But `kubectl attach -i` or
`-t` is reported `Unimplemented` rather than quietly discarding what you type. Use `kubectl exec -it`,
which does allocate a terminal on the native path, or the [`vm` RuntimeClass](vm-runtimeclass.md),
whose guest keeps these endpoints from the moment the container starts.

### `vm` Pods: Isolation Posture

The process that constructs and drives a `vm` Pod's guest runs confined under the **same Seatbelt
sandbox profile** as every other pod-hosting process on the node. That was measured working on the
tested rig, in both possible orderings (confine-then-construct and construct-then-confine). The `vm`
RuntimeClass remains the recommended choice for untrusted or multi-tenant workloads; see
[above](#no-per-pod-uid-isolation) for why the default native path cannot offer the same boundary.

**Within one `vm` Pod, a container can read volumes it does not mount.** The guest stages the Pod's
projected-class volumes (configMap, secret, projected, downwardAPI) into a single pooled directory and
binds each container's declared mounts out of it, but the pooled directory itself is re-exposed inside
every container. A container that mounts no Secret can therefore still read another container's Secret,
and the Pod's ServiceAccount token, by reading the staging path directly. It is read-only, and it does
not cross a Pod boundary, since a `vm` Pod cannot see another Pod's volumes. It is still narrower than
Kubernetes promises, where a container sees only the volumes it mounts.

**Do not rely on container-level volume separation inside a single `vm` Pod as a trust boundary.** If
two containers must not see each other's credentials, put them in separate Pods, where the boundary
is the one this RuntimeClass enforces.

### Node Capability Labels Are Probed Once at Daemon Start

The `k3sm.io/*` node capability labels (`k3sm.io/virtualization`, `k3sm.io/rosetta`,
`k3sm.io/rosetta-linux`) are stamped from probes that run **once, when the node daemon starts**, and
are not re-evaluated while it runs.

The **gain** direction is merely inconvenient. Install Rosetta 2, restart the daemon, and the label
appears
(see [`vm` RuntimeClass](vm-runtimeclass.md#installing-rosetta-after-the-node-is-up-restart-required)).

The **loss** direction is a ceiling. A node that **loses** a capability, whether Rosetta 2 was removed
or the virtualization capability withdrawn, **keeps advertising it** until the daemon restarts. In
that window the scheduler keeps binding Pods that select the capability onto a node that can no longer
honor them, and those Pods fail at start rather than staying `Pending` on another node. Until the
daemon is restarted, remediate by hand:

```sh
# stop advertising the capability immediately
kubectl label node <node> k3sm.io/rosetta- k3sm.io/rosetta-linux-

# then restart the daemon so the probes re-run and the labels reflect reality
sudo launchctl kickstart -k system/io.k3sm.server
```

The label removal on restart is only tested against the node object k3sm *constructs*; whether a
label **deletion** propagates through Virtual Kubelet's node reconcile to the datastore in every case is
not yet verified in a lab. `k3sm.io/virtualization` has always had the same property. Treat the manual
`kubectl label ... -` above as the reliable way to withdraw a capability claim.

### Unprivileged `server` + PVCs Need `--pod-root`

An unprivileged `k3sm server` (no `sudo`) with no `--pod-root` override roots the runtime (image
cache and pod dirs, including PV storage) under `$HOME`, because the default derives from the
control-plane work-dir's parent. The sandbox generator denies `/Users` **unconditionally**. It is a
hard-coded protected prefix with no allowlist knob, and none will be added (closed 2026-08-29). A
PVC under that default root is therefore refused with `ErrProtectedPath`. The remedy is `--pod-root`,
which relocates the runtimed on-disk root off `/Users`. `--work-dir` alone only moves control-plane
state (kine DB, certs, kubeconfig) and does not change the pods root.

### Single-Node Datastore Consistency

k3sm embeds **kine** over **SQLite (WAL)**. On a single node the datastore serves a **consistent LIST**;
under churn there is a **potential watch-staleness** risk that is **soak-pending** validation (the
dev-Mac churn soak). Until that soak is signed off, treat heavy-churn watch semantics as
accepted-with-known-issue rather than guaranteed. See [Backup & restore](backup-restore.md) for the
datastore operational model.

### Mesh MTU Spread and UDP Fragmentation

- Loopback pod aliases sit at MTU 16384. The mesh WireGuard tunnel sits at 1380.
- TCP: the kernel takes the MSS from the route to the destination, and the pod-CIDR routes inherit
  the tunnel MTU, so cross-node connections (IPv4, the only pod family) negotiate an MSS of 1340. k3sm enables no pf and loads
  no pf rule.
- UDP: datagrams up to 1352 bytes cross the tunnel whole. Larger ones are fragmented and delivered.
  With don't-fragment set, a larger send fails locally with `EMSGSIZE`.
- Two unattributed host kernel panics are on record, on two Macs running a node with the mesh
  active, both in the kernel's network packet-segmentation code. Measurements give no evidence
  implicating TCP: connections negotiate an MSS of 1340 and the largest tunnel packet seen is
  1380. UDP above 1352 bytes has not been exercised under load, so as a precaution avoid sustained
  large-datagram UDP across the mesh. A panic costs a reboot of the host. If it recurs, the audit
  gate collects the snapshot needed to attribute it.

## MLX / Apple-GPU Workloads

MLX and Apple-GPU workloads (the `MLXModel` CRD and the `mlx.k3sm.io/gpu` extended resource) have
their own page; see [MLX quickstart](mlx-quickstart.md). They are not covered by these general
user pages, and nothing here should be read as describing GPU behavior.
