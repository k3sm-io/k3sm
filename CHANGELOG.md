# Changelog

User-visible changes, newest first.

Each released section below is the text published as that version's
[GitHub release](https://github.com/k3sm-io/k3sm/releases) notes, with the version heading
dropped and its subsections promoted one level. The
[releases page](https://k3sm.io/releases/) lists every published build with the version to
pin, its date, and the tarball's sha256.

## Unreleased

### Breaking

- **`k3sm status -o json` is versioned.** The report carries `schemaVersion: 1`, and the keys under `version` are now lowerCamel. `k3sm doctor --json` carries the same field. See [status JSON](https://k3sm.io/docs/status-json/).
- **HA servers move to a request-header CA for the aggregation layer.** The join bundle a server hands to another server changes shape, so upgrade the server installed with `--cluster-init` first and then each joined server, one at a time. Workers restart in any order. See [high availability](https://k3sm.io/docs/ha/).
- **`admissionregistration.k8s.io/v1beta1` is no longer served.** The apiserver drops the flags that kept it on, so the whole group returns 404: MutatingAdmissionPolicy, ValidatingAdmissionPolicy and their bindings. kubectl scripts, GitOps manifests and Helm charts that pin `apiVersion: admissionregistration.k8s.io/v1beta1` must move to `v1`, which is served by default; k3sm's own DaemonSet toleration policy already uses `v1`, and stored objects need no migration. The minimum version for this upgrade is this release, the first that writes that policy as `v1`. Upgrade servers one at a time, waiting for each to be Ready with its etcd member healthy before the next, and the control-plane Mac last; when a release also asks for the server installed with `--cluster-init` first, that order wins. Workers restart in any order. Once any server runs this release, rolling a server back to a release before this one is not supported. After the roll, `kubectl get --raw /apis/admissionregistration.k8s.io/v1beta1` returns 404 on every server and `kubectl get mutatingadmissionpolicies` lists the DaemonSet toleration policy. A server rolled back below this release that cannot write the policy logs `provision daemonset-toleration mutating policy` with an error at start and leaves DaemonSet pods Unschedulable on that node; nothing else fails loudly.

### Added

- **`k3sm update check`.** It finds the latest k3sm release the way the install script does and lists every node with its version, `current`, `behind` or `ahead`, plus the Kubernetes version the release ships; `-o json` prints the same report. A server runs the check at most once an hour, and `k3sm status` gains an `update` row: `ok` when every node runs the latest release, `behind` naming the nodes on an older release, `ahead` when a node runs a newer one, `unknown` when GitHub was unreachable or the last check is more than a day old. The row never makes the verdict `degraded`, and `k3sm status` itself never contacts GitHub. See [upgrade](https://k3sm.io/docs/upgrade/).
- **Nodes report their images in `status.images`.** Each node lists the images its store holds, with every tag and digest reference and the size, the 50 largest first, as a kubelet does. `kubectl get node <name> -o json` shows them.
- **`sudo k3sm stop`, `start` and `restart`.** `stop` takes the node down fully, Pods included, and the node stays stopped across a reboot and across `sudo k3sm install` until you run `start` or `install --start`. `restart` restarts the daemons and keeps Pods running. `--reason` records why in the logs, and `k3sm status` shows who stopped the node (`stoppedBy` in the JSON). See [stopping and starting](https://k3sm.io/docs/stop-start/).
- **`k3sm start --print-time-bound`, and a fixed marker for a still-cordoned start.** The flag prints how long `sudo k3sm start` may run before it is cut off, in whole seconds (570 today), and exits 0 without root. A start that exits 1 because the node is still cordoned writes the token `k3sm: node is still cordoned` to stderr, so a script can tell it from a failure. See [stopping and starting](https://k3sm.io/docs/stop-start/).
- **`kubectl top node` has figures.** Each node reports host-wide CPU and memory in its stats summary and on `/metrics/resource`, so the figures include processes k3sm did not start. On a multi-node cluster a worker's row shows `<unknown>`. See [limitations](https://k3sm.io/docs/limitations/).
- **metrics-server ships as an add-on.** A server installed with `--mesh-ip` applies it once a node in the cluster can run `vm` Pods, so `kubectl top pod` works there. The node's metrics endpoints admit metrics-server's ServiceAccount token, and only on those two read-only routes.
- **The aggregation layer is on.** The apiserver trusts a request-header CA, so extension apiservers such as metrics-server can serve through it.
- **LoadBalancer Services are hosted on every node.** The server picks the hosting nodes from node labels (`svclb.k3sm.io/enablelb`, `svclb.k3sm.io/lbpool` and per-pool labels, mapped one to one from k3s), and a Service that no node could bind gets a `NoEligibleNodes` or `HostNotBound` Warning Event. See [multi-node](https://k3sm.io/docs/multi-node/).
- **`--nodeport-addresses` on `k3sm install`, `server` and `agent`.** It binds NodePorts to a list of IPv4 CIDRs, or to `local` (loopback and the node's own address). Empty keeps every interface.
- **`k3sm install --kubeconfig-name`.** Merges the admin context into your kubeconfig under a name of your choice instead of `k3sm`.
- **Scheduled etcd snapshots and restore on HA servers.** A server on embedded etcd snapshots its own member every 12 hours and keeps 5 by default (`--etcd-snapshot-schedule-cron`, `--etcd-snapshot-retention`, `--etcd-disable-snapshots`), and `k3sm snapshot restore` puts a snapshot back as a new single-member cluster. See [backup and restore](https://k3sm.io/docs/backup-restore/).
- **`k3sm status` checks the Service proxy.** On a server, the `services` row compares the backends the proxy routes each Service port to with the cluster's Ready endpoints and names any Service whose sets differ. Run it with `sudo`. See [status JSON](https://k3sm.io/docs/status-json/).
- **`k3sm status daemons -o json`** reads launchd only, never the apiserver, so it is cheap to poll. `k3sm status` also gains a `heartbeat` row for the node's last status post and Lease renewal.
- **`HOSTNAME` is set in `vm` Pods.** Every container sees the Pod's hostname in `HOSTNAME`, and a value from the image or the Pod spec still wins. See [limitations](https://k3sm.io/docs/limitations/).
- **Pods report `PodReadyToStartContainers`**, and pod-level `resources` count toward a Pod's QoS class.
- **`sudo k3sm network lan on|off` and `k3sm network lan status`.** One switch decides whether the NodePort, LoadBalancer and ingress listeners answer on the networks this Mac is attached to, or only on this Mac and the cluster mesh. It applies live without restarting Pods, checks the listening sockets itself, and restores the previous setting if the change cannot be made. `sudo k3sm install --lan on|off` sets it at install time. See [install](https://k3sm.io/docs/install/).
- **`k3sm snapshot save --compress`** writes the snapshot as a zip archive holding one file, the format k3s uses for compressed snapshots, checked before it is compressed and read back before it takes its name. See [backup and restore](https://k3sm.io/docs/backup-restore/).
- **`k3sm install --from-staging` and `--allow-downgrade`.** The macOS app installs through `--from-staging`, which runs only from a root-owned staging folder whose files are all root-owned and signed by one Developer ID team, and which refuses an older version unless `--allow-downgrade` is given. See [install](https://k3sm.io/docs/install/).
- **`k3sm build ls [-o json]`** lists your recent builds, newest first: status, tag, platform, engine, timing, and the image digest or the error. `k3sm build` records each build in `~/.k3sm/builds` and keeps the newest 200. See [images](https://k3sm.io/docs/images/).
- **`ls` as the first argument of `k3sm build` is now the listing subcommand.** A build names `--tag` before its context, so `k3sm build --tag app:v1 ls` still builds a directory named `ls` (as does `./ls`); only the bare `k3sm build ls`, which needed a tag before, now lists builds.
- **`k3sm uninstall --purge --user <name>`** names whose `~/.kube/config` the purge cleans when there is no `sudo` environment.
- **`k3sm status` without `sudo` reads what your account can.** The datastore row reads the apiserver's readiness check, the serving certificate row reads the certificate the apiserver presents, the `mesh-claims` and `services` rows read copies the server writes to `/var/lib/k3sm/status/`, and a worker whose node credential you cannot read uses the `k3sm` context of your kubeconfig. A check only root can run, such as the runtime socket, reports the new row state `needs-admin` with `sudo k3sm status` as its remedy, and never changes the verdict. See [status JSON](https://k3sm.io/docs/status-json/).
- **`k3sm status -o json` reports joined workers and the join target.** A server lists every other node with the version its kubelet reports (`workers`), and an agent reports the server it joined (`joinTarget`). The LAN access setting appears as `network`, also in `k3sm status daemons -o json`, and an unusable setting record is reported as such instead of being left out. See [status JSON](https://k3sm.io/docs/status-json/).

### Experimental

- **Thunderbolt interconnect (alpha).** `k3sm interconnect enable` arms a Thunderbolt cable between Macs as an opt-in network. Pods opt in with the `k3sm.io/interconnects` annotation, and a sharded `MLXModel` can place its ranks on it with `spec.distributed.interconnect`. `k3sm doctor` gains interconnect rows and `k3sm status` an interconnect row. Sharded models no longer read the `DirectLink` graph. See [interconnects](https://k3sm.io/docs/interconnects/).

### Changed

- **The control plane runs Kubernetes v1.37.1**, and the `k8s.io` client libraries are v0.37.1.
- **kine, etcd and etcdutl ship in the release payload**, and the node runs those copies instead of building them at boot. The bundled kine is v0.17.2 and the bundled buildx is v0.38.0.
- **New installs start with LAN access off**, so a NodePort or LoadBalancer on a fresh install answers on this Mac and the cluster mesh only. An existing install keeps LAN access on across an upgrade. Turn it on with `sudo k3sm network lan on`.
- **A single-node server's apiserver certificate is signed by the cluster CA**, as a server with `--mesh-ip` already was. The admin kubeconfig pins the cluster CA and never skips verification, every namespace's `kube-root-ca.crt` becomes the cluster CA, and `--tls-san` works without `--mesh-ip`. The certificate also names the node. A first install waits up to two minutes for the control plane to create the cluster CA and exits non-zero, writing no kubeconfig, if it does not. `k3sm status` gains a `serving-cert` row, and run as root an `admin-kubeconfig` row that checks the kubeconfig install recorded against the cluster CA. See [certificates](https://k3sm.io/docs/certificates/).
- **The install swap folder moved to `/Library/k3sm.swap`**, so it never shares a path with the macOS app's staging folder, `/Library/k3sm.staging`.

### Security

- **The kubelet API binds the node's own address only**, not every interface, so port 10250 is no longer reachable from the LAN. A joined agent under `--network none` holds no mesh address and now refuses to start.
- **Control-plane downloads are checked against their pinned digests** on the boot path, and a Developer ID-signed k3sm verifies its control-plane binaries in place and never re-signs them.
- **The kine, etcd and registry builds pin Go's module verification settings**, so an ambient `GOSUMDB=off` or similar no longer weakens them.
- **`k3sm status` strips control characters** from cluster-supplied text on a terminal.
- **helm and the image registry ship in the release payload and are verified, never re-signed**, on a release install, like every other bundled binary.
- **Example and lab images are pinned by digest**, and the spike and lab downloads are checked against pinned digests before use.

### Fixed

- **Cluster DNS over UDP recovers when its socket stops receiving.** macOS can hand the node's resolver a DNS socket that is bound but can no longer receive. The resolver read nothing from it in a loop that used several CPU cores and kept growing in memory, and pods got no UDP answers while TCP still worked, until the server was restarted. The resolver now refuses such a socket when it receives it and asks for another, replaces a socket that stops receiving later, and logs a warning each time. It also caps the queries it handles at once and drops the rest, which clients retry.
- **`k3sm kubectl` becomes kubectl instead of running it as a child.** A signal sent to `k3sm kubectl`, such as Ctrl-C or a timeout that kills it, now reaches kubectl, and the exit status is kubectl's own. Before, killing the wrapper left kubectl running until it next wrote output.
- **A container restart the node refuses is visible.** Every refused attempt records a Warning `Failed` Event, `Error: restart container <name>: <cause>`, and the cause follows the `CrashLoopBackOff` message in the container status. A `vm` Pod whose guest cannot restart one container says so and names the remedy: delete the Pod, and its replacement boots a guest that can. Before, such a container sat in `CrashLoopBackOff` with a restart count of 0 and no explanation.
- **An in-place `sudo k3sm install` no longer rolls back over a bring-up the old daemon was cut short in.** The install counts a daemon's bring-up failures only from the moment it bootstrapped that daemon, and a daemon stopped during its bring-up no longer records the bring-up the stop cancelled as a failure.
- **DaemonSets schedule on k3sm nodes without a hand-added toleration.** The DaemonSet controller picks nodes from the Pod template, and every k3sm node carries the `k3sm.io/provider:NoSchedule` taint, so a DaemonSet that did not tolerate it reported `desiredNumberScheduled: 0` and created no Pods. A mutating admission policy now adds the provider toleration to the template on create and update, and leaves a template that already tolerates the taint unchanged. It never adds a `nodeSelector`; the DaemonSet's own placement still decides where it runs. An existing DaemonSet picks the toleration up on its next update.
- **`sudo k3sm start` no longer leaves a node cordoned when the apiserver answers late.** The uncordon is retried for up to 90 seconds, which covers a worker whose mesh comes up after its node daemon and a server whose control plane starts cold. If it still cannot land, `start` exits 1 saying the node is still cordoned, and running `sudo k3sm start` again uncordons it.
- **The single-node datastore's write-ahead log is checkpointed again.** kine held a read transaction open from its start, so SQLite could never checkpoint, and `state.db-wal` grew by gigabytes a day until the data volume filled. The first boot after the upgrade folds the old log into `state.db`, which takes longer in proportion to its size and needs room for the database to grow; see [upgrade](https://k3sm.io/docs/upgrade/). Rolling back to an earlier release brings the growth back.
- **A finished Pod's logs are readable after a node-daemon restart.** Before, `kubectl logs` answered that the Pod did not exist and the log tree could be removed as an orphan.
- **A worker on lossy Wi-Fi keeps posting its status and Lease.** Those writes now use their own connection with a short timeout and a health check, so a connection that went half-open after a roam is replaced.
- **An HA server no longer counts a lost leader lease as a crash.** A controller manager or scheduler that exits on losing its lease restarts the daemon without moving toward the crash-loop park; a lease that keeps being lost still parks the server, with a reason that names it.
- **Rewriting a signed binary no longer kills new Pods.** Every binary k3sm stages or signs is written to a new file and renamed into place, because macOS kills a process that maps a signed file rewritten in place.
- **The log directories are repaired when the root network helper starts**, so a macOS upgrade that removes `/var/log/pods` no longer keeps the node from starting.
- **Sharded MLX placement counts GPU slots other Pods hold**, and reports `InsufficientGPU` instead of restarting the gang on a full node.

### Upgrade Notes

- Upgrade with `sudo k3sm install`, never by replacing the binary alone.
- Before upgrading a single-node server, back up its PKI directories, which a rollback to the previous release relies on: `sudo cp -a /var/lib/k3sm/server/tls /var/lib/k3sm/server/apiserver-certs <backup-dir>`.
- On a single-node server, upgrade with `sudo k3sm install`, not a bare restart of the daemon: the apiserver now presents a certificate signed by the cluster CA, and install rewrites the admin kubeconfig to trust it. Until then the old kubeconfig fails with "unknown authority".
- Every namespace's `kube-root-ca.crt` becomes the cluster CA. A Pod that read its `ca.crt` at start fails with "unknown authority" against the apiserver until it is restarted.
- Rolling back by reinstalling the previous release publishes its self-signed certificate in `kube-root-ca.crt` again and rewrites the admin kubeconfig, so a Pod that read the cluster CA fails with "unknown authority" until it is restarted.
- Copy every kubeconfig you took off the node again after the upgrade, for example with `kubectl config view --minify --flatten --context k3sm --raw`.
- On a cluster using LoadBalancer Services, upgrade the agents before the server.
- A node stopped with `k3sm stop` stays stopped across an upgrade; pass `--start` to start it.
- A node built from source needs the registry in its payload: restage with `k3sm payload` before `sudo k3sm install`.

## v0.1.7 — 2026-10-05

`vm` Pods answer on their own pod IP from anywhere in the cluster, and two Macs can run the control plane together as an experimental preview.

### Added

- **`vm` Pods answer on their pod IP from every node.** The node a `vm` Pod runs on holds its pod IP and relays each TCP connection to the guest, so another node, a native Pod on the same node and the node itself reach the Pod at the address `kubectl get pods -o wide` shows, and Services reach `vm` Pods across nodes. The relay covers the ports the Pod declares as a `containerPort` and the ports an EndpointSlice targets at that Pod. Other ports, and UDP to a `vm` Pod's IP, are not relayed. The root network helper binds ports below 1024 on that address only for those same ports, decided from its own reads of the cluster.

### Experimental

- **Two Macs can share the control plane.** `sudo k3sm install --cluster-init` forms an embedded etcd control plane on the first server and `sudo k3sm install --server-join` adds a second. Each server's pod range is the /24 its `--mesh-ip` names. A join whose range is already held is refused before anything is added to etcd, and a server's name stays bound to its Mac. Two servers tolerate no failures: losing either one stops writes until it returns or the survivor runs `k3sm server --cluster-reset`. Workers stay attached to the server they joined through. A controller manager or scheduler that loses its leader lease when quorum is lost is counted as a crash, so repeated quorum loss can park a server. See [high availability](https://k3sm.io/docs/ha/).

## v0.1.6 — 2026-10-05

Hosts survive heavy pod-network traffic, shell tools see mounted paths everywhere, and Pods get curl, TLS, eviction, logs on disk and re-attach across a daemon restart.

### Breaking

- **Runtime proto: `PodBox.rootfs_path` is removed.** Anyone building against the runtime gRPC contract must stop sending the field and regenerate. The daemon now derives the root filesystem path itself and ignores a caller-supplied one. Nothing changes for a Pod author or for the shipped `k3sm` binary.
- **External-datastore HA is removed, and a multi-server control plane is not available in this release.** The `k3sm server` flags `--datastore-endpoint` and `--datastore-endpoint-file`, and their environment variable, are gone, and an old argument list now exits on an unknown flag instead of quietly falling back to SQLite. There is no conversion from an external database to the new HA datastore. Single-node installs are unchanged and keep the SQLite-backed datastore.

### Added

- **A defence against the host kernel panic seen on the pod network.** Every pod address is a loopback alias, and a connection that outlived its alias could re-route onto the mesh interface and trip a macOS kernel panic from an ordinary send. TCP connections on the pod network now have their segment size lowered after connect, and a torn-down pod's address is blackholed so an open connection fails cleanly instead of re-routing.
- **Shell tools see mounted paths.** The re-signed shadow set now covers `tar` and the usual coreutils, and the path shim also rebases directory and metadata calls (`mkdir`, `rmdir`, `rm`, `mv`, `chmod`, `ln`, `touch`, `cp`) and recursive walks (`rm -r`, `ls -R`, `chmod -R`, `find`, `cp -R`). `kubectl cp` into and out of a mounted path works. `sudo k3sm install` lays the set down.
- **curl and TLS clients work in native Pods.** Pods may read the system TLS configuration, so the stock `curl` and anything linked against the system SSL library no longer abort at startup before they dial.
- **Node identity under the Node authorizer.** The server's in-process node now runs as `system:node:<name>` instead of the admin identity, so a node bug can no longer act as cluster admin. The set of RBAC objects k3sm creates is pinned by a golden test.
- **Node-pressure eviction.** When memory runs low the node marks `MemoryPressure` and evicts one Pod at a time, ranked as the kubelet ranks them, with the usual `Evicted` Event and `DisruptionTarget` condition. After three evictions in five minutes it halts and says so on the node.
- **`k3sm install --data-volume`.** Puts the data root on a dedicated, size-capped APFS volume instead of a plain directory on the boot disk. It creates a case-sensitive volume in the boot container (or adopts one you already declared in `/etc/fstab`), mounts it at `/var/lib/k3sm` hidden from Finder, Spotlight and Time Machine, and migrates any existing data root onto it, verifying the copy before the old tree is renamed aside. `--data-volume-size` sets the quota (100 GiB by default, a floor of 32 GiB), and `--data-volume-encrypt` protects it with a random passphrase kept in the System keychain.
- **`k3sm datavol mount|status|delete`.** `mount` is what the new `io.k3sm.datavol` LaunchDaemon runs at boot and is safe to run by hand; `status` reports the volume, its quota, its usage and any leftover pre-migration copy with no privilege needed; `delete --yes` destroys the volume and every declaration of it.
- **`k3sm status` reports the data volume and more.** The data-root row names the volume, its quota and its usage, and warns once usage passes 90% of the quota. A `datavol` row tracks the boot mount daemon, and a `pre-volume` row appears while a migration's pre-migration copy is still on disk. Status also flags Pods stuck terminating, prints the escape, reports a worker's agent daemon and its credential, reports drift in the shadow set, and renders `k3sm doctor` on the status record with `--report`. A worker no longer shows control-plane rows.
- **Container logs on disk.** The runtime writes container logs under `/var/log/pods` in the CRI format, and `kubectl logs` reads them as the kubelet does, with rotation and cleanup. A vm container's status names its log file.
- **A resident shim keeps container output and exit status.** Native containers keep stdio and exit status in a small resident process, so output written just before exit reaches the log. Exec and teardown work on Pods that run under it.
- **Pods survive a node-daemon restart.** A restarted daemon re-attaches live Pods instead of recreating them, and restarts a single container of a re-attached Pod in place.
- **Image pull failures read like the kubelet's.** A failed pull shows as a retryable waiting state (`ErrImagePull`, `ImagePullBackOff`) instead of a failed container.
- **Per-container stop and ephemeral containers.** A single container can be stopped terminally, and ephemeral containers and the Pod-level `runAsNonRoot` are mapped.
- **Projected volumes refresh.** ConfigMap, Secret and projected volumes update at the kubelet's cadence with an atomic swap, so a running Pod sees new content.
- **Helm charts.** `HelmChart` and `HelmChartConfig` objects in `helm.k3sm.io/v1` install and uninstall charts, with the same fields as k3s.
- **Operator manifests.** Manifests placed in a root-owned directory are applied to the cluster automatically.
- **Secrets encryption at rest.** `sudo k3sm install --secrets-encryption` generates a key on the Mac and encrypts Secrets in the datastore of a new cluster. It is opt-in.
- **`sudo k3sm uninstall --purge --yes`.** Removes what a plain uninstall keeps: the cluster data, the service user, the data volume and the kubeconfig context.
- **Worker lifecycle.** A joining Mac gets its own agent LaunchDaemon, reuses its stored node credential on restart, and deregisters from the cluster on uninstall. `--mesh-ip` lets the installer own the server's mesh address.
- **Ingress, load balancers and service policy.** The ingress binds through the network helper and publishes its endpoints. `loadBalancerSourceRanges` is enforced on LoadBalancer traffic. A Service published on a port the node keeps private is rejected. Pods get namespace service links in their environment.
- **MLX scheduling.** `MLXModel` derives GPU slots and a cumulative memory fit from the ceiling and reports replica counts in status.
- **Faster proxy paths.** The UDP relay and the Service proxy pick routes without locks, and the per-query and per-connection allocation counts dropped.

### Experimental

- **Groundwork for Thunderbolt direct links between Macs.** The contracts (`MeshPeer` endpoint candidates, the `net.k3sm.io/v1alpha1` `DirectLink` type, the derived link addresses) and the networking library and root-helper verbs landed; nothing is wired into the node in this release, so no link is enumerated or used yet and no `DirectLink` object appears. The API is alpha.
- **Sharded MLX models (alpha, trusted tenancy only).** An `MLXModel` may set `spec.distributed` (`ranks`, `backend`, `parallelism`); the operator places the ranks as gang-scheduled rank Pods with per-rank DNS and reports placement and link health in status. In this release the `ring` backend places over the existing mesh, because direct links are not yet wired into the node; the `jaccl` backend needs RDMA-capable direct links and reports `ShardsPlaced=False` until they exist. Not yet run on hardware.

### Changed

- **Native Pods refuse `emptyDir` medium `Memory`.** A native Pod that asks for a memory-backed emptyDir is refused with a clear error instead of silently getting a disk-backed one.
- **Workers do not enforce NetworkPolicy.** A joined worker resolves policy against its own Pods only and enforces nothing for traffic it cannot attribute. Policies are enforced for Pods on the server node. The limitations page lists the ceiling.
- **A mid-install failure leaves the old install intact.** The install root is staged and swapped in atomically, and the staged inputs are verified before anything is written.
- **The data-root refusal message** now names `sudo k3sm datavol mount` as the remedy for a declared but unmounted data root.


### Fixed

- **Credentials and logs are locked down.** The admin token and the datastore connection string no longer appear on the server's command line, the mesh keys live under a root-owned state root, and the daemon log directory is restricted to root and admin.
- **Installs refuse unsafe paths.** The installer refuses a symlink where it would change ownership, an untrusted launcher directory and a join to the control plane's own node name, and says how to fix each.
- **Worker joins are sturdier.** A join waits for the network helper and for a recovered start before judging failure, preflights the join endpoint and its CA, releases a mesh allocation when the join fails, and issues the node certificate for the assigned mesh address. Anonymous join requests and attempts per token are bounded.
- **Mesh teardown and resume.** The mesh is torn down on exit, a busy join listener is retried, a resumed peer seed advances correctly, and MeshPeer events coalesce into one reconcile.
- **A control plane that fails to come up says why.** A component that dies before it is marked supervised is reported, bring-up failures are recorded on the crash-loop breaker with secrets redacted from the log tail, and a toolchain-less control-plane build parks on first failure.
- **Clean exit.** The node stops the runtime, its Linux VMs and the control plane together when it exits.
- **Linux guests and vm Pods.** Probes dial a vm Pod at the guest's live address, PodReady waits for its transport, and guest networking waits for carrier and retransmits its address request.
- **Sandbox hardening.** Pod profiles refuse a per-IP host in a network filter, refuse symlinked path components on every vm path, deny the daemon's private trees and loopback dials to the node's private ports, and are swept when stale.
- **Pod bookkeeping.** Same-name Pods are told apart deterministically, force-deleted Pods are reaped after a partition heals, a postStart hook failure under `restartPolicy: Never` kills the container, and `spec.serviceAccountName` resolves from the downward API.
- **A bare exec command resolves on the Pod's `PATH`.**

## v0.1.4 — 2026-09-06

One command that says what is running, and daemons that refuse to write into an unmounted data
root.

### Added

- **`k3sm status`.** One screen that answers "is my cluster up, and if not, which piece is down
  and why": a one-line verdict first, then one row per component — install, netd, server,
  apiserver, node, workloads, data root, datastore, kubeconfig — each with its state, a detail,
  and the command that fixes it. `k3sm status daemons` shows the launchd view (state, pid, runs,
  last exit, plist, log); `k3sm status cluster` the apiserver, node, Pods by phase, control-plane
  children and Linux guest hosts; `k3sm status logs [netd|server]` tails the daemon logs. `-o json`
  emits the same report for scripts, `--wait` blocks until the cluster is running, `--watch`
  re-renders in a terminal. The exit code is the verdict: 0 running, 3 stopped, 4 degraded, 5 not
  installed, 6 unknown (`k3sm status --help` is the reference). Colour and glyphs follow `NO_COLOR`
  and whether stdout is a terminal; the text is never the only signal.
- **Data-root guard.** A data root kept on its own volume is declared in `/etc/fstab`; when that
  volume is not mounted, the netd helper, the server and `sudo k3sm install` now refuse to start
  or install rather than writing a shadow directory into the empty mountpoint — the message names
  the mount command. On a plain-directory data root, the netd helper realigns a root-owned data
  root to the service user on every start, so a wrong owner is repaired by restarting it.

### Fixed

- A data root that was not mounted at boot no longer leaves the server crash-looping on
  `permission denied` behind a root-owned shadow directory, and can no longer receive a fresh,
  empty datastore over the real one. `k3sm status` names the state and the fix.

## v0.1.3 — 2026-09-05

The k3sm command is on PATH after install, and `k3sm kubectl` works without sudo.

### Added

- **A `k3sm` launcher on PATH** — `sudo k3sm install` links `/usr/local/bin/k3sm` to the installed
  binary, so every new terminal finds `k3sm` with no profile edits. The link is a symlink, never a
  copy, so it always runs the same binary the daemons do. The installer refuses to replace a
  non-symlink already at that path and refuses to link into a directory that is not root-owned or
  is group/other-writable, naming the fix in each case; `sudo k3sm uninstall` removes only the link
  it created.

### Fixed

- **`k3sm kubectl` and `k3sm kubeconfig` work as you, not just as root.** Both verbs looked only in
  the control plane's private work directory for the admin kubeconfig and the bundled kubectl, so
  after a normal install they failed for the user who ran it. They now use the `k3sm` context that
  install merges into your `~/.kube/config` (or `$KUBECONFIG`) and the kubectl installed alongside
  k3sm; a user-supplied `--context` still wins, and `K3SM_WORK_DIR` still pins a non-default server
  work directory.
- The installer's closing hint now tells the truth for the current shell: when `k3sm` is not yet on
  PATH it names the launcher and the two ways to reach it (a new terminal, or adding
  `/usr/local/bin` to PATH) instead of suggesting a command that could not work. The pre-escalation
  banner lists the symlink alongside everything else the install lays down.

## v0.1.2 — 2026-09-03

One-command in-cluster image builds, one cluster address for the node registry, and
self-recovering daemons.

### Added

- **One-command builds** — `k3sm build` builds any Dockerfile: a copy-only recipe packages natively
  in about a second, and a recipe with `RUN` steps builds on the cluster's build engine, which
  starts automatically on first use. The image is recorded in the node's image store under its tag
  either way, ready for a Pod to name; `--output` additionally writes a portable artifact.
- **Build and push in one step** — `k3sm build --push` publishes the built image after the store
  recording; a bare tag publishes to the node's own registry, a full reference pushes as written.
- **Linux images as a first-class build target** — `k3sm build --platform linux/arm64` builds a
  Linux image even from a copy-only Dockerfile; multi-platform builds export and push a full OCI
  index.
- **A raw buildx surface for the engine** — `k3sm builder buildx` drives the build engine with the
  bundled, digest-verified buildx; `k3sm builder delete` fully resets the engine, cache included.
- **One cluster address for the node registry** — each node publishes a `registry-<node>` Service
  backed by its relay address, so in-pod tools — Linux guests included — reach the registry at one
  name, and the registry hosting ConfigMap now carries `hostFromClusterNetwork`.
- **Bare image names** — a Pod naming `app:v1` resolves from the node's registry first, then from
  cluster peers, before Docker Hub; no registry prefix required for images you built or pushed
  locally.

### Fixed

- `sudo k3sm install` over a running node now sequences the daemon restart around launchd's
  asynchronous teardown, retries transient bootstrap failures, and verifies both daemons serve
  before reporting success — the in-place upgrade path is exercised by the release suite on every
  cut.
- The installer refuses a `k3sm-vmhost` helper that lacks the virtualization entitlement, naming
  the exact fix, instead of installing it and leaving every `vm` Pod Pending on an opaque
  scheduling message.
- The netd helper exits and restarts cleanly if its control socket is removed or replaced; the
  cluster-DNS listener retries its bind indefinitely instead of giving up; a failed Service-watch
  start no longer leaks a stale retry loop.
- The build engine's output no longer prints a Docker Desktop deep link.

## v0.1.1 — 2026-09-02

Interactive Linux workloads, a node-local image registry, and in-cluster image builds.

### Added

- **Interactive terminals for Linux (`vm`) Pods.** `kubectl exec -it` into a Pod running under the
  `vm` RuntimeClass allocates a real pseudo-terminal in the guest — it was refused outright before.
  Job control, line editing and `stty size` work, resizing your terminal delivers `SIGWINCH`, and
  `tty` names a device that exists **inside** the container, because the terminal is allocated from
  the container's own `devpts` instance rather than the guest's. Exec without a terminal is
  unchanged.
- **A minimal standard `/dev` in every `vm` container.** A container's root filesystem comes from an
  OCI image, whose `/dev` is empty by construction, so a `vm` container previously had no `/dev` at
  all: `echo x > /dev/null` wrote an ordinary file that grew forever, and `/dev/urandom` was missing
  under every language runtime that seeds from it. Each container now gets the OCI runtime-spec
  default character devices (`null`, `zero`, `full`, `random`, `urandom`, `tty`), its own `devpts`
  instance with a `/dev/ptmx` symlink into it, and a private `/dev/shm` bounded at 64 MiB. The set is
  enumerated rather than filtered, and a Pod volume mounted at one of those paths replaces the
  default instead of stacking underneath it — a `Memory` `emptyDir` at `/dev/shm` is how you ask for
  a larger one.
- **`kubectl attach` for `vm` Pods.** A container declaring `tty: true` is started on its own
  terminal (sized 24x80 until a client resizes it, and its session's controlling terminal), and one
  declaring `stdin: true` keeps a writable stdin — so attach has a running process to connect to.
  Detaching never signals the container or closes its stdin, reattaching resumes, and concurrent
  attaches are allowed. Because a terminal merges the two output streams before either leaves the
  container, `kubectl logs` shows one merged stream for a `tty` container, as `docker run -t` does.
  Guests advertise which verbs they can serve, so a Pod booted from an out-of-date guest image
  answers with a message naming the fix rather than a bare "not implemented".
- **A node-local image registry.** `k3sm server --registry-port <port>` runs a small OCI registry on
  the node's loopback interface; `k3sm dev` enables one automatically. Push a locally built image
  with `k3sm image push` (or any OCI tool) and Pods pull `localhost:<port>/name:tag` through the
  ordinary Kubernetes image path — so `imagePullPolicy: Always`, the digest index and real pull
  failures all behave the way they would against a remote registry, which `k3sm image load` cannot
  reproduce. Pulls are anonymous and pushes require a credential regenerated on every server start;
  the listener binds the loopback address and a non-loopback bind is rejected at startup. The
  standard `local-registry-hosting` ConfigMap is published in `kube-public` so tools can discover the
  port. Off unless you ask for it.

- **Image commands work on a stock install.** The server now serves the daemon's control
  socket, so `k3sm image ls`, `df`, `prune`, `load`, and `import` no longer need a separately
  started daemon. The socket is owner-only; the pod sandbox denies it to workloads.
- **The rest of the image verb set.** `k3sm image pull` (warm/pin an image through the same
  verified path a Pod pull takes), `tag` and `untag` (names are edges over digest-pinned
  content — untag removes a name, never bytes; bytes are reclaimed only by reachability-driven
  prune), `inspect`, `save` (verified OCI-layout export), and `push` straight out of the
  node's store.
- **Images travel across the cluster.** A node with the registry enabled advertises it to the
  cluster; when another node's Pod names a `localhost:<port>/...` image it doesn't have, the
  pull falls back to the advertising peers over the encrypted node mesh — content still
  digest-verified on arrival, pushes still credential-gated. Nodes read the advertisements
  through a purpose-made namespace with the narrowest possible grant.
- **Linux-guest Pods can reach the node registry.** The registry is relayed onto the node's
  guest-network gateway address, so a Pod running under the Linux RuntimeClass can pull from —
  and, with the push credential, push to — the node's own registry. This is what lets an
  in-cluster build Pod publish its result without any external registry.

### Known Limitations

- `stdinOnce` is accepted but **not honored** — a container that sets it behaves as though it were
  `false`.
- `kubectl attach` replays a bounded buffer (64 KiB, 4096 writes) before following live, and drops
  bytes for a client too slow to keep up rather than blocking the workload on its own `stdout`.
  Either can leave a full-screen program's first screen garbled; redraw with `Ctrl-L`.
- A Pod under the `vm` RuntimeClass **cannot pull from the node-local registry**: the guest has its
  own loopback, and the registry listens only on the node's. Use a registry the guest can reach, or
  load the image into the node's store directly.
- `kubectl attach` on the **default native path** remains output-only; `-i` / `-t` there is reported
  `Unimplemented`. `kubectl exec -it` works on both paths.

## v0.1.0 — 2026-09-02

The first release of k3sm — a macOS-native Kubernetes distribution for Apple Silicon. Pods run as
native Darwin processes; an experimental `vm` RuntimeClass boots `linux/arm64` images in per-pod
micro-VMs against digest-pinned guest artifacts, verified on every boot.

The archive contains the k3sm binary, the exec shim, both DYLD shims, the entitled `k3sm-vmhost`
helper, and the pre-staged control-plane payload — everything `sudo k3sm install` requires. Ad-hoc
signed, not notarized; the Homebrew tap and notarized package arrive with a later release.
