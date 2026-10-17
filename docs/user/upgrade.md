# Upgrade

Moving a k3sm node or cluster to a new release.

## Checking for an Update

```sh
k3sm update check          # or: k3sm update check -o json
```

`k3sm update check` finds the latest release the way the install script does: the newest stable
release, or, before the first stable release exists, the newest release of any kind. It prints the
release tag, when it was published, the Kubernetes version it ships when its release notes say, the
version of the `k3sm` binary you ran, and every node of the cluster with the version its kubelet
reports, marked `current`, `behind`, or `ahead` (newer than the latest release, such as a build of
a tag not yet published). A node whose kubelet reports no tagged k3sm release (no k3sm version, a
development build, or a build from a modified tree) is `unknown`. It
only reads; it downloads and installs nothing. It exits 0 when the check finished and 1 when it
could not (GitHub unreachable, for example), with the reason on stderr.

The same check feeds the `update` row of `k3sm status` on a server. The server runs it at most once
an hour and records the result; `k3sm status` reads that record and never contacts GitHub itself.
The row is `ok` when every node runs the latest release, `behind` (severity `warn`) naming each node
on an older one, `ahead` when a node runs a newer one and none is behind, and `unknown` when the last
check could not reach GitHub, when no check is recorded, or when the record is more than 24 hours
old. An update never makes the verdict `degraded`.

The row is a convenience signal, not an attestation. Each node's version is what that node reports
of itself in `status.nodeInfo.kubeletVersion`, so a node can claim any version; use it to see what
needs upgrading, never as proof of what a node runs.

The record is `/var/lib/k3sm/status/update.json`, mode 0644, so `k3sm status` reads it without
`sudo`. Run `sudo k3sm update check` to refresh it on demand: the directory belongs to the k3sm
service user, so a check run without `sudo` prints its result but cannot record it.

## Managed Update

A server can roll the whole cluster to a release for you, one node at a time, workers first and
the server last. Five subcommands drive it; every one but `check` reaches the cluster with the
credentials `k3sm status` uses (the server's admin kubeconfig under `sudo`, the `k3sm` context of
`~/.kube/config` otherwise), so run them on a server or from a Mac with the cluster's admin
kubeconfig. A worker's own node credential may not create an update.

```sh
k3sm update check                       # what is behind
k3sm update apply                       # plan, confirm, start
k3sm update status --watch              # follow it
k3sm update cancel                      # stop after the current node
k3sm update abort                       # recover from a failed step
```

`k3sm update apply [--version <tag>] [--drain] [--allow-downgrade] [--signature if-signed|required] [--yes]`
moves the cluster to the latest release, or to the tag `--version` names. It prints the plan
first: the nodes in the order they will be updated with the version each runs, the target, whether
nodes are drained, and the signature policy. It then asks for confirmation; `--yes` skips the
question, and without `--yes` a stdin that is not a terminal is refused (exit 2). Confirmed, it
creates the `Update` named `current` that the server's update controller rolls.

- `--drain` evicts each node's pods before that node is updated, through the eviction API, so
  PodDisruptionBudgets hold. The server is never drained, and a one-node cluster cannot drain.
- `--allow-downgrade` permits a release older than a node runs; without it such an update is
  refused before any node is touched.
- `--signature if-signed` (the default) holds the release to the installed build's signer: a
  Developer ID build accepts only the same team's signature, an ad-hoc build accepts an ad-hoc
  release. `required` refuses any release without a Developer ID signature. The release's
  checksum is verified under either policy.

While an update is in progress, `apply` refuses and names its phase. A finished update
(`Succeeded`, `Failed` or `Cancelled`) is removed and replaced, so a retry is a new update.

`k3sm update status [-o text|json] [--watch]` prints the update's phase, the release it resolved
(tag and digest), one row per node (name, from, to, phase, message, and the time of its last
progress) and the conditions. `--watch` prints again on every change and returns when the update
finishes. With no update it prints `no managed update` and exits 0; `-o json` then prints
`{"phase":"","version":"","resolved":null,"nodes":[],"conditions":[]}`. While an update is in
progress the `update` row of `k3sm status` is `rolling`, naming the phase and the node being
updated, so `k3sm status` alone shows a roll started from any Mac.

`k3sm update cancel` stops the roll: the node being updated finishes its update, the nodes not yet
started are left on the release they run, and the update ends `Cancelled`. A cancel is not a
rollback; nodes already moved stay on the new release.

A failed step stops the roll and leaves its node as it was: cordoned, with its `k3sm.io/update-*`
annotations. `k3sm update abort` is the recovery. It marks the update `Cancelled`, then on every
node removes the `k3sm.io/update-*` annotations and lifts the cordon only where the update
controller set it; a node you cordoned yourself stays cordoned. It prints each step. Run `k3sm
update status` to see which node failed and why before you abort, and fix that node before the
next `apply`.

The k3sm app offers the same update as a menu item and a button, both of which run
`k3sm update apply`.

## Single Node

For script (gen-1) installs, re-run the one-liner:

```sh
curl -fsSL https://k3sm.io/install.sh | sh
```

An unpinned re-run installs the **latest** release. Pin `K3SM_INSTALL_VERSION=vX.Y.Z` to
re-install the version you are already on (repair without upgrading), and pin an older version
to downgrade. That pin-and-re-run is the script channel's rollback path.

The re-run replaces the binary and restarts the k3sm LaunchDaemons (the `io.k3sm.netd` root
helper and the `_k3sm` server/agent jobs) onto the new version, through the `sudo k3sm install`
it performs. The new binary **replaces** the old one, with no side-by-side window and no flag to
switch back, so the node is momentarily unavailable while the daemons restart.

The node daemon's open-file limit (`NumberOfFiles` in its plist) binds only when launchd boots the
job out and bootstraps it again, which `k3sm install` does. `launchctl kickstart -k` alone keeps the
old limit, so reinstall rather than kickstart after an upgrade that changes it; the install log says
when it did.

The kernel also allocates a process at most `kern.maxfilesperproc` file descriptors, whatever limit
launchd grants it, and that ceiling scales with installed RAM (measured on macOS 26: 245760 on a 64 GB
Mac, 10240 on an 8 GB one). When it is below the limit k3sm requests, the install logs a warning and
the node's UDP Service flow capacity drops toward its floor. `sudo sysctl -w kern.maxfiles=131072
kern.maxfilesperproc=131072` raises it until the next reboot.

> **Homebrew is planned; the `k3sm-io/tap` is not published yet.** When it ships, `brew upgrade
> k3sm` will do the same job, restarting the daemons via `launchctl kickstart`.

## Multi-Node Rolling Upgrade

A cluster upgrades **one node at a time**, not all at once. Restarting each node's daemon via `launchctl
kickstart` creates a short **binary-version-skew window** where old and new nodes coexist; k3sm releases
are designed so adjacent versions interoperate across that window. Upgrade agents first and the
control-plane Mac last unless a release note says otherwise. An HA cluster has its own order, mint-authority server first; see [HA](ha.md#upgrading-an-ha-cluster-to-the-aggregation-layer). See [Multi-node](multi-node.md) and
[HA](ha.md).

## Managed Update

A managed update moves the whole cluster to one release through an `Update` object
(`updates.k3sm.io`), node by node, without a re-run of the installer on each Mac.

### Chain of Trust

The server authorises every update, and a node cannot authorise its own. At every start the server
mints an update-signing certificate from the cluster CA (`CN=k3sm:update-signer`,
`O=k3sm:update-signers`, code signing only, held in memory and never written to disk). When it hands
a node a release, it signs the payload naming that release: the tag, the archive URL, the archive's
sha256 from the release checksums, the signature policy and the downgrade permission. The node's
annotations carry the payload (`k3sm.io/update-payload`), the signature
(`k3sm.io/update-payload-sig`) and the signer certificate (`k3sm.io/update-signer`).

A node can write its own annotations, so the annotations alone prove nothing. The `k3sm-netd` root
helper, which installs the release as root, checks that the signer chains to the cluster CA it was
started with (`--cluster-ca`). That CA is the server's own cluster CA certificate on a server, and on
a worker a root-owned copy `sudo k3sm install` writes from the CA the join token pins. The helper
also checks the subject and the signature over the exact payload bytes, and that the archive matches
the signed sha256, before it unpacks or runs anything. Only the holder of the cluster CA key, the
server, can produce a payload a node will install. The signer is valid for a day, and the server
issues a fresh one before the one it holds has less than 12 hours left, so a signed payload that
leaks stops authorising anything within a day.

What this does not protect against: the server's service user (`_k3sm`) holds the cluster CA key,
so a compromise of that user on the server can mint signers for every node. On a node installed
from an ad-hoc signed build that is root on the node; on one installed from a build signed by a
Developer ID team it is limited to a signed rollback to a genuine, team-signed older release. This
is the k3s posture, in which the control plane is root-equivalent for the cluster: protect the
server as you would its root account.

One residual for workers that joined before this release. A worker installed without
`--token-file` has no token to pin its cluster CA, so its first install on this release takes the
root-only copy once from the node credential the service user wrote. Pass `--token-file` once
(`sudo k3sm install --agent --server <server> --token-file <file>`, with a fresh token from
`k3sm token create`) to pin the copy to the CA the token names.

### On Each Node

Every node daemon, server and agent alike, watches its own Node. When the update reaches it, the
node:

1. Checks the payload's signature against the cluster CA it pins, and refuses an unsigned payload,
   one signed by any other CA, or one naming another release than the Node asks for, before it
   downloads anything. It also refuses a release older than the one it runs unless the update
   allows a downgrade.
2. Writes the phase `Downloading` and fetches the release archive over HTTPS from `github.com`
   (following redirects only to `objects.githubusercontent.com` and
   `release-assets.githubusercontent.com`, each one checked), at most 512 MiB and within 10
   minutes, into a fresh directory under `/var/lib/k3sm/updates` that only the `_k3sm` user can
   read. A node installed with `--update-release-base` also accepts that base's own host (below).
3. Writes `Verifying` and checks the archive's sha256 against the signed payload.
4. Writes `Installing` and hands the archive, the payload, its signature and the signer to the
   `k3sm-netd` root helper. The helper verifies them again (above), unpacks only the build set
   (`k3sm`, `k3sm-execshim`, `k3sm-vmhost`, the two shim dylibs and `cp-payload/`) as regular
   files, applies the code-signing policy and the downgrade rule, and only then runs the new
   `k3sm install --from-staging`. That install updates the node in place: it keeps the node's role,
   the server a worker joined and every argument the node was installed with. On a server it normally
   also keeps the admin credential, so a copy of the admin kubeconfig on another Mac still works
   after the server's turn; if the server's stored admin token is missing or corrupt, the update
   mints a new one and says so, and every copy must be refreshed.
5. The signatures follow the installed build. A node installed from a build signed by a
   Developer ID team takes only a release signed by that same team. A node installed from an
   ad-hoc signed build takes an ad-hoc signed release or a team-signed one. Under the `required`
   signature policy every binary must carry a Developer ID team signature, whatever the node runs.
6. Writes `Restarting` while the installer restarts the daemons. The restarted daemon writes
   `Done` once it runs the new release and its pod runtime answers, and the node's kubelet
   version reports it.

The node never runs a downloaded binary itself. A refusal or a failed install writes `Failed`
with the reason (`kubectl get node <name> -o jsonpath='{.metadata.annotations.k3sm\.io/update-phase}'`),
and the download directory stays for diagnosis until the next update attempt or the next daemon
start removes it. A node without the `k3sm-netd` helper, such as a standalone `k3sm node`, does not
take part. A worker that joined before this release has no root-owned CA copy until it is
installed again (`sudo k3sm install --agent --server <server>`), and until then its helper refuses
every managed update.

### Release Base for a Mirror or a Lab

By default the server resolves a release, and each node downloads it, from GitHub. A mirror, or a
lab that serves its own builds, sets another release index at install:

```sh
sudo k3sm install --update-release-base https://mirror.example.com/k3sm/releases
sudo k3sm install --agent --server <server> --update-release-base https://mirror.example.com/k3sm/releases
```

The index must have GitHub's layout: `<base>/download/<tag>/k3sm_<version>_darwin_arm64.tar.gz` and
`<base>/download/<tag>/k3sm_<version>_checksums.txt`. The server reads the release, its checksum and
the update check from it. Each node downloads the archive from it, from the base's own host and port
and from GitHub's hosts, and still verifies the archive's sha256. The base must be `https`. Plain
`http` is accepted only on a loopback address (an index served on the server itself) and refused
on any other host, a private LAN address included: the server signs the checksum it reads from the
index, so over plain `http` any host on the network path could choose the release digest every
node then installs. A lab serving its own builds on the LAN serves them over `https`. Set it on every node of the cluster, the server and each worker. The setting is
recorded with the other install arguments, so later installs, managed updates included, keep it;
install again with another `--update-release-base` to change it.

## Before You Upgrade

- Back up the datastore with `sudo k3sm snapshot save --out <somewhere off this node>`. It is safe to
  run while the cluster is serving, and it verifies the copy before it reports success. The file-level
  fallback (stop the daemon, `PRAGMA wal_checkpoint(TRUNCATE)`, copy, verify the copy) is in
  [Backup & restore](backup-restore.md). k3sm also takes an automatic pre-migration backup when a
  release changes the datastore engine (below), but that copy lives on the same disk as the cluster it
  protects, so it is not a substitute for yours.
- Know your rollback path. On the script channel, prior releases stay downloadable, so rollback is
  `K3SM_INSTALL_VERSION=<prior-tag>` and a re-run. The planned Homebrew channel will retain the
  prior bottle, so rollback there will not need a rebuild round-trip.
- Check the version skew. Confirm the target Kubernetes pin with `k3sm version`; see
  [Versions](versions.md).

## Upgrading Across a Datastore-Engine Change

Some releases move to a newer **kine** (the etcd-shim over SQLite). A newer kine re-runs its schema
migrations against your existing `state.db`, and that is **one-way**. The migrated database is not
converted back if you reinstall the older k3sm.

You do not have to do anything for this, but you should know what it does.

- **Before** the new version opens the database, the server takes a verified backup at
  `db/state.db.pre-<kine-version>.bak` and preserves the old kine binary beside it as
  `kine.pre-<kine-version>`. The mechanics (the WAL drain, the integrity check, the write-once
  rule) are in [Backup & restore](backup-restore.md).
- It **refuses to start** if the volume does not have twice the database size free, rather than
  writing a partial backup. Free space and start it again; nothing was changed.
- The first boot on the new engine is slower than usual (the checkpoint + the copy). Later boots are not.
- Keep the `.bak` until you are satisfied with the new release, then delete it. It is a full copy
  of the database.

A server started with `--cluster-init` keeps its state in an embedded etcd member instead, and none
of this applies there. See [HA](ha.md) for the experimental two-server control plane.

## Upgrading Into the Checkpointing kine

Earlier releases ran a kine that never let SQLite checkpoint its write-ahead log, so on a single-node
server `db/state.db-wal` grew by gigabytes a day. The kine in this release fixes that. Nothing about
the database's schema or encoding changes, and no backup is taken for it.

- **The first boot folds the old log into the database.** kine does this before it starts serving,
  so that boot is slower in proportion to the size of `state.db-wal`. On an Apple-silicon SSD a 2 GB
  log took about 3 seconds, and the server waits up to 15 seconds per GiB on top of its usual wait.
  The server log says when it is recovering a large log, with its size.
- **It needs room for the database to grow.** The checkpoint copies the newest version of every page
  in the log into `state.db`, which grows by that much before the log is truncated. The server reads
  the size it will need from the log itself, and if the volume cannot take it the server refuses to
  start, says how much space it needs, and changes nothing. Free space and start it again.
- **Upgrade with `sudo k3sm install`**, not by replacing the binary alone. The kine is shipped in the
  release's payload, and a server whose binary was swapped without that payload stops on its first
  start and asks you to re-run the install.
- **Rolling back brings the old behaviour back.** A server returned to an earlier release runs the
  old kine again, and the log starts growing again from that boot.

## Upgrading Into the Reserved-Port Policy

The release that moved LoadBalancer listeners to the wildcard also provisions a
`ValidatingAdmissionPolicy` that **rejects** a `type: LoadBalancer` Service declaring a port k3sm's own
listeners own, either the NodePort range `30000-32767` or the kubelet API port `10250`. It matches on
CREATE **and** UPDATE, and it does **not** ratchet on `oldObject`.

That means a cluster **already carrying** such a Service is not grandfathered in. The object stays in
the datastore and keeps working, but **every subsequent write to it is denied**, not just a port
change. A `kubectl label`, an annotation added by an unrelated controller, any `kubectl apply` of the
same manifest: all rejected, with a message naming the port.

Check before you upgrade:

```sh
kubectl get svc -A -o json | jq -r '
  .items[] | select(.spec.type=="LoadBalancer")
  | select(.spec.ports[]? | .port==10250 or (.port>=30000 and .port<=32767))
  | "\(.metadata.namespace)/\(.metadata.name)"'
```

Anything listed has two escape hatches, both a single write **before** the upgrade (or from a
still-permitted path after it):

- Change the port to one outside the reserved set. This is the intended fix, since the Service could
  never have had a working listener on a port k3sm already holds.
- Patch `type` away from `LoadBalancer` (e.g. to `ClusterIP` or `NodePort`); the policy is scoped to
  LoadBalancer Services only, so the object becomes writable again immediately.

There is no `--force` and no exemption. A policy that tolerated a pre-existing offender would leave
the collision silently in place, along with the `kubectl logs`/`exec` outage it can cause.

## Upgrading Into the Denied-Local-Port Policy

Every pod's sandbox denies `connect()` to the node's datastore (kine) listener port. The deny is by
port **number**, whatever address the pod dials, so a Service published on that port is unreachable
from pods no matter its type. The release that added the deny also provisions a
`ValidatingAdmissionPolicy` that **rejects** such a Service, so you meet the problem at
`kubectl apply` rather than inside a pod.

Two things it does differently from the reserved-port policy above:

- **No type scope.** ClusterIP, NodePort, LoadBalancer and headless are all rejected. A headless
  Service is not an exception: its clients dial a pod IP, which the deny covers too.
- **Only `spec.ports[].port` is matched.** A `targetPort` on the datastore port is fine (that is the
  port a pod listens on, not one another pod dials), and so is an allocated `nodePort`.

Like the reserved-port policy, it matches CREATE **and** UPDATE and does **not** ratchet on
`oldObject`, so an existing Service on that port is not grandfathered: it keeps working as an object,
and every subsequent write to it is denied.

Check before you upgrade. `2379` is the default datastore port; use your `--kine-port` value if you
moved it:

```sh
kubectl get svc -A -o json | jq -r '
  .items[] | select(.spec.ports[]? | .port==2379)
  | "\(.metadata.namespace)/\(.metadata.name)"'
```

Anything listed has two ways out:

- Publish it on a different `spec.ports[].port`. This is the intended fix, since no pod can reach the
  Service on the current one.
- Start the server with a different `--kine-port`, which moves the denied number. That is a server
  restart, and it changes the port anything else of yours uses to reach the datastore.

One limit: the policy is a single cluster-scoped object carrying the ports of the server that
provisioned it, while `--kine-port` is per server. A control plane whose servers used different
datastore ports would have a policy that names one of them, and a Service on another server's port
would be admitted by the API and still unreachable from the pods on that server's node. That case
needs more than one server (see [HA](ha.md)).

## Rollback

Rollback means reverting to the previous binary, plus the daemon restart that comes with it. There is
no runtime flag to flip. On the script channel that is `K3SM_INSTALL_VERSION=<prior-tag>` and a
re-run. On the planned Homebrew channel it will be a `brew` pin or a switch to the prior bottle.

If the release you are leaving changed the **datastore engine**, reverting the binary is only half of
it, because the database has already been migrated in place. Restore the
`db/state.db.pre-<kine-version>.bak` the upgrade left behind (or your own pre-upgrade snapshot) with
the daemon stopped:

```sh
sudo launchctl bootout system/io.k3sm.server
sudo k3sm snapshot restore /var/lib/k3sm/server/db/state.db.pre-<kine-version>.bak
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist
```

`k3sm snapshot restore` refuses while the daemon is running, verifies the backup before it touches
anything, and prints the verification step you must then run; see
[Backup & restore](backup-restore.md). Rolling the binary back without restoring the backup leaves an
older k3sm pointed at a database a newer engine has migrated.

### Rolling Back Past the Aggregation Layer

A release without the aggregation layer ignores the new request-header CA files, but the apiserver
keeps the CA it published in `kube-system/extension-apiserver-authentication`. After rolling back,
delete that ConfigMap once, and the older apiserver recreates it with only the client CA:

```sh
kubectl -n kube-system delete configmap extension-apiserver-authentication
```

The scheduler and controller manager watch it and see a short client-CA gap, so delete it once and do
not repeat it. Check that no `requestheader-` key remains:

```sh
kubectl -n kube-system get configmap extension-apiserver-authentication -o jsonpath='{.data}'
```

The output must not contain `requestheader-`. On an HA
cluster, roll back the mint-authority server last and delete the ConfigMap only after the last server
runs the older release, because a running new apiserver adds the CA back. A joined server that will
not restart on the older release is recovered with `sudo k3sm server --cluster-reset` on the server
that keeps the cluster, then the others join again as new members; see [HA](ha.md). No join token,
node certificate or kubeconfig is affected in either direction.

### Mesh Keys After Rolling Back Past the Key Directory Move

The release that made `/var/lib/k3sm` root-owned also moved each node's mesh keys and pod address
record from `/var/lib/k3sm/run/keys` to `/var/lib/k3sm/keys`. `sudo k3sm install` makes that move
once and removes the old copy, and the move is one-way: an older binary looks only in the old
directory, finds nothing, and gives the node a new mesh identity that no peer knows. Before you
downgrade, copy the files back by hand:

```sh
sudo mkdir -p -m 0700 /var/lib/k3sm/run/keys
sudo cp -p /var/lib/k3sm/keys/server.key /var/lib/k3sm/keys/node.key /var/lib/k3sm/keys/node-pod-cidr /var/lib/k3sm/run/keys/
```

A node has only the key for its own role, so `cp` reports the missing one; that is expected. The
older binary's installer also rebuilds its key copy from the node's own work-dir copy, so this step
is a second safeguard rather than the only one.

### Durable State After Rolling Back Past the LoadBalancer Bind Change

The release that moved LoadBalancer/Ingress listeners to the wildcard also changed **what k3sm writes
into the cluster**, and the older binary has no code to clean either of those up. Reverting the binary
does **not** revert them; you have to.

1. **Stale `EXTERNAL-IP` entries.** The new server advertises the node's derived InternalIP (e.g.
   `100.64.0.1`). The old server only ever retracted the address it was configured with, the loopback
   default, so it will **never** remove a derived entry. A rolled-back cluster keeps advertising an
   address its listeners are no longer on. Retract them by hand:

   ```sh
   kubectl get svc -A -o jsonpath='{range .items[?(@.spec.type=="LoadBalancer")]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'
   kubectl patch svc <name> -n <ns> --subresource=status --type=merge -p '{"status":{"loadBalancer":{}}}'
   ```

   Do the same for any `Ingress` of the `k3sm` class (`kubectl patch ingress … --subresource=status`).

2. **The reserved-port Deny policy.** The new server provisions the
   `k3sm-reject-loadbalancer-reserved-port` ValidatingAdmissionPolicy, which lives in the datastore and
   **survives the downgrade**. The old binary neither knows about it nor deletes it, so a
   `type: LoadBalancer` Service on a NodePort-range port or on `10250` stays rejected at
   `kubectl apply`. If you want the old (unguarded) behaviour back, delete both objects:

   ```sh
   kubectl delete validatingadmissionpolicybinding k3sm-reject-loadbalancer-reserved-port-binding
   kubectl delete validatingadmissionpolicy        k3sm-reject-loadbalancer-reserved-port
   ```

   Leaving them in place is also a valid choice, because the policy reflects a real collision on the
   old binary too.

3. **The denied-local-port Deny policy.** The same release provisions
   `k3sm-reject-service-denied-local-port`, which also lives in the datastore and **survives the
   downgrade**, so a Service published on the datastore port stays rejected at `kubectl apply`. Delete
   both objects if you want the old behaviour back:

   ```sh
   kubectl delete validatingadmissionpolicybinding k3sm-reject-service-denied-local-port-binding
   kubectl delete validatingadmissionpolicy        k3sm-reject-service-denied-local-port
   ```

   Check what you are getting back first. If the binary you rolled back to still denies that port in
   every pod sandbox, deleting the policy only hides the problem: the Service is created, its endpoints
   go Ready, and no pod can reach it.

An upgrade leaves a stopped node stopped. To start it from a script, see
[starting a stopped node from a script](stop-start.md#starting-a-stopped-node-from-a-script).

## Next

- [Stopping and starting](stop-start.md) explains why an upgrade leaves a stopped node stopped, and `--start`.
- [Backup & restore](backup-restore.md) covers backing up before an upgrade, and the automatic
  pre-migration copy.
- [Versions](versions.md) describes the version you are moving to.
- [Troubleshooting](troubleshooting.md) is where to go if the daemon does not restart.
