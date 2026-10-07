# High availability

Running the k3sm control plane so a single Mac is not a single point of failure.

> **Status: EXPERIMENTAL.** `k3sm install --cluster-init` forms an embedded etcd control plane on
> the first server, and `k3sm install --server-join` adds a second one. Treat it as preview quality
> and keep datastore backups. A controller manager or scheduler that loses its leader lease when
> quorum is lost is counted as a crash, so repeated quorum loss can park a server. External-datastore (Postgres) HA and the `--datastore-endpoint` and
> `--datastore-endpoint-file` flags were removed in v0.1.6. See [Limitations](limitations.md).

## HA Model

A single-node k3sm embeds the control plane over **kine/SQLite**. HA extends this to multiple
control-plane Macs so the apiserver remains reachable if one node is lost, with an embedded
**etcd** cluster instead of the local SQLite file. The design opts in with `--cluster-init` on the
first server and `--server-join` on the others. There is no conversion from an existing SQLite
cluster to etcd, and none from an external database. The controller-manager and scheduler elect a
leader across the servers, and a joining server authenticates against the same cluster CA bundle.
This builds on the [multi-node](multi-node.md) mesh.

## Mesh Addresses and Pod Ranges

Each server's `--mesh-ip` is also its pod range: the /24 whose first address (`.1`) it is. The
first server conventionally takes `100.64.0.1`, which is the range `100.64.0.0/24`. Give every
further server the `.1` of its own unused /24, for example `100.64.1.1`. The server's loopback
alias, its apiserver, its node's pods and its entry in the wireguard mesh all use that one range,
and workers are never assigned a range a server holds.

When a server joins with `--server-join`, the existing server checks the joiner's range and
reserves it before it adds the joiner's etcd member:

- If another node already holds that range, the join is refused and nothing is added to etcd. The
  holder is never evicted, whether it is a worker or another server. Choose a free `--mesh-ip`, or
  remove the stale entry on the existing server (`kubectl delete meshpeer <holder>` and
  `kubectl -n kube-system delete lease meshrange-<n>`, where `<n>` is the third number of the
  range), then install the joining server again. The joining server records the refusal as a
  permanent failure, so `k3sm status` shows it with this remedy, and the crash-loop record has to
  be cleared before it tries again.
- The joining server's node name is bound to that Mac, the same way a worker's is, so a second Mac
  cannot join under a server name that is already taken.
- An existing server that runs an older k3sm does not reserve the range. The joining server notices
  that its reservation was not acknowledged and refuses to start, asking you to upgrade the
  existing servers first.
- A server's range is never moved for you. If a server's name already holds a different range than
  its `--mesh-ip` names, the server refuses that range until you remove its old `MeshPeer` and lease.
- A server whose range is not its own (another node took it, or its name holds a different one)
  keeps etcd, the apiserver and the controllers running, so the cluster keeps its quorum, but it
  starts no node and no pod network. Its log names the holder and the recovery: while the cluster
  has quorum, delete the stale `MeshPeer` and lease and run
  `sudo launchctl kickstart -k system/io.k3sm.server`; if a server is down, run
  `sudo k3sm server --cluster-reset` on the survivor first.
- A reservation is released again when the etcd member add that follows it fails. One left behind
  for more than 15 minutes, by a server with no Ready node and no etcd member, is listed by
  `k3sm status` on a server (the `mesh-claims` row) and removed the next time a server starts.

## Reaching the Apiservers

Each server writes an admin kubeconfig (`<work-dir>/admin.kubeconfig`) that points at its own mesh
IP. That address is reachable from every Mac on the mesh, so either server's kubeconfig works from
any of them. kubectl takes a single server address and does not fail over, so when one server is
down, use the other server's kubeconfig.

A worker that joins receives a list of apiserver endpoints: the server it joined through first, then
every other server whose node is Ready. Workers stay attached to the server they joined through;
there is no client-side failover between servers yet.

## What to Plan For

- The embedded etcd datastore is the state of record. Read [Backup & restore](backup-restore.md) before
  running HA; a datastore restore is the recovery path if data is lost.
- Control-plane Macs upgrade **node-by-node** via launchd restart, creating a brief
  binary-version-skew window. See [Upgrade](upgrade.md). Upgrade every existing server before you
  join a new one.
- Two servers tolerate no failure: losing either one stops all writes until it returns, or until
  the survivor runs `sudo k3sm server --cluster-reset`. Tolerating the loss of a server takes three.
- Single-node datastore consistency is consistent-LIST with a soak-pending watch-staleness posture,
  and multi-node consistency semantics inherit that caveat. See [Limitations](limitations.md).

## Upgrading an HA Cluster to the Aggregation Layer

The release that adds the aggregation layer gives the cluster a request-header CA (see
[Certificates](certificates.md#the-request-header-ca)) and moves the join bundle to schema 3. An
older joined server cannot read a schema 3 bundle, and a new joined server refuses a schema 2 bundle,
so the order matters:

1. Upgrade the **mint-authority server** first: the one installed with `--cluster-init`. Its
   `k3sm status` shows `ha-role mint-authority` on the `request-header` row. On its next start it
   creates the CA. Wait until it is ready and answering on its join port before going on.
2. Upgrade each **joined server**, one at a time, and wait for it to be ready before the next. On
   start it fetches the CA from the server it joins through (any server already upgraded).
3. You are done when the `request-header` row shows the same pin on every server and a trusted count
   of 1. A count above 1, or a pin that differs between servers, means a CA came from outside this
   procedure and needs investigating.

A joined server whose `--server` is still on the old release waits up to 30 minutes, logging that it
is waiting, and then exits. It starts by itself once that server is upgraded in time, and it writes
nothing while it waits. Workers are not affected and can restart in any order.

Do not restart every server at once while a joined server still lacks the CA. On two servers the
joined server waits for a bundle and the mint authority waits for etcd quorum, so neither comes up.
Recover with etcd's own path: run `sudo k3sm server --cluster-reset` on the mint authority, start it
normally, then wipe the joined server's etcd data and join it again as a new member. Its CA files are
kept.

If the mint-authority server is lost, do not drop `--server-join` on a survivor. Run
`sudo k3sm server --cluster-reset` on it and reinstall it with `--cluster-init` in place of
`--server-join`; it keeps the CAs it imported and becomes the mint authority.

Rolling back is described under [Upgrade](upgrade.md#rolling-back-past-the-aggregation-layer).

## Caveats

Until a two-server cluster has been run end to end, there is no HA control plane to rely on, and no
availability guarantee. Keep datastore backups (see [Backup & restore](backup-restore.md)).
On a server started with `--cluster-init`, `k3sm snapshot save` streams an online snapshot of this
server's etcd member, and `k3sm snapshot restore` refuses, because restoring an etcd member is not
supported in this release.

## Next

- [Multi-node](multi-node.md) is the mesh HA rides on.
- [Backup & restore](backup-restore.md) covers datastore recovery.
- [Upgrade](upgrade.md) describes the rolling restarts.
