# High availability

Running the k3sm control plane so a single Mac is not a single point of failure.

> **Status: not available in v0.1.6.** A k3sm cluster runs one server. `k3sm server` carries the
> `--cluster-init` and `--server-join` flags for an embedded etcd cluster, but a second server
> cannot join yet, and `k3sm install` does not expose the flags. External-datastore (Postgres) HA
> and the `--datastore-endpoint` and `--datastore-endpoint-file` flags were removed in v0.1.6. This
> page describes the design being built. See [Limitations](limitations.md).

## HA Model

A single-node k3sm embeds the control plane over **kine/SQLite**. HA extends this to multiple
control-plane Macs so the apiserver remains reachable if one node is lost, with an embedded
**etcd** cluster instead of the local SQLite file. The design opts in with `--cluster-init` on the
first server and `--server-join` on the others. There is no conversion from an existing SQLite
cluster to etcd, and none from an external database. The controller-manager and scheduler elect a
leader across the servers, and a joining server authenticates against the same cluster CA bundle.
This builds on the [multi-node](multi-node.md) mesh.

## What to Plan For

- The embedded etcd datastore is the state of record. Read [Backup & restore](backup-restore.md) before
  running HA; a datastore restore is the recovery path if data is lost.
- Control-plane Macs upgrade **node-by-node** via launchd restart, creating a brief
  binary-version-skew window. See [Upgrade](upgrade.md).
- Single-node datastore consistency is consistent-LIST with a soak-pending watch-staleness posture,
  and multi-node consistency semantics inherit that caveat. See [Limitations](limitations.md).

## Caveats

Until a second server can join, there is no HA control plane to rely on, and no availability
guarantee. Keep datastore backups of the single server (see [Backup & restore](backup-restore.md)).
On a server started with `--cluster-init`, `k3sm snapshot save` streams an online snapshot of this
server's etcd member, and `k3sm snapshot restore` refuses, because restoring an etcd member is not
supported in this release.

## Next

- [Multi-node](multi-node.md) is the mesh HA rides on.
- [Backup & restore](backup-restore.md) covers datastore recovery.
- [Upgrade](upgrade.md) describes the rolling restarts.
