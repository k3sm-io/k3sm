# High availability

Running the k3sm control plane so a single Mac is not a single point of failure.

> **Status: EXPERIMENTAL.** HA ships as documented **EXPERIMENTAL** and is **not** launch-blocking;
> its de-EXPERIMENTAL graduation is the **v0.3** milestone. Treat it as preview-quality until then.
> See [Limitations](limitations.md).

## HA Model

A single-node k3sm embeds the control plane over **kine/SQLite**. HA extends this to multiple
control-plane Macs so the apiserver remains reachable if one node is lost, with kine pointed at an
operator-managed **Postgres** instead of the local SQLite file. The controller-manager and scheduler
elect a leader across the servers, and a joining server authenticates against the same cluster CA
bundle. This builds on the [multi-node](multi-node.md) mesh.

## What to Plan For

- The Postgres datastore is the state of record. Read [Backup & restore](backup-restore.md) before
  running HA; a datastore restore is the recovery path if data is lost.
- Control-plane Macs upgrade **node-by-node** via launchd restart, creating a brief
  binary-version-skew window. See [Upgrade](upgrade.md).
- Single-node datastore consistency is consistent-LIST with a soak-pending watch-staleness posture,
  and multi-node consistency semantics inherit that caveat. See [Limitations](limitations.md).

## Caveats

Because HA is EXPERIMENTAL, do not treat it as a production availability guarantee yet. Validate
failover and restore on your own hardware, and keep datastore backups. With HA that means
`pg_dump`/PITR against your Postgres, not the single-node SQLite procedure (see
[Backup & restore](backup-restore.md)). `k3sm snapshot save`/`restore` refuse here and say so,
because they cover the single-node SQLite datastore only and k3sm does not read your Postgres.

## Next

- [Multi-node](multi-node.md) is the mesh HA rides on.
- [Backup & restore](backup-restore.md) covers datastore recovery.
- [Upgrade](upgrade.md) describes the rolling restarts.
