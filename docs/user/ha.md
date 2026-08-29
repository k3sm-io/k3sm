# High availability

Running the k3sm control plane so a single Mac is not a single point of failure.

> **Status: EXPERIMENTAL.** HA (M6) ships as documented **EXPERIMENTAL** — a v0.3 headline, not
> launch-blocking. Treat it as preview-quality. See [limitations.md](limitations.md).

## The model

A single-node k3sm embeds the control plane over **kine/SQLite**. HA extends this to multiple
control-plane Macs so the apiserver remains reachable if one node is lost. This builds on the
[multi-node](multi-node.md) mesh.

## What to plan for

- **Datastore** — the kine/SQLite datastore is the state of record. Understand
  [backup-restore.md](backup-restore.md) before running HA; a datastore restore is the recovery path if
  quorum or data is lost.
- **Rolling upgrades** — control-plane Macs upgrade **node-by-node** via launchd restart, creating a
  brief binary-version-skew window. See [upgrade.md](upgrade.md).
- **Consistency** — single-node datastore consistency is consistent-LIST with a soak-pending
  watch-staleness posture; multi-node consistency semantics inherit that caveat. See
  [limitations.md](limitations.md).

## Caveats

Because HA is EXPERIMENTAL, do not treat it as a production availability guarantee yet. Validate
failover and restore on your own hardware, and keep datastore backups — on this posture that means
`pg_dump`/PITR against your Postgres, not the single-node SQLite procedure (see
[backup-restore.md](backup-restore.md)).

## Next

- [multi-node.md](multi-node.md) — the mesh HA rides on.
- [backup-restore.md](backup-restore.md) — datastore recovery.
- [upgrade.md](upgrade.md) — rolling restarts.
