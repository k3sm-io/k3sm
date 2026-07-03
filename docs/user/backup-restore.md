# Backup & restore

k3sm keeps cluster state in an embedded **kine** datastore over **SQLite (WAL)**. Backing it up and
restoring it is how you protect and recover a cluster.

## What holds the state

The control-plane state of record is the kine/SQLite database under the server work directory (the
`db/state.db` family, including its WAL). This is distinct from **PersistentVolume data**, which lives in
local-path directories on each node (see [storage.md](storage.md)) and must be backed up separately.

## Backing up

Because SQLite runs in **WAL** mode, take a consistent snapshot rather than copying the file mid-write.
The supported path is the k3sm snapshot command:

```sh
k3sm snapshot save        # writes a consistent datastore snapshot
```

Keep snapshots off the node (another disk or host) so a machine loss does not take the backup with it.
Snapshot **before every upgrade** — see [upgrade.md](upgrade.md).

## Restoring

```sh
k3sm snapshot restore <snapshot>
```

Restoring replaces the datastore with the snapshot's state; restart the control-plane daemon
(`launchctl kickstart`) afterward so it reads the restored DB. On a [multi-node](multi-node.md) or
[HA](ha.md) cluster, follow the release runbook for restore ordering.

## Consistency notes

Single-node datastore reads are **consistent-LIST**; under heavy churn there is a **potential
watch-staleness** posture that is **soak-pending** validation. Factor that into recovery expectations —
see [limitations.md](limitations.md).

## Datastore migrations

A release may change the datastore schema/encoding. Such changes are **additive and phased** (add →
dual-read → cut → drop), never a live hard-swap, and may be **forward-only** — a snapshot from before a
migration is your safety net. See [upgrade.md](upgrade.md).

## Next

- [upgrade.md](upgrade.md) — snapshot-before-upgrade.
- [ha.md](ha.md) — restore as the HA recovery path.
- [storage.md](storage.md) — backing up PV data separately.
