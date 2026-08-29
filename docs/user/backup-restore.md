# Backup & restore

k3sm keeps cluster state in an embedded **kine** datastore over **SQLite (WAL)**. Backing it up and
restoring it is how you protect and recover a cluster.

## What holds the state

The control-plane state of record is the kine/SQLite database under the server work directory (the
`db/state.db` family, including its WAL). This is distinct from **PersistentVolume data**, which lives in
local-path directories on each node (see [storage.md](storage.md)) and must be backed up separately.

There is no `k3sm snapshot` command. Backups are the file-level procedure below, plus the automatic
pre-upgrade backup k3sm takes for you when a release changes the datastore engine.

## The automatic pre-migration backup

A release may move to a newer kine, which re-runs its schema migrations against your existing
database. That is **one-way**, so before the new version opens the database for the first time, the
server takes a backup — while the control plane is stopped, so there is no writer:

1. It refuses to continue unless the volume has **twice the database size** free. You get a clear
   error and nothing is written; free space and start the server again.
2. It checkpoints the write-ahead log into the main database and **verifies the log drained**. Without
   this, a copy of `state.db` alone would silently omit committed writes.
3. It copies the database to a temporary name, runs `PRAGMA integrity_check` on the **copy**, and only
   then renames it into place. So the backup existing means the backup is complete and verified.
4. It preserves the kine binary that wrote the database beside the backup, because rolling back needs
   the version that can read it.

In the server work directory's `db/` you will find:

| File | What it is |
|---|---|
| `state.db` | the live datastore |
| `state.db.pre-<kine-version>.bak` | the verified backup taken before moving to `<kine-version>` |
| `kine.pre-<kine-version>` | the kine binary that wrote that backup |
| `state.db.kine-pin` | which kine version last opened `state.db` successfully |

The backup is **write-once**: once it exists, later boots leave it alone. It is never overwritten by a
crash-restart loop, and never replaced by a copy of an already-migrated database.

## Backing up by hand

Because SQLite runs in **WAL** mode, do not copy `state.db` out from under a running server — the copy
would be missing whatever is still in the log.

```sh
# 1. Stop the control plane. (kickstart RESTARTS; to back up you need it stopped.)
sudo launchctl bootout system/io.k3sm.server

# 2. Fold the WAL into the database and confirm it drained (the -wal must be 0 bytes or gone).
sqlite3 /var/lib/k3sm/server/db/state.db 'PRAGMA wal_checkpoint(TRUNCATE);'
ls -l /var/lib/k3sm/server/db/state.db-wal

# 3. Copy it, and verify the COPY before you trust it.
cp /var/lib/k3sm/server/db/state.db ~/k3sm-backup-$(date +%Y%m%d).db
sqlite3 -readonly "file:$HOME/k3sm-backup-$(date +%Y%m%d).db?immutable=1" 'PRAGMA integrity_check;'   # must print: ok

# 4. Start the control plane again.
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist
```

Adjust the work-dir path if you run unprivileged (`~/server` under the service user's home) or passed
`--work-dir`. Keep backups **off the node** — another disk or another host — so losing the machine does
not lose the backup with it.

## Restoring

Restoring replaces the datastore with the backup's state. The server must be stopped: an open
datastore file swapped underneath a running kine is corruption, not a restore.

```sh
# 1. Stop the control plane.
sudo launchctl bootout system/io.k3sm.server

# 2. Move the current datastore aside — do NOT delete it. Take its sidecars too; a stale
#    -wal/-shm beside a restored database is exactly how a "successful" restore comes back
#    with the state you were trying to discard.
cd /var/lib/k3sm/server/db
sudo mv state.db state.db.broken
sudo rm -f state.db-wal state.db-shm

# 3. Put the backup in place.
sudo cp state.db.pre-v0.17.0.bak state.db          # or your own copy from above
sudo chown _k3sm state.db

# 4. Start the control plane.
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist
```

### Verify the restore — do not skip this

A restore that starts the daemon is not a restore that worked. Check that the API server is serving
**and that the objects you expected came back**:

```sh
k3sm kubectl get --raw='/readyz?verbose'      # every check ok
k3sm kubectl get nodes                        # your node(s), Ready
k3sm kubectl get pods -A                      # the workloads the backup should contain
k3sm doctor                                   # datastore check: journal_mode=wal, kine pin reported
```

If the objects are missing or the datastore check reports a non-WAL journal, stop, keep
`state.db.broken`, and do not let workloads reconcile against a half-restored cluster.

### Rolling back to the previous kine as well

If you are restoring a `state.db.pre-<version>.bak` **because** a version move went wrong, install the
previous k3sm binary too (see [upgrade.md](upgrade.md) § Rollback). The preserved
`kine.pre-<version>` binary beside the backup is there for that case: the superseded kine pin cannot be
rebuilt from source without a module proxy that still carries it, so those bytes are the copy you have.

## Retention

- **Keep the automatic `.bak` until you are confident in the new version** — a week of real workload
  is a reasonable bar. It is the only pre-migration copy that exists.
- Once you are confident, delete it. It is a full copy of the database and it does not shrink.
- Keep your **own** off-node backups on your own schedule; the automatic one only appears when a
  release changes the datastore engine, so it is not a backup policy.
- Deleting a `.bak` re-arms nothing: the automatic backup is taken per target version, and that
  version has already been recorded as having opened the database.

## Consistency notes

Single-node datastore reads are **consistent-LIST**; under heavy churn there is a **potential
watch-staleness** posture that is **soak-pending** validation. Factor that into recovery expectations —
see [limitations.md](limitations.md).

## HA / Postgres

On the [HA](ha.md) posture the state of record is the operator-managed Postgres, not a local SQLite
file. Nothing above applies: back it up with `pg_dump`/PITR on your Postgres schedule.

## Next

- [upgrade.md](upgrade.md) — what happens to the datastore across a version move.
- [ha.md](ha.md) — the Postgres datastore and its own backup path.
- [storage.md](storage.md) — backing up PV data separately.
