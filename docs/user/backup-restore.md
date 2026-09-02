# Backup & restore

k3sm keeps cluster state in an embedded **kine** datastore over **SQLite (WAL)**. Backing it up and
restoring it is how you protect and recover a cluster.

## What Holds the State

The control-plane state of record is the kine/SQLite database under the server work directory (the
`db/state.db` family, including its WAL). This is distinct from **PersistentVolume data**, which lives in
local-path directories on each node (see [Storage](storage.md)) and must be backed up separately.

Three things back it up: **`k3sm snapshot save`** (below) on your own schedule, the automatic
pre-upgrade backup k3sm takes when a release changes the datastore engine, and the file-level
procedure further down — the fallback for a node where the binary will not run.

## `k3sm snapshot save` — Taking a Backup

```sh
k3sm snapshot save                      # -> <work-dir>/db/snapshots/k3sm-snapshot-<UTC>.db
k3sm snapshot save --out /Volumes/backups/k3sm.db
```

It is safe to run **while the control plane is serving**: the copy is taken by SQLite inside a read
transaction, so a concurrent write cannot tear it. What it does, in order:

1. Refuses if this node's state of record is an external **Postgres** datastore (there is nothing
   local to copy — see [HA / Postgres](#ha--postgres)).
2. Refuses unless the destination volume has **twice the database size** free, rather than writing a
   partial snapshot.
3. Writes a consistent point-in-time image of the datastore, runs `PRAGMA integrity_check` on **that
   image**, and only then renames it into place — so a snapshot that exists under its final name is
   complete and was confirmed readable as a database.

The work directory is owned by the `_k3sm` service user, so run it under `sudo` (or pass
`--work-dir`) when your shell user cannot read it. The snapshot is written `0600`.

**Copy it off the node.** The default location is the same volume as the cluster it protects, which
does not survive losing that volume. `--out` onto another disk or host is the better habit.

The snapshot does **not** contain PersistentVolume data — see [Storage](storage.md).

## `k3sm snapshot restore` — Putting One Back

```sh
sudo launchctl bootout system/io.k3sm.server                       # 1. stop the control plane
sudo k3sm snapshot restore /Volumes/backups/k3sm.db                # 2. restore
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist   # 3. start it again
```

The restore is built to be survivable when it goes wrong:

- It **refuses while a control plane is running** — the launchd job, a foreground `k3sm server`, or a
  `k3sm dev` cluster — and names what to stop. Swapping the datastore under a live kine is
  corruption, not a restore: kine keeps writing to the file it already holds open.
- It **verifies the snapshot before touching anything**. A snapshot that fails `integrity_check`
  costs you an error and nothing else; your current datastore is untouched.
- It **preserves what it replaces**. The superseded `state.db` is moved to
  `state.db.restore-<UTC>.bak` — never deleted — and its `-wal`/`-shm` sidecars and kine pin stamp go
  with it, because a stale sidecar left beside a restored database is exactly how a "successful"
  restore comes back with the state you were trying to discard.
- It prints the **verification step** below, and the `.bak` to keep if verification fails.

Restoring onto a node with no datastore at all (a rebuilt Mac) is supported — that is what the drill
is for.

## Automatic Pre-Migration Backup

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

## Backing Up by Hand — The Fallback

The file-level procedure below does what `k3sm snapshot save` does, with `sqlite3(1)` and `cp`. Use it
when the k3sm binary will not run on the node (a broken install, a rescue boot from another machine's
disk), or when you want to see every step. Otherwise prefer the command: it verifies the copy for you
and refuses rather than writing a partial one.

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

## Restoring by Hand — The Fallback

The same fallback rule applies: prefer `k3sm snapshot restore`, which performs the steps below and
verifies the snapshot before it moves anything. Restoring replaces the datastore with the backup's
state. The server must be stopped: an open datastore file swapped underneath a running kine is
corruption, not a restore.

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

## Verify the Restore — Do Not Skip This

`k3sm snapshot restore` prints these steps when it finishes; run them either way. A restore that
starts the daemon is not a restore that worked. Check that the API server is serving **and that the
objects you expected came back**:

```sh
k3sm kubectl get --raw='/readyz?verbose'      # every check ok
k3sm kubectl get nodes                        # your node(s), Ready
k3sm kubectl get pods -A                      # the workloads the backup should contain
k3sm doctor                                   # datastore check: journal_mode=wal, kine pin reported
```

If the objects are missing or the datastore check reports a non-WAL journal, stop, keep
`state.db.broken`, and do not let workloads reconcile against a half-restored cluster.

## Rolling Back to the Previous kine as Well

If you are restoring a `state.db.pre-<version>.bak` **because** a version move went wrong, install the
previous k3sm binary too (see [Upgrade](upgrade.md) § Rollback). The preserved
`kine.pre-<version>` binary beside the backup is there for that case: the superseded kine pin cannot be
rebuilt from source without a module proxy that still carries it, so those bytes are the copy you have.

## Retention

- **Keep the automatic `.bak` until you are confident in the new version** — a week of real workload
  is a reasonable bar. It is the only pre-migration copy that exists.
- Once you are confident, delete it. It is a full copy of the database and it does not shrink.
- Keep your **own** off-node backups on your own schedule (`k3sm snapshot save --out …`); the
  automatic one only appears when a release changes the datastore engine, so it is not a backup
  policy.
- `k3sm snapshot restore` leaves a `state.db.restore-<UTC>.bak` (plus its sidecars) behind on every
  restore. Keep the most recent one until you are confident in the restored cluster; they are full
  copies and do not shrink.
- Deleting a `.bak` re-arms nothing: the automatic backup is taken per target version, and that
  version has already been recorded as having opened the database.

## Consistency Notes

Single-node datastore reads are **consistent-LIST**; under heavy churn there is a **potential
watch-staleness** posture that is **soak-pending** validation. Factor that into recovery expectations —
see [Limitations](limitations.md).

## HA / Postgres

On the [HA](ha.md) posture the state of record is the operator-managed Postgres, not a local SQLite
file. Nothing above applies: back it up with `pg_dump`/PITR on your Postgres schedule.

`k3sm snapshot save` and `k3sm snapshot restore` **refuse on that posture** and say so, naming
`pg_dump`. That is deliberate: k3sm does not read your Postgres, so anything it could write there
would not be a backup of your cluster. It detects the posture from the server's
`--datastore-endpoint` (or `$K3SM_DATASTORE_ENDPOINT`) and from the `.pgpass` file the server writes
in the work directory; if a node no longer uses Postgres, remove that file and the commands work
again.

## Next

- [Upgrade](upgrade.md) — what happens to the datastore across a version move.
- [HA](ha.md) — the Postgres datastore and its own backup path.
- [Storage](storage.md) — backing up PV data separately.
