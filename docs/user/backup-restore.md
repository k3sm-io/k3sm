# Backup & restore

k3sm keeps cluster state in an embedded **kine** datastore over **SQLite (WAL)**, or, on an HA
server, in an embedded **etcd** member. Backing it up and restoring it is how you protect and
recover a cluster.

## What Holds the State

The control-plane state of record is the kine/SQLite database under the server work directory (the
`db/state.db` family, including its WAL). This is distinct from **PersistentVolume data**, which lives in
local-path directories on each node (see [Storage](storage.md)) and must be backed up separately.

Three things back it up. **`k3sm snapshot save`** (below) runs on your own schedule. k3sm takes an
automatic pre-upgrade backup when a release changes the datastore engine. The file-level procedure
further down is the fallback for a node where the binary will not run.

If the cluster was installed with secrets encryption, back up `/var/lib/k3sm/server/cred` with
every backup and snapshot: neither contains the key, and without it the Secrets are unreadable. See
[Secrets Encryption at Rest](install.md#secrets-encryption-at-rest).

## Taking a Backup with `k3sm snapshot save`

```sh
k3sm snapshot save                      # -> <work-dir>/db/snapshots/k3sm-snapshot-<UTC>.db
k3sm snapshot save --out /Volumes/backups/k3sm.db
```

It is safe to run **while the control plane is serving**, because SQLite takes the copy inside a read
transaction and a concurrent write cannot tear it. What it does, in order:

1. Refuses unless the destination volume has **twice the database size** free, rather than writing a
   partial snapshot.
2. Writes a consistent point-in-time image of the datastore, runs `PRAGMA integrity_check` on **that
   image**, and only then renames it into place. A snapshot that exists under its final name is
   therefore complete and was confirmed readable as a database.

The work directory is owned by the `_k3sm` service user, so run it under `sudo` (or pass
`--work-dir`) when your shell user cannot read it. The snapshot is written `0600`.

**Copy it off the node.** The default location is the same volume as the cluster it protects, which
does not survive losing that volume. `--out` onto another disk or host is the better habit.

The snapshot does **not** contain PersistentVolume data; see [Storage](storage.md).

## Putting a Snapshot Back with `k3sm snapshot restore`

```sh
sudo launchctl bootout system/io.k3sm.server                       # 1. stop the control plane
sudo k3sm snapshot restore /Volumes/backups/k3sm.db                # 2. restore
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist   # 3. start it again
```

The restore is built to be survivable when it goes wrong:

- It **refuses while a control plane is running** (the launchd job, a foreground `k3sm server`, or a
  `k3sm dev` cluster) and names what to stop. Swapping the datastore under a live kine is
  corruption, not a restore, because kine keeps writing to the file it already holds open.
- It **verifies the snapshot before touching anything**. A snapshot that fails `integrity_check`
  costs you an error and nothing else; your current datastore is untouched.
- It **preserves what it replaces**. The superseded `state.db` is moved to
  `state.db.restore-<UTC>.bak` and never deleted, and its `-wal`/`-shm` sidecars and kine pin stamp
  go with it, because a stale sidecar left beside a restored database is exactly how a "successful"
  restore comes back with the state you were trying to discard.
- It prints the **verification step** below, and the `.bak` to keep if verification fails.

Restoring onto a node with no datastore at all (a rebuilt Mac) is supported, and is what the drill
is for.

## Restoring an HA Server (Embedded etcd)

On a server installed with `--cluster-init` or `--server-join`, the datastore is an embedded etcd
member, and `k3sm snapshot save` writes an etcd snapshot. `k3sm snapshot restore` puts one back.
It does what `k3s server --cluster-reset --cluster-reset-restore-path` does: it turns this server
into the **only member of a new etcd cluster** holding the snapshot's data. Every other server then
joins that cluster again as a new member.

Run it on the mint-authority server, the one installed with `--cluster-init`. If that server is
lost, run it on a joined server, then reinstall that server with `--cluster-init` in place of
`--server-join`, as [HA](ha.md) describes for `--cluster-reset`. Stop **every** server first, and
do not start the others again until step 4.

```sh
# 1. On every server: stop it.
sudo launchctl bootout system/io.k3sm.server

# 2. On the server you restore: restore, then start it.
sudo k3sm snapshot restore /Volumes/backups/k3sm-etcd-snapshot.db
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist

# 3. Verify it (see Verify the Restore below), and check that `k3sm status` shows one voting
#    etcd member with a leader present.

# 4. On every OTHER server: move its old etcd data aside, then start it. It joins the restored
#    server as a new member and is promoted.
sudo mv /var/lib/k3sm/server/etcd /var/lib/k3sm/server/etcd.pre-restore
sudo k3sm server --clear-crashloop          # only if it was started on its old data and parked
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist
```

The restore reads the server's member name, etcd peer address and peer port from the installed
server. Pass `--node-name`, `--etcd-peer-ip` and `--etcd-peer-port` to override them, for example on
a rebuilt Mac with no installed server yet. A server joins through its `--server` address, so a
server whose `--server` names a server other than the restored one has to be reinstalled with
`--server` set to the restored server before step 4. If its join is refused for its token, mint a
new server token on the restored server and reinstall with it.

What the restore does, in order:

- It **refuses while the server is running**: the work-dir lock, the etcd client, peer and apiserver
  ports, the launchd job, and the etcd process the server last recorded. A server stopped with
  `kill -9` can leave its etcd process running, and the restore names that process.
- It **refuses the wrong kind of file**. A kine SQLite snapshot is not restored into an etcd server,
  and an etcd snapshot is not restored into a single-server control plane. A copy of an etcd
  member's `member/snap/db` is not a snapshot: it carries no integrity hash, so it cannot be
  verified, and the restore refuses it by name. Take snapshots with `k3sm snapshot save`.
- It **verifies the snapshot before touching anything**: the SHA-256 hash etcd appends to every
  snapshot, then a read-only open of the database with etcd's own buckets. A corrupt or truncated
  file costs you an error and nothing else.
- It refuses unless the volume has **twice the snapshot's size** free.
- It **rebuilds the data dir beside the live one** (`etcd.restore-<UTC>.tmp`, mode 0700, owned like
  the data dir it replaces) with `etcdutl`, built from the same etcd release the server runs. The
  rebuilt cluster gets a new cluster ID, and its revision is raised by one billion and marked
  compacted. Every client that watched the old cluster holds a resource version the restored one
  has not reached, so without that bump a watcher could take old data for new. With it, every
  watcher and informer lists again from scratch.
- It **preserves what it replaces**. The old data dir becomes `etcd.restore-<UTC>.bak` and the etcd
  status record moves beside it. Nothing is deleted. If moving either into place fails, both are
  moved back and the work dir is as it was.

### What a Restore Puts Back, and What It Does Not

The snapshot is the datastore and nothing else. Restoring it puts the **whole datastore** back to
the moment the snapshot was taken:

- Objects created after the snapshot are gone, and objects deleted since are back. That includes
  Nodes and Pods, leases, the node-password bindings that tie node names to Macs, and bootstrap
  tokens. A worker that joined after the snapshot has to join again.
- The PKI is not reverted. The cluster CA, the etcd CAs, the service-account key and every
  certificate stay exactly as they are; the restore only reads them. A certificate issued after the
  snapshot stays valid.
- PersistentVolume data is not in the snapshot. Restore it separately (see [Storage](storage.md)).

### Servers Left on the Old Data

A server started on its old etcd data after the restore belongs to the cluster the restore
replaced. It asks the other servers for their cluster ID, finds the restored server on a different
one, and refuses to start. `k3sm status` shows the etcd row as `this server's etcd member belongs to
a cluster that was reset or restored` with the fix: move `<work-dir>/etcd` aside and join again,
which is step 4 above. The refusal parks the server until the crash-loop record is cleared. If two
servers on old data are started while the restored server is down, they can elect a leader and
serve the old data between them until they reach it. Start the restored server first.

### Snapshots Hold Secrets in Plaintext

An etcd snapshot holds every Secret in the cluster, unencrypted unless the cluster uses
[secrets encryption](install.md#secrets-encryption-at-rest). `k3sm snapshot save` writes it 0600.
Keep it that way, and keep it off shared storage. `k3sm snapshot restore` warns when the file it is
given is readable by its group or by others. It does not change the file's mode, because the file is
yours: run `chmod 600` on it yourself.

## Automatic Pre-Migration Backup

A release may move to a newer kine, which re-runs its schema migrations against your existing
database. That is **one-way**, so before the new version opens the database for the first time, the
server takes a backup with the control plane stopped and no writer running:

1. It refuses to continue unless the volume has **twice the database size** free. You get a clear
   error and nothing is written; free space and start the server again.
2. It checkpoints the write-ahead log into the main database and **verifies the log drained**. Without
   this, a copy of `state.db` alone would silently omit committed writes.
3. It copies the database to a temporary name, runs `PRAGMA integrity_check` on the **copy**, and only
   then renames it into place, so a backup that exists is complete and verified.
4. It preserves the kine binary that wrote the database beside the backup, because rolling back needs
   the version that can read it.

In the server work directory's `db/` you will find:

| File | What it is |
|---|---|
| `state.db` | the live datastore |
| `state.db.pre-<kine-version>.bak` | the verified backup taken before moving to `<kine-version>` |
| `kine.pre-<kine-version>` | the kine binary that wrote that backup |
| `state.db.kine-pin` | which kine version last opened `state.db` successfully |

The backup is **write-once**. Once it exists, later boots leave it alone. A crash-restart loop never
overwrites it, and a copy of an already-migrated database never replaces it.

## Backing Up by Hand

The file-level procedure below does what `k3sm snapshot save` does, with `sqlite3(1)` and `cp`. Use it
when the k3sm binary will not run on the node (a broken install, a rescue boot from another machine's
disk), or when you want to see every step. Otherwise prefer the command, which verifies the copy for
you and refuses rather than writing a partial one.

Because SQLite runs in **WAL** mode, do not copy `state.db` out from under a running server. The copy
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
`--work-dir`. Keep backups **off the node**, on another disk or another host, so losing the machine
does not lose the backup with it.

## Restoring by Hand

The same fallback rule applies. Prefer `k3sm snapshot restore`, which performs the steps below and
verifies the snapshot before it moves anything. Restoring replaces the datastore with the backup's
state. The server must be stopped, because an open datastore file swapped underneath a running kine
is corruption, not a restore.

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
sudo cp state.db.pre-v0.17.1.bak state.db          # or your own copy from above
sudo chown _k3sm state.db

# 4. Start the control plane.
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist
```

## Verify the Restore

`k3sm snapshot restore` prints these steps when it finishes; run them either way. A restore that
starts the daemon is not a restore that worked. Check that the API server is serving **and that the
objects you expected came back**:

```sh
k3sm kubectl get --raw='/readyz?verbose'      # every check ok
k3sm kubectl get nodes                        # your node(s), Ready
k3sm kubectl get pods -A                      # the workloads the backup should contain
k3sm doctor                                   # the datastore row: journal_mode=wal, kine pin reported
```

If the objects are missing or the datastore check reports a non-WAL journal, stop, keep
`state.db.broken`, and do not let workloads reconcile against a half-restored cluster.

## Rolling Back to the Previous kine as Well

If you are restoring a `state.db.pre-<version>.bak` **because** a version move went wrong, install the
previous k3sm binary too (see [Upgrade](upgrade.md) § Rollback). The preserved
`kine.pre-<version>` binary beside the backup is there for that case. The superseded kine pin cannot
be rebuilt from source without a module proxy that still carries it, so those bytes are the copy you
have.

## Retention

- Keep the automatic `.bak` until you are confident in the new version. A week of real workload is a
  reasonable bar, and it is the only pre-migration copy that exists.
- Once you are confident, delete it. It is a full copy of the database and it does not shrink.
- Keep your **own** off-node backups on your own schedule (`k3sm snapshot save --out …`); the
  automatic one only appears when a release changes the datastore engine, so it is not a backup
  policy.
- `k3sm snapshot restore` leaves a `state.db.restore-<UTC>.bak` (plus its sidecars) behind on every
  restore. Keep the most recent one until you are confident in the restored cluster; they are full
  copies and do not shrink.
- Deleting a `.bak` re-arms nothing. The automatic backup is taken per target version, and that
  version has already been recorded as having opened the database.

## Consistency Notes

Single-node datastore reads are **consistent-LIST**. Under heavy churn, **watch staleness** is
possible and its **soak** validation is still pending. Factor that into recovery expectations; see
[Limitations](limitations.md).

## Next

- [Upgrade](upgrade.md) covers what happens to the datastore across a version move.
- [HA](ha.md) describes the multi-server control plane being built, which v0.1.6 does not offer.
- [Storage](storage.md) covers backing up PV data separately.
