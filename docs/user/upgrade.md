# Upgrade

Moving a k3sm node or cluster to a new release.

## Single Node

Script (gen-1) installs — re-run the one-liner:

```sh
curl -fsSL https://k3sm.io/install.sh | sh
```

An unpinned re-run installs the **latest** release. Pin `K3SM_INSTALL_VERSION=vX.Y.Z` to
re-install the version you are already on (repair without upgrading), and pin an older version
to downgrade — that pin-and-re-run is the script channel's rollback path.

Homebrew installs:

```sh
brew upgrade k3sm
```

Either way the upgrade replaces the binary and restarts the k3sm LaunchDaemons (the
`io.k3sm.netd` root helper and the `_k3sm` server/agent jobs) onto the new version — Homebrew
via `launchctl kickstart`, the script via the `sudo k3sm install` re-run. This is a **hard
cut** with a brief daemon restart — the node is momentarily unavailable while the daemons
restart.

## Multi-Node — Roll Node-by-Node

A cluster upgrades **one node at a time**, not all at once. Restarting each node's daemon via `launchctl
kickstart` creates a short **binary-version-skew window** where old and new nodes coexist; k3sm releases
are designed so adjacent versions interoperate across that window. Upgrade agents first and the
control-plane Mac last unless a release note says otherwise. See [Multi-node](multi-node.md) and
[HA](ha.md).

## Before You Upgrade

- **Back up the datastore.** `sudo k3sm snapshot save --out <somewhere off this node>` — it is safe to
  run while the cluster is serving, and it verifies the copy before it reports success. The file-level
  fallback (stop the daemon, `PRAGMA wal_checkpoint(TRUNCATE)`, copy, verify the copy) is in
  [Backup & restore](backup-restore.md). k3sm also takes an automatic pre-migration backup when a
  release changes the datastore engine (below), but that copy lives on the same disk as the cluster it
  protects, so it is not a substitute for yours.
- **Know your rollback path.** Homebrew retains the prior bottle, so rollback does not require a
  rebuild round-trip; on the script channel, prior releases stay downloadable — rollback is
  `K3SM_INSTALL_VERSION=<prior-tag>` and a re-run.
- **Check the version skew.** Confirm the target Kubernetes pin with `k3sm version` — see
  [Versions](versions.md).

## Upgrading Across a Datastore-Engine Change

Some releases move to a newer **kine** (the etcd-shim over SQLite). A newer kine re-runs its schema
migrations against your existing `state.db`, which is **one-way** — the migrated database is not
converted back if you reinstall the older k3sm.

You do not have to do anything for this, but you should know what it does:

- **Before** the new version opens the database, the server takes a verified backup at
  `db/state.db.pre-<kine-version>.bak` and preserves the old kine binary beside it as
  `kine.pre-<kine-version>`. The mechanics — the WAL drain, the integrity check, the write-once
  rule — are in [Backup & restore](backup-restore.md).
- It **refuses to start** if the volume does not have twice the database size free, rather than
  writing a partial backup. Free space and start it again; nothing was changed.
- The first boot on the new engine is slower than usual (the checkpoint + the copy). Later boots are not.
- **Keep the `.bak`** until you are satisfied with the new release, then delete it — it is a full copy
  of the database.

On the [HA](ha.md) Postgres posture none of this applies; the datastore is your Postgres, and its
backup is `pg_dump`/PITR on your schedule.

## Upgrading Into the Reserved-Port Policy

The release that moved LoadBalancer listeners to the wildcard also provisions a
`ValidatingAdmissionPolicy` that **rejects** a `type: LoadBalancer` Service declaring a port k3sm's own
listeners own — the NodePort range `30000-32767`, or the kubelet API port `10250`. It matches on
CREATE **and** UPDATE, and it deliberately does **not** ratchet on `oldObject`.

That means a cluster **already carrying** such a Service is not grandfathered in. The object stays in
the datastore and keeps working, but **every subsequent write to it is denied** — not just a port
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

- **Change the port** to one outside the reserved set — the intended fix, since the Service could never
  have had a working listener on a port k3sm already holds.
- **Patch `type` away from `LoadBalancer`** (e.g. to `ClusterIP` or `NodePort`); the policy is scoped to
  LoadBalancer Services only, so the object becomes writable again immediately.

Do **not** expect a `--force` or an exemption: the ratcheting is omitted on purpose. A policy that
tolerated a pre-existing offender would leave the collision — and the `kubectl logs`/`exec` outage it
can cause — silently in place.

## Rollback

Rollback is **revert to the previous binary** (`brew` pin/switch to the prior bottle, or on the
script channel `K3SM_INSTALL_VERSION=<prior-tag>` and a re-run) plus the daemon restart that
comes with it, not a runtime flag flip.

If the release you are leaving changed the **datastore engine**, reverting the binary is only half of
it — the database has already been migrated in place. Restore the `db/state.db.pre-<kine-version>.bak`
the upgrade left behind (or your own pre-upgrade snapshot) with the daemon stopped:

```sh
sudo launchctl bootout system/io.k3sm.server
sudo k3sm snapshot restore /var/lib/k3sm/server/db/state.db.pre-<kine-version>.bak
sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist
```

`k3sm snapshot restore` refuses while the daemon is running, verifies the backup before it touches
anything, and prints the verification step you must then run — see
[Backup & restore](backup-restore.md). Rolling the binary back without restoring the backup leaves an
older k3sm pointed at a database a newer engine has migrated.

### Rolling Back Past the LoadBalancer Bind Change Leaves Durable State

The release that moved LoadBalancer/Ingress listeners to the wildcard also changed **what k3sm writes
into the cluster**, and the older binary has no code to clean either of those up. Reverting the binary
does **not** revert them; you have to.

1. **Stale `EXTERNAL-IP` entries.** The new server advertises the node's derived InternalIP (e.g.
   `100.64.0.1`). The old server only ever retracted the address it was configured with — the loopback
   default — so it will **never** remove a derived entry. A rolled-back cluster keeps advertising an
   address its listeners are no longer on. Retract them by hand:

   ```sh
   kubectl get svc -A -o jsonpath='{range .items[?(@.spec.type=="LoadBalancer")]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'
   kubectl patch svc <name> -n <ns> --subresource=status --type=merge -p '{"status":{"loadBalancer":{}}}'
   ```

   Do the same for any `Ingress` of the `k3sm` class (`kubectl patch ingress … --subresource=status`).

2. **The reserved-port Deny policy keeps rejecting Services.** The new server provisions the
   `k3sm-reject-loadbalancer-reserved-port` ValidatingAdmissionPolicy, which lives in the datastore and
   **survives the downgrade**. The old binary neither knows about it nor deletes it, so a
   `type: LoadBalancer` Service on a NodePort-range port or on `10250` stays rejected at
   `kubectl apply`. If you want the old (unguarded) behaviour back, delete both objects:

   ```sh
   kubectl delete validatingadmissionpolicybinding k3sm-reject-loadbalancer-reserved-port-binding
   kubectl delete validatingadmissionpolicy        k3sm-reject-loadbalancer-reserved-port
   ```

   Leaving them in place is also a valid choice — the policy reflects a real collision on the old
   binary too.

## Next

- [Backup & restore](backup-restore.md) — back up before upgrading; the automatic pre-migration copy.
- [Versions](versions.md) — the version you are moving to.
- [Troubleshooting](troubleshooting.md) — if the daemon does not restart.
