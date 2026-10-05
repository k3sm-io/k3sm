# High availability

Running the k3sm control plane on more than one Mac.

> **Status: EXPERIMENTAL.** HA ships as documented **EXPERIMENTAL** and is **not** launch-blocking;
> its de-EXPERIMENTAL graduation is the **v0.3** milestone. Treat it as preview-quality until then.
> See [Limitations](limitations.md).

## HA Model

A single-node k3sm keeps its state in **kine over SQLite**, a file on the one control-plane Mac. HA
replaces that with **embedded etcd**: each control-plane Mac runs an etcd member inside its own
`k3sm server`, and the members replicate the cluster state between them. There is no external
datastore to run. The controller-manager and scheduler elect a leader across the servers, and every
server holds the same cluster certificate authorities. HA builds on the [multi-node](multi-node.md) mesh, so each server also needs its own
`--mesh-ip`. That address must be the `.1` of a /24 in the mesh range that no other node uses
(100.64.0.1 on the first server), and the install refuses any other address.

HA is opt-in, and it is decided when a server is installed. The first server forms the cluster with
`--cluster-init`:

```sh
sudo k3sm install --cluster-init --node-ip <first-server-lan-ip> --mesh-ip <first-server-mesh-ip>
```

On that Mac, mint a **server** token. It is a different token from the one a worker joins with:

```sh
sudo k3sm token create --server
```

On the second Mac, put the token in a file only root can read and join with `--server-join`:

```sh
sudo sh -c 'umask 077; cat > /var/root/k3sm-server-token'   # paste the token, then press Ctrl-D
sudo k3sm install --server-join \
  --server <first-server-lan-ip> \
  --token-file /var/root/k3sm-server-token \
  --node-ip <second-server-lan-ip> --mesh-ip <second-server-mesh-ip>
```

`--node-ip` is each Mac's own **LAN** address. The etcd members talk to each other on it, so it must
be an address the other server can reach, and it cannot be loopback. The mesh carries Pod traffic
only. The install hands this address to the server daemon as `--etcd-peer-ip`, which is the etcd
peer address and nothing else. The node itself is known in the cluster by its `--mesh-ip`, the same
as on a single control-plane Mac, so the LAN address is never added to the loopback interface. If you
run `k3sm server` by hand, pass the LAN address as `--etcd-peer-ip` and leave `--node-ip` unset;
`k3sm server` refuses `--cluster-init` or `--server-join` without `--etcd-peer-ip`, and refuses a
`--node-ip` equal to it. `--server` names the first server by that same LAN address; the joining server fetches the
cluster certificate authorities from it and is added to the etcd cluster through it.

The install checks that the server it names answers and is the cluster the token belongs to before
it writes anything. It then copies the token to `/var/lib/k3sm/server/join-token`, owned by the
`_k3sm` service user and readable by nobody else, which is where the daemon reads it on every start.
That copy stays for as long as the Mac is a joined server, so the daemon can restart; it is removed
by `sudo k3sm uninstall`, and by an install that changes the server to `--cluster-init`. Your own
file is read once and is yours to delete afterwards. No token is written into the LaunchDaemon
plist. The joined server still has the admin token the install stages at
`/var/lib/k3sm/server/token`, but that token is not the credential it authenticates with: a joining
server's apiserver generates its own, and its admin kubeconfig is `admin.kubeconfig` in the server
work dir, which works against any server of the cluster.

The HA flags are recorded with the server's other arguments, so a later plain `sudo k3sm install`
keeps them. That includes an install after `sudo k3sm uninstall`, which keeps the recorded
arguments; `sudo k3sm uninstall --purge --yes` discards them. A server's role is fixed once its etcd member has data:
asking a server that formed the cluster to `--server-join` another one (or the other way round) is
refused while its member data is on disk, and the refusal names what to stop and what to remove.
`--cluster-init` cannot be combined with `--server-join`, and neither can be combined with `--agent`.

## What to Plan For

- **Two servers tolerate no failures.** Two voting members need both for every write: if either
  Mac stops, writes stop on the other until it returns. Surviving the loss of one server takes three.
  If one of two servers is lost for good, stop the survivor's daemon and run
  `k3sm server --cluster-reset` there, as the `_k3sm` user with the daemon's own arguments; it
  becomes a one-member cluster that keeps its data, and you can then join a new second server.
- **Any server token holder can evict or replace another server's etcd member**, within the
  authority that token already grants. A server token reconstructs every cluster certificate
  authority, so give it only to a Mac you trust as a control plane, and do not keep the file around.
- **Backups.** `k3sm snapshot save` takes an online snapshot of this server's etcd member.
  Restoring an etcd member from a snapshot is not supported yet, and `k3sm snapshot restore`
  refuses on an HA server. See [Backup & restore](backup-restore.md).
- Control-plane Macs upgrade **node-by-node** via launchd restart, creating a brief
  binary-version-skew window. See [Upgrade](upgrade.md).
- `sudo k3sm uninstall` on an HA server removes its etcd member from the cluster before it stops the
  daemon, so the remaining server is not left waiting for a member that is gone.

## Caveats

Because HA is EXPERIMENTAL, do not treat it as a production availability guarantee yet. Validate
failover and recovery on your own hardware, and take snapshots. An existing single-node cluster is
not converted to HA: `--cluster-init` over a server that already holds a SQLite datastore is refused
when the server starts, so create the HA cluster on a fresh data root.

## Next

- [Multi-node](multi-node.md) is the mesh HA rides on.
- [Backup & restore](backup-restore.md) covers datastore recovery.
- [Upgrade](upgrade.md) describes the rolling restarts.
