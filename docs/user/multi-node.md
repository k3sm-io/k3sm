# Multi-node

Joining more than one Mac into a single k3sm cluster.

> **Status: EXPERIMENTAL.** Multi-node ships as documented **EXPERIMENTAL** and is **not**
> launch-blocking; its de-EXPERIMENTAL graduation is the **v0.3** milestone. Treat it as
> preview-quality until then. See [Limitations](limitations.md).

## Mesh Model

One Mac runs the control plane (`k3sm server`); additional Macs join as **agents** running the Virtual
Kubelet node. Nodes are connected by a **wireguard mesh** (the `MeshPeer` model), so Pods and Services
can be reached across machines.

## Serving the control plane from this Mac

The Mac that runs `k3sm server` needs to know its own wireguard mesh address before other nodes
can join it. Set it with `--mesh-ip` at install time:

```sh
sudo k3sm install --mesh-ip <this-macs-mesh-address>

The mesh address is IPv4 (the default mesh range is 100.64.0.0/10); a link-local or IPv6 address is refused at install time.
```

This writes the address into the server daemon's arguments and restarts it. A plain `sudo k3sm
install` re-run already boots the daemons out and back in, so it always picks up the address you
gave it; there is no need to edit the installed launchd plist by hand, and doing so would not
survive the next install anyway (`launchctl kickstart` alone never re-reads a plist, only a
bootout and bootstrap does, which is what install performs).

Running `sudo k3sm install --mesh-ip <new-address>` again later replaces the stored address with
the new one. Leaving `--mesh-ip` off a later reinstall keeps whatever address was set before.

## Joining an Agent

On the server, mint a join token:

```sh
sudo k3sm token create
```

Run it with `sudo`, because the cluster CA whose hash the token pins lives in the control-plane
state root, which belongs to the `_k3sm` service user. Without `sudo` the work dir resolves to your
own home and the command exits non-zero rather than inventing a CA there.

On the agent Mac, put the token in a file only root can read, then install the agent:

```sh
sudo sh -c 'umask 077; cat > /var/root/k3sm-join-token'   # paste the token, then press Ctrl-D
sudo k3sm install --agent \
  --server <server-underlay-ip> \
  --token-file /var/root/k3sm-join-token
```

`--server` is the control-plane Mac's **underlay** address (a LAN IP or DNS name, no scheme, no
port). The join dials `<server>:9345`, not the apiserver's `:6443`.

`--node-ip` is **optional**, and it does not name this Mac's own LAN address at all. It names the
**mesh** address this node holds inside the cluster's wireguard mesh range (100.64.0.0/10 by
default; there is no flag to change that range). The server assigns that address during the join
and issues the node's certificates for it, so there is nothing you have to supply: pass
`--node-ip <this-macs-mesh-address>` only to assert the address you expect. A value that differs
from the one the server assigns fails the join with a message naming both, instead of bringing the
node up on an address it does not hold.

To predict the address before you join, run this on the server Mac:

```sh
k3sm kubectl get meshpeers
```

Every node already in the mesh shows up here with a `PODCIDR` column, a /24 carved out of the mesh
range in the order nodes joined: the first node holds `100.64.0.0/24`, the second `100.64.1.0/24`,
and so on. The lowest number in the third position that is **not** already listed is the new
node's index, and its mesh address is the first host address in that node's /24 (the address
ending in `.1`). For example: if `get meshpeers` lists one existing peer at `100.64.0.0/24`, the
new node is index 1, its pod range is `100.64.1.0/24`, and the address it will be assigned is
`100.64.1.1`.

`--agent` installs the `io.k3sm.agent` LaunchDaemon, so the worker starts at boot and is restarted
if it exits, exactly as the control plane is on the server Mac. A Mac is one role or the other: an
install that would put the agent on a machine already running the control plane, or the other way
round, is refused. Change a node's role with `sudo k3sm uninstall` and then install again. Uninstall
keeps the data root, the logs and the flags you configured.

`--token-file` names your own file holding the token. It can be anywhere root can read, because
`k3sm install` runs as root and reads it once: the daemon runs as the unprivileged `_k3sm` user and
could not open a file in root's home, so the installer copies the token to
`/var/lib/k3sm/agent/join-token`, owned by that user and readable by nobody else. That copy is what
the daemon reads, and it is the only token on the Mac the daemon ever sees. No token is written into
the LaunchDaemon plist, which is readable by every account.

The install waits for the join to finish before it reports success: it watches for the node
credential the agent writes, so a token the server rejects fails the install with a message instead
of leaving a daemon that retries every 30 seconds behind a healthy process.

Once the node shows up `Ready` in `kubectl get nodes` on the server you can delete **both** copies:
your own file and `/var/lib/k3sm/agent/join-token`. Neither is needed again. A joined node presents
the credential it stored at the join, and a missing token file is not an error at start, so the
daemon keeps restarting normally with both gone. `sudo k3sm uninstall` deletes the staged copy for
you. A node that has already joined needs no token at all, so `--token-file` can be dropped from a
later install.

The agent authenticates with the bootstrap token, receives its node credentials, and its wireguard peer
**public** key is registered in the `MeshPeer` records held in the datastore. Private keys never leave
the node. The `MeshPeer` records carry public keys only.

### Restarting a node

A joined agent keeps its credential in its work dir, so restarting it needs no token. It presents the
certificates it already holds, republishes its wireguard endpoint, and carries on as the same node.
Supply a token again only in three cases: the stored credential is missing, it has expired, or you are
moving this Mac to a different cluster. In that last case the token wins: a token that pins a different
cluster CA makes the agent join the cluster the token came from and replace what it had stored. A token
for the cluster the node is already in is ignored, so leaving one in a start script is harmless.

The node certificate an agent receives at join is valid for one year. Nothing renews it in place, so
renewing it means rejoining with a fresh token before it expires.

### If a node's address changes

The endpoint a node publishes is the address its peers dial to open a wireguard handshake, and on a
Mac that address is not fixed: a DHCP lease can change, and moving between Wi-Fi and Ethernet or
docking and undocking changes it outright. Each node therefore re-checks the address it is reachable
at every 30 seconds and republishes it when it has changed, so its `MeshPeer` record follows the
machine rather than recording where it was when it joined. A change takes about a minute to appear,
because a new value has to be seen twice in a row before it is published. That delay is deliberate:
an address seen once during an interface transition may belong to a link that is about to go away,
and publishing it would point every peer at an address that no longer answers.

The node authenticates this update with its own node certificate, the credential it received when it
joined, and the update can carry nothing but the endpoint. A node can only change its own record. The
join token is not involved and is not kept on the node after the join; it expires after 24 hours by
default, so an update that depended on it would stop working after a day. `kubectl describe node
<name>` shows a `MeshEndpointChanged` event with the old and new values whenever this happens.

### Removing a worker

`sudo k3sm uninstall` on a worker asks the cluster to forget the node before it tears the local
install down. Its `MeshPeer` record and its `Node` object are both deleted, so the Macs that stay in
the cluster drop the wireguard entry and the route they were holding for it, and it stops appearing
in `kubectl get nodes`.

The node authenticates that request with its own node certificate, the same credential the endpoint
update uses, and it can only ever remove itself. The control plane performs the deletion on its
behalf, so a worker is granted no new permission anywhere in the cluster.

This needs the control plane to be reachable, and often it is not: the cluster may be off, asleep, or
on another network by the time a Mac is retired. That never blocks the uninstall. It prints what went
wrong and carries on, and you finish the job from the control plane:

```sh
kubectl delete meshpeer/<node> node/<node>
```

Run that same command for a worker whose disk was wiped, or which was uninstalled by a k3sm release
older than this one. A node with no stored credential, or one whose certificate has already expired,
cannot deregister itself either, and the uninstall says so.

Uninstall keeps the stored credential, as it keeps the rest of the data root. Reinstalling the same
Mac after a deregistration therefore resumes into a cluster that no longer has a `MeshPeer` for it:
supply `--token-file` and it joins again as a new node, and without a token the agent stops and says
it must rejoin.

## What Crosses Nodes

- Services resolve cluster-wide via the userspace Service proxy.
- Mesh traffic between Pods on different nodes rides the wireguard tunnel with per-peer symmetric
  `AllowedIPs`.

## Caveats

- Cross-node Pod traffic has been shown to pass only on the two-Mac lab rig the
  [roadmap](https://github.com/k3sm-io/k3sm/blob/main/ROADMAP.md) records (2026-09-01), not by a
  shipped acceptance gate, and cross-node traffic to or from a `vm` Pod is out of scope for this
  release ([Limitations](limitations.md)).
- Per-pod IP identity and headless/StatefulSet DNS records are present, but multi-node as a whole is
  EXPERIMENTAL. Validate cross-node resolution for your own workload rather than assuming it. See
  [Limitations](limitations.md).
- A cluster upgrade is a **node-by-node** rolling restart of the launchd daemons; see
  [Upgrade](upgrade.md).
- For a highly-available control plane, see [HA](ha.md) (also EXPERIMENTAL).

## Next

- [HA](ha.md) covers the HA control plane.
- [Upgrade](upgrade.md) describes the rolling-restart model.
- [Troubleshooting](troubleshooting.md) covers join and mesh failures.
