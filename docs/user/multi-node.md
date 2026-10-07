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
```

The mesh address is IPv4 (the default mesh range is 100.64.0.0/10); a link-local or IPv6 address is refused at install time.
It must be the first address (`.1`) of a /24 inside that range that no other node uses, such as
100.64.0.1; the install refuses any other address, because that /24 becomes this Mac's pod range.
In an [HA](ha.md) cluster every server works this way: each server's `--mesh-ip` names its own /24,
and a server joining with a range another node already holds is refused rather than taking it.

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

The control plane only starts accepting joins once its own mesh enrolment has finished, which can
take up to a minute after `k3sm install` returns, so a join attempted immediately afterward may need
a retry.

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

On a control-plane install `--node-ip` means something else. There it is accepted only with
`--cluster-init` or `--server-join`, and it names the Mac's own **LAN** address, which the embedded
etcd member binds and the other servers dial. The install passes it to the server daemon as
`--etcd-peer-ip`; the server's node still advertises its `--mesh-ip`, so the LAN address is never
added to the loopback interface. See [HA](ha.md).

A node that joined with a wrong `--node-ip` before this release still holds a certificate issued for
that address, and the control plane cannot reach its kubelet, so `kubectl logs` and `kubectl exec`
against it fail. `k3sm status` on that Mac now reports the agent row as an address mismatch and
names the two addresses in the agent log. The fix is to rejoin with a fresh token, which re-issues
the certificate for the address the server assigns.

To predict the address before you join, run this on the server Mac:

```sh
k3sm kubectl get meshpeers
```

Every node already in the mesh shows up here with a `PODCIDR` column, a /24 carved out of the mesh
range: the first server holds `100.64.0.0/24`, and each worker takes the next free one in the order
nodes joined. The lowest number above 0 in the third position that is **not** already listed is the
new node's index, and its mesh address is the first host address in that node's /24 (the address
ending in `.1`). For example: if `get meshpeers` lists one existing peer at `100.64.0.0/24`, the
new node is index 1, its pod range is `100.64.1.0/24`, and the address it will be assigned is
`100.64.1.1`. A worker is never given index 0, and never a range an [HA](ha.md) server holds or has
reserved, so with a second server at `100.64.1.0/24` the next worker gets `100.64.2.0/24`. Each
range is owned through a claim object (a `Lease` named `meshrange-<n>` in `kube-system`), and two
servers answering joins at once cannot hand out the same range.

The join also returns the list of apiserver endpoints the worker may use: the server it joined
through first, then any other server whose node is Ready. The worker keeps talking to the server it
joined through.

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

**Onboarding several Macs at once:** mint a token per Mac. The server bounds how fast one token may
join, because a join costs it real work (a node-password binding, two signatures, and a mesh address
carved out of the cluster's range), and a token that has spent its budget is answered with a wait
rather than a refusal. An agent waits that out inside its own start, so two or three Macs sharing
one token still come up; a longer batch runs the install out of patience and says so. Running
`sudo k3sm token create` once per Mac costs nothing, and each token gets its own budget. The tokens
expire on their own after 24 hours whether or not you use them.

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

### Node-password bindings

The first join for a node name binds that name to the node's node-password, and every later join for
the name must present the same password. That binding is what stops another holder of a join token
from claiming an existing node's name. The server keeps each binding in the datastore as a
`kube-system` Secret named `<node>.node-password.k3sm`, holding only a hash of the password, so
bindings survive a server restart.

- After upgrading the server to this version, or after its datastore is wiped, workers that joined
  earlier have no binding until their next join. Stop handing out any join token you suspect has
  leaked and let it expire, and rejoin the workers you care about so their names are bound again.
- Rolling back to an older version leaves the Secrets in place. A later upgrade picks them up again.
- If the server logs that its own node-password file no longer matches the binding the datastore
  holds, put the original `server.node-password` file back in the server's work dir and restart the
  server. The log line names the path: `/var/lib/k3sm/server/` for a server running as root, or
  `server/` under the service user's home for one running unprivileged. If that file is gone,
  delete the server's binding and restart, and the server binds its name again:

  ```sh
  kubectl -n kube-system delete secret <node>.node-password.k3sm
  sudo launchctl kickstart -k system/io.k3sm.server
  ```

- A worker refused with a node-password mismatch after a reinstall may also mean another token
  holder bound its name first. Join tokens cannot be revoked from the CLI, so let any token you
  suspect has leaked expire (24 hours by default) before you recover. Then, on the server, delete the
  stale Node and its binding, and rejoin the worker right away with a fresh token from
  `sudo k3sm token create`:

  ```sh
  kubectl delete node <node>
  kubectl -n kube-system delete secret <node>.node-password.k3sm
  ```

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

### A worker on Wi-Fi

A worker proves it is alive with two writes to the apiserver: it renews its `Lease` every 10 seconds
and posts its node status once a minute. The controller-manager marks a node `NotReady` when its
Lease has not been renewed for the node-monitor grace period, 50 seconds by default (40 seconds
before Kubernetes 1.32). A lossy Wi-Fi link, or a roam to a new access point or a new DHCP address,
can break the connection those writes travel on without closing it, so k3sm bounds them:

- Both writes go through a client of their own, on their own connection, separate from the one the
  node's watches use.
- Each request has a 10 second timeout, so a write on a broken connection fails before the next
  renewal is due.
- The connection is checked with an HTTP/2 PING after 5 seconds without traffic, and closed if the
  PING is not answered within 5 seconds. The next write dials a new connection from whatever address
  the Mac has at that moment.

What that gives you:

- If the path to the server comes back within the 50 second grace period, the node stays `Ready`.
- If the path stays down longer, the node goes `NotReady` 50 seconds after its last renewal. Once the
  path returns, the Lease renewal resumes after a retry backoff of up to 7 seconds, and the worker
  posts its status within 10 seconds of finding that the post failed or that the controller-manager
  changed its `Ready` condition, as a kubelet does. The node is `Ready` again about 10 to 20 seconds
  after the path comes back.
- A node that stays `NotReady` or unreachable for 5 minutes has its Pods evicted, because Pods carry
  the default `node.kubernetes.io/not-ready` and `node.kubernetes.io/unreachable` tolerations of 300
  seconds. A Pod with a shorter `tolerationSeconds` is evicted sooner. A flap shorter than that
  evicts nothing, but every flap restarts the clock.

When a write fails, the worker's log says which request failed and why, and repeats of the same
failure are logged at most once every 30 seconds. Once a write has not landed within its window (40
seconds for the Lease, 100 seconds for the status), the log carries a `node heartbeat is stale` line
naming the write and its age, and `k3sm status` shows a `heartbeat` row with both ages. The node does
not restart itself: a write that cannot reach the server is a network problem a restart does not fix.

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

### Changing a Mac's role

A Mac is a control plane or a worker, never both, and it changes role by uninstalling and installing
again. To turn a server into a worker:

```sh
sudo k3sm uninstall
sudo k3sm install --agent \
  --server <server-underlay-ip> \
  --token-file /var/root/k3sm-join-token
```

Going the other way is the same two steps, ending in a plain `sudo k3sm install`. An install while
the other role is still on disk is refused and tells you to uninstall first.

Uninstall keeps the data root, the daemon logs and the node's wireguard key, so the Mac keeps its
mesh identity and nothing you configured is lost. It removes the pod address range this Mac's
networking helper adopted from its last join. That range belongs to the role that received it, and
the new role gets its own when it joins; keeping the old one would make the helper restore the
previous role's range when it starts.

Running `k3sm agent` by hand on a Mac that is still installed as a server is refused with the same
remedy. The networking helper on that Mac was installed for the control plane and still holds the
server's credentials, so it would refuse the worker's privileged Service binds.

Editing the installed launchd plists does not change a role, and neither does a restart:
`launchctl kickstart` never re-reads a plist, only a bootout and bootstrap does, which is what
install performs.

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
- A node that drops offline while running Pods leaves them stuck terminating; see
  [Troubleshooting](troubleshooting.md#a-node-went-offline-and-pods-are-stuck-terminating) for the
  out-of-service taint that unsticks them.

## Next

- [HA](ha.md) covers the HA control plane.
- [Upgrade](upgrade.md) describes the rolling-restart model.
- [Troubleshooting](troubleshooting.md) covers join and mesh failures.
