# Multi-node

Joining more than one Mac into a single k3sm cluster.

> **Status: EXPERIMENTAL** (what that means: [Experimental and alpha](README.md#what-experimental-means)).
> See [Limitations](limitations.md).

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

## Extra Names for the Apiserver Certificate

Every server serves the apiserver with a certificate signed by the cluster CA. It is valid for the
in-cluster names (`kubernetes`, `kubernetes.default` and the rest), `localhost`, the node name,
`127.0.0.1`, the `kubernetes` Service address and, on a server with `--mesh-ip`, the mesh address. To reach the apiserver by another
name, such as a DNS name for this Mac or a load balancer in front of it, add the name with
`--tls-san`, once per name:

```sh
sudo k3sm install --mesh-ip 100.64.0.1 --tls-san api.example.com --tls-san <this-macs-lan-address>
```

Each name is a hostname or an IP address. An IP address must be one this Mac holds: an address on
one of its interfaces, its mesh address, or a loopback address. A hostname is checked for spelling
only and is never looked up, because a load balancer or a public DNS name legitimately points
somewhere else. Install refuses wildcards, a trailing dot, a port, a URL, an IPv6 zone, a name whose
last label is all digits (some resolvers read `10.1` as an address), the names the certificate
already carries, and addresses inside the pod or Service ranges. A server takes at most 32 names.

The list is stored with the other server flags. Passing `--tls-san` on a later install replaces the
whole list; leaving it off keeps the list you set before. The certificate is issued again every time
the server starts, so a changed list takes effect when the server restarts, which install does for
you. If an address in the list later leaves this Mac (a DHCP lease moved it, for example), the server
logs a warning at start and still issues the name.

`--tls-san` works the same way on a single-node server, which has no mesh address to add.

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
port). The join dials `<server>:9345`, not the apiserver's `:6444`.

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
Each node also publishes its pod range on its Node object as `spec.podCIDR` (and `spec.podCIDRs`).

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

### Pushing images from a worker

A worker writes no user kubeconfig, which is also how k3s behaves. To push to the cluster registry
from a worker, copy the admin kubeconfig from the server and write one on the worker:

```sh
k3sm kubeconfig --server https://<server>:6444 --certificate-authority <ca> --write
```

`k3sm build`, `k3sm image load`, `import` and `push` then upload to the server's registry at its
cluster address on port 6450, over HTTPS checked against the cluster CA, with a push token minted
through that kubeconfig. `k3sm registry login` writes the same address and the cluster CA into your
docker config for docker, buildx, crane and oras. A user who should push without administering the
cluster needs the `k3sm:registry-builder-token` Role, bound with a RoleBinding in `k3sm-registry`,
and a read of EndpointSlices there to find the address. See
[the cluster registry](registry.md#pushing-with-other-tools).

### Restarting a node

A joined agent keeps its credential in its work dir, so restarting it needs no token. It presents the
certificates it already holds, republishes its wireguard endpoint, and carries on as the same node.
Supply a token again only in three cases: the stored credential is missing, it has expired, or you are
moving this Mac to a different cluster. In that last case the token wins: a token that pins a different
cluster CA makes the agent join the cluster the token came from and replace what it had stored. A token
for the cluster the node is already in is ignored, so leaving one in a start script is harmless.

The node certificate an agent receives at join is valid for one year. Nothing renews it in place, so
renewing it means rejoining with a fresh token before it expires.

### The datapath identity

Each node's Service proxy, cluster DNS resolver and NetworkPolicy watcher talk to the apiserver as
their own identity, not as the node: a client certificate with the user `k3sm:netserve:<node>` in
the group `k3sm:netservers`, signed by the cluster's client CA. The server binds that group to the
`k3sm:netserve` ClusterRole, which can get, list and watch Services, EndpointSlices, Namespaces,
NetworkPolicies and Pods across the cluster, and nothing else. This is the shape k3s gives its agent
controllers (`system:k3s-controller`).

What that read covers, so you can judge what a compromised node exposes:

- Every Pod spec in every namespace, including literal environment values, command arguments, image
  names, and the names of the Secrets and ConfigMaps a Pod refers to. Put sensitive values in a
  Secret rather than inline in a Pod spec.
- Never the value of a Secret or a ConfigMap: the role has no access to either.
- No Pod logs, no `exec`, `attach` or port-forward, and no write of any kind. It cannot create a
  Service, change a Node or read the Node objects.

An agent receives the certificate when it joins, beside its node certificate, and stores it as
`netserve.kubeconfig` in its work dir with the same `0600` mode. An agent that joined before this
identity existed, or whose copy is missing or about to expire, asks the server for a new one,
authenticating with its node certificate. The server issues it only for that node's own name, at most
five times in a row and then once a minute per node, and never for longer than the node certificate
has left. A worker upgraded in place therefore picks up the identity on its first start after the
upgrade and needs no new token. The server's own datapath mints the same identity in memory.

The certificate lives as long as the node certificate it was issued against, one year from the join.
A running node checks it every six hours and replaces it in place during its last day, without
restarting the datapath; the server does the same for its own copy. As in k3s, nothing revokes an
issued certificate: deleting the Node or the `MeshPeer` does not cut it off, and the only way to
invalidate every outstanding certificate before it expires is to rotate the cluster CA.

Upgrade the server first, then the agents one node at a time. In a cluster where the server is older
than an upgraded agent, that agent does not start: it logs that the server does not issue this
certificate and retries every half minute until the server is upgraded.

The server lays down the role and its binding at every start, and repairs either one if its rules,
subjects or role reference have been changed. If that step fails, the server stops its start rather
than run with a partial grant; fix the cause the log names and restart the server, which applies the
grant again.

With this identity every node enforces NetworkPolicy for its own Pods. To confirm what it may do:

```sh
kubectl auth can-i list pods --all-namespaces --as=k3sm:netserve:<node> --as-group=k3sm:netservers   # yes
kubectl auth can-i list secrets --all-namespaces --as=k3sm:netserve:<node> --as-group=k3sm:netservers  # no
```

If you once added ClusterRoleBindings by hand to give the `system:nodes` group the datapath's reads,
such as one binding the upstream `system:node` ClusterRole to that group, they are no longer needed.
k3sm neither creates nor deletes them; remove them yourself with `kubectl delete clusterrolebinding
<name>`.

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

## LoadBalancer Services Across Nodes

In a multi-node cluster every node can host `type: LoadBalancer` Services. The server decides which
nodes host each Service, and each chosen node binds the Service's ports and forwards connections to
its ClusterIP. `status.loadBalancer.ingress` lists one address per hosting node, and a node is listed
only while it is Ready and holds every TCP port of the Service. With no labels at all, every node
hosts every LoadBalancer Service.

The addresses are the nodes' mesh addresses, for example `100.64.0.1` and `100.64.1.1`. They are
reachable from cluster nodes and pods, not from your LAN; see
[Limitations](limitations.md#which-addresses-your-services-answer-on).

To see which nodes were chosen for a Service and which addresses are published:

```sh
kubectl get service web -o jsonpath='{.metadata.annotations.svclb\.k3sm\.io/hosts}{"\n"}'
kubectl get service web
```

### Node Pools

| Label | On | Effect |
|---|---|---|
| `svclb.k3sm.io/enablelb=true` | Node | Allow-list mode. Once any node carries this label with the value `true`, only nodes labelled `true` host LoadBalancer Services. Any other value does not turn the mode on. |
| `svclb.k3sm.io/lbpool=<pool>` | Service | Host the Service only on nodes in `<pool>`. |
| `svclb.k3sm.io/lbpool=<pool>` | Node | Put the node in one pool. |
| `lbpool.svclb.k3sm.io/<pool>=true` | Node | Put the node in `<pool>`. A node can carry several of these, and they combine with the single-pool label. |

Keep LoadBalancer traffic off one Mac:

```sh
kubectl label node node-a svclb.k3sm.io/enablelb=true
```

Now only `node-a` hosts LoadBalancer Services. Remove the label from every node to return to "every
node hosts".

Split two Services across two pools, so both can use the same port:

```sh
kubectl label node node-a lbpool.svclb.k3sm.io/blue=true
kubectl label node node-b svclb.k3sm.io/lbpool=green
kubectl label service web-blue svclb.k3sm.io/lbpool=blue
kubectl label service web-green svclb.k3sm.io/lbpool=green
```

A Service whose pool no node is in stays `<pending>`, with a `NoEligibleNodes` Warning Event on it.

### Coming From k3s

k3sm reads its own keys only. Relabel when you move a workload over:

| k3s ServiceLB | k3sm |
|---|---|
| `svccontroller.k3s.cattle.io/enablelb` (Node) | `svclb.k3sm.io/enablelb` |
| `svccontroller.k3s.cattle.io/lbpool` (Node and Service) | `svclb.k3sm.io/lbpool` |
| the multi-pool Node label form | `lbpool.svclb.k3sm.io/<pool>=true` |

There are no per-node `svclb-*` pods. Each node's k3sm process holds the listeners itself.

### LoadBalancer Caveats

- Pool and allow-list labels live on Node objects, which a node may edit on itself. A compromised
  node can label itself into a pool and attract that pool's traffic, the same posture as k3s
  ServiceLB. Treat pools as placement, not isolation.
- The same applies to allow-list mode. A node that labels itself `svclb.k3sm.io/enablelb=true`
  turns allow-list mode on for the whole cluster, and if no other node carries the label it becomes
  the only host of every Service without a pool. k3s ServiceLB behaves the same way.
- Two Services on the same port can share a node only if they never land on it together. On one
  node the second bind fails, that node stays out of the second Service's status, and a
  `HostNotBound` Warning Event on the Service names the node. A pod already listening on the port
  has the same effect.
- `externalTrafficPolicy: Local` is not narrowed to nodes with a local endpoint. Every hosting node
  forwards to the ClusterIP, so the client source address is lost.
- Upgrade the server first and then the agents, one node at a time, because an agent needs its
  [datapath identity](#the-datapath-identity) from the server. An agent older than its server hosts
  no LoadBalancer Service until it is upgraded.

## What Crosses Nodes

- Services resolve cluster-wide via the userspace Service proxy.
- Mesh traffic between Pods on different nodes rides the wireguard tunnel with per-peer symmetric
  `AllowedIPs`.
- Pods that opt in can also reach each other over a Thunderbolt cable between two Macs, once an
  admin arms it; see [Interconnects](interconnects.md).

## Caveats

- Native Pods on different Macs reach each other by pod IP, each pod IP sits inside its node's
  published `spec.podCIDR`, and a headless Service answers A, SRV and PTR lookups from either node.
  Since v0.1.7 a `vm` Pod answers on its pod IP from every node, for TCP on
  the ports it declares and the ports a Service targets on it; UDP to a `vm` Pod's IP is not relayed
  ([Limitations](limitations.md#vm-pods-services-and-direct-pod-ips)).
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
