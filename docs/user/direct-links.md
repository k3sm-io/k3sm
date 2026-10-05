# Direct links

Cable two Macs together with Thunderbolt and k3sm uses the cable: it can admit the new Mac into the
cluster over it, it routes Pod and Service traffic between the two Macs across it, and it records
which Macs are cabled to which so a sharded model can be placed on them.

> **Status: EXPERIMENTAL.** Direct links build on [multi-node](multi-node.md), which is itself
> EXPERIMENTAL. Read [the trust statement](#trust-statement) before you cable a Mac you do not
> control.

## What a direct link is

A direct link is a point-to-point cable between two cluster Macs. Thunderbolt is the only medium
today: Thunderbolt 3, 4 and 5 all carry IP, and Thunderbolt 5 on macOS 26.2 or later can also carry
RDMA.

For every Thunderbolt port that has another Mac on the end of it, k3sm:

- takes the port out of the Thunderbolt Bridge (`bridge0`), leaving the bridge itself and any other
  member alone, and never editing the service in System Settings;
- gives the port an address derived from the node's index and the port number, in
  `169.254.0.0/24` or `169.254.255.0/24`. Those two ranges are the reserved halves of the link-local
  range, which macOS never assigns to an interface on its own, so the address cannot collide with a
  self-assigned one on Wi-Fi or Ethernet, and there is no address plan to keep;
- routes the cabled peer's Pods over the cable once both Macs report the cable ready, and keeps the
  wireguard tunnel to that peer as the fallback;
- prefers the cable as the wireguard endpoint, so the mesh itself stays up with no LAN at all.

Each node publishes what it sees as a `DirectLink` object named after the node:

```sh
kubectl get directlinks
kubectl get directlink <node> -o yaml
```

The spec is the node's own view: its ports, the cable at each end, the address and whether the link
and the routes are up. The status is the control plane's view, joining both ends of every cable:

| state | meaning |
|---|---|
| `up` | both Macs list each other, both report link and ready routes, neither sets `tunnelOnly`, and the peer's node heartbeat is current. Pod traffic to that peer crosses the cable. |
| `peer-unknown` | a Mac is cabled to this port, but it is not in the cluster. |
| `down` | anything else. Pod traffic to that peer rides the wireguard tunnel. |

The nodes also carry advisory labels: `k3sm.io/direct-link-ports`, `k3sm.io/direct-link-medium`
(`thunderbolt`), `k3sm.io/direct-link-speed-gbps`, `k3sm.io/direct-links` (the count of links up) and
`k3sm.io/rdma` when RDMA is enabled. A node can set any `k3sm.io` label on itself, so nothing in k3sm
decides placement or routing from these labels; they are for display and coarse selection.

## Plug and join

A Mac with k3sm installed and a Thunderbolt cable to a control-plane Mac can join without a token
and without an address.

On the control plane, open the pairing window and read the cluster pin:

```sh
sudo k3sm pair --for 10m
```

It prints how long the window stays open, the cluster pin, and the exact line for the new Mac. The
window admits at most one completed join unless you pass `--max-joins`, and that is a hard bound:
the control plane hands out no more outstanding tokens than joins the window has left, and it
refuses a token at join time once the window has closed or is full. A token still unused when the
window closes is dead with it, and a token from an earlier window never joins a later one. `k3sm pair`
alone shows the window and prints the line again; `sudo k3sm pair --close` ends it early. You can
also open it at install time with `sudo k3sm install --mesh-ip <address> --pairing 10m`.

On the new Mac, install it as an auto-joining worker:

```sh
sudo k3sm install --auto-join --cluster <pin>
```

Then plug in the cable. Within a few seconds the new Mac hears the control plane's beacon on its
Thunderbolt port, asks it for a join token over the cable, and runs the ordinary join. When
`kubectl get nodes` shows the node `Ready`, it is a member like any other worker.

What happens on the way:

1. The control plane takes each cabled Thunderbolt port out of the bridge and sends a small beacon to
   that port every two seconds, saying which cluster it is and whether its pairing window is open.
2. The new Mac listens for beacons on its Thunderbolt ports and on `bridge0`, because a Mac that has
   not joined yet has its ports in the bridge still. It skips a beacon whose pin differs from
   `--cluster`.
3. It asks the control plane for a token, over TLS pinned to that cluster's CA. The control plane
   answers only when the request reached it on one of its own Thunderbolt ports, from an address on
   the same cable, while the window is open, and not more than once per port every 10 seconds.
4. The token it hands out is an ordinary worker join token that lives for two minutes, works only
   for the node name the Mac asked for, and works once. It is never written to the new Mac's disk.
5. The join is the same join a `--token-file` install runs. The new Mac records the control plane's
   address on the cable, so it can reach the control plane again after a restart with no LAN.

`--auto-join` arms the new Mac for ten minutes (`--arm` changes that). An unarmed Mac ignores every
beacon. If it was not plugged in while armed, re-arm it with:

```sh
sudo k3sm pair --listen 10m --cluster <pin>
```

After a successful join the Mac never pairs again: every later start presents the credential it
stored at the join.

## A cluster with only the cable

A cluster of Macs with no Wi-Fi and no Ethernet between them forms and runs over Thunderbolt alone:
the join runs over the cable's link-local addresses, each node advertises its cable address as its
wireguard endpoint, and the control plane's first route to a new node is installed from the join
itself, before any other link state exists.

Run **one** control plane in such a cluster. The high-availability flags (`--cluster-init`,
`--server-join`) refuse a Thunderbolt link-local or cable address for `--node-ip` and `--server`,
because the datastore peers dial those addresses directly and are not designed to depend on a cable.
See [HA](ha.md).

## Trust statement

Read this section before you cable a Mac you do not control.

- **Traffic on the cable is plaintext.** Pod and Service traffic between two cabled Macs crosses the
  cable as ordinary IP, with no wireguard encryption. The tunnel is used only when the cable is not.
- **Any device on the cable can send as any Pod.** Nothing on the wire checks that a packet arriving
  on the cable with a Pod's source address came from that Pod. Traffic from `vm` Pods leaves the
  host the same way and crosses the cable too.
- **Sharded models listen to every Pod.** The ports the ranks of a sharded model use to talk to each
  other carry no authentication, and every Pod in the cluster can reach them. Run sharded serving
  only for workloads you trust.
- **The beacon tells every device on the cable which cluster this is.** The cluster pin and the
  control plane's node name are in every beacon. The pin is a hash of the cluster's CA certificate,
  which is public; it identifies the cluster, it does not let anyone join it.
- **Without `--cluster`, the new Mac trusts the first server it hears.** While armed, a Mac installed
  with `--auto-join` and no `--cluster` joins the first open-pairing server it hears on its
  Thunderbolt ports. A device on the cable that pretends to be a control plane could then receive
  its join and run Pods on it. Pass the pin `k3sm pair` prints to rule that out, the same way the
  pin in a join token does for a `--token-file` join. Arming is bounded for the same reason.
- **The control plane admits only what arrives on its own Thunderbolt port.** The pairing request is
  judged by the interface the control plane's kernel received the connection on, never by an
  address or a name the requester sends, and only while you hold the window open.

To keep Pod traffic off a cable without unplugging it, set the port to tunnel-only on that node:

```sh
sudo k3sm link tunnel-only en2          # one port
sudo k3sm link tunnel-only --all        # every port
sudo k3sm link tunnel-only --all --off  # undo
```

The node republishes the port with `tunnelOnly: true` within seconds, the control plane reports it
`down`, and both Macs go back to the wireguard tunnel for each other's Pods. An administrator can
set the same field directly with `kubectl patch directlink <node>`; the node keeps it until a local
`k3sm link tunnel-only` says otherwise.

`k3sm status` shows a links row whenever the node has Thunderbolt ports, and it names the plaintext
state:

```text
direct links: 1 up (thunderbolt, 40 Gb/s, plaintext) · rdma: no
```

Every link that comes up or goes down is also a Node event, so `kubectl describe node <node>` shows
when a cable started or stopped carrying plaintext traffic.

## What unplugging does

- **With a LAN or Wi-Fi path still there**, Pod traffic falls back to the wireguard tunnel when the
  cable goes. macOS deletes the routes bound to the Thunderbolt interface as soon as its link drops,
  and the tunnel route for the peer's Pods was never removed, so the fallback needs no k3sm code to
  run. The wireguard endpoint moves to the peer's LAN address on the next mesh reconcile. Open TCP
  connections keep working, because both paths use the same segment size.
- **When the peer sleeps or hangs with the cable still in**, the link stays up and macOS deletes
  nothing. Each node probes its cabled peer every 5 seconds, and three missed probes withdraw the
  direct route, so traffic falls back to the tunnel after about 15 seconds. Thunderbolt has no
  wake-on-LAN, so a sleeping Mac stays asleep. The cable carries Pod traffic again only after the
  peer answers the probe and the control plane reports the link up.
- **In a cluster with only the cable**, unplugging it leaves the two Macs with no path at all. The
  worker's node goes `NotReady` after the 40 second node grace period, and its Pods are evicted
  after the default 300 second toleration, as for any node that loses its network. Plug the cable
  back in and the node reconverges by itself: the routes come back, the endpoint is re-advertised,
  and the node turns `Ready`.
- **Moving the cable to another port** is an unplug followed by a plug: the new port is taken out of
  the bridge, addressed, and published, and the old one stays configured until `k3sm link reset`.

## The `k3sm doctor` section

`k3sm doctor` has a direct-link section: each port with its speed and the peer at the other end
(including a cabled Mac that is not in the cluster, with the pairing command), whether a cabled port
is still in `bridge0`, whether RDMA is available, the time of the last link transition, and three
settings for Macs that run as a cluster: idle sleep off (`sudo pmset -a sleep 0`), automatic login,
and starting after a power failure (`sudo pmset -a autorestart 1`). These are advisories; none of
them fails `doctor`.

## Sharded models

An `MLXModel` with `spec.distributed` shards one model across several Macs, one rank per Mac, behind
one endpoint:

```yaml
apiVersion: mlx.k3sm.io/v1alpha1
kind: MLXModel
metadata:
  name: qwen3-sharded
spec:
  model: mlx-community/Qwen3-0.6B-4bit
  revision: 73e3e38d981303bc594367cd910ea6eb48349da8
  memory: 4Gi
  port: 8000
  runtime:
    image: ghcr.io/k3sm-io/mlx-serve:0.4.1
  cache:
    size: 5Gi
    storageClassName: local-path
  distributed:
    ranks: 2
    backend: ring        # auto | ring | jaccl
    parallelism: tensor  # tensor | pipeline
```

Placement reads the `DirectLink` status, never the labels. The `ring` backend prefers Macs joined by
cables in a cycle and runs over any path; `jaccl` needs an RDMA-capable cable between every pair of
ranks; `auto` picks `jaccl` when such a set of Macs exists and `ring` otherwise. A model that cannot
be placed says why in its `ShardsPlaced` condition, and it never falls back to one Mac. A sharded
model is one replica spanning several Macs, so losing any one rank restarts all of them. See the
[MLX quickstart](mlx-quickstart.md) for the single-Mac path and the serving image.

## Thunderbolt 5 and RDMA

RDMA over Thunderbolt needs Thunderbolt 5 on both Macs and macOS 26.2 or later, and it is enabled
once per Mac in macOS Recovery (`rdma_ctl enable` in the Recovery Terminal, then restart). Nothing
can enable it from a running system, and k3sm never tries; `k3sm doctor` prints the step. A
Thunderbolt 4 Mac carries IP over the cable but no RDMA, so the `jaccl` backend is not available
there. k3sm publishes no RDMA figure it has not measured itself.

## Mixed versions and rolling back

During a rolling upgrade some Macs run a release with direct links and some do not. Upgrade the
control plane first: it serves the pairing verb, the publish verb and the resolver.

- A node on the older release keeps using the wireguard tunnel and publishes no `DirectLink`. A new
  node routes over the cable only toward a peer whose port is `up`, which an older peer can never
  reach, so the two use the tunnel between them.
- A new worker against an older control plane logs once that the control plane is too old for direct
  links and runs over the tunnel until the control plane is upgraded.
- A node on the older release that holds a wireguard endpoint in a cable-only cluster tries the
  cable address and gets no answer; the failed handshakes are harmless.
- A node whose network helper predates direct links logs once and runs over the tunnel.

To roll back, release the host state before you install the older binary, because the older binary
has no code to remove a cable address or route:

```sh
sudo k3sm link tunnel-only --all
sudo launchctl bootout system/io.k3sm.agent   # or io.k3sm.server on the control plane
sudo k3sm link reset
```

`k3sm link reset` removes every Thunderbolt port's address and routes and puts the port back into
`bridge0`. A node that is still running configures its cabled ports again within seconds, which is
why the daemon is stopped first. `sudo k3sm uninstall` runs the same release. A restart also clears
everything. `kubectl delete directlinks --all` removes the objects, which nothing older reads.

## Next

- [Multi-node](multi-node.md) covers joining over the LAN with a token.
- [Limitations](limitations.md) lists the gaps, including the plaintext cable.
- [Troubleshooting](troubleshooting.md#pairing-over-a-cable-does-not-start) covers a pairing that
  does not start and a link that flaps.
