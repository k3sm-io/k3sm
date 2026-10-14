# Interconnects

An interconnect is a Thunderbolt cable between two Macs in the cluster, used as an extra network
beside the mesh. Control-plane traffic, Services, DNS and ordinary Pod traffic stay on the
wireguard mesh over your LAN. A Pod that asks for the interconnect gets a second address on the
cable, and traffic it sends to another interconnect address crosses the cable instead of the LAN.
The main use is the collective traffic between the ranks of a sharded [MLX model](mlx-quickstart.md).

The interconnect is alpha (`net.k3sm.io/v1alpha1`), and it is off until a cluster admin turns it
on.

## How It Works

macOS puts every Thunderbolt port into one bridge interface, `bridge0` (the Thunderbolt Bridge).
k3sm leaves the ports there and never changes `bridge0`'s members. It adds addresses to `bridge0`
from `169.254.0.0/24`. RFC 3927 reserves `169.254.0.0/24` and `169.254.255.0/24` from
self-assignment, so a k3sm address does not collide with the self-assigned `169.254.x.y` address
the bridge already carries.

- Every address is derived from the node's cluster index (the index of its Pod `/24`) and a slot:
  `169.254.0.(8 × index + slot + 1)`. Nothing is allocated.
- Slot 0 is the node's own address. It sits on `bridge0` with a `/24` netmask, which gives the
  kernel one connected route for the whole range. k3sm adds no other route.
- Slot 1 is reserved for the node's sharded MLX rank. Slots 2 to 7 are for other Pods, so a node
  holds at most six general interconnect Pods beside the MLX rank.
- Path selection is by destination address only. A packet crosses the cable when its destination
  is an interconnect address, and only then.
- Wireguard endpoints, the apiserver, Services, DNS and probes never use the cable.

Each node probes its peers' slot-0 addresses every 5 seconds and reports what it reaches on its own
Node object. The server turns those reports into the `Interconnect` object's status: which nodes
are members, which are up, and which form a segment (a group of Macs that reach each other over
cables). A node writes only annotations on its own Node, and never reads the `Interconnect` object.

## Requirements

- Two or more Macs in one cluster, joined by Thunderbolt cables, with their Thunderbolt ports in the
  Thunderbolt Bridge (the macOS default).
- The `k3sm-netd` root helper on every cabled node, which is what `sudo k3sm install` sets up.
  Only the helper adds or removes an interconnect address.
- A cluster index from 0 to 30 on every cabled node. The range holds 31 nodes. A node with a
  higher index is never a member: the `Interconnect` status names it with the reason
  `InterconnectIndexOutOfRange`, and `k3sm status` reports it. It does not fail the other nodes.

## Arming

The server creates the `Interconnect` named `thunderbolt` the first time a node reports a cable to
another Mac. It is created disarmed (`spec.enabled: false`), and no node or Pod gets an
interconnect address until a cluster admin arms it. Plugging a cable in never joins anything, and a
Mac on the cable that is not a cluster node is never a member.

Arm it on the control plane:

```sh
k3sm interconnect enable
```

or with `kubectl patch interconnect thunderbolt --type merge -p '{"spec":{"enabled":true}}'`.
Arming is your trust statement for every cabled segment. The status records it as `armedBy` and
`armedAt`, from the identity the apiserver authenticated. Once armed, any device on a cabled port
can reach and spoof interconnect addresses: every cabled Mac, whether or not it is a member, and
anything a Mac in the middle of a chain forwards.

- `k3sm interconnect disable` (or `spec.enabled: false`) disarms it. No new Pod attaches. A Pod
  that already holds an address keeps it until the Pod is deleted or restarted, and each node
  removes its own address once no Pod on it holds one.
- `spec.excludedNodes` keeps named nodes out, even when they are cabled.
- `spec.fallback` decides what happens to a Pod whose attach cannot be satisfied (see
  [Failure Behaviour](#failure-behaviour)). It defaults to `network`.

## Using It From a Pod

Opt a Pod in with an annotation naming the interconnect:

```yaml
metadata:
  annotations:
    k3sm.io/interconnects: thunderbolt
```

When the node is an armed member and has its address, the provider takes a free slot for the Pod,
asks the root helper for the address, and sets two variables in every container:

- `K3SM_INTERCONNECT_IP` is the Pod's interconnect address.
- `K3SM_INTERCONNECT_CIDRS` is the interconnect range, `169.254.0.0/24`.

The Pod's status gets the condition `k3sm.io/InterconnectAttached`: `True` with the medium as the
reason and the address as the message, or `False` with the reason the attach was refused.

A Pod is reached over the cable only on an explicit bind. A listener must bind
`$K3SM_INTERCONNECT_IP` to accept connections over the cable. For Pods, a wildcard bind
(`0.0.0.0`) stays on the Pod IP, the same as for every native Pod, so a Pod's ordinary listener is
not exposed on the cable by the annotation alone. Host processes are a different case: see
[Plaintext](#plaintext). An outgoing connection to an interconnect address that the Pod has
not bound uses the Pod's interconnect address as its source, so the peer can tell which Pod is
calling.

The provider refuses an attach, with the reason on the condition, when:

- the Pod runs in the `vm` RuntimeClass, or in `container-vm`, a planned RuntimeClass (one
  lightweight Linux VM per container) that no release includes yet (`InterconnectUnsupportedRuntime`);
- every slot on the node is taken (`InterconnectSlotsExhausted`);
- the Pod's namespace is not allowed (`InterconnectNamespaceNotAllowed`, see below);
- the node is not an armed member, or the root helper is missing or too old.

## Namespaces and Trust

The interconnect is for trusted tenancy, the same rule as sharded MLX serving. Nothing on the wire
checks that a packet from an interconnect address came from the Pod that owns it, and rank ports
are unauthenticated.

- `spec.allowedNamespaces` limits which namespaces may attach. Empty means every namespace.
- Slot 1, the MLX rank slot, goes only to a Pod whose controller `ownerReference` is an existing
  `MLXModel` with a matching UID. The provider checks it on the node.
- Who may use the cable is decided by the admin who arms it. Attaching a Pod grants nothing new in
  RBAC.

## Sharded MLX Models

A sharded `MLXModel` chooses its collective path with `spec.distributed.interconnect`:

| value | path |
|---|---|
| `auto` (default) | the cable when one segment holds enough up nodes with GPU capacity for every rank, else Pod IPs over the mesh |
| `thunderbolt` | the cable only. If no segment holds every rank's node, placement fails with `ShardsPlaced=False` and the reason `NoInterconnectSegment` |
| `network` | Pod IPs over the mesh |

On the cable, each rank binds its own slot-1 address, and the ranks find each other through those
addresses. The model's HTTP endpoint, its probes and its ClusterIP Service keep the Pod IP. The
`ShardsPlaced` condition names the path in use, and `LinksHealthy` reports the cable's health.

## Failure Behaviour

- A dead path is detected within about 20 seconds: three missed 5-second probes, then the server
  marks the member down. A sharded model's re-render starts within about 30 seconds.
- A member has to stay up for 60 seconds before it counts as up again, so a flapping cable does not
  flap the status.
- With `fallback: network`, a sharded model that loses the cable is restarted on Pod IPs over the
  mesh. It then stays off the cable for 5 minutes, and k3sm restarts a model because of the cable
  at most once in that window. A model already on the network is never restarted because the cable
  came back; the next restart for any other reason picks the cable up again.
- With `fallback: none`, the model is held on the cable and its status says why.
- For a Pod, `fallback: network` starts it without the interconnect address and records the
  condition `False` with the reason. `fallback: none` holds it in creation and reports the reason
  as an Event. On a node that is not an armed member the fallback cannot be known, so the Pod
  starts on the network with a Warning Event.
- Established connections other than MLX's on a pulled cable hang until their own timeouts. The
  interface stays up when a cable is pulled, so the kernel gives them no error.

## Cable Layouts

Chains and stars work: a Mac in the middle forwards between its ports. A loop (two cables between
the same two Macs, or a ring of three or more) is detected and its members are marked `loop` and not
used. Remove one cable. k3sm never turns on spanning tree.

## Checking It

- `k3sm status` on the control plane carries an `interconnect` row, for example
  `thunderbolt: 2 up, 1 segment, 3 pods attached (plaintext), armed by alice`. `k3sm status
  cluster` lists each attached Pod with its node and address, and `k3sm status -o json` carries
  the same facts in its `interconnect` block (see [Status JSON](status-json.md)).
- `k3sm doctor` on a cabled Mac adds rows starting with `ic-`: `bridge0` and its Thunderbolt
  members, the netd socket, this node's address and its `/24`, the peers and their round trip, the
  Pods on this node holding an interconnect address, cable loops, stray state, and Apple's three
  settings for Macs joined by Thunderbolt. Run it with `sudo` to read the root helper's records.
- `kubectl get interconnect thunderbolt -o yaml` shows the members, segments, conditions and
  `armedBy`.

`k3sm doctor` also reports three settings Apple recommends for Macs joined by Thunderbolt:

- Turn idle sleep off (`sudo pmset -a sleep 0`). Thunderbolt has no Wake-on-LAN, so a sleeping Mac
  drops off the interconnect until someone wakes it.
- Turn on automatic login (System Settings > Users & Groups), so a Mac that restarts does not wait
  at the login window. macOS does not offer it while FileVault is on.
- Start up after a power failure (`sudo pmset -a autorestart 1`), on Macs that offer it.

## Plaintext

Traffic on the cable is not encrypted. The interconnect carries opted-in Pod traffic in the clear
on a bridged segment, and only after an admin armed it. NetworkPolicy and the bind rules act at the
endpoints and do not cover interconnect addresses. k3sm loads no packet filter.

The cable carried the self-assigned `bridge0` address before k3sm, so a host process listening on a
wildcard address is reachable from the segment with or without k3sm. The output of
`k3sm interconnect enable`, the Event recorded when it is armed, and the `k3sm status` row all say
the traffic is plaintext.

## Removing It

- Disarm with `k3sm interconnect disable`, or exclude a node with `spec.excludedNodes`.
- `sudo k3sm uninstall` removes the interconnect addresses the root helper recorded, and the record
  itself. It removes an address only when it is this node's own derived address for its slot, with
  that slot's netmask, and only when the record is a root-owned file no one else can write;
  anything else is left in place with a warning. It never changes `bridge0`'s members.
- Restarting the Mac clears every interconnect address, and the cloned routes described below with
  them; until a restart those routes can stay. No restart is needed to stop using the interconnect.

After an address is removed, macOS can keep a cloned host route for it in the routing table that it
refuses to delete. It is harmless: `k3sm doctor` reports it as pre-existing state, and k3sm never
adds an address over one.
