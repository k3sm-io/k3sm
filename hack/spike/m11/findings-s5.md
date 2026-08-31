# S5 findings — guest networking

> Status: criteria **1a, 1b, 2, 4, 5, 6, 7 RECORDED** from the 2026-08-31
> sitting, run by `s5-run.sh` on the same rig as S1 (two runs; the first lacked
> the criterion-4 liveness controls, so the second is the run of record).
> Criterion **3** and the **lo0-alias VIP legs of criterion 1** are NOT RUN —
> they need root, and the root-needing work is named as a human slice at the
> bottom of this file rather than approximated.
>
> This file is a DECISION TABLE, not a report. Every row carries the observed
> value AND the pre-named consequence that value selects (the branch wording is
> `s5.sh`'s). Every `S5_*=` line quoted below appears verbatim in the run's
> captured console under the lab prefix's `out/` directory.

## Rig and guest

| | |
|---|---|
| host | MikoStudio (the lab Mac, over the harness's ssh path) |
| macOS | 26.6.2 · `hw.model` Mac13,2 · arm64 |
| date (UTC) | 2026-08-31 |
| host kernel for the guest | the S1 throwaway uncompressed arm64 `Image` (Ubuntu `6.8.0-138-generic`) |
| guest rootfs | `alpine-minirootfs-3.24.1-aarch64.tar.gz` |
| rootfs URL | `https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.1-aarch64.tar.gz` |
| rootfs sha256 | `f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259` — pinned in `s5-run.sh` and re-verified on every run |
| initramfs | 10633216 bytes (the Alpine tree + a static Go `/init` + the host-authored `/probe.sh`) |
| vmnet segment | `192.168.64.0/24`, gateway `192.168.64.1` (Apple's NAT default) |

## Decision table

| # | criterion | observed | consequence this selects |
|---|---|---|---|
| **6** | source address the host observes | **the guest's own vmnet IP** — `192.168.64.5`, on TCP and UDP, to both a wildcard-bound and a gateway-address-bound host listener | **per-pod attribution is a straight map; B113b is tractable and the lease→pod registry is buildable.** The gateway-rewrite branch is NOT taken, so B113a's fail-closed does not become the permanent answer |
| **2** | guest vmnet address host-dialable | **yes** — `192.168.64.5:34811` dialed and delivered from the host | the one path carrying readiness probes, port-forward and the Service-proxy backend dial exists; no netd verb needed for host→guest |
| **1a** | guest → host listener, no route added | **wildcard-bound: connected. Gateway-address-bound: connected. Loopback(127.0.0.1)-bound: refused** (TCP); UDP identical by host receipt | a guest reaches any host listener that binds the vmnet gateway address or the wildcard. It does **not** reach a loopback-only bind — which is exactly the shape a ClusterIP lo0 alias has, so this is the first evidence that the VIP leg is not free |
| **1b** | guest-side route for a service-CIDR prefix | `ip route add 10.43.0.0/16 via 192.168.64.1` **accepted**; the dial to `10.43.0.10:34807` got **no answer after 6s** with **`tx_packets_delta=6`** | packets for a service-CIDR prefix **do leave the guest** and are handed to the host as the next hop. Whether the host then weak-host-delivers them to a lo0-alias VIP is UNANSWERED here (no VIP could be plumbed unprivileged) — see the human slice |
| **4** | guest ↔ guest | **NOT reachable, in either protocol** — ICMP 100% loss, TCP unreachable, ARP FAILED — while both guests were proven live to the host | the trust ceiling is **narrower than M11.3-d4 assumed**: on this rig two vm pods on the same NAT segment cannot address each other directly. See the caveat below before this is published |
| **5** | lease stability under a deterministic MAC | **stable**: `192.168.64.5` on all 3 restarts of the same MAC; a control MAC got a different address (`192.168.64.6`) | the deterministic-MAC lease is semi-stable enough for B113b's address→pod registry, **provided** the lease-change liveness contract is still implemented — stability observed over 3 restarts is not a guarantee |
| **7** | guest link MTU | **1500** | above the ≤1380 the mesh mss-clamp reasoning assumes. If cross-node vm traffic is ever claimed, the DHCP/init plan must set the guest MTU down — the link will not do it |
| **3** | PodIP-as-guest-eth0-alias + host route | **NOT RUN** | needs a host route, which needs root. Human slice |

## Criterion 6 — the source address (THE deciding fact) · verbatim

Three host listeners, all unprivileged, all high ports, all reached at the same
destination address (the NAT gateway) from the guest:

```
S5_HOST_WILDCARD_TCPBIND=ok addr=[::]:34801
S5_HOST_WILDCARD_UDPBIND=ok addr=[::]:34802
S5_HOST_WILDCARD_TCP_FROM=192.168.64.5:39099 payload=tcp-from-192.168.64.5
S5_HOST_WILDCARD_UDP_FROM=192.168.64.5:60913 payload=udp-from-192.168.64.5
S5_HOST_GWBOUND_TCPBIND=ok addr=192.168.64.1:34803
S5_HOST_GWBOUND_UDPBIND=ok addr=192.168.64.1:34804
S5_HOST_GWBOUND_TCP_FROM=192.168.64.5:34609 payload=tcp-from-192.168.64.5
S5_HOST_GWBOUND_UDP_FROM=192.168.64.5:58355 payload=udp-from-192.168.64.5
```

The guest's leased address was `S5_C5_ADDR=192.168.64.5`, and the payload it
sent carries that address, so the accepted peer address and the sender agree.
**No source rewrite to the gateway occurs for guest→host traffic.**

Scope of the claim: this is the address an ordinary host socket observes for
traffic **from a guest to the host**. It says nothing about what a host outside
this Mac observes for guest→LAN traffic, which is separately NATted and is not
what B113 attributes.

## Criterion 2 — host → guest · verbatim

```
S5_C2_LISTENING=port=34811 addr=192.168.64.5
S5_HOST_DIAL_GUEST=ok target=192.168.64.5:34811 local=192.168.64.1:54344
S5_HOST_DIAL_GUEST_WRITE=ok payload=host-to-guest-hello
S5_C2_GUEST_RX=host-to-guest-hello
```

The guest received the exact payload, so this is a completed round trip and not
a bare `connect()` success. The host's local address on the dial is the gateway
address — worth carrying into the probe/port-forward design.

## Criterion 1a/1b — guest → host, the unprivileged arrangements · verbatim

```
S5_C1A_WILDCARD_TCP=connected dst=192.168.64.1:34801
S5_C1A_WILDCARD_UDP=sent dst=192.168.64.1:34802 err=
S5_C1A_GWBOUND_TCP=connected dst=192.168.64.1:34803
S5_C1A_GWBOUND_UDP=sent dst=192.168.64.1:34804 err=
S5_C1A_LOBOUND_TCP=refused-or-unreachable dst=192.168.64.1:34805
S5_C1A_LOBOUND_UDP=sent dst=192.168.64.1:34806 err=
S5_HOST_LOBOUND_TCPBIND=ok addr=127.0.0.1:34805
S5_HOST_LOBOUND_UDPBIND=ok addr=127.0.0.1:34806
```

The loopback-bound listener **bound successfully and received nothing** — no
TCP accept, no UDP datagram — while the wildcard and gateway-bound listeners on
the same host received both. For UDP the host receipt is the only authority
(the guest's `nc -u` cannot tell a delivered datagram from a dropped one), and
the host log is the evidence quoted above.

```
S5_C1B_ROUTEADD=ok cidr=10.43.0.0/16 via=192.168.64.1
S5_C1B_ROUTES=default via 192.168.64.1 dev eth0  metric 202 |10.43.0.0/16 via 192.168.64.1 dev eth0 |192.168.64.0/24 dev eth0 scope link  src 192.168.64.5 |
S5_C1B_VIP_TCP=no-answer dst=10.43.0.10:34807 elapsed_s=6 tx_packets_delta=6
```

`tx_packets_delta=6` with a 6-second no-answer is the SYN-retransmit signature:
the packets left `eth0` and nothing answered. The alternative outcome — an
immediate error with no transmit — would have meant the guest never emitted
them. So the guest half of arrangement (b) works unprivileged and needs no
new host surface; what is unresolved is only the host half.

**Consequence, stated conservatively.** `s5.sh`'s branch "(b) alone suffices ⇒
ZERO new privileged surface, the route set becomes data on
`podnet.GuestNetwork`" is **not yet selected** — it cannot be, because the leg
that would confirm it (a VIP on host lo0 receiving those packets) is the
root-needing one. What IS established: the guest-side route is free, and the
loopback-bind result above is a reason to expect the host half to need help.
The netd-route-verb branch stays live until the human slice runs.

## Criterion 4 — guest ↔ guest · RECORDING (a SECURITY FACT) · verbatim

Two guests, booted concurrently on one NAT segment, deterministic MACs.

```
S5_C4_PEER_CTL_GW_ICMP=reachable
S5_C4_PEER_CTL_HOST_TCP=connected
S5_C4_PEER_LISTENING=port=34812 addr=192.168.64.7
S5_C4_CTL_GW_ICMP=reachable
S5_C4_CTL_HOST_TCP=connected
S5_C4_ICMP_RAW=PING 192.168.64.7 (192.168.64.7): 56 data bytes||--- 192.168.64.7 ping statistics ---|3 packets transmitted, 0 packets received, 100% packet loss|
S5_C4_ICMP=unreachable
S5_C4_TCP=refused-or-unreachable dst=192.168.64.7:34812
S5_C4_NEIGH=192.168.64.7 dev eth0  used 0/0/0 probes 6 FAILED|192.168.64.1 dev eth0 lladdr 9e:76:0e:95:82:64 ref 1 used 0/0/0 probes 4 REACHABLE|fe80::9c76:eff:fe95:8264 dev eth0 lladdr 9e:76:0e:95:82:64 router used 0/0/0 probes 0 STALE|
S5_C4_ADJACENCY=NOT-adjacent (ARP attempted, no lladdr: 192.168.64.7 dev eth0  used 0/0/0 probes 6 FAILED|)
```

An INDEPENDENT witness, from the host's own listener during the same phase:

```
S5_HOST_WILDCARD_TCP_FROM=192.168.64.7:39435 payload=peer-alive-192.168.64.7
S5_HOST_WILDCARD_TCP_FROM=192.168.64.8:36871 payload=prober-alive-192.168.64.8
```

| from → to | TCP | ICMP | L2-adjacent or routed via gateway |
|---|---|---|---|
| guest A (`192.168.64.8`) → guest B (`192.168.64.7`) | **refused-or-unreachable** | **100% packet loss** | **neither** — ARP for the peer reached `FAILED` after 6 probes, while ARP for the gateway resolved to an lladdr in the same table |

**Why this is a controlled result and not a broken guest.** Both guests proved
themselves live at their advertised addresses before the matrix ran: each
reached the gateway by ICMP, and each opened a TCP connection to a host
listener that logged its source address — so `192.168.64.7` and
`192.168.64.8` are the addresses the host itself saw. The prober's ICMP and TCP
controls to the gateway both passed in the same boot in which its probes to the
peer failed, so "busybox ping does not work" and "this guest has no stack" are
both excluded.

**Consequence.** This is *narrower* than M11.3-d4 assumed. Its premise —
"guests share one vmnet NAT segment (guest↔guest at NAT addresses bypasses
Services/policy)" — is **not what this rig does**: guest↔guest is blocked, so
the bypass M11.3-d4 was written to document does not exist here, and the
pf-filter follow-on it offered as an alternative has nothing to filter.

**Caveat that must travel with this row, and must be discharged before it is
published as a ceiling.** One rig, one macOS version, one attachment type
(`VZNATNetworkDeviceAttachment`). Apple documents no isolation guarantee for
this attachment, so this is an OBSERVED BEHAVIOUR of macOS 26.6.2, not a
contract. A limitations.md claim of "vm pods are isolated from one another"
would be a security claim resting on undocumented behaviour that a point
release may change. The honest M11.3-d4 wording is therefore the negative one:
we do not rely on guest↔guest reachability, and we do not promise its absence.
A bridged or a `VZFileHandleNetworkDeviceAttachment` topology is a DIFFERENT
question and is untested here.

## Criterion 5 — lease stability under a deterministic MAC · verbatim

```
S5_C5_MAC_A=5a:c3:9b:1a:d2:7f
S5_C5_RUN1_ADDR=192.168.64.5
S5_C5_RUN2_ADDR=192.168.64.5
S5_C5_RUN3_ADDR=192.168.64.5
S5_C5_MAC_CONTROL=5a:c3:a8:78:52:b6
S5_C5_CONTROL_ADDR=192.168.64.6
```

Three full stop/start cycles under one locally-administered MAC derived from a
fixed string; the address did not move. The control MAC took a different
address in the same session, so the stability is MAC-derived and not "this
server hands out one address".

**Consequence.** B113b's address→pod registry is buildable. The observation does
NOT license dropping the lease-change liveness contract: three restarts inside
one session say nothing about a lease expiring, a reboot of the host, or
another guest taking the address after a long gap.

## Criterion 7 — guest link MTU · verbatim

```
S5_C7_MTU=1500
S5_C7_IPLINK=2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state DOWN qlen 1000|    link/ether 5a:c3:9b:1a:d2:7f brd ff:ff:ff:ff:ff:ff|
```

(The `NO-CARRIER`/`state DOWN` flags are busybox `ip`'s rendering; the link
carried DHCP, TCP and UDP in the same boot.)

**Consequence.** 1500, i.e. the link does NOT come up pre-clamped. M11.3-d4's
"guest link MTU ≤1380 if cross-node is ever claimed" is therefore an action for
the DHCP/init plan, not a property to inherit.

## Incidental finding — virtiofs is NOT mountable under this kernel

Every boot attached a read-only virtiofs share and attempted to mount it:

```
VZNET_SHARE=attached tag=s5share
S5_VIRTIOFS=unavailable err=no such device
```

The host device attaches fine; the guest cannot mount it, because the
throwaway Ubuntu `6.8.0-138-generic` kernel builds `virtio_fs` as a MODULE and
an initramfs holds no modules (`virtiofs` is absent from the guest's
`/proc/filesystems`). This is a fact about the throwaway kernel, not about
Apple's device.

**Consequence.** The pinned kernel artifact must build the virtiofs stack **in**
(`=y`, not `=m`) — or ship modules plus something to load them. Everything in
M11 that assumes a virtiofs rootfs or virtiofs volumes depends on it, and S3's
virtiofs measurements cannot even start on a kernel like this one.

**Deviation flagged, not adopted.** `s5-run.sh` was specified to serve the
Alpine tree to the guest over the virtiofs share. That is impossible on this
kernel, so the tree ships **inside the initramfs** instead and the share is kept
only as the probe that produced the finding above. No probe depends on the
share; nothing was widened to work around it.

## NOT RUN — the root-needing human slice

These are recorded as not run, with the reason. No value below is estimated,
inferred, or filled in from a weaker measurement.

| leg | why it did not run |
|---|---|
| criterion 1, arrangements (a)–(d) against a **real lo0-alias VIP** | plumbing a ClusterIP alias needs root: the unprivileged attempt fails with `SIOCAIFADDR: permission denied`. Without a VIP on the host there is nothing for XNU to weak-host-deliver to, so the question "does a guest packet reach a host lo0-alias VIP" is untouched by this sitting |
| criterion 1, arrangement (c) host ip-forwarding | `sysctl net.inet.ip.forwarding=1` is a root write to system state, and out of bounds for the spike guardrails |
| criterion 1, arrangement (d) explicit host route | `route -n add` needs root |
| criterion 3, PodIP-as-guest-eth0-alias + host route | the host route half needs root |
| guest → LAN reachability | deliberately not probed: it sends traffic onto the operator's physical network, which the spike guardrails do not cover |

The human slice is one sitting: with root, plumb `10.43.0.10/32` on lo0, re-run
the criterion-1 arrangements against it, and add the (c)/(d) rows. The harness
already emits every other input that sitting needs — the guest-side route is
proven free, the packets are proven to leave, and the source address is proven
un-rewritten.

## Deviations from the guardrails in lib.sh

1. **The Alpine tree ships in the initramfs, not over virtiofs** — forced by
   the throwaway kernel's module-built virtiofs. Flagged above with the
   evidence; the share is still attached so the finding is observed rather
   than assumed.
2. **No allow-set, privilege, or system-state widening was adopted.** Every
   root-needing leg is in the table above, unrun.
