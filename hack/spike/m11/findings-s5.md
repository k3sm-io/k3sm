# S5 findings — guest networking

> Status: **ALL SEVEN criteria RECORDED.** Criteria **1a, 1b, 2, 4, 5, 6, 7**
> come from the 2026-08-31 no-root sitting, run by `s5-run.sh` on the same rig
> as S1 (two runs; the first lacked the criterion-4 liveness controls, so the
> second is the run of record). Criterion **1's real lo0-alias VIP legs
> (arrangements a–d)** and criterion **3** (PodIP-as-guest-eth0-alias + a host
> route) come from a SEPARATE 2026-08-31 root sitting, run by `s5-root.sh` on
> the same rig — the root-needing human slice this file previously carried at
> the bottom as NOT RUN.
>
> This file is a DECISION TABLE, not a report. Every row carries the observed
> value AND the pre-named consequence that value selects (the branch wording is
> `s5.sh`'s). Every `S5_*=`/`S5ROOT_*=` line quoted below appears verbatim in
> the corresponding run's captured console.

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
| **1 (VIP-a)** | the real lo0-alias VIP, **no guest route, host forwarding OFF, no host route** — the baseline arrangement | **delivers, both TCP and UDP/53**, guest's own vmnet source observed at the VIP-bound listener | the baseline alone answers criterion 1 YES. See "Criterion 1 — the real lo0-alias VIP legs" below |
| **1 (VIP-b)** | + guest-side route for the service CIDR via the NAT gateway | **delivers, both TCP and UDP/53** | consistent with (a); adds nothing (a) did not already give |
| **1 (VIP-c)** | + host `net.inet.ip.forwarding=1` | **delivers, both TCP and UDP/53** | consistent with (a); adds nothing (a) did not already give |
| **1 (VIP-d)** | + an explicit host route for the VIP on lo0 | **delivers, both TCP and UDP/53** | consistent with (a); adds nothing (a) did not already give |
| **4** | guest ↔ guest | **NOT reachable, in either protocol** — ICMP 100% loss, TCP unreachable, ARP FAILED — while both guests were proven live to the host | the trust ceiling is **narrower than M11.3-d4 assumed**: on this rig two vm pods on the same NAT segment cannot address each other directly. See the caveat below before this is published |
| **5** | lease stability under a deterministic MAC | **stable**: `192.168.64.5` on all 3 restarts of the same MAC; a control MAC got a different address (`192.168.64.6`) | the deterministic-MAC lease is semi-stable enough for B113b's address→pod registry, **provided** the lease-change liveness contract is still implemented — stability observed over 3 restarts is not a guarantee |
| **7** | guest link MTU | **1500** | above the ≤1380 the mesh mss-clamp reasoning assumes. If cross-node vm traffic is ever claimed, the DHCP/init plan must set the guest MTU down — the link will not do it |
| **3** | PodIP-as-guest-eth0-alias + a host route | **delivers** — host dials the PodIP and the guest receives the exact payload | the PodIP-as-alias model, if adopted, needs a narrow privileged **host-route** verb (the B232 shape) for THIS leg only — the VIP-delivery legs above need no privileged surface at all |

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

**Consequence, as recorded here.** At the time this no-root sitting ran, `s5.sh`'s
branch "(b) alone suffices ⇒ ZERO new privileged surface, the route set becomes
data on `podnet.GuestNetwork`" could not yet be selected — the leg that would
confirm it (a VIP on host lo0 receiving those packets) needed root. What was
established here (the guest-side route is free, and the loopback-bind result
above raised the expectation that the host half would need help) is now
**superseded by the root sitting below**: even (b)'s guest route turns out to be
unnecessary — see "Criterion 1 — the real lo0-alias VIP legs" next.

## Criterion 1 — the real lo0-alias VIP legs (arrangements a–d) · verbatim

Run by `s5-root.sh` in a separate, root-needing sitting on the same rig — the
human slice this file previously carried as NOT RUN. lo0 carried the alias
`10.43.0.10/32`; a listener bound the VIP itself (not the wildcard, so the
question of what XNU does with the destination address is answered, not begged)
for both TCP `34901` and UDP `53`; four arrangements varied the guest route,
host `net.inet.ip.forwarding`, and an explicit host route for the VIP:

```
S5ROOT_FWD_PRIOR=1
S5ROOT_UNPRIV_ALIAS_RECHECK=ifconfig: ioctl (SIOCAIFADDR): permission denied
S5ROOT_LO0_ALIAS=	inet 10.43.0.10 netmask 0xffffffff
```

The unprivileged-alias recheck reconfirms the same negative `findings-s5.md`
already recorded from the no-root sitting: an ordinary process cannot plumb the
VIP itself, so the alias in this sitting was plumbed by `s5-root.sh` running as
root, not by the guest or an unprivileged helper.

```
S5ROOT_a_FWD=0
S5ROOT_a_HOSTROUTE=absent
S5ROOT_GUEST_ADDR=192.168.64.9
S5ROOT_a_ROUTEADD=not-added (baseline: default route only)
S5ROOT_a_TCP=connected dst=10.43.0.10:34901 elapsed_s=0 tx_packets_delta=6
S5ROOT_a_UDP=sent dst=10.43.0.10:53 err=  tx_packets_delta=1
S5_HOST_VIPa_TCPBIND=ok addr=10.43.0.10:34901
S5_HOST_VIPa_UDPBIND=ok addr=10.43.0.10:53
S5_HOST_VIPa_TCP_FROM=192.168.64.9:35355 payload=vip-tcp-from-192.168.64.9-a
S5_HOST_VIPa_UDP_FROM=192.168.64.9:49988 payload=vip-udp-from-192.168.64.9-a
S5_HOST_VIPa_DONE=yes

S5ROOT_b_FWD=0
S5ROOT_b_HOSTROUTE=absent
S5ROOT_GUEST_ADDR=192.168.64.10
S5ROOT_b_ROUTEADD=ok cidr=10.43.0.0/16 via=192.168.64.1
S5ROOT_b_TCP=connected dst=10.43.0.10:34901 elapsed_s=0 tx_packets_delta=6
S5ROOT_b_UDP=sent dst=10.43.0.10:53 err=  tx_packets_delta=1
S5_HOST_VIPb_TCP_FROM=192.168.64.10:37261 payload=vip-tcp-from-192.168.64.10-b
S5_HOST_VIPb_UDP_FROM=192.168.64.10:34913 payload=vip-udp-from-192.168.64.10-b
S5_HOST_VIPb_DONE=yes

S5ROOT_c_FWD=1
S5ROOT_c_HOSTROUTE=absent
S5ROOT_GUEST_ADDR=192.168.64.11
S5ROOT_c_ROUTEADD=ok cidr=10.43.0.0/16 via=192.168.64.1
S5ROOT_c_TCP=connected dst=10.43.0.10:34901 elapsed_s=0 tx_packets_delta=6
S5ROOT_c_UDP=sent dst=10.43.0.10:53 err=  tx_packets_delta=1
S5_HOST_VIPc_TCP_FROM=192.168.64.11:34901 payload=vip-tcp-from-192.168.64.11-c
S5_HOST_VIPc_UDP_FROM=192.168.64.11:37429 payload=vip-udp-from-192.168.64.11-c
S5_HOST_VIPc_DONE=yes

S5ROOT_d_FWD=1
S5ROOT_d_HOSTROUTE=added (10.43.0.10 -> lo0)
S5ROOT_GUEST_ADDR=192.168.64.12
S5ROOT_d_ROUTEADD=ok cidr=10.43.0.0/16 via=192.168.64.1
S5ROOT_d_TCP=connected dst=10.43.0.10:34901 elapsed_s=0 tx_packets_delta=6
S5ROOT_d_UDP=sent dst=10.43.0.10:53 err=  tx_packets_delta=1
S5_HOST_VIPd_TCP_FROM=192.168.64.12:43737 payload=vip-tcp-from-192.168.64.12-d
S5_HOST_VIPd_UDP_FROM=192.168.64.12:58930 payload=vip-udp-from-192.168.64.12-d
S5_HOST_VIPd_DONE=yes
```

All four arrangements delivered BOTH TCP and UDP/53 to the lo0-alias VIP, and
in every case the host-bound listener observed the **guest's own vmnet source
address** (`192.168.64.9`–`.12`, one per arrangement's successive DHCP lease),
not a rewritten one — consistent with criterion 6's finding from the no-root
sitting.

**Consequence — BETTER than the runbook's best case.** `s5.sh` names "(b)
alone suffices ⇒ ZERO new privileged surface, the route set becomes data on
`podnet.GuestNetwork`, applied by the guest's own route plan" as its best
pre-named branch. The observation here is that **even (b) is unnecessary**:
arrangement (a) — no guest route, host forwarding forced to 0, no host route —
**already delivers**, on both protocols. So VIP delivery needs NO route data
pushed into `podnet.GuestNetwork`, NO netd route verb (B232), NO host
`ip.forwarding=1`, and NO host route for the VIP. The guest's ordinary default
NAT route is sufficient on its own; XNU weak-host-delivers the packet to the
lo0 alias without any of the three widenings the runbook staged as fallbacks.

## Criterion 3 — PodIP-as-guest-eth0-alias + a host route · verbatim

Also run by `s5-root.sh` in the same root sitting. The guest carried the PodIP
`100.64.0.99/32` as a second address on `eth0`, alongside its ordinary vmnet
lease; the host then added an explicit host route to that PodIP via the
guest's vmnet address, and dialed it:

```
S5ROOT_C3_GUEST_VMNET=192.168.64.13
S5ROOT_C3_HOSTROUTE=added (100.64.0.99 via 192.168.64.13)
S5ROOT_C3_ROUTE_GET=   route to: 100.64.0.99|destination: 100.64.0.99|    gateway: 192.168.64.13|  interface: bridge100|      flags: <UP,GATEWAY,HOST,DONE,STATIC>| recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire|       0         0         0         0         0         0      1500         0 |
S5_HOST_DIAL_C3PODIP=ok target=100.64.0.99:34911 local=192.168.64.1:55699
S5_HOST_DIAL_C3PODIP_WRITE=ok payload=host-to-podip-hello
S5ROOT_GUEST_ADDR=192.168.64.13
S5ROOT_C3_ALIAS=ok podip=100.64.0.99 dev=eth0
S5ROOT_C3_ADDRS=2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000|    inet 192.168.64.13/24 scope global eth0|       valid_lft forever preferred_lft forever|    inet 100.64.0.99/32 scope global eth0|       valid_lft forever preferred_lft forever|
S5ROOT_C3_LISTENING=port=34911 podip=100.64.0.99 vmnet=192.168.64.13
S5ROOT_C3_GUEST_RX=host-to-podip-hello
```

The guest received the exact payload (`host-to-podip-hello`), so this is a
completed round trip via the PodIP alias, not a bare `connect()` success.

**Consequence — the design nuance, not a decision.** Criterion 1 above needs no
privileged surface at all for VIP delivery. Criterion 3 is different: it
DELIVERS, but only because the host side carries a host route
(`route add -host 100.64.0.99 192.168.64.13`), and `route -n add` is a
root-only operation (§RUN — the root-needing human slice below, and the
no-root sitting's `SIOCAIFADDR: permission denied` reconfirmed the same class
of negative for the alias case). So **the privileged plumbing need did not
disappear — it moved**:
if the PodIP-as-guest-eth0-alias identity model is adopted for the vm path, a
narrow privileged route verb (the B232 shape named in `s5.sh` — per-pod,
idempotent, revoked at teardown, uid-gated like every existing netd verb) is
needed for **this** leg, not for ordinary VIP/Service delivery. Which identity
model to adopt is not decided here; this file records the dependency only.

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

## RUN — the root-needing human slice (2026-08-31 root sitting)

This section previously recorded these legs as NOT RUN, needing root. A
separate root sitting, run by `s5-root.sh` on the same rig, has since run every
leg but one — see "Criterion 1 — the real lo0-alias VIP legs" and
"Criterion 3" above for the recorded values.

| leg | status |
|---|---|
| criterion 1, arrangements (a)–(d) against a **real lo0-alias VIP** | **RUN** — see Criterion 1 above. `s5-root.sh` plumbed `10.43.0.10/32` on lo0 as root; the unprivileged recheck reconfirmed `SIOCAIFADDR: permission denied` first |
| criterion 1, arrangement (c) host ip-forwarding | **RUN** — see Criterion 1 above (`S5ROOT_c_FWD=1`) |
| criterion 1, arrangement (d) explicit host route | **RUN** — see Criterion 1 above (`S5ROOT_d_HOSTROUTE=added (10.43.0.10 -> lo0)`) |
| criterion 3, PodIP-as-guest-eth0-alias + host route | **RUN** — see Criterion 3 above |
| guest → LAN reachability | **still NOT RUN** — deliberately not probed: it sends traffic onto the operator's physical network, which the spike guardrails do not cover, and `s5-root.sh` did not attempt it either |

**Rig facts from the root sitting.** The four VIP arrangements plus criterion 3
booted five successive guests on one NAT segment; each took the next sequential
DHCP lease — `192.168.64.9`, `.10`, `.11`, `.12`, `.13` — matching the no-root
sitting's finding that leases are sequential per boot on this rig. Guest link
MTU was unchanged from the no-root sitting's criterion-7 finding (`1500`,
confirmed again incidentally by `S5ROOT_C3_ROUTE_GET`'s `mtu 1500` field on the
PodIP host route).

**Exit-path restoration, quoted verbatim.** Every host-state mutation this
sitting made was reversed on exit, and the sitting's own reads prove it:

```
S5ROOT_RESTORE_LO0_ALIAS=removed (10.43.0.10 is no longer on lo0, verified)
S5ROOT_RESTORE_ROUTE_VIP=deleted host route for 10.43.0.10 (present after delete: 0)
S5ROOT_RESTORE_ROUTE_PODIP=deleted host route for 100.64.0.99 (present after delete: 0)
S5ROOT_RESTORE_FWD=restored to 1 (read back: 1)
S5ROOT_RESTORE_PROCESSES=vznet/s5host reaped
```

`S5ROOT_RESTORE_FWD=restored to 1` matches `S5ROOT_FWD_PRIOR=1` read at the
start of the sitting — the forwarding sysctl the arrangements toggled to `0`
and `1` in turn was returned to the value read before the first write, exactly
as the sitting's own pre-run plan promised.

## Deviations from the guardrails in lib.sh

1. **The Alpine tree ships in the initramfs, not over virtiofs** — forced by
   the throwaway kernel's module-built virtiofs. Flagged above with the
   evidence; the share is still attached so the finding is observed rather
   than assumed.
2. **No permanent allow-set, privilege, or system-state widening was
   adopted.** The root-needing legs above WERE run — under root, in one
   dedicated sitting (`s5-root.sh`), with every mutation restored on exit and
   the restoration verified (see the RESTORE lines above) — never left as a
   standing widening of what an unprivileged k3sm process may do.
