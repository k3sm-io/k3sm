# S2 findings — addressing, routing and the R15 figures (M17.0)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m17/s2.sh`. Every figure
> lands as one JSON line in `$K3SM_EVIDENCE/figures.jsonl` (path, metric, unit, the
> exact command, the cable, every value); the tables below carry the medians and p99s.
> Name the Macs by role, model and macOS build only; a LAN address is recorded as
> `<worker-lan>`, never as a number.

## Question

Does the direct-link data path of the M17 plan §1 work on macOS (bridge member
removal, a /32 link alias with an on-link host route, two /25 gateway routes sourced
from the mesh-egress address, weak-host delivery to a lo0 alias), and what do the
direct, wireguard-over-cable and Wi-Fi paths measure?

## Method

Privileged script files with the restore trap configure both Macs as the network
helper would (`ifconfig bridge0 deletem`, the /32 alias, `route add -host <peer>
-interface <enX>`, `-tso -lro`, then `route add -net <half> <peer link> -ifa <mesh
egress>` for both halves). A pod-range lo0 alias (`.250` of the worker's pod /24)
carries a listener that reports each connection's local and peer address. The figures
run iperf3 at MSS 1340 (R15's one clamp) against that alias over the mesh first
(Wi-Fi; wireguard-over-cable when `K3SM_M17_WG_CABLE_ROUTE=1`), then over the /25s
(direct), then through a selector-less ClusterIP Service; ≥ 5 runs each.

## Halt (binding, substitutions pre-decided)

| criterion | on failure |
|---|---|
| s2.4 weak-host delivery | R8: the direct route is route-only via the on-link peer address, with the peer's /25s re-pointed through a second host route (never an on-link /24 alias on `enX`) |
| s2.3b `RTAX_IFA` honoured | R8: the proxy and the shim pin the `.1` source for all cross-node dials, and unbound host dials are documented as cable-only |
| s2.1 / s2.2 / s2.3 / s2.6 / s2.7 / s2.8 | no substitution is pre-decided: the §1 addressing does not hold as written |

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s2.1 not a `bridge0` member after `deletem` (both Macs) | | |
| s2.2 the peer link address ARP-resolves on the cable (both ways) | | |
| s2.3 the /25s are installed and chosen | | |
| s2.3b an unbound dial is sourced from the mesh-egress address | | |
| s2.4 a lo0-alias destination arriving on `enX` is delivered | | |
| s2.5 the reply comes from the lo0-alias address | | |
| s2.6 a dial bound to a reserved-half address connects as `_k3sm` | | |
| s2.7 TSO4, TSO6 and LRO off after `-tso -lro` | | |
| s2.8 the alias survives the rung | | |
| s2.9 (R3) a pod-range source over the cable is accepted (recorded) | | |
| rig: both nodes Ready after the rung | | |

## Figures (R15)

Medians / p99 over ≥ 5 runs. Each row's exact command is in `figures.jsonl`.

| path | TCP 1-stream → | TCP 1-stream ← | TCP 4-stream → | TCP 4-stream ← | RTT idle | RTT loaded | UDP loss 1472 | UDP loss 1473 |
|---|---|---|---|---|---|---|---|---|
| direct (/25s on the cable) | | | | | | | | |
| wireguard over the cable | | | | | | | | |
| Wi-Fi (the mesh on the LAN) | | | | | | | | |
| LAN, raw (reference) | | | | | | | — | — |
| ClusterIP → pod IP (direct) | | | | | | | — | — |

| path | `k3sm-netd` CPU% | k3sm daemon (proxy) CPU% | wireguard CPU% | fragment counters (`netstat -s`) | `enX` errors (`netstat -I`) |
|---|---|---|---|---|---|
| direct | | | | | |
| wireguard over the cable | | | | | |
| Wi-Fi | | | | | |

## Rig

| | server | worker |
|---|---|---|
| model (`hw.model`, chip, memory) | | |
| macOS (version, build) | | |
| cable port (`Thunderbolt N`, `enX`, link speed) | | |
| cable (as described by the operator) | | |

## Consequences recorded here

- Whether the direct route shape of §1 stands or R8's route-only shape replaces it.
- Whether the mesh-egress source rides the /25s, or the proxy and shim pin it.
- The figures any page may quote (R15): a direct-route gain below the
  wireguard-over-cable figure is published as such.
- R3's recorded question: whether a pf filter on the cable is warranted.
