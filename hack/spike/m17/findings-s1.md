# S1 findings — enumeration and mapping (M17.0)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m17/s1.sh`. The rung's
> transcript, raw command output and figures land in `$K3SM_EVIDENCE/s1/`; this file
> records the verdicts and what they mean for the design. Name the two Macs by role
> (server, worker), model and macOS build only, never by hostname.

## Question

Can each Mac find the cable, map it to its `Thunderbolt N` receptacle and `enX`
interface by the `networksetup` mapping (never by interface name), identify the peer
by domain UUID, keep that mapping across a reboot and a dock, and can an unprivileged
`PF_ROUTE` reader see the cable unplug?

## Method

Over ssh, unprivileged except the administrative flip and the reboot: darwin-net's
`linkenum` (the probe's `enum`) and the raw `system_profiler SPThunderboltDataType
-json` and `networksetup -listallhardwareports` output on both Macs; `/usr/bin/time`
over `system_profiler` ten times per Mac; the probe's `watch` (`linkwatch.RouteReader`,
`linkwatch.Poller` and a raw `PF_ROUTE` reader, as the login user) across an
`ifconfig down/up` control and then a prompted physical unplug; an optional worker
reboot (`K3SM_M17_ALLOW_REBOOT=1`); a prompted receptacle or dock move;
`ioreg -c IOThunderboltPort -r -l`.

## Halt (binding, substitutions pre-decided)

| criterion | on failure |
|---|---|
| s1.5 `PF_ROUTE` silent on unplug | R8: the 2 s poll is the only source and the fallback figure is re-measured (S4) |
| s1.1 `NoThunderboltService` | the design's `NoThunderboltService` condition stands; s1.9 says whether `ioreg` can substitute |
| s1.2 / s1.3 / s1.7 | no substitution is pre-decided: the M17 plan §1 mapping does not hold; the spike stops for a re-plan |

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s1.1 `linkenum` enumerates ≥ 1 port on each Mac | | |
| s1.2 one port pair whose peer domain UUIDs point at each other | | |
| s1.3 the cabled receptacle maps to an active `enX` on both Macs | | |
| s1.4 `system_profiler` wall / CPU, median and p99 of 10 (recorded) | | |
| s1.5 the unprivileged `RouteReader` delivers the unplug | | |
| s1.5 control: administrative down/up (recorded) | | |
| s1.6 destroyed or flagged on unplug (recorded) | | |
| s1.7 domain UUID and ordinal stable across a worker reboot | | |
| s1.8 receptacle / dock move (recorded) | | |
| s1.9 what `ioreg -c IOThunderboltPort` carries (recorded) | | |
| rig: both nodes Ready after the rung | | |

## Rig

| | server | worker |
|---|---|---|
| model (`hw.model`, chip) | | |
| macOS (version, build) | | |
| cable port (`Thunderbolt N`, `enX`, link speed) | | |
| cable (as described by the operator) | | |

## Consequences recorded here

- Whether `linkwatch`'s `PF_ROUTE` reader is a real latency optimisation on a
  Thunderbolt `enX`, or the poll carries the stream alone (R8).
- Whether a consumer must treat an unplug as a vanishing (`Gone`) or a flag flip,
  and whether the interface name survives a replug (state stays keyed by domain UUID
  either way).
- The `system_profiler` cost that sizes the 5-minute backstop and the
  on-change re-enumeration.
- Whether `ioreg` can stand in for a deleted Thunderbolt Bridge service, or the
  `NoThunderboltService` condition is final.
