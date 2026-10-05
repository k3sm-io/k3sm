# S4 findings — sleep, unplug and replug under a bulk flow (M17.0)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m17/s4.sh`. The fallback
> figures are in `$K3SM_EVIDENCE/figures.jsonl`; the per-event observer logs (link
> state, `bridge0` membership and the /25 count every 0.5 s) are in `$K3SM_EVIDENCE/s4/`.

## Question

When the cable goes (administratively, physically, or because the peer stops
answering), what does the kernel do to the direct routes, how long until a bulk
flow's traffic rides the tunnel, how often does configd re-add the bridge member, and
does repeated flipping ever fault the kernel?

## Method

Both Macs configured as the network helper would, a pod-range lo0 alias on the worker,
and a bulk iperf3 flow to it from the server at MSS 1340. Per event, an observer on
each Mac samples link state, `bridge0` membership and the /25 count every 0.5 s while
the server pings the alias every 0.1 s (`--apple-time`; the largest reply gap is the
fallback latency). ≥ 10 administrative flips of the worker's port, then ≥ 10 prompted
physical unplug/replug cycles; a pf anchor that drops the worker's cable traffic for
30 s (a silent peer, link up); a real worker sleep with a scheduled wake when
`K3SM_M17_ALLOW_SLEEP=1`; wireguard re-programming time when
`K3SM_M17_WG_CABLE_ROUTE=1`.

## Halt (binding, substitutions pre-decided)

| criterion | on failure |
|---|---|
| s4.3 configd re-adds faster than the watcher | R8: the watcher removes on every network-change event, and the doc says the bridge is managed |
| s1.5 failed (PF_ROUTE silent) | R8: the fallback figure recorded here is the poll-only figure |
| s4.2 a kernel fault | no substitution is pre-decided: the spike stops and the panic report is attached; nothing ships over a path that faults the kernel |

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s4.1 the bulk flow (MSS 1340) survives every event | | |
| s4.2 no kernel fault on either Mac | | |
| s4.3 no `bridge0` re-add within 2 s of a link event | | |
| rig: both nodes Ready after the rung | | |

## Figures

| event | n | fallback median | fallback p99 | the kernel's reaction (routes, alias) |
|---|---|---|---|---|
| administrative flip | | | | |
| physical unplug | | | | |
| silent peer, link up (30 s) | — | | | |
| peer asleep, cable intact | — | | | |
| wireguard over the cable, link down | | | | |

| | count | latency after the link event |
|---|---|---|
| configd `bridge0` re-adds | | |

## Consequences recorded here

- Whether the kernel's own route deletion is the fallback (R14), or a route
  survives a dead link and the liveness probe (R13) is the only thing that withdraws it.
- The fallback figure the doc may quote, and the eviction timing beside it.
- Whether the watcher must re-remove on every network event (R8) or the
  reconcile-time re-confirmation (A2) is enough.
