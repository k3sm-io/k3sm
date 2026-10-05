# S3 findings — link-local after member removal (M17.0)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m17/s3.sh`. The zone value
> recorded here is the golden `TestPairTrustDecision` fakes and the real-socket zone
> test asserts.

## Question

Once a Thunderbolt port leaves `bridge0`, does it get a usable `fe80::%enX` (and how
long does DAD take), does `ff02::1` multicast cross the cable, and does a TLS dial over
a zoned `fe80` literal work, with `net/http` reporting the interface name as the
accepted connection's zone?

## Method

A privileged script with the restore trap removes each port from `bridge0` and polls
`ifconfig` for a non-tentative `fe80` address. The probe's `mcast-listen` /
`mcast-send` (`ff02::1`, both directions) and `zone-serve` / `zone-dial` (`net/http`,
`crypto/tls` 1.3, an in-memory self-signed certificate verified by pin) run as the
login user on each Mac.

## Halt (binding, substitution pre-decided)

Any criterion fails (`fe80` unusable on a removed member) → **R8: the beacon rides
`bridge0` on the unjoined Mac only and the server keeps its ports removed.** Build
amendment A1 already made the joiner side of that the design; this rung records
whether the server side holds.

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s3.1 server: non-tentative `fe80` within 30 s of `deletem` (DAD delay) | | |
| s3.1 worker: non-tentative `fe80` within 30 s of `deletem` (DAD delay) | | |
| s3.2 `ff02::1` server → worker, zone = the worker's cable port | | |
| s3.2 `ff02::1` worker → server, zone = the server's cable port | | |
| s3.3 TLS 1.3 dial over `fe80::…%enX`, local zone = interface name | | |
| rig: both nodes Ready after the rung | | |

## The golden

| value | recorded |
|---|---|
| local zone `net/http` reports for the accepted connection (worker) | |
| remote zone (worker) | |
| dialer's local zone (server) | |

## Consequences recorded here

- The zone string the pairing trust decision reads, verbatim.
- The DAD delay the beacon waits out after member removal.
