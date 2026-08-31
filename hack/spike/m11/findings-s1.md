# S1 findings — minimal VZ Linux boot

> Status: criteria 1, 2, 3 and 6 RECORDED from the 2026-08-31 sitting (three
> runs; the first two exposed harness defects — see Deviations — and the third
> is the run of record). Criteria 4 and 5 are NOT YET RUN: 4 rides the S5
> sitting's network-capable guest, 5 needs the seatbelt harness leg. M11.0-d1
> does not flip done until both are recorded here.

## Rig

| | |
|---|---|
| host | the lab host (the lab Mac, run over the harness's ssh path) |
| macOS | 26.6.2 |
| hw.model | Apple silicon |
| date (UTC) | 2026-08-31 |
| kernel sha256 | 6f905cefaef1f76b2b420967b1f65dc1ea3621e68eecf6bdce164cf4132aa195 |
| kernel bytes | 59079048 (uncompressed arm64 Image, throwaway Ubuntu 24.04 cloud kernel) |
| initramfs bytes | 1573888 (the stub init only) |

## Criterion 1 — entitlement-only ad-hoc signing · **GO/NO-GO**

All three rows are required. The success row alone proves nothing about what is
load-bearing; the two failures are the evidence.

| binary | signature | expected | observed |
|---|---|---|---|
| `vzboot.unsigned` | none | fails to construct a VM | exit=137 (AMFI SIGKILL before any VZ call could report) |
| `vzboot.noent` | ad-hoc, **no** entitlement | fails to construct a VM | exit=1 — `VZErrorDomain Code=2: "The process doesn't have the "com.apple.security.virtualization" entitlement"` at stage=validate |
| `vzboot` | ad-hoc **+** `com.apple.security.virtualization` | boots | constructs, starts, guest init runs to completion |

`codesign -d --entitlements -` output (must show exactly the one entitlement,
never the code-running trio):

```
Executable=<lab prefix>/bin/vzboot   (path redacted; the identity line is the dict below)
[Dict]
	[Key] com.apple.security.virtualization
	[Value]
		[Bool] true
codesign --verify: OK
```

**Verdict:** GO — the entitlement-only ad-hoc dev path is proven sufficient
(row 3) AND necessary (row 2 names the entitlement as the missing piece; row 1
shows an unsigned binary never reaches VZ at all). A NO-GO here would have been
TERMINAL for M11 and fired the M11 plan's R19(b); it did not occur.

## Criterion 2 — console tokens · **GO/NO-GO**

Console transcript (head, run of record):

```
VZBOOT_CREATE_TO_START_NS=128093625
K3SM_S1_TOKEN=s1-1788195065
K3SM_S1_INIT_EXEC_NS=55251458
K3SM_S1_UPTIME=0.05 0.00
K3SM_S1_DONE
[    0.361407] reboot: Power down
```

**2a token observed:** PASS — the host-generated token round-tripped via the
kernel command line and appeared on the virtio console.

**2b gzip control** — `VZLinuxBootLoader` must REJECT a gzipped `Image`. This is
recorded here so B111's uncompressed-arm64 constraint is a fact rather than a
first-boot discovery.

```
gz exit=1
VZBOOT_FAIL stage=start err=Error Domain=VZErrorDomain Code=1
  Description="Internal Virtualization error. The virtual machine failed to start."
```

Note the asymmetry, worth carrying into B111: the missing entitlement fails at
config VALIDATE with a named cause; a gzipped Image fails at START with a
generic internal error. The artifact-verify path must not expect VZ to name a
bad kernel format.

**Verdict:** GO

## Criterion 3 — cold-boot latency · RECORDING

Two figures, because they answer different questions. A is the plan's named
figure; **B is what a user experiences as vm-pod restart cost** and is the one
`limitations.md` publishes.

| figure | min | median | p95 | max |
|---|---|---|---|---|
| A: kernel start → init exec | 50ms | 50ms | 60ms | 60ms |
| B: CreateVM → console token | 148ms | 165ms | 171ms | 172ms |

N=20. Raw: `out/latency.tsv` on the rig. Figure A is the guest's own
`/proc/uptime` at init exec (10ms resolution). Figure B is derived as
create→start (host clock, 98–122ms across runs) plus figure A; the token print
follows init exec by under a millisecond, so the derivation does not flatter it.
`VZBOOT_ELAPSED_NS` is NOT a latency figure — it includes the harness's fixed
8-second wait and must never be quoted as one.

> Review trigger, not a gate: a median B above ~10s should force a re-read of
> the `RestartContainer` → whole-pod-recreate claim in M11.2-d6, whose
> backoff-bounded-churn argument is latency-dependent. **At 165ms median the
> trigger does not fire, with two orders of magnitude of margin.**

## Criterion 4 — guest↔guest reachability · RECORDING (a SECURITY FACT)

Record verbatim. Do not summarise — this text becomes the network-trust ceiling
in `limitations.md` and `privilege-model.md`.

| from → to | TCP | ICMP | L2-adjacent or routed via gateway |
|---|---|---|---|
| guest A → guest B (vmnet addr) | NOT YET RUN | NOT YET RUN | NOT YET RUN |

**NOT YET RUN** — the stub init has no network userland; this matrix is
produced by the S5 sitting's network-capable guest on the same rig and mirrored
here verbatim when recorded.

## Criterion 5 — Seatbelt × VZ coexistence · decides Resolution 7

Mirror `pkg/sandbox/sbpl.go` `Generate()` rule-for-rule and in order, then
construct a VM in the same process. Also test `sandbox_init` **after** VM
creation — the ordering may be the whole answer.

One of three:

- [ ] works as-is
- [ ] fails with a specific denial (capture the denial log VERBATIM below)
- [ ] works only with a named minimal allow-set delta — report it as an
      **ADOPTED ALLOW-SET** block, never a silent widening

```
NOT YET RUN — the harness's vzboot has no seatbelt mode yet; the leg is being
added (sandbox_init via the same cgo build vz already forces).
```

**Consequence:** confined, or a documented residual. NOT terminal — the M11 plan's R22
admits either.

## Criterion 6 — Rosetta availability probe when UNENTITLED

This probe already ships in the product binary and is called eagerly once per
daemon lifetime, so a raise here is a startup crash on exactly the machines M11
targets.

| | |
|---|---|
| probe returned | `LinuxRosettaAvailabilityInstalled` |
| raised? | no — `VZBOOT_ROSETTA_PROBE_DID_NOT_RAISE`, exit=0, unentitled binary |

**Verdict:** PASS — and the rig fact that Rosetta for Linux is INSTALLED here is
recorded for the v0.1.x amd64 follow-on's lab planning.

## Deviations from the guardrails

Three harness defects were found and fixed across the first two runs; none
touches a criterion's meaning, and the fixes ride the same change as this file:

1. vzboot read `S1_TOKEN` from its environment but never placed it on the
   kernel command line, so no token could ever reach the guest.
2. The guest init read the token via `os.Getenv` — impossible for PID 1 across
   a VM boundary; it now parses `s1_token=` off `/proc/cmdline`.
3. Nothing mounted `/proc` in the guest (the initramfs is the init binary
   alone), which silently blanked both the token read and the criterion-3
   uptime figure behind an `if err == nil` guard. The init now mounts it first.

Runs 1 and 2 therefore reported criterion 2a FAIL while their own consoles
showed the guest booting, exec'ing init at ~54ms, and powering down cleanly —
a harness artifact, not a boot failure. Run 3 is the run of record.
