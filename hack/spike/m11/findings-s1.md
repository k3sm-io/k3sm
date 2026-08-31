# S1 findings — minimal VZ Linux boot

> **NOT YET RUN.** This file is the template `hack/spike/m11/s1.sh` fills in. An
> empty verdict below is not a pass; M11.0-a1 requires this file committed with a
> recorded verdict per criterion before the M11.2 wave's live legs proceed.

## Rig

| | |
|---|---|
| host | |
| macOS | |
| hw.model | |
| date (UTC) | |
| kernel sha256 | |
| kernel bytes | |
| initramfs bytes | |

## Criterion 1 — entitlement-only ad-hoc signing · **GO/NO-GO**

All three rows are required. The success row alone proves nothing about what is
load-bearing; the two failures are the evidence.

| binary | signature | expected | observed |
|---|---|---|---|
| `vzboot.unsigned` | none | fails to construct a VM | |
| `vzboot.noent` | ad-hoc, **no** entitlement | fails to construct a VM | |
| `vzboot` | ad-hoc **+** `com.apple.security.virtualization` | boots | |

`codesign -d --entitlements -` output (must show exactly the one entitlement,
never the code-running trio):

```
```

**Verdict:** _(GO / NO-GO)_ — a NO-GO here is TERMINAL for M11 and fires
the M11 plan's R19(b): a dated resolution, the m9 ledger row removed, the announcement
reverted. Never an ad-hoc waiver.

## Criterion 2 — console tokens · **GO/NO-GO**

Console transcript (head):

```
```

**2a token observed:** _(PASS / FAIL)_

**2b gzip control** — `VZLinuxBootLoader` must REJECT a gzipped `Image`. This is
recorded here so B111's uncompressed-arm64 constraint is a fact rather than a
first-boot discovery.

```
```

**Verdict:** _(GO / NO-GO)_

## Criterion 3 — cold-boot latency · RECORDING

Two figures, because they answer different questions. A is the plan's named
figure; **B is what a user experiences as vm-pod restart cost** and is the one
`limitations.md` publishes.

| figure | min | median | p95 | max |
|---|---|---|---|---|
| A: kernel start → init exec | | | | |
| B: `CreateVM` → console token | | | | |

N=20. Raw: `out/latency.tsv`.

> Review trigger, not a gate: a median B above ~10s should force a re-read of
> the `RestartContainer` → whole-pod-recreate claim in M11.2-d6, whose
> backoff-bounded-churn argument is latency-dependent.

## Criterion 4 — guest↔guest reachability · RECORDING (a SECURITY FACT)

Record verbatim. Do not summarise — this text becomes the network-trust ceiling
in `limitations.md` and `privilege-model.md`.

| from → to | TCP | ICMP | L2-adjacent or routed via gateway |
|---|---|---|---|
| guest A → guest B (vmnet addr) | | | |

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
```

**Consequence:** confined, or a documented residual. NOT terminal — the M11 plan's R22
admits either.

## Criterion 6 — Rosetta availability probe when UNENTITLED

This probe already ships in the product binary and is called eagerly once per
daemon lifetime, so a raise here is a startup crash on exactly the machines M11
targets.

| | |
|---|---|
| probe returned | |
| raised? | |

**Verdict:** _(PASS / FAIL)_ — a FAIL HALTS the shipped label path: it is a bug
in already-merged code, and a fix item is filed before any further M11 work.

## Deviations from the guardrails

Anything done beyond a stated exit criterion, flagged rather than adopted:

_(none / …)_
