# Audit findings — A1 adversarial pass

Run 2026-09-07 against `main` at `5d6e2a2`, on branch `audit/a1-hardening`.

Method: the house torture chamber — four report-only auditors (simplify · dedup ·
correctness+optimization · doc-drift) plus the `least-code` ladder, fanned out
concurrently; then an **independent skeptic per finding**, given only the claim and the
code, instructed to refute it and to default to REFUTED when uncertain. Nothing below was
acted on until a skeptic failed to kill it.

**Verdicts:** CONFIRMED (reproduced or irrefutable) · PLAUSIBLE (survives the argument,
unproven) · REFUTED (dropped — kept here with its reason, because a killed finding is a
result).

## Coverage bound — stated, not implied

56,635 non-test LOC over 210 files and 34 packages is more than one pass can audit at
full depth, so the fan-out was scoped by risk and **that scope is a ceiling on these
findings, not a statement about the rest of the tree**. Audited deeply: `pkg/executor`,
`pkg/provider`, `cmd/k3sm`, `pkg/install`, `pkg/oci`, `pkg/policy`, `pkg/netdsvc`,
`pkg/dev`, `pkg/certs`, `pkg/bootstrap`, `pkg/registrysvc`. Grep-level only:
`pkg/mlx`, `pkg/builder`, most of `pkg/registrysvc`, the `image`/`build` commands.
**Not audited at all:** the sibling modules `k3sm.io/{apis,runtimed,darwin-net}` — note
in particular that the OCI tar *extractor* lives in `runtimed` and was not examined,
while this pass fuzzed only the *writer* in `pkg/oci`.

## Baseline

`gofmt` clean · `go vet` clean · `go test -race ./...` green (32 packages, 0 races) ·
`staticcheck` 3 non-test findings · `deadcode -test` 8 unreachable funcs ·
**coverage 70.7%** · **0 benchmarks, 0 fuzz targets**.

## A note on the two withheld rows

Findings 1 and 5 are recorded here as withheld. Both are security findings whose fixes
are **not yet in `main`**, and `SECURITY.md` asks that vulnerabilities not be reported
through public channels — for a distribution shipping privileged components, a public
description of an unfixed issue is a disclosed 0-day. They were reported privately
through the maintainer channel, and their rows will be filled in when the fixes land.

The counts elsewhere in this document include them, so the arithmetic is honest: seven
findings were fixed in this pass, two of which are not described here.

## Fixed in this pass

| # | Finding | Verdict | Landed as |
|---|---|---|---|
| 1 | *Withheld — reported privately; see the note above* | CONFIRMED (reproduced) | *unreleased* |
| 2 | `dev up` hung forever against a wedged apiserver — the probes' own timeouts were unreachable | CONFIRMED (reproduced) | #339 |
| 3 | No supervision of control-plane children after bring-up (#331) | CONFIRMED (reproduced) | #336 |
| 4 | `GetPods` read `t.pod` outside `r.mu` | CONFIRMED (race detector) | #335 |
| 5 | *Withheld — reported privately; see the note above* | CONFIRMED (reproduced) | *unreleased* |
| 6 | Three doc claims the code does not support (hostPath, uninstall, CoreDNS) | CONFIRMED (hostPath reproduced live) | #338 |
| 7 | No fuzzing of the OCI trust boundary | gap | #337 |

Every behaviour-changing fix carries a regression test that was **verified to fail
against the unfixed code**. That check is not ceremony: it caught one test of mine that
passed under both the fixed and unfixed build, and would have pinned nothing.

## Scope corrections the skeptics forced

These matter more than the raw verdicts, because each one changed what got built.

- **#331's consequence was too broad.** "An operator cannot tell this from health" is
  false for the apiserver and kine — `Collector.apiserverRow` does a live `/readyz`, so
  both surface as DEGRADED. It is true, and *worse* than stated, for the **scheduler and
  controller-manager**: no status row, covered by no readyz. A dead scheduler shows up
  only as pods stuck Pending; a dead KCM never shows up at all. **Still open** — see
  `open-items.md`.
- **The `GetPods` damage claim was refuted.** The reported torn-Pod-via-`DeepCopyInto`
  mechanism is wrong; the pointee is genuinely immutable after publication. A real data
  race remains, plus an unsafe-publication hazard under arm64's weak ordering. Fixed on
  those grounds, not the dramatic one.
- **A reported reproduction was itself unsound.** One finding rested on an EPERM read as
  proof a syscall reached its target; EPERM is equally the result when the target is *not*
  reached. The finding survived on different, better evidence. (Details withheld — this is
  one of the two privately reported items.)
- **The first proposed fix for that finding was insufficient.** Details withheld for the
  same reason. The general lesson is the transferable part: a fix that addresses the
  reported symptom without addressing the mechanism is not a fix, and the skeptic pass is
  what surfaced the difference.
- **A validated fix design still had a bug.** The supervision seam as designed gated on
  `started`, which `Start` claims *before* bring-up — so a bring-up crash would cancel
  the boot context and destroy `awaitHealthy`'s log-tail diagnostic, on a coin flip.
  Shipped with a separate `supervising` flag; the test pins the distinction.

## REFUTED — recorded so they are not re-raised

| Finding | Why it died |
|---|---|
| `probe_test.go:273` SA4000 "identical expressions either side of `\|\|`" | False positive: `feed()` mutates via `m.observe()`, so the two calls are different state transitions. The test is correct. |
| Prober published before `pr.start` leaks a live prober | Mechanically real, but **unreachable**: VK's `internal/queue` serialises strictly per pod key, and k3sm adds no other `DeletePod` caller. 2 of 3 claimed consequences also fail independently (`killAndRestart` bails on an untracked pod; `wg.Add` after `wg.Wait` does not panic on Go 1.27). |
| `registrysvc` ensure-loops should reuse `pkg/policy`'s generic | `managedObject[T]` is **unexported**, and four further behavioural breakers (create-first vs get-first, label merge, `publishService` must return the live ClusterIP which `ensure` discards, `Selector = nil` is policy not spec). |
| Ten poll loops should become `wait.PollUntilContextTimeout` | REFUTED as stated: the exception count is wrong (`registrysvc.Service.await` has the same `exited`-channel contract as `awaitHealthy`), and all ten build bespoke last-state errors `DeadlineExceeded` cannot carry. |
| Temp-file leak on rename failure is severe | Leak is real and the count was *understated* (6 sites, not 3), but it is **inert**: readers only ever open the final path, the installer copies by name, `VerifyPayloadSet` is a fail-closed allowlist, and the next attempt truncates. No stale-temp consumption anywhere. |
| A privileged-directory escalation payload | REFUTED on the mechanism: launchd refuses a non-root-owned daemon plist, and the service user cannot produce a root-owned file merely by owning the directory. Path withheld — an adjacent area is under private review. |
| `dev.go` timeout affects six other `BuildConfigFromFlags` sites equally | Only where the context carries no deadline: `netd.go:272` is bounded at 10s and is refuted outright; others are partial. |

## Still open

See `open-items.md`. The largest are the scheduler/KCM observability gap, `pkg/loadbalancer`
(444 LOC, **zero importers**, 83.2% covered — well-tested unreachable code), and the
unbounded `<-c.exited` after SIGKILL in `stopComponent`, where `Supervised.Stop` takes a
context it never reads and can only return `nil`, making the caller's 30s shutdown budget
decorative and its error branch dead.
