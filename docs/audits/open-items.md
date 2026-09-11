# Open items

Ranked by what it costs to be wrong about, not by effort. From the A1 pass of
2026-09-07 (`audit-findings.md`). Items already fixed are not repeated here.

| # | Item | Cost of being wrong | Verdict |
|---|---|---|---|
| 1 | **Scheduler and controller-manager have no health row.** Unlike the apiserver and kine, neither is covered by a `/readyz` probe or rendered by `pkg/status`. They now take the process down when they die (#336), but while merely *wedged* a dead scheduler surfaces only as pods stuck Pending, and a dead KCM not at all. | A cluster that schedules nothing, reported healthy | CONFIRMED |
| 2 | **`Supervised.Stop` ignores its context and cannot fail.** It takes `ctx context.Context`, never reads it, and returns `nil` unconditionally; `stopComponent` takes no context and, after SIGKILL, does an **unbounded `<-c.exited`**. So `server.go`'s 30s `shutCtx` is decorative and its `if err != nil` branch is dead code. `runtimed` already exports a bounded `GracefulStop`/`awaitExit` built for exactly this. | `k3sm server` never exits; `launchctl bootout`, upgrade and uninstall wedge | CONFIRMED |
| 3 | **`pkg/loadbalancer` — 444 LOC, zero importers, 83.2% covered.** Not merely dead: a security-audit HIGH fix landed +111 lines into a package with no caller. `docs/PHASES.md:348` records it as M6.1 with acceptance `met:false`, so this is a knowing gap with a paper trail. Wire it or unbuild it. | Maintaining, auditing and fixing code nothing runs | CONFIRMED |
| 4 | **`hostPath` is silently dropped rather than refused.** The doc now says so (#338), but the behaviour remains a footgun: admission ships PSA `enforce = privileged`, so the Pod is admitted with only a warning, and a declared-but-unmounted `hostPath` runs to completion with no error anywhere. `translate.go`'s own comment records this exact shape as what "made every StatefulSet with a volumeClaimTemplate unschedulable". | A workload silently running without the storage it asked for | CONFIRMED |
| 5 | **`docs/user/what-runs.md` ships two recipes that are denied at admission** (`:22-29` and `:107`), and `quickstart.md:62-64` contradicts them. The same broken example is in `k3sm build --help`. | Every new user's first copy-paste fails | CONFIRMED (reproduced live) |
| 6 | **`hack/ci.sh` runs neither `staticcheck` nor `deadcode`, and its `go test` has no `-race`** — while `docs/GO-STANDARDS.md` says three times that CI adds `-race`. Two lines would have caught item 3 and the deadcode set at landing time. | Findings that a gate should catch arriving by audit instead | CONFIRMED |
| 7 | **The 5 `//nolint:` directives suppress nothing.** Bare `staticcheck` honours `//lint:ignore`, not `//nolint` (a golangci-lint spelling). Proof: `pkg/oci/layer.go:194` is reported *despite* carrying one. So the baseline can never be clean, which is why nobody can gate on it. | A suppression that does not suppress; a gate nobody can adopt | CONFIRMED |
| 8 | **Prober published before `pr.start`** — a real window, currently unreachable because VK serialises per pod key. A landmine for any second `DeletePod` caller. | Latent; zero today | REFUTED as reachable |
| 9 | **`writeParents`/temp-file leak on rename failure** — 6 sites, inert today (no stale-temp consumption anywhere), and `kinemigrate.go` already cleans up at `:224/:255`, so the real argument is same-file inconsistency. | Cosmetic | Severity REFUTED |

## Deliberately not open

Re-raising a settled question should cost a lookup, not an afternoon. Absence from the
list above means somebody decided, not that nobody looked.

| Item | Decision |
|---|---|
| **CI is disabled** (`.github/workflows/ci.yml` is 59 lines, 0 active) | Deliberate, with a stated reason: "macOS runners are billable and we are not spending on CI for now (operator directive 2026-07-02)." Not a defect. Item 6 above is about `hack/ci.sh`, the gate a developer runs by hand, and stands independently of this. |
| Seven yaml modules in `go list -m all` | k3sm's own code imports exactly **one** (`sigs.k8s.io/yaml`, 10 sites). The rest are transitive, mostly inside `sigs.k8s.io/yaml`'s own vendored fork. |
| `Embedded` / the `Executor` interface | An interface with no type position anywhere and a doc comment citing a "Strategy flag" that does not exist. Removal is ~98 LOC. Held as a documented deferred seam — a decision, not an oversight. |
| `--node-ip` marked DORMANT in its own help text | Verified genuinely dormant: the privileged-port authorizer's terminal branch is a default-deny, so the unreachable arm is dead weight, not a hole. |
| `probe_test.go:273` SA4000 | False positive — see `audit-findings.md`. |
