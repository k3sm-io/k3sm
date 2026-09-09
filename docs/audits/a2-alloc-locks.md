# Audit findings — A2 allocation / GC / synchronization pass

Run 2026-09-08 against `main` at `69cd04a`, on branch `audit/a2-alloc-locks`.

Method: the house torture chamber. Report-only auditors produced candidates over
the non-test source; an **independent skeptic per candidate** was given only the
claim plus the code — never the auditor's reasoning — and instructed to refute,
defaulting to REFUTED when uncertain. Nothing was acted on until a skeptic failed
to kill it. Two of the three highest-ranked candidates were **refuted**, one of
them because the fix it proposed was itself a data race.

**Lens.** This pass was scoped to allocation/GC pressure, synchronization, and a
security read. It is **not** the four-auditor sweep (simplify / dedup /
correctness / doc-drift); those dimensions were not run, and their absence here
is a stated bound, not a clean bill.

## The measurement gap this pass closed

The tree carried **zero benchmarks and zero fuzz targets**. Every allocation
claim about it was therefore unfalsifiable. Baselines now exist for the two
byte-scaling paths — see [benchmark-baselines.md](benchmark-baselines.md).
`allocs/op` is deterministic across runs and is the figure to judge against;
`ns/op` on this hardware varies ~10% and should not be read as precise.

## Fixed in this pass

| # | Finding | Verdict | Measured | Commit |
|---|---|---|---|---|
| 1 | `writeTar` allocated a copy buffer per tar entry; for files <32 KiB the buffer equalled the file, so discarded buffer volume tracked total context BYTES (ceiling ~2 GiB) | CONFIRMED (measured) | −89.5% bytes small-file, −97.5% large-file | `ab9f277` |
| 2 | `writeParents` split-and-joined every ancestor of every entry, with the `seen` test *after* the Join | CONFIRMED (measured) | −52% allocs on a depth-10 tree | `ab9f277` |
| 3 | `parseClusterZoneName` returned a `[]string` whose only consumer, at both call sites, was `len()` | CONFIRMED (measured) | −1 alloc on every in-cluster DNS query | `ab9f277` |

Each carries a regression test **verified to fail against the unfixed code**.
Where the change is behaviour-preserving rather than behaviour-changing, the test
pins the property that made it worth doing — an allocation bound, or a
differential against the replaced implementation over a generated corpus.

## REFUTED — recorded so they are not re-raised

| Finding | Why it died |
|---|---|
| `emit`/`publishStatusUpdate` should snapshot the `*podTrack` pointer under `r.mu` and `DeepCopy` outside, as `GetPods` does | **The prescription is a data race**, empirically reproduced under `-race`. `r.mu` guards the `t.pod` *field*, which `UpdatePod` reassigns at `runtimed.go:1170` under that lock; reading `t.pod` after unlocking is an unsynchronized read. The cited precedent was also misread — `GetPods` snapshots the **pod pointer** (`:1304`), which *was* the PR #335 fix and carries a pinned regression test. A corrected form (pod pointer inside the lock, copy outside) is safe but the same skeptic measured the win as tail-latency-only at a low event rate, so it was not taken without a `-mutexprofile` on a real node. |
| `registrysvc.Service.Shutdown` can hang forever after SIGKILL despite its context | **REFUTED at `service.go:288`**: `cmd.Stdout/Stderr` are `*os.File`, so `os/exec` passes the fd directly and registers no copier goroutine — `Wait` reduces to `wait4` on the direct child. Reproduced with an escaping grandchild holding the same fd: `Wait` returned in 894 µs. The `ctx.Done()` arm is also unreachable — `drainGrace` (5s) fires before `registryShutdownGrace` (10s). |
| The same unbounded `<-c.exited` in `pkg/executor/supervised.go` `stopComponent` (recorded as open item #2 of the A1 pass) | **Same refutation applies** — `supervised.go:748` is also `*os.File`. This *corrects a standing entry in the A1 ledger*: it is not the liveness bug it was recorded as. The residual is latent fragility, not a defect: changing either site to a non-`*os.File` writer (a `bytes.Buffer`, a rotating writer, `StdoutPipe`) would interpose a copier goroutine and the escaping-grandchild case *would* then wedge. Worth a comment or a `WaitDelay`, not a fix. |
| `parseEDNS` re-parses the datagram from byte 0 after `respond` already parsed it | **Real, but not an allocation finding.** `BenchmarkFindOPT` = 0 B/op, 0 allocs/op. `dnsmessage.Parser` is a stack value and the `SkipAll*` methods return value types. It costs ~55 ns (~8% of a query) and is a CPU tidy, nothing more. Two independent auditors reached this conclusion separately. |
| `normalizeDNSName` allocates per query | **REFUTED by measurement**: 0 allocs. `strings.ToLower` returns the input unchanged with no allocation for ASCII with no upper-case bytes, and `TrimSuffix` returns a sub-slice. Pod queries are already lower-case. |
| The `".svc."+domain` / `"."+domain` concatenations allocate per query | **REFUTED at the default domain**: 0 allocs — 18 bytes fits Go's 32-byte non-escaping stack buffer. It becomes 1 alloc at ~57 bytes, so it is a latent cost for a long `--cluster-domain`, not a default-path one. `TestParseClusterZoneNameDoesNotAllocate` pins the assumption that makes the zero real. |
| `hdr := &tar.Header{...}` per tar entry (216 B) is a per-entry heap allocation | **REFUTED empirically**: hoisting it changed 479,052 → 479,032 B/op, i.e. noise. Escape analysis proves it does not escape `tw.WriteHeader`, so it is stack-allocated. This one would have been reported from pattern; measurement killed it. |
| `LoadBalancer.mu` should be an `RWMutex` | **REFUTED**: `Pick` *writes* the round-robin cursor (`loadbalancer.go:102`) and is the per-connection call, so the highest-frequency caller is a writer and `RLock` is unavailable to it by construction. The lock is correctly chosen. |
| `sort.SliceStable` / `filepath.Rel` in the oci context walk are allocation findings | **REFUTED as allocation findings** (identical bytes and allocs vs the alternatives); both are real CPU items — `Rel` is ~158 ns/call and effectively zero-alloc. Recorded as CPU, not GC. |

## Still open — measured, not fixed

- **Reverse DNS has no reverse index.** `serviceZone.LookupPTR` (`resolver.go:940`)
  lists every Service and synthesizes each one's complete `RecordSet` to answer a
  single PTR query — cost scales with Service count, both in time and in
  allocation. Its comment justifies this with "PTR queries are rare and the
  Service set is dev-scale". Nothing in-tree issues a PTR lookup, so the first
  half holds for k3sm's own traffic — but the resolver answers pods, and pod
  behaviour is not k3sm's to bound. `BenchmarkRespondReversePTRByServiceCount`
  makes the scaling claim falsifiable rather than asserted. The concrete
  cost figures and the request-shaping questions this raises are reported
  privately rather than spelled out here; ask if you want them. Wants a design
  decision, not a patch.
- **Per-query record synthesis.** `synthA`/`synthSRV` rebuild a service's entire
  record set and then read one map key (`resolver.go:571`). Measured 60 allocs at
  3 endpoints, ~4.2 allocs per endpoint, linear. An informer-driven snapshot fixes
  this and the PTR item together, but it converts a documented no-staleness
  property (`resolver.go:50-52`) into a staleness-bounded one — that comment would
  have to change with the code.
- **`context.WithTimeout` per datagram** costs 4 allocs (`resolver.go:243`) while
  `ctx` inside `respond` is consumed by exactly two expressions, both
  `r.forward(...)` — verified by reading every use. Hoisting the deadline into
  `forward`, its only consumer, preserves the stated goroutine-leak protection.
  Not taken in this pass; contained and cheap.
- **`EnableCompression` is unconditional** (`resolver.go:693`) — 3 allocs and
  288 B to save 25 bytes on a single-A response. A conservative threshold is
  viable but the uncompressed size crosses the 512-byte non-EDNS floor at 12 A
  records, so it needs a boundary test, not a guess.
- **`lookup` holds `r.mu` across an O(n) linear scan** of `r.track`
  (`runtimed.go:1511`) on every exec/attach/logs/GetPodStatus — a longer critical
  section than either DeepCopy the refuted finding targeted. Wants a
  `(namespace,name) → id` index, and a `-mutexprofile` first.
- **`HostProcess.startPod` holds `p.mu` across `MkdirAll`, `os.Create` and
  `exec.Start`** (`hostprocess.go:128`), once per container. Dev-only path
  (`hostprocess` is the documented opt-out; `runtimed` is the default), and the
  fix needs a loser-teardown path or it trades a stall for orphaned processes.
- **`NodeStatusProvider.recompute`** takes a mutex over state only one goroutine
  ever touches. Keep the lock; its comment asserts a single-caller design the lock
  itself contradicts. Documentation fix.

## Security

A security read ran as part of this pass. Its findings are **not recorded here**:
`SECURITY.md` asks that vulnerabilities not be reported through public channels,
because for a distribution shipping privileged components a public report is a
disclosed 0-day before there is a fix. They were reported privately.

## Coverage bound — stated, not implied

**Measured and read fully:** `pkg/netserve/resolver.go`, `pkg/oci` (all seven
non-test files), and the sibling `darwin-net/pkg/dns/synth.go` synthesis path.
**Read fully for synchronization:** all 21 `sync.Mutex`, both `sync.RWMutex`, all
3 `atomic.*` with their 7 use sites, all 8 `WaitGroup` declarations, both
`sync.Once` and the one `OnceValue` — the complete inventory in `pkg/` and `cmd/`.
**Not audited for allocation at all:** `pkg/provider` beyond the two refuted
sites, `pkg/netdsvc`, `pkg/svclb`, `pkg/mlx`, `cmd/k3sm`, and every cold
boot/CLI package (`install`, `dev`, `bootstrap`, `certs`, `status`). The
coldness of `pkg/status` was assumed from the brief, not independently derived.
**Never opened:** the sibling modules' non-DNS surfaces, including
`runtimed/pkg/runtime` — note in particular that the OCI layer *extractor* lives
there and was not examined, while this pass measured only the *writer* in
`pkg/oci`.
