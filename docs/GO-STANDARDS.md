# k3sm Go standards

The shared coding standards for every `k3sm.io/*` repo, kept identical across the four
modules.

Targets **darwin/arm64, macOS 26+**. Go **1.25.x** across all modules.

## Formatting & imports
- `gofmt` (tabs) is non-negotiable — `gofmt -l` must be empty. `goimports` for import grouping.
- Group imports in three blocks: stdlib, third-party, `k3sm.io/*`. One blank line between groups.
- No dead code, no commented-out blocks. Delete it — git remembers.

## Naming
- `MixedCaps` / `mixedCaps`, never `snake_case`. Acronyms keep case: `podID`, `HTTPServer`, `vmnetIP`.
- Package names: short, lowercase, single word, no underscores; the name is part of the API
  (`provider.HostProcess`, not `provider.ProviderHostProcess`). Avoid stutter and `util`/`common` dumps.
- Exported identifiers have a doc comment that **starts with the identifier name**.
- Receivers: short and consistent (`p *HostProcess`), 1–2 letters.

## Errors
- Return errors; **never `panic` in library code** (only `main`/init for truly unrecoverable setup).
- Wrap with context: `fmt.Errorf("create pod %s: %w", name, err)`. Preserve the chain with `%w`.
- Error strings: lowercase, no trailing punctuation. Sentinels via `errors.New`; compare with
  `errors.Is` / `errors.As`, never string matching.
- Check every error. If intentionally ignored, `_ = f()` with a reason, or a `//nolint` note.

## Context
- `ctx context.Context` is the **first** parameter of any blocking/IO/RPC function.
- Never store a `Context` in a struct. Honor cancellation; pass it down; don't `context.Background()`
  deep in a call tree.

## Package layout
- `cmd/<bin>/` for executables (thin `main`), `pkg/` for importable libraries, `internal/` for
  private packages. A `doc.go` carries the package comment for non-trivial packages.
- **No import cycles.** Shared contracts (gRPC protos, cross-repo Go types, CRD types) live in
  **`k3sm.io/apis`**, which depends on nothing in this org. If you need a shared type, add it to
  `apis` — don't duplicate it or reach sideways.

## Interfaces & types
- Define interfaces at the **consumer**, not the producer. Keep them small (1–3 methods).
- Accept interfaces, return concrete types. Zero values should be usable where practical.
- Use `any` over `interface{}`; avoid empty-interface APIs unless unavoidable.

## Concurrency
- Guard shared state with `sync.Mutex`/`RWMutex`; document the locking discipline in a comment.
  Run `cb` callbacks (e.g. VK `NotifyPods`) **outside** held locks to avoid re-entrancy deadlock.
- Every goroutine has a clear lifetime and a way to stop (`ctx`/done channel). No leaks.
- The sender closes channels, never the receiver. Tests run with `-race`.

## Logging
- Structured logging via `log/slog`. No `fmt.Print*` in library code. Levels: Error/Warn/Info/Debug.
- Don't log-and-return the same error (double reporting); log at the boundary that handles it.

## Testing
- Table-driven tests with `t.Run` subtests; descriptive case names. Fixtures in `testdata/`
  (golden files where useful).
- `go test ./...` must pass; CI runs `-race`. No network or real privilege in unit tests — fake at
  seams (interfaces). Integration/e2e tests are build-tagged and live separately.

## Dependencies
- Keep the graph minimal. `go mod tidy` before every commit. Pin versions; no `@latest` in committed go.mod.
- Document every `replace`/`exclude` with a one-line why (e.g. k3sm's `genproto` replace resolves the
  monolith-vs-split ambiguous import).

## Darwin / cgo
- Prefer `golang.org/x/sys/unix` over raw `syscall`. Use **cgo only when necessary** (darwin SPI
  with no Go binding); isolate it in `*_darwin.go` / cgo-tagged files behind a clean Go interface.
- Document any **private/deprecated SPI** use (sandbox/`libsandbox`, `memorystatus`, `clonefile`) at
  the call site, and keep it behind the swappable abstraction + a CI symbol-canary (see DESIGN.md).
- **CGO posture per repo** (set `CGO_ENABLED` accordingly in build/test):
  - `apis`, `darwin-net` — pure Go (`CGO_ENABLED=0`) for now.
  - `k3sm` — **`CGO_ENABLED=1`** (imports runtimed's cgo-backed capability probes; a CGO=0
    build compiles but reports those capabilities unavailable). kine is **not** embedded: the
    executor runs it as a pinned **child process**, built on demand out-of-module
    (`go install …/kine@pin`, CGO on for that child build only); `mattn/go-sqlite3` is not a
    dependency of any `k3sm.io` module.
  - `runtimed` — **`CGO_ENABLED=1`** (darwin syscall shims).

## Project conventions
- Vanity import paths are `k3sm.io/<repo>` (hosted at `github.com/k3sm-io/<repo>`).
- Reverse-DNS identifiers are `io.k3sm.*` (launchd labels, `os_log` subsystem); annotations/labels
  are `k3sm.io/*`; CRD groups are `<area>.k3sm.io`.

## Commit gates (run before every commit)
```sh
gofmt -l .                  # must print nothing
go vet ./...                # clean
go build ./...              # builds
go test ./...               # passes (CI adds -race)
hack/verify-boilerplate.sh  # every .go file carries the Apache-2.0 header
go mod tidy                 # no diff
```
Keep commits small and focused. **Sign off every commit** for the Developer Certificate of Origin (see
`DCO` / `CONTRIBUTING.md`): use `git commit -s`, which adds a `Signed-off-by` line certifying the DCO.
Don't push unless asked.

**Message format.** Commit subjects and PR titles follow **Conventional Commits**; PR bodies follow
a fixed section order. The subject grammar, the closed `type` set, the scope vocabulary (your scope
is the package directory you changed), the breaking-change marking, and the PR-body template are
defined once in **`CONTRIBUTING.md` § Commit messages and pull requests** — this file cites, it does
not restate. The format is **additive**: the sign-off above is still required on every commit.
