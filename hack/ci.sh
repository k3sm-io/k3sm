#!/usr/bin/env bash
# k3sm local CI — the standard CI / pre-commit gate (docs/GO-STANDARDS.md) in one
# command. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=1   # k3sm is CGO_ENABLED=1 — it imports runtimed (cgo syscall shims). kine is a child process, not a dependency.

echo "==> [k3sm] gofmt"
fmt=$(gofmt -l .) || true
[ -z "$fmt" ] || { echo "gofmt -w needed:"; echo "$fmt"; exit 1; }

echo "==> [k3sm] license headers"
hack/verify-boilerplate.sh

# The examples gate runs only in the REAL k3sm module. hack/acceptance/ci_guard_test.go
# runs this very script inside a throwaway module whose hack/ entries are symlinks back
# here; that sandbox has no examples/ and could not build the linter against
# k3sm.io/k3sm anyway. Keying on the module path — not on `[ -d examples ]` — keeps a
# DELETED examples/ a hard failure here rather than a silent skip.
if grep -qx "module k3sm.io/k3sm" go.mod 2>/dev/null; then
	echo "==> [k3sm] examples"
	# --lint-only deliberately: the gate's verdict must not depend on whether the machine
	# running it happens to have a cluster up. The server-dry-run leg is the developer's
	# stronger check (hack/verify-examples.sh with no flags), not CI's.
	hack/verify-examples.sh --lint-only
fi

# Enumerate the Go packages BEFORE deciding to skip anything. Exit 0 with empty
# output means "no Go packages yet" — the legitimate skip this guard was written
# for. A NON-ZERO exit (broken go.mod, unresolvable dependency, bad GOWORK, absent
# toolchain) is a HARD ERROR: the old `[ -n "$(go list ./... 2>/dev/null)" ]` could
# not tell the two apart, so it silently skipped vet/build/test and still reported
# green — a gate that cannot even enumerate its packages must go RED (B168).
golist_err="$(mktemp)"
trap 'rm -f "$golist_err"' EXIT
if ! go_pkgs="$(CGO_ENABLED=$CGO go list ./... 2>"$golist_err")"; then
	echo "FAIL: [k3sm] go list ./... failed — cannot enumerate packages; refusing to skip vet/build/test:" >&2
	cat "$golist_err" >&2
	exit 1
fi

if [ -n "$go_pkgs" ]; then
	echo "==> [k3sm] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [k3sm] go build"; CGO_ENABLED=$CGO go build ./...
	# -race, because docs/GO-STANDARDS.md promises it three times ("CI runs
	# -race", "CI adds -race") and this gate did not deliver it. The A1 and A2
	# audit passes both found races that the gate had let through; both were
	# caught by running -race by hand, which is exactly the work a gate exists
	# to stop repeating.
	echo "==> [k3sm] go test -race"; CGO_ENABLED=$CGO go test -race ./...   # e2e/ is //go:build e2e — excluded here

	# staticcheck, scoped to non-test code with -tests=false.
	#
	# The scope is deliberate and worth stating, because an unscoped run is not
	# gateable today: it reports ~54 findings, 52 of them one mechanical
	# deprecation (fake.NewSimpleClientset -> fake.NewClientset) in test files,
	# plus one known false positive (SA4000 at pkg/provider/probe_test.go,
	# refuted in docs/audits/audit-findings.md — feed() mutates via m.observe(),
	# so the two operands are different state transitions). Gating on non-test
	# code is achievable NOW at zero findings; widening it to tests is a separate
	# mechanical sweep, and gating on something unachievable is how a gate ends
	# up permanently bypassed.
	#
	# Note for anyone adding a suppression: bare staticcheck honours
	# `//lint:ignore <Check> <reason>` on the PRECEDING line. It does NOT honour
	# `//nolint:...`, which is golangci-lint's spelling — this repo carried five
	# of those and every one suppressed nothing.
	#
	# A missing tool is a RED, not a SKIP: a gate that can silently not run and
	# still print green is the failure class the go-list guard above exists to
	# stop. The pin is the version the gate was brought to zero findings with.
	sc=$(command -v staticcheck || true)
	[ -n "$sc" ] || sc="$(go env GOPATH)/bin/staticcheck"
	if [ -x "$sc" ]; then
		echo "==> [k3sm] staticcheck (non-test)"; CGO_ENABLED=$CGO "$sc" -tests=false ./...
	else
		echo "==> [k3sm] staticcheck: not installed; the gate needs it (go install honnef.co/go/tools/cmd/staticcheck@2026.2.1)" >&2
		exit 1
	fi
	# The integration tier is NOT run here (it needs darwin + a real socket), but
	# nothing else in this repo COMPILES the `integration` build tag, so the
	# B116 privilege-premise canary would rot invisibly. Vet it.
	# Every build tag this repo defines gets vetted, not just the ones a stage runs.
	# A tagged file that no stage COMPILES can break on main invisibly: a helper added
	# under no tag collided with one under `kinecompat`, and the compat gate could not
	# build for a full day because nothing here ever tried.
	for tag in integration kinecompat e2e; do
		echo "==> [k3sm] go vet -tags $tag"; CGO_ENABLED=$CGO go vet -tags "$tag" ./...
	done
else
	echo "==> [k3sm] (no Go packages yet — skipping vet/build/test)"
fi

echo "==> [k3sm] go mod tidy (no-diff)"
go mod tidy
if [ -n "$(git status --porcelain -- go.mod go.sum 2>/dev/null)" ]; then
	echo "go.mod/go.sum not tidy after 'go mod tidy':"; git --no-pager diff -- go.mod go.sum; exit 1
fi
# Keep the genproto replace (resolves the monolith-vs-split ambiguous import).
grep -q 'replace google.golang.org/genproto' go.mod || { echo "missing genproto replace in go.mod"; exit 1; }

echo "OK: k3sm ci green"
