#!/usr/bin/env bash
# k3sm local CI — the standard CI / pre-commit gate (docs/GO-STANDARDS.md) in one
# command. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=1   # k3sm is CGO_ENABLED=1 — it imports runtimed (cgo syscall shims). kine is a child process, not a dependency.
STATICCHECK_VERSION=2026.2.1   # keep equal to the install pin in docs/GO-STANDARDS.md §Commit gates
GOVULNCHECK_VERSION=v1.9.0   # the govulncheck the gate requires; keep equal across the k3sm repos (hack/lib/govulncheck.sh reads this line)

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
	# The etcd wrapper module (pkg/executor/etcdchild) is not a module of this repo, so
	# nothing else here verifies its lockfile or scans its dependency graph. It needs
	# the module proxy or a warm cache, like `go mod tidy` below; there is no offline
	# skip, for the same reason that stage has none. A missing or mismatched
	# govulncheck is RED inside the script, and so is a finding.
	echo "==> [k3sm] etcd wrapper"
	hack/etcd-wrapper.sh verify

	# govulncheck, pinned to an exact version like staticcheck: a different release
	# can report different findings. GOVULNCHECK_VERSION (top of file) is the one
	# place the pin is written; hack/lib/govulncheck.sh reads it from that line for
	# hack/etcd-wrapper.sh and hack/release/stage.sh, and owns the tool lookup
	# (PATH first, then $(go env GOPATH)/bin, the first reporting exactly the pin).
	# A missing or mismatched tool is RED, never a skip, and so is a finding or a
	# failure to reach the vulnerability database.
	# shellcheck source=hack/lib/govulncheck.sh
	. hack/lib/govulncheck.sh
	[ "$(gv_pin)" = "$GOVULNCHECK_VERSION" ] || { echo "==> [k3sm] govulncheck: hack/lib/govulncheck.sh reads '$(gv_pin 2>&1)' as the pin, this file says $GOVULNCHECK_VERSION" >&2; exit 1; }
	gv="$(gv_find "$GOVULNCHECK_VERSION")" || exit 1
	echo "==> [k3sm] govulncheck ${GOVULNCHECK_VERSION} ./..."
	GOWORK=off CGO_ENABLED=$CGO "$gv" ./...
	# The release's children scan (hack/release/stage.sh) reads
	# hack/release/govulncheck.allow. Rebuilding the children is release work, not
	# a gate's, so here only the file is checked: every entry well formed and none
	# expired. Stale entries are judged by the scan itself.
	echo "==> [k3sm] govulncheck allow file (format, expiry)"
	gv_allow_lint hack/release/govulncheck.allow "$(date -u +%Y-%m-%d)"
fi

# Enumerate the Go packages BEFORE deciding to skip anything. Exit 0 with empty
# output means "no Go packages yet" — the legitimate skip this guard was written
# for. A NON-ZERO exit (broken go.mod, unresolvable dependency, bad GOWORK, absent
# toolchain) is a HARD ERROR: the old `[ -n "$(go list ./... 2>/dev/null)" ]` could
# not tell the two apart, so it silently skipped vet/build/test and still reported
# green — a gate that cannot even enumerate its packages must go RED.
ci_tmp="$(mktemp -d)"
trap 'rm -rf "$ci_tmp"' EXIT
golist_err="$ci_tmp/golist.err"
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
	# The output is kept so that a red run ends with the failing tests, not only
	# a long scroll.
	echo "==> [k3sm] go test -race"
	# Written to a file and then printed, not piped through tee: the
	# gate runs under a minimal PATH (the staticcheck acceptance test) and
	# the exit status comes straight from go test, not a pipeline.
	test_rc=0
	CGO_ENABLED=$CGO go test -race -count=1 ./... > "$ci_tmp/gotest.log" 2>&1 || test_rc=$?   # e2e/ is //go:build e2e — excluded here
	cat "$ci_tmp/gotest.log"
	if [ "$test_rc" -ne 0 ]; then
		echo "==> [k3sm] go test FAILED; failing tests:" >&2
		grep -E '^[[:space:]]*--- FAIL:|^FAIL[[:space:]]|^panic:' "$ci_tmp/gotest.log" >&2 || echo "    (no FAIL line; read the output above)" >&2
		races="$(grep -c 'WARNING: DATA RACE' "$ci_tmp/gotest.log" || true)"
		[ "$races" = 0 ] || echo "    data races reported: $races" >&2
		exit 1
	fi

	# The race witness: a planted race that go test -race must catch. If the
	# toolchain's race detector is not live, this goes red instead of the gate
	# passing races silently.
	echo "==> [k3sm] race witness"
	if CGO_ENABLED=$CGO go test -race -count=1 ./hack/testdata/racewitness > "$ci_tmp/witness.log" 2>&1; then
		echo "FAIL: [k3sm] the planted race in hack/testdata/racewitness passed; go test -race does not detect races" >&2
		exit 1
	fi
	if ! grep -q 'WARNING: DATA RACE' "$ci_tmp/witness.log"; then
		echo "FAIL: [k3sm] the race witness failed without a race report:" >&2
		cat "$ci_tmp/witness.log" >&2
		exit 1
	fi

	# Wall-clock waits and fixed ports in tests, outside hack/test-sleeps.allow.
	echo "==> [k3sm] test-sleep lint"
	hack/verify-test-sleeps.sh --self-test
	hack/verify-test-sleeps.sh

	# The integration tier is NOT run here (it needs darwin + a real socket), but
	# nothing else in this repo COMPILES the `integration` build tag, so the
	# privilege-premise canary would rot invisibly. Vet it.
	# Every build tag this repo defines gets vetted, not just the ones a stage runs.
	# A tagged file that no stage COMPILES can break on main invisibly: a helper added
	# under no tag collided with one under `kinecompat`, and the compat gate could not
	# build for a full day because nothing here ever tried.
	for tag in integration kinecompat e2e; do
		echo "==> [k3sm] go vet -tags $tag"; CGO_ENABLED=$CGO go vet -tags "$tag" ./...
	done

	# staticcheck, scoped to non-test code with -tests=false.
	#
	# The scope is deliberate and worth stating, because an unscoped run is not
	# gateable today: it reports 11 findings, every one in a _test.go file:
	# three deprecations (tar.Header.Xattrs, go/parser.ParseDir), six unused
	# test helpers (U1000), one dead store (SA4006), and one known false
	# positive (SA4000 at pkg/provider/probe_test.go, refuted in
	# docs/audits/audit-findings.md — feed() mutates via m.observe(), so the two
	# operands are different state transitions). Gating on non-test code is
	# achievable NOW at zero findings; widening it to tests is a separate
	# mechanical sweep, and gating on something unachievable is how a gate ends
	# up permanently bypassed.
	#
	# Note for anyone adding a suppression: bare staticcheck honours exactly one
	# syntax, `//lint:ignore <Check> <reason>` on the PRECEDING line, reason
	# required. It does NOT honour `//nolint:...`, which is golangci-lint's
	# spelling and suppresses nothing here.
	#
	# The version is pinned EXACTLY (STATICCHECK_VERSION, top of file): a
	# different staticcheck reports different findings, so an unpinned stage's
	# verdict would depend on whichever binary the host happens to have. Each
	# candidate (PATH first, then $(go env GOPATH)/bin) is probed and the first
	# reporting exactly the pin is used, so a stale copy on PATH cannot shadow a
	# correct one. Bump the pin together with the Go toolchain (an older
	# staticcheck cannot read a newer Go's export data) and with
	# docs/GO-STANDARDS.md, keeping it in step with the other k3sm repos.
	#
	# A missing or mismatched tool is a RED, not a SKIP: a gate that can silently
	# not run and still print green is the failure class the go-list guard above
	# exists to stop.
	sc_hint="go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}"
	sc=""
	sc_seen=""
	sc_prev=""
	for c in "$(command -v staticcheck || true)" "$(go env GOPATH)/bin/staticcheck"; do
		[ -n "$c" ] && [ -x "$c" ] && [ "$c" != "$sc_prev" ] || continue
		sc_prev="$c"
		c_ver=""
		read -r _ c_ver _ <<<"$("$c" -version 2>/dev/null || true)" || true
		if [ "$c_ver" = "$STATICCHECK_VERSION" ]; then
			sc="$c"
			break
		fi
		sc_seen="${sc_seen}    $c reports ${c_ver:-no version}"$'\n'
	done
	if [ -z "$sc" ] && [ -z "$sc_seen" ]; then
		echo "==> [k3sm] staticcheck: not installed; the gate needs ${STATICCHECK_VERSION} (${sc_hint})" >&2
		exit 1
	elif [ -z "$sc" ]; then
		echo "==> [k3sm] staticcheck: wrong version; the gate needs ${STATICCHECK_VERSION} (${sc_hint}). Found:" >&2
		printf '%s' "$sc_seen" >&2
		exit 1
	fi
	echo "==> [k3sm] staticcheck ${STATICCHECK_VERSION} (non-test)"; CGO_ENABLED=$CGO "$sc" -tests=false ./...
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

# The dependency supply-chain check (hack/verify-deps.sh): the go environment
# cannot weaken verification, go mod verify, the hack/deps.lock module graph,
# the 14-day cooldown on new versions, the OSV malicious-package query, go.mod
# replace discipline, and exact pins on every remote go install / go run. It
# needs proxy.golang.org and api.osv.dev; there is no offline skip, because a
# network failure there is RED by design. Like the examples gate, it runs only in
# the real module: hack/acceptance/ci_guard_test.go runs this script in a
# throwaway module whose graph the lock could never describe.
if grep -qx "module k3sm.io/k3sm" go.mod 2>/dev/null; then
	# The native metrics-server image recipe (hack/images/metrics-server): its
	# pins, records and refusals, hermetically. The build itself is operator-run.
	echo "==> [k3sm] metrics-server image recipe (self-test)"
	hack/images/metrics-server/selftest.sh
	# The release publisher's hermetic self-test (refusals, promote check,
	# the final-release disk-image requirement). set -e reads its exit code.
	echo "==> [k3sm] release publish (self-test)"
	hack/release/publish.sh --self-test
	# The stager's hermetic self-test: the manifest, the signature policy, the
	# release refusal, the children's build stamps and the children vuln scan
	# against a planted local database. set -e reads its exit code.
	echo "==> [k3sm] release stage (self-test)"
	hack/release/stage.sh --self-test
	echo "==> [k3sm] verify-deps (self-test)"
	hack/verify-deps.sh --self-test
	echo "==> [k3sm] verify-deps"
	hack/verify-deps.sh
fi

echo "OK: k3sm ci green"
