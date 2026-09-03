#!/usr/bin/env bash
#
# k3sm B103 acceptance gate — the runnable proof of TRUTHFUL Rosetta node-capability
# advertisement across the runtimed/k3sm seam:
#
#   producer (runtimed)  GetRuntimeInfo grows two additive RuntimeConditions,
#                        RosettaHostAvailable + RosettaGuestAvailable.
#   consumer (k3sm)      ONE GetRuntimeInfo RPC -> provider.NodeCapabilities ->
#                        the k3sm.io/rosetta{,-linux} node labels, presence-only,
#                        delete()-on-loss, rosetta-linux composed as
#                        VMBackendAvailable AND RosettaGuestAvailable.
#
# B103 spans TWO repos, so this gate spans them too: it drives runtimed's producer
# test and k3sm's two consumer tests through the workspace go.work. A standalone
# k3sm checkout cannot prove B103 — that is a hard FAIL below, never a skip.
#
# Usage: bash hack/acceptance/B103.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$K3SM_ROOT/.." && pwd)"
RUNTIMED_ROOT="$WS_ROOT/runtimed"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B103 acceptance (Rosetta node-capability advertisement, runtimed<->k3sm)"

# ---- cross-repo preconditions ------------------------------------------------
# The two halves only compile against each other through the workspace go.work. A
# standalone k3sm clone CANNOT prove the producer half, so its absence is a hard FAIL
# (never a skip and never exit 0 — an unprovable gate must read red, or "B103 green"
# would mean "B103 was not checked").
#
# NOTE: $WS_ROOT is NOT a Go module (it holds go.work only), so never run a bare
# `go build ./...` there — every Go leg below cd's into a repo and uses
# repo-relative package paths.
if [ -f "$WS_ROOT/go.work" ]; then
	ladder ok "b103.pre  workspace go.work present ($WS_ROOT/go.work)"
else
	ladder no "b103.pre  workspace go.work present — B103 spans two repos; a standalone k3sm checkout cannot prove it"
fi
if [ -f "$RUNTIMED_ROOT/go.mod" ]; then
	ladder ok "b103.pre  sibling runtimed module present ($RUNTIMED_ROOT)"
else
	ladder no "b103.pre  sibling runtimed module present — the producer half of B103 is unreachable"
fi
if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B103: $PASS passed, $FAIL failed (cross-repo preconditions unmet)" >&2
	exit 1
fi

# ---- Go leg runner ----------------------------------------------------------
# GOARCH=arm64 CGO_ENABLED=1 is pinned on EVERY Go leg, and it is a CORRECTNESS
# requirement, not hygiene: the guest Rosetta probe's answer is BUILD-ARCH dependent
# (the shim's `#ifdef __arm64__` guard makes an amd64 build report NotSupported on a
# host where an arm64 build reports Installed), so an amd64 gate could go green while
# asserting a FALSE capability verdict. The product is darwin/arm64-only anyway.
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <repo-root> <min-subtests> <TestName> <pkg>
#
# Asserts the leg actually RAN its subtests. `go test -run <filter>` with a
# ZERO-MATCH filter EXITS 0 — so a typo'd or renamed test name would read as PASS
# forever (and hack/go-selftest.sh's stale-gate-name check does not apply to script
# gates). Each leg therefore fails unless (a) "no tests to run" / "no test files" are
# ABSENT from the -v output and (b) the count of `--- PASS: <TestName>/` subtest lines
# meets the pinned per-leg minimum.
run_test() {
	local id="$1" root="$2" min="$3" name="$4" pkg="$5" out rc=0 ran
	out="$(cd "$root" && "${GOFLAGS_ENV[@]}" go test -race -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed/typo'd test name?)"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]+--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min (filter matched nothing or coverage shrank)"
	fi
}

# ---- b103.0a — the producer's new Obj-C entry point compiles under cgo -------
# SCOPED to the two packages the Rosetta probe lives in, on purpose (see 0b).
if (cd "$RUNTIMED_ROOT" && "${GOFLAGS_ENV[@]}" go build ./pkg/sandbox/ ./pkg/runtime/); then
	ladder ok "b103.0a runtimed pkg/sandbox + pkg/runtime build arm64/cgo (the Obj-C entry point links under the arch guard)"
else
	ladder no "b103.0a runtimed pkg/sandbox + pkg/runtime build arm64/cgo"
fi

# ---- b103.0b — pure-Go stub parity ------------------------------------------
# SCOPED to those same two packages ON PURPOSE: `CGO_ENABLED=0 go build ./...` is
# ALREADY RED at runtimed's main for an UNRELATED pre-existing defect
# (cmd/k3sm-execshim/main.go:128:57 — a supervisor.LaunchSpec/Credential mismatch), so
# a whole-module pure-Go leg here would report a failure B103 neither caused nor can
# fix. Do NOT "fix" this scope by widening it to ./... — widen it only once that
# defect is repaired.
if (cd "$RUNTIMED_ROOT" && CGO_ENABLED=0 go build ./pkg/sandbox/ ./pkg/runtime/); then
	ladder ok "b103.0b runtimed pkg/sandbox + pkg/runtime build CGO_ENABLED=0 (pure-Go stub parity)"
else
	ladder no "b103.0b runtimed pkg/sandbox + pkg/runtime build CGO_ENABLED=0 (pure-Go stub parity)"
fi

# ---- b103.0c — no vz in the DAEMON binary -----------------------------------
# The Rosetta GUEST probe must stay a pure capability inference: it may NOT pull
# Code-Hex/vz (the Virtualization.framework binding) into the closure of the runtimed
# DAEMON, or the daemon — which parses tenant images and serves the provider's gRPC
# socket — would inherit the entitlement/link surface of a VM host.
#
# RE-SCOPED 2026-09-03. This rung originally enumerated `./...`, which was an exact
# proxy for "the daemon" only while runtimed shipped no VM host at all. It no longer
# is: the vm path landed cmd/k3sm-vmhost + pkg/vmhost, and github.com/Code-Hex/vz is
# now a deliberate, pinned dependency reachable from exactly those two packages —
# which is the WHOLE POINT of the entitlement split (k3sm-vmhost is the one binary
# carrying com.apple.security.virtualization). A `./...` closure therefore says
# nothing about the daemon and reads red for the intended design. The contract that
# survived that change is the one this rung's own header always named — the DAEMON
# binary — so it is what is asserted now. This is a re-scope, not a relaxation: the
# separation runtimed's own TestVZIsNotReachableFromTheDaemon enforces per-package is
# asserted here over the LINKED binary, which is the question the linker actually asks.
#
# It FAILS CLOSED in four independent ways, because an absence assertion over a
# command's output is the classic gate that reports green when it measured NOTHING
# (the same reason the mapper reads UNSPECIFIED as not-capable rather than trusting a
# zero value):
#   1. `go list`'s EXIT STATUS is captured and a non-zero rc is a FAIL — never
#      swallowed with 2>/dev/null, which would let an empty result grep to 0 and PASS.
#      stderr is deliberately left attached to this script's stderr so the operator
#      sees the loader error, and is NOT folded into the grep input (an error text
#      mentioning the module path must not become a false POSITIVE either).
#   2. a POSITIVE CONTROL: the daemon closure must contain k3sm.io/runtimed/pkg/sandbox
#      (the package the probes live in), so an empty or truncated listing can never
#      read as "vz-clean".
#   3. a NEGATIVE CONTROL: the SAME pattern run over cmd/k3sm-vmhost's closure must
#      MATCH. Without it a typo'd or stale module pattern would report the daemon
#      vz-clean forever — the assertion would be unfalsifiable rather than true.
#   4. the arch/cgo pins the rest of the gate uses are applied here too: the
#      dependency closure is BUILD-TAG dependent, so the closure that matters is the
#      one the darwin/arm64 cgo PRODUCT build resolves.
#
# The pattern matches the MODULE prefix, not an exact package: a future
# github.com/Code-Hex/vz/v4 or a subpackage must redden this too.
VZ_PATTERN='github.com/Code-Hex/vz'
VZ_LIST_RC=0
VZ_LIST="$( (cd "$RUNTIMED_ROOT" && "${GOFLAGS_ENV[@]}" go list -deps ./cmd/k3sm-runtimed) )" || VZ_LIST_RC=$?
VZ_HOST_RC=0
VZ_HOST_LIST="$( (cd "$RUNTIMED_ROOT" && "${GOFLAGS_ENV[@]}" go list -deps ./cmd/k3sm-vmhost) )" || VZ_HOST_RC=$?
if [ "$VZ_LIST_RC" -ne 0 ] || [ "$VZ_HOST_RC" -ne 0 ]; then
	ladder no "b103.0c runtimed daemon/vmhost dependency closures enumerable — go list -deps exited $VZ_LIST_RC/$VZ_HOST_RC (see the error above); the vz canary MEASURED NOTHING, so it fails closed"
elif ! printf '%s\n' "$VZ_LIST" | grep -qx 'k3sm.io/runtimed/pkg/sandbox'; then
	ladder no "b103.0c vz canary positive control — the daemon closure must list k3sm.io/runtimed/pkg/sandbox (the probe's own package); an empty/garbage listing must not read as vz-clean"
elif ! printf '%s\n' "$VZ_HOST_LIST" | grep -q "$VZ_PATTERN"; then
	ladder no "b103.0c vz canary negative control — cmd/k3sm-vmhost's closure must MATCH '$VZ_PATTERN' (it is the binary that links Virtualization); a pattern that matches nothing anywhere cannot prove the daemon clean"
else
	VZ_DEPS="$(printf '%s\n' "$VZ_LIST" | grep -c "$VZ_PATTERN" || true)"
	VZ_PKGS="$(printf '%s\n' "$VZ_LIST" | grep -c . || true)"
	if [ "$VZ_DEPS" -eq 0 ]; then
		ladder ok "b103.0c runtimed DAEMON closure (cmd/k3sm-runtimed) contains no $VZ_PATTERN package (0 found across $VZ_PKGS enumerated packages; positive + negative controls armed)"
	else
		ladder no "b103.0c runtimed DAEMON closure (cmd/k3sm-runtimed) contains no $VZ_PATTERN package (found $VZ_DEPS) — the entitlement split is broken: only cmd/k3sm-vmhost may link Virtualization"
	fi
fi

# ---- b103.1 — the producer: four additive conditions + reason vocabulary ----
run_test "b103.1" "$RUNTIMED_ROOT" 14 TestGetRuntimeInfo_RosettaAvailability ./pkg/runtime/

# ---- b103.2 — the consumer mapper: ONE RPC -> ONE capability value ----------
run_test "b103.2" "$K3SM_ROOT" 10 TestRosettaCapabilitiesFromInfo ./pkg/provider/

# ---- b103.3 — the consumer labels: presence-only, delete() on loss ----------
run_test "b103.3" "$K3SM_ROOT" 11 TestRosettaLabelDeleteOnLoss ./cmd/k3sm/

echo "----------------------------------------"
cat <<'UNPROVEN'
KNOWN-UNPROVEN HERE:
  - The one-line caps thread inside buildProvider (rt.Capabilities(ctx) -> configureNode)
    has no unit seam: buildProvider dials runtimed. Proven only from configureNode
    inward; the buildProvider call itself is compile-checked, not behaviour-checked.
  - Real probe VALUES are host-dependent BY DESIGN. This gate proves the MAPPING and the
    fail-closed verdicts, never that this particular Mac reports Rosetta available.
  - Executing a TRANSLATED darwin/amd64 Mach-O under Seatbelt is B105 (integration tier)
    and is not exercised here — a node may truthfully carry k3sm.io/rosetta before that
    path is end-to-end proven.
  - A LIVE Rosetta-for-Linux guest (boot a VZ Linux guest, run a linux/amd64 ELF) is a
    lab leg. k3sm.io/rosetta-linux is an advertisement of capability, not of a
    demonstrated run.
  - delete()-on-loss is proven against the IN-MEMORY Node template configureNode
    stamps, NOT against observed apiserver state. Virtual Kubelet reconciles the node
    via a three-way merge patch to the STATUS subresource, which emits no deletions
    when its last-applied annotation is missing, so whether a label REMOVAL actually
    reaches kine is an open lab question. B1's shipped k3sm.io/virtualization inherits
    the identical unverified path — B103 does not make it worse, and does not fix it.
    Operator remediation is documented in docs/user/limitations.md.
UNPROVEN
echo "----------------------------------------"
echo "B103: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B103 GREEN ================"
