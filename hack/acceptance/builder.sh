#!/usr/bin/env bash
#
# k3sm builder acceptance — the runnable proof that `k3sm builder up` brings a
# buildkitd engine up in the cluster and hands `k3sm build` a dial endpoint for
# RUN-capable builds.
#
# TWO TIERS, split by what can be proven without a live cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   half: the Pod/Service/PVC render (guest-root, NO securityContext, the vm
#   RuntimeClass, the cache mount, the ClusterIP Service), the buildx pin
#   verification, the lifecycle state machine over a fake kube/exec seam, and the
#   legible-absence contract.
#
#   LIVE TIER (needs $KUBECONFIG on a vm-capable node) — the engine actually
#   serving. It is PRINTED AS OWED here, not run: it needs a booted vm guest, a
#   real buildkitd worker and a real RUN build, which is the orchestrator's
#   single-node lab step, not a CI leg (CI is disabled by operator directive).
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement: a Mac's Go toolchain may be
# x86_64-under-Rosetta, and an unpinned build produces an x86_64 binary this
# arm64-only product cannot run.
#
# Usage:
#   hack/acceptance/builder.sh          # CI tier; prints the owed live tier
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/builder.sh"

PASS=0; FAIL=0; PENDING=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
owed() { echo "OWED  $1"; PENDING=$((PENDING+1)); }

echo "==> k3sm builder acceptance"

# ---- builder.0 — the gate parses and its sources exist ---------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -d "$K3SM_ROOT/pkg/builder" ] || b0=no
[ -f "$K3SM_ROOT/cmd/k3sm/builder.go" ] || b0=no
[ -f "$K3SM_ROOT/pkg/builder/assets/entrypoint.sh" ] || b0=no
ladder "$b0" "builder.0  gate parses (bash -n) + pkg/builder, the CLI and the entrypoint are present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "builder: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "builder: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- builder.0b — the embedded entrypoint is a valid POSIX sh script --------
if bash -n "$K3SM_ROOT/pkg/builder/assets/entrypoint.sh" 2>/dev/null; then
	ladder ok "builder.0b the embedded entrypoint parses (bash -n)"
else
	ladder no "builder.0b the embedded entrypoint parses (bash -n)"
fi

# ---- builder.0c — the entrypoint mounts a WORKING cgroup2 unconditionally ---
# The per-container cgroup2 the guest hands us can be an empty, non-functional
# hierarchy; runc then fails every RUN step with "no cgroup mount found in
# mountinfo". The fix stacks a fresh cgroup2 UNCONDITIONALLY (no is_mounted
# guard) and asserts cgroup.controllers appears. This structural check pins that
# posture so a "skip if already mounted" regression cannot land silently.
EP="$K3SM_ROOT/pkg/builder/assets/entrypoint.sh"
b0c=ok
grep -qE 'mount -t cgroup2 none /sys/fs/cgroup' "$EP" || b0c=no
# The cgroup2 mount must NOT sit behind an `is_mounted /sys/fs/cgroup` guard.
grep -qE 'is_mounted[[:space:]]+/sys/fs/cgroup' "$EP" && b0c=no
# And it must verify controllers rather than trust the mount.
grep -qE '/sys/fs/cgroup/cgroup\.controllers' "$EP" || b0c=no
ladder "$b0c" "builder.0c the entrypoint stacks cgroup2 unconditionally and verifies cgroup.controllers"

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN its subtests: `go test -run <filter>` EXITS 0 on a
# zero-match filter, so a renamed test would read PASS forever.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" out rc=0 ran
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}([ /]|$)" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran result(s) passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran passed, want >= $min"
	fi
}

# ---- builder.1 — the Pod/Service/PVC render (the posture) ------------------
# Guest-root with NO securityContext is the load-bearing fact (m12-plan Res. 5):
# the vm is the isolation boundary and buildkitd needs real root.
run_test "builder.1a" 9 TestPodSpec ./pkg/builder/
run_test "builder.1b" 1 TestServiceSpec ./pkg/builder/
run_test "builder.1c" 1 TestPVCSpec ./pkg/builder/
run_test "builder.1d" 1 TestPodEnvCarriesBuildxPin ./pkg/builder/

# ---- builder.2 — the buildx pin verification ------------------------------
run_test "builder.2a" 3 TestBuildxPinIsWellFormed ./pkg/builder/
run_test "builder.2b" 6 TestValidatePin ./pkg/builder/

# ---- builder.3 — the lifecycle state machine (fake kube/exec seam) ---------
run_test "builder.3a" 6 TestStatus ./pkg/builder/
run_test "builder.3b" 1 TestUpToReady ./pkg/builder/
run_test "builder.3c" 1 TestUpWaitsThenReady ./pkg/builder/
run_test "builder.3d" 1 TestDownKeepsCache ./pkg/builder/
run_test "builder.3e" 3 TestEndpoint ./pkg/builder/
run_test "builder.3f" 1 TestUpCreatesNamespaceBeforePVC ./pkg/builder/

# ---- builder.4 — legible-absence + the image-source default ---------------
run_test "builder.4a" 1 TestStatusAbsentIsLegible ./pkg/builder/
run_test "builder.4b" 1 TestDefaultImageIsUpstreamAtMirrorDigest ./pkg/builder/
run_test "builder.4c" 1 TestBuilderAbsentControlPlaneIsLegible ./cmd/k3sm/

# ---- builder.5 — the CLI wiring -------------------------------------------
run_test "builder.5a" 1 TestBuilderConfigMapping ./cmd/k3sm/
run_test "builder.5b" 1 TestParseBuilderArgsDefaults ./cmd/k3sm/
if grep -q 'case "builder"' "$K3SM_ROOT/cmd/k3sm/main.go"; then
	ladder ok "builder.5c k3sm builder is dispatched from main.go"
else
	ladder no "builder.5c k3sm builder is dispatched from main.go"
fi

# ---- LIVE TIER (owed — the orchestrator's single-node lab step) ------------
owed "builder.6  live: \`k3sm builder up\` registers a buildkit worker          (needs a vm-capable node)"
owed "builder.7  live: a RUN-containing build through Endpoint() produces an OCI layout"
owed "builder.8  live: \`k3sm image push\` of the layout, then a Pod runs it"
owed "builder.9  live: \`k3sm builder down\` deletes the Pod but keeps the cache PVC"

echo "----------------------------------------"
echo "builder: $PASS passed, $FAIL failed, $PENDING OWED (live)"
[ "$FAIL" -eq 0 ] || exit 1
echo "builder: CI TIER GREEN — the LIVE tier is OWED and did NOT run, so this exit 0"
echo "         does NOT mean the engine serves a real build. The orchestrator runs the live tier."
exit 0
