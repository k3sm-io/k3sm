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
#   RuntimeClass, the cache mount, the ClusterIP Service), BOTH buildx pins (the
#   in-pod linux asset and the host darwin asset), the host-side fetch/verify
#   refusal, the builder-instance create/repair decision, the `k3sm builder
#   buildx` passthrough, the `k3sm build` engine ROUTING over a faked engine, the
#   SINK MATRIX (the node's image store is the default terminal state; --output
#   additionally writes the artifact) over a faked store, the lifecycle state
#   machine over a fake kube/exec seam, and the legible-absence contract.
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
# Delete is the full reset (Pod, Service, cache PVC AND namespace) — the contrast
# to Down, which keeps the cache. builder.3g asserts all four are removed.
run_test "builder.3g" 1 TestDeleteRemovesCacheAndNamespace ./pkg/builder/

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
run_test "builder.5d" 1 TestBuilderAcceptsDelete ./cmd/k3sm/
# The delete verb must reach mgr.Delete in the runBuilderVerb dispatch switch —
# a grep pins the wiring the arg-parse test cannot see past the cluster boundary.
if grep -qE 'case "delete":' "$K3SM_ROOT/cmd/k3sm/builder.go"; then
	ladder ok "builder.5e k3sm builder delete is dispatched to mgr.Delete"
else
	ladder no "builder.5e k3sm builder delete is dispatched to mgr.Delete"
fi

# ---- builder.6 — the HOST buildx pin and its fetch/verify contract ---------
# The host asset is a SECOND pin (darwin-arm64, same release tag) because the Mac
# runs buildx to drive the engine. Its bytes are verified on every call, and a
# mismatch must install nothing at all.
run_test "builder.6a" 5 TestHostBuildxPinIsWellFormed ./pkg/builder/
run_test "builder.6b" 5 TestEnsureVerifiedBinary ./pkg/builder/
if grep -q 'darwin-arm64' "$K3SM_ROOT/pkg/builder/buildxhost.go"; then
	ladder ok "builder.6c the host pin names the darwin-arm64 asset"
else
	ladder no "builder.6c the host pin names the darwin-arm64 asset"
fi

# ---- builder.7 — the builder instance and the passthrough ------------------
# BUILDX_CONFIG must be k3sm-owned and identical at create and build time, or
# buildx silently falls back to the docker context; the argv after `buildx` is
# never parsed by k3sm.
run_test "builder.7a" 6 TestEnsureBuilderInstance ./pkg/builder/
run_test "builder.7b" 6 TestInstanceEndpoints ./pkg/builder/
run_test "builder.7c" 3 TestBuildxArgsPassThrough ./pkg/builder/
run_test "builder.7d" 1 TestBuildxEnvForcesConfigDir ./pkg/builder/
run_test "builder.7e" 1 TestBuilderAcceptsBuildx ./cmd/k3sm/
run_test "builder.7f" 1 TestBuilderUsageListsBuildx ./cmd/k3sm/
run_test "builder.7g" 1 TestBuilderBuildxNeedsACommand ./cmd/k3sm/
if grep -qE 'case "buildx":' "$K3SM_ROOT/cmd/k3sm/builder.go"; then
	ladder ok "builder.7h k3sm builder buildx is dispatched from runBuilder"
else
	ladder no "builder.7h k3sm builder buildx is dispatched from runBuilder"
fi
# The passthrough must not grow a flag parser: one FlagSet in the buildx path
# would swallow a buildx flag k3sm has never heard of.
if grep -q 'flag\.' "$K3SM_ROOT/cmd/k3sm/builderbuildx.go"; then
	ladder no "builder.7i the buildx passthrough parses no flags of its own"
else
	ladder ok "builder.7i the buildx passthrough parses no flags of its own"
fi

# ---- builder.8 — `k3sm build` routes a RUN Dockerfile to the engine --------
# THE RED→GREEN RUNG. On main a RUN-bearing Dockerfile is REFUSED
# (oci.ErrRunUnsupported); here it must route to the build engine instead, with
# the engine faked at its seam so the routing is provable without a cluster. A
# malformed Dockerfile still fails natively — booting an engine to re-derive a
# syntax error answers nothing.
run_test "builder.8a" 16 TestNeedsBuildEngine ./cmd/k3sm/
run_test "builder.8b" 5 TestBuildRouting ./cmd/k3sm/
run_test "builder.8c" 4 TestEngineBuildPlatform ./cmd/k3sm/
run_test "builder.8d" 1 TestEngineBuildArgs ./cmd/k3sm/
run_test "builder.8e" 2 TestBuildShortFlags ./cmd/k3sm/
run_test "builder.8f" 4 TestEnsureRunning ./pkg/builder/
# The routing must be wired into the real entry point, not only the seam.
if grep -q 'needsBuildEngine(err)' "$K3SM_ROOT/cmd/k3sm/build.go"; then
	ladder ok "builder.8g k3sm build consults the engine classification"
else
	ladder no "builder.8g k3sm build consults the engine classification"
fi

# ---- builder.9 — the sink matrix (store by default, artifact on request) ---
# Docker parity: `k3sm build -t app:dev .` is followed by naming app:dev in a
# Pod, with nothing in between and no difference between the two build paths.
# The store is faked at its seam, so the CI tier needs no runtimed.
run_test "builder.9a" 6 TestBuildSinkMatrix ./cmd/k3sm/
run_test "builder.9b" 4 TestBuildTagRequiredWithoutOutput ./cmd/k3sm/
# BOTH paths must deliver through the one function, or the two terminal states
# drift and "which engine built it" becomes visible again.
b9c=ok
grep -q 'deliver(ctx, o, ref, img, out, record' "$K3SM_ROOT/cmd/k3sm/build.go" || b9c=no
grep -q 'deliver(ctx, o, ref, img, out, recordInStore' "$K3SM_ROOT/cmd/k3sm/buildengine.go" || b9c=no
ladder "$b9c" "builder.9c both build paths deliver through the same store+artifact function"
# The store leg must use the daemon's own ingest RPC — the CLI never writes the
# store itself (the daemon is its sole writer).
if grep -q 'LOAD_IMAGE_FORMAT_DOCKER_SAVE' "$K3SM_ROOT/cmd/k3sm/buildstore.go"; then
	ladder ok "builder.9d the store recording goes through the daemon's LoadImage ingest"
else
	ladder no "builder.9d the store recording goes through the daemon's LoadImage ingest"
fi

# ---- LIVE TIER (owed — the orchestrator's single-node lab step) ------------
owed "builder.20 live: \`k3sm builder up\` registers a buildkit worker          (needs a vm-capable node)"
owed "builder.21 live: a RUN-containing build through Endpoint() produces an OCI layout"
owed "builder.22 live: \`k3sm builder buildx build --output type=oci,dest=out .\` of a RUN Dockerfile succeeds"
owed "builder.23 live: \`k3sm build -t app:dev .\` on a RUN Dockerfile starts the engine and records app:dev in the store"
owed "builder.23b live: \`k3sm image ls\` shows that entry and a Pod naming app:dev runs (both build paths)"
owed "builder.24 live: \`k3sm image push\` of the layout, then a Pod runs it"
owed "builder.25 live: \`k3sm builder down\` deletes the Pod but keeps the cache PVC"
owed "builder.26 live: \`k3sm builder delete\` removes the Pod, Service, cache PVC AND the namespace (full reset)"

echo "----------------------------------------"
echo "builder: $PASS passed, $FAIL failed, $PENDING OWED (live)"
[ "$FAIL" -eq 0 ] || exit 1
echo "builder: CI TIER GREEN — the LIVE tier is OWED and did NOT run, so this exit 0"
echo "         does NOT mean the engine serves a real build. The orchestrator runs the live tier."
exit 0
