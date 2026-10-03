#!/usr/bin/env bash
#
# k3sm B46 acceptance gate: one runnable command for memory-pressure eviction
# (the provider's eviction manager) and the pressure-kill mark (runtimed spawns
# every pod process pcontrol-KILL, so macOS's out-of-swap kill picks a pod before
# the control plane).
#
#   b46.0  this gate and the lab gate parse; the sibling runtimed checkout exists.
#   b46.1  TestEvictionRanksBestEffortFirst            (k3sm pkg/provider)
#   b46.2  TestEvictionKillsVictimAndSetsEvictedReason  (k3sm pkg/provider)
#   b46.3  TestPressureMonitorSharesMemoryPressurePredicate (k3sm pkg/provider)
#   b46.4  TestComputeNodeConditionsCompressorHeadroom  (k3sm pkg/provider)
#   b46.5  TestPodSpawnMarkedPcontrolKill               (runtimed pkg/supervisor)
#   b46.6  TestResourceSymbolsResolve + TestResourceSymbolsWantList
#                                                       (runtimed internal/spicanary)
#   b46.7  the lab gate's own --self-test (unset K3SM_LAB exits 3, never 0)
#   b46.lab  hack/lab/B46.sh, whose exit code this gate propagates: 3 when
#          K3SM_LAB is unset (LAB-PENDING, not a pass), 2 on a refused
#          precondition, 1 on a failed assertion, 0 only after both real legs.
#
# A `go test -run` filter that matches nothing exits 0, so every unit leg asserts
# its own `--- PASS: <TestName>` line: a renamed test fails the gate instead of
# passing it forever.
#
# Usage:  hack/acceptance/B46.sh          # unit legs, then the lab gate (exit 3 unless K3SM_LAB=1)
#         hack/acceptance/B46.sh --unit   # unit legs only; exit 0 when they pass
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
RUNTIMED_ROOT="$(cd "$K3SM_ROOT/.." && pwd)/runtimed"
SELF="$HERE/B46.sh"
LAB="$K3SM_ROOT/hack/lab/B46.sh"

UNIT_ONLY=no
case "${1:-}" in
--unit) UNIT_ONLY=yes ;;
"") ;;
*) echo "usage: $SELF [--unit]" >&2; exit 2 ;;
esac

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
# GOARCH is pinned: a Mac whose Go toolchain runs x86_64 under Rosetta would
# otherwise build the wrong arch for a darwin/arm64 product. Both repos build
# with cgo.
GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

echo "==> k3sm B46 acceptance (memory-pressure eviction + pressure-kill mark)"

b0=ok
bash -n "$SELF" || b0=no
[ -f "$LAB" ] && bash -n "$LAB" || b0=no
[ -d "$RUNTIMED_ROOT/pkg/supervisor" ] || b0=no
ladder "$b0" "b46.0  gate + lab gate parse; sibling runtimed checkout present"
if [ "$b0" != ok ]; then
	echo "B46: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# run_test <id> <TestName> <pkg> <repo-root>
run_test() {
	local id="$1" name="$2" pkg="$3" root="$4" out rc=0
	out="$(cd "$root" && "${GOENV[@]}" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -eq 0 ] && grep -q -- "^--- PASS: ${name} " <<<"$out"; then
		ladder ok "$id  $name ($pkg)"
	else
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) did not run and pass"
	fi
}

run_test b46.1 TestEvictionRanksBestEffortFirst ./pkg/provider/ "$K3SM_ROOT"
run_test b46.2 TestEvictionKillsVictimAndSetsEvictedReason ./pkg/provider/ "$K3SM_ROOT"
run_test b46.3 TestPressureMonitorSharesMemoryPressurePredicate ./pkg/provider/ "$K3SM_ROOT"
run_test b46.4 TestComputeNodeConditionsCompressorHeadroom ./pkg/provider/ "$K3SM_ROOT"
run_test b46.5 TestPodSpawnMarkedPcontrolKill ./pkg/supervisor/ "$RUNTIMED_ROOT"
run_test b46.6 TestResourceSymbolsResolve ./internal/spicanary/ "$RUNTIMED_ROOT"
run_test b46.6 TestResourceSymbolsWantList ./internal/spicanary/ "$RUNTIMED_ROOT"

if out="$(bash "$LAB" --self-test 2>&1)"; then
	ladder ok "b46.7  lab gate self-test (unset K3SM_LAB exits 3)"
else
	printf '%s\n' "$out"
	ladder no "b46.7  lab gate self-test"
fi

echo "----------------------------------------"
echo "B46 units: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
	exit 1
fi
if [ "$UNIT_ONLY" = yes ]; then
	exit 0
fi

echo "==> B46 lab gate (hack/lab/B46.sh)"
rc=0
bash "$LAB" || rc=$?
exit "$rc"
