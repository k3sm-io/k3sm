#!/usr/bin/env bash
# The M16.0 ladder — S0 through S4, in order, on the M16 rig.
#
# This script IS the M16.0 acceptance: hack/acceptance/phases.json carries an M16.0
# row whose gate is this file, tier integration, requires dev-mac + apple-gpu + vz +
# network, manual: false. So the spikes are run the way every other gate is run, the
# findings are the write-back, and M16.0 never reports "pending lab".
#
# Usage:
#   K3SM_M16_HOST=<rig> hack/spike/m16/run.sh          # the whole ladder
#   K3SM_M16_HOST=<rig> hack/spike/m16/run.sh s2 s3    # re-run selected rungs
#   hack/spike/m16/run.sh --plan                       # every rung's question, no host
#
# THE EXIT CONTRACT is lib.sh's, aggregated:
#   0  every rung that ran reached a verdict and passed.
#   1  a rung FAILED. Its halt is BINDING and its substitution is PRE-DECIDED by the
#      M16 plan, so the ladder stops there: later rungs are written against the shape
#      the failed one was supposed to establish, and running them would produce
#      findings about a design that is no longer the design.
#   2  nothing failed, but at least one rung produced only measurements and no
#      verdict. Not a green M16.0 — a measurement cannot discharge a ledger row.
#
# The rungs are ORDERED BY DEPENDENCY, not by convenience: S0 installs the engine
# venv and the pinned model S3 drives; S1's checkout is where S2 finds the chart's
# own example manifest; S1's build is the runtime wheel S4 imports.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

ALL="s0 s1 s2 s3 s4"
PLAN=0
SELECTED=""
for arg in "$@"; do
	case "$arg" in
	--plan | --dry-run) PLAN=1 ;;
	s0 | s1 | s2 | s3 | s4) SELECTED="$SELECTED $arg" ;;
	*)
		echo "run.sh: unknown argument: $arg (try --plan, or a rung name: $ALL)" >&2
		exit 2
		;;
	esac
done
RUNGS="${SELECTED:-$ALL}"

if [ "$PLAN" = 1 ]; then
	echo "==> k3sm M16.0 spike ladder — PLAN ONLY (nothing is contacted, nothing is written)"
	echo
	echo "rungs, in dependency order"
	echo "  s0  k3sm preconditions      both webhook paths, two engines on one GPU, the guest<->native-pod-IP dial"
	echo "  s1  the Darwin build        pinned toolchain, the wheel and its sha256, an infrastructure-free smoke"
	echo "  s2  the control plane       the digest-pinned chart on k3sm as vm Pods, CRDs, the RBAC dump, conversion"
	echo "  s3  the engine decision     in-process core, pinned KV, abort, block hashes, the publish cost"
	echo "  s4  the worker              the backend contract, the conformance kit, tokens end to end"
	echo
	echo "exit  0 PASS · 1 FAIL (the plan's halt applies; the ladder stops) · 2 RECORDED"
	echo "rig   K3SM_M16_HOST (required on the real path; no default)"
	for r in $RUNGS; do
		echo
		echo "--------------------------------------------------------------------------"
		"$HERE/$r.sh" --plan
	done
	exit 0
fi

WORST=0
for r in $RUNGS; do
	echo
	echo "=========================================================================="
	echo "==> M16.0 $r"
	echo "=========================================================================="
	rc=0
	"$HERE/$r.sh" || rc=$?
	case "$rc" in
	0) echo "==> $r: PASS" ;;
	2)
		echo "==> $r: RECORDED (measurements, no verdict)"
		[ "$WORST" = 0 ] && WORST=2
		;;
	*)
		echo "==> $r: FAIL (exit $rc) — the plan's halt for this rung applies and its substitution is pre-decided; the ladder stops here so no later rung reports on a design that has changed"
		WORST=1
		break
		;;
	esac
done

echo
case "$WORST" in
0) echo "M16.0: PASS — every rung reached a verdict; write the findings back before the next wave" ;;
2) echo "M16.0: RECORDED ONLY — not a green M16.0; a measurement does not discharge a ledger row" ;;
*) echo "M16.0: FAIL — land the failed rung's pre-decided substitution in its findings file, then re-run" ;;
esac
exit "$WORST"
