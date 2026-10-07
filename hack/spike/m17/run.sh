#!/usr/bin/env bash
#
# The M17.0 ladder — S1 through S5, in order, on two Macs joined by one Thunderbolt
# cable.
#
# Row in hack/acceptance/phases.json:
#   M17.0  gate hack/spike/m17/run.sh, tier lab, requires two-macs + thunderbolt-cable,
#          manual: true (a rig run, never greened by CI). The row stays skeleton: true
#          until a rig run is recorded in the findings files; the scripts are real.
#
# Usage:
#   K3SM_LAB=1 K3SM_M17_SERVER=<ssh target> K3SM_M17_WORKER=<ssh target> \
#     K3SM_EVIDENCE=<dir outside any repository> hack/spike/m17/run.sh       # S1 → S5
#   ... hack/spike/m17/run.sh s2 s3     # re-run selected rungs
#   hack/spike/m17/run.sh --plan        # every rung's question and verdict criteria;
#                                       # no host, no cable, nothing contacted
#
# Every rung drives both Macs over ssh and makes each host-networking change in a
# privileged script file with a restore-on-exit trap (lib.sh): bridge0 membership,
# aliases and routes are put back on both Macs, and the LAN route is never touched.
# S6 (Thunderbolt 5 / RDMA) is NOT chained here: it is the M17-rdma row
# (hack/lab/m17-rdma.sh), so this row can exit 0 on a Thunderbolt 4 rig.
#
# THE EXIT CONTRACT is lib.sh's, aggregated, and the worst exit wins:
#   0  every rung that ran reached a verdict and passed.
#   1  a rung FAILED (or refused). Its halt applies and its substitution is the
#      pre-decided one it printed (the M17 plan, R8), so the ladder stops there:
#      later rungs are written against the shape the failed one was supposed to
#      establish.
#   2  nothing failed, but a rung produced only measurements. Never a green.
#
# Honesty contract (TestLabSkeletonHonesty, and the M17.0 spike test beside it):
# --plan is parsed BEFORE any host check and exits 0 anywhere; with K3SM_LAB unset
# this exits 0 saying PENDING (a skip, NOT a pass); under K3SM_LAB=1 a missing host
# or evidence variable is a FAIL (exit 1), never a PENDING.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

ALL="s1 s2 s3 s4 s5"
PLAN=0
SELECTED=""
for arg in "$@"; do
	case "$arg" in
	--plan | --dry-run) PLAN=1 ;;
	s1 | s2 | s3 | s4 | s5) SELECTED="$SELECTED $arg" ;;
	*)
		echo "run.sh: unknown argument: $arg (try --plan, or a rung name: $ALL)" >&2
		exit 2
		;;
	esac
done
RUNGS="${SELECTED:-$ALL}"

if [ "$PLAN" = 1 ]; then
	echo "==> k3sm M17.0 spike ladder — PLAN ONLY (nothing is contacted, nothing is written)"
	echo
	echo "rungs, in dependency order"
	echo "  s1  enumeration     the cable found, mapped and stable; what the link watcher can see"
	echo "  s2  addressing      the /32 alias, the on-link host route, the /25s with RTAX_IFA, weak-host"
	echo "                      delivery, and the R15 figure schema (direct / wireguard-over-cable / Wi-Fi)"
	echo "  s3  link-local      ff02::1 and a TLS dial over fe80::%enX after member removal; the zone golden"
	echo "  s4  unplug          link flips, physical unplugs and a sleeping peer, under a bulk flow"
	echo "  s5  ring ranks      two mlx-lm ranks over the ring backend between pods on the two Macs"
	echo
	echo "not here: s6 (Thunderbolt 5 / RDMA) is the M17-rdma row, hack/lab/m17-rdma.sh"
	echo "exit  0 PASS · 1 FAIL (the halt applies; the ladder stops) · 2 RECORDED (never a green)"
	echo "rig   K3SM_LAB=1, K3SM_M17_SERVER, K3SM_M17_WORKER, K3SM_EVIDENCE (required; no defaults)"
	for r in $RUNGS; do
		echo
		echo "--------------------------------------------------------------------------"
		"$HERE/$r.sh" --plan || exit 1
	done
	exit 0
fi

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M17.0 gate: PENDING (two-macs + thunderbolt-cable). The spike needs K3SM_LAB=1, two Macs joined by a Thunderbolt cable, and K3SM_M17_SERVER, K3SM_M17_WORKER and K3SM_EVIDENCE. This is NOT a pass."
	exit 0
fi

missing=""
for v in K3SM_M17_SERVER K3SM_M17_WORKER K3SM_EVIDENCE; do
	[ -n "${!v:-}" ] || missing="$missing $v"
done
if [ -n "$missing" ]; then
	echo "M17.0 gate: FAIL — K3SM_LAB=1 but missing$missing (no defaults). A lab run that cannot reach its Macs proved nothing: this is a FAIL, never a PENDING."
	exit 1
fi

WORST=0
for r in $RUNGS; do
	echo
	echo "=========================================================================="
	echo "==> M17.0 $r"
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
		echo "==> $r: FAIL (exit $rc) — the halt for this rung applies and its substitution is the pre-decided one it printed; the ladder stops here"
		WORST=1
		break
		;;
	esac
done

echo
case "$WORST" in
0) echo "M17.0: PASS — every rung reached a verdict; write the findings back before M17-lab" ;;
2) echo "M17.0: RECORDED ONLY — not a green M17.0; a measurement does not discharge the row" ;;
*) echo "M17.0: FAIL — land the failed rung's pre-decided substitution in its findings file, then re-run" ;;
esac
exit "$WORST"
