#!/usr/bin/env bash
#
# The M17.0 ladder — S1 through S5, on two Macs joined by one Thunderbolt cable.
# — SKELETON (an honest placeholder; the spike rungs land with the spike work).
#
# # K3SM-SKELETON
#
# Row in hack/acceptance/phases.json:
#   M17.0  gate hack/spike/m17/run.sh, tier lab, requires two-macs + thunderbolt-cable,
#          manual: true, skeleton: true
#
# Usage:
#   K3SM_LAB=1 hack/spike/m17/run.sh     # the whole ladder on the rig (not yet implemented)
#   hack/spike/m17/run.sh --plan         # every rung's question, no host, no cable
#
# The real ladder runs each rung as a privileged script file under sudo on each Mac,
# with a restore-on-exit trap (bridge0 membership, aliases and routes put back; the
# LAN route is never touched, so the remote session survives). The exit contract will
# be the M16 spike's: 0 PASS, 1 FAIL, 2 RECORDED (a measurement without a verdict is
# not a green M17.0). S6 (Thunderbolt 5 / RDMA) is NOT chained here: it is the
# M17-rdma row (hack/lab/m17-rdma.sh), so this row can exit 0 on a Thunderbolt 4 rig.
#
# Honesty contract (TestLabSkeletonHonesty, manual:true ∧ skeleton:true): --plan is
# parsed BEFORE any host check and exits 0 anywhere; otherwise, under no K3SM_LAB this
# exits 0 saying PENDING — a skip, NOT a pass; under K3SM_LAB=1 it exits non-zero,
# because a placeholder that greened on the rig would falsely pass a milestone whose
# real proof is still owed. The spike work replaces this body and flips skeleton to
# false in the SAME change.
set -euo pipefail

plan() {
	echo "==> k3sm M17.0 spike ladder — PLAN ONLY (nothing is contacted, nothing is written)"
	echo
	echo "rungs, in dependency order"
	echo "  s1  enumeration     system_profiler SPThunderboltDataType + networksetup mapping (domain UUID,"
	echo "                      peer UUID, receptacle -> Thunderbolt N -> enX), stability across reboots and"
	echo "                      docks, system_profiler cost, unprivileged PF_ROUTE on enX, destroyed vs"
	echo "                      flagged on unplug, ioreg when the Thunderbolt Bridge service is deleted"
	echo "  s2  addressing      bridge0 deletem, /32 alias + on-link host route over the cable, the two /25"
	echo "                      gateway routes with the mesh-egress source, weak-host delivery to a lo0"
	echo "                      alias, a dial from a reserved-half address under the _k3sm profile,"
	echo "                      TSO/LRO off, and the figure schema (direct / wireguard-over-cable / Wi-Fi,"
	echo "                      medians and p99 over >= 5 runs, Mac models, macOS build, cable)"
	echo "  s3  link-local      ff02::1 multicast and a TLS dial over fe80::%enX after member removal, the"
	echo "                      DAD delay, the zone string net/http reports (the trust-table golden value)"
	echo "  s4  unplug          sleep / unplug / replug under a bulk iperf3 flow: kernel route deletion,"
	echo "                      fallback latency over >= 10 unplugs, no kernel fault, configd re-adds,"
	echo "                      wireguard re-programming time, peer asleep with the cable intact"
	echo "  s5  ring ranks      two mlx-lm ranks over the ring backend between pods on the two Macs, a"
	echo "                      pinned tiny model and fixed prompt, ranks bind and dial pod IPs; tokens/s"
	echo "                      over direct, wireguard and Wi-Fi beside the single-Mac figure"
	echo
	echo "not here: s6 (Thunderbolt 5 / RDMA) is the M17-rdma row, hack/lab/m17-rdma.sh"
	echo "exit  0 PASS · 1 FAIL (the plan's halt applies; the ladder stops) · 2 RECORDED"
	echo "rig   two Macs, one Thunderbolt cable, K3SM_LAB=1"
}

for arg in "$@"; do
	case "$arg" in
	--plan | --dry-run) plan; exit 0 ;;
	*)
		echo "run.sh: unknown argument: $arg (try --plan)" >&2
		exit 2
		;;
	esac
done

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M17.0 gate: PENDING (two-macs + thunderbolt-cable). The spike needs K3SM_LAB=1 and two Macs joined by a Thunderbolt cable, and this script is a skeleton: its rungs land with the spike work. This is NOT a pass."
	exit 0
fi
echo "M17.0 gate: NOT YET IMPLEMENTED — the S1-S5 spike rungs land with the spike work (the M17 plan §Sub-phases M17.0). This is a skeleton and MUST be red under K3SM_LAB=1."
exit 1
