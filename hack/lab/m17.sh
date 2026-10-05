#!/usr/bin/env bash
#
# k3sm M17 lab gate — direct links on two Macs joined by one Thunderbolt cable.
# — SKELETON (an honest placeholder; the real ladder lands with M17.3).
#
# # K3SM-SKELETON
#
# Row in hack/acceptance/phases.json:
#   M17-lab  gate hack/lab/m17.sh, tier lab, requires two-macs + thunderbolt-cable,
#            manual: true, skeleton: true
#
# THE LADDER (written by M17.3 from the M17 plan §Gates; this file asserts NONE of it yet):
#   1  pair         cable-only join via the pairing window (no Wi-Fi, no LAN)
#   2  route        the direct route is up (both ends routeReady, the /25s over enX)
#   3  figures      the direct / wireguard-over-cable / Wi-Fi figures recorded, never failing
#   4  lan-pull     LAN pulled -> the cluster stays
#   5  cable-pull   cable pulled under load with the LAN present -> fallback measured
#   6  peer-asleep  peer asleep with the cable intact -> fallback within 20 s
#   7  cable-only   cable-only unplug -> NotReady; replug -> reconverges
#   8  wifi-pair    a pair request from Wi-Fi is refused
#   9  zone         the real-socket zone value matches the recorded golden
#   10 mixed        mixed-version rung (one Mac old, one new, cable live)
#   11 downgrade    downgrade with a live cable leaves no stale enX state
#   12 sharded      a sharded ring MLXModel serves through rank 0, tokens/s beside the
#                   single-Mac figure
# The run log will carry the M11 header (gate, artifact sha256, per-repo git SHA, result).
#
# Honesty contract (TestLabSkeletonHonesty, manual:true ∧ skeleton:true): under no K3SM_LAB
# this exits 0 saying PENDING — a skip, NOT a pass; under K3SM_LAB=1 it exits non-zero,
# because a placeholder that greened on the rig would falsely pass a milestone whose real
# proof is still owed. M17.3 replaces this body and flips skeleton to false in the SAME change.
set -euo pipefail
case "${1:-}" in
	"") ;;
	-h|--help) echo "usage: $0   (no arguments: the full direct-links ladder)"; exit 0 ;;
	*) echo "$0: unknown argument $1 (expected no arguments)" >&2; exit 2 ;;
esac
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M17-lab gate: PENDING (two-macs + thunderbolt-cable). The direct-links ladder needs K3SM_LAB=1 and two Macs joined by a Thunderbolt cable, and this script is a skeleton: its ladder lands with M17.3. This is NOT a pass."
	exit 0
fi
echo "M17-lab gate: NOT YET IMPLEMENTED — the direct-links ladder lands with M17.3 (the M17 plan §Gates). This is a skeleton and MUST be red under K3SM_LAB=1."
exit 1
