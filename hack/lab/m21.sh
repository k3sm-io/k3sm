#!/usr/bin/env bash
#
# k3sm M21 lab gates G3, G5 and G6 — node resource budget and pressure signals on the lab host.
# — SKELETON (an honest placeholder; each mode is replaced as its phase lands).
#
# # K3SM-SKELETON
#
# Rows in hack/acceptance/phases.json (all gate hack/lab/m21.sh, tier lab, manual: true, skeleton: true):
#   M21-G3  --g3  page reads, EPERM, and write and lock denial
#   M21-G5  --g5  vm OOMKilled, memory.high, and the guest page
#   M21-G6  --g6  both kill tiers, admission, and the marks
# The CI-runnable modes --g0, --g1 and --g2 live in hack/acceptance/m21.sh.
#
# Honesty contract (TestLabSkeletonHonesty, manual:true and skeleton:true): under no K3SM_LAB
# this exits 0 saying PENDING, a skip and NOT a pass; under K3SM_LAB=1 it exits non-zero,
# because a placeholder that greened on the lab host would falsely pass a milestone whose real
# proof is still owed. Each mode's body replaces this one and flips its row's skeleton to
# false in the SAME change.
set -euo pipefail
case "${1:-}" in
	"") mode="all modes" ;;
	--g3|--g5|--g6) mode="${1#--}" ;;
	-h|--help) echo "usage: $0 [--g3|--g5|--g6]   (a skeleton: PENDING without K3SM_LAB=1, red with it)"; exit 0 ;;
	*) echo "$0: unknown argument $1 (expected --g3, --g5 or --g6)" >&2; exit 2 ;;
esac
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M21-lab gate (${mode}): PENDING (dev-mac). It needs K3SM_LAB=1 and the lab host, and this script is a skeleton. This is NOT a pass."
	exit 0
fi
echo "M21-lab gate (${mode}): NOT YET IMPLEMENTED. The real ladder lands with its M21 phase. This is a skeleton and MUST be red under K3SM_LAB=1."
exit 1
