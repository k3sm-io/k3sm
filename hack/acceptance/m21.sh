#!/usr/bin/env bash
#
# k3sm M21 gates G0, G1 and G2 — node resource budget and pressure signals
# — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# Rows in hack/acceptance/phases.json (all gate hack/acceptance/m21.sh, skeleton: true):
#   M21-G0  --g0  tier lab, manual: false  parses the committed P0 results table
#   M21-G1  --g1  tier integration         the P1 leaves' tests plus the restart leg
#   M21-G2  --g2  tier integration         relay, taint, policy, RBAC 403 and watch,
#                                          and no node grant
# The lab-run modes --g3, --g5 and --g6 live in hack/lab/m21.sh.
#
# Honesty contract: a manual:false gate skeleton MUST exit non-zero UNCONDITIONALLY
# until real, in every mode and with no argument, because the release process trusts
# an exit 0 as "milestone proven". Pinned always-RED by TestNonManualSkeletonsAlwaysRed,
# which runs the script with no argument under BOTH K3SM_LAB unset and K3SM_LAB=1.
# Each mode is replaced by its real body in the same change that flips its row's
# skeleton flag to false.
set -euo pipefail
case "${1:-}" in
	"") mode="all modes" ;;
	--g0|--g1|--g2) mode="${1#--}" ;;
	-h|--help) echo "usage: $0 [--g0|--g1|--g2]   (a skeleton: every mode exits non-zero)"; exit 0 ;;
	*) echo "$0: unknown argument $1 (expected --g0, --g1 or --g2)" >&2; exit 2 ;;
esac
echo "M21 gate (${mode}): NOT YET IMPLEMENTED. The real gate lands with its M21 phase. This is a skeleton and MUST be red."
exit 1
