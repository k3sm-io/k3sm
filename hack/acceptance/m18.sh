#!/usr/bin/env bash
#
# k3sm M18 gate — the lifecycle CLI and the k3sm-side contract of the macOS app
# (the CI-runnable single-Mac slice) — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M18 row in hack/acceptance/phases.json (gate hack/acceptance/m18.sh,
# tier integration, requires dev-mac, manual: false, skeleton: true). The two-Mac slice
# is the SEPARATE row M18-lab (hack/lab/m18.sh, manual: true).
#
# The REAL M18 gate is a COMPOSITE (the M18 plan §Gates), written as M18.1 lands:
#   1 k3sm stop on an installed single-Mac node leaves no node daemon, netd, exec shim
#     or pod process and no cluster lo0 alias, keeps the plists, and writes the
#     stoppedBy marker (phase stopped)
#   2 k3sm status and k3sm status daemons report stoppedBy, with the verdict stopped
#   3 k3sm install (no --start) on a stopped node leaves it stopped
#   4 k3sm start returns the node Ready and clears the marker
#   5 k3sm restart keeps a running pod's pid
#   6 a second k3sm stop after an interrupted one converges
# NONE of that composite exists here yet.
#
# Honesty contract: a manual:false CI-runnable gate skeleton MUST exit non-zero
# UNCONDITIONALLY until real — the release process trusts its exit 0 as "milestone
# proven". Pinned always-RED by TestNonManualSkeletonsAlwaysRed, which runs it under
# BOTH K3SM_LAB unset and K3SM_LAB=1.
set -euo pipefail
echo "M18 gate: NOT YET IMPLEMENTED — the real M18 composite gate (stop leaves no process or alias and keeps the plists, status reports stoppedBy, install honours the stop, start returns Ready, restart keeps pods, an interrupted stop converges) lands with M18.1. This is a skeleton and MUST be red."
exit 1
