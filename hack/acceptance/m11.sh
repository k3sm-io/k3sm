#!/usr/bin/env bash
#
# k3sm M11 gate — Linux containers & multi-arch (the CI-runnable integration slice)
# — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M11 row in hack/acceptance/phases.json (gate hack/acceptance/m11.sh,
# tier integration, requires dev-mac, manual: false, skeleton: true). The hardware
# slices are the SEPARATE lab rows M11-core and M11-lab (both hack/lab/m11.sh,
# manual: true) — this row is the part that boots no VZ guest and can therefore run
# in hack/ci.sh --integration.
#
# The REAL M11 gate is a COMPOSITE of the vm path's host-side, hardware-free
# criteria: multi-arch OCI platform selection, the Linux rootfs assembled from OCI
# layers, and the truthful k3sm.io/rosetta{,-linux} capability advertisement (B229 —
# a node must not advertise a capability it lacks). NONE of that composite exists
# here yet; the per-slice unit gates are the current proof.
#
# Honesty contract (Res. 2): a manual:false CI-runnable gate skeleton MUST exit
# non-zero UNCONDITIONALLY until real — the gate is run DIRECTLY by the release
# process and its exit 0 is trusted as "milestone proven", so a placeholder that
# exited 0 (the hack/lab/*.sh K3SM_LAB-unset pattern) would falsely pass M11. This
# gate is pinned always-RED by TestNonManualSkeletonsAlwaysRed, which runs it under
# BOTH K3SM_LAB unset and K3SM_LAB=1.
set -euo pipefail
echo "M11 gate: NOT YET IMPLEMENTED — the real M11 composite gate (multi-arch platform selection + Linux rootfs from OCI layers + truthful Rosetta capability advertisement) is unbuilt; this skeleton is always RED (Res. 2). The hardware slices are the M11-core / M11-lab rows (hack/lab/m11.sh)." >&2
exit 1
