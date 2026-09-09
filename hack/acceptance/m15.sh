#!/usr/bin/env bash
#
# k3sm M15 gate — the container-vm RuntimeClass (the CI-runnable host-side slice)
# — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M15 row in hack/acceptance/phases.json (gate hack/acceptance/m15.sh,
# tier integration, requires dev-mac, manual: false, skeleton: true). The hardware
# slices are the SEPARATE lab rows M15-core and M15-lab (both hack/lab/m15.sh,
# manual: true) — this row is the part that boots no guest and can therefore run in
# hack/ci.sh --integration.
#
# The REAL M15 gate is a COMPOSITE of the container-vm path's host-side criteria:
# the handler→backend table row and its fail-closed refusal on a node without the
# capability, the ext4-root cache's protected prefix and hit-time digest check, the
# GuestBackend generalization keeping the vm dispatch golden, and the capability probe
# that never consults any container CLI. NONE of that composite exists here yet.
#
# Honesty contract: a manual:false CI-runnable gate skeleton MUST exit non-zero
# UNCONDITIONALLY until real — the release process trusts its exit 0 as "milestone
# proven". Pinned always-RED by TestNonManualSkeletonsAlwaysRed, which runs it under
# BOTH K3SM_LAB unset and K3SM_LAB=1.
set -euo pipefail
echo "M15 gate: NOT YET IMPLEMENTED — the real M15 composite gate (handler table + ext4-cache integrity + GuestBackend golden dispatch + CLI-free capability probe) lands with M15.2/M15.3. This is a skeleton and MUST be red."
exit 1
