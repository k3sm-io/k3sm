#!/usr/bin/env bash
#
# k3sm M17 gate — direct links (the CI-runnable single-Mac slice)
# — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M17 row in hack/acceptance/phases.json (gate hack/acceptance/m17.sh,
# tier integration, requires dev-mac, manual: false, skeleton: true). It needs no
# cable. The cabled slices are the SEPARATE rows M17.0 (hack/spike/m17/run.sh),
# M17-lab (hack/lab/m17.sh) and M17-rdma (hack/lab/m17-rdma.sh), all manual: true.
#
# The REAL M17 gate is a COMPOSITE (the M17 plan §Gates), written by M17.4:
#   1 enumeration with no cable attached yields an EMPTY DirectLink for the node
#   2 the DirectLink and MeshPeer CRDs are ensured by the binary
#   3 k3sm doctor prints the direct-link section
#   4 an MLXModel with spec.distributed.ranks: 2 reports ShardsPlaced=False with the
#     named reason (never a single-node fallback)
#   5 a rank Pod is admitted by the admission policy (the shared guardrail builder)
#   6 kubectl logs and kubectl exec on a rank Pod work
#   7 kubectl delete pod <model>-rank-1 ends in the documented gang restart
# NONE of that composite exists here yet.
#
# Honesty contract: a manual:false CI-runnable gate skeleton MUST exit non-zero
# UNCONDITIONALLY until real — the release process trusts its exit 0 as "milestone
# proven". Pinned always-RED by TestNonManualSkeletonsAlwaysRed, which runs it under
# BOTH K3SM_LAB unset and K3SM_LAB=1.
set -euo pipefail
echo "M17 gate: NOT YET IMPLEMENTED — the real M17 composite gate (empty DirectLink with no cable + CRDs ensured + doctor section + ShardsPlaced=False with the named reason + rank-Pod admission + kubectl logs/exec/delete rank rungs) lands with M17.4. This is a skeleton and MUST be red."
exit 1
