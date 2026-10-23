#!/usr/bin/env bash
#
# k3sm M19 gate — the wasm RuntimeClass (the CI-runnable single-Mac slice)
# — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M19 row in hack/acceptance/phases.json (gate hack/acceptance/m19.sh,
# tier integration, requires dev-mac, manual: false, skeleton: true). The rig slice
# is the SEPARATE row M19-lab (hack/lab/m19.sh, manual: true).
#
# The REAL M19 gate is a COMPOSITE (listed below), written as M19.3 lands:
#   1 the handler table and the SandboxBackend enum pin (wasm is 5, container-vm is 6)
#   2 the wasm class is provisioned with the k3sm.io/wasm selector merged with the
#     darwin selector and no tolerations
#   3 the k3sm.io/wasm label is derived from the backend condition, including
#     delete-on-loss
#   4 the platform rows, the alias rows and the linux/* refusal message
#   5 the refusal reasons: wasm under require-signed or require-notarized, exec
#     probes and exec lifecycle hooks, and a mixed native/wasm pod
#   6 sibling-set consistency across RequiredSiblings, stage.sh and goreleaser
#   7 the canary on a staged k3sm-wasmhost
# NONE of that composite exists here yet.
#
# Honesty contract: a manual:false CI-runnable gate skeleton MUST exit non-zero
# UNCONDITIONALLY until real — the release process trusts its exit 0 as "milestone
# proven". Pinned always-RED by TestNonManualSkeletonsAlwaysRed, which runs it under
# BOTH K3SM_LAB unset and K3SM_LAB=1.
set -euo pipefail
echo "M19 gate: NOT YET IMPLEMENTED — the real M19 composite gate (handler table and enum pin, class provisioning, label derivation, platform rows, refusal reasons, sibling-set consistency, the staged-helper canary) lands with M19.3. This is a skeleton and MUST be red."
exit 1
