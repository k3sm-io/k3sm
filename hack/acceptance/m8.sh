#!/usr/bin/env bash
#
# k3sm M8 gate — MLX native Apple-Silicon ML serving — SKELETON ONLY
# (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M8 row in hack/acceptance/phases.json (gate hack/acceptance/m8.sh, tier
# integration, requires dev-mac + apple-gpu + network, manual: false, skeleton: true).
# There is deliberately NO M8-lab row — a GPU dev-mac covers it (docs/m8-plan.md §M8.6,
# Res. 15).
#
# The REAL M8 proof (per docs/m8-plan.md §M8.6) applies examples/mlxmodel.yaml against
# a pinned model repo+revision, waits for status Ready (conditions, not just Phase),
# gets an OpenAI chat completion via the ClusterIP returning tokens, records TTFT +
# tokens/sec through the ClusterIP path vs the direct backend, deletes, and asserts
# GC-clean per the whenDeleted:Delete deletion contract (poll-to-absent). It also
# gates mlx-quickstart.md (not m7/docs.sh). NONE of that exists yet.
#
# Honesty contract (Res. 2): a manual:false CI-runnable gate skeleton MUST exit
# non-zero UNCONDITIONALLY until real. This gate is pinned always-RED by
# TestNonManualSkeletonsAlwaysRed.
set -euo pipefail
echo "M8 gate: NOT YET IMPLEMENTED — the real MLX e2e gate (MLXModel → Ready → OpenAI completion via ClusterIP → GC-clean) is unbuilt; this skeleton is always RED (Res. 2)." >&2
exit 1
