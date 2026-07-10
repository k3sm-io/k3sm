#!/usr/bin/env bash
#
# k3sm M10 gate — Kubernetes conformance hardening (apiserver config + workload
# fidelity) — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M10 row in hack/acceptance/phases.json (gate hack/acceptance/m10.sh,
# tier integration, requires dev-mac, manual: false, skeleton: true). The lab slice
# (cross-node per-pod-IP / in-pod SRV/PTR) is the SEPARATE M10-lab row
# (hack/lab/m10.sh, manual: true).
#
# The REAL M10 gate (Res.9) is a COMPOSITE: its non-skeleton form execs the M10
# conformance criteria so the release process proves M10 via its own canonical gate
# — composing M10.0's §-gate enforcement e2e (apply a
# privileged pod → expect 403; grep the audit file for the event at the asserted
# level; a negative control asserts system pods + a baseline reference workload are
# still ADMITTED; an apiserver boot smoke-test) with M10.1's server-side gate
# (TestCreatePodAssignsDistinctPodIP + TestHeadlessServiceReturnsAllPodIPs). It boots
# only `k3sm server` (no root/GPU/reboot), so it runs in hack/ci.sh --integration.
# NONE of that exists yet.
#
# Honesty contract (Res. 2): a manual:false CI-runnable gate skeleton MUST exit
# non-zero UNCONDITIONALLY until real — the gate is run DIRECTLY and its exit 0 is
# trusted as "milestone proven", so a placeholder that exited 0 would falsely pass
# M10. This gate is pinned always-RED by TestNonManualSkeletonsAlwaysRed.
set -euo pipefail
echo "M10 gate: NOT YET IMPLEMENTED — the real M10 composite gate (M10.0 PSA/audit enforcement e2e + M10.1 server-side per-pod-IP/headless criteria) is unbuilt; this skeleton is always RED (Res. 2)." >&2
exit 1
