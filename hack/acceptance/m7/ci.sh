#!/usr/bin/env bash
#
# k3sm M7.2 sub-gate — GitHub Actions CI — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is a sub-gate of the M7 umbrella (hack/acceptance/m7.sh execs it); it lives
# under hack/acceptance/m7/ deliberately OUTSIDE the m[0-9]*.sh orphan glob in
# phases_test.go, so it needs no phases.json row of its own (Res. 5).
#
# The REAL M7.2 gate (per docs/m7-plan.md §M7.2) asserts: actionlint + zizmor over
# every workflow, a workflow-manifest assert (a required workflow file missing = RED),
# the self-hosted-trigger allowlist ({schedule, workflow_dispatch, push@main} only),
# trufflehog registered as a required status check, a symbol-canary liveness assert,
# and a post-merge run-green check bound to the flip SHA. NONE of that exists yet.
#
# Honesty contract: a manual:false CI-runnable gate skeleton MUST exit non-zero
# UNCONDITIONALLY (Res. 2) — it is NOT the hack/lab/*.sh K3SM_LAB-unset→exit-0
# pattern, which would fake-green a non-manual row that /orchestrate runs directly
# and trusts on exit 0. This stays RED until the real M7.2 CI gate replaces it.
set -euo pipefail
echo "M7.2 ci.sh gate: NOT YET IMPLEMENTED — the real GitHub Actions CI gate (actionlint/zizmor + workflow manifest + self-hosted allowlist + trufflehog + canary liveness) is unbuilt; this skeleton is always RED (Res. 2)." >&2
exit 1
