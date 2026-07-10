#!/usr/bin/env bash
#
# k3sm M5 gate — SKELETON ONLY (vm-RuntimeClass reachability placeholder).
#
# This is the M5 row in hack/acceptance/phases.json (gate hack/lab/m5.sh, tier lab,
# requires vz, manual: true). It is a DELIBERATELY UNIMPLEMENTED skeleton: the real
# M5 proof — that a Pod scheduled under the vm RuntimeClass boots in a Virtualization
# .framework (VZ) guest and is reachable on the pod network — is owned by backlog
# item B34 and is NOT performed here. This file exists so the manifest's gate path
# resolves (hack/acceptance/phases_test.go) and so the release process has a
# runnable referent under K3SM_LAB=1, not so it can prove the milestone.
#
# Honesty contract (why each branch exits the way it does):
#   - K3SM_LAB unset / != 1 (the common case, incl. CI): this gate is NOT on a real
#     VZ-capable rig, so it prints a PENDING notice and exits 0 — a "skip",
#     reported as "pending lab" and NEVER counted as a proven milestone
#     (mirrors hack/lab/m3.sh and hack/lab/m6.sh).
#   - K3SM_LAB == 1 (a real lab run is being attempted): this placeholder CANNOT
#     prove vm reachability, so it exits 1 (RED) rather than 0. An exit 0 here would
#     be read as "M5 proven" and falsely pass the milestone; the gate
#     therefore stays RED until B34 replaces this skeleton with the real vm
#     reachability assertion.
#
# Tier: lab (vz). The real implementation is B34.
#
# Usage: K3SM_LAB=1 hack/lab/m5.sh   (pending B34 — currently always exits 1)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Lab guard: only run under K3SM_LAB=1 (a real VZ-capable macOS host). ────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M5 gate: PENDING (vz). This lab gate needs K3SM_LAB=1 + a real Virtualization.framework (VZ) host; this is NOT a pass."
	exit 0
fi

# ── K3SM_LAB=1: the real gate is owned by B34; this skeleton cannot prove it. ───
echo "M5 gate: NOT YET IMPLEMENTED — the real M5 (vm reachability) gate is owned by B34; this skeleton cannot prove the milestone." >&2
echo "         (under K3SM_LAB=1 this exits 1 by design so the gate fails closed rather than falsely passing M5 from a placeholder; repo root: $REPO_ROOT)" >&2
exit 1
