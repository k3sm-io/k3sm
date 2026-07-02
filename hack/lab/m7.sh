#!/usr/bin/env bash
#
# k3sm M7-lab gate — release-artifact reboot/brew survival — SKELETON ONLY.
#
# This is the M7-lab row in hack/acceptance/phases.json (gate hack/lab/m7.sh, tier
# lab, requires macos-runner + reboot + signing, manual: true, skeleton: true). It
# also backs the RE-POINTED M4-lab row: the reboot-survival proof needs the M7.1
# brew/pkg artifact, so the ex-M4-lab reboot debt now runs here in the M7 tail (the
# old hack/lab/m4.sh skeleton is deleted in this same change; B35 tombstoned —
# docs/m7-plan.md §"Gate machinery", Res. 3).
#
# The REAL M7-lab proof (per docs/m7-plan.md §M7.1) uses real Developer-ID certs:
# spctl/stapler validate the notarized artifacts, then a clean-Mac `brew install` →
# `sudo k3sm install` → cluster Ready → reboot → Ready (launchd survival), greening
# the transferred M4.0 acceptance AND the ex-M4-lab reboot debt in one run. NONE of
# that exists yet.
#
# Honesty contract (why each branch exits the way it does; mirrors hack/lab/m5.sh):
#   - K3SM_LAB unset / != 1 (the common case, incl. CI): this gate is NOT on a real
#     reboot/signing rig, so it prints a PENDING notice and exits 0 — a "skip", which
#     /orchestrate reports as "pending lab" and NEVER counts as a proven milestone.
#   - K3SM_LAB == 1 (a real lab run is being attempted): this placeholder CANNOT
#     prove reboot/brew survival, so it exits 1 (RED) rather than 0. An exit 0 here
#     would be read by /orchestrate as "M7-lab/M4-lab proven" and fake-green the
#     milestone; the gate therefore stays RED until the M7.1 release pipeline replaces
#     this skeleton with the real spctl/stapler + clean-Mac brew/reboot assertion.
#
# Tier: lab (macos-runner + reboot + signing). The real implementation is M7.1.
#
# Usage: K3SM_LAB=1 hack/lab/m7.sh   (pending M7.1 — currently always exits 1)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Lab guard: only run under K3SM_LAB=1 (a real reboot/signing-capable macOS runner). ──
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M7-lab gate: PENDING (macos-runner + reboot + signing). This lab gate needs K3SM_LAB=1 + real reboot-capable, Developer-ID-signing hardware; this is NOT a pass."
	exit 0
fi

# ── K3SM_LAB=1: the real gate is owned by M7.1; this skeleton cannot prove it. ──
echo "M7-lab gate: NOT YET IMPLEMENTED — the real M7-lab (spctl/stapler + clean-Mac brew install → Ready → reboot → Ready) gate is owned by M7.1; this skeleton cannot prove the milestone." >&2
echo "             (under K3SM_LAB=1 this exits 1 by design so /orchestrate never fake-greens M7-lab/M4-lab from a placeholder; repo root: $REPO_ROOT)" >&2
exit 1
