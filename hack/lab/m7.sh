#!/usr/bin/env bash
#
# k3sm M7-lab gate — release-artifact reboot/brew survival — SKELETON ONLY.
#
# This is the M7-lab row in hack/acceptance/phases.json (gate hack/lab/m7.sh, tier
# lab, requires macos-runner + reboot + signing, manual: true, skeleton: true). It
# also backs the RE-POINTED M4-lab row: the reboot-survival proof needs the signed
# brew/pkg artifact, so the ex-M4-lab reboot debt now runs here in the M7 tail (the
# old hack/lab/m4.sh skeleton is deleted in this same change).
#
# The REAL M7-lab proof uses real Developer-ID certs:
# spctl/stapler validate the notarized artifacts, then a clean-Mac `brew install` →
# `sudo k3sm install` → cluster Ready → reboot → Ready (launchd survival), greening
# the transferred M4.0 acceptance AND the ex-M4-lab reboot debt in one run. NONE of
# that exists yet.
#
# Honesty contract (why each branch exits the way it does; mirrors hack/lab/m5.sh):
#   - K3SM_LAB unset / != 1 (the common case, incl. CI): this gate is NOT on a real
#     reboot/signing rig, so it prints a PENDING notice and exits 0 — a "skip",
#     reported as "pending lab" and NEVER counted as a proven milestone.
#   - K3SM_LAB == 1 (a real lab run is being attempted): this placeholder CANNOT
#     prove reboot/brew survival, so it exits 1 (RED) rather than 0. An exit 0 here
#     would be read as "M7-lab/M4-lab proven" and falsely pass the milestone; the
#     gate therefore stays RED until the signing/notarization pipeline replaces this
#     skeleton with the real spctl/stapler + clean-Mac brew/reboot assertion.
#
# Tier: lab (macos-runner + reboot + signing). The real implementation is the
# signing/notarization slice.
#
# Usage: K3SM_LAB=1 hack/lab/m7.sh   (pending — currently always exits 1)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Lab guard: only run under K3SM_LAB=1 (a real reboot/signing-capable macOS runner). ──
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M7-lab gate: PENDING (macos-runner + reboot + signing). This lab gate needs K3SM_LAB=1 + real reboot-capable, Developer-ID-signing hardware; this is NOT a pass."
	exit 0
fi

# ── K3SM_LAB=1: the real gate is owned by the signing slice; this skeleton cannot prove it. ──
echo "M7-lab gate: NOT YET IMPLEMENTED — the real M7-lab (spctl/stapler + clean-Mac brew install → Ready → reboot → Ready) gate is owned by the signing/notarization slice; this skeleton cannot prove the milestone." >&2
echo "             (under K3SM_LAB=1 this exits 1 by design so the gate fails closed rather than falsely passing M7-lab/M4-lab from a placeholder; repo root: $REPO_ROOT)" >&2
exit 1
