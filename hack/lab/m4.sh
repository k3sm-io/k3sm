#!/usr/bin/env bash
#
# k3sm M4-lab gate — SKELETON ONLY (reboot-survival placeholder).
#
# This is the M4-lab row in hack/acceptance/phases.json (gate hack/lab/m4.sh, tier
# lab, requires macos-runner + reboot, manual: true). It is a DELIBERATELY
# UNIMPLEMENTED skeleton: the real M4-lab proof — that a k3sm node and its native
# pods survive a host reboot, restarted from the installed launchd jobs — is owned
# by backlog item B35 and is NOT performed here. This file exists so the manifest's
# gate path resolves (hack/acceptance/phases_test.go) and so /orchestrate has a
# runnable referent under K3SM_LAB=1, not so it can prove the milestone.
#
# Honesty contract (why each branch exits the way it does):
#   - K3SM_LAB unset / != 1 (the common case, incl. CI): this gate is NOT on a real
#     reboot rig, so it prints a PENDING notice and exits 0 — a "skip", which
#     /orchestrate reports as "pending lab" and NEVER counts as a proven milestone
#     (mirrors hack/lab/m3.sh and hack/lab/m6.sh).
#   - K3SM_LAB == 1 (a real lab run is being attempted): this placeholder CANNOT
#     prove reboot-survival, so it exits 1 (RED) rather than 0. An exit 0 here would
#     be read by /orchestrate as "M4-lab proven" and fake-green the milestone; the
#     gate therefore stays RED until B35 replaces this skeleton with the real
#     reboot-survival assertion.
#
# Tier: lab (macos-runner + reboot). The real implementation is B35.
#
# Usage: K3SM_LAB=1 hack/lab/m4.sh   (pending B35 — currently always exits 1)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Lab guard: only run under K3SM_LAB=1 (a real reboot-capable macOS runner). ──
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M4-lab gate: PENDING (macos-runner + reboot). This lab gate needs K3SM_LAB=1 + real reboot-capable hardware; this is NOT a pass."
	exit 0
fi

# ── K3SM_LAB=1: the real gate is owned by B35; this skeleton cannot prove it. ───
echo "M4-lab gate: NOT YET IMPLEMENTED — the real M4-lab (reboot-survival) gate is owned by B35; this skeleton cannot prove the milestone." >&2
echo "             (under K3SM_LAB=1 this exits 1 by design so /orchestrate never fake-greens M4-lab from a placeholder; repo root: $REPO_ROOT)" >&2
exit 1
