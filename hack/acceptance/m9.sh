#!/usr/bin/env bash
#
# k3sm M9 gate — Launch pre-flight — SKELETON ONLY (honesty contract).
#
# This is the M9 row in hack/acceptance/phases.json (gate hack/acceptance/m9.sh, tier
# lab, requires dev-mac, manual: true, skeleton: true). M9 is the public flip / site
# go-live / v0.1.0 tag / announcement (docs/m7-plan.md §Scope + the m9-plan doc). Its
# gate is a machine PRE-FLIGHT that enumerates the launch-blocking gate set from the
# validation-debt disposition table (m2/m3/m4 dev-mac, hack/lab/m3.sh two-Mac,
# hack/lab/m7.sh reboot/brew, the B28 soak, m8.sh MLX) and confirms each is green at
# the flip SHA. NONE of that enumeration exists yet — it is encoded via m9-plan.
#
# Honesty contract (mirrors hack/lab/m5.sh; TestLabSkeletonHonesty pins it):
#   - K3SM_LAB unset / != 1 (the common case, incl. CI): this pre-flight is NOT being
#     run against a real launch-candidate, so it prints a PENDING notice and exits 0 —
#     a "skip", which /orchestrate reports as "pending lab" and NEVER counts as
#     "launch cleared".
#   - K3SM_LAB == 1 (a real launch pre-flight is being attempted): this placeholder
#     CANNOT enumerate/verify the launch-blocking gate set, so it exits 1 (RED) rather
#     than 0. An exit 0 here would be read by /orchestrate as "M9 launch cleared" and
#     fake-green the flip; the gate therefore stays RED until the m9-plan pre-flight
#     replaces this skeleton.
#
# Tier: lab (dev-mac). The real implementation is encoded via docs/m9-plan.md.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Lab guard: only run under K3SM_LAB=1 (a real launch-candidate pre-flight). ──
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M9 gate: PENDING (launch pre-flight). This gate needs K3SM_LAB=1 + a real launch candidate; it enumerates the launch-blocking gate set and is NOT a pass."
	exit 0
fi

# ── K3SM_LAB=1: the real pre-flight is owned by m9-plan; this skeleton cannot prove it. ──
echo "M9 gate: NOT YET IMPLEMENTED — the real M9 launch pre-flight (enumerate + verify the launch-blocking gate set at the flip SHA) is owned by docs/m9-plan.md; this skeleton cannot clear launch." >&2
echo "         (under K3SM_LAB=1 this exits 1 by design so /orchestrate never fake-greens M9 from a placeholder; repo root: $REPO_ROOT)" >&2
exit 1
