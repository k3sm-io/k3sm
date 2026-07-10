#!/usr/bin/env bash
#
# k3sm M10-lab gate — cross-node per-pod-IP / in-pod SRV/PTR — SKELETON ONLY
# (honesty contract).
#
# This is the M10-lab row in hack/acceptance/phases.json (gate hack/lab/m10.sh, tier
# lab, requires dev-mac + network, manual: true, skeleton: true). It is a DELIBERATELY
# UNIMPLEMENTED skeleton: the real M10-lab proof — that on a multi-node cluster each
# pod carries its own /32 (converged on the runtimed path, darwin-net the sole IPAM
# allocator) and that a headless Service returns all pod IPs with in-pod SRV/PTR
# resolution working through the getaddrinfo-shim res_query extension — is owned by
# M10.1 and is NOT performed here. This file exists so the manifest's gate path
# resolves (hack/acceptance/phases_test.go) and so the release process has a
# runnable referent under K3SM_LAB=1, not so it can prove the milestone.
#
# Honesty contract (why each branch exits the way it does):
#   - K3SM_LAB unset / != 1 (the common case, incl. CI): this gate is NOT on a real
#     multi-node rig, so it prints a PENDING notice and exits 0 — a "skip",
#     reported as "pending lab" and NEVER counted as a proven milestone
#     (mirrors hack/lab/m3.sh, hack/lab/m5.sh, hack/lab/m6.sh).
#   - K3SM_LAB == 1 (a real lab run is being attempted): this placeholder CANNOT
#     prove cross-node per-pod-IP / in-pod SRV/PTR, so it exits 1 (RED) rather than 0.
#     An exit 0 here would be read as "M10-lab proven" and falsely pass the
#     milestone; the gate therefore stays RED until M10.1 replaces this skeleton
#     with the real cross-node per-pod-IP + in-pod SRV/PTR assertion.
#
# Tier: lab (dev-mac + network). The real implementation is M10.1.
#
# Usage: K3SM_LAB=1 hack/lab/m10.sh   (pending M10.1 — currently always exits 1)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Lab guard: only run under K3SM_LAB=1 (a real multi-node macOS rig). ──────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M10-lab gate: PENDING (dev-mac + network). This lab gate needs K3SM_LAB=1 + a real multi-node cluster (cross-node per-pod-IP / in-pod SRV/PTR); this is NOT a pass."
	exit 0
fi

# ── K3SM_LAB=1: the real gate is owned by M10.1; this skeleton cannot prove it. ──
echo "M10-lab gate: NOT YET IMPLEMENTED — the real M10-lab (cross-node per-pod-IP + in-pod SRV/PTR) gate is owned by M10.1; this skeleton cannot prove the milestone." >&2
echo "         (under K3SM_LAB=1 this exits 1 by design so the gate fails closed rather than falsely passing M10-lab from a placeholder; repo root: $REPO_ROOT)" >&2
exit 1
