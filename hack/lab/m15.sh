#!/usr/bin/env bash
#
# k3sm M15 lab gate — the container-vm RuntimeClass on a real VZ-capable Mac.
# — SKELETON (an honest placeholder; the real ladder lands with M15.3).
#
# # K3SM-SKELETON
#
# Rows in hack/acceptance/phases.json:
#   M15-core  gate hack/lab/m15.sh, args ["--core"], tier lab, manual: true, skeleton: true
#   M15-lab   gate hack/lab/m15.sh,                  tier lab, manual: true, skeleton: true
#
# --core is a STRICT SUBSET (rungs 1-9). A green --core run NEVER satisfies M15-lab.
#
# THE LADDER (written by M15.3 from the M15 plan §Gates; this file asserts NONE of it yet):
#   1 preflight   k3sm.io/container-vm label present; the RuntimeClass provisioned; the
#                 capability probe never consulted any container CLI (a negative assertion)
#   2 boot        uname -sm = Linux aarch64 AND uname -r = the pinned kernel string
#                 (never /proc/1/comm: PID 1 inside the container is the workload)
#   3 logs        marker returned; --tail=N returns exactly N
#   4 exec        exit 42 propagates 42
#   5 workload    a published image whose entrypoint is a bare name
#   6 storage     PVC survives a SIGKILL of the helper
#   7 network     in-guest lease, cluster DNS, ClusterIP reach
#   8 amd64       an amd64-only image FAILS and names the mismatch (NEGATIVE)
#   9 footprint   recorded, never failing
#   10 service / 11 logs -f / 12 /stats/summary / 13 Attach semantics / 14 the live
#                 cross-backend segment measurement — FULL only
#
# Honesty contract (TestLabSkeletonHonesty, manual:true ∧ skeleton:true): under no K3SM_LAB
# this exits 0 saying PENDING — a skip, NOT a pass; under K3SM_LAB=1 it exits non-zero,
# because a placeholder that greened on a lab host would falsely pass a milestone whose
# real proof is still owed. M15.3 replaces this body and flips skeleton to false in the
# SAME change (the M11 plan's R27).
set -euo pipefail
MODE=full
case "${1:-}" in
	--core) MODE=core ;;
	"") ;;
	-h|--help) echo "usage: $0 [--core]   (--core = the launch subset; no args = the full ledger)"; exit 0 ;;
	*) echo "$0: unknown argument $1 (expected --core or no arguments)" >&2; exit 2 ;;
esac
GATE_NAME="M15-lab"; [ "$MODE" = core ] && GATE_NAME="M15-core"
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "${GATE_NAME} gate: PENDING (dev-mac + vz + network). The container-vm path needs K3SM_LAB=1 + a real VZ-capable Mac, and this script is a skeleton: its ladder lands with M15.3. This is NOT a pass."
	exit 0
fi
echo "${GATE_NAME} gate: NOT YET IMPLEMENTED — the container-vm ladder lands with M15.3 (the M15 plan §Gates). This is a skeleton and MUST be red under K3SM_LAB=1."
exit 1
