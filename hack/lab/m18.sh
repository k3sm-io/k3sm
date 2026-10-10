#!/usr/bin/env bash
#
# k3sm M18 lab gate — the lifecycle CLI and the macOS app on the two lab Macs.
# — SKELETON (an honest placeholder; the real ladder lands with M18.4 and M18.5).
#
# # K3SM-SKELETON
#
# Row in hack/acceptance/phases.json:
#   M18-lab  gate hack/lab/m18.sh, tier lab, requires two-macs, manual: true, skeleton: true
#
# THE LADDER (from the M18 plan §Gates; this file asserts NONE of it yet):
#   1  worker-stop   stop the worker: cordoned, no process, no alias, stoppedBy; pods reschedule
#   2  worker-start  start the worker: Ready, uncordoned, mesh back
#   3  server-stop   stop the server with a joined worker: the warning, the control plane down
#   4  server-start  start the server: workers reconverge their mesh with no operator action
#   5  install-stop  an install on a stopped node leaves it stopped; --start starts it
#   6  update-order  the in-app Update is refused on the server before every worker is updated
#   7  channels      curl channel then app update; app channel then CLI uninstall
#   8  helper        the lifecycle helper refuses a non-admin caller and an unsigned client
#   9  auto-stop     an untrusted network stops the node after the debounce; an unknown
#                    identity does nothing; a trusted network offers Start, never starts
#   10 join          the copied join command joins a worker within its TTL
# The run log will carry the M11 header (gate, artifact sha256, per-repo git SHA, result).
#
# Honesty contract (TestLabSkeletonHonesty, manual:true ∧ skeleton:true): under no K3SM_LAB
# this exits 0 saying PENDING — a skip, NOT a pass; under K3SM_LAB=1 it exits non-zero,
# because a placeholder that greened on the rig would falsely pass a milestone whose real
# proof is still owed. The ladder replaces this body and flips skeleton to false in the SAME change.
set -euo pipefail
case "${1:-}" in
	"") ;;
	-h|--help) echo "usage: $0   (no arguments: the full M18 ladder)"; exit 0 ;;
	*) echo "$0: unknown argument $1 (expected no arguments)" >&2; exit 2 ;;
esac
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M18-lab gate: PENDING (two-macs). The lifecycle and app ladder needs K3SM_LAB=1 and the two lab Macs, and this script is a skeleton: its ladder lands with M18.4 and M18.5. This is NOT a pass."
	exit 0
fi
echo "M18-lab gate: NOT YET IMPLEMENTED — the lifecycle and app ladder lands with M18.4 and M18.5 (the M18 plan §Gates). This is a skeleton and MUST be red under K3SM_LAB=1."
exit 1
