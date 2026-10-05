#!/usr/bin/env bash
#
# k3sm M17 RDMA gate — S6 and the jaccl leg, RDMA over Thunderbolt 5.
# — SKELETON (an honest placeholder; RECORDED-only until a Thunderbolt 5 rig exists).
#
# # K3SM-SKELETON
#
# Row in hack/acceptance/phases.json:
#   M17-rdma  gate hack/lab/m17-rdma.sh, tier lab, requires thunderbolt5 + rdma,
#             manual: true, skeleton: true
#
# WHAT THE REAL GATE WILL ASSERT (the M17 plan §Gates and §Sub-phases S6), on two
# Thunderbolt 5 Macs with RDMA enabled in macOS Recovery (rdma_ctl enable — a human
# step nothing can automate):
#   S6.1  ibv_devices and rdma_ctl status, run as the _k3sm service user
#   S6.2  the exact iokit-user-client-class librdma opens (the sandbox grant's input)
#   S6.3  a JACCL all_sum between the two Macs
#   S6.4  the RDMA GID table matches the /32 link address on each port
#   jaccl a sharded MLXModel with backend: jaccl serves through rank 0, with its
#         measured tokens/s
#
# NO PASS WITHOUT A MEASUREMENT: this script never prints a PASS-shaped line unless it
# has a measured RDMA figure in hand. No such figure exists here, so it cannot pass.
# Under K3SM_LAB=1 on a Mac without RDMA it reports RECORDED "pending, no TB5 rig"
# (exit 2: neither a pass nor a FAIL).
#
# Honesty contract (TestLabSkeletonHonesty, manual:true ∧ skeleton:true): under no
# K3SM_LAB this exits 0 saying PENDING — a skip, NOT a pass; under K3SM_LAB=1 it exits
# non-zero, so the row can never be read as proven.
set -euo pipefail
case "${1:-}" in
	"") ;;
	-h|--help) echo "usage: $0   (no arguments: S6 and the jaccl leg)"; exit 0 ;;
	*) echo "$0: unknown argument $1 (expected no arguments)" >&2; exit 2 ;;
esac
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M17-rdma gate: PENDING (thunderbolt5 + rdma). RDMA over Thunderbolt needs K3SM_LAB=1 and two Thunderbolt 5 Macs with RDMA enabled in macOS Recovery, and this script is a skeleton. This is NOT a pass."
	exit 0
fi
# No code path below measures an RDMA figure, so no code path below may pass.
echo "M17-rdma gate: RECORDED — pending, no TB5 rig. No RDMA figure was measured (S6 and the jaccl leg are not implemented, and no Thunderbolt 5 Mac with RDMA enabled is attached). This is NOT a pass."
exit 2
