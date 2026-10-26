#!/usr/bin/env bash
#
# k3sm M19 lab gate — the wasm RuntimeClass on the lab host.
# — SKELETON (an honest placeholder; the real ladder is not written yet).
#
# # K3SM-SKELETON
#
# Row in hack/acceptance/phases.json:
#   M19-lab  gate hack/lab/m19.sh, tier lab, requires dev-mac and network, manual: true, skeleton: true
#
# THE LADDER (from the gates listed below; this file asserts NONE of it yet):
#   1  preflight   the k3sm.io/wasm label is present, the class is provisioned, the helper is signed
#   2  hello       a WASI module runs; the exit code propagates and logs --tail shows its output
#   3  http        a component serves wasi:http through a ClusterIP and cluster DNS
#   4  pull        the positive wasi/wasm32 pull beside the linux/arm64 negative
#   5  oom         a container over its memory limit reports OOMKilled from the sampler
#   6  confine     the guest cannot read another pod's directory or /Users by ../ or an absolute path
#   7  policy      the signature-policy negative: wasm under require-signed is refused
#   8  refusals    exec probes, exec lifecycle hooks and a mixed native/wasm pod are refused
#   9  logs        logs --previous works across a container restart
#   10 attach      non-interactive attach, port-forward and top work
#   11 kickstart   a wasm pod survives launchctl kickstart -k io.k3sm.agent
#   12 skew        a new server with an old worker: the pod stays Pending, no crash
#   13 rollback    drain, revert: pods are Pending, not crash-looping
#   14 footprint   the per-pod footprint is recorded
# The run log will carry the M11 header (gate, artifact sha256, per-repo git SHA, result).
#
# Honesty contract (TestLabSkeletonHonesty, manual:true ∧ skeleton:true): under no K3SM_LAB
# this exits 0 saying PENDING — a skip, NOT a pass; under K3SM_LAB=1 it exits non-zero,
# because a placeholder that greened on the lab host would falsely pass a milestone whose real
# proof is still owed. The ladder replaces this body and flips skeleton to false in the SAME change.
set -euo pipefail
case "${1:-}" in
	"") ;;
	-h|--help) echo "usage: $0   (no arguments: the full M19 ladder)"; exit 0 ;;
	*) echo "$0: unknown argument $1 (expected no arguments)" >&2; exit 2 ;;
esac
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M19-lab gate: PENDING (dev-mac, network). The wasm RuntimeClass ladder needs K3SM_LAB=1 and the lab host, and this script is a skeleton: its ladder is not written yet. This is NOT a pass."
	exit 0
fi
echo "M19-lab gate: NOT YET IMPLEMENTED — the wasm RuntimeClass ladder is not written yet (listed below). This is a skeleton and MUST be red under K3SM_LAB=1."
exit 1
