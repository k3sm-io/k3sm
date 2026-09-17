#!/usr/bin/env bash
#
# k3sm M16 gate — the MLX serving fleet: an upstream-compatible inference control
# plane over native MLX workers — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M16 row in hack/acceptance/phases.json (gate hack/acceptance/m16.sh,
# tier integration, requires dev-mac + apple-gpu + vz + network, manual: false,
# skeleton: true). There is deliberately no lab row beside it: the whole ladder
# runs on ONE Mac that hosts its own single-node k3sm server, so a GPU dev-mac with
# Virtualization covers the proof. The M16 plan's single-slot branch is the only
# branch that would add an M16-lab row, and M16.5 writes it in the same change that
# replaces this body.
#
# The REAL M16 gate is a COMPOSITE — a ten-rung ladder over a running cluster, and
# NONE of it exists here yet:
#
#   m16.0   preflight    a GPU node, the vm RuntimeClass, the examples on disk, and
#                        the MIRROR DIGESTS resolving (digests, never tags).
#   m16.1   install      the pinned chart: nine CRDs Established, the operator Ready
#                        as a vm Pod, memory requests present on operator+frontend.
#   m16.1b  rbac         the operator ClusterRole re-asserted LIVE against the
#                        pinned grant (no wildcard verb/resource, no stray secrets).
#   m16.2   conversion   a v1alpha1 read of a v1beta1 object answers through the
#                        conversion webhook's ClusterIP. Its proof already exists,
#                        as the two e2e tests the plan's R14 names — they carry no
#                        TestM16 prefix by design, so this rung selects them with
#                        the -run pattern verbatim:
#                          go test -tags e2e -run '^Test(Admission|Conversion)WebhookDeliveryThroughProxy$' -timeout 20m ./e2e/
#                        TestAdmissionWebhookDeliveryThroughProxy covers the
#                        operator's OTHER service-referenced webhook (validating
#                        admission) over the same path; both back a vm Pod.
#   m16.3   worker       fleet.yaml applied, the worker Running, mlx.k3sm.io/gpu in
#                        requests == limits and memory request == limit.
#   m16.4   discovery    the worker is named in the discovery metadata.
#   m16.5   models       GET /v1/models through the frontend's ClusterIP.
#   m16.6   completion   a chat completion through the ClusterIP inside a PLACEHOLDER
#                        budget (TTFT <= 3x and tok/s >= 0.5x the hack/acceptance/m8.sh
#                        direct figure ON THE SAME MACHINE), with per-hop timing
#                        recorded — a measured-but-unbounded metric is documentation,
#                        not a gate.
#   m16.7   conformance  the backend conformance kit plus the in-process invariants
#                        test (continuous batching, pinned KV).
#   m16.8   routing      two worker replicas on this node, a repeated prefix steered
#                        to the WARM pod, asserted from router metrics AND a measured
#                        TTFT gap. Required; SKIP-class only under the plan's sidecar
#                        substitution, where round-robin is the documented contract.
#   m16.9   deletion     every fleet object gone, zero Terminating, the M8 PVC
#                        untouched.
#   m16.10  restart      launchctl kickstart, re-run m16.1-m16.6, record the time
#                        back to serving — a kickstart kills every vm Pod, so the
#                        restart cost is part of the deploy contract.
#
# Honesty contract: a manual:false CI-runnable gate skeleton MUST exit non-zero
# UNCONDITIONALLY until real — the release process trusts its exit 0 as "milestone
# proven". Pinned always-RED by TestNonManualSkeletonsAlwaysRed, which runs it under
# BOTH K3SM_LAB unset and K3SM_LAB=1.
set -euo pipefail
echo "M16 gate: NOT YET IMPLEMENTED — the real M16 composite gate (the ten-rung ladder m16.0-m16.10: mirror-digest preflight, chart install, live RBAC assertion, CRD conversion, worker guardrails, discovery, /v1/models, a budgeted completion with per-hop timing, the conformance kit, warm-prefix routing across two workers, deletion, and the kickstart re-run) lands with M16.5. This is a skeleton and MUST be red."
exit 1
