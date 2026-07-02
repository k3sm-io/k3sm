#!/usr/bin/env bash
#
# k3sm M7.3 sub-gate — user docs — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# A sub-gate of the M7 umbrella (hack/acceptance/m7.sh execs it); it lives under
# hack/acceptance/m7/ outside the m[0-9]*.sh orphan glob (Res. 5), so it carries no
# phases.json row of its own.
#
# The REAL M7.3 gate (per docs/m7-plan.md §M7.3) asserts: the docs/user/ page
# manifest, a hermetic link-check, yaml-applies (every examples/ manifest applies
# against a schema check), and a stale-string denylist seeded from the known
# offenders ("Pre-M0", "private development"). The network-tier external-link job is
# split out of the hermetic gate. NONE of that exists yet.
#
# Honesty contract: manual:false skeleton → exit non-zero UNCONDITIONALLY (Res. 2).
set -euo pipefail
echo "M7.3 docs.sh gate: NOT YET IMPLEMENTED — the real user-docs gate (page manifest + hermetic link-check + yaml-applies + stale-string denylist) is unbuilt; this skeleton is always RED (Res. 2)." >&2
exit 1
