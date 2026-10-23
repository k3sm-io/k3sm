#!/usr/bin/env bash
#
# k3sm docs sub-gate — user docs — SKELETON ONLY (always RED until real).
#
# # K3SM-SKELETON
#
# A sub-gate of the M7 umbrella (hack/acceptance/m7.sh execs it); it lives under
# hack/acceptance/m7/ outside the m[0-9]*.sh orphan glob, so it carries no
# phases.json row of its own.
#
# The REAL docs gate asserts: the docs/user/ page
# manifest, a hermetic link-check, yaml-applies (every examples/ manifest applies
# against a schema check), and a stale-string denylist seeded from the known
# offenders ("Pre-M0", "private development"). The network-tier external-link job is
# split out of the hermetic gate. NONE of that exists yet.
#
# Honesty contract: manual:false skeleton → exit non-zero UNCONDITIONALLY.
set -euo pipefail
echo "docs.sh gate: NOT YET IMPLEMENTED — the real user-docs gate (page manifest + hermetic link-check + yaml-applies + stale-string denylist) is unbuilt; this skeleton is always RED." >&2
exit 1
