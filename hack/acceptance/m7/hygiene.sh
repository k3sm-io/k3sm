#!/usr/bin/env bash
#
# k3sm M7.5 sub-gate — public-flip hygiene & security scrub — SKELETON ONLY
# (always RED until real).
#
# # K3SM-SKELETON
#
# A sub-gate of the M7 umbrella (hack/acceptance/m7.sh execs it); it lives under
# hack/acceptance/m7/ outside the m[0-9]*.sh orphan glob (Res. 5), so it carries no
# phases.json row of its own.
#
# The REAL M7.5 gate asserts: a scan-clean result (zero
# unresolved trufflehog --only-verified findings against the reviewed rotated-
# credentials baseline — Res. 15), MAINTAINERS/SECURITY content asserts, a
# repo-settings drift check, and per-repo NOTICE verification. NONE of that exists
# yet.
#
# Honesty contract: manual:false skeleton → exit non-zero UNCONDITIONALLY (Res. 2).
set -euo pipefail
echo "M7.5 hygiene.sh gate: NOT YET IMPLEMENTED — the real public-flip hygiene gate (scan-clean + MAINTAINERS/SECURITY + repo-settings drift + NOTICE) is unbuilt; this skeleton is always RED (Res. 2)." >&2
exit 1
