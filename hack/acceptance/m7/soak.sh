#!/usr/bin/env bash
#
# k3sm M7.0 sub-gate — B28 watch-staleness churn soak — SKELETON ONLY
# (always RED until real).
#
# # K3SM-SKELETON
#
# The B28 dev-mac churn variant of the single-node watch-staleness soak (kine
# ConsistentListFromCache posture), run in the M7 tail against the M7.1 kine >=0.16.x
# single-pin which carries the WatchProgress fix (Res. 12). It is a deliberately
# non-glob-colliding path — hack/acceptance/m7/soak.sh, NOT hack/lab/m1-soak.sh which
# would trip the orphan glob — so it needs no phases.json row of its own and is
# invoked out-of-band in M7.0 (M4's `done` flip excludes it).
#
# The REAL soak (per docs/m7-plan.md §M7.0 + the validation-debt table) drives a
# single-node cluster under object churn and asserts consistent-LIST staleness stays
# bounded across the new kine pin. NONE of that exists yet.
#
# Honesty contract: a CI-runnable soak skeleton → exit non-zero UNCONDITIONALLY
# (Res. 2), so an unbuilt soak can never be read as "B28 proven".
set -euo pipefail
echo "M7.0 soak.sh gate: NOT YET IMPLEMENTED — the real B28 churn soak (single-node consistent-LIST staleness under churn, against the M7.1 kine >=0.16.x pin) is unbuilt; this skeleton is always RED (Res. 2/12)." >&2
exit 1
