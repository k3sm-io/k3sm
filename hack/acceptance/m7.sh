#!/usr/bin/env bash
#
# k3sm M7 umbrella gate — release-engineering pipeline — SKELETON ONLY
# (always RED until real).
#
# # K3SM-SKELETON
#
# This is the M7 row in hack/acceptance/phases.json (gate hack/acceptance/m7.sh,
# tier integration, requires dev-mac + network, manual: false, skeleton: true). It
# is the SINGLE canonical umbrella gate for M7: it execs the sub-gates
# hack/acceptance/m7/{ci,docs,hygiene}.sh (Res. 5), which live
# in a subdirectory OUTSIDE the m[0-9]*.sh orphan glob so the one-canonical-gate
# contract holds without glob surgery. Running the sub-gates here is what forward-
# checks them (they have no phases.json row of their own).
#
# The REAL M7 proof additionally asserts a goreleaser
# snapshot build, bidirectional codesign entitlement asserts (server carries exactly
# the JIT/unsigned-exec-memory/library-validation trio; k3sm-netd carries NONE), a
# formula render, the four-repo sibling-layout assert, and a kine-nocgo dep-lint.
# NONE of that exists yet.
#
# Honesty contract (Res. 2): a manual:false CI-runnable gate skeleton MUST exit
# non-zero UNCONDITIONALLY until real — the gate is run directly and its exit 0 is
# trusted, so the hack/lab/*.sh K3SM_LAB-unset→exit-0 pattern would falsely pass the
# M7 milestone. This gate is pinned always-RED by TestNonManualSkeletonsAlwaysRed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "M7 umbrella gate: NOT YET IMPLEMENTED — running the m7/ sub-gate skeletons, each always RED (Res. 2); the real release-engineering pipeline gate is unbuilt." >&2

# Exec each sub-gate so the umbrella transitively forward-checks them (Res. 5). Every
# sub-gate is an always-RED skeleton today, so the umbrella stays RED regardless.
rc=0
for sub in ci docs hygiene; do
	if ! bash "$HERE/m7/$sub.sh"; then
		rc=1
	fi
done

if [ "$rc" -eq 0 ]; then
	# Defensive: the sub-gates are always-RED skeletons, so this branch is
	# unreachable today; if it is ever reached, the umbrella is NOT yet a real
	# proof and must still fail until this skeleton is replaced.
	echo "M7 umbrella gate: sub-gates unexpectedly passed, but the umbrella is still a skeleton — forcing RED (Res. 2)." >&2
fi
exit 1
