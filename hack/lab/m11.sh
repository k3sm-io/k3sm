#!/usr/bin/env bash
#
# k3sm M11 lab gate — Linux containers & multi-arch on the vm path — SKELETON ONLY
# (honesty contract).
#
# This script backs TWO rows in hack/acceptance/phases.json, and the distinction is
# load-bearing:
#
#   M11-core  gate hack/lab/m11.sh, args ["--core"], tier lab, manual: true,
#             requires dev-mac + vz + network. The LAUNCH row: the functional-
#             EXPERIMENTAL vm path both arches must demonstrate before v0.1 ships.
#   M11-lab   gate hack/lab/m11.sh (NO args), tier lab, manual: true,
#             requires vz + network. The FULL B109 ledger — every vm-path leg.
#
# --core is a STRICT SUBSET. A green --core run NEVER satisfies M11-lab; the two rows
# exist precisely so a launch-blocking subset cannot be mistaken for the whole ledger,
# and that is why the mode is a parsed argument rather than an environment nudge.
#
# Both rows are skeleton: true today. The real legs are a later hardware wave; this
# file exists so the manifest's gate path resolves (hack/acceptance/phases_test.go),
# so the release process has a runnable referent under K3SM_LAB=1, and so the
# hack/lab/runs/ evidence convention has a declared emitter — NOT so it can prove
# anything.
#
# Honesty contract (why each branch exits the way it does):
#   - K3SM_LAB unset / != 1 (the common case, incl. CI): this gate is NOT on a real
#     VZ-capable rig, so it prints a PENDING notice and exits 0 — a "skip",
#     reported as "pending lab" and NEVER counted as a proven milestone
#     (mirrors hack/lab/m3.sh, hack/lab/m5.sh, hack/lab/m6.sh, hack/lab/m10.sh).
#   - K3SM_LAB == 1 (a real lab run is being attempted): this placeholder CANNOT
#     prove the vm path, so it emits a run-log header recording result: FAIL and
#     exits 1 (RED) rather than 0. An exit 0 here would be read as "M11 proven" and
#     falsely pass the milestone.
#
# Usage:
#   K3SM_LAB=1 hack/lab/m11.sh --core | tee hack/lab/runs/m11-core-<rc-tag>-<UTCdate>.log
#   K3SM_LAB=1 hack/lab/m11.sh        | tee hack/lab/runs/m11-lab-<rc-tag>-<UTCdate>.log
# See hack/lab/runs/README.md for the evidence convention this header implements.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Mode parsing: --core selects the launch subset; bare selects the full ledger. ──
# An unknown flag is REJECTED rather than ignored, so a typo ("--cores") can never be
# silently downgraded into a full-ledger run whose log then claims the wrong scope.
MODE="full"
GATE_NAME="M11-lab"
while [ "$#" -gt 0 ]; do
	case "$1" in
	--core)
		MODE="core"
		GATE_NAME="M11-core"
		;;
	-h | --help)
		echo "usage: $0 [--core]   (--core = the launch subset; no args = the full B109 ledger)"
		exit 0
		;;
	*)
		echo "$0: unknown argument $1 (expected --core or no arguments)" >&2
		exit 2
		;;
	esac
	shift
done

# ── The hack/lab/runs/ run-log header (README.md documents the convention). ─────────
# Four fields are REQUIRED of every k3sm lab run log, and this is the one emitter:
#   gate            which gate row this log is evidence for (M11-core vs M11-lab)
#   artifact_sha256 the sha256 of the artifact under test — "local:<sha>" for a
#                   developer build, the bare rc sha for the release-candidate run
#                   that alone satisfies an rc-artifact-bound ledger row
#   git_sha.<repo>  the per-repo commit each of the four modules was built from
#   result          PASS or FAIL — the verdict, recorded in the log itself
emit_run_log_header() {
	local result="$1"
	echo "# k3sm lab run log"
	echo "gate: ${GATE_NAME}"
	echo "mode: ${MODE}"
	echo "rc_tag: ${K3SM_RC_TAG:-none}"
	echo "artifact_sha256: $(artifact_sha256)"
	local repo
	for repo in apis runtimed darwin-net k3sm; do
		echo "git_sha.${repo}: $(repo_git_sha "$repo")"
	done
	echo "started_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "result: ${result}"
}

# artifact_sha256 reports the sha256 of the k3sm binary under test. K3SM_ARTIFACT names
# it; an unset or absent artifact reports "unknown" rather than an empty field, because a
# blank evidence line reads as "recorded nothing" and is indistinguishable from a
# truncated log.
artifact_sha256() {
	local artifact="${K3SM_ARTIFACT:-}"
	if [ -n "$artifact" ] && [ -f "$artifact" ]; then
		local sum
		sum="$(shasum -a 256 "$artifact" | cut -d' ' -f1)"
		if [ -n "${K3SM_RC_TAG:-}" ]; then
			echo "$sum"
		else
			echo "local:${sum}"
		fi
		return
	fi
	echo "unknown"
}

# repo_git_sha reports one sibling module's HEAD commit, or "unknown" when that repo is
# not checked out beside this one. It never fails the run: a missing sibling is an
# evidence gap to record, not a reason to abort a lab leg mid-flight.
repo_git_sha() {
	local repo="$1" dir
	if [ "$repo" = "k3sm" ]; then
		dir="$REPO_ROOT"
	else
		dir="$REPO_ROOT/../$repo"
	fi
	if [ -e "$dir/.git" ] && git -C "$dir" rev-parse HEAD >/dev/null 2>&1; then
		git -C "$dir" rev-parse HEAD
		return
	fi
	echo "unknown"
}

# ── Lab guard: only run under K3SM_LAB=1 (a real VZ-capable macOS host). ───────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	if [ "$MODE" = "core" ]; then
		echo "${GATE_NAME} gate: PENDING (dev-mac + vz + network). The launch subset of the vm path (--core) needs K3SM_LAB=1 + a real VZ-capable Mac; this is NOT a pass."
	else
		echo "${GATE_NAME} gate: PENDING (vz + network). The FULL B109 vm-path ledger needs K3SM_LAB=1 + a real VZ-capable Mac; a --core green does not satisfy it. This is NOT a pass."
	fi
	exit 0
fi

# ── K3SM_LAB=1: the real legs are a later hardware wave; this cannot prove them. ───
emit_run_log_header FAIL
echo "${GATE_NAME} gate: NOT YET IMPLEMENTED — the real M11 vm-path legs (mode: ${MODE}) are owned by a later hardware wave; this skeleton cannot prove the milestone." >&2
echo "         (under K3SM_LAB=1 this exits 1 by design so the gate fails closed rather than falsely passing ${GATE_NAME} from a placeholder; repo root: $REPO_ROOT)" >&2
exit 1
