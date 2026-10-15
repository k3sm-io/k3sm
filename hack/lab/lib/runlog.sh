#!/usr/bin/env bash
# shellcheck disable=SC2154 # GATE_NAME, MODE and REPO_ROOT are set by the sourcing script
#
# The run-log header and verdict of a k3sm lab run (hack/lab/runs/README.md).
#
# Sourced, never executed (bash 3.2, set -u safe). The sourcing script sets:
#   GATE_NAME   the gate row the log is evidence for
#   MODE        the run's mode
#   REPO_ROOT   the k3sm checkout; the sibling modules sit beside it
# and sources hack/lab/lib/tolerations.sh first (the header carries its
# lab_tolerations_header line). K3SM_ARTIFACT and K3SM_RC_TAG are read from the
# environment.
#
# Functions:
#   emit_run_log_header <result>   the header that opens a run log
#   emit_run_log_verdict <result>  the authoritative verdict that closes it
#   artifact_sha256                the sha256 of the artifact under test
#   repo_git_sha <repo>            one module's HEAD commit

# ── The hack/lab/runs/ run-log header (README.md documents the convention). ─────────
# Four fields are REQUIRED of every k3sm lab run log, and this is the one emitter:
#   gate            which gate row this log is evidence for (M11-core vs M11-lab)
#   artifact_sha256 the sha256 of the artifact under test — "local:<sha>" for a
#                   developer build, the bare rc sha for the release-candidate run
#                   that alone satisfies an rc-artifact-bound ledger row
#   git_sha.<repo>  the per-repo commit each of the four modules was built from
#   result          PASS or FAIL — the verdict, recorded in the log itself
#
# The log OPENS with this header, so its result is necessarily PROVISIONAL: the verdict
# is not known until the legs have run. It is therefore emitted FAIL-CLOSED — a log that
# ends where it was truncated records no pass — and the authoritative verdict is the
# `result:` line emitted by emit_run_log_verdict at the very end. Only the final line is
# a bare PASS/FAIL, so grepping `result: PASS` cannot match the provisional one.
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
	lab_tolerations_header
	echo "result: ${result}"
}

# emit_run_log_verdict closes the log with the AUTHORITATIVE verdict. It is the only
# place a bare "result: PASS" or "result: FAIL" is written.
emit_run_log_verdict() {
	echo "gate: ${GATE_NAME}"
	echo "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "result: $1"
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
