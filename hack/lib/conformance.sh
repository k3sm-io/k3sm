#!/usr/bin/env bash
# conformance.sh — the NON-VACUOUS conformance-gate guard shared by the milestone
# gates (hack/acceptance/m2.sh, hack/acceptance/m3.sh, hack/lab/m3.sh).
#
# It runs the build-tagged per-criterion e2e tests (e2e/, //go:build e2e) for a
# milestone slice and asserts that EVERY required criterion shows a top-level
# `--- PASS: TestM<n>_<Criterion>` AND that NONE is `--- SKIP:`. This closes the
# two false-greens of the old `-run TestM<n>` guard, which greened on:
#   - PARTIAL coverage (1 of N criteria present + passing), and
#   - ALL-SKIP (every criterion t.Skip'd still prints the `ok` package line).
# A missing, failed, or skipped REQUIRED criterion turns the slice RED. Deferred
# criteria (authored as t.Skip'd TODO tests) are simply absent from the required
# list, so their skip is allowed and visible — the required set is the checklist
# of record.
#
# k3sm is CGO_ENABLED=1 from M1 (kine → mattn/go-sqlite3), so the e2e invocation is
# pinned CGO_ENABLED=1 here. $KUBECONFIG must point at the running cluster.

# run_conformance_slice <repo_root> <run_regex> <timeout> <crit1> [crit2 ...]
#   <run_regex>  the `go test -run` pattern selecting the slice (e.g. TestM2, or
#                'TestM3_(NodePort|PVCPersistsAcrossRestart)$' to scope to the
#                single-node-testable criteria).
#   <crit...>    the REQUIRED criteria WITHOUT the "Test" prefix (e.g.
#                M2_ConfigMapMount); each must PASS, none may SKIP.
# Prints an indented test log + a per-criterion ladder. Returns 0 iff every
# required criterion passed (and the suite exited 0).
run_conformance_slice() {
	local repo_root="$1" run_regex="$2" timeout="$3"
	shift 3
	local crits=("$@")
	local out rc=0
	# -count=1 DISABLES go's test-result cache: these e2e criteria talk to a live
	# cluster (state go cannot track), so a cached result would silently replay a
	# STALE run — greening (or reddening) against code + a cluster that no longer
	# exist. Every conformance slice MUST re-run against the running cluster.
	out="$(cd "$repo_root" && CGO_ENABLED=1 go test -tags e2e -count=1 -run "$run_regex" -timeout "$timeout" -v ./e2e/... 2>&1)" || rc=1
	printf '%s\n' "$out" | sed 's/^/    /'

	# A vacuous run (the -run pattern matched nothing) is RED, never green.
	if printf '%s\n' "$out" | grep -qE 'no tests to run|warning: no tests to run'; then
		echo "  RED  conformance VACUOUS: -run '$run_regex' matched no tests (criterion set not authored)"
		return 1
	fi

	local crit name fail=0
	for crit in "${crits[@]}"; do
		name="Test${crit}"
		if printf '%s\n' "$out" | grep -qE "^--- SKIP: ${name} \("; then
			echo "  RED  ${name}: SKIPPED (expected PASS — feature missing or precondition unmet)"
			fail=1
		elif printf '%s\n' "$out" | grep -qE "^--- PASS: ${name} \("; then
			echo "  PASS ${name}"
		else
			echo "  RED  ${name}: no top-level PASS (failed, errored, or not authored)"
			fail=1
		fi
	done
	if [ "$rc" -ne 0 ]; then
		echo "  RED  go test exited $rc (a non-required test failed or the suite errored)"
		fail=1
	fi
	return "$fail"
}
