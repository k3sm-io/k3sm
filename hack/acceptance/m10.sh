#!/usr/bin/env bash
#
# k3sm M10 gate: Kubernetes conformance hardening, the composite.
#
# This is the M10 row in hack/acceptance/phases.json (gate hack/acceptance/m10.sh,
# tier integration, requires dev-mac, manual: false). The lab slice (cross-node
# per-pod IP, in-pod SRV/PTR) is the SEPARATE M10-lab row (hack/lab/m10.sh).
#
# It runs every M10 criterion and reports each one PASS, FAIL or SKIP:
#   - the M10 e2e criteria, `go test -tags e2e -run '^TestM10_' ./e2e/`, against the
#     RUNNING cluster in $KUBECONFIG (this gate boots nothing);
#   - the server-side unit gates, pkg/provider TestCreatePodAssignsDistinctPodIP
#     and pkg/netserve TestHeadlessServiceReturnsAllPodIPs.
# `--plan` prints the criterion table. TestM10_PSAEnforceCutover is a SKIP-SPEC: it
# needs a server booted with --psa-enforce-baseline (the human-gated enforce cutover),
# which the harness cannot do per test, so its SKIP is reported and not counted; run
# against such a server with K3SM_PSA_ENFORCE=1 it must PASS like any other.
#
# Exit: 0 when every criterion that is not a skipped SKIP-SPEC PASSED; 1 when any
# FAILED, SKIPPED, or is missing from the run; 2 when a precondition refused the run
# ($KUBECONFIG unset, the cluster not serving, a multi-node cluster with no
# K3SM_E2E_NODE) and nothing was created.
#
# Environment:
#   KUBECONFIG          the admin kubeconfig of the running cluster (required)
#   K3SM_E2E_NODE       the node every criterion pins its pods to; required when the
#                       cluster has more than one node. Run the gate ON that node's Mac:
#                       TestM10_ImagePullSecret serves its registry on this host's loopback.
#   K3SM_WORK_DIR       the server work dir TestM10_AuditLogLevel reads the audit log
#                       from (default /var/lib/k3sm/server); the invoking user must be
#                       able to read it.
#   K3SM_E2E_INGRESS_HTTP_PORT / K3SM_E2E_INGRESS_HTTPS_PORT
#                       the ingress listener ports when the server runs the high-port
#                       listener (default: the canonical Service's http/https ports).
#   K3SM_M10_TIMEOUT    go test -timeout for the e2e run (default 45m; the
#                       CrashLoopBackOff stabilization leg alone needs over 10 minutes).
#
# Usage:  hack/acceptance/m10.sh --plan         # the criterion table; contacts nothing
#         hack/acceptance/m10.sh --self-test    # offline checks of this script
#         KUBECONFIG=<kubeconfig> [K3SM_E2E_NODE=<node>] hack/acceptance/m10.sh [<evidence-dir>]
#             (default evidence dir: a new mktemp directory; the go test logs land there)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# The criterion table: `name|kind|statement`.
#   kind e2e    a TestM10_ criterion in e2e/; it must PASS
#   kind spec   a SKIP-SPEC e2e criterion; a SKIP is reported and not counted, any
#               other result counts like e2e
#   kind <pkg>  a server-side unit gate in ./<pkg>/; it must PASS
CRITERIA=(
	"TestM10_AuditLogLevel|e2e|audit: secret events at level Metadata, no payload at rest, PSA audit annotation"
	"TestM10_PSADefaultWarn|e2e|PSA: a baseline-violating pod is admitted with a warning; a clean pod warns nothing"
	"TestM10_PSAEnforceCutover|spec|PSA enforce: a hostNetwork pod is 403 under --psa-enforce-baseline (needs that server)"
	"TestM10_ImagePullSecret|e2e|imagePullSecrets: a private image pulls with the secret, is refused without, leaks nowhere"
	"TestM10_PerPodIP|e2e|per-pod IP: two same-node pods get distinct in-range /32s; a headless Service answers both"
	"TestM10_ProviderEvents|e2e|Events: Pulled/Created/Started per container, BackOff on a crash loop, Killing on delete"
	"TestM10_CrashLoopBackOff|e2e|restart: in-place re-exec, CrashLoopBackOff 10s/20s/40s, Running phase, stabilization reset"
	"TestM10_JobCompletion|e2e|Jobs: Complete, BackoffLimitExceeded, OnFailure in place, a sidecar Job ends on its main"
	"TestM10_NativeSidecar|e2e|sidecars: stay running beside the main, stop after it in reverse order, then the pod is terminal"
	"TestM10_Ingress|e2e|ingress: class + canonical Service, host routing + 404, honest statuses, svclb + conflict, TLS SNI + rotation"
	"TestCreatePodAssignsDistinctPodIP|pkg/provider|server-side: the podnet adapter assigns each pod a distinct IP"
	"TestHeadlessServiceReturnsAllPodIPs|pkg/netserve|server-side: the resolver answers a headless name with every pod IP"
)

crit_field() { # crit_field <entry> <1|2|3>
	local IFS='|'
	# shellcheck disable=SC2206
	local parts=($1)
	printf '%s\n' "${parts[$(($2 - 1))]}"
}

# e2e_names: the names of the e2e and spec criteria, one per line.
e2e_names() {
	local e k
	for e in "${CRITERIA[@]}"; do
		k="$(crit_field "$e" 2)"
		if [ "$k" = e2e ] || [ "$k" = spec ]; then crit_field "$e" 1; fi
	done
}

plan() {
	echo "M10 composite gate: criteria (kind e2e and pkg/* must PASS; spec may SKIP)"
	local e
	for e in "${CRITERIA[@]}"; do
		printf '  %-36s %-13s %s\n' "$(crit_field "$e" 1)" "$(crit_field "$e" 2)" "$(crit_field "$e" 3)"
	done
}

# classify <test> <log>: the top-level verdict of one test in a `go test -v` log.
classify() {
	local name="$1" log="$2"
	if grep -qE "^--- PASS: ${name} \(" "$log"; then
		echo PASS
	elif grep -qE "^--- FAIL: ${name} \(" "$log"; then
		echo FAIL
	elif grep -qE "^--- SKIP: ${name} \(" "$log"; then
		echo SKIP
	else
		echo MISSING
	fi
}

# verdict <e2e-log> <unit-log>: prints the per-criterion ladder and returns 0 iff
# every criterion counted PASSED and the e2e run was not vacuous.
verdict() {
	local e2e_log="$1" unit_log="$2" e name kind res log fail=0 pass=0 skipped=0
	if grep -qE 'no tests to run' "$e2e_log"; then
		echo "FAIL  e2e run VACUOUS: -run '^TestM10_' matched no tests"
		fail=$((fail + 1))
	fi
	for e in "${CRITERIA[@]}"; do
		name="$(crit_field "$e" 1)"
		kind="$(crit_field "$e" 2)"
		log="$e2e_log"
		case "$kind" in pkg/*) log="$unit_log" ;; esac
		res="$(classify "$name" "$log")"
		if [ "$kind" = spec ] && [ "$res" = SKIP ]; then
			printf 'SKIP  %-36s SKIP-SPEC (not counted): %s\n' "$name" "$(skip_reason "$name" "$log")"
			skipped=$((skipped + 1))
		elif [ "$res" = PASS ]; then
			printf 'PASS  %s\n' "$name"
			pass=$((pass + 1))
		elif [ "$res" = SKIP ]; then
			printf 'FAIL  %-36s SKIPPED (a skip is not a pass): %s\n' "$name" "$(skip_reason "$name" "$log")"
			fail=$((fail + 1))
		else
			printf 'FAIL  %-36s %s\n' "$name" "$res"
			fail=$((fail + 1))
		fi
	done
	echo "----------------------------------------"
	echo "M10: $pass passed, $fail failed, $skipped SKIP-SPEC"
	[ "$fail" -eq 0 ]
}

# skip_reason <test> <log>: the first line of the test's own skip message, if any.
skip_reason() {
	awk -v n="$1" '
		$0 ~ "^=== RUN   " n "$" { in_t = 1; next }
		in_t && /^(=== RUN|--- )/ { exit }
		in_t && /: SKIP|\.go:[0-9]+: / { sub(/^[ \t]+/, ""); print; exit }
	' "$2" | cut -c1-160
}

self_test() {
	local tmp ok=0 bad=0
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' RETURN
	check() { if [ "$1" = ok ]; then echo "ok    $2"; ok=$((ok + 1)); else echo "FAIL  $2"; bad=$((bad + 1)); fi; }
	expect() { # expect <description> <command...>: the command must succeed
		local d="$1"
		shift
		if "$@"; then check ok "$d"; else check no "$d"; fi
	}

	# The table and the e2e sources agree: every TestM10_ function is a criterion,
	# and every e2e/spec criterion exists.
	local src tab
	src="$(grep -hoE '^func TestM10_[A-Za-z0-9_]+' "$REPO_ROOT"/e2e/*.go | sed 's/^func //' | sort -u)"
	tab="$(e2e_names | sort -u)"
	if [ "$src" = "$tab" ]; then check ok "criterion table matches the TestM10_ functions in e2e/"; else
		check no "criterion table matches the TestM10_ functions in e2e/ (source: ${src//$'\n'/ }; table: ${tab//$'\n'/ })"
	fi
	local e name kind
	for e in "${CRITERIA[@]}"; do
		kind="$(crit_field "$e" 2)"
		case "$kind" in pkg/*)
			name="$(crit_field "$e" 1)"
			if grep -qE "^func ${name}\(" "$REPO_ROOT/$kind"/*_test.go; then check ok "unit gate $name exists in $kind"; else check no "unit gate $name exists in $kind"; fi
			;;
		esac
	done
	if grep -lE 't\.Skip\("TODO' "$REPO_ROOT"/e2e/m10_*test.go >/dev/null 2>&1; then
		check no "no M10 criterion is still a t.Skip TODO"
	else
		check ok "no M10 criterion is still a t.Skip TODO"
	fi

	# A fake run: one log line per criterion with the given result.
	fake() { # fake <file> <default> [name=RESULT ...]
		local f="$1" def="$2" e n r
		shift 2
		: >"$f"
		for e in "${CRITERIA[@]}"; do
			n="$(crit_field "$e" 1)"
			r="$def"
			local kv
			for kv in "$@"; do [ "${kv%%=*}" = "$n" ] && r="${kv#*=}"; done
			[ "$r" = MISSING ] && continue
			printf '=== RUN   %s\n    x_test.go:1: reason for %s\n--- %s: %s (0.01s)\n' "$n" "$n" "$r" "$n" >>"$f"
		done
	}
	run_verdict() { verdict "$tmp/e2e" "$tmp/unit" >"$tmp/out" 2>&1 && echo 0 || echo 1; }

	fake "$tmp/e2e" PASS TestM10_PSAEnforceCutover=SKIP
	cp "$tmp/e2e" "$tmp/unit"
	expect "all PASS + SKIP-SPEC skipped -> exit 0" test "$(run_verdict)" = 0
	expect "SKIP-SPEC reported as SKIP" grep -q '^SKIP  TestM10_PSAEnforceCutover .*SKIP-SPEC' "$tmp/out"
	expect "skip reason carried into the ladder" grep -q 'reason for TestM10_PSAEnforceCutover' "$tmp/out"

	fake "$tmp/e2e" PASS
	expect "SKIP-SPEC that ran and PASSED -> exit 0" test "$(run_verdict)" = 0

	fake "$tmp/e2e" PASS TestM10_PSAEnforceCutover=FAIL
	expect "SKIP-SPEC that ran and FAILED -> exit 1" test "$(run_verdict)" = 1

	fake "$tmp/e2e" PASS TestM10_PSAEnforceCutover=SKIP TestM10_Ingress=FAIL
	expect "one e2e FAIL -> exit 1" test "$(run_verdict)" = 1
	expect "the failing criterion is named" grep -q '^FAIL  TestM10_Ingress' "$tmp/out"

	fake "$tmp/e2e" PASS TestM10_PSAEnforceCutover=SKIP TestM10_PerPodIP=SKIP
	expect "a non-spec SKIP -> exit 1 (a skip is not a pass)" test "$(run_verdict)" = 1

	fake "$tmp/e2e" PASS TestM10_PSAEnforceCutover=SKIP TestM10_JobCompletion=MISSING
	expect "a criterion missing from the run -> exit 1" test "$(run_verdict)" = 1

	fake "$tmp/e2e" PASS TestM10_PSAEnforceCutover=SKIP
	fake "$tmp/unit" PASS TestHeadlessServiceReturnsAllPodIPs=FAIL
	expect "a failed unit gate -> exit 1" test "$(run_verdict)" = 1
	cp "$tmp/e2e" "$tmp/unit"

	printf 'testing: warning: no tests to run\n' >>"$tmp/e2e"
	expect "a vacuous e2e run -> exit 1" test "$(run_verdict)" = 1

	# An indented subtest verdict is not the criterion's own verdict.
	printf '=== RUN   TestM10_Ingress\n    --- PASS: TestM10_Ingress/tls (0.01s)\n--- FAIL: TestM10_Ingress (1.00s)\n' >"$tmp/one"
	expect "classify reads the top-level line, not a subtest's" test "$(classify TestM10_Ingress "$tmp/one")" = FAIL

	# The plan prints every criterion.
	expect "--plan lists every criterion" test "$(plan | grep -cE '^  Test')" = "${#CRITERIA[@]}"

	if command -v shellcheck >/dev/null 2>&1; then
		expect "shellcheck clean" shellcheck -x -f quiet "$0"
	fi
	echo "----------------------------------------"
	echo "m10.sh self-test: $ok ok, $bad failed"
	[ "$bad" -eq 0 ]
}

case "${1:-}" in
--plan)
	plan
	exit 0
	;;
--self-test)
	self_test
	exit $?
	;;
-h | --help)
	sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
	exit 0
	;;
esac

EVIDENCE="${1:-}"
if [ -z "${KUBECONFIG:-}" ]; then
	echo "m10.sh: KUBECONFIG must point at a RUNNING k3sm cluster (this gate boots nothing)" >&2
	exit 2
fi
command -v kubectl >/dev/null 2>&1 || { echo "m10.sh: kubectl not found" >&2; exit 2; }
command -v go >/dev/null 2>&1 || { echo "m10.sh: go not found" >&2; exit 2; }
kubectl get --raw /healthz >/dev/null 2>&1 || { echo "m10.sh: the cluster at \$KUBECONFIG is not serving" >&2; exit 2; }
NODES="$(kubectl get nodes -o name | wc -l | tr -d ' ')"
if [ "$NODES" -gt 1 ] && [ -z "${K3SM_E2E_NODE:-}" ]; then
	echo "m10.sh: the cluster has $NODES nodes; set K3SM_E2E_NODE to the node under test (run on its Mac)" >&2
	exit 2
fi
if [ -z "$EVIDENCE" ]; then EVIDENCE="$(mktemp -d)"; fi
mkdir -p "$EVIDENCE"
E2E_LOG="$EVIDENCE/m10-e2e.log"
UNIT_LOG="$EVIDENCE/m10-unit.log"

echo "==> k3sm M10 composite gate (node ${K3SM_E2E_NODE:-<the only node>}; evidence $EVIDENCE)"
plan
echo "==> server-side unit gates"
(cd "$REPO_ROOT" && CGO_ENABLED=1 go test -count=1 -v -run '^TestCreatePodAssignsDistinctPodIP$' ./pkg/provider/ &&
	CGO_ENABLED=1 go test -count=1 -v -run '^TestHeadlessServiceReturnsAllPodIPs$' ./pkg/netserve/) >"$UNIT_LOG" 2>&1 || true
echo "==> e2e criteria (go test -tags e2e -run '^TestM10_', timeout ${K3SM_M10_TIMEOUT:-45m})"
(cd "$REPO_ROOT" && CGO_ENABLED=1 go test -tags e2e -count=1 -v -run '^TestM10_' -timeout "${K3SM_M10_TIMEOUT:-45m}" ./e2e/) >"$E2E_LOG" 2>&1 || true
grep -E '^(--- |    --- |FAIL|ok|panic)' "$E2E_LOG" | sed 's/^/    /' || true
echo "----------------------------------------"
if verdict "$E2E_LOG" "$UNIT_LOG"; then
	echo "=========== M10 GREEN ==========="
	exit 0
fi
echo "M10 RED: see $E2E_LOG and $UNIT_LOG" >&2
exit 1
