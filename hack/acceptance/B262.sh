#!/usr/bin/env bash
# k3sm B262 acceptance gate — the crash-loop circuit breaker (k3sm#344).
#
# After #336 a dead control-plane child takes `k3sm server` down and launchd's
# KeepAlive brings it back. A PERSISTENT fault made that a loop with no throttle,
# no give-up, and no status signal. This gate is the runnable red->green proof of
# the answer:
#
#   b262.1  pkg/executor: the crash record trips at CrashLoopThreshold inside
#           CrashLoopWindow, not at threshold-1, not when spread wider than the
#           window; the trip survives Prune until an operator clears it; the file
#           round-trips at mode 0600 and an absent file is an empty record.
#   b262.2  cmd/k3sm: a tripped daemon PARKS (resident, idle, answers SIGTERM,
#           exits only when the marker is cleared) because the plist's KeepAlive
#           is a bare `true` and any exit is one more lap; the healthy-window
#           reset never erases a crash recorded first; --clear-crashloop is a
#           flag; the wiring is structural (park precedes NewSupervised, record
#           precedes crashCancel).
#   b262.3  cmd/k3sm: the repo gives ONE answer on fatal faults — "unsurvivable
#           faults exit; survivable ones continue" — at both log-and-continue
#           sites, and no comment claims an "unbounded respawn" loop.
#   b262.4  pkg/status: a tripped record makes the server row FAIL with the
#           remedy; crashes inside the window WARN "restarting"; a record the
#           user cannot read is noted, never judged; the row never quotes the
#           record's detail field.
#
# Everything here is a unit test with a fake clock and a temp dir: no launchd,
# no privilege, no real control plane. Red on main (the tests do not exist).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B262.sh"
export CGO_ENABLED=1

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
run() { ( cd "$K3SM_ROOT" && go test -count=1 -run "$2" "$1" >/dev/null 2>&1 ) && echo ok || echo no; }

echo "==> k3sm B262 acceptance (crash-loop circuit breaker: record, park, one answer, status)"

b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in pkg/executor/crashloop.go cmd/k3sm/crashloop.go pkg/status/crashloop.go; do [ -f "$K3SM_ROOT/$f" ] || b0=no; done
ladder "$b0" "b262.0  gate parses (bash -n) + the three breaker sources exist"
if [ "$b0" != ok ]; then
	echo "B262: $PASS passed, $FAIL failed" >&2
	exit 1
fi

ladder "$(run ./pkg/executor/ '^TestCrashRecord')" "b262.1  pkg/executor crash record: threshold, window, trip persistence, 0600 round trip"
ladder "$(run ./cmd/k3sm/ '^(TestParkUntilCleared|TestCrashBreaker|TestClearCrashLoopFlag|TestRunServerWiresTheCrashLoopBreaker)')" "b262.2  cmd/k3sm: park semantics, ordered reset, the flag, the structural wiring"
ladder "$(run ./cmd/k3sm/ '^(TestRunServerHasOneAnswerOnFatalFaults|TestServerMeshBringUpIsLogAndContinue)$')" "b262.3  cmd/k3sm: one answer on fatal faults at both log-and-continue sites"
ladder "$(run ./pkg/status/ '^(TestClassifyCrashLoop|TestApplyCrashLoop|TestCollectorServerRowReadsTheCrashRecord)')" "b262.4  pkg/status: parked FAIL + remedy, restarting WARN, unreadable noted, detail never quoted"

echo "----------------------------------------"
echo "B262: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
