#!/usr/bin/env bash
#
# k3sm `status` acceptance gate — the runnable proof that `k3sm status` tells the
# truth about this Mac, and that its exit code is a contract a script can branch on.
#
# WHY THE VERB EXISTS. After a reboot the two LaunchDaemons come back on their own,
# and when one of them does not there was nothing to run that said so in one screen:
# an operator had to know `launchctl print`, know which of two labels to print, know
# that the server's own log is at /var/log/k3sm/server.log rather than in the unified
# log, and know that a data root declared in /etc/fstab but not mounted looks exactly
# like an empty cluster. `k3sm status` answers all of that in one place and names the
# command that fixes whatever is down.
#
# NOT REGISTERED IN phases.json. That file is the milestone ledger's acceptance
# index; a feature gate that belongs to no milestone deliverable carries no row
# there, and adding one would claim a ledger entry that does not exist. The gate is
# run by name.
#
# THREE TIERS, split by what each can prove without touching the machine:
#
#   CI TIER (always runs, CGO_ENABLED=1) — the unit-provable contract: the launchctl
#   parser against captures of every posture the daemons reach, the verdict table,
#   the rendered goldens, the exit codes, the decoration invariant, the wait/watch
#   loops on a fake clock, the vm-host filter, and the disclosure gate that keeps a
#   join token out of every surface. Plus structural pins so the verb stays wired
#   and the exit-code table stays documented where it is documented.
#   RED BEFORE: on the unmodified tree pkg/status does not exist, so every Go leg
#   fails to build and the structural pins fail.
#
#   LAB TIER (K3SM_LAB=1, a Mac with k3sm installed; NO ROOT REQUIRED) — the legs
#   that need a real launchctl and a real cluster: the launchctl output-format
#   canary (the four keys the parser reads are still printed as `key = value`), the
#   JSON verdict being one of the five words, the exit code matching the table for
#   the verdict actually reported, and `--wait` reaching 0 on a healthy cluster.
#   The format canary is the leg that matters most: nothing else notices when a
#   macOS update renames a launchctl key, and the parser's answer for that is
#   "unknown", which is safe but useless.
#
#   DESTRUCTIVE TIER (K3SM_LAB=1 AND K3SM_LAB_DESTRUCTIVE=1) — the data-root shadow,
#   reproduced: unmount the data root with the daemons down, prove the report says
#   `not-mounted` and `stopped`, then mount it back and prove `--wait` returns to 0.
#   It STOPS THE CLUSTER, so it never runs unless both variables are set, and it
#   restores the mount and both daemons on any failure via a trap.
#
# Usage:  hack/acceptance/status.sh                                   # CI tier only
#         K3SM_LAB=1 hack/acceptance/status.sh                        # + the live tier
#         K3SM_LAB=1 K3SM_LAB_DESTRUCTIVE=1 hack/acceptance/status.sh # + the shadow reproduction
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
MAIN_GO="$K3SM_ROOT/cmd/k3sm/main.go"
STATUS_GO="$K3SM_ROOT/cmd/k3sm/status.go"
SELF="$HERE/status.sh"
DATA_ROOT="/var/lib/k3sm"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
lab_pending() { echo "LAB-PENDING  $1"; }

echo "==> k3sm status acceptance (the one screen, and its exit-code contract)"

# ---- s.0 — the gate parses and its wiring sources exist ---------------------
s0=ok
[ -f "$SELF" ] && bash -n "$SELF" || s0=no
[ -f "$MAIN_GO" ] || s0=no
[ -f "$STATUS_GO" ] || s0=no
[ -d "$K3SM_ROOT/pkg/status" ] || s0=no
ladder "$s0" "s.0  gate parses (bash -n) + cmd/k3sm/status.go and pkg/status present"
if [ "$s0" != ok ]; then
	echo "----------------------------------------"
	echo "status: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "status: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- s.1 — the verb is wired, and wired to return its OWN exit code ---------
# The second pin is the load-bearing one: every other verb in main.go funnels
# through `os.Exit(1)` on error, which would collapse stopped / degraded /
# not-installed / unknown into a single number and destroy the contract.
w=ok
grep -q 'case "status":' "$MAIN_GO" || w=no
grep -q 'os.Exit(runStatus(os.Args\[2:\]))' "$MAIN_GO" || w=no
grep -q '  status      show what is running' "$MAIN_GO" || w=no
ladder "$w" "s.1  main.go dispatches status and exits with runStatus's own code"

# ---- s.2 — the exit-code table is documented where it is defined ------------
# `k3sm status --help` is the canonical home of the table. A code that exists in
# the switch but not in the help text is a contract nobody can read.
t=ok
for code in \
	'0  running' '1  internal error' '2  usage' \
	'3  stopped' '4  degraded' '5  not installed' '6  unknown'; do
	grep -qF "$code" "$STATUS_GO" || t=no
done
grep -qF 'ADDITIVE ONLY' "$STATUS_GO" || t=no
ladder "$t" "s.2  statusUsage documents all seven exit codes and their additive-only rule"

# ---- s.3 — the launchctl fixtures still carry the token the redaction test hunts
# TestReportNeverContainsSecrets is only meaningful while its input contains a
# secret. This pin catches the day someone "cleans up" the fixture.
f=ok
grep -q -- '--token k3sm-' "$K3SM_ROOT/pkg/status/testdata/launchctl_server_crashloop.txt" || f=no
ladder "$f" "s.3  the launchctl fixture still carries a fake token (the disclosure test is non-vacuous)"

# ---- Go legs (CGO_ENABLED=1) ------------------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-Rosetta
# would otherwise build the wrong arch for a product that is darwin/arm64-only.
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <TestName-regexp> <pkg> <min-top-level-passes>
# Asserts the legs actually RAN: `go test -run` EXITS 0 on a zero-match filter, so a
# renamed test would read PASS forever.
run_test() {
	local id="$1" filter="$2" pkg="$3" min="$4" out rc=0 ran
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -race -v -run "$filter" "$pkg" 2>&1)" || rc=$?
	ran="$(printf '%s\n' "$out" | grep -c '^--- PASS: ' || true)"
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -40
		ladder no "$id  $filter ($pkg) passed"
		return
	fi
	if [ "$ran" -lt "$min" ]; then
		ladder no "$id  $filter ($pkg) ran $ran top-level tests, expected at least $min"
		return
	fi
	ladder ok "$id  $filter ($pkg) — $ran top-level tests passed"
}

run_test "s.4" '^(TestParseLaunchctlPrintFixtures|TestParseLaunchctlPrintIgnoresOutputOnError|TestParseLaunchctlPrintFirstMatchWins|TestClassifyDaemon|TestClassifyDaemonSeverity|TestMarkDisabled)$' ./pkg/status/ 6
run_test "s.5" '^(TestAggregateVerdicts|TestVerdictExitCodes)$' ./pkg/status/ 2
run_test "s.6" '^(TestRenderGoldens|TestRenderContent|TestRenderGlyphsAndColor|TestRenderDetailViews|TestRenderWideAddsColumnsOnly)$' ./pkg/status/ 5
run_test "s.7" '^(TestCollectorHealthyCluster|TestCollectorCrashLoopingServer|TestCollectorShadowedDataRoot|TestCollectorWrongOwnerDataRoot|TestCollectorUnreadableAsOrdinaryUser|TestCollectorSkipsRuntimedUnprivileged)$' ./pkg/status/ 6
run_test "s.8" '^(TestReportNeverContainsSecrets|TestRedact|TestRuntimedReachable)$' ./pkg/status/ 3
run_test "s.9" '^(TestColorEnabled|TestDatastorePosture|TestStatusJSONRoundTrip)$' ./pkg/status/ 3
run_test "s.10" '^(TestStatusExitCodes|TestStatusUsageDocumentsExitCodes|TestStatusJSONIsTheOnlyThingOnStdout|TestParseStatusArgs)$' ./cmd/k3sm/ 4
run_test "s.11" '^(TestStatusWaitPolls|TestStatusWatchRenders|TestStatusWatchRefusesNonTTY|TestStatusLogsPermissionDenied|TestStatusLogsRedactsAndSeparates)$' ./cmd/k3sm/ 5
run_test "s.12" '^(TestVMHostsFiltersZombiesAndForeignParents|TestProcTableLivenessOfSelf|TestNormalizeMountPoint|TestReadTail|TestRuntimedForRefusesUnprivileged|TestStatusWorkDirIsTheInstalledOne)$' ./cmd/k3sm/ 6

# ---- LAB TIER ---------------------------------------------------------------
if [ "${K3SM_LAB:-}" != 1 ]; then
	lab_pending "s.L1  launchctl still prints the four keys the parser reads"
	lab_pending "s.L2  \`k3sm status -o json\` reports one of the five verdict words"
	lab_pending "s.L3  the exit code equals the table's code for the reported verdict"
	lab_pending "s.L4  \`k3sm status --wait --timeout 120s\` returns 0 on a healthy cluster"
else
	K3SM_BIN="${K3SM_BIN:-k3sm}"
	if ! command -v "$K3SM_BIN" >/dev/null 2>&1; then
		ladder no "s.L0  the k3sm launcher is on PATH (set K3SM_BIN to override)"
	else
		ladder ok "s.L0  the k3sm launcher is on PATH ($K3SM_BIN)"

		# s.L1 — the output-format canary. The parser reads exactly four keys out of
		# `launchctl print`, and a macOS update that renames one degrades every daemon
		# row to "unknown" — safe, and useless. Nothing else in the tree would notice.
		canary="$(launchctl print system/io.k3sm.netd 2>/dev/null || true)"
		c=ok
		for key in state pid runs; do
			printf '%s\n' "$canary" | grep -Eq "^[[:space:]]*${key} = " || c=no
		done
		printf '%s\n' "$canary" | grep -Eq '^[[:space:]]*last exit code = ' || c=no
		ladder "$c" "s.L1  launchctl print still emits 'state = ', 'pid = ', 'runs = ' and 'last exit code = '"

		# s.L2/s.L3 — the JSON verdict and the exit code it implies, read together so
		# a report that says one thing and exits another cannot pass.
		json="$("$K3SM_BIN" status -o json 2>/dev/null)" && rc=0 || rc=$?
		verdict="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null || true)"
		case "$verdict" in
			running|degraded|stopped|not-installed|unknown)
				ladder ok "s.L2  -o json reports verdict '$verdict'" ;;
			*)
				ladder no "s.L2  -o json reports a verdict in the enum (got '${verdict:-<unparseable>}')" ;;
		esac
		case "$verdict" in
			running)       want=0 ;;
			stopped)       want=3 ;;
			degraded)      want=4 ;;
			not-installed) want=5 ;;
			unknown)       want=6 ;;
			*)             want="" ;;
		esac
		if [ -n "$want" ] && [ "$rc" = "$want" ]; then
			ladder ok "s.L3  exit code $rc matches the table's code for '$verdict'"
		else
			ladder no "s.L3  exit code $rc does not match the table's code (${want:-n/a}) for '${verdict:-<none>}'"
		fi

		# s.L4 — --wait on a cluster that is already up must return immediately with 0.
		# A cluster that is legitimately degraded (a second node down, say) cannot pass
		# this leg, and says so rather than being softened into a skip.
		if "$K3SM_BIN" status --wait --timeout 120s >/dev/null 2>&1; then
			ladder ok "s.L4  --wait --timeout 120s returned 0"
		else
			ladder no "s.L4  --wait --timeout 120s returned non-zero (the cluster is not running)"
		fi
	fi
fi

# ---- DESTRUCTIVE TIER -------------------------------------------------------
if [ "${K3SM_LAB:-}" != 1 ] || [ "${K3SM_LAB_DESTRUCTIVE:-}" != 1 ]; then
	lab_pending "s.D1  [destructive] an unmounted data root reports not-mounted + stopped, and remounting returns it to running"
	lab_pending "     set K3SM_LAB=1 AND K3SM_LAB_DESTRUCTIVE=1 to run it — it stops the cluster"
elif ! grep -qE "^[^#]*[[:space:]]${DATA_ROOT}[[:space:]]" /etc/fstab 2>/dev/null; then
	lab_pending "s.D1  [destructive] skipped — /etc/fstab does not declare $DATA_ROOT as a mount point"
else
	K3SM_BIN="${K3SM_BIN:-k3sm}"
	VOLUME="$(diskutil info "$DATA_ROOT" 2>/dev/null | awk -F': *' '/Device Node/ {print $2}' | tr -d ' ')"
	NETD_PLIST=/Library/LaunchDaemons/io.k3sm.netd.plist
	SERVER_PLIST=/Library/LaunchDaemons/io.k3sm.server.plist

	# A mount point is a directory whose device differs from its parent's -- the
	# one test that survives /var -> /private/var (mount(8) prints the resolved
	# path, so a string match on $DATA_ROOT silently fails on every Mac).
	mounted() { [ "$(stat -f %d "$DATA_ROOT" 2>/dev/null)" != "$(stat -f %d "$(dirname "$DATA_ROOT")" 2>/dev/null)" ]; }
	loaded() { launchctl print "system/$1" >/dev/null 2>&1; }
	# bootout returns before launchd finishes tearing the job down; a bootstrap
	# issued inside that window fails with errno 37/5 (the documented race). So:
	# wait for the label to leave the domain, then bootstrap with a bounded retry.
	await_unloaded() { for _ in $(seq 1 15); do loaded "$1" || return 0; sleep 2; done; return 1; }
	bootstrap_job() {
		local label="$1" plist="$2"
		for _ in $(seq 1 10); do
			if loaded "$label"; then return 0; fi
			sudo launchctl bootstrap system "$plist" >/dev/null 2>&1 || true
			sleep 2
		done
		loaded "$label"
	}
	restore() {
		echo "--- restoring $DATA_ROOT and the daemons"
		mounted || sudo diskutil mount -mountPoint "$DATA_ROOT" "$VOLUME" >/dev/null 2>&1 || true
		bootstrap_job io.k3sm.netd "$NETD_PLIST" || true
		sudo launchctl kickstart -k system/io.k3sm.netd >/dev/null 2>&1 || true
		bootstrap_job io.k3sm.server "$SERVER_PLIST" || true
		sudo launchctl kickstart -k system/io.k3sm.server >/dev/null 2>&1 || true
	}
	trap restore EXIT

	if [ -z "$VOLUME" ]; then
		ladder no "s.D1  [destructive] could not read the data root's device node from diskutil"
	else
		sudo launchctl bootout system/io.k3sm.server >/dev/null 2>&1 || true
		sudo launchctl bootout system/io.k3sm.netd >/dev/null 2>&1 || true
		await_unloaded io.k3sm.server || true
		await_unloaded io.k3sm.netd || true
		# A k3sm-vmhost that outlives the booted-out server keeps the volume busy
		# (observed 2026-09-06: "dissented by PID <n> (/Library/k3sm/k3sm-vmhost)").
		# That is a product observation the gate records rather than hides; the
		# reproduction still needs the volume, so the orphan is terminated here.
		orphans="$(pgrep -x k3sm-vmhost 2>/dev/null | tr '\n' ' ' || true)"
		if [ -n "$orphans" ]; then
			echo "NOTE  s.D0  k3sm-vmhost outlived io.k3sm.server (pids: $orphans) — terminated so the volume can unmount; see the run log for the follow-up"
			for pid in $orphans; do sudo kill "$pid" 2>/dev/null || true; done
			sleep 3
			for pid in $orphans; do sudo kill -9 "$pid" 2>/dev/null || true; done
		fi
		# The volume is busy until the daemons' files close; bounded retry, then a
		# loud FAIL that names the cause -- and NOTHING below runs against a
		# volume that is still mounted (the 2026-09-06 first run of this tier
		# deleted the real run/ dir, mesh key included, for exactly that reason).
		unmount_out=""
		for _ in $(seq 1 10); do
			unmount_out="$(sudo diskutil unmount "$DATA_ROOT" 2>&1 || true)"
			mounted || break
			sleep 3
		done
		if mounted; then
			ladder no "s.D1  [destructive] could not unmount $DATA_ROOT after the daemons were booted out: ${unmount_out}"
		else
			if [ -z "$(ls -A "$DATA_ROOT" 2>/dev/null)" ]; then
				ladder ok "s.D1a [destructive] the bare mountpoint is empty before netd starts"
			else
				ladder no "s.D1a [destructive] the bare mountpoint already holds: $(ls -A "$DATA_ROOT" | tr '\n' ' ')"
			fi
			bootstrap_job io.k3sm.netd "$NETD_PLIST" || true
			sleep 6
			if [ -z "$(ls -A "$DATA_ROOT" 2>/dev/null)" ]; then
				ladder ok "s.D1b [destructive] netd created NOTHING in the unmounted mountpoint"
			else
				ladder no "s.D1b [destructive] netd wrote into the unmounted mountpoint: $(ls -A "$DATA_ROOT" | tr '\n' ' ')"
			fi
			if sudo tail -50 /var/log/k3sm/netd.log 2>/dev/null | grep -q 'declared in /etc/fstab but not mounted'; then
				ladder ok "s.D1c [destructive] netd's log carries the refusal naming the mount"
			else
				ladder no "s.D1c [destructive] netd's log does not carry the refusal"
			fi
			shadow_json="$("$K3SM_BIN" status -o json 2>/dev/null)" && srC=0 || srC=$?
			sv="$(printf '%s' "$shadow_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null || true)"
			sd="$(printf '%s' "$shadow_json" | python3 -c 'import json,sys; print(next(r["state"] for r in json.load(sys.stdin)["rows"] if r["name"]=="data-root"))' 2>/dev/null || true)"
			if [ "$sd" = "not-mounted" ]; then
				ladder ok "s.D1d [destructive] the data-root row reports not-mounted"
			else
				ladder no "s.D1d [destructive] the data-root row reports not-mounted (got '${sd:-<none>}')"
			fi
			if [ "$sv" = "stopped" ] && [ "$srC" = 3 ]; then
				ladder ok "s.D1e [destructive] the verdict is stopped and the exit code is 3"
			else
				ladder no "s.D1e [destructive] the verdict is stopped/3 (got '${sv:-<none>}'/$srC)"
			fi
			sudo diskutil mount -mountPoint "$DATA_ROOT" "$VOLUME" >/dev/null 2>&1 || true
			sudo launchctl kickstart -k system/io.k3sm.netd >/dev/null 2>&1 || true
			bootstrap_job io.k3sm.server "$SERVER_PLIST" || true
			if "$K3SM_BIN" status --wait --timeout 180s >/dev/null 2>&1; then
				ladder ok "s.D1f [destructive] remounting and restarting returns the cluster to running with no reinstall"
			else
				ladder no "s.D1f [destructive] the cluster did not return to running within 180s"
			fi
		fi
	fi
	trap - EXIT
	restore
fi

echo "----------------------------------------"
echo "status: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB_DESTRUCTIVE:-}" = 1 ] && [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ status GREEN (CI + lab + destructive tiers) ================"
elif [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ status GREEN (CI + lab tiers) ================"
else
	echo "================ status GREEN (CI tier) ================"
fi
