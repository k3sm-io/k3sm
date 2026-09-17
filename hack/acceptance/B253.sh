#!/usr/bin/env bash
#
# k3sm B253 acceptance gate — the runnable proof that a node which exits stops the
# runtime it embedded, so no k3sm-vmhost outlives `launchctl bootout
# system/io.k3sm.server`.
#
# The problem it closes: `k3sm server` builds its runtimed runtime in-process
# (provider.NewRuntimed) and drives it by direct RPC, never through
# runtime.Server.Serve — so the graceful stop the STANDALONE k3sm-runtimed daemon
# runs once Serve returns had no counterpart on this path and was never called.
# Every vm pod's k3sm-vmhost therefore survived the daemon that booted it, holding
# the data root open (it is the server plist's WorkingDirectory), and the next
# `diskutil unmount` of the data root was dissented by the orphan helper's pid
# (observed on the rig 2026-09-06, worked around inside status.sh's destructive
# tier). Native host-process pods are deliberately untouched by the stop: they
# survive a daemon restart by design and the next start's pod reap reconciles
# them, while a vm guest never does.
#
# TWO TIERS, split by what a Mac can prove without a running cluster:
#
#   CI TIER (always runs, CGO_ENABLED=1 — k3sm's posture) — the unit-provable
#   half: the teardown closure stops the embedded runtime exactly once on BOTH of
#   startNode's exit paths and before the control socket comes down, a Close
#   failure is reported rather than propagated, and a runtime-less provider
#   (HostProcess) yields a safe no-op. Plus the structural pins no unit test can
#   carry, because each is a fact about where a line sits rather than about a
#   function's behaviour: the teardown is wired into startNode, its defer is
#   registered AFTER the control socket's (LIFO runs it first, so the vm stop does
#   not queue its 35s bound behind the socket's shutdown grace inside launchd's
#   single ExitTimeOut), the stop takes no context (threading the node's already
#   cancelled context in would make the vm sweep return instantly having stopped
#   nothing — the bug, reintroduced in a shape that looks like care), the startup
#   orphan reap that backstops it is still wired, and — the rung no Go test can
#   carry — the 37 seconds pkg/install BUDGETS for this stage still equal the
#   bounds runtimed actually ships (its two constants are unexported, so the
#   budget is a literal on the k3sm side and this is its drift alarm).
#   RED BEFORE: on the unmodified tree stopEmbeddedRuntime and awaitNodeExit do
#   not exist, so the Go leg fails to build and every structural pin fails.
#
#   LAB TIER (K3SM_LAB=1, a Mac with k3sm installed AND at least one vm pod
#   running; root, prompts for sudo) — the only tier that can prove the thing the
#   fix is about: boot out io.k3sm.server and watch every k3sm-vmhost go with it
#   inside the plist's ExitTimeOut, then prove the data root unmounts with no
#   dissent. It STOPS THE CLUSTER, so it is announced LAB-PENDING and never
#   silently passed when K3SM_LAB is unset, it refuses to run as a pass when the
#   rig has no vm pod (the assertion would be vacuous), and it restores the mount
#   and both daemons on every path via a trap. It touches /var/lib/k3sm ONLY
#   under K3SM_LAB=1.
#
# Usage:  hack/acceptance/B253.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B253.sh # + the lab tier (root; stops the cluster)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B253.sh"
NODE_GO="$K3SM_ROOT/cmd/k3sm/node.go"
TEST_GO="$K3SM_ROOT/cmd/k3sm/nodeexit_test.go"
PROVIDER_GO="$K3SM_ROOT/pkg/provider/runtimed.go"
DATA_ROOT="/var/lib/k3sm"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
lab_pending() { echo "LAB-PENDING  $1"; }

echo "==> k3sm B253 acceptance (no k3sm-vmhost outlives the node that booted it)"

# ---- b253.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$NODE_GO" ] || b0=no
[ -f "$TEST_GO" ] || b0=no
[ -f "$PROVIDER_GO" ] || b0=no
ladder "$b0" "b253.0  gate parses (bash -n) + cmd/k3sm/node.go, its exit test and pkg/provider/runtimed.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B253: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B253: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b253.1 — the WIRING, read straight out of the source ------------------
# The teardown exists AND startNode is what defers it. A closure nobody wires is
# the bug with a unit test attached.
w=ok
grep -qF 'stopRuntime := stopEmbeddedRuntime(prov, slog.Default())' "$NODE_GO" || w=no
grep -qE '^\s*defer stopRuntime\(\)$' "$NODE_GO" || w=no
grep -qF 'return awaitNodeExit(ctx, errc, stopRuntime)' "$NODE_GO" || w=no
ladder "$w" "b253.1  startNode builds the embedded-runtime teardown, defers it, and runs it on both exit paths"

# LIFO: the LATER defer runs FIRST, so the runtime's vm stop is registered AFTER
# the control socket's teardown. Reversing these two lines silently gives the 35s
# vm sweep whatever is left of the ExitTimeOut after the socket's own shutdown
# grace — and launchd answers a blown ExitTimeOut with SIGKILL, stranding exactly
# the helpers the sweep exists to stop.
o=ok
sock_line="$(grep -nE '^\s*defer stopControlSocket\(\)$' "$NODE_GO" | head -1 | cut -d: -f1)"
rt_line="$(grep -nE '^\s*defer stopRuntime\(\)$' "$NODE_GO" | head -1 | cut -d: -f1)"
if [ -z "$sock_line" ] || [ -z "$rt_line" ] || [ "$sock_line" -ge "$rt_line" ]; then o=no; fi
ladder "$o" "b253.1  the runtime teardown is deferred AFTER the control socket's, so LIFO stops the vm guests first (lines ${sock_line:-?} < ${rt_line:-?})"

# The stop takes NO context. Close derives its own 35s vm bound from
# context.Background(); handing it the node's context would hand it one that is
# already cancelled on the commonest shutdown path (SIGTERM), and StopAllVMs would
# return instantly having stopped nothing.
c=ok
grep -qF 'func stopEmbeddedRuntime(prov vkadapter.Provider, log *slog.Logger) func()' "$NODE_GO" || c=no
ladder "$c" "b253.1  stopEmbeddedRuntime takes no context (the vm bound is Close's own, never the node's cancelled one)"

# The startup orphan sweep is the BACKSTOP that makes Close's bound a bound rather
# than a promise: a helper still running when it expires is reaped at the next
# start. The fix does not replace it, so it must still be wired.
r=ok
grep -qF 'if err := rt.ReapOrphanedPods(); err != nil {' "$PROVIDER_GO" || r=no
ladder "$r" "b253.1  the startup pod reap is still wired into provider.NewRuntimed (the backstop for a helper that misses the bound)"

# ---- b253.1 — the BUDGET, and the two copies that must not drift -----------
# The node's close is now a named stage of the plist's ExitTimeOut, which
# pkg/install derives (serverExitTimeOut / agentExitTimeOut). Two of the stage
# bounds are runtimed's, and runtimed does not export them — so the k3sm side
# carries a literal, and this is the only thing that notices when runtimed moves
# it. Reading runtimed's source through `go list` rather than a relative path
# keeps it correct in a lane, a module cache, or a sibling checkout.
b=ok
grep -qE '^\s*teardownRuntimedClose = 37$' "$K3SM_ROOT/pkg/install/install.go" || b=no
grep -qF 'ExitTimeOut: serverExitTimeOut,' "$K3SM_ROOT/pkg/install/install.go" || b=no
grep -qF 'ExitTimeOut:      agentExitTimeOut,' "$K3SM_ROOT/pkg/install/install.go" || b=no
grep -qE '^\s*teardownControlPlane  = 30$' "$K3SM_ROOT/pkg/install/install.go" || b=no
# The stage literals are bound to their owners by assertions, not by trust. This
# one has an importable owner, so the binding lives in the Go test; the rung below
# is the binding for runtimed's two, which are unexported.
grep -qF 'int(executor.StopBound/time.Second)' "$K3SM_ROOT/pkg/install/exittimeout_test.go" || b=no
ladder "$b" "b253.1  both node plists render a DERIVED ExitTimeOut and the control-plane stage is bound to executor.StopBound by a test"

d=ok
RUNTIMED_DIR="$(cd "$K3SM_ROOT" && go list -m -f '{{.Dir}}' k3sm.io/runtimed 2>/dev/null || true)"
if [ -z "$RUNTIMED_DIR" ] || [ ! -f "$RUNTIMED_DIR/pkg/runtime/close.go" ]; then
	d=no
	echo "    could not locate runtimed's pkg/runtime/close.go (go list -m said '${RUNTIMED_DIR:-<nothing>}')"
else
	vm_bound="$(grep -oE 'vmShutdownBound = [0-9]+' "$RUNTIMED_DIR/pkg/runtime/close.go" | grep -oE '[0-9]+' || true)"
	close_grace="$(grep -oE 'defaultCloseGrace = [0-9]+' "$RUNTIMED_DIR/pkg/runtime/close.go" | grep -oE '[0-9]+' || true)"
	budget="$(grep -oE 'teardownRuntimedClose = [0-9]+' "$K3SM_ROOT/pkg/install/install.go" | grep -oE '[0-9]+' || true)"
	if [ -z "$vm_bound" ] || [ -z "$close_grace" ] || [ -z "$budget" ]; then
		d=no
		echo "    could not read one of the bounds (vmShutdownBound='${vm_bound:-}' defaultCloseGrace='${close_grace:-}' budget='${budget:-}')"
	elif [ "$((vm_bound + close_grace))" -ne "$budget" ]; then
		d=no
		echo "    runtimed close costs $((vm_bound + close_grace))s (${vm_bound}+${close_grace}) but pkg/install budgets ${budget}s"
	fi
fi
ladder "$d" "b253.1  pkg/install's runtimed-close budget still equals runtimed's own vmShutdownBound + defaultCloseGrace"

# ---- Go leg runner ---------------------------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-
# Rosetta would otherwise build the wrong arch for a darwin/arm64-only product.
#
# run_test <id> <min-subtests> <TestName>
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever.
run_test() {
	local id="$1" min="$2" name="$3" pkg="${4:-./cmd/k3sm/}" out rc=0 ran
	out="$(cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=1 go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name}( |\$)"; then
		ladder no "$id  $name ($pkg) actually RAN — no top-level --- PASS line"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- b253.2 — the behaviour: closed exactly once, on both paths, first ------
run_test "b253.2" 2 TestNodeExitClosesTheEmbeddedRuntime
run_test "b253.3" 0 TestNodeExitReportsAFailedRuntimeClose
run_test "b253.4" 0 TestStopEmbeddedRuntimeWithoutARuntimeIsANoop
# The budget the stage above has to fit inside: derived, not chosen, and asserted
# to cover the sum of every serial stage.
run_test "b253.5" 2 TestExitTimeOutCoversTheDaemonTeardown ./pkg/install/

# ---- b253.L — the lab tier --------------------------------------------------
if [ "${K3SM_LAB:-}" != 1 ]; then
	lab_pending "b253.L1  booting out io.k3sm.server leaves no k3sm-vmhost running"
	lab_pending "b253.L2  the data root unmounts with no dissent once the server is out"
	lab_pending "     set K3SM_LAB=1 to run them on a rig with a vm pod — they stop the cluster"
elif [ "$(uname -s)" != Darwin ]; then
	lab_pending "b253.L  skipped — the lab tier needs a Mac with k3sm installed"
elif ! launchctl print system/io.k3sm.server >/dev/null 2>&1; then
	lab_pending "b253.L  skipped — io.k3sm.server is not loaded on this Mac"
else
	SERVER_PLIST=/Library/LaunchDaemons/io.k3sm.server.plist
	NETD_PLIST=/Library/LaunchDaemons/io.k3sm.netd.plist
	# The plist's ExitTimeOut is the budget the daemon has to stop its helpers;
	# the assertion below is given that budget plus a small margin for launchd
	# itself, and no more — a helper that outlives it is stranded.
	# Read from the INSTALLED plist, never from a constant in this checkout: the
	# rig's daemon is stopping on the budget launchd actually gave it. The fallback
	# is this tree's derived server value, used only when plutil cannot read it.
	EXIT_TIMEOUT="$(plutil -extract ExitTimeOut raw -o - "$SERVER_PLIST" 2>/dev/null || true)"
	case "$EXIT_TIMEOUT" in
		''|*[!0-9]*) EXIT_TIMEOUT=60 ;;  # this tree's derived serverExitTimeOut, pinned by b253.1
	esac
	DEADLINE=$((EXIT_TIMEOUT + 10))

	loaded() { launchctl print "system/$1" >/dev/null 2>&1; }
	# await_unloaded waits for a job to leave launchd; the optional second argument
	# is the bound in seconds (default 30). The server's serial teardown can take
	# most of its ExitTimeOut, so its callers pass the deadline.
	await_unloaded() { local n=$(( ${2:-30} / 2 )); for _ in $(seq 1 "$n"); do loaded "$1" || return 0; sleep 2; done; return 1; }
	# await_exited waits for the server PROCESS itself to be gone: the job can be
	# unloaded while the process is still inside its teardown, and a diskutil
	# unmount in that window is dissented by the server's own pid, not by an
	# orphan helper, which is a different fact from the one L2 proves.
	await_exited() { for _ in $(seq 1 "${1:-30}"); do pgrep -f "^/Library/k3sm/k3sm server" >/dev/null 2>&1 || return 0; sleep 1; done; return 1; }
	bootstrap_job() {
		local label="$1" plist="$2"
		for _ in $(seq 1 $(( DEADLINE / 2 ))); do
			if loaded "$label"; then return 0; fi
			sudo launchctl bootstrap system "$plist" >/dev/null 2>&1 || true
			sleep 2
		done
		loaded "$label"
	}
	# A mount point is a directory whose device differs from its parent's — the one
	# test that survives /var -> /private/var (mount(8) prints the resolved path).
	mounted() { [ "$(stat -f %d "$DATA_ROOT" 2>/dev/null)" != "$(stat -f %d "$(dirname "$DATA_ROOT")" 2>/dev/null)" ]; }
	# A plain-directory data root has no volume: diskutil exits non-zero, which
	# under pipefail would end the tier before the helper leg ran. Empty means
	# "not a separate volume" and the L2 rung reports itself pending below.
	VOLUME="$( (diskutil info "$DATA_ROOT" 2>/dev/null || true) | awk -F': *' '/Device Node/ {print $2}' | tr -d ' ')"

	restore() {
		echo "--- restoring $DATA_ROOT and the daemons"
		if [ -n "$VOLUME" ]; then mounted || sudo diskutil mount -mountPoint "$DATA_ROOT" "$VOLUME" >/dev/null 2>&1 || true; fi
		bootstrap_job io.k3sm.netd "$NETD_PLIST" || true
		bootstrap_job io.k3sm.server "$SERVER_PLIST" || true
		sudo launchctl kickstart -k system/io.k3sm.server >/dev/null 2>&1 || true
	}

	# NON-VACUITY GATE. With no vm pod on the rig there is no helper to strand, so
	# "pgrep found nothing" would pass on the broken build too. The tier refuses to
	# report a pass it did not earn.
	before="$(pgrep -x k3sm-vmhost 2>/dev/null | tr '\n' ' ' || true)"
	if [ -z "$before" ]; then
		lab_pending "b253.L1  skipped — no k3sm-vmhost is running, so the assertion would be vacuous; start a vm-RuntimeClass pod first"
		lab_pending "b253.L2  skipped — same reason (the dissent this proves is an orphan helper holding the data root)"
	else
		trap restore EXIT
		echo "--- k3sm-vmhost pids before the bootout: $before"
		sudo launchctl bootout system/io.k3sm.server >/dev/null 2>&1 || true
		await_unloaded io.k3sm.server || true

		l1=no; waited=0
		while [ "$waited" -lt "$DEADLINE" ]; do
			if [ -z "$(pgrep -x k3sm-vmhost 2>/dev/null || true)" ]; then l1=ok; break; fi
			sleep 2; waited=$((waited + 2))
		done
		if [ "$l1" = ok ]; then
			ladder ok "b253.L1  every k3sm-vmhost stopped ${waited}s after the bootout (ExitTimeOut ${EXIT_TIMEOUT}s)"
		else
			ladder no "b253.L1  k3sm-vmhost outlived io.k3sm.server by ${DEADLINE}s (pids: $(pgrep -x k3sm-vmhost | tr '\n' ' '))"
		fi

		# The consequence the operator actually hits: an orphan helper's cwd IS the
		# data root, so the volume is busy and diskutil dissents by pid.
		if [ -z "$VOLUME" ]; then
			lab_pending "b253.L2  skipped — $DATA_ROOT is not a separate volume on this Mac, so there is nothing to unmount"
		elif ! mounted; then
			lab_pending "b253.L2  skipped — $DATA_ROOT is not mounted"
		else
			# The server must be fully out before the unmount: its own pid holds the
			# data root as its cwd until the last stage of its teardown returns.
			await_unloaded io.k3sm.server "$DEADLINE" || true
			await_exited "$DEADLINE" || echo "--- the server process is still alive ${DEADLINE}s after the bootout (pids: $(pgrep -f '^/Library/k3sm/k3sm server' | tr '\n' ' '))"
			sudo launchctl bootout system/io.k3sm.netd >/dev/null 2>&1 || true
			await_unloaded io.k3sm.netd || true
			unmount_out="$(sudo diskutil unmount "$DATA_ROOT" 2>&1 || true)"
			# A NATIVE pod's process survives the daemon stop by design (see the
			# header), and its rootfs sits under <data root>/pods, so on a rig that
			# runs native workloads the unmount is dissented by that pod's pid. That
			# dissent is not the defect this leg proves — an orphan HELPER (or the
			# server's own pid) holding the root — so it passes with the dissenter
			# named; any other dissenter, or a busy root with no named pid, fails.
			if mounted; then
				if printf '%s' "$unmount_out" | grep -qE 'dissented by PID [0-9]+ \((/private)?'"$DATA_ROOT"'/pods/'; then
					ladder ok "b253.L2  no helper or server pid held $DATA_ROOT once the server was out; the one dissenter is a native pod process, which survives the stop by design: $unmount_out"
				else
					ladder no "b253.L2  $DATA_ROOT did not unmount after the server was booted out: $unmount_out"
				fi
			elif printf '%s' "$unmount_out" | grep -qi 'dissent'; then
				ladder no "b253.L2  the unmount was dissented: $unmount_out"
			else
				ladder ok "b253.L2  $DATA_ROOT unmounted with no dissent once the server was out"
			fi
		fi

		trap - EXIT
		restore
	fi
fi

echo "----------------------------------------"
echo "B253: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ B253 GREEN (CI + lab tiers) ================"
else
	echo "================ B253 GREEN (CI tier; the lab tier needs K3SM_LAB=1, root and a vm pod) ================"
fi
