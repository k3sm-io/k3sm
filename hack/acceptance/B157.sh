#!/usr/bin/env bash
#
# k3sm B157 acceptance gate — the runnable proof that the acceptance harness
# leaves the host as it found it AFTER THE LAST GATE: hack/lib/clusterup.sh's
# cluster_down reaps the node/server process it can attribute to this rig, and
# flushes the lo0 aliases the run created.
#
# The bug it pins (observed directly 2026-08-27 on an ALL-GREEN m0 -> m1 -> m3 ->
# m4 sequence, so this is NOT a failure path): the host was left with a root
# `k3sm server` alive for 16 minutes still holding *:10250, plus lo0 aliases
# 10.43.0.10 and 100.64.0.1, and they had to be reaped by hand. B150 made the
# BRING-UP side self-cleaning, which is why the sequence itself passed; nothing
# reaps on EXIT after the final gate because no later bring-up follows it. The
# residue is exactly what produces the misleading "listen tcp :10250: bind:
# address already in use" and "IP 10.43.0.10 already allocated" failures in a
# LATER unrelated run — or in a human's own `k3sm dev up` on the same Mac.
#
# Unit-tier and hermetic by construction: it sources the library and drives
# cluster_down against SCRATCH directories under mktemp. It never boots a
# cluster, never downloads, never needs root. Its listener fixtures bind
# 127.0.0.1:0 and are this run's own processes; `ifconfig` and `pkill` are PATH
# stubs for every cluster_down call, so no real host networking is touched and no
# real process is signalled, at any uid.
#
# Usage: hack/acceptance/B157.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
LIB="$REPO_ROOT/hack/lib/clusterup.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B157 acceptance (exit-side host cleanup: clusterup.sh cluster_down)"

# ---- b157.0 — the library exists and parses --------------------------------
if [ -f "$LIB" ] && bash -n "$LIB"; then
	ladder ok "b157.0  hack/lib/clusterup.sh present + parses (bash -n)"
else
	ladder no "b157.0  hack/lib/clusterup.sh present + parses (bash -n)"
	echo "----------------------------------------"
	echo "B157: clusterup.sh missing or unparseable — nothing else can run" >&2
	echo "B157: $PASS passed, $((FAIL)) failed" >&2
	exit 1
fi

WORK="$(mktemp -d /tmp/b157.XXXXXX)"
LISTENER_PIDS=()
cleanup() {
	for p in "${LISTENER_PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── stubs ───────────────────────────────────────────────────────────────────
# ifconfig and pkill are stubbed for EVERY cluster_down invocation below.
#   ifconfig — so the lo0 sweep runs against a synthetic alias table and can
#     never remove a real alias (an operator's own `k3sm dev` VIPs) even if this
#     gate is run as root.
#   pkill    — a no-op, which is what makes b157.2/b157.3 sharp: with the
#     path-anchored pkills disabled, the ONLY thing left in cluster_down that can
#     free a port is the new reap loop.
STUBS="$WORK/stubs"; mkdir -p "$STUBS"
cat > "$STUBS/ifconfig" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${B157_IFCONFIG_LOG:?}"
# `ifconfig lo0` (no further args) is the enumeration lo0_flush parses.
if [ "$#" -eq 1 ] && [ "$1" = lo0 ] && [ -n "${B157_LO0_ALIASES:-}" ]; then
	cat "$B157_LO0_ALIASES"
fi
exit 0
STUB
cat > "$STUBS/pkill" <<'STUB'
#!/bin/bash
printf 'pkill %s\n' "$*" >> "${B157_PKILL_LOG:-/dev/null}"
exit 0
STUB
chmod +x "$STUBS"/*

# A synthetic lo0 table: two aliases INSIDE the cluster CIDRs (the exact pair the
# leak left behind), and four that must never be touched — the loopback address
# itself, a 10.44/16 that is close to but outside the Service CIDR, an RFC1918
# LAN address, and an IPv6 line.
cat > "$WORK/lo0.txt" <<'ALIASES'
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
	inet 10.43.0.10 netmask 0xffffffff
	inet 100.64.0.1 netmask 0xffffffff
	inet 10.44.0.1 netmask 0xffffffff
	inet 192.168.5.5 netmask 0xffffffff
ALIASES

# down runs cluster_down in a fresh bash with the library sourced against a
# SCRATCH work dir and the stubs first on PATH. KUBECONFIG is unset so the
# library's source-time export can never point at an operator's real cluster.
# $2 is an optional snippet evaluated AFTER sourcing and BEFORE cluster_down.
#   down <workdir> [preamble] → cluster_down's exit status
down() {
	local wd="$1" pre="${2:-}"
	env -u KUBECONFIG K3SM_WORKDIR="$wd" \
		APISERVER_PORT="${B157_APISERVER_PORT:-6444}" KINE_PORT="${B157_KINE_PORT:-2379}" \
		PATH="$STUBS:$PATH" \
		B157_IFCONFIG_LOG="${B157_IFCONFIG_LOG:-/dev/null}" \
		B157_PKILL_LOG="${B157_PKILL_LOG:-/dev/null}" \
		B157_LO0_ALIASES="${B157_LO0_ALIASES:-}" \
		B157_FIXTURE_PORT="${B157_FIXTURE_PORT:-}" \
		bash -c "set -euo pipefail
			. '$LIB'
			$pre
			cluster_down"
}

# NODE_PORT_REDIRECT reroutes reap_port's listener lookup for the FIXED kubelet
# port 10250 onto an ephemeral fixture port. Binding the real :10250 in a unit
# gate would collide with any node actually running on this Mac, so the port
# number under test stays 10250 (that is the contract) while the socket behind it
# is this run's own. Everything else — the attribution rule, the TERM/KILL
# escalation, the re-poll — is the library's real code path.
NODE_PORT_REDIRECT='
_port_listeners() {
	local p="$1"
	if [ "$p" = 10250 ] && [ -n "${B157_FIXTURE_PORT:-}" ]; then p="$B157_FIXTURE_PORT"; fi
	lsof -nP -iTCP:"$p" -sTCP:LISTEN -t 2>/dev/null | sort -u || true
}'

# ---- listener fixtures (same shape as B150's) -------------------------------
cat > "$WORK/listen.py" <<'PY'
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(1)
open(sys.argv[2], "w").write(str(s.getsockname()[1]))
while True:
    time.sleep(1)
PY
PORTS="$WORK/ports"; mkdir -p "$PORTS"

# start_listener sets LISTEN_PID + LISTEN_PORT. It deliberately does NOT echo the
# port through a command substitution: the fixture is a BACKGROUND process, and a
# $(...) would both hang on its inherited stdout and lose $! to a subshell.
start_listener() { # <attribution-arg> <portfile-name>
	local marker="$1" pf="$PORTS/$2" i=0
	rm -f "$pf"
	python3 "$WORK/listen.py" "$marker" "$pf" >/dev/null 2>&1 &
	LISTEN_PID=$!
	LISTENER_PIDS+=("$LISTEN_PID")
	# Drop it from the job table so bash prints no "Killed: 9" job notice after
	# the gate's own verdict line.
	disown "$LISTEN_PID" 2>/dev/null || true
	while [ ! -s "$pf" ]; do
		i=$((i + 1))
		if [ "$i" -gt 200 ]; then echo "listener never reported its port" >&2; exit 1; fi
		sleep 0.05
	done
	LISTEN_PORT="$(cat "$pf")"
}

# free_port reports an ephemeral port nothing is listening on — used to point the
# overridable $APISERVER_PORT/$KINE_PORT at dead air so the sweep in the tests
# below cannot meet a real :6444/:2379 on the developer's machine.
free_port() { python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'; }

QUIET_A="$(free_port)"; QUIET_B="$(free_port)"
export B157_APISERVER_PORT="$QUIET_A" B157_KINE_PORT="$QUIET_B"

# ---- b157.1 — cluster_down is safe on a quiet host, and reaps no state ------
# It runs from an EXIT trap under `set -e`, so a non-zero return could only
# corrupt an already-decided verdict; and it must not take the work dir with it,
# because a failed gate's logs have to stay findable (the fixed-path rationale).
QUIET="$WORK/quiet"; mkdir -p "$QUIET/bin" "$QUIET/server/db"
echo cp > "$QUIET/bin/kube-apiserver"
echo log > "$QUIET/server.log"
echo state > "$QUIET/server/db/state.db"
quiet_rc=0
down "$QUIET" >/dev/null 2>&1 || quiet_rc=$?
kept=true
for f in "$QUIET/bin/kube-apiserver" "$QUIET/server.log" "$QUIET/server/db/state.db"; do
	if [ ! -e "$f" ]; then echo "  cluster_down removed work-dir state: $f" >&2; kept=false; fi
done
if [ "$quiet_rc" -eq 0 ] && $kept; then
	ladder ok "b157.1  cluster_down returns 0 on a quiet host and removes no work-dir state (logs stay findable)"
else
	ladder no "b157.1  cluster_down returns 0 on a quiet host and removes no work-dir state (rc=$quiet_rc kept=$kept)"
fi

# ---- b157.2 — THE CONTRACT: teardown reaps the rig's node holding :10250 ----
# The observed leak, reproduced: a process this rig launched is still listening on
# the kubelet port after the gate is done. It must not survive cluster_down. This
# is the check that goes red if the exit-side reap is reverted.
REAP="$WORK/reap"; mkdir -p "$REAP"
start_listener "$REAP/pods" node.port     # argv names the rig's work dir — attributable
export B157_FIXTURE_PORT="$LISTEN_PORT"
node_rc=0
down "$REAP" "$NODE_PORT_REDIRECT" >/dev/null 2>&1 || node_rc=$?
# The assertion is on the PORT, not on `kill -0` of the pid: a killed child of
# this shell is a zombie until reaped, and kill -0 succeeds on a zombie.
if [ "$node_rc" -eq 0 ] && [ -z "$(lsof -nP -iTCP:"$B157_FIXTURE_PORT" -sTCP:LISTEN -t 2>/dev/null)" ]; then
	ladder ok "b157.2  cluster_down reaps THIS rig's leftover node/server still holding :10250 (the B157 contract)"
else
	ladder no "b157.2  cluster_down reaps THIS rig's leftover node/server still holding :10250 (rc=$node_rc, port still held)"
fi

# ---- b157.3 — it never kills a listener it cannot attribute -----------------
# Nothing in this fixture's argv names the rig. Teardown must leave it alone AND
# still return 0: on the way out, a foreign listener is a fact to report, not a
# teardown failure.
start_listener "/tmp/b157-unrelated-process" foreign.port
export B157_FIXTURE_PORT="$LISTEN_PORT"
foreign_rc=0
down "$REAP" "$NODE_PORT_REDIRECT" >/dev/null 2>&1 || foreign_rc=$?
foreign_alive=false
if [ -n "$(lsof -nP -iTCP:"$B157_FIXTURE_PORT" -sTCP:LISTEN -t 2>/dev/null)" ]; then foreign_alive=true; fi
if [ "$foreign_rc" -eq 0 ] && $foreign_alive; then
	ladder ok "b157.3  cluster_down never kills an unattributable :10250 listener, and still returns 0"
else
	ladder no "b157.3  cluster_down never kills an unattributable :10250 listener (rc=$foreign_rc alive=$foreign_alive)"
fi
unset B157_FIXTURE_PORT

# ---- b157.4 — the swept port set, and the mode ------------------------------
# reap_port is replaced with a recorder, so this reads the ports teardown asks
# about rather than grepping for them. 10250 is the node/kubelet port the leak was
# on; 10259/10257 are scheduler/CM; $APISERVER_PORT/$KINE_PORT are the CP pair a
# -9'd supervisor can orphan. Every one must be `warn` — a `fatal` in teardown
# would turn a foreign listener into a failed gate.
RECORD="$WORK/reapcalls"; : > "$RECORD"
env -u KUBECONFIG K3SM_WORKDIR="$WORK/record" APISERVER_PORT="$QUIET_A" KINE_PORT="$QUIET_B" \
	PATH="$STUBS:$PATH" B157_REAP_LOG="$RECORD" \
	bash -c "set -euo pipefail
		. '$LIB'
		reap_port() { printf '%s %s\n' \"\$1\" \"\${2:-fatal}\" >> \"\$B157_REAP_LOG\"; return 0; }
		cluster_down" >/dev/null 2>&1 || true
ports_ok=true
for want in "10250 warn" "10259 warn" "10257 warn" "$QUIET_A warn" "$QUIET_B warn"; do
	if ! grep -qxF "$want" "$RECORD"; then
		echo "  teardown never reaped: $want" >&2
		ports_ok=false
	fi
done
if grep -q ' fatal$' "$RECORD"; then
	echo "  teardown used reap_port ... fatal: $(grep ' fatal$' "$RECORD" | tr '\n' ';')" >&2
	ports_ok=false
fi
# The node/server port must go first, so the supervisor dies before the children
# it would otherwise re-parent.
if [ "$(head -1 "$RECORD" 2>/dev/null | cut -d' ' -f1)" != 10250 ]; then
	echo "  the first port teardown reaps is not the node port 10250: $(head -1 "$RECORD" 2>/dev/null)" >&2
	ports_ok=false
fi
if $ports_ok; then
	ladder ok "b157.4  teardown reaps :10250 first, then 10259/10257/apiserver/kine — all in warn mode, never fatal"
else
	ladder no "b157.4  teardown reaps :10250 first, then 10259/10257/apiserver/kine — all in warn mode, never fatal"
fi

# ---- b157.5 — the lo0 sweep, and its CIDR scope -----------------------------
# lo0 aliases are kernel-global and outlive every process reaped above, so this is
# the half of the residue no amount of killing removes. The scope is the sharp
# part: an address outside the cluster CIDRs — a neighbour /16, the LAN, the
# loopback address itself — must never be flushed.
IFLOG="$WORK/ifconfig.log"; : > "$IFLOG"
B157_IFCONFIG_LOG="$IFLOG" B157_LO0_ALIASES="$WORK/lo0.txt" \
	down "$WORK/lo0" >/dev/null 2>&1 || true
flushed="$(awk '/-alias/{print $3}' "$IFLOG" | sort -u | tr '\n' ' ')"
if [ "$flushed" = "10.43.0.10 100.64.0.1 " ]; then
	ladder ok "b157.5  cluster_down flushes exactly the cluster-CIDR lo0 aliases (10.43.0.10, 100.64.0.1) and nothing else"
else
	ladder no "b157.5  cluster_down flushes exactly the cluster-CIDR lo0 aliases — it flushed: [$flushed]"
fi
if grep -q '^lo0$' "$IFLOG"; then
	ladder ok "b157.5b cluster_down enumerates lo0 on teardown (the flush is wired, not dead code)"
else
	ladder no "b157.5b cluster_down enumerates lo0 on teardown (the flush is wired, not dead code)"
fi

# ---- b157.6 — the attribution rule is not loosened --------------------------
# A broad `pkill -f k3sm` would reap the leak in one line and would also kill a
# human's unrelated `k3sm dev` cluster on this machine. Every kill in the library
# stays behind a path-anchored pattern or reap_port's _proc_is_ours witnesses.
broad="$(grep -n 'pkill' "$LIB" \
	| grep -vE '^[0-9]+:[[:space:]]*#' \
	| grep -vE 'pkill -f "\$(BIN|SERVER_WORKDIR)/' || true)"
witnesses=true
grep -qF 'case "$comm" in' "$LIB" || witnesses=false
grep -qF '"$K3SM_WORKDIR"/*|"$SERVER_WORKDIR"/*|"$STAGE_DIR"/*) return 0 ;;' "$LIB" || witnesses=false
grep -qF '*"$K3SM_WORKDIR"/*|*"$SERVER_WORKDIR"/*|*"$STAGE_DIR"/*) return 0 ;;' "$LIB" || witnesses=false
if [ -z "$broad" ] && $witnesses; then
	ladder ok "b157.6  no unanchored pkill in the library; _proc_is_ours keeps both attribution witnesses"
else
	ladder no "b157.6  attribution loosened (unanchored pkill: ${broad:-none}; witnesses=$witnesses)"
fi

# ---- b157.7 — B150's bring-up contract is still wired -----------------------
# This item extends TEARDOWN. The bring-up reap it depends on (and must not
# regress) is B150's; assert the entry points still reset first, so a green B157
# can never coexist with a silently-unwired cluster_reset.
if grep -qF 'cluster_reset || return 1' "$LIB" \
	&& [ "$(grep -cF 'cluster_reset || return 1' "$LIB")" -ge 2 ] \
	&& grep -qF 'stage_dir_ok && rm -rf /Library/k3sm-acceptance' "$LIB"; then
	ladder ok "b157.7  B150's bring-up reset is still wired into both entry points, STAGE_DIR removal still guarded"
else
	ladder no "b157.7  B150's bring-up reset is still wired into both entry points, STAGE_DIR removal still guarded"
fi

echo "----------------------------------------"
echo "B157: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B157 GREEN ================"
