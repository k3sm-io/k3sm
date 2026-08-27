#!/usr/bin/env bash
#
# k3sm B150 acceptance gate — the runnable proof that the acceptance gates are
# INDEPENDENTLY RUNNABLE IN SEQUENCE: every bring-up in hack/lib/clusterup.sh
# starts from a clean cluster work dir and from ports no previous run still holds.
#
# The bug it pins (measured on real hardware 2026-08-27): K3SM_WORKDIR is a FIXED
# path and nothing removed it, so m0..m10 run back-to-back had m3 and m4 die on
# "apiserver healthz not ok within 180s" over `failed to allocate IP 10.43.0.10:
# provided IP is already allocated` — the PREVIOUS gate's Service IP allocation,
# read out of the previous gate's kine datastore. Each passed from a clean slate.
# A second symptom of the same shape: `listen tcp :10250: bind: address already
# in use` from a stale listener. Green individually, red in sequence.
#
# Unit-tier and hermetic by construction: it sources the library and drives
# cluster_reset/reap_port against SCRATCH directories under mktemp — it never
# boots a cluster, never downloads, never needs root, and never touches
# /tmp/k3sm-cluster or $STAGE_DIR. Its listener fixtures bind 127.0.0.1:0 and are
# this run's own processes.
#
# Usage: hack/acceptance/B150.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
LIB="$REPO_ROOT/hack/lib/clusterup.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B150 acceptance (per-run cluster isolation: clusterup.sh cluster_reset)"

# ---- b150.0 — the library exists and parses --------------------------------
if [ -f "$LIB" ] && bash -n "$LIB"; then
	ladder ok "b150.0  hack/lib/clusterup.sh present + parses (bash -n)"
else
	ladder no "b150.0  hack/lib/clusterup.sh present + parses (bash -n)"
	echo "----------------------------------------"
	echo "B150: clusterup.sh missing or unparseable — nothing else can run" >&2
	echo "B150: $PASS passed, $((FAIL)) failed" >&2
	exit 1
fi

WORK="$(mktemp -d /tmp/b150.XXXXXX)"
LISTENER_PIDS=()
cleanup() {
	for p in "${LISTENER_PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# sub runs a snippet in a fresh bash with the library sourced against a SCRATCH
# work dir. KUBECONFIG is unset so the library's source-time export derives from
# the scratch dir and can never point at an operator's real cluster.
#   sub <workdir> <snippet>   → the snippet's exit status
sub() {
	local wd="$1" snippet="$2"
	env -u KUBECONFIG K3SM_WORKDIR="$wd" bash -c "set -euo pipefail; . '$LIB'; $snippet"
}

# ---- b150.1 — workdir_ok: the removal guard's truth table -------------------
# The stage_dir_ok analog. $K3SM_WORKDIR is a genuine knob, so the guard is
# structural; it is what stops a root-run reset from being aimed at a real
# installation (/var/lib/k3sm/server, /Library/k3sm) or at a system prefix.
guard_ok=true
for d in "/tmp/k3sm-cluster" "$WORK/scratch" "/var/tmp/k3sm-run" "/Users/nobody/k3sm-run"; do
	if ! sub "$WORK/scratch" "workdir_ok '$d'"; then
		echo "  workdir_ok rejected a legitimate work dir: $d" >&2
		guard_ok=false
	fi
done
for d in "" "relative/dir" "/" "/tmp" "/Library/k3sm" "/Library/k3sm/server" "/var/lib/k3sm" "/var/lib/k3sm/server" "/usr/local/k3sm" "/etc/k3sm" "/System/k3sm" "$WORK/a/../a" "$HOME"; do
	if sub "$WORK/scratch" "workdir_ok '$d'"; then
		echo "  workdir_ok ACCEPTED a path a root rm must never be aimed at: $d" >&2
		guard_ok=false
	fi
done
if $guard_ok; then
	ladder ok "b150.1  workdir_ok accepts scratch/tmp work dirs, refuses /, /tmp, \$HOME, /Library/k3sm, /var/lib/k3sm, system prefixes, traversal"
else
	ladder no "b150.1  workdir_ok accepts scratch/tmp work dirs, refuses /, /tmp, \$HOME, /Library/k3sm, /var/lib/k3sm, system prefixes, traversal"
fi

# ---- b150.2 — cluster_reset removes state, KEEPS the binary caches ----------
W="$WORK/reset"
mkdir -p "$W/bin" "$W/db" "$W/pods/p1" "$W/apiserver-certs" "$W/server/bin" "$W/server/db" "$W/server/pki"
echo cp   > "$W/bin/kube-apiserver"
echo kine > "$W/server/bin/kine"
echo state > "$W/db/state.db"
echo state > "$W/server/db/state.db"
echo kubeconfig > "$W/cluster.kubeconfig"
echo kubeconfig > "$W/server/k3sm.kubeconfig"
echo token > "$W/tokens.csv"
echo log > "$W/server.log"
echo key > "$W/server/pki/cluster-ca.key"
: > "$W/.hidden-residue"
if sub "$W" "cluster_reset" >/dev/null; then
	gone=true
	for f in "$W/db/state.db" "$W/server/db/state.db" "$W/cluster.kubeconfig" \
		"$W/server/k3sm.kubeconfig" "$W/tokens.csv" "$W/server.log" \
		"$W/server/pki/cluster-ca.key" "$W/pods/p1" "$W/apiserver-certs" "$W/.hidden-residue"; do
		if [ -e "$f" ]; then echo "  survived the reset: $f" >&2; gone=false; fi
	done
	kept=true
	for f in "$W/bin/kube-apiserver" "$W/server/bin/kine" "$W" "$W/server"; do
		if [ ! -e "$f" ]; then echo "  reset removed something it must keep: $f" >&2; kept=false; fi
	done
	if $gone && $kept; then
		ladder ok "b150.2  cluster_reset wipes datastore/certs/kubeconfig/logs/pods, keeps bin caches + the work dirs"
	else
		ladder no "b150.2  cluster_reset wipes datastore/certs/kubeconfig/logs/pods, keeps bin caches + the work dirs"
	fi
else
	ladder no "b150.2  cluster_reset wipes datastore/certs/kubeconfig/logs/pods, keeps bin caches + the work dirs (cluster_reset exited non-zero)"
fi

# ---- b150.3 — THE CONTRACT: gate N+1 does not inherit gate N's datastore ----
# Two independent "gate" processes over one fixed work dir, exactly the m0..m10
# sequence's shape. This is the check that goes red if the isolation is reverted.
SEQ="$WORK/sequence"
mkdir -p "$SEQ/bin" && echo cp > "$SEQ/bin/kube-apiserver"
# `|| true`: gate A is the FIXTURE, not an assertion — if the isolation is missing
# entirely, the verdict must be the FAIL line below, not an early set -e abort.
sub "$SEQ" 'cluster_reset; mkdir -p "$SERVER_WORKDIR/db"; echo "gate-A service IP 10.43.0.10 allocated" > "$SERVER_WORKDIR/db/state.db"' >/dev/null 2>&1 || true
mkdir -p "$SEQ/server/db" && echo "gate-A service IP 10.43.0.10 allocated" > "$SEQ/server/db/state.db"
if sub "$SEQ" 'cluster_reset; [ ! -e "$SERVER_WORKDIR/db/state.db" ]' >/dev/null 2>&1; then
	ladder ok "b150.3  a second gate over the same work dir starts with NO previous datastore (the B150 contract)"
else
	ladder no "b150.3  a second gate over the same work dir starts with NO previous datastore (the B150 contract)"
fi
if [ -f "$SEQ/bin/kube-apiserver" ]; then
	ladder ok "b150.3b the sequence keeps the download cache across gates (no re-download per gate)"
else
	ladder no "b150.3b the sequence keeps the download cache across gates (no re-download per gate)"
fi

# ---- b150.4 — one reset per gate PROCESS, not one per bring-up call ---------
# A gate that stops and restarts the cluster inside one run is testing
# continuity; a second reset must not delete the datastore underneath it.
ONCE="$WORK/once"
if sub "$ONCE" 'cluster_reset; echo live > "$K3SM_WORKDIR/in-run-state"; cluster_reset; [ -f "$K3SM_WORKDIR/in-run-state" ]' >/dev/null; then
	ladder ok "b150.4  cluster_reset is once-per-process (a second call inside one gate is a no-op)"
else
	ladder no "b150.4  cluster_reset is once-per-process (a second call inside one gate is a no-op)"
fi

# ---- b150.5 — the guard REFUSES without removing anything ------------------
mkdir -p "$WORK/guard"
echo precious > "$WORK/guard/precious"
if sub "$WORK/guard/../guard" "cluster_reset" >/dev/null 2>&1; then
	ladder no "b150.5  cluster_reset refuses a work dir workdir_ok rejects (it returned 0)"
elif [ -f "$WORK/guard/precious" ]; then
	ladder ok "b150.5  cluster_reset refuses a work dir workdir_ok rejects, removing nothing"
else
	ladder no "b150.5  cluster_reset refuses a work dir workdir_ok rejects, removing nothing (it deleted first)"
fi

# ---- b150.6 / b150.7 — the wiring: cluster_up and server_up reset FIRST -----
# Proven behaviorally, not by grep: cluster_reset is replaced with a recorder
# that fails, and every external command the bring-up would reach for is a PATH
# stub that logs. A bring-up that got past the reset would leave a stub line.
STUBS="$WORK/stubs"; mkdir -p "$STUBS"
for t in gh go codesign openssl nc nohup mkdir pkill lsof; do
	cat > "$STUBS/$t" <<STUB
#!/bin/bash
printf '%s %s\n' "$t" "\$*" >> "\${B150_STUB_LOG:?}"
exit 0
STUB
done
chmod +x "$STUBS"/*

wiring() { # <name> <call>  → sets WIRE_RC; writes $WORK/<name>.{stub,reset}
	local name="$1" call="$2"
	: > "$WORK/$name.stub"; : > "$WORK/$name.reset"
	set +e
	env -u KUBECONFIG K3SM_WORKDIR="$WORK/wire-$name" \
		PATH="$STUBS:$PATH" B150_STUB_LOG="$WORK/$name.stub" B150_RESET_LOG="$WORK/$name.reset" \
		bash -c "set -euo pipefail
			. '$LIB'
			cluster_reset() { echo called >> \"\$B150_RESET_LOG\"; return 1; }
			$call" >/dev/null 2>&1
	WIRE_RC=$?
	set -e
}

wiring cluster_up "cluster_up"
if [ "$WIRE_RC" -ne 0 ] && [ -s "$WORK/cluster_up.reset" ] && [ ! -s "$WORK/cluster_up.stub" ]; then
	ladder ok "b150.6  cluster_up calls cluster_reset FIRST and aborts when it fails (nothing else ran)"
else
	ladder no "b150.6  cluster_up calls cluster_reset FIRST and aborts when it fails (rc=$WIRE_RC, stubs: $(tr '\n' ';' < "$WORK/cluster_up.stub"))"
fi

wiring server_up "server_up k3sm-b150 hostprocess none"
if [ "$WIRE_RC" -ne 0 ] && [ -s "$WORK/server_up.reset" ] && [ ! -s "$WORK/server_up.stub" ]; then
	ladder ok "b150.7  server_up calls cluster_reset FIRST and aborts when it fails (nothing else ran)"
else
	ladder no "b150.7  server_up calls cluster_reset FIRST and aborts when it fails (rc=$WIRE_RC, stubs: $(tr '\n' ';' < "$WORK/server_up.stub"))"
fi

# ---- b150.8 / b150.9 — reap_port: kill OUR stale listener, never a foreign one
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
REAP="$WORK/reap"        # the scratch work dir listeners are attributed against
PORTS="$WORK/ports"; mkdir -p "$REAP" "$PORTS"

# start_listener sets LISTEN_PID + LISTEN_PORT. It deliberately does NOT echo the
# port through a command substitution: the fixture is a BACKGROUND process, and a
# $(...) would both hang waiting on its inherited stdout and lose $! to a subshell.
start_listener() { # <attribution-arg> <portfile-name>
	local marker="$1" pf="$PORTS/$2" i=0
	rm -f "$pf"
	python3 "$WORK/listen.py" "$marker" "$pf" >/dev/null 2>&1 &
	LISTEN_PID=$!
	LISTENER_PIDS+=("$LISTEN_PID")
	# Drop it from the job table: otherwise bash prints a "Killed: 9" job notice on
	# stderr when the fixture is reaped, AFTER the gate's own verdict line.
	disown "$LISTEN_PID" 2>/dev/null || true
	while [ ! -s "$pf" ]; do
		i=$((i + 1))
		if [ "$i" -gt 200 ]; then echo "listener never reported its port" >&2; exit 1; fi
		sleep 0.05
	done
	LISTEN_PORT="$(cat "$pf")"
}

# OURS: the argv names the rig's work dir — the same witness that attributes a
# `go run`-launched `k3sm server --work-dir …` squatting :10250.
start_listener "$REAP/pods" ours.port
PORT_OURS="$LISTEN_PORT"
# The assertion is on the PORT, not on `kill -0` of the pid: a killed child of
# this shell is a zombie until it is reaped, and kill -0 succeeds on a zombie.
ours_reaped=false
sub "$REAP" "reap_port $PORT_OURS fatal" >/dev/null 2>&1 && ours_reaped=true
if $ours_reaped && [ -z "$(lsof -nP -iTCP:"$PORT_OURS" -sTCP:LISTEN -t 2>/dev/null)" ]; then
	ladder ok "b150.8  reap_port frees a port held by THIS rig's stale process"
else
	ladder no "b150.8  reap_port frees a port held by THIS rig's stale process (rc_ok=$ours_reaped)"
fi

# FOREIGN: nothing in its argv names the rig. It must survive, fatal must refuse
# (a foreign endpoint on the kine/apiserver port would pass wait_tcp and the gate
# would run against someone else's cluster), warn must tolerate it.
start_listener "/tmp/b150-unrelated-process" foreign.port
PORT_FOREIGN="$LISTEN_PORT"
fatal_refused=false; warn_tolerated=false
sub "$REAP" "reap_port $PORT_FOREIGN fatal" >/dev/null 2>&1 || fatal_refused=true
sub "$REAP" "reap_port $PORT_FOREIGN warn"  >/dev/null 2>&1 && warn_tolerated=true
foreign_alive=false
if [ -n "$(lsof -nP -iTCP:"$PORT_FOREIGN" -sTCP:LISTEN -t 2>/dev/null)" ]; then foreign_alive=true; fi
if $fatal_refused && $warn_tolerated && $foreign_alive; then
	ladder ok "b150.9  reap_port never kills an unattributable listener (fatal refuses, warn tolerates, listener survives)"
else
	ladder no "b150.9  reap_port never kills an unattributable listener (fatal=$fatal_refused warn=$warn_tolerated alive=$foreign_alive)"
fi

# ---- b150.10 — the stage_dir_ok discipline is intact -----------------------
# clusterup.sh's root-run rm -rf of $STAGE_DIR is guarded at every mutating site.
# This change adds removals; it must not have loosened the existing ones.
if grep -qF 'stage_dir_ok() { [ "$STAGE_DIR" = /Library/k3sm-acceptance ]; }' "$LIB" \
	&& grep -qF 'stage_dir_ok && rm -rf /Library/k3sm-acceptance' "$LIB" \
	&& grep -qF 'stage_dir_ok || { echo "server_up: refusing to stage into unexpected STAGE_DIR' "$LIB"; then
	ladder ok "b150.10 stage_dir_ok still declared and asserted at both STAGE_DIR mutation sites"
else
	ladder no "b150.10 stage_dir_ok still declared and asserted at both STAGE_DIR mutation sites"
fi

# ---- b150.11 — every rm -rf in the library is an accounted-for site ---------
# The removal surface stays enumerable: the guarded reset child, the guarded
# STAGE_DIR pair, and node_up's own pod root. A new unguarded rm -rf goes red.
unaccounted="$(grep -n 'rm -rf' "$LIB" \
	| grep -vE '^[0-9]+:[[:space:]]*#' \
	| grep -v 'rm -rf "\$child"' \
	| grep -v 'rm -rf "\$STAGE_DIR"' \
	| grep -v 'rm -rf /Library/k3sm-acceptance' \
	| grep -v 'rm -rf "\$pod_root"' \
	| grep -v 'sudo rm -rf \$d' || true)"
if [ -z "$unaccounted" ]; then
	ladder ok "b150.11 no unaccounted-for rm -rf site in clusterup.sh"
else
	ladder no "b150.11 no unaccounted-for rm -rf site in clusterup.sh: $unaccounted"
fi

echo "----------------------------------------"
echo "B150: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B150 GREEN ================"
