#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# keystore-activation-probe: the measurement that decides whether the keystore's
# non-root socket listener ships with launchd socket activation or binds its own
# socket (docs/design/keystore.md, "The socket's directory is root's", "The
# client pins the server", Open requirements 3, 4, 5 and 15, "Owed to K7a").
# A probe, not a test: it prints what it saw and decides nothing.
#
# README
#
#   Build (on a Mac with the Command Line Tools; cgo links Security,
#   CoreFoundation, libSystem and libbsm only):
#     CGO_ENABLED=1 go build -tags spike -o <out> ./hack/acceptance/keystore-activation-probe
#
#   Run on the test Mac, as root, never prompting:
#     sudo [KEYSTORE_PROBE_HOLD_SECS=<s>] hack/acceptance/keystore-activation-probe/run.sh <out> <login-user> 2>&1 | tee probe.txt
#
#   Steps (each echoes a "== step" header):
#     1  create /var/lib/k3sm/keystore-probe/ root:wheel 0755 (refuse if it
#        exists), a root 0755 bin/ holding a copy of the probe, and a
#        _k3sm-owned 0700 log/
#     2  write /Library/LaunchDaemons/io.k3sm.keystore-probe.plist: UserName
#        _k3sm, a Sockets entry "keys" at keystore-probe/keys.sock, mode 0666;
#        the job runs "serve --activated keys --child-grab both"
#     3  launchctl bootstrap system
#     4  the socket's lstat and the job's state before any connection
#     5  "probe connect" as the login user, as _k3sm and as root
#     6  "probe grab keys" as the login user and as _k3sm (not the job)
#     7  the server's JSON lines (listen, child_grab, one accept per client)
#     8  step 5 again against a "serve --self-bind" server started by hand as
#        _k3sm in keystore-probe/self/ (_k3sm 0755)
#     9  optional hold (KEYSTORE_PROBE_HOLD_SECS, at most 1800) for the Pod
#        run below, then the server's lines again
#     cleanup (trap, always): bootout the label, remove the plist, remove
#        /var/lib/k3sm/keystore-probe by its exact name
#
#   What each line answers:
#     - listen.activate: does launchd activate a Sockets socket for a job with
#       UserName set, and does the job (as _k3sm) receive it (rc/errno/count,
#       fstat owner and mode of the listening descriptor, cloexec as passed).
#     - listen.child_grab: can a descendant of the job obtain the listener
#       (Open requirement 5), from the job's session and after setsid, before
#       and after the job itself took it.
#     - connect.server: does the client see the accepting server or launchd
#       (uid 0, pid 1) through LOCAL_PEERCRED, LOCAL_PEERPID and LOCAL_PEERTOKEN,
#       and does the code lookup from the token resolve it (Open requirement 4,
#       "The client pins the server").
#     - accept.peer.sandbox_token: sandbox_check_by_audit_token on each client
#       (Open requirement 15); a login shell must read not-sandboxed.
#     - grab: whether a process that is not the job gets the listener.
#
#   The Pod leg (pod.yaml.tmpl, run during the hold): the probe binary is about
#   4.8 MB, over the 1 MiB ConfigMap limit, so it is not shipped by ConfigMap.
#   The Pod runs a shell check: it tries the host copy at
#   /var/lib/k3sm/keystore-probe/bin/probe (connect, grab keys) and then
#   connects with /usr/bin/nc -U, which prints the server's accept line for
#   that connection, so the Pod's stdout and the server log show what
#   sandbox_check and the code lookup report for a confined Pod process.
#     sudo KEYSTORE_PROBE_HOLD_SECS=300 .../run.sh <out> <login-user> &
#     # once "== step 9" prints:
#     sed 's/__NODE__/<node>/' hack/acceptance/keystore-activation-probe/pod.yaml.tmpl | kubectl apply -f -
#     kubectl -n keystore-probe logs probe      # after it completes
#     kubectl delete namespace keystore-probe
#   Limit: a Pod's "grab keys" asks launchd about the Pod's own ancestor job
#   (the k3sm server's), not io.k3sm.keystore-probe, so it does not answer Open
#   requirement 5 for this socket; listen.child_grab does (a child of the job).
set -euo pipefail

LABEL=io.k3sm.keystore-probe
PLIST=/Library/LaunchDaemons/io.k3sm.keystore-probe.plist
DIR=/var/lib/k3sm/keystore-probe
SOCK="$DIR/keys.sock"
BINDIR="$DIR/bin"
BIN="$BINDIR/probe"
LOGDIR="$DIR/log"
SELFDIR="$DIR/self"
SELFSOCK="$SELFDIR/keys.sock"
SVC=_k3sm
HOLD_SECS="${KEYSTORE_PROBE_HOLD_SECS:-0}"

die() {
	echo "keystore-activation-probe: refusing: $*" >&2
	exit 2
}
step() {
	echo
	echo "== step $*"
}

[ "$(id -u)" = 0 ] || die "run as root (it bootstraps a system launchd job and runs the probe as other users)"
[ $# = 2 ] || die "usage: run.sh <built-probe> <login-user>"
SRC="$1"
LOGIN="$2"
[ -f "$SRC" ] && [ -x "$SRC" ] || die "$SRC is not an executable file"
id -u "$LOGIN" >/dev/null 2>&1 || die "no user $LOGIN"
[ "$(id -u "$LOGIN")" -ge 501 ] || die "$LOGIN is not a login user (uid below 501)"
id -u "$SVC" >/dev/null 2>&1 || die "no user $SVC"
SVC_GID="$(id -g "$SVC")"
[ -d /var/lib/k3sm ] || die "/var/lib/k3sm does not exist"
if [ -e "$DIR" ] || [ -L "$DIR" ]; then die "$DIR already exists"; fi
if [ -e "$PLIST" ] || [ -L "$PLIST" ]; then die "$PLIST already exists"; fi
if launchctl print "system/$LABEL" >/dev/null 2>&1; then die "system/$LABEL is already loaded"; fi
case "$HOLD_SECS" in '' | *[!0-9]*) die "KEYSTORE_PROBE_HOLD_SECS must be a whole number of seconds" ;; esac
[ "$HOLD_SECS" -le 1800 ] || die "KEYSTORE_PROBE_HOLD_SECS is over 1800"
cd /

DIR_MADE=0
PLIST_MADE=0
BOOTED=0
SELF_PID=""

cleanup() {
	local rc=$?
	set +e
	echo
	echo "== step cleanup"
	if [ -n "$SELF_PID" ]; then
		kill "$SELF_PID" 2>/dev/null
		wait "$SELF_PID" 2>/dev/null
	fi
	if [ "$BOOTED" = 1 ] || launchctl print "system/$LABEL" >/dev/null 2>&1; then
		launchctl bootout "system/$LABEL" && echo "booted out system/$LABEL"
	fi
	if [ "$PLIST_MADE" = 1 ]; then
		rm -f -- /Library/LaunchDaemons/io.k3sm.keystore-probe.plist && echo "removed the plist"
	fi
	if [ "$DIR_MADE" = 1 ]; then
		rm -rf -- /var/lib/k3sm/keystore-probe && echo "removed /var/lib/k3sm/keystore-probe"
	fi
	echo "cleanup done (exit $rc)"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

show() { # <path>...
	local p
	for p in "$@"; do
		if [ -e "$p" ] || [ -L "$p" ]; then
			stat -f '%N owner=%Su(%u):%Sg(%g) mode=%Sp type=%HT' "$p"
		else
			echo "$p absent"
		fi
	done
}

as() { # <user> <args...>: run the probe as user; a failure is printed, not fatal
	local u="$1"
	shift
	echo "-- as $u: probe $*"
	sudo -n -u "$u" -- "$BIN" "$@" || echo "(probe exit $?)"
}

wait_sock() { # <path> <tenths>
	local i=0
	while [ "$i" -lt "$2" ]; do
		[ -S "$1" ] && return 0
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

step "1 directories"
mkdir -- "$DIR"
DIR_MADE=1
chown root:wheel "$DIR"
chmod 0755 "$DIR"
mkdir -- "$BINDIR"
chown root:wheel "$BINDIR"
chmod 0755 "$BINDIR"
cp -- "$SRC" "$BIN"
chown root:wheel "$BIN"
chmod 0755 "$BIN"
mkdir -- "$LOGDIR"
chown "$SVC:$SVC_GID" "$LOGDIR"
chmod 0700 "$LOGDIR"
show "$DIR" "$BINDIR" "$BIN" "$LOGDIR"

step "2 plist"
PLIST_MADE=1
cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$BIN</string>
		<string>serve</string>
		<string>--activated</string>
		<string>keys</string>
		<string>--n</string>
		<string>64</string>
		<string>--timeout</string>
		<string>600</string>
		<string>--child-grab</string>
		<string>both</string>
	</array>
	<key>UserName</key>
	<string>$SVC</string>
	<key>Sockets</key>
	<dict>
		<key>keys</key>
		<dict>
			<key>SockPathName</key>
			<string>$SOCK</string>
			<key>SockPathMode</key>
			<integer>438</integer>
		</dict>
	</dict>
	<key>StandardOutPath</key>
	<string>$LOGDIR/server.log</string>
	<key>StandardErrorPath</key>
	<string>$LOGDIR/server.err</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 0644 "$PLIST"
plutil -lint "$PLIST"
cat "$PLIST"

step "3 bootstrap"
launchctl bootstrap system "$PLIST"
BOOTED=1
echo "bootstrapped system/$LABEL"

step "4 socket before any connection"
wait_sock "$SOCK" 50 || echo "socket did not appear within 5s"
show "$DIR" "$SOCK"
launchctl print "system/$LABEL" || echo "(launchctl print exit $?)"

step "5 connect to the activated socket"
as "$LOGIN" connect "$SOCK"
as "$SVC" connect "$SOCK"
as root connect "$SOCK"

step "6 grab keys from processes that are not the job"
as "$LOGIN" grab keys
as "$SVC" grab keys

step "7 activated server lines"
sleep 1
show "$SOCK"
launchctl print "system/$LABEL" || echo "(launchctl print exit $?)"
echo "-- server.log"
cat "$LOGDIR/server.log" 2>/dev/null || echo "(no server.log)"
echo "-- server.err"
cat "$LOGDIR/server.err" 2>/dev/null || echo "(no server.err)"

step "8 self-bind server as $SVC"
mkdir -- "$SELFDIR"
chown "$SVC:$SVC_GID" "$SELFDIR"
chmod 0755 "$SELFDIR"
show "$SELFDIR"
# shellcheck disable=SC2024 # root writes the log, in the root-owned probe directory
sudo -n -u "$SVC" -- "$BIN" serve --self-bind "$SELFSOCK" --n 3 --timeout 60 >"$DIR/self.log" 2>&1 &
SELF_PID=$!
if wait_sock "$SELFSOCK" 100; then
	show "$SELFSOCK"
	as "$LOGIN" connect "$SELFSOCK"
	as "$SVC" connect "$SELFSOCK"
	as root connect "$SELFSOCK"
else
	echo "self-bind socket did not appear within 10s"
	kill "$SELF_PID" 2>/dev/null || true
fi
wait "$SELF_PID" || echo "(self-bind server exit $?)"
SELF_PID=""
echo "-- self.log"
cat "$DIR/self.log"

step "9 hold for the Pod leg (${HOLD_SECS}s)"
if [ "$HOLD_SECS" -gt 0 ]; then
	echo "apply pod.yaml.tmpl now (see the header); holding ${HOLD_SECS}s"
	sleep "$HOLD_SECS"
	echo "-- server.log after the hold"
	cat "$LOGDIR/server.log" 2>/dev/null || echo "(no server.log)"
	echo "-- server.err after the hold"
	cat "$LOGDIR/server.err" 2>/dev/null || echo "(no server.err)"
else
	echo "no hold (KEYSTORE_PROBE_HOLD_SECS unset)"
fi
