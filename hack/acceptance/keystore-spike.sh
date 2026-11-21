#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# keystore-spike: measure the platform facts the keystore's user scope stands on,
# on the rig's server node, before any product code depends on them. A spike, not
# proof: it answers "can the design stand", and its results are quoted into the
# design as a dated amendment.
#
# Runs as root, only with K3SM_LAB=1. Every leg prints one status line
# (PASS, FAIL or INFO, with the measured fact) and writes its evidence to
# $K3SM_SPIKE_OUT. Everything it creates (files, flags, sockets, listeners, the
# namespace) is removed by the EXIT trap, on success and on failure.
#
# Legs and how each one decides:
#
#   1. sappnd defeat list. A temp dir under the data root, owned by the service user
#      0700 (so directory permissions do not stop a rename or unlink, and only the
#      flag does), holding a 64 KiB file owned by the service user 0600 and flagged
#      `chflags sappnd` by root. For each attempt the file is recreated and
#      re-flagged, then the helper runs the attempt as the service user and compares
#      the file before and after: the same inode at the path, SF_APPEND still set,
#      the mode unchanged, the original bytes unchanged, no shortening.
#        append                 O_APPEND write; must succeed and grow the file
#        truncate, ftruncate   truncate(2); ftruncate(2) on an O_APPEND fd
#        open-trunc             open O_TRUNC, and O_APPEND|O_TRUNC
#        pwrite                 open O_RDWR (non-append) and pwrite at 0; pwrite at 0 on an O_APPEND fd
#        punchhole              fcntl(F_PUNCHHOLE) on an O_RDWR and on an O_APPEND fd
#        link-unlink            link(2) to a new name, then unlink the original
#        clone-swap             fclonefileat to a new name, then rename the clone over the original
#        rename-over            rename a fresh file over it
#        rename-away            rename it to a new name
#        unlink                 unlink(2)
#        chflags-clear          chflags nosappnd
#        chmod                  chmod 0644 then 0666 (widening counts as a defeat)
#      PASS: append succeeded and every other attempt left the file intact. FAIL:
#      append failed or any attempt changed the file (named in the line). The same
#      line carries three recorded facts: `sysctl kern.securelevel`, whether root's
#      `chflags nosappnd` works at that level, and whether root can rename a fresh
#      file over a flagged target without clearing the flag first.
#   2. LOCAL_PEERCRED both ways. A listener runs as the service user in a 0755
#      service-user dir under the data root; root and $K3SM_SPIKE_USER each
#      connect. PASS: for each client the server read the client's own euid and pid
#      (LOCAL_PEERCRED, LOCAL_PEERPID), and the client read the service uid and the
#      listener's pid off the connected fd. FAIL otherwise.
#   3. GeneratedUID. 20 fresh helper processes (run as the service user, the
#      server's identity) each call mbr_uid_to_uuid for $K3SM_SPIKE_USER's uid once
#      (cold) and then 20 times (warm). PASS: every value is the same, and equals
#      `dscl . -read /Users/<user> GeneratedUID`. The line carries the latencies
#      (first process's cold call, the worst cold call, the median warm call).
#   4. Pod reach. A namespace keystore-spike-<rand>, a ConfigMap holding the
#      probe, and one native pod pinned by nodeName ($K3SM_SPIKE_NODE) with the
#      darwin nodeSelector and only the provider toleration. The script places a
#      listener at /var/lib/k3sm/keystore-run/keys.sock (it refuses if
#      keystore-run/ already exists, and removes both afterwards). The pod tries to
#      read keystore-floor.json, keystore-delivery.json, server/keystore/,
#      server/cred/, and to connect(2) keys.sock (perl's connect, then nc -U).
#      Each result is EPERM, ENOENT, EACCES, ECONNREFUSED, success or OTHER. The
#      host's own stat of each target is in the evidence, so an ENOENT can be read
#      against whether the file exists. FAIL: the pod did not finish or printed no
#      results, or it read server/keystore or server/cred (an existing deny
#      regressed). Otherwise INFO with every result: the profile under test is the
#      current one, without the user scope's denies, so a readable top-level file or a
#      reachable socket is the fail-before the measurement exists to record.
#   5. Pod uid. The same pod run records `id -u` and `id -un` (and the listener
#      records the peer uid of any pod that connected). PASS: a numeric uid below
#      501. FAIL: a uid of 501 or above, or none recorded.
#
# Leg 5, the runtimed paths that set a pod process's uid (read from the runtimed
# sources at b311adc; the script only records the live uid):
#   - pkg/runtime/security.go:40-61 resolveCredential: uid = the first non-zero of
#     container securityContext.runAsUser, pod securityContext.runAsUser,
#     PodBox.uid; Drop = uid != 0 || gid != 0. No lower or upper bound on the uid:
#     runAsUser: 501 resolves to a drop to 501. Callers: pkg/runtime/pod.go:1910
#     (native spawn, via WrapCommand), pkg/runtime/attach.go:593,
#     pkg/runtime/xcodeenv.go:167, pkg/runtime/vmcontainers.go:331 (VM backend).
#   - The provider passes runAsUser/runAsGroup through unchanged:
#     k3sm pkg/provider/translate.go:1150-1172.
#   - The drop itself: pkg/supervisor/privdrop.go:295-301 RunLaunchSequence
#     (setgid, initgroups, setuid), pkg/supervisor/privdrop_darwin.go:37-54
#     (unix.Setgid, Setgroups, Setuid), internal/execshim/drop.go:43-58 and
#     cmd/k3sm-execshim/main.go:90 (the exec-shim applies it before Seatbelt).
#   - The only guard: pkg/supervisor/privdrop.go:79 Credential.Validate refuses
#     any drop when the daemon's euid is not 0 (ErrDropRequiresRoot). So on the
#     service-user daemon a pod runs at the daemon's uid; on a daemon running as root,
#     a runAsUser of 501 or above is honoured.
#   - Inside a VM only (not a host uid): cmd/k3sm-guest-init/main_linux.go:815,
#     cmd/k3sm-guest-init/agent_linux.go:298 (syscall.Credential), and
#     pkg/guestinit/user.go:216-252.
#   - pkg/hostshare/delegate.go:41 MinDelegateUID = 500 bounds host-share
#     delegations to user uids; it grants path access, it does not start a pod
#     process under that uid.
#
# The helper is hack/acceptance/keystore-spike/ (package main, build tag spike,
# so ./... never builds it; stdlib and golang.org/x/sys only, plus cgo for
# mbr_uid_to_uuid and F_PUNCHHOLE). The script builds it with GOCACHE in its temp
# dir; set K3SM_SPIKE_HELPER to a binary you built yourself
# (`CGO_ENABLED=1 go build -tags spike -o <path> ./hack/acceptance/keystore-spike/`)
# to skip the build as root.
#
# Usage:
#   sudo K3SM_LAB=1 K3SM_SPIKE_NODE=<server-node> hack/acceptance/keystore-spike.sh --lab
#   sudo K3SM_LAB=1 hack/acceptance/keystore-spike.sh --leg 1
# Env: K3SM_SPIKE_OUT (evidence dir, default ./keystore-spike-out),
#   K3SM_SPIKE_USER (the login user, default miko), K3SM_SPIKE_NODE (the server
#   node's name, required by legs 4 and 5), K3SM_SPIKE_SERVICE_USER (default
#   _k3sm), K3SM_SPIKE_DATA_ROOT (default /var/lib/k3sm), K3SM_SPIKE_HELPER,
#   K3SM_SPIKE_POD_TIMEOUT (seconds, default 300), KUBECTL (default kubectl,
#   current context), GO (default go).
#
# Exit 0 when no leg failed, 1 when one did, 2 usage or refusal (K3SM_LAB unset,
# not root), 3 a precondition unmet (no data root, no service user, no kubectl or
# K3SM_SPIKE_NODE for legs 4 and 5, the helper does not build).
# The legs run through "leg$leg" and cleanup through the trap, which shellcheck
# cannot follow, so it reports every function as never invoked.
# shellcheck disable=SC2329
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh disable=SC1091
. "$HERE/../lab/lib/tolerations.sh"

usage() {
	echo "usage: K3SM_LAB=1 $0 --lab | --leg N   (N in 1..5; run as root)" >&2
	exit 2
}

LEGS=""
case "${1:-}" in
--lab)
	[ "$#" -eq 1 ] || usage
	LEGS="1 2 3 4 5"
	;;
--leg)
	[ "$#" -eq 2 ] || usage
	case "$2" in 1 | 2 | 3 | 4 | 5) LEGS="$2" ;; *) usage ;; esac
	;;
*) usage ;;
esac

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "keystore-spike: refusing: set K3SM_LAB=1; this runs on the lab rig only" >&2
	exit 2
fi
if [ "$(id -u)" != 0 ]; then
	echo "keystore-spike: refusing: run as root (it sets system flags, runs helpers as other users and binds under the data root)" >&2
	exit 2
fi

DATA_ROOT="${K3SM_SPIKE_DATA_ROOT:-/var/lib/k3sm}"
SVC="${K3SM_SPIKE_SERVICE_USER:-_k3sm}"
LOGIN="${K3SM_SPIKE_USER:-miko}"
NODE="${K3SM_SPIKE_NODE:-}"
POD_TIMEOUT="${K3SM_SPIKE_POD_TIMEOUT:-300}"
OUT="${K3SM_SPIKE_OUT:-./keystore-spike-out}"
RUN_DIR="$DATA_ROOT/keystore-run"
FAILED=0

pre() {
	echo "keystore-spike: precondition: $*" >&2
	exit 3
}
[ -d "$DATA_ROOT" ] || pre "no data root at $DATA_ROOT"
SVC_UID="$(id -u "$SVC" 2>/dev/null)" || pre "no service user $SVC"
SVC_GID="$(id -g "$SVC" 2>/dev/null)" || pre "no group for $SVC"
case " $LEGS " in *" 4 "* | *" 5 "*)
	command -v "${KUBECTL:-kubectl}" >/dev/null 2>&1 || pre "kubectl not found (legs 4 and 5)"
	[ -n "$NODE" ] || pre "K3SM_SPIKE_NODE is required for legs 4 and 5"
	;;
esac

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

kc() { "${KUBECTL:-kubectl}" "$@"; }
say() { printf '%s\n' "$*"; }
# status <leg> <PASS|FAIL|INFO> <fact>: the leg's one status line, also kept in the evidence.
status() {
	[ "$2" = FAIL ] && FAILED=1
	say "leg $1 $2 $3"
	printf 'leg %s %s %s\n' "$1" "$2" "$3" >>"$OUT/status.txt"
}
# field <line> <key>: the value of the first key=value in line.
field() { printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1; }

WORK=""
NS=""
LISTENERS=""
RUN_CREATED=0
cleanup() {
	local rc=$? p
	set +e
	for p in $LISTENERS; do kill "$p" 2>/dev/null; done
	for p in $LISTENERS; do wait "$p" 2>/dev/null; done
	if [ "$RUN_CREATED" = 1 ]; then
		rm -f "$RUN_DIR/keys.sock"
		rmdir "$RUN_DIR" 2>/dev/null || say "cleanup: WARN $RUN_DIR not empty; left in place"
		[ -e "$RUN_DIR" ] || say "cleanup: removed $RUN_DIR"
	fi
	if [ -n "$NS" ]; then
		kc delete namespace "$NS" --wait=true --timeout=180s >/dev/null 2>&1
		if kc get namespace "$NS" >/dev/null 2>&1; then
			say "cleanup: WARN namespace $NS still present"
		else
			say "cleanup: namespace $NS gone"
		fi
	fi
	if [ -n "$WORK" ] && [ -d "$WORK" ]; then
		chflags -R nosappnd "$WORK" 2>/dev/null
		rm -rf "$WORK"
		if [ -e "$WORK" ]; then
			say "cleanup: WARN $WORK could not be removed (a flag root cannot clear at this securelevel?)"
		else
			say "cleanup: removed $WORK"
		fi
	fi
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

WORK="$(mktemp -d "$DATA_ROOT/keystore-spike.XXXXXX")"
chmod 0755 "$WORK"
mkdir "$WORK/bin"
chmod 0755 "$WORK/bin"
H="$WORK/bin/keystore-spike"
if [ -n "${K3SM_SPIKE_HELPER:-}" ]; then
	cp "$K3SM_SPIKE_HELPER" "$H"
else
	(cd "$REPO" && GOCACHE="$WORK/gocache" CGO_ENABLED=1 "${GO:-go}" build -tags spike -o "$H" ./hack/acceptance/keystore-spike/) ||
		pre "the helper did not build"
	rm -rf "$WORK/gocache"
fi
chmod 0755 "$H"

{
	echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "host: $(hostname)"
	echo "os: $(sw_vers -productVersion 2>/dev/null) $(uname -r)"
	echo "k3sm: $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
	echo "legs: $LEGS"
	echo "service user: $SVC ($SVC_UID:$SVC_GID); login user: $LOGIN; node: ${NODE:-none}"
	echo "data root: $(stat -f '%Su:%Sg %Sp' "$DATA_ROOT")"
	df -P "$DATA_ROOT"
} >"$OUT/run.txt" 2>&1
: >"$OUT/status.txt"

as_svc() { sudo -n -u "$SVC" "$@"; }

# ---- leg 1 -----------------------------------------------------------------
L1_ATTEMPTS="append truncate ftruncate open-trunc pwrite punchhole link-unlink clone-swap rename-over rename-away unlink chflags-clear chmod"

l1_prep() { # <dir> <file>: a fresh 64 KiB file, the service user's 0600, flagged sappnd by root
	chflags -R nosappnd "$1" 2>/dev/null || true
	find "$1" -mindepth 1 -delete
	head -c 65536 /dev/zero | tr '\0' A >"$2"
	chown "$SVC_UID:$SVC_GID" "$2"
	chmod 0600 "$2"
	chflags sappnd "$2"
}

leg1() {
	local d="$WORK/l1" f ev="$OUT/leg1.txt" a line v held=0 total=0 bad="" appendv="" sl rr rc rename clear
	f="$d/floor.log"
	mkdir "$d"
	chown "$SVC_UID:$SVC_GID" "$d"
	chmod 0700 "$d"
	{
		echo "# leg 1: sappnd defeat list as $SVC ($SVC_UID) on $f"
		echo "# fs: $(df -P "$DATA_ROOT" | tail -n 1)"
		diskutil info "$(df -P "$DATA_ROOT" | tail -n 1 | awk '{print $1}')" 2>/dev/null | grep -Ei 'type|personality|mount point' || true
	} >"$ev"
	for a in $L1_ATTEMPTS; do
		l1_prep "$d" "$f"
		line="$(as_svc "$H" attempt "$a" "$d" "$f" 2>&1)" || line="ATTEMPT $a error ${line//$'\n'/ }"
		echo "$line" >>"$ev"
		v="$(printf '%s\n' "$line" | awk '{print $3}')"
		if [ "$a" = append ]; then
			appendv="$v"
			[ "$v" = ok ] || bad="$bad append:$v"
			continue
		fi
		total=$((total + 1))
		if [ "$v" = held ]; then
			held=$((held + 1))
		else
			bad="$bad $a:$v"
		fi
	done

	sl="$(sysctl -n kern.securelevel 2>&1)"
	echo "sysctl kern.securelevel: $sl" >>"$ev"

	l1_prep "$d" "$f"
	rr="$("$H" root-rename "$d" "$f" 2>&1)" || true
	echo "$rr" >>"$ev"
	rename="$(field "$rr" rename)"
	l1_prep "$d" "$f"
	rc="$("$H" root-clear "$f" 2>&1)" || true
	echo "$rc" >>"$ev"
	clear="$(field "$rc" cleared)"
	chflags -R nosappnd "$d" 2>/dev/null || true
	find "$d" -mindepth 1 -delete 2>/dev/null || true

	local facts
	facts="kern.securelevel=$sl; root chflags nosappnd: chflags=$(field "$rc" chflags) cleared=${clear:-unknown}; root rename over a flagged target without clearing: rename=${rename:-unknown} replaced=$(field "$rr" replaced)"
	if [ -z "$bad" ]; then
		status 1 PASS "sappnd: append $appendv, $held/$total defeat attempts held; $facts"
	else
		status 1 FAIL "sappnd: defeated or broken:$bad ($held/$total held); $facts"
	fi
}

# ---- listener helper ---------------------------------------------------------
# start_listener <sock> <max> <secs> <log>: a listener as the service user, in the
# background; waits up to 10 s for the socket.
start_listener() {
	local _
	as_svc "$H" listen "$1" "$2" "$3" >"$4" 2>&1 &
	LISTENERS="$LISTENERS $!"
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		[ -S "$1" ] && return 0
		sleep 0.5
	done
	return 1
}

# ---- leg 2 -----------------------------------------------------------------
# l2_check <client-line> <want-client-uid>: "ok" or the first mismatch.
l2_check() {
	local line="$1" want="$2" c s
	c="${line%% | *}"
	s="${line#* | }"
	[ "$(field "$c" connect)" = ok ] || { echo "connect=$(field "$c" connect)"; return; }
	[ "$(field "$c" uid)" = "$want" ] || { echo "client-uid=$(field "$c" uid)"; return; }
	[ "$(field "$c" server-euid)" = "$SVC_UID" ] || { echo "client-saw-server-euid=$(field "$c" server-euid)"; return; }
	[ "$(field "$c" server-pid)" = "$(field "$s" pid)" ] || { echo "client-saw-server-pid=$(field "$c" server-pid)/$(field "$s" pid)"; return; }
	[ "$(field "$s" saw-euid)" = "$want" ] || { echo "server-saw-euid=$(field "$s" saw-euid)"; return; }
	[ "$(field "$s" saw-pid)" = "$(field "$c" pid)" ] || { echo "server-saw-pid=$(field "$s" saw-pid)/$(field "$c" pid)"; return; }
	echo ok
}

leg2() {
	local d="$WORK/l2" sock ev="$OUT/leg2.txt" login_uid lr lu r u
	sock="$d/s.sock"
	login_uid="$(id -u "$LOGIN" 2>/dev/null)" || {
		status 2 FAIL "no login user $LOGIN"
		return
	}
	mkdir "$d"
	chown "$SVC_UID:$SVC_GID" "$d"
	chmod 0755 "$d"
	echo "# leg 2: listener as $SVC ($SVC_UID) at $sock ($(stat -f '%Su %Sp' "$d")); clients root and $LOGIN ($login_uid)" >"$ev"
	if ! start_listener "$sock" 2 60 "$OUT/leg2-server.txt"; then
		status 2 FAIL "the listener did not come up (see leg2-server.txt)"
		return
	fi
	lr="$("$H" dial "$sock" 2>&1)" || true
	lu="$(sudo -n -u "$LOGIN" "$H" dial "$sock" 2>&1)" || true
	{
		echo "root:   $lr"
		echo "$LOGIN: $lu"
	} >>"$ev"
	sleep 1
	cat "$OUT/leg2-server.txt" >>"$ev"
	r="$(l2_check "$lr" 0)"
	u="$(l2_check "$lu" "$login_uid")"
	local s_lu="${lu#* | }" fact
	fact="server saw root euid=$(field "${lr#* | }" saw-euid) pid=$(field "${lr#* | }" saw-pid), $LOGIN euid=$(field "$s_lu" saw-euid) pid=$(field "$s_lu" saw-pid); clients saw server euid=$(field "${lu%% | *}" server-euid) (want $SVC_UID)"
	if [ "$r" = ok ] && [ "$u" = ok ]; then
		status 2 PASS "LOCAL_PEERCRED both ways: $fact"
	else
		status 2 FAIL "LOCAL_PEERCRED: root=$r $LOGIN=$u; $fact"
	fi
}

# ---- leg 3 -----------------------------------------------------------------
leg3() {
	local ev="$OUT/leg3.txt" uid ds line uuids="" colds="" first_cold="" u
	uid="$(id -u "$LOGIN" 2>/dev/null)" || {
		status 3 FAIL "no login user $LOGIN"
		return
	}
	ds="$(dscl . -read "/Users/$LOGIN" GeneratedUID 2>&1 | awk '/GeneratedUID:/ {print $2}')"
	echo "# leg 3: mbr_uid_to_uuid($uid) as $SVC, 20 fresh processes x (1 cold + 20 warm); dscl GeneratedUID=$ds" >"$ev"
	for _ in $(seq 1 20); do
		line="$(as_svc "$H" guid "$uid" 20 2>&1)" || true
		echo "$line" >>"$ev"
		u="$(field "$line" uuid)"
		uuids="$uuids$u"$'\n'
		colds="$colds$(field "$line" cold_ns)"$'\n'
		[ -n "$first_cold" ] || first_cold="$(field "$line" cold_ns)"
	done
	local distinct stable_all warm_med cold_max
	distinct="$(printf '%s' "$uuids" | sort -u | wc -l | tr -d ' ')"
	stable_all="$(grep -c 'stable=true' "$ev" || true)"
	cold_max="$(printf '%s' "$colds" | sort -n | tail -n 1)"
	warm_med="$(sed -n 's/.*warm_med_ns=\([0-9]*\).*/\1/p' "$ev" | sort -n | awk '{a[NR]=$1} END {if (NR) print a[int((NR+1)/2)]}')"
	ms() { awk -v n="${1:-0}" 'BEGIN {printf "%.3fms", n/1000000}'; }
	u="$(printf '%s' "$uuids" | head -n 1)"
	local fact
	fact="uuid=$u dscl=$ds; cold first=$(ms "$first_cold") cold max=$(ms "$cold_max") (20 processes); warm median=$(ms "$warm_med")"
	if [ -n "$u" ] && [ "$distinct" = 1 ] && [ "$stable_all" = 20 ] &&
		[ "$(printf '%s' "$u" | tr '[:lower:]' '[:upper:]')" = "$(printf '%s' "$ds" | tr '[:lower:]' '[:upper:]')" ]; then
		status 3 PASS "GeneratedUID stable and equal to dscl: $fact"
	else
		status 3 FAIL "GeneratedUID: distinct=$distinct stable-processes=$stable_all/20; $fact"
	fi
}

# ---- legs 4 and 5: one pod run -----------------------------------------------
POD_DONE=0
POD_PHASE=""
POD_LOG=""

probe_script() {
	cat <<'EOF'
#!/bin/sh
# keystore-spike pod probe: one RESULT line per target, then the pod's identity.
cls() { # <rc> <stderr>
	[ "$1" = 0 ] && { echo success; return; }
	case "$2" in
	*"Operation not permitted"*) echo EPERM ;;
	*"No such file or directory"*) echo ENOENT ;;
	*"Permission denied"*) echo EACCES ;;
	*"Connection refused"*) echo ECONNREFUSED ;;
	*) echo OTHER ;;
	esac
}
one() { printf '%s' "$1" | tr '\n' ' ' | cut -c1-200; }
for p in /var/lib/k3sm/keystore-floor.json /var/lib/k3sm/keystore-delivery.json; do
	err="$(cat "$p" 2>&1 >/dev/null)"; rc=$?
	echo "RESULT read:$p $(cls "$rc" "$err") $(one "$err")"
done
for p in /var/lib/k3sm/server/keystore/ /var/lib/k3sm/server/cred/; do
	err="$(ls -a "$p" 2>&1 >/dev/null)"; rc=$?
	echo "RESULT list:$p $(cls "$rc" "$err") $(one "$err")"
done
s=/var/lib/k3sm/keystore-run/keys.sock
err="$(/usr/bin/perl -MSocket -e 'socket(my $s, PF_UNIX, SOCK_STREAM, 0) or die "socket: $!\n"; connect($s, pack_sockaddr_un($ARGV[0])) or die "connect: $!\n"; my $l = <$s>; print STDERR "connected: ", ($l // ""), "\n"; exit 0' "$s" 2>&1)"; rc=$?
echo "RESULT connect-perl:$s $(cls "$rc" "$err") $(one "$err")"
err="$(/usr/bin/nc -U -w 3 "$s" </dev/null 2>&1)"; rc=$?
echo "RESULT connect-nc:$s $(cls "$rc" "$err") $(one "$err")"
echo "ID uid=$(id -u 2>&1 | tr ' ' '_') name=$(id -un 2>&1 | tr ' ' '_')"
echo DONE
EOF
}

pod_manifest() { # <namespace> <node> <tolerations>
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: probe, namespace: $1}
spec:
  nodeName: $2
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$3]
  restartPolicy: Never
  containers:
  - name: probe
    image: native
    command: ["/bin/sh", "/spike/probe.sh"]
    volumeMounts: [{name: spike, mountPath: /spike}]
  volumes:
  - name: spike
    configMap: {name: keystore-spike-probe}
EOF
}

pod_run() {
	[ "$POD_DONE" = 1 ] && return 0
	POD_DONE=1
	local ev="$OUT/leg4-pod.txt" tol rand t end
	: >"$ev"
	if [ -e "$RUN_DIR" ]; then
		POD_PHASE="refused: $RUN_DIR already exists; the spike does not touch it"
		return 1
	fi
	mkdir "$RUN_DIR"
	RUN_CREATED=1
	chown "$SVC_UID:$SVC_GID" "$RUN_DIR"
	chmod 0755 "$RUN_DIR"
	if ! start_listener "$RUN_DIR/keys.sock" 0 "$((POD_TIMEOUT + 120))" "$OUT/leg4-listener.txt"; then
		POD_PHASE="the keys.sock listener did not come up"
		return 1
	fi
	{
		echo "# host view of each target (as root)"
		for t in "$DATA_ROOT/keystore-floor.json" "$DATA_ROOT/keystore-delivery.json" "$DATA_ROOT/server/keystore" "$DATA_ROOT/server/cred" "$RUN_DIR" "$RUN_DIR/keys.sock"; do
			if [ -e "$t" ]; then
				echo "$t $(stat -f '%Su:%Sg %Sp' "$t")"
			else
				echo "$t absent"
			fi
		done
	} >"$OUT/leg4-host-targets.txt"

	# Only the provider toleration, of every effect: K3SM_LAB_TOLERATE_KEYS is
	# blanked so the pod tolerates nothing else.
	tol="$(K3SM_LAB_TOLERATE_KEYS="" lab_tolerations_yaml "")" || return 1
	rand="$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
	NS="keystore-spike-$rand"
	probe_script >"$WORK/probe.sh"
	pod_manifest "$NS" "$NODE" "$tol" >"$OUT/leg4-pod.yaml"
	{
		kc create namespace "$NS"
		kc -n "$NS" create configmap keystore-spike-probe --from-file=probe.sh="$WORK/probe.sh"
		kc apply -f "$OUT/leg4-pod.yaml"
	} >>"$ev" 2>&1 || {
		POD_PHASE="could not create the namespace, ConfigMap or pod (see leg4-pod.txt)"
		return 1
	}
	end=$(($(date +%s) + POD_TIMEOUT))
	while :; do
		POD_PHASE="$(kc -n "$NS" get pod probe -o jsonpath='{.status.phase}' 2>/dev/null || true)"
		case "$POD_PHASE" in Succeeded | Failed) break ;; esac
		if [ "$(date +%s)" -ge "$end" ]; then
			POD_PHASE="timeout:${POD_PHASE:-none}"
			break
		fi
		sleep 3
	done
	kc -n "$NS" get pod probe -o yaml >"$OUT/leg4-pod-status.yaml" 2>&1 || true
	POD_LOG="$(kc -n "$NS" logs probe 2>&1 || true)"
	printf '%s\n' "$POD_LOG" >"$OUT/leg4-pod-log.txt"
	echo "phase: $POD_PHASE" >>"$ev"
	case "$POD_PHASE" in Succeeded | Failed) return 0 ;; *) return 1 ;; esac
}

# result <label-prefix>: the class of the RESULT line whose label starts with it.
result() { printf '%s\n' "$POD_LOG" | awk -v p="$1" '$1 == "RESULT" && index($2, p) == 1 {print $3; exit}'; }

leg4() {
	if ! pod_run; then
		status 4 FAIL "pod reach not measured: $POD_PHASE"
		return
	fi
	if ! printf '%s\n' "$POD_LOG" | grep -q '^DONE$'; then
		status 4 FAIL "the probe did not finish (phase $POD_PHASE; see leg4-pod-log.txt)"
		return
	fi
	local floor deliv sk sc cp cn conn
	floor="$(result "read:/var/lib/k3sm/keystore-floor.json")"
	deliv="$(result "read:/var/lib/k3sm/keystore-delivery.json")"
	sk="$(result "list:/var/lib/k3sm/server/keystore/")"
	sc="$(result "list:/var/lib/k3sm/server/cred/")"
	cp="$(result "connect-perl:")"
	cn="$(result "connect-nc:")"
	case "$cp" in EPERM | ENOENT | EACCES | ECONNREFUSED | success) conn="$cp" ;; *) conn="$cn" ;; esac
	local fact
	fact="keystore-floor.json=$floor keystore-delivery.json=$deliv server/keystore=$sk server/cred=$sc keys.sock connect=$conn (perl=$cp nc=$cn); listener accepts=$(grep -c '^ACCEPT' "$OUT/leg4-listener.txt" || true)"
	if [ "$sk" = success ] || [ "$sc" = success ]; then
		status 4 FAIL "pod reached server/ (an existing deny regressed): $fact"
	else
		status 4 INFO "pod reach, current profile: $fact"
	fi
}

leg5() {
	if ! pod_run; then
		status 5 FAIL "pod uid not measured: $POD_PHASE"
		return
	fi
	local id uid name peer
	id="$(printf '%s\n' "$POD_LOG" | grep '^ID ' | head -n 1)"
	uid="$(field "$id" uid)"
	name="$(field "$id" name)"
	peer="$(sed -n 's/.*saw-euid=\([0-9]*\).*/\1/p' "$OUT/leg4-listener.txt" 2>/dev/null | sort -u | tr '\n' ' ')"
	local fact
	fact="id -u=${uid:-none} id -un=${name:-none}; peer euid at keys.sock: ${peer:-no connection}"
	case "$uid" in
	'' | *[!0-9]*) status 5 FAIL "no numeric pod uid recorded: $fact" ;;
	*)
		if [ "$uid" -ge 501 ]; then
			status 5 FAIL "pod process uid is a user uid: $fact"
		else
			status 5 PASS "pod process uid below 501: $fact"
		fi
		;;
	esac
}

for leg in $LEGS; do
	"leg$leg"
done
say "evidence: $OUT"
exit "$FAILED"
