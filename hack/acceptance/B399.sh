#!/usr/bin/env bash
#
# k3sm B399 acceptance gate — the conformance helper binaries reach the worker Mac,
# and a root-owned helper dir is named instead of failing inside `go test`.
#
# Native pods exec a host binary path, so a TestM3 pod pinned to the worker needs
# the helpers TestMain built on the gate host ($K3SM_CONFORMANCE_BIN) at the SAME
# absolute path on the worker. hack/lib/conformance-stage.sh carries the two
# host-side prerequisites; hack/lab/m3.sh calls them. This gate is hermetic: no
# cluster, no real ssh/scp (recording fakes injected through K3SM_SSH_BIN and
# K3SM_SCP_BIN, the resolution seams), no go test.
#
#   b399.0  the lib exists and both functions are defined after sourcing.
#   b399.1  preflight on a fresh writable dir returns 0 and prints nothing.
#   b399.2  preflight on a non-writable dir returns 1 and names the path + remedy.
#   b399.3  with K3SM_WORKER_SSH set, staging records mkdir -p <dir> over ssh, one
#           scp per helper to <target>:<dir>/, and the chmod +x.
#   b399.4  with K3SM_WORKER_SSH unset, the prerequisite notice names every helper.
#   b399.5  hack/lab/m3.sh sources the lib and calls both functions.
#
# RED BEFORE: on main there is no hack/lib/conformance-stage.sh, so b399.0 fails
# (hack/lab/m3.sh only carries a comment asking the operator to stage by hand, and
# hack/acceptance/m2.sh leaves the fixed dir root-owned).
#
# Usage:  hack/acceptance/B399.sh [--help]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
LIB="$K3SM_ROOT/hack/lib/conformance-stage.sh"
LAB="$K3SM_ROOT/hack/lab/m3.sh"

case "${1:-}" in
-h | --help)
	sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
"") ;;
*)
	echo "usage: $0 [--help]" >&2
	exit 2
	;;
esac

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B399 acceptance (conformance helpers staged on the worker Mac)"

# ---- b399.0 — the lib exists and defines both functions ---------------------
b0=ok
if [ -f "$LIB" ] && bash -n "$LIB"; then
	# shellcheck source=SCRIPTDIR/../lib/conformance-stage.sh
	. "$LIB"
	declare -F conformance_bin_preflight >/dev/null || b0=no
	declare -F conformance_stage_worker >/dev/null || b0=no
else
	b0=no
fi
ladder "$b0" "b399.0  hack/lib/conformance-stage.sh parses and defines conformance_bin_preflight + conformance_stage_worker"
if [ "$b0" != ok ]; then
	echo "B399: $PASS passed, $FAIL failed" >&2
	exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'chmod -R u+w "$WORKDIR" 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

# ---- b399.1 — preflight: writable, self-owned dir is silent success ---------
b1=ok
OKDIR="$WORKDIR/writable"
mkdir -p "$OKDIR"
rc=0; out="$(conformance_bin_preflight "$OKDIR" 2>&1)" || rc=$?
[ "$rc" -eq 0 ] && [ -z "$out" ] || b1=no
ladder "$b1" "b399.1  preflight on a writable self-owned dir returns 0 silently (rc=$rc, output bytes=${#out})"

# ---- b399.2 — preflight: non-writable dir is refused with the remedy --------
# chmod 555, still owned by this user: this proves the not-writable branch. The lab
# case (a dir left root-owned by a sudo gate run) takes the same branch, via the
# owner-uid check as well as the writability check. A root run (uid 0) is exempt by
# construction (root can always rebuild into the dir), so it cannot be proven here
# without privilege and is not asserted.
b2=ok
RODIR="$WORKDIR/readonly"
mkdir -p "$RODIR"; chmod 555 "$RODIR"
if [ -w "$RODIR" ]; then
	# Running as root: every dir is writable, so this branch cannot be exercised.
	b2=no
	echo "  (b399.2 cannot run as root: chmod 555 does not remove root's write access)"
fi
rc=0; out="$(conformance_bin_preflight "$RODIR" 2>&1)" || rc=$?
[ "$rc" -eq 1 ] || b2=no
printf '%s\n' "$out" | grep -qF "$RODIR" || b2=no
printf '%s\n' "$out" | grep -qF "sudo rm -rf $RODIR" || b2=no
printf '%s\n' "$out" | grep -qF "K3SM_CONFORMANCE_BIN" || b2=no
printf '%s\n' "$out" | grep -qF "SAME absolute path on the worker" || b2=no
[ "$b2" = ok ] || printf '%s\n' "$out" | sed 's/^/    /'
ladder "$b2" "b399.2  preflight on a non-writable dir returns 1 and names the path + remedy (rc=$rc)"

# ---- fixtures: two fake helpers + recording ssh/scp -------------------------
HDIR="$WORKDIR/helpers"
mkdir -p "$HDIR"
printf 'fake\n' >"$HDIR/helper-one"
printf 'fake\n' >"$HDIR/helper-two"
LOG="$WORKDIR/argv.log"
: >"$LOG"
cat >"$WORKDIR/fake-ssh" <<FAKE
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$LOG"
FAKE
cat >"$WORKDIR/fake-scp" <<FAKE
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$LOG"
FAKE
chmod +x "$WORKDIR/fake-ssh" "$WORKDIR/fake-scp"

# ---- b399.3 — staging with K3SM_WORKER_SSH set ------------------------------
b3=ok
rc=0
out="$(K3SM_WORKER_SSH=lab@worker K3SM_SSH_BIN="$WORKDIR/fake-ssh" K3SM_SCP_BIN="$WORKDIR/fake-scp" \
	conformance_stage_worker "$HDIR" helper-one helper-two 2>&1)" || rc=$?
[ "$rc" -eq 0 ] || b3=no
grep -qE "^ssh lab@worker mkdir -p $HDIR( |\$)" "$LOG" || b3=no
grep -qxF "scp $HDIR/helper-one lab@worker:$HDIR/" "$LOG" || b3=no
grep -qxF "scp $HDIR/helper-two lab@worker:$HDIR/" "$LOG" || b3=no
[ "$(grep -c '^scp ' "$LOG")" -eq 2 ] || b3=no
grep -qxF "ssh lab@worker chmod +x $HDIR/helper-one $HDIR/helper-two" "$LOG" || b3=no
[ "$(printf '%s\n' "$out" | grep -c '^staged ')" -eq 2 ] || b3=no
[ "$b3" = ok ] || { echo "  recorded argv:"; sed 's/^/    /' "$LOG"; printf '%s\n' "$out" | sed 's/^/    /'; }
ladder "$b3" "b399.3  K3SM_WORKER_SSH set: mkdir -p over ssh, one scp per helper to lab@worker:<dir>/, chmod +x (rc=$rc, $(wc -l <"$LOG" | tr -d ' ') argv lines)"

# ---- b399.4 — K3SM_WORKER_SSH unset: the prerequisite notice ----------------
b4=ok
: >"$LOG"
rc=0
out="$(unset K3SM_WORKER_SSH; K3SM_SSH_BIN="$WORKDIR/fake-ssh" K3SM_SCP_BIN="$WORKDIR/fake-scp" \
	conformance_stage_worker "$HDIR" helper-one helper-two 2>&1)" || rc=$?
[ "$rc" -eq 0 ] || b4=no
printf '%s\n' "$out" | grep -qF "PREREQUISITE (worker Mac): the worker needs the same conformance helpers at the same absolute path $HDIR" || b4=no
printf '%s\n' "$out" | grep -qF "helper-one" || b4=no
printf '%s\n' "$out" | grep -qF "helper-two" || b4=no
printf '%s\n' "$out" | grep -qF "K3SM_WORKER_SSH=" || b4=no
[ -s "$LOG" ] && b4=no
[ "$b4" = ok ] || printf '%s\n' "$out" | sed 's/^/    /'
ladder "$b4" "b399.4  K3SM_WORKER_SSH unset: prerequisite notice names the path and every helper, returns 0, calls no ssh/scp (rc=$rc)"

# ---- b399.5 — hack/lab/m3.sh sources the lib and calls both functions --------
# Source-level: the lab gate exits 0 without K3SM_LAB=1, so running it proves nothing.
# The patterns match literal $VAR text in the script, hence single quotes.
b5=ok
# shellcheck disable=SC2016
{
	grep -qE '^\. "\$HERE/\.\./lib/conformance-stage\.sh"' "$LAB" || b5=no
	grep -qE 'conformance_bin_preflight "\$K3SM_CONFORMANCE_BIN"' "$LAB" || b5=no
	grep -qE 'conformance_stage_worker "\$K3SM_CONFORMANCE_BIN"' "$LAB" || b5=no
	grep -qE 'conformance_helper_names "\$REPO_ROOT"' "$LAB" || b5=no
}
ladder "$b5" "b399.5  hack/lab/m3.sh sources conformance-stage.sh and calls preflight + stage (helper names read from e2e/testdata/cmd)"

echo "----------------------------------------"
echo "B399: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B399 GREEN ================"
