#!/usr/bin/env bash
#
# k3sm B404 acceptance gate — the SIT's T2 (psa-enforce) leg preflights its work
# dir and resets its server log before it boots.
#
# `sudo hack/sit/run.sh` runs T2 as root, so $SIT_PSA_WORKDIR (default
# /tmp/k3sm-sit-psa) is left root-owned. A later rootless run then failed T2 with
# "server.log: Permission denied" at the boot redirect, and its failure path
# printed that EARLIER run's server.log as "the flagged server's last log lines".
# The fix runs the dir-generic owner/writability preflight from
# hack/lib/conformance-stage.sh on $SIT_PSA_WORKDIR before the boot, aborting
# with the remedy, and removes the previous server.log before the boot line.
#
# Hermetic: boots nothing, builds nothing, needs no root. Checks read ONE
# function body (run_psa_enforce_leg), extracted by a scoped range, never a
# file-wide grep.
#
#   b404.0  run.sh, the lib and this gate parse (bash -n); run.sh sources
#           conformance-stage.sh; run_psa_enforce_leg and the preflight exist.
#   b404.1  in run_psa_enforce_leg, `if ! conformance_bin_preflight
#           "$SIT_PSA_WORKDIR" SIT_PSA_WORKDIR` precedes the boot line (the
#           `nohup ... "$BIN"` launch).
#   b404.2  in run_psa_enforce_leg, an `rm -f "$log"` precedes the boot line.
#   b404.3  the preflight on a chmod-555 fixture dir returns 1 and its message
#           names the fixture path, `sudo rm -rf <path>`, and SIT_PSA_WORKDIR=.
#
# RED BEFORE: on main run.sh neither calls the preflight nor removes the log, so
# b404.0 (no source line) and b404.1-2 fail.
#
# Usage:  hack/acceptance/B404.sh [--help]
#         B404_K3SM_ROOT=<checkout> hack/acceptance/B404.sh   # check another tree
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SELF="$HERE/B404.sh"
K3SM_ROOT="${B404_K3SM_ROOT:-$(cd "$HERE/../.." && pwd)}"
RUN="$K3SM_ROOT/hack/sit/run.sh"
LIB="$K3SM_ROOT/hack/lib/conformance-stage.sh"

case "${1:-}" in
-h | --help)
	sed -n '2,/^set -euo pipefail$/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'
	exit 0 ;;
"") ;;
*) echo "usage: $0 [--help]" >&2; exit 2 ;;
esac

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B404 acceptance (SIT T2 preflights its work dir and resets its log) [$K3SM_ROOT]"

# body prints run_psa_enforce_leg, header to the first column-0 `}`, as
# "<in-body line no>\x1f<line>" (1 = the header).
body() { sed -n '/^run_psa_enforce_leg() {/,/^}/p' "$RUN" | awk '{ printf "%d\037%s\n", NR, $0 }'; }
# first_ln <ERE> prints the first body line number whose text matches <ERE>.
# The pattern reaches awk via ENVIRON, not -v, which would eat the \$ escapes.
first_ln() { body | RE="$1" awk -F'\037' '$2 ~ ENVIRON["RE"] { print $1; exit }'; }

# ---- b404.0 — parse + presence ---------------------------------------------
b0=ok
bash -n "$SELF" || b0=no
bash -n "$RUN" || b0=no
bash -n "$LIB" || b0=no
[ -n "$(body)" ] || { b0=no; echo "  run_psa_enforce_leg() not found in $RUN"; }
# shellcheck disable=SC2016 # literal source text
grep -qE '^\. "\$HERE/\.\./lib/conformance-stage\.sh"' "$RUN" || { b0=no; echo "  run.sh does not source hack/lib/conformance-stage.sh"; }
# shellcheck source=SCRIPTDIR/../lib/conformance-stage.sh
. "$LIB"
declare -F conformance_bin_preflight >/dev/null || { b0=no; echo "  conformance_bin_preflight not defined by $LIB"; }
ladder "$b0" "b404.0  run.sh, the lib and the gate parse; run.sh sources conformance-stage.sh; leg + preflight present"

# shellcheck disable=SC2016 # the $ in these anchors is literal source text
boot_ln="$(first_ln '^[[:space:]]*nohup .*"\$BIN"')"

# ---- b404.1 — preflight precedes the boot ----------------------------------
b1=ok
# shellcheck disable=SC2016
pre_ln="$(first_ln '^[[:space:]]*if ! conformance_bin_preflight "\$SIT_PSA_WORKDIR" SIT_PSA_WORKDIR; then$')"
if [ -z "$boot_ln" ]; then
	b1=no; echo "  no nohup ... \"\$BIN\" boot line in run_psa_enforce_leg"
elif [ -z "$pre_ln" ]; then
	b1=no; echo "  no 'if ! conformance_bin_preflight \"\$SIT_PSA_WORKDIR\" SIT_PSA_WORKDIR' in run_psa_enforce_leg"
elif [ "$pre_ln" -ge "$boot_ln" ]; then
	b1=no; echo "  preflight (line $pre_ln) is not before the boot (line $boot_ln)"
fi
ladder "$b1" "b404.1  T2 preflights \$SIT_PSA_WORKDIR (body line ${pre_ln:-<none>}) before the boot (${boot_ln:-<none>})"

# ---- b404.2 — server.log reset precedes the boot ---------------------------
b2=ok
# shellcheck disable=SC2016
rm_ln="$(first_ln '^[[:space:]]*rm -f "\$log"[[:space:]]*$')"
# shellcheck disable=SC2016
log_ln="$(first_ln 'log="\$SIT_PSA_WORKDIR/server\.log"')"
if [ -z "$boot_ln" ] || [ -z "$log_ln" ]; then
	b2=no; echo "  cannot locate the boot line or the log=\$SIT_PSA_WORKDIR/server.log assignment"
elif [ -z "$rm_ln" ]; then
	b2=no; echo "  no rm -f \"\$log\" in run_psa_enforce_leg"
elif ! { [ "$rm_ln" -gt "$log_ln" ] && [ "$rm_ln" -lt "$boot_ln" ]; }; then
	b2=no; echo "  rm -f \"\$log\" (line $rm_ln) not between the log assignment ($log_ln) and the boot ($boot_ln)"
fi
ladder "$b2" "b404.2  T2 removes the previous server.log (body line ${rm_ln:-<none>}) before the boot (${boot_ln:-<none>})"

# ---- b404.3 — preflight on a non-writable fixture --------------------------
b3=ok
TMP="$(mktemp -d "${TMPDIR:-/tmp}/b404.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT
RODIR="$TMP/k3sm-sit-psa"
mkdir "$RODIR"
chmod 555 "$RODIR"
if [ -w "$RODIR" ]; then
	b3=no
	echo "  (b404.3 cannot run as root: chmod 555 does not remove root's write access)"
fi
rc=0; out="$(conformance_bin_preflight "$RODIR" SIT_PSA_WORKDIR 2>&1)" || rc=$?
[ "$rc" -eq 1 ] || b3=no
printf '%s\n' "$out" | grep -qF "$RODIR" || b3=no
printf '%s\n' "$out" | grep -qF "sudo rm -rf $RODIR" || b3=no
printf '%s\n' "$out" | grep -qF "SIT_PSA_WORKDIR=" || b3=no
[ "$b3" = ok ] || printf '%s\n' "$out" | sed 's/^/    /'
ladder "$b3" "b404.3  preflight on a chmod-555 dir returns 1 and names the path + remedy (rc=$rc)"

echo "----------------------------------------"
echo "B404: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B404 GREEN ================"
