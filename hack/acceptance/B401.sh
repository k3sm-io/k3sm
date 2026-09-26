#!/usr/bin/env bash
#
# k3sm B401 acceptance gate — every bare-boot helper in hack/lib/clusterup.sh
# gives its node a per-run container log dir.
#
# `k3sm server`, `agent` and `node` all validate --pod-logs-dir at boot, and its
# default (/var/log/pods) exists only after `k3sm install`. A helper that passes
# no flag therefore dies on a fresh Mac, or right after `k3sm uninstall`, with
# "container log directory /var/log/pods is not available". The fix mirrors the
# `k3sm dev` layout: <pod-root>/log/pods, created after the helper's reset (a
# directory made before server_up is wiped by its cluster_reset).
#
# Hermetic: boots nothing, builds nothing. Each check reads ONE function body,
# extracted by a scoped range (`/^name() {/,/^}/`), never a file-wide grep.
#
#   b401.0    hack/lib/clusterup.sh and this gate parse (bash -n); the three
#             helpers are present.
#   b401.1-3  server_up / node_up / agent_up: the launch statement (the `nohup`
#             line plus its `\` continuations) carries --pod-logs-dir, and its
#             value is exactly the same statement's --pod-root value + /log/pods.
#   b401.4    server_up: the --pod-logs-dir flag sits on the launch statement
#             that follows the `fi` closing `if [ "$runtime" = runtimed ]`, and no
#             --pod-logs-dir appears inside that block. Pins: the flag is on the
#             one launch both runtimes reach, so hostprocess gets it too.
#   b401.5-7  per body, a `mkdir -p` naming the log dir comes AFTER the body's
#             reset (server_up: cluster_reset; node_up: rm -rf of the pod root;
#             agent_up: the AGENT_POD_ROOT assignment, the body having no reset of
#             its own, since server_up's cluster_reset owns it) and BEFORE the
#             launch statement.
#
# RED BEFORE: on main no helper passes --pod-logs-dir, so b401.1-3 fail (and
# b401.4-7 with them, having no flag or log-dir mkdir to place).
#
# Usage:  hack/acceptance/B401.sh [--help]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B401.sh"
LIB="$K3SM_ROOT/hack/lib/clusterup.sh"

case "${1:-}" in
-h | --help)
	sed -n '2,/^set -euo pipefail$/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'
	exit 0 ;;
"") ;;
*) echo "usage: $0 [--help]" >&2; exit 2 ;;
esac

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B401 acceptance (bare-boot helpers pass a per-run --pod-logs-dir)"

# body <fn> prints the function's definition, from its header to the first
# column-0 `}`, as "<in-body line no>\x1f<line>" (1 = the header). The unit
# separator, not a tab, because the bodies are tab-indented.
body() { sed -n "/^$1() {/,/^}/p" "$LIB" | awk '{ printf "%d\037%s\n", NR, $0 }'; }

# launch <numbered body> prints "<first line no>\t<joined statement>" for the
# first `nohup` statement, joining its backslash continuations.
launch() {
	awk -F'\037' '
		!inl && $2 ~ /^[[:space:]]*nohup / { inl = 1; start = $1; stmt = "" }
		inl {
			l = $2; sub(/^[[:space:]]+/, "", l)
			cont = (l ~ /\\$/); sub(/[[:space:]]*\\$/, "", l)
			stmt = stmt " " l
			if (!cont) { printf "%d\t%s\n", start, stmt; exit }
		}'
}

# flagval <stmt> <flag> prints the double-quoted value following <flag>.
flagval() { printf '%s\n' "$1" | sed -n "s/.*$2 \"\\([^\"]*\\)\".*/\\1/p"; }

# ---- b401.0 — parse + presence ---------------------------------------------
b0=ok
bash -n "$SELF" || b0=no
bash -n "$LIB" || b0=no
for fn in server_up node_up agent_up; do
	[ -n "$(body "$fn")" ] || { b0=no; echo "  $fn() not found in $LIB"; }
done
ladder "$b0" "b401.0  clusterup.sh and the gate parse; server_up/node_up/agent_up present"
if [ "$b0" != ok ]; then
	echo "B401: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b401.1-3 — launch carries --pod-logs-dir = <pod-root>/log/pods ---------
n=1
for fn in server_up node_up agent_up; do
	b=ok
	l="$(body "$fn" | launch)"
	stmt="${l#*$'\t'}"
	root="$(flagval "$stmt" --pod-root)"
	logs="$(flagval "$stmt" --pod-logs-dir)"
	if [ -z "$l" ]; then
		b=no; echo "  $fn: no nohup launch statement"
	elif [ -z "$logs" ]; then
		b=no; echo "  $fn: launch passes no --pod-logs-dir"
	elif [ -z "$root" ] || [ "$logs" != "$root/log/pods" ]; then
		b=no; echo "  $fn: --pod-logs-dir \"$logs\" is not --pod-root \"$root\" + /log/pods"
	fi
	ladder "$b" "b401.$n  $fn launch passes --pod-logs-dir ${logs:-<none>} (= pod root + /log/pods)"
	n=$((n+1))
done

# ---- b401.4 — server_up: flag on the common launch, not in the runtimed block
b4=ok
sb="$(body server_up)"
if_ln="$(printf '%s\n' "$sb" | awk -F'\037' '$2 ~ /^\tif \[ "\$runtime" = runtimed \]; then$/ { print $1; exit }')"
fi_ln=""
[ -n "$if_ln" ] && fi_ln="$(printf '%s\n' "$sb" | awk -F'\037' -v s="$if_ln" '$1 > s && $2 ~ /^\tfi$/ { print $1; exit }')"
l="$(printf '%s\n' "$sb" | launch)"
launch_ln="${l%%$'\t'*}"
if [ -z "$if_ln" ] || [ -z "$fi_ln" ]; then
	b4=no; echo "  server_up: cannot locate the if [ \"\$runtime\" = runtimed ] ... fi block"
else
	if printf '%s\n' "$sb" | awk -F'\037' -v s="$if_ln" -v e="$fi_ln" '$1 > s && $1 < e' | grep -q -- '--pod-logs-dir'; then
		b4=no; echo "  server_up: --pod-logs-dir appears inside the runtimed-only block"
	fi
	if [ -z "$launch_ln" ] || [ "$launch_ln" -le "$fi_ln" ]; then
		b4=no; echo "  server_up: the launch (line $launch_ln) is not after the runtimed block's fi (line $fi_ln)"
	fi
	case "${l#*$'\t'}" in *--pod-logs-dir*) ;; *) b4=no; echo "  server_up: the common launch lacks --pod-logs-dir" ;; esac
fi
ladder "$b4" "b401.4  server_up: --pod-logs-dir is on the launch after the runtimed block's fi (both runtimes)"

# ---- b401.5-7 — mkdir of the log dir after the reset, before the launch ----
n=5
# The anchors reach awk via ENVIRON, not -v, which would eat the \$ escape.
# shellcheck disable=SC2016 # the $ in these anchors is literal source text
for spec in 'server_up|^[[:space:]]*cluster_reset( |$)' \
	'node_up|^[[:space:]]*rm -rf "\$pod_root"' \
	'agent_up|^[[:space:]]*AGENT_POD_ROOT='; do
	fn="${spec%%|*}"; re="${spec#*|}"
	b=ok
	bd="$(body "$fn")"
	l="$(printf '%s\n' "$bd" | launch)"
	launch_ln="${l%%$'\t'*}"
	logs="$(flagval "${l#*$'\t'}" --pod-logs-dir)"
	reset_ln="$(printf '%s\n' "$bd" | RE="$re" awk -F'\037' '$2 ~ ENVIRON["RE"] { print $1; exit }')"
	mk_ln=""
	[ -n "$logs" ] && mk_ln="$(printf '%s\n' "$bd" | awk -F'\037' -v d="\"$logs\"" '$2 ~ /(^|[;[:space:]])mkdir -p / && index($2, d) { print $1; exit }')"
	if [ -z "$logs" ]; then
		b=no; echo "  $fn: no --pod-logs-dir to find a mkdir for"
	elif [ -z "$reset_ln" ]; then
		b=no; echo "  $fn: reset anchor /$re/ not found"
	elif [ -z "$mk_ln" ]; then
		b=no; echo "  $fn: no mkdir -p of \"$logs\""
	elif ! { [ "$mk_ln" -gt "$reset_ln" ] && [ "$mk_ln" -lt "$launch_ln" ]; }; then
		b=no; echo "  $fn: mkdir (line $mk_ln) not between reset (line $reset_ln) and launch (line $launch_ln)"
	fi
	ladder "$b" "b401.$n  $fn: mkdir -p of the log dir after the reset (body line ${reset_ln:-?}) and before the launch (${launch_ln:-?}), at ${mk_ln:-<none>}"
	n=$((n+1))
done

echo "----------------------------------------"
echo "B401: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B401 GREEN ================"
