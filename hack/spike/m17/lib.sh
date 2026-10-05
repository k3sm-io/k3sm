#!/usr/bin/env bash
# shellcheck disable=SC2034 # a sourced library: the variables it sets are read by the rungs
# Shared plumbing for the M17.0 spikes (s1.sh … s5.sh) and for run.sh, which chains
# them. The M17 plan's §Sub-phases M17.0 is what each rung answers; its Phase B
# resolution R8 is the list of pre-decided substitutions every halt below quotes.
#
# THE RIG. Two Macs joined by one Thunderbolt cable, both members of one k3sm
# cluster (one server, one agent), both on main, both Ready. The DRIVER (this
# script) runs on a third shell, or on either Mac, and reaches both Macs over ssh on
# their LAN. Every privileged change is a SCRIPT FILE written to the evidence
# directory, copied to the Mac and run there under `sudo -n /bin/bash <file>` (one
# sudo over the whole file: `ssh host "sudo a && b"` runs only `a` as root). Each
# such script carries the restore library below, which records every change it makes
# in a root-owned ledger on that Mac and undoes them in reverse:
#
#   * bridge0 membership put back for every Thunderbolt port the spike removed;
#   * every interface alias, lo0 alias and route the spike added removed again;
#   * TSO/LRO and interface up/down state put back; any packet-filter anchor flushed.
#
# The LAN route is NEVER touched: the ledger only ever names what the spike added,
# and the add helpers refuse the default route and any route over the interface the
# default route uses, so the ssh session the driver rides survives every rung.
# A rung restores both Macs on exit (normal, FAIL, Ctrl-C or a dropped session), and
# every rung begins by replaying any ledger an interrupted earlier run left behind.
#
# Usage (from a k3sm checkout):
#   K3SM_LAB=1 K3SM_M17_SERVER=<ssh target> K3SM_M17_WORKER=<ssh target> \
#     K3SM_EVIDENCE=<dir outside any repository> hack/spike/m17/run.sh
#   ... hack/spike/m17/s2.sh             # one rung
#   hack/spike/m17/s2.sh --plan          # the question and verdict criteria, no host
#
# K3SM_M17_SERVER and K3SM_M17_WORKER are REQUIRED on the real path and have NO
# default: they name an operator's own machines, so naming one here would put a
# private host in a public repository. No rung ever prints them, or any hostname:
# evidence names the two Macs by role (server, worker), model and macOS build only.
#
# ---------------------------------------------------------------------------------
# THE EXIT CONTRACT (defined here, ONCE; every s<N>.sh and run.sh obey it)
#
#   0  PASS      every required criterion of the rung reached a verdict, and passed.
#   1  FAIL      a required criterion failed, or the rung refused to run (no
#                K3SM_LAB=1, a missing host or evidence variable, a rig that is not
#                ready). For a failed criterion the M17 plan's halt applies and the
#                substitution printed beside it is pre-decided (R8).
#   2  RECORDED  nothing failed, but the rung produced only measurements and no
#                verdict. NOT a green M17.0: a measurement does not discharge a row.
#
# A rung that passes a criterion and records figures exits 0: recording is
# additive evidence, never a downgrade. Only a rung with no verdict at all exits 2.
# ---------------------------------------------------------------------------------
#
# SOURCING THIS FILE REQUIRES NOTHING. The host and evidence variables are demanded
# by spike_begin, which runs on the real path only, so `s<N>.sh --plan` works on a
# machine with no rig, no cable and no cluster.
#
# Optional knobs (each recorded in the rung's context file when used):
#   K3SM_M17_SERVER_IFACE, K3SM_M17_WORKER_IFACE   pin the cable interfaces instead
#                                                  of discovering them (S1's mapping)
#   K3SM_M17_CABLE        the cable as the operator describes it (model, length);
#                         recorded beside every figure, "undeclared" when unset
#   K3SM_M17_RUNS         runs per figure (default 5; fewer is refused)
#   K3SM_M17_UNPLUGS      physical unplugs S4 asks for (default 10; fewer is refused)
#   K3SM_M17_FLIPS        administrative link flips S4 performs (default 10)
#   K3SM_M17_PROMPT_WAIT  seconds a physical-touch prompt waits (default 180)
#   K3SM_M17_ALLOW_REBOOT=1      S1 reboots the worker to test receptacle stability
#   K3SM_M17_ALLOW_SLEEP=1       S4 sleeps the worker (with a scheduled wake)
#   K3SM_M17_WG_CABLE_ROUTE=1    the wireguard-over-cable legs pin the worker's path
#                                to the server's wireguard endpoint onto the cable
#   K3SM_M17_MLX_IMAGE, K3SM_M17_MODEL, K3SM_M17_MODEL_REV, K3SM_M17_RANK_MEMORY  (S5)

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPIKE_REPO_ROOT="$(cd "$SPIKE_DIR/../../.." && pwd)"

# Where scripts and the probe land on each Mac (the login user's), and where the
# root-owned restore ledger lives (inside the k3sm footprint, never elsewhere).
REMOTE_DIR="/tmp/k3sm-m17-spike"
STATE_DIR="/var/lib/k3sm/spike-m17"
NS="k3sm-m17-spike"

RUNS="${K3SM_M17_RUNS:-5}"
UNPLUGS="${K3SM_M17_UNPLUGS:-10}"
FLIPS="${K3SM_M17_FLIPS:-10}"
PROMPT_WAIT="${K3SM_M17_PROMPT_WAIT:-180}"
CABLE_DESC="${K3SM_M17_CABLE:-undeclared}"

# The S5 pins. The model and revision are the ones the M16 spike and the M17-lab
# ladder pin, so the single-Mac figure is comparable across all three; the image is
# the one the M17-lab ladder runs, and the digest it resolves to is recorded.
MLX_IMAGE="${K3SM_M17_MLX_IMAGE:-ghcr.io/k3sm-io/mlx-serve:0.4.1}"
MODEL_REPO="${K3SM_M17_MODEL:-mlx-community/Qwen3-0.6B-4bit}"
MODEL_REV="${K3SM_M17_MODEL_REV:-73e3e38d981303bc594367cd910ea6eb48349da8}"
RANK_MEMORY="${K3SM_M17_RANK_MEMORY:-3Gi}"
COLLECTIVE_PORT=29500

PASSES=0
FAILS=0
RECORDS=0

# The topology spike_topology fills in; empty until then, so a rung that stops
# early can still run its exit path under `set -u`.
SRV_IF="" WRK_IF="" SRV_PORT=-1 WRK_PORT=-1 SRV_UUID="" WRK_UUID="" SPEED_GBPS=0
SRV_NODE="" WRK_NODE="" SRV_POD_CIDR="" WRK_POD_CIDR=""
SRV_LINK="" WRK_LINK="" SRV_EGRESS="" WRK_EGRESS="" SRV_HALVES="" WRK_HALVES=""
SRV_PROBE_IP="" WRK_PROBE_IP="" TOPOLOGY_OK=0 RUNG="" RUNG_DIR=""

note() { printf '\n==> %s\n' "$*"; }
pass() {
	echo "PASS      $*"
	PASSES=$((PASSES + 1))
}
fail() {
	echo "FAIL      $*"
	FAILS=$((FAILS + 1))
}
record() {
	echo "RECORDED  $*"
	RECORDS=$((RECORDS + 1))
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# spike_verdict <rung> — print the scoreboard and exit per the contract above.
spike_verdict() {
	local rung="$1" f
	f="findings-$(lower "$rung").md"
	echo
	echo "==== $rung: $PASSES passed, $FAILS failed, $RECORDS recorded ===="
	if [ "$FAILS" -gt 0 ]; then
		echo "$rung: FAIL — the halt for the failed criterion applies; land its pre-decided substitution (printed beside it) in hack/spike/m17/$f"
		exit 1
	fi
	if [ "$PASSES" -eq 0 ]; then
		echo "$rung: RECORDED ONLY — measurements without a verdict do not discharge the row"
		exit 2
	fi
	echo "$rung: PASS"
	exit 0
}

# spike_plan <rung> <question> <criteria> <method> <halt> — the --plan handler. It
# prints the rung and exits 0 WITHOUT reading any host or evidence variable, so the
# ladder's shape is reviewable with no rig attached.
spike_plan() {
	echo "==> k3sm M17.0 spike $1 — PLAN ONLY (nothing is contacted, nothing is written)"
	echo
	echo "question"
	printf '%s\n' "$2" | sed 's/^/  /'
	echo
	echo "verdict criteria (PASS/FAIL; anything else is RECORDED)"
	printf '%s\n' "$3" | sed 's/^/  /'
	echo
	echo "method"
	printf '%s\n' "$4" | sed 's/^/  /'
	echo
	echo "halt and pre-decided substitution (the M17 plan, R8)"
	printf '%s\n' "$5" | sed 's/^/  /'
	echo
	echo "findings   hack/spike/m17/findings-$(lower "$1").md"
	echo "exit       0 PASS · 1 FAIL · 2 RECORDED (hack/spike/m17/lib.sh)"
	echo "rig        K3SM_LAB=1, K3SM_M17_SERVER, K3SM_M17_WORKER, K3SM_EVIDENCE (required; no defaults)"
	exit 0
}

# spike_args <rung> <question> <criteria> <method> <halt> "$@" — every rung's
# argument handling, so --plan is parsed before anything else is read.
spike_args() {
	local rung="$1" q="$2" c="$3" m="$4" h="$5"
	shift 5
	case "${1:-}" in
	--plan | --dry-run) spike_plan "$rung" "$q" "$c" "$m" "$h" ;;
	"") ;;
	*)
		echo "$(lower "$rung").sh: unknown argument: $1 (try --plan)" >&2
		exit 2
		;;
	esac
}

# spike_require — the refusal half of the contract. Under no K3SM_LAB=1 a rung
# REFUSES (exit 1: it never ran, so it is never a green). Under K3SM_LAB=1 a
# missing host or evidence variable is a FAIL, never a PENDING: a lab run that
# cannot reach its Macs proved nothing.
spike_require() {
	local rung="$1" missing="" v
	if [ "${K3SM_LAB:-}" != "1" ]; then
		echo "M17.0 $rung: REFUSED — this rung changes host networking on two Macs and runs only under K3SM_LAB=1 with K3SM_M17_SERVER, K3SM_M17_WORKER and K3SM_EVIDENCE set. This is NOT a pass." >&2
		exit 1
	fi
	for v in K3SM_M17_SERVER K3SM_M17_WORKER K3SM_EVIDENCE; do
		[ -n "${!v:-}" ] || missing="$missing $v"
	done
	if [ -n "$missing" ]; then
		echo "FAIL      M17.0 $rung: missing$missing (no defaults: the ssh targets are the operator's own machines, and evidence lives outside any repository). A missing host is a FAIL, never a PENDING." >&2
		exit 1
	fi
	case "$K3SM_EVIDENCE" in
	/*) ;;
	*)
		echo "FAIL      M17.0 $rung: K3SM_EVIDENCE must be an absolute path" >&2
		exit 1
		;;
	esac
	# Judge the nearest existing ancestor BEFORE creating anything, so a refused
	# path never leaves a directory behind inside a repository.
	local probe="$K3SM_EVIDENCE"
	while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
	if git -C "$probe" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		echo "FAIL      M17.0 $rung: K3SM_EVIDENCE is inside a git work tree; evidence never lands in a repository" >&2
		exit 1
	fi
	mkdir -p "$K3SM_EVIDENCE" || {
		echo "FAIL      M17.0 $rung: cannot create $K3SM_EVIDENCE" >&2
		exit 1
	}
}

target_of() {
	case "$1" in
	server) printf '%s' "$K3SM_M17_SERVER" ;;
	worker) printf '%s' "$K3SM_M17_WORKER" ;;
	*)
		echo "lib.sh: unknown side $1" >&2
		return 1
		;;
	esac
}

peer_of() { if [ "$1" = server ]; then echo worker; else echo server; fi; }

# on <side> <command> — run one command on a Mac in a login shell (a
# non-interactive ssh gets no login PATH otherwise).
on() {
	local t
	t="$(target_of "$1")" || return 1
	ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 "$t" "zsh -lc $(printf '%q' "$2")"
}

# kc <kubectl args...> — kubectl on the server Mac through `k3sm kubectl` (which
# resolves the admin context the installer merged for the login user).
kc() { on server "k3sm kubectl --request-timeout=30s $(printf '%q ' "$@")"; }

# ---------------------------------------------------------------------------------
# Payloads. A payload is a heredoc on stdin; the driver writes it, with the preamble
# (and, for a privileged payload, the restore library) and the named variables, to
# $RUNG_DIR/<side>-<name>.sh, copies it to the Mac and runs it. A payload reports
# ONLY through `verdict PASS|FAIL <text>` and `recorded <text>` lines, which the
# driver scans into the scoreboard, so a verdict is data the Mac produced, never the
# driver's reading of a log.
# ---------------------------------------------------------------------------------

read -r -d '' PAYLOAD_PREAMBLE <<'PREEOF' || true
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
verdict()  { echo "VERDICT $1 $2"; }
recorded() { echo "RECORD $*"; }
ms()       { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }

run_timeout() {
  local secs="$1"; shift
  "$@" & local pid=$!
  ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null; sleep 2; kill -KILL "$pid" 2>/dev/null ) 2>/dev/null &
  local watcher=$!
  local rc=0; wait "$pid" 2>/dev/null || rc=$?
  kill -TERM "$watcher" 2>/dev/null || true
  return "$rc"
}

link_state() {   # active | inactive | gone
  if ! ifconfig "$1" >/dev/null 2>&1; then echo gone; return; fi
  if ifconfig "$1" | grep -q 'status: active'; then echo active; else echo inactive; fi
}

# wait_link <iface> <active|inactive|gone|down> <seconds> — block until the state is
# reached (down = inactive or gone); print the epoch ms it was seen, or "timeout".
wait_link() {
  local deadline=$(( $(date +%s) + $3 )) s
  while [ "$(date +%s)" -lt "$deadline" ]; do
    s="$(link_state "$1")"
    if [ "$s" = "$2" ] || { [ "$2" = down ] && [ "$s" != active ]; }; then ms; return 0; fi
    sleep 0.2
  done
  echo timeout; return 1
}

is_member() { ifconfig bridge0 2>/dev/null | awk '$1=="member:"{print $2}' | grep -qx "$1"; }

tso_lro_on() {   # prints the offload flags still on, empty when all are off
  ifconfig "$1" | sed -n 's/.*options=[0-9a-f]*<\(.*\)>.*/\1/p' | tr ',' '\n' | grep -E '^(TSO4|TSO6|LRO)$' | tr '\n' ' '
}
PREEOF

# THE RESTORE LIBRARY, injected into every privileged payload. Every change goes
# through a spike_* helper that appends one ledger line; spike_restore replays the
# ledger in reverse and truncates it. SPIKE_HOLD=1 keeps the changes past the
# payload's normal exit (a rung that configures once and measures many times); the
# driver's own exit then restores them. A signal ALWAYS restores.
read -r -d '' RESTORE_LIB <<'RESTEOF' || true
STATE_DIR="${STATE_DIR:-/var/lib/k3sm/spike-m17}"
LEDGER="$STATE_DIR/restore.ledger"
mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR" && touch "$LEDGER"
LAN_IF="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"

ledger() { echo "$*" >>"$LEDGER"; }
refuse() { echo "RESTORE-LIB REFUSED: $*" >&2; return 1; }
in_reserved() { case "$1" in 169.254.0.*|169.254.255.*) return 0 ;; esac; return 1; }
not_lan() { [ -n "$1" ] && [ "$1" != "$LAN_IF" ] || refuse "interface '$1' is the LAN interface (the default route) or empty"; }

spike_deletem() {         # spike_deletem <iface>
  not_lan "$1" || return 1
  is_member "$1" || return 0
  ifconfig bridge0 deletem "$1" && ledger "member $1"
  ! is_member "$1"
}
spike_alias() {           # spike_alias <iface> <reserved-half ip>
  not_lan "$1" || return 1
  in_reserved "$2" || { refuse "$2 is outside the reserved direct-link halves"; return 1; }
  ifconfig "$1" | grep -q "inet $2 " && return 0
  ifconfig "$1" inet "$2" "$2" netmask 255.255.255.255 alias && ledger "alias $1 $2"
}
spike_lo0_alias() {       # spike_lo0_alias <ip>
  ifconfig lo0 | grep -q "inet $1 " && { refuse "$1 is already a lo0 alias (a pod or the mesh owns it)"; return 1; }
  ifconfig lo0 alias "$1/32" && ledger "lo0alias $1"
}
spike_route() {           # spike_route -host|-net <dest> <gateway args...>
  local kind="$1" dest="$2"; shift 2
  case "$dest" in default|0.0.0.0|0.0.0.0/*|*/0) refuse "the default route is never touched"; return 1 ;; esac
  case " $* " in *" $LAN_IF "*) refuse "a route over the LAN interface is never touched"; return 1 ;; esac
  route -n add "$kind" "$dest" "$@" >/dev/null && ledger "route $kind $dest"
}
spike_unroute() {         # spike_unroute -host|-net <dest> — one ledger route, early
  route -n delete "$1" "$2" >/dev/null 2>&1
  grep -vxF "route $1 $2" "$LEDGER" >"$LEDGER.tmp"; mv "$LEDGER.tmp" "$LEDGER"
}
spike_offload_off() {     # spike_offload_off <iface>
  not_lan "$1" || return 1
  local on tso=0 lro=0; on="$(tso_lro_on "$1")"
  case "$on" in *TSO*) tso=1 ;; esac
  case "$on" in *LRO*) lro=1 ;; esac
  ledger "offload $1 $tso $lro"
  ifconfig "$1" -tso 2>/dev/null; ifconfig "$1" -lro 2>/dev/null; return 0
}
spike_ifdown() {          # spike_ifdown <iface>
  not_lan "$1" || return 1
  ifconfig "$1" down && ledger "ifup $1"
}
spike_ifup() {            # spike_ifup <iface> — undo one spike_ifdown early
  ifconfig "$1" up
  grep -vxF "ifup $1" "$LEDGER" >"$LEDGER.tmp"; mv "$LEDGER.tmp" "$LEDGER"
}
spike_pf_block() {        # spike_pf_block <anchor> <rule>
  local tok; tok="$(pfctl -E 2>&1 | awk '/Token/{print $3}')"
  ledger "pf $1 ${tok:-none}"
  echo "$2" | pfctl -a "com.apple/$1" -f - 2>/dev/null
}
spike_pf_clear() {        # spike_pf_clear <anchor> — undo one spike_pf_block early
  local tok; tok="$(awk -v a="$1" '$1=="pf" && $2==a{print $3}' "$LEDGER" | tail -1)"
  pfctl -a "com.apple/$1" -F all >/dev/null 2>&1
  [ -n "$tok" ] && [ "$tok" != none ] && pfctl -X "$tok" >/dev/null 2>&1
  awk -v a="$1" '!($1=="pf" && $2==a)' "$LEDGER" >"$LEDGER.tmp"; mv "$LEDGER.tmp" "$LEDGER"
}
spike_restore() {
  [ -s "$LEDGER" ] || return 0
  local kind a b c n=0
  while read -r kind a b c; do
    case "$kind" in
    route)    route -n delete "$a" "$b" >/dev/null 2>&1 ;;
    alias)    ifconfig "$a" -alias "$b" 2>/dev/null ;;
    lo0alias) ifconfig lo0 -alias "$a" 2>/dev/null ;;
    member)   ifconfig bridge0 >/dev/null 2>&1 && { is_member "$a" || ifconfig bridge0 addm "$a"; } ;;
    offload)  [ "$b" = 1 ] && ifconfig "$a" tso 2>/dev/null; [ "$c" = 1 ] && ifconfig "$a" lro 2>/dev/null ;;
    ifup)     ifconfig "$a" up ;;
    pf)       pfctl -a "com.apple/$a" -F all >/dev/null 2>&1; [ "$b" != none ] && pfctl -X "$b" >/dev/null 2>&1 ;;
    esac
    n=$((n + 1))
  done < <(tail -r "$LEDGER")
  : >"$LEDGER"
  echo "restore: $n ledger entries undone"
}
trap 'spike_restore; exit 130' HUP INT TERM
if [ "${SPIKE_HOLD:-0}" != 1 ]; then trap 'spike_restore' EXIT; fi
RESTEOF

# payload_file <side> <name> <sudo:0|1> [K=V ...] — compose a payload from stdin.
payload_file() {
	local side="$1" name="$2" priv="$3" kv
	shift 3
	local f="$RUNG_DIR/$side-$name.sh"
	{
		echo "#!/bin/bash"
		echo "# M17.0 $RUNG payload '$name' for the $side Mac (written by hack/spike/m17/lib.sh)"
		echo "set -u"
		printf 'export SIDE=%q PEER=%q STATE_DIR=%q REMOTE_DIR=%q\n' "$side" "$(peer_of "$side")" "$STATE_DIR" "$REMOTE_DIR"
		for kv in "$@"; do printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"; done
		printf '%s\n' "$PAYLOAD_PREAMBLE"
		[ "$priv" = 1 ] && printf '%s\n' "$RESTORE_LIB"
		cat
	} >"$f"
	chmod 0755 "$f"
	printf '%s' "$f"
}

# remote_raw <side> <name> <sudo:0|1> [K=V ...] <<'EOF' — ship and run, print output.
remote_raw() {
	local side="$1" name="$2" priv="$3" f t
	f="$(payload_file "$@")"
	t="$(target_of "$side")" || return 1
	scp -q -o BatchMode=yes -o ConnectTimeout=10 "$f" "$t:$REMOTE_DIR/$name.sh" || {
		echo "VERDICT FAIL copy payload $name to the $side Mac"
		return 1
	}
	if [ "$priv" = 1 ]; then
		on "$side" "sudo -n /bin/bash $REMOTE_DIR/$name.sh" </dev/null
	else
		on "$side" "/bin/bash $REMOTE_DIR/$name.sh" </dev/null
	fi
}

# remote / remote_sudo <side> <name> [K=V ...] <<'EOF' — run, keep the transcript in
# the evidence directory, and turn the payload's VERDICT/RECORD lines into the
# scoreboard. A payload that exits non-zero is itself a FAIL.
remote() { remote_scan "$1" "$2" 0 "${@:3}"; }
remote_sudo() { remote_scan "$1" "$2" 1 "${@:3}"; }
remote_scan() {
	local side="$1" name="$2" log="$RUNG_DIR/$1-$2.log" rc=0
	remote_raw "$@" 2>&1 | tee "$log" || rc=$?
	[ "$rc" = 0 ] || fail "$name on the $side Mac: the payload exited $rc (transcript: $log)"
	spike_scan "$log"
}

spike_scan() {
	local line
	while IFS= read -r line; do
		case "$line" in
		"VERDICT PASS "*) pass "${line#VERDICT PASS }" ;;
		"VERDICT FAIL "*) fail "${line#VERDICT FAIL }" ;;
		"RECORD "*) record "${line#RECORD }" ;;
		esac
	done <"$1"
}

# jq_py <file> <python expression over `d`> — read one value out of a JSON file.
jq_py() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"; }

# stats <values...> — "n=<n> median=<m> p99=<p>" (nearest-rank p99).
stats() {
	python3 - "$@" <<'PY'
import math, statistics, sys
v = sorted(float(x) for x in sys.argv[1:])
if not v:
    print("n=0 median=- p99=-")
else:
    p99 = v[max(0, math.ceil(0.99 * len(v)) - 1)]
    print(f"n={len(v)} median={statistics.median(v):.3f} p99={p99:.3f}")
PY
}

# figure <path> <metric> <unit> <command> <values...> — one R15 figure: appended to
# figures.jsonl (with the run context) and printed as a RECORDED line. The command
# is the exact one run, with LAN addresses replaced by a role placeholder.
figure() {
	local path="$1" metric="$2" unit="$3" cmd="$4" s
	shift 4
	s="$(stats "$@")"
	python3 - "$K3SM_EVIDENCE/figures.jsonl" "$RUNG" "$path" "$metric" "$unit" "$cmd" "$CABLE_DESC" "$*" <<'PY'
import json, sys
f, rung, path, metric, unit, cmd, cable, vals = sys.argv[1:9]
v = [float(x) for x in vals.split()]
with open(f, "a") as out:
    out.write(json.dumps({"rung": rung, "path": path, "metric": metric, "unit": unit,
                          "command": cmd, "cable": cable, "values": v}) + "\n")
PY
	record "figure $path $metric ($unit): $s  [$cmd]"
}

# spike_prompt <message> — ask the operator for a physical touch. It never blocks
# on input: the caller polls the hardware for the change with a bounded wait, and
# an absent operator is RECORDED, never a FAIL.
spike_prompt() {
	local msg="
############################################################################
#  M17.0 $RUNG — OPERATOR ACTION REQUESTED (waiting up to ${PROMPT_WAIT}s)
#  $1
############################################################################"
	printf '\a%s\n' "$msg" >&2
	if [ -w /dev/tty ]; then printf '\a%s\n' "$msg" >/dev/tty 2>/dev/null || true; fi
}

# ---------------------------------------------------------------------------------
# Rung lifecycle.
# ---------------------------------------------------------------------------------

# spike_begin <rung> — refuse or prepare: hosts, evidence, tools, sudo, the probe
# shipped to both Macs, any leftover ledger replayed, the restore trap armed, and
# the topology (cable interfaces, nodes, derived addresses) discovered.
spike_begin() {
	RUNG="$1"
	spike_require "$RUNG"
	RUNG_DIR="$K3SM_EVIDENCE/$(lower "$RUNG")"
	mkdir -p "$RUNG_DIR"
	exec > >(tee -a "$RUNG_DIR/driver.log") 2>&1
	note "M17.0 $RUNG — evidence in $RUNG_DIR"

	local tool
	for tool in ssh scp python3 go; do
		command -v "$tool" >/dev/null 2>&1 || {
			echo "FAIL      M17.0 $RUNG: the driver needs $tool on PATH"
			exit 1
		}
	done
	local side
	for side in server worker; do
		if ! on "$side" "mkdir -p $REMOTE_DIR && sudo -n true" >/dev/null 2>&1; then
			echo "FAIL      M17.0 $RUNG: the $side Mac is unreachable over ssh, or its sudo is not passwordless"
			exit 1
		fi
	done
	spike_ship_probe || {
		echo "FAIL      M17.0 $RUNG: could not build or ship the probe"
		exit 1
	}
	spike_restore_both
	trap 'spike_on_exit' EXIT
	trap 'exit 130' INT TERM HUP
	TOPOLOGY_OK=1
	if ! spike_topology; then
		TOPOLOGY_OK=0
		if [ "${SPIKE_TOPOLOGY_OPTIONAL:-0}" != 1 ]; then
			echo "FAIL      M17.0 $RUNG: the rig's topology could not be established (see above; S1 is the rung that diagnoses it)"
			exit 1
		fi
	fi
}

# spike_ship_probe — build the probe for the Macs (darwin/arm64, pure Go) and copy
# it to both. Built once per evidence directory.
spike_ship_probe() {
	local bin="$K3SM_EVIDENCE/probe/probe" side
	if [ ! -x "$bin" ]; then
		mkdir -p "$K3SM_EVIDENCE/probe"
		(cd "$SPIKE_REPO_ROOT" && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$bin" ./hack/spike/m17/probe) || return 1
	fi
	for side in server worker; do
		scp -q -o BatchMode=yes "$bin" "$(target_of "$side"):$REMOTE_DIR/probe" || return 1
	done
}

# spike_restore_both — replay both Macs' ledgers (privileged, idempotent).
spike_restore_both() {
	local side
	for side in server worker; do
		[ -n "${RUNG_DIR:-}" ] || return 0
		remote_raw "$side" restore 1 <<'EOF' 2>&1 | sed "s/^/      [$side] /"
spike_restore
EOF
	done
}

spike_on_exit() {
	local rc=$?
	trap - EXIT
	note "restoring both Macs"
	spike_restore_both
	[ "$(type -t spike_cleanup)" = function ] && spike_cleanup
	exit "$rc"
}

# spike_end <rung> — the lab-rig invariant (both nodes Ready), then the verdict.
spike_end() {
	note "rig check: both Macs restored and both nodes Ready"
	spike_restore_both
	[ "$(type -t spike_cleanup)" = function ] && spike_cleanup
	local nodes
	nodes="$(kc get nodes --no-headers 2>/dev/null)"
	if [ -n "$SRV_NODE" ] && [ -n "$WRK_NODE" ] &&
		printf '%s\n' "$nodes" | awk -v n="$SRV_NODE" '$1==n && $2=="Ready"' | grep -q . &&
		printf '%s\n' "$nodes" | awk -v n="$WRK_NODE" '$1==n && $2=="Ready"' | grep -q .; then
		pass "rig: both nodes Ready after the rung"
	else
		fail "rig: a node is not Ready after the rung (the rig must be left with both nodes Ready)"
	fi
	trap - EXIT
	spike_verdict "$1"
}

# spike_topology — discover the cable: run the production enumeration on both Macs
# (the probe's `enum`), find the port pair whose peer domain UUIDs point at each
# other, then the nodes (by matching each node's InternalIP to a Mac's addresses),
# their pod /24s and the addresses the product derives from them. Writes
# $RUNG_DIR/topology.env and exports the result.
spike_topology() {
	local side
	for side in server worker; do
		on "$side" "$REMOTE_DIR/probe enum" >"$RUNG_DIR/enum-$side.json" 2>"$RUNG_DIR/enum-$side.err" || true
		on "$side" "ifconfig -a inet | awk '/inet /{print \$2}'" >"$RUNG_DIR/addrs-$side.txt" 2>/dev/null || true
		on "$side" "sysctl -n hw.model; sw_vers -productVersion; sw_vers -buildVersion" >"$RUNG_DIR/context-$side.txt" 2>/dev/null || true
	done
	kc get nodes -o json >"$RUNG_DIR/nodes.json" 2>/dev/null || {
		echo "      the server Mac's k3sm kubectl cannot list nodes"
		return 1
	}
	# k3sm leaves Node.spec.podCIDR empty; a node's pod /24 is its MeshPeer's spec.podCIDR.
	kc get meshpeers.net.k3sm.io -o json >"$RUNG_DIR/meshpeers.json" 2>/dev/null || {
		echo "      the server Mac's k3sm kubectl cannot list meshpeers"
		return 1
	}
	python3 - "$RUNG_DIR" "${K3SM_M17_SERVER_IFACE:-}" "${K3SM_M17_WORKER_IFACE:-}" >"$RUNG_DIR/topology.env" <<'PY' || return 1
import json, sys
d, srv_if, wrk_if = sys.argv[1:4]
def ports(side):
    try:
        return json.load(open(f"{d}/enum-{side}.json")).get("ports") or []
    except Exception:
        return []
sp, wp = ports("server"), ports("worker")
pair = None
for a in sp:
    for b in wp:
        if a.get("PeerDomainUUID") and a["PeerDomainUUID"] == b.get("DomainUUID") and b.get("PeerDomainUUID") == a.get("DomainUUID"):
            pair = (a, b)
if srv_if and wrk_if:
    a = next((p for p in sp if p["Iface"] == srv_if), {"Iface": srv_if, "PortOrdinal": -1})
    b = next((p for p in wp if p["Iface"] == wrk_if), {"Iface": wrk_if, "PortOrdinal": -1})
    pair = (a, b)
if not pair:
    sys.stderr.write("no Thunderbolt port pair whose peer domain UUIDs point at each other (is the cable in?)\n")
    sys.exit(1)
nodes = json.load(open(f"{d}/nodes.json"))["items"]
cidrs = {m["spec"].get("nodeName", m["metadata"]["name"]): m["spec"].get("podCIDR", "")
         for m in json.load(open(f"{d}/meshpeers.json"))["items"]}
def node_for(side):
    mine = set(open(f"{d}/addrs-{side}.txt").read().split())
    for n in nodes:
        ips = {a["address"] for a in n["status"].get("addresses", []) if a["type"] == "InternalIP"}
        if ips & mine:
            name = n["metadata"]["name"]
            return name, n["spec"].get("podCIDR") or cidrs.get(name, "")
    return "", ""
sn, scidr = node_for("server")
wn, wcidr = node_for("worker")
a, b = pair
print(f"SRV_IF={a['Iface']}\nWRK_IF={b['Iface']}\nSRV_PORT={a.get('PortOrdinal', -1)}\nWRK_PORT={b.get('PortOrdinal', -1)}")
print(f"SRV_UUID={a.get('DomainUUID','')}\nWRK_UUID={b.get('DomainUUID','')}\nSPEED_GBPS={a.get('SpeedGbps', 0)}")
print(f"SRV_NODE={sn}\nWRK_NODE={wn}\nSRV_POD_CIDR={scidr}\nWRK_POD_CIDR={wcidr}")
PY
	# shellcheck disable=SC1091
	. "$RUNG_DIR/topology.env"
	if [ -z "$SRV_NODE" ] || [ -z "$WRK_NODE" ] || [ -z "$SRV_POD_CIDR" ] || [ -z "$WRK_POD_CIDR" ]; then
		echo "      could not match both Macs to cluster nodes with a pod /24"
		return 1
	fi
	local srv_json wrk_json
	srv_json="$(on server "$REMOTE_DIR/probe linkip -node-cidr $SRV_POD_CIDR -port $SRV_PORT")" || {
		echo "      no link address derives for the server port (ordinal $SRV_PORT)"
		return 1
	}
	wrk_json="$(on worker "$REMOTE_DIR/probe linkip -node-cidr $WRK_POD_CIDR -port $WRK_PORT")" || {
		echo "      no link address derives for the worker port (ordinal $WRK_PORT)"
		return 1
	}
	printf '%s\n' "$srv_json" >"$RUNG_DIR/linkip-server.json"
	printf '%s\n' "$wrk_json" >"$RUNG_DIR/linkip-worker.json"
	SRV_LINK="$(jq_py "$RUNG_DIR/linkip-server.json" 'd["linkIP"]')"
	WRK_LINK="$(jq_py "$RUNG_DIR/linkip-worker.json" 'd["linkIP"]')"
	SRV_EGRESS="$(jq_py "$RUNG_DIR/linkip-server.json" 'd["meshEgress"]')"
	WRK_EGRESS="$(jq_py "$RUNG_DIR/linkip-worker.json" 'd["meshEgress"]')"
	SRV_HALVES="$(jq_py "$RUNG_DIR/linkip-server.json" '" ".join(d["halves"])')"
	WRK_HALVES="$(jq_py "$RUNG_DIR/linkip-worker.json" '" ".join(d["halves"])')"
	# The spike's own pod-range listener address on each Mac: .250 of the pod /24,
	# refused later by spike_lo0_alias if a pod already holds it.
	SRV_PROBE_IP="${SRV_POD_CIDR%.*/*}.250"
	WRK_PROBE_IP="${WRK_POD_CIDR%.*/*}.250"
	{
		echo "SRV_LINK=$SRV_LINK"
		echo "WRK_LINK=$WRK_LINK"
		echo "SRV_EGRESS=$SRV_EGRESS"
		echo "WRK_EGRESS=$WRK_EGRESS"
		echo "SRV_HALVES='$SRV_HALVES'"
		echo "WRK_HALVES='$WRK_HALVES'"
		echo "SRV_PROBE_IP=$SRV_PROBE_IP"
		echo "WRK_PROBE_IP=$WRK_PROBE_IP"
	} >>"$RUNG_DIR/topology.env"
	echo "      cable: server $SRV_IF (port $SRV_PORT, $SRV_LINK) <-> worker $WRK_IF (port $WRK_PORT, $WRK_LINK); ${SPEED_GBPS} Gb/s"
	echo "      server: $(tr '\n' ' ' <"$RUNG_DIR/context-server.txt")  worker: $(tr '\n' ' ' <"$RUNG_DIR/context-worker.txt")  cable: $CABLE_DESC"
}

# The common direct-link configuration a rung holds while it measures: on each Mac
# the cable port out of bridge0, the /32 link alias, the on-link host route to the
# peer's link address, offload off, and (with "routes") the two /25 gateway routes
# to the peer's pod /24 sourced from the mesh-egress address (RTAX_IFA).
spike_configure_link() { # spike_configure_link <side> [routes]
	local side="$1" with_routes="${2:-}"
	local ifc link peer halves egress
	if [ "$side" = server ]; then
		ifc="$SRV_IF" link="$SRV_LINK" peer="$WRK_LINK" halves="$WRK_HALVES" egress="$SRV_EGRESS"
	else
		ifc="$WRK_IF" link="$WRK_LINK" peer="$SRV_LINK" halves="$SRV_HALVES" egress="$WRK_EGRESS"
	fi
	remote_sudo "$side" "configure-link" SPIKE_HOLD=1 IFC="$ifc" LINK="$link" PEER_LINK="$peer" \
		HALVES="$halves" EGRESS="$egress" WITH_ROUTES="$with_routes" <<'EOF'
foreign="$(ifconfig "$IFC" | awk '/inet 169\.254\.(0|255)\./{print $2}' | grep -vxF "$LINK" || true)"
if [ -n "$foreign" ]; then
  verdict FAIL "link-config/$SIDE: $IFC already carries a reserved-half address the spike did not add ($foreign): the installed k3sm configures direct links itself; run the spike against a build that does not, or with the links tunnel-only"
  exit 0
fi
spike_deletem "$IFC" || { verdict FAIL "link-config/$SIDE: $IFC is still a bridge0 member after deletem"; exit 0; }
spike_alias "$IFC" "$LINK" || { verdict FAIL "link-config/$SIDE: the /32 alias $LINK on $IFC was refused"; exit 0; }
spike_route -host "$PEER_LINK" -interface "$IFC" || route -n get "$PEER_LINK" | grep -q "interface: $IFC" || { verdict FAIL "link-config/$SIDE: the on-link host route to $PEER_LINK over $IFC"; exit 0; }
spike_offload_off "$IFC"
if [ "$WITH_ROUTES" = routes ]; then
  for h in $HALVES; do
    spike_route -net "$h" "$PEER_LINK" -ifa "$EGRESS" || route -n get "${h%/*}" | grep -q "interface: $IFC" || { verdict FAIL "link-config/$SIDE: the /25 $h via $PEER_LINK (ifa $EGRESS)"; exit 0; }
  done
fi
echo "configured $IFC: alias $LINK, host route $PEER_LINK${WITH_ROUTES:+, /25s $HALVES via $PEER_LINK ifa $EGRESS}"
EOF
}

# figures_from_log <path> <log> — turn a payload's "FIG <metric> <value>" and
# "CMD <metric> <exact command>" lines into R15 figures (one per metric, all its
# values: median and p99). The unit follows the metric's family.
figures_from_log() {
	local path="$1" log="$2" metric unit cmd
	while IFS= read -r metric; do
		case "$metric" in
		tcp-*) unit="Gbit/s" ;;
		rtt-*) unit="ms" ;;
		udp-loss-*) unit="% lost" ;;
		cpu-*) unit="% of one core" ;;
		tps-*) unit="tokens/s" ;;
		dad-* | fallback-* | *-ms) unit="ms" ;;
		*) unit="value" ;;
		esac
		cmd="$(awk -v m="$metric" '$1=="CMD" && $2==m{$1=""; $2=""; sub(/^  /, ""); print; exit}' "$log")"
		# shellcheck disable=SC2046
		figure "$path" "$metric" "$unit" "${cmd:-see $log}" $(awk -v m="$metric" '$1=="FIG" && $2==m{print $3}' "$log")
	done < <(awk '$1=="FIG"{print $2}' "$log" | sort -u)
}

# The server-side measuring payload S2 runs per path: TCP single and 4-stream in
# both directions at MSS 1340 (R15's one clamp for every cross-node path, so the
# figure is the one a pod socket sees), idle and loaded RTT, and (UDP=1) loss at the MTU boundary, each
# RUNS times, against TARGET; TARGET_LABEL is what the recorded command shows (a
# LAN address is never recorded, only its role).
read -r -d '' MEASURE_PAYLOAD <<'MEOF' || true
bps() { python3 -c 'import json,sys
d=json.load(sys.stdin); e=d.get("end",{}); s=e.get("sum_received") or e.get("sum") or {}
print("%.3f" % (s.get("bits_per_second",0)/1e9))'; }
lost() { python3 -c 'import json,sys
d=json.load(sys.stdin); print("%.3f" % d.get("end",{}).get("sum",{}).get("lost_percent",100))'; }
for mode in single p4; do
  for dir in fwd rev; do
    flags="-M 1340"; [ "$mode" = p4 ] && flags="$flags -P 4"; [ "$dir" = rev ] && flags="$flags -R"
    echo "CMD tcp-$mode-$dir iperf3 -c $TARGET_LABEL -p 5201 -t 10 $flags -J"
    for _ in $(seq 1 "$RUNS"); do
      # shellcheck disable=SC2086
      v="$(iperf3 -c "$TARGET" -p 5201 -t 10 $flags -J 2>/dev/null | bps)" && echo "FIG tcp-$mode-$dir $v"
    done
  done
done
echo "CMD rtt-idle ping -c 20 -i 0.2 -q $TARGET_LABEL (avg)"
for _ in $(seq 1 "$RUNS"); do
  ping -c 20 -i 0.2 -q "$TARGET" | awk -F'/' '/round-trip/{print "FIG rtt-idle", $5}'
done
echo "CMD rtt-loaded ping -c 20 -i 0.2 -q $TARGET_LABEL (avg) during iperf3 -c $TARGET_LABEL -p 5201 -t 8 -P 4"
for _ in $(seq 1 "$RUNS"); do
  iperf3 -c "$TARGET" -p 5201 -t 8 -P 4 >/dev/null 2>&1 & ip=$!
  sleep 2
  ping -c 20 -i 0.2 -q "$TARGET" | awk -F'/' '/round-trip/{print "FIG rtt-loaded", $5}'
  wait "$ip"
done
if [ "${UDP:-0}" = 1 ]; then
  for size in 1472 1473; do
    echo "CMD udp-loss-$size iperf3 -c $TARGET_LABEL -p 5201 -u -b 500M -l $size -t 5 -J"
    for _ in $(seq 1 "$RUNS"); do
      v="$(iperf3 -c "$TARGET" -p 5201 -u -b 500M -l "$size" -t 5 -J 2>/dev/null | lost)" && echo "FIG udp-loss-$size $v"
    done
  done
fi
MEOF

# The CPU sampler: ten samples, two seconds apart, of every k3sm and wireguard
# process (the helper, the daemon that hosts the proxy, any wireguard-go), printed
# as FIG cpu-<side>-<name> lines. LOAD_TARGET set = it drives the 4-stream load.
read -r -d '' CPU_PAYLOAD <<'CEOF' || true
if [ -n "${LOAD_TARGET:-}" ]; then
  iperf3 -c "$LOAD_TARGET" -p 5201 -t 25 -P 4 >/dev/null 2>&1 & ip=$!
  sleep 3
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do
  ps -A -o %cpu=,comm= | awk -v s="$SIDE" '{c=$1; $1=""; sub(/^ /,""); n=$0; sub(/.*\//,"",n); if (n ~ /k3sm|wireguard/) print "FIG cpu-" s "-" n, c}'
  sleep 2
done
[ -n "${ip:-}" ] && wait "$ip"
echo "CMD cpu-$SIDE ps -A -o %cpu=,comm= x10 every 2 s during iperf3 -P 4 -t 25"
CEOF

# counters <side> <tag> — snapshot netstat -s -p ip (fragment lines) and netstat -I
# <cable iface> on one Mac into the rung's evidence.
counters() {
	local ifc="$SRV_IF"
	[ "$1" = worker ] && ifc="$WRK_IF"
	on "$1" "netstat -s -p ip | grep -i frag; echo '--'; netstat -I $ifc | sed -n 2p" >"$RUNG_DIR/counters-$1-$2.txt" 2>/dev/null || true
}

# counters_delta <side> <before-tag> <after-tag> — RECORD the counter deltas.
counters_delta() {
	local d
	d="$(python3 - "$RUNG_DIR/counters-$1-$2.txt" "$RUNG_DIR/counters-$1-$3.txt" <<'PY'
import sys
def read(f):
    frag, iface = {}, []
    part = 0
    for line in open(f):
        line = line.strip()
        if line == "--":
            part = 1
            continue
        if part == 0 and line:
            n, _, label = line.partition(" ")
            if n.isdigit():
                frag[label] = int(n)
        elif part == 1 and line:
            iface = line.split()
    return frag, iface
fb, ib = read(sys.argv[1])
fa, ia = read(sys.argv[2])
out = [f"{k}: +{fa.get(k, 0) - v}" for k, v in fb.items() if fa.get(k, 0) != v]
cols = ["Ipkts", "Ierrs", "Opkts", "Oerrs", "Coll"]
if len(ib) >= 9 and len(ia) >= 9:
    for i, c in enumerate(cols):
        try:
            out.append(f"{c}: +{int(ia[4 + i]) - int(ib[4 + i])}")
        except ValueError:
            pass
print("; ".join(out) or "no change")
PY
)"
	record "counters $1 ($2 -> $3): $d"
}
