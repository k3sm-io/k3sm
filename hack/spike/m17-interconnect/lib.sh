#!/usr/bin/env bash
# shellcheck disable=SC2034 # a sourced library: the variables it sets are read by the driver
#
# Plumbing for the two-Mac interconnect spike (hack/lab/m17-interconnect-spike.sh).
#
# THE RIG. Two Macs joined by one Thunderbolt cable whose ports are still members of
# bridge0 on both sides. The DRIVER runs on one of the two Macs (the "local" side)
# and reaches the other (the "peer" side) over ssh as PEER_SSH. Every host change is
# a SCRIPT FILE run under `sudo -n /bin/bash <file>`, locally or (after scp) on the
# peer: one sudo over the whole file, never an `ssh host "sudo a && b"` chain, which
# runs only `a` as root.
#
# WHAT A PRIVILEGED SCRIPT MAY CHANGE, and nothing else:
#   * an alias on bridge0 inside 169.254.0.0/24 or 169.254.255.0/24 (the two halves
#     RFC 3927 §2.1 forbids self-assignment in);
#   * a `-net` route for exactly 169.254.0.0/24 or 169.254.255.0/24 to bridge0.
# Each change appends one line to a root-owned ledger on that Mac; the restore
# replays the ledger in reverse and removes exactly those aliases and routes. It
# never adds or removes a bridge0 member, never touches the default route or the
# LAN interface, never loads a packet-filter rule and never reboots. A reserved-half
# alias or route the spike did not add is FOREIGN: the spike refuses to run beside
# it and never removes it.
#
# SOURCING THIS FILE REQUIRES NOTHING: the host and evidence variables are demanded
# by the driver after `--plan` and the K3SM_LAB check, so the plan works anywhere.

IC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Where payload scripts land on the peer (the login user's), and where the
# root-owned restore ledger lives on both Macs (inside the k3sm footprint).
IC_REMOTE_DIR="/tmp/k3sm-interconnect-spike"
IC_STATE_DIR="/var/lib/k3sm/spike-interconnect"

# The two reserved halves, the only destinations a route may name.
IC_HALF_LOW="169.254.0.0/24"
IC_HALF_HIGH="169.254.255.0/24"

IC_SEQ=0
PAYLOAD_PATH=""

# ---------------------------------------------------------------------------------
# Scoreboard. A form's checks count into FORM_*; the run's own criteria (preflight,
# the configd check) count into the RUN_* totals. A form that does not cross the
# cable is RECORDED as such when a later form passes; only "no form crossed" is a
# FAIL of the address question.
# ---------------------------------------------------------------------------------
RUN_PASSES=0 RUN_FAILS=0 RUN_RECORDS=0
FORM_PASSES=0 FORM_FAILS=0

note() { printf '\n==> %s\n' "$*"; }
ok() {
	echo "PASS      $*"
	FORM_PASSES=$((FORM_PASSES + 1))
	finding "- PASS $*"
}
bad() {
	echo "FAIL      $*"
	FORM_FAILS=$((FORM_FAILS + 1))
	finding "- FAIL $*"
}
run_pass() {
	echo "PASS      $*"
	RUN_PASSES=$((RUN_PASSES + 1))
	finding "- PASS $*"
}
run_fail() {
	echo "FAIL      $*"
	RUN_FAILS=$((RUN_FAILS + 1))
	finding "- FAIL $*"
}
record() {
	echo "RECORDED  $*"
	RUN_RECORDS=$((RUN_RECORDS + 1))
	finding "- RECORDED $*"
}

# finding <markdown line> — append to the findings summary (once it exists).
finding() {
	[ -n "${IC_FINDINGS:-}" ] && [ -f "$IC_FINDINGS" ] && printf '%s\n' "$*" >>"$IC_FINDINGS"
	return 0
}

# ---------------------------------------------------------------------------------
# Payloads. A payload is a heredoc on stdin; payload_file writes it, behind a fixed
# preamble (and, for a privileged payload, the restore library), to the evidence
# directory and sets PAYLOAD_PATH. payload_exec runs it on a side.
# ---------------------------------------------------------------------------------

read -r -d '' IC_PREAMBLE <<'PREEOF' || true
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
in_reserved() { case "$1" in 169.254.0.*|169.254.255.*) return 0 ;; esac; return 1; }
PREEOF

# IC_NETSTAT_AWK — the one reader of `netstat -rn -f inet` used by the payloads and
# the driver. It prints "<addr>/<mask> <flags> <netif> <gateway>" for every entry in the
# reserved halves with a mask of /24 or longer (a host entry is /32). netstat
# abbreviates destinations ("169.254/24" is 169.254.0.0/24, a bare "169.254" is the
# /16), and macOS link-local routes are interface-scoped, so `route -n get` cannot
# be trusted to see them; this reader is.
read -r -d '' IC_NETSTAT_AWK <<'AWKEOF' || true
{ d = $1; m = -1; a = d
  if (index(d, "/")) { split(d, p, "/"); a = p[1]; m = p[2] + 0 }
  n = split(a, o, ".")
  if (n < 1 || o[1] !~ /^[0-9]+$/) next
  if (m < 0) m = (n == 4) ? 32 : 8 * n
  for (i = n + 1; i <= 4; i++) o[i] = 0
  if (o[1] != 169 || o[2] != 254 || (o[3] != 0 && o[3] != 255) || m < 24) next
  print o[1] "." o[2] "." o[3] "." o[4] "/" m, $3, $4, $2 }
AWKEOF

read -r -d '' IC_RESTORE_LIB <<'RESTEOF' || true
LEDGER="$IC_STATE_DIR/restore.ledger"
# CREATED is every alias and route this spike ever added on this Mac, never
# truncated: the post-restore residue check deletes an entry only when it is listed.
CREATED="$IC_STATE_DIR/created"
mkdir -p "$IC_STATE_DIR" && chmod 700 "$IC_STATE_DIR" && touch "$LEDGER" "$CREATED"
refuse() { echo "RESTORE-LIB REFUSED: $*" >&2; return 1; }
is_half() { [ "$1" = 169.254.0.0/24 ] || [ "$1" = 169.254.255.0/24 ]; }
has_alias() { grep -qxF "$1" <<<"$(ifconfig bridge0 | awk '$1=="inet"{print $2}')"; }
reserved_routes() { netstat -rn -f inet | awk "$IC_NETSTAT_AWK"; }
has_half_route() {   # a route for exactly this half exists, on any interface
  grep -q . <<<"$(reserved_routes | awk -v d="$1" '$1==d')"
}
created() { grep -qxF "$1" "$CREATED" || echo "$1" >>"$CREATED"; }
# covered <ip> — a non-ARP route entry for exactly this address already exists (for
# example an undeletable entry an earlier run's alias left behind).
covered() { grep -q . <<<"$(reserved_routes | awk -v d="$1/32" '$1==d && $2 !~ /L/')"; }
ic_alias() {         # ic_alias <reserved-half ip> <netmask>
  in_reserved "$1" || { refuse "$1 is outside the reserved halves"; return 1; }
  has_alias "$1" && { refuse "$1 is already on bridge0 and not in this spike's ledger"; return 1; }
  covered "$1" && { refuse "a route entry for $1/32 already exists (left by an earlier run); no alias is added over it"; return 5; }
  ifconfig bridge0 inet "$1" netmask "$2" alias && echo "alias $1" >>"$LEDGER" && created "alias $1"
}
ic_route() {         # ic_route <reserved half> — the add's own output is printed as ROUTE-ADD
  is_half "$1" || { refuse "$1 is not one of the two reserved halves"; return 1; }
  local out rc=0
  out="$(route -n add -net "$1" -interface bridge0 2>&1)" || rc=$?
  echo "ROUTE-ADD $1 exit=$rc: $out"
  # Ledgered whatever the exit: route(8) has been seen to print an error and exit 0,
  # and deleting an absent route for exactly this half on bridge0 is harmless.
  echo "route $1" >>"$LEDGER"
  created "route $1"
  return "$rc"
}
ic_restore() {
  [ -s "$LEDGER" ] || return 0
  local kind a n=0
  while read -r kind a; do
    case "$kind" in
    route) is_half "$a" && route -n delete -net "$a" -interface bridge0 >/dev/null 2>&1 ;;
    alias) in_reserved "$a" && ifconfig bridge0 -alias "$a" 2>/dev/null ;;
    esac
    n=$((n + 1))
  done < <(tail -r "$LEDGER")
  : >"$LEDGER"
  echo "restore: $n ledger entries undone (reserved-half aliases and routes on bridge0 only)"
}
# was_created <addr/mask> — a /32 for an alias the spike added, a route it added, or
# the connected /24 of a half one of its aliases lived in.
was_created() {
  local a="${1%/*}" m="${1#*/}" x
  [ "$m" = 32 ] && { grep -qxF "alias $a" "$CREATED"; return; }
  grep -qxF "route $1" "$CREATED" && return 0
  [ "$m" = 24 ] || return 1
  for x in $(awk '$1=="alias"{print $2}' "$CREATED"); do
    [ "${x%.*}.0/24" = "$1" ] && return 0
  done
  return 1
}
entry_left() { grep -q . <<<"$(reserved_routes | awk -v d="$1" '$1==d && $2 !~ /L/')"; }
# ic_residue — after a restore, every reserved-half route entry that is not an ARP
# host entry (flags with L) is residue. IC_RESIDUE_MODE selects the rule:
#   preflight  an entry this spike recorded creating is deleted; whatever remains
#              (or was never ours) is RESIDUE-PREEXISTING: recorded, not deleted, and
#              the driver keeps it as the run's baseline.
#   post       an entry in IC_BASELINE with identical flags, interface and gateway is
#              RESIDUE-BASELINE (skipped); otherwise an entry on bridge0 listed in
#              CREATED is deleted, and anything left is RESIDUE-LEFT.
# A /32 the spike created that is a non-static cloned entry (C without S) and will
# not delete carries the tag UNDELETABLE-CLONE.
ic_residue() {
  local dest flags netif gw try out found=0 tag
  while read -r dest flags netif gw; do
    case "$flags" in *L*) continue ;; esac
    found=1
    if [ "${IC_RESIDUE_MODE:-post}" = post ] && grep -qxF "$dest $flags $netif $gw" <<<"${IC_BASELINE:-}"; then
      echo "RESIDUE-BASELINE $dest $flags $netif $gw (present at preflight, unchanged)"
      continue
    fi
    if [ "$netif" != bridge0 ] || ! was_created "$dest"; then
      if [ "${IC_RESIDUE_MODE:-post}" = preflight ]; then
        echo "RESIDUE-PREEXISTING $dest $flags $netif $gw (not created by this spike; not ours to delete)"
      else
        echo "RESIDUE-LEFT $dest $flags $netif $gw (not created by this spike; left alone)"
      fi
      continue
    fi
    out=""
    for try in "-host ${dest%/*} -ifscope bridge0" "-host ${dest%/*}" "-net $dest -ifscope bridge0" "-net $dest -interface bridge0" "-net $dest"; do
      # shellcheck disable=SC2086
      out="$out [route -n delete $try: $(route -n delete $try 2>&1)]"
      entry_left "$dest" || break
    done
    if entry_left "$dest"; then
      tag=""
      case "$dest:$flags" in */32:*C*) case "$flags" in *S*) ;; *) tag=" UNDELETABLE-CLONE" ;; esac ;; esac
      if [ "${IC_RESIDUE_MODE:-post}" = preflight ]; then
        echo "RESIDUE-PREEXISTING $dest $flags $netif $gw (created by an earlier run of this spike; every delete failed)$tag:$out"
      else
        echo "RESIDUE-LEFT $dest $flags $netif $gw (created by this spike; every delete failed)$tag:$out"
      fi
    else
      echo "RESIDUE-DELETED $dest $flags $netif $gw:$out"
    fi
  done < <(reserved_routes)
  [ "$found" = 0 ] && echo "RESIDUE-NONE the reserved halves hold no route entry (ARP host entries aside)"
  return 0
}
trap 'ic_restore; exit 130' HUP INT TERM
if [ "${IC_HOLD:-0}" != 1 ]; then trap 'ic_restore' EXIT; fi
RESTEOF

# payload_file <side> <name> <priv:0|1> [K=V ...] — compose from stdin; sets PAYLOAD_PATH.
payload_file() {
	local side="$1" name="$2" priv="$3" kv
	shift 3
	IC_SEQ=$((IC_SEQ + 1))
	mkdir -p "$EVIDENCE_DIR/payloads"
	PAYLOAD_PATH="$EVIDENCE_DIR/payloads/$(printf '%03d' "$IC_SEQ")-$side-$name.sh"
	{
		echo "#!/bin/bash"
		echo "# interconnect spike payload '$name' for the $side Mac (hack/spike/m17-interconnect/lib.sh)"
		echo "set -u"
		printf 'export SIDE=%q IC_STATE_DIR=%q\n' "$side" "$IC_STATE_DIR"
		printf 'IC_NETSTAT_AWK=%q\n' "$IC_NETSTAT_AWK"
		for kv in "$@"; do printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"; done
		printf '%s\n' "$IC_PREAMBLE"
		[ "$priv" = 1 ] && printf '%s\n' "$IC_RESTORE_LIB"
		cat
	} >"$PAYLOAD_PATH"
	chmod 0755 "$PAYLOAD_PATH"
}

ssh_peer() { ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 "$PEER_SSH" "$@"; }

# payload_exec <side> <priv:0|1> <file> — run a composed payload on a side.
payload_exec() {
	local side="$1" priv="$2" f="$3" dst
	if [ "$side" = local ]; then
		if [ "$priv" = 1 ]; then sudo -n /bin/bash "$f"; else /bin/bash "$f"; fi
		return
	fi
	dst="$IC_REMOTE_DIR/$(basename "$f")"
	scp -q -o BatchMode=yes -o ConnectTimeout=10 "$f" "$PEER_SSH:$dst" || {
		echo "copy of payload $(basename "$f") to the peer failed" >&2
		return 1
	}
	if [ "$priv" = 1 ]; then
		ssh_peer "zsh -lc $(printf '%q' "sudo -n /bin/bash $dst")" </dev/null
	else
		ssh_peer "zsh -lc $(printf '%q' "/bin/bash $dst")" </dev/null
	fi
}

# payload <side> <name> <priv> [K=V ...] <<'EOF' — compose and run. The output goes
# to the transcript beside the payload (PAYLOAD_LOG) and is echoed. Never call this
# inside $(...) or a pipeline: the sequence counter must survive the call.
PAYLOAD_LOG=""
payload() {
	local side="$1" priv="$3"
	payload_file "$@"
	local rc=0
	PAYLOAD_LOG="${PAYLOAD_PATH%.sh}.log"
	payload_exec "$side" "$priv" "$PAYLOAD_PATH" </dev/null >"$PAYLOAD_LOG" 2>&1 || rc=$?
	sed "s/^/      [$side] /" "$PAYLOAD_LOG"
	return "$rc"
}

# restore_side <side> [preflight] — replay that Mac's ledger (privileged,
# idempotent), then the residue check. RESIDUE lines land in residue-<side>.log.
# In preflight mode every remaining entry is RECORDED and kept in BASELINE_<side>;
# afterwards a RESIDUE-LEFT appends to RESIDUE_LEFT, which the caller turns into
# "restore left residue" (exit 1).
RESIDUE_LEFT=""
BASELINE_local=""
BASELINE_peer=""
NAMED_CLONE=0
restore_side() {
	local side="$1" mode="${2:-post}" base line entry
	if [ "$side" = local ]; then base="$BASELINE_local"; else base="$BASELINE_peer"; fi
	payload "$side" restore 1 IC_RESIDUE_MODE="$mode" IC_BASELINE="$base" <<'EOF' || true
ic_restore
ic_residue
EOF
	while IFS= read -r line; do
		echo "$line" >>"$EVIDENCE_DIR/residue-$side.log"
		entry="$(echo "$line" | awk '{print $2, $3, $4, $5}')"
		case "$line" in
		"RESIDUE-PREEXISTING "*)
			record "pre-existing reserved-half entry left by an earlier run, not ours to delete ($side Mac): $entry"
			if [ "$side" = local ]; then
				BASELINE_local="$BASELINE_local$entry"$'\n'
			else
				BASELINE_peer="$BASELINE_peer$entry"$'\n'
			fi
			;;
		"RESIDUE-LEFT "*)
			RESIDUE_LEFT="$RESIDUE_LEFT $side:$(echo "$line" | awk '{print $2}')"
			finding "- FAIL restore left residue on the $side Mac: ${line#RESIDUE-LEFT }"
			;;
		"RESIDUE-DELETED "*) finding "- RECORDED restore residue deleted on the $side Mac: ${line#RESIDUE-DELETED }" ;;
		esac
		case "$line" in
		*UNDELETABLE-CLONE*)
			if [ "$NAMED_CLONE" = 0 ]; then
				NAMED_CLONE=1
				finding ""
				finding "**Named finding: a removed /32 bridge0 alias can leave an undeletable cloned route (macOS 27).** After the alias is removed, a non-static \`UC\` /32 entry for its address stays in the routing table and every \`route delete\` form answers \"not in table\". The node reconcile and the doctor have to live with it: never re-add an alias over it, and report it rather than fail on it."
				finding ""
			fi
			finding "- RECORDED undeletable cloned route on the $side Mac: $entry"
			;;
		esac
	done < <(grep '^RESIDUE-' "$PAYLOAD_LOG")
}

# ---------------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------------

# norm_mac <mac> — lower-case, two hex digits per octet (arp prints "a:b:c...").
norm_mac() {
	local IFS=: o out=""
	for o in $1; do
		out="$out$(printf '%02x' "0x$o" 2>/dev/null):"
	done
	printf '%s' "${out%:}" | tr '[:upper:]' '[:lower:]'
}

# kv <file> <key> — read KEY=value from a side-info file.
kv() { awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/, ""); print; exit}' "$1"; }

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

# figure <path> <metric> <unit> <command> <values...> — one figure, appended to
# figures.jsonl and printed as a RECORDED line. The command is the one run, with
# addresses shown by role, never a hostname.
figure() {
	local path="$1" metric="$2" unit="$3" cmd="$4" s
	shift 4
	s="$(stats "$@")"
	python3 - "$EVIDENCE_DIR/figures.jsonl" "$path" "$metric" "$unit" "$cmd" "$*" <<'PY'
import json, sys
f, path, metric, unit, cmd, vals = sys.argv[1:7]
with open(f, "a") as out:
    out.write(json.dumps({"path": path, "metric": metric, "unit": unit, "command": cmd,
                          "values": [float(x) for x in vals.split()]}) + "\n")
PY
	record "figure $path $metric ($unit): $s  [$cmd]"
}

# The one-shot TCP listener: binds the given address explicitly (an interconnect
# address is reachable only on an explicit bind), prints LISTEN, then one ACCEPT
# line with the connection's local and peer addresses.
IC_LISTEN_PY='import socket,sys;a,p,t=sys.argv[1],int(sys.argv[2]),float(sys.argv[3]);s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((a,p));s.listen(1);s.settimeout(t);print("LISTEN",a,p,flush=True);c,r=s.accept();print("ACCEPT",c.getsockname()[0],r[0],flush=True);c.close()'
