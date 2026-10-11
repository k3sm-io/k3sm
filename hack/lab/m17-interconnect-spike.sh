#!/usr/bin/env bash
#
# k3sm M17 interconnect spike: can two Macs joined by a Thunderbolt cable reach each
# other on k3sm-owned addresses on bridge0, with the cable ports left in the bridge?
#
# Row in hack/acceptance/phases.json:
#   M17-interconnect-spike  gate hack/lab/m17-interconnect-spike.sh, tier lab,
#                           requires two-macs + thunderbolt-cable, manual: true
#
# Usage:
#   hack/lab/m17-interconnect-spike.sh --plan     # the rung plan; no host, nothing contacted
#   K3SM_LAB=1 PEER_SSH=<ssh target of the other Mac> \
#     EVIDENCE_DIR=<absolute dir outside any git tree> hack/lab/m17-interconnect-spike.sh
#
# The driver runs on one of the two Macs (the "local" side) and reaches the other
# (the "peer" side) over ssh. It needs passwordless sudo on the peer, and a sudo
# credential on the local Mac (`sudo -v` first when it asks for a password). Every
# host change is a script file run under `sudo -n /bin/bash <file>`, with a restore
# trap that removes only the reserved-half aliases and routes it added on bridge0
# (hack/spike/m17-interconnect/lib.sh). It never changes bridge0 membership, never
# touches the LAN interface or the default route, never loads a packet-filter rule,
# never toggles network settings and never reboots.
#
# Optional knobs (recorded in the findings):
#   K3SM_INTERCONNECT_RUNS            runs per figure (default 5; fewer is refused)
#   K3SM_INTERCONNECT_IPERF_SECONDS   seconds per iperf3 run (default 5)
#   K3SM_INTERCONNECT_PEER_MESH_IP    the peer's mesh address (default: discovered,
#                                     the peer's first address in 100.64.0.0/10)
#
# THE EXIT CONTRACT (the M16/M17 spike shape):
#   0  PASS      an address form crossed the cable, every required check passed, and
#                every figure was measured. RECORDED rungs beside it are additive.
#   1  FAIL      no address form crossed the cable, a required check failed, or the
#                run refused (K3SM_LAB=1 with a missing variable, an unready rig,
#                reserved-half state on bridge0 the spike did not add).
#   2  RECORDED  a form passed but a figure could not be measured (iperf3 missing,
#                no mesh address). Never a green.
#
# Honesty contract: --plan is parsed before any host check and exits 0 anywhere;
# with K3SM_LAB unset this exits 0 saying PENDING (a skip, NOT a pass); under
# K3SM_LAB=1 a missing PEER_SSH or EVIDENCE_DIR is a FAIL (exit 1), never a PENDING.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=../spike/m17-interconnect/lib.sh
. "$HERE/../spike/m17-interconnect/lib.sh"

ROW="M17-interconnect-spike"
RUNS="${K3SM_INTERCONNECT_RUNS:-5}"
SECS="${K3SM_INTERCONNECT_IPERF_SECONDS:-5}"

print_plan() {
	cat <<'PLAN'
==> k3sm M17 interconnect spike: PLAN ONLY (nothing is contacted, nothing is written)

question (Q1)
  Do two k3sm-owned addresses on bridge0, in the reserved halves 169.254.0.0/24 and
  169.254.255.0/24, carry IPv4 across the Thunderbolt cable with the cable ports left
  in the bridge, ARP-resolving to the peer's MAC and never the Mac's own?

address forms, in the pre-decided order (the first that passes is measured)
  form A  own-half alias: the node address as a /24-netmask alias in its own half
          (local 169.254.0.1/24, peer 169.254.255.1/24), one -net route to bridge0 for
          the other half, pod addresses as /32 aliases inside the connected subnet
  form B  single half: both node addresses in 169.254.0.0/24 with a /24 netmask
          (local 169.254.0.1, peer 169.254.0.9), no extra route; caps a cluster at 31
          interconnect nodes (a stated ceiling)
  form C  /32 aliases (local 169.254.0.1, peer 169.254.255.1) plus both /24 interface
          routes to bridge0 on each side
  none crosses -> FAIL: the downstream build halts and the design returns for
          re-planning (no fallback to enX addressing, which the earlier rig run disproved)

checks per form (PASS/FAIL)
  carrier      bridge0 has a Thunderbolt member with carrier, on both Macs
  ping         node address to node address, both directions (ping -S)
  tcp          node to node, both directions: nc -s dials a listener bound explicitly
               to the peer's node address, which reports the dialer's source
  arp          the ARP entry for the peer's address is the peer's MAC (bridge0 or a
               member, read over ssh), never the local MAC, never a permanent entry
  pod          a second /32 alias per side as a pod address: ping and tcp across,
               the listener's local address (lsof) is the pod address, ARP as above

on the passing form
  configd      after a read-only `scutil --nwi` and a 10 s hold, the aliases and the
               routes the form added are still present (PASS/FAIL); no network setting
               is toggled, so a real network change stays RECORDED
  figures      iperf3 single and -P 4, both directions (-R), RUNS runs each, median and
               p99, over the interconnect, beside the mesh path (the peer's mesh
               address) and the self-assigned bridge0 address; ping RTT per path.
               iperf3 not installed -> RECORDED, never a made-up number
  retransmits  netstat -s TCP retransmit delta over the interconnect runs, with the
               bridge0 MTU (1500 expected; recorded, never changed)

RECORDED rungs (not exercised here, and the run says so)
  unplug       carrier unplug and replug: needs a human at the cable and the node
               reconcile that re-adds addresses, a later change
  shim dial    a shim-pinned dial from a native pod sourcing its interconnect address:
               needs the shim's interconnect environment, a later change
  mlx ring     an MLX ring between two pods binding the interconnect addresses, with
               tokens/s: needs the operator's interconnect hostfile, a later change
  Q2 loops     bridged ports in a loop: needs a second cable or a third Mac
  Q3 rdma      RDMA with the ports bridged: needs a Thunderbolt 5 Mac; the M17-rdma
               row (hack/lab/m17-rdma.sh) owns it

host changes  reserved-half aliases on bridge0 and -net routes for exactly the two
              halves, ledgered and removed by a restore trap; bridge0 membership, the
              LAN interface and the default route are never touched; no pf; no reboot
exit          0 PASS · 1 FAIL · 2 RECORDED (never a green)
rig           K3SM_LAB=1, PEER_SSH, EVIDENCE_DIR (required; no defaults)
findings      EVIDENCE_DIR/findings.md (with figures.jsonl and every payload transcript)
PLAN
}

case "${1:-}" in
--plan | --dry-run)
	print_plan
	exit 0
	;;
-h | --help)
	echo "usage: $0 [--plan]   (K3SM_LAB=1 PEER_SSH=<ssh target> EVIDENCE_DIR=<dir> for a rig run)"
	exit 0
	;;
"") ;;
*)
	echo "$0: unknown argument: $1 (try --plan)" >&2
	exit 1
	;;
esac
if [ "$#" -gt 1 ]; then
	echo "$0: too many arguments (try --plan)" >&2
	exit 1
fi

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "$ROW gate: PENDING (two-macs + thunderbolt-cable). The spike needs K3SM_LAB=1, two Macs joined by a Thunderbolt cable, PEER_SSH and EVIDENCE_DIR. This is NOT a pass."
	exit 0
fi

missing=""
for v in PEER_SSH EVIDENCE_DIR; do
	[ -n "${!v:-}" ] || missing="$missing $v"
done
if [ -n "$missing" ]; then
	echo "$ROW gate: FAIL — K3SM_LAB=1 but missing$missing (no defaults: the ssh target is the operator's own machine, and evidence lives outside any repository). A lab run that cannot reach its Macs proved nothing: this is a FAIL, never a PENDING."
	exit 1
fi
case "$EVIDENCE_DIR" in
/*) ;;
*)
	echo "$ROW gate: FAIL — EVIDENCE_DIR must be an absolute path"
	exit 1
	;;
esac
# Judge the nearest existing ancestor BEFORE creating anything, so a refused path
# never leaves a directory behind inside a repository.
probe="$EVIDENCE_DIR"
while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
if git -C "$probe" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "$ROW gate: FAIL — EVIDENCE_DIR is inside a git work tree; evidence never lands in a repository"
	exit 1
fi
if ! [ "$RUNS" -ge 5 ] 2>/dev/null; then
	echo "$ROW gate: FAIL — K3SM_INTERCONNECT_RUNS=$RUNS; a median and p99 need >= 5 runs"
	exit 1
fi
if ! [ "$SECS" -ge 1 ] 2>/dev/null; then
	echo "$ROW gate: FAIL — K3SM_INTERCONNECT_IPERF_SECONDS=$SECS is not a positive integer"
	exit 1
fi
mkdir -p "$EVIDENCE_DIR" || {
	echo "$ROW gate: FAIL — cannot create $EVIDENCE_DIR"
	exit 1
}

exec > >(tee -a "$EVIDENCE_DIR/driver.log") 2>&1
IC_FINDINGS="$EVIDENCE_DIR/findings.md"
{
	echo "# $ROW findings ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
	echo
	echo "Two Macs joined by one Thunderbolt cable, cable ports left in bridge0. The Macs are named"
	echo "by role (local runs the driver, peer is reached over ssh), never by hostname."
	echo
	echo "Runs per figure: $RUNS; seconds per iperf3 run: $SECS."
	echo
} >"$IC_FINDINGS"

FINAL_RC=1
FINAL_MSG="interrupted before a verdict: FAIL"
ARMED=0
BG_PIDS=""
FIGURES_MISSING=0

finish() {
	FINAL_RC="$1"
	FINAL_MSG="$2"
	exit "$1"
}

# shellcheck disable=SC2329 # invoked by the EXIT trap below
on_exit() {
	local rc=$?
	trap - EXIT
	if [ "$ARMED" = 1 ]; then
		note "restoring both Macs (reserved-half aliases and routes this run added)"
		local p
		for p in $BG_PIDS; do kill "$p" 2>/dev/null; done
		on_peer "for f in $IC_REMOTE_DIR/iperf-*.pid; do [ -s \"\$f\" ] && kill \"\$(cat \"\$f\")\" 2>/dev/null; rm -f \"\$f\"; done" >/dev/null 2>&1 || true
		restore_side local
		restore_side peer
	fi
	[ "$FINAL_MSG" = "interrupted before a verdict: FAIL" ] && FINAL_RC=$((rc == 0 ? 1 : rc))
	{
		echo
		echo "## Verdict"
		echo
		echo "exit $FINAL_RC: $FINAL_MSG"
	} >>"$IC_FINDINGS"
	echo
	echo "$ROW: $FINAL_MSG"
	echo "findings: $IC_FINDINGS"
	exit "$FINAL_RC"
}
trap on_exit EXIT
trap 'exit 130' INT TERM HUP

# on <side> <command> — one unprivileged read on a side, in a login shell's PATH.
on_local() { /bin/bash -c "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:\$PATH; $1"; }
on_peer() { ssh_peer "zsh -lc $(printf '%q' "$1")" </dev/null; }
on() { if [ "$1" = local ]; then on_local "$2"; else on_peer "$2"; fi; }
other() { if [ "$1" = local ]; then echo peer; else echo local; fi; }

# ---------------------------------------------------------------------------------
note "preflight: tools, sudo, the peer"
# ---------------------------------------------------------------------------------
for tool in ssh scp python3 nc ping arp lsof; do
	command -v "$tool" >/dev/null 2>&1 || finish 1 "FAIL — the local Mac needs $tool on PATH"
done
sudo -n true 2>/dev/null || finish 1 "FAIL — sudo on the local Mac needs a password; run \`sudo -v\` first, then re-run"
on_peer "mkdir -p $IC_REMOTE_DIR && sudo -n true" >/dev/null 2>&1 ||
	finish 1 "FAIL — the peer is unreachable over ssh as PEER_SSH, or its sudo is not passwordless"
ARMED=1
note "replaying any ledger an interrupted earlier run left behind"
restore_side local
restore_side peer

# The side-info payload: bridge0, its members, which are Thunderbolt and have
# carrier, the MACs, MTU, the default-route interface, the self-assigned and mesh
# addresses, any reserved-half alias already present, the tools, and the context
# every figure carries. Read-only.
for side in local peer; do
	payload "$side" info 0 <<'EOF' || true
br="$(ifconfig bridge0 2>/dev/null)" || { echo BRIDGE=absent; exit 0; }
echo BRIDGE=present
echo "BRIDGE_MAC=$(printf '%s\n' "$br" | awk '$1=="ether"{print $2; exit}')"
echo "BRIDGE_STATUS=$(printf '%s\n' "$br" | awk '$1=="status:"{print $2; exit}')"
echo "BRIDGE_MTU=$(printf '%s\n' "$br" | awk '{for(i=1;i<NF;i++) if($i=="mtu"){print $(i+1); exit}}')"
members="$(printf '%s\n' "$br" | awk '$1=="member:"{print $2}')"
tbdevs="$(networksetup -listallhardwareports 2>/dev/null | awk '/^Hardware Port:/{tb=($0 ~ /Thunderbolt/ && $0 !~ /Bridge/)} /^Device:/{if(tb) print $2; tb=0}')"
tbm="" tba="" macs=""
for m in $members; do
  macs="$macs $(ifconfig "$m" 2>/dev/null | awk '$1=="ether"{print $2; exit}')"
  if printf '%s\n' "$tbdevs" | grep -qx "$m"; then
    tbm="$tbm $m"
    ifconfig "$m" | grep -q 'status: active' && tba="$tba $m"
  fi
done
echo "MEMBERS=$(echo $members)"
echo "TB_MEMBERS=$(echo $tbm)"
echo "TB_ACTIVE=$(echo $tba)"
echo "MEMBER_MACS=$(echo $macs)"
echo "DEFAULT_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
self="" reserved=""
for a in $(printf '%s\n' "$br" | awk '$1=="inet"{print $2}'); do
  if in_reserved "$a"; then reserved="$reserved $a"; else case "$a" in 169.254.*) [ -z "$self" ] && self="$a" ;; esac; fi
done
echo "SELF_ADDR=$self"
echo "RESERVED=$(echo $reserved)"
echo "MESH_ADDR=$(ifconfig -a inet | awk '$1=="inet"{print $2}' | awk -F. '$1==100 && $2>=64 && $2<=127' | head -1)"
echo "MODEL=$(sysctl -n hw.model)"
echo "OS=$(sw_vers -productVersion) ($(sw_vers -buildVersion))"
for t in iperf3 python3 nc lsof; do
  if command -v "$t" >/dev/null 2>&1; then echo "HAS_$t=yes"; else echo "HAS_$t=no"; fi
done
EOF
	cp "$PAYLOAD_LOG" "$EVIDENCE_DIR/info-$side.env"
done
LI="$EVIDENCE_DIR/info-local.env"
PI="$EVIDENCE_DIR/info-peer.env"

{
	echo "## Rig"
	echo
	for side in local peer; do
		f="$EVIDENCE_DIR/info-$side.env"
		echo "- $side: $(kv "$f" MODEL), macOS $(kv "$f" OS); bridge0 members [$(kv "$f" MEMBERS)], Thunderbolt [$(kv "$f" TB_MEMBERS)], carrier [$(kv "$f" TB_ACTIVE)]; bridge0 MTU $(kv "$f" BRIDGE_MTU)"
	done
	echo
	echo "## Preflight"
	echo
} >>"$IC_FINDINGS"

for side in local peer; do
	f="$EVIDENCE_DIR/info-$side.env"
	[ "$(kv "$f" BRIDGE)" = present ] || finish 1 "FAIL — the $side Mac has no bridge0"
	[ "$(kv "$f" DEFAULT_IF)" != bridge0 ] || finish 1 "FAIL — the $side Mac's default route uses bridge0; the spike never runs where it could touch the LAN path"
	[ -z "$(kv "$f" RESERVED)" ] ||
		finish 1 "FAIL — the $side Mac's bridge0 already carries reserved-half addresses this spike did not add ($(kv "$f" RESERVED)); they are left alone and the spike does not run beside them"
	[ "$(kv "$f" HAS_python3)" = yes ] || finish 1 "FAIL — the $side Mac needs python3 (the TCP listener)"
	[ "$(kv "$f" HAS_nc)" = yes ] || finish 1 "FAIL — the $side Mac needs nc"
	run_pass "preflight $side: bridge0 present, default route off bridge0, no foreign reserved-half address"
done

# Every MAC a side owns on bridge0 (the bridge's own and its members').
macs_of() {
	local f="$1" m out=""
	for m in $(kv "$f" BRIDGE_MAC) $(kv "$f" MEMBER_MACS); do out="$out $(norm_mac "$m")"; done
	printf '%s' "$out"
}
MACS_local="$(macs_of "$LI")"
MACS_peer="$(macs_of "$PI")"

# ---------------------------------------------------------------------------------
# The forms.
# ---------------------------------------------------------------------------------
form_addrs() {
	case "$1" in
	A)
		FORM_DESC="own-half /24-netmask alias plus one -net route for the other half"
		L_NODE=169.254.0.1 P_NODE=169.254.255.1 L_POD=169.254.0.2 P_POD=169.254.255.2
		L_MASK=255.255.255.0 P_MASK=255.255.255.0
		L_ROUTES="$IC_HALF_HIGH" P_ROUTES="$IC_HALF_LOW"
		;;
	B)
		FORM_DESC="single half: both nodes in 169.254.0.0/24 with a /24 netmask, no extra route"
		L_NODE=169.254.0.1 P_NODE=169.254.0.9 L_POD=169.254.0.2 P_POD=169.254.0.10
		L_MASK=255.255.255.0 P_MASK=255.255.255.0
		L_ROUTES="" P_ROUTES=""
		;;
	C)
		FORM_DESC="/32 aliases plus both /24 interface routes to bridge0"
		L_NODE=169.254.0.1 P_NODE=169.254.255.1 L_POD=169.254.0.2 P_POD=169.254.255.2
		L_MASK=255.255.255.255 P_MASK=255.255.255.255
		L_ROUTES="$IC_HALF_LOW $IC_HALF_HIGH" P_ROUTES="$IC_HALF_LOW $IC_HALF_HIGH"
		;;
	esac
}

# configure <side> <form> — the privileged payload: refuse beside foreign state,
# then the node alias, the pod alias and the form's routes, all ledgered. Held past
# the payload's exit (IC_HOLD=1); the driver restores. Exit 3 = foreign state.
configure() {
	local side="$1" node mask pod routes
	if [ "$side" = local ]; then node="$L_NODE" mask="$L_MASK" pod="$L_POD" routes="$L_ROUTES"; else node="$P_NODE" mask="$P_MASK" pod="$P_POD" routes="$P_ROUTES"; fi
	payload "$side" "configure-$2" 1 IC_HOLD=1 NODE_IP="$node" NODE_MASK="$mask" POD_IP="$pod" ROUTES="$routes" <<'EOF'
[ "$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')" = bridge0 ] && { echo "REFUSED: the default route uses bridge0"; exit 3; }
ifconfig bridge0 >/dev/null 2>&1 || { echo "REFUSED: no bridge0"; exit 3; }
[ -s "$LEDGER" ] && { echo "REFUSED: the restore ledger is not empty"; exit 3; }
for a in $(ifconfig bridge0 | awk '$1=="inet"{print $2}'); do
  in_reserved "$a" && { echo "REFUSED: $a is a reserved-half address this spike did not add"; exit 3; }
done
for h in 169.254.0.0/24 169.254.255.0/24; do
  has_half_route "$h" && { echo "REFUSED: a route for $h exists that this spike did not add"; exit 3; }
done
ic_alias "$NODE_IP" "$NODE_MASK" || exit 4
ic_alias "$POD_IP" 255.255.255.255 || exit 4
for h in $ROUTES; do ic_route "$h" || exit 4; done
echo "CONFIGURED node $NODE_IP netmask $NODE_MASK, pod $POD_IP/32, routes [${ROUTES}] on bridge0"
ifconfig bridge0 | awk '$1=="inet"'
netstat -rn -f inet | awk '$1 ~ /^169\.254/'
EOF
}

# check_carrier <side> — a Thunderbolt member of bridge0 with carrier, read now.
check_carrier() {
	local out
	out="$(on "$1" "tb=\$(networksetup -listallhardwareports | awk '/^Hardware Port:/{tb=(\$0 ~ /Thunderbolt/ && \$0 !~ /Bridge/)} /^Device:/{if(tb) print \$2; tb=0}'); for m in \$(ifconfig bridge0 | awk '\$1==\"member:\"{print \$2}'); do printf '%s\n' \"\$tb\" | grep -qx \"\$m\" && ifconfig \"\$m\" | grep -q 'status: active' && echo \"\$m\"; done" 2>/dev/null | tr '\n' ' ')"
	if [ -n "${out// /}" ]; then
		ok "form $FORM carrier $1: Thunderbolt bridge0 member(s) with carrier: $out"
	else
		bad "form $FORM carrier $1: no Thunderbolt member of bridge0 has carrier (is the cable in a bridged port?)"
	fi
}

# check_ping <side> <src> <dst> <label>
check_ping() {
	local out recv avg
	out="$(on "$1" "ping -c 3 -t 8 -S $2 $3" 2>&1)"
	printf '%s\n' "--- ping $4 from $1: -S $2 $3" "$out" >>"$EVIDENCE_DIR/form-$FORM.log"
	recv="$(printf '%s\n' "$out" | awk '/packets received/{print $4; exit}')"
	avg="$(printf '%s\n' "$out" | awk -F/ '/round-trip/{print $5; exit}')"
	if [ "${recv:-0}" -gt 0 ] 2>/dev/null; then
		ok "form $FORM ping $4 ($1 -> $(other "$1")): $recv/3 replies, avg ${avg:-?} ms"
	else
		bad "form $FORM ping $4 ($1 -> $(other "$1")): no reply from $3 sourced from $2"
	fi
}

# check_tcp <listen-side> <listen-addr> <src-addr> <port> <label> [lsof] — a
# listener bound explicitly to listen-addr on one side, an nc dial sourced from
# src-addr on the other; the listener must report src-addr as the peer address.
check_tcp() {
	local ls="$1" la="$2" sa="$3" port="$4" label="$5" want_lsof="${6:-}"
	local ds log pid rc acc name
	ds="$(other "$ls")"
	log="$EVIDENCE_DIR/form-$FORM-tcp-$port.listen"
	if [ "$ls" = local ]; then
		python3 -c "$IC_LISTEN_PY" "$la" "$port" 20 >"$log" 2>&1 &
	else
		on_peer "python3 -c $(printf '%q' "$IC_LISTEN_PY") $la $port 20" >"$log" 2>&1 &
	fi
	pid=$!
	BG_PIDS="$BG_PIDS $pid"
	for _ in $(seq 1 50); do
		grep -q '^LISTEN' "$log" 2>/dev/null && break
		sleep 0.2
	done
	if ! grep -q '^LISTEN' "$log" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		bad "form $FORM tcp $label: the listener on the $ls Mac could not bind $la:$port ($(tr '\n' ' ' <"$log"))"
		return
	fi
	if [ -n "$want_lsof" ]; then
		name="$(on "$ls" "lsof -nP -iTCP:$port -sTCP:LISTEN" 2>/dev/null | awk 'NR>1{print $9; exit}')"
		if [ "$name" = "$la:$port" ]; then
			ok "form $FORM tcp $label: the listener's local address (lsof) is the pod address $la:$port"
		else
			bad "form $FORM tcp $label: the listener's local address (lsof) is '$name', want $la:$port"
		fi
	fi
	rc=0
	on "$ds" "nc -z -G 5 -w 5 -s $sa $la $port" >>"$EVIDENCE_DIR/form-$FORM.log" 2>&1 || rc=$?
	wait "$pid" 2>/dev/null
	acc="$(awk '$1=="ACCEPT"{print $2" "$3; exit}' "$log")"
	if [ "$rc" = 0 ] && [ "$acc" = "$la $sa" ]; then
		ok "form $FORM tcp $label ($ds -> $ls): connected; the listener saw local $la, peer $sa"
	else
		bad "form $FORM tcp $label ($ds -> $ls): nc exit $rc, the listener saw '${acc:-no connection}' (want '$la $sa')"
	fi
}

# check_arp <side> <dst> <label> — the ARP entry the side holds for dst must be one
# of the other Mac's MACs, never its own, never permanent.
check_arp() {
	local side="$1" dst="$2" label="$3" line mac nm mine theirs
	line="$(on "$side" "arp -n $dst" 2>&1)"
	printf '%s\n' "--- arp $label on $side: $line" >>"$EVIDENCE_DIR/form-$FORM.log"
	mac="$(printf '%s\n' "$line" | awk '{print $4; exit}')"
	if [ "$side" = local ]; then mine="$MACS_local" theirs="$MACS_peer"; else mine="$MACS_peer" theirs="$MACS_local"; fi
	nm="$(norm_mac "$mac")"
	if printf '%s\n' "$line" | grep -q permanent; then
		bad "form $FORM arp $label on $side: a permanent entry for $dst ($mac): the self-ARP trap, nothing crosses the cable"
	elif [ -z "$mac" ] || [ "$mac" = "(incomplete)" ] || [ "$mac" = no ] || [ "$mac" = entry ]; then
		bad "form $FORM arp $label on $side: no resolved entry for $dst ($line)"
	elif [[ " $mine " == *" $nm "* ]]; then
		bad "form $FORM arp $label on $side: $dst resolves to this Mac's own MAC $nm"
	elif [[ " $theirs " == *" $nm "* ]]; then
		ok "form $FORM arp $label on $side: $dst resolves to the $(other "$side") Mac's MAC $nm"
	else
		bad "form $FORM arp $label on $side: $dst resolves to $nm, which is neither Mac's bridge0 or member MAC"
	fi
}

# run_form <form> — 0 passed, 1 did not pass, 2 refused (foreign state).
run_form() {
	FORM="$1"
	FORM_PASSES=0 FORM_FAILS=0
	form_addrs "$FORM"
	note "form $FORM: $FORM_DESC"
	finding ""
	finding "## Form $FORM: $FORM_DESC"
	finding ""
	local side rc
	for side in local peer; do
		rc=0
		configure "$side" "$FORM" || rc=$?
		case "$rc" in
		0) ;;
		3)
			bad "form $FORM configure $side: refused beside reserved-half state the spike did not add"
			return 2
			;;
		*)
			bad "form $FORM configure $side: the alias or route was refused (payload exit $rc)"
			return 1
			;;
		esac
	done
	sleep 2
	check_carrier local
	check_carrier peer
	check_ping local "$L_NODE" "$P_NODE" node
	check_ping peer "$P_NODE" "$L_NODE" node
	check_tcp peer "$P_NODE" "$L_NODE" 5371 node
	check_tcp local "$L_NODE" "$P_NODE" 5372 node
	check_arp local "$P_NODE" node
	check_arp peer "$L_NODE" node
	check_ping local "$L_POD" "$P_POD" pod
	check_ping peer "$P_POD" "$L_POD" pod
	check_tcp peer "$P_POD" "$L_POD" 5373 pod lsof
	check_tcp local "$L_POD" "$P_POD" 5374 pod lsof
	check_arp local "$P_POD" pod
	check_arp peer "$L_POD" pod
	[ "$FORM_FAILS" = 0 ] && [ "$FORM_PASSES" -gt 0 ]
}

WINNER=""
for form in A B C; do
	rc=0
	run_form "$form" || rc=$?
	if [ "$rc" = 0 ]; then
		WINNER="$form"
		break
	fi
	if [ "$rc" = 2 ]; then
		finish 1 "FAIL — a reserved-half alias or route the spike did not add appeared on bridge0; nothing of it was touched"
	fi
	record "form $form did not cross the cable ($FORM_FAILS failed checks, above); next form in the pre-decided order"
	restore_side local
	restore_side peer
done
if [ -z "$WINNER" ]; then
	finish 1 "FAIL — no address form crossed the cable (A, B and C all failed). The downstream build halts and the design returns for re-planning; there is no fallback to enX addressing."
fi
finding ""
finding "**Form $WINNER passed** ($FORM_DESC)."
RUN_PASSES=$((RUN_PASSES + FORM_PASSES))

# ---------------------------------------------------------------------------------
note "form $WINNER: configd re-read check (read only; no network setting is toggled)"
# ---------------------------------------------------------------------------------
finding ""
finding "## Form $WINNER: configd, figures, retransmits"
finding ""
for side in local peer; do
	on "$side" "scutil --nwi" >"$EVIDENCE_DIR/scutil-nwi-$side.txt" 2>&1 || true
done
sleep 10
present_check() { # present_check <side> <aliases> <routes>
	local side="$1" a h miss=""
	for a in $2; do
		on "$side" "ifconfig bridge0" 2>/dev/null | awk '$1=="inet"{print $2}' | grep -qxF "$a" || miss="$miss alias:$a"
	done
	for h in $3; do
		on "$side" "route -n get -net $h" 2>/dev/null | awk -v d="${h%/*}" '/destination:/{x=$2} /mask:/{m=$2} /interface:/{i=$2} END{exit !(x==d && m=="255.255.255.0" && i=="bridge0")}' || miss="$miss route:$h"
	done
	if [ -z "$miss" ]; then
		run_pass "configd $side: after scutil --nwi and a 10 s hold, the aliases [$2] and routes [${3}] are still on bridge0"
	else
		run_fail "configd $side: missing after scutil --nwi and a 10 s hold:$miss"
	fi
}
present_check local "$L_NODE $L_POD" "$L_ROUTES"
present_check peer "$P_NODE $P_POD" "$P_ROUTES"
record "configd across a real network change: not exercised (it needs a human to toggle a network setting; this run only reads configd state)"

# ---------------------------------------------------------------------------------
note "form $WINNER: figures (iperf3, RTT) and TCP retransmits"
# ---------------------------------------------------------------------------------
L_MTU="$(kv "$LI" BRIDGE_MTU)" P_MTU="$(kv "$PI" BRIDGE_MTU)"
PEER_MESH="${K3SM_INTERCONNECT_PEER_MESH_IP:-$(kv "$PI" MESH_ADDR)}"
PEER_SELF="$(kv "$PI" SELF_ADDR)"

retrans() { on "$1" "netstat -s -p tcp" 2>/dev/null | awk '/data packets .*retransmitted/{print $1; exit}'; }

bps() {
	python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(1)
e=d.get("end",{}); s=e.get("sum_received") or e.get("sum") or {}
b=s.get("bits_per_second")
if not b: sys.exit(1)
print("%.3f" % (b/1e9))'
}

# measure_path <path> <dst> <src or -> <port>
measure_path() {
	local path="$1" dst="$2" src="$3" port="$4" mode dir flags vals v bind="" sflag="" shown
	if [ "$src" != - ]; then
		bind="-B $src"
		sflag="-S $src"
	fi
	for mode in single p4; do
		for dir in fwd rev; do
			flags=""
			[ "$mode" = p4 ] && flags="$flags -P 4"
			[ "$dir" = rev ] && flags="$flags -R"
			vals=""
			for _ in $(seq 1 "$RUNS"); do
				# shellcheck disable=SC2086
				v="$(iperf3 -c "$dst" $bind -p "$port" -t "$SECS" $flags -J 2>>"$EVIDENCE_DIR/iperf3.err" | bps)" && vals="$vals $v"
			done
			shown="iperf3 -c <peer $path address>"
			[ -n "$bind" ] && shown="$shown -B <local $path address>"
			shown="$shown -p $port -t $SECS$flags -J"
			if [ -z "$vals" ]; then
				record "figure $path tcp-$mode-$dir: no run produced a value (see iperf3.err); no number is recorded"
				FIGURES_MISSING=1
			else
				# shellcheck disable=SC2086
				figure "$path" "tcp-$mode-$dir" "Gbit/s" "$shown" $vals
			fi
		done
	done
	vals=""
	for _ in $(seq 1 "$RUNS"); do
		v="$(on_local "ping -c 5 -q $sflag $dst" 2>/dev/null | awk -F/ '/round-trip/{print $5; exit}')"
		[ -n "$v" ] && vals="$vals $v"
	done
	if [ -n "$vals" ]; then
		# shellcheck disable=SC2086
		figure "$path" "rtt" "ms" "ping -c 5 -q <peer $path address> (avg)" $vals
	else
		record "figure $path rtt: no ping reply; no number is recorded"
		FIGURES_MISSING=1
	fi
}

if [ "$(kv "$LI" HAS_iperf3)" != yes ] || [ "$(kv "$PI" HAS_iperf3)" != yes ]; then
	record "figures: iperf3 is not installed on $([ "$(kv "$LI" HAS_iperf3)" != yes ] && echo "the local Mac ")$([ "$(kv "$PI" HAS_iperf3)" != yes ] && echo "the peer Mac")(brew install iperf3); no throughput figure was measured, and none is made up"
	FIGURES_MISSING=1
else
	servers="$P_NODE:5311"
	[ -n "$PEER_MESH" ] && servers="$servers $PEER_MESH:5312"
	[ -n "$PEER_SELF" ] && servers="$servers $PEER_SELF:5313"
	payload peer iperf-start 0 SERVERS="$servers" IC_REMOTE_DIR="$IC_REMOTE_DIR" <<'EOF' || true
for s in $SERVERS; do
  a="${s%:*}" p="${s##*:}"
  iperf3 -s -D -B "$a" -p "$p" -I "$IC_REMOTE_DIR/iperf-$p.pid" && echo "iperf3 server on $a:$p"
done
EOF
	sleep 1
	l0="$(retrans local)" p0="$(retrans peer)"
	measure_path interconnect "$P_NODE" "$L_NODE" 5311
	l1="$(retrans local)" p1="$(retrans peer)"
	if [ -n "$l0" ] && [ -n "$l1" ] && [ -n "$p0" ] && [ -n "$p1" ]; then
		record "tcp retransmits over the interconnect runs: local +$((l1 - l0)), peer +$((p1 - p0)) data packets (netstat -s -p tcp); bridge0 MTU local ${L_MTU:-?}, peer ${P_MTU:-?}$([ "$L_MTU" = 1500 ] && [ "$P_MTU" = 1500 ] || echo " (not 1500 on both; recorded, never changed)")"
	else
		record "tcp retransmits: netstat -s -p tcp gave no retransmit line; no delta recorded"
	fi
	if [ -n "$PEER_MESH" ]; then
		measure_path mesh "$PEER_MESH" - 5312
	else
		record "figures mesh: the peer has no address in 100.64.0.0/10 (set K3SM_INTERCONNECT_PEER_MESH_IP); the comparison is owed"
		FIGURES_MISSING=1
	fi
	if [ -n "$PEER_SELF" ]; then
		measure_path self-assigned "$PEER_SELF" - 5313
	else
		record "figures self-assigned: the peer's bridge0 has no self-assigned 169.254/16 address; no figure"
	fi
	on_peer "for f in $IC_REMOTE_DIR/iperf-*.pid; do [ -s \"\$f\" ] && kill \"\$(cat \"\$f\")\" 2>/dev/null; rm -f \"\$f\"; done" >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------------
note "RECORDED rungs (not exercised by this run)"
# ---------------------------------------------------------------------------------
finding ""
finding "## Recorded, not exercised"
finding ""
record "unplug and replug: not exercised. It needs a human at the cable and the node reconcile that re-adds addresses (a later change); this script never touches the cable"
record "shim-pinned dial: not exercised. It needs the shim's interconnect environment (a later change)"
record "MLX ring over the interconnect: not exercised. It needs the operator's interconnect hostfile (a later change); no tokens/s figure"
record "Q2 bridged loops: not exercised. It needs a second cable or a third Mac (a physical touch); this script never forms a loop"
record "Q3 RDMA with bridged ports: not exercised. It needs a Thunderbolt 5 Mac; the M17-rdma row (hack/lab/m17-rdma.sh) owns it"

finding ""
finding "Totals: $RUN_PASSES passed, $RUN_FAILS failed, $RUN_RECORDS recorded."
if [ "$RUN_FAILS" -gt 0 ]; then
	finish 1 "FAIL — form $WINNER crossed the cable, but a required check failed (above)"
fi
if [ "$FIGURES_MISSING" = 1 ]; then
	finish 2 "RECORDED — form $WINNER crossed the cable, but a figure was not measured (above); not a green spike"
fi
finish 0 "PASS — form $WINNER crossed the cable on both node and pod addresses, configd left it alone, and every figure was measured"
