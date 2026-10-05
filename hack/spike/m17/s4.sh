#!/usr/bin/env bash
# M17.0 / S4 — sleep, unplug and replug UNDER A BULK FLOW: what the kernel does when
# the cable goes, how long traffic takes to find the tunnel, and whether a cable flip
# can fault the kernel (the B350/B370 panic class was a route change moving an open
# socket between interfaces; a cable flip is the same class of event).
#
#   (1) What the kernel does to the cable port's routes (the /25s, the host route,
#       the alias) on a link loss and on its return.
#   (2) The fallback latency distribution: the largest reply gap of a 0.1 s ping to a
#       pod-range address across the cable, over >= 10 administrative flips and
#       >= 10 PHYSICAL unplugs (the operator is prompted; RECORDED when nobody acts).
#   (3) No kernel fault across the repeated flips (kern.boottime unchanged, no new
#       panic report, on both Macs).
#   (4) How often configd re-adds the port to bridge0, and how soon after a link event.
#   (5) Wireguard re-programming time when the tunnel itself rode the cable
#       (K3SM_M17_WG_CABLE_ROUTE=1).
#   (6) The peer asleep with the cable intact: a silent peer (its cable traffic
#       dropped by a packet-filter anchor, link up) always; a real sleep with a
#       scheduled wake when K3SM_M17_ALLOW_SLEEP=1.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$HERE/lib.sh"

RUNG="S4"
QUESTION="When the cable goes (administratively, physically, or by a peer that stops answering), what does the kernel
do to the direct routes, how long until a bulk flow's traffic rides the tunnel, how often does configd re-add the
bridge member, and does repeated flipping ever fault the kernel?"
CRITERIA="s4.2 no kernel fault on either Mac across every flip and unplug (kern.boottime unchanged, no new panic report)
s4.3 configd never re-adds a removed port to bridge0 within 2 s of a link event (faster than the watcher's poll)
s4.1 the bulk iperf3 flow across the cable (MSS 1340, R15) is still running at the end of the rung
RECORDED: the route table's reaction per event; fallback latency (median, p99) over the flips and over the physical
unplugs; configd re-add count and latency; wireguard re-programming time; the silent-peer and sleeping-peer windows"
METHOD="Both Macs configured as netd would (privileged, restore trap held for the rung), a pod-range lo0 alias on the
worker and a bulk iperf3 flow to it from the server. Per event, an observer on each Mac samples link state, bridge0
membership and the /25 count every 0.5 s while the server pings the alias every 0.1 s (--apple-time); FLIPS
(>= 10) administrative down/up of the worker's port, then UNPLUGS (>= 10) prompted physical unplug/replug cycles;
a pf anchor that drops the worker's cable traffic for 30 s; an optional real sleep with pmset schedule wake."
HALT="s4.3 fails (configd re-adds faster than the watcher) -> R8: the watcher removes on every network-change event,
  and the doc says the bridge is managed.
s1.5 failed earlier (PF_ROUTE silent) -> R8: the fallback figure recorded here is the poll-only figure.
s4.2 fails (a kernel fault) -> no substitution is pre-decided: the spike stops and the fault is reported with its
  panic report; nothing in M17 ships over a path that faults the kernel."

spike_args "$RUNG" "$QUESTION" "$CRITERIA" "$METHOD" "$HALT" "$@"

spike_require "$RUNG"
if ! [ "$UNPLUGS" -ge 10 ] 2>/dev/null || ! [ "$FLIPS" -ge 10 ] 2>/dev/null; then
	echo "FAIL      M17.0 S4: K3SM_M17_UNPLUGS=$UNPLUGS K3SM_M17_FLIPS=$FLIPS; the fallback distribution needs >= 10 of each" >&2
	exit 1
fi

spike_begin "$RUNG"

spike_cleanup() {
	on server "[ -s $REMOTE_DIR/bulk.pid ] && kill \$(cat $REMOTE_DIR/bulk.pid) 2>/dev/null; rm -f $REMOTE_DIR/bulk.pid" </dev/null >/dev/null 2>&1 || true
	on worker "[ -s $REMOTE_DIR/iperf3.pid ] && kill \$(cat $REMOTE_DIR/iperf3.pid) 2>/dev/null; rm -f $REMOTE_DIR/iperf3.pid" </dev/null >/dev/null 2>&1 || true
}

R8_S4="halt (R8): the watcher removes on every network-change event, and the doc says the bridge is managed"

# The observer: link state, bridge0 membership and the /25 count every 0.5 s for
# DURATION seconds; with PING_TARGET, a 0.1 s ping whose largest reply gap is the
# fallback latency. Run privileged (the 0.1 s interval) but HELD: it changes nothing.
read -r -d '' OBSERVER <<'OEOF' || true
end=$(( $(date +%s) + DURATION ))
if [ -n "${PING_TARGET:-}" ]; then
  ping -i 0.1 --apple-time "$PING_TARGET" >"$REMOTE_DIR/ping-$TAG.txt" 2>&1 & pp=$!
fi
last_state="" last_change="$(ms)" last_r="" prev_member=""
while [ "$(date +%s)" -lt "$end" ]; do
  t="$(ms)"; s="$(link_state "$IFC")"
  if [ "$s" != "$last_state" ]; then echo "OBS $t link $s"; last_state="$s"; last_change="$t"; fi
  if is_member "$IFC"; then m=1; else m=0; fi
  if [ "$m" = 1 ] && [ "$prev_member" = 0 ]; then echo "OBS $t member-readded $((t - last_change))"; fi
  prev_member="$m"
  r="$(netstat -rn -f inet | awk -v i="$IFC" '$NF==i && $1 ~ /\/25$/' | grep -c . || true)"
  if [ "$r" != "$last_r" ]; then echo "OBS $t routes25 $r"; last_r="$r"; fi
  sleep 0.5
done
if [ -n "${pp:-}" ]; then
  kill "$pp" 2>/dev/null; wait "$pp" 2>/dev/null
  python3 - "$REMOTE_DIR/ping-$TAG.txt" <<'PY'
import re, sys
ts = []
for line in open(sys.argv[1]):
    m = re.match(r"(\d+):(\d+):(\d+\.\d+) \d+ bytes from", line)
    if m:
        ts.append(int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3)))
gaps = [b - a for a, b in zip(ts, ts[1:]) if b >= a]
print("GAP %d %d" % (round(max(gaps) * 1000) if gaps else -1, len(ts)))
PY
fi
OEOF

# observe <tag> <seconds> — start both observers in the background (the server's
# with the ping). observe_wait collects them.
observe() {
	OBS_PIDS=""
	printf '%s\n' "$OBSERVER" | remote_raw server "obs-$1" 1 SPIKE_HOLD=1 IFC="$SRV_IF" DURATION="$2" TAG="$1" PING_TARGET="$WRK_PROBE_IP" >"$RUNG_DIR/obs-$1-server.log" 2>&1 &
	OBS_PIDS="$!"
	printf '%s\n' "$OBSERVER" | remote_raw worker "obs-$1" 1 SPIKE_HOLD=1 IFC="$WRK_IF" DURATION="$2" TAG="$1" >"$RUNG_DIR/obs-$1-worker.log" 2>&1 &
	OBS_PIDS="$OBS_PIDS $!"
	sleep 2
}
observe_wait() {
	local p
	for p in $OBS_PIDS; do wait "$p" 2>/dev/null || true; done
}
gap_of() { awk '$1=="GAP"{print $2}' "$RUNG_DIR/obs-$1-server.log" | tail -1; }
readds_of() { cat "$RUNG_DIR/obs-$1-server.log" "$RUNG_DIR/obs-$1-worker.log" 2>/dev/null | awk '$1=="OBS" && $3=="member-readded"{print $4}'; }
routes_of() { awk '$1=="OBS" && ($3=="routes25" || $3=="link"){printf "%s=%s ", $3, $4}' "$RUNG_DIR/obs-$1-server.log"; }

# check_readds <tag> — s4.3 over one event's observers.
READD_FAST=0
READD_COUNT=0
check_readds() {
	local l
	for l in $(readds_of "$1"); do
		READD_COUNT=$((READD_COUNT + 1))
		[ "$l" -lt 2000 ] && READD_FAST=$((READD_FAST + 1))
	done
}

# reconfigure — put the held configuration back after an event (idempotent: what
# survived is left alone, what the kernel removed is added again).
reconfigure() {
	spike_configure_link server routes >/dev/null
	spike_configure_link worker routes >/dev/null
}

# faults — kern.boottime and the panic-report count on both Macs.
faults() {
	local side
	for side in server worker; do
		on "$side" "sysctl -n kern.boottime | sed 's/.*sec = \([0-9]*\).*/\1/'; ls /Library/Logs/DiagnosticReports 2>/dev/null | grep -c '\.panic$' || true" </dev/null 2>/dev/null | tr '\n' ' '
		echo
	done
}

# ---------------------------------------------------------------------------------
note "S4 setup — the link configured on both Macs, the alias, the bulk flow"
# ---------------------------------------------------------------------------------
spike_configure_link server routes
spike_configure_link worker routes
remote_sudo worker "s4-lo0-alias" SPIKE_HOLD=1 IP="$WRK_PROBE_IP" <<'EOF'
spike_lo0_alias "$IP" || verdict FAIL "s4 setup: the lo0 alias $IP was refused"
EOF
remote worker "s4-iperf-server" <<'EOF'
iperf3 -s -p 5201 -D --pidfile "$REMOTE_DIR/iperf3.pid" >/dev/null 2>&1; sleep 2
[ -s "$REMOTE_DIR/iperf3.pid" ] || verdict FAIL "s4 setup: iperf3 did not start on the worker"
EOF
if [ "$FAILS" -gt 0 ]; then spike_end "$RUNG"; fi
remote server "s4-bulk" T="$WRK_PROBE_IP" <<'EOF'
# MSS 1340: the one clamp R15 applies to every cross-node path, so a flow that moves
# from the cable to the tunnel never carries a segment the tunnel cannot.
nohup iperf3 -c "$T" -p 5201 -t 86400 -i 1 -M 1340 --forceflush </dev/null >"$REMOTE_DIR/bulk.log" 2>&1 &
echo $! >"$REMOTE_DIR/bulk.pid"
EOF
FAULTS_BEFORE="$(faults)"
record "s4 kern.boottime and panic-report count before (server, worker): $(echo "$FAULTS_BEFORE" | tr '\n' '|')"
sleep 5

# ---------------------------------------------------------------------------------
note "S4(1,2) — $FLIPS administrative flips of the worker's cable port"
# ---------------------------------------------------------------------------------
gaps=""
for i in $(seq 1 "$FLIPS"); do
	observe "flip$i" 20
	remote_sudo worker "s4-flip" SPIKE_HOLD=1 IFC="$WRK_IF" <<'EOF' >/dev/null
spike_ifdown "$IFC"; sleep 8; spike_ifup "$IFC"
EOF
	observe_wait
	g="$(gap_of "flip$i")"
	[ -n "$g" ] && [ "$g" -ge 0 ] && gaps="$gaps $g"
	check_readds "flip$i"
	echo "      flip $i: largest reply gap ${g:-?} ms; server $(routes_of "flip$i")"
	reconfigure
	sleep 3
done
# shellcheck disable=SC2086
figure flip "fallback-admin-ms" "ms" "ifconfig <worker port> down; sleep 8; ifconfig <worker port> up — largest gap of ping -i 0.1 --apple-time <worker pod-range alias> on the server" $gaps
record "s4.1 kernel reaction to a flip (first flip, server side): $(routes_of flip1)"

# ---------------------------------------------------------------------------------
note "S4(2,4) — physical unplugs ($UNPLUGS asked for)"
# ---------------------------------------------------------------------------------
gaps=""
done_unplugs=0
for i in $(seq 1 "$UNPLUGS"); do
	observe "unplug$i" "$((PROMPT_WAIT + 150))"
	spike_prompt "UNPLUG #$i of $UNPLUGS: pull the Thunderbolt cable now (you will then be asked to plug it back)."
	remote worker "s4-unplug-wait" IFC="$WRK_IF" WAIT="$PROMPT_WAIT" <<'EOF' >/dev/null
wait_link "$IFC" down "$WAIT" >/dev/null && echo "UNPLUGGED" || echo "NOT-UNPLUGGED"
EOF
	if grep -q '^NOT-UNPLUGGED' "$RUNG_DIR/worker-s4-unplug-wait.log"; then
		observe_wait
		record "s4.2 unplug #$i: nobody unplugged the cable within ${PROMPT_WAIT}s; stopping the physical series at $done_unplugs"
		break
	fi
	sleep 10
	spike_prompt "PLUG the cable BACK into the same receptacles (#$i)."
	remote worker "s4-replug-wait" IFC="$WRK_IF" WAIT="$PROMPT_WAIT" <<'EOF' >/dev/null
wait_link "$IFC" active "$WAIT" >/dev/null && echo "REPLUGGED" || echo "NOT-REPLUGGED"
EOF
	observe_wait
	done_unplugs=$((done_unplugs + 1))
	g="$(gap_of "unplug$i")"
	[ -n "$g" ] && [ "$g" -ge 0 ] && gaps="$gaps $g"
	check_readds "unplug$i"
	echo "      unplug $i: largest reply gap ${g:-?} ms; server $(routes_of "unplug$i")"
	if grep -q '^NOT-REPLUGGED' "$RUNG_DIR/worker-s4-replug-wait.log"; then
		record "s4.2 the cable was not plugged back after unplug #$i; stopping the physical series"
		break
	fi
	sleep 10
	reconfigure
done
if [ "$done_unplugs" -gt 0 ]; then
	# shellcheck disable=SC2086
	figure unplug "fallback-unplug-ms" "ms" "physical unplug/replug — largest gap of ping -i 0.1 --apple-time <worker pod-range alias> on the server" $gaps
	[ "$done_unplugs" -lt 10 ] && record "s4.2 only $done_unplugs physical unplugs were performed; the plan asks for >= 10"
	record "s4.1 kernel reaction to an unplug (first unplug, server side): $(routes_of unplug1)"
fi

# ---------------------------------------------------------------------------------
note "S4(5) — wireguard re-programming time when the tunnel rode the cable"
# ---------------------------------------------------------------------------------
if [ "${K3SM_M17_WG_CABLE_ROUTE:-}" != 1 ]; then
	record "s4.5 not measured — it needs K3SM_M17_WG_CABLE_ROUTE=1"
else
	kc get meshpeers -o json </dev/null >"$RUNG_DIR/meshpeers.json" 2>/dev/null || true
	ep="$(python3 - "$RUNG_DIR/meshpeers.json" "$SRV_NODE" <<'PY'
import json, sys
try:
    items = json.load(open(sys.argv[1]))["items"]
except Exception:
    items = []
for m in items:
    if m["spec"].get("nodeName") == sys.argv[2]:
        print(m["spec"].get("endpoint", "").rsplit(":", 1)[0].strip("[]"))
PY
)"
	if [ -z "$ep" ]; then
		record "s4.5 not measured — the server's MeshPeer endpoint could not be read"
	else
		# The worker reaches the server's mesh-egress address through the tunnel only
		# (its /25s toward the server withdrawn for the leg), and the tunnel's own
		# packets to the server's endpoint ride the cable.
		remote_sudo worker "s4-wg-on" SPIKE_HOLD=1 EP="$ep" GW="$SRV_LINK" HALVES="$SRV_HALVES" <<'EOF'
for h in $HALVES; do spike_unroute -net "$h"; done
spike_route -host "$EP" "$GW" || verdict FAIL "s4.5 the host route to the server's wireguard endpoint was refused"
EOF
		sleep 15
		printf '%s\n' "$OBSERVER" | remote_raw worker "obs-wg" 1 SPIKE_HOLD=1 IFC="$WRK_IF" DURATION=40 TAG=wg PING_TARGET="$SRV_EGRESS" >"$RUNG_DIR/obs-wg-worker.log" 2>&1 &
		op=$!
		sleep 3
		remote_sudo worker "s4-wg-flip" SPIKE_HOLD=1 IFC="$WRK_IF" <<'EOF' >/dev/null
spike_ifdown "$IFC"; sleep 20; spike_ifup "$IFC"
EOF
		wait "$op" 2>/dev/null || true
		g="$(awk '$1=="GAP"{print $2}' "$RUNG_DIR/obs-wg-worker.log" | tail -1)"
		if [ -n "$g" ] && [ "$g" -ge 0 ]; then
			figure wg-cable "fallback-wg-ms" "ms" "worker: ping -i 0.1 --apple-time <server mesh egress> through the tunnel while the tunnel rode the cable; ifconfig <worker port> down for 20 s" "$g"
		else
			record "s4.5 the tunnel's re-programming gap could not be read (see $RUNG_DIR/obs-wg-worker.log)"
		fi
		remote_sudo worker "s4-wg-off" SPIKE_HOLD=1 EP="$ep" <<'EOF'
spike_unroute -host "$EP"
EOF
		reconfigure
	fi
fi

# ---------------------------------------------------------------------------------
note "S4(6) — the peer silent with the cable intact (link up, its cable traffic dropped)"
# ---------------------------------------------------------------------------------
observe silent 45
remote_sudo worker "s4-silent" SPIKE_HOLD=1 IFC="$WRK_IF" <<'EOF' >/dev/null
spike_pf_block k3sm-m17-spike "block drop quick on $IFC all"
sleep 30
spike_pf_clear k3sm-m17-spike
EOF
observe_wait
record "s4.6 silent peer, link up, 30 s: server $(routes_of silent); largest reply gap $(gap_of silent) ms (routes that stay up while the peer is silent are what the R13 liveness probe exists for)"
check_readds silent

if [ "${K3SM_M17_ALLOW_SLEEP:-}" != 1 ]; then
	record "s4.6 a real worker sleep was not measured — it needs K3SM_M17_ALLOW_SLEEP=1 (pmset schedule wake + pmset sleepnow on the worker)"
else
	observe sleep 300
	remote_sudo worker "s4-sleep" SPIKE_HOLD=1 <<'EOF'
pmset schedule wake "$(date -v+3M '+%m/%d/%y %H:%M:%S')" && ( sleep 3; pmset sleepnow ) >/dev/null 2>&1 &
echo "sleep scheduled with a wake in 3 minutes"
EOF
	observe_wait
	back=0
	for _ in $(seq 1 60); do
		if on worker true </dev/null >/dev/null 2>&1; then
			back=1
			break
		fi
		sleep 10
	done
	record "s4.6 worker asleep (cable intact): server $(routes_of sleep); largest reply gap $(gap_of sleep) ms; worker back over ssh: $([ "$back" = 1 ] && echo yes || echo no)"
	check_readds sleep
	reconfigure
fi

# ---------------------------------------------------------------------------------
note "S4(3) — faults, configd, and the bulk flow"
# ---------------------------------------------------------------------------------
FAULTS_AFTER="$(faults)"
if [ "$FAULTS_AFTER" = "$FAULTS_BEFORE" ]; then
	pass "s4.2 no kernel fault on either Mac across $FLIPS flips and $done_unplugs unplugs (kern.boottime and panic-report count unchanged)"
else
	fail "s4.2 a Mac's boot time or panic-report count changed (before: $(echo "$FAULTS_BEFORE" | tr '\n' '|') after: $(echo "$FAULTS_AFTER" | tr '\n' '|')) — halt: no substitution is pre-decided; collect the panic report"
fi
if [ "$READD_FAST" -gt 0 ]; then
	fail "s4.3 configd re-added a removed port to bridge0 within 2 s of a link event $READD_FAST time(s) (of $READD_COUNT re-adds) — $R8_S4"
else
	pass "s4.3 configd never re-added a removed port within 2 s of a link event ($READD_COUNT re-adds in all)"
fi
on server "[ -s $REMOTE_DIR/bulk.pid ] && kill -0 \$(cat $REMOTE_DIR/bulk.pid) && tail -3 $REMOTE_DIR/bulk.log" </dev/null >"$RUNG_DIR/bulk-tail.txt" 2>&1
if [ -s "$RUNG_DIR/bulk-tail.txt" ] && grep -q 'bits/sec' "$RUNG_DIR/bulk-tail.txt"; then
	pass "s4.1 the bulk iperf3 flow survived every event: $(tail -1 "$RUNG_DIR/bulk-tail.txt" | tr -s ' ')"
else
	fail "s4.1 the bulk iperf3 flow (MSS 1340) did not survive the rung (see $RUNG_DIR/bulk-tail.txt) — halt: no substitution is pre-decided"
fi
on server "cat $REMOTE_DIR/bulk.log" </dev/null >"$RUNG_DIR/bulk.log" 2>&1 || true

spike_end "$RUNG"
