#!/usr/bin/env bash
# M17.0 / S1 — enumeration and mapping. THE RUNG EVERY OTHER ONE STANDS ON: it finds
# the cable, maps it to an interface by the method the product uses, and asks what
# the link watcher can and cannot see.
#
#   (1) The F3 commands on both Macs (system_profiler SPThunderboltDataType -json and
#       networksetup -listallhardwareports), through darwin-net's linkenum (the probe's
#       `enum`), so the finding is about the production parser.
#   (2) Domain UUID <-> peer: a port pair whose peer domain UUIDs point at each other.
#   (3) Thunderbolt N -> enX: the cabled receptacle maps to an interface that exists
#       and is active on both Macs.
#   (4) system_profiler's wall and CPU cost, 10 runs per Mac (RECORDED).
#   (5) Whether an UNPRIVILEGED PF_ROUTE socket delivers RTM_IFINFO for the cable enX
#       on a PHYSICAL unplug (linkwatch.RouteReader and a raw reader, beside the poll);
#       an administrative down/up is recorded first, as a control.
#   (6) Whether the unplugged interface is destroyed or merely flagged (RECORDED).
#   (7) Receptacle stability across a worker reboot (K3SM_M17_ALLOW_REBOOT=1).
#   (8) Receptacle stability when the cable moves to another receptacle or a dock
#       (an operator touch; RECORDED when nobody moves it).
#   (9) ioreg -c IOThunderboltPort as the substitute source when the Thunderbolt
#       Bridge network service is deleted (RECORDED: what ioreg carries; the user's
#       service is never deleted, R10).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$HERE/lib.sh"

RUNG="S1"
QUESTION="Can each Mac find the cable, map it to its Thunderbolt N receptacle and enX interface by the networksetup mapping (never by interface name), identify the peer by domain UUID, keep that mapping across a reboot and a dock, and can an unprivileged PF_ROUTE reader see the cable unplug?"
CRITERIA="s1.1 linkenum enumerates >= 1 Thunderbolt port on each Mac (no NoThunderboltService)
s1.2 exactly one port pair whose peer domain UUIDs point at each other
s1.3 the cabled receptacle maps to an enX that exists and is active on both Macs
s1.5 on a physical unplug, the unprivileged linkwatch.RouteReader delivers an event for the cable enX
s1.7 (K3SM_M17_ALLOW_REBOOT=1) after a worker reboot the cabled port keeps its domain UUID and port ordinal
RECORDED: system_profiler wall/user/sys over 10 runs; destroyed vs flagged on unplug; the admin
down/up control; the receptacle/dock move; what ioreg -c IOThunderboltPort carries"
METHOD="Over ssh, unprivileged except the admin flip and the reboot: the probe's enum (linkenum.Exec) and the raw
command output on both Macs; /usr/bin/time over system_profiler x10; the probe's watch (RouteReader, Poller and a
raw PF_ROUTE reader, run as the login user) on both Macs across an ifconfig down/up and then across a physical
unplug the operator is prompted for (bounded wait); an optional worker reboot; a prompted receptacle/dock move;
ioreg -c IOThunderboltPort -r -l."
HALT="s1.5 fails (PF_ROUTE silent on unplug) -> R8: the 2 s poll is the only source and the fallback figure is
  re-measured (S4).
s1.1 NoThunderboltService -> the design's NoThunderboltService condition stands; s1.9 records whether ioreg can
  substitute (no further substitution is pre-decided).
s1.2/s1.3/s1.7 fail -> no substitution is pre-decided: the mapping the M17 plan §1 rests on does not hold, and the
  spike stops for a re-plan."

spike_args "$RUNG" "$QUESTION" "$CRITERIA" "$METHOD" "$HALT" "$@"

SPIKE_TOPOLOGY_OPTIONAL=1
spike_begin "$RUNG"

# ---------------------------------------------------------------------------------
note "S1(1-3) — enumeration, UUID <-> peer, receptacle -> enX"
# ---------------------------------------------------------------------------------
for side in server worker; do
	on "$side" "/usr/sbin/system_profiler SPThunderboltDataType -json" >"$RUNG_DIR/system_profiler-$side.json" 2>/dev/null || true
	on "$side" "/usr/sbin/networksetup -listallhardwareports" >"$RUNG_DIR/networksetup-$side.txt" 2>/dev/null || true
	n="$(jq_py "$RUNG_DIR/enum-$side.json" 'len(d.get("ports") or [])' 2>/dev/null || echo 0)"
	err="$(jq_py "$RUNG_DIR/enum-$side.json" 'd.get("error","")' 2>/dev/null || echo "no enum output")"
	if [ "${n:-0}" -ge 1 ] && [ -z "$err" ]; then
		pass "s1.1 $side: linkenum enumerated $n Thunderbolt port(s) in $(jq_py "$RUNG_DIR/enum-$side.json" 'd["elapsedMs"]') ms"
	else
		fail "s1.1 $side: linkenum enumerated no port ($err) — halt: the NoThunderboltService condition stands; see s1.9 for ioreg"
	fi
done
if [ "$TOPOLOGY_OK" = 1 ] && [ "$SRV_PORT" -ge 0 ] && [ "$WRK_PORT" -ge 0 ]; then
	pass "s1.2 peer UUIDs point at each other: server port $SRV_PORT ($SRV_UUID) <-> worker port $WRK_PORT ($WRK_UUID)"
else
	fail "s1.2 no port pair whose peer domain UUIDs point at each other — halt: no substitution is pre-decided (the M17 plan §1 mapping does not hold)"
fi

if [ -n "$SRV_IF" ] && [ -n "$WRK_IF" ]; then
	for side in server worker; do
		ifc="$SRV_IF"
		[ "$side" = worker ] && ifc="$WRK_IF"
		remote "$side" "s1-iface" IFC="$ifc" <<'EOF'
s="$(link_state "$IFC")"
if [ "$s" = active ]; then
  verdict PASS "s1.3 $SIDE: the cabled receptacle maps to $IFC, which exists and is active"
else
  verdict FAIL "s1.3 $SIDE: the cabled receptacle maps to $IFC, which is $s — halt: no substitution is pre-decided"
fi
recorded "s1.3 $SIDE: bridge0 member: $(is_member "$IFC" && echo yes || echo no); $(ifconfig "$IFC" | grep -E 'media:|options=' | tr -s ' ' | tr '\n' ' ')"
EOF
	done
fi

# ---------------------------------------------------------------------------------
note "S1(4) — system_profiler cost, 10 runs per Mac"
# ---------------------------------------------------------------------------------
for side in server worker; do
	remote "$side" "s1-cost" <<'EOF'
for i in 1 2 3 4 5 6 7 8 9 10; do
  /usr/bin/time -p /usr/sbin/system_profiler SPThunderboltDataType -json 2>&1 >/dev/null |
    awk '/^real/{r=$2} /^user/{u=$2} /^sys/{s=$2} END{print "COST", r, u, s}'
done
EOF
	log="$RUNG_DIR/$side-s1-cost.log"
	# shellcheck disable=SC2046
	figure "$side" "system_profiler-wall" "s" "/usr/bin/time -p /usr/sbin/system_profiler SPThunderboltDataType -json" $(awk '/^COST/{print $2}' "$log")
	# shellcheck disable=SC2046
	figure "$side" "system_profiler-cpu" "s (user+sys)" "/usr/bin/time -p /usr/sbin/system_profiler SPThunderboltDataType -json" $(awk '/^COST/{print $3 + $4}' "$log")
done

# watch_both <label> <seconds> — start the probe's watch on both Macs (unprivileged)
# in the background; watch_collect waits for them.
watch_both() {
	WATCH_PIDS=""
	local side ifc
	for side in server worker; do
		ifc="$SRV_IF"
		[ "$side" = worker ] && ifc="$WRK_IF"
		on "$side" "$REMOTE_DIR/probe watch -iface $ifc -for ${2}s" </dev/null >"$RUNG_DIR/watch-$1-$side.jsonl" 2>&1 &
		WATCH_PIDS="$WATCH_PIDS $!"
	done
	sleep 3
}
watch_collect() {
	local p
	for p in $WATCH_PIDS; do wait "$p" 2>/dev/null || true; done
}
# watch_summary <file> — "route=<n> poll=<n> raw_ifinfo=<n> gone=<n> notexists=<n> uid=<uid>"
watch_summary() {
	python3 - "$1" <<'PY'
import json, sys
c = {"route": 0, "poll": 0, "raw_ifinfo": 0, "gone": 0, "notexists": 0, "uid": "?"}
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("start"):
        c["uid"] = e.get("uid")
        continue
    s = e.get("source")
    if s in ("route", "poll") and "error" not in e:
        c[s] += 1
    if s == "raw" and e.get("rtm") == "RTM_IFINFO":
        c["raw_ifinfo"] += 1
    if e.get("gone"):
        c["gone"] += 1
    if "exists" in e and not e["exists"]:
        c["notexists"] += 1
print(" ".join(f"{k}={v}" for k, v in c.items()))
PY
}

if [ -n "$SRV_IF" ] && [ -n "$WRK_IF" ]; then
	# -----------------------------------------------------------------------------
	note "S1(5) control — an administrative down/up of the worker's $WRK_IF"
	# -----------------------------------------------------------------------------
	watch_both admin 25
	remote_sudo worker "s1-admin-flip" IFC="$WRK_IF" <<'EOF'
spike_ifdown "$IFC"
sleep 6
spike_restore
EOF
	watch_collect
	for side in server worker; do
		record "s1.5 control ($side, admin down/up of the worker port): $(watch_summary "$RUNG_DIR/watch-admin-$side.jsonl")"
	done

	# -----------------------------------------------------------------------------
	note "S1(5,6) — a PHYSICAL unplug, watched unprivileged on both Macs"
	# -----------------------------------------------------------------------------
	watch_both unplug "$((PROMPT_WAIT + 150))"
	spike_prompt "UNPLUG the Thunderbolt cable between the two Macs, wait about 10 seconds, then PLUG IT BACK into the SAME receptacles."
	remote worker "s1-unplug-wait" IFC="$WRK_IF" WAIT="$PROMPT_WAIT" <<'EOF'
t0="$(wait_link "$IFC" down "$WAIT")" || { echo "UNPLUG none"; exit 0; }
t1="$(wait_link "$IFC" active 120)" || t1=timeout
echo "UNPLUG $t0 $t1"
EOF
	watch_collect
	ul="$(awk '/^UNPLUG/{print $2, $3}' "$RUNG_DIR/worker-s1-unplug-wait.log" | tail -1)"
	if [ -z "$ul" ] || [ "${ul%% *}" = none ]; then
		record "s1.5/s1.6 nobody unplugged the cable within ${PROMPT_WAIT}s — PF_ROUTE delivery on a physical unplug is NOT measured"
	else
		for side in server worker; do
			sum="$(watch_summary "$RUNG_DIR/watch-unplug-$side.jsonl")"
			record "s1.5 $side: $sum (uid != 0 is the unprivileged requirement)"
			case "$sum" in *"uid=0"*) fail "s1.5 $side: the watch ran as root; the unprivileged question is unanswered" ;; esac
			case "$sum" in
			*"route=0"*) fail "s1.5 $side: the poll saw the unplug but the unprivileged PF_ROUTE reader delivered nothing for the cable port — halt (R8): the 2 s poll is the only source and the fallback figure is re-measured in S4" ;;
			*) pass "s1.5 $side: the unprivileged PF_ROUTE reader delivered the unplug for the cable port" ;;
			esac
			case "$sum" in
			*"gone=0 notexists=0"*) record "s1.6 $side: the interface was FLAGGED (it stayed in the interface list) on unplug" ;;
			*) record "s1.6 $side: the interface was DESTROYED (vanished from the interface list) on unplug" ;;
			esac
		done
		record "s1.6 unplug/replug at epoch ms $ul (worker side)"
	fi
fi

# ports_summary <enum.json> [all|cabled|peer=<uuid>] — "domain:ordinal:iface:peer" per port.
ports_summary() {
	python3 - "$1" "${2:-all}" <<'PY'
import json, sys
try:
    ports = json.load(open(sys.argv[1])).get("ports") or []
except Exception:
    ports = []
mode = sys.argv[2]
out = []
for p in ports:
    peer = p.get("PeerDomainUUID") or ""
    if mode == "cabled" and not peer:
        continue
    if mode.startswith("peer=") and peer != mode[5:]:
        continue
    out.append(f"{p.get('DomainUUID', '')}:{p.get('PortOrdinal', '')}:{p.get('Iface', '')}:{peer}")
print(" ".join(out))
PY
}

# ---------------------------------------------------------------------------------
note "S1(7) — receptacle stability across a worker reboot"
# ---------------------------------------------------------------------------------
if [ "${K3SM_M17_ALLOW_REBOOT:-}" != 1 ]; then
	record "s1.7 not measured: a worker reboot needs K3SM_M17_ALLOW_REBOOT=1"
elif [ "$TOPOLOGY_OK" != 1 ]; then
	record "s1.7 not measured: there is no cable pair to compare"
else
	remote_sudo worker "s1-reboot" <<'EOF'
( sleep 3; /sbin/shutdown -r now ) >/dev/null 2>&1 &
echo "reboot scheduled"
EOF
	sleep 60
	back=0
	for _ in $(seq 1 60); do
		if on worker "true" >/dev/null 2>&1; then
			back=1
			break
		fi
		sleep 10
	done
	if [ "$back" != 1 ]; then
		fail "s1.7 the worker did not come back over ssh within 11 minutes of the reboot"
	else
		on worker "$REMOTE_DIR/probe enum" >"$RUNG_DIR/enum-worker-after-reboot.json" 2>/dev/null ||
			{ on worker "mkdir -p $REMOTE_DIR" && scp -q "$K3SM_EVIDENCE/probe/probe" "$K3SM_M17_WORKER:$REMOTE_DIR/probe" &&
				on worker "$REMOTE_DIR/probe enum" >"$RUNG_DIR/enum-worker-after-reboot.json" 2>/dev/null; } || true
		after="$(ports_summary "$RUNG_DIR/enum-worker-after-reboot.json" "peer=$SRV_UUID")"
		if [ "${after%%:*}" = "$WRK_UUID" ] && [ "$(echo "$after" | cut -d: -f2)" = "$WRK_PORT" ]; then
			pass "s1.7 after a reboot the worker's cabled port kept its domain UUID and port ordinal ($after; before: $WRK_UUID:$WRK_PORT:$WRK_IF)"
		else
			fail "s1.7 after a reboot the worker's cabled port is '$after' (before: $WRK_UUID:$WRK_PORT:$WRK_IF) — halt: no substitution is pre-decided"
		fi
		ready=0
		for _ in $(seq 1 30); do
			if kc get node "$WRK_NODE" --no-headers 2>/dev/null | awk '{print $2}' | grep -qx Ready; then
				ready=1
				break
			fi
			sleep 10
		done
		[ "$ready" = 1 ] || record "s1.7 the worker node was not Ready 5 minutes after the reboot (check its k3sm data volume is mounted before re-running)"
	fi
fi

# ---------------------------------------------------------------------------------
note "S1(8) — the cable moved to another receptacle or through a dock"
# ---------------------------------------------------------------------------------
if [ "$TOPOLOGY_OK" != 1 ]; then
	record "s1.8 not measured: there is no cable pair to move"
else
	spike_prompt "MOVE the worker's end of the cable to a DIFFERENT Thunderbolt receptacle, or through a Thunderbolt dock. Leave it there; you will be asked to move it back."
	# Moved = the worker's cabled-port set is non-empty and differs from the start
	# (another receptacle, another interface, or a dock as the new peer).
	initial="$(ports_summary "$RUNG_DIR/enum-worker.json" cabled)"
	moved=""
	deadline=$((SECONDS + PROMPT_WAIT))
	while [ "$SECONDS" -lt "$deadline" ]; do
		sleep 10
		on worker "$REMOTE_DIR/probe enum" >"$RUNG_DIR/enum-worker-moved.json" 2>/dev/null || continue
		now="$(ports_summary "$RUNG_DIR/enum-worker-moved.json" cabled)"
		if [ -n "$now" ] && [ "$now" != "$initial" ]; then
			moved="$now"
			break
		fi
	done
	if [ -z "$moved" ]; then
		record "s1.8 not measured: the cable was not moved within ${PROMPT_WAIT}s"
	else
		sleep 15
		on worker "$REMOTE_DIR/probe enum" >"$RUNG_DIR/enum-worker-moved.json" 2>/dev/null || true
		on worker "/usr/sbin/networksetup -listallhardwareports" >"$RUNG_DIR/networksetup-worker-moved.txt" 2>/dev/null || true
		record "s1.8 after the move the worker reports (domain:ordinal:iface:peer) $(ports_summary "$RUNG_DIR/enum-worker-moved.json"); before: $WRK_UUID:$WRK_PORT:$WRK_IF:$SRV_UUID"
		spike_prompt "MOVE the cable BACK to the worker receptacle it started in (ordinal $WRK_PORT, Thunderbolt $((WRK_PORT + 1)))."
		remote worker "s1-moved-back" IFC="$WRK_IF" WAIT="$PROMPT_WAIT" <<'EOF'
wait_link "$IFC" active "$WAIT" >/dev/null && echo "BACK yes" || echo "BACK no"
EOF
		grep -q '^BACK yes' "$RUNG_DIR/worker-s1-moved-back.log" ||
			record "s1.8 the cable is not back on the worker's $WRK_IF; later rungs re-discover the topology and will use wherever it is"
	fi
fi

# ---------------------------------------------------------------------------------
note "S1(9) — ioreg as the substitute when the Thunderbolt Bridge service is gone"
# ---------------------------------------------------------------------------------
for side in server worker; do
	remote "$side" "s1-ioreg" <<'EOF'
out="$(ioreg -c IOThunderboltPort -r -l 2>/dev/null)"
n="$(printf '%s\n' "$out" | grep -c '+-o IOThunderboltPort' || true)"
keys="$(printf '%s\n' "$out" | grep -oE '"(Port Number|Socket ID|UID|Description|Link Width|Current Speed|Adapter Type)"' | sort -u | tr '\n' ' ')"
bsd="$(printf '%s\n' "$out" | grep -c '"BSD Name"' || true)"
recorded "s1.9 $SIDE: ioreg lists $n IOThunderboltPort object(s); keys seen: ${keys:-none}; BSD Name entries: $bsd (a substitute needs a receptacle number AND an interface name)"
EOF
	on "$side" "ioreg -c IOThunderboltPort -r -l" >"$RUNG_DIR/ioreg-$side.txt" 2>/dev/null || true
done
record "s1.9 the Thunderbolt Bridge service itself is never deleted (R10: the user's System Settings are not edited); whether ioreg alone can substitute is judged from the keys above"

spike_end "$RUNG"
