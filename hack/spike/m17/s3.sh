#!/usr/bin/env bash
# M17.0 / S3 — link-local after member removal: the discovery and pairing path.
#
#   (1) After `ifconfig bridge0 deletem <enX>`, the port gets its own fe80::%enX, and
#       the time from removal to a non-tentative address (the DAD delay) is recorded:
#       it is what the beacon waits for.
#   (2) Link-local multicast to ff02::1 (the beacon's group) crosses the cable, both
#       ways, and arrives with the cable interface as its zone.
#   (3) A TLS 1.3 dial to a zoned fe80::...%enX literal connects, and the zone string
#       Go's net/http reports for the ACCEPTED connection's local address is recorded.
#       That string is the golden value TestPairTrustDecision fakes and the real-socket
#       zone test asserts; the M17-lab ladder re-asserts it on the cable.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$HERE/lib.sh"

RUNG="S3"
QUESTION="Once a Thunderbolt port leaves bridge0, does it get a usable fe80::%enX (and how long does DAD take), does
ff02::1 multicast cross the cable, and does a TLS dial over a zoned fe80 literal work, with net/http reporting the
interface name as the accepted connection's zone?"
CRITERIA="s3.1 each Mac's cable port has a non-tentative fe80 address within 30 s of deletem (the delay is recorded)
s3.2 an ff02::1 datagram sent on one Mac's cable port is received on the other's, zone = its cable port (both ways)
s3.3 a TLS 1.3 dial to the worker's fe80::...%<server port> connects (certificate pinned), and net/http on the worker
     reports the cable interface name as the zone of the accepted connection's local address (the golden)
RECORDED: the DAD delay per Mac; the remote zone; the dial time; whether the port had an fe80 while a member"
METHOD="A privileged script with the restore trap removes each port from bridge0 and polls ifconfig for the fe80
address; the probe's mcast-listen/mcast-send and zone-serve/zone-dial (net/http, crypto/tls, in-memory self-signed
certificate verified by pin) run as the login user on each Mac."
HALT="s3.1/s3.2/s3.3 fail (fe80 unusable on a removed member) -> R8: the beacon rides bridge0 on the UNJOINED Mac only
  and the server keeps its ports removed. (Build amendment A1 already made that the design: the joiner pairs from
  bridge0; this rung records whether the server side of A1 holds.)"

spike_args "$RUNG" "$QUESTION" "$CRITERIA" "$METHOD" "$HALT" "$@"
spike_begin "$RUNG"

R8_S3="halt (R8): the beacon rides bridge0 on the unjoined Mac only and the server keeps its ports removed"

# ---------------------------------------------------------------------------------
note "S3(1) — member removal and the DAD delay, both Macs"
# ---------------------------------------------------------------------------------
for side in server worker; do
	ifc="$SRV_IF"
	[ "$side" = worker ] && ifc="$WRK_IF"
	remote_sudo "$side" "s3-deletem" SPIKE_HOLD=1 IFC="$ifc" R8="$R8_S3" <<'EOF'
before="$(ifconfig "$IFC" | awk '/inet6 fe80/{print $2}' | head -1)"
recorded "s3.1 $SIDE: fe80 on $IFC while a bridge0 member: ${before:-none}; member: $(is_member "$IFC" && echo yes || echo no)"
t0="$(ms)"
spike_deletem "$IFC" || { verdict FAIL "s3.1 $SIDE: $IFC is still a bridge0 member after deletem"; exit 0; }
addr=""
for _ in $(seq 1 150); do
  addr="$(ifconfig "$IFC" | awk '/inet6 fe80/ && !/tentative/{print $2}' | head -1)"
  [ -n "$addr" ] && break
  sleep 0.2
done
t1="$(ms)"
if [ -n "$addr" ]; then
  verdict PASS "s3.1 $SIDE: $IFC has $addr $((t1 - t0)) ms after deletem"
  echo "FIG dad-ms $((t1 - t0))"
else
  verdict FAIL "s3.1 $SIDE: $IFC has no non-tentative fe80 address 30 s after deletem ($(ifconfig "$IFC" | grep inet6 | tr -s ' \t' ' ' | tr '\n' ';')) — $R8"
fi
EOF
	figures_from_log "$side" "$RUNG_DIR/$side-s3-deletem.log"
done
if [ "$FAILS" -gt 0 ]; then spike_end "$RUNG"; fi

# ---------------------------------------------------------------------------------
note "S3(2) — ff02::1 across the cable, both ways"
# ---------------------------------------------------------------------------------
for dir in server:worker worker:server; do
	tx="${dir%%:*}" rx="${dir##*:}"
	txif="$SRV_IF" rxif="$WRK_IF"
	[ "$tx" = worker ] && txif="$WRK_IF" rxif="$SRV_IF"
	out="$RUNG_DIR/mcast-$tx-to-$rx.jsonl"
	on "$rx" "$REMOTE_DIR/probe mcast-listen -iface $rxif -port 19347 -for 40s" </dev/null >"$out" 2>&1 &
	lp=$!
	sleep 2
	on "$tx" "$REMOTE_DIR/probe mcast-send -iface $txif -port 19347 -count 20" </dev/null >"$RUNG_DIR/mcast-send-$tx.jsonl" 2>&1 || true
	wait "$lp" 2>/dev/null || true
	zone="$(python3 - "$out" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if "from" in e:
        print(e.get("zone", ""))
        break
PY
)"
	if [ "$zone" = "$rxif" ]; then
		pass "s3.2 $tx -> $rx: an ff02::1 datagram crossed the cable and arrived with zone $zone"
	else
		fail "s3.2 $tx -> $rx: no ff02::1 datagram arrived on $rxif (zone seen: '${zone:-none}') — $R8_S3"
	fi
done

# ---------------------------------------------------------------------------------
note "S3(3) — TLS over fe80::%enX, and the zone net/http reports (the golden)"
# ---------------------------------------------------------------------------------
serve="$RUNG_DIR/zone-serve-worker.jsonl"
on worker "$REMOTE_DIR/probe zone-serve -iface $WRK_IF -port 19346 -for 60s" </dev/null >"$serve" 2>&1 &
sp=$!
listen="" pin=""
for _ in $(seq 1 20); do
	sleep 1
	read -r listen pin < <(python3 - "$serve" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if "listen" in e:
        print(e["listen"], e["pin"])
        break
PY
	) || true
	[ -n "$pin" ] && break
done
if [ -z "$pin" ]; then
	fail "s3.3 the worker's TLS listener on fe80::%$WRK_IF did not start (see $serve) — $R8_S3"
	kill "$sp" 2>/dev/null
else
	# The worker's address, zoned for the SERVER's side of the cable.
	host="${listen%]:*}"
	host="${host#[}"
	dial_addr="${host%%%*}%$SRV_IF"
	on server "$REMOTE_DIR/probe zone-dial -addr '$dial_addr' -port 19346 -pin $pin" </dev/null >"$RUNG_DIR/zone-dial-server.jsonl" 2>&1 || true
	wait "$sp" 2>/dev/null || true
	result="$(python3 - "$serve" "$RUNG_DIR/zone-dial-server.jsonl" <<'PY'
import json, sys
seen = dial = None
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if "localZone" in e:
        seen = e
for line in open(sys.argv[2]):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if "ok" in e:
        dial = e
if not dial or not dial.get("ok"):
    print("nodial", (dial or {}).get("error", "no dial output"))
elif not seen:
    print("noserve")
else:
    print("ok", seen["localZone"], seen["remoteZone"], seen["local"], dial.get("elapsedMs", ""), dial.get("localZone", ""))
PY
)"
	read -r status lzone rzone laddr elapsed dzone <<<"$result"
	case "$status" in
	ok)
		if [ "$lzone" = "$WRK_IF" ]; then
			pass "s3.3 a TLS 1.3 dial over fe80::%$SRV_IF connected in ${elapsed} ms; net/http reported the accepted connection's local zone as '$lzone' (the interface name: the golden)"
		else
			fail "s3.3 net/http reported the local zone '$lzone' for a connection accepted on $WRK_IF (local $laddr) — the pairing trust decision cannot read the interface from it; $R8_S3"
		fi
		record "s3.3 golden: local zone '$lzone', remote zone '$rzone' (worker); dialer local zone '$dzone' (server)"
		;;
	*)
		fail "s3.3 the TLS dial over fe80::%$SRV_IF did not complete ($result) — $R8_S3"
		;;
	esac
fi

spike_end "$RUNG"
