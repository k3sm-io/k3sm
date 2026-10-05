#!/usr/bin/env bash
# M17.0 / S2 — addressing and routing, and the R15 figure schema. The rung that says
# whether the M17 plan §1 data path works at all on macOS, and what it is worth.
#
#   (1) `ifconfig bridge0 deletem <enX>` takes the cable port out of the bridge.
#   (2) The /32 alias plus an on-link host route to the peer's link address ARP-
#       resolves across the cable.
#   (3) The two /25 gateway routes to the peer's pod /24 through its link address,
#       sourced from the mesh-egress address (RTAX_IFA, `route add ... -ifa`), are
#       installed and chosen; an UNBOUND dial is sourced from the mesh-egress address.
#   (4) Weak-host acceptance: a lo0-alias (pod-range) destination arriving on enX is
#       delivered.
#   (5) The reply comes from that lo0-alias address.
#   (6) A TCP dial sourced from a reserved-half address works, as the _k3sm user.
#   (7) TSO/LRO are off on the cable port after `-tso -lro` (build amendment A3).
#   (8) configd leaves the alias alone for the length of the rung.
#   (9) R3's recorded question: nothing on the wire checks that a pod-range source
#       arriving on enX is that peer's pod (a dial from a pod-range address is
#       accepted).
#   THE FIGURES (R15; RECORDED, never a verdict): iperf3 single and 4-stream, both
#   directions, for direct, wireguard-over-cable and Wi-Fi (plus the raw LAN as a
#   reference); idle and loaded RTT; k3sm/helper/wireguard CPU%; ClusterIP vs pod-IP;
#   UDP loss at the MTU boundary; netstat -s fragment and netstat -I error counters.
#   Medians and p99 over >= 5 runs, each with the exact command, the Mac models, the
#   macOS build and the cable. Never a hostname.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$HERE/lib.sh"

RUNG="S2"
QUESTION="Does the direct-link data path of the M17 plan §1 work on macOS (bridge member removal, a /32 link alias with
an on-link host route, two /25 gateway routes sourced from the mesh-egress address, weak-host delivery to a lo0
alias), and what do the direct, wireguard-over-cable and Wi-Fi paths measure under the R15 figure schema?"
CRITERIA="s2.1 the cable port is not a bridge0 member after deletem (read back), on both Macs
s2.2 the peer's link address ARP-resolves on the cable port through the on-link host route, both ways
s2.3 the two /25s through the peer's link address are installed and chosen for a pod-range destination
s2.3b an unbound TCP dial over the /25s is sourced from the mesh-egress address (RTAX_IFA honoured)
s2.4 a lo0-alias destination arriving on enX is delivered (weak host)
s2.5 the reply's source is the lo0-alias address
s2.6 a TCP dial bound to a reserved-half address connects, as the _k3sm user
s2.7 TSO4, TSO6 and LRO are off on the cable port after -tso -lro
s2.8 the link alias is still present at the end of the rung (configd left it alone)
RECORDED: every R15 figure (median, p99, exact command, Mac models, macOS build, cable); s2.9 (R3)"
METHOD="Privileged script files with the restore trap configure both Macs as netd would (deletem, the /32 alias, the
on-link host route, -tso -lro, then the /25s with -ifa <mesh egress>); a pod-range lo0 alias (.250 of the worker's pod
/24) carries a python listener that reports each connection's local and peer address; dials are made from the server
as the login user and as _k3sm. The figures run iperf3 against that alias over the utun first (Wi-Fi, and
wireguard-over-cable when K3SM_M17_WG_CABLE_ROUTE=1 pins the worker's path to the server's wireguard endpoint onto
the cable), then over the /25s (direct), then through a selector-less ClusterIP Service whose EndpointSlice names the
alias; RUNS (>= 5) runs each."
HALT="s2.4 fails (weak host) -> R8: the direct route is route-only via the on-link peer address, with the peer's /25s
  re-pointed through a second host route (never an on-link /24 alias on enX, which would fight the lo0 aliases).
s2.3b fails (RTAX_IFA not honoured) -> R8: the proxy and the shim pin the .1 source for all cross-node dials, and
  unbound host dials are documented as cable-only.
s2.1/s2.2/s2.3/s2.6/s2.7/s2.8 fail -> no substitution is pre-decided: the M17 plan §1 addressing does not hold
  as written, and the spike stops for a re-plan."

spike_args "$RUNG" "$QUESTION" "$CRITERIA" "$METHOD" "$HALT" "$@"

spike_require "$RUNG"
if ! [ "$RUNS" -ge 5 ] 2>/dev/null; then
	echo "FAIL      M17.0 S2: K3SM_M17_RUNS=$RUNS; the R15 figure schema needs >= 5 runs" >&2
	exit 1
fi

spike_begin "$RUNG"

spike_cleanup() {
	on worker "for p in $REMOTE_DIR/iperf3.pid $REMOTE_DIR/info.pid; do [ -s \$p ] && kill \$(cat \$p) 2>/dev/null; rm -f \$p; done" </dev/null >/dev/null 2>&1 || true
	kc delete namespace "$NS" --ignore-not-found --wait=false </dev/null >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------------
note "S2 preflight — tools, the context every figure carries, the listener address"
# ---------------------------------------------------------------------------------
for side in server worker; do
	remote "$side" "s2-preflight" <<'EOF'
for t in iperf3 python3 perl; do
  command -v "$t" >/dev/null 2>&1 || verdict FAIL "s2 preflight $SIDE: $t is not installed (iperf3 from Homebrew; python3 from the Xcode tools)"
done
hw="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name|Model Identifier|Chip|Memory:/{gsub(/^ +/,"",$1); printf "%s=%s; ", $1, $2}')"
recorded "context $SIDE: ${hw}macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
EOF
done
record "context cable: $CABLE_DESC; link ${SPEED_GBPS} Gb/s as enumerated (Thunderbolt 4 class unless enumerated otherwise)"
if [ "$FAILS" -gt 0 ]; then spike_end "$RUNG"; fi

if kc get pods -A -o 'jsonpath={range .items[*]}{.status.podIP}{" "}{end}' </dev/null 2>/dev/null | tr ' ' '\n' | grep -qxF "$WRK_PROBE_IP"; then
	fail "s2 preflight: a pod already holds $WRK_PROBE_IP; pick a free pod-range address before re-running"
	spike_end "$RUNG"
fi

# ---------------------------------------------------------------------------------
note "S2(1,2,7) — the link on both Macs: deletem, /32 alias, on-link host route, offload off"
# ---------------------------------------------------------------------------------
spike_configure_link server
spike_configure_link worker
if [ "$FAILS" -gt 0 ]; then spike_end "$RUNG"; fi

for side in server worker; do
	if [ "$side" = server ]; then ifc="$SRV_IF" peer="$WRK_LINK"; else ifc="$WRK_IF" peer="$SRV_LINK"; fi
	remote_sudo "$side" "s2-link-check" SPIKE_HOLD=1 IFC="$ifc" PEER_LINK="$peer" <<'EOF'
if is_member "$IFC"; then verdict FAIL "s2.1 $SIDE: $IFC is still a bridge0 member after deletem"; else verdict PASS "s2.1 $SIDE: $IFC is not a bridge0 member (read back)"; fi
ping -c 3 -t 5 -q "$PEER_LINK" >/dev/null 2>&1
if arp -n "$PEER_LINK" 2>/dev/null | grep -q "on $IFC" && arp -n "$PEER_LINK" | grep -qv incomplete; then
  verdict PASS "s2.2 $SIDE: $PEER_LINK ARP-resolves on $IFC ($(arp -n "$PEER_LINK" | awk '{print $4}'))"
else
  verdict FAIL "s2.2 $SIDE: $PEER_LINK does not ARP-resolve on $IFC ($(arp -n "$PEER_LINK" 2>&1 | head -1))"
fi
on="$(tso_lro_on "$IFC")"
if [ -z "$on" ]; then verdict PASS "s2.7 $SIDE: TSO4, TSO6 and LRO are off on $IFC"; else verdict FAIL "s2.7 $SIDE: $IFC still has $on after -tso -lro"; fi
recorded "s2 $SIDE: $(ifconfig "$IFC" | grep -E 'options=|inet ' | tr -s ' \t' ' ' | tr '\n' ';')"
EOF
done

# ---------------------------------------------------------------------------------
note "S2 — the pod-range listener on the worker, and iperf3"
# ---------------------------------------------------------------------------------
remote_sudo worker "s2-lo0-alias" SPIKE_HOLD=1 IP="$WRK_PROBE_IP" <<'EOF'
spike_lo0_alias "$IP" || verdict FAIL "s2 setup: the lo0 alias $IP was refused"
EOF
remote worker "s2-listeners" PROBE_IP="$WRK_PROBE_IP" LINK="$WRK_LINK" <<'EOF'
cat >"$REMOTE_DIR/info.py" <<'PY'
import socket, sys, threading
def serve(ip, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port)); s.listen(16)
    while True:
        c, _ = s.accept()
        c.sendall(f"local={c.getsockname()[0]} peer={c.getpeername()[0]}\n".encode()); c.close()
for spec in sys.argv[1:]:
    ip, port = spec.rsplit(":", 1)
    threading.Thread(target=serve, args=(ip, int(port)), daemon=True).start()
threading.Event().wait()
PY
nohup python3 "$REMOTE_DIR/info.py" "$PROBE_IP:19401" "$LINK:19402" </dev/null >"$REMOTE_DIR/info.log" 2>&1 &
echo $! >"$REMOTE_DIR/info.pid"
iperf3 -s -p 5201 -D --pidfile "$REMOTE_DIR/iperf3.pid" >/dev/null 2>&1
sleep 2
[ -s "$REMOTE_DIR/iperf3.pid" ] || verdict FAIL "s2 setup: iperf3 did not start on the worker"
EOF
if [ "$FAILS" -gt 0 ]; then spike_end "$RUNG"; fi

# shellcheck disable=SC2016 # expanded on the worker, deliberately
WORKER_LAN="$(on worker 'ipconfig getifaddr "$(route -n get default | awk "/interface:/{print \$2}")"' </dev/null 2>/dev/null)"

# measure <path> <target> <label> <udp:0|1> — the figure payload on the server.
measure() {
	local log="$RUNG_DIR/server-measure-$1.log"
	{
		printf '%s\n' "$MEASURE_PAYLOAD"
	} | remote_raw server "measure-$1" 0 TARGET="$2" TARGET_LABEL="$3" RUNS="$RUNS" UDP="$4" >"$log" 2>&1
	figures_from_log "$1" "$log"
}
# cpu <path> <target> — the CPU sampler on both Macs during a 4-stream load.
cpu() {
	local wlog="$RUNG_DIR/worker-cpu-$1.log" slog="$RUNG_DIR/server-cpu-$1.log" wp
	printf '%s\n' "$CPU_PAYLOAD" | remote_raw worker "cpu-$1" 0 >"$wlog" 2>&1 &
	wp=$!
	printf '%s\n' "$CPU_PAYLOAD" | remote_raw server "cpu-$1" 0 LOAD_TARGET="$2" >"$slog" 2>&1
	wait "$wp" 2>/dev/null || true
	figures_from_log "$1" "$slog"
	figures_from_log "$1" "$wlog"
}

# ---------------------------------------------------------------------------------
note "S2 figures, phase A — no /25s: the pod path over the mesh (Wi-Fi), and the raw LAN"
# ---------------------------------------------------------------------------------
on server "route -n get $WRK_PROBE_IP" </dev/null >"$RUNG_DIR/route-wifi.txt" 2>&1 || true
record "path wifi: $WRK_PROBE_IP routes via $(awk '/interface:/{print $2}' "$RUNG_DIR/route-wifi.txt") (the mesh, wireguard over the LAN)"
for side in server worker; do counters "$side" wifi-before; done
measure wifi "$WRK_PROBE_IP" "$WRK_PROBE_IP" 1
for side in server worker; do
	counters "$side" wifi-after
	counters_delta "$side" wifi-before wifi-after
done
cpu wifi "$WRK_PROBE_IP"
if [ -n "$WORKER_LAN" ]; then
	measure lan-raw "$WORKER_LAN" "<worker-lan>" 0
else
	record "path lan-raw: not measured (the worker's LAN address could not be read)"
fi

# ---------------------------------------------------------------------------------
note "S2 figures — wireguard over the cable (K3SM_M17_WG_CABLE_ROUTE=1)"
# ---------------------------------------------------------------------------------
if [ "${K3SM_M17_WG_CABLE_ROUTE:-}" != 1 ]; then
	record "path wg-cable: not measured — it needs K3SM_M17_WG_CABLE_ROUTE=1 (a worker host route to the server's wireguard endpoint through the server's link address, for the leg only)"
else
	kc get meshpeers -o json </dev/null >"$RUNG_DIR/meshpeers.json" 2>/dev/null || true
	SRV_WG_HOST="$(python3 - "$RUNG_DIR/meshpeers.json" "$SRV_NODE" <<'PY'
import json, sys
try:
    items = json.load(open(sys.argv[1]))["items"]
except Exception:
    items = []
for m in items:
    if m["spec"].get("nodeName") == sys.argv[2]:
        ep = m["spec"].get("endpoint", "")
        print(ep.rsplit(":", 1)[0].strip("[]"))
PY
)"
	if [ -z "$SRV_WG_HOST" ]; then
		record "path wg-cable: not measured — the server's MeshPeer endpoint could not be read"
	else
		remote_sudo worker "s2-wg-cable-on" SPIKE_HOLD=1 EP="$SRV_WG_HOST" GW="$SRV_LINK" <<'EOF'
spike_route -host "$EP" "$GW" || verdict FAIL "s2 wg-cable: the host route to the server's wireguard endpoint via $GW was refused"
ping -c 5 -q "$EP" >/dev/null 2>&1
EOF
		sleep 15
		for side in server worker; do counters "$side" wgcable-before; done
		measure wg-cable "$WRK_PROBE_IP" "$WRK_PROBE_IP" 1
		for side in server worker; do
			counters "$side" wgcable-after
			counters_delta "$side" wgcable-before wgcable-after
		done
		cpu wg-cable "$WRK_PROBE_IP"
		record "path wg-cable: the cable-port packet counters above are the evidence the tunnel rode the cable"
		remote_sudo worker "s2-wg-cable-off" SPIKE_HOLD=1 EP="$SRV_WG_HOST" <<'EOF'
spike_unroute -host "$EP"
EOF
	fi
fi

# ---------------------------------------------------------------------------------
note "S2(3,4,5,6,9) — the /25s with RTAX_IFA, weak host, reply source, reserved-half dial"
# ---------------------------------------------------------------------------------
spike_configure_link server routes
spike_configure_link worker routes
on server "route -n get $WRK_PROBE_IP" </dev/null >"$RUNG_DIR/route-direct.txt" 2>&1 || true
gw="$(awk '/gateway:/{print $2}' "$RUNG_DIR/route-direct.txt")"
via="$(awk '/interface:/{print $2}' "$RUNG_DIR/route-direct.txt")"
if [ "$gw" = "$WRK_LINK" ] && [ "$via" = "$SRV_IF" ]; then
	pass "s2.3 $WRK_PROBE_IP routes via $WRK_LINK on $SRV_IF (the /25 is chosen over the utun /24)"
else
	fail "s2.3 $WRK_PROBE_IP routes via '$gw' on '$via', not $WRK_LINK on $SRV_IF — halt: no substitution is pre-decided"
fi

counters worker dial-before
remote server "s2-dial" T="$WRK_PROBE_IP" EGRESS="$SRV_EGRESS" <<'EOF'
out="$(python3 - "$T" <<'PY'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], 19401), timeout=5)
    line = s.recv(200).decode().strip()
    print(f"ok sock={s.getsockname()[0]} peer={s.getpeername()[0]} {line}")
except OSError as e:
    print(f"fail {e}")
PY
)"
echo "DIAL $out"
case "$out" in
ok*)
  verdict PASS "s2.4 a lo0-alias destination ($T) arriving on the cable is delivered (weak host): $out"
  peer_seen="$(printf '%s' "$out" | sed -n 's/.*local=[^ ]* peer=\([^ ]*\).*/\1/p')"
  if [ "$peer_seen" = "$EGRESS" ]; then
    verdict PASS "s2.3b the unbound dial was sourced from the mesh-egress address $EGRESS (RTAX_IFA honoured)"
  else
    verdict FAIL "s2.3b the unbound dial was sourced from $peer_seen, not the mesh-egress $EGRESS — halt (R8): the proxy and the shim pin the .1 source for all cross-node dials, and unbound host dials are documented as cable-only"
  fi
  reply_from="$(printf '%s' "$out" | sed -n 's/.* peer=\([^ ]*\) local=.*/\1/p')"
  if [ "$reply_from" = "$T" ]; then verdict PASS "s2.5 the reply came from the lo0-alias address $T"; else verdict FAIL "s2.5 the reply came from '$reply_from', not $T"; fi
  ;;
*)
  verdict FAIL "s2.4 a lo0-alias destination ($T) over the cable was not delivered ($out) — halt (R8): the direct route is route-only via the on-link peer address, with the peer's /25s re-pointed through a second host route (never an on-link /24 alias on enX)"
  ;;
esac
EOF
counters worker dial-after
counters_delta worker dial-before dial-after

remote_sudo server "s2-reserved-dial" SPIKE_HOLD=1 SRC="$SRV_LINK" DST="$WRK_LINK" PODSRC="$SRV_PROBE_IP" PODDST="$WRK_PROBE_IP" <<'EOF'
dial='import socket, sys
s = socket.socket(); s.settimeout(5)
try:
    s.bind((sys.argv[1], 0)); s.connect((sys.argv[2], int(sys.argv[3])))
    print("ok " + s.recv(200).decode().strip())
except OSError as e:
    print(f"fail {e}")'
user=_k3sm
id "$user" >/dev/null 2>&1 || user="$(stat -f %Su /dev/console)"
out="$(sudo -u "$user" python3 -c "$dial" "$SRC" "$DST" 19402 2>&1)"
case "$out" in
"ok "*"peer=$SRC"*) verdict PASS "s2.6 a TCP dial bound to the reserved-half $SRC reached $DST:19402 as $user ($out)" ;;
*) verdict FAIL "s2.6 a TCP dial bound to the reserved-half $SRC did not connect as $user ($out) — halt: no substitution is pre-decided" ;;
esac
[ "$user" = _k3sm ] || recorded "s2.6 there is no _k3sm user on this Mac; the dial ran as $user"
spike_lo0_alias "$PODSRC" >/dev/null 2>&1
out="$(python3 -c "$dial" "$PODSRC" "$PODDST" 19401 2>&1)"
recorded "s2.9 (R3) a dial sourced from the server's pod-range address $PODSRC to $PODDST over the cable: $out — nothing on the wire checks a pod source"
EOF

# ---------------------------------------------------------------------------------
note "S2 figures, phase B — direct (the /25s) and ClusterIP vs pod IP"
# ---------------------------------------------------------------------------------
for side in server worker; do counters "$side" direct-before; done
measure direct "$WRK_PROBE_IP" "$WRK_PROBE_IP" 1
for side in server worker; do
	counters "$side" direct-after
	counters_delta "$side" direct-before direct-after
done
cpu direct "$WRK_PROBE_IP"

kc apply -f - >"$RUNG_DIR/clusterip-apply.txt" 2>&1 <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
---
apiVersion: v1
kind: Service
metadata:
  name: m17-iperf
  namespace: $NS
spec:
  ports:
  - name: iperf
    port: 5201
    protocol: TCP
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: m17-iperf-1
  namespace: $NS
  labels:
    kubernetes.io/service-name: m17-iperf
addressType: IPv4
ports:
- name: iperf
  port: 5201
  protocol: TCP
endpoints:
- addresses: ["$WRK_PROBE_IP"]
  conditions:
    ready: true
EOF
CIP="$(kc get service m17-iperf -n "$NS" -o 'jsonpath={.spec.clusterIP}' </dev/null 2>/dev/null)"
if [ -z "$CIP" ]; then
	record "path clusterip: not measured — the Service did not get a ClusterIP (see $RUNG_DIR/clusterip-apply.txt)"
else
	sleep 10
	measure clusterip "$CIP" "$CIP (ClusterIP -> $WRK_PROBE_IP)" 0
	cpu clusterip "$CIP"
fi

# ---------------------------------------------------------------------------------
note "S2(8) — the alias survived the rung"
# ---------------------------------------------------------------------------------
for side in server worker; do
	if [ "$side" = server ]; then ifc="$SRV_IF" link="$SRV_LINK"; else ifc="$WRK_IF" link="$WRK_LINK"; fi
	remote "$side" "s2-alias-kept" IFC="$ifc" LINK="$link" <<'EOF'
if ifconfig "$IFC" | grep -q "inet $LINK "; then verdict PASS "s2.8 $SIDE: the alias $LINK is still on $IFC"; else verdict FAIL "s2.8 $SIDE: the alias $LINK is gone from $IFC (configd or another agent removed it) — halt: no substitution is pre-decided"; fi
EOF
done

record "figures: $K3SM_EVIDENCE/figures.jsonl (one JSON line per figure: path, metric, unit, exact command, cable, values)"
spike_end "$RUNG"
