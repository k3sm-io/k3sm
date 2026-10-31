#!/usr/bin/env bash
# shellcheck disable=SC2329 # the assertions and their helpers run through the rung table's "$fn"
#
# k3sm M17 lab ladder: the Thunderbolt cable between two cluster Macs as an
# admin-armed interconnect beside the wireguard mesh (the cabled-interconnect
# ladder). This file is the one executable
# home of the ladder; hack/lab/m17.sh execs it.
#
# Row in hack/acceptance/phases.json:
#   M17-lab  gate hack/lab/m17-interconnect.sh, tier lab, requires two-macs +
#            thunderbolt-cable, manual: true, skeleton: false (hack/lab/m17.sh is a
#            shim that execs this file)
#
# Usage:
#   hack/lab/m17-interconnect.sh --plan                 # the rung table; no host
#   hack/lab/m17-interconnect.sh --self-test            # the predicates over fixtures
#   hack/lab/m17-interconnect.sh --verify-twice <A> <B> # two run evidence dirs
#   K3SM_LAB=1 PEER_SSH=<ssh target of the other Mac> \
#     EVIDENCE_DIR=<absolute dir outside any git tree> \
#     [K3SM_ARTIFACT=<the k3sm binary under test>] [K3SM_RC_TAG=<rc tag>] \
#     hack/lab/m17-interconnect.sh
#
# The driver runs on one of the two Macs (local) with the admin KUBECONFIG and
# reaches the other (peer) over ssh. Every privileged step is a script file run
# under `sudo -n /bin/bash <file>` (never an ssh "sudo a && b" chain). The run
# arms the interconnect itself (r1) and disarms it (r8); it never runs beside an
# Interconnect the operator armed, and it never touches bridge0 membership, the
# LAN interface, the default route or a packet filter, and never reboots.
#
# Rungs (the table below is the one declaration --plan and the runner read):
#   r0-disarmed      after the join the Interconnect exists disabled, nothing on bridge0
#   r1-arm           k3sm interconnect enable: armedBy, the Event, slot-0 aliases, peers up
#   r2-attach        an annotated pod gets a slot, its env, a bound listener, the peer's MAC
#   r3-cable-path    a fixed transfer to the peer slot address crosses the cable
#   r4-mesh-traffic  ordinary pod and ClusterIP traffic stays on the mesh; wildcard and
#                    source-pin negatives
#   r5-ring          a sharded MLXModel on the interconnect serves through rank 0
#   r6-unplug        the unplug budget measured from the carrier event; UpHold; one restart
#   r7-desired-forge a node-forged desired annotation yields no out-of-policy alias
#   r8-killswitch    k3sm interconnect disable leaves no reserved-half state anywhere
#   r9-downgrade     the previous binary node by node leaves no state; HelperTooOld leg
#
# THE EXIT CONTRACT:
#   0  PASS     every rung returned PASS. A RECORDED figure never gates.
#   1  FAIL     a rung asserted and failed (or the run was interrupted).
#   2  REFUSED  a precondition or a missing mechanism, printed as
#               REFUSED(<rung>): <what is absent> (BI<n>); also a bad argument.
#   3  K3SM_LAB unset: "LAB-PENDING: not a pass".
#
# Required under K3SM_LAB=1: PEER_SSH, EVIDENCE_DIR (missing -> exit 2).
# Optional knobs (each recorded in the log):
#   K3SM_M17_LOCAL_NODE, K3SM_M17_PEER_NODE   node names (default: matched by mesh address)
#   K3SM_M17_CLUSTER_CIDR      the cluster pod aggregate (default 10.42.0.0/16)
#   K3SM_M17_PAYLOAD_MB        r3/r4 payload in MiB (default 128, at least 100)
#   K3SM_M17_LAN_SLACK_BYTES   bytes the flat interface may move (default 8388608)
#   K3SM_M17_DESIRED_INTERVAL  seconds of the node's DesiredInterval (default 60)
#   K3SM_M17_MLX_MODEL, K3SM_M17_MLX_MEMORY, K3SM_M17_MLX_READY_TIMEOUT  r5's model
#   K3SM_M17_PREVIOUS_ARTIFACT the previous k3sm binary for r9 (absent -> REFUSED)
#   K3SM_M17_REINSTALL_ARGS    extra arguments for the r9 `k3sm install` re-runs
#   K3SM_LAB_TOLERATE_KEYS     extra taint keys every lab pod tolerates, space-separated
#                              (hack/lab/lib/tolerations.sh)
#   K3SM_LAB_PRINT_MANIFESTS=1 print the pod manifests and exit; contacts nothing
#
# Evidence: the run log is hack/lab/runs/m17-lab-<rc-tag>-<UTCdate>.log (gitignored;
# hack/lab/runs/README.md) and EVIDENCE_DIR/run.log, with the M11 run-log header
# (gate, artifact_sha256, git_sha.<repo>, result) emitted by hack/lab/lib/runlog.sh;
# per-rung transcripts, counters and figures sit under EVIDENCE_DIR/<rung>/;
# EVIDENCE_DIR/rungs.tsv is the per-rung verdict --verify-twice reads.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC2034 # REPO_ROOT, GATE_NAME and MODE are read by the header functions (lib/runlog.sh)
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/m17-interconnect.sh"
# shellcheck source-path=SCRIPTDIR source=lib/m17-interconnect-predicates.sh
. "$HERE/lib/m17-interconnect-predicates.sh"
# shellcheck source-path=SCRIPTDIR source=lib/tolerations.sh
. "$HERE/lib/tolerations.sh"
[ -r "$HERE/lib/runlog.sh" ] || {
	echo "preflight: run-log library missing or unreadable: $HERE/lib/runlog.sh" >&2
	exit 2
}
# shellcheck source-path=SCRIPTDIR source=lib/runlog.sh
. "$HERE/lib/runlog.sh" || exit 2
LAB_TOLERATIONS="$(lab_tolerations_yaml NoSchedule)" || exit 2

# shellcheck disable=SC2034 # see REPO_ROOT
GATE_NAME="m17-lab"
ROW="M17-lab"
# shellcheck disable=SC2034 # see REPO_ROOT
MODE="ladder"
PENDING_TEXT="LAB-PENDING: not a pass"
FIXTURES="$HERE/testdata/m17-interconnect"
IC_REMOTE_DIR="/tmp/k3sm-m17-lab"
NS="k3sm-m17-lab"
IC_NAME="thunderbolt"
NETD_SOCK="/var/lib/k3sm/run/netd.sock"
NETD_LEDGER="/var/lib/k3sm/keys/interconnect-aliases"
NODE_KUBECONFIG="/var/lib/k3sm/agent/node.kubeconfig"
K3SM_BIN="/usr/local/bin/k3sm"
SELFTEST_WATCHDOG="${K3SM_M17_SELFTEST_WATCHDOG:-120}"

# ── The rung table: id | summary | prerequisites | assertion | evidence | owning BI ──
read -r -d '' RUNG_TABLE <<'RUNGS' || true
r0-disarmed|after the join the Interconnect exists with enabled false, no k3sm alias on bridge0, no desired annotation, no members|crd,bridge,index,unarmed|assert_r0_disarmed|r0-disarmed/|BI6
r1-arm|k3sm interconnect enable: armedBy is the caller, the InterconnectArmed Warning Event, the slot-0 alias on exactly the cabled nodes, ic-peers up on both|crd,verbs,doctor,netd,armable|assert_r1_arm|r1-arm/|BI6
r2-attach|an annotated pod gets a slot: K3SM_INTERCONNECT_IP is its alias, the listener's lsof address is the slot not *, the peer's ARP entry is the peer's MAC|armed,attach,tools|assert_r2_attach|r2-attach/|BI7
r3-cable-path|a fixed transfer to the peer slot address: route bridge0, peer MAC, the Thunderbolt member counters rise by the payload, the LAN stays flat; RTT slot vs mesh RECORDED|armed,attached,tools|assert_r3_cable_path|r3-cable-path/|BI10
r4-mesh-traffic|pod-to-pod and ClusterIP flows ride a utun and the LAN with the cable flat; a wildcard listener is unreachable on its slot; an unbound dial sources K3SM_INTERCONNECT_IP|armed,attached,tools|assert_r4_mesh_traffic|r4-mesh-traffic/|BI4
r5-ring|a sharded MLXModel with interconnect thunderbolt serves through rank 0: ranks on slot-1 addresses, the ring on the cable, LinksHealthy True, the endpoint on the pod IP; tokens/s RECORDED beside network and single-Mac|armed,mlxhosts,gpu,mlximage|assert_r5_ring|r5-ring/|BI8
r6-unplug|a pulled cable: member down <= 20 s and the MLX re-render <= 30 s after the carrier drop, the mesh loses at most one reply, UpHold 60 s on replug, one transition per direction, no second gang restart inside 5 min|armed,ring,operator|assert_r6_unplug|r6-unplug/|BI6
r7-desired-forge|no-address-channel smoke test: the desired annotation carries no address or slot, so values the node forges with its own credential (unknown address/slot fields, a foreign interconnect name, schema 99) can only hold or drop slot 0: no out-of-policy alias or route, only the two netd verbs; an in-policy rewrite restores slot 0|armed,nodecred|assert_r7_desired_forge|r7-desired-forge/|BI3
r8-killswitch|k3sm interconnect disable: no reserved-half address, route, permanent ARP or ledger entry on either Mac, membership, lo0 and the mesh unchanged, the annotation, members and attached pods gone, the ring on the mesh|armed|assert_r8_killswitch|r8-killswitch/|BI6
r9-downgrade|disable, then the previous binary node by node: every r8 host assertion again, doctor ic-stray and ic-residue clean, HelperTooOld on the mixed leg, no reboot; then the artifact under test is reinstalled|disarmed,prevbin|assert_r9_downgrade|r9-downgrade/|BI3
RUNGS
REQUIRED_IDS="r0-disarmed r1-arm r2-attach r3-cable-path r4-mesh-traffic r5-ring r6-unplug r7-desired-forge r8-killswitch r9-downgrade"

# The closed prerequisite set. Static tokens are probed before either Mac is
# changed (a miss is exit 2 before any rung); rung tokens are probed at their
# rung; runtime tokens are set when an earlier rung passes.
PREREQ_STATIC="crd verbs doctor netd attach mlxhosts nodirectlink artifact bridge index unarmed tools"
PREREQ_RUNG="gpu mlximage operator nodecred prevbin"
PREREQ_RUNTIME="armable armed attached ring disarmed"
PREREQ_SET="$PREREQ_STATIC $PREREQ_RUNG $PREREQ_RUNTIME"

# prereq_what <token> — "<what is absent> (BI<n>)" for a refusal line.
prereq_what() {
	case "$1" in
	crd) echo "the net.k3sm.io Interconnect CRD is not served (BI6)" ;;
	verbs) echo "k3sm interconnect enable/disable are not in the installed binary (BI6)" ;;
	doctor) echo "k3sm doctor has no ic-* rows (BI9)" ;;
	netd) echo "the netd helper does not report MinorInterconnect >= 2 on both Macs (BI3)" ;;
	attach) echo "the provider has no k3sm.io/InterconnectAttached condition (BI7)" ;;
	mlxhosts) echo "the binary does not render K3SM_MLX_HOSTS (BI8)" ;;
	nodirectlink) echo "a DirectLink CRD is still served (BI5/BI11)" ;;
	artifact) echo "the two Macs (and K3SM_ARTIFACT) are not on one artifact sha (BI10)" ;;
	bridge) echo "bridge0 with a Thunderbolt member that has carrier, on both Macs (BI10)" ;;
	index) echo "a node's cluster index is beyond MaxInterconnectNodeIndex 30 (BI6)" ;;
	unarmed) echo "an Interconnect already armed, or reserved-half state this run did not create (BI6)" ;;
	tools) echo "a required tool on one of the Macs (BI10)" ;;
	gpu) echo "mlx.k3sm.io/gpu capacity on both nodes (BI8)" ;;
	mlximage) echo "the mlx serving image (BI8)" ;;
	operator) echo "an operator at /dev/tty to pull and replug the cable (BI10)" ;;
	nodecred) echo "the worker's installed node kubeconfig (BI6)" ;;
	prevbin) echo "K3SM_M17_PREVIOUS_ARTIFACT and K3SM_ARTIFACT, the previous and current binaries (BI10)" ;;
	armable) echo "r0-disarmed did not pass" ;;
	armed) echo "r1-arm did not pass" ;;
	attached) echo "r2-attach did not pass" ;;
	ring) echo "r5-ring did not pass" ;;
	disarmed) echo "r8-killswitch did not pass" ;;
	*) echo "unknown prerequisite $1" ;;
	esac
}

# ── Rung scoring ────────────────────────────────────────────────────────────────
RUNG="" RUNG_DIR="" R_PASS=0 R_FAIL=0 R_REFUSED_MSG=""
pass() {
	echo "PASS      [$RUNG] $*"
	R_PASS=$((R_PASS + 1))
}
fail() {
	echo "FAIL      [$RUNG] $*"
	R_FAIL=$((R_FAIL + 1))
}
rec() { echo "RECORDED  [$RUNG] $*"; }
info() { echo "          $*"; }
# refuse_rung <what is absent> <BI> — the rung's mechanism or precondition is
# missing; the assertion returns 2 right after.
refuse_rung() { R_REFUSED_MSG="$1 ($2)"; }
# check <description> <command...> — PASS/FAIL on the command's status, with its
# output kept beside the line.
check() {
	local d="$1" out rc=0
	shift
	out="$("$@" 2>&1)" || rc=$?
	if [ "$rc" = 0 ]; then pass "$d${out:+: $out}"; else fail "$d${out:+: $out}"; fi
	return "$rc"
}

has_text() { [[ "$1" == *"$2"* ]]; }
pod_ips_only() { [ -n "${1// /}" ] && [[ "$1" != *169.254.* ]]; }
file_lacks() { ! grep -q "$2" "$1"; }

# ── Remote and cluster glue (run mode only) ─────────────────────────────────────
on_local() { /bin/bash -c "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:\$PATH; $1"; }
on_peer() { ssh_peer "zsh -lc $(printf '%q' "$1")" </dev/null; }
on() { if [ "$1" = local ]; then on_local "$2"; else on_peer "$2"; fi; }
other() { if [ "$1" = local ]; then echo peer; else echo local; fi; }
# priv <side> <name> [K=V ...] <<'EOF' — a privileged script file on a side, its
# output in PAYLOAD_LOG. Never inside $(...): the payload counter must survive.
priv() {
	local side="$1" name="$2"
	shift 2
	payload_file "$side" "$name" 0 "$@"
	PAYLOAD_LOG="${PAYLOAD_PATH%.sh}.log"
	payload_exec "$side" 1 "$PAYLOAD_PATH" </dev/null >"$PAYLOAD_LOG" 2>&1
}
kc() { kubectl --request-timeout=15s "$@"; }
side_var() { eval "printf '%s' \"\${$1_$2}\""; }
node_of() { side_var "$1" NODE; }

# wait_until <seconds> <command...> — poll every 2 s until the command succeeds.
wait_until() {
	local deadline=$((SECONDS + $1))
	shift
	while [ "$SECONDS" -lt "$deadline" ]; do
		"$@" >/dev/null 2>&1 && return 0
		sleep 2
	done
	"$@" >/dev/null 2>&1
}

# snap <side> <tag> — host state into RUNG_DIR/<side>-<tag>-*.txt.
snap() {
	local side="$1" tag="$2" b="$RUNG_DIR/$1-$2"
	on "$side" "ifconfig bridge0" >"$b-bridge0.txt" 2>&1
	on "$side" "netstat -rn -f inet" >"$b-netstat.txt" 2>&1
	on "$side" "arp -an" >"$b-arp.txt" 2>&1
	on "$side" "ifconfig lo0 | awk '\$1==\"inet\"' | sort" >"$b-lo0.txt" 2>&1
}
# counters <side> <tag> <iface...> — netstat -I -b per interface.
counters() {
	local side="$1" tag="$2" i
	shift 2
	for i in "$@"; do on "$side" "netstat -I $i -b" >"$RUNG_DIR/$side-$tag-$i.txt" 2>&1; done
}
retrans() { on "$1" "netstat -s -p tcp" 2>/dev/null | awk '/data packets .*retransmitted/{print $1; exit}'; }
mtu_of() { on "$1" "ifconfig $2" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="mtu"){print $(i+1); exit}}'; }
# record_link_context <side> — MTU of bridge0 and the Thunderbolt member.
record_link_context() { rec "$1 Mac MTU: bridge0 $(mtu_of "$1" bridge0), $(side_var "$1" TB) $(mtu_of "$1" "$(side_var "$1" TB)")"; }

ic_json() { kc get interconnect "$IC_NAME" -o json 2>/dev/null; }
ic_field() { ic_json | python3 -I -c "import json,sys
d=json.load(sys.stdin); $1"; }
desired_of() { kc get node "$1" -o jsonpath='{.metadata.annotations.k3sm\.io/interconnect-desired}' 2>/dev/null; }
member_state() { ic_field "print(next((m.get('state','') for m in (d.get('status') or {}).get('members') or [] if m.get('node')=='$1'), ''))"; }
members_count() { ic_field "print(len((d.get('status') or {}).get('members') or []))"; }
# scrape_metrics <tag> — every node's interconnect metrics endpoint.
scrape_metrics() {
	local n
	for n in $L_NODE $P_NODE; do
		kc get --raw "/api/v1/nodes/$n/proxy/metrics/interconnect" >"$RUNG_DIR/metrics-$1-$n.txt" 2>&1 || true
	done
	cat "$RUNG_DIR"/metrics-"$1"-*.txt >"$RUNG_DIR/metrics-$1.txt" 2>/dev/null
}
alias_present() { grep -qx "$2 ${3:-0xffffff00}" <<<"$(on "$1" "ifconfig bridge0" | awk '$1=="inet"{print $2, $4}')"; }
halves_empty_on() {
	on "$1" "ifconfig bridge0" >"$RUNG_DIR/.he-$1.txt" 2>&1
	icp_halves_empty "$RUNG_DIR/.he-$1.txt"
}
# netd_hello <side> — the helper's reply to a Hello, as root, into RUNG_DIR.
netd_hello() {
	# The frame is icp_netd_hello_frame's (darwin-net pkg/netd/wire/protocol.go
	# ReadFrame: a 4-byte big-endian length, then JSON; minor 2 is the wire
	# package's MinorInterconnect), pinned by the self-test. It is deliberately
	# not the k3sm client: the probe must not trust the code under test.
	priv "$1" netd-hello SOCK="$NETD_SOCK" FRAME="$(icp_netd_hello_frame)" <<'EOF'
python3 -I - "$SOCK" "$FRAME" <<'PY'
import socket, struct, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sys.argv[1])
    s.sendall(bytes.fromhex(sys.argv[2]))
    h = b""
    while len(h) < 4:
        c = s.recv(4 - len(h))
        if not c:
            raise OSError("closed before the reply header")
        h += c
    n = struct.unpack(">I", h)[0]
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            raise OSError("closed mid-reply")
        body += c
    print(body.decode())
except Exception as e:
    print("error: %s" % e)
PY
EOF
	cp "$PAYLOAD_LOG" "$RUNG_DIR/netd-hello-$1.json"
}
read_ledger() {
	priv "$1" ledger LEDGER="$NETD_LEDGER" <<'EOF'
[ -f "$LEDGER" ] && cat "$LEDGER"
exit 0
EOF
	cp "$PAYLOAD_LOG" "$RUNG_DIR/ledger-$1.json"
}
peers_ok() {
	doctor_json "$1"
	[ "$(icp_doctor_row_state "$RUNG_DIR/doctor-$1.json" ic-peers)" = ok ]
}
# slot_general <idx> <address> — the address is InterconnectSlotAddress(idx, 2..7).
slot_general() {
	local sl
	[ -n "$2" ] && sl="$(icp_slot_of "$1" "$2")" && [ "$sl" -ge 2 ]
}
doctor_json() {
	local bin="${2:-$K3SM_BIN}"
	priv "$1" doctor BIN="$bin" <<'EOF'
"$BIN" doctor --json 2>/dev/null
exit 0
EOF
	cp "$PAYLOAD_LOG" "$RUNG_DIR/doctor-$1.json"
}

# ic_pod_manifest <name> <node> <annotated 0|1> <shell command> — a native pod
# pinned to a node (nodeName AND the darwin selector; the provider toleration plus
# K3SM_LAB_TOLERATE_KEYS, never a blanket one). ic_pod applies it.
ic_pod_manifest() {
	local ann=""
	[ "$3" = 1 ] && ann="annotations: {k3sm.io/interconnects: $IC_NAME}"
	cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: $NS
  labels: {app: $1}
  $ann
spec:
  nodeName: $2
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$LAB_TOLERATIONS]
  restartPolicy: Never
  containers:
  - name: c
    image: native
    command: ["/bin/sh", "-c", $(python3 -I -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$4")]
EOF
}
ic_pod() { ic_pod_manifest "$@" | kc apply -f - >/dev/null; }
pod_ready() { [ "$(kc get pod -n "$NS" "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ]; }
pod_done() { case "$(kc get pod -n "$NS" "$1" -o jsonpath='{.status.phase}' 2>/dev/null)" in Succeeded | Failed) return 0 ;; esac; return 1; }
pod_log_value() { kc logs -n "$NS" "$1" 2>/dev/null | awk -v k="$2" 'index($0, k)==1{v=substr($0, length(k)+1)} END{print v}'; }
pod_ip() { kc get pod -n "$NS" "$1" -o jsonpath='{.status.podIP}' 2>/dev/null; }
pod_attached() { kc get pod -n "$NS" "$1" -o jsonpath='{.status.conditions[?(@.type=="k3sm.io/InterconnectAttached")].status}' 2>/dev/null; }

# The attached listener: 5400 bound explicitly to the interconnect address, 5401
# on the wildcard (the shim rewrites it to the pod IP). Each received stream's
# byte count is a log line. Single-quoted on purpose: it expands in the pod.
# shellcheck disable=SC2016
LISTENER_CMD='echo "ICIP=${K3SM_INTERCONNECT_IP:-}"; echo "PODIP=${K3SM_POD_IP:-}"
if [ -n "${K3SM_INTERCONNECT_IP:-}" ]; then
  ( while :; do n=$(/usr/bin/nc -l "$K3SM_INTERCONNECT_IP" 5400 | /usr/bin/wc -c); echo "RECV5400=$((n + 0))"; done ) &
fi
while :; do n=$(/usr/bin/nc -l 5401 | /usr/bin/wc -c); echo "RECV5401=$((n + 0))"; done'

# ── The assertions ──────────────────────────────────────────────────────────────

assert_r0_disarmed() {
	if ! wait_until 120 ic_json; then
		fail "no Interconnect $IC_NAME within 120 s of a node reporting a Thunderbolt peer (the server auto-creates it, I1)"
		return 1
	fi
	ic_json >"$RUNG_DIR/interconnect.json"
	check "spec.enabled is false (auto-created disarmed, I1)" \
		test "$(ic_field "print(str((d.get('spec') or {}).get('enabled', False)).lower())")" = false
	check "status.members is empty" test "$(members_count)" = 0
	local s
	for s in local peer; do
		snap "$s" r0
		check "$s Mac: no inet in 169.254.0.0/24 or 169.254.255.0/24 on bridge0 (the self-assigned /16 aside)" \
			icp_halves_empty "$RUNG_DIR/$s-r0-bridge0.txt"
		check "$s Mac: no desired annotation on node $(node_of "$s")" test -z "$(desired_of "$(node_of "$s")")"
	done
}

assert_r1_arm() {
	local who out s n idx want
	who="$(kc auth whoami -o jsonpath='{.status.userInfo.username}' 2>/dev/null)"
	out="$(on_local "$K3SM_BIN interconnect enable" 2>&1)"
	printf '%s\n' "$out" >"$RUNG_DIR/enable.txt"
	ARMED_BY_RUN=1
	info "$out"
	if ! wait_until 60 test "$(ic_field "print((d.get('status') or {}).get('armedBy',''))")" != ""; then
		fail "status.armedBy never appeared"
	fi
	ic_json >"$RUNG_DIR/interconnect.json"
	local armed_by
	armed_by="$(ic_field "print((d.get('status') or {}).get('armedBy',''))")"
	if [ -n "$who" ]; then
		check "status.armedBy '$armed_by' is the caller '$who'" test "$armed_by" = "$who"
	else
		check "status.armedBy '$armed_by' is set (kubectl auth whoami unavailable; the caller is not cross-checked)" test -n "$armed_by"
		rec "the caller identity could not be read with kubectl auth whoami; armedBy is checked for presence only"
	fi
	kc get events -A --field-selector reason=InterconnectArmed -o json >"$RUNG_DIR/events.json" 2>&1
	check "an InterconnectArmed Warning Event exists" \
		python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if any(e.get("type")=="Warning" for e in d.get("items",[])) else 1)' "$RUNG_DIR/events.json"
	for s in local peer; do
		n="$(node_of "$s")" idx="$(side_var "$s" IDX)"
		want="$(icp_slot_addr "$idx" 0)"
		if wait_until 120 alias_present "$s" "$want" 0xffffff00; then
			pass "$s Mac: slot-0 alias $want/24 on bridge0 within 120 s"
		else
			fail "$s Mac: slot-0 alias $want/24 did not appear within 120 s"
		fi
		snap "$s" r1
		check "$s Mac: every reserved-half inet on bridge0 is in policy for index $idx" icp_alias_policy "$RUNG_DIR/$s-r1-bridge0.txt" "$idx"
		check "$s Mac: status.members[$n].index is $idx (the server's recompute)" \
			test "$(ic_field "print(next((m.get('index') for m in (d.get('status') or {}).get('members') or [] if m.get('node')=='$n'), ''))")" = "$idx"
	done
	check "status.members holds exactly the two cabled nodes" test "$(members_count)" = 2
	for s in local peer; do
		wait_until 90 peers_ok "$s" || true
		check "$s Mac: doctor ic-peers is ok (the peer answers on its slot-0 address)" \
			test "$(icp_doctor_row_state "$RUNG_DIR/doctor-$s.json" ic-peers)" = ok
	done
}

assert_r2_attach() {
	kc create namespace "$NS" >/dev/null 2>&1 && NS_CREATED=1
	local s n p icip idx line
	for s in local peer; do
		ic_pod "ic-l-$s" "$(node_of "$s")" 1 "$LISTENER_CMD"
	done
	for s in local peer; do
		p="ic-l-$s" n="$(node_of "$s")" idx="$(side_var "$s" IDX)"
		if ! wait_until 180 pod_ready "$p"; then
			fail "pod $p never became Ready on $n"
			continue
		fi
		kc get pod -n "$NS" "$p" -o json >"$RUNG_DIR/$p.json" 2>&1
		check "$p: condition k3sm.io/InterconnectAttached is True" test "$(pod_attached "$p")" = True
		icip="$(pod_log_value "$p" ICIP=)"
		eval "${s}_ICIP=\$icip"
		check "$p: K3SM_INTERCONNECT_IP '$icip' is InterconnectSlotAddress($idx, 2..7)" slot_general "$idx" "$icip"
		check "$s Mac: $icip is a /32 alias on bridge0" alias_present "$s" "$icip" 0xffffffff
		priv "$s" lsof-5400 <<'EOF'
lsof -nP -iTCP:5400 -sTCP:LISTEN
EOF
		cp "$PAYLOAD_LOG" "$RUNG_DIR/$s-lsof-5400.txt"
		check "$s Mac: the listener's local address (lsof) is $icip:5400, not *:5400" \
			test "$(awk 'NR>1{print $9; exit}' "$RUNG_DIR/$s-lsof-5400.txt")" = "$icip:5400"
	done
	for s in local peer; do
		p="$(other "$s")"
		on "$s" "ping -c 2 -t 4 $(side_var "$p" ICIP)" >"$RUNG_DIR/$s-ping-peer.txt" 2>&1
		line="$(on "$s" "arp -n $(side_var "$p" ICIP)" 2>&1)"
		printf '%s\n' "$line" >"$RUNG_DIR/$s-arp-peer.txt"
		check "$s Mac: the ARP entry for the peer pod's address" icp_arp_verdict "$line" "$(side_var "$s" MACS)" "$(side_var "$p" MACS)"
	done
	[ "$R_FAIL" = 0 ] && HAVE="$HAVE attached"
	return 0
}

# measure_rtt <label> <dst> — RECORDED RTT, five pings, average.
measure_rtt() { on_local "ping -c 5 -q $2" 2>/dev/null | awk -F/ '/round-trip/{print $5; exit}'; }

assert_r3_cable_path() {
	local bytes=$((PAYLOAD_MB * 1048576)) dst="$peer_ICIP" s got r0l r0p r1l r1p tbd land v rtt_ic rtt_mesh
	for s in local peer; do
		on "$s" "route -n get $(side_var "$(other "$s")" ICIP)" >"$RUNG_DIR/$s-route.txt" 2>&1
		check "$s Mac: route -n get $(side_var "$(other "$s")" ICIP) names bridge0" test "$(icp_route_iface "$RUNG_DIR/$s-route.txt")" = bridge0
		counters "$s" before "$(side_var "$s" TB)" "$(side_var "$s" LAN)"
		record_link_context "$s"
	done
	r0l="$(retrans local)" r0p="$(retrans peer)"
	on_local "dd if=/dev/zero bs=1048576 count=$PAYLOAD_MB 2>/dev/null | nc -G 5 -w 15 $dst 5400" >"$RUNG_DIR/transfer.txt" 2>&1
	sleep 2
	r1l="$(retrans local)" r1p="$(retrans peer)"
	for s in local peer; do
		counters "$s" after "$(side_var "$s" TB)" "$(side_var "$s" LAN)"
		tbd="$(icp_total_delta "$RUNG_DIR/$s-before-$(side_var "$s" TB).txt" "$RUNG_DIR/$s-after-$(side_var "$s" TB).txt")" || tbd=0
		land="$(icp_total_delta "$RUNG_DIR/$s-before-$(side_var "$s" LAN).txt" "$RUNG_DIR/$s-after-$(side_var "$s" LAN).txt")" || land=999999999999
		check "$s Mac: counters ($(side_var "$s" TB) vs LAN $(side_var "$s" LAN))" icp_cable_path_verdict "$bytes" "$tbd" "$land" "$LAN_SLACK"
		line="$(on "$s" "arp -n $(side_var "$(other "$s")" ICIP)" 2>&1)"
		check "$s Mac: ARP for the peer slot address" icp_arp_verdict "$line" "$(side_var "$s" MACS)" "$(side_var "$(other "$s")" MACS)"
	done
	got="$(pod_log_value ic-l-peer RECV5400=)"
	check "the peer pod received the whole payload on its slot address ($got of $bytes bytes)" test "${got:-0}" = "$bytes"
	rec "tcp retransmits during the transfer: local +$((${r1l:-0} - ${r0l:-0})), peer +$((${r1p:-0} - ${r0p:-0}))"
	rtt_ic="$(measure_rtt slot "$dst")" rtt_mesh="$(measure_rtt mesh "$peer_MESH")"
	v="$(icp_ratio "${rtt_mesh:-0}" "${rtt_ic:-0}")"
	rec "RTT over the slot address ${rtt_ic:-none} ms vs the mesh address ${rtt_mesh:-none} ms (mesh/slot ratio $v); recorded, never the pass criterion"
}

# mesh_flow <label> <destination> <port> — a sender pod on the local node streams
# the payload to the destination; the local Mac's counters bracket it.
mesh_flow() {
	local label="$1" dst="$2" port="$3" bytes=$((PAYLOAD_MB * 1048576)) ut tbd land utd before got r0 p="ic-send-$1"
	on_local "route -n get $dst" >"$RUNG_DIR/route-$label.txt" 2>&1
	ut="$(icp_route_iface "$RUNG_DIR/route-$label.txt")"
	if [ "$label" = pod ]; then
		case "$ut" in utun*) pass "route -n get $dst (the peer pod IP) names $ut" ;; *) fail "route -n get $dst names '$ut', not a utun" ;; esac
	fi
	case "$ut" in utun*) ;; *) ut="$MESH_UTUN" ;; esac
	counters local "$label-before" "$ut" "$local_LAN" "$local_TB"
	before="$(pod_log_value ic-l-peer RECV5401=)"
	r0="$(retrans local)"
	ic_pod "$p" "$local_NODE" 0 "/bin/dd if=/dev/zero bs=1048576 count=$PAYLOAD_MB 2>/dev/null | /usr/bin/nc -G 5 -w 15 $dst $port; echo SENT=\$?"
	wait_until 300 pod_done "$p" || fail "sender pod $p did not finish within 300 s"
	sleep 2
	counters local "$label-after" "$ut" "$local_LAN" "$local_TB"
	rec "$label flow: tcp retransmits +$(($(retrans local || echo 0) - ${r0:-0})) on the local Mac; MTU $ut $(mtu_of local "$ut"), bridge0 $(mtu_of local bridge0), $local_TB $(mtu_of local "$local_TB")"
	utd="$(icp_total_delta "$RUNG_DIR/local-$label-before-$ut.txt" "$RUNG_DIR/local-$label-after-$ut.txt")" || utd=0
	land="$(icp_total_delta "$RUNG_DIR/local-$label-before-$local_LAN.txt" "$RUNG_DIR/local-$label-after-$local_LAN.txt")" || land=0
	tbd="$(icp_total_delta "$RUNG_DIR/local-$label-before-$local_TB.txt" "$RUNG_DIR/local-$label-after-$local_TB.txt")" || tbd=999999999999
	check "$label flow counters ($ut, LAN $local_LAN, cable $local_TB)" icp_mesh_path_verdict "$bytes" "$utd" "$land" "$tbd" "$LAN_SLACK"
	got="$(pod_log_value ic-l-peer RECV5401=)"
	check "$label flow: the peer pod's wildcard listener received the payload ($got bytes; before $before)" test "${got:-0}" = "$bytes"
	kc delete pod -n "$NS" "$p" --wait=false >/dev/null 2>&1
}

assert_r4_mesh_traffic() {
	local pip cip out rc=0 icd
	pip="$(pod_ip ic-l-peer)"
	MESH_UTUN="$(on_local "route -n get $peer_MESH" | awk '$1=="interface:"{print $2; exit}')"
	mesh_flow pod "$pip" 5401
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: ic-svc, namespace: $NS}
spec:
  selector: {app: ic-l-peer}
  ports: [{port: 5401, targetPort: 5401}]
EOF
	cip="$(kc get svc -n "$NS" ic-svc -o jsonpath='{.spec.clusterIP}')"
	mesh_flow clusterip "$cip" 5401
	out="$(on_local "nc -z -G 3 -w 3 $peer_ICIP 5401" 2>&1)" || rc=$?
	printf 'rc=%s %s\n' "$rc" "$out" >"$RUNG_DIR/wildcard-negative.txt"
	check "wildcard negative: the peer pod's *:5401 listener does not answer on its slot address $peer_ICIP" test "$rc" != 0
	# Source pin: an unbound dial from an attached pod to the peer's slot-0 address,
	# against a host listener there that reports the connection's source.
	on_peer "python3 -c $(printf '%q' "$IC_LISTEN_PY") $peer_SLOT0 5402 120" >"$RUNG_DIR/pin-listener.txt" 2>&1 &
	BG_PIDS="$BG_PIDS $!"
	sleep 2
	ic_pod ic-pin "$local_NODE" 1 "echo ICIP=\${K3SM_INTERCONNECT_IP:-}; sleep 3; /usr/bin/nc -z -G 5 -w 5 $peer_SLOT0 5402; echo RC=\$?"
	wait_until 120 pod_done ic-pin || fail "the source-pin dialer pod did not finish within 120 s"
	sleep 2
	icd="$(pod_log_value ic-pin ICIP=)"
	check "source pin: the peer saw the dial from the pod's K3SM_INTERCONNECT_IP '$icd'" \
		test "$(awk '$1=="ACCEPT"{print $3; exit}' "$RUNG_DIR/pin-listener.txt")" = "${icd:-none}"
	kc delete pod -n "$NS" ic-pin --wait=false >/dev/null 2>&1
}

# mlx_model <name> <interconnect|-> — apply the r5 model (- = single-Mac).
mlx_model() {
	local dist=""
	[ "$2" != - ] && dist="distributed: {ranks: 2, backend: ring, interconnect: $2}"
	kc apply -f - >/dev/null <<EOF
apiVersion: mlx.k3sm.io/v1alpha1
kind: MLXModel
metadata: {name: $1, namespace: $NS}
spec:
  model: $MLX_MODEL
  memory: $MLX_MEMORY
  $dist
EOF
}
model_ready() { grep -qx True <<<"$(kc get mlxmodel -n "$NS" "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"; }
# ring_on <path> — ic-ring is Ready with both rank pods on that path.
ring_on() { model_ready ic-ring && [ "$(rank_pods ic-ring | awk -v p="$1" '$4==p' | wc -l | tr -d ' ')" = 2 ]; }
model_cond() { kc get mlxmodel -n "$NS" "$1" -o jsonpath="{.status.conditions[?(@.type==\"$2\")].$3}" 2>/dev/null; }
rank_pods() { kc get pods -n "$NS" -o json 2>/dev/null | python3 -I -c "import json,sys
for p in json.load(sys.stdin)['items']:
    if any(o.get('kind')=='MLXModel' and o.get('name')=='$1' for o in p['metadata'].get('ownerReferences') or []):
        print(p['metadata']['name'], p['metadata']['uid'], p['spec'].get('nodeName',''), (p['metadata'].get('annotations') or {}).get('k3sm.io/mlx-interconnect',''))"; }
image_pull_failed() { grep -Eq 'ErrImagePull|ImagePullBackOff' <<<"$(kc get pods -n "$NS" -o jsonpath='{range .items[*]}{.status.containerStatuses[*].state.waiting.reason}{"\n"}{end}' 2>/dev/null)"; }
# tokens_per_s <model> <file> — one completion against the endpoint; prints
# "<tokens/s> <request+response bytes>" or nothing.
tokens_per_s() {
	local ep
	ep="$(kc get mlxmodel -n "$NS" "$1" -o jsonpath='{.status.endpoint}' 2>/dev/null)"
	[ -n "$ep" ] || return 1
	case "$ep" in http*) ;; *) ep="http://$ep" ;; esac
	# unpinned: a POST to the model's in-cluster endpoint; the response is a completion, never an artifact that runs
	curl -sS -m 300 -o "$2" -w '%{time_total} %{size_upload} %{size_download}\n' "$ep/v1/completions" \
		-H 'Content-Type: application/json' \
		-d '{"prompt":"Write a long story about two computers joined by a cable.","max_tokens":256}' >"$2.timing" 2>&1 || return 1
	python3 -I -c 'import json,sys
t,u,d=open(sys.argv[2]).read().split()[:3]
n=json.load(open(sys.argv[1])).get("usage",{}).get("completion_tokens",0)
print("%.2f %d" % (n/float(t), int(float(u))+int(float(d))))' "$2" "$2.timing"
}

assert_r5_ring() {
	local alloc s m out line http r0l r0p fig_net fig_single fig_tb tbd utd ip
	for s in local peer; do
		alloc="$(kc get node "$(node_of "$s")" -o jsonpath='{.status.allocatable.mlx\.k3sm\.io/gpu}' 2>/dev/null)"
		if [ "${alloc:-0}" -lt 1 ] 2>/dev/null || [ -z "$alloc" ]; then
			refuse_rung "$(prereq_what gpu): node $(node_of "$s") advertises '${alloc:-none}'" BI8
			return 2
		fi
	done
	# Control figures first (RECORDED): the same model over the network, and one Mac.
	mlx_model ic-ring network
	if ! wait_until "$MLX_READY_TIMEOUT" model_ready ic-ring; then
		if image_pull_failed; then
			refuse_rung "$(prereq_what mlximage): a rank pod cannot pull it" BI8
			return 2
		fi
		fail "MLXModel ic-ring (interconnect network) never became Ready within ${MLX_READY_TIMEOUT}s"
		return 1
	fi
	fig_net="$(tokens_per_s ic-ring "$RUNG_DIR/completion-network.json")" || fig_net=""
	mlx_model ic-single -
	if wait_until "$MLX_READY_TIMEOUT" model_ready ic-single; then
		fig_single="$(tokens_per_s ic-single "$RUNG_DIR/completion-single.json")" || fig_single=""
	fi
	kc delete mlxmodel -n "$NS" ic-single --wait=false >/dev/null 2>&1
	# The interconnect run.
	kc patch mlxmodel -n "$NS" ic-ring --type merge -p '{"spec":{"distributed":{"interconnect":"thunderbolt"}}}' >/dev/null
	sleep 5
	if ! wait_until "$MLX_READY_TIMEOUT" ring_on thunderbolt; then
		fail "MLXModel ic-ring did not become Ready with both ranks on the thunderbolt path"
		rank_pods ic-ring >"$RUNG_DIR/ranks.txt"
		return 1
	fi
	rank_pods ic-ring >"$RUNG_DIR/ranks.txt"
	kc get mlxmodel -n "$NS" ic-ring -o json >"$RUNG_DIR/mlxmodel.json" 2>&1
	check "both rank pods carry k3sm.io/mlx-interconnect thunderbolt" test "$(awk '$4=="thunderbolt"' "$RUNG_DIR/ranks.txt" | wc -l | tr -d ' ')" = 2
	check "ShardsPlaced names the thunderbolt path" has_text "$(model_cond ic-ring ShardsPlaced message)" thunderbolt
	check "LinksHealthy is True" test "$(model_cond ic-ring LinksHealthy status)" = True
	rec "MLXModelStatus has no interconnect field (the path rides ShardsPlaced and the rank annotation); status.interconnect reads '$(kc get mlxmodel -n "$NS" ic-ring -o jsonpath='{.status.interconnect}' 2>/dev/null)'"
	for s in local peer; do
		priv "$s" lsof-29500 <<'EOF'
lsof -nP -iTCP:29500
EOF
		cp "$PAYLOAD_LOG" "$RUNG_DIR/$s-lsof-29500.txt"
		m="$(icp_slot_addr "$(side_var "$s" IDX)" 1)"
		out="$(icp_slot_addr "$(side_var "$(other "$s")" IDX)" 1)"
		check "$s Mac: a rank socket on 29500 has local $m and the peer's slot-1 $out as remote" \
			grep -Eq "$m:[0-9]+->$out:[0-9]+|$m:29500->$out:|$out:[0-9]+->$m:29500" "$RUNG_DIR/$s-lsof-29500.txt"
	done
	ip="$(kc get endpoints -n "$NS" -o jsonpath='{range .items[*]}{.subsets[*].addresses[*].ip}{" "}{end}' 2>/dev/null)"
	printf '%s\n' "$ip" >"$RUNG_DIR/endpoints.txt"
	check "the ClusterIP endpoints are pod IPs, never an interconnect address ($ip)" pod_ips_only "$ip"
	kc get pods -n "$NS" -o jsonpath='{range .items[*]}{.spec.containers[*].readinessProbe.httpGet.host}{.spec.containers[*].livenessProbe.httpGet.host}{end}' >"$RUNG_DIR/probe-hosts.txt" 2>&1
	check "no probe names an interconnect host (probes stay on the pod IP)" file_lacks "$RUNG_DIR/probe-hosts.txt" 169.254
	counters local ring-before "$local_TB" "$MESH_UTUN"
	counters peer ring-before "$peer_TB" "$PEER_UTUN"
	r0l="$(retrans local)" r0p="$(retrans peer)"
	line="$(tokens_per_s ic-ring "$RUNG_DIR/completion-thunderbolt.json")" || line=""
	counters local ring-after "$local_TB" "$MESH_UTUN"
	counters peer ring-after "$peer_TB" "$PEER_UTUN"
	rec "tcp retransmits during the completion: local +$(($(retrans local || echo 0) - ${r0l:-0})), peer +$(($(retrans peer || echo 0) - ${r0p:-0}))"
	fig_tb="${line%% *}" http="${line##* }"
	if [ -z "$line" ]; then
		fail "rank 0 did not serve a completion through the endpoint"
	else
		tbd=$(($(icp_total_delta "$RUNG_DIR/local-ring-before-$local_TB.txt" "$RUNG_DIR/local-ring-after-$local_TB.txt" || echo 0) + $(icp_total_delta "$RUNG_DIR/peer-ring-before-$peer_TB.txt" "$RUNG_DIR/peer-ring-after-$peer_TB.txt" || echo 0)))
		utd=$(($(icp_total_delta "$RUNG_DIR/local-ring-before-$MESH_UTUN.txt" "$RUNG_DIR/local-ring-after-$MESH_UTUN.txt" || echo 0) + $(icp_total_delta "$RUNG_DIR/peer-ring-before-$PEER_UTUN.txt" "$RUNG_DIR/peer-ring-after-$PEER_UTUN.txt" || echo 0)))
		check "the ring rode the cable while the mesh carried only the HTTP exchange" icp_ring_path_verdict "$http" "$tbd" "$utd" "$LAN_SLACK"
	fi
	record_link_context local
	record_link_context peer
	rec "tokens/s: thunderbolt ${fig_tb:-none}, network ${fig_net:-none}, single Mac ${fig_single:-none} (model $MLX_MODEL); recorded, never gating"
	[ "$R_FAIL" = 0 ] && HAVE="$HAVE ring"
	return 0
}

# The r6 poller: one monotonic clock on the local Mac. Lines "<t> <kind> <value>"
# on change only: carrier of the local Thunderbolt member every 0.1 s; member
# states, LinksHealthy and the rank pod UID set every 0.5 s.
read -r -d '' POLLER_PY <<'PY' || true
import json, os, subprocess, sys, threading, time
iface, ns, ic, out, stop = sys.argv[1:6]
lock = threading.Lock()
last = {}
f = open(out, "a", buffering=1)
def emit(kind, value):
    with lock:
        if last.get(kind) != value:
            last[kind] = value
            f.write("%.3f %s %s\n" % (time.monotonic(), kind, value))
def carrier():
    while not os.path.exists(stop):
        o = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
        emit("carrier", "active" if "status: active" in o else "inactive")
        time.sleep(0.1)
def cluster():
    while not os.path.exists(stop):
        try:
            d = json.loads(subprocess.run(["kubectl", "--request-timeout=5s", "get", "interconnect", ic, "-o", "json"], capture_output=True, text=True).stdout)
            for m in (d.get("status") or {}).get("members") or []:
                emit("member:" + m.get("node", ""), m.get("state", ""))
            d = json.loads(subprocess.run(["kubectl", "--request-timeout=5s", "get", "mlxmodel", "-n", ns, "ic-ring", "-o", "json"], capture_output=True, text=True).stdout)
            for c in (d.get("status") or {}).get("conditions") or []:
                if c.get("type") == "LinksHealthy":
                    emit("links", c.get("status", ""))
            p = json.loads(subprocess.run(["kubectl", "--request-timeout=5s", "get", "pods", "-n", ns, "-o", "json"], capture_output=True, text=True).stdout)
            uids = sorted(x["metadata"]["uid"] for x in p["items"] if any(o.get("name") == "ic-ring" for o in x["metadata"].get("ownerReferences") or []))
            emit("gang", ",".join(uids) or "none")
        except Exception as e:
            emit("pollerr", type(e).__name__)
        time.sleep(0.5)
threading.Thread(target=carrier, daemon=True).start()
cluster()
PY

# t_after <line> <kind> <value> — the first timestamp after poll.log line <line>.
t_after() { tail -n +"$(($1 + 1))" "$RUNG_DIR/poll.log" | awk -v k="$2" -v v="$3" '$2==k && (v=="" || $3==v){print $1; exit}'; }
t_change_after() { tail -n +"$(($1 + 1))" "$RUNG_DIR/poll.log" | awk -v k="$2" '$2==k{print $1; exit}'; }
poll_lines() { wc -l <"$RUNG_DIR/poll.log" | tr -d ' '; }
prompt() { printf '\n>>> %s\n' "$*" >/dev/tty; }
# wait_poll <seconds> <line> <kind> [value] — wait for a poll event after a line.
wait_poll() {
	local deadline=$((SECONDS + $1)) t
	while [ "$SECONDS" -lt "$deadline" ]; do
		t="$(if [ -n "${4:-}" ]; then t_after "$2" "$3" "$4"; else t_change_after "$2" "$3"; fi)"
		[ -n "$t" ] && {
			echo "$t"
			return 0
		}
		sleep 0.2
	done
	return 1
}

# rerender_after <seconds> <line> — the earliest of LinksHealthy False and a new
# gang (rank pod UID set) after the line: the MLX re-render start.
rerender_after() {
	local deadline=$((SECONDS + $1)) tl tg
	while [ "$SECONDS" -lt "$deadline" ]; do
		tl="$(t_after "$2" links False)" tg="$(t_change_after "$2" gang)"
		if [ -n "$tl$tg" ]; then
			sleep 1
			tl="$(t_after "$2" links False)" tg="$(t_change_after "$2" gang)"
			printf '%s\n%s\n' "$tl" "$tg" | awk 'NF{if(m==""||$1<m)m=$1} END{print m}'
			return 0
		fi
		sleep 0.2
	done
	return 1
}

assert_r6_unplug() {
	if ! (: </dev/tty) 2>/dev/null; then
		refuse_rung "$(prereq_what operator)" BI10
		return 2
	fi
	local stopf="$RUNG_DIR/poll.stop" mark t0 t1 t1p t2 r0 r1 gap s d before after n uids1 restarted1 pingn=6000
	: >"$RUNG_DIR/poll.log"
	python3 -I -c "$POLLER_PY" "$local_TB" "$NS" "$IC_NAME" "$RUNG_DIR/poll.log" "$stopf" >"$RUNG_DIR/poller.err" 2>&1 &
	BG_PIDS="$BG_PIDS $!"
	# The probes run as root for the 0.2 s cadence; their output files are the driver's.
	# shellcheck disable=SC2024
	sudo -n ping -i 0.2 -c "$pingn" "$peer_MESH" >"$RUNG_DIR/ping-mesh.txt" 2>&1 &
	PING_PIDS="$PING_PIDS $!"
	# shellcheck disable=SC2024
	sudo -n ping -i 0.2 -c "$pingn" -S "$local_SLOT0" "$peer_SLOT0" >"$RUNG_DIR/ping-slot0.txt" 2>&1 &
	PING_PIDS="$PING_PIDS $!"
	scrape_metrics before
	sleep 3
	d="$(python3 -I -c 'import time; print("%.3f" % time.time())')"
	s="$(on_peer 'python3 -c "import time; print(\"%.3f\" % time.time())"')"
	rec "wall-clock skew peer minus local ~ $(awk -v a="$s" -v b="$d" 'BEGIN{printf "%.3f", a-b}') s (ssh latency included); T0..T2 are read on the local Mac's monotonic clock only"
	mark="$(poll_lines)"
	prompt "r6: PULL the Thunderbolt cable now (between the two Macs). Waiting up to 300 s for the carrier to drop..."
	if ! t0="$(wait_poll 300 "$mark" carrier inactive)"; then
		fail "the local Thunderbolt member's carrier never dropped within 300 s (the cable was not pulled)"
		touch "$stopf"
		return 1
	fi
	info "T0 carrier drop at $t0"
	t1="$(wait_poll 60 "$mark" "member:$local_NODE" down)" || t1=""
	t1p="$(wait_poll 5 "$mark" "member:$peer_NODE" down)" || t1p=""
	[ -n "$t1" ] || t1="$t1p"
	t2="$(rerender_after 90 "$mark")" || t2=""
	check "I10 budget" icp_i10_verdict "$t0" "$t1" "$t2"
	restarted1="$(kc get mlxmodel -n "$NS" ic-ring -o jsonpath='{.metadata.annotations.k3sm\.io/mlx-interconnect-restarted-at}' 2>/dev/null)"
	mark="$(poll_lines)"
	prompt "r6: REPLUG the cable now. Waiting up to 300 s for the carrier..."
	if ! r0="$(wait_poll 300 "$mark" carrier active)"; then
		fail "the carrier never returned within 300 s"
		touch "$stopf"
		return 1
	fi
	r1="$(wait_poll 240 "$mark" "member:$local_NODE" up)" || r1=""
	check "UpHold" icp_uphold_verdict "$r0" "$r1"
	scrape_metrics after
	for n in $local_NODE $peer_NODE; do
		before="$(icp_metric_sum "$RUNG_DIR/metrics-before.txt" k3sm_interconnect_member_transitions_total "node=\"$n\"")"
		after="$(icp_metric_sum "$RUNG_DIR/metrics-after.txt" k3sm_interconnect_member_transitions_total "node=\"$n\"")"
		check "node $n: exactly one transition per direction (k3sm_interconnect_member_transitions_total +$((after - before)), want +2)" test $((after - before)) = 2
	done
	# The second pull, inside the five-minute restart limit of the first.
	uids1="$(awk '$2=="gang"{v=$3} END{print v}' "$RUNG_DIR/poll.log")"
	mark="$(poll_lines)"
	prompt "r6: PULL the cable a SECOND time now (within 5 minutes of the first). Waiting up to 120 s..."
	if t0="$(wait_poll 120 "$mark" carrier inactive)"; then
		awk -v a="$t0" -v b="$t2" 'BEGIN{exit !(a-b < 300)}' || fail "the second pull came $(awk -v a="$t0" -v b="$t2" 'BEGIN{printf "%.0f", a-b}') s after the first restart, outside the 5-minute window"
		sleep 40
		check "no second gang restart inside 5 minutes (rank pod UIDs unchanged)" test "$(awk '$2=="gang"{v=$3} END{print v}' "$RUNG_DIR/poll.log")" = "$uids1"
		check "the restart marker is unchanged" test "$(kc get mlxmodel -n "$NS" ic-ring -o jsonpath='{.metadata.annotations.k3sm\.io/mlx-interconnect-restarted-at}' 2>/dev/null)" = "$restarted1"
		mark="$(poll_lines)"
		prompt "r6: REPLUG the cable (last time). Waiting up to 300 s..."
		wait_poll 300 "$mark" carrier active >/dev/null || fail "the carrier never returned after the second pull"
		wait_poll 240 "$mark" "member:$local_NODE" up >/dev/null || fail "the member never came back up after the second replug"
	else
		fail "the second pull did not happen within 120 s"
	fi
	touch "$stopf"
	for n in $PING_PIDS; do sudo -n kill "$n" 2>/dev/null; done
	PING_PIDS=""
	sleep 1
	gap="$(icp_ping_max_gap "$RUNG_DIR/ping-mesh.txt")"
	check "the mesh probe lost at most one reply in a row across both pulls (max gap $gap)" test "$gap" -le 1
	rec "slot-0 probe max gap $(icp_ping_max_gap "$RUNG_DIR/ping-slot0.txt") replies (expected while unplugged)"
}

# forge_value <original JSON> <variant> — the forged desired annotation.
forge_value() {
	python3 -I -c 'import json,sys
d=json.loads(sys.argv[1] or "{}")
if sys.argv[2]=="extra":
    d["address"]="169.254.0.249"; d["slot"]=9
elif sys.argv[2]=="name":
    d["interconnect"]="evil-cable"
else:
    d["schema"]=99
print(json.dumps(d, separators=(",",":")))' "$1" "$2"
}
# node_annotate <side> <value|-> — the worker's OWN credential (the installed node
# kubeconfig, read by root on that Mac; never copied) writes its desired annotation.
node_annotate() {
	priv "$1" node-annotate BIN="$K3SM_BIN" KC="$NODE_KUBECONFIG" NODE="$(node_of "$1")" VALUE="$2" <<'EOF'
[ -s "$KC" ] || { echo "NO-NODE-KUBECONFIG"; exit 3; }
if [ "$VALUE" = - ]; then
  "$BIN" kubectl --kubeconfig "$KC" annotate node "$NODE" k3sm.io/interconnect-desired- 2>&1
else
  "$BIN" kubectl --kubeconfig "$KC" annotate node "$NODE" --overwrite "k3sm.io/interconnect-desired=$VALUE" 2>&1
fi
echo "EXIT=$?"
EOF
}

# policy_watch <side> <seconds> <tag> — sample bridge0 every 10 s for the window and
# apply the alias policy to every sample (a transient alias is caught too).
policy_watch() {
	local side="$1" end=$((SECONDS + $2)) i=0 bad=0 idx
	idx="$(side_var "$side" IDX)"
	while [ "$SECONDS" -lt "$end" ]; do
		i=$((i + 1))
		on "$side" "ifconfig bridge0" >"$RUNG_DIR/$3-sample-$i.txt" 2>&1
		icp_alias_policy "$RUNG_DIR/$3-sample-$i.txt" "$idx" >"$RUNG_DIR/$3-sample-$i.policy" || bad=1
		desired_of "$(node_of "$side")" >"$RUNG_DIR/$3-sample-$i.desired"
		if grep -qx "OK $(icp_slot_addr "$idx" 0) slot 0 netmask 0xffffff00" "$RUNG_DIR/$3-sample-$i.policy"; then
			echo held >"$RUNG_DIR/$3-sample-$i.slot0"
		else
			echo absent >"$RUNG_DIR/$3-sample-$i.slot0"
		fi
		sleep 10
	done
	if [ "$bad" = 0 ]; then
		pass "$3: every one of $i bridge0 samples over $2 s held only in-policy addresses for index $idx"
	else
		fail "$3: an out-of-policy address appeared ($(grep -h VIOLATION "$RUNG_DIR/$3"-sample-*.policy | sort -u | tr '\n' ';'))"
	fi
}

assert_r7_desired_forge() {
	local w side orig v out idx members0
	w="$WORKER_NODE"
	side="local"
	[ "$w" = "$peer_NODE" ] && side=peer
	priv "$side" nodecred KC="$NODE_KUBECONFIG" <<'EOF'
[ -s "$KC" ] && echo PRESENT || echo ABSENT
EOF
	if ! grep -q PRESENT "$PAYLOAD_LOG"; then
		refuse_rung "$(prereq_what nodecred): $NODE_KUBECONFIG on node $w" BI6
		return 2
	fi
	idx="$(side_var "$side" IDX)"
	orig="$(desired_of "$w")"
	printf '%s\n' "$orig" >"$RUNG_DIR/desired-original.json"
	FORGED_SIDE="$side" FORGED_ORIG="$orig"
	snap "$side" before
	members0="$(icp_bridge_members "$RUNG_DIR/$side-before-bridge0.txt")"
	scrape_metrics before
	# What the node's DesiredHandler does with each value (pkg/interconnect/
	# desired.go Reconcile over apis ParseInterconnectDesired): extra fields are
	# ignored and a foreign interconnect name is still a valid object name, so both
	# parse and the handler ENSURES slot 0 (held); schema 99 fails the schema read,
	# is treated as absent, and the handler REMOVES slot 0 (the safe direction).
	# The server's resolver rewrites the value on its next reconcile, so the
	# forged value may be live only briefly; the samples record which value each
	# one saw.
	local fv held total seen rm0 rm1
	for v in extra name schema; do
		fv="$(forge_value "$orig" "$v")"
		scrape_metrics "pre-$v"
		node_annotate "$side" "$fv"
		cp "$PAYLOAD_LOG" "$RUNG_DIR/forge-$v.txt"
		if ! grep -q '^EXIT=0' "$PAYLOAD_LOG"; then
			refuse_rung "the apiserver did not accept node $w's patch of its own desired annotation ($(tail -2 "$PAYLOAD_LOG" | tr '\n' ' ')); the I6 forge precondition does not hold" BI6
			return 2
		fi
		pass "forge '$v': the apiserver accepted node $w's own-credential patch (precondition)"
		policy_watch "$side" $((2 * DESIRED_INTERVAL)) "forge-$v"
		scrape_metrics "post-$v"
		total="$(cat "$RUNG_DIR/forge-$v"-sample-*.slot0 | wc -l | tr -d ' ')"
		held="$(cat "$RUNG_DIR/forge-$v"-sample-*.slot0 | grep -c '^held$')"
		seen="$(cat "$RUNG_DIR/forge-$v"-sample-*.desired | grep -cxF -- "$fv")"
		rm0="$(icp_metric_sum "$RUNG_DIR/metrics-pre-$v.txt" k3sm_interconnect_netd_verb_results_total 'result="ok",verb="RemoveInterconnectAlias"')"
		rm1="$(icp_metric_sum "$RUNG_DIR/metrics-post-$v.txt" k3sm_interconnect_netd_verb_results_total 'result="ok",verb="RemoveInterconnectAlias"')"
		rec "forge '$v': the forged value was live in $seen of $total samples; slot 0 held in $held; RemoveInterconnectAlias ok +$((rm1 - rm0))"
		case "$v" in
		extra | name)
			check "forge '$v' parses, so the handler holds slot 0 (held in $held of $total samples)" test "$held" = "$total"
			;;
		schema)
			if [ "$seen" = 0 ] && [ "$rm1" = "$rm0" ]; then
				rec "forge 'schema': the resolver restored the annotation before any sample or handler saw schema 99; the handler's removal is not observable in this run"
			else
				check "forge 'schema' reads as absent, so the handler removed slot 0 (RemoveInterconnectAlias ok +$((rm1 - rm0)), slot 0 absent in $((total - held)) samples)" \
					test $((rm1 - rm0)) -gt 0 -a "$held" -lt "$total"
			fi
			;;
		esac
	done
	snap "$side" after
	check "bridge0 membership unchanged ($members0)" test "$(icp_bridge_members "$RUNG_DIR/$side-after-bridge0.txt")" = "$members0"
	check "nothing in 169.254.255.0/24 and no route beyond the connected /24" \
		icp_route_residue "$RUNG_DIR/$side-before-netstat.txt" "$RUNG_DIR/$side-after-netstat.txt" "169.254.0.0/24" "$(for s in 0 1 2 3 4 5 6 7; do icp_slot_addr "$idx" "$s"; done | tr '\n' ' ')"
	scrape_metrics after
	check "netd saw only the two node verbs (no verb carries an address)" icp_netd_verbs_closed "$RUNG_DIR/metrics-after.txt"
	rec "EnsureInterconnectAlias ok +$(($(icp_metric_sum "$RUNG_DIR/metrics-after.txt" k3sm_interconnect_netd_verb_results_total 'result="ok",verb="EnsureInterconnectAlias"') - $(icp_metric_sum "$RUNG_DIR/metrics-before.txt" k3sm_interconnect_netd_verb_results_total 'result="ok",verb="EnsureInterconnectAlias"'))), RemoveInterconnectAlias ok +$(($(icp_metric_sum "$RUNG_DIR/metrics-after.txt" k3sm_interconnect_netd_verb_results_total 'result="ok",verb="RemoveInterconnectAlias"') - $(icp_metric_sum "$RUNG_DIR/metrics-before.txt" k3sm_interconnect_netd_verb_results_total 'result="ok",verb="RemoveInterconnectAlias"'))) over the forge windows"
	# Positive control: the in-policy value, written the same way, yields slot 0.
	node_annotate "$side" "${orig:--}"
	cp "$PAYLOAD_LOG" "$RUNG_DIR/restore.txt"
	FORGED_SIDE=""
	out="$(icp_slot_addr "$idx" 0)"
	if wait_until $((2 * DESIRED_INTERVAL)) alias_present "$side" "$out" 0xffffff00; then
		pass "positive control: the in-policy desired value restores the slot-0 alias $out/24"
	else
		fail "positive control: slot-0 alias $out/24 absent $((2 * DESIRED_INTERVAL)) s after the in-policy rewrite"
	fi
}

# host_clean <side> <tag> — the r8/r9 host assertions on one Mac.
host_clean() {
	local s="$1" t="$2" idx own
	idx="$(side_var "$s" IDX)"
	own="$(for x in 0 1 2 3 4 5 6 7; do icp_slot_addr "$idx" "$x"; done | tr '\n' ' ')"
	snap "$s" "$t"
	check "$s Mac: no inet in 169.254.0.0/24 or 169.254.255.0/24 on bridge0" icp_halves_empty "$RUNG_DIR/$s-$t-bridge0.txt"
	check "$s Mac: no reserved-half route beyond the baseline and no cloned host route for a peer slot" \
		icp_route_residue "$BASE_DIR/$s-base-netstat.txt" "$RUNG_DIR/$s-$t-netstat.txt" "" "$own"
	check "$s Mac: bridge0 membership is the baseline's" \
		test "$(icp_bridge_members "$RUNG_DIR/$s-$t-bridge0.txt")" = "$(icp_bridge_members "$BASE_DIR/$s-base-bridge0.txt")"
	check "$s Mac: no permanent ARP entry in the reserved halves" icp_arp_permanent "$RUNG_DIR/$s-$t-arp.txt"
	read_ledger "$s"
	check "$s Mac: the netd interconnect ledger is empty" icp_ledger_empty "$RUNG_DIR/ledger-$s.json"
	icp_route_residue "$BASE_DIR/$s-base-netstat.txt" "$RUNG_DIR/$s-$t-netstat.txt" "" "$own" | grep '^RECORDED' | while read -r line; do
		rec "$s Mac (macOS $(side_var "$s" OS)): $line"
	done
}

assert_r8_killswitch() {
	local s out mp0 mp1 p
	for s in local peer; do snap "$s" pre; done
	kc get meshpeers.net.k3sm.io -o jsonpath='{range .items[*]}{.metadata.name} {.spec}{"\n"}{end}' >"$RUNG_DIR/meshpeers-pre.txt" 2>&1
	out="$(on_local "$K3SM_BIN interconnect disable" 2>&1)"
	printf '%s\n' "$out" >"$RUNG_DIR/disable.txt"
	info "$out"
	for s in local peer; do
		wait_until 180 halves_empty_on "$s" || true
		host_clean "$s" post
		check "$s Mac: lo0 pod aliases unchanged" cmp -s "$RUNG_DIR/$s-pre-lo0.txt" "$RUNG_DIR/$s-post-lo0.txt"
		check "$s Mac: desired annotation gone from node $(node_of "$s")" test -z "$(desired_of "$(node_of "$s")")"
	done
	ARMED_BY_RUN=0
	kc get meshpeers.net.k3sm.io -o jsonpath='{range .items[*]}{.metadata.name} {.spec}{"\n"}{end}' >"$RUNG_DIR/meshpeers-post.txt" 2>&1
	check "MeshPeer specs (wireguard peers and AllowedIPs) unchanged" cmp -s "$RUNG_DIR/meshpeers-pre.txt" "$RUNG_DIR/meshpeers-post.txt"
	mp0="$(on_local "ping -c 3 -t 6 $peer_MESH" | awk '/packets received/{print $4}')"
	check "the mesh ping still answers ($mp0/3)" test "${mp0:-0}" -gt 0
	check "status.members is empty" test "$(members_count)" = 0
	for p in ic-l-local ic-l-peer; do
		mp1="$(pod_attached "$p")"
		check "pod $p: k3sm.io/InterconnectAttached is False ('$mp1')" test "$mp1" = False
	done
	scrape_metrics post
	check "k3sm_interconnect_attached_pods is 0" test "$(icp_metric_sum "$RUNG_DIR/metrics-post.txt" k3sm_interconnect_attached_pods)" = 0
	if kc get mlxmodel -n "$NS" ic-ring >/dev/null 2>&1; then
		if wait_until 180 ring_on network; then
			pass "the ring fell back to the mesh (both ranks on the network path)"
		else
			fail "the ring did not fall back to the mesh within 180 s"
		fi
	else
		rec "no ring model to fall back (r5 did not leave one); the ring half of the kill switch is not exercised"
	fi
	[ "$R_FAIL" = 0 ] && HAVE="$HAVE disarmed"
	return 0
}

# reinstall <side> <local binary> <tag> — copy a k3sm binary to a Mac and run its
# own install there as a script file under sudo; wait for both nodes Ready.
reinstall() {
	local side="$1" bin="$2" dst="$IC_REMOTE_DIR/k3sm-$3"
	if [ "$side" = local ]; then
		mkdir -p "$IC_REMOTE_DIR" && cp "$bin" "$dst"
	else
		scp -q -o BatchMode=yes "$bin" "$PEER_SSH:$dst" || return 1
	fi
	priv "$side" "install-$3" BIN="$dst" ARGS="$REINSTALL_ARGS" <<'EOF'
chmod 0755 "$BIN"
# shellcheck disable=SC2086
"$BIN" install $ARGS
rc=$?
echo "INSTALL-EXIT=$rc"
/usr/local/bin/k3sm version 2>&1 | head -3
exit "$rc"
EOF
	local rc=$?
	cp "$PAYLOAD_LOG" "$RUNG_DIR/install-$3-$side.txt"
	wait_until 300 bash -c "[ \"\$(kubectl --request-timeout=10s get nodes --no-headers 2>/dev/null | awk '\$2==\"Ready\"' | wc -l | tr -d ' ')\" -ge 2 ]" || return 1
	return "$rc"
}

assert_r9_downgrade() {
	local prev="${K3SM_M17_PREVIOUS_ARTIFACT:-}" first second s v
	if [ -z "$prev" ] || [ ! -f "$prev" ] || [ -z "${K3SM_ARTIFACT:-}" ] || [ ! -f "${K3SM_ARTIFACT:-}" ]; then
		refuse_rung "$(prereq_what prevbin)" BI10
		return 2
	fi
	first=peer second=local
	[ "$WORKER_NODE" = "$local_NODE" ] && first=local second=peer
	rec "order: interconnect disabled in r8; previous binary on the worker ($(node_of "$first")) then the server ($(node_of "$second")); each install restarts io.k3sm.netd itself"
	reinstall "$first" "$prev" prev || fail "the previous binary did not install cleanly on the $first Mac, or the nodes did not return Ready"
	netd_hello "$first"
	v="$(icp_helper_verdict "$RUNG_DIR/netd-hello-$first.json")"
	case "$v" in
	HelperTooOld) pass "mixed leg: the downgraded helper answers a minor-2 Hello as HelperTooOld, not an error" ;;
	minor2) rec "mixed leg: the previous helper already speaks minor 2, so HelperTooOld is not exercised by this binary pair" ;;
	*) fail "mixed leg: the downgraded helper's reply is an error, not HelperTooOld ($(head -c 200 "$RUNG_DIR/netd-hello-$first.json"))" ;;
	esac
	reinstall "$second" "$prev" prev || fail "the previous binary did not install cleanly on the $second Mac, or the nodes did not return Ready"
	for s in local peer; do
		host_clean "$s" downgraded
		if [ "$s" = local ]; then cp "$K3SM_ARTIFACT" "$IC_REMOTE_DIR/k3sm-current"; else scp -q -o BatchMode=yes "$K3SM_ARTIFACT" "$PEER_SSH:$IC_REMOTE_DIR/k3sm-current"; fi
		doctor_json "$s" "$IC_REMOTE_DIR/k3sm-current"
		check "$s Mac: doctor ic-stray is clean" test "$(icp_doctor_row_state "$RUNG_DIR/doctor-$s.json" ic-stray)" = ok
		check "$s Mac: doctor ic-residue is clean" test "$(icp_doctor_row_state "$RUNG_DIR/doctor-$s.json" ic-residue)" = ok
		check "$s Mac: no reboot happened (kern.boottime unchanged; a reboot is never the cleanup)" \
			test "$(on "$s" 'sysctl -n kern.boottime' 2>/dev/null)" = "$(side_var "$s" BOOT)"
	done
	# Leave the lab host on the artifact under test, worker first.
	reinstall "$first" "$K3SM_ARTIFACT" current || fail "the artifact under test did not reinstall on the $first Mac (the lab hosts are left downgraded: fix by hand)"
	reinstall "$second" "$K3SM_ARTIFACT" current || fail "the artifact under test did not reinstall on the $second Mac (the lab hosts are left downgraded: fix by hand)"
}

# ── --plan ──────────────────────────────────────────────────────────────────────
print_plan() {
	local id summary prereqs fn ev bi tmp rc
	echo "==> k3sm $ROW: the two-Mac interconnect ladder (PLAN ONLY: nothing is contacted)"
	echo "id | summary | prerequisites | assertion | evidence | owning BI"
	while IFS='|' read -r id summary prereqs fn ev bi; do
		[ -n "$id" ] && echo "$id | $summary | $prereqs | $fn | EVIDENCE_DIR/$ev | $bi"
	done <<<"$RUNG_TABLE"
	echo "prerequisites (closed set): static [$PREREQ_STATIC] probed before either Mac changes; rung [$PREREQ_RUNG]; runtime [$PREREQ_RUNTIME]"
	echo "exit: 0 PASS (every rung PASS) | 1 FAIL | 2 REFUSED(<rung>): <what> (BI<n>) | 3 $PENDING_TEXT"
	tmp="$(mktemp -t m17-rungs.XXXXXX)"
	printf '%s\n' "$RUNG_TABLE" >"$tmp"
	rc=0
	icp_validate_rungs "$tmp" "$REQUIRED_IDS" "$PREREQ_SET" || rc=1
	rm -f "$tmp"
	if [ "$rc" = 0 ]; then
		echo "plan: $(printf '%s\n' "$RUNG_TABLE" | grep -c .) rungs, every assertion defined, every prerequisite in the closed set"
	else
		echo "plan: INVALID (above)"
	fi
	return "$rc"
}

# ── --self-test ─────────────────────────────────────────────────────────────────
ST_MISS=0
st() { # st <name> <want 0|1> <command...>
	local name="$1" want="$2" rc=0 out
	shift 2
	out="$("$@" 2>&1)" || rc=$?
	if { [ "$want" = 0 ] && [ "$rc" = 0 ]; } || { [ "$want" = 1 ] && [ "$rc" != 0 ]; }; then
		echo "ok    $name"
	else
		echo "MISS  $name (exit $rc, want $([ "$want" = 0 ] && echo 0 || echo non-zero)): $(printf '%s' "$out" | head -c 300)"
		ST_MISS=$((ST_MISS + 1))
	fi
}
st_out() { # st_out <name> <text> <command...> — the output names the text
	local name="$1" text="$2" out
	shift 2
	out="$("$@" 2>&1)"
	if grep -qF -- "$text" <<<"$out"; then echo "ok    $name"; else
		echo "MISS  $name: output lacks '$text': $(printf '%s' "$out" | head -c 300)"
		ST_MISS=$((ST_MISS + 1))
	fi
}
st_eq() { # st_eq <name> <got> <want>
	if [ "$2" = "$3" ]; then echo "ok    $1"; else
		echo "MISS  $1: got '$2', want '$3'"
		ST_MISS=$((ST_MISS + 1))
	fi
}
# gate_run <expected exit> <grep text|-> <env...> -- <args...>
gate_run() {
	local want="$1" text="$2" rc=0 out
	shift 2
	local envs=()
	while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
		envs+=("$1")
		shift
	done
	shift
	out="$(env -u K3SM_LAB -u PEER_SSH -u EVIDENCE_DIR -u K3SM_LAB_PRINT_MANIFESTS ${envs[@]+"${envs[@]}"} bash "$SELF" "$@" 2>&1)" || rc=$?
	[ "$rc" = "$want" ] || {
		echo "exit $rc, want $want: $(printf '%s' "$out" | tail -3)"
		return 1
	}
	[ "$text" = - ] || grep -qF -- "$text" <<<"$out" || {
		echo "output lacks '$text'"
		return 1
	}
}

# runlog_missing_refuses <dir> — a copy of this ladder whose lib/ lacks runlog.sh
# (the other sourced files laid out as in the tree), started as a rig run, must
# print only the preflight refusal and exit 2.
runlog_missing_refuses() {
	local d="$1" rc=0 out want
	mkdir -p "$d/lab/lib" "$d/spike/m17-interconnect" || return 1
	cp "$SELF" "$d/lab/m17-interconnect.sh" || return 1
	cp "$HERE/lib/m17-interconnect-predicates.sh" "$HERE/lib/tolerations.sh" "$d/lab/lib/" || return 1
	cp "$HERE/../spike/m17-interconnect/lib.sh" "$d/spike/m17-interconnect/" || return 1
	want="preflight: run-log library missing or unreadable: $d/lab/lib/runlog.sh"
	out="$(env -u K3SM_LAB_PRINT_MANIFESTS K3SM_LAB=1 PEER_SSH=self-test.invalid EVIDENCE_DIR="$d/ev" bash "$d/lab/m17-interconnect.sh" 2>&1)" || rc=$?
	[ "$rc" = 2 ] || {
		echo "exit $rc, want 2: $(printf '%s' "$out" | tail -3)"
		return 1
	}
	grep -qxF -- "$want" <<<"$out" || {
		echo "output lacks '$want': $(printf '%s' "$out" | tail -3)"
		return 1
	}
	[ "$(printf '%s\n' "$out" | grep -c .)" = 1 ] || {
		echo "output beyond the refusal (a rung or preflight ran): $(printf '%s' "$out" | head -3)"
		return 1
	}
	[ ! -e "$d/ev" ] || {
		echo "the evidence directory was created"
		return 1
	}
}

# st_driver_run <rung> <profile> — the body st_driver runs in a subshell: the
# stubs below replace the host and cluster helpers there only.
st_driver_run() {
	local rung="$1" prof="$2"
	D="$FIXTURES/driver/$prof" F="$FIXTURES"
	RUNG_DIR="$(mktemp -d -t m17-driver.XXXXXX)" RUNG="$rung" R_PASS=0 R_FAIL=0
	PAYLOAD_MB=128 LAN_SLACK=8388608 NS=stub
	local_TB=en2 peer_TB=en2 local_LAN=en0 peer_LAN=en0 local_NODE=node-a peer_NODE=node-b
	local_MACS="36:a1:5c:00:00:01" peer_MACS="36:a1:5c:00:00:02" local_ICIP=169.254.0.11 peer_ICIP=169.254.0.19
	peer_MESH=100.64.1.1 peer_SLOT0=169.254.0.9 MESH_UTUN=utun3 BG_PIDS=""
	sleep() { :; }
	wait_until() { shift; "$@"; }
	retrans() { echo 10; }
	mtu_of() { echo 1500; }
	measure_rtt() { echo 0.7; }
	ic_pod() { :; }
	# The source-pin dialer is done only once the peer listener has logged the dial:
	# r4 backgrounds that listener (into BG_PIDS) and reads its output after
	# pod_done, so waiting on the job makes the read ordered, not timed (sleep is
	# a no-op here). The job only prints, so the wait is bounded by its exit.
	pod_done() {
		local p
		[ "$1" = ic-pin ] || return 0
		for p in $BG_PIDS; do wait "$p"; done
	}
	pod_ip() { echo 10.42.1.7; }
	kc() { case "$*" in *clusterIP*) echo 10.43.0.10 ;; esac; }
	pod_log_value() { case "$2" in RECV*) echo $((PAYLOAD_MB * 1048576)) ;; ICIP=) echo 169.254.0.12 ;; esac; }
	counters() { local side="$1" tag="$2" i; shift 2; for i in "$@"; do cp "$D/netstat-I-$i-${tag##*-}.txt" "$RUNG_DIR/$side-$tag-$i.txt"; done; }
	on() {
		case "$2" in
		"route -n get 10.42."* | "route -n get 100.64."*) cat "$F/route-get-utun.txt" ;;
		"route -n get "*) cat "$F/route-get-bridge0.txt" ;;
		"arp -n "*) if [ "$1" = local ]; then echo "? (x) at 36:a1:5c:0:0:2 on bridge0 ifscope [bridge]"; else echo "? (x) at 36:a1:5c:0:0:1 on bridge0 ifscope [bridge]"; fi ;;
		"nc -z "*) return 1 ;;
		*) : ;;
		esac
	}
	on_local() { on local "$1"; }
	on_peer() { case "$1" in python3*) echo "LISTEN"; echo "ACCEPT 169.254.0.9 169.254.0.12" ;; *) on peer "$1" ;; esac; }
	if [ "$rung" = r3 ]; then assert_r3_cable_path; else assert_r4_mesh_traffic; fi
	wait
	rm -rf "$RUNG_DIR"
	echo "DRIVER passes=$R_PASS fails=$R_FAIL"
}

# st_driver <r3|r4> <profile> <want 0|1> — run the real r3 or r4 assertion with the
# host and cluster helpers stubbed over fixture outputs (driver/<profile>/), so a
# swapped argument between the rung glue and its predicates reds without a rig.
# The stubs live only in the subshell.
st_driver() {
	local rung="$1" prof="$2" want="$3" out rc=0
	out="$(st_driver_run "$rung" "$prof")" || rc=$?
	if { [ "$want" = 0 ] && [[ "$out" == *"DRIVER passes=7 fails=0"* ]]; } || { [ "$want" = 1 ] && [[ "$out" == *"DRIVER passes="* ]] && [[ "$out" != *" fails=0"* ]]; }; then
		echo "ok    rung driver $rung over $prof (want $([ "$want" = 0 ] && echo green || echo red))"
	else
		echo "MISS  rung driver $rung over $prof: $(printf '%s' "$out" | grep -E '^(FAIL|DRIVER)' | head -5 | tr '\n' ';')"
		ST_MISS=$((ST_MISS + 1))
	fi
}

self_test_body() {
	local F="$FIXTURES" tmp r
	if [ "${K3SM_M17_SELFTEST_HANG:-}" = 1 ]; then
		# The watchdog's own red fixture: a check that never returns.
		echo "==> $ROW self-test: a deliberately hanging check (watchdog proof)"
		sleep 30 >/dev/null 2>&1
		return 0
	fi
	tmp="$(mktemp -d -t m17-selftest.XXXXXX)"
	echo "==> $ROW self-test (fixtures: hack/lab/testdata/m17-interconnect)"
	st "the script parses" 0 bash -n "$SELF"
	st "--plan exits 0" 0 gate_run 0 "plan: 10 rungs" -- --plan
	for r in $REQUIRED_IDS; do st "--plan lists $r" 0 gate_run 0 "$r |" -- --plan; done
	st "an unknown argument exits 2" 0 gate_run 2 - -- --bogus
	st "--verify-twice with one dir exits 2" 0 gate_run 2 - -- --verify-twice "$F/run-a"
	st "K3SM_LAB unset exits 3 with the pending line" 0 gate_run 3 "$PENDING_TEXT" --
	st "the watchdog fires on a hung check and maps to FAIL (exit 1)" 0 gate_run 1 "watchdog fired" K3SM_M17_SELFTEST_WATCHDOG=2 K3SM_M17_SELFTEST_HANG=1 -- --self-test
	st "K3SM_LAB=1 without PEER_SSH/EVIDENCE_DIR exits 2 REFUSED" 0 gate_run 2 "REFUSED(preflight)" K3SM_LAB=1 --
	st "K3SM_LAB=1 with a relative EVIDENCE_DIR exits 2" 0 gate_run 2 "REFUSED(preflight)" K3SM_LAB=1 PEER_SSH=x EVIDENCE_DIR=rel --

	st_eq "node index 10.42.3.0/24 in 10.42.0.0/16" "$(icp_node_index 10.42.0.0/16 10.42.3.0/24)" 3
	st "node index outside the aggregate fails" 1 icp_node_index 10.42.0.0/16 10.43.0.0/24
	st "node index of a /25 fails" 1 icp_node_index 10.42.0.0/16 10.42.3.0/25
	st_eq "slot address (3, 0)" "$(icp_slot_addr 3 0)" 169.254.0.25
	st_eq "slot address (30, 7)" "$(icp_slot_addr 30 7)" 169.254.0.248
	st "slot address index 31 fails" 1 icp_slot_addr 31 0
	st "slot address slot 8 fails" 1 icp_slot_addr 0 8

	st "alias policy: armed bridge0 for index 3" 0 icp_alias_policy "$F/ifconfig-bridge0-armed.txt" 3
	st "alias policy red: a forged address" 1 icp_alias_policy "$F/ifconfig-bridge0-forged-addr.txt" 3
	st "alias policy red: slot 0 as a /32" 1 icp_alias_policy "$F/ifconfig-bridge0-slot0-mask.txt" 3
	st "alias policy red: 169.254.255.0/24" 1 icp_alias_policy "$F/ifconfig-bridge0-high-half.txt" 3
	st "alias policy red: the wrong node index" 1 icp_alias_policy "$F/ifconfig-bridge0-armed.txt" 4
	st "halves empty: disarmed bridge0" 0 icp_halves_empty "$F/ifconfig-bridge0-disarmed.txt"
	st "halves empty red: armed bridge0" 1 icp_halves_empty "$F/ifconfig-bridge0-armed.txt"
	st_eq "bridge members" "$(icp_bridge_members "$F/ifconfig-bridge0-armed.txt")" "en1 en2"

	st_eq "Thunderbolt member byte delta" "$(icp_total_delta "$F/netstat-I-en2-before.txt" "$F/netstat-I-en2-after.txt")" 142000000
	st_eq "utun byte delta (no MAC column)" "$(icp_total_delta "$F/netstat-I-utun3-before.txt" "$F/netstat-I-utun3-after.txt")" 137000000
	st "counter delta red: a counter went backwards" 1 icp_counter_delta 10 5
	st "cable path: cable carried it, LAN flat" 0 icp_cable_path_verdict 134217728 142000000 100000 8388608
	st "cable path red: the cable moved less than the payload" 1 icp_cable_path_verdict 134217728 1000000 100000 8388608
	st "cable path red: the LAN moved the payload" 1 icp_cable_path_verdict 134217728 142000000 140000000 8388608
	st "mesh path: utun and LAN, cable flat" 0 icp_mesh_path_verdict 134217728 137000000 140000000 20000 8388608
	st "mesh path red: the cable moved" 1 icp_mesh_path_verdict 134217728 137000000 140000000 140000000 8388608
	st "mesh path red: the tunnel did not" 1 icp_mesh_path_verdict 134217728 1000 140000000 20000 8388608
	st "ring path: the cable beyond the HTTP" 0 icp_ring_path_verdict 4000 90000000 6000 8388608
	st "ring path red: the ring rode the mesh" 1 icp_ring_path_verdict 4000 90000000 90000000 8388608
	st "ring path red: nothing crossed the cable" 1 icp_ring_path_verdict 4000 3000 6000 8388608
	st_eq "route iface: bridge0" "$(icp_route_iface "$F/route-get-bridge0.txt")" bridge0
	st_eq "route iface: utun" "$(icp_route_iface "$F/route-get-utun.txt")" utun3

	local mine="36:a1:5c:00:00:01" theirs="36:a1:5c:00:00:02"
	st "arp: the peer's MAC" 0 icp_arp_verdict "? (169.254.0.10) at 36:a1:5c:0:0:2 on bridge0 ifscope [bridge]" "$mine" "$theirs"
	st "arp red: this Mac's own MAC" 1 icp_arp_verdict "? (169.254.0.10) at 36:a1:5c:0:0:1 on bridge0 ifscope [bridge]" "$mine" "$theirs"
	st "arp red: permanent" 1 icp_arp_verdict "? (169.254.0.10) at 36:a1:5c:0:0:2 on bridge0 ifscope permanent [bridge]" "$mine" "$theirs"
	st "arp red: incomplete" 1 icp_arp_verdict "? (169.254.0.10) at (incomplete) on bridge0 ifscope [bridge]" "$mine" "$theirs"

	st "route residue: only the allowed connected /24 and ARP" 0 icp_route_residue "$F/netstat-rn-baseline.txt" "$F/netstat-rn-armed.txt" "169.254.0.0/24" ""
	st "route residue red: the connected /24 after disarm" 1 icp_route_residue "$F/netstat-rn-baseline.txt" "$F/netstat-rn-armed.txt" "" ""
	st "route residue red: a cloned route for a peer slot" 1 icp_route_residue "$F/netstat-rn-baseline.txt" "$F/netstat-rn-peer-clone.txt" "" "169.254.0.25 169.254.0.26"
	st "route residue: an own-alias clone does not fail" 0 icp_route_residue "$F/netstat-rn-baseline.txt" "$F/netstat-rn-own-clone.txt" "" "169.254.0.25 169.254.0.26"
	st_out "route residue: an own-alias clone is RECORDED, never passed silently" "RECORDED 169.254.0.26/32" icp_route_residue "$F/netstat-rn-baseline.txt" "$F/netstat-rn-own-clone.txt" "" "169.254.0.25 169.254.0.26"
	st "arp permanent: clean" 0 icp_arp_permanent "$F/arp-an-clean.txt"
	st "arp permanent red" 1 icp_arp_permanent "$F/arp-an-permanent.txt"

	st "I10: inside the budget" 0 icp_i10_verdict 100.0 112.5 125.0
	st "I10 red: member down after 20 s" 1 icp_i10_verdict 100.0 121.0 125.0
	st "I10 red: re-render after 30 s" 1 icp_i10_verdict 100.0 110.0 131.0
	st "I10 red: a missing timestamp" 1 icp_i10_verdict 100.0 "" 125.0
	st "I10: member down at exactly 20.0 s" 0 icp_i10_verdict 100.0 120.0 125.0
	st "I10 red: member down at 20.1 s" 1 icp_i10_verdict 100.0 120.1 125.0
	st "I10 red: member down at 25 s" 1 icp_i10_verdict 100.0 125.0 128.0
	st "UpHold: 61 s" 0 icp_uphold_verdict 200.0 261.0
	st "UpHold red: 30 s" 1 icp_uphold_verdict 200.0 230.0
	st "UpHold red: no replug timestamp" 1 icp_uphold_verdict 200.0 ""
	st_eq "ping gap: none" "$(icp_ping_max_gap "$F/ping-gap0.txt")" 0
	st_eq "ping gap: one" "$(icp_ping_max_gap "$F/ping-gap1.txt")" 1
	st_eq "ping gap red: three" "$(icp_ping_max_gap "$F/ping-gap3.txt")" 3

	st_eq "transitions delta node-a" "$(($(icp_metric_sum "$F/metrics-after.txt" k3sm_interconnect_member_transitions_total 'node="node-a"') - $(icp_metric_sum "$F/metrics-before.txt" k3sm_interconnect_member_transitions_total 'node="node-a"')))" 2
	st_eq "attached pods" "$(icp_metric_sum "$F/metrics-after.txt" k3sm_interconnect_attached_pods)" 0
	st "netd verbs: the closed two" 0 icp_netd_verbs_closed "$F/metrics-after.txt"
	st "netd verbs red: a foreign verb" 1 icp_netd_verbs_closed "$F/metrics-foreign-verb.txt"
	st_eq "netd Hello frame bytes (4-byte big-endian length + JSON)" "$(icp_netd_hello_frame)" "$(cat "$F/netd-hello-frame.hex")"
	st_eq "helper: minor 2" "$(icp_helper_verdict "$F/hello-minor2.json")" minor2
	st_eq "helper red: an old helper is HelperTooOld" "$(icp_helper_verdict "$F/hello-minor1.json")" HelperTooOld
	st_eq "helper red: no reply is an error" "$(icp_helper_verdict "$F/hello-error.txt")" error
	st "ledger: no aliases" 0 icp_ledger_empty "$F/ledger-empty.json"
	st "ledger: absent" 0 icp_ledger_empty "$F/no-such-ledger.json"
	st "ledger red: one alias" 1 icp_ledger_empty "$F/ledger-one.json"
	st_eq "doctor: ic-residue clean" "$(icp_doctor_row_state "$F/doctor-clean.json" ic-residue)" ok
	st_eq "doctor red: ic-stray warns" "$(icp_doctor_row_state "$F/doctor-residue.json" ic-stray)" warn
	st_eq "doctor: a missing row" "$(icp_doctor_row_state "$F/doctor-clean.json" ic-peers)" absent
	st_eq "doctor red: not a doctor report" "$(icp_doctor_row_state "$F/hello-error.txt" ic-stray)" unreadable

	printf '%s\n' "$RUNG_TABLE" >"$tmp/plan.tsv"
	st "plan validator: the real table" 0 icp_validate_rungs "$tmp/plan.tsv" "$REQUIRED_IDS" "$PREREQ_SET"
	st_out "plan validator red: a rung without an assertion is named" "assertion assert_r10_extra is not defined" icp_validate_rungs "$F/plan-missing-assert.tsv" "$REQUIRED_IDS" "$PREREQ_SET"
	st "plan validator red: exit non-zero on a missing assertion" 1 icp_validate_rungs "$F/plan-missing-assert.tsv" "$REQUIRED_IDS" "$PREREQ_SET"
	st "plan validator red: an unknown prerequisite" 1 icp_validate_rungs "$F/plan-unknown-prereq.tsv" "r0-disarmed" "$PREREQ_SET"
	st_out "plan validator red: the unknown prerequisite is named" "unknown prerequisite 'wifi'" icp_validate_rungs "$F/plan-unknown-prereq.tsv" "r0-disarmed" "$PREREQ_SET"
	{
		printf '%s\n' "$RUNG_TABLE"
		printf '%s\n' "$RUNG_TABLE" | head -1
	} >"$tmp/plan-dup.tsv"
	st "plan validator red: a duplicate id" 1 icp_validate_rungs "$tmp/plan-dup.tsv" "$REQUIRED_IDS" "$PREREQ_SET"

	st "verify-twice: two distinct green runs" 0 icp_verify_twice "$F/run-a" "$F/run-b" "$REQUIRED_IDS"
	st "verify-twice red: one directory twice" 1 icp_verify_twice "$F/run-a" "$F/run-a" "$REQUIRED_IDS"
	st "verify-twice red: differing artifact sha" 1 icp_verify_twice "$F/run-a" "$F/run-b-sha" "$REQUIRED_IDS"
	st "verify-twice red: a rung REFUSED (exit 2)" 1 icp_verify_twice "$F/run-a" "$F/run-b-refused" "$REQUIRED_IDS"
	st "verify-twice red: only rungs.tsv says REFUSED" 1 icp_verify_twice "$F/run-a" "$F/run-b-rung-refused" "$REQUIRED_IDS"
	st_out "verify-twice red: the per-rung check names it" "rung r5-ring is 'REFUSED', not PASS" icp_verify_twice "$F/run-a" "$F/run-b-rung-refused" "$REQUIRED_IDS"
	st_out "verify-twice red: a copied log is one run (started_utc)" "started_utc is the same in both" icp_verify_twice "$F/run-a" "$F/run-a" "$REQUIRED_IDS"
	st "--verify-twice mode exits 0 on the green pair" 0 gate_run 0 PASS -- --verify-twice "$F/run-a" "$F/run-b"
	st "--verify-twice mode exits 1 on a copy" 0 gate_run 1 - -- --verify-twice "$F/run-a" "$F/run-a"

	st "the M11 run-log header loads from hack/lab/lib/runlog.sh" 0 declare -F emit_run_log_header emit_run_log_verdict artifact_sha256 repo_git_sha
	st "a missing run-log library refuses (exit 2) before any rung" 0 runlog_missing_refuses "$tmp/nolib"
	if declare -F emit_run_log_header emit_run_log_verdict artifact_sha256 repo_git_sha >/dev/null; then
		# A fixture stands in for the artifact so artifact_sha256 is a real value.
		K3SM_ARTIFACT="$F/hello-minor2.json" K3SM_RC_TAG="" emit_run_log_header "FAIL (provisional)" >"$tmp/header.txt" 2>&1
		for r in "gate: m17-lab" "artifact_sha256: local:$(shasum -a 256 "$F/hello-minor2.json" | cut -d' ' -f1)" "git_sha.apis: " "git_sha.runtimed: " "git_sha.darwin-net: " "git_sha.k3sm: " "started_utc: " "tolerate_keys: " "result: FAIL"; do
			st "the m11 header emitted over a fixture carries '$r'" 0 grep -qF -- "$r" "$tmp/header.txt"
		done
	fi
	st_driver r3 cable 0
	st_driver r3 cable-red 1
	st_driver r4 mesh 0
	st_driver r4 mesh-red 1
	rm -rf "$tmp"
	if [ "$ST_MISS" -gt 0 ]; then
		echo "$ROW self-test: FAIL ($ST_MISS miss(es))"
		return 1
	fi
	echo "$ROW self-test: PASS"
}

# self_test — the body under a watchdog: a hung check is a FAIL, never a pass.
self_test() {
	local pid wd rc
	self_test_body &
	pid=$!
	(
		sleep "$SELFTEST_WATCHDOG"
		kill -TERM "$pid" 2>/dev/null
	) >/dev/null 2>&1 &
	wd=$!
	wait "$pid"
	rc=$?
	pkill -P "$wd" sleep 2>/dev/null
	kill "$wd" 2>/dev/null
	wait "$wd" 2>/dev/null
	if [ "$rc" -ge 128 ]; then
		echo "$ROW self-test: FAIL (the ${SELFTEST_WATCHDOG}s watchdog fired)"
		return 1
	fi
	return "$rc"
}

# ── Arguments ───────────────────────────────────────────────────────────────────
usage() { echo "usage: $0 [--plan | --self-test | --verify-twice <run dir A> <run dir B>]   (K3SM_LAB=1 PEER_SSH=<ssh target> EVIDENCE_DIR=<dir> for a rig run)"; }
case "${1:-}" in
--plan)
	[ "$#" = 1 ] || {
		usage >&2
		exit 2
	}
	print_plan
	exit $?
	;;
--self-test)
	[ "$#" = 1 ] || {
		usage >&2
		exit 2
	}
	self_test
	exit $?
	;;
--verify-twice)
	[ "$#" = 3 ] || {
		usage >&2
		exit 2
	}
	icp_verify_twice "$2" "$3" "$REQUIRED_IDS"
	exit $?
	;;
-h | --help)
	usage
	exit 0
	;;
"") ;;
*)
	echo "$0: unknown argument: $1" >&2
	usage >&2
	exit 2
	;;
esac

# ── The run ─────────────────────────────────────────────────────────────────────
if [ "${K3SM_LAB_PRINT_MANIFESTS:-}" = 1 ]; then
	lab_tolerations_header
	ic_pod_manifest ic-l-local "<local-node>" 1 "$LISTENER_CMD"
	echo "---"
	ic_pod_manifest ic-flow "<local-node>" 0 "echo flow"
	exit 0
fi
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "$PENDING_TEXT"
	echo "$ROW gate: the interconnect ladder needs K3SM_LAB=1, two Macs joined by a Thunderbolt cable, PEER_SSH and EVIDENCE_DIR."
	exit 3
fi
refuse_run() {
	echo "REFUSED($1): $2"
	FINAL_RC=2
	exit 2
}
FINAL_RC=2
for v in PEER_SSH EVIDENCE_DIR; do
	[ -n "${!v:-}" ] || refuse_run preflight "K3SM_LAB=1 but $v is unset (no defaults: the ssh target is the operator's own Mac, and evidence lives outside any repository) (BI10)"
done
case "$EVIDENCE_DIR" in /*) ;; *) refuse_run preflight "EVIDENCE_DIR must be an absolute path (BI10)" ;; esac
probe="$EVIDENCE_DIR"
while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
git -C "$probe" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
	refuse_run preflight "EVIDENCE_DIR is inside a git work tree; evidence never lands in a repository (BI10)"
PAYLOAD_MB="${K3SM_M17_PAYLOAD_MB:-128}"
[ "$PAYLOAD_MB" -ge 100 ] 2>/dev/null || refuse_run preflight "K3SM_M17_PAYLOAD_MB=$PAYLOAD_MB; the transfer is at least 100 MiB (BI10)"
LAN_SLACK="${K3SM_M17_LAN_SLACK_BYTES:-8388608}"
DESIRED_INTERVAL="${K3SM_M17_DESIRED_INTERVAL:-60}"
CLUSTER_CIDR="${K3SM_M17_CLUSTER_CIDR:-10.42.0.0/16}"
MLX_MODEL="${K3SM_M17_MLX_MODEL:-mlx-community/Qwen2.5-0.5B-Instruct-4bit}"
MLX_MEMORY="${K3SM_M17_MLX_MEMORY:-4Gi}"
MLX_READY_TIMEOUT="${K3SM_M17_MLX_READY_TIMEOUT:-1800}"
REINSTALL_ARGS="${K3SM_M17_REINSTALL_ARGS:-}"
mkdir -p "$EVIDENCE_DIR" || refuse_run preflight "cannot create $EVIDENCE_DIR (BI10)"

RUN_LOG="$HERE/runs/m17-lab-${K3SM_RC_TAG:-local}-$(date -u +%Y-%m-%d).log"
mkdir -p "$HERE/runs"
exec > >(tee "$EVIDENCE_DIR/run.log" | tee -a "$RUN_LOG") 2>&1
emit_run_log_header "FAIL (provisional; the final result line below is the verdict, and a log that ends here did not finish)"
echo "evidence_dir: $EVIDENCE_DIR"
echo "knobs: payload ${PAYLOAD_MB} MiB, LAN slack ${LAN_SLACK} B, DesiredInterval ${DESIRED_INTERVAL}s, cluster CIDR $CLUSTER_CIDR, model $MLX_MODEL ($MLX_MEMORY)"
: >"$EVIDENCE_DIR/rungs.tsv"

# Per-side facts, filled from the probes below (local_* and peer_*); several are
# read only through side_var "<side>" <FIELD>.
# shellcheck disable=SC2034
{
	local_NODE="" peer_NODE="" local_IDX="" peer_IDX="" local_SLOT0="" peer_SLOT0=""
	local_TB="" peer_TB="" local_LAN="" peer_LAN="" local_MESH="" peer_MESH=""
	local_SHA="" peer_SHA="" local_BOOT="" peer_BOOT="" local_OS="" peer_OS=""
	local_MACS="" peer_MACS="" local_ICIP="" peer_ICIP="" WORKER_NODE=""
}
HAVE="" ARMED_BY_RUN=0 FORGED_SIDE="" FORGED_ORIG="" BG_PIDS="" PING_PIDS="" NS_CREATED=0
N_PASS=0 N_FAIL=0 N_REFUSED=0
MESH_UTUN="" PEER_UTUN=""
on_exit() {
	local rc=$? p
	trap - EXIT
	set +e
	for p in $BG_PIDS; do kill "$p" 2>/dev/null; done
	for p in $PING_PIDS; do sudo -n kill "$p" 2>/dev/null; done
	[ -n "${RUNG_DIR:-}" ] && touch "$RUNG_DIR/poll.stop" 2>/dev/null
	if [ -n "$FORGED_SIDE" ]; then
		echo "cleanup: restoring node $(node_of "$FORGED_SIDE")'s desired annotation"
		if [ -n "$FORGED_ORIG" ]; then
			kc annotate node "$(node_of "$FORGED_SIDE")" --overwrite "k3sm.io/interconnect-desired=$FORGED_ORIG" >/dev/null 2>&1
		else
			kc annotate node "$(node_of "$FORGED_SIDE")" k3sm.io/interconnect-desired- >/dev/null 2>&1
		fi
	fi
	if [ "$ARMED_BY_RUN" = 1 ]; then
		echo "cleanup: disarming the interconnect this run armed"
		on_local "$K3SM_BIN interconnect disable" 2>&1 | sed 's/^/          /'
	fi
	[ "$NS_CREATED" = 1 ] && kc delete namespace "$NS" --wait=false >/dev/null 2>&1
	# Exit 0 only when every rung passed; an interrupted ladder is a FAIL.
	if [ "$rc" = 0 ] && { [ "$N_FAIL" -gt 0 ] || [ "$N_REFUSED" -gt 0 ] || [ "$N_PASS" -lt 10 ]; }; then rc=1; fi
	case "$rc" in 0 | 1 | 2) ;; *) rc=1 ;; esac
	echo "----------------------------------------"
	echo "$ROW: $N_PASS rung(s) PASS, $N_FAIL FAIL, $N_REFUSED REFUSED (evidence: $EVIDENCE_DIR)"
	if [ "$rc" = 0 ]; then emit_run_log_verdict PASS; else emit_run_log_verdict FAIL; fi
	exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT TERM HUP

# ── Capability probes: read only; any miss is exit 2 before either Mac changes ──
BASE_DIR="$EVIDENCE_DIR/baseline"
RUNG_DIR="$BASE_DIR"
mkdir -p "$BASE_DIR"
need() { grep -qw "$1" <<<"$HAVE"; }
probe_miss() { refuse_run "${2:-probe}" "$(prereq_what "$1")${3:+: $3}"; }
for t in kubectl ssh scp python3 nc curl; do
	command -v "$t" >/dev/null 2>&1 || probe_miss tools preflight "the local Mac has no $t on PATH"
done
[ -x "$K3SM_BIN" ] || probe_miss tools preflight "no $K3SM_BIN on the local Mac"
sudo -n true 2>/dev/null || probe_miss tools preflight "sudo on the local Mac needs a password; run sudo -v first"
on_peer "mkdir -p $IC_REMOTE_DIR && sudo -n true" >/dev/null 2>&1 || probe_miss tools preflight "the peer is unreachable as PEER_SSH or its sudo is not passwordless"

for side in local peer; do
	payload "$side" info 0 K3SM_BIN="$K3SM_BIN" <<'EOF' || true
br="$(ifconfig bridge0 2>/dev/null)" || { echo BRIDGE=absent; exit 0; }
echo BRIDGE=present
tbdevs="$(networksetup -listallhardwareports 2>/dev/null | awk '/^Hardware Port:/{tb=($0 ~ /Thunderbolt/ && $0 !~ /Bridge/)} /^Device:/{if(tb) print $2; tb=0}')"
macs="$(printf '%s\n' "$br" | awk '$1=="ether"{print $2; exit}')" tba=""
for m in $(printf '%s\n' "$br" | awk '$1=="member:"{print $2}'); do
  macs="$macs $(ifconfig "$m" 2>/dev/null | awk '$1=="ether"{print $2; exit}')"
  grep -qx "$m" <<<"$tbdevs" && grep -q 'status: active' <<<"$(ifconfig "$m")" && tba="$tba $m"
done
echo "TB_ACTIVE=$(echo $tba)"
echo "MACS=$(echo $macs)"
echo "LAN=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
echo "MESH=$(ifconfig -a inet | awk '$1=="inet"{print $2}' | awk -F. '$1==100 && $2>=64 && $2<=127' | head -1)"
bin="$(readlink -f "$K3SM_BIN" 2>/dev/null || echo "$K3SM_BIN")"
echo "SHA=$(shasum -a 256 "$bin" 2>/dev/null | cut -d' ' -f1)"
grep -aqF 'k3sm.io/InterconnectAttached' "$bin" && echo HAS_attach=yes || echo HAS_attach=no
grep -aqF 'K3SM_MLX_HOSTS' "$bin" && echo HAS_mlxhosts=yes || echo HAS_mlxhosts=no
echo "BOOT=$(sysctl -n kern.boottime)"
echo "OS=$(sw_vers -productVersion) ($(sw_vers -buildVersion))"
for t in python3 nc lsof; do command -v "$t" >/dev/null 2>&1 && echo "HAS_$t=yes" || echo "HAS_$t=no"; done
EOF
	cp "$PAYLOAD_LOG" "$BASE_DIR/info-$side.env"
	f="$BASE_DIR/info-$side.env"
	[ "$(kv "$f" BRIDGE)" = present ] || probe_miss bridge preflight "the $side Mac has no bridge0"
	tb="$(kv "$f" TB_ACTIVE)"
	[ -n "$tb" ] || probe_miss bridge preflight "no Thunderbolt member of the $side Mac's bridge0 has carrier"
	[ "$(kv "$f" LAN)" != bridge0 ] || probe_miss bridge preflight "the $side Mac's default route uses bridge0"
	for t in python3 nc lsof; do [ "$(kv "$f" "HAS_$t")" = yes ] || probe_miss tools preflight "the $side Mac has no $t"; done
	[ "$(kv "$f" HAS_attach)" = yes ] || probe_miss attach preflight "the $side Mac's installed binary"
	[ "$(kv "$f" HAS_mlxhosts)" = yes ] || probe_miss mlxhosts preflight "the $side Mac's installed binary"
	eval "${side}_TB=\${tb%% *} ${side}_LAN=\$(kv \"\$f\" LAN) ${side}_MESH=\$(kv \"\$f\" MESH) ${side}_SHA=\$(kv \"\$f\" SHA) ${side}_BOOT=\$(kv \"\$f\" BOOT) ${side}_OS=\$(kv \"\$f\" OS)"
	macs=""
	for m in $(kv "$f" MACS); do macs="$macs $(norm_mac "$m")"; done
	eval "${side}_MACS=\$macs"
done
[ -n "$local_SHA" ] && [ "$local_SHA" = "$peer_SHA" ] || probe_miss artifact preflight "local $local_SHA, peer $peer_SHA"
if [ -n "${K3SM_ARTIFACT:-}" ]; then
	a="$(shasum -a 256 "$K3SM_ARTIFACT" 2>/dev/null | cut -d' ' -f1)"
	[ "$a" = "$local_SHA" ] || probe_miss artifact preflight "K3SM_ARTIFACT is $a, the Macs run $local_SHA"
fi
kc get crd interconnects.net.k3sm.io >/dev/null 2>&1 || probe_miss crd preflight
kc get crd directlinks.net.k3sm.io >/dev/null 2>&1 && probe_miss nodirectlink preflight
help="$(on_local "$K3SM_BIN interconnect --help" 2>&1)"
[[ "$help" == *enable* ]] && [[ "$help" == *disable* ]] || probe_miss verbs preflight
for side in local peer; do
	doctor_json "$side"
	for row in ic-bridge ic-netd ic-peers ic-stray ic-residue; do
		case "$(icp_doctor_row_state "$BASE_DIR/doctor-$side.json" "$row")" in
		absent | unreadable) probe_miss doctor preflight "the $side Mac's doctor --json has no $row row" ;;
		esac
	done
	netd_hello "$side"
	v="$(icp_helper_verdict "$BASE_DIR/netd-hello-$side.json")" || probe_miss netd preflight "the $side Mac's helper answers '$v' (a HelperTooOld is a refusal, never a pass)"
done
# Node names: by mesh address unless named.
mesh_node() { kc get meshpeers.net.k3sm.io -o jsonpath='{range .items[*]}{.metadata.name} {.spec.meshIP}{"\n"}{end}' 2>/dev/null | awk -v ip="$1" '$2==ip{print $1; exit}'; }
local_NODE="${K3SM_M17_LOCAL_NODE:-$(mesh_node "$local_MESH")}"
peer_NODE="${K3SM_M17_PEER_NODE:-$(mesh_node "$peer_MESH")}"
[ -n "$local_NODE" ] && [ -n "$peer_NODE" ] && [ "$local_NODE" != "$peer_NODE" ] ||
	probe_miss index preflight "the two node names could not be matched by mesh address (set K3SM_M17_LOCAL_NODE and K3SM_M17_PEER_NODE)"
for side in local peer; do
	n="$(node_of "$side")"
	cidr="$(kc get node "$n" -o jsonpath='{.spec.podCIDR}' 2>/dev/null)"
	idx="$(icp_node_index "$CLUSTER_CIDR" "$cidr")" || probe_miss index preflight "node $n pod CIDR '$cidr' is not a /24 inside $CLUSTER_CIDR"
	[ "$idx" -le "$ICP_MAX_NODE_INDEX" ] || probe_miss index preflight "node $n has cluster index $idx"
	eval "${side}_IDX=\$idx ${side}_SLOT0=\$(icp_slot_addr \"\$idx\" 0)"
done
WORKER_NODE="$(kc get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
[ -n "$WORKER_NODE" ] || WORKER_NODE="$peer_NODE"
# Never beside an Interconnect the operator armed, nor beside reserved-half state.
[ "$(kc get interconnect "$IC_NAME" -o jsonpath='{.spec.enabled}' 2>/dev/null)" != true ] || probe_miss unarmed preflight "Interconnect $IC_NAME is already enabled; the ladder never disarms what the operator armed"
for side in local peer; do
	[ -z "$(desired_of "$(node_of "$side")")" ] || probe_miss unarmed preflight "node $(node_of "$side") already carries a desired annotation"
	snap "$side" base
	icp_halves_empty "$BASE_DIR/$side-base-bridge0.txt" >/dev/null || probe_miss unarmed preflight "the $side Mac's bridge0 already holds reserved-half addresses"
	read_ledger "$side"
	icp_ledger_empty "$BASE_DIR/ledger-$side.json" >/dev/null || probe_miss unarmed preflight "the $side Mac's netd ledger is not empty"
	on "$side" "netstat -I $(side_var "$side" LAN) -b" >/dev/null 2>&1
	on "$side" "route -n get default" >"$BASE_DIR/$side-base-default.txt" 2>&1
done
PEER_UTUN="$(on_peer "route -n get $local_MESH" | awk '$1=="interface:"{print $2; exit}')"
MESH_UTUN="$(on_local "route -n get $peer_MESH" | awk '$1=="interface:"{print $2; exit}')"
HAVE="$PREREQ_STATIC"
FINAL_RC=1
echo "baseline: local $local_NODE (index $local_IDX, $local_TB, LAN $local_LAN, macOS $local_OS), peer $peer_NODE (index $peer_IDX, $peer_TB, LAN $peer_LAN, macOS $peer_OS); artifact $local_SHA; worker $WORKER_NODE"

# ── The rungs, in table order ──────────────────────────────────────────────────
while IFS='|' read -r id summary prereqs fn ev bi; do
	[ -n "$id" ] || continue
	RUNG="$id" RUNG_DIR="$EVIDENCE_DIR/${ev%/}" R_PASS=0 R_FAIL=0 R_REFUSED_MSG=""
	mkdir -p "$RUNG_DIR"
	printf '\n==> %s (%s): %s\n' "$id" "$bi" "$summary"
	missing=""
	for p in ${prereqs//,/ }; do
		case " $PREREQ_STATIC $PREREQ_RUNTIME " in *" $p "*) need "$p" || missing="$p" ;; esac
		[ -n "$missing" ] && break
	done
	verdict=""
	if [ -n "$missing" ]; then
		echo "REFUSED($id): $(prereq_what "$missing")"
		verdict=REFUSED
	else
		rc=0
		"$fn" </dev/null || rc=$?
		if [ "$rc" = 2 ] || [ -n "$R_REFUSED_MSG" ]; then
			echo "REFUSED($id): ${R_REFUSED_MSG:-the assertion refused}"
			verdict=REFUSED
		elif [ "$R_FAIL" = 0 ] && [ "$R_PASS" -gt 0 ]; then
			verdict=PASS
		else
			verdict=FAIL
		fi
	fi
	[ "$id" = r0-disarmed ] && [ "$verdict" = PASS ] && HAVE="$HAVE armable"
	[ "$id" = r1-arm ] && [ "$verdict" = PASS ] && HAVE="$HAVE armed"
	case "$verdict" in PASS) N_PASS=$((N_PASS + 1)) ;; FAIL) N_FAIL=$((N_FAIL + 1)) ;; REFUSED) N_REFUSED=$((N_REFUSED + 1)) ;; esac
	printf '%s\t%s\n' "$id" "$verdict" >>"$EVIDENCE_DIR/rungs.tsv"
	echo "RUNG $id $verdict ($R_PASS passed, $R_FAIL failed)"
done <<<"$RUNG_TABLE"

if [ "$N_FAIL" -gt 0 ]; then
	FINAL_RC=1
elif [ "$N_REFUSED" -gt 0 ]; then
	FINAL_RC=2
else
	FINAL_RC=0
fi
exit "$FINAL_RC"
