#!/usr/bin/env bash
# k3sm B299 lab measurement: what TCP MSS, UDP size and path-MTU behaviour pod
# traffic actually gets on the wireguard mesh between two joined Macs, against
# an INSTALLED, RUNNING two-node cluster ($KUBECONFIG). This gate boots nothing.
#
# Background. A pod socket is bound to an lo0 alias (MTU 16384) while the mesh
# tunnel (a utun) is MTU 1380. The mesh loads a pf rule (`scrub out on <utun>
# proto tcp max-mss 1340`) into the io.k3sm.mesh anchor, but nothing references
# that anchor from the main ruleset, so pf never evaluates it. The question this
# script answers on real hardware is whether that matters: does a SYN from an
# lo0-bound socket to a remote pod IP carry an MSS above 1340 on the tunnel, or
# does the kernel already derive the MSS from the route to the utun?
# (Answered: the kernel takes the MSS from the route, 1340. The mesh has since
# stopped loading that rule; this background describes the release measured.)
#
# It is READ-ONLY toward the host network configuration. It runs `pfctl -s`,
# `pfctl -sr`, `pfctl -a io.k3sm.mesh -sr`, `route -n get`, `ifconfig` (read),
# `ping` and `tcpdump -i <utun>`; it never enables, disables, loads or flushes
# pf, never changes a route or an interface MTU, and toggles no system setting.
# Its only writes are two pods in the `b299` namespace it owns and
# deletes on exit.
#
# Legs (each writes its own log under the run directory):
#   pf      pf status, main ruleset, the io.k3sm.mesh anchor, utun + route MTU,
#           on both nodes; records whether the anchor is evaluable.
#   panic   lists /Library/Logs/DiagnosticReports/*.panic on both nodes (run
#           before the traffic legs and again at the end).
#   mss     tcpdump on both utuns while four lo0-sourced clients connect across
#           the mesh: local pod -> peer pod, peer pod -> local pod, local node
#           address -> peer pod, peer node address -> local pod. Records the MSS
#           option of every SYN and SYN-ACK seen at each capture point, plus the
#           TCP_MAXSEG each socket reports after connect.
#   udp     lo0-sourced UDP datagrams of several sizes (some above the 1352-byte
#           payload a 1380 MTU carries) in both directions, with and without
#           IP_DONTFRAG; per size: sent, fragments seen on the sending utun,
#           received by the peer pod -> pass / fragmented / loss / refused.
#   pmtud   DF ping sweep across the tunnel from each node's lo0 address to the
#           remote pod IP (1352 / 1353 bytes), and over the outer path to the
#           peer's wireguard endpoint (1472 / 1473 bytes).
#   bulk    a timed TCP bulk transfer pod -> pod in each direction: throughput,
#           the largest IP packet seen on the sending utun, ICMP frag-needed on
#           either utun, and CPU of the k3sm processes on both nodes.
#   soak    bounded (default 300 s, cap 600 s): bidirectional bulk TCP, a
#           fragmenting UDP stream and a `kubectl cp` loop at once, with the
#           panic-file lists taken before and after.
#
# Verdict line: `MSS<=1340 everywhere` when every observed SYN/SYN-ACK MSS on the
# tunnel is at most 1340, `MSS>1340` otherwise. Either is a completed
# measurement (exit 0); no MSS observation at all, a leg that could not run, or a
# new panic file is exit 1. Unset K3SM_LAB exits 3 (not run, not a pass).
#
# Knobs:
#   K3SM_B299_PEER_SSH      ssh destination of the OTHER node (required)
#   K3SM_B299_EVIDENCE_DIR  where per-leg logs go (default: a temp dir)
#   K3SM_B299_LEGS          comma list (default pf,panic,mss,udp,pmtud,bulk,soak)
#   K3SM_B299_BULK_SECS     per-direction bulk duration (default 30)
#   K3SM_B299_SOAK_SECS     soak duration (default 300, capped at 600)
#   K3SM_ARTIFACT           the k3sm binary under test (default: the one on PATH)
#   K3SM_B299_PYTHON        interpreter path on BOTH nodes (default: the Command
#                           Line Tools python3, which a native pod can exec;
#                           the /usr/bin/python3 stub cannot resolve it inside
#                           the sandbox)
#
# Requires: kubectl, ssh (non-interactive) to the peer, passwordless sudo on both
# nodes for tcpdump/pfctl reads and the panic-directory listing, and the
# K3SM_B299_PYTHON interpreter on both nodes (the pods are native and use the
# host interpreter; the tool is passed inline with -c, so no file is mounted).
set -uo pipefail

GATE_NAME="B299"
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "${GATE_NAME} gate: PENDING (two joined Macs + the mesh). Set K3SM_LAB=1 on a lab rig; this is NOT a pass."
	exit 3
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PEER_SSH="${K3SM_B299_PEER_SSH:-}"
LEGS="${K3SM_B299_LEGS:-pf,panic,mss,udp,pmtud,bulk,soak}"
BULK_SECS="${K3SM_B299_BULK_SECS:-30}"
PY="${K3SM_B299_PYTHON:-/Library/Developer/CommandLineTools/usr/bin/python3}"
SOAK_SECS="${K3SM_B299_SOAK_SECS:-300}"
[ "$SOAK_SECS" -gt 600 ] && SOAK_SECS=600
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
EVID="${K3SM_B299_EVIDENCE_DIR:-$(mktemp -d -t b299)}"
RUN_DIR="$EVID/run-$RUN_ID"
NS=b299
MSS_LIMIT=1340
PORT_SYN=18299; PORT_BULK=18302; PORT_SOAK=18303
UDP_PORT=18301; UDP_PORT_DF=18304; UDP_PORT_SOAK=18305
CTRL_PORT=18306  # the server reports its state here (a native pod's python stdout
                 # does not reach kubectl logs, so state is read back over exec)
UDP_SIZES="1200,1352,1353,1400,2000,4000,8000"
UDP_REPEAT=5
WORK="$(mktemp -d -t b299work)"
mkdir -p "$RUN_DIR"
LOCAL_UTUN=""; PEER_UTUN=""; PF_LOCAL=""; PF_PEER=""; CPU_L=""; CPU_P=""
UTUN_MTU_LOCAL=""; UTUN_MTU_PEER=""; ROUTE_MTU_LOCAL=""; ROUTE_MTU_PEER=""

kc() { kubectl "$@"; }
log() { echo "[$(date -u +%H:%M:%S)] $*"; }
has_leg() { case ",$LEGS," in *",$1,"*) return 0 ;; esac; return 1; }
# rsh runs one command line on the peer under a login shell (ssh hands the
# command to the remote login shell; a login shell is what puts its tools on PATH).
rsh() { ssh -n -o BatchMode=yes -o ConnectTimeout=15 "$PEER_SSH" "zsh -lc $(printf '%q' "$1")"; }
# rsh_stdin runs the command with this side's stdin forwarded.
rsh_stdin() { ssh -o BatchMode=yes -o ConnectTimeout=15 "$PEER_SSH" "zsh -lc $(printf '%q' "$1")"; }

repo_git_sha() {
	local repo="$1" dir
	if [ "$repo" = "k3sm" ]; then dir="$REPO_ROOT"; else dir="$REPO_ROOT/../$repo"; fi
	if [ -e "$dir/.git" ] && git -C "$dir" rev-parse HEAD >/dev/null 2>&1; then
		git -C "$dir" rev-parse HEAD
		return
	fi
	echo "unknown"
}
artifact_sha256() {
	local artifact="${K3SM_ARTIFACT:-$(command -v k3sm 2>/dev/null || true)}"
	if [ -n "$artifact" ] && [ -f "$artifact" ]; then
		local sum
		sum="$(shasum -a 256 "$artifact" | cut -d' ' -f1)"
		if [ -n "${K3SM_RC_TAG:-}" ]; then echo "$sum"; else echo "local:${sum}"; fi
		return
	fi
	echo "unknown"
}

echo "# k3sm lab run log"
echo "gate: ${GATE_NAME}"
echo "mode: measurement"
echo "rc_tag: ${K3SM_RC_TAG:-none}"
echo "artifact_sha256: $(artifact_sha256)"
for r in apis runtimed darwin-net k3sm; do echo "git_sha.${r}: $(repo_git_sha "$r")"; done
echo "started_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "result: FAIL (provisional; the final result line is the verdict)"
echo "run_dir: $RUN_DIR"
echo "legs: $LEGS"

INCOMPLETE=""
note_incomplete() { INCOMPLETE="$INCOMPLETE $1"; log "LEG INCOMPLETE: $1 ($2)"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[ -n "$PEER_SSH" ] || { echo "K3SM_B299_PEER_SSH must name the ssh destination of the other node" >&2; exit 1; }
kc get --raw /healthz >/dev/null 2>&1 || { echo "the cluster at \$KUBECONFIG is not serving" >&2; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo is required on this node (tcpdump/pfctl reads)" >&2; exit 1; }
rsh "sudo -n true" >/dev/null 2>&1 || { echo "ssh + passwordless sudo is required on the peer" >&2; exit 1; }
[ -x "$PY" ] && rsh "test -x $PY" || { echo "$PY must exist on both nodes (K3SM_B299_PYTHON)" >&2; exit 1; }

LOCAL_NODE=""; LOCAL_NODE_IP=""; PEER_NODE=""; PEER_NODE_IP=""
while read -r name ip ready; do
	[ "$ready" = "True" ] || { echo "node $name is not Ready" >&2; exit 1; }
	if ifconfig lo0 | grep -q "inet $ip "; then
		LOCAL_NODE="$name"; LOCAL_NODE_IP="$ip"
	elif [ -z "$PEER_NODE" ]; then
		PEER_NODE="$name"; PEER_NODE_IP="$ip"
	else
		echo "more than one remote node; this measurement takes exactly two" >&2; exit 1
	fi
done < <(kc get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.addresses[?(@.type=="InternalIP")].address}{" "}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}')
[ -n "$LOCAL_NODE" ] && [ -n "$PEER_NODE" ] || { echo "could not identify the local and the peer node" >&2; exit 1; }
LOCAL_UTUN="$(route -n get "$PEER_NODE_IP" 2>/dev/null | awk '/interface:/{print $2}')"
PEER_UTUN="$(rsh "route -n get $LOCAL_NODE_IP" 2>/dev/null | awk '/interface:/{print $2}')"
case "$LOCAL_UTUN" in utun*) ;; *) echo "local route to the peer is not via a utun ($LOCAL_UTUN)" >&2; exit 1 ;; esac
case "$PEER_UTUN" in utun*) ;; *) echo "peer route to this node is not via a utun ($PEER_UTUN)" >&2; exit 1 ;; esac
PEER_ENDPOINT="$(kc get meshpeer "$PEER_NODE" -o jsonpath='{.spec.endpoint}' 2>/dev/null || true)"
PEER_ENDPOINT_HOST="${PEER_ENDPOINT%:*}"
log "local node $LOCAL_NODE ($LOCAL_NODE_IP) via $LOCAL_UTUN; peer node $PEER_NODE ($PEER_NODE_IP) via $PEER_UTUN"

# ── The traffic tool (inline in the pod command; also run on the hosts) ─────────────
cat >"$WORK/tool.py" <<'PY'
import errno, json, os, socket, sys, threading, time

IP_DONTFRAG = 28  # <netinet/in.h> on darwin
TCP_MAXSEG = getattr(socket, "TCP_MAXSEG", 2)


def out(s):
    print(s, flush=True)


def maxseg(s):
    try:
        return s.getsockopt(socket.IPPROTO_TCP, TCP_MAXSEG)
    except OSError:
        return -1


EVENTS = []


def tcp_conn(c, a, port):
    t0, n, mss = time.time(), 0, maxseg(c)
    try:
        while True:
            b = c.recv(262144)
            if not b:
                break
            n += len(b)
    except OSError:
        pass
    dt = max(time.time() - t0, 1e-6)
    EVENTS.append("tcp-recv port=%d peer=%s bytes=%d secs=%.2f mbps=%.1f maxseg=%d" % (port, a[0], n, dt, n * 8 / dt / 1e6, mss))
    c.close()


def tcp_srv(ip, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(64)
    while True:
        c, a = s.accept()
        threading.Thread(target=tcp_conn, args=(c, a, port), daemon=True).start()


def udp_srv(ip, port, counts, lock):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((ip, port))
    while True:
        d, _ = s.recvfrom(65535)
        k = "%d:%d" % (port, len(d))
        with lock:
            counts[k] = counts.get(k, 0) + 1


def serve(tcp_ports, udp_ports, ctrl_port):
    ip = os.environ.get("POD_IP") or "0.0.0.0"
    counts, lock = {}, threading.Lock()
    for p in tcp_ports.split(","):
        threading.Thread(target=tcp_srv, args=(ip, int(p)), daemon=True).start()
    for p in udp_ports.split(","):
        threading.Thread(target=udp_srv, args=(ip, int(p), counts, lock), daemon=True).start()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, int(ctrl_port)))
    s.listen(8)
    while True:
        c, _ = s.accept()
        with lock:
            state = {"ready": True, "ip": ip, "udp": dict(counts), "tcp": list(EVENTS)}
        c.sendall(json.dumps(state, sort_keys=True).encode())
        c.close()


def query(ip, port):
    s = socket.create_connection((ip, int(port)), timeout=10)
    b = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        b += d
    out(b.decode())


def connect(src, dst, port):
    s = socket.socket()
    s.bind((src, 0))
    s.settimeout(15)
    s.connect((dst, int(port)))
    return s


def syn(src, dst, port):
    s = connect(src, dst, port)
    out("syn-ok src=%s dst=%s port=%s maxseg=%d" % (src, dst, port, maxseg(s)))
    s.sendall(b"x")
    s.close()


def bulk(src, dst, port, secs):
    s = connect(src, dst, port)
    buf, n, t0 = b"\0" * 65536, 0, time.time()
    end = t0 + float(secs)
    while time.time() < end:
        s.sendall(buf)
        n += len(buf)
    dt = time.time() - t0
    out("bulk-sent src=%s dst=%s bytes=%d secs=%.2f mbps=%.1f maxseg=%d" % (src, dst, n, dt, n * 8 / dt / 1e6, maxseg(s)))
    s.close()


def udp(src, dst, port, df, sizes, repeat):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    if df == "1":
        s.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG, 1)
    for size in sizes.split(","):
        sent, err = 0, "none"
        for _ in range(int(repeat)):
            try:
                s.sendto(b"u" * int(size), (dst, int(port)))
                sent += 1
            except OSError as e:
                err = errno.errorcode.get(e.errno, str(e.errno))
            time.sleep(0.05)
        out("udp-send size=%s df=%s sent=%d err=%s" % (size, df, sent, err))


def udpstream(src, dst, port, size, secs, pps):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    end, sent, errs, gap = time.time() + float(secs), 0, 0, 1.0 / float(pps)
    while time.time() < end:
        try:
            s.sendto(b"s" * int(size), (dst, int(port)))
            sent += 1
        except OSError:
            errs += 1
        time.sleep(gap)
    out("udpstream-sent size=%s sent=%d errs=%d" % (size, sent, errs))


cmd, args = sys.argv[1], sys.argv[2:]  # with -c, argv[0] is "-c"
{"serve": serve, "query": query, "syn": syn, "bulk": bulk, "udp": udp, "udpstream": udpstream}[cmd](*args)
PY

# ── Cleanup ───────────────────────────────────────────────────────────────────
BG_PIDS=""
cleanup() {
	local p
	for p in $BG_PIDS; do kill "$p" 2>/dev/null || true; done
	[ -n "$LOCAL_UTUN" ] && sudo -n pkill -INT -f "[t]cpdump -i $LOCAL_UTUN -nn -v -l" 2>/dev/null
	[ -n "$PEER_UTUN" ] && rsh "sudo -n pkill -INT -f '[t]cpdump -i $PEER_UTUN -nn -v -l'" >/dev/null 2>&1 || true
	kc delete namespace "$NS" --ignore-not-found --wait=true --timeout=90s >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

# ── Capture helpers (tcpdump on the utun only; -l line-buffered text) ─────────
# cap_start <file> local|peer <filter>  ;  cap_stop local|peer <filter-tail>
cap_start() {
	local file="$1" side="$2" filter="$3"
	if [ "$side" = local ]; then
		sudo -n tcpdump -i "$LOCAL_UTUN" -nn -v -l -s 128 "$filter" >"$file" 2>&1 &
	else
		rsh "sudo -n tcpdump -i $PEER_UTUN -nn -v -l -s 128 '$filter'" >"$file" 2>&1 &
	fi
	BG_PIDS="$BG_PIDS $!"
	local i
	for i in $(seq 1 20); do grep -q "listening on" "$file" 2>/dev/null && return 0; sleep 0.5; done
	log "capture did not start ($side): $(head -c 300 "$file")"
	return 1
}
cap_stop() {
	local side="$1" tail="$2"
	sleep 1
	if [ "$side" = local ]; then
		sudo -n pkill -INT -f "[t]cpdump -i $LOCAL_UTUN -nn -v -l -s 128 .*$tail" 2>/dev/null || true
	else
		rsh "sudo -n pkill -INT -f '[t]cpdump -i $PEER_UTUN -nn -v -l -s 128 .*$tail'" >/dev/null 2>&1 || true
	fi
	sleep 1
}
# mss_rows <capture-file> <point> prints "point src > dst flags mss" per SYN/SYN-ACK.
mss_rows() {
	grep -E 'Flags \[S' "$1" | sed -nE "s/^ *([0-9.]+)\.[0-9]+ > ([0-9.]+)\.[0-9]+: Flags \[(S[^]]*)\].*mss ([0-9]+).*/$2 \1 > \2 \3 \4/p"
}

# ── Leg: pf (read-only) ───────────────────────────────────────────────────────
ANCHOR_LOCAL=unknown; ANCHOR_PEER=unknown
pf_read() {
	echo "## pfctl -s info"; sudo -n pfctl -s info 2>&1 | grep -v ALTQ | head -4
	echo "## pfctl -sr"; sudo -n pfctl -sr 2>&1 | grep -v ALTQ
	echo "## pfctl -a io.k3sm.mesh -sr"; sudo -n pfctl -a io.k3sm.mesh -sr 2>&1 | grep -v ALTQ
}
leg_pf() {
	local f="$RUN_DIR/pf.log"
	{
		echo "### local ($LOCAL_NODE)"
		pf_read
		echo "## ifconfig $LOCAL_UTUN"; ifconfig "$LOCAL_UTUN"
		echo "## route -n get $PEER_NODE_IP"; route -n get "$PEER_NODE_IP"
		echo "### peer ($PEER_NODE)"
		rsh "sudo -n pfctl -s info 2>&1 | grep -v ALTQ | head -4; echo '## pfctl -sr'; sudo -n pfctl -sr 2>&1 | grep -v ALTQ; echo '## pfctl -a io.k3sm.mesh -sr'; sudo -n pfctl -a io.k3sm.mesh -sr 2>&1 | grep -v ALTQ; echo '## ifconfig $PEER_UTUN'; ifconfig $PEER_UTUN; echo '## route -n get $LOCAL_NODE_IP'; route -n get $LOCAL_NODE_IP"
	} >"$f" 2>&1
	if sudo -n pfctl -sr 2>/dev/null | grep -q 'io\.k3sm\.mesh'; then ANCHOR_LOCAL=referenced; else ANCHOR_LOCAL=unreferenced; fi
	if rsh "sudo -n pfctl -sr 2>/dev/null" | grep -q 'io\.k3sm\.mesh'; then ANCHOR_PEER=referenced; else ANCHOR_PEER=unreferenced; fi
	PF_LOCAL="$(sudo -n pfctl -s info 2>/dev/null | awk '/^Status:/{print $2}')"
	PF_PEER="$(rsh "sudo -n pfctl -s info 2>/dev/null" | awk '/^Status:/{print $2}')"
	UTUN_MTU_LOCAL="$(ifconfig "$LOCAL_UTUN" | sed -nE 's/.* mtu ([0-9]+).*/\1/p' | head -1)"
	UTUN_MTU_PEER="$(rsh "ifconfig $PEER_UTUN" | sed -nE 's/.* mtu ([0-9]+).*/\1/p' | head -1)"
	ROUTE_MTU_LOCAL="$(route -n get "$PEER_NODE_IP" | awk '/mtu/{getline; print $7}')"
	ROUTE_MTU_PEER="$(rsh "route -n get $LOCAL_NODE_IP" | awk '/mtu/{getline; print $7}')"
	log "pf: local status=$PF_LOCAL anchor=$ANCHOR_LOCAL utun_mtu=$UTUN_MTU_LOCAL route_mtu=$ROUTE_MTU_LOCAL; peer status=$PF_PEER anchor=$ANCHOR_PEER utun_mtu=$UTUN_MTU_PEER route_mtu=$ROUTE_MTU_PEER"
}

# ── Leg: panic-file lists ─────────────────────────────────────────────────────
panic_list() { # <tag>
	{
		echo "### local ($LOCAL_NODE)"; sudo -n ls -la /Library/Logs/DiagnosticReports/ 2>&1 | grep -i '\.panic' || echo "(none)"
		echo "### peer ($PEER_NODE)"; rsh "sudo -n ls -la /Library/Logs/DiagnosticReports/ 2>&1 | grep -i '\.panic' || echo '(none)'"
	} >"$RUN_DIR/panic-$1.log" 2>&1
	log "panic files ($1): local=$(sudo -n ls /Library/Logs/DiagnosticReports/ 2>/dev/null | grep -v '^\.' | grep -c '\.panic$') peer=$(rsh "sudo -n ls /Library/Logs/DiagnosticReports/ 2>/dev/null | grep -v '^\.' | grep -c '\.panic\$'")"
}

# ── Pods ──────────────────────────────────────────────────────────────────────
POD_L="b299-l-$RUN_ID"; POD_P="b299-p-$RUN_ID"
POD_L=$(echo "$POD_L" | tr 'A-Z' 'a-z'); POD_P=$(echo "$POD_P" | tr 'A-Z' 'a-z')
POD_L_IP=""; POD_P_IP=""
pod_json() { # <name> <node>  (the tool source rides the command as -c)
	"$PY" - "$1" "$2" "$NS" "$PY" "$PORT_SYN,$PORT_BULK,$PORT_SOAK" "$UDP_PORT,$UDP_PORT_DF,$UDP_PORT_SOAK" "$CTRL_PORT" "$WORK/tool.py" <<'PYJ'
import json, sys
name, node, ns, py, tcp, udp, ctrl, tool = sys.argv[1:]
print(json.dumps({
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": name, "namespace": ns, "labels": {"app": "b299"}},
    "spec": {
        "nodeName": node,
        "nodeSelector": {"kubernetes.io/os": "darwin"},
        "tolerations": [{"key": "k3sm.io/provider", "operator": "Exists", "effect": "NoSchedule"}],
        "restartPolicy": "Never",
        "containers": [{
            "name": "c", "image": "native",
            "command": [py, "-u", "-c", open(tool).read(), "serve", tcp, udp, ctrl],
            "env": [{"name": "POD_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}}],
            "volumeMounts": [{"name": "data", "mountPath": "/data"}],
        }],
        "volumes": [{"name": "data", "emptyDir": {}}],
    },
}))
PYJ
}
pods_up() {
	kc delete namespace "$NS" --ignore-not-found --wait=true --timeout=90s >/dev/null 2>&1 || true
	kc create namespace "$NS" >/dev/null
	pod_json "$POD_L" "$LOCAL_NODE" | kc apply -f - >/dev/null
	pod_json "$POD_P" "$PEER_NODE" | kc apply -f - >/dev/null
	kc wait --for=condition=Ready "pod/$POD_L" "pod/$POD_P" -n "$NS" --timeout=180s >/dev/null || return 1
	POD_L_IP="$(kc get pod "$POD_L" -n "$NS" -o jsonpath='{.status.podIP}')"
	POD_P_IP="$(kc get pod "$POD_P" -n "$NS" -o jsonpath='{.status.podIP}')"
	local i p ip
	for p in "$POD_L:$POD_L_IP" "$POD_P:$POD_P_IP"; do
		ip="${p#*:}"; p="${p%%:*}"
		for i in $(seq 1 30); do srv_state "$p" "$ip" | grep -q '"ready": true' && break; sleep 1; done
		srv_state "$p" "$ip" | grep -q "\"ip\": \"$ip\"" || { log "pod $p server not ready: $(srv_state "$p" "$ip" 2>&1 | tail -3)"; return 1; }
	done
	log "pods: $POD_L $POD_L_IP on $LOCAL_NODE; $POD_P $POD_P_IP on $PEER_NODE"
}
px() { local pod="$1"; shift; kc exec -n "$NS" "$pod" -- "$PY" -u -c "$(cat "$WORK/tool.py")" "$@"; }
# srv_state <pod> <pod-ip> prints the server's JSON state (udp counts, tcp records).
srv_state() { px "$1" query "$2" "$CTRL_PORT" 2>&1; }
# srv_tcp <pod> <pod-ip> <port> prints the last tcp-recv record for that port.
srv_tcp() { srv_state "$1" "$2" | "$PY" -c "import json,sys
try: d=json.loads(sys.stdin.read())
except ValueError: d={'tcp': []}
r=[e for e in d['tcp'] if 'port=$3 ' in e]
print(r[-1] if r else '')"; }

# ── Leg: mss ──────────────────────────────────────────────────────────────────
MSS_ROWS_FILE="$RUN_DIR/mss-rows.txt"; : >"$MSS_ROWS_FILE"
leg_mss() {
	local d="$RUN_DIR/mss" filt="tcp port $PORT_SYN and tcp[tcpflags] & tcp-syn != 0"
	mkdir -p "$d"
	cap_start "$d/cap-local.txt" local "$filt" || return 1
	cap_start "$d/cap-peer.txt" peer "$filt" || return 1
	{
		echo "## pod L -> pod P"; px "$POD_L" syn "$POD_L_IP" "$POD_P_IP" "$PORT_SYN"
		echo "## pod P -> pod L"; px "$POD_P" syn "$POD_P_IP" "$POD_L_IP" "$PORT_SYN"
		echo "## node L ($LOCAL_NODE_IP, lo0) -> pod P"; "$PY" "$WORK/tool.py" syn "$LOCAL_NODE_IP" "$POD_P_IP" "$PORT_SYN"
		echo "## node P ($PEER_NODE_IP, lo0) -> pod L"; rsh_stdin "$PY - syn $PEER_NODE_IP $POD_L_IP $PORT_SYN" <"$WORK/tool.py"
	} >"$d/clients.log" 2>&1
	cap_stop local "port $PORT_SYN"
	cap_stop peer "port $PORT_SYN"
	{ mss_rows "$d/cap-local.txt" "local-$LOCAL_UTUN"; mss_rows "$d/cap-peer.txt" "peer-$PEER_UTUN"; } | tee -a "$MSS_ROWS_FILE" >"$d/rows.txt"
	log "mss: $(wc -l <"$d/rows.txt" | tr -d ' ') SYN/SYN-ACK observations; client TCP_MAXSEG: $(grep -o 'maxseg=[0-9-]*' "$d/clients.log" | tr '\n' ' ')"
	[ "$(grep -c 'syn-ok' "$d/clients.log")" -eq 4 ] || { log "mss: not all four clients connected: $(grep -v syn-ok "$d/clients.log" | head -5)"; return 1; }
}

# ── Leg: udp ──────────────────────────────────────────────────────────────────
UDP_TABLE="$RUN_DIR/udp-table.txt"; : >"$UDP_TABLE"
udp_dir() { # <label> <client-pod> <src> <dst> <server-pod> <capture-side>
	local label="$1" cpod="$2" src="$3" dst="$4" spod="$5" side="$6" d="$RUN_DIR/udp/$1" size df port cap sent err frags pkts recv
	mkdir -p "$d"
	for size in $(echo "$UDP_SIZES" | tr ',' ' '); do
		for df in 0 1; do
			port=$UDP_PORT; [ "$df" = 1 ] && port=$UDP_PORT_DF
			cap="$d/cap-$size-df$df.txt"
			cap_start "$cap" "$side" "dst host $dst and (udp port $port or ip[6:2] & 0x1fff != 0)" || return 1
			px "$cpod" udp "$src" "$dst" "$port" "$df" "$size" "$UDP_REPEAT" >>"$d/clients.log" 2>&1
			cap_stop "$side" "dst host $dst and .udp port $port"
			sent="$(grep "udp-send size=$size df=$df " "$d/clients.log" | tail -1 | sed -nE 's/.*sent=([0-9]+).*/\1/p')"
			err="$(grep "udp-send size=$size df=$df " "$d/clients.log" | tail -1 | sed -nE 's/.*err=([A-Z0-9a-z]+).*/\1/p')"
			pkts="$(grep -c 'proto UDP (17)' "$cap")"
			frags="$(grep 'proto UDP (17)' "$cap" | grep -cE 'flags \[\+\]|offset [1-9]')"
			echo "$label $size $df ${sent:-0} ${err:-?} $pkts $frags" >>"$d/sent.txt"
		done
	done
	sleep 3
	local counts
	counts="$(srv_state "$spod" "$dst" | "$PY" -c "import json,sys
try: print(json.dumps(json.loads(sys.stdin.read())['udp']))
except ValueError: print('{}')")"
	echo "server counts: $counts" >>"$d/clients.log"
	while read -r lab sz df s e pk fr; do
		port=$UDP_PORT; [ "$df" = 1 ] && port=$UDP_PORT_DF
		recv="$(echo "$counts" | "$PY" -c "import json,sys; d=json.loads(sys.stdin.read() or '{}'); print(d.get('$port:$sz',0))")"
		local outcome
		if [ "$s" -eq 0 ] && [ "$e" != none ]; then outcome="refused-locally($e)"
		elif [ "$recv" -ge "$s" ] && [ "$fr" -gt 0 ]; then outcome="fragmented-delivered"
		elif [ "$recv" -ge "$s" ]; then outcome="pass"
		elif [ "$recv" -eq 0 ]; then outcome="loss"
		else outcome="partial"; fi
		printf '%-8s %6s %3s %5s %5s %6s %6s  %s\n' "$lab" "$sz" "$df" "$s" "$recv" "$pk" "$fr" "$outcome" >>"$UDP_TABLE"
	done <"$d/sent.txt"
}
leg_udp() {
	udp_dir "L->P" "$POD_L" "$POD_L_IP" "$POD_P_IP" "$POD_P" local || return 1
	udp_dir "P->L" "$POD_P" "$POD_P_IP" "$POD_L_IP" "$POD_L" peer || return 1
	log "udp: done ($(wc -l <"$UDP_TABLE" | tr -d ' ') rows)"
}

# ── Leg: pmtud ────────────────────────────────────────────────────────────────
PMTUD_TABLE="$RUN_DIR/pmtud-table.txt"; : >"$PMTUD_TABLE"
ping_row() { # <label> <where> <cmd-output-file>
	local res
	if grep -q 'Message too long' "$3"; then res="refused-locally(EMSGSIZE)"
	elif grep -qE ' 0(\.0)?% packet loss' "$3"; then res="pass"
	elif grep -q '100.0% packet loss' "$3"; then res="loss"
	else res="other"; fi
	printf '%-34s %s\n' "$1" "$res" >>"$PMTUD_TABLE"
}
leg_pmtud() {
	local d="$RUN_DIR/pmtud" s
	mkdir -p "$d"
	for s in 1352 1353; do
		ping -D -c 2 -t 6 -S "$LOCAL_NODE_IP" -s "$s" "$POD_P_IP" >"$d/l2p-$s.txt" 2>&1
		ping_row "inner L->P DF payload $s" local "$d/l2p-$s.txt"
		rsh "ping -D -c 2 -t 6 -S $PEER_NODE_IP -s $s $POD_L_IP" >"$d/p2l-$s.txt" 2>&1
		ping_row "inner P->L DF payload $s" peer "$d/p2l-$s.txt"
	done
	if [ -n "$PEER_ENDPOINT_HOST" ]; then
		for s in 1472 1473; do
			ping -D -c 2 -t 6 -s "$s" "$PEER_ENDPOINT_HOST" >"$d/outer-$s.txt" 2>&1
			ping_row "outer L->P endpoint DF payload $s" local "$d/outer-$s.txt"
		done
		local oif
		oif="$(route -n get "$PEER_ENDPOINT_HOST" 2>/dev/null | awk '/interface:/{print $2}')"
		echo "outer interface $oif mtu=$(ifconfig "$oif" 2>/dev/null | sed -nE 's/.* mtu ([0-9]+).*/\1/p' | head -1)" >>"$PMTUD_TABLE"
	else
		echo "outer path: no MeshPeer endpoint found" >>"$PMTUD_TABLE"
	fi
	{ echo "local:"; sysctl net.inet.tcp.path_mtu_discovery; echo "peer:"; rsh "sysctl net.inet.tcp.path_mtu_discovery"; } >"$d/sysctl.txt" 2>&1
	log "pmtud: done"
}

# ── CPU sampler ───────────────────────────────────────────────────────────────
cpu_sample() { # <file> <secs>  (local and peer, every 2 s)
	local n=$(( $2 / 2 + 1 ))
	( echo "load $(sysctl -n vm.loadavg)"; echo "host $(top -l 1 -n 0 | grep 'CPU usage')"
	  for _ in $(seq 1 "$n"); do ps -Ao pcpu=,comm= | awk '/k3sm|kine|kube-/'; echo "--"; sleep 2; done ) >"$1.local" 2>&1 &
	BG_PIDS="$BG_PIDS $!"; CPU_L=$!
	rsh "echo load \$(sysctl -n vm.loadavg); echo host \$(top -l 1 -n 0 | grep 'CPU usage'); for i in \$(seq 1 $n); do ps -Ao pcpu=,comm= | awk '/k3sm|kine|kube-/'; echo --; sleep 2; done" >"$1.peer" 2>&1 &
	BG_PIDS="$BG_PIDS $!"; CPU_P=$!
}
# cpu_summary <file.side>: per k3sm / control-plane process (pod workloads that
# merely live under a k3sm path are excluded), plus the host load average and
# whole-host CPU taken when sampling started.
cpu_summary() {
	awk '$1!="--" && $1!="load" && $1!="host"{n=split($2,a,"/"); k=a[n]; if (k !~ /^(k3sm|kine|kube-)/) next; s[k]+=$1; c[k]++; if($1>m[k])m[k]=$1} END{for(k in s) printf "%s avg=%.1f%% max=%.1f%%; ", k, s[k]/c[k], m[k]}' "$1"
	grep -m1 '^load' "$1"; grep -m1 '^host' "$1"
}

# ── Leg: bulk ─────────────────────────────────────────────────────────────────
BULK_TABLE="$RUN_DIR/bulk-table.txt"; : >"$BULK_TABLE"
bulk_dir() { # <label> <client-pod> <src> <dst> <server-pod> <capture-side>
	local label="$1" cpod="$2" src="$3" dst="$4" spod="$5" side="$6" d="$RUN_DIR/bulk/$1" other
	other=peer; [ "$side" = peer ] && other=local
	mkdir -p "$d"
	cap_start "$d/cap-send.txt" "$side" "tcp port $PORT_BULK" || return 1
	cap_start "$d/icmp-$side.txt" "$side" "icmp and icmp[0] == 3 and icmp[1] == 4 and not port $PORT_BULK" || return 1
	cap_start "$d/icmp-$other.txt" "$other" "icmp and icmp[0] == 3 and icmp[1] == 4 and not port $PORT_BULK" || return 1
	cpu_sample "$d/cpu" "$BULK_SECS"
	px "$cpod" bulk "$src" "$dst" "$PORT_BULK" "$BULK_SECS" >"$d/client.log" 2>&1
	wait "$CPU_L" "$CPU_P" 2>/dev/null
	cap_stop "$side" "tcp port $PORT_BULK"
	cap_stop "$side" "and not port $PORT_BULK"
	cap_stop "$other" "and not port $PORT_BULK"
	sleep 2
	srv_tcp "$spod" "$dst" "$PORT_BULK" >"$d/server.log"
	mss_rows "$d/cap-send.txt" "$side-bulk" >>"$MSS_ROWS_FILE"
	local maxlen pk icmp mbps_s mbps_r
	maxlen="$(grep -oE 'proto TCP \(6\), length [0-9]+' "$d/cap-send.txt" | awk '{print $NF}' | sort -n | tail -1)"
	pk="$(grep -c 'proto TCP (6)' "$d/cap-send.txt")"
	icmp="$(cat "$d/icmp-$side.txt" "$d/icmp-$other.txt" | grep -c 'ICMP')"
	mbps_s="$(sed -nE 's/.*mbps=([0-9.]+).*/\1/p' "$d/client.log")"
	mbps_r="$(sed -nE 's/.*mbps=([0-9.]+).*/\1/p' "$d/server.log")"
	printf '%-6s sent=%sMbit/s recv=%sMbit/s pkts_seen=%s max_ip_len=%s icmp_fragneeded=%s %s\n' "$label" "${mbps_s:-?}" "${mbps_r:-?}" "$pk" "${maxlen:-?}" "$icmp" "$(grep -o 'maxseg=[0-9-]*' "$d/client.log")" >>"$BULK_TABLE"
	printf '       cpu local: %s\n       cpu peer:  %s\n' "$(cpu_summary "$d/cpu.local" | tr '\n' ' ')" "$(cpu_summary "$d/cpu.peer" | tr '\n' ' ')" >>"$BULK_TABLE"
	[ -n "$mbps_s" ] || return 1
}
leg_bulk() {
	bulk_dir "L->P" "$POD_L" "$POD_L_IP" "$POD_P_IP" "$POD_P" local || return 1
	bulk_dir "P->L" "$POD_P" "$POD_P_IP" "$POD_L_IP" "$POD_L" peer || return 1
	log "bulk: done"
}

# ── Leg: soak ─────────────────────────────────────────────────────────────────
SOAK_SUMMARY=""
leg_soak() {
	local d="$RUN_DIR/soak" end cp_ok=0 cp_fail=0 health_fail=0 t0 blob
	mkdir -p "$d"
	blob="$WORK/blob"
	dd if=/dev/urandom of="$blob" bs=1048576 count=32 2>/dev/null
	log "soak: ${SOAK_SECS}s bidirectional bulk TCP + 1400-byte UDP stream both ways + kubectl cp loop"
	cpu_sample "$d/cpu" "$SOAK_SECS"
	px "$POD_L" bulk "$POD_L_IP" "$POD_P_IP" "$PORT_SOAK" "$SOAK_SECS" >"$d/bulk-l2p.log" 2>&1 & BG_PIDS="$BG_PIDS $!"; local b1=$!
	px "$POD_P" bulk "$POD_P_IP" "$POD_L_IP" "$PORT_SOAK" "$SOAK_SECS" >"$d/bulk-p2l.log" 2>&1 & BG_PIDS="$BG_PIDS $!"; local b2=$!
	px "$POD_L" udpstream "$POD_L_IP" "$POD_P_IP" "$UDP_PORT_SOAK" 1400 "$SOAK_SECS" 100 >"$d/udp-l2p.log" 2>&1 & BG_PIDS="$BG_PIDS $!"; local u1=$!
	px "$POD_P" udpstream "$POD_P_IP" "$POD_L_IP" "$UDP_PORT_SOAK" 1400 "$SOAK_SECS" 100 >"$d/udp-p2l.log" 2>&1 & BG_PIDS="$BG_PIDS $!"; local u2=$!
	t0=$(date +%s); end=$(( t0 + SOAK_SECS ))
	# kubectl cp is tar over the exec stream; when tar in the pod cannot reach the
	# mount the copy falls back to the same exec stream without tar (recorded).
	CP_MODE="kubectl cp"
	kc cp "$blob" "$NS/$POD_P:/data/blob" -c c >>"$d/cp.log" 2>&1 || CP_MODE="kubectl exec -i (cat >/dev/null)"
	echo "cp mode: $CP_MODE" >>"$d/cp.log"
	push_blob() { # <pod>
		if [ "$CP_MODE" = "kubectl cp" ]; then kc cp "$blob" "$NS/$1:/data/blob" -c c >>"$d/cp.log" 2>&1
		else kc exec -i -n "$NS" "$1" -- /bin/sh -c 'cat >/dev/null' <"$blob" >>"$d/cp.log" 2>&1; fi
	}
	while [ "$(date +%s)" -lt "$end" ]; do
		if push_blob "$POD_P"; then cp_ok=$((cp_ok+1)); else cp_fail=$((cp_fail+1)); fi
		if push_blob "$POD_L"; then cp_ok=$((cp_ok+1)); else cp_fail=$((cp_fail+1)); fi
		kc get --raw /healthz >/dev/null 2>&1 || health_fail=$((health_fail+1))
		echo "$(( $(date +%s) - t0 ))s cp_ok=$cp_ok cp_fail=$cp_fail health_fail=$health_fail" >>"$d/progress.log"
	done
	wait "$b1" "$b2" "$u1" "$u2" "$CPU_L" "$CPU_P" 2>/dev/null
	sleep 3
	srv_state "$POD_P" "$POD_P_IP" >"$d/server-p.json"
	srv_state "$POD_L" "$POD_L_IP" >"$d/server-l.json"
	local udp_rx_p udp_rx_l
	udp_rx_p="$("$PY" -c "import json,sys
try: print(sum(v for k,v in json.load(open(sys.argv[1]))['udp'].items() if k.startswith('$UDP_PORT_SOAK:')))
except Exception: print('?')" "$d/server-p.json")"
	udp_rx_l="$("$PY" -c "import json,sys
try: print(sum(v for k,v in json.load(open(sys.argv[1]))['udp'].items() if k.startswith('$UDP_PORT_SOAK:')))
except Exception: print('?')" "$d/server-l.json")"
	local nodes_ready
	nodes_ready="$(kc get nodes -o jsonpath='{range .items[*]}{.metadata.name}={.status.conditions[?(@.type=="Ready")].status} {end}')"
	SOAK_SUMMARY="secs=$SOAK_SECS bulk L->P $(sed -nE 's/.*mbps=([0-9.]+).*/\1/p' "$d/bulk-l2p.log")Mbit/s, P->L $(sed -nE 's/.*mbps=([0-9.]+).*/\1/p' "$d/bulk-p2l.log")Mbit/s; udp L->P $(tr '\n' ' ' <"$d/udp-l2p.log")recv=$udp_rx_p, P->L $(tr '\n' ' ' <"$d/udp-p2l.log")recv=$udp_rx_l; ${CP_MODE} ok=$cp_ok fail=$cp_fail (32 MiB each); healthz_fail=$health_fail; nodes: $nodes_ready"
	printf '       cpu local: %s\n       cpu peer:  %s\n' "$(cpu_summary "$d/cpu.local" | tr '\n' ' ')" "$(cpu_summary "$d/cpu.peer" | tr '\n' ' ')" >"$d/cpu-summary.txt"
	log "soak: $SOAK_SUMMARY"
	grep -q bulk-sent "$d/bulk-l2p.log" && grep -q bulk-sent "$d/bulk-p2l.log" || return 1
}

# ── Run ───────────────────────────────────────────────────────────────────────
has_leg pf && { leg_pf || note_incomplete pf "read failed"; }
PANIC_BEFORE_L="$(sudo -n ls /Library/Logs/DiagnosticReports/ 2>/dev/null | grep '\.panic$' | grep -v '^\.' | sort)"
PANIC_BEFORE_P="$(rsh "sudo -n ls /Library/Logs/DiagnosticReports/ 2>/dev/null" | grep '\.panic$' | grep -v '^\.' | sort)"
has_leg panic && panic_list before
NEED_PODS=no
for l in mss udp pmtud bulk soak; do has_leg "$l" && NEED_PODS=yes; done
if [ "$NEED_PODS" = yes ]; then
	if pods_up; then
		has_leg mss && { leg_mss || note_incomplete mss "see $RUN_DIR/mss"; }
		has_leg udp && { leg_udp || note_incomplete udp "see $RUN_DIR/udp"; }
		has_leg pmtud && { leg_pmtud || note_incomplete pmtud "see $RUN_DIR/pmtud"; }
		has_leg bulk && { leg_bulk || note_incomplete bulk "see $RUN_DIR/bulk"; }
		has_leg soak && { leg_soak || note_incomplete soak "see $RUN_DIR/soak"; }
	else
		note_incomplete pods "the measurement pods did not come up"
	fi
fi
has_leg panic && panic_list after
PANIC_AFTER_L="$(sudo -n ls /Library/Logs/DiagnosticReports/ 2>/dev/null | grep '\.panic$' | grep -v '^\.' | sort)"
PANIC_AFTER_P="$(rsh "sudo -n ls /Library/Logs/DiagnosticReports/ 2>/dev/null" | grep '\.panic$' | grep -v '^\.' | sort)"
NEW_PANICS="$(comm -13 <(echo "$PANIC_BEFORE_L") <(echo "$PANIC_AFTER_L") | sed 's/^/local:/'; comm -13 <(echo "$PANIC_BEFORE_P") <(echo "$PANIC_AFTER_P") | sed 's/^/peer:/')"
NEW_PANICS="$(echo "$NEW_PANICS" | grep -v '^$' || true)"

# ── Results ───────────────────────────────────────────────────────────────────
echo
echo "================ B299 results ================"
echo "pf: local status=${PF_LOCAL:-?} io.k3sm.mesh=${ANCHOR_LOCAL}; peer status=${PF_PEER:-?} io.k3sm.mesh=${ANCHOR_PEER}"
echo "tunnel: local $LOCAL_UTUN mtu=${UTUN_MTU_LOCAL:-?} route-mtu=${ROUTE_MTU_LOCAL:-?}; peer $PEER_UTUN mtu=${UTUN_MTU_PEER:-?} route-mtu=${ROUTE_MTU_PEER:-?}"
if [ "$ANCHOR_LOCAL" = referenced ] || [ "$ANCHOR_PEER" = referenced ]; then
	echo "clamp: the anchor IS referenced on at least one node; MSS rows below are with the clamp evaluable there"
else
	echo "clamp: the anchor is referenced on neither node, so every MSS row below is the kernel's own (unclamped) value; a clamped leg cannot be produced without changing pf, which this script never does"
fi
echo
echo "-- TCP MSS (capture-point  src > dst  flags  mss) --"
sort -u "$MSS_ROWS_FILE"
MAX_MSS="$(awk '{print $NF}' "$MSS_ROWS_FILE" | sort -n | tail -1)"
N_MSS="$(sort -u "$MSS_ROWS_FILE" | grep -c . || true)"
echo "observations=$N_MSS max_mss=${MAX_MSS:-none}"
echo
echo "-- UDP (dir size df sent recv pkts frags outcome) --"
cat "$UDP_TABLE"
echo
echo "-- PMTUD --"
cat "$PMTUD_TABLE"
echo
echo "-- bulk throughput / CPU --"
cat "$BULK_TABLE"
echo
echo "-- soak --"
echo "${SOAK_SUMMARY:-not run}"
[ -f "$RUN_DIR/soak/cpu-summary.txt" ] && cat "$RUN_DIR/soak/cpu-summary.txt"
echo
echo "-- panic files --"
echo "before: local=[$(echo $PANIC_BEFORE_L)] peer=[$(echo $PANIC_BEFORE_P)]"
echo "after:  local=[$(echo $PANIC_AFTER_L)] peer=[$(echo $PANIC_AFTER_P)]"
echo "new: ${NEW_PANICS:-none}"
echo

RESULT=PASS
if [ -z "$MAX_MSS" ] || [ "$N_MSS" -eq 0 ]; then
	echo "verdict: INCONCLUSIVE (no MSS observed on the tunnel)"
	RESULT=FAIL
elif [ "$MAX_MSS" -le "$MSS_LIMIT" ]; then
	echo "verdict: MSS<=${MSS_LIMIT} everywhere (max observed ${MAX_MSS} over ${N_MSS} SYN/SYN-ACK)"
else
	echo "verdict: MSS>${MSS_LIMIT} (max observed ${MAX_MSS} over ${N_MSS} SYN/SYN-ACK)"
fi
[ -n "$INCOMPLETE" ] && { echo "incomplete legs:$INCOMPLETE"; RESULT=FAIL; }
[ -n "$NEW_PANICS" ] && { echo "NEW PANIC FILE(S): $NEW_PANICS"; RESULT=FAIL; }
echo "gate: ${GATE_NAME}"
echo "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "result: $RESULT"
[ "$RESULT" = PASS ] || exit 1
