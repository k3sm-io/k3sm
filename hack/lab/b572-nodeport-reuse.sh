#!/usr/bin/env bash
# k3sm B572 repro: a NodePort reused after its Service and namespace are deleted
# must answer only the live Service's pod, from both nodes.
#
# LAB ONLY (K3SM_LAB=1). Runs against the RUNNING two-node cluster in $KUBECONFIG,
# from a machine with kubectl and ssh to both Macs (the hack/lab/b416.sh
# conventions). Without K3SM_LAB=1 it prints the pending line and exits 3.
#   Required:
#     K3SM_B572_SERVER_NODE   the server's node name
#     K3SM_B572_WORKER_NODE   the joined worker's node name (every backend pod runs here)
#     K3SM_B572_SERVER_SSH    ssh destination of the server Mac
#     K3SM_B572_WORKER_SSH    ssh destination of the worker Mac
#   Optional:
#     K3SM_B572_P1, K3SM_B572_P2   the two NodePorts (default 31520, 31521)
#     K3SM_B572_EVIDENCE      evidence directory (default: a new mktemp dir)
#     KUBECTL                 kubectl binary (default kubectl)
#     K3SM_LAB_TOLERATE_KEYS  extra taint keys every lab pod tolerates (hack/lab/lib/tolerations.sh)
#     K3SM_LAB_PRINT_MANIFESTS=1  print the pod manifest and exit; contacts nothing
#
# Steps (every dial is the 2x2 matrix {server, worker} -> {server, worker} mesh
# address, so the worker's own proxy and the server's proxy are both exercised):
#   s.0  per pod: Ready, and (s0b) its 8080 listener is bound to its own pod IP,
#        not the wildcard. The server is Homebrew python3 (a non-platform binary
#        the pod bind shim wraps) bound to POD_IP from the downward API; a
#        platform binary such as /usr/bin/nc binds *:8080, where a dial to any
#        pod IP on the node lands on whichever wildcard socket the kernel picks,
#        so a regression there is this named red, not a scrambled dial.
#   s.1  ns b572-a: native pod on the worker answering "A" on 8080, NodePort p1;
#        ns b572-b: the same answering "B", NodePort p2. p1 -> A and p2 -> B.
#   s.2  ns b572-a deleted (--wait): within 60 s p1 answers nothing from either
#        node and neither node holds a listener on p1; no process of pod A
#        (its serve.sh, serve.py and their children, recorded just before the
#        delete)
#        is still running on the worker.
#   s.3  ns b572-c: "C" on p1. Five rounds: p1 -> C and p2 -> B, every dial.
#   Recorded, not asserted: the pod IPs of A and C (reuse is expected) and
#   whether A's IP is still a lo0 alias after the delete. Dumps (NodePort and
#   8080 listeners, the nc, serve.sh and serve.py
#   processes, the k3sm status rows naming the ports) are taken at every step
#   and at every failing check.
#
# Exit: 0 every assertion passed, 1 an assertion failed, 2 a lab precondition
# refused the run, 3 K3SM_LAB unset (nothing was run).
#
# Usage:  hack/lab/b572-nodeport-reuse.sh --self-test    # the helpers, no cluster
#         K3SM_LAB=1 K3SM_B572_SERVER_NODE=node-a K3SM_B572_WORKER_NODE=node-b \
#           K3SM_B572_SERVER_SSH=node-a.example K3SM_B572_WORKER_SSH=node-b.example \
#           hack/lab/b572-nodeport-reuse.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/tolerations.sh
. "$HERE/lib/tolerations.sh"

P1="${K3SM_B572_P1:-31520}"
P2="${K3SM_B572_P2:-31521}"
DUMP_PORTS="$P1-$((P2 + 1))"

# ---- pure helpers (the --self-test surface) -----------------------------------

# norm <text>: the text with surrounding whitespace removed; empty prints "nothing".
norm() {
	local s="$1"
	s="${s#"${s%%[![:space:]]*}"}"
	s="${s%"${s##*[![:space:]]}"}"
	[ -n "$s" ] || s=nothing
	printf '%s' "$s"
}

# body_is <got> <want>: 0 iff the normalized answer equals want ("nothing" for
# no answer).
body_is() { [ "$(norm "$1")" = "$2" ]; }

# listen_count <lsof-output> <port>: the LISTEN rows bound to that port, any address.
listen_count() {
	printf '%s\n' "$1" | awk -v p=":$2" '/\(LISTEN\)/ { a = $(NF-1); if (substr(a, length(a) - length(p) + 1) == p) n++ } END { print n + 0 }'
}

# listen_addrs <lsof-output> <port>: the bound address:port of each LISTEN row on
# that port, space-separated, sorted.
listen_addrs() {
	printf '%s\n' "$1" | awk -v p=":$2" '/\(LISTEN\)/ { a = $(NF-1); if (substr(a, length(a) - length(p) + 1) == p) print a }' | sort | xargs
}

# bound_to_ip <listen-addrs> <ip>: 0 iff the listeners are exactly <ip>:8080
# (one or more sockets, none on the wildcard or another address).
bound_to_ip() {
	local a
	[ -n "$1" ] || return 1
	for a in $1; do [ "$a" = "$2:8080" ] || return 1; done
	return 0
}

# ip_aliased <ifconfig-lo0-output> <ip>: 0 iff an "inet <ip> " line is present
# (an exact match: 100.64.1.2 never matches 100.64.1.29).
ip_aliased() {
	printf '%s\n' "$1" | awk -v ip="$2" '$1 == "inet" && $2 == ip { f = 1 } END { exit !f }'
}

# survivors <live-pids> <recorded-pids>: the recorded pids still in the live list.
survivors() {
	local p out=""
	for p in $2; do
		case " $(echo "$1" | xargs) " in *" $p "*) out="${out:+$out }$p" ;; esac
	done
	printf '%s' "$out"
}

# port_rows <text> <port...>: the lines naming any of the ports, or "none".
port_rows() {
	local text="$1" pat="" p
	shift
	for p in "$@"; do pat="${pat:+$pat|}(^|[^0-9])$p([^0-9]|\$)"; done
	printf '%s\n' "$text" | grep -E "$pat" || echo none
}

# ---- manifests ------------------------------------------------------------------

LAB_TOLERATIONS="$(lab_tolerations_yaml "")" || exit 2

# backend <ns> <node> <body> <nodePort>: the ConfigMap, a native pod answering
# exactly <body> on 8080 and a NodePort Service selecting it. The server is
# Homebrew python3 (not a platform binary, so the pod bind shim loads) bound to
# the pod's own IP from the downward API. The argv of serve.sh and serve.py
# carries the namespace as a tag so the pod's processes are findable; the
# scripts ride a ConfigMap (a native pod cannot read files under /tmp).
backend() {
	local ns="$1" node="$2" body="$3" port="$4"
	cat <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: b572-script, namespace: $ns}
data:
  serve.sh: |
    /opt/homebrew/bin/python3 /cfg/serve.py "\$1" "\$2"
  serve.py: |
    import http.server, os, sys
    BODY = sys.argv[2].encode()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        def log_message(self, *args):
            pass
    http.server.HTTPServer((os.environ["POD_IP"], 8080), Handler).serve_forever()
---
apiVersion: v1
kind: Pod
metadata: {name: b572-web, namespace: $ns, labels: {app: b572-web}}
spec:
  nodeName: $node
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$LAB_TOLERATIONS]
  containers:
  - name: web
    image: native
    command: ["/bin/sh", "/cfg/serve.sh", "$ns", "$body"]
    env: [{name: POD_IP, valueFrom: {fieldRef: {fieldPath: status.podIP}}}]
    ports: [{containerPort: 8080}]
    volumeMounts: [{name: cfg, mountPath: /cfg}]
  volumes: [{name: cfg, configMap: {name: b572-script}}]
---
apiVersion: v1
kind: Service
metadata: {name: b572-web, namespace: $ns}
spec:
  type: NodePort
  selector: {app: b572-web}
  ports: [{port: 8080, targetPort: 8080, nodePort: $port}]
EOF
}

# ---- --self-test ----------------------------------------------------------------

self_test() {
	local bad=0 lsof ifc m
	check() { if [ "$1" = ok ]; then echo "ok    $2"; else echo "FAIL  $2"; bad=1; fi; }
	t() { if "$@"; then echo ok; else echo no; fi; }

	check "$(t body_is 'A' A)" "body_is: exact body"
	check "$(t body_is $'  A\n' A)" "body_is: surrounding whitespace ignored"
	check "$(t body_is '' nothing)" "body_is: empty answer is nothing"
	check "$([ "$(t body_is 'b548worker' A)" = no ] && echo ok)" "body_is: a stale body is not A"
	check "$([ "$(t body_is 'AB' A)" = no ] && echo ok)" "body_is: a longer body is not A"

	lsof='COMMAND  PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
k3sm    2184 _k3sm   62u  IPv4 0xb05f38acaea00751      0t0  TCP 100.64.1.1:31520 (LISTEN)
k3sm    2184 _k3sm   63u  IPv4 0x793ca02f40e67309      0t0  TCP 127.0.0.1:31520 (LISTEN)
k3sm   66718 _k3sm  168u  IPv6 0x3056016b06228df1      0t0  TCP *:31521 (LISTEN)
k3sm   66718 _k3sm  170u  IPv6 0x3056016b06228df2      0t0  TCP *:315200 (LISTEN)
nc     91200 _k3sm    3u  IPv4 0x967312696460f780      0t0  TCP *:8080 (LISTEN)'
	check "$([ "$(listen_count "$lsof" 31520)" = 2 ] && echo ok)" "listen_count: two binds of 31520, not 315200"
	check "$([ "$(listen_count "$lsof" 31521)" = 1 ] && echo ok)" "listen_count: one wildcard bind of 31521"
	check "$([ "$(listen_count "$lsof" 31522)" = 0 ] && echo ok)" "listen_count: none for an absent port"
	check "$([ "$(listen_count "none" 31520)" = 0 ] && echo ok)" "listen_count: the 'none' dump is zero"
	check "$([ "$(listen_addrs "$lsof" 31520)" = "100.64.1.1:31520 127.0.0.1:31520" ] && echo ok)" "listen_addrs: sorted bound addresses"
	check "$([ "$(listen_addrs "$lsof" 8080)" = "*:8080" ] && echo ok)" "listen_addrs: a wildcard nc bind"

	check "$(t bound_to_ip "100.64.1.29:8080" 100.64.1.29)" "bound_to_ip: the pod's own /32"
	check "$([ "$(t bound_to_ip "*:8080" 100.64.1.29)" = no ] && echo ok)" "bound_to_ip: the wildcard is a red"
	check "$([ "$(t bound_to_ip "*:8080 100.64.1.29:8080" 100.64.1.29)" = no ] && echo ok)" "bound_to_ip: a wildcard beside the /32 is a red"
	check "$([ "$(t bound_to_ip "100.64.1.30:8080" 100.64.1.29)" = no ] && echo ok)" "bound_to_ip: another pod's /32 is a red"
	check "$([ "$(t bound_to_ip "" 100.64.1.29)" = no ] && echo ok)" "bound_to_ip: no listener is a red"

	ifc='lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
	inet 100.64.1.29 netmask 0xffffffff
	inet 100.64.1.3 netmask 0xffffffff'
	check "$(t ip_aliased "$ifc" 100.64.1.29)" "ip_aliased: a present /32"
	check "$([ "$(t ip_aliased "$ifc" 100.64.1.2)" = no ] && echo ok)" "ip_aliased: no prefix match (.2 vs .29)"
	check "$([ "$(t ip_aliased "$ifc" 100.64.1.30)" = no ] && echo ok)" "ip_aliased: an absent /32"

	check "$([ "$(survivors $'101\n202\n303' '202 404')" = 202 ] && echo ok)" "survivors: one recorded pid still live"
	check "$([ -z "$(survivors '1010 2020' '101 202')" ] && echo ok)" "survivors: no substring match"
	check "$([ -z "$(survivors '' '101')" ] && echo ok)" "survivors: nothing live"

	check "$([ "$(port_rows $'a 31520 x\nb 315201\nc :31521' 31520 31521)" = $'a 31520 x\nc :31521' ] && echo ok)" "port_rows: whole-number matches only"
	check "$([ "$(port_rows 'nothing here' 31520)" = none ] && echo ok)" "port_rows: none"

	m="$(backend b572-a node-b A 31520)"
	case "$m" in *"nodeName: node-b"*) check ok "manifest: nodeName" ;; *) check no "manifest: nodeName" ;; esac
	case "$m" in *"nodeSelector: {kubernetes.io/os: darwin}"*) check ok "manifest: darwin nodeSelector" ;; *) check no "manifest: darwin nodeSelector" ;; esac
	case "$m" in *"{key: k3sm.io/provider, operator: Exists}"*) check ok "manifest: provider toleration (keyed)" ;; *) check no "manifest: provider toleration (keyed)" ;; esac
	case "$m" in *"{operator"*) check no "manifest: no key-less toleration" ;; *) check ok "manifest: no key-less toleration" ;; esac
	case "$m" in *"nodePort: 31520"*) check ok "manifest: NodePort" ;; *) check no "manifest: NodePort" ;; esac
	case "$m" in *'"/cfg/serve.sh", "b572-a", "A"'*) check ok "manifest: tagged argv carries the body" ;; *) check no "manifest: tagged argv carries the body" ;; esac
	case "$m" in *"fieldPath: status.podIP"*) check ok "manifest: POD_IP from the downward API" ;; *) check no "manifest: POD_IP from the downward API" ;; esac
	case "$m" in *"/opt/homebrew/bin/python3 /cfg/serve.py"*) check ok "manifest: a non-platform server" ;; *) check no "manifest: a non-platform server" ;; esac
	case "$m" in *"/usr/bin/nc"*) check no "manifest: no platform-binary nc" ;; *) check ok "manifest: no platform-binary nc" ;; esac

	if [ "$bad" = 0 ]; then echo "b572 self-test: green"; else echo "b572 self-test: RED"; fi
	return "$bad"
}

if [ "${1:-}" = --self-test ]; then
	self_test
	exit $?
fi

if [ "${K3SM_LAB_PRINT_MANIFESTS:-}" = 1 ]; then
	lab_tolerations_header
	backend b572-a "<worker-node>" A "$P1"
	exit 0
fi

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "LAB-PENDING: not a pass (B572 NodePort reuse repro needs K3SM_LAB=1 and the two-node rig)"
	exit 3
fi

# ---- LAB ------------------------------------------------------------------------
missing=""
for v in KUBECONFIG K3SM_B572_SERVER_NODE K3SM_B572_WORKER_NODE K3SM_B572_SERVER_SSH K3SM_B572_WORKER_SSH; do
	[ -n "${!v:-}" ] || missing="$missing $v"
done
if [ -n "$missing" ]; then
	echo "B572: required variable(s) unset:$missing (see the header of $0)" >&2
	exit 2
fi
KUBECTL="${KUBECTL:-kubectl}"
SERVER="$K3SM_B572_SERVER_NODE"
WORKER="$K3SM_B572_WORKER_NODE"
EVIDENCE="${K3SM_B572_EVIDENCE:-$(mktemp -d -t b572-evidence)}"
mkdir -p "$EVIDENCE"
kc() { "$KUBECTL" "$@"; }
# Remote commands need a login shell on the rig Macs.
on() { local host="$1"; shift; ssh -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"; }
ssh_of() { if [ "$1" = "$SERVER" ]; then echo "$K3SM_B572_SERVER_SSH"; else echo "$K3SM_B572_WORKER_SSH"; fi; }

kc get --raw /healthz >/dev/null || { echo "the cluster at \$KUBECONFIG is not serving" >&2; exit 2; }
for n in "$SERVER" "$WORKER"; do
	ready="$(kc get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
	[ "$ready" = True ] || { echo "B572: node $n is not Ready (got '${ready:-absent}')" >&2; exit 2; }
done
mesh_ip() { kc get meshpeers.net.k3sm.io "$1" -o jsonpath='{.spec.meshIP}'; }
SERVER_IP="$(mesh_ip "$SERVER")"
WORKER_IP="$(mesh_ip "$WORKER")"
[ -n "$SERVER_IP" ] && [ -n "$WORKER_IP" ] || { echo "B572: a MeshPeer mesh address is missing (server '$SERVER_IP', worker '$WORKER_IP')" >&2; exit 2; }
echo "==> k3sm B572 NodePort reuse (server $SERVER @ $SERVER_IP, worker $WORKER @ $WORKER_IP; p1 $P1, p2 $P2; evidence $EVIDENCE)"
lab_tolerations_header

PASS=0; FAIL=0
STEP=start
ladder() {
	if [ "$1" = ok ]; then
		echo "PASS  $2"; PASS=$((PASS + 1))
	else
		echo "FAIL  $2"; FAIL=$((FAIL + 1))
		dump "failed: $2"
	fi
}
obs() { echo "OBS   $*"; }

# lsof_on <node> <ports>: the LISTEN rows on those ports (root: the proxy runs as _k3sm).
lsof_on() { on "$(ssh_of "$1")" "sudo -n lsof -nP -iTCP:$2 -sTCP:LISTEN 2>/dev/null || true"; }
# procs_on <node>: pid ppid pgid user command of every nc on 8080 and every b572
# serve.sh / serve.py.
procs_on() { on "$(ssh_of "$1")" "sudo -n ps -axo pid=,ppid=,pgid=,user=,command= | grep -E '[n]c -l 8080|[s]erve[.](sh|py) b572-' || true"; }
# status_on <node>: the node daemon's status JSON (no root needed for the read).
status_on() { on "$(ssh_of "$1")" "k=\$(command -v k3sm || echo /Library/k3sm/k3sm); \$k status -o json 2>/dev/null || true"; }

# dump <label>: every node's NodePort and 8080 listeners, the nc/serve processes
# processes and the k3sm status rows naming the ports, into the log and evidence.
DUMPN=0
dump() {
	local n f
	DUMPN=$((DUMPN + 1))
	for n in "$SERVER" "$WORKER"; do
		f="$EVIDENCE/dump-$DUMPN-$n.txt"
		{
			echo "== dump $DUMPN [$STEP] $1: $n"
			echo "## NodePort listeners ($DUMP_PORTS)"; lsof_on "$n" "$DUMP_PORTS" | sed 's/^/  /'
			echo "## 8080 listeners"; lsof_on "$n" 8080 | sed 's/^/  /'
			echo "## nc / serve.sh / serve.py processes (pid ppid pgid user command)"; procs_on "$n" | sed 's/^/  /'
			echo "## k3sm status rows naming $P1 $P2 $((P2 + 1))"; port_rows "$(status_on "$n")" "$P1" "$P2" "$((P2 + 1))" | sed 's/^/  /'
		} 2>&1 | tee "$f"
	done
}

# dial <from-node> <ip> <port>: the answer an HTTP GET returns, fetched FROM that
# node; "nothing" when none.
dial() { norm "$(on "$(ssh_of "$1")" "curl -s --max-time 5 http://$2:$3/" 2>/dev/null || true)"; }

# matrix <port> <want>: dial the port on both mesh addresses from both nodes. An
# empty answer is retried twice (a transient connect miss); a
# wrong body is never retried. Prints "from->ip=body ..." and returns 0 iff
# every answer equals want.
matrix() {
	local port="$1" want="$2" from ip got tries out="" rc=0
	for from in "$SERVER" "$WORKER"; do
		for ip in "$SERVER_IP" "$WORKER_IP"; do
			tries=0
			while :; do
				got="$(dial "$from" "$ip" "$port")"
				[ "$got" = nothing ] && [ "$want" != nothing ] && [ "$tries" -lt 2 ] || break
				tries=$((tries + 1)); sleep 1
			done
			out="$out $from->$ip=$got"
			[ "$got" = "$want" ] || rc=1
		done
	done
	echo "${out# }"
	return "$rc"
}

NAMESPACES="b572-a b572-b b572-c"
cleanup() {
	set +e
	STEP=cleanup
	for ns in $NAMESPACES; do kc delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1; done
	for ns in $NAMESPACES; do kc wait --for=delete "namespace/$ns" --timeout=180s >/dev/null 2>&1; done
	dump "final"
}

# Preflight: no b572 namespace, no Service and no listener on p1/p2.
for ns in $NAMESPACES; do
	if kc get namespace "$ns" >/dev/null 2>&1; then
		echo "namespace $ns exists; deleting and waiting"
		kc delete namespace "$ns" --wait=false >/dev/null
		kc wait --for=delete "namespace/$ns" --timeout=180s >/dev/null || { echo "B572: namespace $ns still present after 180s" >&2; exit 2; }
	fi
done
held="$(kc get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{range .spec.ports[*]}{.nodePort}{","}{end}{"\n"}{end}' |
	awk -v a="$P1" -v b="$P2" '{ n = split($2, q, ","); for (i = 1; i <= n; i++) if (q[i] == a || q[i] == b) print $1 }')"
[ -z "$held" ] || { echo "B572: NodePort $P1/$P2 already held by: $held" >&2; exit 2; }
for n in "$SERVER" "$WORKER"; do
	out="$(lsof_on "$n" "$P1,$P2")"
	[ "$(listen_count "$out" "$P1")$(listen_count "$out" "$P2")" = 00 ] || { echo "B572: $n already listens on $P1/$P2:" >&2; echo "$out" >&2; exit 2; }
	stray="$(listen_addrs "$(lsof_on "$n" 8080)" 8080)"
	[ -z "$stray" ] || echo "WARN  $n already has 8080 listener(s) before any b572 pod: $stray (see the dump)"
done
trap cleanup EXIT
STEP=preflight; dump "before any b572 object"

# create <ns> <body> <port>: the namespace and backend; FAIL + exit 1 if not Ready.
create() {
	kc create namespace "$1" >/dev/null
	backend "$1" "$WORKER" "$2" "$3" | kc apply -f - >/dev/null
	if ! kc wait --for=condition=Ready pod/b572-web -n "$1" --timeout=180s >/dev/null; then
		ladder no "b572 $1 backend pod Ready"
		kc get events -n "$1" --sort-by=.lastTimestamp 2>&1 | tail -8
		exit 1
	fi
	ladder ok "b572.s0a $1 backend pod Ready on $WORKER (pod IP $(pod_ip "$1"))"
	local ip pids p addrs=""
	ip="$(pod_ip "$1")"
	pids="$(on "$K3SM_B572_WORKER_SSH" "sudo -n pgrep -f 'serve.py $1 ' || true" | xargs)"
	for p in $pids; do
		addrs="$addrs $(listen_addrs "$(on "$K3SM_B572_WORKER_SSH" "sudo -n lsof -nP -a -p $p -iTCP -sTCP:LISTEN 2>/dev/null || true")" 8080)"
	done
	addrs="$(echo "$addrs" | xargs)"
	if bound_to_ip "$addrs" "$ip"; then
		ladder ok "b572.s0b $1 listener bound to its pod IP ($addrs)"
	else
		ladder no "b572.s0b $1 listener bound to its pod IP $ip:8080, not * (got '${addrs:-no listener}' from serve.py pid(s) [${pids:-none}])"
	fi
}
pod_ip() { kc get pod b572-web -n "$1" -o jsonpath='{.status.podIP}'; }

# s.1 -----------------------------------------------------------------------------
STEP=s1
create b572-a A "$P1"
create b572-b B "$P2"
IP_A="$(pod_ip b572-a)"
if got="$(matrix "$P1" A)"; then ladder ok "b572.s1a p1 $P1 -> A from both nodes ($got)"; else ladder no "b572.s1a p1 $P1 -> A from both nodes ($got)"; fi
if got="$(matrix "$P2" B)"; then ladder ok "b572.s1b p2 $P2 -> B from both nodes ($got)"; else ladder no "b572.s1b p2 $P2 -> B from both nodes ($got)"; fi
dump "A and B live"

# Pod A's processes, recorded just before the delete: its serve.sh, serve.py and
# their children.
A_TOP="$(on "$K3SM_B572_WORKER_SSH" "sudo -n pgrep -f 'serve[.](sh|py) b572-a ' || true" | xargs)"
A_PIDS="$A_TOP"
for p in $A_TOP; do A_PIDS="$A_PIDS $(on "$K3SM_B572_WORKER_SSH" "sudo -n pgrep -P $p || true" | xargs)"; done
A_PIDS="$(echo "$A_PIDS" | tr ' ' '\n' | sort -un | xargs)"
obs "pod A pod IP $IP_A, processes [$A_PIDS]"

# s.2 -----------------------------------------------------------------------------
STEP=s2
kc delete namespace b572-a --wait=true --timeout=180s >/dev/null || ladder no "b572.s2  namespace b572-a deleted within 180 s"
n=0; got=""; lis=""; dial_ok=no; lis_ok=no
while :; do
	if got="$(matrix "$P1" nothing)"; then dial_ok=yes; else dial_ok=no; fi
	lis=""; lis_ok=yes
	for node in "$SERVER" "$WORKER"; do
		c="$(listen_count "$(lsof_on "$node" "$P1")" "$P1")"
		lis="${lis:+$lis }$node=$c"
		[ "$c" = 0 ] || lis_ok=no
	done
	[ "$dial_ok$lis_ok" = yesyes ] && break
	[ "$n" -ge 60 ] && break
	sleep 5; n=$((n + 5))
done
if [ "$dial_ok" = yes ]; then
	ladder ok "b572.s2a p1 $P1 answers nothing from both nodes after the delete ($got)"
else
	ladder no "b572.s2a p1 $P1 answers nothing from both nodes after the delete, within 60 s ($got)"
fi
if [ "$lis_ok" = yes ]; then
	ladder ok "b572.s2b no listener on p1 $P1 on either node ($lis)"
else
	ladder no "b572.s2b no listener on p1 $P1 on either node, within 60 s ($lis)"
fi
left="$(survivors "$(on "$K3SM_B572_WORKER_SSH" "ps -axo pid=")" "$A_PIDS")"
if [ -z "$left" ]; then
	ladder ok "b572.s2c no process of pod A survives on $WORKER (recorded [$A_PIDS])"
else
	ladder no "b572.s2c no process of pod A survives on $WORKER (still running: $left)"
fi
if ip_aliased "$(on "$K3SM_B572_WORKER_SSH" "ifconfig lo0")" "$IP_A"; then
	obs "pod A's IP $IP_A is STILL a lo0 alias on $WORKER after the delete"
else
	obs "pod A's IP $IP_A is no longer a lo0 alias on $WORKER"
fi
dump "after deleting b572-a"

# s.3 -----------------------------------------------------------------------------
STEP=s3
create b572-c C "$P1"
IP_C="$(pod_ip b572-c)"
if [ "$IP_A" = "$IP_C" ]; then obs "pod C reused pod A's IP $IP_A"; else obs "pod C got $IP_C (pod A had $IP_A): no reuse this run"; fi
r=1
while [ "$r" -le 5 ]; do
	if got="$(matrix "$P1" C)"; then ladder ok "b572.s3a.$r p1 $P1 -> C from both nodes ($got)"; else ladder no "b572.s3a.$r p1 $P1 -> C from both nodes ($got)"; fi
	if got="$(matrix "$P2" B)"; then ladder ok "b572.s3b.$r p2 $P2 -> B still from both nodes ($got)"; else ladder no "b572.s3b.$r p2 $P2 -> B still from both nodes ($got)"; fi
	r=$((r + 1))
done
dump "C and B live"

echo "----------------------------------------"
echo "B572: $PASS passed, $FAIL failed (evidence $EVIDENCE)"
[ "$FAIL" -eq 0 ] || exit 1
echo "B572 NodePort reuse repro GREEN"
