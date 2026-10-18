#!/usr/bin/env bash
#
# k3sm M10-lab gate: per-pod IP and cluster DNS identity across a two-Mac cluster.
#
# This is the M10-lab row in hack/acceptance/phases.json (tier lab, manual: true). It
# runs against the RUNNING two-node cluster in $KUBECONFIG and boots nothing. Every
# object it creates lives in one namespace minted per run, which the exit trap deletes.
#
# Assertions (`--plan` prints them; the names are the run log's verdict keys):
#   m10.1  two native probe pods, pinned one per node, each carry a pod IP, the two
#          differ, and each equals the in-pod K3SM_POD_IP (the /32 the bind shim pins)
#   m10.2  each probe pod IP is inside its node's spec.podCIDR and inside the cluster
#          pod CIDR, the K3SM_CLUSTER_CIDRS entry that holds that node range
#   m10.3  each probe pod IP differs from its node's InternalIP
#   m10.4  a 2-replica StatefulSet behind a headless Service lands one replica per node
#          (required anti-affinity on kubernetes.io/hostname), and an in-pod A query of
#          the Service name, from a pod on each node, returns exactly both replica IPs
#   m10.5  an in-pod SRV query for the named port, from each node, returns both
#          replicas' DNS names (<pod>.<svc>.<ns>.svc.<domain>) on that port
#   m10.6  an in-pod PTR query of each replica IP, from each node, returns that
#          replica's DNS name
#   m10.7  cross-node pod-to-pod by pod IP: each probe dials the replica on the OTHER
#          node at its pod IP and reads that replica's name back. Asserted because
#          docs/user/multi-node.md claims it ("Nodes are connected by a wireguard
#          mesh (the `MeshPeer` model), so Pods and Services can be reached across
#          machines.").
#
# How the in-pod lookups are made. A native pod on a cluster-first dnsPolicy gets the
# cluster DNS configuration as K3SM_DNS_* environment. The probe sends each query
# with /usr/bin/dig straight to $K3SM_DNS_SERVER (its node's resolver VIP), from
# inside the pod. That proves the records a pod receives on each node; it does NOT
# exercise a res_query() interpose in the getaddrinfo shim, which interposes
# getaddrinfo, bind and connect only, so this gate says nothing about libresolv
# callers inside a shimmed process. The cross-node dial runs under /bin/bash (a
# shimmed shell, so the connect rung source-pins it to the probe's own /32); the
# replica answers through /usr/bin/nc bound to its own pod IP.
#
# Pods follow the lab rig rules: nodeName AND the darwin nodeSelector on the probes,
# the StatefulSet held to the two nodes by required node affinity; tolerations are
# k3sm.io/provider (keyed) plus only what the operator names; scripts ride a
# ConfigMap (a native pod cannot read /tmp); Events are selected by involvedObject.uid.
#
# Environment:
#   K3SM_LAB=1                  run the gate (anything else: PENDING, exit 0)
#   KUBECONFIG                  the admin kubeconfig of the running cluster
#   KUBECTL                     kubectl binary (default: kubectl)
#   K3SM_M10_NODES              "<node-a> <node-b>": the two nodes (default: the first
#                               two Ready darwin nodes, sorted by name)
#   K3SM_M10_PORT               the replicas' named port (default 18759)
#   K3SM_LAB_TOLERATE_KEYS      taint keys every pod tolerates with Exists
#                               (hack/lab/lib/tolerations.sh)
#   K3SM_LAB_TOLERATE_TAINTS    space-separated exact taints, each `key=value:Effect`
#                               (or `key:Effect` for an empty value), tolerated with
#                               operator Equal, that value and that effect only
# A NoSchedule or NoExecute taint on either node that neither list tolerates refuses
# the run (exit 2) and names the taint, rather than leaving a pod Pending or evicted.
#
# Exit: 0 every assertion held; 1 an assertion failed; 2 a precondition refused the run
# (kubectl missing, the cluster not serving, fewer than two Ready darwin nodes, an
# untolerated taint, a bad argument) and nothing was created. K3SM_LAB unset prints
# PENDING and exits 0: a skip, never a pass.
#
# Usage:  hack/lab/m10.sh --plan          # the assertions; contacts nothing
#         hack/lab/m10.sh --self-test     # offline checks of this script
#         K3SM_LAB=1 KUBECONFIG=<admin kubeconfig> hack/lab/m10.sh [<evidence-dir>]
#             (default evidence dir: a new mktemp directory)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/tolerations.sh
. "$HERE/lib/tolerations.sh"

GATE_NAME="M10-lab"
MODE="lab"
PORT="${K3SM_M10_PORT:-18759}"
PORT_NAME="web"
STS="m10-web"
PROBE_WAIT=120

# The assertion table: `name|statement`. --plan prints it, the run reports against it,
# and --self-test checks that every name is unique and every name is reported.
ASSERTIONS=(
	"m10.1|two native pods pinned one per node carry distinct pod IPs, each equal to the in-pod K3SM_POD_IP"
	"m10.2|each pod IP is inside its node's spec.podCIDR and the cluster pod CIDR (K3SM_CLUSTER_CIDRS)"
	"m10.3|each pod IP differs from its node's InternalIP"
	"m10.4|a headless Service over a 2-replica StatefulSet (one replica per node) answers an in-pod A query, on each node, with exactly both replica IPs"
	"m10.5|an in-pod SRV query for the named port, on each node, returns both replicas' DNS names on that port"
	"m10.6|an in-pod PTR query of each replica IP, on each node, returns that replica's DNS name"
	"m10.7|cross-node pod-to-pod by pod IP: each probe reads the name of the replica on the other node"
)
# shellcheck disable=SC2016 # the doc line's literal backticks, not an expansion
CROSS_NODE_CLAIM='docs/user/multi-node.md: "Nodes are connected by a **wireguard mesh** (the `MeshPeer` model), so Pods and Services can be reached across machines."'

# ---- pure helpers (the --self-test surface) -----------------------------------------

# ip_to_int <a.b.c.d>: the address as an integer; fails on anything else.
ip_to_int() {
	local ip="$1" o n=0 count=0 rest
	rest="$ip."
	while [ -n "$rest" ]; do
		o="${rest%%.*}"
		rest="${rest#*.}"
		case "$o" in '' | *[!0-9]*) return 1 ;; esac
		[ "${#o}" -le 3 ] && [ "$o" -le 255 ] || return 1
		n=$(((n << 8) + 10#$o))
		count=$((count + 1))
	done
	[ "$count" -eq 4 ] || return 1
	echo "$n"
}

# cidr_parts <a.b.c.d/len>: "<network-int> <mask-int> <len>"; fails on a malformed CIDR.
cidr_parts() {
	local cidr="$1" addr len n mask
	case "$cidr" in */*) ;; *) return 1 ;; esac
	addr="${cidr%/*}"
	len="${cidr#*/}"
	case "$len" in '' | *[!0-9]*) return 1 ;; esac
	[ "$len" -le 32 ] || return 1
	n="$(ip_to_int "$addr")" || return 1
	if [ "$len" -eq 0 ]; then mask=0; else mask=$(((0xffffffff << (32 - len)) & 0xffffffff)); fi
	echo "$((n & mask)) $mask $len"
}

# in_cidr <ip> <cidr>: 0 iff the address is inside the CIDR.
in_cidr() {
	local n parts net mask
	n="$(ip_to_int "$1")" || return 1
	parts="$(cidr_parts "$2")" || return 1
	net="${parts%% *}"
	mask="${parts#* }"
	mask="${mask%% *}"
	[ $((n & mask)) -eq "$net" ]
}

# cidr_within <inner> <outer>: 0 iff the inner range lies wholly inside the outer one.
cidr_within() {
	local inner outer ilen olen
	inner="$(cidr_parts "$1")" || return 1
	outer="$(cidr_parts "$2")" || return 1
	ilen="${inner##* }"
	olen="${outer##* }"
	[ "$ilen" -ge "$olen" ] || return 1
	in_cidr "$(int_to_ip "${inner%% *}")" "$2"
}

# int_to_ip <n>: the dotted quad.
int_to_ip() {
	local n="$1"
	echo "$(((n >> 24) & 255)).$(((n >> 16) & 255)).$(((n >> 8) & 255)).$((n & 255))"
}

# pod_cidr_of <comma-list> <node-podCIDR>: the K3SM_CLUSTER_CIDRS entry that holds the
# node's pod range (the cluster pod CIDR; the Service CIDR never holds it). Empty when
# no entry does.
pod_cidr_of() {
	local list="$1" node_cidr="$2" c
	local IFS=,
	for c in $list; do
		if cidr_within "$node_cidr" "$c"; then
			echo "$c"
			return 0
		fi
	done
	return 1
}

# words_sorted <words...>: the words, sorted and space-joined.
words_sorted() {
	if [ "$#" -eq 0 ]; then return 0; fi
	printf '%s\n' "$@" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'
}

# commas_sorted <comma-list>: the comma-separated items, sorted and comma-joined.
commas_sorted() {
	[ -n "$1" ] || return 0
	printf '%s\n' "$1" | tr ',' '\n' | sed '/^$/d' | LC_ALL=C sort | tr '\n' ',' | sed 's/,$//'
}

# probe_field <log> <key>: the last value the probe reported for key (`M10 key=value`).
probe_field() {
	printf '%s\n' "$1" | awk -v k="M10 $2=" 'index($0, k) == 1 { v = substr($0, length(k) + 1) } END { print v }'
}

# taint_spec_valid <key=value:Effect>: 0 iff the exact-taint spec is well formed.
taint_spec_valid() {
	local spec="$1" effect kv key value
	case "$spec" in *:*) ;; *) return 1 ;; esac
	effect="${spec##*:}"
	kv="${spec%:*}"
	case "$effect" in NoSchedule | PreferNoSchedule | NoExecute) ;; *) return 1 ;; esac
	key="${kv%%=*}"
	value=""
	case "$kv" in *=*) value="${kv#*=}" ;; esac
	lab_tol_valid_key "$key" || return 1
	[ "${#value}" -le 63 ] || return 1
	[ -z "$value" ] || [[ "$value" =~ ^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$ ]] || return 1
}

# exact_taints: the validated K3SM_LAB_TOLERATE_TAINTS specs, space-joined; a bad spec
# prints a usage error and exits 2.
exact_taints() {
	local out="" spec restore_glob=0
	case "$-" in *f*) ;; *)
		restore_glob=1
		set -f
		;;
	esac
	for spec in ${K3SM_LAB_TOLERATE_TAINTS:-}; do
		if ! taint_spec_valid "$spec"; then
			[ "$restore_glob" = 1 ] && set +f
			echo "K3SM_LAB_TOLERATE_TAINTS: '$spec' is not key=value:Effect (Effect NoSchedule, PreferNoSchedule or NoExecute)" >&2
			exit 2
		fi
		out="${out:+$out }$spec"
	done
	[ "$restore_glob" = 1 ] && set +f
	printf '%s' "$out"
}

# normalize_taint <key=value:Effect | key:Effect>: the spec with an explicit `=`.
normalize_taint() {
	local spec="$1" kv
	kv="${spec%:*}"
	case "$kv" in *=*) printf '%s' "$spec" ;; *) printf '%s=:%s' "$kv" "${spec##*:}" ;; esac
}

# tolerations_yaml: the body of the YAML flow sequence every pod carries.
tolerations_yaml() {
	local line spec specs kv key value effect
	line="$(lab_tolerations_yaml "")" || exit 2
	specs="$(exact_taints)" || exit 2
	for spec in $specs; do
		spec="$(normalize_taint "$spec")"
		effect="${spec##*:}"
		kv="${spec%:*}"
		key="${kv%%=*}"
		value="${kv#*=}"
		line="$line, {key: $key, operator: Equal, value: \"$value\", effect: $effect}"
	done
	printf '%s\n' "$line"
}

# untolerated <taint-lines>: the NoSchedule/NoExecute taints (one `key=value:Effect` a
# line) that the provider entry, K3SM_LAB_TOLERATE_KEYS and K3SM_LAB_TOLERATE_TAINTS
# leave untolerated, space-joined.
untolerated() {
	local lines="$1" t key effect keys exact out="" spec specs
	keys=" $(lab_tol_keys) " || exit 2
	specs="$(exact_taints)" || exit 2
	exact=" "
	for spec in $specs; do exact="$exact$(normalize_taint "$spec") "; done
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		effect="${t##*:}"
		key="${t%%=*}"
		[ "$effect" = PreferNoSchedule ] && continue
		[ "$key" = k3sm.io/provider ] && continue
		case "$keys" in *" $key "*) continue ;; esac
		case "$exact" in *" $t "*) continue ;; esac
		out="${out:+$out }$t"
	done <<<"$lines"
	printf '%s' "$out"
}

# ---- in-pod scripts (delivered by ConfigMap) ----------------------------------------

# serve_script: a replica answers its own pod name on <POD_IP>:<M10_PORT>, one
# connection at a time, bound to its pod IP rather than the wildcard.
serve_script() {
	cat <<'SERVE'
#!/bin/bash
while :; do
	printf '%s\n' "$POD_NAME" | /usr/bin/nc -l "$POD_IP" "$M10_PORT" >/dev/null 2>&1 || sleep 1
done
SERVE
}

# probe_script: the in-pod probe. It reports `M10 key=value` lines between `M10 begin`
# and `M10 end`, then idles so its pod IP stays allocated while the gate reads it.
probe_script() {
	cat <<'PROBE'
#!/bin/bash
emit() { printf 'M10 %s\n' "$*"; }
emit begin
domain="${K3SM_DNS_DOMAIN:-}"
domain="${domain%.}"
server="${K3SM_DNS_SERVER:-}"
port="${K3SM_DNS_PORT:-53}"
emit "pod_ip=${K3SM_POD_IP:-}"
emit "cluster_cidrs=${K3SM_CLUSTER_CIDRS:-}"
emit "dns_server=$server"
emit "dns_port=$port"
emit "dns_domain=$domain"
DIG=/usr/bin/dig
if [ -x "$DIG" ]; then emit "dig=$DIG"; else emit "dig=missing"; fi
q() { "$DIG" +short +time=2 +tries=2 -p "$port" "@$server" "$@" 2>/dev/null | sed 's/\.$//'; }
joined() { LC_ALL=C sort | tr '\n' "$1" | sed "s/$1\$//"; }
deadline=$((SECONDS + M10_WAIT))
fqdn="$M10_SVC.$M10_NS.svc.$domain"
emit "fqdn=$fqdn"
a="" srv=""
if [ -x "$DIG" ] && [ -n "$server" ] && [ -n "$domain" ]; then
	while :; do
		a="$(q A "$fqdn" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | joined ' ')"
		[ "$(printf '%s' "$a" | wc -w | tr -d ' ')" -ge "$M10_WANT" ] && break
		[ "$SECONDS" -ge "$deadline" ] && break
		sleep 2
	done
	while :; do
		srv="$(q SRV "_$M10_PORT_NAME._tcp.$fqdn" | awk 'NF == 4 { print $3 ":" $4 }' | joined ',')"
		[ "$(printf '%s' "$srv" | tr ',' ' ' | wc -w | tr -d ' ')" -ge "$M10_WANT" ] && break
		[ "$SECONDS" -ge "$deadline" ] && break
		sleep 2
	done
	for ip in $M10_PTR_IPS; do
		emit "ptr.$ip=$(q -x "$ip" | grep -v '^;' | joined ',')"
	done
fi
emit "a=$a"
emit "srv=$srv"
tcp_banner() {
	(
		exec 3<>"/dev/tcp/$1/$2" || exit 1
		IFS= read -r -t 5 line <&3 || exit 1
		printf '%s\n' "$line"
	) 2>/dev/null &
	pid=$!
	(sleep 10 && kill "$pid") >/dev/null 2>&1 &
	killer=$!
	wait "$pid"
	rc=$?
	kill "$killer" 2>/dev/null
	wait "$killer" 2>/dev/null
	return "$rc"
}
tcp=""
if [ -n "${M10_PEER_IP:-}" ]; then
	while :; do
		tcp="$(tcp_banner "$M10_PEER_IP" "$M10_PORT" || true)"
		[ "$tcp" = "$M10_PEER_NAME" ] && break
		[ "$SECONDS" -ge "$deadline" ] && break
		sleep 2
	done
fi
emit "tcp=$tcp"
emit end
while :; do sleep 3600; done
PROBE
}

# ---- manifests ------------------------------------------------------------------------

# scripts_configmap <ns>
scripts_configmap() {
	local ns="$1"
	echo "apiVersion: v1"
	echo "kind: ConfigMap"
	echo "metadata: {name: m10-scripts, namespace: $ns}"
	echo "data:"
	echo "  serve.sh: |"
	serve_script | sed 's/^/    /'
	echo "  probe.sh: |"
	probe_script | sed 's/^/    /'
}

# web_manifest <ns> <hostname-a> <hostname-b> <tolerations>: the headless Service and
# the StatefulSet, held to the two nodes, one replica per node.
web_manifest() {
	local ns="$1" ha="$2" hb="$3" tol="$4"
	cat <<EOF
apiVersion: v1
kind: Service
metadata: {name: $STS, namespace: $ns}
spec:
  clusterIP: None
  selector: {app: $STS}
  ports: [{name: $PORT_NAME, port: $PORT, targetPort: $PORT, protocol: TCP}]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: $STS, namespace: $ns}
spec:
  serviceName: $STS
  replicas: 2
  podManagementPolicy: Parallel
  selector: {matchLabels: {app: $STS}}
  template:
    metadata: {labels: {app: $STS}}
    spec:
      nodeSelector: {kubernetes.io/os: darwin}
      tolerations: [$tol]
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions: [{key: kubernetes.io/hostname, operator: In, values: ["$ha", "$hb"]}]
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector: {matchLabels: {app: $STS}}
            topologyKey: kubernetes.io/hostname
      containers:
      - name: web
        image: native
        command: ["/bin/bash", "/m10/serve.sh"]
        env:
        - {name: POD_NAME, valueFrom: {fieldRef: {fieldPath: metadata.name}}}
        - {name: POD_IP, valueFrom: {fieldRef: {fieldPath: status.podIP}}}
        - {name: M10_PORT, value: "$PORT"}
        ports: [{name: $PORT_NAME, containerPort: $PORT}]
        volumeMounts: [{name: m10, mountPath: /m10}]
      volumes: [{name: m10, configMap: {name: m10-scripts}}]
EOF
}

# probe_manifest <ns> <name> <node> <tolerations> <ptr-ips> <peer-ip> <peer-name>
probe_manifest() {
	local ns="$1" name="$2" node="$3" tol="$4" ptr="$5" peer_ip="$6" peer_name="$7"
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $name, namespace: $ns, labels: {app: m10-probe}}
spec:
  nodeName: $node
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$tol]
  restartPolicy: Never
  containers:
  - name: probe
    image: native
    command: ["/bin/bash", "/m10/probe.sh"]
    env:
    - {name: M10_NS, valueFrom: {fieldRef: {fieldPath: metadata.namespace}}}
    - {name: M10_SVC, value: "$STS"}
    - {name: M10_PORT, value: "$PORT"}
    - {name: M10_PORT_NAME, value: "$PORT_NAME"}
    - {name: M10_WANT, value: "2"}
    - {name: M10_WAIT, value: "$PROBE_WAIT"}
    - {name: M10_PTR_IPS, value: "$ptr"}
    - {name: M10_PEER_IP, value: "$peer_ip"}
    - {name: M10_PEER_NAME, value: "$peer_name"}
    volumeMounts: [{name: m10, mountPath: /m10}]
  volumes: [{name: m10, configMap: {name: m10-scripts}}]
EOF
}

# ---- --plan -----------------------------------------------------------------------------

plan() {
	local row
	echo "M10-lab gate: PLAN ONLY (contacts nothing)"
	echo "assertions:"
	for row in "${ASSERTIONS[@]}"; do
		printf '  %-6s %s\n' "${row%%|*}" "${row#*|}"
	done
	echo "cross-node claim (m10.7 is asserted because the docs claim it):"
	echo "  $CROSS_NODE_CLAIM"
	echo "in-pod DNS path: /usr/bin/dig from inside the pod to \$K3SM_DNS_SERVER; not a res_query() interpose (the getaddrinfo shim has none)"
	echo "exit: 0 every assertion held, 1 an assertion failed, 2 a precondition refused the run; K3SM_LAB unset: PENDING, exit 0"
}

# ---- --self-test --------------------------------------------------------------------------

self_test() {
	local bad=0 row name names="" dup m tmp fake out code src t
	check() { if [ "$1" = ok ]; then echo "ok    $2"; else echo "FAIL  $2"; bad=1; fi; }
	yes_if() { if "$@"; then echo ok; else echo no; fi; }
	no_if() { if "$@"; then echo no; else echo ok; fi; }

	if command -v shellcheck >/dev/null 2>&1; then
		if out="$(shellcheck -x "$HERE/m10.sh" 2>&1)"; then
			check ok "shellcheck: clean"
		else
			printf '%s\n' "$out"
			check no "shellcheck: clean"
		fi
	else
		echo "skip  shellcheck (not installed)"
	fi
	if probe_script | bash -n 2>/dev/null && serve_script | bash -n 2>/dev/null; then
		check ok "in-pod scripts parse (bash -n)"
	else
		check no "in-pod scripts parse (bash -n)"
	fi

	# Assertion names: unique, each reported by exactly the run (a verdict call), and
	# no verdict reports an undeclared name.
	src="$(cat "$HERE/m10.sh")"
	for row in "${ASSERTIONS[@]}"; do
		name="${row%%|*}"
		case " $names " in *" $name "*) dup="$name" ;; esac
		names="$names $name"
		case "$src" in *"verdict $name "*) ;; *) check no "assertion $name is reported by a verdict call" ;; esac
	done
	check "$([ -z "${dup:-}" ] && echo ok)" "assertion names unique (${#ASSERTIONS[@]}:${names})"
	t="$(printf '%s\n' "$src" | grep -oE 'verdict m10\.[0-9]+ ' | sed 's/^verdict //; s/ $//' | sort -u | tr '\n' ' ')"
	for name in $t; do
		case " $names " in *" $name "*) ;; *) check no "verdict $name is a declared assertion" ;; esac
	done

	check "$([ "$(ip_to_int 100.64.1.5)" = $(((100 << 24) + (64 << 16) + (1 << 8) + 5)) ] && echo ok)" "ip_to_int: a dotted quad"
	check "$(no_if ip_to_int 100.64.1)" "ip_to_int: three octets refused"
	check "$(no_if ip_to_int 100.64.1.256)" "ip_to_int: octet over 255 refused"
	check "$(yes_if in_cidr 100.64.1.5 100.64.0.0/10)" "in_cidr: inside the /10"
	check "$(no_if in_cidr 100.128.0.1 100.64.0.0/10)" "in_cidr: just past the /10"
	check "$(yes_if in_cidr 100.64.1.5 100.64.1.0/24)" "in_cidr: inside the node /24"
	check "$(no_if in_cidr 100.64.0.5 100.64.1.0/24)" "in_cidr: another node's /24"
	check "$(no_if in_cidr 100.64.1.5 100.64.1.0)" "in_cidr: a CIDR without a length refused"
	check "$(yes_if cidr_within 100.64.1.0/24 100.64.0.0/10)" "cidr_within: node /24 in the cluster /10"
	check "$(no_if cidr_within 100.64.0.0/10 100.64.1.0/24)" "cidr_within: the wider range is not within"
	check "$([ "$(pod_cidr_of 10.43.0.0/16,100.64.0.0/10 100.64.1.0/24)" = 100.64.0.0/10 ] && echo ok)" "pod_cidr_of: picks the entry holding the node range, in any order"
	check "$(no_if pod_cidr_of 10.43.0.0/16 100.64.1.0/24)" "pod_cidr_of: no entry holds it"
	check "$([ "$(words_sorted 100.64.1.9 100.64.0.7)" = "100.64.0.7 100.64.1.9" ] && echo ok)" "words_sorted"
	check "$([ "$(commas_sorted 'b,a,')" = a,b ] && echo ok)" "commas_sorted"
	t=$'M10 begin\nnoise\nM10 a=1.2.3.4 5.6.7.8\nM10 ptr.1.2.3.4=x.y\nM10 a=9.9.9.9\nM10 end'
	check "$([ "$(probe_field "$t" a)" = 9.9.9.9 ] && echo ok)" "probe_field: the last report wins"
	check "$([ "$(probe_field "$t" ptr.1.2.3.4)" = x.y ] && echo ok)" "probe_field: a dotted key"
	check "$([ -z "$(probe_field "$t" srv)" ] && echo ok)" "probe_field: absent is empty"

	check "$(yes_if taint_spec_valid example.io/estate-off=one-node:NoExecute)" "taint spec: key=value:Effect"
	check "$(yes_if taint_spec_valid example.io/drain:NoSchedule)" "taint spec: empty value"
	check "$(no_if taint_spec_valid example.io/x=v:Sometimes)" "taint spec: unknown effect refused"
	check "$(no_if taint_spec_valid 'example.io/x=bad value:NoExecute')" "taint spec: bad value refused"
	check "$([ "$(normalize_taint example.io/drain:NoSchedule)" = example.io/drain=:NoSchedule ] && echo ok)" "normalize_taint: explicit ="
	t="$(K3SM_LAB_TOLERATE_KEYS="" K3SM_LAB_TOLERATE_TAINTS="example.io/estate-off=one-node:NoExecute" tolerations_yaml)"
	check "$([ "$t" = '{key: k3sm.io/provider, operator: Exists}, {key: example.io/estate-off, operator: Equal, value: "one-node", effect: NoExecute}' ] && echo ok)" "tolerations: provider keyed, exact taint Equal with its value and effect"
	case "$t" in *"{operator"*) check no "tolerations: no key-less entry" ;; *) check ok "tolerations: no key-less entry" ;; esac
	t=$'k3sm.io/provider=:NoSchedule\nexample.io/estate-off=one-node:NoExecute\nexample.io/soft=x:PreferNoSchedule'
	check "$([ "$(K3SM_LAB_TOLERATE_KEYS="" K3SM_LAB_TOLERATE_TAINTS="" untolerated "$t")" = example.io/estate-off=one-node:NoExecute ] && echo ok)" "untolerated: an unnamed NoExecute taint is reported"
	check "$([ -z "$(K3SM_LAB_TOLERATE_KEYS="" K3SM_LAB_TOLERATE_TAINTS="example.io/estate-off=one-node:NoExecute" untolerated "$t")" ] && echo ok)" "untolerated: the exact spec tolerates it"
	check "$([ -n "$(K3SM_LAB_TOLERATE_KEYS="" K3SM_LAB_TOLERATE_TAINTS="example.io/estate-off=other:NoExecute" untolerated "$t")" ] && echo ok)" "untolerated: a different value does not"

	m="$(probe_manifest ns-x m10-probe-a node-a "$(K3SM_LAB_TOLERATE_KEYS="" K3SM_LAB_TOLERATE_TAINTS="" tolerations_yaml)" "1.2.3.4 5.6.7.8" 5.6.7.8 m10-web-1)"
	case "$m" in *"nodeName: node-a"*) check ok "probe manifest: nodeName" ;; *) check no "probe manifest: nodeName" ;; esac
	case "$m" in *"nodeSelector: {kubernetes.io/os: darwin}"*) check ok "probe manifest: darwin nodeSelector" ;; *) check no "probe manifest: darwin nodeSelector" ;; esac
	case "$m" in *'command: ["/bin/bash", "/m10/probe.sh"]'*'configMap: {name: m10-scripts}'*) check ok "probe manifest: script by ConfigMap" ;; *) check no "probe manifest: script by ConfigMap" ;; esac
	m="$(web_manifest ns-x host-a host-b "{key: k3sm.io/provider, operator: Exists}")"
	case "$m" in *"clusterIP: None"*"name: $PORT_NAME, port: $PORT"*) check ok "web manifest: headless Service with the named port" ;; *) check no "web manifest: headless Service with the named port" ;; esac
	case "$m" in *"podAntiAffinity:"*"topologyKey: kubernetes.io/hostname"*) check ok "web manifest: required anti-affinity on hostname" ;; *) check no "web manifest: required anti-affinity on hostname" ;; esac
	case "$m" in *'values: ["host-a", "host-b"]'*) check ok "web manifest: held to the two nodes" ;; *) check no "web manifest: held to the two nodes" ;; esac
	case "$m" in *"nodeSelector: {kubernetes.io/os: darwin}"*) check ok "web manifest: darwin nodeSelector" ;; *) check no "web manifest: darwin nodeSelector" ;; esac
	m="$(scripts_configmap ns-x)"
	case "$m" in *"  probe.sh: |"*"    emit end"*"  serve.sh: |"*|*"  serve.sh: |"*"  probe.sh: |"*"    emit end"*) check ok "ConfigMap: both scripts, indented" ;; *) check no "ConfigMap: both scripts, indented" ;; esac

	# The honesty contract, run as a child process.
	out="$(env -u K3SM_LAB bash "$HERE/m10.sh" 2>&1)" && code=0 || code=$?
	case "$out" in *PENDING*) ;; *) code=99 ;; esac
	check "$([ "$code" = 0 ] && echo ok)" "K3SM_LAB unset: PENDING, exit 0 (got $code)"

	out="$(bash "$HERE/m10.sh" --plan 2>&1)" && code=0 || code=$?
	for row in "${ASSERTIONS[@]}"; do
		case "$out" in *"${row%%|*} "*) ;; *) code=98 ;; esac
	done
	check "$([ "$code" = 0 ] && echo ok)" "--plan: exit 0, every assertion listed"

	tmp="$(mktemp -d "${TMPDIR:-/tmp}/m10-selftest.XXXXXX")"
	fake="$tmp/kubectl"
	cat >"$fake" <<'FAKE'
#!/bin/bash
printf '%s\n' "$*" >>"${0%/*}/calls.log"
case "$*" in
*"get --raw /healthz"*) echo ok ;;
*"get nodes"*) printf 'only-node\tTrue\n' ;;
esac
exit 0
FAKE
	chmod +x "$fake"
	out="$(K3SM_LAB=1 KUBECTL="$fake" K3SM_M10_NODES="" bash "$HERE/m10.sh" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "one Ready node: refused, exit 2 (got $code)"
	if grep -Eq '(^| )(apply|create|delete|label|patch)( |$)' "$tmp/calls.log" 2>/dev/null || [ -e "$tmp/evidence" ]; then
		check no "one Ready node: nothing created"
	else
		check ok "one Ready node: nothing created"
	fi
	out="$(K3SM_LAB=1 KUBECTL="$tmp/no-such-kubectl" bash "$HERE/m10.sh" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/evidence" ] && echo ok)" "kubectl missing: refused, exit 2, nothing created (got $code)"
	out="$(K3SM_LAB=1 KUBECTL="$fake" K3SM_LAB_TOLERATE_TAINTS="bad" bash "$HERE/m10.sh" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "a malformed K3SM_LAB_TOLERATE_TAINTS: refused, exit 2 (got $code)"
	rm -rf "$tmp"

	if [ "$bad" = 0 ]; then echo "m10 self-test: green"; else echo "m10 self-test: RED"; fi
	return "$bad"
}

case "${1:-}" in
--plan)
	plan
	exit 0
	;;
--self-test)
	self_test
	exit $?
	;;
-h | --help)
	sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
	exit 0
	;;
-*)
	echo "m10.sh: unknown option $1 (try --plan, --self-test)" >&2
	exit 2
	;;
esac

# ---- lab guard ---------------------------------------------------------------------------
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M10-lab gate: PENDING (two Macs). Set K3SM_LAB=1 against a running two-node cluster to run it; this is NOT a pass."
	exit 0
fi

# ---- preconditions (exit 2, nothing created) ---------------------------------------------
refuse() {
	echo "M10-lab gate: REFUSED: $*" >&2
	exit 2
}
KUBECTL="${KUBECTL:-kubectl}"
command -v "$KUBECTL" >/dev/null 2>&1 || refuse "kubectl not found ($KUBECTL); the gate needs the admin client of the running cluster"
kc() { "$KUBECTL" "$@"; }
TOLERATIONS="$(tolerations_yaml)" || exit 2
kc get --raw /healthz >/dev/null 2>&1 || refuse "the cluster at \$KUBECONFIG is not serving (/healthz)"

ready_nodes="$(kc get nodes -l kubernetes.io/os=darwin -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null | awk -F'\t' '$2 == "True" { print $1 }' | LC_ALL=C sort)"
if [ -n "${K3SM_M10_NODES:-}" ]; then
	read -r NODE_A NODE_B extra <<<"$K3SM_M10_NODES"
	[ -n "${NODE_B:-}" ] && [ -z "${extra:-}" ] && [ "$NODE_A" != "$NODE_B" ] || refuse "K3SM_M10_NODES must name two distinct nodes (got '$K3SM_M10_NODES')"
	for n in "$NODE_A" "$NODE_B"; do
		printf '%s\n' "$ready_nodes" | grep -qx "$n" || refuse "node $n is not a Ready darwin node"
	done
else
	count="$(printf '%s\n' "$ready_nodes" | grep -c . || true)"
	[ "$count" -ge 2 ] || refuse "need two Ready darwin nodes, found $count (${ready_nodes:-none}); join a worker first"
	NODE_A="$(printf '%s\n' "$ready_nodes" | sed -n 1p)"
	NODE_B="$(printf '%s\n' "$ready_nodes" | sed -n 2p)"
fi
node_taints() { kc get node "$1" -o jsonpath='{range .spec.taints[*]}{.key}={.value}:{.effect}{"\n"}{end}'; }
for n in "$NODE_A" "$NODE_B"; do
	left="$(untolerated "$(node_taints "$n")")" || exit 2
	[ -z "$left" ] || refuse "node $n carries taint(s) this run does not tolerate: $left (name each exactly in K3SM_LAB_TOLERATE_TAINTS='key=value:Effect' to tolerate it)"
done
node_hostname() { kc get node "$1" -o jsonpath='{.metadata.labels.kubernetes\.io/hostname}'; }
HOST_A="$(node_hostname "$NODE_A")"
HOST_B="$(node_hostname "$NODE_B")"
[ -n "$HOST_A" ] && [ -n "$HOST_B" ] || refuse "a node has no kubernetes.io/hostname label ($NODE_A '$HOST_A', $NODE_B '$HOST_B')"

EVIDENCE="${1:-}"
if [ -z "$EVIDENCE" ]; then
	EVIDENCE="$(mktemp -d "${TMPDIR:-/tmp}/m10-lab-evidence.XXXXXX")"
fi
mkdir -p "$EVIDENCE"

# ---- the run ----------------------------------------------------------------------------
# shellcheck source-path=SCRIPTDIR source=lib/runlog.sh
. "$HERE/lib/runlog.sh"
NS="m10-lab-$(date -u +%Y%m%d%H%M%S)-$$"
RUNLOG="$EVIDENCE/run.log"
emit_run_log_header FAIL >"$RUNLOG"
log() { printf '%s\n' "$*" | tee -a "$RUNLOG"; }
PASS=0
FAIL=0
# verdict <name> <ok|no> <detail>
verdict() {
	if [ "$2" = ok ]; then
		log "PASS  $1  $3"
		PASS=$((PASS + 1))
	else
		log "FAIL  $1  $3"
		FAIL=$((FAIL + 1))
	fi
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	set +e
	kc get pods,statefulsets,services,endpointslices -n "$NS" -o wide >"$EVIDENCE/final-state.txt" 2>&1
	kc get events -n "$NS" -o wide >"$EVIDENCE/events.txt" 2>&1
	kc delete namespace "$NS" --wait=true --timeout=180s >/dev/null 2>&1
	if kc get namespace "$NS" >/dev/null 2>&1; then
		echo "cleanup: namespace $NS is still terminating" >>"$RUNLOG"
	fi
}
trap cleanup EXIT

# events_for <kind/name>: the Events whose involvedObject.uid is that object's uid.
events_for() {
	local uid
	uid="$(kc get "$1" -n "$NS" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
	[ -n "$uid" ] || return 0
	echo "--- events for $1 (uid $uid)"
	kc get events -n "$NS" --field-selector "involvedObject.uid=$uid" -o wide 2>&1 || true
}
# dump_failure <kind/name>...: Events by uid and the latest log of each object.
dump_failure() {
	local o
	for o in "$@"; do
		events_for "$o" >>"$EVIDENCE/failure-events.txt"
		case "$o" in pod/*) kc logs -n "$NS" "${o#pod/}" >"$EVIDENCE/log-${o#pod/}.txt" 2>&1 || true ;; esac
	done
}

log "==> k3sm M10-lab gate: nodes $NODE_A + $NODE_B, namespace $NS, evidence $EVIDENCE"
log "    tolerations: [$TOLERATIONS]"

kc create namespace "$NS" >/dev/null
scripts_configmap "$NS" >"$EVIDENCE/m10-scripts.yaml"
kc apply -f "$EVIDENCE/m10-scripts.yaml" >/dev/null
web_manifest "$NS" "$HOST_A" "$HOST_B" "$TOLERATIONS" >"$EVIDENCE/web.yaml"
kc apply -f "$EVIDENCE/web.yaml" >/dev/null

# wait_ready <label-selector> <count> <seconds>: 0 once <count> pods match and are Ready.
wait_ready() {
	local sel="$1" want="$2" deadline=$((SECONDS + $3)) n
	while [ "$SECONDS" -lt "$deadline" ]; do
		n="$(kc get pods -n "$NS" -l "$sel" -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null | grep -c '^True$' || true)"
		[ "$n" -ge "$want" ] && return 0
		sleep 3
	done
	return 1
}
pod_rows() { kc get pods -n "$NS" -l "$1" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.podIP}{"\t"}{.spec.nodeName}{"\n"}{end}' 2>/dev/null | LC_ALL=C sort; }

web_ready=no
wait_ready "app=$STS" 2 240 && web_ready=ok
WEB_ROWS="$(pod_rows "app=$STS")"
printf '%s\n' "$WEB_ROWS" >"$EVIDENCE/replicas.txt"
if [ "$web_ready" != ok ]; then
	log "    the StatefulSet replicas were not both Ready within 240 s"
	dump_failure "statefulset/$STS" "pod/$STS-0" "pod/$STS-1"
fi
W0_IP="$(printf '%s\n' "$WEB_ROWS" | awk -F'\t' -v p="$STS-0" '$1 == p { print $2 }')"
W0_NODE="$(printf '%s\n' "$WEB_ROWS" | awk -F'\t' -v p="$STS-0" '$1 == p { print $3 }')"
W1_IP="$(printf '%s\n' "$WEB_ROWS" | awk -F'\t' -v p="$STS-1" '$1 == p { print $2 }')"
W1_NODE="$(printf '%s\n' "$WEB_ROWS" | awk -F'\t' -v p="$STS-1" '$1 == p { print $3 }')"
log "    replicas: $STS-0 ${W0_IP:-?} on ${W0_NODE:-?}; $STS-1 ${W1_IP:-?} on ${W1_NODE:-?}"

# peer_for <node>: "<ip> <name>" of the replica on the other node, if there is one.
peer_for() {
	if [ -n "$W0_NODE" ] && [ "$W0_NODE" != "$1" ] && [ -n "$W0_IP" ]; then
		echo "$W0_IP $STS-0"
	elif [ -n "$W1_NODE" ] && [ "$W1_NODE" != "$1" ] && [ -n "$W1_IP" ]; then
		echo "$W1_IP $STS-1"
	fi
}
PTR_IPS="$(words_sorted ${W0_IP:+"$W0_IP"} ${W1_IP:+"$W1_IP"})"
for side in a b; do
	if [ "$side" = a ]; then node="$NODE_A"; else node="$NODE_B"; fi
	peer="$(peer_for "$node")"
	probe_manifest "$NS" "m10-probe-$side" "$node" "$TOLERATIONS" "$PTR_IPS" "${peer%% *}" "${peer#* }" >"$EVIDENCE/probe-$side.yaml"
	kc apply -f "$EVIDENCE/probe-$side.yaml" >/dev/null
done

probes_ready=no
wait_ready app=m10-probe 2 180 && probes_ready=ok
[ "$probes_ready" = ok ] || dump_failure pod/m10-probe-a pod/m10-probe-b
# probe_log <side>: the probe's report, once it printed `M10 end` (or the deadline).
probe_log() {
	local deadline=$((SECONDS + PROBE_WAIT + 60)) out=""
	while [ "$SECONDS" -lt "$deadline" ]; do
		out="$(kc logs -n "$NS" "m10-probe-$1" 2>/dev/null || true)"
		case "$out" in *"M10 end"*) break ;; esac
		sleep 3
	done
	printf '%s\n' "$out"
}
LOG_A="$(probe_log a)"
LOG_B="$(probe_log b)"
printf '%s\n' "$LOG_A" >"$EVIDENCE/probe-a.log"
printf '%s\n' "$LOG_B" >"$EVIDENCE/probe-b.log"
case "$LOG_A$LOG_B" in *"M10 dig=missing"*) log "    /usr/bin/dig is missing inside a probe pod; the DNS assertions cannot be made" ;; esac

PROBE_ROWS="$(pod_rows app=m10-probe)"
node_internal_ip() { kc get node "$1" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'; }
node_pod_cidr() { kc get node "$1" -o jsonpath='{.spec.podCIDR}'; }

# m10.1 -----------------------------------------------------------------------------------
IP_A="$(printf '%s\n' "$PROBE_ROWS" | awk -F'\t' '$1 == "m10-probe-a" { print $2 }')"
IP_B="$(printf '%s\n' "$PROBE_ROWS" | awk -F'\t' '$1 == "m10-probe-b" { print $2 }')"
ON_A="$(printf '%s\n' "$PROBE_ROWS" | awk -F'\t' '$1 == "m10-probe-a" { print $3 }')"
ON_B="$(printf '%s\n' "$PROBE_ROWS" | awk -F'\t' '$1 == "m10-probe-b" { print $3 }')"
SHIM_A="$(probe_field "$LOG_A" pod_ip)"
SHIM_B="$(probe_field "$LOG_B" pod_ip)"
d="probe-a ${IP_A:-none} on ${ON_A:-?} (in-pod ${SHIM_A:-none}); probe-b ${IP_B:-none} on ${ON_B:-?} (in-pod ${SHIM_B:-none})"
if [ "$probes_ready" = ok ] && [ "$ON_A" = "$NODE_A" ] && [ "$ON_B" = "$NODE_B" ] &&
	[ -n "$IP_A" ] && [ -n "$IP_B" ] && [ "$IP_A" != "$IP_B" ] &&
	[ "$SHIM_A" = "$IP_A" ] && [ "$SHIM_B" = "$IP_B" ]; then
	verdict m10.1 ok "$d"
else
	verdict m10.1 no "$d"
fi

# m10.2 -----------------------------------------------------------------------------------
ok2=ok
d=""
for side in a b; do
	if [ "$side" = a ]; then node="$NODE_A" ip="$IP_A" plog="$LOG_A"; else node="$NODE_B" ip="$IP_B" plog="$LOG_B"; fi
	ncidr="$(node_pod_cidr "$node")"
	ccidr="$(pod_cidr_of "$(probe_field "$plog" cluster_cidrs)" "$ncidr" || true)"
	d="$d probe-$side ${ip:-none} in node ${ncidr:-none} / cluster ${ccidr:-none};"
	if [ -z "$ip" ] || [ -z "$ncidr" ] || [ -z "$ccidr" ] || ! in_cidr "$ip" "$ncidr" || ! in_cidr "$ip" "$ccidr"; then ok2=no; fi
done
verdict m10.2 "$ok2" "${d# }"

# m10.3 -----------------------------------------------------------------------------------
NIP_A="$(node_internal_ip "$NODE_A")"
NIP_B="$(node_internal_ip "$NODE_B")"
d="probe-a ${IP_A:-none} vs node ${NIP_A:-none}; probe-b ${IP_B:-none} vs node ${NIP_B:-none}"
if [ -n "$IP_A" ] && [ -n "$IP_B" ] && [ -n "$NIP_A" ] && [ -n "$NIP_B" ] &&
	[ "$IP_A" != "$NIP_A" ] && [ "$IP_B" != "$NIP_B" ]; then
	verdict m10.3 ok "$d"
else
	verdict m10.3 no "$d"
fi

# The names each DNS assertion expects; the domain is what the pod was handed.
DOMAIN="$(probe_field "$LOG_A" dns_domain)"
[ -n "$DOMAIN" ] || DOMAIN="$(probe_field "$LOG_B" dns_domain)"
SVC_FQDN="$STS.$NS.svc.$DOMAIN"
NAME0="$STS-0.$SVC_FQDN"
NAME1="$STS-1.$SVC_FQDN"
WANT_A="$PTR_IPS"
WANT_SRV="$(commas_sorted "$PORT:$NAME0,$PORT:$NAME1")"
distinct_nodes=no
[ -n "$W0_NODE" ] && [ -n "$W1_NODE" ] && [ "$W0_NODE" != "$W1_NODE" ] && distinct_nodes=ok

# m10.4 -----------------------------------------------------------------------------------
GOT_A_A="$(probe_field "$LOG_A" a)"
GOT_A_B="$(probe_field "$LOG_B" a)"
d="want '$WANT_A' for $SVC_FQDN; from $NODE_A '$GOT_A_A', from $NODE_B '$GOT_A_B'; replicas on distinct nodes: $distinct_nodes"
if [ "$web_ready" = ok ] && [ "$distinct_nodes" = ok ] && [ -n "$DOMAIN" ] &&
	[ "$(printf '%s' "$WANT_A" | wc -w | tr -d ' ')" = 2 ] &&
	[ "$GOT_A_A" = "$WANT_A" ] && [ "$GOT_A_B" = "$WANT_A" ]; then
	verdict m10.4 ok "$d"
else
	verdict m10.4 no "$d"
fi

# m10.5 -----------------------------------------------------------------------------------
GOT_S_A="$(commas_sorted "$(probe_field "$LOG_A" srv)")"
GOT_S_B="$(commas_sorted "$(probe_field "$LOG_B" srv)")"
d="want '$WANT_SRV' for _$PORT_NAME._tcp.$SVC_FQDN; from $NODE_A '$GOT_S_A', from $NODE_B '$GOT_S_B'"
if [ "$web_ready" = ok ] && [ -n "$DOMAIN" ] && [ "$GOT_S_A" = "$WANT_SRV" ] && [ "$GOT_S_B" = "$WANT_SRV" ]; then
	verdict m10.5 ok "$d"
else
	verdict m10.5 no "$d"
fi

# m10.6 -----------------------------------------------------------------------------------
ok6=ok
d=""
[ "$web_ready" = ok ] && [ -n "$DOMAIN" ] && [ -n "$W0_IP" ] && [ -n "$W1_IP" ] || ok6=no
for pair in "$W0_IP $NAME0" "$W1_IP $NAME1"; do
	ip="${pair%% *}"
	want="${pair#* }"
	[ -n "$ip" ] || continue
	for side in a b; do
		if [ "$side" = a ]; then plog="$LOG_A"; else plog="$LOG_B"; fi
		got="$(probe_field "$plog" "ptr.$ip")"
		d="$d $ip from probe-$side '$got';"
		[ "$got" = "$want" ] || ok6=no
	done
done
verdict m10.6 "$ok6" "want <pod>.$SVC_FQDN;${d}"

# m10.7 -----------------------------------------------------------------------------------
PEER_A="$(peer_for "$NODE_A")"
PEER_B="$(peer_for "$NODE_B")"
GOT_T_A="$(probe_field "$LOG_A" tcp)"
GOT_T_B="$(probe_field "$LOG_B" tcp)"
d="probe-a -> ${PEER_A:-none} read '$GOT_T_A'; probe-b -> ${PEER_B:-none} read '$GOT_T_B' (claimed by $CROSS_NODE_CLAIM)"
if [ "$distinct_nodes" = ok ] && [ -n "$PEER_A" ] && [ -n "$PEER_B" ] &&
	[ "$GOT_T_A" = "${PEER_A#* }" ] && [ "$GOT_T_B" = "${PEER_B#* }" ]; then
	verdict m10.7 ok "$d"
else
	verdict m10.7 no "$d"
fi

if [ "$FAIL" -gt 0 ]; then
	dump_failure "statefulset/$STS" "pod/$STS-0" "pod/$STS-1" pod/m10-probe-a pod/m10-probe-b
fi
log "----------------------------------------"
log "M10-lab: $PASS passed, $FAIL failed (evidence $EVIDENCE)"
if [ "$FAIL" -eq 0 ]; then
	log "================ M10-lab GREEN ================"
	emit_run_log_verdict PASS >>"$RUNLOG"
	exit 0
fi
emit_run_log_verdict FAIL >>"$RUNLOG"
exit 1
