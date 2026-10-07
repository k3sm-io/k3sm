#!/usr/bin/env bash
# k3sm B243 acceptance: the node resolver floor and the shadow shells, against
# an INSTALLED, RUNNING node (`sudo k3sm install` on this Mac, a live cluster at
# $KUBECONFIG). This gate boots nothing itself.
#
# Background. dyld strips DYLD_INSERT_LIBRARIES from a restricted (platform,
# CS_RESTRICT, hardened) binary, so a pod that starts through /bin/sh used to
# lose the getaddrinfo + path-rebase shim for everything it ran. B243 answers in
# layers: netd publishes one supplemental DNS entry (svc + the cluster domain
# routed to the DNS VIP, no search domains) that mDNSResponder applies to every
# process; install makes re-signed copies of bash/zsh/dash/env that runtimed
# execs in place of the host shells; and a restricted main process gets a
# ShimInactive Warning Event.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. a `/bin/sh -c` pod, a direct `./entrypoint.sh` pod (#!/bin/sh) and an
#      `/usr/bin/env`-wrapped pod each resolve kubernetes.default.svc AND the
#      single-label `kubernetes` (the shim survived the wrapper: only the shim
#      applies the pod search list), and each one's wildcard listener is bound
#      to its own pod IP (the shim's bind discipline survived too),
#   2. a /usr/bin/python3 pod gets the ShimInactive Warning Event,
#   3. a host `curl` resolves kubernetes.default.svc.cluster.local to the
#      apiserver ClusterIP (no shim on the host: the node resolver entry),
#   4. `scutil --dns` lists supplemental resolvers for svc and the cluster
#      domain at the DNS VIP, and /etc/resolv.conf has no k3sm search line,
#   5. `k3sm status -o json` reports node-resolver and shadow-shells ok.
#
# The teardown half is a SEPARATE invocation, because it needs the node gone:
#
#   KUBECONFIG=... hack/acceptance/B243.sh            # legs 1-5, installed
#   sudo k3sm uninstall
#   hack/acceptance/B243.sh --after-uninstall          # leg 6
#
#   6. after uninstall, `scutil --dns` has no resolver at the DNS VIP and the
#      dynamic-store key is gone.
#
# Every pod is pinned with nodeName to THIS Mac's node (k3sm-<short hostname>,
# or $K3SM_NODE_NAME), because the fixtures and the shadow set live here. The
# pods tolerate only the provider taint, never node.kubernetes.io/unschedulable.
#
# Needs K3SM_LAB=1. With K3SM_LAB unset the gate reports LAB-PENDING and exits
# 3, which is not a pass and never 0.
#
# Requires: kubectl, curl, dig, go (builds the fixtures), codesign, scutil,
# netstat.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

DNS_VIP="${DNS_VIP:-10.43.0.10}"
CLUSTER_DOMAIN="${CLUSTER_DOMAIN:-cluster.local}"
STORE_KEY="State:/Network/Service/io.k3sm.dns/DNS"
NS=default

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
finish() {
	echo "----------------------------------------"
	echo "B243: $PASS passed, $FAIL failed"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "=========== B243 GREEN ==========="
}

# supplemental_at_vip <domain> — scutil --dns lists a resolver for <domain>
# whose nameserver is the DNS VIP.
supplemental_at_vip() {
	scutil --dns | awk -v d="$1" -v vip="$DNS_VIP" '
		/^resolver #/ { dom=""; ns="" }
		$1=="domain" { dom=$3 }
		$1 ~ /^nameserver/ { ns=$3; if (dom==d && ns==vip) found=1 }
		END { exit found ? 0 : 1 }'
}

if [ "${1:-}" = "--after-uninstall" ]; then
	echo "==> B243 acceptance, after uninstall"
	if ! scutil --dns | grep -q "nameserver\[[0-9]*\] : $DNS_VIP\$" \
		&& printf 'show %s\n' "$STORE_KEY" | scutil | grep -q "No such key"; then
		ladder ok "b243-6  scutil --dns clean after uninstall (no resolver at $DNS_VIP, $STORE_KEY gone)"
	else
		ladder no "b243-6  scutil --dns clean after uninstall (a resolver at $DNS_VIP or $STORE_KEY remains)"
	fi
	finish
	exit 0
fi

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "B243 gate: LAB-PENDING: not a pass (needs K3SM_LAB=1 and an installed node at \$KUBECONFIG)" >&2
	exit 3
fi
if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at the RUNNING cluster this installed node belongs to (this gate boots nothing itself)" >&2
	exit 1
fi
kc() { kubectl "$@"; }
kc get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

# Per-run pod names, so a previous run's leftover Event or a pod still being
# deleted can never match this run's checks. The cleanup and the port table
# below use the same names.
RUN="$(date +%s)"
POD_SH="b243-sh-$RUN"
POD_SCRIPT="b243-script-$RUN"
POD_ENV="b243-env-$RUN"
POD_PY="b243-py-$RUN"
PODS=("$POD_SH" "$POD_SCRIPT" "$POD_ENV" "$POD_PY")
ENTRYPOINT_CM="b243-entrypoint-$RUN"
cleanup() {
	for p in "${PODS[@]}"; do
		kc delete pod "$p" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
	kc delete configmap "$ENTRYPOINT_CM" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

NODE_NAME="${K3SM_NODE_NAME:-k3sm-$(hostname -s | tr '[:upper:]' '[:lower:]')}"
if ! kc get node "$NODE_NAME" >/dev/null 2>&1; then
	echo "node $NODE_NAME is not in the cluster: this gate pins its pods to THIS Mac's node (set K3SM_NODE_NAME to override)" >&2
	exit 1
fi
echo "==> B243 acceptance (node $NODE_NAME, DNS VIP $DNS_VIP, cluster domain $CLUSTER_DOMAIN)"

# The node resolver starts listening some seconds after the node is Ready;
# wait for it before any leg reads a lookup result.
dns_up=no
for _ in $(seq 1 45); do
	if [ -n "$(dig +short +time=2 +tries=1 @"$DNS_VIP" "kubernetes.default.svc.$CLUSTER_DOMAIN" 2>/dev/null)" ]; then
		dns_up=yes; break
	fi
	sleep 2
done
[ "$dns_up" = yes ] || { echo "node DNS at $DNS_VIP did not answer kubernetes.default.svc.$CLUSTER_DOMAIN within 90 s" >&2; exit 1; }

# Fixtures: conftool (net.LookupHost through libSystem getaddrinfo, so the shim
# applies when loaded) and hello-http (a wildcard listener the shim rebinds to
# the pod IP), built and ad-hoc signed onto a Seatbelt-admitted path. The
# #!/bin/sh entrypoint script is delivered the way real pods get one, from a
# ConfigMap volume: the pod sandbox may exec the fixture dir but not read it,
# and a mounted path also exercises the spawn-time shebang rewrite through the
# pod's mount rebase.
FIXTURE_BIN="${K3SM_CONFORMANCE_BIN:-/tmp/k3sm-conformance-bin}"
mkdir -p "$FIXTURE_BIN"; chmod 755 "$FIXTURE_BIN"
(cd "$REPO_ROOT" && go build -o "$FIXTURE_BIN/conftool" ./e2e/testdata/cmd/conftool)
(cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$FIXTURE_BIN/hello-http" ./e2e/testdata/cmd/hello-http)
codesign -s - -f "$FIXTURE_BIN/conftool" >/dev/null 2>&1 || true
codesign -s - -f "$FIXTURE_BIN/hello-http" >/dev/null 2>&1 || true

# body <id> <port> - resolve both names, then serve on a wildcard port.
body() {
	echo "$FIXTURE_BIN/conftool resolve -name kubernetes.default.svc -name kubernetes && exec $FIXTURE_BIN/hello-http --id $1 --addr :$2"
}
kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: $ENTRYPOINT_CM, namespace: $NS}
data:
  entrypoint.sh: |
    #!/bin/sh
    $(body "$POD_SCRIPT" 18432)
EOF

# native_pod <name> <json argv> [<configmap>] - a host-binary pod in $NS on
# $NODE_NAME; with a ConfigMap, it is mounted at /b243 with mode 0755.
native_pod() {
	local mount=""
	if [ -n "${3:-}" ]; then
		mount="    volumeMounts: [{name: entry, mountPath: /b243}]
  volumes: [{name: entry, configMap: {name: $3, defaultMode: 0755}}]"
	fi
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS}
spec:
  nodeName: $NODE_NAME
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  restartPolicy: Never
  containers:
  - name: c
    image: native
    command: $2
$mount
EOF
}
native_pod "$POD_SH" "[\"/bin/sh\", \"-c\", \"$(body "$POD_SH" 18431)\"]"
native_pod "$POD_SCRIPT" '["/b243/entrypoint.sh"]' "$ENTRYPOINT_CM"
native_pod "$POD_ENV" "[\"/usr/bin/env\", \"B243=1\", \"/bin/sh\", \"-c\", \"$(body "$POD_ENV" 18433)\"]"
native_pod "$POD_PY" '["/usr/bin/python3", "-c", "import time; time.sleep(3600)"]'

# 1. Each wrapped pod resolved both names (conftool exits non-zero otherwise,
#    and hello-http is exec'd only after it succeeds) and its listener is on
#    its own pod IP.
#    Ready comes before the wrapped process has written anything, so both
#    checks poll (2 s steps, 30 s budget) instead of reading once.
resolved() {
	grep -q "resolve: kubernetes.default.svc -> " <<<"$1" && grep -q "resolve: kubernetes -> " <<<"$1"
}
listening() {
	netstat -an -p tcp | awk '$NF=="LISTEN"{print $4}' | grep -qx "$1.$2"
}
for spec in "$POD_SH:18431" "$POD_SCRIPT:18432" "$POD_ENV:18433"; do
	pod="${spec%%:*}"; port="${spec##*:}"
	ready=no
	kc wait --for=condition=Ready "pod/$pod" -n "$NS" --timeout=120s >/dev/null 2>&1 && ready=yes
	logs=""
	for _ in $(seq 1 15); do
		logs="$(kc logs "$pod" -n "$NS" 2>/dev/null || true)"
		resolved "$logs" && break
		# A terminated container will print nothing more.
		[ -n "$(kc get pod "$pod" -n "$NS" -o jsonpath='{.status.containerStatuses[0].state.terminated.reason}' 2>/dev/null || true)" ] && break
		sleep 2
	done
	if [ "$ready" = yes ] && resolved "$logs"; then
		ladder ok "b243-1a $pod resolves kubernetes.default.svc and the single-label kubernetes"
	else
		ladder no "b243-1a $pod resolves kubernetes.default.svc and the single-label kubernetes (ready=$ready, logs: $(tr '\n' ' ' <<<"$logs" | cut -c1-200))"
	fi
	pod_ip="$(kc get pod "$pod" -n "$NS" -o jsonpath='{.status.podIP}' 2>/dev/null || true)"
	bound=no
	if [ -n "$pod_ip" ]; then
		for _ in $(seq 1 15); do
			listening "$pod_ip" "$port" && { bound=yes; break; }
			sleep 2
		done
	fi
	if [ "$bound" = yes ]; then
		ladder ok "b243-1b $pod listener bound to its own pod IP $pod_ip:$port"
	else
		ladder no "b243-1b $pod listener bound to its own pod IP ${pod_ip:-?}:$port (listeners on :$port: $(netstat -an -p tcp | awk '$NF=="LISTEN"{print $4}' | grep "\.$port\$" | tr '\n' ' '))"
	fi
done

# 2. The restricted main process is reported on THIS pod: Events are selected
#    by the pod's uid, so nothing a previous pod of any name recorded counts.
py_uid="$(kc get pod "$POD_PY" -n "$NS" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
ev=""
for _ in $(seq 1 30); do
	[ -n "$py_uid" ] || break
	ev="$(kc get events -n "$NS" --field-selector "involvedObject.uid=$py_uid,reason=ShimInactive" -o jsonpath='{.items[*].type}' 2>/dev/null || true)"
	[ -n "$ev" ] && break
	sleep 2
done
if [ "$ev" = "Warning" ]; then
	ladder ok "b243-2  /usr/bin/python3 pod has one ShimInactive Warning Event"
else
	ladder no "b243-2  /usr/bin/python3 pod has one ShimInactive Warning Event (got types: '${ev:-none}')"
fi

# 3. The host resolves the apiserver FQDN with no shim at all.
#    Run as the invoking user with Homebrew first on PATH, as the rig does;
#    /usr/bin/curl prints "*   Trying <ip>:443...", and either curl prints
#    "* Connected to <host> (<ip>) port 443" once the connect succeeds.
api_ip="$(kc get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')"
curl_out="$(PATH="/opt/homebrew/bin:$PATH" curl -sv --connect-timeout 3 -m 5 -k "https://kubernetes.default.svc.$CLUSTER_DOMAIN/" 2>&1 || true)"
if grep -qF "Trying $api_ip:" <<<"$curl_out" || grep -qF "($api_ip)" <<<"$(grep 'Connected to' <<<"$curl_out")"; then
	ladder ok "b243-3  host curl resolves kubernetes.default.svc.$CLUSTER_DOMAIN -> $api_ip"
else
	ladder no "b243-3  host curl resolves kubernetes.default.svc.$CLUSTER_DOMAIN -> $api_ip"
fi

# 4. The entry is in the host resolver configuration and adds no search list.
if supplemental_at_vip svc && supplemental_at_vip "$CLUSTER_DOMAIN"; then
	ladder ok "b243-4a scutil --dns: supplemental resolvers for svc and $CLUSTER_DOMAIN at $DNS_VIP"
else
	ladder no "b243-4a scutil --dns: supplemental resolvers for svc and $CLUSTER_DOMAIN at $DNS_VIP"
fi
if ! grep -Eq "^(search|domain).*(svc|$CLUSTER_DOMAIN)" /etc/resolv.conf; then
	ladder ok "b243-4b /etc/resolv.conf gains no cluster search domain"
else
	ladder no "b243-4b /etc/resolv.conf gains no cluster search domain ($(grep -E '^(search|domain)' /etc/resolv.conf))"
fi

# 5. k3sm status sees both.
status_json="$(k3sm status -o json 2>/dev/null || true)"
for row in node-resolver shadow-shells; do
	if python3 -c 'import json,sys; r={x["name"]:x for x in json.load(sys.stdin)["rows"]}; sys.exit(0 if r.get(sys.argv[1],{}).get("severity")=="ok" else 1)' "$row" <<<"$status_json" 2>/dev/null; then
		ladder ok "b243-5  k3sm status: $row ok"
	else
		ladder no "b243-5  k3sm status: $row ok"
	fi
done

finish
