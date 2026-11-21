#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# B20b: a dnsPolicy None Pod resolves through its own dnsConfig, exclusively.
#
# Unit tier (always), in pkg/provider under -race:
#   TestToPodBoxDNSPolicyNoneInjectsCustomConfig  a None Pod's nameservers, search
#       and ndots reach every container as the shim's exclusive-mode env; Default
#       injects nothing; ClusterFirst is unchanged; a mixed v4/v6 list runs on the
#       v4 subset with a DNSConfigPartial Event; an all-IPv6 list waits
#       CreateContainerConfigError and never reaches the runtime
#   TestPodDNSConfigNoneFeedsGuestResolvConf  a vm None Pod's guest network gets
#       the Pod's nameservers and no cluster DNS VIP
# Rig tier (K3SM_LAB=1, an installed running node, kubectl configured), a native
# and a vm None Pod for each leg, pinned to this Mac's node:
#   1. nameservers [the cluster DNS VIP], searches [default.svc.<domain>]: the
#      bare name `kubernetes` resolves (the custom server is used and its search
#      list applied; before B20b the bare name never expanded).
#   2. nameservers [an address nothing answers on]: kubernetes.default.svc.<domain>
#      does NOT resolve. The host resolver answers that name from the node
#      resolver entry, so any fallback to the host resolves it: this leg is the
#      behavioural no-fallback oracle.
#
# Exit 0 pass, 1 fail, 3 LAB-PENDING (K3SM_LAB unset: the rig tier did not run,
# which is not a pass).
#
# Usage:
#   K3SM_LAB=1 B20B_VM_IMAGE=<linux image with getent> hack/acceptance/B20b.sh
# Env: DNS_VIP (10.43.0.10), CLUSTER_DOMAIN (cluster.local), B20B_DEAD_NS
# (192.0.2.53, TEST-NET-1), K3SM_NODE_NAME (k3sm-<short hostname>).
# Requires: go, kubectl, codesign.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=../lab/lib/tolerations.sh
. "$HERE/../lab/lib/tolerations.sh"
cd "$REPO_ROOT"
export CGO_ENABLED=1

run_tests() { # <regex> <name>...
	local re="$1"; shift
	local out
	out="$(go test -race -count=1 -v -run "$re" ./pkg/provider/ 2>&1)" || {
		printf '%s\n' "$out"; echo "B20b: FAIL: go test -run '$re'"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |    --- |ok|PASS)'
	# A test that does not run is not a pass.
	for t in "$@"; do
		printf '%s\n' "$out" | grep -q -- "--- PASS: $t" || { echo "B20b: FAIL: $t did not run"; exit 1; }
	done
}

run_tests '^(TestToPodBoxDNSPolicyNoneInjectsCustomConfig|TestPodDNSConfigNoneFeedsGuestResolvConf)$' \
	'TestToPodBoxDNSPolicyNoneInjectsCustomConfig/(i)_None' \
	'TestToPodBoxDNSPolicyNoneInjectsCustomConfig/(ii)_Default' \
	'TestToPodBoxDNSPolicyNoneInjectsCustomConfig/(iii)_ClusterFirst' \
	'TestToPodBoxDNSPolicyNoneInjectsCustomConfig/(iv)_mixed' \
	'TestToPodBoxDNSPolicyNoneInjectsCustomConfig/(v)_all_IPv6' \
	'TestPodDNSConfigNoneFeedsGuestResolvConf/SetupGuest_receives' \
	'TestPodDNSConfigNoneFeedsGuestResolvConf/an_all-IPv6'

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "B20b: LAB-PENDING: the rig tier needs K3SM_LAB=1; the unit tier alone is not a pass"
	exit 3
fi
: "${B20B_VM_IMAGE:?K3SM_LAB=1 needs B20B_VM_IMAGE=<a linux image with getent>}"

DNS_VIP="${DNS_VIP:-10.43.0.10}"
CLUSTER_DOMAIN="${CLUSTER_DOMAIN:-cluster.local}"
DEAD_NS="${B20B_DEAD_NS:-192.0.2.53}"
NODE_NAME="${K3SM_NODE_NAME:-k3sm-$(hostname -s | tr '[:upper:]' '[:lower:]')}"
NS=default
FQDN="kubernetes.default.svc.$CLUSTER_DOMAIN"
PODS="b20b-native-1 b20b-native-2 b20b-vm-1 b20b-vm-2"

FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; else echo "FAIL  $2"; FAIL=1; fi; }
cleanup() {
	for p in $PODS; do kubectl delete pod "$p" -n "$NS" --wait=false --ignore-not-found >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
cleanup

# conftool resolves through libSystem getaddrinfo, so the shim applies to it.
FIXTURE_BIN="${K3SM_CONFORMANCE_BIN:-/tmp/k3sm-conformance-bin}"
mkdir -p "$FIXTURE_BIN"; chmod 755 "$FIXTURE_BIN"
go build -o "$FIXTURE_BIN/conftool" ./e2e/testdata/cmd/conftool
codesign -s - -f "$FIXTURE_BIN/conftool" >/dev/null 2>&1 || true

TOLERATIONS="$(lab_tolerations_yaml NoSchedule)" || exit 1

# none_pod <name> <nameserver> <image> <runtimeClass or ""> <json argv>
none_pod() {
	local rc=""
	[ -n "$4" ] && rc="runtimeClassName: $4"
	kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS}
spec:
  nodeName: $NODE_NAME
  $rc
  tolerations: [$TOLERATIONS]
  restartPolicy: Never
  dnsPolicy: None
  dnsConfig:
    nameservers: [$2]
    searches: [default.svc.$CLUSTER_DOMAIN]
  containers:
  - name: c
    image: $3
    command: $5
EOF
}

# The native Pods print their verdict and stay up; the vm Pods sleep and are
# probed with exec.
probe() { # <name>
	echo "if $FIXTURE_BIN/conftool resolve -name $1; then echo B20B-RESOLVED; else echo B20B-NO-RESOLVE; fi; exec sleep 3600"
}
none_pod b20b-native-1 "$DNS_VIP" native "" "[\"/bin/sh\", \"-c\", \"$(probe kubernetes)\"]"
none_pod b20b-native-2 "$DEAD_NS" native "" "[\"/bin/sh\", \"-c\", \"$(probe "$FQDN")\"]"
none_pod b20b-vm-1 "$DNS_VIP" "$B20B_VM_IMAGE" vm '["/bin/sleep", "3600"]'
none_pod b20b-vm-2 "$DEAD_NS" "$B20B_VM_IMAGE" vm '["/bin/sleep", "3600"]'

native_verdict() { # <pod> -> RESOLVED | NO-RESOLVE | "" (none yet)
	local logs
	for _ in $(seq 1 30); do
		logs="$(kubectl logs "$1" -n "$NS" 2>/dev/null || true)"
		case "$logs" in
		*B20B-RESOLVED*) echo RESOLVED; return ;;
		*B20B-NO-RESOLVE*) echo NO-RESOLVE; return ;;
		esac
		sleep 2
	done
}
vm_lookup() { # <pod> <name> -> getent's status in the guest; 100 when the Pod never got Ready
	kubectl wait --for=condition=Ready "pod/$1" -n "$NS" --timeout=180s >/dev/null 2>&1 || return 100
	kubectl exec "$1" -n "$NS" -- getent hosts "$2" >/dev/null 2>&1
}

v="$(native_verdict b20b-native-1)"
if [ "$v" = RESOLVED ]; then
	ladder ok "b20b-1 native: kubernetes resolves through the Pod's own nameserver and search"
else
	ladder no "b20b-1 native: kubernetes resolves through the Pod's own nameserver and search (verdict '${v:-none}')"
fi
v="$(native_verdict b20b-native-2)"
if [ "$v" = NO-RESOLVE ]; then
	ladder ok "b20b-2 native: $FQDN does not resolve with an unanswered nameserver (no host fallback)"
else
	ladder no "b20b-2 native: $FQDN does not resolve with an unanswered nameserver (verdict '${v:-none}')"
fi
rc=0; vm_lookup b20b-vm-1 kubernetes || rc=$?
if [ "$rc" = 0 ]; then
	ladder ok "b20b-1 vm: kubernetes resolves through the Pod's own nameserver and search"
else
	ladder no "b20b-1 vm: kubernetes resolves through the Pod's own nameserver and search (rc $rc, 100 = not Ready; resolv.conf: $(kubectl exec b20b-vm-1 -n "$NS" -- cat /etc/resolv.conf 2>&1 | tr '\n' ' '))"
fi
rc=0; vm_lookup b20b-vm-2 "$FQDN" || rc=$?
if [ "$rc" != 0 ] && [ "$rc" != 100 ]; then
	ladder ok "b20b-2 vm: $FQDN does not resolve with an unanswered nameserver (getent rc $rc)"
else
	ladder no "b20b-2 vm: $FQDN does not resolve with an unanswered nameserver (rc $rc, 0 = it resolved, 100 = not Ready)"
fi

[ "$FAIL" -eq 0 ] || { echo "B20b: FAIL"; exit 1; }
echo "B20b: PASS"
