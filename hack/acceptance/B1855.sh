#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# B1855: new unpinned pods prefer a node whose Mac is not CPU-busy.
#
# --lab is the gate, against a live cluster of two or more Ready nodes. Each leg
# runs through kubectl only and deletes what it made when it ends, pass or fail.
#
#   --wait NODE busy|calm   wait (bound --timeout, default 420 s) until NODE
#       publishes HostCPUBusy=True and carries the k3sm.io/host-cpu-busy
#       PreferNoSchedule taint (busy), or publishes it False or not at all and
#       carries no such taint (calm). The driver makes a Mac busy with its own
#       CPU burner; this script burns nothing.
#   --place N [--expect-on NODE | --expect-spread]   create a namespace and N
#       independent one-replica Deployments (each its own selector, so no
#       topology-spread default ties them together: the shape of the singletons
#       that pile onto one node), unpinned (image native, /bin/sleep, a 10m CPU
#       request, the provider toleration and nothing else, no nodeName and no
#       nodeSelector but kubernetes.io/os), wait until every replica is scheduled,
#       print the replicas per node and the taints at that moment, then delete
#       the namespace. --expect-on passes when at least three quarters of the
#       replicas are on NODE. --expect-spread passes when every Ready node got at
#       least one replica. With neither, the distribution is recorded and the leg
#       passes once every replica is scheduled.
#
# Exit 0 pass, 1 fail, 2 usage, 3 a precondition unmet (K3SM_LAB unset, kubectl
# missing, fewer than two Ready nodes): not a pass.
#
# Usage:
#   K3SM_LAB=1 hack/acceptance/B1855.sh --lab --wait k3sm-mikostudio busy
#   K3SM_LAB=1 hack/acceptance/B1855.sh --lab --place 6 --expect-on k3sm-mikobook
#   K3SM_LAB=1 hack/acceptance/B1855.sh --lab --place 6 --expect-spread
#   hack/acceptance/B1855.sh --plan
# Env: KUBECTL (default kubectl), B1855_CONTEXT (a kubeconfig context, default the
# current one), K3SM_LAB_TOLERATE_KEYS (hack/lab/lib/tolerations.sh).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh disable=SC1091
. "$HERE/../lab/lib/tolerations.sh"

GATE=B1855
TAINT_KEY=k3sm.io/host-cpu-busy
COND=HostCPUBusy

plan() {
	cat <<'EOF'
B1855 --lab legs (the driver orders them and runs the burners):
  1. --place N                         on the build under test, record where unpinned pods land
  2. --wait <busy node> busy            after a sustained host load, condition True and taint present
  3. --place N --expect-on <calm node>  new unpinned replicas prefer the calm node
  4. --place N --expect-spread          with no node, or every node, busy: replicas reach every node
  5. --wait <node> calm                 after the load stops, condition False and taint gone
EOF
}

usage() {
	echo "usage: K3SM_LAB=1 $0 --lab (--wait NODE busy|calm [--timeout S] | --place N [--expect-on NODE | --expect-spread])" >&2
	echo "       $0 --plan" >&2
	exit 2
}

say() { printf '%s %s %s\n' "$(date -u +%H:%M:%SZ)" "$GATE" "$*"; }

kc() {
	if [ -n "${B1855_CONTEXT:-}" ]; then
		"${KUBECTL:-kubectl}" --context "$B1855_CONTEXT" "$@"
	else
		"${KUBECTL:-kubectl}" "$@"
	fi
}

# node_state <node> - prints "<condition status or none> <taint present: yes|no>".
node_state() {
	kc get node "$1" -o json | python3 -I -c '
import json, sys
n = json.load(sys.stdin)
cond = next((c["status"] for c in n["status"].get("conditions", []) if c["type"] == sys.argv[1]), "none")
taint = any(t.get("key") == sys.argv[2] and t.get("effect") == "PreferNoSchedule" for t in n["spec"].get("taints") or [])
print(cond, "yes" if taint else "no")
' "$COND" "$TAINT_KEY"
}

ready_nodes() {
	kc get nodes -o json | python3 -I -c '
import json, sys
for n in json.load(sys.stdin)["items"]:
    if any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"].get("conditions", [])):
        print(n["metadata"]["name"])
'
}

taints_line() {
	kc get nodes -o json | python3 -I -c '
import json, sys
for n in json.load(sys.stdin)["items"]:
    ts = ",".join("%s:%s" % (t["key"], t["effect"]) for t in n["spec"].get("taints") or [])
    cond = next((c["status"] + "/" + c.get("message", "") for c in n["status"].get("conditions", []) if c["type"] == "HostCPUBusy"), "none")
    print("  %s taints=[%s] HostCPUBusy=%s" % (n["metadata"]["name"], ts, cond))
'
}

wait_leg() {
	local node="$1" want="$2" timeout="$3" deadline state
	case "$want" in busy | calm) ;; *) usage ;; esac
	deadline=$(($(date +%s) + timeout))
	while :; do
		state="$(node_state "$node")"
		say "wait $node $want: HostCPUBusy=${state% *} taint=${state#* }"
		case "$want:$state" in
		"busy:True yes") say "PASS $node busy"; return 0 ;;
		"calm:False no" | "calm:none no") say "PASS $node calm"; return 0 ;;
		esac
		if [ "$(date +%s)" -ge "$deadline" ]; then
			say "FAIL $node not $want within ${timeout}s"
			taints_line
			return 1
		fi
		sleep 15
	done
}

NS=""
cleanup() {
	if [ -n "$NS" ]; then
		kc delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
		say "cleanup: namespace $NS deleted"
	fi
}

place_leg() {
	local n="$1" expect="$2" target="$3" tol deadline sched dist
	NS="b1855-lab-$$"
	trap cleanup EXIT
	tol="$(lab_tolerations_json NoSchedule)"
	kc create namespace "$NS" >/dev/null
	local i
	for i in $(seq 1 "$n"); do
		kc -n "$NS" apply -f - >/dev/null <<EOF
{"apiVersion": "apps/v1", "kind": "Deployment",
 "metadata": {"name": "solo-$i", "labels": {"b1855": "lab"}},
 "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "b1855-solo-$i"}},
  "template": {"metadata": {"labels": {"app": "b1855-solo-$i", "b1855": "lab"}},
   "spec": {"nodeSelector": {"kubernetes.io/os": "darwin"},
    "tolerations": [$tol],
    "terminationGracePeriodSeconds": 1,
    "containers": [{"name": "c", "image": "native", "command": ["/bin/sleep", "3600"],
     "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}}}]}}}}
EOF
	done
	say "placed $n independent one-replica Deployments in $NS"
	taints_line
	deadline=$(($(date +%s) + 180))
	while :; do
		sched="$(kc -n "$NS" get pods -l b1855=lab -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | grep -c . || true)"
		[ "$sched" -ge "$n" ] && break
		if [ "$(date +%s)" -ge "$deadline" ]; then
			say "FAIL only $sched of $n replicas scheduled within 180s"
			kc -n "$NS" get pods -o wide || true
			return 1
		fi
		sleep 3
	done
	kc -n "$NS" get pods -o wide
	dist="$(kc -n "$NS" get pods -l b1855=lab -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort | uniq -c | awk '{print $2"="$1}' | tr '\n' ' ')"
	say "distribution: $dist"
	case "$expect" in
	on)
		local got
		# shellcheck disable=SC2086 # split the distribution into its words
		got="$(printf '%s\n' $dist | awk -F= -v t="$target" '$1 == t {print $2}')"
		got="${got:-0}"
		if [ $((got * 4)) -ge $((n * 3)) ]; then
			say "PASS $got of $n replicas on $target"
		else
			say "FAIL $got of $n replicas on $target, want at least three quarters"
			return 1
		fi
		;;
	spread)
		local node missing=""
		for node in $(ready_nodes); do
			case " $dist" in *" $node="*) ;; *) missing="$missing $node" ;; esac
		done
		if [ -z "$missing" ]; then
			say "PASS every Ready node got a replica"
		else
			say "FAIL no replica on:$missing"
			return 1
		fi
		;;
	*) say "PASS recorded" ;;
	esac
}

main() {
	local mode="" node="" want="" n="" expect="" target="" timeout=420
	[ $# -gt 0 ] || usage
	while [ $# -gt 0 ]; do
		case "$1" in
		--plan) plan; exit 0 ;;
		--lab) shift ;;
		--wait) [ $# -ge 3 ] || usage; mode="wait"; node="$2"; want="$3"; shift 3 ;;
		--timeout) [ $# -ge 2 ] || usage; timeout="$2"; shift 2 ;;
		--place) [ $# -ge 2 ] || usage; mode="place"; n="$2"; shift 2 ;;
		--expect-on) [ $# -ge 2 ] || usage; expect=on; target="$2"; shift 2 ;;
		--expect-spread) expect=spread; shift ;;
		*) usage ;;
		esac
	done
	[ -n "$mode" ] || usage
	[ "${K3SM_LAB:-}" = 1 ] || { echo "$GATE: K3SM_LAB=1 is required (a live cluster)" >&2; exit 3; }
	command -v "${KUBECTL:-kubectl}" >/dev/null || { echo "$GATE: kubectl not found" >&2; exit 3; }
	[ "$(ready_nodes | grep -c .)" -ge 2 ] || { echo "$GATE: fewer than two Ready nodes" >&2; exit 3; }
	case "$mode" in
	wait) wait_leg "$node" "$want" "$timeout" ;;
	place)
		case "$n" in '' | *[!0-9]* | 0) usage ;; esac
		place_leg "$n" "$expect" "$target"
		;;
	esac
}

main "$@"
