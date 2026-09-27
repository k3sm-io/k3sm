#!/usr/bin/env bash
# k3sm B124 acceptance: native pods survive a node-daemon restart (re-attach),
# and `k3sm uninstall` leaves no pod process behind. It runs against an
# INSTALLED, RUNNING node (`sudo k3sm install` on this Mac, a live cluster at
# $KUBECONFIG) and boots nothing itself. It ends by UNINSTALLING this node; the
# driver rejoins it afterwards, this script only asserts.
#
# Background. A native pod's processes are session leaders that outlive the
# node daemon. On start, the daemon lists the pods bound to its node from the
# apiserver and re-attaches to each running pod whose processes are still
# alive (same pod IP, same restartCount, one PodReattached Warning Event)
# instead of killing and recreating it. Uninstall stops every recorded pod
# process group once the daemons are gone.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. a logging hello-http pod pinned to this node is Running, its listener
#      bound to its own pod IP;
#   2. after `sudo launchctl kickstart -k system/<node daemon>`, within 60 s:
#      a. the pod is Running with restartCount and containerID unchanged,
#      b. a PodReattached Event is recorded for this pod's uid,
#      c. its listener is still bound to the same pod IP and answers,
#      d. its log continues past the restart (a tick later than any logged
#         before the restart appears);
#   3. killing the re-attached container's process recreates the pod (a
#      re-attached pod cannot restart a container in place): within 90 s the
#      pod is Running again with a new UID or restartCount+1, a
#      PodRecreatedAfterReattach Event is recorded, and its listener is back;
#   4. deleting the pod ends its process group;
#   5. `sudo k3sm uninstall` with a pod still running leaves no process of that
#      pod's group and no fixture process of this run.
#
# The node daemon label defaults to io.k3sm.agent (a worker) and falls back to
# io.k3sm.server when this Mac carries no agent daemon; K3SM_DAEMON_LABEL
# overrides both.
#
# Requires: kubectl, curl, go (builds the fixture), codesign, netstat, pgrep,
# ps, sudo.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
NS=default

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
finish() {
	echo "----------------------------------------"
	echo "B124: $PASS passed, $FAIL failed"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "=========== B124 GREEN ==========="
}

if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at the RUNNING cluster this installed node belongs to (this gate boots nothing itself)" >&2
	exit 1
fi
kc() { kubectl "$@"; }
kc get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

NODE_NAME="${K3SM_NODE_NAME:-k3sm-$(hostname -s | tr '[:upper:]' '[:lower:]')}"
if ! kc get node "$NODE_NAME" >/dev/null 2>&1; then
	echo "node $NODE_NAME is not in the cluster: this gate pins its pods to THIS Mac's node (set K3SM_NODE_NAME to override)" >&2
	exit 1
fi
LABEL="${K3SM_DAEMON_LABEL:-}"
if [ -z "$LABEL" ]; then
	if sudo launchctl print system/io.k3sm.agent >/dev/null 2>&1; then
		LABEL=io.k3sm.agent
	else
		LABEL=io.k3sm.server
	fi
fi
echo "==> B124 acceptance (node $NODE_NAME, daemon $LABEL)"

# Per-run pod names, so a previous run's leftover Event or a pod still being
# deleted can never match this run's checks.
RUN="$(date +%s)"
POD="b124-web-$RUN"
POD_U="b124-uninstall-$RUN"
PORT=18441
PORT_U=18442
cleanup() {
	for p in "$POD" "$POD_U"; do
		kc delete pod "$p" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
}
trap cleanup EXIT

# The fixture: hello-http (a listener the pod shim binds to the pod IP), built
# and ad-hoc signed onto a Seatbelt-admitted path, behind a shell that also
# prints a numbered tick every second, so the log has a line to continue.
FIXTURE_BIN="${K3SM_CONFORMANCE_BIN:-/tmp/k3sm-conformance-bin}"
mkdir -p "$FIXTURE_BIN"; chmod 755 "$FIXTURE_BIN"
(cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$FIXTURE_BIN/hello-http" ./e2e/testdata/cmd/hello-http)
codesign -s - -f "$FIXTURE_BIN/hello-http" >/dev/null 2>&1 || true

# logging_pod <name> <port> - a host-binary pod in $NS on $NODE_NAME.
logging_pod() {
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS}
spec:
  nodeName: $NODE_NAME
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  containers:
  - name: c
    image: native
    command: ["/bin/sh", "-c", "(i=0; while :; do i=\$((i+1)); echo tick \$i; sleep 1; done) & exec $FIXTURE_BIN/hello-http --id $1 --addr :$2"]
EOF
}

listening() {
	netstat -an -p tcp | awk '$NF=="LISTEN"{print $4}' | grep -qx "$1.$2"
}
# max_tick <pod> - the highest tick number in the pod's log, or 0.
max_tick() {
	kc logs "$1" -n "$NS" 2>/dev/null | awk '$1=="tick" && $2+0>m {m=$2+0} END {print m+0}'
}
# pod_pgid <pod name> - the process group of this run's hello-http for the pod.
pod_pgid() {
	local pid
	pid="$(pgrep -f "hello-http --id $1 " | head -n1 || true)"
	if [ -n "$pid" ]; then
		ps -o pgid= -p "$pid" | tr -d ' ' || true
	fi
}
jp() { kc get pod "$1" -n "$NS" -o jsonpath="$2" 2>/dev/null || true; }

# 1. The pod runs and listens on its own pod IP.
logging_pod "$POD" "$PORT"
ready=no
kc wait --for=condition=Ready "pod/$POD" -n "$NS" --timeout=120s >/dev/null 2>&1 && ready=yes
POD_IP="$(jp "$POD" '{.status.podIP}')"
bound=no
for _ in $(seq 1 15); do
	[ -n "$POD_IP" ] && listening "$POD_IP" "$PORT" && { bound=yes; break; }
	sleep 2
done
if [ "$ready" = yes ] && [ "$bound" = yes ]; then
	ladder ok "b124-1  $POD Running, listener bound to its pod IP $POD_IP:$PORT"
else
	ladder no "b124-1  $POD Running, listener bound to its pod IP (ready=$ready, bound=$bound, ip=${POD_IP:-?})"
	finish
fi
UID_="$(jp "$POD" '{.metadata.uid}')"
RC0="$(jp "$POD" '{.status.containerStatuses[0].restartCount}')"
CID0="$(jp "$POD" '{.status.containerStatuses[0].containerID}')"
PGID="$(pod_pgid "$POD")"
sleep 3
TICK0="$(max_tick "$POD")"

# 2. Restart the node daemon under the live pod.
echo "==> sudo launchctl kickstart -k system/$LABEL (pod pgid ${PGID:-?}, restartCount $RC0, last tick $TICK0)"
sudo launchctl kickstart -k "system/$LABEL"
T_KICK="$(date +%s)"
running=no; same_rc=no; same_cid=no; event=no; still_bound=no; answers=no; continued=no
while [ $(( $(date +%s) - T_KICK )) -lt 60 ]; do
	[ "$(jp "$POD" '{.status.phase}')" = Running ] && running=yes
	[ "$(jp "$POD" '{.status.containerStatuses[0].restartCount}')" = "$RC0" ] && same_rc=yes
	[ "$(jp "$POD" '{.status.containerStatuses[0].containerID}')" = "$CID0" ] && same_cid=yes
	if [ "$event" = no ] && [ -n "$(kc get events -n "$NS" --field-selector "involvedObject.uid=$UID_,reason=PodReattached" -o jsonpath='{.items[*].type}' 2>/dev/null || true)" ]; then
		event=yes
	fi
	listening "$POD_IP" "$PORT" && still_bound=yes
	curl -fsS --connect-timeout 2 -m 3 "http://$POD_IP:$PORT/" >/dev/null 2>&1 && answers=yes
	[ "$(max_tick "$POD")" -gt $((TICK0 + 3)) ] && continued=yes
	if [ "$running$same_rc$same_cid$event$still_bound$answers$continued" = yesyesyesyesyesyesyes ]; then
		break
	fi
	sleep 2
done
if [ "$running" = yes ] && [ "$same_rc" = yes ] && [ "$same_cid" = yes ]; then
	ladder ok "b124-2a $POD Running with restartCount $RC0 and containerID unchanged"
else
	ladder no "b124-2a $POD Running with restartCount $RC0 and containerID unchanged (running=$running rc=$(jp "$POD" '{.status.containerStatuses[0].restartCount}') cid-same=$same_cid)"
fi
if [ "$event" = yes ]; then
	ladder ok "b124-2b PodReattached Event recorded for $POD"
else
	ladder no "b124-2b PodReattached Event recorded for $POD"
fi
if [ "$still_bound" = yes ] && [ "$answers" = yes ]; then
	ladder ok "b124-2c listener still bound to $POD_IP:$PORT and answering"
else
	ladder no "b124-2c listener still bound to $POD_IP:$PORT and answering (bound=$still_bound answers=$answers)"
fi
if [ "$continued" = yes ]; then
	ladder ok "b124-2d log continues past the restart (tick > $((TICK0 + 3)))"
else
	ladder no "b124-2d log continues past the restart (max tick $(max_tick "$POD"), was $TICK0)"
fi

# 3. Kill the re-attached container's process: its restart policy (Always)
#    wants a restart, which for a re-attached pod is a recreate.
PID_K="$(pgrep -f "hello-http --id $POD " | head -n1 || true)"
echo "==> sudo kill -KILL ${PID_K:-?} (the re-attached hello-http of $POD)"
[ -n "$PID_K" ] && sudo kill -KILL "$PID_K"
T_KILL="$(date +%s)"
recreated=no; ev_re=no; back=no
while [ $(( $(date +%s) - T_KILL )) -lt 90 ]; do
	uid_now="$(jp "$POD" '{.metadata.uid}')"
	rc_now="$(jp "$POD" '{.status.containerStatuses[0].restartCount}')"
	if [ "$(jp "$POD" '{.status.phase}')" = Running ] && [ -n "$rc_now" ] \
		&& { [ -n "$uid_now" ] && [ "$uid_now" != "$UID_" ] || [ "$rc_now" -gt "$RC0" ]; }; then
		recreated=yes
	fi
	if [ "$ev_re" = no ] && [ -n "$(kc get events -n "$NS" --field-selector "involvedObject.name=$POD,reason=PodRecreatedAfterReattach" -o jsonpath='{.items[*].type}' 2>/dev/null || true)" ]; then
		ev_re=yes
	fi
	ip_now="$(jp "$POD" '{.status.podIP}')"
	if [ "$recreated" = yes ] && [ -n "$ip_now" ] && listening "$ip_now" "$PORT" \
		&& curl -fsS --connect-timeout 2 -m 3 "http://$ip_now:$PORT/" >/dev/null 2>&1; then
		back=yes
	fi
	[ "$recreated$ev_re$back" = yesyesyes ] && break
	sleep 2
done
if [ "$recreated" = yes ]; then
	ladder ok "b124-3a $POD recreated after its re-attached container was killed (uid $(jp "$POD" '{.metadata.uid}'), restartCount $(jp "$POD" '{.status.containerStatuses[0].restartCount}'), was $RC0)"
else
	ladder no "b124-3a $POD recreated after its re-attached container was killed (phase $(jp "$POD" '{.status.phase}'), restartCount $(jp "$POD" '{.status.containerStatuses[0].restartCount}'), was $RC0)"
fi
if [ "$ev_re" = yes ]; then
	ladder ok "b124-3b PodRecreatedAfterReattach Event recorded for $POD"
else
	ladder no "b124-3b PodRecreatedAfterReattach Event recorded for $POD"
fi
if [ "$back" = yes ]; then
	ladder ok "b124-3c listener back on $(jp "$POD" '{.status.podIP}'):$PORT and answering"
else
	ladder no "b124-3c listener back on the recreated pod's IP:$PORT and answering"
fi
# The recreated pod runs a new process group.
PGID="$(pod_pgid "$POD")"

# 4. Deleting the pod ends its process group.
kc delete pod "$POD" -n "$NS" --wait=true --timeout=90s >/dev/null 2>&1 || true
gone=no
for _ in $(seq 1 30); do
	if [ -n "$PGID" ] && ! pgrep -g "$PGID" >/dev/null 2>&1; then gone=yes; break; fi
	sleep 2
done
if [ "$gone" = yes ]; then
	ladder ok "b124-4  deleting $POD ended process group $PGID"
else
	ladder no "b124-4  deleting $POD ended process group ${PGID:-?} (members: $(pgrep -g "${PGID:-0}" 2>/dev/null | tr '\n' ' '))"
fi

# 5. Uninstall with a pod still running leaves no pod process behind.
logging_pod "$POD_U" "$PORT_U"
kc wait --for=condition=Ready "pod/$POD_U" -n "$NS" --timeout=120s >/dev/null 2>&1 || true
PGID_U=""
for _ in $(seq 1 15); do
	PGID_U="$(pod_pgid "$POD_U")"
	[ -n "$PGID_U" ] && break
	sleep 2
done
if [ -z "$PGID_U" ]; then
	ladder no "b124-5  a running pod to uninstall under ($POD_U never started a process)"
	finish
fi
echo "==> sudo k3sm uninstall (pod $POD_U, pgid $PGID_U)"
sudo k3sm uninstall
trap - EXIT
if ! pgrep -g "$PGID_U" >/dev/null 2>&1 && ! pgrep -f "hello-http --id b124-[a-z]*-$RUN " >/dev/null 2>&1; then
	ladder ok "b124-5  uninstall left no pod process (group $PGID_U and every b124-*-$RUN fixture gone)"
else
	ladder no "b124-5  uninstall left no pod process (still running: $(pgrep -lf "hello-http --id b124-[a-z]*-$RUN " 2>/dev/null | tr '\n' ' ') group: $(pgrep -g "$PGID_U" 2>/dev/null | tr '\n' ' '))"
fi
echo "==> this node is uninstalled; the driver rejoins it"

finish
