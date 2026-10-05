#!/usr/bin/env bash
# k3sm B124 acceptance: native pods survive a node-daemon restart (re-attach),
# and `k3sm uninstall` leaves no pod process behind. It runs against an
# INSTALLED, RUNNING node (`sudo k3sm install` on this Mac, a live cluster at
# $KUBECONFIG) and boots nothing itself. It ends by UNINSTALLING this node; the
# driver rejoins it afterwards, this script only asserts.
#
# Background. A native pod's processes are session leaders that outlive the
# node daemon. Each container runs under a resident shim that leads its group,
# holds its output, reaps it for the real exit status and serves exec, so all
# three survive a daemon restart. On start, the daemon lists the pods bound to
# its node from the apiserver and re-attaches to each running pod whose
# processes are still alive (same pod IP, same restartCount, one PodReattached
# Warning Event) instead of killing and recreating it, reconnecting to each
# container's shim. Uninstall stops every recorded pod process group once the
# daemons are gone.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. a logging hello-http pod pinned to this node is Running, its listener
#      bound to its own pod IP;
#   2. after `sudo launchctl kickstart -k system/<node daemon>`, within 60 s:
#      a. the pod is Running with restartCount and containerID unchanged,
#      b. a PodReattached Event is recorded for this pod's uid,
#      c. its listener is still bound to the same pod IP and answers,
#      d. its log continues past the restart (a tick later than any logged
#         before the restart appears),
#      e. `kubectl exec` into the re-attached pod runs a command and returns
#         its output with exit 0;
#      g. a BestEffort pod (no resources) in a namespace with no LimitRange
#         execs `/bin/echo ok` with exit 0 both before the restart and after
#         it (the `default` namespace's LimitRange makes every pod Burstable,
#         so the legs above never exercise the BestEffort path);
#   3. a second, two-container pod (containers a and b, one hello-http
#      listener each) is re-attached by the same restart; killing container
#      a's process restarts that one container in place: within 90 s the pod
#      UID and pod IP are unchanged, a's restartCount is one higher and b's is
#      unchanged with the same pid, a's listener is back on the same IP and
#      port, `kubectl logs --previous -c a` serves a tick logged before the
#      kill, a's lastState.terminated is the real status of the SIGKILL
#      (exitCode 137, reason Error), and no PodRecreatedAfterReattach Event is
#      recorded;
#   4. deleting the pod ends its process group;
#   5. `sudo k3sm uninstall` with a pod still running leaves no process of that
#      pod's group and no fixture process of this run.
#
# The node daemon label defaults to io.k3sm.agent (a worker) and falls back to
# io.k3sm.server when this Mac carries no agent daemon; K3SM_DAEMON_LABEL
# overrides both.
#
# Needs K3SM_LAB=1. With K3SM_LAB unset the gate reports LAB-PENDING and exits
# 3, which is not a pass and never 0.
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

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "B124 gate: LAB-PENDING: not a pass (needs K3SM_LAB=1 and an installed node at \$KUBECONFIG)" >&2
	exit 3
fi
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
POD_2="b124-pair-$RUN"
NS_BE="b124-be-$RUN"
POD_BE="b124-besteffort-$RUN"
ID_A="b124-paira-$RUN"
ID_B="b124-pairb-$RUN"
PORT=18441
PORT_U=18442
PORT_A=18443
PORT_B=18444
cleanup() {
	for p in "$POD" "$POD_U" "$POD_2"; do
		kc delete pod "$p" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
	kc delete namespace "$NS_BE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
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

# pair_pod - the two-container pod of leg 3: containers a and b, each a
# ticking hello-http on its own port.
pair_pod() {
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $POD_2, namespace: $NS}
spec:
  nodeName: $NODE_NAME
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  containers:
  - name: a
    image: native
    command: ["/bin/sh", "-c", "(i=0; while :; do i=\$((i+1)); echo tick \$i; sleep 1; done) & exec $FIXTURE_BIN/hello-http --id $ID_A --addr :$PORT_A"]
  - name: b
    image: native
    command: ["/bin/sh", "-c", "(i=0; while :; do i=\$((i+1)); echo tick \$i; sleep 1; done) & exec $FIXTURE_BIN/hello-http --id $ID_B --addr :$PORT_B"]
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
# cs <pod> <container> <field> - one field of a named container's status.
cs() { jp "$1" "{.status.containerStatuses[?(@.name==\"$2\")].$3}"; }
# fixture_pid <id> - the pid of this run's hello-http started with --id <id>.
fixture_pid() { pgrep -f "hello-http --id $1 " | head -n1 || true; }

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

# The leg-3 pod runs through the same daemon restart, so it is re-attached too.
pair_pod
kc wait --for=condition=Ready "pod/$POD_2" -n "$NS" --timeout=120s >/dev/null 2>&1 || true
UID_2="$(jp "$POD_2" '{.metadata.uid}')"

# Leg 2g fixture: a namespace with NO LimitRange and a pod with NO resources,
# so it is BestEffort (the default namespace's LimitRange would make it Burstable).
kc create namespace "$NS_BE" >/dev/null 2>&1 || true
kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $POD_BE, namespace: $NS_BE}
spec:
  nodeName: $NODE_NAME
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  containers:
  - name: c
    image: native
    command: ["/bin/sh", "-c", "exec sleep 3600"]
EOF
kc wait --for=condition=Ready "pod/$POD_BE" -n "$NS_BE" --timeout=120s >/dev/null 2>&1 || true
LR_BE="$(kc get limitrange -n "$NS_BE" -o name 2>/dev/null || echo unknown)"
QOS_BE="$(kc get pod "$POD_BE" -n "$NS_BE" -o jsonpath='{.status.qosClass}' 2>/dev/null || true)"
# be_exec - exec /bin/echo ok in the BestEffort pod, retrying while the node settles.
be_exec() {
	BE_RC=1; BE_OUT=""
	for _ in $(seq 1 15); do
		BE_RC=0
		BE_OUT="$(kc exec "$POD_BE" -n "$NS_BE" -- /bin/echo ok 2>&1)" || BE_RC=$?
		[ "$BE_RC" -eq 0 ] && [ "$BE_OUT" = ok ] && break
		sleep 2
	done
}
if [ -z "$LR_BE" ] && [ "$QOS_BE" = BestEffort ]; then
	ladder ok "b124-2g0 $NS_BE has no LimitRange and $POD_BE is BestEffort"
else
	ladder no "b124-2g0 $NS_BE has no LimitRange and $POD_BE is BestEffort (limitrange='$LR_BE' qosClass='${QOS_BE:-?}')"
fi
be_exec
if [ "$BE_RC" -eq 0 ] && [ "$BE_OUT" = ok ]; then
	ladder ok "b124-2g1 kubectl exec into BestEffort $POD_BE before the restart prints ok, exit 0"
else
	ladder no "b124-2g1 kubectl exec into BestEffort $POD_BE before the restart prints ok, exit 0 (exit $BE_RC, output '$BE_OUT')"
fi

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
# e. Exec into the re-attached pod: its container's shim serves the session.
EXEC_WANT="b124-exec-$RUN"
exec_out=""; exec_rc=1
for _ in $(seq 1 15); do
	exec_rc=0
	exec_out="$(kc exec "$POD" -n "$NS" -c c -- /bin/echo "$EXEC_WANT" 2>&1)" || exec_rc=$?
	[ "$exec_rc" -eq 0 ] && [ "$exec_out" = "$EXEC_WANT" ] && break
	sleep 2
done
if [ "$exec_rc" -eq 0 ] && [ "$exec_out" = "$EXEC_WANT" ]; then
	ladder ok "b124-2e kubectl exec into the re-attached $POD returns its output, exit 0"
else
	ladder no "b124-2e kubectl exec into the re-attached $POD returns its output, exit 0 (exit $exec_rc, output '$exec_out')"
fi

# g. The same BestEffort exec after the restart.
be_exec
if [ "$BE_RC" -eq 0 ] && [ "$BE_OUT" = ok ]; then
	ladder ok "b124-2g  kubectl exec into BestEffort $POD_BE after the restart prints ok, exit 0"
else
	ladder no "b124-2g  kubectl exec into BestEffort $POD_BE after the restart prints ok, exit 0 (exit $BE_RC, output '$BE_OUT')"
fi
kc delete namespace "$NS_BE" --ignore-not-found --wait=false >/dev/null 2>&1 || true

# 3. Kill container a of the re-attached two-container pod: its restart policy
#    (Always) restarts that one container in place; b keeps running.
reattached=no
for _ in $(seq 1 15); do
	if [ -n "$UID_2" ] && [ -n "$(kc get events -n "$NS" --field-selector "involvedObject.uid=$UID_2,reason=PodReattached" -o jsonpath='{.items[*].type}' 2>/dev/null || true)" ]; then
		reattached=yes; break
	fi
	sleep 2
done
if [ "$reattached" = yes ]; then
	ladder ok "b124-3a $POD_2 re-attached by the restart (PodReattached Event)"
else
	ladder no "b124-3a $POD_2 re-attached by the restart (no PodReattached Event for uid ${UID_2:-?})"
fi
IP_2="$(jp "$POD_2" '{.status.podIP}')"
RC0_A="$(cs "$POD_2" a restartCount)"
RC0_B="$(cs "$POD_2" b restartCount)"
PID_B0="$(fixture_pid "$ID_B")"
PID_A="$(fixture_pid "$ID_A")"
TICK_A="$(kc logs "$POD_2" -c a -n "$NS" 2>/dev/null | awk '$1=="tick" && $2+0>m {m=$2+0} END {print m+0}')"
echo "==> sudo kill -KILL ${PID_A:-?} (container a of $POD_2; restartCount a=${RC0_A:-?} b=${RC0_B:-?}, last tick $TICK_A)"
[ -n "$PID_A" ] && sudo kill -KILL "$PID_A"
T_KILL="$(date +%s)"
same_pod=no; a_bumped=no; b_same=no; back=no; previous=no; real_exit=no
while [ $(( $(date +%s) - T_KILL )) -lt 90 ]; do
	uid_ok=no; ip_ok=no; b_rc_ok=no; b_pid_ok=no
	[ "$(jp "$POD_2" '{.metadata.uid}')" = "$UID_2" ] && uid_ok=yes
	[ -n "$IP_2" ] && [ "$(jp "$POD_2" '{.status.podIP}')" = "$IP_2" ] && ip_ok=yes
	[ "$uid_ok$ip_ok" = yesyes ] && same_pod=yes
	[ -n "$RC0_A" ] && [ "$(cs "$POD_2" a restartCount)" = "$((RC0_A + 1))" ] && a_bumped=yes
	[ -n "$RC0_B" ] && [ "$(cs "$POD_2" b restartCount)" = "$RC0_B" ] && b_rc_ok=yes
	[ -n "$PID_B0" ] && [ "$(fixture_pid "$ID_B")" = "$PID_B0" ] && b_pid_ok=yes
	[ "$b_rc_ok$b_pid_ok" = yesyes ] && b_same=yes
	if [ "$a_bumped" = yes ] && listening "$IP_2" "$PORT_A" \
		&& curl -fsS --connect-timeout 2 -m 3 "http://$IP_2:$PORT_A/" >/dev/null 2>&1; then
		back=yes
	fi
	if [ "$a_bumped" = yes ] && [ "$TICK_A" -gt 0 ] \
		&& kc logs "$POD_2" -c a --previous -n "$NS" 2>/dev/null | grep -qx "tick $TICK_A"; then
		previous=yes
	fi
	if [ "$(cs "$POD_2" a lastState.terminated.exitCode)" = 137 ] \
		&& [ "$(cs "$POD_2" a lastState.terminated.reason)" = Error ]; then
		real_exit=yes
	fi
	[ "$same_pod$a_bumped$b_same$back$previous$real_exit" = yesyesyesyesyesyes ] && break
	sleep 2
done
recreates="$(kc get events -n "$NS" --field-selector "involvedObject.name=$POD_2,reason=PodRecreatedAfterReattach" -o jsonpath='{.items[*].type}' 2>/dev/null || true)"
if [ "$same_pod" = yes ]; then
	ladder ok "b124-3b $POD_2 kept its uid $UID_2 and pod IP $IP_2"
else
	ladder no "b124-3b $POD_2 kept its uid and pod IP (uid $(jp "$POD_2" '{.metadata.uid}') was ${UID_2:-?}, ip $(jp "$POD_2" '{.status.podIP}') was ${IP_2:-?})"
fi
if [ "$a_bumped" = yes ] && [ "$b_same" = yes ]; then
	ladder ok "b124-3c only a restarted (a restartCount $((RC0_A + 1)); b restartCount $RC0_B and pid $PID_B0 unchanged)"
else
	ladder no "b124-3c only a restarted (a restartCount $(cs "$POD_2" a restartCount), was ${RC0_A:-?}; b restartCount $(cs "$POD_2" b restartCount), was ${RC0_B:-?}; b pid $(fixture_pid "$ID_B"), was ${PID_B0:-?})"
fi
if [ "$back" = yes ]; then
	ladder ok "b124-3d a's listener back on $IP_2:$PORT_A and answering"
else
	ladder no "b124-3d a's listener back on ${IP_2:-?}:$PORT_A and answering"
fi
if [ "$previous" = yes ]; then
	ladder ok "b124-3e kubectl logs --previous -c a serves the pre-kill tick $TICK_A"
else
	ladder no "b124-3e kubectl logs --previous -c a serves the pre-kill tick $TICK_A"
fi
if [ "$real_exit" = yes ]; then
	ladder ok "b124-3f a's lastState.terminated is the real SIGKILL status (exitCode 137, reason Error)"
else
	ladder no "b124-3f a's lastState.terminated is the real SIGKILL status (got exitCode '$(cs "$POD_2" a lastState.terminated.exitCode)', reason '$(cs "$POD_2" a lastState.terminated.reason)')"
fi
if [ -z "$recreates" ]; then
	ladder ok "b124-3g no PodRecreatedAfterReattach Event for $POD_2"
else
	ladder no "b124-3g no PodRecreatedAfterReattach Event for $POD_2 (got: $recreates)"
fi
kc delete pod "$POD_2" -n "$NS" --wait=true --timeout=90s >/dev/null 2>&1 || true

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
