#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# k3sm B29 acceptance: `kubectl debug` (ephemeral containers) against an
# INSTALLED, RUNNING node (`sudo k3sm install` on this Mac, a live cluster at
# $KUBECONFIG). This gate boots nothing itself.
#
# Background. The provider maps spec.ephemeralContainers into the PodBox and
# forwards an append through UpdatePod; runtimed starts the new entry once,
# inside the pod's own sandbox, and reports it under ephemeralContainerStatuses.
# targetContainerName is refused on the node (a Darwin process has no process
# namespace another process can join), a vm pod cannot start one at all, and the
# foreign-user admission policy judges the pods/ephemeralcontainers UPDATE.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. `kubectl debug --image=native` on a native pod runs its command: the
#      ephemeral container terminates exit 0 and `kubectl logs -c` carries the
#      marker. Interactive attach to a native process is unsupported (a
#      documented ceiling: `kubectl debug -it` is refused), so the leg runs the
#      debug container non-interactively and reads its output through logs;
#   2. `kubectl debug --target` is refused with the stated message, seen by the
#      kubectl user (kubectl's own output, else the pod's Warning Event; the
#      ladder line names which), and the status is Waiting
#      CreateContainerConfigError;
#   3. an ephemeral container asking for a foreign runAsUser is denied at
#      admission and never added;
#   4. on a vm pod the ephemeral container is Waiting with the vm refusal, the
#      pod carries the Warning Event, and after a settle period the pod is still
#      Running and not ProviderFailed;
#   5. self-check: the leg-2 status probe, pointed at an ephemeral container
#      that was never created, misses, and the ladder records FAIL without
#      exiting, so a vacuous probe would be visible.
#
# Every pod is pinned with nodeName to THIS Mac's node (k3sm-<short hostname>,
# or $K3SM_NODE_NAME) and keeps the darwin nodeSelector. The pods tolerate only
# the provider taint.
#
# Knobs:
#   K3SM_LAB=1           required; with it unset the gate reports LAB-PENDING
#                        and exits 3, which is not a pass and never 0
#   B29_VM_IMAGE         leg 4's Linux image (default alpine:3.20, hack/lab/m11.sh's)
#   B29_DEBUG_PROFILE    kubectl debug --profile (default general, kubectl's own;
#                        use restricted on a cluster started with
#                        --psa-enforce-baseline, which rejects general's SYS_PTRACE)
#   B29_SETTLE           leg 4's settle period in seconds (default 20)
#   B29_READY_TIMEOUT    seconds to wait for a pod to be Ready (default 600: a
#                        first vm boot pulls and unpacks the image)
#
# Requires: kubectl (with `debug --custom`), python3.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

GATE_NAME=B29
NS=default
VM_IMAGE="${B29_VM_IMAGE:-alpine:3.20}"
PROFILE="${B29_DEBUG_PROFILE:-general}"
READY_TIMEOUT="${B29_READY_TIMEOUT:-600}"
FOREIGN_UID=4242

# The texts the node and the admission policy produce. They are the provider's
# and the policy's constants verbatim (pkg/provider/ephemeral.go,
# pkg/policy/admission.go); a drift there turns a leg red here.
TARGET_MSG="k3sm: targetContainerName is not supported (Darwin processes have no shared process namespace to join); re-run kubectl debug without --target"
VM_MSG="ephemeral containers are not supported on the vm RuntimeClass"
VAP_PREFIX="k3sm: pods may not request a foreign runAsUser"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

# repo_git_sha <repo> - the HEAD of one of the four modules, or "unknown" when it
# is not checked out beside this one (the hack/lab/runs/README.md convention).
repo_git_sha() {
	local dir="$REPO_ROOT/../$1"
	[ "$1" = k3sm ] && dir="$REPO_ROOT"
	if [ -e "$dir/.git" ] && git -C "$dir" rev-parse HEAD >/dev/null 2>&1; then
		git -C "$dir" rev-parse HEAD
	else
		echo unknown
	fi
}
emit_header() {
	echo "# k3sm lab run log"
	echo "gate: $GATE_NAME"
	local repo
	for repo in apis runtimed darwin-net k3sm; do
		echo "git_sha.$repo: $(repo_git_sha "$repo")"
	done
	echo "started_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "result: FAIL (provisional; the final result line below is the verdict)"
}
finish() {
	echo "----------------------------------------"
	echo "$GATE_NAME: $PASS passed, $FAIL failed"
	echo "gate: $GATE_NAME"
	echo "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	if [ "$FAIL" -ne 0 ]; then
		echo "result: FAIL"
		exit 1
	fi
	echo "result: PASS"
	echo "=========== $GATE_NAME GREEN ==========="
}

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "$GATE_NAME gate: LAB-PENDING: not a pass (needs K3SM_LAB=1 and an installed node at \$KUBECONFIG)" >&2
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

emit_header
echo "==> $GATE_NAME acceptance (node $NODE_NAME, vm image $VM_IMAGE, debug profile $PROFILE)"

# Per-run names, so a leftover pod or Event of an earlier run can never match.
RUN="$(date +%s)"
POD_NATIVE="b29-native-$RUN"
POD_VM="b29-vm-$RUN"
SCRATCH="$(mktemp -d)"
cleanup() {
	for p in "$POD_NATIVE" "$POD_VM"; do
		kc delete pod "$p" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
	rm -rf "$SCRATCH"
}
trap cleanup EXIT

# bounded <seconds> <cmd...> - run cmd, killing it after the budget. macOS ships
# no timeout(1), and a kubectl debug that waits on a container that will never
# run must not hang the gate.
bounded() {
	local secs="$1"; shift
	"$@" &
	local pid=$!
	# The watchdog's output goes nowhere: an orphaned sleep must not hold the
	# caller's command-substitution pipe open.
	( sleep "$secs"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
	local watchdog=$!
	local rc=0
	wait "$pid" || rc=$?
	kill "$watchdog" 2>/dev/null || true
	wait "$watchdog" 2>/dev/null || true
	return "$rc"
}

jp() { kc get pod "$1" -n "$NS" -o jsonpath="$2" 2>/dev/null || true; }
# ecs <pod> <container> <field> - one field of a named ephemeral container's status.
ecs() { jp "$1" "{.status.ephemeralContainerStatuses[?(@.name==\"$2\")].$3}"; }
# wait_field <seconds> <want> <pod> <container> <field> - poll ecs until it reads want.
wait_field() {
	local secs="$1" want="$2" got=""
	for _ in $(seq 1 "$secs"); do
		got="$(ecs "$3" "$4" "$5")"
		[ "$got" = "$want" ] && { echo "$got"; return 0; }
		sleep 1
	done
	echo "$got"
	return 1
}
# warning_events <pod> - the messages of the pod's Warning Events, by uid.
warning_events() {
	local uid
	uid="$(jp "$1" '{.metadata.uid}')"
	[ -n "$uid" ] || return 0
	kc get events -n "$NS" --field-selector "involvedObject.uid=$uid,type=Warning" -o jsonpath='{range .items[*]}{.message}{"\n"}{end}' 2>/dev/null || true
}

pin() {
	cat <<EOF
  nodeName: $NODE_NAME
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
EOF
}

# The native target: a host binary that just stays up.
kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $POD_NATIVE, namespace: $NS}
spec:
$(pin)
  containers:
  - name: c
    image: native
    command: ["/bin/sleep", "3600"]
EOF
if ! kc wait --for=condition=Ready "pod/$POD_NATIVE" -n "$NS" --timeout="${READY_TIMEOUT}s" >/dev/null 2>&1; then
	ladder no "b29-0  native pod $POD_NATIVE Ready within ${READY_TIMEOUT}s"
	finish
fi

# 1. A debug container runs and exits. Interactive attach to a native process
#    is unsupported, so the debug container is started WITHOUT -i/-t (kubectl
#    returns once it is added), the leg waits for it to terminate, and the
#    output is read through `kubectl logs -c`, the path a user takes.
out1="$(bounded 60 kubectl debug "$POD_NATIVE" -n "$NS" --image=native --profile="$PROFILE" \
	--container=dbg1 -- /bin/sh -c 'echo b29-debug-ok' 2>&1)" && rc1=0 || rc1=$?
exit1="$(wait_field 60 0 "$POD_NATIVE" dbg1 state.terminated.exitCode || true)"
logs1="$(bounded 30 kubectl logs "$POD_NATIVE" -n "$NS" -c dbg1 2>&1)" || true
if [ "$rc1" -eq 0 ] && [ "$exit1" = 0 ] && grep -q "b29-debug-ok" <<<"$logs1"; then
	ladder ok "b29-1  kubectl debug --image=native ran: dbg1 terminated exit 0, kubectl logs -c dbg1 carries the marker"
else
	ladder no "b29-1  kubectl debug --image=native ran (kubectl rc=$rc1, dbg1 exit='${exit1}', debug output: $(tr '\n' ' ' <<<"$out1" | cut -c1-200), logs: $(tr '\n' ' ' <<<"$logs1" | cut -c1-200))"
fi

# 2. --target is refused on the node, and the kubectl user sees why. kubectl
#    waits for a container that will never run, hence the budget.
out2="$(bounded 45 kubectl debug "$POD_NATIVE" -n "$NS" -i --image=native --profile="$PROFILE" \
	--target=c --container=dbg2 -- /bin/true </dev/null 2>&1)" || true
reason2="$(wait_field 60 CreateContainerConfigError "$POD_NATIVE" dbg2 state.waiting.reason || true)"
surface=""
if grep -qF "$TARGET_MSG" <<<"$out2"; then
	surface="kubectl output"
else
	for _ in $(seq 1 30); do
		if grep -qF "$TARGET_MSG" <<<"$(warning_events "$POD_NATIVE")"; then
			surface="pod Warning Event"
			break
		fi
		sleep 1
	done
fi
if [ -n "$surface" ] && [ "$reason2" = CreateContainerConfigError ]; then
	ladder ok "b29-2  --target refused with the stated message (seen on: $surface), dbg2 Waiting CreateContainerConfigError"
else
	ladder no "b29-2  --target refused with the stated message (surface='${surface:-none}', dbg2 reason='$reason2', kubectl: $(tr '\n' ' ' <<<"$out2" | cut -c1-300))"
fi

# 3. A foreign runAsUser on the ephemeral container is denied at admission.
printf '{"securityContext": {"runAsUser": %d}}\n' "$FOREIGN_UID" >"$SCRATCH/foreign.json"
out3="$(bounded 60 kubectl debug "$POD_NATIVE" -n "$NS" --image=native --profile="$PROFILE" \
	--custom="$SCRATCH/foreign.json" --container=dbg3 -- /bin/true 2>&1)" && rc3=0 || rc3=$?
added3="$(kc get pod "$POD_NATIVE" -n "$NS" -o jsonpath='{.spec.ephemeralContainers[?(@.name=="dbg3")].name}' 2>/dev/null || true)"
if [ "$rc3" -ne 0 ] && grep -qF "$VAP_PREFIX" <<<"$out3" && [ -z "$added3" ]; then
	ladder ok "b29-3  ephemeral runAsUser $FOREIGN_UID denied at admission, dbg3 never added"
else
	ladder no "b29-3  ephemeral runAsUser $FOREIGN_UID denied at admission (kubectl rc=$rc3, added='${added3}', output: $(tr '\n' ' ' <<<"$out3" | cut -c1-300))"
fi

# 4. A vm pod cannot start an ephemeral container; it says so and keeps running.
kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $POD_VM, namespace: $NS}
spec:
  runtimeClassName: vm
$(pin)
  containers:
  - name: c
    image: $VM_IMAGE
    command: ["/bin/sh", "-c", "sleep 3600"]
EOF
if kc wait --for=condition=Ready "pod/$POD_VM" -n "$NS" --timeout="${READY_TIMEOUT}s" >/dev/null 2>&1; then
	bounded 60 kubectl debug "$POD_VM" -n "$NS" --image="$VM_IMAGE" --profile="$PROFILE" \
		--container=dbg4 -- /bin/true >"$SCRATCH/vm.out" 2>&1 || true
	msg4="$(wait_field 90 "$VM_MSG" "$POD_VM" dbg4 state.waiting.message || true)"
	# Settle, then re-read: a refusal handed back to virtual-kubelet as an error
	# lands the pod ProviderFailed some seconds AFTER the status first shows.
	sleep "${B29_SETTLE:-20}"
	phase4="$(jp "$POD_VM" '{.status.phase}')"
	reason4="$(jp "$POD_VM" '{.status.reason}')"
	ev4=no
	for _ in $(seq 1 30); do
		if grep -qF "$VM_MSG" <<<"$(warning_events "$POD_VM")"; then ev4=yes; break; fi
		sleep 1
	done
	if [ "$msg4" = "$VM_MSG" ] && [ "$phase4" = Running ] && [ "$reason4" != ProviderFailed ] && [ "$ev4" = yes ]; then
		ladder ok "b29-4  vm pod: dbg4 Waiting '$VM_MSG' with its Warning Event, pod still Running (not ProviderFailed) after the settle"
	else
		ladder no "b29-4  vm pod: dbg4 Waiting '$VM_MSG' with its Warning Event, pod still Running after the settle (message='$msg4', phase='$phase4', reason='$reason4', event=$ev4)"
	fi
else
	ladder no "b29-4  vm pod $POD_VM Ready within ${READY_TIMEOUT}s (image $VM_IMAGE)"
fi

# 5. Re-arm: the leg-2 probe pointed at an ephemeral container that was never
#    created must MISS, and the ladder must record that as FAIL and keep going.
#    A probe that matched anything would make legs 1, 2 and 4 vacuous.
probe="$(PASS=0; FAIL=0
	if got="$(wait_field 3 CreateContainerConfigError "$POD_NATIVE" "b29-never-created-$RUN" state.waiting.reason)"; then
		ladder ok "b29-5 probe (read '$got')"
	else
		ladder no "b29-5 probe"
	fi
	echo "continued FAIL=$FAIL")"
if grep -q "^FAIL  b29-5 probe" <<<"$probe" && grep -q "continued FAIL=1" <<<"$probe"; then
	ladder ok "b29-5  self-check: the leg-2 probe misses a never-created container and the ladder records FAIL without exiting"
else
	ladder no "b29-5  self-check: the leg-2 probe misses a never-created container and the ladder records FAIL without exiting (got: $(tr '\n' ' ' <<<"$probe"))"
fi

finish
