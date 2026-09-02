#!/usr/bin/env bash
#
# k3sm M11 lab gate — Linux containers on the vm path, on real VZ hardware.
#
# This script backs TWO rows in hack/acceptance/phases.json, and the distinction is
# load-bearing:
#
#   M11-core  gate hack/lab/m11.sh, args ["--core"], tier lab, manual: true,
#             requires dev-mac + vz + network. The LAUNCH row: the vm path
#             (linux/arm64) must demonstrate this before v0.1 ships.
#   M11-lab   gate hack/lab/m11.sh (NO args), tier lab, manual: true,
#             requires vz + network. The FULL B109 ledger — every vm-path leg.
#
# --core is a STRICT SUBSET. A green --core run NEVER satisfies M11-lab; the two rows
# exist precisely so a launch-blocking subset cannot be mistaken for the whole ledger,
# and that is why the mode is a parsed argument rather than an environment nudge.
#
# It BOOTS NO CLUSTER. $KUBECONFIG must point at a RUNNING k3sm server on a Mac whose
# node advertises k3sm.io/virtualization, with egress to the image registry.
#
# THE LADDER (--core runs 1-9; the bare full-ledger run adds 10-12):
#
#   m11.1  preflight   a vm-capable node (k3sm.io/virtualization + k3sm.io/vm-artifacts),
#                      k3sm.io/rosetta-linux ABSENT (the key is deleted, never "false"),
#                      and the vm RuntimeClass provisioned.
#   m11.2  boot        an arm64 Linux image under runtimeClassName: vm reaches Running
#                      1/1, and `uname -sm` through exec answers Linux aarch64 — the
#                      identity assertion, because "Running" alone would also be true of
#                      a native darwin process.
#   m11.3  logs        kubectl logs returns a marker the container echoed, and
#                      --tail=N returns EXACTLY N lines.
#   m11.4  exec        kubectl exec -- sh -c 'exit 42' propagates 42. An exec path that
#                      swallowed the status would report every failing command as success.
#   m11.5  workload    a real published image (nats:2.10-alpine, whose entrypoint is the
#                      BARE NAME docker-entrypoint.sh and so must resolve execvp-style in
#                      the guest) reaches Running and logs "Server is ready".
#   m11.6  storage     a local-path PVC mounted in a vm pod: write a marker, SIGKILL the
#                      pod's k3sm-vmhost helper, watch the pod go unready, delete and
#                      recreate against the SAME claim, and find BOTH the old and a new
#                      marker. Root-in-guest image and NO fsGroup, deliberately: spike
#                      S3(2) recorded NO (Apple's virtiofs refuses
#                      mount_setattr(MOUNT_ATTR_IDMAP), EINVAL), and the M11 plan's
#                      pre-decided consequence moves the fsGroup case to the follow-on.
#   m11.7  network     in-guest: eth0 UP with an address on the node's vmnet segment and
#                      a default route; an FQDN resolved through the cluster DNS VIP; a
#                      TCP connect to the kubernetes ClusterIP:443. From the host: a TCP
#                      connect to the guest's leased address on a port the pod listens on.
#   m11.8  amd64       NEGATIVE: an amd64-only image under runtimeClassName: vm FAILS,
#                      and the failure names the platform mismatch. This is the arm64-only
#                      posture of this release (M11 plan R19(a)/R26), asserted so a silent
#                      widening — or an opaque exec-format death in the guest — is caught.
#   m11.9  footprint   the host-side footprint of ONE vm pod, RECORDED for the B24
#                      overhead reconcile. A recording criterion never fails the gate:
#                      there is no committed budget to hold it to, and inventing one here
#                      would be either vacuous or flaky.
#   m11.10 service     FULL ONLY. A Service selecting a vm pod has a populated
#                      EndpointSlice and answers through its ClusterIP.
#   m11.11 logs -f     FULL ONLY. kubectl logs -f streams new lines and terminates when
#                      the pod goes away, rather than hanging.
#   m11.12 stats       FULL ONLY. The node's /stats/summary reports the vm pod with a
#                      memory working set (per-container cgroup2 leaves exist in the
#                      guest). Deliberately NOT `kubectl top`: that needs an
#                      operator-installed metrics-server, which k3sm does not ship
#                      (docs/user/limitations.md).
#
# Every wait is bounded. A hang is a FAIL against a named rung, never a gate that runs
# until someone kills it. Every object the gate creates lives in ONE namespace, deleted
# on exit including on failure.
#
# PRIVILEGE: m11.6 SIGKILLs the pod's own k3sm-vmhost helper, which the root runtimed
# daemon spawned. Run the gate as root, or with sudo available (the gate calls
# `sudo pkill` and will prompt), or set K3SM_M11_VMHOST_KILL to a command that kills the
# helper for the pod whose UID it is handed in $K3SM_M11_POD_UID.
#
# Usage:
#   K3SM_LAB=1 hack/lab/m11.sh --core | tee hack/lab/runs/m11-core-<rc-tag>-<UTCdate>.log
#   K3SM_LAB=1 hack/lab/m11.sh        | tee hack/lab/runs/m11-lab-<rc-tag>-<UTCdate>.log
# See hack/lab/runs/README.md for the evidence convention this header implements.
#
# Knobs (all optional):
#   K3SM_M11_NAMESPACE      namespace to run in (default k3sm-m11; created and deleted)
#   K3SM_M11_IMAGE          the arm64 Linux image (default alpine:3.20)
#   K3SM_M11_WORKLOAD_IMAGE the real-workload image (default nats:2.10-alpine)
#   K3SM_M11_AMD64_IMAGE    the amd64-only image (default docker.io/amd64/alpine:3.20)
#   K3SM_M11_VMNET_CIDR     the node's vmnet segment (default 192.168.64.0/24, the
#                           observed Apple NAT default — netserve.DefaultVMNetSubnet)
#   K3SM_M11_READY_TIMEOUT  seconds to wait for a vm pod to go Ready (default 600)
#   K3SM_M11_VMHOST_KILL    command that kills one pod's k3sm-vmhost helper
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Mode parsing: --core selects the launch subset; bare selects the full ledger. ──
# An unknown flag is REJECTED rather than ignored, so a typo ("--cores") can never be
# silently downgraded into a full-ledger run whose log then claims the wrong scope.
MODE="full"
GATE_NAME="M11-lab"
while [ "$#" -gt 0 ]; do
	case "$1" in
	--core)
		MODE="core"
		GATE_NAME="M11-core"
		;;
	-h | --help)
		echo "usage: $0 [--core]   (--core = the launch subset; no args = the full B109 ledger)"
		exit 0
		;;
	*)
		echo "$0: unknown argument $1 (expected --core or no arguments)" >&2
		exit 2
		;;
	esac
	shift
done

# ── The hack/lab/runs/ run-log header (README.md documents the convention). ─────────
# Four fields are REQUIRED of every k3sm lab run log, and this is the one emitter:
#   gate            which gate row this log is evidence for (M11-core vs M11-lab)
#   artifact_sha256 the sha256 of the artifact under test — "local:<sha>" for a
#                   developer build, the bare rc sha for the release-candidate run
#                   that alone satisfies an rc-artifact-bound ledger row
#   git_sha.<repo>  the per-repo commit each of the four modules was built from
#   result          PASS or FAIL — the verdict, recorded in the log itself
#
# The log OPENS with this header, so its result is necessarily PROVISIONAL: the verdict
# is not known until the legs have run. It is therefore emitted FAIL-CLOSED — a log that
# ends where it was truncated records no pass — and the authoritative verdict is the
# `result:` line emitted by emit_run_log_verdict at the very end. Only the final line is
# a bare PASS/FAIL, so grepping `result: PASS` cannot match the provisional one.
emit_run_log_header() {
	local result="$1"
	echo "# k3sm lab run log"
	echo "gate: ${GATE_NAME}"
	echo "mode: ${MODE}"
	echo "rc_tag: ${K3SM_RC_TAG:-none}"
	echo "artifact_sha256: $(artifact_sha256)"
	local repo
	for repo in apis runtimed darwin-net k3sm; do
		echo "git_sha.${repo}: $(repo_git_sha "$repo")"
	done
	echo "started_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "result: ${result}"
}

# emit_run_log_verdict closes the log with the AUTHORITATIVE verdict. It is the only
# place a bare "result: PASS" or "result: FAIL" is written.
emit_run_log_verdict() {
	echo "gate: ${GATE_NAME}"
	echo "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "result: $1"
}

# artifact_sha256 reports the sha256 of the k3sm binary under test. K3SM_ARTIFACT names
# it; an unset or absent artifact reports "unknown" rather than an empty field, because a
# blank evidence line reads as "recorded nothing" and is indistinguishable from a
# truncated log.
artifact_sha256() {
	local artifact="${K3SM_ARTIFACT:-}"
	if [ -n "$artifact" ] && [ -f "$artifact" ]; then
		local sum
		sum="$(shasum -a 256 "$artifact" | cut -d' ' -f1)"
		if [ -n "${K3SM_RC_TAG:-}" ]; then
			echo "$sum"
		else
			echo "local:${sum}"
		fi
		return
	fi
	echo "unknown"
}

# repo_git_sha reports one sibling module's HEAD commit, or "unknown" when that repo is
# not checked out beside this one. It never fails the run: a missing sibling is an
# evidence gap to record, not a reason to abort a lab leg mid-flight.
repo_git_sha() {
	local repo="$1" dir
	if [ "$repo" = "k3sm" ]; then
		dir="$REPO_ROOT"
	else
		dir="$REPO_ROOT/../$repo"
	fi
	if [ -e "$dir/.git" ] && git -C "$dir" rev-parse HEAD >/dev/null 2>&1; then
		git -C "$dir" rev-parse HEAD
		return
	fi
	echo "unknown"
}

# ── Lab guard: only run under K3SM_LAB=1 (a real VZ-capable macOS host). ───────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	if [ "$MODE" = "core" ]; then
		echo "${GATE_NAME} gate: PENDING (dev-mac + vz + network). The launch subset of the vm path (--core) needs K3SM_LAB=1 + a real VZ-capable Mac; this is NOT a pass."
	else
		echo "${GATE_NAME} gate: PENDING (vz + network). The FULL B109 vm-path ledger needs K3SM_LAB=1 + a real VZ-capable Mac; a --core green does not satisfy it. This is NOT a pass."
	fi
	exit 0
fi

emit_run_log_header "FAIL (provisional — the final result line below is the verdict; a log that ends here did not finish)"

# ── Knobs ──────────────────────────────────────────────────────────────────────────
NS="${K3SM_M11_NAMESPACE:-k3sm-m11}"
IMAGE_LINUX="${K3SM_M11_IMAGE:-alpine:3.20}"
IMAGE_WORKLOAD="${K3SM_M11_WORKLOAD_IMAGE:-nats:2.10-alpine}"
IMAGE_AMD64="${K3SM_M11_AMD64_IMAGE:-docker.io/amd64/alpine:3.20}"
VMNET_CIDR="${K3SM_M11_VMNET_CIDR:-192.168.64.0/24}"
READY_TIMEOUT="${K3SM_M11_READY_TIMEOUT:-600}"
PULLFAIL_TIMEOUT="${K3SM_M11_PULLFAIL_TIMEOUT:-300}"

# The platform-mismatch substring m11.8 asserts. It is the SUBSTRING, not the whole
# message: the observed failure reads "no image manifest matches a runnable platform:
# want [linux/arm64/v8], image provides [linux/amd64]", and the bracketed platform lists
# are free to gain a variant without the assertion going stale.
AMD64_SUBSTR="${K3SM_M11_AMD64_SUBSTR:-no image manifest matches a runnable platform}"

LOG_LINES=20      # marker lines the boot pod echoes before it starts serving
TAIL_N=5          # kubectl logs --tail=N must return EXACTLY this many lines
LISTEN_PORT=9376  # the in-guest listener m11.7 and m11.10 dial

POD_BOOT=m11-boot
POD_WORKLOAD=m11-nats
POD_STORE=m11-store
POD_AMD64=m11-amd64
POD_FOLLOW=m11-follow
SVC_BOOT=m11-boot-svc
PVC=m11-data
MARKER="m11-marker-$$"
MARKER_A="store-a-$$"
MARKER_B="store-b-$$"

PASS=0; FAIL=0; REC=0
ladder() {
	case "$1" in
	ok)  echo "PASS  $2"; PASS=$((PASS + 1)) ;;
	rec) echo "REC   $2"; REC=$((REC + 1)) ;;
	*)   echo "FAIL  $2"; FAIL=$((FAIL + 1)) ;;
	esac
}
note() { echo "      $*"; }

finish() {
	local result=FAIL
	if [ "$FAIL" -eq 0 ]; then result=PASS; fi
	echo "----------------------------------------"
	echo "${GATE_NAME}: $PASS passed, $FAIL failed, $REC recorded (mode: $MODE)"
	emit_run_log_verdict "$result"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "================ ${GATE_NAME} GREEN ================"
	exit 0
}

# ── Preflight tooling. Every one of these is used by a rung below, so a missing tool
# is a gate that cannot run, not a leg that may be skipped. ────────────────────────
for tool in kubectl python3 nc curl; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "${GATE_NAME} gate requires $tool on PATH" >&2
		emit_run_log_verdict FAIL
		exit 1
	}
done
if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at a RUNNING k3sm cluster on a VZ-capable Mac (this gate boots nothing itself)" >&2
	emit_run_log_verdict FAIL
	exit 1
fi
export KUBECONFIG
kubectl --request-timeout=15s get --raw /healthz >/dev/null || {
	echo "cluster at \$KUBECONFIG is not serving" >&2
	emit_run_log_verdict FAIL
	exit 1
}

FOLLOW_PID=""
# shellcheck disable=SC2329  # invoked by the EXIT trap below, which shellcheck does not follow
cleanup() {
	if [ -n "$FOLLOW_PID" ]; then kill "$FOLLOW_PID" >/dev/null 2>&1 || true; fi
	kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1
	return 0
}
trap cleanup EXIT

echo "==> k3sm ${GATE_NAME} gate — the vm path on real VZ hardware (ns $NS, mode $MODE)"

# ── Shared helpers ────────────────────────────────────────────────────────────────

# kn runs kubectl against the gate's namespace.
kn() { kubectl -n "$NS" "$@"; }

# gexec runs one shell command inside a vm pod's guest and prints its output. It
# deliberately keeps the guest side to plain commands and parses on the HOST: the guest
# is busybox, and a quoting mistake in an in-guest awk reads as a product failure.
gexec() { kn exec "$1" -- /bin/sh -c "$2"; }

# wait_ready polls a pod to Running with every container ready, bounded. It prints a
# note whenever the phase or waiting reason changes, so a stuck boot names its own
# reason in the log instead of only a timeout.
wait_ready() {
	local pod="$1" timeout="$2" deadline=$((SECONDS + $2)) last="" phase ready reason
	while [ "$SECONDS" -lt "$deadline" ]; do
		phase="$(kn get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
		ready="$(kn get pod "$pod" -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null || true)"
		if [ "$phase" = "Running" ] && [ -n "$ready" ] && ! printf '%s' "$ready" | grep -q false; then
			return 0
		fi
		reason="$(kn get pod "$pod" -o jsonpath='{.status.containerStatuses[*].state.waiting.reason}' 2>/dev/null || true)"
		if [ "${phase}/${reason}" != "$last" ]; then
			note "$pod: phase=${phase:-?} waiting=${reason:-none} ready=${ready:-?} (${SECONDS}s)"
			last="${phase}/${reason}"
		fi
		sleep 5
	done
	note "$pod: NOT ready within ${timeout}s — recent state follows"
	kn describe pod "$pod" 2>&1 | tail -n 25 | sed 's/^/      /' || true
	return 1
}

# ready_containers prints "<ready>/<total>" for a pod, so the 1/1 claim in m11.2 is an
# assertion rather than a reading of `kubectl get pod` prose.
ready_containers() {
	kn get pod "$1" -o json 2>/dev/null | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("0/0"); sys.exit(0)
cs = (d.get("status") or {}).get("containerStatuses") or []
print("%d/%d" % (sum(1 for c in cs if c.get("ready")), len(cs)))
'
}

# in_cidr reports whether an address falls inside a CIDR. ipaddress rather than an octet
# prefix match: the vmnet segment is a knob, and a hand-rolled prefix compare would be
# silently wrong for any mask that is not /24.
in_cidr() {
	python3 -c '
import ipaddress,sys
try:
    print("yes" if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else "no")
except Exception:
    print("no")
' "$1" "$2"
}

# EVERY pod manifest below carries the same three guardrail stanzas, and each is
# load-bearing rather than boilerplate:
#   runtimeClassName: vm                        the path under test — without it the pod
#                                               runs as a native Darwin process and every
#                                               rung below would pass while proving nothing
#   nodeSelector kubernetes.io/os: darwin       k3sm's os=darwin Deny VAP rejects a pod
#                                               that does not declare it (the intent guard)
#   toleration k3sm.io/provider:NoSchedule      the VK node taint (the placement guard);
#                                               without it the pod sits Unschedulable

# ── m11.1 preflight ───────────────────────────────────────────────────────────────
# Every pod is PINNED to one named vm-capable node, and THIS host's node is preferred.
# Two rungs are host-side — the host->guest dial (m11.7-e) and the footprint recording
# (m11.9) — and both are meaningless against a guest running on a different Mac, so the
# choice of node is part of the gate rather than left to the scheduler.
VM_NODES="$(kubectl get nodes -l k3sm.io/virtualization=true -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
LOCAL_NODE="k3sm-$(hostname -s | tr '[:upper:]' '[:lower:]')"
VM_NODE=""
for n in $VM_NODES; do
	if [ "$n" = "$LOCAL_NODE" ]; then VM_NODE="$n"; fi
done
if [ -z "$VM_NODE" ]; then
	VM_NODE="$(printf '%s' "$VM_NODES" | awk '{print $1}')"
fi
if [ -n "$VM_NODE" ]; then
	ladder ok "m11.1-a  a node advertises k3sm.io/virtualization=true ($VM_NODE; candidates: $VM_NODES)"
	if [ "$VM_NODE" != "$LOCAL_NODE" ]; then
		note "WARNING: $VM_NODE is not this host's node ($LOCAL_NODE) — the host-side rungs m11.7-e and m11.9 observe THIS Mac and will not see a guest on another one"
	fi
else
	ladder no "m11.1-a  NO node advertises k3sm.io/virtualization — this gate requires a VZ-capable, entitled Mac"
	finish
fi

ARTIFACTS="$(kubectl get node "$VM_NODE" -o jsonpath='{.metadata.labels.k3sm\.io/vm-artifacts}' 2>/dev/null || true)"
if [ "$ARTIFACTS" = "true" ]; then
	ladder ok "m11.1-b  $VM_NODE advertises k3sm.io/vm-artifacts=true (the pinned guest kernel+initramfs are ensured and verified)"
else
	ladder no "m11.1-b  $VM_NODE does not advertise k3sm.io/vm-artifacts (got '${ARTIFACTS:-absent}')"
fi

# ABSENT, not "false": the node DELETES the key when the capability is not there, so
# testing for the string "false" would pass on a node that never wrote the label at all.
ROSETTA_PRESENT="$(kubectl get node "$VM_NODE" -o json 2>/dev/null | python3 -c '
import json,sys
d = json.load(sys.stdin)
print("yes" if "k3sm.io/rosetta-linux" in ((d.get("metadata") or {}).get("labels") or {}) else "no")
')"
if [ "$ROSETTA_PRESENT" = "no" ]; then
	ladder ok "m11.1-c  k3sm.io/rosetta-linux is ABSENT on $VM_NODE — the arm64-only posture of this release, advertised truthfully"
else
	ladder no "m11.1-c  k3sm.io/rosetta-linux is PRESENT on $VM_NODE — this release attaches no guest Rosetta share, so the label would be a capability claim the helper cannot honour"
fi

if kubectl get runtimeclass vm >/dev/null 2>&1; then
	ladder ok "m11.1-d  the vm RuntimeClass is provisioned"
else
	ladder no "m11.1-d  the vm RuntimeClass is absent — a k3sm server provisions it at start"
	finish
fi

# A namespace left Terminating by a previous run reads as "present" but accepts no
# objects, so wait it out rather than applying into a namespace that will drop the work.
deadline=$((SECONDS + 180))
while [ "$SECONDS" -lt "$deadline" ]; do
	nsphase="$(kubectl get namespace "$NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
	if [ "$nsphase" != "Terminating" ]; then break; fi
	note "namespace $NS is still Terminating from a previous run (${SECONDS}s)"
	sleep 5
done
if ! kubectl get namespace "$NS" >/dev/null 2>&1; then
	kubectl create namespace "$NS" >/dev/null
fi

# ── m11.2 boot + identity ─────────────────────────────────────────────────────────
# One long-lived pod carries m11.2/3/4/7/9 and, in the full run, m11.10/12: it echoes a
# fixed number of marker lines (so --tail=N is exact) and then serves the marker over
# HTTP from the guest, which is what the host->guest and Service legs dial.
kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD_BOOT
  namespace: $NS
  labels: {app: $POD_BOOT}
spec:
  runtimeClassName: vm
  nodeSelector: {kubernetes.io/os: darwin, kubernetes.io/hostname: $VM_NODE}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  containers:
    - name: app
      image: $IMAGE_LINUX
      command: ["/bin/sh", "-c"]
      args:
        - |
          mkdir -p /www
          echo "$MARKER" > /www/index.html
          i=1
          while [ \$i -le $LOG_LINES ]; do echo "m11-log-\$i $MARKER"; i=\$((i + 1)); done
          if command -v httpd >/dev/null 2>&1; then exec httpd -f -p $LISTEN_PORT -h /www; fi
          while true; do
            printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n$MARKER\n' | nc -l -p $LISTEN_PORT >/dev/null 2>&1 || sleep 1
          done
EOF

BOOT_OK=0
if wait_ready "$POD_BOOT" "$READY_TIMEOUT"; then
	RC="$(ready_containers "$POD_BOOT")"
	if [ "$RC" = "1/1" ]; then
		BOOT_OK=1
		ladder ok "m11.2-a  $IMAGE_LINUX under runtimeClassName: vm is Running $RC on $VM_NODE"
	else
		ladder no "m11.2-a  $POD_BOOT is Running but $RC ready, want 1/1"
	fi
else
	ladder no "m11.2-a  $IMAGE_LINUX under runtimeClassName: vm did not reach Running+Ready within ${READY_TIMEOUT}s"
fi

if [ "$BOOT_OK" -eq 1 ]; then
	UNAME="$(gexec "$POD_BOOT" 'uname -sm' 2>/dev/null | tr -d '\r' | head -1 || true)"
	if [ "$UNAME" = "Linux aarch64" ]; then
		ladder ok "m11.2-b  the guest is really Linux/arm64 (uname -sm = '$UNAME')"
	else
		ladder no "m11.2-b  uname -sm in the guest = '${UNAME:-<no output>}', want 'Linux aarch64' — Running alone does not prove a Linux guest"
	fi
else
	ladder no "m11.2-b  guest identity not asserted — $POD_BOOT never became ready"
fi

# ── m11.2-c the ServiceAccount projection, AT its mountPath ───────────────────────
# Read at the path Kubernetes promises, never at the staging share the guest binds
# from: every base image symlinks /var/run -> /run, so a bind that resolved that
# symlink against the GUEST's root instead of the container's landed outside the
# container and left the token silently absent while every upstream step looked
# correct. The gate passed 24/24 without noticing, because nothing read the token.
# An in-cluster client library sees exactly what this rung sees.
if [ "$BOOT_OK" -eq 1 ]; then
	SA_DIR=/var/run/secrets/kubernetes.io/serviceaccount
	SA_SEEN="$(gexec "$POD_BOOT" "cat $SA_DIR/namespace 2>/dev/null | tr -d '\n'" 2>/dev/null | tr -d '\r' || true)"
	SA_HAS_TOKEN="$(gexec "$POD_BOOT" "[ -s $SA_DIR/token ] && [ -s $SA_DIR/ca.crt ] && echo yes" 2>/dev/null | tr -d '\r' | head -1 || true)"
	if [ "$SA_SEEN" = "$NS" ] && [ "$SA_HAS_TOKEN" = "yes" ]; then
		ladder ok "m11.2-c  the ServiceAccount projection is readable at $SA_DIR (namespace=$SA_SEEN, non-empty token and ca.crt)"
	else
		ladder no "m11.2-c  the ServiceAccount projection is NOT usable at $SA_DIR (namespace='${SA_SEEN:-<absent>}' want '$NS', token+ca.crt present='${SA_HAS_TOKEN:-no}') — a vm Pod cannot authenticate to the apiserver as itself"
	fi
	# Gated on the projection actually being there. A write that fails because the
	# directory does not exist proves nothing about read-only enforcement, and a
	# security rung that can pass for the wrong reason is worse than no rung.
	if [ "$SA_HAS_TOKEN" != "yes" ]; then
		ladder no "m11.2-d  read-only enforcement not asserted — $SA_DIR is absent, so a failed write would prove nothing"
	elif gexec "$POD_BOOT" "touch $SA_DIR/m11-write-probe" >/dev/null 2>&1; then
		ladder no "m11.2-d  $SA_DIR is WRITABLE — a projected credential must be read-only in the container"
	else
		ladder ok "m11.2-d  $SA_DIR exists and refuses a write (projected credentials stay read-only in the guest)"
	fi
else
	ladder no "m11.2-c  ServiceAccount projection not asserted — $POD_BOOT never became ready"
	ladder no "m11.2-d  credential writability not asserted — $POD_BOOT never became ready"
fi

# ── m11.3 logs ────────────────────────────────────────────────────────────────────
if [ "$BOOT_OK" -eq 1 ]; then
	LOGS="$(kn logs "$POD_BOOT" 2>/dev/null || true)"
	if printf '%s\n' "$LOGS" | grep -q "m11-log-${LOG_LINES} $MARKER"; then
		ladder ok "m11.3-a  kubectl logs returns the marker the container echoed (m11-log-${LOG_LINES} $MARKER)"
	else
		ladder no "m11.3-a  kubectl logs does not contain the container's marker (got $(printf '%s\n' "$LOGS" | grep -c . || true) lines)"
	fi
	TAILED="$(kn logs "$POD_BOOT" --tail="$TAIL_N" 2>/dev/null | grep -c . || true)"
	if [ "$TAILED" = "$TAIL_N" ]; then
		ladder ok "m11.3-b  kubectl logs --tail=$TAIL_N returns exactly $TAIL_N lines"
	else
		ladder no "m11.3-b  kubectl logs --tail=$TAIL_N returned $TAILED lines, want exactly $TAIL_N"
	fi
else
	ladder no "m11.3  logs not asserted — $POD_BOOT never became ready"
fi

# ── m11.4 exec exit code ──────────────────────────────────────────────────────────
if [ "$BOOT_OK" -eq 1 ]; then
	rc=0
	kn exec "$POD_BOOT" -- /bin/sh -c 'exit 42' >/dev/null 2>&1 || rc=$?
	if [ "$rc" -eq 42 ]; then
		ladder ok "m11.4  kubectl exec propagates the guest exit code (exit 42 -> 42)"
	else
		ladder no "m11.4  kubectl exec -- sh -c 'exit 42' returned $rc, want 42 — a swallowed status reports every failing command as success"
	fi
else
	ladder no "m11.4  exec exit code not asserted — $POD_BOOT never became ready"
fi

# ── m11.7 guest network (asserted while the boot pod is up) ───────────────────────
GUEST_IP=""
if [ "$BOOT_OK" -eq 1 ]; then
	ADDR_OUT="$(gexec "$POD_BOOT" 'ip -4 -o addr show eth0 2>/dev/null || ifconfig eth0' 2>/dev/null || true)"
	GUEST_IP="$(printf '%s\n' "$ADDR_OUT" | awk '{for (i = 1; i <= NF; i++) if ($i == "inet") {split($(i+1), a, "/"); print a[1]; exit}}')"
	LINK_OUT="$(gexec "$POD_BOOT" 'ip -o link show eth0 2>/dev/null || ifconfig eth0' 2>/dev/null || true)"
	if [ -n "$GUEST_IP" ] && [ "$(in_cidr "$GUEST_IP" "$VMNET_CIDR")" = "yes" ] && printf '%s' "$LINK_OUT" | grep -q UP; then
		ladder ok "m11.7-a  guest eth0 is UP with $GUEST_IP, inside the node's vmnet segment $VMNET_CIDR"
	else
		ladder no "m11.7-a  guest eth0 address '${GUEST_IP:-none}' is not an UP address inside $VMNET_CIDR"
		note "addr: $ADDR_OUT"
		note "link: $LINK_OUT"
	fi

	ROUTE_OUT="$(gexec "$POD_BOOT" 'ip route show default 2>/dev/null || netstat -rn 2>/dev/null | grep "^0.0.0.0"' 2>/dev/null || true)"
	if [ -n "$(printf '%s' "$ROUTE_OUT" | tr -d '[:space:]')" ]; then
		ladder ok "m11.7-b  the guest has a default route ($(printf '%s' "$ROUTE_OUT" | head -1))"
	else
		ladder no "m11.7-b  the guest has NO default route"
	fi

	DNS_VIP="$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
	API_CLUSTERIP="$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
	if [ -n "$DNS_VIP" ] && [ -n "$API_CLUSTERIP" ]; then
		NS_OUT="$(gexec "$POD_BOOT" "nslookup kubernetes.default.svc.cluster.local $DNS_VIP" 2>&1 || true)"
		if printf '%s\n' "$NS_OUT" | grep -q "$API_CLUSTERIP"; then
			ladder ok "m11.7-c  kubernetes.default.svc.cluster.local resolves to $API_CLUSTERIP through the cluster DNS VIP $DNS_VIP"
		else
			ladder no "m11.7-c  the FQDN did not resolve to $API_CLUSTERIP through $DNS_VIP"
			printf '%s\n' "$NS_OUT" | sed 's/^/      /'
		fi

		nc_rc=0
		NC_OUT="$(gexec "$POD_BOOT" "nc -w 5 $API_CLUSTERIP 443 </dev/null" 2>&1)" || nc_rc=$?
		if [ "$nc_rc" -eq 0 ]; then
			ladder ok "m11.7-d  the guest completes a TCP connect to the kubernetes ClusterIP $API_CLUSTERIP:443"
		else
			ladder no "m11.7-d  the guest could not TCP-connect to $API_CLUSTERIP:443 (rc $nc_rc): ${NC_OUT:-no output}"
		fi
	else
		ladder no "m11.7-cd  could not resolve the cluster DNS VIP / kubernetes ClusterIP from the cluster (dns='${DNS_VIP:-none}' api='${API_CLUSTERIP:-none}')"
	fi

	if [ -n "$GUEST_IP" ]; then
		# Retried: with busybox httpd absent the pod serves from a single-shot `nc -l`
		# loop, so one dial can land in the window between connections. Three tries
		# distinguish "not listening" from "was between accepts".
		hostdial=1
		for _ in 1 2 3; do
			if nc -z -w 5 "$GUEST_IP" "$LISTEN_PORT" >/dev/null 2>&1; then hostdial=0; break; fi
			sleep 2
		done
		if [ "$hostdial" -eq 0 ]; then
			ladder ok "m11.7-e  the host completes a TCP connect to the guest's leased address $GUEST_IP:$LISTEN_PORT"
		else
			ladder no "m11.7-e  the host could NOT connect to $GUEST_IP:$LISTEN_PORT — the path that carries probes, port-forward and the Service-proxy backend dial"
		fi
	else
		ladder no "m11.7-e  host->guest connect not asserted — no guest address was read"
	fi
else
	ladder no "m11.7  guest network not asserted — $POD_BOOT never became ready"
fi

# ── m11.9 per-VM host footprint (RECORDED, never thresholded) ─────────────────────
BOOT_UID="$(kn get pod "$POD_BOOT" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
VMHOST_PID=""
if [ -n "$BOOT_UID" ]; then VMHOST_PID="$(pgrep -f "k3sm-vmhost.*$BOOT_UID" 2>/dev/null | head -1 || true)"; fi
if [ -n "$VMHOST_PID" ]; then
	FOOTPRINT="$(ps -o rss=,vsz=,etime=,pcpu= -p "$VMHOST_PID" 2>/dev/null | sed 's/^ *//' || true)"
	RSS_KB="$(printf '%s' "$FOOTPRINT" | awk '{print $1}')"
	RSS_MIB="$(python3 -c 'import sys; print("%.1f" % (int(sys.argv[1]) / 1024.0))' "${RSS_KB:-0}" 2>/dev/null || echo "?")"
	ladder rec "m11.9  per-VM host footprint: k3sm-vmhost pid $VMHOST_PID rss ${RSS_MIB} MiB (rss_kb vsz_kb etime pcpu: $FOOTPRINT)"
	note "recorded for the B24 overhead reconcile (RuntimeClass overhead.podFixed); this rung never fails the gate"
else
	ladder rec "m11.9  per-VM host footprint: NOT RECORDED — no k3sm-vmhost process matched pod uid '${BOOT_UID:-none}'"
fi

# ── m11.5 real-image workload ─────────────────────────────────────────────────────
# nats:2.10-alpine's entrypoint is the BARE NAME docker-entrypoint.sh, so it exercises
# execvp-style PATH resolution in the guest, not just an absolute-path spawn.
kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD_WORKLOAD
  namespace: $NS
  labels: {app: $POD_WORKLOAD}
spec:
  runtimeClassName: vm
  nodeSelector: {kubernetes.io/os: darwin, kubernetes.io/hostname: $VM_NODE}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  containers:
    - name: nats
      image: $IMAGE_WORKLOAD
EOF

if wait_ready "$POD_WORKLOAD" "$READY_TIMEOUT"; then
	found=0
	deadline=$((SECONDS + 120))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if kn logs "$POD_WORKLOAD" 2>/dev/null | grep -q "Server is ready"; then found=1; break; fi
		sleep 5
	done
	if [ "$found" -eq 1 ]; then
		ladder ok "m11.5  $IMAGE_WORKLOAD is Running and logs 'Server is ready' (bare-name entrypoint resolved in the guest)"
	else
		ladder no "m11.5  $IMAGE_WORKLOAD is Running but never logged 'Server is ready'"
		kn logs "$POD_WORKLOAD" --tail=20 2>&1 | sed 's/^/      /' || true
	fi
else
	ladder no "m11.5  $IMAGE_WORKLOAD did not reach Running+Ready within ${READY_TIMEOUT}s"
fi

# ── m11.6 storage durability ──────────────────────────────────────────────────────
# storageClassName is REQUIRED: local-path is deliberately not the default class, so a
# claim that omits it never binds (docs/user/storage.md).
#
# Root-in-guest image and NO fsGroup: spike S3(2) recorded NO — Apple's virtiofs refuses
# mount_setattr(MOUNT_ATTR_IDMAP) with EINVAL — and the M11 plan's pre-decided
# consequence substitutes a root-in-guest image here and moves PVC-PGDATA-with-fsGroup to
# the follow-on. Adding an fsGroup here would assert a capability the platform does not
# have.
kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $PVC
  namespace: $NS
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 1Gi
EOF

store_pod() {
	kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD_STORE
  namespace: $NS
  labels: {app: $POD_STORE}
spec:
  runtimeClassName: vm
  nodeSelector: {kubernetes.io/os: darwin, kubernetes.io/hostname: $VM_NODE}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: $PVC
  containers:
    - name: app
      image: $IMAGE_LINUX
      command: ["/bin/sh", "-c"]
      args:
        - |
          echo "$1" >> /data/markers
          sync
          while true; do sleep 5; done
      volumeMounts:
        - {name: data, mountPath: /data}
EOF
}

STORE_OK=0
store_pod "$MARKER_A"
if wait_ready "$POD_STORE" "$READY_TIMEOUT"; then
	BOUND="$(kn get pvc "$PVC" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
	MARKERS="$(gexec "$POD_STORE" 'cat /data/markers' 2>/dev/null || true)"
	if [ "$BOUND" = "Bound" ] && printf '%s\n' "$MARKERS" | grep -q "$MARKER_A"; then
		STORE_OK=1
		PVNAME="$(kn get pvc "$PVC" -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)"
		ladder ok "m11.6-a  local-path PVC $PVC is $BOUND (PV ${PVNAME:-?}) and the vm pod wrote $MARKER_A into it"
		note "the local-path class reclaims Retain, so deleting this gate's namespace leaves PV ${PVNAME:-?} and its bytes on the node — remove it by hand"
	else
		ladder no "m11.6-a  PVC phase '${BOUND:-none}' / marker not written (got: ${MARKERS:-none})"
	fi
else
	ladder no "m11.6-a  the PVC-backed vm pod did not reach Running+Ready within ${READY_TIMEOUT}s"
fi

if [ "$STORE_OK" -eq 1 ]; then
	STORE_UID="$(kn get pod "$POD_STORE" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
	KILL_PID="$(pgrep -f "k3sm-vmhost.*$STORE_UID" 2>/dev/null | head -1 || true)"
	kill_rc=0
	if [ -n "${K3SM_M11_VMHOST_KILL:-}" ]; then
		note "killing the helper via \$K3SM_M11_VMHOST_KILL (pod uid $STORE_UID)"
		K3SM_M11_POD_UID="$STORE_UID" eval "$K3SM_M11_VMHOST_KILL" || kill_rc=$?
	elif [ "$(id -u)" = "0" ]; then
		pkill -9 -f "k3sm-vmhost.*$STORE_UID" || kill_rc=$?
	else
		note "the k3sm-vmhost helper is root-owned; running: sudo pkill -9 -f 'k3sm-vmhost.*$STORE_UID' (sudo may prompt)"
		sudo pkill -9 -f "k3sm-vmhost.*$STORE_UID" || kill_rc=$?
	fi
	if [ "$kill_rc" -ne 0 ]; then
		ladder no "m11.6-b  could not SIGKILL the pod's k3sm-vmhost helper (rc $kill_rc; matched pid '${KILL_PID:-none}')"
	else
		unhealthy=0
		deadline=$((SECONDS + 180))
		while [ "$SECONDS" -lt "$deadline" ]; do
			ready="$(kn get pod "$POD_STORE" -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null || true)"
			reason="$(kn get pod "$POD_STORE" -o jsonpath='{.status.containerStatuses[*].state.waiting.reason}' 2>/dev/null || true)"
			phase="$(kn get pod "$POD_STORE" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
			if [ "$reason" = "CrashLoopBackOff" ] || printf '%s' "$ready" | grep -q false || [ "$phase" = "Failed" ]; then
				unhealthy=1
				note "$POD_STORE after the helper SIGKILL: phase=${phase:-?} waiting=${reason:-none} ready=${ready:-?}"
				break
			fi
			sleep 5
		done
		if [ "$unhealthy" -eq 1 ]; then
			ladder ok "m11.6-b  SIGKILLing the pod's k3sm-vmhost helper (pid ${KILL_PID:-?}) takes the pod out of service (CrashLoopBackOff / not ready)"
		else
			ladder no "m11.6-b  the pod still reports ready 180s after its k3sm-vmhost helper was SIGKILLed — a dead guest must not present as a healthy backend"
		fi
	fi

	kn delete pod "$POD_STORE" --ignore-not-found --wait=true --timeout=180s >/dev/null 2>&1 || true
	gone=1
	if kn get pod "$POD_STORE" >/dev/null 2>&1; then gone=0; fi
	if [ "$gone" -eq 0 ]; then
		ladder no "m11.6-c  $POD_STORE did not delete within 180s — the recreate-against-the-same-claim leg cannot run"
	else
		store_pod "$MARKER_B"
		if wait_ready "$POD_STORE" "$READY_TIMEOUT"; then
			MARKERS="$(gexec "$POD_STORE" 'cat /data/markers' 2>/dev/null || true)"
			if printf '%s\n' "$MARKERS" | grep -q "$MARKER_A" && printf '%s\n' "$MARKERS" | grep -q "$MARKER_B"; then
				ladder ok "m11.6-c  a fresh vm pod on the SAME claim sees both the pre-kill marker $MARKER_A and the new $MARKER_B — the bytes survived the guest"
			else
				ladder no "m11.6-c  the recreated pod does not see both markers (got: ${MARKERS:-none})"
			fi
		else
			ladder no "m11.6-c  the recreated PVC-backed vm pod did not reach Running+Ready within ${READY_TIMEOUT}s"
		fi
	fi
else
	ladder no "m11.6-bc  durability not asserted — the PVC-backed vm pod never came up"
fi

# ── m11.8 amd64 fail-closed (NEGATIVE assertion) ──────────────────────────────────
kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD_AMD64
  namespace: $NS
spec:
  runtimeClassName: vm
  nodeSelector: {kubernetes.io/os: darwin, kubernetes.io/hostname: $VM_NODE}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  containers:
    - name: app
      image: $IMAGE_AMD64
      command: ["/bin/sh", "-c", "sleep 3600"]
EOF

matched=0
ran=0
phase=""
EVIDENCE=""
deadline=$((SECONDS + PULLFAIL_TIMEOUT))
while [ "$SECONDS" -lt "$deadline" ]; do
	phase="$(kn get pod "$POD_AMD64" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
	if [ "$phase" = "Running" ] || [ "$phase" = "Succeeded" ]; then ran=1; break; fi
	EVIDENCE="$( { kn describe pod "$POD_AMD64"; kn get events --field-selector "involvedObject.name=$POD_AMD64"; } 2>/dev/null || true )"
	if printf '%s\n' "$EVIDENCE" | grep -qF "$AMD64_SUBSTR"; then matched=1; break; fi
	sleep 5
done
if [ "$ran" -eq 1 ]; then
	ladder no "m11.8  the amd64-only image $IMAGE_AMD64 REACHED $phase under runtimeClassName: vm — this release attaches no guest Rosetta share, so an amd64 payload must be refused, not admitted"
elif [ "$matched" -eq 1 ]; then
	ladder ok "m11.8  $IMAGE_AMD64 fails closed and the failure names the platform mismatch ('$AMD64_SUBSTR')"
	printf '%s\n' "$EVIDENCE" | grep -F "$AMD64_SUBSTR" | head -2 | sed 's/^/      /' || true
else
	ladder no "m11.8  $IMAGE_AMD64 did not surface the platform mismatch within ${PULLFAIL_TIMEOUT}s (last phase '${phase:-?}') — a failure that does not name the mismatch is an opaque failure"
	kn describe pod "$POD_AMD64" 2>&1 | tail -n 20 | sed 's/^/      /' || true
fi
kn delete pod "$POD_AMD64" --ignore-not-found --wait=false >/dev/null 2>&1 || true

# ── The launch subset ends here. --core NEVER runs the rungs below. ───────────────
if [ "$MODE" = "core" ]; then
	note "m11.10-12 (Service, logs -f, stats) are the FULL ledger's rungs and are NOT part of --core"
	finish
fi

# ── m11.10 Service leg (FULL) ─────────────────────────────────────────────────────
kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $SVC_BOOT
  namespace: $NS
spec:
  selector: {app: $POD_BOOT}
  ports:
    - {name: http, port: 80, targetPort: $LISTEN_PORT, protocol: TCP}
EOF

if [ "$BOOT_OK" -eq 1 ]; then
	POD_IP="$(kn get pod "$POD_BOOT" -o jsonpath='{.status.podIP}' 2>/dev/null || true)"
	SVC_IP="$(kn get svc "$SVC_BOOT" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
	eps=""
	epready=""
	deadline=$((SECONDS + 120))
	while [ "$SECONDS" -lt "$deadline" ]; do
		eps="$(kn get endpointslices -l "kubernetes.io/service-name=$SVC_BOOT" -o jsonpath='{.items[*].endpoints[*].addresses[*]}' 2>/dev/null || true)"
		epready="$(kn get endpointslices -l "kubernetes.io/service-name=$SVC_BOOT" -o jsonpath='{.items[*].endpoints[*].conditions.ready}' 2>/dev/null || true)"
		if [ -n "$eps" ]; then break; fi
		sleep 5
	done
	if [ -n "$POD_IP" ] && printf '%s' "$eps" | grep -qF "$POD_IP" && printf '%s' "$epready" | grep -q true; then
		ladder ok "m11.10-a  the EndpointSlice for $SVC_BOOT carries the vm pod's published IP $POD_IP, ready"
	else
		ladder no "m11.10-a  the EndpointSlice for $SVC_BOOT does not carry a ready endpoint for pod IP '${POD_IP:-none}' (addresses: '${eps:-none}', ready: '${epready:-none}')"
	fi
	body=""
	if [ -n "$SVC_IP" ]; then
		deadline=$((SECONDS + 60))
		while [ "$SECONDS" -lt "$deadline" ]; do
			body="$(curl -sS -m 10 "http://$SVC_IP/" 2>/dev/null || true)"
			if printf '%s' "$body" | grep -qF "$MARKER"; then break; fi
			sleep 5
		done
	fi
	if printf '%s' "$body" | grep -qF "$MARKER"; then
		ladder ok "m11.10-b  a client reaches the vm-hosted workload through the ClusterIP $SVC_IP (marker $MARKER)"
	else
		ladder no "m11.10-b  the ClusterIP '${SVC_IP:-none}' did not serve the vm pod's marker (got: '${body:-nothing}')"
	fi
else
	ladder no "m11.10  Service leg not asserted — $POD_BOOT never became ready"
fi

# ── m11.11 kubectl logs -f (FULL) ─────────────────────────────────────────────────
# Its own pod, because the leg ENDS by deleting the pod: a follower that keeps running
# after its subject is gone is the failure this rung exists to catch, and proving that
# requires being allowed to delete the subject.
kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD_FOLLOW
  namespace: $NS
spec:
  runtimeClassName: vm
  nodeSelector: {kubernetes.io/os: darwin, kubernetes.io/hostname: $VM_NODE}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  containers:
    - name: app
      image: $IMAGE_LINUX
      command: ["/bin/sh", "-c"]
      args:
        - |
          i=1
          while true; do echo "m11-beat-\$i"; i=\$((i + 1)); sleep 1; done
EOF

if wait_ready "$POD_FOLLOW" "$READY_TIMEOUT"; then
	FOLLOW_OUT="$(mktemp -t m11-follow)"
	kn logs -f "$POD_FOLLOW" >"$FOLLOW_OUT" 2>&1 &
	FOLLOW_PID=$!
	sleep 10
	first="$(wc -l <"$FOLLOW_OUT" | tr -d " ")"
	sleep 10
	second="$(wc -l <"$FOLLOW_OUT" | tr -d " ")"
	if [ "$first" -gt 0 ] && [ "$second" -gt "$first" ]; then
		ladder ok "m11.11-a  kubectl logs -f STREAMS (line count grew $first -> $second over 10s)"
	else
		ladder no "m11.11-a  kubectl logs -f did not stream new lines ($first -> $second) — a one-shot dump is not a follow"
	fi
	kn delete pod "$POD_FOLLOW" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	exited=0
	deadline=$((SECONDS + 120))
	while [ "$SECONDS" -lt "$deadline" ]; do
		kill -0 "$FOLLOW_PID" 2>/dev/null || { exited=1; break; }
		sleep 2
	done
	if [ "$exited" -eq 1 ]; then
		frc=0
		wait "$FOLLOW_PID" 2>/dev/null || frc=$?
		FOLLOW_PID=""
		ladder ok "m11.11-b  kubectl logs -f terminates on its own once the pod is gone (exit $frc)"
	else
		ladder no "m11.11-b  kubectl logs -f was still running 120s after the pod was deleted — the follower hangs"
		kill "$FOLLOW_PID" >/dev/null 2>&1 || true
		FOLLOW_PID=""
	fi
	rm -f "$FOLLOW_OUT"
else
	ladder no "m11.11  logs -f not asserted — $POD_FOLLOW did not reach Running+Ready within ${READY_TIMEOUT}s"
fi

# ── m11.12 stats (FULL) ───────────────────────────────────────────────────────────
# The node's own /stats/summary, NOT `kubectl top`: top needs an operator-installed
# metrics-server, which k3sm deliberately does not ship (docs/user/limitations.md), so
# asserting top would test the operator's cluster rather than k3sm's stats path.
if [ "$BOOT_OK" -eq 1 ]; then
	SUMMARY="$(kubectl get --raw "/api/v1/nodes/$VM_NODE/proxy/stats/summary" 2>/dev/null || true)"
	WS="$(printf '%s' "$SUMMARY" | python3 -c '
import json,sys
ns, pod = sys.argv[1], sys.argv[2]
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); sys.exit(0)
for p in d.get("pods") or []:
    ref = p.get("podRef") or {}
    if ref.get("namespace") == ns and ref.get("name") == pod:
        print((p.get("memory") or {}).get("workingSetBytes") or "")
        sys.exit(0)
print("")
' "$NS" "$POD_BOOT" 2>/dev/null || true)"
	if [ -n "$WS" ] && [ "$WS" -gt 0 ] 2>/dev/null; then
		ladder ok "m11.12  /stats/summary reports $NS/$POD_BOOT with a memory working set ($WS bytes)"
	else
		ladder no "m11.12  /stats/summary does not report a memory working set for $NS/$POD_BOOT (got '${WS:-nothing}')"
	fi
else
	ladder no "m11.12  stats not asserted — $POD_BOOT never became ready"
fi

finish
