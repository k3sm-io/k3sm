#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# k3sm B239 acceptance: inside one vm Pod, a volume that no container mounts is
# out of every container's reach, against an INSTALLED, RUNNING node
# (`sudo k3sm install` on this Mac, a live cluster at $KUBECONFIG). This gate
# boots nothing itself.
#
# Background. The guest mounts a Pod's projected-class volumes (configMap,
# secret, projected, downwardAPI) from one pooled share, staged under
# /run/k3sm/shares/<tag>, and binds each declared volume out of it into the
# containers. The staging mount is guest-private: the guest binds every
# container's volumes out of it and then detaches it before the first
# container starts, so nothing is mounted at the staging path once a workload
# runs. Two ceilings stay and are documented in docs/user/limitations.md: the
# guest's mount list is pod-level (a container sees a sibling's declared volume
# at the sibling's mount path), and a uid-0 container can mount the shared
# volume device itself.
#
# The fixture: one vm Pod with automountServiceAccountToken false and
#   - container `a`, which mounts nothing;
#   - container `b`, which alone mounts a Secret (marker MB) and a projected
#     ServiceAccount token;
#   - a second Secret volume (marker MU) that no container mounts.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. in `a`, `ls -A /run/k3sm/shares` lists nothing;
#   2. in `a`, the guest-root view (/proc/1/root/run/k3sm/shares) holds no file,
#      and no ServiceAccount token is readable through either staging path;
#   3. in `a`, marker MU is found nowhere, neither in a's own tree nor through
#      /proc/1/root;
#   4. in `b`, its own Secret (MB) and its own token read at its mount paths;
#   5. ceiling, expected to SUCCEED: `a` reads b's Secret at b's mount path;
#   6. ceiling, expected to SUCCEED: `a` (uid 0) mounts the shared volume
#      device and finds MU in it;
#   7. docs/user/limitations.md no longer carries the two removed paragraphs
#      and does carry the ceiling items;
#   8. self-check: leg 3's search, run in `b` for MB, finds it, so a search
#      that could never match would be visible.
#
# The pod is pinned with nodeName to THIS Mac's node (k3sm-<short hostname>,
# or $K3SM_NODE_NAME) and keeps the darwin nodeSelector. It tolerates only the
# provider taint.
#
# Knobs:
#   K3SM_LAB=1            required; without it this gate FAILS (it never skips green)
#   B239_VM_IMAGE         the Linux image (default alpine:3.20, hack/lab/m11.sh's)
#   B239_SHARE_TAG        the pooled projected-volume share tag (default k3sm.proj)
#   B239_READY_TIMEOUT    seconds to wait for the pod to be Ready (default 600:
#                         a first vm boot pulls and unpacks the image)
#
# Requires: kubectl.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

GATE_NAME=B239
NS=default
VM_IMAGE="${B239_VM_IMAGE:-alpine:3.20}"
SHARE_TAG="${B239_SHARE_TAG:-k3sm.proj}"
READY_TIMEOUT="${B239_READY_TIMEOUT:-600}"
LIMITATIONS="$REPO_ROOT/docs/user/limitations.md"
STAGE=/run/k3sm/shares

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

# 7. The doc leg first: it needs no cluster, and it must hold whatever the
#    cluster says. The two removed paragraphs are matched by their opening
#    sentences; the ceiling by the phrases that state each item.
doc_leg() {
	local missing=""
	if grep -qF "a container can read volumes it does not mount" "$LIMITATIONS"; then
		missing="$missing removed-paragraph-1-still-present"
	fi
	if grep -qF "container-level volume separation inside a single" "$LIMITATIONS"; then
		missing="$missing removed-paragraph-2-still-present"
	fi
	local phrase
	for phrase in \
		"A volume that no container in the Pod mounts is not visible in any container's filesystem," \
		"except to a uid 0 container that mounts the shared volume device itself" \
		"Every container sees every volume that any container in the Pod mounts" \
		"separated by chroot only" \
		"can mount the Pod's shared" \
		"Put credentials that must not be shared in separate Pods"; do
		grep -qF "$phrase" "$LIMITATIONS" || missing="$missing absent:[$phrase]"
	done
	if [ -z "$missing" ]; then
		ladder ok "b239-7  limitations.md drops both removed paragraphs and carries the ceiling items"
	else
		ladder no "b239-7  limitations.md:$missing"
	fi
}

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "$GATE_NAME gate: NOT RUN. It needs K3SM_LAB=1 and an installed node at \$KUBECONFIG; this is a failure, not a skip." >&2
	exit 1
fi
if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at the RUNNING cluster this installed node belongs to (this gate boots nothing itself)" >&2
	exit 1
fi
kc() { kubectl "$@"; }
kc get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

NODE_NAME="${K3SM_NODE_NAME:-k3sm-$(hostname -s | tr '[:upper:]' '[:lower:]')}"
if ! kc get node "$NODE_NAME" >/dev/null 2>&1; then
	echo "node $NODE_NAME is not in the cluster: this gate pins its pod to THIS Mac's node (set K3SM_NODE_NAME to override)" >&2
	exit 1
fi

emit_header
echo "==> $GATE_NAME acceptance (node $NODE_NAME, vm image $VM_IMAGE, share tag $SHARE_TAG)"

doc_leg

# Per-run names and markers, so a leftover object of an earlier run can never
# match, and a marker cannot be found by accident in an image file.
RUN="$(date +%s)"
POD="b239-vm-$RUN"
SEC_B="b239-mounted-$RUN"
SEC_U="b239-unmounted-$RUN"
MB="b239-mounted-marker-$RUN-$$"
MU="b239-unmounted-marker-$RUN-$$"
cleanup() {
	kc delete pod "$POD" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kc delete secret "$SEC_B" "$SEC_U" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

# bounded <seconds> <cmd...> - run cmd, killing it after the budget. macOS ships
# no timeout(1), and an exec into a wedged guest must not hang the gate.
bounded() {
	local secs="$1"; shift
	"$@" &
	local pid=$!
	( sleep "$secs"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
	local watchdog=$!
	local rc=0
	wait "$pid" || rc=$?
	kill "$watchdog" 2>/dev/null || true
	wait "$watchdog" 2>/dev/null || true
	return "$rc"
}
# kx <container> <script> - run a shell script in one container of the pod.
kx() { bounded 300 kubectl exec "$POD" -n "$NS" -c "$1" -- sh -c "$2" 2>&1; }

kc create secret generic "$SEC_B" -n "$NS" --from-literal=key="$MB" >/dev/null
kc create secret generic "$SEC_U" -n "$NS" --from-literal=key="$MU" >/dev/null

kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $POD, namespace: $NS}
spec:
  runtimeClassName: vm
  nodeName: $NODE_NAME
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 1
  containers:
  - name: a
    image: $VM_IMAGE
    command: ["sleep", "3600"]
  - name: b
    image: $VM_IMAGE
    command: ["sleep", "3600"]
    volumeMounts:
    - {name: sec-b, mountPath: /etc/b239-secret, readOnly: true}
    - {name: token, mountPath: /var/run/b239-token, readOnly: true}
  volumes:
  - name: sec-b
    secret: {secretName: $SEC_B}
  - name: sec-u
    secret: {secretName: $SEC_U}
  - name: token
    projected:
      sources:
      - serviceAccountToken: {path: token, expirationSeconds: 3600}
EOF
if ! kc wait --for=condition=Ready "pod/$POD" -n "$NS" --timeout="${READY_TIMEOUT}s" >/dev/null 2>&1; then
	ladder no "b239-0  vm pod $POD Ready within ${READY_TIMEOUT}s (phase: $(kc get pod "$POD" -n "$NS" -o jsonpath='{.status.phase} {.status.message}' 2>/dev/null || true))"
	finish
fi
ladder ok "b239-0  vm pod $POD Ready"

# search_script <root> <marker> - prints the files under root that carry marker.
# Every proc, sys and dev directory is pruned (a guest root holds one per
# container, and walking procfs never ends); regular files only, so a projected
# volume's ..data symlinks are reached through the real files they point at.
search_script() {
	printf '%s' "find $1 \\( -name proc -o -name sys -o -name dev \\) -prune -o -type f -size -64k -print 2>/dev/null | while read -r f; do grep -lF '$2' \"\$f\" 2>/dev/null; done"
}

# 1. Nothing is mounted at the staging root once the containers run.
out1="$(kx a "ls -A $STAGE 2>/dev/null | wc -l")" || true
if [ "$(tr -d ' \n' <<<"$out1")" = 0 ]; then
	ladder ok "b239-1  in a, ls -A $STAGE lists nothing"
else
	ladder no "b239-1  in a, ls -A $STAGE lists entries (got: $(tr '\n' ' ' <<<"$out1" | cut -c1-200))"
fi

# 2. The guest-root view holds no staged file, and no token reads through
#    either staging path. The pooled share lays each volume out under its
#    volume name (<tag>/<volume>/<key>), so the token volume "token" with path
#    "token" is <tag>/token/token; leg 6 reads that same relative path off the
#    mounted device as the positive control, so a wrong guess turns leg 6 red.
out2="$(kx a "find /proc/1/root$STAGE -type f 2>/dev/null | wc -l; cat $STAGE/$SHARE_TAG/token/token /proc/1/root$STAGE/$SHARE_TAG/token/token 2>/dev/null | wc -c")" || true
files2="$(sed -n 1p <<<"$out2" | tr -d ' ')"
bytes2="$(sed -n 2p <<<"$out2" | tr -d ' ')"
if [ "$files2" = 0 ] && [ "$bytes2" = 0 ]; then
	ladder ok "b239-2  in a, /proc/1/root$STAGE holds no file and no token reads through either staging path"
else
	ladder no "b239-2  in a, staged files reachable (files under /proc/1/root$STAGE: '${files2}', token bytes read: '${bytes2}')"
fi

# 3. The unmounted volume's marker is found nowhere, in a's tree or the guest root.
hits3a="$(kx a "$(search_script / "$MU")")" || true
hits3b="$(kx a "$(search_script /proc/1/root "$MU")")" || true
if [ -z "$(tr -d ' \n' <<<"$hits3a$hits3b")" ]; then
	ladder ok "b239-3  in a, the unmounted volume's marker is found nowhere (own tree and /proc/1/root)"
else
	ladder no "b239-3  in a, the unmounted volume's marker is reachable at: $(tr '\n' ' ' <<<"$hits3a $hits3b" | cut -c1-300)"
fi

# 4. b reads its own declared volumes.
own4="$(kx b "cat /etc/b239-secret/key; echo; wc -c < /var/run/b239-token/token")" || true
if grep -qF "$MB" <<<"$own4" && [ "$(sed -n 2p <<<"$own4" | tr -d ' ')" -gt 0 ] 2>/dev/null; then
	ladder ok "b239-4  in b, its own Secret and its own ServiceAccount token read at its mount paths"
else
	ladder no "b239-4  in b, its own mounts did not read (got: $(tr '\n' ' ' <<<"$own4" | cut -c1-200))"
fi

# 5. Ceiling, expected to succeed: the pod-level mount list puts b's volume in a.
ceil5="$(kx a "cat /etc/b239-secret/key 2>/dev/null")" || true
if grep -qF "$MB" <<<"$ceil5"; then
	ladder ok "b239-5  ceiling holds as documented: a reads b's Secret at b's mount path"
else
	ladder no "b239-5  ceiling changed: a cannot read b's Secret at b's mount path; update limitations.md and this leg together"
fi

# 6. Ceiling, expected to succeed: uid 0 mounts the still-attached device.
ceil6="$(kx a "d=\$(mktemp -d) && mount -t virtiofs $SHARE_TAG \"\$d\" && { h=\$($(search_script "\$d" "$MU")); t=\$(wc -c < \"\$d/token/token\" 2>/dev/null || echo 0); umount \"\$d\"; [ -n \"\$h\" ] && [ \"\$t\" -gt 0 ] && echo B239-FOUND; }")" || true
if grep -qx "B239-FOUND" <<<"$ceil6"; then
	ladder ok "b239-6  ceiling holds as documented: uid 0 in a mounts the $SHARE_TAG device and reaches the unmounted volume and the token at <tag>/token/token"
else
	ladder no "b239-6  ceiling changed: a could not mount $SHARE_TAG or found nothing (got: $(tr '\n' ' ' <<<"$ceil6" | cut -c1-200)); update limitations.md and this leg together"
fi

# 8. Self-check: the leg-3 search finds a marker that is present.
self8="$(kx b "h=\$($(search_script / "$MB")); [ -n \"\$h\" ] && echo B239-FOUND")" || true
if grep -qx "B239-FOUND" <<<"$self8"; then
	ladder ok "b239-8  self-check: the leg-3 search finds b's marker in b's tree, so it is not vacuous"
else
	ladder no "b239-8  self-check: the leg-3 search found nothing in b, so leg 3 proves nothing"
fi

finish
