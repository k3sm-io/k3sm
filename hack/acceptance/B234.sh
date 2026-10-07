#!/usr/bin/env bash
# k3sm B234 acceptance: projected volumes refresh at the kubelet cadence, against
# an INSTALLED, RUNNING node (`sudo k3sm install` on this Mac, a live cluster at
# $KUBECONFIG). This gate boots nothing itself.
#
# Background. A running pod used to hold its creation-time ConfigMap, Secret and
# ServiceAccount token until it was recreated. The provider now asks the runtime
# to re-render every running native pod's configMap / secret / downwardAPI /
# projected volumes about once a minute, each swap an atomic ..data flip.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern), all against ONE native pod:
#   1. the configMap mount dir carries a ..data symlink (the atomic-writer
#      layout) and every mounted value reads its initial v1,
#   2. the apiserver rejects an edit of an immutable ConfigMap (the premise of
#      leg 7),
#   3. an edited ConfigMap value reaches the pod within 120 s,
#   4. an updated Secret value reaches the pod within 120 s,
#   5. a ConfigMap deleted underneath the running pod raises a
#      ProjectedVolumeRefreshFailed Warning Event on the pod, and the mounted
#      file keeps its old value,
#   6. a subPath-mounted key does NOT change (one full refresh after leg 3),
#   7. an immutable ConfigMap is not re-read: deleting it and recreating it
#      under the same name with a new value does not reach the pod (one full
#      refresh after leg 3),
#   8. a projected ServiceAccount token with expirationSeconds 600 is re-minted
#      (the JWT exp claim moves forward) before the old token expires. The
#      refresh re-mints under 20% of remaining lifetime, so this leg waits up to
#      about nine minutes and dominates the run time.
#
# The pod is pinned with nodeName to THIS Mac's node (k3sm-<short hostname>, or
# $K3SM_NODE_NAME) and tolerates only the provider taint. Names carry a per-run
# suffix. The pod reads its mounts with shell builtins only (read, [ -L ]), so
# the reads go through the re-signed shell that keeps the path-rebase shim; it
# logs the JWT payload segment only, never the signed token.
#
# Needs K3SM_LAB=1. With K3SM_LAB unset the gate reports LAB-PENDING and exits
# 3, which is not a pass and never 0.
#
# Requires: kubectl, python3.
set -euo pipefail

NS=default
PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
finish() {
	echo "----------------------------------------"
	echo "B234: $PASS passed, $FAIL failed"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "=========== B234 GREEN ==========="
}

if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "B234 gate: LAB-PENDING: not a pass (needs K3SM_LAB=1 and an installed node at \$KUBECONFIG)" >&2
	exit 3
fi
if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at the RUNNING cluster this installed node belongs to (this gate boots nothing itself)" >&2
	exit 1
fi
kc() { kubectl "$@"; }
kc get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

RUN="$(date +%s)"
POD="b234-pod-$RUN"
CM_CFG="b234-cfg-$RUN"
CM_IMM="b234-imm-$RUN"
CM_GONE="b234-gone-$RUN"
SECRET="b234-sec-$RUN"
cleanup() {
	kc delete pod "$POD" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	for cm in "$CM_CFG" "$CM_IMM" "$CM_GONE"; do
		kc delete configmap "$cm" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
	kc delete secret "$SECRET" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

NODE_NAME="${K3SM_NODE_NAME:-k3sm-$(hostname -s | tr '[:upper:]' '[:lower:]')}"
if ! kc get node "$NODE_NAME" >/dev/null 2>&1; then
	echo "node $NODE_NAME is not in the cluster: this gate pins its pod to THIS Mac's node (set K3SM_NODE_NAME to override)" >&2
	exit 1
fi
echo "==> B234 acceptance (node $NODE_NAME, run $RUN)"

# configmap <name> <value> [immutable]
configmap() {
	local imm=""
	[ "${3:-}" = immutable ] && imm="immutable: true"
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: $1, namespace: $NS}
$imm
data: {key: $2}
EOF
}
configmap "$CM_CFG" v1
configmap "$CM_IMM" v1 immutable
configmap "$CM_GONE" v1
kc create secret generic "$SECRET" -n "$NS" --from-literal=key=v1 >/dev/null

# The pod prints one line every 5 s with every mounted value. Shell builtins
# only: a platform binary such as /bin/cat would lose the path-rebase shim.
# Indented to its place in the pod manifest's block scalar below.
READER="$(cat <<'EOF'
      while :; do
        c=; s=; e=; i=; g=; t=; d=no
        read -r c < /b234/cfg/key
        read -r s < /b234/sub/key
        read -r e < /b234/sec/key
        read -r i < /b234/imm/key
        read -r g < /b234/gone/key
        read -r t < /b234/tok/token
        [ -L /b234/cfg/..data ] && d=yes
        p=${t#*.}; p=${p%%.*}
        echo "B234 cfg=$c sub=$s sec=$e imm=$i gone=$g data=$d tok=$p"
        sleep 5
      done
EOF
)"
kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $POD, namespace: $NS}
spec:
  nodeName: $NODE_NAME
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  restartPolicy: Never
  containers:
  - name: c
    image: native
    command: ["/bin/sh", "-c"]
    args:
    - |
$READER
    volumeMounts:
    - {name: cfg, mountPath: /b234/cfg}
    - {name: cfg, mountPath: /b234/sub/key, subPath: key}
    - {name: sec, mountPath: /b234/sec}
    - {name: imm, mountPath: /b234/imm}
    - {name: gone, mountPath: /b234/gone}
    - {name: tok, mountPath: /b234/tok}
  volumes:
  - {name: cfg, configMap: {name: $CM_CFG}}
  - {name: sec, secret: {secretName: $SECRET}}
  - {name: imm, configMap: {name: $CM_IMM}}
  - {name: gone, configMap: {name: $CM_GONE}}
  - name: tok
    projected:
      sources:
      - serviceAccountToken: {path: token, expirationSeconds: 600}
EOF

# line: the pod's latest reader line. field <name> <line>: one value from it.
line() { kc logs "$POD" -n "$NS" --tail=20 2>/dev/null | grep '^B234 ' | tail -1 || true; }
field() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<<"$2"; }
# jwt_exp <payload segment>: the exp claim of a base64url JWT payload.
jwt_exp() {
	python3 -c 'import base64,json,sys; p=sys.argv[1]; p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))["exp"])' "$1" 2>/dev/null || true
}
# wait_for <budget seconds> <field> <value>: poll the reader until field=value.
wait_for() {
	local deadline=$(( $(date +%s) + $1 )) l
	while [ "$(date +%s)" -lt "$deadline" ]; do
		l="$(line)"
		[ "$(field "$2" "$l")" = "$3" ] && return 0
		sleep 3
	done
	return 1
}

ready=no
kc wait --for=condition=Ready "pod/$POD" -n "$NS" --timeout=120s >/dev/null 2>&1 && ready=yes
first=""
for _ in $(seq 1 20); do
	first="$(line)"
	[ -n "$(field tok "$first")" ] && break
	sleep 3
done

# 1. The atomic-writer layout, and every initial value.
if [ "$ready" = yes ] && [ "$(field data "$first")" = yes ] \
	&& [ "$(field cfg "$first")/$(field sub "$first")/$(field sec "$first")/$(field imm "$first")/$(field gone "$first")" = "v1/v1/v1/v1/v1" ]; then
	ladder ok "b234-1  configMap mount has a ..data symlink and every mount reads v1"
else
	ladder no "b234-1  configMap mount has a ..data symlink and every mount reads v1 (ready=$ready, line: ${first:-none})"
fi
exp0="$(jwt_exp "$(field tok "$first")")"

# 2. The premise of leg 7: an immutable ConfigMap cannot be edited in place.
if ! kc patch configmap "$CM_IMM" -n "$NS" --type merge -p '{"data":{"key":"v2"}}' >/dev/null 2>&1; then
	ladder ok "b234-2  the apiserver rejects an edit of an immutable ConfigMap"
else
	ladder no "b234-2  the apiserver rejects an edit of an immutable ConfigMap (the patch was accepted)"
fi

# The edits, all at once.
kc patch configmap "$CM_CFG" -n "$NS" --type merge -p '{"data":{"key":"v2"}}' >/dev/null
kc patch secret "$SECRET" -n "$NS" --type merge -p '{"stringData":{"key":"v2"}}' >/dev/null
kc delete configmap "$CM_IMM" -n "$NS" --wait=true >/dev/null
configmap "$CM_IMM" v2 immutable
kc delete configmap "$CM_GONE" -n "$NS" --wait=true >/dev/null

# 3 and 4. The edited values arrive within 120 s.
if wait_for 120 cfg v2; then
	ladder ok "b234-3  an edited ConfigMap value reaches the pod within 120 s"
else
	ladder no "b234-3  an edited ConfigMap value reaches the pod within 120 s (line: $(line))"
fi
cfg_seen="$(date +%s)"
if wait_for 60 sec v2; then
	ladder ok "b234-4  an updated Secret value reaches the pod"
else
	ladder no "b234-4  an updated Secret value reaches the pod (line: $(line))"
fi

# 5. The deleted ConfigMap: a Warning Event on THIS pod, and the old file stays.
uid="$(kc get pod "$POD" -n "$NS" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
ev=""
for _ in $(seq 1 40); do
	[ -n "$uid" ] || break
	ev="$(kc get events -n "$NS" --field-selector "involvedObject.uid=$uid,reason=ProjectedVolumeRefreshFailed" -o jsonpath='{.items[*].message}' 2>/dev/null || true)"
	grep -q '"gone"' <<<"$ev" && break
	sleep 3
done
if grep -q '"gone"' <<<"$ev"; then
	ladder ok "b234-5a a ConfigMap deleted underneath the pod raises a ProjectedVolumeRefreshFailed Warning"
else
	ladder no "b234-5a a ConfigMap deleted underneath the pod raises a ProjectedVolumeRefreshFailed Warning (events: '${ev:-none}')"
fi
if [ "$(field gone "$(line)")" = v1 ]; then
	ladder ok "b234-5b the deleted ConfigMap's mounted file keeps its old value"
else
	ladder no "b234-5b the deleted ConfigMap's mounted file keeps its old value (line: $(line))"
fi

# 6 and 7. One full refresh after leg 3 saw the new value, the subPath key and
# the immutable volume still read v1.
settle=$(( cfg_seen + 75 - $(date +%s) ))
[ "$settle" -gt 0 ] && sleep "$settle"
last="$(line)"
if [ "$(field sub "$last")" = v1 ] && [ "$(field cfg "$last")" = v2 ]; then
	ladder ok "b234-6  a subPath-mounted key is never refreshed (sub=v1 while cfg=v2)"
else
	ladder no "b234-6  a subPath-mounted key is never refreshed (line: $last)"
fi
if [ "$(field imm "$last")" = v1 ]; then
	ladder ok "b234-7  an immutable ConfigMap is not re-read (recreated as v2, pod still reads v1)"
else
	ladder no "b234-7  an immutable ConfigMap is not re-read (line: $last)"
fi

# 8. The token is re-minted before the old one expires.
exp1=""
if [ -n "$exp0" ]; then
	while [ "$(date +%s)" -lt $(( exp0 - 30 )) ]; do
		exp1="$(jwt_exp "$(field tok "$(line)")")"
		[ -n "$exp1" ] && [ "$exp1" -gt "$exp0" ] && break
		sleep 10
	done
fi
if [ -n "$exp0" ] && [ -n "$exp1" ] && [ "$exp1" -gt "$exp0" ]; then
	ladder ok "b234-8  the projected SA token is re-minted before it expires (exp $exp0 -> $exp1)"
else
	ladder no "b234-8  the projected SA token is re-minted before it expires (exp before '${exp0:-?}', after '${exp1:-?}')"
fi

finish
