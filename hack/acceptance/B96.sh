#!/usr/bin/env bash
# k3sm B96 acceptance: HelmChart objects become helm Jobs, against an INSTALLED,
# RUNNING server (`sudo k3sm install` on this Mac, a live cluster at
# $KUBECONFIG). This gate boots nothing itself.
#
# Background. The server runs a helm controller (the k3s helm-controller
# analog): a helm.k3sm.io/v1 HelmChart is reconciled into a helm-install-<chart>
# Job that runs the pinned host helm as a native pod, and deleting the chart runs
# helm-delete-<chart> before its finalizer is released. A HelmChart dropped in the
# root-owned manifest directory is applied by the manifest reconciler, the k3s
# server/manifests shape.
#
# Asserts (the m1.sh PASS/FAIL ladder pattern):
#   1. the HelmChart CRD is Established,
#   2. a HelmChart dropped in /var/lib/k3sm/manifests (sudo) appears in the
#      cluster; its chartContent is a tiny chart of one ConfigMap built here,
#   3. helm-install-<chart> reaches Complete,
#   4. the chart's ConfigMap exists in the target namespace, carrying the value
#      the HelmChart's valuesContent set,
#   5. status.jobName names the install Job and the Failed condition is not True,
#   6. deleting the HelmChart runs helm-delete-<chart> to Complete,
#   7. the release's ConfigMap is gone, the chart's cluster-admin
#      ClusterRoleBinding (helm-<ns>-<chart>) is gone, and the HelmChart is gone,
#   8. an http:// repo is refused: the apiserver rejects the plain form (the CRD
#      rule), and a form the rule's prefix check misses (leading space) gets
#      Failed/InsecureRepo from the controller and no install Job,
#   9. (B96_ONLINE=1 only) a repo chart is fetched over https and installed:
#      podinfo with replicaCount 0, so no Linux pod is ever scheduled.
#
# Nothing is pinned to a node: the Job's own nodeSelector and toleration decide.
# Names carry a per-run suffix; everything created is removed on exit.
#
# Requires: kubectl, python3, sudo (to write the root-owned manifest directory).
set -euo pipefail

NS=kube-system
TARGET=default
MANIFEST_DIR=/var/lib/k3sm/manifests
PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
finish() {
	echo "----------------------------------------"
	echo "B96: $PASS passed, $FAIL failed"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "=========== B96 GREEN ==========="
}

if [ -z "${KUBECONFIG:-}" ]; then
	echo "KUBECONFIG must point at the RUNNING cluster this installed server belongs to (this gate boots nothing itself)" >&2
	exit 1
fi
kc() { kubectl "$@"; }
kc get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

RUN="$(date +%s)"
CHART="b96-$RUN"
CM="b96-cm-$RUN"
INSECURE="b96-insecure-$RUN"
ONLINE="b96-online-$RUN"
MANIFEST="$MANIFEST_DIR/b96-$RUN.yaml"
WORK="$(mktemp -d)"
cleanup() {
	sudo rm -f "$MANIFEST" 2>/dev/null || true
	for c in "$CHART" "$INSECURE" "$ONLINE"; do
		kc delete helmchart "$c" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	done
	kc delete configmap "$CM" -n "$TARGET" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT
echo "==> B96 acceptance (run $RUN)"

# wait_until <budget seconds> <command...>: poll until the command succeeds.
wait_until() {
	local deadline=$(( $(date +%s) + $1 )); shift
	while [ "$(date +%s)" -lt "$deadline" ]; do
		"$@" >/dev/null 2>&1 && return 0
		sleep 3
	done
	return 1
}
job_complete() {
	[ "$(kc get job "$1" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null)" = True ]
}
gone() { ! kc get "$@" >/dev/null 2>&1; }

# The chart: one ConfigMap whose name comes from values, so the install also
# proves valuesContent reaches helm. Built here, gzipped and base64'd for
# chartContent (no network, no helm on this side).
CONTENT="$(python3 - <<'PY'
import base64, io, tarfile
files = {
    "b96/Chart.yaml": "apiVersion: v2\nname: b96\nversion: 0.1.0\n",
    "b96/values.yaml": "name: unset\nvalue: unset\n",
    "b96/templates/cm.yaml": (
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n"
        "data:\n  value: {{ .Values.value | quote }}\n"
    ),
}
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    for name, text in files.items():
        data = text.encode()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(data))
print(base64.b64encode(buf.getvalue()).decode())
PY
)"

# 1. The CRD is Established (the controller ensures it at server start).
if kc wait --for=condition=Established crd/helmcharts.helm.k3sm.io --timeout=180s >/dev/null 2>&1; then
	ladder ok "b96-1  the helmcharts.helm.k3sm.io CRD is Established"
else
	ladder no "b96-1  the helmcharts.helm.k3sm.io CRD is Established"
fi

# 2. Drop the HelmChart in the root-owned manifest directory.
cat >"$WORK/chart.yaml" <<EOF2
apiVersion: helm.k3sm.io/v1
kind: HelmChart
metadata:
  name: $CHART
  namespace: $NS
spec:
  targetNamespace: $TARGET
  chartContent: $CONTENT
  valuesContent: |
    name: $CM
    value: from-values-$RUN
EOF2
sudo install -d -m 0755 -o root -g wheel "$MANIFEST_DIR"
sudo install -m 0644 -o root -g wheel "$WORK/chart.yaml" "$MANIFEST"
# The manifest sweep runs on fsnotify and at least every 60 s.
if wait_until 150 kc get helmchart "$CHART" -n "$NS"; then
	ladder ok "b96-2  a HelmChart dropped in $MANIFEST_DIR is applied"
else
	ladder no "b96-2  a HelmChart dropped in $MANIFEST_DIR is applied"
fi

# 3. The install Job completes.
if wait_until 300 job_complete "helm-install-$CHART"; then
	ladder ok "b96-3  helm-install-$CHART reaches Complete"
else
	ladder no "b96-3  helm-install-$CHART reaches Complete ($(kc get job "helm-install-$CHART" -n "$NS" -o jsonpath='{.status}' 2>/dev/null || echo absent))"
fi

# 4. The release's ConfigMap, with the value from valuesContent.
got="$(kc get configmap "$CM" -n "$TARGET" -o jsonpath='{.data.value}' 2>/dev/null || true)"
if [ "$got" = "from-values-$RUN" ]; then
	ladder ok "b96-4  the chart's ConfigMap exists with the valuesContent value"
else
	ladder no "b96-4  the chart's ConfigMap exists with the valuesContent value (got '${got:-absent}')"
fi

# 5. Status: jobName set, Failed not True.
job_name="$(kc get helmchart "$CHART" -n "$NS" -o jsonpath='{.status.jobName}' 2>/dev/null || true)"
failed="$(kc get helmchart "$CHART" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || true)"
if [ "$job_name" = "helm-install-$CHART" ] && [ "$failed" != True ]; then
	ladder ok "b96-5  status.jobName is the install Job and Failed is not True"
else
	ladder no "b96-5  status.jobName is the install Job and Failed is not True (jobName '$job_name', Failed '$failed')"
fi

# 6. Delete: remove the file first (the manifest directory never deletes, and a
# present file would re-create the chart), then the object.
sudo rm -f "$MANIFEST"
kc delete helmchart "$CHART" -n "$NS" --wait=false >/dev/null
if wait_until 300 job_complete "helm-delete-$CHART"; then
	ladder ok "b96-6  deleting the HelmChart runs helm-delete-$CHART to Complete"
else
	ladder no "b96-6  deleting the HelmChart runs helm-delete-$CHART to Complete"
fi

# 7. The release, the cluster-admin binding and the chart are gone.
if wait_until 60 gone configmap "$CM" -n "$TARGET"; then
	ladder ok "b96-7a the release's ConfigMap is uninstalled"
else
	ladder no "b96-7a the release's ConfigMap is uninstalled"
fi
if wait_until 60 gone clusterrolebinding "helm-$NS-$CHART"; then
	ladder ok "b96-7b the chart's cluster-admin ClusterRoleBinding helm-$NS-$CHART is removed"
else
	ladder no "b96-7b the chart's cluster-admin ClusterRoleBinding helm-$NS-$CHART is removed"
fi
if wait_until 60 gone helmchart "$CHART" -n "$NS"; then
	ladder ok "b96-7c the HelmChart is gone (finalizer released)"
else
	ladder no "b96-7c the HelmChart is gone (finalizer released)"
fi

# 8. An http:// repo is refused, at admission and by the controller.
insecure() {
	cat <<EOF2
apiVersion: helm.k3sm.io/v1
kind: HelmChart
metadata:
  name: $INSECURE
  namespace: $NS
spec:
  chart: podinfo
  repo: "$1"
EOF2
}
if out="$(insecure "http://charts.example.invalid" | kc apply -f - 2>&1)"; then
	ladder no "b96-8a the apiserver rejects an http:// repo (it was accepted)"
	kc delete helmchart "$INSECURE" -n "$NS" --wait=false >/dev/null 2>&1 || true
else
	if grep -q "must not be an http://" <<<"$out"; then
		ladder ok "b96-8a the apiserver rejects an http:// repo"
	else
		ladder no "b96-8a the apiserver rejects an http:// repo (error: $out)"
	fi
fi
insecure " http://charts.example.invalid" | kc apply -f - >/dev/null
reason_is_insecure() {
	[ "$(kc get helmchart "$INSECURE" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Failed")].reason}' 2>/dev/null)" = InsecureRepo ]
}
if wait_until 60 reason_is_insecure && gone job "helm-install-$INSECURE" -n "$NS"; then
	ladder ok "b96-8b the controller refuses a leading-space http:// repo: Failed/InsecureRepo, no install Job"
else
	ladder no "b96-8b the controller refuses a leading-space http:// repo: Failed/InsecureRepo, no install Job"
fi
kc delete helmchart "$INSECURE" -n "$NS" --wait=false >/dev/null 2>&1 || true

# 9. Online (opt-in): a repo chart fetched over https.
if [ "${B96_ONLINE:-0}" = 1 ]; then
	kc apply -f - >/dev/null <<EOF2
apiVersion: helm.k3sm.io/v1
kind: HelmChart
metadata:
  name: $ONLINE
  namespace: $NS
spec:
  targetNamespace: $TARGET
  repo: https://stefanprodan.github.io/podinfo
  chart: podinfo
  set:
    replicaCount: 0
EOF2
	if wait_until 300 job_complete "helm-install-$ONLINE"; then
		ladder ok "b96-9  a repo chart is fetched over https and installed"
	else
		ladder no "b96-9  a repo chart is fetched over https and installed"
	fi
	kc delete helmchart "$ONLINE" -n "$NS" --wait=false >/dev/null 2>&1 || true
	wait_until 300 gone helmchart "$ONLINE" -n "$NS" || true
else
	echo "SKIP  b96-9  online repo leg (set B96_ONLINE=1)"
fi

finish
