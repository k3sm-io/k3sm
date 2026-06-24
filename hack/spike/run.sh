#!/usr/bin/env bash
# k3sm M0 spike — bring up a REAL Kubernetes control plane NATIVELY on macOS/arm64
# (kube-apiserver + kube-scheduler + kube-controller-manager) backed by kine+SQLite,
# with kubectl working and a darwin node Ready. Zero Linux, no VM.
#
# Validates DESIGN.md §3/§5c on real hardware. See docs/M0-spike.md for the ladder.
#
# Usage:
#   hack/spike/run.sh up                    # download, build, start, validate (default)
#   hack/spike/run.sh down                  # stop all spike processes
#   hack/spike/run.sh kubectl get pods -A   # run kubectl against the spike cluster
#
# Requires: macOS 26+ arm64, Go (brew install go), Xcode CLT (clang), gh, curl, openssl.
set -euo pipefail

KUBE_VERSION="${KUBE_VERSION:-v1.36.2}"          # latest darwin-arm64 on kwok-ci/k8s
KINE_VERSION="${KINE_VERSION:-v1.14.2}"
WORKDIR="${K3SM_SPIKE_WORKDIR:-/tmp/k3sm-spike}"
APISERVER_PORT="${APISERVER_PORT:-6444}"         # NOT 6443 — Docker Desktop's k8s squats on 6443
KINE_PORT=2379
BIN="$WORKDIR/bin"
KUBECONFIG_FILE="$WORKDIR/spike.kubeconfig"
TOKEN="spike-secret-token"

kc() { "$BIN/kubectl" --server="https://127.0.0.1:$APISERVER_PORT" --insecure-skip-tls-verify=true --token="$TOKEN" "$@"; }

down() {
  for p in kube-controller-manager kube-scheduler kube-apiserver kine; do
    pkill -f "$BIN/$p" 2>/dev/null && echo "stopped $p" || true
  done
}
wait_tcp() { local port=$1 n=0; until nc -z 127.0.0.1 "$port" 2>/dev/null; do sleep 0.3; n=$((n+1)); [ $n -gt 100 ] && { echo "timeout :$port"; return 1; }; done; }

case "${1:-up}" in
  down)    down; exit 0 ;;
  kubectl) shift; kc "$@"; exit $? ;;
esac

echo "==> work dir: $WORKDIR"; mkdir -p "$BIN"; cd "$WORKDIR"; down || true

# 1. control-plane binaries — prebuilt darwin/arm64 (upstream refuses to ship these: k/k#118359).
if [ ! -x "$BIN/kube-apiserver" ]; then
  echo "==> downloading control-plane binaries ($KUBE_VERSION darwin-arm64) from kwok-ci/k8s"
  gh release download "${KUBE_VERSION}-kwok.0-darwin-arm64" --repo kwok-ci/k8s --dir "$BIN" --clobber
  chmod +x "$BIN"/*
fi
# arm64 Mach-O must be at least ad-hoc signed to exec — the same codesign-on-pull k3sm will use.
for b in "$BIN"/kube-apiserver "$BIN"/kube-scheduler "$BIN"/kube-controller-manager "$BIN"/kubectl; do
  codesign -s - -f "$b" >/dev/null 2>&1 || true
done

# 2. kine — REQUIRES CGO (mattn/go-sqlite3). The no-cgo build *disables* sqlite. (Spike finding.)
if [ ! -x "$BIN/kine" ]; then
  echo "==> building kine $KINE_VERSION (CGO_ENABLED=1)"
  CGO_ENABLED=1 GOWORK=off GOBIN="$BIN" go install "github.com/k3s-io/kine@${KINE_VERSION}"
  codesign -s - -f "$BIN/kine" >/dev/null 2>&1 || true
fi

# 3. SA keypair, static token, kubeconfig
[ -f sa.key ] || { openssl genrsa -out sa.key 2048 2>/dev/null; openssl rsa -in sa.key -pubout -out sa.pub 2>/dev/null; }
printf '%s,admin,admin-uid,"system:masters"\n' "$TOKEN" > tokens.csv; chmod 600 tokens.csv
mkdir -p apiserver-certs
cat > "$KUBECONFIG_FILE" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: spike, cluster: {server: "https://127.0.0.1:$APISERVER_PORT", insecure-skip-tls-verify: true}}]
contexts: [{name: spike, context: {cluster: spike, user: admin}}]
current-context: spike
users: [{name: admin, user: {token: $TOKEN}}]
EOF

# 4. kine (etcd shim over sqlite)
echo "==> starting kine"; nohup "$BIN/kine" --listen-address "127.0.0.1:$KINE_PORT" > kine.log 2>&1 & wait_tcp "$KINE_PORT"

# 5. apiserver  (AlwaysAllow auto-disables anonymous → static token auth; advertise 127.0.0.1 is fine for the spike)
echo "==> starting kube-apiserver on :$APISERVER_PORT"
nohup "$BIN/kube-apiserver" \
  --etcd-servers="http://127.0.0.1:$KINE_PORT" --service-cluster-ip-range=10.43.0.0/16 \
  --service-account-key-file="$WORKDIR/sa.pub" --service-account-signing-key-file="$WORKDIR/sa.key" \
  --service-account-issuer=https://kubernetes.default.svc.cluster.local \
  --token-auth-file="$WORKDIR/tokens.csv" --authorization-mode=AlwaysAllow \
  --bind-address=127.0.0.1 --advertise-address=127.0.0.1 \
  --secure-port="$APISERVER_PORT" --cert-dir="$WORKDIR/apiserver-certs" --allow-privileged=true > apiserver.log 2>&1 &
echo -n "==> waiting for apiserver healthz"; until [ "$(kc get --raw /healthz 2>/dev/null)" = "ok" ]; do echo -n "."; sleep 0.5; done; echo " ok"

# 6. scheduler + controller-manager
echo "==> starting kube-scheduler + kube-controller-manager"
nohup "$BIN/kube-scheduler" --kubeconfig="$KUBECONFIG_FILE" \
  --authentication-kubeconfig="$KUBECONFIG_FILE" --authorization-kubeconfig="$KUBECONFIG_FILE" \
  --leader-elect=false --bind-address=127.0.0.1 --secure-port=10259 > scheduler.log 2>&1 &
nohup "$BIN/kube-controller-manager" --kubeconfig="$KUBECONFIG_FILE" \
  --authentication-kubeconfig="$KUBECONFIG_FILE" --authorization-kubeconfig="$KUBECONFIG_FILE" \
  --leader-elect=false --service-account-private-key-file="$WORKDIR/sa.key" \
  --root-ca-file="$WORKDIR/apiserver-certs/apiserver.crt" --bind-address=127.0.0.1 --secure-port=10257 \
  --controllers=serviceaccount,serviceaccount-token,namespace,garbagecollector > cm.log 2>&1 &

# 7. register a darwin node Ready (API-level stand-in for the Virtual Kubelet provider — that's next product code)
echo "==> waiting for CM to create default ServiceAccounts"
until [ "$(kc get sa -A --no-headers 2>/dev/null | grep -c default)" -ge 4 ]; do sleep 0.5; done
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Node
metadata: {name: spike-darwin-node, labels: {kubernetes.io/os: darwin, kubernetes.io/arch: arm64}}
EOF
kc patch node spike-darwin-node --subresource=status --type=merge \
  -p "{\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\",\"reason\":\"SpikeReady\",\"lastHeartbeatTime\":\"$NOW\",\"lastTransitionTime\":\"$NOW\"}],\"nodeInfo\":{\"operatingSystem\":\"darwin\",\"architecture\":\"arm64\",\"kubeletVersion\":\"k3sm-spike\"}}}" >/dev/null

echo; echo "================ k3sm M0 spike: native control plane UP ================"
kc version | sed 's/^/  /'; echo; kc get ns; echo; kc get nodes -o wide
echo; echo "kubectl:  hack/spike/run.sh kubectl <args>   (KUBECONFIG=$KUBECONFIG_FILE)"
echo "stop:     hack/spike/run.sh down"
