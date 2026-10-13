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

KUBE_PINNED_VERSION=v1.36.2                      # latest darwin-arm64 on kwok-ci/k8s; the pins below are for it
KUBE_VERSION="${KUBE_VERSION:-$KUBE_PINNED_VERSION}"
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

# Control-plane binary pins, one per release asset, for $KUBE_PINNED_VERSION only.
# kwok-ci/k8s publishes no checksums file for its releases (none among the
# assets, none in the release notes), so each digest is the `digest` field the
# GitHub release-asset API reports for the uploaded asset
# (GET /repos/kwok-ci/k8s/releases/tags/v1.36.2-kwok.0-darwin-arm64, read on
# 2026-10-13; the release was published 2026-06-13): GitHub's
# own hash of the bytes it serves, NOT a vendor-signed checksum. It binds every
# run to the bytes uploaded at release time; it cannot vouch for those bytes.
# Another KUBE_VERSION must supply all four K3SM_SPIKE_*_SHA256 overrides, or
# the download fails closed.
if [ "$KUBE_VERSION" = "$KUBE_PINNED_VERSION" ]; then
  _pin_apiserver=1afff09280a70553c72561e4c2d55ec95f8c979fa5933dba770aade5a3a93ca5          # GitHub asset API digest
  _pin_controller_manager=a2ad45b40d8a367022cd545d390469913aeef3c3b83300477e629c6af1bd2dad # GitHub asset API digest
  _pin_scheduler=c46f96dd961607a325482bd46f7e53fd78cf6106fcbac48315506f37a417f6ba          # GitHub asset API digest
  _pin_kubectl=112ed6605c8a68d5d3e6abef5f1beb5c087309e3979dc18d7c38b018cd7758a9            # GitHub asset API digest
else
  _pin_apiserver= _pin_controller_manager= _pin_scheduler= _pin_kubectl=
fi
KUBE_APISERVER_SHA256="${K3SM_SPIKE_KUBE_APISERVER_SHA256:-$_pin_apiserver}"
KUBE_CONTROLLER_MANAGER_SHA256="${K3SM_SPIKE_KUBE_CONTROLLER_MANAGER_SHA256:-$_pin_controller_manager}"
KUBE_SCHEDULER_SHA256="${K3SM_SPIKE_KUBE_SCHEDULER_SHA256:-$_pin_scheduler}"
KUBECTL_SHA256="${K3SM_SPIKE_KUBECTL_SHA256:-$_pin_kubectl}"

# kube_pin ASSET — the pinned sha256 of one release asset; empty if unpinned.
kube_pin() {
  case "$1" in
    kube-apiserver)          echo "$KUBE_APISERVER_SHA256" ;;
    kube-controller-manager) echo "$KUBE_CONTROLLER_MANAGER_SHA256" ;;
    kube-scheduler)          echo "$KUBE_SCHEDULER_SHA256" ;;
    kubectl)                 echo "$KUBECTL_SHA256" ;;
    *)                       echo "" ;;
  esac
}

# owned_dir DIR — refuse a directory that is a symlink or not owned by us: the
# verified binaries are staged, signed and run from here.
owned_dir() {
  if [ -L "$1" ] || [ ! -d "$1" ] || [ "$(stat -f %u "$1")" != "$(id -u)" ]; then
    echo "refusing $1: a symlink, not a directory, or not owned by uid $(id -u)"; exit 1
  fi
}

echo "==> work dir: $WORKDIR"; mkdir -p "$BIN"; owned_dir "$WORKDIR"; owned_dir "$BIN"
cd "$WORKDIR"; down || true

# 1. control-plane binaries — prebuilt darwin/arm64 (upstream refuses to ship these: k/k#118359).
# Each asset is downloaded by name into a private staging dir and kept there
# UNSIGNED: codesign -f rewrites the Mach-O, so the pin can only ever be checked
# before signing. The staged copy is re-verified on EVERY run (a warm cache
# included); it is then copied once into a private temp file in $BIN, which is
# verified AGAIN (closing the window between the first check and the copy),
# signed, and renamed over $BIN/$asset. A signed Mach-O is never overwritten in
# place; the temp file is removed on any failure.
STAGE="$WORKDIR/stage"
[ -L "$STAGE" ] && { echo "refusing $STAGE: a symlink"; exit 1; }
mkdir -m 0700 -p "$STAGE"; owned_dir "$STAGE"; chmod 0700 "$STAGE"
KUBE_TAG="${KUBE_VERSION}-kwok.0-darwin-arm64"
for asset in kube-apiserver kube-controller-manager kube-scheduler kubectl; do
  want=$(kube_pin "$asset")
  [ -n "$want" ] || { echo "no sha256 pin for $asset at $KUBE_VERSION (set K3SM_SPIKE_*_SHA256)"; exit 1; }
  if [ ! -f "$STAGE/$asset" ]; then
    echo "==> downloading $asset ($KUBE_TAG) from kwok-ci/k8s"
    gh release download "$KUBE_TAG" --repo kwok-ci/k8s --pattern "$asset" --dir "$STAGE" --clobber
  fi
  printf '%s  %s\n' "$want" "$STAGE/$asset" | shasum -a 256 -c - >/dev/null \
    || { echo "sha256 mismatch for $asset (pinned $want); removed the staged copy"; rm -f "$STAGE/$asset"; exit 1; }
  tmp=$(mktemp "$BIN/.$asset.XXXXXX") || { echo "mktemp in $BIN failed for $asset"; exit 1; }
  cp "$STAGE/$asset" "$tmp" || { rm -f "$tmp"; echo "copy of $asset failed"; exit 1; }
  printf '%s  %s\n' "$want" "$tmp" | shasum -a 256 -c - >/dev/null \
    || { rm -f "$tmp"; echo "sha256 mismatch for the $asset copy (pinned $want)"; exit 1; }
  chmod 0755 "$tmp" || { rm -f "$tmp"; echo "chmod of $asset failed"; exit 1; }
  # arm64 Mach-O must be at least ad-hoc signed to exec — the same codesign-on-pull k3sm will use.
  codesign -s - -f "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; echo "ad-hoc codesign of $asset failed"; exit 1; }
  mv -f "$tmp" "$BIN/$asset" || { rm -f "$tmp"; echo "install of $asset failed"; exit 1; }
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
