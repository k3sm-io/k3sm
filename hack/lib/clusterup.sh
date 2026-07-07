#!/usr/bin/env bash
# k3sm cluster bring-up library — sourced by every hack/acceptance/m<n>.sh gate.
# Adapted from the validated M0 spike (hack/spike/run.sh), which remains the M0 reference.
#
# Pre-M1 cluster_up uses prebuilt darwin/arm64 control-plane binaries (kwok-ci/k8s) + kine,
# exactly like the spike. From M1, the acceptance gates swap cluster_up's CP bring-up for
# `go run ./cmd/k3sm server` (the embedded control plane from source) — the kc()/wait_*/
# node_up helpers and the e2e asserts stay identical.
#
# Requires: macOS 26+ arm64, Go, Xcode CLT (clang), gh, curl, openssl, nc.

: "${KUBE_VERSION:=v1.36.2}"          # latest darwin-arm64 on kwok-ci/k8s
: "${KINE_VERSION:=v1.14.2}"
: "${K3SM_WORKDIR:=/tmp/k3sm-cluster}"
: "${APISERVER_PORT:=6444}"           # NOT 6443 — Docker Desktop's k8s squats there
: "${KINE_PORT:=2379}"

BIN="$K3SM_WORKDIR/bin"
export KUBECONFIG="${KUBECONFIG:-$K3SM_WORKDIR/cluster.kubeconfig}"
CP_TOKEN="acceptance-secret-token"
NODE_PID=""
SERVER_PID=""
# From M1 the gates can bring the whole control plane + node up via `k3sm server`
# (the embedded-by-supervision executor). It manages its own workdir/kubeconfig.
: "${SERVER_WORKDIR:=$K3SM_WORKDIR/server}"
# repo root = this file's dir /../.. (hack/lib -> repo), resolved regardless of caller cwd.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# kc runs kubectl against the acceptance cluster.
kc() { "$BIN/kubectl" --server="https://127.0.0.1:$APISERVER_PORT" --insecure-skip-tls-verify=true --token="$CP_TOKEN" "$@"; }

# wait_tcp blocks until 127.0.0.1:<port> accepts a connection (or times out).
wait_tcp() { local port=$1 n=0; until nc -z 127.0.0.1 "$port" 2>/dev/null; do sleep 0.3; n=$((n+1)); [ $n -gt 100 ] && { echo "timeout :$port" >&2; return 1; }; done; }

# cluster_down stops the node and every control-plane process.
cluster_down() {
	[ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
	for p in k3sm kube-controller-manager kube-scheduler kube-apiserver kine; do
		pkill -f "$BIN/$p" 2>/dev/null && echo "stopped $p" || true
	done
	# `k3sm server` supervises the CP binaries under $SERVER_WORKDIR/bin; clean those too.
	[ -n "$SERVER_WORKDIR" ] && for p in kube-controller-manager kube-scheduler kube-apiserver kine; do
		pkill -f "$SERVER_WORKDIR/bin/$p" 2>/dev/null || true
	done
}

# cluster_up brings up kine + apiserver + scheduler + controller-manager and writes $KUBECONFIG.
cluster_up() {
	mkdir -p "$BIN"
	( cd "$K3SM_WORKDIR"
	  # 1. prebuilt control-plane binaries (upstream won't ship darwin/arm64: k/k#118359)
	  if [ ! -x "$BIN/kube-apiserver" ]; then
		gh release download "${KUBE_VERSION}-kwok.0-darwin-arm64" --repo kwok-ci/k8s --dir "$BIN" --clobber
		chmod +x "$BIN"/*
	  fi
	  for b in kube-apiserver kube-scheduler kube-controller-manager kubectl; do codesign -s - -f "$BIN/$b" >/dev/null 2>&1 || true; done
	  # 2. kine — REQUIRES cgo (mattn/go-sqlite3); the no-cgo build disables sqlite
	  if [ ! -x "$BIN/kine" ]; then CGO_ENABLED=1 GOWORK=off GOBIN="$BIN" go install "github.com/k3s-io/kine@${KINE_VERSION}"; codesign -s - -f "$BIN/kine" >/dev/null 2>&1 || true; fi
	  # 3. SA keypair, static token, kubeconfig
	  [ -f sa.key ] || { openssl genrsa -out sa.key 2048 2>/dev/null; openssl rsa -in sa.key -pubout -out sa.pub 2>/dev/null; }
	  printf '%s,admin,admin-uid,"system:masters"\n' "$CP_TOKEN" > tokens.csv; chmod 600 tokens.csv
	  mkdir -p apiserver-certs
	  cat > "$KUBECONFIG" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: k3sm, cluster: {server: "https://127.0.0.1:$APISERVER_PORT", insecure-skip-tls-verify: true}}]
contexts: [{name: k3sm, context: {cluster: k3sm, user: admin}}]
current-context: k3sm
users: [{name: admin, user: {token: $CP_TOKEN}}]
EOF
	  # 4. kine (etcd shim over sqlite)
	  nohup "$BIN/kine" --listen-address "127.0.0.1:$KINE_PORT" > kine.log 2>&1 & wait_tcp "$KINE_PORT"
	  # 5. apiserver (AlwaysAllow auto-disables anonymous -> static token auth)
	  nohup "$BIN/kube-apiserver" \
		--etcd-servers="http://127.0.0.1:$KINE_PORT" --service-cluster-ip-range=10.43.0.0/16 \
		--service-account-key-file="$K3SM_WORKDIR/sa.pub" --service-account-signing-key-file="$K3SM_WORKDIR/sa.key" \
		--service-account-issuer=https://kubernetes.default.svc.cluster.local \
		--token-auth-file="$K3SM_WORKDIR/tokens.csv" --authorization-mode=AlwaysAllow \
		--bind-address=127.0.0.1 --advertise-address=127.0.0.1 \
		--secure-port="$APISERVER_PORT" --cert-dir="$K3SM_WORKDIR/apiserver-certs" --allow-privileged=true > apiserver.log 2>&1 &
	  until [ "$(kc get --raw /healthz 2>/dev/null)" = "ok" ]; do sleep 0.5; done
	  # 6. scheduler + controller-manager
	  nohup "$BIN/kube-scheduler" --kubeconfig="$KUBECONFIG" --authentication-kubeconfig="$KUBECONFIG" --authorization-kubeconfig="$KUBECONFIG" --leader-elect=false --bind-address=127.0.0.1 --secure-port=10259 > scheduler.log 2>&1 &
	  nohup "$BIN/kube-controller-manager" --kubeconfig="$KUBECONFIG" --authentication-kubeconfig="$KUBECONFIG" --authorization-kubeconfig="$KUBECONFIG" --leader-elect=false --service-account-private-key-file="$K3SM_WORKDIR/sa.key" --root-ca-file="$K3SM_WORKDIR/apiserver-certs/apiserver.crt" --bind-address=127.0.0.1 --secure-port=10257 --controllers=serviceaccount,serviceaccount-token,namespace,garbagecollector > cm.log 2>&1 &
	)
}

# node_up builds and starts a k3sm Virtual Kubelet node, then waits for it Ready.
#   node_up [node-name] [pod-root]
# --runtime hostprocess is PINNED: the M0 gate's posture is deliberately rootless
# (no netd helper, no root) and the binary's default flipped to runtimed in M10.1,
# so relying on the default would refuse to start via the runtimed preflight.
node_up() {
	local node_name="${1:-k3sm-m0}" pod_root="${2:-$K3SM_WORKDIR/pods}"
	( cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$BIN/k3sm" ./cmd/k3sm )
	codesign -s - -f "$BIN/k3sm" >/dev/null 2>&1 || true
	rm -rf "$pod_root"; mkdir -p "$pod_root"
	nohup "$BIN/k3sm" node --kubeconfig "$KUBECONFIG" --node-name "$node_name" --pod-root "$pod_root" --node-ip 127.0.0.1 --runtime hostprocess > "$K3SM_WORKDIR/node.log" 2>&1 &
	NODE_PID=$!
	local n=0
	until [ "$(kc get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "True" ]; do
		sleep 0.5; n=$((n+1)); [ $n -gt 60 ] && { echo "node $node_name not Ready within 30s" >&2; return 1; }
	done
}

# server_up brings the FULL stack up via `go run ./cmd/k3sm server`: the
# child-process control-plane executor (kine+apiserver+scheduler+CM) AND the
# Virtual Kubelet node, in one process. It is the M1 replacement for
# cluster_up+node_up. It points $KUBECONFIG + $CP_TOKEN at the server's own
# kubeconfig/token, then waits for healthz and the node Ready.
#   server_up [node-name] [runtime] [network]
#     runtime = hostprocess (helper default) | runtimed
#     network = none (default) | direct | helper | auto
#
# The runtime is ALWAYS passed explicitly on the argv (an explicit pin): the
# k3sm binary's own default flipped to runtimed in M10.1, but the gates that use
# this helper without root keep the deliberately rootless hostprocess posture.
#
# network=none is the NON-ROOT CI/dev bring-up: run the control plane + node
# WITHOUT the privileged host-network datapath (no lo0/utun plumbing) and WITHOUT
# the helper probe — an explicit control-plane-only backend (the network analog of
# a noop CNI), NOT a production fallback. M1's lo0/DNS data-path leg was always
# root-gated, so none preserves M1's assertions.
#
# network=direct is the ROOT integration bring-up that DOES serve a datapath: the
# Service proxy binds the wildcard *:nodePort listener directly and (with the
# runtimed runtime) pods get routable lo0 IPs, so NodePort is reachable and
# EndpointSlices populate. hack/acceptance/m3.sh uses `server_up <n> runtimed
# direct` under root. NOTE: under sudo, `go run` compiles into root's GOCACHE (a
# cold first build); that is expected for the integration tier.
server_up() {
	local node_name="${1:-k3sm-m1}" runtime="${2:-hostprocess}" network="${3:-none}"
	mkdir -p "$BIN" "$SERVER_WORKDIR"
	( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$BIN/kubectl-dl" ./cmd/k3sm >/dev/null 2>&1 ) || true
	# The server downloads/ad-hoc-signs the CP binaries + kubectl into its workdir.
	nohup env CGO_ENABLED=1 go run "$REPO_ROOT/cmd/k3sm" server \
		--work-dir "$SERVER_WORKDIR" --node-name "$node_name" --node-ip 127.0.0.1 \
		--runtime "$runtime" --pod-root "$K3SM_WORKDIR/pods" --network "$network" \
		> "$K3SM_WORKDIR/server.log" 2>&1 &
	SERVER_PID=$!

	export KUBECONFIG="$SERVER_WORKDIR/k3sm.kubeconfig"
	# Reuse the server's kubectl + read its token for the kc() helper.
	[ -x "$SERVER_WORKDIR/bin/kubectl" ] || true
	local n=0
	until [ -f "$KUBECONFIG" ] && [ -x "$SERVER_WORKDIR/bin/kubectl" ]; do
		sleep 1; n=$((n+1)); [ $n -gt 180 ] && { echo "k3sm server did not provision within 180s" >&2; tail -40 "$K3SM_WORKDIR/server.log" >&2; return 1; }
	done
	CP_TOKEN="$(awk -F'token: ' '/token: /{print $2}' "$KUBECONFIG" | tr -d '\r')"
	BIN="$SERVER_WORKDIR/bin"   # kc() uses $BIN/kubectl
	n=0
	until [ "$(kc get --raw /healthz 2>/dev/null)" = "ok" ]; do
		sleep 1; n=$((n+1)); [ $n -gt 180 ] && { echo "apiserver healthz not ok within 180s" >&2; tail -40 "$K3SM_WORKDIR/server.log" >&2; return 1; }
	done
	n=0
	until [ "$(kc get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "True" ]; do
		sleep 1; n=$((n+1)); [ $n -gt 120 ] && { echo "node $node_name not Ready within 120s" >&2; return 1; }
	done
}
