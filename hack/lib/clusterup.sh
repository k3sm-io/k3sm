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
# Pod-support artifacts staged for the runtimed posture (see server_up). It MUST sit
# under a prefix the per-pod Seatbelt profile admits for reading — /Library is in that
# baseline, $K3SM_WORKDIR is not — and it is deliberately NOT /Library/k3sm, which
# belongs to a real `k3sm install`; a gate must never write into or delete that.
#
# This is a FIXED internal path, NOT a knob. It is `readonly` on purpose: the gate
# both `rm -rf`s and recreates it, as root, and the two names differ by a single
# token — so an overridden value is not a customization, it is a root-owned
# `rm -rf` pointed at a real installation. stage_dir_ok below is asserted at every
# site that mutates it, so the invariant holds at all of them rather than at one.
readonly STAGE_DIR="${STAGE_DIR:-/Library/k3sm-acceptance}"
stage_dir_ok() { [ "$STAGE_DIR" = /Library/k3sm-acceptance ]; }
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

# Every timeout guard below is `if [ $n -gt N ]; then ...; fi`, NEVER the shorter
# `[ $n -gt N ] && { ...; }`. This is a correctness requirement, not style: a
# while/until loop exits with the status of the LAST command its body ran, and the
# short form evaluates to FALSE (status 1) on every pass that does not time out. When
# such a loop is the last statement of a function, the function inherits that 1, and
# under `set -e` the CALLER dies — silently, with no message, at the moment the wait
# actually SUCCEEDED. That is precisely how server_up used to abort m3.sh after the
# node reached Ready, printing nothing at all. `if/fi` yields 0 when the guard does
# not fire, so the loop and the function report success.
#
# wait_tcp blocks until 127.0.0.1:<port> accepts a connection (or times out).
wait_tcp() { local port=$1 n=0; until nc -z 127.0.0.1 "$port" 2>/dev/null; do sleep 0.3; n=$((n+1)); if [ $n -gt 100 ]; then echo "timeout :$port" >&2; return 1; fi; done; }

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
	# Remove the staged pod-support artifacts, through the same assertion the
	# bring-up side uses, so this can never become an arbitrary root rm -rf.
	stage_dir_ok && rm -rf /Library/k3sm-acceptance 2>/dev/null
	return 0
}

# lo0_flush sweeps lo0 of every /32 alias inside the given service + pod CIDRs —
# the datapath teardown/pre-flight step cluster_down does NOT do (it reaps
# PROCESSES but not kernel-global lo0 aliases, which outlive the process; see the
# m2.sh:~127 residual-alias assertion this satisfies). Requires root to remove an
# alias; a rootless caller allocates none, so it is a no-op over an empty set.
# It mirrors pkg/dev's lo0FlushCIDRs so the SIT (hack/sit/run.sh) and `k3sm dev`
# share one flush contract.
#   lo0_flush <svc-cidr> <pod-cidr>
lo0_flush() {
	local svc="${1:-10.43.0.0/16}" pod="${2:-100.64.0.0/10}" ip
	# `ifconfig lo0` inet lines → the IPv4 aliases; keep only those in a target CIDR.
	for ip in $(ifconfig lo0 2>/dev/null | awk '/inet /{print $2}'); do
		if _ip_in_cidr "$ip" "$svc" || _ip_in_cidr "$ip" "$pod"; then
			ifconfig lo0 -alias "$ip" 2>/dev/null && echo "flushed lo0 alias $ip" || true
		fi
	done
}

# _ip_in_cidr reports whether an IPv4 dotted-quad is inside a CIDR (pure bash
# integer math — no python/ipcalc dependency). Handles the /8,/10,/16 masks the
# cluster CIDRs use.
_ip_in_cidr() {
	local ip="$1" cidr="$2" net bits
	net="${cidr%/*}"; bits="${cidr#*/}"
	[ "$net" = "$cidr" ] && return 1   # not a CIDR
	local ipn netn mask
	ipn=$(_ip_to_int "$ip") || return 1
	netn=$(_ip_to_int "$net") || return 1
	if [ "$bits" -eq 0 ]; then mask=0; else mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF )); fi
	[ $(( ipn & mask )) -eq $(( netn & mask )) ]
}

# _ip_to_int converts a dotted-quad to a 32-bit integer.
_ip_to_int() {
	local a b c d IFS=.
	read -r a b c d <<<"$1"
	[ -n "$d" ] || return 1
	echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
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
		sleep 0.5; n=$((n+1)); if [ $n -gt 60 ]; then echo "node $node_name not Ready within 30s" >&2; return 1; fi
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
	# The runtimed runtime resolves three pod-support artifacts as SIBLINGS of the
	# running executable: k3sm-execshim (sandbox.FindExecShim — also falls back to
	# PATH) and the two DYLD shims (cmd/k3sm resolveSiblingDylib — sibling ONLY, no
	# override for the path shim). `go run` puts the executable in a temp build
	# directory, so NONE of those lookups can hit; the installed posture m2.sh proves
	# works only because `k3sm install` stages all three next to the binary.
	#
	# So for runtimed we build a real binary and stage its siblings, exactly as the
	# install path does, instead of `go run`. The failure this repairs is not
	# cosmetic: without the exec shim the server dies during node bring-up AFTER the
	# control plane is healthy.
	#
	# WHERE they are staged is equally load-bearing, and NOT a free choice. The path
	# shim is injected into the POD via DYLD_INSERT_LIBRARIES, so the POD's Seatbelt
	# profile must be able to READ it — and that profile's read baseline is exactly
	# /System, /usr, /bin and /Library (sbpl.go). It also DENIES the server work-dir
	# root, which is under $K3SM_WORKDIR. Staging beside the workdir therefore makes
	# dyld fail closed with "blocked by sandbox" and every pod dies at exec with
	# SIGABRT — which is what happens if you put these in $BIN. `k3sm install` avoids
	# this by staging into /Library/k3sm; we use a distinct /Library directory so a
	# gate run can never collide with, or clean up, a real installation.
	#
	# hostprocess needs none of this and keeps the cheaper `go run` path.
	local server_cmd=(go run "$REPO_ROOT/cmd/k3sm")
	if [ "$runtime" = runtimed ]; then
		[ "$(id -u)" -eq 0 ] || { echo "server_up: the runtimed posture stages pod-readable artifacts under $STAGE_DIR and needs root" >&2; return 1; }
		# Assert BEFORE the rm -rf, not only on teardown: this runs as root, and
		# /Library/k3sm-acceptance vs /Library/k3sm is one token apart.
		stage_dir_ok || { echo "server_up: refusing to stage into unexpected STAGE_DIR $STAGE_DIR" >&2; return 1; }
		rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"; chmod 755 "$STAGE_DIR"
		( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$STAGE_DIR/k3sm" ./cmd/k3sm ) \
			|| { echo "server_up: building k3sm failed" >&2; return 1; }
		codesign -s - -f "$STAGE_DIR/k3sm" >/dev/null 2>&1 || true
		( cd "$REPO_ROOT/.." && CGO_ENABLED=1 go build -o "$STAGE_DIR/k3sm-execshim" k3sm.io/runtimed/cmd/k3sm-execshim ) \
			|| { echo "server_up: building k3sm-execshim failed — the runtimed sandbox backend cannot start without it" >&2; return 1; }
		codesign -s - -f "$STAGE_DIR/k3sm-execshim" >/dev/null 2>&1 || true
		"$REPO_ROOT/../runtimed/hack/build-pathshim.sh" "$STAGE_DIR" >/dev/null \
			|| { echo "server_up: building the path-rebase shim failed — absolute volume mounts would escape the pod data volume" >&2; return 1; }
		codesign -s - -f "$STAGE_DIR/libk3sm_pathrebase_shim.dylib" >/dev/null 2>&1 || true
		"$REPO_ROOT/../darwin-net/hack/build-shim.sh" "$STAGE_DIR" >/dev/null \
			|| { echo "server_up: building the getaddrinfo DNS shim failed — in-pod cluster DNS would NXDOMAIN" >&2; return 1; }
		codesign -s - -f "$STAGE_DIR/libk3sm_getaddrinfo_shim.dylib" >/dev/null 2>&1 || true
		# The pod runs as a different uid than the staging root; the dylibs must be
		# world-readable or dyld fails closed exactly as an unadmitted path does.
		chmod 644 "$STAGE_DIR"/*.dylib 2>/dev/null || true
		server_cmd=("$STAGE_DIR/k3sm")
	fi
	# The server downloads/ad-hoc-signs the CP binaries + kubectl into its workdir.
	nohup env CGO_ENABLED=1 "${server_cmd[@]}" server \
		--work-dir "$SERVER_WORKDIR" --node-name "$node_name" --node-ip 127.0.0.1 \
		--runtime "$runtime" --pod-root "$K3SM_WORKDIR/pods" --network "$network" \
		> "$K3SM_WORKDIR/server.log" 2>&1 &
	SERVER_PID=$!

	export KUBECONFIG="$SERVER_WORKDIR/k3sm.kubeconfig"
	# Reuse the server's kubectl + read its token for the kc() helper.
	[ -x "$SERVER_WORKDIR/bin/kubectl" ] || true

	# server_died reports whether the server process we launched is gone. Every wait
	# below polls it, because the server can fail LONG after the control plane is
	# healthy — node bring-up runs last, and when it fails the server tears the whole
	# control plane down and exits. Without this check the waits below spin their full
	# timeout against a corpse and then blame the apiserver, hiding the one line in
	# server.log that actually says what happened.
	server_died() { [ -n "$SERVER_PID" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; }
	server_died_report() {
		echo "k3sm server exited during $1 — its last log lines:" >&2
		tail -20 "$K3SM_WORKDIR/server.log" >&2
		return 1
	}

	local n=0
	until [ -f "$KUBECONFIG" ] && [ -x "$SERVER_WORKDIR/bin/kubectl" ]; do
		server_died && { server_died_report "provisioning"; return 1; }
		sleep 1; n=$((n+1)); if [ $n -gt 180 ]; then echo "k3sm server did not provision within 180s" >&2; tail -40 "$K3SM_WORKDIR/server.log" >&2; return 1; fi
	done
	CP_TOKEN="$(awk -F'token: ' '/token: /{print $2}' "$KUBECONFIG" | tr -d '\r')"
	BIN="$SERVER_WORKDIR/bin"   # kc() uses $BIN/kubectl
	n=0
	until [ "$(kc get --raw /healthz 2>/dev/null)" = "ok" ]; do
		server_died && { server_died_report "control-plane bring-up"; return 1; }
		sleep 1; n=$((n+1)); if [ $n -gt 180 ]; then echo "apiserver healthz not ok within 180s" >&2; tail -40 "$K3SM_WORKDIR/server.log" >&2; return 1; fi
	done
	n=0
	until [ "$(kc get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "True" ]; do
		server_died && { server_died_report "node bring-up"; return 1; }
		sleep 1; n=$((n+1)); if [ $n -gt 120 ]; then echo "node $node_name not Ready within 120s" >&2; tail -20 "$K3SM_WORKDIR/server.log" >&2; return 1; fi
	done

	# A Ready node is NOT yet a cluster you can create a pod in. The apiserver's
	# ServiceAccount admission plugin refuses every pod until default/default exists,
	# and that object is created ASYNCHRONOUSLY by the controller-manager's
	# serviceaccount controller. A gate that starts creating pods the instant the node
	# goes Ready races it and fails with:
	#
	#   pods "..." is forbidden: error looking up service account default/default:
	#   serviceaccount "default" not found
	#
	# which reads like a misconfigured cluster but is only a bring-up that returned
	# too early. The race is timing-dependent, so it hides in whichever gate happens
	# to spend longer compiling its suite — m3.sh passed while m1.sh failed on the
	# very same bring-up. Waiting here fixes it for every caller at once.
	n=0
	until kc get serviceaccount default -n default >/dev/null 2>&1; do
		server_died && { server_died_report "default ServiceAccount creation"; return 1; }
		sleep 1; n=$((n+1)); if [ $n -gt 60 ]; then echo "default/default ServiceAccount not created within 60s" >&2; tail -20 "$K3SM_WORKDIR/server.log" >&2; return 1; fi
	done
}
