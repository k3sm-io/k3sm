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

# ── per-run isolation (cluster_reset) ───────────────────────────────────────
# Every gate boots its cluster into $K3SM_WORKDIR, whose default is a FIXED path —
# and nothing removed it, at bring-up or at teardown. So consecutive gates ran
# against each other's kine SQLite datastore. That is not theoretical: running
# m0..m10 back-to-back on 2026-08-27, m3 and m4 both died on "apiserver healthz not
# ok within 180s" over a server log reading `failed to allocate IP 10.43.0.10:
# provided IP is already allocated` — the PREVIOUS gate's Service IP allocation,
# replayed out of the previous gate's datastore; each then passed from a clean
# slate. A second symptom of the same shape: `listen tcp :10250: bind: address
# already in use`, a listener a previous gate left behind. A gate whose verdict
# depends on which gate ran before it is not a gate.
#
# cluster_reset is the repair, and the ONLY site that removes cluster state. Every
# bring-up entry point (cluster_up, server_up) calls it FIRST, so each gate starts
# from a clean cluster no matter what preceded it.
#
# It CLEANS THE FIXED DIR rather than allocating a mktemp one per run, deliberately:
#   - $K3SM_WORKDIR/bin and $SERVER_WORKDIR/bin are DOWNLOAD CACHES (a kwok-ci/k8s
#     release download plus a cgo `go install` of kine, per dir). A fresh dir per
#     run pays both for every gate and leaves an unbounded pile of trees in /tmp.
#     They hold no state — the datastore does — so keeping them is free of the bug.
#   - a temp dir isolates only the FILESYSTEM. Half the contamination is host-global
#     state no path can namespace: the :6444/:2379/:10250 listeners above, and the
#     lo0 aliases lo0_flush already sweeps. Those need an explicit reap either way.
#   - a fixed path keeps the logs of a failed gate findable afterwards.
# So: keep the path, keep the two bin caches, remove EVERYTHING else, reap first.
#
# CLUSTER_RESET_DONE makes it fire AT MOST ONCE per gate process. A gate that
# brings the cluster up, tears it down and brings it up again inside one run is
# testing continuity, and must not have its datastore deleted underneath it; the
# contract is "each gate RUN starts clean", not "each bring-up call wipes".
CLUSTER_RESET_DONE=""

# workdir_ok is the workdir analog of stage_dir_ok, and exists for the same reason:
# cluster_reset removes files, as root in the m2/m3 postures, under a path that is
# one token away from a real installation (/var/lib/k3sm/server is the installed
# server work dir; $SERVER_WORKDIR is the gate's). Unlike STAGE_DIR, $K3SM_WORKDIR
# is a genuine knob, so it cannot be pinned to a literal — it is constrained
# STRUCTURALLY instead, and asserted at EVERY site that removes or kills
# (cluster_reset, reset_dir, reap_port) rather than once at the top. A path that
# fails the assertion aborts the bring-up; nothing proceeds best-effort on a path
# the library could not vouch for.
workdir_ok() {
	local d="${1:-}"
	[ -n "$d" ] || return 1
	case "$d" in
	/*) ;;                                  # absolute only
	*) return 1 ;;
	esac
	case "$d" in
	*/../*|*/..|*//*) return 1 ;;           # no traversal, no empty component
	esac
	if [ "$d" = "/" ]; then return 1; fi
	# At least two components: /tmp is refused, /tmp/k3sm-cluster is accepted.
	if [ "$(dirname "$d")" = "/" ]; then return 1; fi
	if [ -n "${HOME:-}" ] && [ "$d" = "$HOME" ]; then return 1; fi
	# Never a real installation, never a system prefix. The trailing slash makes
	# the directory itself match its own prefix pattern.
	case "$d/" in
	/Library/k3sm/*|/var/lib/k3sm/*|/etc/*|/usr/*|/bin/*|/sbin/*|/dev/*|/System/*|/Applications/*|/Volumes/*|/Users/*/Library/*) return 1 ;;
	esac
	return 0
}

# reset_dir <dir> [keep...] removes every DIRECT CHILD of <dir> except the named
# keep entries. It never removes <dir> itself, never recurses past depth 1 for the
# decision, and refuses outright on a dir workdir_ok cannot vouch for. Residue it
# could not delete (the common case: a previous ROOT gate's files, seen by a later
# rootless gate) is a hard failure with the remediation printed — silently building
# on top of it is exactly the bug this file is fixing.
reset_dir() {
	local d="$1"; shift
	local keep=" $* " child base left=""
	if ! workdir_ok "$d"; then
		echo "reset_dir: refusing to clean an implausible work dir: $d" >&2
		return 1
	fi
	[ -d "$d" ] || return 0
	while IFS= read -r -d '' child; do
		base="${child##*/}"
		case "$keep" in
		*" $base "*) continue ;;
		esac
		rm -rf "$child" 2>/dev/null || true
		if [ -e "$child" ]; then left="$left $base"; fi
	done < <(find "$d" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
	if [ -n "$left" ]; then
		echo "reset_dir: could not remove stale cluster state in $d:$left" >&2
		echo "reset_dir: it is most likely owned by a previous ROOT gate run — clear it with: sudo rm -rf $d" >&2
		return 1
	fi
	return 0
}

# _port_listeners <port> → the pids LISTENING on <port>. As a non-root user lsof
# reports only this user's processes, so a root-owned stale listener is invisible
# here; that is a limit of the rootless posture, not something to work around.
#
# The trailing `|| true` is load-bearing, not defensive noise: lsof exits 1 when
# nothing matches, and the gates run under `set -euo pipefail`, where a plain
# `pids="$(_port_listeners "$port")"` assignment would then kill the caller — at
# the exact moment the port turned out to be FREE, i.e. on the success path.
_port_listeners() { lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | sort -u || true; }

# _proc_is_ours attributes a pid to THIS acceptance rig before anything kills it.
# Two witnesses, both structural: the executable path lies under one of the rig's
# own directories ($BIN, $SERVER_WORKDIR/bin, $STAGE_DIR), or the argv names one of
# them (`k3sm server --work-dir $SERVER_WORKDIR …` run via `go run` executes out of
# a temp build dir, so the path witness cannot see it — and that process is exactly
# the :10250 squatter). Anything else is left alone: an unattributable listener is
# someone else's process.
_proc_is_ours() {
	local pid="$1" comm args
	comm="$(ps -o comm= -p "$pid" 2>/dev/null || true)"
	args="$(ps -o args= -p "$pid" 2>/dev/null || true)"
	case "$comm" in
	"$K3SM_WORKDIR"/*|"$SERVER_WORKDIR"/*|"$STAGE_DIR"/*) return 0 ;;
	esac
	case "$args" in
	*"$K3SM_WORKDIR"/*|*"$SERVER_WORKDIR"/*|*"$STAGE_DIR"/*) return 0 ;;
	esac
	return 1
}

# reap_port <port> [fatal|warn] frees a port a PREVIOUS gate left listening.
# It kills only pids _proc_is_ours attributes to the rig (TERM, then KILL after a
# grace period). A listener it cannot attribute is never killed; what happens then
# is the mode:
#   fatal (default) — return non-zero. For $KINE_PORT/$APISERVER_PORT a foreign
#     listener is worse than a failure: wait_tcp would SUCCEED against it and the
#     gate would run against someone else's endpoint.
#   warn            — report and return 0. For the kubelet/scheduler/CM ports a
#     foreign holder produces an honest, self-explanatory bind error inside the
#     gate, so refusing to start over it would be a false pre-flight abort.
reap_port() {
	local port="$1" mode="${2:-fatal}" pid pids comm n=0
	if ! workdir_ok "$K3SM_WORKDIR"; then
		echo "reap_port: refusing to attribute processes against an implausible K3SM_WORKDIR: $K3SM_WORKDIR" >&2
		return 1
	fi
	for pid in $(_port_listeners "$port"); do
		if _proc_is_ours "$pid"; then
			kill "$pid" 2>/dev/null || true
			echo "reaped a stale :$port listener from a previous run (pid $pid)"
		fi
	done
	while [ -n "$(_port_listeners "$port")" ]; do
		sleep 0.2; n=$((n+1))
		if [ "$n" -eq 15 ]; then
			for pid in $(_port_listeners "$port"); do
				if _proc_is_ours "$pid"; then kill -9 "$pid" 2>/dev/null || true; fi
			done
		fi
		if [ "$n" -gt 25 ]; then break; fi
	done
	pids="$(_port_listeners "$port")"
	if [ -n "$pids" ]; then
		for pid in $pids; do
			comm="$(ps -o comm= -p "$pid" 2>/dev/null || true)"
			echo "reap_port: :$port is held by pid $pid ($comm), which is NOT one of this rig's processes — not killing it" >&2
		done
		if [ "$mode" = warn ]; then return 0; fi
		echo "reap_port: free :$port before running the gate (a foreign endpoint there would be indistinguishable from ours)" >&2
		return 1
	fi
	return 0
}

# cluster_reset puts the host back to a pre-gate state: no stale listeners on the
# ports the bring-up needs, and no cluster state under the work dirs except the two
# binary caches. Called first by cluster_up and server_up; safe to call directly.
cluster_reset() {
	local keep_extra="" rel port
	if [ -n "$CLUSTER_RESET_DONE" ]; then return 0; fi
	if ! workdir_ok "$K3SM_WORKDIR"; then
		echo "cluster_reset: refusing to reset an implausible K3SM_WORKDIR: $K3SM_WORKDIR" >&2
		return 1
	fi
	if ! workdir_ok "$SERVER_WORKDIR"; then
		echo "cluster_reset: refusing to reset an implausible SERVER_WORKDIR: $SERVER_WORKDIR" >&2
		return 1
	fi
	# Ports first: a live process holding the datastore open would otherwise be
	# writing into the tree while it is removed.
	for port in "$KINE_PORT" "$APISERVER_PORT"; do
		reap_port "$port" fatal || return 1
	done
	for port in 10250 10259 10257; do
		reap_port "$port" warn || return 1
	done
	# $SERVER_WORKDIR defaults INSIDE $K3SM_WORKDIR, so the outer sweep must keep
	# the component leading to it — otherwise it would take the server's bin cache
	# with it (a full CP re-download per gate).
	case "$SERVER_WORKDIR" in
	"$K3SM_WORKDIR"/*)
		rel="${SERVER_WORKDIR#"$K3SM_WORKDIR"/}"
		keep_extra="${rel%%/*}" ;;
	esac
	if [ -n "$keep_extra" ]; then
		reset_dir "$K3SM_WORKDIR" bin "$keep_extra" || return 1
	else
		reset_dir "$K3SM_WORKDIR" bin || return 1
	fi
	reset_dir "$SERVER_WORKDIR" bin || return 1
	mkdir -p "$K3SM_WORKDIR" "$SERVER_WORKDIR" || return 1
	CLUSTER_RESET_DONE=1
	return 0
}

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

# cluster_down stops the node and every control-plane process, and hands the host
# back the global state the run took from it: the ports, and the lo0 aliases.
#
# It is the EXIT-side mirror of cluster_reset (B150), and it exists because
# reaping only at BRING-UP leaves the LAST gate of a sequence uncleaned — nothing
# follows it to sweep up after. Measured on an ALL-GREEN m0 -> m1 -> m3 -> m4 run
# (2026-08-27, so this is not a failure path): the host was left with a root
# `k3sm server` alive 16 minutes still holding *:10250, plus lo0 aliases
# 10.43.0.10 and 100.64.0.1. That residue is precisely what makes a LATER,
# unrelated run — or a human's own `k3sm dev up` on the same Mac — die on
# "listen tcp :10250: bind: address already in use" or "failed to allocate IP
# 10.43.0.10: provided IP is already allocated".
#
# The signal-and-pkill block below provably does not cover two cases, and the
# observed leak is both of them at once, which is why the port sweep is the step
# that actually reaps the node rather than belt-and-braces:
#   - A process that hangs or ignores TERM. $SERVER_PID is signalled here, and the
#     leaked process IS that one: its control-plane children were already stopped
#     in the log while it kept the kubelet listener open. Only a KILL escalation
#     frees the port — which reap_port already implements (TERM, grace, KILL)
#     behind the rig-attribution rule.
#   - The pkill patterns are anchored at $BIN/<name>, so they cannot match the
#     `go run` temp binary (hostprocess posture) nor $STAGE_DIR/k3sm (runtimed
#     posture, where $BIN has by then been repointed at $SERVER_WORKDIR/bin).
#     reap_port's argv witness matches both.
cluster_down() {
	local port
	[ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
	for p in k3sm kube-controller-manager kube-scheduler kube-apiserver kine; do
		pkill -f "$BIN/$p" 2>/dev/null && echo "stopped $p" || true
	done
	# `k3sm server` supervises the CP binaries under $SERVER_WORKDIR/bin; clean those too.
	[ -n "$SERVER_WORKDIR" ] && for p in kube-controller-manager kube-scheduler kube-apiserver kine; do
		pkill -f "$SERVER_WORKDIR/bin/$p" 2>/dev/null || true
	done
	# Whatever survived the signals above is freed through the SAME attribution
	# rule the bring-up side uses: reap_port only ever kills a pid _proc_is_ours
	# can tie to this rig's own dirs or argv. A broad `pkill -f k3sm` would be
	# shorter and would kill a human's unrelated `k3sm dev` cluster on this
	# machine, so it is not an option here. The node/server port goes FIRST, so
	# the supervisor dies before the children it would otherwise re-parent.
	#
	# ALWAYS `warn`, never `fatal`: on the way out, a listener this rig cannot
	# attribute is a fact to report, not a teardown failure. cluster_down runs from
	# an EXIT trap under `set -e` and the gate's verdict is already decided by then,
	# so a non-zero return here could only corrupt an already-correct verdict.
	for port in 10250 10259 10257 "$APISERVER_PORT" "$KINE_PORT"; do
		reap_port "$port" warn || true
	done
	# Remove the staged pod-support artifacts, through the same assertion the
	# bring-up side uses, so this can never become an arbitrary root rm -rf.
	stage_dir_ok && rm -rf /Library/k3sm-acceptance 2>/dev/null
	# lo0 aliases are KERNEL-GLOBAL: they outlive every process reaped above, so no
	# amount of killing removes them. The datapath postures (m2/m3/m4, root) alias
	# the Service VIP and the pod IPs onto lo0 and nothing ever gave them back.
	# lo0_flush is CIDR-scoped to the ranges this rig allocates from, so an address
	# outside them is never touched; a rootless gate allocates none and cannot
	# remove one, which makes this a no-op there rather than a special case.
	lo0_flush 10.43.0.0/16 100.64.0.0/10 || true
	return 0
}

# lo0_flush sweeps lo0 of every /32 alias inside the given service + pod CIDRs —
# the datapath half of teardown, which killing PROCESSES cannot do because the
# aliases are kernel-global and outlive them (see the m2.sh:~127 residual-alias
# assertion this satisfies). cluster_down calls it as its last step; a gate with
# its own trap (m2.sh, hack/sit/run.sh) calls it directly. Requires root to remove
# an alias; a rootless caller allocates none, so it is a no-op over an empty set.
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
	# First statement, before anything is created or downloaded: a gate must not
	# inherit the previous gate's datastore or listeners (see cluster_reset).
	cluster_reset || return 1
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
	# First statement, before anything is created or built: a gate must not inherit
	# the previous gate's datastore or listeners (see cluster_reset).
	cluster_reset || return 1
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
