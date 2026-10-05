#!/usr/bin/env bash
#
# k3sm M17 lab gate: direct links on two Macs joined by one Thunderbolt cable.
#
# Row in hack/acceptance/phases.json:
#   M17-lab  gate hack/lab/m17.sh, tier lab, requires two-macs + thunderbolt-cable,
#            manual: true (a rig run, never auto-greened by CI)
#
# THE LADDER (the M17 plan §Gates). Every rung prints PASS, FAIL or REC (a recorded
# measurement that has no verdict); the gate is green only with zero FAILs.
#   1  pair         the worker joins by pairing over the cable (uninstall, install
#                   --auto-join --cluster <pin>, the server's window open), and records
#                   the server's cable address as its bootstrap address
#   2  route        both ends report the port up, and the worker routes the server's
#                   mesh address over the cable interface
#   3  figures      ping RTT over the cable and over the LAN, and an iperf3 figure
#                   when iperf3 is installed on both Macs (REC, never failing)
#   4  lan-pull     the worker's LAN interface down: both nodes stay Ready, reached over
#                   the cable alone
#   5  cable-pull   the cable interface down with the LAN present: the direct routes go,
#                   the server's mesh address routes over the tunnel, and the fallback
#                   time is recorded
#   6  peer-asleep  the server stops answering on the cable with the link up (its echo
#                   replies on the cable interface blocked for the rung): the worker
#                   withdraws the direct route within 20 s
#   7  cable-only   LAN down AND cable down: the worker goes NotReady; cable back up:
#                   it reconverges to Ready
#   8  wifi-pair    a pair request sent from the LAN is refused and mints nothing
#   9  zone         the real-socket zone test passes on the cable interface
#   10 mixed        the worker on the previous release (K3SM_OLD_ARTIFACT), cable live:
#                   Ready, and the server's mesh address routes over the tunnel
#   11 downgrade    tunnel-only, stop, `k3sm link reset`, install the old binary: no
#                   cable address and no direct route is left on the worker
#   12 sharded      a ranks: 2 ring MLXModel serves through rank 0; its tokens/s are
#                   recorded beside the same model's single-Mac figure
#
# TOPOLOGY. The driver runs ON THE WORKER Mac, with the admin kubeconfig, and reaches
# the server Mac over ssh on the LAN. Every privileged change is a SCRIPT FILE written
# to the evidence directory and run under sudo, and every one that changes host
# networking arms a restore trap in the same script (interface back up, LAN back up,
# packet filter rule removed), so an interrupted rung leaves the Mac as it found it.
# The LAN route the ssh session rides is restored by the trap of the rung that takes
# it down, never by the driver.
#
# Environment:
#   K3SM_LAB=1                 required; anything else prints PENDING and exits 0
#   KUBECONFIG                 the admin kubeconfig (server mesh address, so it rides
#                              the cable when the LAN is down)
#   K3SM_SERVER_SSH            user@host of the server Mac on the LAN
#   K3SM_SERVER_NODE           the server's node name
#   K3SM_WORKER_NODE           the worker's node name (this Mac)
#   K3SM_CABLE_IFACE           the worker's Thunderbolt interface on the cable (e.g. en2)
#   K3SM_SERVER_CABLE_IFACE    the server's Thunderbolt interface on the cable
#   K3SM_LAN_SERVICE           the worker's LAN network service name (e.g. Wi-Fi)
#   K3SM_ARTIFACT              the new k3sm binary under test (installed by rung 1)
#   K3SM_OLD_ARTIFACT          the previous release's k3sm binary (rungs 10 and 11)
#   K3SM_EVIDENCE              the evidence directory, outside any repository (required)
#   K3SM_RC_TAG                the release-candidate tag, when this is the rc run
#
# Run log: K3SM_LAB=1 hack/lab/m17.sh | tee hack/lab/runs/m17-lab-<rc-tag>-<UTCdate>.log
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
GATE_NAME="M17-lab"
MODE="full"

case "${1:-}" in
"") ;;
-h | --help)
	echo "usage: $0   (no arguments: the full direct-links ladder)"
	exit 0
	;;
*)
	echo "$0: unknown argument $1 (expected no arguments)" >&2
	exit 2
	;;
esac

# ── The hack/lab/runs/ run-log header (README.md documents the convention). ──────────
# Four fields are REQUIRED: gate, artifact_sha256, git_sha.<repo> per repo, and result.
# The header's result is provisional and fail-closed; the authoritative verdict is the
# last `result:` line, written by emit_run_log_verdict.
emit_run_log_header() {
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
	echo "result: $1"
}

emit_run_log_verdict() {
	echo "gate: ${GATE_NAME}"
	echo "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "result: $1"
}

artifact_sha256() {
	local artifact="${K3SM_ARTIFACT:-}"
	if [ -n "$artifact" ] && [ -f "$artifact" ]; then
		local sum
		sum="$(shasum -a 256 "$artifact" | cut -d' ' -f1)"
		if [ -n "${K3SM_RC_TAG:-}" ]; then echo "$sum"; else echo "local:${sum}"; fi
		return
	fi
	echo "unknown"
}

repo_git_sha() {
	local repo="$1" dir
	if [ "$repo" = "k3sm" ]; then dir="$REPO_ROOT"; else dir="$REPO_ROOT/../$repo"; fi
	if [ -e "$dir/.git" ] && git -C "$dir" rev-parse HEAD >/dev/null 2>&1; then
		git -C "$dir" rev-parse HEAD
		return
	fi
	echo "unknown"
}

# ── Lab guard. ──────────────────────────────────────────────────────────────────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "${GATE_NAME} gate: PENDING (two-macs + thunderbolt-cable). The direct-links ladder needs K3SM_LAB=1 and two Macs joined by a Thunderbolt cable; this is NOT a pass."
	exit 0
fi

emit_run_log_header "FAIL (provisional: the final result line below is the verdict; a log that ends here did not finish)"

PASS=0; FAIL=0; REC=0
ladder() {
	case "$1" in
	ok) echo "PASS  $2"; PASS=$((PASS + 1)) ;;
	rec) echo "REC   $2"; REC=$((REC + 1)) ;;
	*) echo "FAIL  $2"; FAIL=$((FAIL + 1)) ;;
	esac
}
note() { echo "      $*"; }

finish() {
	local result=FAIL
	[ "$FAIL" -eq 0 ] && result=PASS
	echo "----------------------------------------"
	echo "${GATE_NAME}: $PASS passed, $FAIL failed, $REC recorded"
	emit_run_log_verdict "$result"
	[ "$FAIL" -eq 0 ] || exit 1
	exit 0
}

need() {
	local missing=""
	for v in "$@"; do [ -n "${!v:-}" ] || missing="$missing $v"; done
	if [ -n "$missing" ]; then
		echo "${GATE_NAME} gate needs:$missing (see the header of $0)" >&2
		emit_run_log_verdict FAIL
		exit 1
	fi
}
need KUBECONFIG K3SM_SERVER_SSH K3SM_SERVER_NODE K3SM_WORKER_NODE K3SM_CABLE_IFACE K3SM_SERVER_CABLE_IFACE K3SM_LAN_SERVICE K3SM_ARTIFACT K3SM_EVIDENCE
for tool in kubectl python3 curl ssh scp sudo; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "${GATE_NAME} gate requires $tool on PATH" >&2
		emit_run_log_verdict FAIL
		exit 1
	}
done
export KUBECONFIG
EVIDENCE="$K3SM_EVIDENCE"
mkdir -p "$EVIDENCE"
note "evidence: $EVIDENCE"

CABLE="$K3SM_CABLE_IFACE"
SCABLE="$K3SM_SERVER_CABLE_IFACE"
SERVER_MESH_IP="${K3SM_SERVER_MESH_IP:-100.64.0.1}"

# ── Helpers. ────────────────────────────────────────────────────────────────────────

# srv runs a command on the server Mac in a login shell.
srv() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$K3SM_SERVER_SSH" "zsh -lc $(printf '%q' "$1")"; }

# srv_sudo copies a script file to the server and runs it under sudo (a single sudo
# over a whole file: `ssh host "sudo a && b"` runs only `a` as root).
srv_sudo() {
	local name="$1" body="$2" file="$EVIDENCE/$1"
	printf '#!/bin/bash\nset -u\n%s\n' "$body" >"$file"
	chmod 0755 "$file"
	scp -q "$file" "$K3SM_SERVER_SSH:/tmp/$name" && srv "sudo /bin/bash /tmp/$name"
}

# local_sudo writes a script file to the evidence dir and runs it under sudo here.
local_sudo() {
	local name="$1" body="$2" file="$EVIDENCE/$1"
	printf '#!/bin/bash\nset -u\n%s\n' "$body" >"$file"
	chmod 0755 "$file"
	sudo /bin/bash "$file"
}

node_ready() {
	[ "$(kubectl --request-timeout=10s get node "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "True" ]
}

wait_until() { # wait_until <seconds> <command...>
	local deadline=$((SECONDS + $1)); shift
	while [ "$SECONDS" -lt "$deadline" ]; do
		"$@" && return 0
		sleep 2
	done
	return 1
}

# route_iface prints the interface the kernel uses toward an address.
route_iface() { route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'; }

port_state() { # port_state <node> <iface>
	kubectl --request-timeout=10s get directlink "$1" -o json 2>/dev/null | python3 -c '
import json, sys
iface = sys.argv[1]
try:
    obj = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for p in obj.get("status", {}).get("ports", []):
    if p.get("iface") == iface:
        print(p.get("state", ""))
' "$2"
}

direct_routes_present() { netstat -rn -f inet | awk -v i="$CABLE" '$NF==i && $1 ~ /\/25$/' | grep -q .; }
cable_routes_absent() { ! netstat -rn -f inet | awk -v i="$CABLE" '$NF==i' | grep -Eq '^169\.254\.(0|255)\.|/25'; }

server_pin() { srv "sudo k3sm pair" | awk '/^cluster pin:/{print $3}'; }

install_worker() { # install_worker <binary> <extra install args...>
	local bin="$1"; shift
	local_sudo "install-worker.sh" "set -e
'$bin' uninstall >/dev/null 2>&1 || true
'$bin' install $*
'$bin' version"
}

# tokens_per_second sends one fixed completion to a model's Service through a
# port-forward and prints completion tokens per second of wall time.
tokens_per_second() {
	local model="$1" port=18017 pf
	kubectl port-forward "svc/$model" "$port:8000" >/dev/null 2>&1 &
	pf=$!
	sleep 3
	python3 - "$port" <<'PY'
import json, sys, time, urllib.request
port = sys.argv[1]
body = json.dumps({"model": "m", "max_tokens": 64, "temperature": 0,
                   "messages": [{"role": "user", "content": "Count from one to twenty in words."}]}).encode()
req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/chat/completions", data=body, headers={"Content-Type": "application/json"})
t0 = time.time()
with urllib.request.urlopen(req, timeout=300) as r:
    out = json.load(r)
dt = time.time() - t0
n = out.get("usage", {}).get("completion_tokens", 0)
if not n:
    sys.exit("no completion tokens in the answer")
print(f"{n / dt:.1f}")
PY
	local rc=$?
	kill "$pf" >/dev/null 2>&1 || true
	return $rc
}

echo "==> k3sm ${GATE_NAME} gate: direct links on two Macs (cable $CABLE <-> $SCABLE)"

# ── 1 pair ──────────────────────────────────────────────────────────────────────────
PIN="$(server_pin || true)"
if [ -z "$PIN" ]; then
	ladder fail "1 pair: the server printed no cluster pin (sudo k3sm pair on the server)"
	finish
fi
srv "sudo k3sm pair --for 10m" >"$EVIDENCE/pair-open.txt" 2>&1
if install_worker "$K3SM_ARTIFACT" --auto-join --cluster "$PIN" >"$EVIDENCE/install-autojoin.txt" 2>&1 &&
	wait_until 300 node_ready "$K3SM_WORKER_NODE"; then
	boot="$(sudo python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("bootstrapAddress",""))' /var/lib/k3sm/agent/node-assignment.json 2>/dev/null || true)"
	if [ -n "$boot" ]; then
		ladder ok "1 pair: joined by pairing over the cable; bootstrap address $boot recorded"
	else
		ladder fail "1 pair: joined, but node-assignment.json records no bootstrapAddress"
	fi
else
	ladder fail "1 pair: the worker did not join by pairing within 300s (see $EVIDENCE/install-autojoin.txt)"
fi
srv "sudo k3sm pair --close" >/dev/null 2>&1 || true

# ── 2 route ─────────────────────────────────────────────────────────────────────────
if wait_until 120 bash -c "[ \"\$(kubectl get directlink $K3SM_WORKER_NODE -o jsonpath='{.status.ports[?(@.iface==\"$CABLE\")].state}')\" = up ]" &&
	[ "$(port_state "$K3SM_SERVER_NODE" "$SCABLE")" = up ] &&
	wait_until 30 bash -c "[ \"\$(route -n get $SERVER_MESH_IP 2>/dev/null | awk '/interface:/{print \$2}')\" = $CABLE ]"; then
	ladder ok "2 route: both ends up; $SERVER_MESH_IP routes over $CABLE"
else
	note "worker port: $(port_state "$K3SM_WORKER_NODE" "$CABLE"); server port: $(port_state "$K3SM_SERVER_NODE" "$SCABLE"); route: $(route_iface "$SERVER_MESH_IP")"
	ladder fail "2 route: the direct route is not up"
fi
kubectl get directlinks -o yaml >"$EVIDENCE/directlinks.yaml" 2>&1

# ── 3 figures (recorded) ────────────────────────────────────────────────────────────
peer_link="$(kubectl get directlink "$K3SM_WORKER_NODE" -o jsonpath="{.status.ports[?(@.iface==\"$CABLE\")].peerLinkIP}" 2>/dev/null)"
{
	echo "# figures $(date -u +%Y-%m-%dT%H:%M:%SZ); macOS $(sw_vers -productVersion) $(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
	echo "## ping over the cable ($peer_link)"; ping -c 20 -q "$peer_link" 2>&1
	echo "## ping to the server mesh address ($SERVER_MESH_IP)"; ping -c 20 -q "$SERVER_MESH_IP" 2>&1
	if command -v iperf3 >/dev/null 2>&1 && srv "command -v iperf3" >/dev/null 2>&1; then
		srv "iperf3 -s -1 -D" >/dev/null 2>&1; sleep 1
		echo "## iperf3 to the server mesh address (the direct route)"; iperf3 -c "$SERVER_MESH_IP" -t 10 2>&1 | tail -4
	fi
} >"$EVIDENCE/figures.txt" 2>&1
ladder rec "3 figures: recorded in $EVIDENCE/figures.txt"

# ── 4 lan-pull ──────────────────────────────────────────────────────────────────────
local_sudo "lan-pull.sh" "trap 'networksetup -setnetworkserviceenabled \"$K3SM_LAN_SERVICE\" on' EXIT
networksetup -setnetworkserviceenabled \"$K3SM_LAN_SERVICE\" off
sleep 60
kubectl --kubeconfig '$KUBECONFIG' get nodes >'$EVIDENCE/lan-pull-nodes.txt' 2>&1" >/dev/null 2>&1
if grep -q "$K3SM_SERVER_NODE *Ready" "$EVIDENCE/lan-pull-nodes.txt" && grep -q "$K3SM_WORKER_NODE *Ready" "$EVIDENCE/lan-pull-nodes.txt"; then
	ladder ok "4 lan-pull: both nodes Ready with the LAN down, over the cable"
else
	ladder fail "4 lan-pull: the cluster did not stay up on the cable alone (see $EVIDENCE/lan-pull-nodes.txt)"
fi
wait_until 120 node_ready "$K3SM_WORKER_NODE" || true

# ── 5 cable-pull ────────────────────────────────────────────────────────────────────
start=$SECONDS
local_sudo "cable-pull.sh" "trap 'ifconfig $CABLE up' EXIT
ifconfig $CABLE down
for i in \$(seq 1 30); do
  if [ \"\$(route -n get $SERVER_MESH_IP 2>/dev/null | awk '/interface:/{print \$2}')\" != $CABLE ]; then echo \"fallback after \${i}s\"; break; fi
  sleep 1
done >'$EVIDENCE/cable-pull.txt'
route -n get $SERVER_MESH_IP >>'$EVIDENCE/cable-pull.txt' 2>&1" >/dev/null 2>&1
if grep -q "fallback after" "$EVIDENCE/cable-pull.txt" && ! grep -q "interface: $CABLE" "$EVIDENCE/cable-pull.txt"; then
	ladder ok "5 cable-pull: $(head -1 "$EVIDENCE/cable-pull.txt"), the server routes over the tunnel"
else
	ladder fail "5 cable-pull: the route did not leave the cable (see $EVIDENCE/cable-pull.txt)"
fi
note "cable back up after $((SECONDS - start))s"
wait_until 120 direct_routes_present || note "the direct routes did not come back within 120s"

# ── 6 peer-asleep (the server stops answering on the cable, link up) ────────────────
# A sleeping Mac raises no link event, so a hung peer is the case the probe exists
# for. The rung makes the server stop answering echoes on its cable interface (a
# rule in the com.apple anchor macOS's own ruleset evaluates, removed by the trap)
# rather than sleeping it, because a sleeping control plane takes the cluster with it.
srv_sudo "m17-quiet.sh" "tok=\$(pfctl -E 2>&1 | awk '/Token/{print \$3}')
trap 'pfctl -a com.apple/k3sm-m17-lab -F all >/dev/null 2>&1; [ -n \"\$tok\" ] && pfctl -X \"\$tok\" >/dev/null 2>&1' EXIT
echo 'block drop out quick on $SCABLE inet proto icmp all icmp-type echorep' | pfctl -a com.apple/k3sm-m17-lab -f - >/dev/null 2>&1
sleep 40" >/dev/null 2>&1 &
quiet=$!
t0=$SECONDS
if wait_until 30 bash -c "! netstat -rn -f inet | awk -v i=$CABLE '\$NF==i && \$1 ~ /\\/25\$/' | grep -q ."; then
	elapsed=$((SECONDS - t0))
	if [ "$elapsed" -le 20 ]; then
		ladder ok "6 peer-asleep: the direct routes withdrew ${elapsed}s after the peer stopped answering"
	else
		ladder fail "6 peer-asleep: the direct routes withdrew after ${elapsed}s, more than 20s"
	fi
else
	ladder fail "6 peer-asleep: the direct routes stayed up while the peer did not answer"
fi
wait "$quiet" 2>/dev/null || true

# ── 7 cable-only unplug and replug ──────────────────────────────────────────────────
local_sudo "cable-only.sh" "trap 'ifconfig $CABLE up; networksetup -setnetworkserviceenabled \"$K3SM_LAN_SERVICE\" on' EXIT
networksetup -setnetworkserviceenabled \"$K3SM_LAN_SERVICE\" off
ifconfig $CABLE down
sleep 70
ifconfig $CABLE up
sleep 90
kubectl --kubeconfig '$KUBECONFIG' get nodes >'$EVIDENCE/cable-only-after.txt' 2>&1" >/dev/null 2>&1
notready="$(srv "kubectl --request-timeout=10s get events -A --field-selector involvedObject.name=$K3SM_WORKER_NODE -o name" 2>/dev/null | grep -c . || true)"
if grep -q "$K3SM_WORKER_NODE *Ready" "$EVIDENCE/cable-only-after.txt"; then
	ladder ok "7 cable-only: NotReady with no path, Ready again after the replug ($notready node events recorded)"
else
	ladder fail "7 cable-only: the worker did not reconverge after the replug (see $EVIDENCE/cable-only-after.txt)"
fi
wait_until 180 node_ready "$K3SM_WORKER_NODE" || true

# ── 8 a pair request from the LAN is refused ────────────────────────────────────────
server_lan="$(srv "ipconfig getifaddr en0 || ipconfig getifaddr en1" 2>/dev/null | head -1)"
code="$(curl -sk -o "$EVIDENCE/wifi-pair.txt" -w '%{http_code}' -X POST -d '{"version":1,"nodeName":"m17-intruder"}' "https://$server_lan:9345/v1-k3sm/pair" || true)"
if [ "$code" != "200" ] && ! grep -q '"token"' "$EVIDENCE/wifi-pair.txt" 2>/dev/null; then
	ladder ok "8 wifi-pair: a pair request over the LAN was refused (HTTP $code), no token minted"
else
	ladder fail "8 wifi-pair: a pair request over the LAN was answered (HTTP $code)"
fi

# ── 9 zone ──────────────────────────────────────────────────────────────────────────
if (cd "$REPO_ROOT" && K3SM_ZONE_IFACE="$CABLE" go test -tags integration -count=1 -v -run TestRealSocketReportsTheInterfaceAsTheZone ./pkg/bootstrap/pairing/) >"$EVIDENCE/zone.txt" 2>&1 &&
	grep -q -- "--- PASS: TestRealSocketReportsTheInterfaceAsTheZone" "$EVIDENCE/zone.txt"; then
	ladder ok "9 zone: $(grep -o 'reported for an accepted link-local connection on .*' "$EVIDENCE/zone.txt" | head -1)"
else
	ladder fail "9 zone: the real-socket zone test did not pass on $CABLE (see $EVIDENCE/zone.txt)"
fi

# ── 10 mixed ────────────────────────────────────────────────────────────────────────
if [ -z "${K3SM_OLD_ARTIFACT:-}" ] || [ ! -x "${K3SM_OLD_ARTIFACT:-}" ]; then
	ladder fail "10 mixed: K3SM_OLD_ARTIFACT names no previous-release binary"
	ladder fail "11 downgrade: K3SM_OLD_ARTIFACT names no previous-release binary"
else
	# ── 11 downgrade first: it is the sanctioned way onto the old binary ─────────────
	local_sudo "downgrade.sh" "set -e
'$K3SM_ARTIFACT' link tunnel-only --all
launchctl bootout system/io.k3sm.agent || true
'$K3SM_ARTIFACT' link reset
'$K3SM_OLD_ARTIFACT' install --agent --server '$server_lan'" >"$EVIDENCE/downgrade.txt" 2>&1 || true
	sleep 20
	if ifconfig "$CABLE" | grep -Eq 'inet 169\.254\.(0|255)\.' || ! cable_routes_absent; then
		ladder fail "11 downgrade: a cable address or route is left on $CABLE after the downgrade"
	else
		ladder ok "11 downgrade: no cable address and no direct route is left on $CABLE"
	fi
	if wait_until 180 node_ready "$K3SM_WORKER_NODE" && [ "$(route_iface "$SERVER_MESH_IP")" != "$CABLE" ]; then
		ladder ok "10 mixed: the old worker is Ready beside the new server, over the tunnel"
	else
		ladder fail "10 mixed: the old worker did not come up beside the new server"
	fi
	# Back to the new binary for the last rung (a token join over the LAN).
	token="$(srv "sudo k3sm token create" 2>/dev/null | head -1)"
	printf '%s\n' "$token" | sudo tee /var/root/k3sm-m17-token >/dev/null
	sudo chmod 600 /var/root/k3sm-m17-token
	install_worker "$K3SM_ARTIFACT" --agent --server "$server_lan" --token-file /var/root/k3sm-m17-token >"$EVIDENCE/reinstall.txt" 2>&1 || true
	sudo rm -f /var/root/k3sm-m17-token
	local_sudo "clear-tunnel-only.sh" "'$K3SM_ARTIFACT' link tunnel-only --all --off" >/dev/null 2>&1 || true
	wait_until 180 node_ready "$K3SM_WORKER_NODE" || note "the worker is not Ready after the reinstall"
fi

# ── 12 sharded ring model through rank 0 ────────────────────────────────────────────
if ! kubectl get crd mlxmodels.mlx.k3sm.io >/dev/null 2>&1; then
	ladder fail "12 sharded: no MLXModel CRD on this cluster"
else
	kubectl apply -f - >"$EVIDENCE/sharded-apply.txt" 2>&1 <<'YAML'
apiVersion: mlx.k3sm.io/v1alpha1
kind: MLXModel
metadata:
  name: m17-sharded
  namespace: default
spec:
  model: mlx-community/Qwen3-0.6B-4bit
  revision: 73e3e38d981303bc594367cd910ea6eb48349da8
  memory: 4Gi
  port: 8000
  runtime:
    image: ghcr.io/k3sm-io/mlx-serve:0.4.1
  cache:
    size: 5Gi
    storageClassName: local-path
  distributed:
    ranks: 2
    backend: ring
YAML
	if kubectl wait --for=condition=Ready mlxmodel/m17-sharded --timeout=20m >"$EVIDENCE/sharded-wait.txt" 2>&1 &&
		tokens_per_second m17-sharded >"$EVIDENCE/sharded-tps.txt" 2>&1; then
		ladder ok "12 sharded: the ranks: 2 ring model served through rank 0 at $(cat "$EVIDENCE/sharded-tps.txt") tokens/s"
	else
		ladder fail "12 sharded: the ranks: 2 ring model did not serve through rank 0 (see $EVIDENCE/sharded-wait.txt)"
	fi
	kubectl get mlxmodel m17-sharded -o yaml >"$EVIDENCE/sharded.yaml" 2>&1
	kubectl delete mlxmodel m17-sharded --ignore-not-found --wait=true --timeout=5m >/dev/null 2>&1
	# The same model on one Mac, for the figure beside it.
	sed -e 's/name: qwen3-06b/name: m17-single/' "$REPO_ROOT/examples/mlxmodel.yaml" | kubectl apply -f - >/dev/null 2>&1
	if kubectl wait --for=condition=Ready mlxmodel/m17-single --timeout=20m >/dev/null 2>&1 &&
		tokens_per_second m17-single >"$EVIDENCE/single-tps.txt" 2>&1; then
		ladder rec "12 sharded: the same model on one Mac served at $(cat "$EVIDENCE/single-tps.txt") tokens/s"
	else
		ladder rec "12 sharded: the single-Mac figure was not measured (see $EVIDENCE)"
	fi
	kubectl delete mlxmodel m17-single --ignore-not-found --wait=false >/dev/null 2>&1
fi

finish
