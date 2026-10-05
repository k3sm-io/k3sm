#!/usr/bin/env bash
# k3sm M6 lab gate — the runnable proof of HA on embedded etcd: two control-plane
# servers, each running one etcd member (the second joined as a learner and promoted),
# plus leader election (M6.0) and the identical-CA bootstrap bundle v2 (M6.1)
# (DESIGN §9 M6; docs/PHASES.md M6.0/M6.1). It needs TWO server Macs, so it is
# manual: true / requires two-macs in hack/acceptance/phases.json and runs ONLY under
# K3SM_LAB=1. With K3SM_LAB unset it prints PENDING and exits 0 (never a pass).
#
# SCOPE: on two Macs this proves the mechanics (join, TLS, replication, leader
# election, quorum loss, recovery, reset, cold restart), not fault tolerance. Two
# voting members tolerate ZERO failures: losing either Mac stops all writes until it
# returns or the survivor runs --cluster-reset. Fault tolerance needs three members on
# three hosts; the loopback integration tests in pkg/executor are the nearest proxy.
# Every evidence line this script prints says so.
#
# Legs:
#   m6.0  both /readyz ok (incl. /readyz/etcd); TestM6_EtcdTwoVotingMembers sees 2
#         started voting members and 0 learners from each server's own member.
#   m6.M  the mesh: each server's MeshPeer is labelled net.k3sm.io/control-plane=true
#         at the /24 its own --mesh-ip names; default/kubernetes lists both mesh IPs;
#         both admin kubeconfigs answer from this host.
#   m6.A  (a) TestM6_WriteOnAReadOnB  (b) TestM6_LeaderElectionSingleActive
#         (c) TestM6_WatchStalenessSoak at its 20 s default
#         (e) TestM6_SecondServerJoinsReconstructsCAs incl. the etcd CA pins.
#   m6.B  stop A. FIRST the precondition: B's daemon is running, B's /livez is ok and
#         B's etcd answers Status. Then, within 60 s: B's etcd reports no leader, a
#         write through B's apiserver fails with a timeout/no-leader error, and a
#         serializable read of B's local etcd still succeeds. B's crash-loop record
#         stays empty for 3 minutes (the survivor waits, it is not parked).
#   m6.C  start A; both /readyz ok within 2 min; the pre-kill object reads on both; a
#         new write succeeds. Then `kill -9` B's etcd child in the middle of a write
#         loop; every acknowledged write is present on both after it restarts.
#   m6.D  stop A and B; `k3sm server --cluster-reset` on B (B's own daemon args, as the
#         service user); B serves alone with all prior data; wipe A's etcd dir and
#         re-join A through $K3SM_M6_REJOIN_A; back to 2 voting members. Then A's
#         MeshPeer is back at its pre-reset /24 with the SAME public key (the wipe
#         removes only $WD/etcd, so A's mesh key file survives it), and B's member list
#         carries the pre-reset etcd peer URLs (A's https://<A LAN ip>:2380, never a
#         mesh address).
#   m6.E  cold restart: stop both, start B first, after 5 min B must still be waiting
#         (daemon running, not parked, no leader); then start A; both /readyz ok
#         within 2 min.
#   m6.Q  platform qualification: $K3SM_M6_QUAL_SECONDS (default 3600) of apiserver
#         churn across both servers, recording WAL fsync p99,
#         etcd_server_leader_changes_seen_total, leader-lease transitions and the
#         cross-server read-after-write tally into the evidence dir. Recorded, not a
#         pass threshold.
#
# Prerequisites (manual two-Mac setup, NOT done here; placeholders in <>):
#   - server A:  sudo k3sm install --cluster-init --node-ip <A LAN ip> --mesh-ip <A mesh ip>
#   - on A, mint the SERVER-class token (it reconstructs every cluster CA, including
#     the two etcd CAs; give it ONLY to a trusted control-plane Mac):
#                sudo k3sm token create --server
#   - server B:  put the token in a root-only file, then
#                sudo sh -c 'umask 077; cat > /var/root/k3sm-server-token'   # paste, Ctrl-D
#                sudo k3sm install --server-join --server <A LAN ip> \
#                  --token-file /var/root/k3sm-server-token \
#                  --node-ip <B LAN ip> --mesh-ip <B mesh ip>
#     (the etcd peers talk on the LAN addresses; the mesh carries pod traffic only.
#     `k3sm install --node-ip` on a server is the etcd peer address and is rendered
#     onto the daemon as `k3sm server --etcd-peer-ip`; each server's node advertises
#     and lo0-aliases its --mesh-ip, never the LAN address. The install stages the
#     token at <work-dir>/join-token for B's daemon, which reads it at every start;
#     the root-only file is yours to delete afterwards)
#   - this host: kubectl, curl and go (the e2e criteria run from this checkout); each server's HA admin kubeconfig (the CA-bearing
#     <work-dir>/admin.kubeconfig, NOT the loopback token kubeconfig) as $KUBECONFIG
#     (server A) and $K3SM_KUBECONFIG_B (server B).
#   - THIS HOST IS SERVER B. Each admin kubeconfig targets its server's mesh-bound
#     apiserver, reached over the wireguard mesh. m6.B stops A, which takes A's end of
#     the mesh down with it, so a run host other than B would lose its path to B
#     exactly when the legs need it. The preflight fails unless B's mesh IP (the
#     server of $K3SM_KUBECONFIG_B) is an address of this host.
#
# Environment (under K3SM_LAB=1 every one marked required must be set, or the run FAILS):
#   KUBECONFIG, K3SM_KUBECONFIG_B      required — server A's / server B's admin kubeconfig
#   K3SM_M6_ON_A, K3SM_M6_ON_B         required — a command PREFIX that runs a command as
#                                      root on that server and passes stdin through, e.g.
#                                      'ssh <server-a> sudo' (or 'sudo' when this host IS
#                                      the server). The etcd checks run there, against
#                                      that server's own loopback with its client.crt:
#                                      the etcd client listener is loopback-only.
#   K3SM_M6_EVIDENCE_DIR               required — where every artifact and the log land
#   K3SM_M6_REJOIN_A                   required by m6.D — a shell command run on THIS host
#                                      that reinstalls server A as a joining server of B
#                                      (sudo k3sm install --server-join --server <B LAN ip>
#                                      --token-file <file holding B's server token>
#                                      --node-ip <A LAN ip> --mesh-ip <A mesh ip>, run on
#                                      A); m6.D runs it after removing A's etcd dir, which
#                                      is what lets the install replace A's recorded
#                                      --cluster-init; m6.D FAILS without it
#   K3SM_M6_WORK_DIR                   server work dir (default /var/lib/k3sm/server)
#   K3SM_M6_ETCD_CLIENT_PORT           etcd loopback client port (default 2379, --kine-port)
#   K3SM_M6_ETCD_METRICS_PORT          etcd loopback metrics port (default 2381)
#   K3SM_M6_QUAL_SECONDS               m6.Q churn duration (default 3600)
#
# Tier: lab (two-macs). Exit 0 iff every leg passes (or the gate is pending).
#
# Usage: K3SM_LAB=1 KUBECONFIG=<A> K3SM_KUBECONFIG_B=<B> K3SM_M6_ON_A='<prefix>' \
#          K3SM_M6_ON_B='<prefix>' K3SM_M6_EVIDENCE_DIR=<dir> K3SM_M6_REJOIN_A='<cmd>' \
#          hack/lab/m6.sh
# Every remote script is single-quoted on purpose: it expands on the server, not here.
# shellcheck disable=SC2016
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=SCRIPTDIR/../lib/conformance.sh
. "$HERE/../lib/conformance.sh"

SCOPE="two Macs prove the mechanics (join, TLS, replication, leader election, quorum loss, recovery, reset, cold restart), not fault tolerance"

# ── Lab guard: only run under K3SM_LAB=1 (a real two-Mac rig). ─────────────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M6 lab gate: PENDING (two-macs). Set K3SM_LAB=1 with two embedded-etcd servers to run; this is NOT a pass. Scope: $SCOPE."
	exit 0
fi

PASS=0; FAIL=0
EV="${K3SM_M6_EVIDENCE_DIR:-}"
LOG=/dev/null
ladder() {
	local line
	if [ "$1" = ok ]; then line="PASS  $2"; PASS=$((PASS+1)); else line="FAIL  $2"; FAIL=$((FAIL+1)); fi
	line="$line [scope: $SCOPE]"
	echo "$line"
	echo "$(date -u +%FT%TZ) $line" >> "$LOG"
}
# note: an evidence line that is not a verdict; it carries the scope too.
note() { echo "$(date -u +%FT%TZ) $* [scope: $SCOPE]" >> "$LOG"; }
finish() {
	echo "----------------------------------------"
	echo "M6: $PASS passed, $FAIL failed [scope: $SCOPE]" | tee -a "$LOG"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "================ M6 GREEN ================"
	exit 0
}

# ── Prerequisites: any missing one is a FAIL under K3SM_LAB=1, never a skip. ──
missing=0
for tool in kubectl curl go; do
	if ! command -v "$tool" >/dev/null 2>&1; then ladder no "m6.pre  $tool on PATH"; missing=1; fi
done
for var in KUBECONFIG K3SM_KUBECONFIG_B K3SM_M6_ON_A K3SM_M6_ON_B K3SM_M6_EVIDENCE_DIR; do
	if [ -z "${!var:-}" ]; then ladder no "m6.pre  \$$var is set"; missing=1; fi
done
[ "$missing" -eq 0 ] || finish
# kube_host <kubeconfig>: the host of the kubeconfig's server URL (a mesh IP here).
kube_host() { kubectl config view --kubeconfig "$1" --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null | sed -E 's#^https?://##; s#:[0-9]+/?$##'; }
MESH_A="$(kube_host "$KUBECONFIG")"; MESH_B="$(kube_host "$K3SM_KUBECONFIG_B")"
if [ -z "$MESH_B" ] || ! ifconfig 2>/dev/null | grep -Eq "inet ${MESH_B//./\\.} "; then
	ladder no "m6.pre  this host is server B (B's mesh IP ${MESH_B:-unknown} is not an address here; m6.B stops A and would cut a run host on A's side off from B)"
	finish
fi
mkdir -p "$EV"
LOG="$EV/m6.log"
note "M6 lab run"

KA="$KUBECONFIG"; KB="$K3SM_KUBECONFIG_B"
WD="${K3SM_M6_WORK_DIR:-/var/lib/k3sm/server}"
CP="${K3SM_M6_ETCD_CLIENT_PORT:-2379}"
MP="${K3SM_M6_ETCD_METRICS_PORT:-2381}"
LABEL=io.k3sm.server
PLIST="/Library/LaunchDaemons/$LABEL.plist"
kA() { kubectl --kubeconfig "$KA" "$@"; }
kB() { kubectl --kubeconfig "$KB" "$@"; }

# The script every remote call is prefixed with: POSIX sh, run as root on a server.
# etcd is asked through its v3 JSON gateway on the loopback client listener, with
# the server's own etcd client identity (client.crt, clientAuth only).
REMOTE_LIB="$(cat <<'EOF'
set -u
PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
E="$WD/tls/etcd"
etcd_api() { curl -sS --max-time 10 --cacert "$E/server-ca.crt" --cert "$E/client.crt" --key "$E/client.key" -X POST -d "$2" "https://127.0.0.1:$CP$1"; }
etcd_metrics() { curl -sS --max-time 10 "http://127.0.0.1:$MP/metrics"; }
daemon_running() { launchctl print "system/$LABEL" 2>/dev/null | grep -q 'state = running'; }
daemon_stop() {
	launchctl bootout "system/$LABEL" 2>/dev/null || true
	i=0; while [ $i -lt 60 ] && pgrep -f "^$WD/bin/etcd " >/dev/null; do sleep 1; i=$((i+1)); done
	! pgrep -f "^$WD/bin/etcd " >/dev/null
}
daemon_start() { launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl kickstart "system/$LABEL"; }
crash_record_empty() { f="$WD/crashloop.json"; [ ! -s "$f" ] || ! grep -Eq '"component"|"tripped_at"' "$f"; }
crash_record_tripped() { grep -q '"tripped_at"' "$WD/crashloop.json" 2>/dev/null; }
etcd_pid() { pgrep -f "^$WD/bin/etcd " | head -n 1; }
EOF
)"

# remote <A|B> <script>: run <script> (after REMOTE_LIB) as root on that server
# through its hook prefix; stdout comes back.
remote() {
	local hook pfx
	if [ "$1" = A ]; then hook="$K3SM_M6_ON_A"; else hook="$K3SM_M6_ON_B"; fi
	read -r -a pfx <<<"$hook"
	printf 'WD=%s\nCP=%s\nMP=%s\nLABEL=%s\nPLIST=%s\n%s\n%s\n' "$WD" "$CP" "$MP" "$LABEL" "$PLIST" "$REMOTE_LIB" "$2" |
		"${pfx[@]}" sh -s
}

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
readyz() { [ "$(kubectl --kubeconfig "$1" get --raw /readyz 2>/dev/null || true)" = ok ] &&
	[ "$(kubectl --kubeconfig "$1" get --raw /readyz/etcd 2>/dev/null || true)" = ok ]; }
# await <seconds> <cmd...>: poll every 3 s until <cmd> succeeds.
await() {
	local end=$((SECONDS + $1)); shift
	until "$@"; do [ "$SECONDS" -lt "$end" ] || return 1; sleep 3; done
}
both_ready() { readyz "$KA" && readyz "$KB"; }
member_list() { remote "$1" 'etcd_api /v3/cluster/member/list "{\"linearizable\":true}"'; }
# voting <A|B> <n>: that server's member reports exactly n members and no learner.
voting() {
	local out; out="$(member_list "$1" 2>/dev/null || true)"
	[ "$(printf '%s' "$out" | grep -o '"ID":' | wc -l | tr -d ' ')" = "$2" ] && ! printf '%s' "$out" | grep -q '"isLearner":true'
}
cm_value() { kubectl --kubeconfig "$1" get configmap -n default "$2" -o jsonpath='{.data.v}' 2>/dev/null || true; }
put_cm() { kubectl --kubeconfig "$1" create configmap -n default "$2" --from-literal=v="$3" --request-timeout=20s >/dev/null 2>&1; }

echo "==> k3sm M6 lab gate (two embedded-etcd servers; A=$KA B=$KB; evidence $EV)"
echo "    scope: $SCOPE"

# ── m6.0 — both servers ready, and each member sees 2 voting members ───────────
if both_ready; then
	ladder ok "m6.0  both servers /readyz ok, incl. /readyz/etcd"
else
	ladder no "m6.0  both servers /readyz ok, incl. /readyz/etcd"
	finish
fi
member_list A > "$EV/members-A.json" || true
member_list B > "$EV/members-B.json" || true
for s in A B; do
	mkdir -p "$EV/etcd-ca-$s"
	remote "$s" 'cat "$E/server-ca.crt"' > "$EV/etcd-ca-$s/server-ca.crt" || true
	remote "$s" 'cat "$E/peer-ca.crt"' > "$EV/etcd-ca-$s/peer-ca.crt" || true
done
export K3SM_M6_MEMBERS_A="$EV/members-A.json" K3SM_M6_MEMBERS_B="$EV/members-B.json"
export K3SM_M6_ETCD_CA_A="$EV/etcd-ca-A" K3SM_M6_ETCD_CA_B="$EV/etcd-ca-B"
M6_CRITERIA="M6_EtcdTwoVotingMembers M6_WriteOnAReadOnB M6_LeaderElectionSingleActive M6_WatchStalenessSoak M6_SecondServerJoinsReconstructsCAs"
read -r -a crits <<<"$M6_CRITERIA"
if run_conformance_slice "$REPO_ROOT" '^TestM6_EtcdTwoVotingMembers$' 300s "${crits[0]}" | tee -a "$LOG"; then
	ladder ok "m6.0  TestM6_EtcdTwoVotingMembers: 2 started voting members, 0 learners, on both servers"
else
	ladder no "m6.0  TestM6_EtcdTwoVotingMembers: 2 started voting members, 0 learners, on both servers"
fi

# ── m6.M — each server's MeshPeer at its own /24, both apiservers advertised ────
# mesh_cidr <mesh ip>: the /24 a server's --mesh-ip is the .1 of.
mesh_cidr() { printf '%s.0/24' "${1%.*}"; }
server_peers() { kA get meshpeers -l net.k3sm.io/control-plane=true -o jsonpath='{range .items[*]}{.spec.podCIDR}={.spec.publicKey}{"\n"}{end}' 2>/dev/null || true; }
SERVER_PEERS="$(server_peers)"
printf '%s\n' "$SERVER_PEERS" > "$EV/server-meshpeers.txt"
if printf '%s\n' "$SERVER_PEERS" | grep -q "^$(mesh_cidr "$MESH_A")=" &&
	printf '%s\n' "$SERVER_PEERS" | grep -q "^$(mesh_cidr "$MESH_B")=" &&
	[ "$(printf '%s\n' "$SERVER_PEERS" | grep -c '=')" = 2 ]; then
	ladder ok "m6.M  two MeshPeers labelled net.k3sm.io/control-plane=true, at $(mesh_cidr "$MESH_A") and $(mesh_cidr "$MESH_B")"
else
	ladder no "m6.M  two MeshPeers labelled net.k3sm.io/control-plane=true, at $(mesh_cidr "$MESH_A") and $(mesh_cidr "$MESH_B") (got: $(printf '%s' "$SERVER_PEERS" | sed 's/=.*//' | tr '\n' ' '))"
fi
EPS="$(kA get endpoints -n default kubernetes -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
if printf ' %s ' "$EPS" | grep -q " $MESH_A " && printf ' %s ' "$EPS" | grep -q " $MESH_B "; then
	ladder ok "m6.M  default/kubernetes lists both apiservers ($MESH_A, $MESH_B)"
else
	ladder no "m6.M  default/kubernetes lists both apiservers ($MESH_A, $MESH_B; got: ${EPS:-none})"
fi
if [ "$(kA get --raw /readyz 2>/dev/null || true)" = ok ] && [ "$(kB get --raw /readyz 2>/dev/null || true)" = ok ]; then
	ladder ok "m6.M  both admin kubeconfigs answer from this host ($MESH_A, $MESH_B)"
else
	ladder no "m6.M  both admin kubeconfigs answer from this host ($MESH_A, $MESH_B)"
fi
A_PEER_BEFORE="$(printf '%s\n' "$SERVER_PEERS" | grep "^$(mesh_cidr "$MESH_A")=" || true)"

# ── m6.A — replication, one active scheduler/KCM, read-after-write, bundle v2 ──
if (unset K3SM_M6_SOAK_DURATION; run_conformance_slice "$REPO_ROOT" \
	'^TestM6_(WriteOnAReadOnB|LeaderElectionSingleActive|WatchStalenessSoak|SecondServerJoinsReconstructsCAs)$' \
	1800s "${crits[@]:1}") | tee -a "$LOG"; then
	ladder ok "m6.A  write on A read on B, single active leader, 20 s read-after-write soak, identical cluster + etcd CAs"
else
	ladder no "m6.A  write on A read on B, single active leader, 20 s read-after-write soak, identical cluster + etcd CAs (a criterion missing, failed or skipped)"
fi

# ── m6.B — kill one: stop A; B must lose quorum for the right reason, fail safe ─
PREKILL="m6-prekill-$(date +%s)"
if ! put_cm "$KA" "$PREKILL" before-kill; then
	ladder no "m6.B  write the pre-kill object $PREKILL through A"
fi
pre_ok=yes
remote B 'daemon_running' || pre_ok="no (B's daemon is not running)"
[ "$(kB get --raw /livez 2>/dev/null || true)" = ok ] || pre_ok="no (B's /livez is not ok)"
remote B 'etcd_api /v3/maintenance/status "{}"' 2>/dev/null | grep -q '"header"' || pre_ok="no (B's etcd does not answer Status)"
if [ "$pre_ok" != yes ]; then
	ladder no "m6.B  precondition: B alive, /livez ok, its etcd answers Status — $pre_ok"
else
	ladder ok "m6.B  precondition: B's daemon alive, /livez ok, its etcd answers Status"
	if ! remote A 'daemon_stop'; then
		ladder no "m6.B  stop A's daemon and its etcd child"
	else
		stopped_at=$SECONDS
		key="$(b64 "/registry/configmaps/default/$PREKILL")"
		noleader=no; writefail=no; localread=no; lastwrite=""
		end=$((SECONDS + 60))
		while [ "$SECONDS" -lt "$end" ]; do
			st="$(remote B 'etcd_api /v3/maintenance/status "{}"' 2>/dev/null || true)"
			if printf '%s' "$st" | grep -q '"header"' && ! printf '%s' "$st" | grep -q '"leader":"[1-9]'; then noleader=yes; fi
			if [ "$noleader" = yes ] && [ "$writefail" = no ]; then
				if lastwrite="$(kB create configmap -n default "m6-noleader-$SECONDS" --from-literal=v=x --request-timeout=15s 2>&1)"; then
					lastwrite="the write SUCCEEDED without quorum: $lastwrite"
				elif printf '%s' "$lastwrite" | grep -Eqi 'no leader|leader changed|timeout|timed out|deadline exceeded|unable to return a response in the time allotted'; then
					writefail=yes
				fi
			fi
			if remote B "etcd_api /v3/kv/range '{\"key\":\"$key\",\"serializable\":true}'" 2>/dev/null | grep -q '"kvs"'; then localread=yes; fi
			[ "$noleader$writefail$localread" = yesyesyes ] && break
			sleep 3
		done
		note "m6.B last write attempt through B: $lastwrite"
		if [ "$noleader$writefail$localread" = yesyesyes ]; then
			ladder ok "m6.B  A down: B reports no leader, a write through B fails (timeout/no leader), a serializable local read still serves"
		else
			ladder no "m6.B  A down within 60 s: no-leader=$noleader write-fails-for-the-right-reason=$writefail serializable-local-read=$localread"
		fi
		wait_left=$((180 - (SECONDS - stopped_at)))
		[ "$wait_left" -le 0 ] || sleep "$wait_left"
		if remote B 'daemon_running && crash_record_empty'; then
			ladder ok "m6.B  after 3 min without quorum B's daemon still runs and its crash-loop record is empty"
		else
			ladder no "m6.B  after 3 min without quorum B's daemon still runs and its crash-loop record is empty"
		fi
	fi
fi

# ── m6.C — recover A; then SIGKILL B's etcd mid write loop ─────────────────────
remote A 'daemon_start' >/dev/null 2>&1 || true
if await 120 both_ready; then
	ladder ok "m6.C  A restarted: both /readyz ok within 2 min"
else
	ladder no "m6.C  A restarted: both /readyz ok within 2 min"
fi
if [ "$(cm_value "$KA" "$PREKILL")" = before-kill ] && [ "$(cm_value "$KB" "$PREKILL")" = before-kill ]; then
	ladder ok "m6.C  the pre-kill object reads on A and on B"
else
	ladder no "m6.C  the pre-kill object reads on A and on B"
fi
# shellcheck disable=SC2329  # invoked through await, which shellcheck does not follow
recovered_on_b() { [ "$(cm_value "$KB" "m6-recovered-$PREKILL")" = recovered ]; }
if put_cm "$KA" "m6-recovered-$PREKILL" recovered && await 15 recovered_on_b; then
	ladder ok "m6.C  a new write after recovery commits and replicates"
else
	ladder no "m6.C  a new write after recovery commits and replicates"
fi
ACKED="$EV/m6C-acked.txt"; : > "$ACKED"
(
	end=$((SECONDS + 45)); i=0
	while [ "$SECONDS" -lt "$end" ]; do
		i=$((i+1))
		if put_cm "$KB" "m6-wal-$PREKILL-$i" "$i"; then echo "$i" >> "$ACKED"; fi
	done
) &
loop=$!
sleep 6
killed="$(remote B 'p="$(etcd_pid)"; [ -n "$p" ] && kill -9 "$p" && echo "$p"' 2>/dev/null || true)"
wait "$loop" || true
note "m6.C killed B's etcd pid ${killed:-none}; acknowledged writes: $(wc -l < "$ACKED" | tr -d ' ')"
if [ -z "$killed" ]; then
	ladder no "m6.C  kill -9 B's etcd child mid write loop (no etcd child found)"
elif ! await 120 both_ready; then
	ladder no "m6.C  after kill -9 of B's etcd both /readyz ok within 2 min"
else
	lost=0
	while read -r i; do
		for k in "$KA" "$KB"; do [ "$(cm_value "$k" "m6-wal-$PREKILL-$i")" = "$i" ] || lost=$((lost+1)); done
	done < "$ACKED"
	n="$(wc -l < "$ACKED" | tr -d ' ')"
	if [ "$n" -gt 0 ] && [ "$lost" -eq 0 ]; then
		ladder ok "m6.C  kill -9 of B's etcd mid write loop: all $n acknowledged writes present on A and B after restart"
	else
		ladder no "m6.C  kill -9 of B's etcd mid write loop: $n acknowledged, $lost missing reads after restart"
	fi
fi

# ── m6.D — reset: B alone keeps the data; A wiped and re-joined ─────────────────
# peer_urls <member list json>: the sorted etcd peer URLs in it.
peer_urls() { printf '%s' "$1" | grep -o '"peerURLs":\[[^]]*\]' | grep -o 'https://[^"]*' | sort -u; }
if [ -z "${K3SM_M6_REJOIN_A:-}" ]; then
	ladder no "m6.D  \$K3SM_M6_REJOIN_A is set (the command that re-installs A as a joining server of B)"
else
	PEER_URLS_BEFORE="$(peer_urls "$(member_list B 2>/dev/null || true)")"
	remote A 'daemon_stop' || true
	remote B 'daemon_stop' || true
	# The reset runs B's own daemon arguments plus --cluster-reset, as the service
	# user the daemon runs as, so every file it re-mints keeps the daemon's ownership.
	# The daemon's work dir defaults to $HOME/server, and launchd gives it HOME and
	# its WorkingDirectory from the plist, so the replay carries both, not only
	# ProgramArguments, or the reset opens a work dir under the caller's home.
	if remote B '
home="$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:HOME" "$PLIST" 2>/dev/null || true)"
wdir="$(/usr/libexec/PlistBuddy -c "Print :WorkingDirectory" "$PLIST" 2>/dev/null || echo /)"
cd "$wdir" || exit 1
i=0; set --
while v="$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:$i" "$PLIST" 2>/dev/null)"; do set -- "$@" "$v"; i=$((i+1)); done
[ "$#" -ge 2 ] && [ "$2" = server ] || { echo "unexpected ProgramArguments in $PLIST" >&2; exit 1; }
bin=$1; shift 2
user="$(/usr/libexec/PlistBuddy -c "Print :UserName" "$PLIST" 2>/dev/null || echo root)"
sudo -u "$user" env HOME="${home:-$HOME}" "$bin" server --cluster-reset "$@"' >> "$LOG" 2>&1; then
		ladder ok "m6.D  k3sm server --cluster-reset on B exited 0"
	else
		ladder no "m6.D  k3sm server --cluster-reset on B exited 0"
	fi
	remote B 'daemon_start' >/dev/null 2>&1 || true
	if await 120 readyz "$KB" && voting B 1 && [ "$(cm_value "$KB" "$PREKILL")" = before-kill ] &&
		[ "$(cm_value "$KB" "m6-recovered-$PREKILL")" = recovered ]; then
		ladder ok "m6.D  B serves alone after the reset (1 voting member) with all prior data"
	else
		ladder no "m6.D  B serves alone after the reset (1 voting member) with all prior data"
	fi
	if remote A 'rm -rf "$WD/etcd"' && bash -c "$K3SM_M6_REJOIN_A" >> "$LOG" 2>&1 &&
		await 300 voting B 2 && await 120 both_ready; then
		ladder ok "m6.D  A wiped and re-joined through B: 2 voting members, both /readyz ok"
	else
		ladder no "m6.D  A wiped and re-joined through B: 2 voting members, both /readyz ok"
	fi
	member_list B > "$EV/members-after-reset-B.json" || true
	# A rejoined with its mesh key file intact (the wipe above removes only
	# $WD/etcd), so its reservation re-asserts the same row: same /24, same key.
	# shellcheck disable=SC2329  # invoked through await
	a_peer_back() { [ -n "$A_PEER_BEFORE" ] && server_peers | grep -qxF "$A_PEER_BEFORE"; }
	if await 120 a_peer_back; then
		ladder ok "m6.D  A's MeshPeer is back at $(mesh_cidr "$MESH_A") with its pre-reset public key"
	else
		ladder no "m6.D  A's MeshPeer is back at $(mesh_cidr "$MESH_A") with its pre-reset public key (now: $(server_peers | grep "^$(mesh_cidr "$MESH_A")=" || echo none))"
	fi
	PEER_URLS_AFTER="$(peer_urls "$(cat "$EV/members-after-reset-B.json" 2>/dev/null || true)")"
	note "m6.D etcd peer URLs before: $(printf '%s' "$PEER_URLS_BEFORE" | tr '\n' ' ') after: $(printf '%s' "$PEER_URLS_AFTER" | tr '\n' ' ')"
	if [ -n "$PEER_URLS_BEFORE" ] && [ "$PEER_URLS_AFTER" = "$PEER_URLS_BEFORE" ] &&
		! printf '%s\n' "$PEER_URLS_AFTER" | grep -Eq '^https://100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.'; then
		ladder ok "m6.D  B's member list carries the pre-reset peer URLs, A's on its LAN address, none on the mesh"
	else
		ladder no "m6.D  B's member list carries the pre-reset peer URLs, A's on its LAN address, none on the mesh"
	fi
fi

# ── m6.E — cold restart, B first ─────────────────────────────────────────────
remote A 'daemon_stop' || true
remote B 'daemon_stop' || true
remote B 'daemon_start' >/dev/null 2>&1 || true
sleep 300
# etcd serves client requests only after the member publishes itself through raft,
# which needs quorum, so on a cold start alone its client port answers nothing; the
# metrics listener is separate and reports the waiting state directly.
if remote B 'daemon_running && ! crash_record_tripped && curl -s --max-time 5 "http://127.0.0.1:$MP/metrics" | grep -qx "etcd_server_has_leader 0" && curl -s --max-time 5 "http://127.0.0.1:$MP/health" | grep -q "RAFT NO LEADER"'; then
	ladder ok "m6.E  B started alone: after 5 min its daemon still runs, unparked, waiting for quorum (no leader)"
else
	ladder no "m6.E  B started alone: after 5 min its daemon still runs, unparked, waiting for quorum (no leader)"
fi
remote A 'daemon_start' >/dev/null 2>&1 || true
if await 120 both_ready; then
	ladder ok "m6.E  A started: both /readyz ok within 2 min"
else
	ladder no "m6.E  A started: both /readyz ok within 2 min"
fi

# ── m6.Q — platform qualification churn (recorded, not a threshold) ─────────
Q="$EV/m6Q"; mkdir -p "$Q"
QSECS="${K3SM_M6_QUAL_SECONDS:-3600}"
leases() { for l in kube-scheduler kube-controller-manager; do
	echo "$l $(kA get lease -n kube-system "$l" -o jsonpath='{.spec.leaseTransitions}' 2>/dev/null || echo unknown)"; done; }
for s in A B; do remote "$s" 'etcd_metrics' > "$Q/metrics-$s-start.txt" 2>/dev/null || true; done
leases > "$Q/leases-start.txt"
ops=0; wfail=0; rawok=0; rawfail=0
end=$((SECONDS + QSECS))
while [ "$SECONDS" -lt "$end" ]; do
	ops=$((ops+1)); name="m6q-$((ops % 32))"
	if [ $((ops % 2)) -eq 0 ]; then wk="$KA"; rk="$KB"; else wk="$KB"; rk="$KA"; fi
	if kubectl --kubeconfig "$wk" create configmap -n default "$name" --from-literal=v="$ops" --dry-run=client -o yaml 2>/dev/null |
		kubectl --kubeconfig "$wk" apply -f - --request-timeout=20s >/dev/null 2>&1; then
		if [ "$(cm_value "$rk" "$name")" = "$ops" ]; then rawok=$((rawok+1)); else
			rawfail=$((rawfail+1)); echo "$(date -u +%FT%TZ) read-after-write miss op=$ops $name" >> "$Q/raw-misses.txt"; fi
	else
		wfail=$((wfail+1))
	fi
done
for s in A B; do remote "$s" 'etcd_metrics' > "$Q/metrics-$s-end.txt" 2>/dev/null || true; done
leases > "$Q/leases-end.txt"
# p99 of the WAL fsync histogram over the run (end minus start, cumulative buckets;
# reported as the upper bound of the bucket holding the 99th percentile).
p99() {
	awk -v m=etcd_disk_wal_fsync_duration_seconds_bucket '
		FNR==1 { f++ }
		index($0, m"{") == 1 { split($0, a, "le=\""); split(a[2], b, "\""); le=b[1]; v=$NF
			if (f==1) s[le]=v; else { e[le]=v; if (!(le in seen)) { seen[le]=1; o[++n]=le } } }
		END { if (!("+Inf" in e)) { print "unknown"; exit } tot=e["+Inf"]-s["+Inf"]
			if (tot<=0) { print "unknown (no fsyncs)"; exit }
			for (i=1;i<=n;i++) { le=o[i]; if (e[le]-s[le] >= 0.99*tot) { print "<= " le " s (" tot " fsyncs)"; exit } } }' "$1" "$2"
}
leader_changes() {
	awk '/^etcd_server_leader_changes_seen_total/ { if (FNR==NR) s=$NF; else e=$NF } END { if (e=="") print "unknown"; else print e-s }' "$1" "$2"
}
{
	echo "m6.Q platform qualification, $QSECS s; recorded, not a pass threshold"
	for s in A B; do
		echo "server $s WAL fsync p99: $(p99 "$Q/metrics-$s-start.txt" "$Q/metrics-$s-end.txt")"
		echo "server $s etcd_server_leader_changes_seen_total delta: $(leader_changes "$Q/metrics-$s-start.txt" "$Q/metrics-$s-end.txt")"
	done
	echo "leader-lease transitions (start):"; cat "$Q/leases-start.txt"
	echo "leader-lease transitions (end):"; cat "$Q/leases-end.txt"
	echo "churn ops: $ops; write failures: $wfail; cross-server read-after-write: $rawok ok, $rawfail missed"
} | sed "s|\$| [scope: $SCOPE]|" > "$Q/summary.txt"
cat "$Q/summary.txt" >> "$LOG"
if [ "$ops" -gt 0 ] && [ -s "$Q/summary.txt" ]; then
	ladder ok "m6.Q  qualification recorded in $Q/summary.txt ($ops ops; read-after-write $rawok ok / $rawfail missed)"
else
	ladder no "m6.Q  qualification recorded (no churn ran)"
fi

finish
