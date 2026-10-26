#!/usr/bin/env bash
#
# k3sm fresh-datastore first-boot lab gate: a server's very first boot on an EMPTY
# datastore brings its own mesh up, every time.
#
# On a fresh datastore the server's first node-password Secret write and its first
# mesh range-claim Lease write follow the `k3sm control plane healthy` report at once
# (cmd/k3sm/server.go steps 2a and 2b, enrollServerMesh in cmd/k3sm/serverphases.go),
# racing the creation of the system namespaces. Only the Secret write retries
# (bindSelfNodePassword in cmd/k3sm/servermesh.go: 5 attempts, 2 s doubling). A lost
# race is log-and-continue: the control plane serves on, but the server holds no
# range claim, writes no MeshPeer and brings no wireguard device up until its next
# restart. This gate boots such a server several times and asserts it never loses.
#
# The real cluster's server is NEVER touched beyond minting one short-lived join
# token. The throwaway server boots on the WORKER Mac:
#   1. the worker leaves the cluster with a plain `k3sm uninstall` (never a purge:
#      the data root, the PV data under /var/lib/k3sm/storage, the logs and the
#      recorded arguments stay; pkg/install/manifest.go dispPreserve);
#   2. `k3sm install --mesh-ip <mesh-ip>` makes it a single-node server on a fresh,
#      empty datastore at /var/lib/k3sm/server (install has no work-dir flag; the
#      server work dir is <data root>/server), the probe asserts the mesh came up,
#      and `k3sm uninstall` plus the removal of everything that boot created
#      returns the worker to its left state; repeated K3SM_FDB_BOOTS times;
#   3. the worker rejoins as an agent with a fresh five-minute token, and every
#      non-k3sm label and taint it carried before is put back if the rejoin lost it.
# Every remote root step is a script file run under `sudo -n /bin/bash`. The exit
# trap tears a throwaway server down and rejoins the worker on any failure.
#
# Legs (`--plan` prints them; the first red leg ends the run, exit 1, naming the leg):
#   fdb.1  pre: the worker's labels and taints (from the cluster), its k3sm version
#          and its PV directory listing are recorded
#   fdb.2  leave: a plain `k3sm uninstall` removes the agent daemon and keeps the
#          agent state, the data root and every PV directory
#   fdb.3  fresh first boots, each one within K3SM_FDB_BOOT_BOUND seconds of the
#          server logging `k3sm control plane healthy`:
#            - exactly one kube-system Secret <node>.node-password.k3sm
#              (secretNodePasswords, cmd/k3sm/serverjoin.go;
#              bootstrap.NodePasswordSecretSuffix)
#            - a kube-system Lease labelled net.k3sm.io/mesh-range-claim=true held
#              by <node> on the mesh-ip's /24 (claimRange, cmd/k3sm/meshclaim.go)
#            - the MeshPeer <node> (EnrollSelf, cmd/k3sm/enroll.go)
#            - a utun carrying the mesh link address, the /24's .255 (bringUpMesh;
#              podnet.MeshLinkIP)
#            - the log line `enrolled this control-plane node into its own mesh`,
#              and neither `server mesh bring-up failed` (serverMeshBringUpFailure)
#              nor `pod range is not its own` (parkServerDataPath)
#          then the throwaway server is uninstalled and its state removed
#   fdb.4  rejoin: the join port answers, a fresh 5m token is minted on the server,
#          `k3sm install --agent` rejoins the worker, and its node is Ready
#   fdb.5  restore: every non-k3sm label and taint recorded in fdb.1 is on the node
#          again (only those; nothing else is added)
#   fdb.6  end state: the worker runs the version it ran before, both nodes print
#          `k3sm version`, and every PV directory recorded in fdb.1 is still there
#
# Environment (required under K3SM_LAB=1):
#   KUBECONFIG              the admin kubeconfig of the running cluster
#   K3SM_OIS_SERVER_NODE    the server's node name
#   K3SM_OIS_WORKER_NODE    the joined worker's node name
#   K3SM_OIS_SERVER_SSH     ssh destination of the server Mac (`local` runs here)
#   K3SM_OIS_WORKER_SSH     ssh destination of the worker Mac (`local` runs here)
#   K3SM_OIS_SERVER_LAN     the server's underlay (LAN) address the worker joins at
#                           <addr>:9345; must equal the worker's installed --server
#   K3SM_FDB_WORKER_K3SM    absolute path, ON THE WORKER, of the k3sm binary of a
#                           build set (its required artifacts beside it) at the
#                           version the worker runs; the install directory is gone
#                           once the worker has left, so every install runs from it
# Optional:
#   K3SM_FDB_BOOTS            how many fresh first boots (default 3)
#   K3SM_FDB_MESH_IP          the throwaway server's --mesh-ip, the .1 of a /24
#                             (default 100.64.0.1)
#   K3SM_FDB_KUBECONFIG_NAME  the kubeconfig entry the throwaway server merges into
#                             the worker user's ~/.kube/config (default
#                             k3sm-fresh-boot); the file is restored afterwards
#   K3SM_FDB_HEALTHY_BOUND    seconds to wait for the healthy line (default 300)
#   K3SM_FDB_BOOT_BOUND       seconds after it for the mesh to be up (default 90)
#   K3SM_FDB_READY_BOUND      seconds for the rejoined node to be Ready (default 300)
#   KUBECTL                   kubectl binary (default: kubectl)
#
# Refused (exit 2, nothing changed) when the worker already holds server state the
# gate would reuse or remove: /var/lib/k3sm/server (the datastore would not be
# fresh), the server-arguments record, or a server LaunchDaemon.
#
# Exit: 0 every leg held; 1 a leg failed (the run log names it); 2 the run did not
# happen: K3SM_LAB unset (SKIP, never a pass), a bad argument, or a refused
# precondition.
#
# Usage:  hack/acceptance/B701.sh --plan        # the legs; contacts nothing
#         hack/acceptance/B701.sh --self-test   # offline checks of this script
#         K3SM_LAB=1 ... hack/acceptance/B701.sh [<evidence-dir>]
#             (default evidence dir: a new mktemp directory)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B701.sh"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh
. "$REPO_ROOT/hack/lab/lib/tolerations.sh"

GATE_NAME="fresh-datastore-boot"
MODE="lab"
REQUIRED_ENV="KUBECONFIG K3SM_OIS_SERVER_NODE K3SM_OIS_WORKER_NODE K3SM_OIS_SERVER_SSH K3SM_OIS_WORKER_SSH K3SM_OIS_SERVER_LAN K3SM_FDB_WORKER_K3SM"
BOOTS="${K3SM_FDB_BOOTS:-3}"
MESH_IP="${K3SM_FDB_MESH_IP:-100.64.0.1}"
KC_NAME="${K3SM_FDB_KUBECONFIG_NAME:-k3sm-fresh-boot}"
HEALTHY_BOUND="${K3SM_FDB_HEALTHY_BOUND:-300}"
BOOT_BOUND="${K3SM_FDB_BOOT_BOUND:-90}"
READY_BOUND="${K3SM_FDB_READY_BOUND:-300}"
JOIN_PORT=9345

# The paths the gate reads and the throwaway server writes, on the worker. Each one
# is the installer's own (pkg/install, pkg/dataroot); none is a knob.
DATA_ROOT="/var/lib/k3sm"
SERVER_DIR="$DATA_ROOT/server"
AGENT_DIR="$DATA_ROOT/agent"
STORAGE_DIR="$DATA_ROOT/storage"
SERVER_KEY="$DATA_ROOT/keys/server.key"
SERVER_RECORD="/Library/Preferences/io.k3sm.server-args.json"
SERVER_PLIST="/Library/LaunchDaemons/io.k3sm.server.plist"
AGENT_PLIST="/Library/LaunchDaemons/io.k3sm.agent.plist"
SERVER_LOG="/var/log/k3sm/server.log"

# The leg table: `name|statement`. --plan prints it, the run reports against it, and
# --self-test checks every name is unique and run.
LEGS=(
	"fdb.1|pre: the worker's labels, taints, k3sm version and PV directories are recorded"
	"fdb.2|leave: a plain uninstall removes the agent daemon and keeps the data root and every PV directory"
	"fdb.3|every fresh first boot binds its node-password, claims its range, writes its MeshPeer and brings its utun up"
	"fdb.4|rejoin: join port open, a fresh 5m token, install --agent, the worker node Ready"
	"fdb.5|restore: every recorded non-k3sm label and taint is on the worker node again"
	"fdb.6|end state: the worker's version is unchanged and every recorded PV directory is still there"
)

# ---- pure helpers (the --self-test surface) -----------------------------------------

# FDB_PY answers one question about a JSON document on stdin.
#   plist-server             the agent's --server, from the LaunchDaemon's
#                            ProgramArguments (as `plutil -extract ... json` prints it)
#   meta                     a Node's non-k3sm labels and taints, one per line
#   missing-meta <pre-file>  the meta lines of <pre-file> (a Node) absent from stdin's
#                            Node: a label whose key is gone, a taint whose
#                            key+effect is gone; a changed value is not "missing"
FDB_PY='
import json, sys
op, a = sys.argv[1], sys.argv[2:]
def managed(key):
    p = key.split("/", 1)[0] if "/" in key else ""
    for d in ("kubernetes.io", "k8s.io", "k3sm.io"):
        if p == d or p.endswith("." + d):
            return True
    return False
def meta(node):
    out = []
    for k, v in sorted(((node.get("metadata") or {}).get("labels") or {}).items()):
        if not managed(k):
            out.append(("label", k, v or "", ""))
    for t in (node.get("spec") or {}).get("taints") or []:
        k = t.get("key", "")
        if k and not managed(k):
            out.append(("taint", k, t.get("value") or "", t.get("effect") or ""))
    return out
d = json.load(sys.stdin)
if op == "plist-server":
    v = ""
    for i, x in enumerate(d):
        if x == "--server" and i + 1 < len(d):
            v = d[i + 1]
        elif isinstance(x, str) and x.startswith("--server="):
            v = x[len("--server="):]
    print(v)
elif op == "meta":
    for m in meta(d):
        print("\t".join(m))
elif op == "missing-meta":
    with open(a[0]) as f:
        pre = meta(json.load(f))
    cur = meta(d)
    labels = {m[1] for m in cur if m[0] == "label"}
    taints = {(m[1], m[3]) for m in cur if m[0] == "taint"}
    for m in pre:
        if (m[0] == "label" and m[1] not in labels) or (m[0] == "taint" and (m[1], m[3]) not in taints):
            print("\t".join(m))
else:
    sys.exit("unknown op " + op)
'
# fjson <op> [args...] < document
fjson() { python3 -c "$FDB_PY" "$@"; }

# probe_field <output> <key>: the last value a remote script reported (`FDB key=value`).
probe_field() {
	printf '%s\n' "$1" | awk -v k="FDB $2=" 'index($0, k) == 1 { v = substr($0, length(k) + 1) } END { print v }'
}

# mesh_cidr / mesh_link <mesh-ip>: the /24 a server's --mesh-ip names and that /24's
# .255, the utun's point-to-point address (serverSelfPodCIDR; podnet.MeshLinkIP).
# Both refuse anything that is not the .1 of a /24.
mesh_cidr() {
	[[ "$1" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.1$ ]] || return 1
	echo "${BASH_REMATCH[1]}.0/24"
}
mesh_link() {
	[[ "$1" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.1$ ]] || return 1
	echo "${BASH_REMATCH[1]}.255"
}

# is_count <value>: a positive decimal integer.
is_count() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

# missing_lines <before> <after>: the lines of before that after lacks.
missing_lines() {
	comm -23 <(printf '%s\n' "$1" | LC_ALL=C sort -u | sed '/^$/d') <(printf '%s\n' "$2" | LC_ALL=C sort -u | sed '/^$/d')
}

# judge_boot <probe-output> <want-cidr>: prints the verdict detail; 0 when the boot
# brought its mesh up, 1 naming the first missing property otherwise.
judge_boot() {
	local out="$1" cidr="$2" node secrets n
	if [ "$(probe_field "$out" healthy)" != 1 ]; then
		echo "the server never logged 'k3sm control plane healthy' within ${HEALTHY_BOUND}s"
		return 1
	fi
	if [ "$(probe_field "$out" bringup_failed)" = 1 ]; then
		echo "the server logged 'server mesh bring-up failed': its first boot lost the race and it is NOT on its own mesh"
		return 1
	fi
	if [ "$(probe_field "$out" refused)" = 1 ]; then
		echo "the server parked its data path: its pod range is not its own"
		return 1
	fi
	secrets="$(probe_field "$out" secrets)"
	# shellcheck disable=SC2086 # word-split the space-separated node list
	set -- $secrets
	if [ "$#" != 1 ]; then
		echo "want exactly one kube-system Secret <node>.node-password.k3sm, got $# (${secrets:-none})"
		return 1
	fi
	node="$1"
	case " $(probe_field "$out" leases) " in *" $node|$cidr "*) ;; *)
		echo "no range-claim Lease held by $node on $cidr (got: $(probe_field "$out" leases))"
		return 1
		;;
	esac
	case " $(probe_field "$out" meshpeers) " in *" $node "*) ;; *)
		echo "no MeshPeer $node (got: $(probe_field "$out" meshpeers))"
		return 1
		;;
	esac
	if [ "$(probe_field "$out" utun)" != 1 ]; then
		echo "no utun carries the mesh link address: the wireguard device is not up"
		return 1
	fi
	if [ "$(probe_field "$out" enrolled)" != 1 ]; then
		echo "no 'enrolled this control-plane node into its own mesh' line"
		return 1
	fi
	n="$(probe_field "$out" settle)"
	echo "node $node: Secret, Lease on $cidr, MeshPeer and utun all present ${n:-?}s after the healthy line was seen"
}

# ---- the remote root scripts ------------------------------------------------------------
# Each prints a bash script that a lab Mac runs under `sudo -n /bin/bash <file>`. The
# header assigns its inputs (printf %q), the quoted body never expands locally.
# Results come back as `FDB key=value` lines.

script_head() {
	echo '#!/bin/bash'
	echo 'set -u'
	echo 'PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
	printf '%s\n' 'emit() { printf "FDB %s\n" "$*"; }'
	local kv
	for kv in "$@"; do
		printf '%s=%q\n' "${kv%%=*}" "${kv#*=}"
	done
}

# storage_body: emits one `FDB-S <path>` line per entry under STORAGE_DIR, three deep.
storage_body() {
	cat <<'BODY'
if [ -d "$STORAGE_DIR" ]; then
	find "$STORAGE_DIR" -mindepth 1 -maxdepth 3 -print 2>/dev/null | LC_ALL=C sort | sed 's/^/FDB-S /'
fi
BODY
}

# facts_script <k3sm>: what the worker holds; reads only.
facts_script() {
	script_head "K3SM=$1" "SERVER_DIR=$SERVER_DIR" "AGENT_DIR=$AGENT_DIR" "STORAGE_DIR=$STORAGE_DIR" \
		"SERVER_KEY=$SERVER_KEY" "SERVER_RECORD=$SERVER_RECORD" "SERVER_PLIST=$SERVER_PLIST" \
		"AGENT_PLIST=$AGENT_PLIST" "SERVER_LOG=$SERVER_LOG"
	cat <<'BODY'
have() { if [ -e "$1" ]; then echo 1; else echo 0; fi; }
emit server_dir=$(have "$SERVER_DIR")
emit server_record=$(have "$SERVER_RECORD")
emit server_plist=$(have "$SERVER_PLIST")
emit server_key=$(have "$SERVER_KEY")
emit server_log=$(have "$SERVER_LOG")
emit agent_plist=$(have "$AGENT_PLIST")
emit agent_dir=$(have "$AGENT_DIR")
if [ -e "$AGENT_PLIST" ]; then
	printf 'FDB-PLIST %s\n' "$(plutil -extract ProgramArguments json -o - "$AGENT_PLIST" 2>/dev/null)"
fi
bin_ok=0
if [ -x "$K3SM" ]; then
	bin_ok=1
	dir="$(dirname "$K3SM")"
	req="$("$K3SM" install --print-required-artifacts 2>/dev/null)" || bin_ok=0
	while IFS= read -r a; do
		[ -n "$a" ] || continue
		[ -e "$dir/$a" ] || { bin_ok=0; emit missing_artifact="$a"; }
	done <<<"$req"
	printf 'FDB-VERSION %s\n' "$("$K3SM" version 2>/dev/null | tr '\n' ' ')"
fi
emit bin_ok=$bin_ok
BODY
	storage_body
	echo 'emit end'
}

# leave_script <k3sm>: the worker leaves the cluster, plainly.
leave_script() {
	script_head "K3SM=$1" "AGENT_PLIST=$AGENT_PLIST" "AGENT_DIR=$AGENT_DIR" "STORAGE_DIR=$STORAGE_DIR"
	cat <<'BODY'
"$K3SM" uninstall 2>&1
emit uninstall_rc=$?
if [ -e "$AGENT_PLIST" ]; then emit agent_plist=1; else emit agent_plist=0; fi
if [ -d "$AGENT_DIR" ]; then emit agent_dir=1; else emit agent_dir=0; fi
BODY
	storage_body
	echo 'emit end'
}

# boot_script <k3sm> <mesh-ip> <kubeconfig-name> <user>: one fresh first boot.
boot_script() {
	script_head "K3SM=$1" "MESH_IP=$2" "KC_NAME=$3" "TARGET_USER=$4" "SERVER_DIR=$SERVER_DIR" \
		"SERVER_PLIST=$SERVER_PLIST" "AGENT_PLIST=$AGENT_PLIST" "SERVER_LOG=$SERVER_LOG"
	cat <<'BODY'
if [ -e "$SERVER_PLIST" ] || [ -e "$AGENT_PLIST" ]; then emit error=a-node-daemon-is-installed; emit end; exit 1; fi
if [ -e "$SERVER_DIR" ]; then emit error=the-datastore-is-not-fresh; emit end; exit 1; fi
off=0
[ -e "$SERVER_LOG" ] && off="$(stat -f %z "$SERVER_LOG")"
emit log_offset="$off"
"$K3SM" install --mesh-ip "$MESH_IP" --kubeconfig-name "$KC_NAME" --user "$TARGET_USER" 2>&1
emit install_rc=$?
emit end
BODY
}

# probe_script <k3sm> <log-offset> <mesh-ip>: waits for the healthy line, then for
# the mesh, and reports what it saw and the new server-log lines.
probe_script() {
	script_head "K3SM=$1" "OFF=$2" "LINK=$(mesh_link "$3")" "HEALTHY_BOUND=$HEALTHY_BOUND" \
		"BOOT_BOUND=$BOOT_BOUND" "SERVER_DIR=$SERVER_DIR" "SERVER_LOG=$SERVER_LOG"
	cat <<'BODY'
newlog() { tail -c +"$((OFF + 1))" "$SERVER_LOG" 2>/dev/null; }
seen() { newlog | grep -qF "$1"; }
kc() { K3SM_WORK_DIR="$SERVER_DIR" "$K3SM" kubectl "$@" 2>/dev/null; }
utun_up() {
	ifconfig 2>/dev/null | awk '/^utun[0-9]+:/ { u = 1; next } /^[^ \t]/ { u = 0 } u && /inet /' | grep -qF "inet $LINK --> $LINK "
}
healthy=0
deadline=$((SECONDS + HEALTHY_BOUND))
while [ "$SECONDS" -lt "$deadline" ]; do
	if seen 'k3sm control plane healthy'; then healthy=1; break; fi
	sleep 1
done
emit healthy=$healthy
secrets="" leases="" peers="" utun=0 enrolled=0 failed=0 refused=0 settle=""
if [ "$healthy" = 1 ]; then
	t0=$SECONDS
	end=$((t0 + BOOT_BOUND))
	while :; do
		secrets="$(kc get secrets -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sed -n 's/\.node-password\.k3sm$//p' | tr '\n' ' ')"
		leases="$(kc get leases -n kube-system -l net.k3sm.io/mesh-range-claim=true -o jsonpath='{range .items[*]}{.spec.holderIdentity}{"|"}{.metadata.annotations.net\.k3sm\.io/pod-cidr}{"\n"}{end}' | tr '\n' ' ')"
		peers="$(kc get meshpeers.net.k3sm.io -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | tr '\n' ' ')"
		if utun_up; then utun=1; else utun=0; fi
		if seen 'enrolled this control-plane node into its own mesh'; then enrolled=1; fi
		if seen 'server mesh bring-up failed'; then failed=1; fi
		if seen 'pod range is not its own'; then refused=1; fi
		if [ "$failed" = 1 ] || [ "$refused" = 1 ]; then break; fi
		if [ -n "$secrets" ] && [ -n "$leases" ] && [ -n "$peers" ] && [ "$utun" = 1 ] && [ "$enrolled" = 1 ]; then break; fi
		[ "$SECONDS" -lt "$end" ] || break
		sleep 2
	done
	settle=$((SECONDS - t0))
fi
emit secrets="$secrets"
emit leases="$leases"
emit meshpeers="$peers"
emit utun=$utun
emit enrolled=$enrolled
emit bringup_failed=$failed
emit refused=$refused
emit settle=$settle
newlog | tail -n 400 | sed 's/^/LOG| /'
emit end
BODY
}

# teardown_script <k3sm> <remove-key 0|1> <remove-log 0|1>: uninstalls the throwaway
# server and removes the state its boot created. The precondition refused a worker
# that held any of it before the run, so all of it is the run's own.
teardown_script() {
	script_head "K3SM=$1" "REMOVE_KEY=$2" "REMOVE_LOG=$3" "SERVER_DIR=$SERVER_DIR" \
		"SERVER_RECORD=$SERVER_RECORD" "SERVER_PLIST=$SERVER_PLIST" "SERVER_KEY=$SERVER_KEY" "SERVER_LOG=$SERVER_LOG"
	cat <<'BODY'
rc=0
if [ -e "$SERVER_PLIST" ]; then "$K3SM" uninstall 2>&1 || rc=1; fi
if [ -e "$SERVER_PLIST" ]; then emit error=the-server-daemon-is-still-installed; emit end; exit 1; fi
case "$SERVER_DIR" in /var/lib/k3sm/server) rm -rf "$SERVER_DIR" ;; *) rc=1 ;; esac
rm -f "$SERVER_RECORD"
[ "$REMOVE_KEY" = 1 ] && rm -f "$SERVER_KEY"
[ "$REMOVE_LOG" = 1 ] && rm -f "$SERVER_LOG"
[ -e "$SERVER_DIR" ] && rc=1
emit teardown_rc=$rc
emit end
BODY
}

# rejoin_script <k3sm> <server-lan> <user>: the join token arrives on stdin and
# lives only in a root-only temp file for the length of the install.
rejoin_script() {
	script_head "K3SM=$1" "SERVER_LAN=$2" "TARGET_USER=$3"
	cat <<'BODY'
IFS= read -r token || token=""
[ -n "$token" ] || { emit error=no-token; emit end; exit 1; }
umask 077
tf="$(mktemp /var/root/k3sm-join-token.XXXXXX)" || { emit error=no-token-file; emit end; exit 1; }
printf '%s\n' "$token" >"$tf"
"$K3SM" install --agent --server "$SERVER_LAN" --token-file "$tf" --user "$TARGET_USER" 2>&1
rc=$?
rm -f "$tf"
emit install_rc=$rc
emit end
BODY
}

# token_script: the server mints one short-lived join token; only the token is on stdout.
token_script() {
	script_head
	echo 'exec k3sm token create --ttl 5m --work-dir /var/lib/k3sm/server 2>/dev/null'
}

# ---- --plan -----------------------------------------------------------------------------

plan() {
	local row
	echo "fresh-datastore-boot lab gate: PLAN ONLY (contacts nothing)"
	echo "legs (the first red leg ends the run):"
	for row in "${LEGS[@]}"; do
		printf '  %-6s %s\n' "${row%%|*}" "${row#*|}"
	done
	echo "boots: $BOOTS; mesh ip: $MESH_IP; bounds: healthy ${HEALTHY_BOUND}s, mesh ${BOOT_BOUND}s, Ready ${READY_BOUND}s"
	echo "required under K3SM_LAB=1: $REQUIRED_ENV"
	echo "exit: 0 every leg held, 1 a leg failed, 2 not run (K3SM_LAB unset: SKIP; a bad argument; a refused precondition)"
}

# ---- --self-test --------------------------------------------------------------------------

self_test() {
	local bad=0 row name names="" dup="" src t out code fake tmp pre cur f
	check() { if [ "$1" = ok ]; then echo "ok    $2"; else echo "FAIL  $2"; bad=1; fi; }

	if command -v shellcheck >/dev/null 2>&1; then
		if out="$(shellcheck -x "$SELF" 2>&1)"; then check ok "shellcheck: clean"; else
			printf '%s\n' "$out"
			check no "shellcheck: clean"
		fi
	else
		echo "skip  shellcheck (not installed)"
	fi

	# Every remote root script parses.
	for f in "facts_script /x/k3sm" "leave_script /x/k3sm" "boot_script /x/k3sm 100.64.0.1 kc-x u" \
		"probe_script /x/k3sm 0 100.64.0.1" "teardown_script /x/k3sm 1 0" "rejoin_script /x/k3sm host.invalid u" "token_script"; do
		# shellcheck disable=SC2086 # the function name and its arguments
		if $f | bash -n 2>/dev/null; then check ok "remote script parses: ${f%% *}"; else check no "remote script parses: ${f%% *}"; fi
	done
	out="$(boot_script "/x/k 3sm" 100.64.0.1 "kc'x" "a user")"
	case "$out" in *"K3SM=/x/k\\ 3sm"*"KC_NAME=kc\\'x"*"TARGET_USER=a\\ user"*) check ok "remote script inputs are shell-quoted" ;; *) check no "remote script inputs are shell-quoted" ;; esac
	out="$(probe_script /x/k3sm 17 100.64.3.1)"
	case "$out" in *"OFF=17"*"LINK=100.64.3.255"*) check ok "probe: the log offset and the mesh link address" ;; *) check no "probe: the log offset and the mesh link address" ;; esac
	out="$(boot_script /x/k3sm 100.64.0.1 kc-x u)"
	# shellcheck disable=SC2016 # the literal text of the remote script
	case "$out" in *'install --mesh-ip "$MESH_IP" --kubeconfig-name "$KC_NAME" --user "$TARGET_USER"'*) check ok "boot: a single-node server install with the mesh ip" ;; *) check no "boot: a single-node server install with the mesh ip" ;; esac
	case "$out" in *--agent*) check no "boot: no --agent" ;; *) check ok "boot: no --agent" ;; esac
	out="$(rejoin_script /x/k3sm host.invalid u)"
	# shellcheck disable=SC2016 # the literal text of the remote script
	case "$out" in *'install --agent --server "$SERVER_LAN" --token-file "$tf"'*'rm -f "$tf"'*) check ok "rejoin: install --agent from a token file it removes" ;; *) check no "rejoin: install --agent from a token file it removes" ;; esac
	out="$(token_script)"
	case "$out" in *"token create --ttl 5m --work-dir /var/lib/k3sm/server"*) check ok "token: five minutes, the server work dir" ;; *) check no "token: five minutes, the server work dir" ;; esac
	out="$(teardown_script /x/k3sm 0 0)"
	# shellcheck disable=SC2016 # the literal text of the remote script
	case "$out" in *'/var/lib/k3sm/server) rm -rf "$SERVER_DIR"'*) check ok "teardown: removes only the literal server work dir" ;; *) check no "teardown: removes only the literal server work dir" ;; esac

	src="$(cat "$SELF")"
	case "$src" in *"--pur""ge"*) check no "no purge anywhere" ;; *) check ok "no purge anywhere" ;; esac
	# The only sudo uses: the passwordless probe and a script file run under bash.
	t="$(printf '%s\n' "$src" | grep -oE 'sudo -n [a-z/]+' | sort -u | tr '\n' ' ')"
	check "$([ "$t" = "sudo -n /bin/bash sudo -n true " ] && echo ok)" "sudo runs only script files (got: $t)"
	t="$(printf '%s\n' "$src" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | { grep -vE '^100\.64\.' || true; } | sort -u | tr '\n' ' ')"
	check "$([ -z "$t" ] && echo ok)" "no address but the mesh range is written into the file (got: ${t:-none})"

	for row in "${LEGS[@]}"; do
		name="${row%%|*}"
		case " $names " in *" $name "*) dup="$name" ;; esac
		names="$names $name"
		case "$src" in *"run_leg $name"$'\n'*) ;; *) check no "leg $name is run by a run_leg call" ;; esac
	done
	check "$([ -z "$dup" ] && echo ok)" "leg names unique (${#LEGS[@]}:${names})"
	t="$(printf '%s\n' "$src" | grep -oE '^run_leg fdb\.[0-9]+$' | sed 's/^run_leg //' | tr '\n' ' ')"
	check "$([ " $t" = "$names " ] && echo ok)" "legs run in table order ($t)"

	check "$([ "$(mesh_cidr 100.64.0.1)" = 100.64.0.0/24 ] && echo ok)" "mesh_cidr: the /24 of the .1"
	check "$([ "$(mesh_link 100.64.7.1)" = 100.64.7.255 ] && echo ok)" "mesh_link: the /24's .255"
	check "$(if mesh_cidr 100.64.0.2 >/dev/null; then echo no; else echo ok; fi)" "mesh_cidr: refuses an address that is not the .1"
	check "$(if mesh_link 100.64.0 >/dev/null; then echo no; else echo ok; fi)" "mesh_link: refuses a malformed address"
	check "$(is_count 3 && echo ok)" "is_count: 3"
	check "$(if is_count 0 || is_count x || is_count ""; then echo no; else echo ok; fi)" "is_count: refuses 0, a word, empty"
	check "$([ "$(missing_lines $'a\nb\nc' $'c\na\nd')" = b ] && echo ok)" "missing_lines: what the second lacks"
	check "$([ -z "$(missing_lines $'a\nb' $'b\na\nz')" ] && echo ok)" "missing_lines: a superset lacks nothing"

	t='FDB x=1
FDB x=2'
	check "$([ "$(probe_field "$t" x)" = 2 ] && echo ok)" "probe_field: the last report wins"
	t='["/Library/k3sm/bin/k3sm","agent","--server","lan.invalid","--token-file","/x"]'
	check "$([ "$(printf '%s' "$t" | fjson plist-server)" = lan.invalid ] && echo ok)" "plist-server: --server <v>"
	t='["/Library/k3sm/bin/k3sm","agent","--server=lan.invalid"]'
	check "$([ "$(printf '%s' "$t" | fjson plist-server)" = lan.invalid ] && echo ok)" "plist-server: --server=<v>"

	tmp="$(mktemp -d "${TMPDIR:-/tmp}/fdb-selftest.XXXXXX")"
	pre='{"metadata":{"labels":{"kubernetes.io/os":"darwin","node-role.kubernetes.io/worker":"","k3sm.io/provider":"darwin","net.k3sm.io/x":"1","example.io/estate":"on","plain":"v"}},"spec":{"taints":[{"key":"k3sm.io/provider","value":"darwin","effect":"NoSchedule"},{"key":"node.kubernetes.io/unreachable","effect":"NoExecute"},{"key":"example.io/estate-off","effect":"NoExecute"},{"key":"example.io/soft","value":"y","effect":"PreferNoSchedule"}]}}'
	printf '%s' "$pre" >"$tmp/pre.json"
	t="$(printf '%s' "$pre" | fjson meta)"
	check "$([ "$t" = "$(printf 'label\texample.io/estate\ton\t\nlabel\tplain\tv\t\ntaint\texample.io/estate-off\t\tNoExecute\ntaint\texample.io/soft\ty\tPreferNoSchedule')" ] && echo ok)" "meta: only non-k3sm, non-kubernetes labels and taints"
	cur='{"metadata":{"labels":{"kubernetes.io/os":"darwin","plain":"changed"}},"spec":{"taints":[{"key":"example.io/soft","value":"y","effect":"NoSchedule"}]}}'
	t="$(printf '%s' "$cur" | fjson missing-meta "$tmp/pre.json")"
	check "$([ "$t" = "$(printf 'label\texample.io/estate\ton\t\ntaint\texample.io/estate-off\t\tNoExecute\ntaint\texample.io/soft\ty\tPreferNoSchedule')" ] && echo ok)" "missing-meta: a gone label, a gone taint, a taint whose effect changed; a changed value is not missing"
	t="$(printf '%s' "$pre" | fjson missing-meta "$tmp/pre.json")"
	check "$([ -z "$t" ] && echo ok)" "missing-meta: nothing missing from the same node"
	check "$([ "$(meta_args $'label\tplain\tv\t')" = "label plain=v" ] && echo ok)" "meta_args: a label"
	check "$([ "$(meta_args $'label\tempty\t\t')" = "label empty=" ] && echo ok)" "meta_args: an empty-valued label"
	check "$([ "$(meta_args $'taint\tk/x\t\tNoExecute')" = "taint k/x:NoExecute" ] && echo ok)" "meta_args: a valueless taint"
	check "$([ "$(meta_args $'taint\tk/x\tv\tNoSchedule')" = "taint k/x=v:NoSchedule" ] && echo ok)" "meta_args: a valued taint"

	# The verdict on one boot, from probe reports in the shape probe_script emits.
	green='FDB healthy=1
FDB secrets=node-a
FDB leases=node-a|100.64.0.0/24
FDB meshpeers=node-a
FDB utun=1
FDB enrolled=1
FDB bringup_failed=0
FDB refused=0
FDB settle=4'
	out="$(judge_boot "$green" 100.64.0.0/24)" && code=0 || code=$?
	check "$([ "$code" = 0 ] && echo ok)" "judge_boot: every property present is green ($out)"
	for t in "healthy=0|healthy" "bringup_failed=1|bring-up failed" "refused=1|not its own" "secrets=|exactly one" \
		"secrets=node-a node-b|exactly one" "leases=node-a|100.64.9.0/24|no range-claim Lease" "leases=other|100.64.0.0/24|no range-claim Lease" \
		"meshpeers=|no MeshPeer" "utun=0|wireguard device" "enrolled=0|enrolled this"; do
		f="${t%|*}"
		out="$(judge_boot "$green"$'\n'"FDB $f" 100.64.0.0/24)" && code=0 || code=$?
		case "$code:$out" in 1:*"${t##*|}"*) check ok "judge_boot: $f is red, named" ;; *) check no "judge_boot: $f is red, named (got $code: $out)" ;; esac
	done

	# The exit contract, as child processes with kubectl, ssh, scp and sudo stand-ins
	# that record any call: nothing may reach a host.
	mkdir -p "$tmp/bin"
	for fake in kubectl ssh scp sudo; do
		printf '#!/bin/sh\necho %s "$@" >>"%s/calls.log"\nexit 1\n' "$fake" "$tmp" >"$tmp/bin/$fake"
		chmod +x "$tmp/bin/$fake"
	done
	t="PATH=$tmp/bin:/usr/bin:/bin"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" 2>&1)" && code=0 || code=$?
	case "$out" in *SKIP*"NOT a pass"*) ;; *) code=99 ;; esac
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_LAB unset: SKIP, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=0 /bin/bash "$SELF" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_LAB=0: SKIP, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --plan 2>&1)" && code=0 || code=$?
	for row in "${LEGS[@]}"; do
		case "$out" in *"${row%%|*} "*) ;; *) code=98 ;; esac
	done
	check "$([ "$code" = 0 ] && echo ok)" "--plan: exit 0, every leg listed (got $code)"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --bogus 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "an unknown option: exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 /bin/bash "$SELF" a b 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "two positional arguments: exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 /bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	case "$out" in *"K3SM_OIS_SERVER_NODE"*"K3SM_OIS_SERVER_LAN"*"K3SM_FDB_WORKER_K3SM"*) ;; *) code=97 ;; esac
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/evidence" ] && echo ok)" "K3SM_LAB=1, required variables unset: refused, exit 2, names them, no evidence dir (got $code)"
	set -- KUBECONFIG=/nonexistent K3SM_OIS_SERVER_NODE=a K3SM_OIS_SERVER_SSH=local K3SM_OIS_WORKER_SSH=local \
		K3SM_OIS_SERVER_LAN=lan.invalid K3SM_FDB_WORKER_K3SM=/x/k3sm
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 "$@" K3SM_OIS_WORKER_NODE=a /bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "the same node as server and worker: refused, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 "$@" K3SM_OIS_WORKER_NODE=b K3SM_FDB_BOOTS=0 /bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_FDB_BOOTS=0: refused, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 "$@" K3SM_OIS_WORKER_NODE=b K3SM_FDB_MESH_IP=100.64.0.7 /bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "a mesh ip that is not the .1 of a /24: refused, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 "$@" K3SM_OIS_WORKER_NODE=b K3SM_FDB_WORKER_K3SM=k3sm /bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "a relative worker k3sm path: refused, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 "$@" K3SM_OIS_WORKER_NODE=b /bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/evidence" ] && echo ok)" "the cluster not serving: refused, exit 2, no evidence dir (got $code)"
	if grep -Eq '(install|uninstall|token|label|taint|delete|apply)( |$)' "$tmp/calls.log" 2>/dev/null; then
		check no "no refused run made a write call: $(tr '\n' ';' <"$tmp/calls.log")"
	else
		check ok "no refused run made a write call"
	fi
	rm -rf "$tmp"

	if [ "$bad" = 0 ]; then echo "fresh-datastore-boot self-test: green"; else echo "fresh-datastore-boot self-test: RED"; fi
	return "$bad"
}

# meta_args <meta-line>: `label key=value` or `taint key[=value]:effect`, the
# argument kubectl label/taint takes to put one recorded line back.
meta_args() {
	# Split by hand: a tab is IFS whitespace, so `read` would fold an empty value.
	local rest="$1" kind key value effect
	kind="${rest%%$'\t'*}" rest="${rest#*$'\t'}"
	key="${rest%%$'\t'*}" rest="${rest#*$'\t'}"
	value="${rest%%$'\t'*}" effect="${rest#*$'\t'}"
	if [ "$kind" = label ]; then
		echo "label $key=$value"
	elif [ -n "$value" ]; then
		echo "taint $key=$value:$effect"
	else
		echo "taint $key:$effect"
	fi
}

case "${1:-}" in
--plan)
	plan
	exit 0
	;;
--self-test)
	self_test
	exit $?
	;;
-h | --help)
	sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
	exit 0
	;;
-*)
	echo "B701.sh: unknown option $1 (try --plan, --self-test)" >&2
	exit 2
	;;
esac

# ---- lab guard ---------------------------------------------------------------------------
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "fresh-datastore-boot lab gate: SKIP (two Macs). Set K3SM_LAB=1 against the running two-node cluster to run it; this is NOT a pass."
	exit 2
fi

# ---- preconditions (exit 2, nothing changed) ---------------------------------------------
REMOTE_W=""
REMOTE_S=""
refuse() {
	echo "fresh-datastore-boot lab gate: REFUSED: $*" >&2
	exit 2
}
[ "$#" -le 1 ] || refuse "at most one argument, the evidence directory (got $#)"
missing=""
for v in $REQUIRED_ENV; do
	[ -n "${!v:-}" ] || missing="$missing $v"
done
[ -z "$missing" ] || refuse "required variable(s) unset:$missing (see the header of $SELF)"
SERVER="$K3SM_OIS_SERVER_NODE"
WORKER="$K3SM_OIS_WORKER_NODE"
SERVER_LAN="$K3SM_OIS_SERVER_LAN"
WK3SM="$K3SM_FDB_WORKER_K3SM"
[ "$SERVER" != "$WORKER" ] || refuse "K3SM_OIS_SERVER_NODE and K3SM_OIS_WORKER_NODE name the same node ($SERVER)"
is_count "$BOOTS" || refuse "K3SM_FDB_BOOTS must be a positive integer (got '$BOOTS')"
for v in HEALTHY_BOUND BOOT_BOUND READY_BOUND; do
	is_count "${!v}" || refuse "K3SM_FDB_$v must be a positive integer (got '${!v}')"
done
MESH_CIDR="$(mesh_cidr "$MESH_IP")" || refuse "K3SM_FDB_MESH_IP must be the .1 of a /24 (got '$MESH_IP')"
case "$WK3SM" in /*) ;; *) refuse "K3SM_FDB_WORKER_K3SM must be an absolute path on the worker (got '$WK3SM')" ;; esac
[[ "$KC_NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]] || refuse "K3SM_FDB_KUBECONFIG_NAME must be lowercase letters, digits and dashes (got '$KC_NAME')"
[ "$KC_NAME" != k3sm ] || refuse "K3SM_FDB_KUBECONFIG_NAME must not be the default k3sm entry"
KUBECTL="${KUBECTL:-kubectl}"
command -v "$KUBECTL" >/dev/null 2>&1 || refuse "kubectl not found ($KUBECTL)"
command -v python3 >/dev/null 2>&1 || refuse "python3 not found; the gate reads Node JSON with it"
kc() { "$KUBECTL" "$@"; }
kc get --raw /healthz >/dev/null 2>&1 || refuse "the cluster at \$KUBECONFIG is not serving (/healthz)"
for n in "$SERVER" "$WORKER"; do
	ready="$(kc get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
	[ "$ready" = True ] || refuse "node $n is not Ready (got '${ready:-absent}')"
done

# on <ssh-destination|local> <command>: run a command on a lab Mac in a login shell;
# stdin passes through.
on() {
	local host="$1"
	shift
	if [ "$host" = local ]; then
		zsh -lc "$*"
	else
		ssh -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"
	fi
}
on_server() { on "$K3SM_OIS_SERVER_SSH" "$@"; }
on_worker() { on "$K3SM_OIS_WORKER_SSH" "$@"; }

# as_root <server|worker> <name> <script-text>: copies the script into the run's
# remote directory on that Mac and runs it there under `sudo -n /bin/bash <file>`,
# never as an `ssh host "sudo a && b"` chain; the caller's stdin reaches the script.
as_root() {
	local who="$1" name="$2" text="$3" host dir
	if [ "$who" = server ]; then host="$K3SM_OIS_SERVER_SSH" dir="$REMOTE_S"; else host="$K3SM_OIS_WORKER_SSH" dir="$REMOTE_W"; fi
	[ -n "$dir" ] || return 1
	printf '%s\n' "$text" | on "$host" "cat > '$dir/$name.sh' && chmod 600 '$dir/$name.sh'" || return 1
	on "$host" "sudo -n /bin/bash '$dir/$name.sh'"
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
drop_remote_dirs() {
	[ -n "$REMOTE_W" ] && on_worker "rm -rf '$REMOTE_W'" >/dev/null 2>&1
	[ -n "$REMOTE_S" ] && on_server "rm -rf '$REMOTE_S'" >/dev/null 2>&1
	REMOTE_W="" REMOTE_S=""
	return 0
}
trap drop_remote_dirs EXIT

PRE_WORKER_VERSION="$(on_worker 'k3sm version' 2>/dev/null)" || refuse "k3sm does not run on the worker ($K3SM_OIS_WORKER_SSH)"
on_server 'k3sm version' >/dev/null 2>&1 || refuse "k3sm does not run on the server ($K3SM_OIS_SERVER_SSH)"
on_server 'sudo -n true' >/dev/null 2>&1 || refuse "passwordless sudo is not available on the server"
on_worker 'sudo -n true' >/dev/null 2>&1 || refuse "passwordless sudo is not available on the worker"
on_worker 'command -v nc >/dev/null' >/dev/null 2>&1 || refuse "nc is not on the worker; the join-port poll needs it"
WORKER_USER="$(on_worker 'id -un' 2>/dev/null | tail -1)"
[ -n "$WORKER_USER" ] && [ "$WORKER_USER" != root ] || refuse "the worker's ssh user must be a non-root human (got '${WORKER_USER:-none}')"
# shellcheck disable=SC2016 # expanded by the remote shell
REMOTE_W="$(on_worker 'mktemp -d "${TMPDIR:-/tmp}/fdb.XXXXXX"' 2>/dev/null | tail -1)"
# shellcheck disable=SC2016 # expanded by the remote shell
REMOTE_S="$(on_server 'mktemp -d "${TMPDIR:-/tmp}/fdb.XXXXXX"' 2>/dev/null | tail -1)"
[ -n "$REMOTE_W" ] && [ -n "$REMOTE_S" ] || refuse "could not make a run directory on both Macs"

PRE_FACTS="$(as_root worker facts "$(facts_script "$WK3SM")" 2>&1)" || true
printf '%s\n' "$PRE_FACTS" | grep -q '^FDB end$' || refuse "the worker's fact script did not finish: $(printf '%s' "$PRE_FACTS" | tail -3 | tr '\n' ' ')"
[ "$(probe_field "$PRE_FACTS" agent_plist)" = 1 ] || refuse "the worker carries no agent LaunchDaemon ($AGENT_PLIST): it is not a joined worker"
[ "$(probe_field "$PRE_FACTS" server_plist)" = 0 ] || refuse "the worker carries a server LaunchDaemon ($SERVER_PLIST)"
[ "$(probe_field "$PRE_FACTS" server_dir)" = 0 ] || refuse "the worker already holds $SERVER_DIR: a boot there would not be on a fresh datastore, and this gate never removes state it did not create"
[ "$(probe_field "$PRE_FACTS" server_record)" = 0 ] || refuse "the worker already holds $SERVER_RECORD: a server install would reuse its recorded arguments"
[ "$(probe_field "$PRE_FACTS" bin_ok)" = 1 ] || refuse "$WK3SM on the worker is not a k3sm build set with its required artifacts beside it$(m="$(probe_field "$PRE_FACTS" missing_artifact)"; [ -n "$m" ] && echo " (missing $m)")"
BIN_VERSION="$(printf '%s\n' "$PRE_FACTS" | sed -n 's/^FDB-VERSION //p' | sed 's/ *$//')"
[ "$BIN_VERSION" = "$(printf '%s' "$PRE_WORKER_VERSION" | tr '\n' ' ' | sed 's/ *$//')" ] ||
	refuse "$WK3SM is '$BIN_VERSION' but the worker runs '$(printf '%s' "$PRE_WORKER_VERSION" | tr '\n' ' ')': the rejoin must restore the version the worker runs"
PLIST_SERVER="$(printf '%s\n' "$PRE_FACTS" | sed -n 's/^FDB-PLIST //p' | fjson plist-server 2>/dev/null || true)"
[ "$PLIST_SERVER" = "$SERVER_LAN" ] || refuse "K3SM_OIS_SERVER_LAN is '$SERVER_LAN' but the worker's agent joins '${PLIST_SERVER:-unknown}'"
PRE_KEY_EXISTED="$(probe_field "$PRE_FACTS" server_key)"
PRE_LOG_EXISTED="$(probe_field "$PRE_FACTS" server_log)"
case "$PRE_KEY_EXISTED$PRE_LOG_EXISTED" in 00 | 01 | 10 | 11) ;; *) refuse "the worker's fact script reported no server key or server log state" ;; esac

EVIDENCE="${1:-}"
[ -n "$EVIDENCE" ] || EVIDENCE="$(mktemp -d "${TMPDIR:-/tmp}/fresh-datastore-boot-evidence.XXXXXX")"
mkdir -p "$EVIDENCE"

# ---- the run ----------------------------------------------------------------------------
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/runlog.sh
. "$REPO_ROOT/hack/lab/lib/runlog.sh"
RUN="fdb-$(date -u +%m%d%H%M%S)"
RUNLOG="$EVIDENCE/run.log"
KUBE_BACKUP="\$HOME/.kube/config.$RUN"
emit_run_log_header FAIL >"$RUNLOG"
log() { printf '%s\n' "$*" | tee -a "$RUNLOG"; }
printf '%s\n' "$PRE_FACTS" >"$EVIDENCE/pre-facts.txt"

# STATE is what the trap has to undo: joined (nothing), left (the worker is out of
# the cluster), server (a throwaway server may be installed on it).
STATE=joined
KUBE_SAVED=""

# kube_save / kube_restore: the worker user's ~/.kube/config, which a server
# install merges its admin entry into, is copied aside once and put back after
# every throwaway boot; the copy is removed at the end.
kube_save() {
	# shellcheck disable=SC2016 # expanded by the worker's shell
	KUBE_SAVED="$(on_worker "if [ -e \"\$HOME/.kube/config\" ]; then cp -p \"\$HOME/.kube/config\" \"$KUBE_BACKUP\" && echo 1; else echo 0; fi" 2>/dev/null | tail -1)"
	[ "$KUBE_SAVED" = 1 ] || [ "$KUBE_SAVED" = 0 ]
}
kube_restore() {
	case "$KUBE_SAVED" in
	1) on_worker "cp -p \"$KUBE_BACKUP\" \"\$HOME/.kube/config\"" ;;
	0) on_worker "rm -f \"\$HOME/.kube/config\"" ;;
	*) return 0 ;;
	esac
}
# shellcheck disable=SC2329 # invoked by the EXIT trap
kube_drop() { [ "$KUBE_SAVED" = 1 ] && on_worker "rm -f \"$KUBE_BACKUP\""; KUBE_SAVED=""; return 0; }

# teardown: uninstall the throwaway server and remove what its boot created.
teardown() {
	local out
	out="$(as_root worker "teardown-$1" "$(teardown_script "$WK3SM" "$((1 - PRE_KEY_EXISTED))" "$((1 - PRE_LOG_EXISTED))")" 2>&1)"
	printf '%s\n' "$out" >"$EVIDENCE/teardown-$1.txt"
	kube_restore >>"$EVIDENCE/teardown-$1.txt" 2>&1 || return 1
	[ "$(probe_field "$out" teardown_rc)" = 0 ]
}

# rejoin: the worker joins the cluster again as an agent. Detail in DETAIL.
rejoin() {
	local i token out
	for ((i = 0; i < 40; i++)); do
		on_worker "nc -z -G 3 '$SERVER_LAN' $JOIN_PORT" >/dev/null 2>&1 && break
		sleep 3
	done
	if [ "$i" = 40 ]; then
		DETAIL="the join port $JOIN_PORT on the server's LAN address did not answer within 120s"
		return 1
	fi
	token="$(as_root server token "$(token_script)" 2>/dev/null | tail -1)" || token=""
	if [ -z "$token" ] || [[ "$token" =~ [[:space:]] ]]; then
		DETAIL="the server minted no join token"
		return 1
	fi
	out="$(printf '%s\n' "$token" | as_root worker rejoin "$(rejoin_script "$WK3SM" "$SERVER_LAN" "$WORKER_USER")" 2>&1)" || true
	token=""
	printf '%s\n' "$out" >"$EVIDENCE/rejoin-install.txt"
	if [ "$(probe_field "$out" install_rc)" != 0 ]; then
		DETAIL="install --agent failed (rc $(probe_field "$out" install_rc); $EVIDENCE/rejoin-install.txt)"
		return 1
	fi
	STATE=joined
	local deadline=$((SECONDS + READY_BOUND))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if [ "$(kc get node "$WORKER" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ]; then
			DETAIL="rejoined at $SERVER_LAN:$JOIN_PORT with a fresh 5m token; node $WORKER Ready"
			return 0
		fi
		sleep 5
	done
	DETAIL="node $WORKER not Ready within ${READY_BOUND}s of the rejoin"
	return 1
}

# restore_meta: puts back every recorded non-k3sm label and taint the node lacks.
restore_meta() {
	local line args kind arg
	kc get node "$WORKER" -o json >"$EVIDENCE/node-after-rejoin.json" 2>/dev/null || return 1
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		args="$(meta_args "$line")"
		kind="${args%% *}"
		arg="${args#* }"
		log "    restore $kind $arg"
		kc "$kind" node "$WORKER" "$arg" >>"$EVIDENCE/restore-meta.txt" 2>&1 || return 1
	done < <(fjson missing-meta "$EVIDENCE/pre-node.json" <"$EVIDENCE/node-after-rejoin.json")
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	set +e
	if [ "$STATE" = server ]; then
		teardown trap || echo "cleanup: the throwaway server on the worker did not tear down cleanly ($EVIDENCE/teardown-trap.txt); finish it by hand: sudo k3sm uninstall, then remove $SERVER_DIR and $SERVER_RECORD" >>"$RUNLOG"
		STATE=left
	fi
	if [ "$STATE" = left ]; then
		kube_restore >/dev/null 2>&1
		if rejoin; then
			restore_meta || echo "cleanup: could not restore the worker's labels and taints; compare $EVIDENCE/pre-node.json" >>"$RUNLOG"
			echo "cleanup: the worker rejoined ($DETAIL)" >>"$RUNLOG"
		else
			echo "cleanup: the worker did NOT rejoin ($DETAIL); rejoin it by hand as docs/user/multi-node.md describes" >>"$RUNLOG"
		fi
	fi
	kube_drop >/dev/null 2>&1
	kc get nodes -o wide >"$EVIDENCE/final-nodes.txt" 2>&1
	drop_remote_dirs
}
trap cleanup EXIT

DETAIL=""
LEG=""
# Each leg is three statements: `run_leg <name>; <leg function> || leg_red; leg_pass`.
run_leg() {
	local row desc=""
	LEG="$1"
	DETAIL=""
	for row in "${LEGS[@]}"; do [ "${row%%|*}" = "$LEG" ] && desc="${row#*|}"; done
	log "==> $LEG  $desc"
}
leg_pass() { log "PASS  $LEG  ${DETAIL}"; }
leg_red() {
	log "FAIL  $LEG  ${DETAIL}"
	log "fresh-datastore-boot: RED at leg $LEG (evidence $EVIDENCE)"
	emit_run_log_verdict FAIL >>"$RUNLOG"
	exit 1
}

log "==> k3sm fresh-datastore-boot lab gate: server $SERVER, worker $WORKER, run $RUN, $BOOTS boot(s) on mesh ip $MESH_IP, evidence $EVIDENCE"

# ---- fdb.1 pre ----------------------------------------------------------------------------
PRE_STORAGE=""
leg_pre() {
	kc get node "$WORKER" -o json >"$EVIDENCE/pre-node.json" 2>/dev/null || {
		DETAIL="could not read node $WORKER"
		return 1
	}
	fjson meta <"$EVIDENCE/pre-node.json" >"$EVIDENCE/pre-meta.txt" || {
		DETAIL="could not parse node $WORKER"
		return 1
	}
	printf '%s\n' "$PRE_WORKER_VERSION" >"$EVIDENCE/pre-worker-version.txt"
	PRE_STORAGE="$(printf '%s\n' "$PRE_FACTS" | sed -n 's/^FDB-S //p')"
	printf '%s\n' "$PRE_STORAGE" >"$EVIDENCE/pre-storage.txt"
	DETAIL="$(wc -l <"$EVIDENCE/pre-meta.txt" | tr -d ' ') non-k3sm label/taint(s), $(printf '%s' "$PRE_STORAGE" | grep -c . || true) PV entr(ies), worker version $(printf '%s' "$PRE_WORKER_VERSION" | head -1)"
}
run_leg fdb.1
leg_pre || leg_red
leg_pass

# ---- fdb.2 leave --------------------------------------------------------------------------
leg_leave() {
	local out gone
	kube_save || {
		DETAIL="could not copy the worker user's ~/.kube/config aside"
		return 1
	}
	STATE=left
	out="$(as_root worker leave "$(leave_script "$WK3SM")" 2>&1)" || true
	printf '%s\n' "$out" >"$EVIDENCE/leave.txt"
	if [ "$(probe_field "$out" uninstall_rc)" != 0 ] || [ "$(probe_field "$out" agent_plist)" != 0 ]; then
		DETAIL="the plain uninstall failed or left the agent daemon ($EVIDENCE/leave.txt)"
		return 1
	fi
	if [ "$(probe_field "$out" agent_dir)" != 1 ]; then
		DETAIL="the plain uninstall removed $AGENT_DIR"
		return 1
	fi
	gone="$(missing_lines "$PRE_STORAGE" "$(printf '%s\n' "$out" | sed -n 's/^FDB-S //p')")"
	if [ -n "$gone" ]; then
		DETAIL="PV entries gone after the plain uninstall: $(printf '%s' "$gone" | tr '\n' ' ')"
		return 1
	fi
	DETAIL="agent daemon removed; $AGENT_DIR and every PV entry kept"
}
run_leg fdb.2
leg_leave || leg_red
leg_pass

# ---- fdb.3 fresh first boots ----------------------------------------------------------------
boot_once() {
	local i="$1" out off verdict
	STATE=server
	out="$(as_root worker "boot-$i" "$(boot_script "$WK3SM" "$MESH_IP" "$KC_NAME" "$WORKER_USER")" 2>&1)" || true
	printf '%s\n' "$out" >"$EVIDENCE/boot-$i-install.txt"
	off="$(probe_field "$out" log_offset)"
	if [ "$(probe_field "$out" install_rc)" != 0 ] || [ -z "$off" ]; then
		DETAIL="boot $i/$BOOTS: the server install failed ($(probe_field "$out" error)${off:+, rc $(probe_field "$out" install_rc)}; $EVIDENCE/boot-$i-install.txt)"
		return 1
	fi
	out="$(as_root worker "probe-$i" "$(probe_script "$WK3SM" "$off" "$MESH_IP")" 2>&1)" || true
	printf '%s\n' "$out" >"$EVIDENCE/boot-$i-probe.txt"
	if ! verdict="$(judge_boot "$out" "$MESH_CIDR")"; then
		DETAIL="boot $i/$BOOTS: $verdict ($EVIDENCE/boot-$i-probe.txt)"
		return 1
	fi
	if ! teardown "$i"; then
		DETAIL="boot $i/$BOOTS: the throwaway server did not tear down cleanly ($EVIDENCE/teardown-$i.txt)"
		return 1
	fi
	STATE=left
	log "    boot $i/$BOOTS: $verdict"
}
leg_boots() {
	local i
	for ((i = 1; i <= BOOTS; i++)); do
		boot_once "$i" || return 1
	done
	DETAIL="$BOOTS fresh first boot(s), every one on its own mesh"
}
run_leg fdb.3
leg_boots || leg_red
leg_pass

# ---- fdb.4 rejoin ---------------------------------------------------------------------------
run_leg fdb.4
rejoin || leg_red
leg_pass

# ---- fdb.5 restore labels and taints --------------------------------------------------------
leg_restore() {
	local left
	restore_meta || {
		DETAIL="could not put a recorded label or taint back ($EVIDENCE/restore-meta.txt)"
		return 1
	}
	kc get node "$WORKER" -o json >"$EVIDENCE/node-final.json" 2>/dev/null || {
		DETAIL="could not read node $WORKER"
		return 1
	}
	left="$(fjson missing-meta "$EVIDENCE/pre-node.json" <"$EVIDENCE/node-final.json")"
	if [ -n "$left" ]; then
		DETAIL="still missing: $(printf '%s' "$left" | tr '\t\n' ' ;')"
		return 1
	fi
	DETAIL="every recorded non-k3sm label and taint is on $WORKER"
}
run_leg fdb.5
leg_restore || leg_red
leg_pass

# ---- fdb.6 end state ------------------------------------------------------------------------
leg_end() {
	local wv sv out gone
	wv="$(on_worker 'k3sm version' 2>/dev/null)"
	sv="$(on_server 'k3sm version' 2>/dev/null)"
	printf 'server %s:\n%s\nworker %s:\n%s\n' "$SERVER" "$sv" "$WORKER" "$wv" | tee "$EVIDENCE/final-versions.txt" >>"$RUNLOG"
	if [ "$wv" != "$PRE_WORKER_VERSION" ]; then
		DETAIL="the worker runs '$(printf '%s' "$wv" | head -1)', not '$(printf '%s' "$PRE_WORKER_VERSION" | head -1)'"
		return 1
	fi
	out="$(as_root worker facts-final "$(facts_script "$WK3SM")" 2>&1)" || true
	printf '%s\n' "$out" >"$EVIDENCE/final-facts.txt"
	gone="$(missing_lines "$PRE_STORAGE" "$(printf '%s\n' "$out" | sed -n 's/^FDB-S //p')")"
	if [ -n "$gone" ]; then
		DETAIL="PV entries gone: $(printf '%s' "$gone" | tr '\n' ' ')"
		return 1
	fi
	if [ "$(probe_field "$out" server_dir)" != 0 ] || [ "$(probe_field "$out" server_record)" != 0 ] || [ "$(probe_field "$out" server_plist)" != 0 ]; then
		DETAIL="throwaway server state is left on the worker ($EVIDENCE/final-facts.txt)"
		return 1
	fi
	DETAIL="server $(printf '%s' "$sv" | head -1); worker $(printf '%s' "$wv" | head -1), unchanged; every PV entry present; no throwaway server state left"
}
run_leg fdb.6
leg_end || leg_red
leg_pass

log "fresh-datastore-boot: GREEN ($BOOTS boot(s); evidence $EVIDENCE)"
emit_run_log_verdict PASS >>"$RUNLOG"
exit 0
