#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The managed-updates tracer: a two-Mac cluster rolled from a stable release to release
# candidates and on to the final, from a test release index, through `k3sm` and
# `kubectl` only. Every build is ad-hoc signed and nothing is published: the index
# serves from the server's loopback, and an SSH forward puts it on the worker's own
# loopback, so both nodes install with --update-release-base http://127.0.0.1:<port>/...,
# which ParseReleaseBase allows and which needs no certificate.
#
# The clean start. A leftover /var/lib/k3sm/updates once hid a defect: a directory an
# earlier build had made kept a roll green while a fresh install could not update. So
# this gate stops each Mac with `sudo k3sm stop` (which also stops k3sm-netd, the other
# thing that makes the directory), removes the directory, asserts it is gone, installs,
# and asserts the install made it: owner _k3sm, mode 0700, born after the removal on that
# Mac's own clock. The rest of the data root stays, so the operator's workloads survive.
#
# Legs, in order (a roll that does not end as its leg needs stops the run; every leg not
# reached is a failure, and the rig is still put back):
#   c.0  each Mac is stopped and its updates directory removed and absent
#   c.1  install recreated it: _k3sm, 0700, born after the removal
#   c.2  both Macs run the stable build, with no pin, Update or UpdatePolicy left
#   f.1  the worker's loopback reaches the index only once the SSH forward is up
#   p.1  the real apiserver refuses an UpdatePolicy with another name
#   p.2  the real apiserver refuses another channel value (a good object passes dry-run)
#   s.1  on stable, with a candidate published: no candidate offered
#   r.1  `k3sm update channel rc` offers rc.1 and starts no roll
#   r.2  the worker's status row names rc and rc.1
#   a.1  apply to rc.1: worker before server, and the worker's archive came through the
#        forward (fetched while the server was still Pending)
#   a.2  the roll to rc.1 succeeds, both nodes on it, nothing cordoned
#   b.1  on the roll to rc.2 the worker is bounced mid-download and fetches again
#   b.2  the server is restarted mid-roll and its controller carries on
#   b.3  the roll to rc.2 succeeds, nothing cordoned, a Pod runs on each Mac
#   l.1  leaving rc on rc.2: every node ahead, no offer
#   l.2  a lower release without --allow-downgrade is refused with no node touched
#   d.1  --allow-downgrade goes back to the stable release, the documented way off
#   m.1  setting the channel mid-roll leaves the roll's target alone
#   m.2  that roll still ends on its target, and only the offer moved
#   z.1  once the final is published rc offers it, and rc.2 rolls to it
#   w.1  a candidate withdrawn mid-roll, then cancel: the listing falls back, the worker
#        finishes, the Update ends Cancelled, the cluster stays mixed
#   w.2  a candidate withdrawn with no cancel: the server fails at download and the roll
#        stops; cancel has nothing to cancel, and abort clears the cordon and annotations
#   w.3  a candidate withdrawn before the first node's GET is answered: that node fails on
#        the 404, the server is never started, no node moves, abort clears
#   e.1  the namespace, the Update and the UpdatePolicy are gone
#   e.2  both Macs are back on this tree's build, Ready, with the test index forgotten
#   e.3  no label or taint another workload owns was lost (reported, never repaired)
#
# `install --update-release-base` keeps the recorded value when given none, so nothing
# can clear it short of an uninstall. The way back from the test index is to record
# GitHub's own URL, which is the default's value and means the same thing.
#
# The archive holds only what k3sm-netd unpacks. `publish.sh` adds PAYLOAD-SHA256 to a
# release's tarball, and darwin-net's extractUpdateArchive refuses a member outside its
# set, so K3SM_B1240_KEEP_MANIFEST=1 packs publish.sh's shape, to see what a published
# release does on this path.
#
# Records that predate the run. `k3sm update apply` replaces a finished Update named
# current, and the run sets the channel, so neither an Update nor an UpdatePolicy already
# there can survive it. Saving one and putting it back is no answer: an Update created
# again has no status, so the controller would take it for a new roll. So the run refuses
# them (exit 2, the rig untouched) and the operator decides; what it deletes at the end is
# only what it created.
#
# When a withdrawal happens. Node phase Downloading does not say a GET has been made: the
# controller writes it at the handover, before the node has read it. So w.1 and w.2
# withdraw once the index has logged the worker's 200, which is when its file is open, and
# w.3 holds the worker's GET at the index, withdraws, then lets the GET be answered.
#
# Run it detached: it takes over an hour. One poll or remote step is bounded, and the
# legs poll until their own budgets end. It takes the rig for the run; one rig run at a
# time.
#
# kubectl is `sudo k3sm kubectl` on the server, so the admin token an install rotates
# never strands the run.
#
# Environment. Required:
#   K3SM_B1240_SERVER_SSH     ssh name of the server, or `local` when this runs on it
#   K3SM_B1240_WORKER_SSH     ssh name of the worker, or `local`
#   K3SM_B1240_SERVER_LAN     the server's LAN address, which the worker joins
#   K3SM_B1240_SERVER_WORK    empty or absent absolute directory on the server (scratch)
#   K3SM_B1240_WORKER_WORK    empty or absent absolute directory on the worker (scratch);
#                             the join token sits in its private/ during an install, so
#                             neither work directory may be inside the evidence directory
#   K3SM_B1240_SETS           directory for the built sets on this Mac; a set found
#                             complete there is reused, so a re-run skips the builds
# Optional:
#   K3SM_B1240_WORKER_FROM_SERVER  how the server's ssh names the worker (default: the
#                             worker's ssh name); the forward is opened from the server
#   K3SM_B1240_PORT           the index port on both loopbacks (default 47240)
#   K3SM_B1240_USER           --user for install (default: the remote account)
#   K3SM_B1240_CONTEXT        the admin context to copy to the worker (default k3sm)
#   K3SM_B1240_MIN_FREE_GB_SERVER / _WORKER  free disk demanded first (default 16 / 8)
#   K3SM_B1240_STEP_TIMEOUT   seconds for one remote step (default 120, at most 240)
#   K3SM_B1240_READY_TIMEOUT  seconds a node gets to come Ready (default 240, at most 240)
#   K3SM_B1240_THROTTLE       seconds one held download takes (default 150, at most 240)
#   K3SM_B1240_INSTALL_TIMEOUT seconds for one install (default 900)
#   K3SM_B1240_ROLL_TIMEOUT   seconds for one roll to end (default 1800)
#   K3SM_B1240_POLL           seconds between polls (default 2)
#   K3SM_B1240_KEEP_MANIFEST  1 packs publish.sh's archive shape (see above)
#   K3SM_B1240_SKIP_TREE_CHECK  --self-test only: its fake run has no sets to build
#   K3SM_CP_CACHE             stage.sh's control-plane build cache: name a kept one, or
#                             the first build compiles Kubernetes
#   K3SM_LAB_TOLERATE_KEYS    extra taint keys every pod tolerates with Exists
#
# Exit: 0 every leg held and the rig is back; 1 a leg failed (the run log names it) and
# the rig was still put back; 2 the run did not happen: K3SM_LAB unset (SKIP, never a
# pass), a bad argument, or a refused precondition, with the rig untouched.
#
# Usage:  hack/acceptance/B1240.sh --plan        # the legs; contacts nothing
#         hack/acceptance/B1240.sh --self-test   # offline, over fakes and a loopback index
#         K3SM_LAB=1 hack/acceptance/B1240.sh <evidence-dir>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B1240.sh"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh disable=SC1091
. "$REPO_ROOT/hack/lab/lib/tolerations.sh"

GATE_NAME="B1240"
# shellcheck disable=SC2034  # read by the sourced runlog.sh
MODE="full"
NS="b1240-tracer"

# The tags. The line sits above every real release, so no test tag can be taken for one
# and every step along it is the ordering the leg means.
TAG_BASE="v0.90.0"
TAG_RC1="v0.91.0-rc.1"
TAG_RC2="v0.91.0-rc.2"
TAG_FINAL="v0.91.0"
TAG_W1="v0.92.0-rc.1"
TAG_W2="v0.92.0-rc.2"
TAG_W3="v0.92.0-rc.3"
ALL_TAGS="$TAG_BASE $TAG_RC1 $TAG_RC2 $TAG_FINAL $TAG_W1 $TAG_W2 $TAG_W3"
INDEX_PATH="/k3sm/releases"
GITHUB_BASE="https://github.com/k3sm-io/k3sm/releases"

# What the root helper unpacks (darwin-net pkg/netd/extract.go updateSetFiles, then the
# cp-payload tree). --self-test compares this with that file when the sibling is there.
ARCHIVE_SET="k3sm k3sm-execshim k3sm-vmhost libk3sm_getaddrinfo_shim.dylib libk3sm_pathrebase_shim.dylib"

STEP_TIMEOUT="${K3SM_B1240_STEP_TIMEOUT:-120}"
READY_TIMEOUT="${K3SM_B1240_READY_TIMEOUT:-240}"
THROTTLE="${K3SM_B1240_THROTTLE:-150}"
INSTALL_TIMEOUT="${K3SM_B1240_INSTALL_TIMEOUT:-900}"
ROLL_TIMEOUT="${K3SM_B1240_ROLL_TIMEOUT:-1800}"
POLL="${K3SM_B1240_POLL:-2}"
PORT="${K3SM_B1240_PORT:-47240}"
# These exist so --self-test can run over fakes; a real run leaves them alone.
K3SM_BIN="${K3SM_B1240_K3SM:-/Library/k3sm/k3sm}"
DATA_ROOT="${K3SM_B1240_DATA_ROOT:-/var/lib/k3sm}"
SERVICE_USER="${K3SM_B1240_SERVICE_USER:-_k3sm}"
PLIST_DIR="${K3SM_B1240_PLIST_DIR:-/Library/LaunchDaemons}"

# The leg table: `name|statement`. --plan prints it; a run reports every name.
LEGS=(
	"c.0|each Mac stopped, its updates directory removed and absent"
	"c.1|install recreated it: the service user, 0700, born after the removal"
	"c.2|both Macs run the stable build; no pin, Update or UpdatePolicy left"
	"f.1|the worker's loopback reaches the index only through the SSH forward"
	"p.1|the real apiserver refuses an UpdatePolicy with another name"
	"p.2|the real apiserver refuses another channel value; a good object passes"
	"s.1|on stable, with a candidate published, no candidate is offered"
	"r.1|setting rc offers rc.1 and starts no roll"
	"r.2|the worker's status row names rc and rc.1"
	"a.1|apply to rc.1: worker first, its archive fetched through the forward"
	"a.2|the roll to rc.1 succeeds, both nodes on it, nothing cordoned"
	"b.1|a worker bounced mid-download fetches again and the roll holds"
	"b.2|a server restarted mid-roll: the controller carries on"
	"b.3|the roll to rc.2 succeeds, nothing cordoned, a Pod runs on each Mac"
	"l.1|leaving rc on rc.2: every node ahead, no offer"
	"l.2|a lower release without --allow-downgrade is refused, no node touched"
	"d.1|--allow-downgrade goes back to the stable release"
	"m.1|setting the channel mid-roll leaves the roll's target alone"
	"m.2|that roll ends on its target; only the offer moved"
	"z.1|the final published: rc offers it, and rc.2 rolls to it"
	"w.1|a candidate withdrawn mid-roll, then cancel: mixed, Cancelled, nothing cordoned"
	"w.2|withdrawn with no cancel: the server fails at download, the roll stops, abort clears"
	"w.3|withdrawn before the first node's GET: it fails on the 404, the roll stops, abort clears"
	"e.1|the namespace, the Update and the UpdatePolicy are gone"
	"e.2|both Macs on this tree's build, Ready, the test index forgotten"
	"e.3|no label or taint another workload owns was lost"
)

# ---- pure helpers (the --self-test surface) ---------------------------------------------

# tag_ver <tag>: the version as a stamp and an asset name carry it.
tag_ver() { printf '%s' "${1#v}"; }
archive_name() { printf 'k3sm_%s_darwin_arm64.tar.gz' "$(tag_ver "$1")"; }
checksums_name() { printf 'k3sm_%s_checksums.txt' "$(tag_ver "$1")"; }
# node_version_is <kubelet-version> <tag>: whether a Node reports this release.
node_version_is() { case "$1" in *"+k3sm.$(tag_ver "$2")") return 0 ;; *) return 1 ;; esac; }

# J <python-expression>: one answer about the JSON on stdin. The expression is always a
# literal of this script; the JSON is only ever data.
J() {
	python3 -I -c '
import json, sys
d = json.load(sys.stdin)
def named(key, n):
    return next((r for r in (d.get(key) or []) if r.get("name") == n), {})
def row(n):
    return named("rows", n)
def node(n):
    return named("nodes", n)
def foreign(item):
    keep = lambda k: not k.startswith("k3sm.io/") and "kubernetes.io" not in k
    labels = sorted(k + "=" + v for k, v in (item["metadata"].get("labels") or {}).items() if keep(k))
    taints = sorted(t["key"] + ":" + t.get("effect", "") for t in (item["spec"].get("taints") or []) if keep(t["key"]))
    return " ".join(labels + taints)
print(eval(sys.argv[1]))
' "$1"
}

# untolerated_keys <taint-lines>: the NoSchedule/NoExecute taint keys (lines of
# key:Effect) the provider entry and K3SM_LAB_TOLERATE_KEYS leave untolerated. A node
# cordoned by `k3sm stop` is never read here: this runs before the stop.
untolerated_keys() {
	local lines="$1" t key effect keys out=""
	keys=" $(lab_tol_keys) " || exit 2
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		key="${t%:*}"
		effect="${t##*:}"
		[ "$effect" = PreferNoSchedule ] && continue
		[ "$key" = k3sm.io/provider ] && continue
		case "$keys" in *" $key "*) continue ;; esac
		out="${out:+$out }$key"
	done <<<"$lines"
	printf '%s' "$out"
}

# probe_pod <ns> <name> <node> <tolerations>: a native Pod that runs one script from the
# ConfigMap and ends.
probe_pod() {
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $2, namespace: $1}
spec:
  nodeName: $3
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$4]
  restartPolicy: Never
  containers:
  - name: probe
    image: native
    command: ["/bin/sh", "/scripts/probe.sh"]
    volumeMounts:
    - {name: scripts, mountPath: /scripts}
  volumes:
  - name: scripts
    configMap: {name: b1240-scripts}
EOF
}

# scripts_configmap <ns>
scripts_configmap() {
	cat <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: b1240-scripts, namespace: $1}
data:
  probe.sh: |
    #!/bin/sh
    echo "B1240 probe ran"
EOF
}

# policy_object <name> <channel>
policy_object() {
	cat <<EOF
apiVersion: updates.k3sm.io/v1alpha1
kind: UpdatePolicy
metadata: {name: $1}
spec: {channel: $2}
EOF
}

# index_py: the test release index, in GitHub's layout under one base path. It serves
# what sits in <root>/published/<tag>/, so publishing and withdrawing a release are one
# rename, and a download in flight keeps its open file across a withdrawal: the 200 is
# logged only once the file is open. <root>/throttle holds how many seconds one archive
# should take, read again as it streams, so a leg can hold a node in Downloading and then
# let it go. While <root>/gate exists an archive GET is logged as 102 and waits, and is
# answered from what is published when the gate goes. It binds loopback only.
index_py() {
	cat <<'PY'
import http.server, json, os, re, socketserver, sys, time, urllib.parse
root, port, base = sys.argv[1], int(sys.argv[2]), sys.argv[3]
TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.(0|[1-9][0-9]*))?$")
FILE = re.compile(r"^k3sm_[0-9A-Za-z.-]+(_darwin_arm64\.tar\.gz|_checksums\.txt)$")
LOG = os.path.join(root, "access.log")
def tags():
    d = os.path.join(root, "published")
    return [t for t in os.listdir(d) if TAG.match(t)]
def order(tag):
    m = TAG.match(tag)
    rc = int(m.group(5)) if m.group(5) is not None else None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 1 if rc is None else 0, rc or 0)
def entry(tag):
    at = os.stat(os.path.join(root, "published", tag)).st_mtime
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))
    return {"tag_name": tag, "draft": False, "prerelease": "-rc." in tag, "published_at": stamp, "body": ""}
def throttle():
    try:
        with open(os.path.join(root, "throttle")) as f:
            return float(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0.0
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def note(self, code):
        with open(LOG, "a") as f:
            f.write("%d %s %s %d %s\n" % (time.time(), self.command, self.path, code, self.headers.get("User-Agent", "-").replace(" ", "_")))
    def reply(self, code, body=b"", ctype="text/plain", headers=()):
        self.note(code)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
    def send_json(self, v):
        self.reply(200, json.dumps(v).encode(), "application/json")
    def download(self, tag, name):
        path = os.path.join(root, "published", tag, name)
        if not (TAG.match(tag) and FILE.match(name)):
            return self.reply(404, b"not found")
        gate = os.path.join(root, "gate")
        if name.endswith(".tar.gz") and os.path.exists(gate):
            self.note(102)
            while os.path.exists(gate):
                time.sleep(0.2)
        try:
            f = open(path, "rb")
        except OSError:
            return self.reply(404, b"not found")
        with f:
            self.note(200)
            size = os.fstat(f.fileno()).st_size
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            if self.command == "HEAD":
                return
            sent = 0
            while sent < size:
                block = f.read(1 << 20)
                if not block:
                    return
                self.wfile.write(block)
                sent += len(block)
                hold = throttle()
                if hold > 0 and name.endswith(".tar.gz"):
                    time.sleep(min(2.0, hold * len(block) / max(size, 1)))
    def do_HEAD(self):
        self.do_GET()
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path != base and not u.path.startswith(base + "/"):
            return self.reply(404, b"not found")
        rest = u.path[len(base):].strip("/")
        parts = rest.split("/") if rest else []
        if not parts:
            return self.send_json([entry(t) for t in sorted(tags(), key=order, reverse=True)])
        if parts == ["latest"]:
            finals = [t for t in tags() if "-rc." not in t]
            where = base + "/tag/" + max(finals, key=order) if finals else base
            return self.reply(302, headers=[("Location", where)])
        if len(parts) == 2 and parts[0] == "tag":
            return self.reply(200 if parts[1] in tags() else 404)
        if len(parts) == 2 and parts[0] == "tags":
            if parts[1] in tags():
                return self.send_json(entry(parts[1]))
            return self.reply(404, b"not found")
        if len(parts) == 3 and parts[0] == "download":
            return self.download(parts[1], parts[2])
        return self.reply(404, b"not found")
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
S(("127.0.0.1", port), H).serve_forever()
PY
}

# ---- remote steps -------------------------------------------------------------------------

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)

# bounded <seconds> <cmd...>: run cmd, killing it after the budget. macOS ships no
# timeout(1). The explicit <&0 keeps stdin, which a background job otherwise loses.
bounded() {
	local secs="$1" pid watchdog rc=0
	shift
	"$@" <&0 &
	pid=$!
	(
		sleep "$secs"
		kill "$pid" 2>/dev/null
	) >/dev/null 2>&1 &
	watchdog=$!
	wait "$pid" || rc=$?
	kill "$watchdog" 2>/dev/null || true
	wait "$watchdog" 2>/dev/null || true
	return "$rc"
}

# quoted <args...>: one shell word per argument.
quoted() { printf '%q ' "$@"; }

# rsh_raw <host> <shell-text>: shell text on the host, ssh's or local.
rsh_raw() {
	if [ "$1" = local ]; then
		/bin/bash -c "$2"
	else
		# shellcheck disable=SC2029 # the text is built to expand on this side, quoted
		ssh "${SSH_OPTS[@]}" "$1" "$2"
	fi
}
# rsh <host> <args...>: one command on the host, bounded by STEP_TIMEOUT.
rsh() {
	local h="$1"
	shift
	bounded "$STEP_TIMEOUT" rsh_raw "$h" "$(quoted "$@")"
}
# put <host> <local-file> <remote-path>
put() {
	if [ "$1" = local ]; then
		cp "$2" "$3"
	else
		scp -q "${SSH_OPTS[@]}" "$2" "$1:$3"
	fi
}
# root_run <host> <work-dir> <name> <bound>: the script on stdin (fd 3 for the root step's
# own stdin, when given), as a file under sudo: `ssh host "sudo a && b"` runs only a as root.
root_run() {
	local h="$1" work="$2" name="$3" bound="$4" f
	f="$EVIDENCE/scripts/$name.sh"
	{
		echo '#!/bin/bash'
		cat
	} >"$f"
	put "$h" "$f" "$work/$name.sh"
	bounded "$bound" rsh_raw "$h" "$(quoted sudo /bin/bash "$work/$name.sh")" <&3
}

# k <args...>: k3sm on the server under sudo, so the server's admin credentials.
k() { rsh "$SERVER" sudo "$K3SM_BIN" "$@"; }
# kc <args...>: kubectl through it.
kc() { k kubectl "$@"; }
# kw <args...>: k3sm on the worker under sudo.
kw() { rsh "$WORKER" sudo "$K3SM_BIN" "$@"; }

# ---- the plan ------------------------------------------------------------------------------

plan() {
	local row
	echo "B1240 managed-updates tracer: what a K3SM_LAB=1 run does, in order."
	echo "tags: stable $TAG_BASE; candidates $TAG_RC1, $TAG_RC2; final $TAG_FINAL; withdrawn $TAG_W1, $TAG_W2, $TAG_W3"
	echo "index: http://127.0.0.1:$PORT$INDEX_PATH on the server, forwarded to the worker's loopback"
	echo "clean start: sudo k3sm stop on each Mac, remove <data root>/updates, assert absent, install, assert recreated"
	for row in "${LEGS[@]}"; do
		printf '  %-5s %s\n' "${row%%|*}" "${row#*|}"
	done
}

# ---- the fakes (--self-test) ---------------------------------------------------------------

# fake_k3sm: a cluster in one JSON file. `update status` advances a roll one step per read;
# the release list is read from the real test index, so the index is held to a reader.
fake_k3sm() {
	cat <<'FAKE'
#!/usr/bin/env python3
import json, os, re, shlex, subprocess, sys, urllib.request, urllib.error
st_dir, brk, host = os.environ["FAKE_STATE"], os.environ.get("FAKE_BREAK", ""), os.environ.get("FAKE_HOST", "srv")
argv, path = sys.argv[1:], os.path.join(os.environ["FAKE_STATE"], "cluster.json")
NODES = {"srv": "node-s", "wrk": "node-w"}
SRV, WRK = NODES["srv"], NODES["wrk"]
def load():
    if os.path.exists(path):
        return json.load(open(path))
    fresh = {"ver": {SRV: "main", WRK: "main"}, "cord": {SRV: False, WRK: False}, "base": {}, "channel": None,
             "update": None, "stopped": {}, "ann": {}, "pods": {}, "ns": [], "pub": None, "dl": 0}
    if brk == "old-update":
        fresh["update"] = {"phase": "Succeeded", "version": "v0.2.3", "nodes": [], "finished": True, "cancel": False}
    if brk == "old-policy":
        fresh["channel"] = "stable"
    return fresh
s = load()
def save():
    json.dump(s, open(path, "w"))
def out(v):
    print(json.dumps(v))
def log(line):
    with open(os.path.join(st_dir, "calls.log"), "a") as f:
        f.write(line + "\n")
log(host + " " + " ".join(argv))
def kver(n):
    return "v1.37.1+k3sm." + s["ver"][n]
def parts(t):
    m = re.match(r"^v(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?$", t)
    return (int(m[1]), int(m[2]), int(m[3]), 1 if m[4] is None else 0, int(m[4] or 0))
def ver_parts(v):
    return parts("v" + v) if re.match(r"^\d", v) and "main" not in v else (0, 0, 0, 0, 0)
def latest(ch):
    b = s["base"].get(SRV, "")
    if ch == "rc":
        lst = json.load(urllib.request.urlopen(b + "?per_page=100"))
        tags = [e["tag_name"] for e in lst]
        if brk == "no-fallback" and s.get("w1seen"):
            return "v0.92.0-rc.1"
        if "v0.92.0-rc.1" in tags:
            s["w1seen"] = True
        return max(tags, key=parts)
    r = urllib.request.urlopen(urllib.request.Request(b + "/latest", method="HEAD"))
    t = r.geturl().rsplit("/", 1)[-1]
    if brk == "stable-rc":
        return max([e["tag_name"] for e in json.load(urllib.request.urlopen(b))], key=parts)
    return t
def state(n, tag):
    a, b = ver_parts(s["ver"][n]), parts(tag)
    return "current" if a == b else ("behind" if a < b else "ahead")
def check():
    ch = s["channel"] or "stable"
    tag = latest(ch)
    s["pub"] = {"channel": ch, "latest": tag}
    return {"channel": ch, "latest": {"tag": tag}, "nodes": [{"name": n, "version": kver(n), "state": state(n, tag)} for n in (SRV, WRK)]}
def view():
    u = s["update"]
    if u is None:
        return {"phase": "", "version": "", "resolved": None, "nodes": [], "conditions": []}
    return {k: u[k] for k in ("phase", "version", "nodes", "finished")} | {"name": "current", "resolved": None, "conditions": [], "cancel": u["cancel"]}
def fetch(n, tag):
    v = tag[1:]
    b = s["base"].get(n)
    try:
        urllib.request.urlopen(b + "/download/" + tag + "/k3sm_" + v + "_darwin_arm64.tar.gz", timeout=10).read(1)
        return True
    except urllib.error.HTTPError:
        return False
# The withdrawal legs' tags move as a real node does: Downloading comes first, and the GET
# reaches the index a moment later, from another process. A withdrawal timed on the phase
# alone turns that GET into a 404. (a.1 and b.1 still read the count at Downloading.)
def async_fetch(tag):
    return tag.startswith("v0.92.")
def fetch_file(n, tag):
    return os.path.join(st_dir, "fetch-%s-%s" % (n, tag))
def fetch_later(n, tag):
    url = s["base"].get(n) + "/download/" + tag + "/k3sm_" + tag[1:] + "_darwin_arm64.tar.gz"
    sh = 'sleep 0.5; /usr/bin/curl -s -o /dev/null --max-time 20 -w "%{http_code}" "$1" >"$2.tmp"; mv "$2.tmp" "$2"'
    subprocess.Popen(["/bin/sh", "-c", sh, "sh", url, fetch_file(n, tag)], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
def tick():
    u = s["update"]
    if u is None or u["finished"]:
        return
    if u.get("refused"):
        u.update(phase="Failed", finished=True)
        for n in u["nodes"]:
            n["phase"] = "Pending"
        return
    for row in u["nodes"]:
        name = row["name"]
        if row["phase"] in ("Done", "Skipped"):
            continue
        if row["phase"] == "Failed":
            return
        if row["phase"] == "Pending":
            if u["cancel"]:
                u.update(phase="Cancelled", finished=True)
                return
            s["cord"][name] = True
            row["phase"] = "Downloading"
            if async_fetch(u["version"]):
                row["held"] = 0
                if not (brk == "no-get" and u["version"] == "v0.92.0-rc.1"):
                    fetch_later(name, u["version"])
                return
            if not fetch(name, u["version"]):
                row.update(phase="Failed", message="fetch the archive: http 404 Not Found")
                u.update(phase="Failed", finished=True)
                return
            row["held"] = 0
            return
        if row["phase"] == "Downloading":
            if async_fetch(u["version"]):
                if not os.path.exists(fetch_file(name, u["version"])):
                    return
                if open(fetch_file(name, u["version"])).read() != "200":
                    row.update(phase="Failed", message="fetch the archive: http 404 Not Found")
                    u.update(phase="Failed", finished=True)
                    if brk == "past-failure":
                        s["cord"][SRV] = True
                        u["nodes"][-1]["phase"] = "Downloading"
                    return
            row["held"] += 1
            if row["held"] < 4 or (brk == "no-resume" and s.get("bounced")):
                return
            s["ver"][name] = u["version"][1:]
            if brk != "stays-cordoned":
                s["cord"][name] = False
            row["phase"] = "Done"
            return
    u.update(phase="Succeeded", finished=True)
if argv[:1] == ["version"]:
    print("k3sm", s["ver"][NODES[host]])
elif argv[:1] == ["stop"]:
    s["stopped"][host] = True
elif argv[:1] == ["restart"]:
    u = s["update"]
    if host == "wrk" and u and not u["finished"]:
        s["bounced"] = True
        for row in u["nodes"]:
            if row["name"] == WRK and row["phase"] == "Downloading" and brk != "no-resume":
                fetch(WRK, u["version"])
                row["held"] = 0
    if host == "srv" and brk == "server-restart-fails":
        sys.exit(1)
elif argv[:1] == ["token"]:
    if os.path.exists(os.path.join(os.environ["K3SM_B1240_WORKER_WORK"], "private", "join-token")):
        open(os.path.join(st_dir, "token-left"), "w").close()
    print("fake-token")
elif argv[:1] == ["install"]:
    ver = open(os.path.join(os.environ["FAKE_SET_DIR"], "fake-version")).read().strip()
    node = NODES[host]
    if "--agent" in argv and not ("--server" in argv and "--token-file" in argv):
        sys.exit("install --agent needs --server and --token-file")
    if "--agent" in argv:
        tf = argv[argv.index("--token-file") + 1]
        if os.path.dirname(tf) != os.path.join(os.environ["K3SM_B1240_WORKER_WORK"], "private"):
            sys.exit("the token file is outside the private directory: " + tf)
        if os.stat(tf).st_mode & 0o777 != 0o600 or os.stat(os.path.dirname(tf)).st_mode & 0o777 != 0o700:
            sys.exit("the token file is not 0600 in a 0700 directory")
        if open(tf).read().strip() != "fake-token":
            sys.exit("the token file does not hold the token")
        if brk == "worker-install-fails" and ver != "main":
            sys.exit("the install failed")
    for a in argv:
        if a.startswith("--update-release-base="):
            s["base"][node] = a.split("=", 1)[1]
    if "--update-release-base" in argv:
        s["base"][node] = argv[argv.index("--update-release-base") + 1]
    if not (brk == "base-left" and ver == "main"):
        with open(os.path.join(os.environ["K3SM_B1240_PLIST_DIR"], "io.k3sm.%s.plist" % ("agent" if host == "wrk" else "server")), "w") as f:
            f.write(s["base"].get(node, ""))
    s["ver"][node], s["stopped"][host] = ver, False
    s["cord"][node] = False
    s["installs"] = s.get("installs", 0) + 1
    root = os.environ["K3SM_B1240_DATA_ROOT"]
    if brk != "no-updates-row":
        os.makedirs(os.path.join(root, "updates"), mode=0o700, exist_ok=True)
elif argv[:1] == ["status"]:
    pub = s["pub"] or {}
    wide = {"channel": pub.get("channel", ""), "latest": pub.get("latest", "")}
    if brk == "worker-row" and host == "wrk":
        wide = {"channel": "stable", "latest": "v0.90.0"}
    tag = pub.get("latest")
    states = [state(n, tag) for n in (SRV, WRK)] if tag else []
    word = "behind" if "behind" in states else ("ahead" if "ahead" in states else "ok")
    out({"rows": [{"name": "update", "state": word, "detail": "fake", "wide": wide}]})
elif argv[:2] == ["update", "channel"]:
    if len(argv) == 2:
        print(s["channel"] or "stable")
    else:
        s["channel"] = argv[2]
        if brk == "roll-on-set" and argv[2] == "rc":
            s["update"] = {"phase": "Rolling", "version": "v0.91.0-rc.1", "nodes": [], "finished": False, "cancel": False}
        print("The update channel is now", argv[2])
        check()
elif argv[:2] == ["update", "check"]:
    out(check())
elif argv[:2] == ["update", "apply"]:
    if "--clear-pin" in argv:
        print("There is no release pin.")
    else:
        tag = argv[argv.index("--version") + 1] if "--version" in argv else latest(s["channel"] or "stable")
        order = [WRK, SRV] if brk != "server-first" else [SRV, WRK]
        low = any(parts(tag) < ver_parts(s["ver"][n]) for n in order)
        refused = low and "--allow-downgrade" not in argv and brk != "no-refuse"
        s["update"] = {"phase": "Pending", "version": tag, "finished": False, "cancel": False, "refused": refused,
                       "nodes": [{"name": n, "from": s["ver"][n], "to": tag, "phase": "Pending", "message": "older" if refused else ""} for n in order]}
        print("Created the Update current to", tag)
elif argv[:2] == ["update", "status"]:
    tick()
    if brk == "mid-channel" and s["update"] and s["channel"] == "stable" and not s["update"]["finished"] and s["update"]["version"] == "v0.91.0-rc.2":
        s["update"]["version"] = "v0.90.0"
    out(view())
elif argv[:2] == ["update", "cancel"]:
    u = s["update"]
    if u and u["finished"]:
        print("The Update current to", u["version"], "is already", u["phase"] + "; there is nothing to cancel.")
    elif u and brk != "cancel-ignored":
        u["cancel"] = True
        print("Cancel requested")
elif argv[:2] == ["update", "abort"]:
    if s["update"]:
        s["update"]["finished"] = True
    if brk != "abort-keeps-cordon":
        s["cord"] = {SRV: False, WRK: False}
    s["ann"] = {}
elif argv[:1] == ["kubectl"]:
    a = argv[1:]
    if a[:1] == ["config"]:
        print("apiVersion: v1\nkind: Config\n")
    elif a[:1] == ["get"] and a[1:2] == ["--raw"]:
        print("ok")
    elif a[:2] == ["get", "nodes"]:
        def item(n):
            lab = {"kubernetes.io/os": "darwin", "example.com/mine": "1"}
            if n == SRV:
                lab["node-role.kubernetes.io/control-plane"] = "true"
            if brk == "label-lost" and n == WRK and s.get("installs", 0) >= 4:
                del lab["example.com/mine"]
            return {"metadata": {"name": n, "labels": lab, "annotations": {}},
                    "spec": {"unschedulable": s["cord"][n], "taints": [{"key": "k3sm.io/provider", "effect": "NoSchedule"}]},
                    "status": {"nodeInfo": {"kubeletVersion": kver(n)}, "conditions": [{"type": "Ready", "status": "True"}]}}
        out({"items": [item(SRV), item(WRK)]})
    elif a[:1] == ["apply"] or a[:1] == ["create"]:
        body = sys.stdin.read() if "-" in a else ""
        if "kind: UpdatePolicy" in body:
            if "name: cluster" not in body and brk != "cel-name":
                sys.exit("the UpdatePolicy must be named cluster")
            if "channel: beta" in body and brk != "cel-value":
                sys.exit('Unsupported value: "beta"')
        for m in re.finditer(r"metadata: \{name: ([^,}]+)", body):
            if "kind: Pod" in body:
                s["pods"][m[1]] = "Succeeded" if brk != "pod-fails" else "Failed"
    elif a[:2] == ["create", "namespace"]:
        pass
    elif a[:1] == ["get"] and a[1] == "pod":
        ph = s["pods"].get(a[2])
        if ph is None:
            sys.exit("not found")
        out({"metadata": {"uid": "u"}, "status": {"phase": ph}})
    elif a[:1] == ["logs"]:
        print("B1240 probe ran")
    elif a[:1] == ["get"] and a[1:2] == ["ns"]:
        print("default")
    elif a[:1] == ["get"] and a[1:2] == ["namespace"]:
        if a[2] not in s["ns"] and not (brk == "leftover" and s.get("deleted_ns")):
            sys.exit("not found")
    elif a[:1] == ["delete"]:
        if a[1] == "namespace":
            s["deleted_ns"] = True
            s["ns"] = [x for x in s["ns"] if x != a[2]]
        if a[1].startswith("pod"):
            s["pods"].pop(a[2], None)
        if a[1].startswith("updatepolic"):
            s["channel"] = None
        if a[1].startswith("updates"):
            s["update"] = None
    elif a[:1] == ["get"]:
        if "updatepolic" in a[1] and s["channel"]:
            print("cluster")
        if "updates.updates" in a[1] and s["update"]:
            print("current")
if a_ns := (argv[1:3] == ["create", "namespace"] and argv[3]):
    s["ns"].append(a_ns)
save()
FAKE
}

# fake_ssh: runs a remote command here, naming the host, and fakes the forward by holding.
fake_ssh() {
	cat <<'FAKE'
#!/bin/bash
while [ $# -gt 0 ]; do
	case "$1" in
	-o) shift 2 ;;
	-N) NOCMD=1; shift ;;
	-R) shift 2 ;;
	-*) shift ;;
	*) break ;;
	esac
done
host="$1"
shift
if [ -n "${NOCMD:-}" ]; then
	[ "${FAKE_BREAK:-}" = forward-dead ] && exit 1
	: >"$FAKE_STATE/forward-up"
	exec sleep 600
fi
FAKE_HOST="$host" exec /bin/bash -c "$*"
FAKE
}

self_test() {
	local bad=0 tmp t pyd out code row brk want m tol port pid dir sum f u v name
	check() {
		if [ "$1" = ok ]; then echo "ok   $2"; else
			echo "FAIL $2"
			bad=1
		fi
	}
	echo "==> B1240 self-test"
	check "$([ "$(tag_ver v0.91.0-rc.1)" = 0.91.0-rc.1 ] && echo ok)" "tag_ver"
	check "$([ "$(archive_name v0.91.0)" = k3sm_0.91.0_darwin_arm64.tar.gz ] && echo ok)" "archive_name"
	check "$([ "$(checksums_name v0.91.0-rc.1)" = k3sm_0.91.0-rc.1_checksums.txt ] && echo ok)" "checksums_name"
	check "$(node_version_is 'v1.37.1+k3sm.0.91.0-rc.1' v0.91.0-rc.1 && echo ok)" "node_version_is: the candidate"
	check "$(node_version_is 'v1.37.1+k3sm.0.91.0-rc.1' v0.91.0 || echo ok)" "node_version_is: its final is another release"
	t="$(printf 'k3sm.io/provider:NoSchedule\nexample.com/held:NoExecute\nexample.com/soft:PreferNoSchedule\n')"
	out="$(K3SM_LAB_TOLERATE_KEYS="" untolerated_keys "$t")"
	check "$([ "$out" = example.com/held ] && echo ok)" "untolerated_keys: a foreign NoExecute taint ($out)"
	out="$(printf '%s' '{"rows":[{"name":"update","state":"ahead","wide":{"channel":"rc"}}]}' | J 'row("update")["wide"]["channel"]')"
	check "$([ "$out" = rc ] && echo ok)" "J: reads a row"

	tol="$(K3SM_LAB_TOLERATE_KEYS="" lab_tolerations_yaml NoSchedule)"
	m="$(probe_pod ns-x p-1 node-a "$tol")"
	case "$m" in *"nodeName: node-a"*) check ok "pod: nodeName" ;; *) check no "pod: nodeName" ;; esac
	case "$m" in *"nodeSelector: {kubernetes.io/os: darwin}"*) check ok "pod: darwin nodeSelector" ;; *) check no "pod: darwin nodeSelector" ;; esac
	case "$m" in *"tolerations: [$tol]"*) check ok "pod: tolerations from the helper" ;; *) check no "pod: tolerations from the helper" ;; esac
	case "$m" in *"{operator"* | *"- operator"*) check no "pod: no key-less toleration" ;; *) check ok "pod: no key-less toleration" ;; esac
	case "$m" in *"configMap: {name: b1240-scripts}"*) check ok "pod: script by ConfigMap" ;; *) check no "pod: script by ConfigMap" ;; esac

	# The archive set against what the root helper really unpacks.
	f="$REPO_ROOT/../darwin-net/pkg/netd/extract.go"
	if [ -f "$f" ]; then
		want="$(sed -n '/^var updateSetFiles/,/^}/p' "$f" | sed -n 's/^[[:space:]]*"\([^"]*\)",$/\1/p' | LC_ALL=C sort | tr '\n' ' ')"
		out="$(tr ' ' '\n' <<<"$ARCHIVE_SET" | LC_ALL=C sort | tr '\n' ' ')"
		check "$([ "$want" = "$out" ] && echo ok)" "ARCHIVE_SET is darwin-net's updateSetFiles ($want)"
	else
		echo "note the darwin-net sibling is not here; ARCHIVE_SET not compared"
	fi

	tmp="$(mktemp -d "${TMPDIR:-/tmp}/b1240-selftest.XXXXXX")"
	mkdir -p "$tmp/bin"
	fake_k3sm >"$tmp/bin/k3sm"
	fake_ssh >"$tmp/bin/ssh"
	# shellcheck disable=SC2016 # these are the fakes' own text
	printf '#!/bin/bash\n[ "$1" = -n ] && shift\nexec "$@"\n' >"$tmp/bin/sudo"
	# shellcheck disable=SC2016
	printf '#!/bin/bash\nif [ "${FAKE_HOST:-}" = wrk ] && [ ! -e "$FAKE_STATE/forward-up" ]; then exit 7; fi\nexec /usr/bin/curl "$@"\n' >"$tmp/bin/curl"
	printf '#!/bin/bash\nexit 0\n' >"$tmp/bin/nc"
	# shellcheck disable=SC2016
	printf '#!/bin/bash\nwhile [ $# -gt 2 ]; do shift; done\nexec cp "$1" "${2#*:}"\n' >"$tmp/bin/scp"
	chmod +x "$tmp/bin/"*
	pyd="$(dirname "$(command -v python3)")"
	t="PATH=$tmp/bin:/usr/bin:/bin:$pyd"

	# The index on its own: held to GitHub's layout, on a real loopback socket.
	port=47999
	dir="$tmp/idx"
	mkdir -p "$dir/published/v0.90.0" "$dir/published/v0.91.0-rc.1" "$dir/withdrawn"
	printf 'archive-bytes' >"$dir/published/v0.90.0/k3sm_0.90.0_darwin_arm64.tar.gz"
	printf 'sum  k3sm_0.90.0_darwin_arm64.tar.gz\n' >"$dir/published/v0.90.0/k3sm_0.90.0_checksums.txt"
	index_py >"$tmp/index.py"
	python3 -I "$tmp/index.py" "$dir" "$port" "$INDEX_PATH" >/dev/null 2>&1 &
	pid=$!
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if curl -fsS -o /dev/null "http://127.0.0.1:$port$INDEX_PATH" 2>/dev/null; then break; fi
		sleep 0.3
	done
	u="http://127.0.0.1:$port$INDEX_PATH"
	out="$(curl -sI -o /dev/null -w '%{http_code} %{redirect_url}' "$u/latest")"
	check "$([ "$out" = "302 $u/tag/v0.90.0" ] && echo ok)" "index: latest redirects to the highest final, not a candidate ($out)"
	out="$(curl -fsS "$u?per_page=100" | J '",".join(e["tag_name"] for e in d) if isinstance(d, list) else ""' 2>/dev/null || curl -fsS "$u?per_page=100" | python3 -I -c 'import json,sys; print(",".join(e["tag_name"] for e in json.load(sys.stdin)))')"
	check "$([ "$out" = "v0.91.0-rc.1,v0.90.0" ] && echo ok)" "index: the listing holds finals and candidates ($out)"
	out="$(curl -fsS "$u/tags/v0.90.0" | python3 -I -c 'import json,sys; e=json.load(sys.stdin); print(e["tag_name"], e["draft"], bool(e["published_at"]))')"
	check "$([ "$out" = "v0.90.0 False True" ] && echo ok)" "index: one release by tag ($out)"
	out="$(curl -fsS "$u/download/v0.90.0/k3sm_0.90.0_darwin_arm64.tar.gz")"
	check "$([ "$out" = archive-bytes ] && echo ok)" "index: an archive downloads"
	code="$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$u/download/v0.90.0/../../../idx/access.log")"
	check "$([ "$code" = 404 ] && echo ok)" "index: a path out of its tree is 404 ($code)"
	code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/elsewhere")"
	check "$([ "$code" = 404 ] && echo ok)" "index: outside its base is 404 ($code)"
	mv "$dir/published/v0.91.0-rc.1" "$dir/withdrawn/"
	out="$(curl -fsS "$u" | python3 -I -c 'import json,sys; print(",".join(e["tag_name"] for e in json.load(sys.stdin)))')"
	check "$([ "$out" = v0.90.0 ] && echo ok)" "index: a withdrawn candidate leaves the listing ($out)"
	mv "$dir/published/v0.90.0" "$dir/withdrawn/"
	code="$(curl -s -o /dev/null -w '%{http_code}' "$u/download/v0.90.0/k3sm_0.90.0_darwin_arm64.tar.gz")"
	check "$([ "$code" = 404 ] && echo ok)" "index: a withdrawn archive is 404 ($code)"
	out="$(curl -sI -o /dev/null -w '%{redirect_url}' "$u/latest")"
	check "$([ "$out" = "$u" ] && echo ok)" "index: with no final, latest lands on the base ($out)"
	grep -q ' GET /k3sm/releases/download/v0.90.0/k3sm_0.90.0_darwin_arm64.tar.gz 200 ' "$dir/access.log" && sum=ok || sum=no
	check "$sum" "index: a download is in the access log"
	mv "$dir/withdrawn/v0.90.0" "$dir/published/"
	: >"$dir/gate"
	curl -s -o /dev/null -w '%{http_code}' "$u/download/v0.90.0/k3sm_0.90.0_darwin_arm64.tar.gz" >"$tmp/held.code" &
	code=$!
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if grep -q ' GET /k3sm/releases/download/v0.90.0/k3sm_0.90.0_darwin_arm64.tar.gz 102 ' "$dir/access.log"; then break; fi
		sleep 0.3
	done
	grep -q ' GET /k3sm/releases/download/v0.90.0/k3sm_0.90.0_darwin_arm64.tar.gz 102 ' "$dir/access.log" && sum=ok || sum=no
	check "$sum" "index: a gated GET is logged as 102"
	check "$([ ! -s "$tmp/held.code" ] && echo ok)" "index: a gated GET is not answered"
	mv "$dir/published/v0.90.0" "$dir/withdrawn/"
	rm -f "$dir/gate"
	wait "$code" || true
	out="$(cat "$tmp/held.code")"
	check "$([ "$out" = 404 ] && echo ok)" "index: a GET gated across a withdrawal answers 404 ($out)"
	if lsof -nP -a -p "$pid" -iTCP -sTCP:LISTEN 2>/dev/null | grep -q "127.0.0.1:$port"; then check ok "index: binds loopback only"; else check no "index: binds loopback only"; fi
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true

	# The sets a fake run reuses: real archives, with a k3sm that calls the fake.
	mkdir -p "$tmp/sets"
	for name in main $ALL_TAGS; do
		dir="$tmp/sets/$name"
		mkdir -p "$dir/tree"
		# shellcheck disable=SC2016
		printf '#!/bin/bash\nFAKE_SET_DIR="$(dirname "$0")" exec "%s" "$@"\n' "$tmp/bin/k3sm" >"$dir/tree/k3sm"
		chmod +x "$dir/tree/k3sm"
		v="$(tag_ver "$name")"
		printf '%s\n' "$v" >"$dir/tree/fake-version"
		if [ "$name" = main ]; then
			tar -czf "$dir/set.tar.gz" -C "$dir/tree" k3sm fake-version
			printf 'main\n' >"$dir/version"
		else
			tar -czf "$dir/$(archive_name "$name")" -C "$dir/tree" k3sm fake-version
			(cd "$dir" && shasum -a 256 "$(archive_name "$name")" >"$(checksums_name "$name")")
		fi
		rm -rf "$dir/tree"
		: >"$dir/.complete"
	done

	run_fake() { # <state-dir> <break> <port> <args...>
		local state="$1" brk="$2" p="$3"
		shift 3
		mkdir -p "$state/data/updates" "$state/server" "$state/worker" "$state/.kube"
		printf 'seed\n' >"$state/.kube/config"
		printf 'older\n' >"$state/.kube/config.b1240-19990101000000"
		env -i "$t" HOME="$state" TMPDIR="$state" FAKE_STATE="$state" FAKE_BREAK="$brk" K3SM_LAB=1 \
			K3SM_B1240_SERVER_SSH=srv K3SM_B1240_WORKER_SSH=wrk K3SM_B1240_SERVER_LAN=192.0.2.1 \
			K3SM_B1240_SERVER_WORK="$state/server" K3SM_B1240_WORKER_WORK="$state/worker" \
			K3SM_B1240_SETS="$tmp/sets" K3SM_B1240_PORT="$p" K3SM_B1240_K3SM="$tmp/bin/k3sm" \
			K3SM_B1240_DATA_ROOT="$state/data" K3SM_B1240_SERVICE_USER="$(id -un)" K3SM_B1240_PLIST_DIR="$state" \
			K3SM_B1240_MIN_FREE_GB_SERVER=0 K3SM_B1240_MIN_FREE_GB_WORKER=0 \
			K3SM_B1240_STEP_TIMEOUT="${FAKE_STEP:-30}" K3SM_B1240_READY_TIMEOUT=5 K3SM_B1240_THROTTLE=1 K3SM_B1240_INSTALL_TIMEOUT=30 \
			K3SM_B1240_ROLL_TIMEOUT=30 K3SM_B1240_POLL=0 K3SM_B1240_SKIP_TREE_CHECK=1 \
			/bin/bash "$SELF" "$@" 2>&1
	}

	out="$(env -i "$t" HOME="$tmp" FAKE_STATE="$tmp" /bin/bash "$SELF" "$tmp/nope-ev" 2>&1)" && code=0 || code=$?
	case "$out" in *SKIP*"NOT a pass"*) ;; *) code=99 ;; esac
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/nope-ev" ] && echo ok)" "K3SM_LAB unset: SKIP, exit 2, nothing created (got $code)"
	out="$(env -i "$t" HOME="$tmp" FAKE_STATE="$tmp" K3SM_LAB=0 /bin/bash "$SELF" "$tmp/nope-ev" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_LAB=0: SKIP, exit 2 (got $code)"
	check "$([ ! -e "$tmp/calls.log" ] && echo ok)" "a SKIP makes no k3sm call"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --plan 2>&1)" && code=0 || code=$?
	for row in "${LEGS[@]}"; do
		case "$out" in *"${row%%|*} "*) ;; *) code=98 ;; esac
	done
	check "$([ "$code" = 0 ] && echo ok)" "--plan: exit 0, every leg listed (got $code)"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --bogus 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "an unknown option: exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 /bin/bash "$SELF" "$tmp/nope-ev" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/nope-ev" ] && echo ok)" "no rig named: refused, exit 2 (got $code)"
	out="$(run_fake "$tmp/noev" "" 47998)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "no evidence directory: refused, exit 2 (got $code)"
	out="$(FAKE_STEP=241 run_fake "$tmp/lim" "" 47998 "$tmp/lim-ev")" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/lim/calls.log" ] && echo ok)" "a wait over 240 seconds: refused, exit 2, no k3sm call (got $code)"
	mkdir -p "$tmp/occ/server"
	: >"$tmp/occ/server/left"
	out="$(run_fake "$tmp/occ" "" 47998 "$tmp/occ-ev")" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/occ-ev" ] && echo ok)" "a work directory in use: refused, exit 2, nothing created (got $code)"

	out="$(run_fake "$tmp/inev" "" 47998 "$tmp/inev")" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/inev/calls.log" ] && echo ok)" "a work directory inside the evidence: refused, exit 2, no k3sm call (got $code)"

	# The positive control: every leg, in one run.
	out="$(run_fake "$tmp/green" "" 47900 "$tmp/green-ev")" && code=0 || code=$?
	if [ "$code" != 0 ]; then printf '%s\n' "$out"; fi
	check "$([ "$code" = 0 ] && echo ok)" "a healthy fake rig: exit 0 (got $code)"
	case "$out" in *"result: PASS"*) check ok "a healthy fake rig: result: PASS" ;; *) check no "a healthy fake rig: result: PASS" ;; esac
	for row in "${LEGS[@]}"; do
		case "$out" in *"PASS  ${row%%|*} "*) ;; *) check no "green run reports ${row%%|*}" ;; esac
	done
	if grep -q '^srv stop' "$tmp/green/calls.log" && grep -q '^wrk stop' "$tmp/green/calls.log"; then check ok "green run stops both Macs before the install"; else check no "green run stops both Macs before the install"; fi
	case "$(cat "$tmp/green/calls.log")" in
	*"--update-release-base=$GITHUB_BASE"*) check ok "green run records GitHub's URL on the way back" ;;
	*) check no "green run records GitHub's URL on the way back" ;;
	esac
	if grep -q 'delete namespace '"$NS" "$tmp/green/calls.log"; then check ok "green run deletes its namespace"; else check no "green run deletes its namespace"; fi
	if pgrep -f "$tmp/green/server/index.py" >/dev/null 2>&1; then check no "green run stops its index"; else check ok "green run stops its index"; fi

	if grep -rqF --exclude=B1240.sh fake-token "$tmp/green-ev"; then check no "green run: the token is not in the evidence"; else check ok "green run: the token is not in the evidence"; fi
	check "$([ ! -e "$tmp/green/token-left" ] && echo ok)" "green run: no token file outlives its install"
	check "$([ "$(find "$tmp/green/.kube" -name 'config.b1240-*' -exec basename {} \;)" = config.b1240-19990101000000 ] && echo ok)" "green run: its kubeconfig copies are gone, another's stays"
	check "$(grep -q '^apiVersion' "$tmp/green/.kube/config" && echo ok)" "green run: the live kubeconfig stays, refreshed"
	f="$tmp/green/calls.log"
	v="$(grep -n 'kubectl delete updates\.' "$f" | cut -d: -f1 | tr '\n' ' ')"
	u="$(grep -n 'update apply --yes' "$f" | head -1 | cut -d: -f1)"
	check "$([ -n "$u" ] && [ "${v%% *}" -gt "$u" ] && [ "${v#* }" = "" ] && echo ok)" "green run deletes the Update once, after it created one (deleted at line $v, created at $u)"
	check "$([ "$(grep -c 'kubectl delete updatepolic' "$f")" = 1 ] && echo ok)" "green run deletes the UpdatePolicy once"
	for brk in old-update old-policy; do
		out="$(run_fake "$tmp/$brk" "$brk" 47998 "$tmp/$brk-ev")" && code=0 || code=$?
		case "$out" in *"predate"*) ;; *) code="no reason given" ;; esac
		check "$([ "$code" = 2 ] && [ ! -e "$tmp/$brk-ev" ] && echo ok)" "$brk: refused, exit 2, nothing created (got $code)"
		if grep -Eq ' (stop|install|update apply|kubectl delete)( |$)' "$tmp/$brk/calls.log"; then check no "$brk: the rig untouched, nothing deleted"; else check ok "$brk: the rig untouched, nothing deleted"; fi
	done

	# The negative controls: each property broken alone reds its own leg, exit 1, and the
	# rig is still put back on this tree's build. They run side by side: each is a full run.
	port=47901
	for row in no-updates-row:c.1 forward-dead:f.1 cel-name:p.1 cel-value:p.2 stable-rc:s.1 \
		roll-on-set:r.1 worker-row:r.2 server-first:a.1 stays-cordoned:a.2 no-resume:b.1 \
		server-restart-fails:b.2 pod-fails:b.3 no-refuse:l.2 mid-channel:m.1 no-fallback:w.1 \
		worker-install-fails:c.1 cancel-ignored:w.1 no-get:w.1 abort-keeps-cordon:w.2 past-failure:w.3 leftover:e.1 base-left:e.2 label-lost:e.3; do
		(
			brk="${row%%:*}"
			want="${row#*:}"
			got="$(run_fake "$tmp/b-$brk" "$brk" "$port" "$tmp/b-$brk-ev")" && code=0 || code=$?
			case "$got" in
			*"FAIL  $want "*"result: FAIL"*) ;;
			*)
				printf '%s\n' "$got" | tail -40
				code="no FAIL $want"
				;;
			esac
			case "$(grep -c -- "--update-release-base=$GITHUB_BASE" "$tmp/b-$brk/calls.log" || true)" in
			2) ;;
			*) code="the rig was not put back" ;;
			esac
			if [ "$code" = 1 ]; then echo "ok   broken $brk: FAIL $want, exit 1, rig put back"; else
				echo "FAIL broken $brk: FAIL $want, exit 1, rig put back (got $code)"
			fi
		) >"$tmp/result-$port.txt" 2>&1 &
		port=$((port + 1))
	done
	wait
	for f in "$tmp"/result-*.txt; do
		cat "$f"
		if grep -q '^FAIL' "$f"; then bad=1; fi
	done
	check "$([ ! -e "$tmp/b-worker-install-fails/token-left" ] && echo ok)" "a failed install leaves no token file"
	check "$([ "$(find "$tmp/b-base-left/.kube" -name 'config.b1240-*' | wc -l)" -gt 1 ] && echo ok)" "a restore that did not pass keeps its kubeconfig copies"
	if grep -rqF --exclude=B1240.sh fake-token "$tmp/b-worker-install-fails-ev"; then check no "a failed install: the token is not in the evidence"; else check ok "a failed install: the token is not in the evidence"; fi
	if grep -Eq 'kubectl delete (updates\.|updatepolic)' "$tmp/b-no-updates-row/calls.log"; then check no "a run stopped before any roll deletes no Update or UpdatePolicy"; else check ok "a run stopped before any roll deletes no Update or UpdatePolicy"; fi
	rm -rf "$tmp"

	if [ "$bad" = 0 ]; then echo "B1240 self-test: green"; else echo "B1240 self-test: RED"; fi
	return "$bad"
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
	echo "B1240.sh: unknown option $1 (try --plan, --self-test)" >&2
	exit 2
	;;
esac

# ---- lab guard ------------------------------------------------------------------------------
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "B1240 lab gate: SKIP (two Macs). Set K3SM_LAB=1 and name the rig to run it; this is NOT a pass."
	exit 2
fi

# ---- preconditions (exit 2, the rig untouched) --------------------------------------------
refuse() {
	echo "B1240 lab gate: REFUSED: $*" >&2
	exit 2
}
for v in K3SM_B1240_SERVER_SSH K3SM_B1240_WORKER_SSH K3SM_B1240_SERVER_LAN K3SM_B1240_SERVER_WORK K3SM_B1240_WORKER_WORK K3SM_B1240_SETS; do
	[ -n "${!v:-}" ] || refuse "$v is not set (see --help)"
done
SERVER="$K3SM_B1240_SERVER_SSH"
WORKER="$K3SM_B1240_WORKER_SSH"
SERVER_LAN="$K3SM_B1240_SERVER_LAN"
SERVER_WORK="$K3SM_B1240_SERVER_WORK"
WORKER_WORK="$K3SM_B1240_WORKER_WORK"
SETS="$K3SM_B1240_SETS"
WORKER_FROM_SERVER="${K3SM_B1240_WORKER_FROM_SERVER:-$WORKER}"
CONTEXT="${K3SM_B1240_CONTEXT:-k3sm}"
MIN_FREE_SERVER="${K3SM_B1240_MIN_FREE_GB_SERVER:-16}"
MIN_FREE_WORKER="${K3SM_B1240_MIN_FREE_GB_WORKER:-8}"
[ "$#" = 1 ] || refuse "name one evidence directory, an absolute path under ../k3sm-io.scratch/ (got $# arguments)"
case "$1" in /*) ;; *) refuse "the evidence directory must be absolute (got '$1')" ;; esac
EVIDENCE="$1"
for p in "$SERVER_WORK" "$WORKER_WORK" "$SETS"; do
	case "$p" in
	*[!A-Za-z0-9_./-]*) refuse "a work directory must be a plain path (got '$p')" ;;
	/*) ;;
	*) refuse "a work directory must be absolute (got '$p')" ;;
	esac
done
for p in "$SERVER_WORK" "$WORKER_WORK"; do
	case "$p/" in "$EVIDENCE"/*) refuse "a work directory must not be inside the evidence directory (got '$p')" ;; esac
done
for v in "$STEP_TIMEOUT" "$READY_TIMEOUT" "$THROTTLE"; do
	case "$v" in '' | *[!0-9]*) refuse "a timeout must be a number of seconds (got '$v')" ;; esac
	[ "$v" -ge 1 ] && [ "$v" -le 240 ] || refuse "a step timeout must be 1 to 240 seconds (got $v)"
done
for v in "$INSTALL_TIMEOUT" "$ROLL_TIMEOUT" "$POLL" "$PORT" "$MIN_FREE_SERVER" "$MIN_FREE_WORKER"; do
	case "$v" in '' | *[!0-9]*) refuse "expected a number (got '$v')" ;; esac
done
command -v python3 >/dev/null 2>&1 || refuse "python3 not found; the gate reads JSON with it"
TOLERATIONS="$(lab_tolerations_yaml NoSchedule)" || exit 2
TEST_BASE="http://127.0.0.1:$PORT$INDEX_PATH"
INDEX_DIR="$SERVER_WORK/index"

# The build this run leaves behind must be main, and a modified tree is not. A diff
# outside hack/acceptance means this checkout is not main's product.
if [ "${K3SM_B1240_SKIP_TREE_CHECK:-}" != 1 ]; then
	command -v go >/dev/null 2>&1 || refuse "go not found; the sets are built here"
	[ -n "$(go env GOWORK)" ] || refuse "GOWORK is empty; stage.sh builds the sibling modules through go.work"
	[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ] || refuse "this checkout is modified, so its build is not main"
	drift="$(git -C "$REPO_ROOT" diff --name-only origin/main...HEAD -- . ':(exclude)hack/acceptance' 2>/dev/null || echo unknown)"
	[ -z "$drift" ] || refuse "this checkout differs from origin/main outside hack/acceptance, so its build is not main: $drift"
fi

# Reachable, and nothing in the way: read only, before anything is built.
rsh_probe() { bounded "$STEP_TIMEOUT" rsh_raw "$1" "$2" </dev/null; }
rsh_probe "$SERVER" "sudo -n /usr/bin/true" >/dev/null 2>&1 || refuse "no passwordless sudo over ssh on the server ($SERVER)"
rsh_probe "$WORKER" "sudo -n /usr/bin/true" >/dev/null 2>&1 || refuse "no passwordless sudo over ssh on the worker ($WORKER)"
[ "$SERVER" = local ] || command -v scp >/dev/null 2>&1 || refuse "scp not found"
for side in server worker; do
	if [ "$side" = server ]; then h="$SERVER" w="$SERVER_WORK" need="$MIN_FREE_SERVER"; else h="$WORKER" w="$WORKER_WORK" need="$MIN_FREE_WORKER"; fi
	here="$(rsh_probe "$h" "if [ -d $(quoted "$w") ]; then ls -A $(quoted "$w"); fi")" || refuse "cannot read $w on the $side"
	[ -z "$here" ] || refuse "$w on the $side is not empty: a leftover run, or someone else's"
	free="$(rsh_probe "$h" "df -g / | tail -1" | awk '{print $4}')" || refuse "cannot read the free disk on the $side"
	case "$free" in '' | *[!0-9]*) refuse "cannot read the free disk on the $side (got '$free')" ;; esac
	[ "$free" -ge "$need" ] || refuse "the $side has ${free} GB free and a run needs $need GB (K3SM_B1240_MIN_FREE_GB_*)"
	if rsh_probe "$h" "curl -s -o /dev/null --max-time 3 http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
		refuse "something already answers on port $PORT on the $side's loopback"
	fi
done
nodes_doc() { rsh "$SERVER" sudo "$K3SM_BIN" kubectl get nodes -o json </dev/null; }
kc get --raw /healthz >/dev/null 2>&1 </dev/null || refuse "the cluster is not serving (/healthz, sudo k3sm kubectl on the server)"
DOC="$(nodes_doc 2>/dev/null)" || refuse "cannot list the nodes"
SERVER_NODE="$(printf '%s' "$DOC" | J '" ".join(i["metadata"]["name"] for i in d["items"] if "node-role.kubernetes.io/control-plane" in i["metadata"].get("labels",{}))')"
WORKER_NODE="$(printf '%s' "$DOC" | J '" ".join(i["metadata"]["name"] for i in d["items"] if "node-role.kubernetes.io/control-plane" not in i["metadata"].get("labels",{}))')"
case "$SERVER_NODE" in '' | *" "*) refuse "this gate needs exactly one server node (found '$SERVER_NODE')" ;; esac
case "$WORKER_NODE" in '' | *" "*) refuse "this gate needs exactly one worker node (found '$WORKER_NODE')" ;; esac
notready="$(printf '%s' "$DOC" | J '" ".join(i["metadata"]["name"] for i in d["items"] if not any(c["type"]=="Ready" and c["status"]=="True" for c in i["status"]["conditions"]))')"
[ -z "$notready" ] || refuse "not Ready: $notready"
cordoned="$(printf '%s' "$DOC" | J '" ".join(i["metadata"]["name"] for i in d["items"] if i["spec"].get("unschedulable"))')"
[ -z "$cordoned" ] || refuse "cordoned: $cordoned; this run reads a cordon as its own, so lift or explain it first"
for n in "$SERVER_NODE" "$WORKER_NODE"; do
	lines="$(printf '%s' "$DOC" | J '"\n".join(t["key"]+":"+t.get("effect","") for i in d["items"] if i["metadata"]["name"]=="'"$n"'" for t in (i["spec"].get("taints") or []))')"
	left="$(untolerated_keys "$lines")" || exit 2
	[ -z "$left" ] || refuse "node $n carries taint key(s) this run does not tolerate: $left (name them in K3SM_LAB_TOLERATE_KEYS)"
done
leftover="$(printf '%s' "$DOC" | J '" ".join(i["metadata"]["name"] for i in d["items"] if any(k.startswith("k3sm.io/update-") for k in i["metadata"].get("annotations",{})))')"
[ -z "$leftover" ] || refuse "k3sm.io/update-* annotations on: $leftover; run \`k3sm update abort\` first"
UPDOC="$(k update status -o json </dev/null 2>/dev/null)" || refuse "cannot read the Update"
if [ -n "$(printf '%s' "$UPDOC" | J 'd["version"] if not d.get("finished") else ""')" ]; then
	refuse "an Update is in progress: another run holds the rig"
fi
if kc get namespace "$NS" >/dev/null 2>&1 </dev/null; then
	refuse "namespace $NS already exists: a leftover run, or someone else's; it is left alone"
fi
RECORDS="$(kc get updates.updates.k3sm.io,updatepolicies.updates.k3sm.io -o name </dev/null 2>/dev/null)" || refuse "cannot list the Updates and UpdatePolicies"
if [ -n "$RECORDS" ]; then
	refuse "these predate the run and a roll would replace them: $(tr '\n' ' ' <<<"$RECORDS")(see --help); remove them yourself if they can go"
fi
FOREIGN_BEFORE="$(printf '%s' "$DOC" | J '"; ".join(i["metadata"]["name"]+": "+foreign(i) for i in sorted(d["items"], key=lambda i: i["metadata"]["name"]))')"

mkdir -p "$EVIDENCE/scripts" "$EVIDENCE/pods" "$EVIDENCE/manifests" "$SETS"
exec 3</dev/null

# ---- the run ---------------------------------------------------------------------------------
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/runlog.sh disable=SC1091
. "$REPO_ROOT/hack/lab/lib/runlog.sh"
RUNLOG="$EVIDENCE/run.log"
RESULTS="$EVIDENCE/results.tsv"
: >"$RESULTS"
log() { printf '%s\n' "$*" | tee -a "$RUNLOG"; }
emit_run_log_header "FAIL (provisional; the final result line below is the verdict)" | tee "$RUNLOG"
log "foreign labels and taints before: $FOREIGN_BEFORE"
PASS=0
FAIL=0
REPORTED=" "
# leg <name> <ok|no> <detail>
leg() {
	local verdict=FAIL
	if [ "$2" = ok ]; then
		verdict=PASS
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
	fi
	REPORTED="$REPORTED$1 "
	log "$verdict  $1 $3"
	printf '%s\t%s\t%s\n' "$1" "$verdict" "$3" >>"$RESULTS"
}
# not_reached <why>: every leg not yet reported is a failure.
not_reached() {
	local row n
	for row in "${LEGS[@]}"; do
		n="${row%%|*}"
		case "$n" in e.*) continue ;; esac
		case "$REPORTED" in *" $n "*) ;; *) leg "$n" no "not reached: $1" ;; esac
	done
}

RIG_TOUCHED=0
# What this run may delete at the end: the preflight refused any that were already here.
RUN_UPDATE=0
RUN_POLICY=0
INDEX_UP=0
PUT_BACK=0

# ---- the sets --------------------------------------------------------------------------------
# build_set <name>: main (unstamped: the build the rig is left on) or a tag (stamped as a
# release stamps). The tree comes from stage.sh, the one producer of an install set; the
# archive is publish.sh's packing, less what k3sm-netd refuses.
build_set() {
	local name="$1" dir tree v got m members flags commit
	dir="$SETS/$name"
	[ -f "$dir/.complete" ] && return 0
	tree="$dir/tree"
	rm -rf "$dir"
	mkdir -p "$dir"
	v="$(tag_ver "$name")"
	flags=()
	if [ "$name" != main ]; then
		commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
		flags=(--ldflags "-s -w -X k3sm.io/k3sm/pkg/version.Version=$v -X k3sm.io/k3sm/pkg/version.Commit=$commit -X k3sm.io/k3sm/pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)")
	fi
	log "==> staging $name"
	"$REPO_ROOT/hack/release/stage.sh" "$tree" "${flags[@]+"${flags[@]}"}" >"$dir/stage.log" 2>&1 || {
		log "stage.sh failed for $name (last lines of $dir/stage.log):"
		log "$(tail -15 "$dir/stage.log")"
		return 1
	}
	got="$("$tree/k3sm" version | sed -n 1p | awk '{print $2}')"
	if [ "$name" != main ] && [ "$got" != "$v" ]; then
		log "the staged $name reports '$got': the stamp did not take"
		return 1
	fi
	members=()
	for m in $ARCHIVE_SET cp-payload; do members+=("$m"); done
	if [ "${K3SM_B1240_KEEP_MANIFEST:-}" = 1 ] && [ -f "$tree/PAYLOAD-SHA256" ]; then members+=(PAYLOAD-SHA256); fi
	if [ "$name" = main ]; then
		COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$dir/set.tar.gz" -C "$tree" "${members[@]}" -C "$REPO_ROOT" LICENSE NOTICE
		printf '%s\n' "$got" >"$dir/version"
	else
		COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$dir/$(archive_name "$name")" -C "$tree" "${members[@]}" -C "$REPO_ROOT" LICENSE NOTICE
		(cd "$dir" && shasum -a 256 "$(archive_name "$name")" >"$(checksums_name "$name")")
	fi
	rm -rf "$tree" "$tree.PAYLOAD-SHA256"
	: >"$dir/.complete"
}

for s in main $ALL_TAGS; do
	build_set "$s" || {
		emit_run_log_verdict FAIL | tee -a "$RUNLOG"
		echo "B1240 lab gate: REFUSED: could not build the $s set; the rig was not touched" >&2
		exit 2
	}
done
log "main build: $(cat "$SETS/main/version")"
du -sh "$SETS" >>"$RUNLOG" 2>&1 || true

# ---- the index and the forward --------------------------------------------------------------
# on_host_detached <host> <dir> <name> <shell-text>: a process that outlives this ssh, its
# pid in <dir>/<name>.pid and its output in <dir>/<name>.log.
on_host_detached() {
	local f="$EVIDENCE/scripts/$3.sh"
	printf '#!/bin/bash\n%s\n' "$4" >"$f"
	put "$1" "$f" "$2/$3.sh"
	rsh_raw "$1" "/bin/bash -c $(quoted "nohup /bin/bash $2/$3.sh >$2/$3.log 2>&1 </dev/null & echo \$! >$2/$3.pid")" </dev/null
}
kill_detached() {
	rsh_raw "$1" "if [ -f $2/$3.pid ]; then p=\$(cat $2/$3.pid); /usr/bin/pkill -P \"\$p\" 2>/dev/null; kill \"\$p\" 2>/dev/null; rm -f $2/$3.pid; fi; true" </dev/null >/dev/null 2>&1 || true
}
idx() { rsh_raw "$SERVER" "$1" </dev/null; }
publish() { idx "mv $INDEX_DIR/held/$1 $INDEX_DIR/published/$1"; }
withdraw() { idx "mv $INDEX_DIR/published/$1 $INDEX_DIR/withdrawn/$1"; }
hold_downloads() { idx "printf '%s' $1 >$INDEX_DIR/throttle"; }
# fetches_of <tag>: the archive GETs the index has answered for tag.
fetches_of() {
	idx "grep -c ' GET $INDEX_PATH/download/$1/$(archive_name "$1") ' $INDEX_DIR/access.log || true"
}
# archive_answers <tag> <code>: the archive GETs the index logged with this code for tag.
archive_answers() {
	idx "grep -c ' GET $INDEX_PATH/download/$1/$(archive_name "$1") $2 ' $INDEX_DIR/access.log || true"
}
# wait_archive <tag> <code>: 0 once the index has logged an archive GET with this code.
wait_archive() {
	local deadline=$((SECONDS + READY_TIMEOUT)) n
	while [ "$SECONDS" -lt "$deadline" ]; do
		n="$(archive_answers "$1" "$2")"
		[ "${n:-0}" -ge 1 ] && return 0
		sleep "$POLL"
	done
	return 1
}
gate_downloads() { idx ": >$INDEX_DIR/gate"; }
open_gate() { idx "rm -f $INDEX_DIR/gate"; }
forward_up() {
	rsh "$WORKER" curl -fsS --max-time 10 -o /dev/null "$TEST_BASE" </dev/null >/dev/null 2>&1
}
start_forward() {
	on_host_detached "$SERVER" "$SERVER_WORK" forward "exec ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -R 127.0.0.1:$PORT:127.0.0.1:$PORT $WORKER_FROM_SERVER"
}
# ensure_forward: before a roll. A dropped forward is reopened once and said so: the bytes
# are checked by digest, so a reopened tunnel proves the same thing.
ensure_forward() {
	forward_up && return 0
	log "the forward is down; reopening it once"
	kill_detached "$SERVER" "$SERVER_WORK" forward
	start_forward
	sleep 2
	forward_up
}

# ---- the clean start and the installs ---------------------------------------------------------
# ship_set <host> <work> <set>: the set's archive, unpacked beside k3sm's own layout.
ship_set() {
	local h="$1" w="$2" name="$3" a
	if [ "$name" = main ]; then a=set.tar.gz; else a="$(archive_name "$name")"; fi
	put "$h" "$SETS/$name/$a" "$w/$name.tar.gz" </dev/null
	rsh "$h" /bin/mkdir -p "$w/$name" </dev/null
	bounded "$INSTALL_TIMEOUT" rsh_raw "$h" "$(quoted /usr/bin/tar -xzf "$w/$name.tar.gz" -C "$w/$name")" </dev/null
	rsh "$h" /bin/rm -f "$w/$name.tar.gz" </dev/null
}
# clean_node <host> <work> <label>: stop, remove, say what was seen.
clean_node() {
	root_run "$1" "$2" "clean-$3" "$INSTALL_TIMEOUT" 3</dev/null <<EOF
K3SM=$(quoted "$K3SM_BIN"); DATA=$(quoted "$DATA_ROOT")
"\$K3SM" stop --reason b1240-clean-start 2>&1 | tail -5
# An install backup is never kept on the rig; a driver that finds one removes it.
for c in /Library/k3sm.pre-* "\$DATA"/server.*-etcd-*; do
	if [ -e "\$c" ]; then echo "removing the install backup \$c"; rm -rf "\$c"; fi
done
rm -rf "\$DATA/updates"
echo "removed_at=\$(date +%s)"
if [ -e "\$DATA/updates" ]; then echo updates=present; else echo updates=absent; fi
EOF
}
# token_path: the join token's one home, in a directory only the account can read, which
# the put-back removes and which is never under the evidence (the preflight refuses that).
token_path() { printf '%s' "$WORKER_WORK/private/join-token"; }
# drop_token: the install's own script removes the file on every way out but a kill; this
# covers that. The directory is the account's, so it can unlink root's file.
drop_token() { rsh "$WORKER" /bin/rm -f "$(token_path)" </dev/null >/dev/null 2>&1 || true; }
# install_server <set> <base> / install_worker <set> <base>: an in-place install keeps the
# node's other arguments and, on the server, its datastore. A worker takes a fresh short
# token first, so its root-owned cluster CA is pinned to what the token names.
install_server() {
	root_run "$SERVER" "$SERVER_WORK" "install-server-$1" "$INSTALL_TIMEOUT" 3</dev/null <<EOF
TU=$(quoted "${K3SM_B1240_USER:-$(rsh_raw "$SERVER" "id -un" </dev/null)}")
exec $(quoted "$SERVER_WORK/$1/k3sm") install --start --update-release-base=$(quoted "$2") --user "\$TU"
EOF
}
install_worker() {
	local token i=0 rc=0
	while [ "$i" -lt 40 ]; do
		rsh "$WORKER" nc -z -G 3 "$SERVER_LAN" 9345 </dev/null >/dev/null 2>&1 && break
		sleep 3
		i=$((i + 1))
	done
	[ "$i" -lt 40 ] || {
		log "the join port on $SERVER_LAN did not open"
		return 1
	}
	token="$(k token create --ttl 5m --work-dir "$DATA_ROOT/server" </dev/null 2>/dev/null)" || return 1
	[ -n "$token" ] || return 1
	root_run "$WORKER" "$WORKER_WORK" "install-worker-$1" "$INSTALL_TIMEOUT" 3< <(printf '%s\n' "$token") <<EOF || rc=$?
TU=$(quoted "${K3SM_B1240_USER:-$(rsh_raw "$WORKER" "id -un" </dev/null)}")
IFS= read -r token
tf=$(quoted "$(token_path)")
trap 'rm -f "\$tf"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077
rm -f "\$tf"
printf '%s\n' "\$token" >"\$tf"
chmod 600 "\$tf"
$(quoted "$WORKER_WORK/$1/k3sm") install --agent --server $(quoted "$SERVER_LAN") --token-file "\$tf" --start --update-release-base=$(quoted "$2") --user "\$TU"
EOF
	drop_token
	return "$rc"
}
# updates_dir <host>: owner, mode and birth of the updates directory.
updates_dir() { rsh "$1" sudo /usr/bin/stat -f '%Su %Lp %B' "$DATA_ROOT/updates" </dev/null 2>/dev/null; }
# copy_kubeconfig: a server install rotates the admin token, and the worker's copy is the
# laptop's own kubeconfig. A dated backup first, and never an empty overwrite. Each backup
# is named for this run, so drop_kube_copies can tell them from anyone else's; KUBE_FRESH
# says whether the last copy reached the worker.
RUN_ID="$(date +%Y%m%d%H%M%S)-$$"
KUBE_COPIES=0
KUBE_FRESH=0
copy_kubeconfig() {
	local cfg
	KUBE_FRESH=0
	cfg="$(rsh "$SERVER" "$K3SM_BIN" kubectl config view --minify --flatten --raw --context "$CONTEXT" </dev/null 2>/dev/null)" || cfg=""
	if [ -z "$cfg" ]; then
		log "note: could not read the admin context $CONTEXT on the server; the worker's ~/.kube/config is stale"
		return 0
	fi
	KUBE_COPIES=$((KUBE_COPIES + 1))
	if printf '%s\n' "$cfg" | bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "umask 077; mkdir -p ~/.kube; if [ -f ~/.kube/config ]; then cp ~/.kube/config ~/.kube/config.b1240-$RUN_ID-$KUBE_COPIES; fi; cat >~/.kube/config"; then
		KUBE_FRESH=1
	else
		log "note: could not copy the admin kubeconfig to the worker"
	fi
}
# drop_kube_copies: this run's backups, named one by one. The live config stays, and so
# does any other copy, which is not this run's to remove.
drop_kube_copies() {
	local i=1 files=""
	while [ "$i" -le "$KUBE_COPIES" ]; do
		files="$files ~/.kube/config.b1240-$RUN_ID-$i"
		i=$((i + 1))
	done
	[ -n "$files" ] || return 0
	if bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "rm -f$files" </dev/null; then
		log "removed this run's $KUBE_COPIES dated kubeconfig copies from the worker"
	else
		log "note: could not remove this run's dated kubeconfig copies (~/.kube/config.b1240-$RUN_ID-*)"
	fi
}
# wait_ready: both nodes Ready and schedulable: `k3sm stop` cordons, and the start lifts it.
wait_ready() {
	local deadline=$((SECONDS + READY_TIMEOUT)) doc left
	while [ "$SECONDS" -lt "$deadline" ]; do
		doc="$(nodes_doc 2>/dev/null)" || doc=""
		if [ -n "$doc" ]; then
			left="$(printf '%s' "$doc" | J '" ".join(i["metadata"]["name"] for i in d["items"] if i["spec"].get("unschedulable") or not any(c["type"]=="Ready" and c["status"]=="True" for c in i["status"]["conditions"]))')"
			[ -n "$left" ] || return 0
		fi
		sleep "$POLL"
	done
	return 1
}
# versions: `<server-kubelet> <worker-kubelet>`, and cordon state in CORDONED.
CORDONED=""
SERVER_VER=""
WORKER_VER=""
read_nodes() {
	local doc
	doc="$(nodes_doc 2>/dev/null)" || return 1
	SERVER_VER="$(printf '%s' "$doc" | J 'next(i["status"]["nodeInfo"]["kubeletVersion"] for i in d["items"] if i["metadata"]["name"]=="'"$SERVER_NODE"'")')"
	WORKER_VER="$(printf '%s' "$doc" | J 'next(i["status"]["nodeInfo"]["kubeletVersion"] for i in d["items"] if i["metadata"]["name"]=="'"$WORKER_NODE"'")')"
	CORDONED="$(printf '%s' "$doc" | J '" ".join(i["metadata"]["name"] for i in d["items"] if i["spec"].get("unschedulable"))')"
}
both_on() {
	read_nodes || return 1
	node_version_is "$SERVER_VER" "$1" && node_version_is "$WORKER_VER" "$1"
}

# ---- the rolls -------------------------------------------------------------------------------
ST=""
read_status() { ST="$(k update status -o json </dev/null 2>/dev/null)" || ST=""; [ -n "$ST" ]; }
st() { printf '%s' "$ST" | J "$1"; }
# apply_roll <apply-args...>: start one, its output kept. Fails when it was not created.
apply_roll() {
	ensure_forward || {
		log "the forward to the worker's loopback is down"
		return 1
	}
	RUN_UPDATE=1
	k update apply --yes "$@" </dev/null >>"$EVIDENCE/apply.log" 2>&1
}
# wait_node_phase <node> <phase> <budget>: 0 once the node reports it. 1 when the roll ended
# first or the budget ran out.
wait_node_phase() {
	local deadline=$((SECONDS + $3))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if read_status; then
			[ "$(st 'node("'"$1"'").get("phase","")')" = "$2" ] && return 0
			[ "$(st 'd.get("finished",False)')" = True ] && return 1
		fi
		sleep "$POLL"
	done
	return 1
}
# wait_roll <budget>: until the roll ends; the phase is in ROLL_END. A read that fails is the
# apiserver restarting on the server's turn, not an answer.
ROLL_END=""
wait_roll() {
	local deadline=$((SECONDS + $1))
	ROLL_END=""
	while [ "$SECONDS" -lt "$deadline" ]; do
		if read_status && [ "$(st 'd.get("finished",False)')" = True ]; then
			ROLL_END="$(st 'd["phase"]')"
			printf '%s\n' "$ST" >>"$EVIDENCE/rolls.jsonl"
			return 0
		fi
		sleep "$POLL"
	done
	ROLL_END="timeout"
	return 1
}
check_doc() { k update check -o json </dev/null 2>/dev/null; }
# offers <tag> <state>: `update check` answers latest tag, both nodes in state; CHECK says
# what it said.
CHECK=""
offers() {
	local doc
	doc="$(check_doc)" || {
		CHECK="the check failed"
		return 1
	}
	CHECK="$(printf '%s' "$doc" | J '"channel %s latest %s: %s" % (d.get("channel"), d["latest"].get("tag"), ", ".join(n["name"]+" "+n["state"] for n in d["nodes"]))')"
	[ "$(printf '%s' "$doc" | J 'd["latest"].get("tag")')" = "$1" ] || return 1
	[ -z "${2:-}" ] && return 0
	[ "$(printf '%s' "$doc" | J '" ".join(sorted(set(n["state"] for n in d["nodes"])))')" = "$2" ]
}
# row_of <k3sm-runner> <python>: the update row of a Mac's `k3sm status`.
row_of() { "$1" status -o json </dev/null 2>/dev/null | J "$2"; }

leg_clean() {
	local v before_s before_w at s w born now
	RIG_TOUCHED=1
	# The worker first, so it does not spend the stop retrying a server that went away.
	before_w="$(clean_node "$WORKER" "$WORKER_WORK" worker 2>&1)" || true
	before_s="$(clean_node "$SERVER" "$SERVER_WORK" server 2>&1)" || true
	printf '%s\n%s\n' "$before_w" "$before_s" >>"$RUNLOG"
	case "$before_s$before_w" in
	*updates=present*) v=no ;;
	*updates=absent*updates=absent*) v=ok ;;
	*) v=no ;;
	esac
	leg c.0 "$v" "server: $(grep -o 'updates=[a-z]*' <<<"$before_s" || echo none); worker: $(grep -o 'updates=[a-z]*' <<<"$before_w" || echo none)"
	[ "$v" = ok ] || return 1

	ship_set "$SERVER" "$SERVER_WORK" "$TAG_BASE" || return 1
	ship_set "$WORKER" "$WORKER_WORK" "$TAG_BASE" || return 1
	install_server "$TAG_BASE" "$TEST_BASE" >>"$EVIDENCE/install-server.log" 2>&1 || {
		leg c.1 no "the server's install failed ($EVIDENCE/install-server.log)"
		return 1
	}
	s="$(updates_dir "$SERVER")" || s=""
	install_worker "$TAG_BASE" "$TEST_BASE" >>"$EVIDENCE/install-worker.log" 2>&1 || {
		leg c.1 no "the worker's install failed ($EVIDENCE/install-worker.log)"
		return 1
	}
	w="$(updates_dir "$WORKER")" || w=""
	v=ok
	at="$(sed -n 's/^removed_at=//p' <<<"$before_s")"
	born="${s##* }"
	case "$s" in "$SERVICE_USER 700 "*) [ "${born:-0}" -ge "${at:-0}" ] || v=no ;; *) v=no ;; esac
	at="$(sed -n 's/^removed_at=//p' <<<"$before_w")"
	born="${w##* }"
	case "$w" in "$SERVICE_USER 700 "*) [ "${born:-0}" -ge "${at:-0}" ] || v=no ;; *) v=no ;; esac
	leg c.1 "$v" "server: ${s:-absent}; worker: ${w:-absent} (want $SERVICE_USER 700, born after the removal)"
	[ "$v" = ok ] || return 1
	copy_kubeconfig
	wait_ready || {
		leg c.2 no "the nodes were not Ready and schedulable within ${READY_TIMEOUT}s"
		return 1
	}
	k update apply --clear-pin </dev/null >>"$RUNLOG" 2>&1 || true
	now="$(kc get updates.updates.k3sm.io,updatepolicies.updates.k3sm.io -o name </dev/null 2>/dev/null || true)"
	log "installed: server $(rsh "$SERVER" "$K3SM_BIN" version </dev/null | sed -n 1p); worker $(rsh "$WORKER" "$K3SM_BIN" version </dev/null | sed -n 1p)"
	if both_on "$TAG_BASE" && [ -z "$now" ]; then
		leg c.2 ok "both on $TAG_BASE, no pin, Update or UpdatePolicy"
	else
		leg c.2 no "server $SERVER_VER, worker $WORKER_VER; left: ${now:-none}"
		return 1
	fi
}

leg_forward() {
	local want got
	if forward_up; then
		leg f.1 no "the worker's loopback answered before the forward was opened"
		return 1
	fi
	start_forward
	sleep 2
	want="$(cat "$SETS/$TAG_BASE/$(checksums_name "$TAG_BASE")")"
	got="$(rsh "$WORKER" curl -fsS --max-time 20 "$TEST_BASE/download/$TAG_BASE/$(checksums_name "$TAG_BASE")" </dev/null 2>/dev/null)" || got=""
	if [ -n "$want" ] && [ "$want" = "$got" ]; then
		leg f.1 ok "unreachable before the forward; the checksums file reads the same through it"
	else
		leg f.1 no "through the forward the worker read '$(cut -c1-80 <<<"$got")' (log: $SERVER_WORK/forward.log)"
		return 1
	fi
}

leg_policy() {
	local out
	if out="$(policy_object other stable | k kubectl create -f - 2>&1)"; then
		kc delete updatepolicies.updates.k3sm.io other --ignore-not-found </dev/null >>"$RUNLOG" 2>&1 || true
		leg p.1 no "an UpdatePolicy named other was accepted"
	else
		case "$out" in
		*"named cluster"*) leg p.1 ok "refused: $(cut -c1-160 <<<"$out")" ;;
		*) leg p.1 no "refused for another reason: $(cut -c1-200 <<<"$out")" ;;
		esac
	fi
	if out="$(policy_object cluster beta | k kubectl create -f - 2>&1)"; then
		kc delete updatepolicies.updates.k3sm.io cluster --ignore-not-found </dev/null >>"$RUNLOG" 2>&1 || true
		leg p.2 no "a channel of beta was accepted"
	else
		case "$out" in
		*beta*) ;;
		*)
			leg p.2 no "refused for another reason: $(cut -c1-200 <<<"$out")"
			return 0
			;;
		esac
		if policy_object cluster stable | k kubectl create --dry-run=server -f - >>"$RUNLOG" 2>&1; then
			leg p.2 ok "beta refused, and the named object with stable passes a dry run"
		else
			leg p.2 no "the good object was refused too, so the refusal proves nothing"
		fi
	fi
}

leg_stable() {
	local w
	publish "$TAG_RC1" || return 1
	if offers "$TAG_BASE" current; then
		w="$(row_of k 'row("update").get("state","")')" || w=""
		if [ "$w" = ok ]; then
			leg s.1 ok "$CHECK; the row is ok"
		else
			leg s.1 no "$CHECK; the row is '$w'"
		fi
	else
		leg s.1 no "$CHECK (want $TAG_BASE, current, with $TAG_RC1 published)"
	fi
}

leg_set_rc() {
	local out ch deadline w
	RUN_POLICY=1
	if ! out="$(k update channel rc </dev/null 2>&1)"; then
		leg r.1 no "k3sm update channel rc failed: $(cut -c1-200 <<<"$out")"
		return 1
	fi
	ch="$(k update channel </dev/null 2>/dev/null)" || ch=""
	read_status || ST='{}'
	if [ "$ch" = rc ] && offers "$TAG_RC1" behind && [ -z "$(st 'd.get("version","")')" ]; then
		leg r.1 ok "$CHECK; no Update"
	else
		leg r.1 no "channel '$ch'; $CHECK; Update '$(st 'd.get("version","")')'"
		return 1
	fi
	# The worker reads the pair its server publishes, on the server's next poll.
	deadline=$((SECONDS + READY_TIMEOUT))
	w=""
	while [ "$SECONDS" -lt "$deadline" ]; do
		w="$(row_of kw '"%s %s" % (row("update").get("wide",{}).get("channel"), row("update").get("wide",{}).get("latest"))')" || w=""
		[ "$w" = "rc $TAG_RC1" ] && break
		sleep "$POLL"
	done
	if [ "$w" = "rc $TAG_RC1" ]; then
		leg r.2 ok "the worker's update row: channel rc, latest $TAG_RC1"
	else
		leg r.2 no "the worker's update row: '$w' after ${READY_TIMEOUT}s"
	fi
}

leg_rc1() {
	local order fetched server_phase
	hold_downloads "$THROTTLE"
	apply_roll || {
		leg a.1 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	# No --version: the target has to be what the channel chose.
	grep -q "Created the Update current to $TAG_RC1" "$EVIDENCE/apply.log" || {
		leg a.1 no "apply on rc did not choose $TAG_RC1 ($EVIDENCE/apply.log)"
		return 1
	}
	if ! wait_node_phase "$WORKER_NODE" Downloading "$ROLL_TIMEOUT"; then
		leg a.1 no "the worker never reported Downloading: $(st 'node("'"$WORKER_NODE"'")')"
		return 1
	fi
	order="$(st '" ".join(n["name"] for n in d["nodes"])')"
	server_phase="$(st 'node("'"$SERVER_NODE"'").get("phase","")')"
	fetched="$(fetches_of "$TAG_RC1")"
	if [ "$order" = "$WORKER_NODE $SERVER_NODE" ] && [ "$server_phase" = Pending ] && [ "${fetched:-0}" -ge 1 ]; then
		leg a.1 ok "order $order; the server Pending while the index served the archive ($fetched fetch)"
	else
		leg a.1 no "order '$order', server '$server_phase', archive fetches ${fetched:-0}"
	fi
	hold_downloads 0
	wait_roll "$ROLL_TIMEOUT" || true
	if [ "$ROLL_END" = Succeeded ] && both_on "$TAG_RC1" && [ -z "$CORDONED" ]; then
		leg a.2 ok "Succeeded; both on $TAG_RC1"
	else
		leg a.2 no "ended '$ROLL_END'; server $SERVER_VER, worker $WORKER_VER; cordoned '${CORDONED:-none}'"
		return 1
	fi
}

# run_probes: a Pod on each Mac runs to the end, by the lab rules.
run_probes() {
	local n i=0 pod deadline ph uid
	kc create namespace "$NS" </dev/null >>"$RUNLOG" 2>&1 || return 1
	scripts_configmap "$NS" | tee "$EVIDENCE/manifests/scripts.yaml" | k kubectl apply -f - >>"$RUNLOG" 2>&1 || return 1
	for n in "$SERVER_NODE" "$WORKER_NODE"; do
		i=$((i + 1))
		pod="probe-$i"
		probe_pod "$NS" "$pod" "$n" "$TOLERATIONS" | tee "$EVIDENCE/manifests/$pod.yaml" | k kubectl apply -f - >>"$RUNLOG" 2>&1 || return 1
		deadline=$((SECONDS + READY_TIMEOUT))
		ph=""
		while [ "$SECONDS" -lt "$deadline" ]; do
			ph="$(kc get pod "$pod" -n "$NS" -o json </dev/null 2>/dev/null | J 'd["status"].get("phase","")')" || ph=""
			case "$ph" in Succeeded | Failed) break ;; esac
			sleep "$POLL"
		done
		if [ "$ph" != Succeeded ] || ! kc logs "$pod" -n "$NS" </dev/null 2>/dev/null | grep -q 'B1240 probe ran'; then
			uid="$(kc get pod "$pod" -n "$NS" -o json </dev/null 2>/dev/null | J 'd["metadata"]["uid"]')" || uid=""
			kc get events -n "$NS" --field-selector "involvedObject.uid=$uid" -o wide </dev/null >"$EVIDENCE/pods/$pod.events.txt" 2>&1 || true
			log "the probe on $n ended '$ph' ($EVIDENCE/pods/$pod.events.txt)"
			return 1
		fi
		kc delete pod "$pod" -n "$NS" --wait=true </dev/null >>"$RUNLOG" 2>&1 || true
	done
}

leg_rc2() {
	local first second deadline
	publish "$TAG_RC2" || return 1
	offers "$TAG_RC2" behind || log "note: $CHECK (want $TAG_RC2 offered)"
	hold_downloads "$THROTTLE"
	apply_roll || {
		leg b.1 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	if ! wait_node_phase "$WORKER_NODE" Downloading "$ROLL_TIMEOUT"; then
		leg b.1 no "the worker never reported Downloading"
		return 1
	fi
	first="$(fetches_of "$TAG_RC2")"
	# A restart outlasts STEP_TIMEOUT on a loaded Mac: it stops every Pod first.
	bounded "$INSTALL_TIMEOUT" rsh_raw "$WORKER" "$(quoted sudo "$K3SM_BIN" restart --reason b1240-bounce)" </dev/null >>"$RUNLOG" 2>&1 || log "note: the worker's restart exited non-zero"
	# The fetch count is what a resume shows: its daemon starts the download over.
	deadline=$((SECONDS + READY_TIMEOUT))
	second="$first"
	while [ "$SECONDS" -lt "$deadline" ]; do
		second="$(fetches_of "$TAG_RC2")"
		[ "${second:-0}" -gt "${first:-0}" ] && break
		read_status || true
		sleep "$POLL"
	done
	read_status || ST='{}'
	if [ "${second:-0}" -gt "${first:-0}" ] && [ "$(st 'd.get("finished",False)')" != True ]; then
		leg b.1 ok "archive fetches $first then $second; the roll held"
	else
		leg b.1 no "archive fetches $first then $second; the roll is '$(st 'd.get("phase","")')'"
	fi
	if bounded "$INSTALL_TIMEOUT" rsh_raw "$SERVER" "$(quoted sudo "$K3SM_BIN" restart --reason b1240-bounce)" </dev/null >>"$RUNLOG" 2>&1; then
		leg b.2 ok "the server restarted while the worker was mid-update; the roll goes on below"
	else
		leg b.2 no "sudo k3sm restart failed on the server"
	fi
	hold_downloads 0
	wait_roll "$ROLL_TIMEOUT" || true
	if [ "$ROLL_END" != Succeeded ] || ! both_on "$TAG_RC2" || [ -n "$CORDONED" ]; then
		leg b.3 no "ended '$ROLL_END'; server $SERVER_VER, worker $WORKER_VER; cordoned '${CORDONED:-none}'"
		return 1
	fi
	if run_probes; then
		leg b.3 ok "Succeeded after both restarts; both on $TAG_RC2; a Pod ran on each Mac"
	else
		leg b.3 no "the roll Succeeded but a Pod did not run"
	fi
}

leg_leave() {
	local before w
	k update channel stable </dev/null >>"$RUNLOG" 2>&1 || {
		leg l.1 no "k3sm update channel stable failed"
		return 1
	}
	w="$(row_of k 'row("update").get("state","")')" || w=""
	if offers "$TAG_BASE" ahead && [ "$w" = ahead ]; then
		leg l.1 ok "$CHECK; the row is ahead"
	else
		leg l.1 no "$CHECK; the row is '$w' (want every node ahead, no offer)"
	fi
	read_nodes || true
	before="$SERVER_VER $WORKER_VER"
	apply_roll --version "$TAG_BASE" || {
		leg l.2 no "apply failed to create the Update ($EVIDENCE/apply.log)"
		return 1
	}
	wait_roll "$ROLL_TIMEOUT" || true
	read_nodes || true
	if [ "$ROLL_END" = Failed ] && [ "$SERVER_VER $WORKER_VER" = "$before" ] && [ -z "$CORDONED" ]; then
		leg l.2 ok "the controller refused it; no node moved or cordoned"
	else
		leg l.2 no "ended '$ROLL_END'; nodes '$SERVER_VER $WORKER_VER', were '$before'; cordoned '${CORDONED:-none}'"
		return 1
	fi
}

leg_back() {
	hold_downloads 0
	apply_roll --version "$TAG_BASE" --allow-downgrade || {
		leg d.1 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	wait_roll "$ROLL_TIMEOUT" || true
	if [ "$ROLL_END" = Succeeded ] && both_on "$TAG_BASE" && [ -z "$CORDONED" ] && offers "$TAG_BASE" current; then
		leg d.1 ok "Succeeded; $CHECK"
	else
		leg d.1 no "ended '$ROLL_END'; server $SERVER_VER, worker $WORKER_VER; ${CHECK:-}"
		return 1
	fi
}

leg_mid_channel() {
	local v
	k update channel rc </dev/null >>"$RUNLOG" 2>&1 || return 1
	hold_downloads "$THROTTLE"
	apply_roll || {
		leg m.1 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	if ! wait_node_phase "$WORKER_NODE" Downloading "$ROLL_TIMEOUT"; then
		leg m.1 no "the worker never reported Downloading"
		return 1
	fi
	v="$(st 'd.get("version","")')"
	k update channel stable </dev/null >>"$RUNLOG" 2>&1 || {
		leg m.1 no "setting the channel mid-roll failed"
		return 1
	}
	read_status || ST='{}'
	if [ "$v" = "$TAG_RC2" ] && [ "$(st 'd.get("version","")')" = "$TAG_RC2" ] && [ "$(st 'd.get("finished",False)')" != True ]; then
		leg m.1 ok "the roll still targets $TAG_RC2 with the channel on stable"
	else
		leg m.1 no "target '$v', then '$(st 'd.get("version","")')', finished '$(st 'd.get("finished",False)')'"
	fi
	hold_downloads 0
	wait_roll "$ROLL_TIMEOUT" || true
	if [ "$ROLL_END" = Succeeded ] && both_on "$TAG_RC2" && offers "$TAG_BASE" ahead; then
		leg m.2 ok "Succeeded on $TAG_RC2; $CHECK"
	else
		leg m.2 no "ended '$ROLL_END'; server $SERVER_VER, worker $WORKER_VER; ${CHECK:-}"
		return 1
	fi
}

leg_final() {
	publish "$TAG_FINAL" || return 1
	k update channel rc </dev/null >>"$RUNLOG" 2>&1 || return 1
	if ! offers "$TAG_FINAL" behind; then
		leg z.1 no "$CHECK (want the final offered on rc, both behind)"
		return 1
	fi
	apply_roll || {
		leg z.1 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	wait_roll "$ROLL_TIMEOUT" || true
	if [ "$ROLL_END" = Succeeded ] && both_on "$TAG_FINAL" && [ -z "$CORDONED" ] && offers "$TAG_FINAL" current; then
		leg z.1 ok "rc.2 rolled to the final; $CHECK"
	else
		leg z.1 no "ended '$ROLL_END'; server $SERVER_VER, worker $WORKER_VER; ${CHECK:-}"
		return 1
	fi
}

leg_withdraw_cancel() {
	local detail ok=1 listed
	publish "$TAG_W1" || return 1
	offers "$TAG_W1" behind || log "note: $CHECK (want $TAG_W1 offered)"
	hold_downloads "$THROTTLE"
	apply_roll || {
		leg w.1 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	if ! wait_node_phase "$WORKER_NODE" Downloading "$ROLL_TIMEOUT"; then
		leg w.1 no "the worker never reported Downloading"
		return 1
	fi
	if ! wait_archive "$TAG_W1" 200; then
		leg w.1 no "the index served the worker no archive within ${READY_TIMEOUT}s"
		return 1
	fi
	withdraw "$TAG_W1" || return 1
	offers "$TAG_FINAL" && listed=1 || listed=0
	detail="after the withdrawal: $CHECK"
	[ "$listed" = 1 ] || ok=0
	k update cancel </dev/null >>"$RUNLOG" 2>&1 || {
		ok=0
		detail="$detail; cancel failed"
	}
	hold_downloads 0
	wait_roll "$ROLL_TIMEOUT" || true
	read_nodes || true
	node_version_is "$WORKER_VER" "$TAG_W1" && node_version_is "$SERVER_VER" "$TAG_FINAL" || ok=0
	[ "$ROLL_END" = Cancelled ] && [ -z "$CORDONED" ] || ok=0
	detail="$detail; ended '$ROLL_END'; worker $WORKER_VER, server $SERVER_VER; cordoned '${CORDONED:-none}'"
	if [ "$ok" = 1 ]; then leg w.1 ok "$detail"; else leg w.1 no "$detail"; fi
	[ "$ROLL_END" = Cancelled ]
}

leg_withdraw_fail() {
	local detail ok=1 msg out ann
	publish "$TAG_W2" || return 1
	offers "$TAG_W2" || log "note: $CHECK (want $TAG_W2 offered)"
	hold_downloads "$THROTTLE"
	apply_roll || {
		leg w.2 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	if ! wait_node_phase "$WORKER_NODE" Downloading "$ROLL_TIMEOUT"; then
		leg w.2 no "the worker never reported Downloading"
		return 1
	fi
	if ! wait_archive "$TAG_W2" 200; then
		leg w.2 no "the index served the worker no archive within ${READY_TIMEOUT}s"
		return 1
	fi
	withdraw "$TAG_W2" || return 1
	hold_downloads 0
	wait_roll "$ROLL_TIMEOUT" || true
	read_nodes || true
	msg="$(st 'node("'"$SERVER_NODE"'").get("message","")')"
	[ "$ROLL_END" = Failed ] && node_version_is "$WORKER_VER" "$TAG_W2" && node_version_is "$SERVER_VER" "$TAG_FINAL" || ok=0
	case "$msg" in *404*) ;; *) ok=0 ;; esac
	detail="ended '$ROLL_END'; worker $WORKER_VER, server $SERVER_VER; the server: '$(cut -c1-120 <<<"$msg")'"
	out="$(k update cancel </dev/null 2>&1)" || ok=0
	case "$out" in *"nothing to cancel"*) detail="$detail; cancel: nothing to cancel" ;; *)
		ok=0
		detail="$detail; cancel said '$(cut -c1-120 <<<"$out")'"
		;;
	esac
	k update abort </dev/null >>"$RUNLOG" 2>&1 || {
		ok=0
		detail="$detail; abort failed"
	}
	read_nodes || true
	ann="$(nodes_doc 2>/dev/null | J '" ".join(k for i in d["items"] for k in i["metadata"].get("annotations",{}) if k.startswith("k3sm.io/update-"))')" || ann="unreadable"
	[ -z "$CORDONED" ] && [ -z "$ann" ] || ok=0
	detail="$detail; after abort cordoned '${CORDONED:-none}', annotations '${ann:-none}'"
	if [ "$ok" = 1 ]; then leg w.2 ok "$detail"; else leg w.2 no "$detail"; fi
}

# The first node of a roll meets the 404 itself. The GET is held at the index across the
# withdrawal, so this is the node's own fetch failing, not a race for one.
leg_withdraw_first() {
	local detail ok=1 before msg phase server_phase got gone out ann
	read_nodes || true
	before="$SERVER_VER $WORKER_VER"
	publish "$TAG_W3" || return 1
	offers "$TAG_W3" || log "note: $CHECK (want $TAG_W3 offered)"
	gate_downloads
	apply_roll || {
		leg w.3 no "apply failed ($EVIDENCE/apply.log)"
		return 1
	}
	if ! wait_node_phase "$WORKER_NODE" Downloading "$ROLL_TIMEOUT"; then
		leg w.3 no "the worker never reported Downloading"
		return 1
	fi
	if ! wait_archive "$TAG_W3" 102; then
		leg w.3 no "the worker's GET did not reach the index within ${READY_TIMEOUT}s"
		return 1
	fi
	withdraw "$TAG_W3" || return 1
	open_gate
	wait_roll "$ROLL_TIMEOUT" || true
	read_nodes || true
	phase="$(st 'node("'"$WORKER_NODE"'").get("phase","")')"
	msg="$(st 'node("'"$WORKER_NODE"'").get("message","")')"
	server_phase="$(st 'node("'"$SERVER_NODE"'").get("phase","")')"
	got="$(archive_answers "$TAG_W3" 200)"
	gone="$(archive_answers "$TAG_W3" 404)"
	[ "$ROLL_END" = Failed ] && [ "$phase" = Failed ] && [ "$server_phase" = Pending ] || ok=0
	case "$msg" in *404*) ;; *) ok=0 ;; esac
	[ "$SERVER_VER $WORKER_VER" = "$before" ] && [ "$CORDONED" = "$WORKER_NODE" ] || ok=0
	[ "${got:-0}" = 0 ] && [ "${gone:-0}" = 1 ] || ok=0
	detail="ended '$ROLL_END'; the worker $phase: '$(cut -c1-120 <<<"$msg")'; the server $server_phase; archive answers 200:${got:-0} 404:${gone:-0}; nodes '$SERVER_VER $WORKER_VER', were '$before'; cordoned '${CORDONED:-none}'"
	out="$(k update cancel </dev/null 2>&1)" || ok=0
	case "$out" in *"nothing to cancel"*) detail="$detail; cancel: nothing to cancel" ;; *)
		ok=0
		detail="$detail; cancel said '$(cut -c1-120 <<<"$out")'"
		;;
	esac
	k update abort </dev/null >>"$RUNLOG" 2>&1 || {
		ok=0
		detail="$detail; abort failed"
	}
	read_nodes || true
	ann="$(nodes_doc 2>/dev/null | J '" ".join(k for i in d["items"] for k in i["metadata"].get("annotations",{}) if k.startswith("k3sm.io/update-"))')" || ann="unreadable"
	[ -z "$CORDONED" ] && [ -z "$ann" ] || ok=0
	detail="$detail; after abort cordoned '${CORDONED:-none}', annotations '${ann:-none}'"
	if [ "$ok" = 1 ]; then leg w.3 ok "$detail"; else leg w.3 no "$detail"; fi
}

run_legs() {
	leg_clean || return 0
	leg_forward || return 0
	leg_policy || return 0
	leg_stable || return 0
	leg_set_rc || return 0
	leg_rc1 || return 0
	leg_rc2 || return 0
	leg_leave || return 0
	leg_back || return 0
	leg_mid_channel || return 0
	leg_final || return 0
	leg_withdraw_cancel || return 0
	leg_withdraw_fail || return 0
	leg_withdraw_first || return 0
}

# ---- putting the rig back ---------------------------------------------------------------------
# put_back: on every exit once the rig was touched. Test objects go first, while the
# cluster still answers; then this tree's build on both Macs, the server first; then the
# forward and the index, which the installs no longer need, and the work directories.
put_back() {
	[ "$PUT_BACK" = 0 ] || return 0
	PUT_BACK=1
	set +e
	exec 3</dev/null
	log "==> putting the rig back"
	if [ "$INDEX_UP" = 1 ]; then
		hold_downloads 0
		open_gate
	fi
	if [ "$RIG_TOUCHED" = 1 ]; then
		if read_status && [ -n "$(st 'd.get("version","")')" ] && [ "$(st 'd.get("finished",False)')" != True ]; then
			k update abort </dev/null >>"$RUNLOG" 2>&1
		fi
		ship_set "$SERVER" "$SERVER_WORK" main
		ship_set "$WORKER" "$WORKER_WORK" main
		install_server main "$GITHUB_BASE" >>"$EVIDENCE/install-server.log" 2>&1 || log "the server's install of main FAILED: the rig is not on main ($EVIDENCE/install-server.log)"
		install_worker main "$GITHUB_BASE" >>"$EVIDENCE/install-worker.log" 2>&1 || log "the worker's install of main FAILED: the rig is not on main ($EVIDENCE/install-worker.log)"
		copy_kubeconfig
		wait_ready || log "the nodes did not come Ready within ${READY_TIMEOUT}s"
		{
			k update apply --clear-pin
			kc delete namespace "$NS" --ignore-not-found --wait=true --timeout=120s
			if [ "$RUN_UPDATE" = 1 ]; then kc delete updates.updates.k3sm.io current --ignore-not-found; fi
			if [ "$RUN_POLICY" = 1 ]; then kc delete updatepolicies.updates.k3sm.io cluster --ignore-not-found; fi
		} </dev/null >>"$RUNLOG" 2>&1
		log "installed: server $(rsh "$SERVER" "$K3SM_BIN" version </dev/null | sed -n 1p); worker $(rsh "$WORKER" "$K3SM_BIN" version </dev/null | sed -n 1p)"
	fi
	if [ "$INDEX_UP" = 1 ]; then
		kill_detached "$SERVER" "$SERVER_WORK" forward
		kill_detached "$SERVER" "$SERVER_WORK" index
		rsh_raw "$SERVER" "cat $(quoted "$INDEX_DIR/access.log")" </dev/null >"$EVIDENCE/index-access.log" 2>/dev/null
	fi
	rsh "$SERVER" /bin/rm -rf "$SERVER_WORK" </dev/null
	rsh "$WORKER" /bin/rm -rf "$WORKER_WORK" </dev/null
	kc get nodes -o wide </dev/null >"$EVIDENCE/get-after.txt" 2>&1
	kc get ns </dev/null >"$EVIDENCE/namespaces-after.txt" 2>&1
	log "$(cat "$EVIDENCE/namespaces-after.txt")"
	set -e
	return 0
}

leg_end() {
	local left base_left want doc after
	left=""
	kc get namespace "$NS" </dev/null >/dev/null 2>&1 && left="namespace $NS"
	doc="$(kc get updates.updates.k3sm.io,updatepolicies.updates.k3sm.io -o name </dev/null 2>/dev/null || true)"
	left="$left$doc"
	if [ -z "$left" ]; then leg e.1 ok "gone"; else leg e.1 no "still here: $left"; fi

	want="$(cat "$SETS/main/version")"
	want="${want#v}"
	read_nodes || true
	base_left=""
	for h in "$SERVER" "$WORKER"; do
		if rsh_raw "$h" "cat $PLIST_DIR/io.k3sm.server.plist $PLIST_DIR/io.k3sm.agent.plist 2>/dev/null | grep -q '127.0.0.1:$PORT'" </dev/null >/dev/null 2>&1; then
			base_left="$base_left $h"
		fi
	done
	case "$SERVER_VER $WORKER_VER" in
	*"+k3sm.$want "*"+k3sm.$want") ;;
	*) base_left="$base_left (versions: $SERVER_VER, $WORKER_VER; want $want)" ;;
	esac
	if ! wait_ready; then base_left="$base_left (not Ready and schedulable)"; fi
	if [ -z "$base_left" ]; then leg e.2 ok "both on $want, Ready, $GITHUB_BASE recorded"; else leg e.2 no "$base_left"; fi
	# Only a restore that held makes the backups spare.
	if [ -z "$base_left" ] && [ "$KUBE_FRESH" = 1 ]; then
		drop_kube_copies
	else
		log "kept this run's dated kubeconfig copies on the worker (~/.kube/config.b1240-$RUN_ID-*): the restore did not pass"
	fi

	doc="$(nodes_doc 2>/dev/null)" || doc=""
	after="$(printf '%s' "$doc" | J '"; ".join(i["metadata"]["name"]+": "+foreign(i) for i in sorted(d["items"], key=lambda i: i["metadata"]["name"]))' 2>/dev/null || echo unreadable)"
	if [ "$after" = "$FOREIGN_BEFORE" ]; then
		leg e.3 ok "unchanged: $after"
	else
		leg e.3 no "before: $FOREIGN_BEFORE; after: $after (reported, not repaired)"
	fi
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
on_exit() {
	local rc=$?
	trap - EXIT
	drop_token
	if [ "$PUT_BACK" = 0 ]; then
		put_back
		log "the run stopped early (exit $rc)"
		emit_run_log_verdict FAIL | tee -a "$RUNLOG"
		[ "$rc" != 0 ] || rc=1
	fi
	exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- preflight and the index -------------------------------------------------------------------
log "==> $GATE_NAME: server $SERVER ($SERVER_NODE), worker $WORKER ($WORKER_NODE), index $TEST_BASE"
kc get nodes,pods -A -o wide </dev/null >"$EVIDENCE/get-before.txt" 2>&1 || true
cp "$SELF" "$EVIDENCE/B1240.sh"
rsh "$SERVER" /bin/mkdir -p -m 700 "$SERVER_WORK" </dev/null
rsh "$WORKER" /bin/mkdir -p -m 700 "$WORKER_WORK" </dev/null
rsh "$WORKER" /bin/mkdir -p -m 700 "$WORKER_WORK/private" </dev/null
rsh_raw "$SERVER" "mkdir -p $INDEX_DIR/held $INDEX_DIR/published $INDEX_DIR/withdrawn" </dev/null
for t in $ALL_TAGS; do
	rsh_raw "$SERVER" "mkdir -p $INDEX_DIR/held/$t" </dev/null
	put "$SERVER" "$SETS/$t/$(archive_name "$t")" "$INDEX_DIR/held/$t/$(archive_name "$t")" </dev/null
	put "$SERVER" "$SETS/$t/$(checksums_name "$t")" "$INDEX_DIR/held/$t/$(checksums_name "$t")" </dev/null
done
index_py >"$EVIDENCE/scripts/index.py"
put "$SERVER" "$EVIDENCE/scripts/index.py" "$SERVER_WORK/index.py" </dev/null
publish "$TAG_BASE"
on_host_detached "$SERVER" "$SERVER_WORK" index "exec python3 -I $SERVER_WORK/index.py $INDEX_DIR $PORT $INDEX_PATH"
INDEX_UP=1
sleep 2
rsh "$SERVER" curl -fsS --max-time 10 -o /dev/null "$TEST_BASE" </dev/null >/dev/null 2>&1 || {
	log "the index did not come up on the server's loopback ($SERVER_WORK/index.log)"
	exit 1
}

run_legs
not_reached "an earlier leg stopped the run"
put_back
leg_end

log "----------------------------------------"
log "$GATE_NAME: $PASS passed, $FAIL failed"
trap - EXIT
if [ "$FAIL" -ne 0 ]; then
	emit_run_log_verdict FAIL | tee -a "$RUNLOG"
	exit 1
fi
emit_run_log_verdict PASS | tee -a "$RUNLOG"
