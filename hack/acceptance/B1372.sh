#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The model-store tracer: a model pushed once to the cluster's own registry is served
# by an MLXModel on either Mac, with no internet from the pod, one verified copy per
# node read without extraction, and the space back after deletion.
#
# It runs against the RUNNING two-Mac cluster in $KUBECONFIG and installs nothing. The
# driver has already installed the build under test on both Macs. Surfaces: kubectl,
# k3sm and Pods; the node reads (the view, the cache blobs, the partial download, free
# space, the serving process's footprint) and the daemon restart go over SSH, because
# that evidence lives nowhere public.
#
# Rungs (`--plan` prints them; the first red rung ends the run, every rung not reached
# is red, and the cleanup f.1 runs green or red):
#   p.0   preconditions, read-only: K3SM_LAB=1, tools, the environment, an empty
#         evidence dir, the model directory against its sha256 list (exactly the
#         listed files, each with its hash), both nodes Ready with the GPU label and
#         no untolerated taint, the CRD carries spec.artifact and
#         status.resolvedArtifact, the node caches hold none of the model's blobs (the
#         cold rung needs a cold cache). A refusal exits 3 with the rig untouched.
#   t.0   `k3sm version` on both Macs and the tree's commit; `kubectl get nodes`;
#         free space of both node caches and of the registry store (the baseline)
#   t.1   `k3sm model push <dir> <run>:v1`, then the same push again: the same
#         digest, and the registry's blob files for the repository unchanged (names,
#         inodes, sizes and mtimes), so the second push wrote zero bytes
#   t.2   two MLXModels naming that one artifact, one pinned to each Mac by
#         kubernetes.io/hostname (one MLXModel's nodeSelector is one map for every
#         replica, so per-Mac placement needs one object per Mac); no egress
#         annotation, no cache. The worker's watcher for t.3b starts first.
#   t.3   both Ready; status.resolvedArtifact equals t.1's digest on both; every
#         rendered Pod has one image volume naming the cluster registry by that
#         digest, no PVC, no egress annotation and no trust_remote_code. RECORDED:
#         cold time to Ready and the fetch rate (model bytes over the window from
#         PodScheduled to the container's start, which holds the fetch), and the
#         serving process's peak footprint against spec.memory
#   t.3b  during the worker's pull, `launchctl kickstart -k` of the worker's node
#         daemon (runtimed runs in it): the partial download is still there after
#         the restart, same inode, no shorter; the blob is then committed under its
#         digest, the partial is gone, the daemon's pid changed, and the replica is
#         Ready
#   t.4   a client Pod on each Mac (script by ConfigMap) POSTs /v1/chat/completions
#         to the other Mac's replica through its Service: non-empty content, both ways
#   t.5   `kubectl exec` in each serving Pod: https to the Hub fails while a control
#         Pod with the egress annotation, same image and node, reaches it; a write
#         to the mounted weights fails with EPERM; an exec of a mounted file fails
#         (errno RECORDED: EPERM is the profile, EACCES the mode); RECORDED as a
#         stated negative, a copied and chmod +x'ed file runs from the data volume.
#         On each Mac: one view of the manifest; each view file a distinct inode
#         from its cache blob on the same device, same size and blocks, 0444, root
#   t.6   the server's MLXModel scaled to 2 (three replicas, two on the server Mac):
#         the server's free space drops by under 1% of the model, the view is the
#         same one (same inodes). RECORDED: warm time to Ready and fetch window
#   t.7   both MLXModels deleted and their Pods gone; `k3sm image prune --force` on
#         both Macs; `k3sm model rm <run>:v1`, then the registry prune; each node's
#         view is gone and free space on both caches and the registry store is back
#         at t.0's within 1% of the model
#   f.1   cleanup, green or red: the namespace (MLXModels, ConfigMap, client and
#         control Pods), the pushed tag, the remote scratch dirs; each step that
#         fails is named and fails the run
#   t.8   after f.1: `kubectl get ns` recorded, no leftover object of the run, both
#         nodes Ready, each Mac on the build t.0 recorded
#
# A green t.4 with a red t.5 is the failure this tracer exists to catch: a model served
# while the pod still reaches the internet proves nothing about the store.
#
# Free space is `df -k` Avail of the volume, and each reading carries a digest of
# `tmutil listlocalsnapshots` for that volume: two readings compare only when no local
# snapshot appeared or went between them, so snapshot-held blocks never count.
#
# `k3sm image prune --force` evicts every cached image no pod uses at that moment on
# that Mac, another workload's included; t.7 runs it because it is the one verb that
# returns node space.
#
# Environment (required under --lab):
#   KUBECONFIG                   the admin kubeconfig of the running cluster
#   K3SM_MST_SERVER_SSH          ssh destination of the server Mac (`local` runs here)
#   K3SM_MST_WORKER_SSH          ssh destination of the worker Mac (`local` runs here)
#   K3SM_MST_SERVER_NODE         the server's node name
#   K3SM_MST_WORKER_NODE         the worker's node name
#   K3SM_MST_SERVER_CACHE        absolute: the server node's runtimed cache root (holds
#                                blobs/, artifacts/, artifact-partial/)
#   K3SM_MST_WORKER_CACHE        absolute: the worker node's runtimed cache root
#   K3SM_MST_SERVER_WORK         absolute, absent: scratch on the server; removed by f.1
#   K3SM_MST_WORKER_WORK         absolute, absent: scratch on the worker; removed by f.1
# Optional:
#   K3SM_MST_REGISTRY_ROOT       the registry store on the server
#                                (default /var/lib/k3sm/server/registry)
#   K3SM_MST_K3SM                k3sm on the Macs (default /Library/k3sm/k3sm)
#   K3SM_MST_LOCAL_K3SM          k3sm on this host, for the push (default k3sm)
#   K3SM_MST_WORKER_LABEL        the worker's node daemon (default io.k3sm.agent)
#   K3SM_MST_MEMORY              spec.memory (default 4Gi)
#   K3SM_MST_IMAGE               spec.runtime.image (default: the examples/mlxmodel.yaml pin)
#   K3SM_MST_PORT                spec.port, matching the image (default 8000)
#   K3SM_MST_PYTHON              python in the serving image (default python3)
#   K3SM_MST_STEP_TIMEOUT        seconds for one remote or kubectl step (default 120, <=240)
#   K3SM_MST_READY_TIMEOUT       seconds for a model to come Ready (default 900)
#   K3SM_MST_RECLAIM_TIMEOUT     seconds t.7 waits for space to come back (default 240)
#   K3SM_MST_POLL                seconds between polls (default 2)
#   K3SM_MST_VIEW_UID            uid a view file must have (default 0)
#   KUBECTL                      kubectl binary (default kubectl)
#   K3SM_LAB_TOLERATE_KEYS       extra taint keys every pod tolerates with Exists
#
# Exit: 0 every rung held and the cleanup was clean; 1 a rung or the cleanup failed
# (the run log names it); 2 usage; 3 not run (K3SM_LAB unset or a p.0 refusal), the
# rig untouched.
#
# Usage:  <this script> --plan
#         <this script> --self-test
#         K3SM_LAB=1 <this script> --lab --model-dir DIR --model-sums FILE --evidence DIR
#             --model-sums: one `<sha256-hex>  <relative path>` line per file (shasum -a 256 form)
# shellcheck disable=SC2016 # the remote script texts expand on the remote side
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/$(basename "$0")"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh
. "$REPO_ROOT/hack/lab/lib/tolerations.sh"

GATE="model-store tracer"
REG_HOST="registry-k3sm:6450"
MOUNT="/var/lib/mlx/model"
EGRESS_ANNOTATION="k3sm.io/internet-egress"
GPU_LABEL="mlx.k3sm.io/gpu.present"
HUB_URL="https://huggingface.co"

RUNGS=(
	"p.0|preconditions, read-only; a refusal exits 3 with the rig untouched"
	"t.0|k3sm version on both Macs and the tree's commit; nodes; free-space baseline (caches, registry store)"
	"t.1|model push, then push again: same digest, zero bytes written to the registry"
	"t.2|one MLXModel per Mac on the one artifact (hostname-pinned, no egress, no cache)"
	"t.3|both Ready; resolvedArtifact = the pushed digest; image volume by digest, no PVC, no egress, no trust_remote_code; cold time, fetch rate, peak footprint vs spec.memory"
	"t.3b|kickstart the worker's node daemon mid-pull: the partial survives, the blob commits, the replica is Ready"
	"t.4|a client Pod on each Mac gets a non-empty completion from the other Mac's replica"
	"t.5|in-pod: no egress (control reaches it), write EPERM, exec fails; on each Mac one view of clones (inode, dev, blocks, 0444, root)"
	"t.6|three replicas, two on the server Mac: free-space drop under 1% of the model, same view; warm time"
	"t.7|delete, prune both Macs, model rm, registry prune: views gone, free space back within 1% on both caches and the registry store"
	"f.1|cleanup green or red: namespace, MLXModels, ConfigMap, Pods, the pushed tag, remote scratch"
	"t.8|kubectl get ns recorded; no leftover; both nodes Ready on the build t.0 recorded"
)

plan() {
	local row
	echo "$GATE: what a K3SM_LAB=1 --lab run does, in order (the first red rung stops the ladder; f.1 and t.8 always run)"
	for row in "${RUNGS[@]}"; do printf '  %-5s %s\n' "${row%%|*}" "${row#*|}"; done
}

# ---- pure helpers (the --self-test surface) ------------------------------------------

# bounded <secs> <cmd...>: the command, killed after secs. The watchdog takes its
# own sleep with it when it is stopped, so no step leaves a stray process behind.
bounded() {
	local secs="$1" pid watchdog rc=0
	shift
	"$@" <&0 &
	pid=$!
	(
		s=""
		trap '[ -z "$s" ] || kill "$s" 2>/dev/null; exit 0' TERM
		sleep "$secs" &
		s=$!
		wait "$s" && kill "$pid" 2>/dev/null
	) >/dev/null 2>&1 &
	watchdog=$!
	wait "$pid" || rc=$?
	kill "$watchdog" 2>/dev/null || true
	wait "$watchdog" 2>/dev/null || true
	return "$rc"
}

quoted() { printf '%q ' "$@"; }

# py <code> [args...]: isolated python.
py() {
	local code="$1"
	shift
	python3 -I -c "$code" "$@"
}

# verify_sums <dir> <sums-file>: the directory holds exactly the listed regular files,
# each with its listed sha256. Prints `<hex> <size> <relpath>` per file, largest last.
verify_sums() {
	py '
import hashlib, os, sys
root, sums = sys.argv[1], sys.argv[2]
want = {}
for n, line in enumerate(open(sums), 1):
    line = line.rstrip("\n")
    if not line.strip():
        continue
    parts = line.split(None, 1)
    if len(parts) != 2 or len(parts[0]) != 64 or any(c not in "0123456789abcdef" for c in parts[0]):
        sys.exit("sums line %d is not <sha256-hex>  <path>" % n)
    rel = parts[1].lstrip("*").strip()
    if rel in want or rel.startswith("/") or ".." in rel.split("/"):
        sys.exit("sums line %d: bad or repeated path %r" % (n, rel))
    want[rel] = parts[0]
if not want:
    sys.exit("the sums file lists no file")
have = {}
for d, dirs, files in os.walk(root):
    for f in files:
        p = os.path.join(d, f)
        if os.path.islink(p) or not os.path.isfile(p):
            sys.exit("not a regular file: %s" % os.path.relpath(p, root))
        have[os.path.relpath(p, root)] = p
extra = sorted(set(have) - set(want))
missing = sorted(set(want) - set(have))
if extra or missing:
    sys.exit("model dir and sums differ: extra %s, missing %s" % (extra, missing))
rows = []
for rel, hexd in want.items():
    h = hashlib.sha256()
    with open(have[rel], "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != hexd:
        sys.exit("sha256 mismatch: %s" % rel)
    rows.append((os.path.getsize(have[rel]), hexd, rel))
for size, hexd, rel in sorted(rows):
    print(hexd, size, rel)
' "$1" "$2"
}

# quantity_bytes <quantity>: a Kubernetes memory quantity in bytes.
quantity_bytes() {
	py '
import re, sys
m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(Ki|Mi|Gi|Ti|k|M|G|T)?", sys.argv[1])
if not m:
    sys.exit("bad quantity %r" % sys.argv[1])
mul = {None: 1, "Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12}[m.group(2)]
print(int(float(m.group(1)) * mul))
' "$1"
}

# footprint_bytes <footprint output file>: the peak footprint the tool reports
# (phys_footprint_peak), else its current footprint; empty when it names neither.
footprint_bytes() {
	py '
import re, sys
text = open(sys.argv[1]).read()
units = {"B": 1, "BYTES": 1, "KB": 1 << 10, "K": 1 << 10, "MB": 1 << 20, "M": 1 << 20, "GB": 1 << 30, "G": 1 << 30}
def find(pat):
    best = None
    for m in re.finditer(pat + r"\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)?", text, re.I):
        v = int(float(m.group(1)) * units.get((m.group(2) or "B").upper(), 1))
        best = v if best is None else max(best, v)
    return best
v = find(r"phys_footprint_peak")
if v is None:
    v = find(r"(?<![_a-z])footprint")
print("" if v is None else v)
' "$1"
}

# pod_checks <pods.json> <digest> <node> <count>: the rendered serving Pods hold.
pod_checks() {
	py '
import json, sys
f, dig, node, count, reg, egress = sys.argv[1:7]
items = json.load(open(f)).get("items", [])
errs = []
if len(items) != int(count):
    errs.append("%d serving pods, want %s" % (len(items), count))
for p in items:
    n, s = p["metadata"]["name"], p.get("spec", {})
    if s.get("nodeName") != node:
        errs.append("%s runs on %s, want %s" % (n, s.get("nodeName"), node))
    vols = s.get("volumes") or []
    imgs = [v for v in vols if "image" in v]
    if len(imgs) != 1:
        errs.append("%s has %d image volumes, want 1" % (n, len(imgs)))
    else:
        ref = imgs[0]["image"].get("reference", "")
        if not ref.startswith(reg + "/") or not ref.endswith("@" + dig):
            errs.append("%s image volume %r is not %s/...@%s" % (n, ref, reg, dig))
    if any("persistentVolumeClaim" in v for v in vols):
        errs.append("%s mounts a PVC" % n)
    if egress in (p["metadata"].get("annotations") or {}):
        errs.append("%s carries %s" % (n, egress))
    for c in s.get("containers") or []:
        argv = " ".join((c.get("command") or []) + (c.get("args") or []))
        if "trust_remote_code" in argv or "trust-remote-code" in argv:
            errs.append("%s passes trust_remote_code" % n)
    if not [c for c in p.get("status", {}).get("conditions", []) if c.get("type") == "Ready" and c.get("status") == "True"]:
        errs.append("%s is not Ready" % n)
print("\n".join(errs))
sys.exit(1 if errs else 0)
' "$1" "$2" "$3" "$4" "$REG_HOST" "$EGRESS_ANNOTATION"
}

# pod_times <pod.json>: `<ready-seconds> <fetch-window-seconds>`: creation to Ready,
# and PodScheduled to the container's start (the window holding the fetch).
pod_times() {
	py '
import datetime, json, sys
p = json.load(open(sys.argv[1]))
def t(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
cond = {c["type"]: c for c in p.get("status", {}).get("conditions", [])}
created = t(p["metadata"]["creationTimestamp"])
ready = t(cond["Ready"]["lastTransitionTime"])
# The node provider may publish PodScheduled without a transition time; then
# status.startTime (when the node accepted it) is that instant, then creation.
sched = t(cond.get("PodScheduled", {}).get("lastTransitionTime") or p["status"].get("startTime") or p["metadata"]["creationTimestamp"])
cs = p["status"]["containerStatuses"][0]
st = (cs.get("state", {}).get("running") or {}).get("startedAt") or (cs.get("lastState", {}).get("terminated") or {}).get("startedAt")
print(int(ready - created), int(t(st) - sched))
' "$1"
}

# view_checks <view lines> <uid>: one view of the manifest on the node, each file a
# clone of its blob: distinct inode, same device, same size and blocks, 0444, uid.
# A line is `VIEWS <n>` or `F <rel> <ino> <dev> <blocks> <size> <mode> <uid> | <ino> <dev> <blocks> <size>`.
view_checks() {
	py '
import sys
lines = [l.split() for l in open(sys.argv[1]) if l.strip()]
uid = sys.argv[2]
errs, files = [], 0
views = [l for l in lines if l[0] == "VIEWS"]
if not views:
    errs.append("no view of the manifest on the node")
elif views[0][1] != "1":
    errs.append("%s views of the manifest on the node, want 1" % views[0][1])
for l in lines:
    if l[0] != "F":
        continue
    files += 1
    rel = l[1]
    if "missing" in l or len(l) != 13:
        errs.append("%s: view file or blob missing" % rel)
        continue
    vino, vdev, vblk, vsize, vmode, vuid, _, bino, bdev, bblk, bsize = l[2:13]
    if vino == bino:
        errs.append("%s: the view file is the blob inode (a hardlink, not a clone)" % rel)
    if vdev != bdev:
        errs.append("%s: view and blob on different devices" % rel)
    if vsize != bsize or vblk != bblk:
        errs.append("%s: size/blocks %s/%s differ from the blob %s/%s" % (rel, vsize, vblk, bsize, bblk))
    if vmode != "444":
        errs.append("%s: mode %s, want 444" % (rel, vmode))
    if vuid != uid:
        errs.append("%s: uid %s, want %s" % (rel, vuid, uid))
if views and views[0][1] == "1" and files == 0:
    errs.append("the view lists no file")
print("\n".join(errs))
sys.exit(1 if errs else 0)
' "$1" "$2"
}

# view_inodes <view lines>: `<rel> <ino>` per file, for comparing two readings.
view_inodes() { awk '$1 == "F" { print $2, $3 }' "$1"; }

# within <a-kb> <b-kb> <tolerance-bytes>: |a-b| KiB is within the tolerance.
within() {
	local d=$((($1 - $2) * 1024))
	[ "$d" -lt 0 ] && d=$((-d))
	[ "$d" -le "$3" ]
}

# ---- run state ------------------------------------------------------------------------

STEP_TIMEOUT="${K3SM_MST_STEP_TIMEOUT:-120}"
READY_TIMEOUT="${K3SM_MST_READY_TIMEOUT:-900}"
RECLAIM_TIMEOUT="${K3SM_MST_RECLAIM_TIMEOUT:-240}"
POLL="${K3SM_MST_POLL:-2}"
K3SM_BIN="${K3SM_MST_K3SM:-/Library/k3sm/k3sm}"
LOCAL_K3SM="${K3SM_MST_LOCAL_K3SM:-k3sm}"
WORKER_LABEL="${K3SM_MST_WORKER_LABEL:-io.k3sm.agent}"
MEMORY="${K3SM_MST_MEMORY:-4Gi}"
# The operator ships no default serving image, so the run names one; the default is the
# pin examples/mlxmodel.yaml carries, and the port must agree with it.
IMAGE="${K3SM_MST_IMAGE:-ghcr.io/k3sm-io/mlx-serve:0.5.0-k3sm.5@sha256:a225253effc92f5f5ff8ec2ec2e2f8894aa690a3d6a908bb879439de6733d0e8}"
PORT="${K3SM_MST_PORT:-8000}"
# The serving image's interpreter is the Mach-O itself: a native pod runs argv[0] as a
# path inside the image root (no PATH search), and the runtime signs only a regular file,
# never the /bin/python3 symlink.
PYBIN="${K3SM_MST_PYTHON:-/bin/python3.12}"
VIEW_UID="${K3SM_MST_VIEW_UID:-0}"
REG_ROOT="${K3SM_MST_REGISTRY_ROOT:-/var/lib/k3sm/server/registry}"
KUBECTL="${KUBECTL:-kubectl}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

SERVER="" WORKER="" SNODE="" WNODE="" SCACHE="" WCACHE="" SWORK="" WWORK=""
MODEL_DIR="" MODEL_SUMS="" EV=""
RUN="" NS="" REPO="" TAG="" MA="" MB=""
FILES="" MODEL_BYTES=0 BIG_HEX="" BIG_SIZE=0 DIGEST="" MHEX="" TOL=0
TOUCHED=0 NS_MADE=0 PUSHED=0 TAG_REMOVED=0 WORK_MADE=0 WATCH_PID=""
SHOST_LABEL="" WHOST_LABEL="" SIMG="" FAILED="" REACHED=""
BASE_S="" BASE_W="" BASE_R="" VER_S="" VER_W=""

log() { echo "[mst] $*"; }
# bad <why>: a rung's reason, to its log and the run's reason file.
bad() {
	echo "FAIL: $*" >&2
	printf '%s\n' "$*" >>"$EV/reasons"
}
measure() { printf '%s\t%s\n' "$1" "$2" >>"$EV/measurements.tsv"; }
record() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >>"$EV/result.tsv"; }

kc() { bounded "$STEP_TIMEOUT" "$KUBECTL" "$@"; }

# rsh_raw <host> <shell-text>: shell text on the host, ssh's or local.
rsh_raw() {
	if [ "$1" = local ]; then
		/bin/bash -c "$2"
	else
		# shellcheck disable=SC2029 # the text is built here, quoted
		ssh "${SSH_OPTS[@]}" "$1" "$2"
	fi
}
# rsh <host> <args...>: one command on the host, bounded.
rsh() {
	local h="$1"
	shift
	bounded "$STEP_TIMEOUT" rsh_raw "$h" "$(quoted "$@")"
}
# ku <host> <args...>: k3sm on the host, as root.
ku() {
	local h="$1"
	shift
	rsh "$h" sudo -n "$K3SM_BIN" "$@"
}
# rroot <host> <bound> <script-text> [args...]: one bash script as root on the host;
# the whole text runs under sudo, never just its first command.
rroot() {
	local h="$1" b="$2" text="$3"
	shift 3
	bounded "$b" rsh_raw "$h" "sudo -n /bin/bash -c $(printf '%q' "$text") mst $(quoted "$@")"
}

# df_read <host> <path>: `<avail-KiB> <snapshot-digest>` of the path's volume.
DF_SCRIPT='
p="$1"
line="$(df -k "$p" | awk "NR==2")" || exit 1
avail="$(printf "%s\n" "$line" | awk "{print \$4}")"
mnt="$(printf "%s\n" "$line" | awk "{print \$NF}")"
snap="$(tmutil listlocalsnapshots "$mnt" 2>/dev/null | shasum -a 256 | cut -c1-16)"
echo "$avail $snap"
'
df_read() { rroot "$1" "$STEP_TIMEOUT" "$DF_SCRIPT" "$2"; }

# df_back <base> <now> <what>: comparable (same snapshot set) and within TOL.
df_back() {
	local b_kb="${1% *}" b_snap="${1#* }" n_kb="${2% *}" n_snap="${2#* }"
	[ "$b_snap" = "$n_snap" ] || { bad "$3: a local snapshot appeared or went between readings; free space is not comparable"; return 2; }
	within "$b_kb" "$n_kb" "$TOL"
}

# VIEW_SCRIPT <cache> <manifest-hex> <hex:rel...>: the node's view lines.
VIEW_SCRIPT='
cache="$1"; mhex="$2"; shift 2
d="$cache/artifacts/$mhex"
[ -d "$d" ] || { echo "VIEWS 0"; exit 0; }
n=0; v=""
for e in "$d"/*; do [ -e "$e" ] || continue; n=$((n+1)); v="$e"; done
echo "VIEWS $n"
[ "$n" = 1 ] || exit 0
for pair in "$@"; do
	hex="${pair%%:*}"; rel="${pair#*:}"
	vs="$(stat -f "%i %d %b %z %Lp %u" "$v/$rel" 2>/dev/null || echo missing)"
	bs="$(stat -f "%i %d %b %z" "$cache/blobs/sha256/$hex" 2>/dev/null || echo missing)"
	echo "F $rel $vs | $bs"
done
'
view_read() {
	local h="$1" cache="$2" out="$3" pairs=() hex rel
	while read -r hex _ rel; do pairs+=("$hex:$rel"); done <<<"$FILES"
	rroot "$h" "$STEP_TIMEOUT" "$VIEW_SCRIPT" "$cache" "$MHEX" "${pairs[@]}" >"$out"
}

# The t.3b watcher, on the worker as root: waits for the big blob's partial, then
# kickstarts the node daemon and reads the partial again.
WATCH_SCRIPT='
cache="$1"; hex="$2"; size="$3"; label="$4"; bound="$5"; poll="$6"; work="$7"
p="$cache/artifact-partial/sha256-$hex.partial"
end=$(( $(date +%s) + bound ))
while :; do
	if [ -f "$p" ]; then
		s="$(stat -f %z "$p" 2>/dev/null || echo 0)"
		if [ "$s" -gt 0 ] && [ "$s" -lt "$size" ]; then break; fi
	fi
	[ ! -e "$cache/blobs/sha256/$hex" ] || { echo "MISSED the blob was committed before a partial was seen"; exit 0; }
	[ "$(date +%s)" -lt "$end" ] || { echo "MISSED no partial within the bound"; exit 0; }
	[ -d "$work" ] || { echo "MISSED stopped: the scratch dir is gone"; exit 0; }
	sleep "$poll"
done
pid0="$(launchctl print "system/$label" | awk "/^[[:space:]]*pid = /{print \$3; exit}")"
ino0="$(stat -f %i "$p")"
echo "BEFORE $s $ino0 ${pid0:-none}"
launchctl kickstart -k "system/$label"
echo "KICK $?"
if [ -f "$p" ]; then echo "AFTER $(stat -f "%z %i" "$p")"; elif [ -e "$cache/blobs/sha256/$hex" ]; then echo "AFTER committed"; else echo "AFTER gone"; fi
'

# ---- p.0 ------------------------------------------------------------------------------

refuse() {
	echo "$GATE: NOT RUN (p.0): $*" >&2
	exit 3
}

p0() {
	local v n json t left
	for v in KUBECONFIG K3SM_MST_SERVER_SSH K3SM_MST_WORKER_SSH K3SM_MST_SERVER_NODE K3SM_MST_WORKER_NODE \
		K3SM_MST_SERVER_CACHE K3SM_MST_WORKER_CACHE K3SM_MST_SERVER_WORK K3SM_MST_WORKER_WORK; do
		[ -n "${!v:-}" ] || refuse "$v is not set"
	done
	SERVER="$K3SM_MST_SERVER_SSH" WORKER="$K3SM_MST_WORKER_SSH"
	SNODE="$K3SM_MST_SERVER_NODE" WNODE="$K3SM_MST_WORKER_NODE"
	SCACHE="$K3SM_MST_SERVER_CACHE" WCACHE="$K3SM_MST_WORKER_CACHE"
	SWORK="$K3SM_MST_SERVER_WORK" WWORK="$K3SM_MST_WORKER_WORK"
	for v in "$SCACHE" "$WCACHE" "$SWORK" "$WWORK" "$REG_ROOT"; do
		case "$v" in /?*) ;; *) refuse "$v is not an absolute path" ;; esac
	done
	[ "$SWORK" != "$WWORK" ] || [ "$SERVER" != "$WORKER" ] || refuse "the two scratch dirs are one directory"
	case "$STEP_TIMEOUT$READY_TIMEOUT$RECLAIM_TIMEOUT" in *[!0-9]*) refuse "a timeout is not a whole number of seconds" ;; esac
	[ "$STEP_TIMEOUT" -le 240 ] || refuse "K3SM_MST_STEP_TIMEOUT is over 240"
	for t in python3 shasum awk "$KUBECTL" "$LOCAL_K3SM"; do command -v "$t" >/dev/null 2>&1 || refuse "$t is not on PATH"; done
	TOLERATIONS="$(lab_tolerations_json NoSchedule)" || exit 2

	# The evidence dir: absent, or present and empty.
	[ -n "$EV" ] || refuse "--evidence is required"
	if [ -e "$EV" ]; then
		[ -d "$EV" ] || refuse "$EV is not a directory"
		[ -z "$(ls -A "$EV")" ] || refuse "evidence dir $EV is not empty"
	fi
	mkdir -p "$EV" || refuse "cannot create $EV"
	EV="$(cd "$EV" && pwd)"

	# The model, before anything is pushed.
	[ -d "$MODEL_DIR" ] || refuse "--model-dir $MODEL_DIR is not a directory"
	[ -f "$MODEL_SUMS" ] || refuse "--model-sums $MODEL_SUMS is not a file"
	FILES="$(verify_sums "$MODEL_DIR" "$MODEL_SUMS" 2>"$EV/p.0.sums.err")" || refuse "model dir: $(cat "$EV/p.0.sums.err")"
	printf '%s\n' "$FILES" >"$EV/model-files.txt"
	MODEL_BYTES="$(awk '{s += $2} END {print s + 0}' <<<"$FILES")"
	BIG_HEX="$(tail -n 1 <<<"$FILES" | awk '{print $1}')"
	BIG_SIZE="$(tail -n 1 <<<"$FILES" | awk '{print $2}')"
	TOL=$((MODEL_BYTES / 100))
	quantity_bytes "$MEMORY" >/dev/null || refuse "K3SM_MST_MEMORY $MEMORY is not a quantity"

	# The cluster, read-only.
	kc get --raw /healthz >/dev/null 2>&1 || refuse "the cluster at \$KUBECONFIG is not serving"
	for n in "$SNODE" "$WNODE"; do
		json="$(kc get node "$n" -o json 2>/dev/null)" || refuse "node $n is absent"
		v="$(py 'import json,sys; d=json.loads(sys.stdin.read()); c=[x["status"] for x in d["status"]["conditions"] if x["type"]=="Ready"]; l=d["metadata"].get("labels",{}); print(c[0] if c else "", l.get(sys.argv[1],""), l.get("kubernetes.io/hostname",""))' "$GPU_LABEL" <<<"$json")"
		# shellcheck disable=SC2086 # split on purpose
		set -- $v
		[ "${1:-}" = True ] || refuse "node $n is not Ready"
		[ "${2:-}" = true ] || refuse "node $n lacks $GPU_LABEL=true"
		[ -n "${3:-}" ] || refuse "node $n has no kubernetes.io/hostname label"
		if [ "$n" = "$SNODE" ]; then SHOST_LABEL="$3"; else WHOST_LABEL="$3"; fi
		left="$(py '
import json, sys
keys = set(sys.argv[1].split()) | {"k3sm.io/provider"}
d = json.loads(sys.stdin.read())
print(" ".join(t["key"] for t in d["spec"].get("taints", []) or [] if t.get("effect") != "PreferNoSchedule" and t["key"] not in keys))
' "$(lab_tol_keys)" <<<"$json")"
		[ -z "$left" ] || refuse "node $n carries taint key(s) this run does not tolerate: $left (name them in K3SM_LAB_TOLERATE_KEYS)"
	done
	json="$(kc get crd mlxmodels.mlx.k3sm.io -o json 2>/dev/null)" || refuse "the MLXModel CRD is absent"
	case "$json" in *'"artifact"'*'"resolvedArtifact"'* | *'"resolvedArtifact"'*'"artifact"'*) ;; *) refuse "the MLXModel CRD lacks spec.artifact or status.resolvedArtifact" ;; esac

	# The Macs, read-only: reachable, the caches there, cold for this model, scratch absent.
	for v in "$SERVER|$SCACHE|$SWORK" "$WORKER|$WCACHE|$WWORK"; do
		IFS='|' read -r n t left <<<"$v"
		rroot "$n" "$STEP_TIMEOUT" '[ -d "$1/blobs" ] && [ ! -e "$2" ]' "$t" "$left" ||
			refuse "on $n: $t/blobs is not a directory, $left already exists, or root is not available"
		# shellcheck disable=SC2046 # one argument per hash
		rroot "$n" "$STEP_TIMEOUT" 'c="$1"; shift; for h in "$@"; do [ ! -e "$c/blobs/sha256/$h" ] || exit 1; done' "$t" $(awk '{print $1}' <<<"$FILES") ||
			refuse "on $n: the node cache already holds a blob of this model; the cold rung needs it gone (k3sm image prune)"
	done
	rroot "$SERVER" "$STEP_TIMEOUT" '[ -d "$1" ]' "$REG_ROOT" || refuse "the registry store $REG_ROOT is not on the server"
}

# ---- rungs ----------------------------------------------------------------------------

t0() {
	VER_S="$(ku "$SERVER" version 2>&1)" || { bad "k3sm version on the server: $VER_S"; return 1; }
	VER_W="$(ku "$WORKER" version 2>&1)" || { bad "k3sm version on the worker: $VER_W"; return 1; }
	printf 'server: %s\nworker: %s\ntree: %s\n' "$VER_S" "$VER_W" "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" | tee "$EV/t.0.versions"
	kc get nodes -o wide >"$EV/t.0.nodes" 2>&1 || { bad "kubectl get nodes"; return 1; }
	BASE_S="$(df_read "$SERVER" "$SCACHE")" || { bad "free space of the server cache"; return 1; }
	BASE_W="$(df_read "$WORKER" "$WCACHE")" || { bad "free space of the worker cache"; return 1; }
	BASE_R="$(df_read "$SERVER" "$REG_ROOT")" || { bad "free space of the registry store"; return 1; }
	measure t0_server_cache_avail_kib "${BASE_S% *}"
	measure t0_worker_cache_avail_kib "${BASE_W% *}"
	measure t0_registry_avail_kib "${BASE_R% *}"
}

REPO_LS='d="$1/$2/blobs/sha256"; [ -d "$d" ] || exit 1; cd "$d" && for f in *; do stat -f "%N %i %z %m" "$f"; done'

t1() {
	local out1 out2 d2 ls1 ls2
	TOUCHED=1
	out1="$(bounded "$((STEP_TIMEOUT * 2))" "$LOCAL_K3SM" model push "$MODEL_DIR" "$TAG" 2>&1)" || { bad "model push: $out1"; return 1; }
	PUSHED=1
	echo "$out1"
	DIGEST="$(awk '$1 == "digest:" {print $2}' <<<"$out1")"
	case "$DIGEST" in sha256:????????????????????????????????????????????????????????????????) ;; *) bad "model push printed no digest"; return 1 ;; esac
	MHEX="${DIGEST#sha256:}"
	ls1="$(rroot "$SERVER" "$STEP_TIMEOUT" "$REPO_LS" "$REG_ROOT" "models/$REPO")" || { bad "the registry holds no blobs for models/$REPO"; return 1; }
	out2="$(bounded "$((STEP_TIMEOUT * 2))" "$LOCAL_K3SM" model push "$MODEL_DIR" "$TAG" 2>&1)" || { bad "second model push: $out2"; return 1; }
	echo "$out2"
	d2="$(awk '$1 == "digest:" {print $2}' <<<"$out2")"
	[ "$d2" = "$DIGEST" ] || { bad "the second push returned $d2, the first $DIGEST"; return 1; }
	ls2="$(rroot "$SERVER" "$STEP_TIMEOUT" "$REPO_LS" "$REG_ROOT" "models/$REPO")" || { bad "registry listing after the second push"; return 1; }
	printf '%s\n' "$ls1" >"$EV/t.1.registry-before"
	printf '%s\n' "$ls2" >"$EV/t.1.registry-after"
	# Name, inode and size: the registry refreshes a blob's mtime on access to keep it inside
	# the GC grace, so a changed mtime is not a write. A rewrite shows as a new inode or size.
	[ "$(awk '{print $1, $2, $3}' <<<"$ls1")" = "$(awk '{print $1, $2, $3}' <<<"$ls2")" ] ||
		{ bad "the second push changed the registry's blob files for models/$REPO (it wrote bytes)"; return 1; }
	measure t1_digest "$DIGEST"
	measure model_bytes "$MODEL_BYTES"
}

mlxmodel_json() { # <name> <hostname-label> <replicas>
	cat <<JSON
{"apiVersion":"mlx.k3sm.io/v1alpha1","kind":"MLXModel","metadata":{"name":"$1","namespace":"$NS"},
 "spec":{"artifact":{"reference":"$REG_HOST/models/$REPO:v1"},"memory":"$MEMORY","replicas":$3,
  "port":$PORT,"runtime":{"image":"$IMAGE"},
  "nodeSelector":{"kubernetes.io/hostname":"$2","kubernetes.io/os":"darwin"}}}
JSON
}

t2() {
	local out
	out="$(kc create namespace "$NS" 2>&1)" || { bad "create namespace: $out"; return 1; }
	NS_MADE=1
	rroot "$WORKER" "$STEP_TIMEOUT" 'mkdir -p "$1" && chmod 700 "$1"' "$WWORK" || { bad "make the worker scratch"; return 1; }
	rroot "$SERVER" "$STEP_TIMEOUT" 'mkdir -p "$1" && chmod 700 "$1"' "$SWORK" || { bad "make the server scratch"; return 1; }
	WORK_MADE=1
	bounded "$((READY_TIMEOUT + 60))" rsh_raw "$WORKER" "sudo -n /bin/bash -c $(printf '%q' "$WATCH_SCRIPT") mst $(quoted "$WCACHE" "$BIG_HEX" "$BIG_SIZE" "$WORKER_LABEL" "$READY_TIMEOUT" "$POLL" "$WWORK")" >"$EV/t.3b.watch" 2>&1 &
	WATCH_PID=$!
	mlxmodel_json "$MA" "$SHOST_LABEL" 1 >"$EV/t.2.$MA.json"
	mlxmodel_json "$MB" "$WHOST_LABEL" 1 >"$EV/t.2.$MB.json"
	out="$(kc apply -f - <"$EV/t.2.$MA.json" 2>&1)" || { bad "apply $MA: $out"; return 1; }
	out="$(kc apply -f - <"$EV/t.2.$MB.json" 2>&1)" || { bad "apply $MB: $out"; return 1; }
}

# sample_fp: the server replica's serving processes' footprint, the largest seen.
FP_MAX=0
FP_SCRIPT='for pid in $(pgrep -f -- "--served-model-name $1( |$)"); do footprint "$pid" 2>/dev/null; done'
sample_fp() {
	local f="$EV/t.3.footprint" v
	rroot "$SERVER" "$STEP_TIMEOUT" "$FP_SCRIPT" "$MA" >"$f" 2>/dev/null || return 0
	v="$(footprint_bytes "$f")"
	[ -z "$v" ] || [ "$v" -le "$FP_MAX" ] || FP_MAX="$v"
}

# wait_ready <model> <replicas> [sample]: the model Ready with that many replicas.
wait_ready() {
	local m="$1" want="$2" end i=0 st last=""
	end=$(($(date +%s) + READY_TIMEOUT))
	while :; do
		st="$(kc get mlxmodel "$m" -n "$NS" -o json 2>/dev/null | py 'import json,sys; s=json.loads(sys.stdin.read()).get("status",{}); print(s.get("phase",""), s.get("readyReplicas",0))' 2>/dev/null || true)"
		[ -z "${3:-}" ] || sample_fp "$i"
		[ "$st" = "${last:-}" ] || { printf '%s %s\n' "$(date +%s)" "${st:-none}" >>"$EV/wait.$m.trail"; last="$st"; }
		[ "$st" != "Ready $want" ] || return 0
		[ "$(date +%s)" -lt "$end" ] || { bad "$m not Ready with $want replicas in ${READY_TIMEOUT}s (last: ${st:-none})"; return 1; }
		i=$((i + 1))
		sleep "$POLL"
	done
}

t3() {
	local m node r mem why times p
	wait_ready "$MA" 1 sample || return 1
	wait_ready "$MB" 1 || return 1
	for m in "$MA" "$MB"; do
		kc get mlxmodel "$m" -n "$NS" -o json >"$EV/t.3.$m.mlxmodel.json" || { bad "read $m"; return 1; }
		r="$(py 'import json,sys; print(json.load(open(sys.argv[1])).get("status",{}).get("resolvedArtifact",""))' "$EV/t.3.$m.mlxmodel.json")"
		[ "$r" = "$DIGEST" ] || { bad "$m status.resolvedArtifact $r, want $DIGEST"; return 1; }
		node="$SNODE"
		[ "$m" = "$MA" ] || node="$WNODE"
		kc get pods -n "$NS" -l "app.kubernetes.io/instance=$m" -o json >"$EV/t.3.$m.pods.json" || { bad "read $m pods"; return 1; }
		why="$(pod_checks "$EV/t.3.$m.pods.json" "$DIGEST" "$node" 1)" || {
			kc logs -n "$NS" -l "app.kubernetes.io/instance=$m" --tail=200 >"$EV/t.3.$m.logs" 2>&1 || true
			kc get events -n "$NS" -o wide >"$EV/t.3.events" 2>&1 || true
			bad "$m: $why"
			return 1
		}
	done
	[ -z "$(kc get pvc -n "$NS" -o name 2>/dev/null)" ] || { bad "the namespace holds a PVC"; return 1; }
	p="$(py 'import json,sys; print(json.load(open(sys.argv[1]))["items"][0]["metadata"]["name"])' "$EV/t.3.$MA.pods.json")"
	kc get pod "$p" -n "$NS" -o json >"$EV/t.3.cold-pod.json" || { bad "read $p"; return 1; }
	times="$(pod_times "$EV/t.3.cold-pod.json")" || { bad "the cold pod has no Ready or start time"; return 1; }
	measure cold_ready_seconds "${times% *}"
	measure cold_fetch_window_seconds "${times#* }"
	measure cold_fetch_bytes_per_second "$((MODEL_BYTES / (${times#* } > 0 ? ${times#* } : 1)))"
	SIMG="$(py 'import json,sys; print(json.load(open(sys.argv[1]))["spec"]["containers"][0]["image"])' "$EV/t.3.cold-pod.json")"
	sample_fp final
	mem="$(quantity_bytes "$MEMORY")"
	[ "$FP_MAX" -gt 0 ] || { bad "no footprint of the serving process could be read"; return 1; }
	measure peak_footprint_bytes "$FP_MAX"
	measure spec_memory_bytes "$mem"
	measure peak_footprint_over_spec_memory "$(py 'import sys; print("%.3f" % (int(sys.argv[1]) / int(sys.argv[2])))' "$FP_MAX" "$mem")"
}

t3b() {
	local before after kick pid1 sum _rc=0
	[ -n "$WATCH_PID" ] && { wait "$WATCH_PID" || _rc=$?; }
	WATCH_PID=""
	cat "$EV/t.3b.watch"
	grep -q '^MISSED' "$EV/t.3b.watch" && { bad "watcher: $(grep '^MISSED' "$EV/t.3b.watch" | cut -c8-) (the kickstart never landed during a pull)"; return 1; }
	before="$(awk '$1 == "BEFORE" {print $2, $3, $4}' "$EV/t.3b.watch")"
	kick="$(awk '$1 == "KICK" {print $2}' "$EV/t.3b.watch")"
	after="$(awk '$1 == "AFTER" {$1 = ""; print substr($0, 2)}' "$EV/t.3b.watch")"
	[ -n "$before" ] || { bad "the watcher saw no partial (exit $_rc)"; return 1; }
	[ "$kick" = 0 ] || { bad "launchctl kickstart -k system/$WORKER_LABEL exited ${kick:-unknown}"; return 1; }
	# shellcheck disable=SC2086 # split on purpose
	set -- $before
	measure t3b_partial_bytes_at_kick "$1"
	case "$after" in
	committed | gone | "") bad "after the restart the partial was '$after': its survival is unobserved"; return 1 ;;
	esac
	measure t3b_partial_bytes_after_kick "${after% *}"
	[ "${after% *}" -ge "$1" ] || { bad "the partial shrank across the restart (${after% *} < $1): the pull restarted"; return 1; }
	[ "${after#* }" = "$2" ] || { bad "the partial is a new file after the restart"; return 1; }
	pid1="$(rroot "$WORKER" "$STEP_TIMEOUT" 'launchctl print "system/$1" | awk "/^[[:space:]]*pid = /{print \$3; exit}"' "$WORKER_LABEL")" || true
	[ -n "$pid1" ] && [ "$pid1" != "$3" ] || { bad "the node daemon's pid did not change ($3 -> ${pid1:-none})"; return 1; }
	sum="$(rroot "$WORKER" "$STEP_TIMEOUT" 'shasum -a 256 "$1/blobs/sha256/$2" | cut -d" " -f1; [ ! -e "$1/artifact-partial/sha256-$2.partial" ] || echo partial-left' "$WCACHE" "$BIG_HEX")" || true
	[ "$sum" = "$BIG_HEX" ] || { bad "after the resumed pull the worker's blob is not $BIG_HEX (got: $sum)"; return 1; }
	wait_ready "$MB" 1 || return 1
}

CLIENT_PY='import json, sys, time, urllib.request
url, model = sys.argv[1], sys.argv[2]
body = json.dumps({"model": model, "messages": [{"role": "user", "content": "Say hello."}], "max_tokens": 16}).encode()
end, err = time.time() + 120, ""
while time.time() < end:
    try:
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        d = json.loads(urllib.request.urlopen(req, timeout=60).read())
        text = (d["choices"][0]["message"].get("content") or "").strip()
        print("COMPLETION-OK %d" % len(text) if text else "COMPLETION-EMPTY")
        sys.exit(0 if text else 1)
    except Exception as e:
        err = repr(e)
        time.sleep(3)
print("COMPLETION-ERROR " + err)
sys.exit(1)
'
EGRESS_PY='import sys, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=15)
    print("EGRESS-REACHED")
except Exception as e:
    print("EGRESS-BLOCKED " + type(e).__name__)
    sys.exit(1)
'

pod_json() { # <name> <node> <args-json> [annotations-json]
	local ann="${4:-}"
	[ -n "$ann" ] || ann='{}'
	cat <<JSON
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"$1","namespace":"$NS","annotations":$ann},
 "spec":{"nodeName":"$2","nodeSelector":{"kubernetes.io/os":"darwin"},"restartPolicy":"Never",
  "tolerations":[$TOLERATIONS],
  "containers":[{"name":"probe","image":"$SIMG","command":$3,"volumeMounts":[{"name":"probe","mountPath":"/probe"}]}],
  "volumes":[{"name":"probe","configMap":{"name":"mst-probe"}}]}}
JSON
}

# wait_done <pod>: the pod Succeeded or Failed; echoes the phase.
wait_done() {
	local end ph
	end=$(($(date +%s) + READY_TIMEOUT))
	while :; do
		ph="$(kc get pod "$1" -n "$NS" -o json 2>/dev/null | py 'import json,sys; print(json.loads(sys.stdin.read()).get("status",{}).get("phase",""))' 2>/dev/null || true)"
		case "$ph" in Succeeded | Failed) echo "$ph"; return 0 ;; esac
		[ "$(date +%s)" -lt "$end" ] || { echo "timeout:${ph:-none}"; return 1; }
		sleep "$POLL"
	done
}

svc_url() { # <model>
	local port
	port="$(kc get svc "$1" -n "$NS" -o json | py 'import json,sys; print(json.loads(sys.stdin.read())["spec"]["ports"][0]["port"])')" || return 1
	echo "http://$1.$NS.svc:$port/v1/chat/completions"
}

t4() {
	local cm out url pod node m ph logs
	cm="$(py 'import json,sys; print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"mst-probe","namespace":sys.argv[1]},"data":{"client.py":sys.argv[2],"egress.py":sys.argv[3]}}))' "$NS" "$CLIENT_PY" "$EGRESS_PY")"
	out="$(kc apply -f - <<<"$cm" 2>&1)" || { bad "apply the probe ConfigMap: $out"; return 1; }
	for pod in "mst-client-w|$WNODE|$MA" "mst-client-s|$SNODE|$MB"; do
		IFS='|' read -r pod node m <<<"$pod"
		url="$(svc_url "$m")" || { bad "no Service for $m"; return 1; }
		pod_json "$pod" "$node" "[\"$PYBIN\",\"/probe/client.py\",\"$url\",\"$m\"]" >"$EV/t.4.$pod.json"
		out="$(kc apply -f - <"$EV/t.4.$pod.json" 2>&1)" || { bad "apply $pod: $out"; return 1; }
	done
	for pod in "mst-client-w|$MA" "mst-client-s|$MB"; do
		m="${pod#*|}" pod="${pod%|*}"
		ph="$(wait_done "$pod")" || { bad "$pod did not finish ($ph)"; return 1; }
		logs="$(kc logs "$pod" -n "$NS" 2>&1 || true)"
		printf '%s\n' "$logs" >"$EV/t.4.$pod.log"
		case "$logs" in *COMPLETION-OK*) ;; *) bad "$pod -> $m: no non-empty completion ($ph: $(tail -n 1 <<<"$logs"))"; return 1 ;; esac
	done
}

PROBE_WRITE='import sys
try:
    open(sys.argv[1], "ab").close()
    print("WRITE-OK")
except OSError as e:
    print("WRITE-ERRNO %d" % e.errno)
'
PROBE_EXEC='import os, sys
try:
    os.execv(sys.argv[1], [sys.argv[1]])
except OSError as e:
    print("EXEC-ERRNO %d" % e.errno)
'
PROBE_COPYRUN='import os, subprocess, tempfile
d = tempfile.mkdtemp()
p = os.path.join(d, "copied")
open(p, "w").write("#!/bin/sh\necho ran\n")
os.chmod(p, 0o755)
try:
    print("COPYRUN-RAN" if subprocess.run([p], capture_output=True, text=True).stdout.strip() == "ran" else "COPYRUN-DENIED")
except OSError as e:
    print("COPYRUN-DENIED %d" % e.errno)
'

t5() {
	local m pod node out first ph logs h cache errno
	first="$(head -n 1 <<<"$FILES" | awk '{print $3}')"
	pod_json mst-egress-control "$SNODE" "[\"$PYBIN\",\"/probe/egress.py\",\"$HUB_URL\"]" "{\"$EGRESS_ANNOTATION\":\"true\"}" >"$EV/t.5.control.json"
	out="$(kc apply -f - <"$EV/t.5.control.json" 2>&1)" || { bad "apply the egress control: $out"; return 1; }
	for m in "$MA" "$MB"; do
		pod="$m-0"
		out="$(kc exec -n "$NS" "$pod" -- "$PYBIN" -c "$EGRESS_PY" "$HUB_URL" 2>&1 || true)"
		printf '%s\n' "$out" >"$EV/t.5.$pod.egress"
		case "$out" in *EGRESS-BLOCKED*) ;; *) bad "$pod reaches $HUB_URL (egress is on): $(tail -n 1 <<<"$out")"; return 1 ;; esac
		out="$(kc exec -n "$NS" "$pod" -- "$PYBIN" -c "$PROBE_WRITE" "$MOUNT/$first" 2>&1 || true)"
		printf '%s\n' "$out" >"$EV/t.5.$pod.write"
		errno="$(awk '$1 == "WRITE-ERRNO" {print $2}' <<<"$out")"
		[ "$errno" = 1 ] || { bad "$pod: a write to $MOUNT/$first did not fail with EPERM: $(tail -n 1 <<<"$out")"; return 1; }
		out="$(kc exec -n "$NS" "$pod" -- "$PYBIN" -c "$PROBE_EXEC" "$MOUNT/$first" 2>&1 || true)"
		printf '%s\n' "$out" >"$EV/t.5.$pod.exec"
		errno="$(awk '$1 == "EXEC-ERRNO" {print $2}' <<<"$out")"
		case "$errno" in
		1) measure "t5_${m}_exec_denied_by" "profile (EPERM)" ;;
		13) measure "t5_${m}_exec_denied_by" "mode (EACCES)" ;;
		[0-9]*) measure "t5_${m}_exec_denied_by" "errno $errno" ;;
		*) bad "$pod: an exec of $MOUNT/$first did not fail: $(tail -n 1 <<<"$out")"; return 1 ;;
		esac
		out="$(kc exec -n "$NS" "$pod" -- "$PYBIN" -c "$PROBE_COPYRUN" 2>&1 || true)"
		printf '%s\n' "$out" >"$EV/t.5.$pod.copyrun"
		measure "t5_${m}_copied_chmod_x_file" "$(grep -o 'COPYRUN-[A-Z]*' <<<"$out" | head -n 1 || echo unread)"
	done
	ph="$(wait_done mst-egress-control)" || { bad "the egress control did not finish ($ph)"; return 1; }
	logs="$(kc logs mst-egress-control -n "$NS" 2>&1 || true)"
	printf '%s\n' "$logs" >"$EV/t.5.control.log"
	case "$logs" in *EGRESS-REACHED*) ;; *) bad "the control Pod with $EGRESS_ANNOTATION cannot reach $HUB_URL either, so the negative proves nothing"; return 1 ;; esac
	for h in "$SERVER|$SCACHE|s" "$WORKER|$WCACHE|w"; do
		IFS='|' read -r h cache node <<<"$h"
		view_read "$h" "$cache" "$EV/t.5.view.$node" || { bad "read the view on $h"; return 1; }
		out="$(view_checks "$EV/t.5.view.$node" "$VIEW_UID")" || { bad "view on $h: $out"; return 1; }
	done
}

t6() {
	local d0 d1 p times out
	d0="$(df_read "$SERVER" "$SCACHE")" || { bad "free space before the scale"; return 1; }
	out="$(kc patch mlxmodel "$MA" -n "$NS" --type merge -p '{"spec":{"replicas":2}}' 2>&1)" || { bad "scale $MA: $out"; return 1; }
	wait_ready "$MA" 2 || return 1
	d1="$(df_read "$SERVER" "$SCACHE")" || { bad "free space after the scale"; return 1; }
	measure t6_server_avail_drop_bytes "$(((${d0% *} - ${d1% *}) * 1024))"
	df_back "$d0" "$d1" "t.6" || { [ $? = 2 ] || bad "the server's free space dropped by $(((${d0% *} - ${d1% *}) * 1024)) bytes for a second replica, over 1% of the model ($TOL)"; return 1; }
	kc get pods -n "$NS" -l "app.kubernetes.io/instance=$MA" -o json >"$EV/t.6.pods.json" || { bad "read $MA pods"; return 1; }
	out="$(pod_checks "$EV/t.6.pods.json" "$DIGEST" "$SNODE" 2)" || { bad "$MA: $out"; return 1; }
	view_read "$SERVER" "$SCACHE" "$EV/t.6.view.s" || { bad "read the server view"; return 1; }
	out="$(view_checks "$EV/t.6.view.s" "$VIEW_UID")" || { bad "server view after the scale: $out"; return 1; }
	[ "$(view_inodes "$EV/t.5.view.s")" = "$(view_inodes "$EV/t.6.view.s")" ] || { bad "the server's view was rebuilt for the second replica (inodes changed)"; return 1; }
	p="$MA-1"
	kc get pod "$p" -n "$NS" -o json >"$EV/t.6.warm-pod.json" || { bad "read $p"; return 1; }
	times="$(pod_times "$EV/t.6.warm-pod.json")" || { bad "the warm pod has no Ready or start time"; return 1; }
	measure warm_ready_seconds "${times% *}"
	measure warm_fetch_window_seconds "${times#* }"
}

t7() {
	local m end out ns rs rw rr h cache tag ok
	for m in "$MA" "$MB"; do
		out="$(kc delete mlxmodel "$m" -n "$NS" --wait=false 2>&1)" || { bad "delete $m: $out"; return 1; }
	done
	end=$(($(date +%s) + READY_TIMEOUT))
	while :; do
		ns="$(kc get pods -n "$NS" -l app.kubernetes.io/name=mlx-model -o name 2>/dev/null || echo error)"
		[ -n "$ns" ] || break
		[ "$(date +%s)" -lt "$end" ] || { bad "serving pods still present: $ns"; return 1; }
		sleep "$POLL"
	done
	for h in "$SERVER|s" "$WORKER|w"; do
		tag="${h#*|}" h="${h%|*}"
		out="$(ku "$h" image prune --force -o json 2>&1)" || { bad "image prune on $h: $out"; return 1; }
		printf '%s\n' "$out" >"$EV/t.7.prune.$tag.json"
		measure "t7_prune_reclaimed_bytes_$tag" "$(py 'import json,sys; print(json.loads(sys.stdin.read())["cache"]["reclaimedBytes"])' <<<"$out" 2>/dev/null || echo unread)"
	done
	out="$(ku "$SERVER" model rm "$TAG" 2>&1)" || { bad "model rm $TAG: $out"; return 1; }
	TAG_REMOVED=1
	out="$(ku "$SERVER" image prune --force -o json 2>&1)" || { bad "registry prune: $out"; return 1; }
	printf '%s\n' "$out" >"$EV/t.7.prune.registry.json"
	for h in "$SERVER|$SCACHE|s" "$WORKER|$WCACHE|w"; do
		IFS='|' read -r h cache tag <<<"$h"
		view_read "$h" "$cache" "$EV/t.7.view.$tag" || { bad "read the view dir on $h"; return 1; }
		grep -qx 'VIEWS 0' "$EV/t.7.view.$tag" || { bad "the view of $DIGEST is still on $h after the prune"; return 1; }
	done
	end=$(($(date +%s) + RECLAIM_TIMEOUT))
	while :; do
		if ! { rs="$(df_read "$SERVER" "$SCACHE")" && rw="$(df_read "$WORKER" "$WCACHE")" && rr="$(df_read "$SERVER" "$REG_ROOT")"; }; then
			bad "free-space reading"
			return 1
		fi
		ok=1
		df_back "$BASE_S" "$rs" "server cache" || { [ $? = 2 ] && return 1; ok=0; }
		df_back "$BASE_W" "$rw" "worker cache" || { [ $? = 2 ] && return 1; ok=0; }
		df_back "$BASE_R" "$rr" "registry store" || { [ $? = 2 ] && return 1; ok=0; }
		[ "$ok" = 0 ] || break
		[ "$(date +%s)" -lt "$end" ] || {
			bad "free space not back within 1% of the model ($TOL bytes) in ${RECLAIM_TIMEOUT}s: server cache $(((${BASE_S% *} - ${rs% *}) * 1024)), worker cache $(((${BASE_W% *} - ${rw% *}) * 1024)), registry store $(((${BASE_R% *} - ${rr% *}) * 1024)) bytes short"
			return 1
		}
		sleep "$POLL"
	done
	measure t7_server_cache_short_bytes "$(((${BASE_S% *} - ${rs% *}) * 1024))"
	measure t7_worker_cache_short_bytes "$(((${BASE_W% *} - ${rw% *}) * 1024))"
	measure t7_registry_short_bytes "$(((${BASE_R% *} - ${rr% *}) * 1024))"
}

# ---- f.1 and t.8 ----------------------------------------------------------------------

f1() {
	local rc=0 end out
	if [ -n "$WATCH_PID" ]; then
		# The t.3b watcher ends on its own once the worker's scratch dir is gone, so
		# it can never kickstart the node daemon after the run.
		rroot "$WORKER" "$STEP_TIMEOUT" 'case "$1" in /?*) rm -rf -- "$1" ;; *) exit 1 ;; esac' "$WWORK" || true
		end=$(($(date +%s) + STEP_TIMEOUT))
		while kill -0 "$WATCH_PID" 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do sleep "$POLL"; done
		if kill -0 "$WATCH_PID" 2>/dev/null; then
			bad "f.1: the t.3b watcher on the worker did not stop"
			rc=1
			kill "$WATCH_PID" 2>/dev/null || true
		fi
		wait "$WATCH_PID" 2>/dev/null || true
		WATCH_PID=""
	fi
	if [ "$NS_MADE" = 1 ]; then
		kc delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
		end=$(($(date +%s) + READY_TIMEOUT))
		while kc get namespace "$NS" -o name >/dev/null 2>&1; do
			[ "$(date +%s)" -lt "$end" ] || { bad "f.1: namespace $NS (its MLXModels, ConfigMap and Pods) is still present"; rc=1; break; }
			sleep "$POLL"
		done
	fi
	if [ "$PUSHED" = 1 ] && [ "$TAG_REMOVED" = 0 ]; then
		if out="$(ku "$SERVER" model rm "$TAG" 2>&1)"; then TAG_REMOVED=1; else bad "f.1: model rm $TAG: $out"; rc=1; fi
	fi
	if [ "$WORK_MADE" = 1 ]; then
		# shellcheck disable=SC2016 # expands remotely
		rroot "$SERVER" "$STEP_TIMEOUT" 'case "$1" in /?*) rm -rf -- "$1" ;; *) exit 1 ;; esac' "$SWORK" || { bad "f.1: remove $SWORK on the server"; rc=1; }
		# shellcheck disable=SC2016 # expands remotely
		rroot "$WORKER" "$STEP_TIMEOUT" 'case "$1" in /?*) rm -rf -- "$1" ;; *) exit 1 ;; esac' "$WWORK" || { bad "f.1: remove $WWORK on the worker"; rc=1; }
	fi
	return "$rc"
}

t8() {
	local n st v
	kc get ns >"$EV/t.8.namespaces" 2>&1 || { bad "kubectl get ns"; return 1; }
	cat "$EV/t.8.namespaces"
	! grep -q "^$NS " "$EV/t.8.namespaces" || { bad "namespace $NS is left"; return 1; }
	[ -z "$(kc get mlxmodel -A -o name 2>/dev/null | grep -F "$RUN" || true)" ] || { bad "an MLXModel of the run is left"; return 1; }
	for n in "$SNODE" "$WNODE"; do
		st="$(kc get node "$n" -o json 2>/dev/null | py 'import json,sys; print([c["status"] for c in json.loads(sys.stdin.read())["status"]["conditions"] if c["type"]=="Ready"][0])' 2>/dev/null || true)"
		[ "$st" = True ] || { bad "node $n is not Ready at the end"; return 1; }
	done
	v="$(ku "$SERVER" version 2>&1)" || { bad "k3sm version on the server at the end: $v"; return 1; }
	[ "$v" = "$VER_S" ] || { bad "the server's build changed during the run"; return 1; }
	v="$(ku "$WORKER" version 2>&1)" || { bad "k3sm version on the worker at the end: $v"; return 1; }
	[ "$v" = "$VER_W" ] || { bad "the worker's build changed during the run"; return 1; }
}

# run_rung <rung> <function>: one rung, its output to its own log.
run_rung() {
	local r="$1" f="$2" rc=0
	REACHED="$r"
	log "$r: $(for row in "${RUNGS[@]}"; do [ "${row%%|*}" = "$r" ] && echo "${row#*|}"; done)"
	: >"$EV/reasons"
	"$f" >>"$EV/$r.log" 2>&1 || rc=$?
	if [ "$rc" = 0 ]; then
		record "$r" PASS
		log "$r: PASS"
		return 0
	fi
	record "$r" FAIL "$(tr '\n' ' ' <"$EV/reasons")"
	log "$r: FAIL: $(tr '\n' ' ' <"$EV/reasons")"
	[ -n "$FAILED" ] || FAILED="$r"
	return 1
}

finish() {
	local rc=$? r seen=0 row
	trap - EXIT INT TERM
	[ -n "$EV" ] && [ "$TOUCHED" = 1 ] || exit "$rc"
	for row in "${RUNGS[@]}"; do
		r="${row%%|*}"
		case "$r" in p.0 | f.1 | t.8) continue ;; esac
		[ "$r" = "$REACHED" ] && { seen=1; continue; }
		[ "$seen" = 1 ] && record "$r" "NOT-REACHED"
	done
	run_rung f.1 f1 || true
	run_rung t.8 t8 || true
	log "evidence: $EV"
	if [ -z "$FAILED" ] && [ "$rc" = 0 ]; then
		echo "result: PASS"
		exit 0
	fi
	echo "result: FAIL (${FAILED:-interrupted})"
	exit 1
}

lab() {
	if [ "${K3SM_LAB:-}" != 1 ]; then
		echo "$GATE: LAB-PENDING: not a pass (needs K3SM_LAB=1)" >&2
		exit 3
	fi
	RUN="mst-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
	NS="$RUN" REPO="$RUN" TAG="$RUN:v1" MA="$RUN-a" MB="$RUN-b"
	p0
	record p.0 PASS
	log "run $RUN; namespace $NS; tag models/$TAG; evidence $EV"
	TOUCHED=1
	trap finish EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	run_rung t.0 t0 &&
		run_rung t.1 t1 &&
		run_rung t.2 t2 &&
		run_rung t.3 t3 &&
		run_rung t.3b t3b &&
		run_rung t.4 t4 &&
		run_rung t.5 t5 &&
		run_rung t.6 t6 &&
		run_rung t.7 t7 || true
}

# ---- --self-test ----------------------------------------------------------------------

write_fakes() { # <bin dir> <fake.py>
	local bin="$1" fpy="$2" t
	mkdir -p "$bin"
	cat >"$fpy" <<'PY'
import datetime, hashlib, json, os, shutil, stat, sys, time
ST = os.environ["FAKE_STATE"]
BRK = set(x for x in os.environ.get("FAKE_BREAK", "").split(",") if x)
NODES = {}
for e in os.environ["FAKE_NODES"].split():
    h, n, c = e.split("=", 2)
    NODES[h] = (n, c)
N2H = {v[0]: k for k, v in NODES.items()}
SRV = os.environ["FAKE_SERVER_HOST"]
REG = os.environ["FAKE_REG_ROOT"]
HOST = os.environ.get("FAKE_HOST", SRV)

def call_log(argv):
    with open(os.path.join(ST, "calls"), "a") as f:
        f.write(HOST + " " + " ".join(argv) + "\n")

def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def jload(name, default):
    try:
        with open(os.path.join(ST, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def jsave(name, v):
    p = os.path.join(ST, name)
    with open(p + ".tmp", "w") as f:
        json.dump(v, f)
    os.replace(p + ".tmp", p)

def df_get(h):
    try:
        return int(open(os.path.join(ST, "df-" + h)).read())
    except FileNotFoundError:
        return 100000000

def df_add(h, kb):
    v = df_get(h) + kb
    with open(os.path.join(ST, "df-" + h), "w") as f:
        f.write(str(v))

def model_files(d):
    out = []
    for root, _, files in os.walk(d):
        for f in files:
            p = os.path.join(root, f)
            out.append([hashlib.sha256(open(p, "rb").read()).hexdigest(), os.path.relpath(p, d), os.path.getsize(p), p])
    return sorted(out, key=lambda r: r[1])

def kicked(h):
    return os.path.exists(os.path.join(ST, "kicked-" + h))

def kicked_settled(h):
    # The fake's daemon resumes half a second after the restart, so the
    # watcher reads the partial the restart left before the pull goes on.
    p = os.path.join(ST, "kicked-" + h)
    return os.path.exists(p) and time.time() - os.path.getmtime(p) > 0.5

def rmtree(p):
    if not os.path.exists(p):
        return
    for root, dirs, files in os.walk(p):
        os.chmod(root, 0o755)
    shutil.rmtree(p)

def commit(h, reg, s):
    cache = NODES[h][1]
    blobs = os.path.join(cache, "blobs", "sha256")
    os.makedirs(blobs, exist_ok=True)
    for hexd, rel, size, src in reg["files"]:
        shutil.copyfile(src, os.path.join(blobs, hexd))
    pathset = hashlib.sha256("\n".join(sorted(r[1] for r in reg["files"])).encode()).hexdigest()
    mdir = os.path.join(cache, "artifacts", reg["digest"].split(":")[1])
    sets = [pathset] + (["other"] if "view-twice" in BRK else [])
    for ps in sets:
        v = os.path.join(mdir, ps)
        for hexd, rel, size, src in reg["files"]:
            dst = os.path.join(v, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if "view-hardlink" in BRK:
                os.link(os.path.join(blobs, hexd), dst)
            else:
                shutil.copyfile(os.path.join(blobs, hexd), dst)
                os.chmod(dst, 0o444)
    part = os.path.join(cache, "artifact-partial", "sha256-%s.partial" % reg["big"])
    if os.path.exists(part):
        os.remove(part)
    df_add(h, -reg["kb"])
    s["pulled"][h] = True

def reconcile(s):
    reg = jload("reg.json", None)
    for key, m in list(s["objs"].items()):
        if not key.startswith("MLXModel/"):
            continue
        ns, name = m["metadata"]["namespace"], m["metadata"]["name"]
        sp = m["spec"]
        rep = sp.get("replicas", 1)
        node = sp["nodeSelector"]["kubernetes.io/hostname"]
        h = N2H[node]
        st = m.setdefault("status", {})
        st["resolvedArtifact"] = reg["digest"] if "resolved-mismatch" not in BRK else "sha256:" + "0" * 64
        if not s["pulled"].get(h):
            if h != SRV and "no-partial" not in BRK and not kicked_settled(h):
                pd = os.path.join(NODES[h][1], "artifact-partial")
                os.makedirs(pd, exist_ok=True)
                p = os.path.join(pd, "sha256-%s.partial" % reg["big"])
                if not os.path.exists(p):
                    with open(p, "wb") as f:
                        f.write(b"\0" * (reg["bigsize"] // 2))
            else:
                commit(h, reg, s)
        ready = 0
        for i in range(rep):
            pn = "%s-%d" % (name, i)
            pk = ns + "/" + pn
            p = s["pods"].get(pk)
            if p is None:
                t = now()
                vols = [{"name": "model", "image": {"reference": "registry-k3sm:6450/models/%s@%s" % (reg["repo"], st["resolvedArtifact"]), "pullPolicy": "IfNotPresent"}}]
                if "pvc" in BRK:
                    vols.append({"name": "cache", "persistentVolumeClaim": {"claimName": "x"}})
                args = ["/var/lib/mlx/model", "--port", "8080", "--served-model-name", name]
                if "trust-remote-code" in BRK:
                    args.append("--trust-remote-code")
                ann = {"k3sm.io/internet-egress": "true"} if "egress-annotation" in BRK else {}
                p = {"apiVersion": "v1", "kind": "Pod",
                     "metadata": {"name": pn, "namespace": ns, "creationTimestamp": t, "annotations": ann,
                                  "labels": {"app.kubernetes.io/name": "mlx-model", "app.kubernetes.io/instance": name}},
                     "spec": {"nodeName": node, "volumes": vols, "containers": [{"name": "mlx-serve", "image": "fake/mlx:1", "args": args}]},
                     "status": {"phase": "Pending", "conditions": [{"type": "PodScheduled", "status": "True", "lastTransitionTime": t}]}}
                s["pods"][pk] = p
                if i >= 1 and "scale-copies" in BRK:
                    df_add(h, -reg["kb"])
            if s["pulled"].get(h) and p["status"]["phase"] != "Running":
                t = now()
                p["status"]["phase"] = "Running"
                p["status"]["conditions"].append({"type": "Ready", "status": "True", "lastTransitionTime": t})
                p["status"]["containerStatuses"] = [{"name": "mlx-serve", "state": {"running": {"startedAt": t}}}]
            if p["status"]["phase"] == "Running":
                ready += 1
        for pk in [k for k in s["pods"] if k.startswith(ns + "/" + name + "-")]:
            if int(pk.rsplit("-", 1)[1]) >= rep:
                del s["pods"][pk]
        st["phase"] = "Ready" if ready == rep else "Loading"
        st["readyReplicas"] = ready
        st["replicas"] = rep

def out(v):
    print(json.dumps(v))

def kubectl(argv):
    s = jload("k8s.json", {"ns": [], "objs": {}, "pods": {}, "pulled": {}})
    flags, pos, i = {}, [], 0
    dash = []
    while i < len(argv):
        a = argv[i]
        if a == "--":
            dash = argv[i + 1:]
            break
        if a in ("-n", "-o", "-l", "-f", "-p", "--type", "-c"):
            flags[a] = argv[i + 1]
            i += 2
            continue
        if a.startswith("-"):
            flags[a] = True
            i += 1
            continue
        pos.append(a)
        i += 1
    verb = pos[0]
    ns = flags.get("-n", "")
    reconcile(s) if verb in ("get", "patch") and s.get("reg_ok", True) else None
    rc = 0
    if verb == "get" and flags.get("--raw"):
        print("ok")
    elif verb == "get" and pos[1] == "node":
        n = pos[2]
        out({"metadata": {"name": n, "labels": {"kubernetes.io/hostname": n, "mlx.k3sm.io/gpu.present": "true"}},
             "spec": {"taints": [{"key": "k3sm.io/provider", "effect": "NoSchedule"}]},
             "status": {"conditions": [{"type": "Ready", "status": "True"}]}})
    elif verb == "get" and pos[1] == "nodes":
        print("NAME STATUS\n" + "\n".join("%s Ready" % v[0] for v in NODES.values()))
    elif verb == "get" and pos[1] == "crd":
        out({"spec": {"versions": [{"schema": {"openAPIV3Schema": {"properties": {"spec": {"properties": {"artifact": {}}}, "status": {"properties": {"resolvedArtifact": {}}}}}}}]}})
    elif verb == "get" and pos[1] in ("ns", "namespace") and len(pos) > 2:
        if pos[2] in s["ns"]:
            print("namespace/" + pos[2])
        else:
            rc = 1
    elif verb == "get" and pos[1] in ("ns", "namespaces"):
        print("NAME STATUS AGE\ndefault Active 1d\n" + "\n".join("%s Active 1m" % n for n in s["ns"]))
    elif verb == "create" and pos[1] in ("namespace", "ns"):
        if "create-refused" in BRK:
            print("refused", file=sys.stderr)
            rc = 1
        else:
            s["ns"].append(pos[2])
    elif verb == "apply":
        o = json.loads(sys.stdin.read())
        if o["kind"] == "MLXModel" and "apply-refused" in BRK:
            print("admission refused", file=sys.stderr)
            rc = 1
        else:
            key = "%s/%s/%s" % (o["kind"], o["metadata"]["namespace"], o["metadata"]["name"])
            s["objs"][key] = o
    elif verb == "get" and pos[1] == "mlxmodel" and flags.get("-A"):
        for k in s["objs"]:
            if k.startswith("MLXModel/"):
                print("mlxmodel.mlx.k3sm.io/" + k.split("/")[2])
    elif verb == "get" and pos[1] == "mlxmodel":
        o = s["objs"].get("MLXModel/%s/%s" % (ns, pos[2]))
        if o is None:
            rc = 1
        else:
            out(o)
    elif verb == "get" and pos[1] == "pods":
        sel = flags.get("-l", "")
        k, v = sel.split("=")
        items = [p for key, p in s["pods"].items() if key.startswith(ns + "/") and p["metadata"]["labels"].get(k) == v]
        if flags.get("-o") == "name":
            print("\n".join("pod/" + p["metadata"]["name"] for p in items))
        else:
            out({"items": items})
    elif verb == "get" and pos[1] == "pod":
        p = s["pods"].get(ns + "/" + pos[2])
        if p is None:
            o = s["objs"].get("Pod/%s/%s" % (ns, pos[2]))
            if o is None:
                rc = 1
            else:
                o = dict(o)
                o["status"] = {"phase": "Succeeded"}
                out(o)
        else:
            out(p)
    elif verb == "get" and pos[1] == "svc":
        out({"spec": {"ports": [{"port": 8080}]}})
    elif verb == "get" and pos[1] == "pvc":
        if "pvc" in BRK:
            print("persistentvolumeclaim/cache")
    elif verb == "patch":
        o = s["objs"]["MLXModel/%s/%s" % (ns, pos[2])]
        o["spec"].update(json.loads(flags["-p"])["spec"])
        reconcile(s)
    elif verb == "delete" and pos[1] == "mlxmodel":
        s["objs"].pop("MLXModel/%s/%s" % (ns, pos[2]), None)
        for k in [k for k in s["pods"] if k.startswith(ns + "/" + pos[2] + "-")]:
            del s["pods"][k]
    elif verb == "delete" and pos[1] in ("namespace", "ns"):
        if "ns-stuck" not in BRK and pos[2] in s["ns"]:
            s["ns"].remove(pos[2])
            for d in ("objs", "pods"):
                for k in [k for k in s[d] if ("/" + pos[2] + "/") in ("/" + k) or k.startswith(pos[2] + "/")]:
                    del s[d][k]
    elif verb == "logs":
        name = pos[1]
        if name.startswith("mst-client"):
            print("COMPLETION-EMPTY" if "empty-completion" in BRK else "COMPLETION-OK 12")
        elif name == "mst-egress-control":
            print("EGRESS-BLOCKED URLError" if "control-blocked" in BRK else "EGRESS-REACHED")
    elif verb == "exec":
        code = " ".join(dash)
        if "urlopen" in code:
            if "egress-open" in BRK:
                print("EGRESS-REACHED")
            else:
                print("EGRESS-BLOCKED URLError")
                rc = 1
        elif "WRITE-" in code:
            print("WRITE-OK" if "write-ok" in BRK else "WRITE-ERRNO 13" if "write-eacces" in BRK else "WRITE-ERRNO 1")
        elif "EXEC-" in code:
            if "exec-ok" in BRK:
                print("exec ran")
            else:
                print("EXEC-ERRNO 13")
        elif "COPYRUN" in code:
            print("COPYRUN-RAN")
    else:
        print("fake kubectl: unhandled %r" % argv, file=sys.stderr)
        rc = 2
    jsave("k8s.json", s)
    return rc

def k3sm(argv):
    if argv[:1] == ["version"]:
        if "version-fails" in BRK and HOST != SRV:
            print("cannot reach the daemon", file=sys.stderr)
            return 1
        print("k3sm v0.0.0-fake")
        return 0
    if argv[:2] == ["model", "push"]:
        d, name = argv[2], argv[3]
        repo = name.split(":")[0]
        files = model_files(d)
        digest = "sha256:" + hashlib.sha256(json.dumps([f[:3] for f in files]).encode()).hexdigest()
        reg = jload("reg.json", None)
        kb = sum(f[2] for f in files) // 1024
        big = max(files, key=lambda f: f[2])
        rdir = os.path.join(REG, "models", repo, "blobs", "sha256")
        if reg is None:
            os.makedirs(rdir, exist_ok=True)
            for f in files:
                shutil.copyfile(f[3], os.path.join(rdir, f[0]))
            df_add(SRV, -kb)
            reg = {"digest": digest, "repo": repo, "files": files, "kb": kb, "big": big[0], "bigsize": big[2], "tagged": True, "pushes": 0}
        reg["pushes"] += 1
        shown = digest
        if reg["pushes"] == 2 and "push-digest" in BRK:
            shown = "sha256:" + "1" * 64
        if reg["pushes"] == 2 and "push-bytes" in BRK:
            open(os.path.join(rdir, "extra"), "w").write("x")
        jsave("reg.json", reg)
        print("pushed registry-k3sm:6450/models/%s (%d files)\n  digest: %s" % (name, len(files), shown))
        return 0
    if argv[:2] == ["model", "rm"]:
        reg = jload("reg.json", None)
        if reg is None or not reg["tagged"]:
            print("MANIFEST_UNKNOWN", file=sys.stderr)
            return 1
        reg["tagged"] = False
        jsave("reg.json", reg)
        print("removed")
        return 0
    if argv[:2] == ["image", "prune"]:
        s = jload("k8s.json", {"ns": [], "objs": {}, "pods": {}, "pulled": {}})
        reg = jload("reg.json", None)
        node = NODES[HOST][0]
        reclaimed = 0
        live = [p for p in s["pods"].values() if p["spec"]["nodeName"] == node]
        if reg and s["pulled"].get(HOST) and not live and "prune-keeps" not in BRK:
            cache = NODES[HOST][1]
            rmtree(os.path.join(cache, "artifacts", reg["digest"].split(":")[1]))
            for f in reg["files"]:
                p = os.path.join(cache, "blobs", "sha256", f[0])
                if os.path.exists(p):
                    os.remove(p)
            df_add(HOST, reg["kb"])
            s["pulled"][HOST] = False
            reclaimed = reg["kb"] * 1024
            jsave("k8s.json", s)
        if HOST == SRV and reg and not reg["tagged"] and not reg.get("reclaimed") and "registry-keeps" not in BRK:
            rmtree(os.path.join(REG, "models", reg["repo"]))
            df_add(SRV, reg["kb"])
            reg["reclaimed"] = True
            jsave("reg.json", reg)
        out({"dryRun": False, "registry": {"name": "registry-k3sm:6450", "manifests": [], "kept": []}, "cache": {"blobs": [], "reclaimedBytes": reclaimed}})
        return 0
    print("fake k3sm: unhandled %r" % argv, file=sys.stderr)
    return 2

def launchctl(argv):
    if argv[0] == "print":
        print("\tstate = running\n\tpid = %d" % (101 if kicked(HOST) else 100))
        return 0
    if argv[0] == "kickstart":
        reg = jload("reg.json", None)
        part = os.path.join(NODES[HOST][1], "artifact-partial", "sha256-%s.partial" % reg["big"])
        if "kick-truncates" in BRK and os.path.exists(part):
            os.remove(part)
            open(part, "wb").close()
        open(os.path.join(ST, "kicked-" + HOST), "w").close()
        return 0
    return 2

def main():
    tool, argv = sys.argv[1], sys.argv[2:]
    call_log([tool] + argv)
    if tool == "kubectl":
        return kubectl(argv)
    if tool == "k3sm":
        return k3sm(argv)
    if tool == "launchctl":
        return launchctl(argv)
    if tool == "df":
        print("Filesystem 1024-blocks Used Available Capacity Mounted on")
        print("/dev/fake 200000000 100000000 %d 50%% /" % df_get(HOST))
        return 0
    if tool == "tmutil":
        return 0
    if tool == "pgrep":
        s = jload("k8s.json", {"pods": {}})
        node = NODES[HOST][0]
        pat = argv[-1]
        for p in s["pods"].values():
            if p["spec"]["nodeName"] == node and p["status"]["phase"] == "Running" and ("--served-model-name " + p["metadata"]["labels"]["app.kubernetes.io/instance"]) in pat:
                print(4242)
                return 0
        return 1
    if tool == "footprint":
        print("python3 [%s]: 64-bit    Footprint: 700 MB\nphys_footprint: 700 MB\nphys_footprint_peak: 900 MB" % argv[-1])
        return 0
    return 2

sys.exit(main())
PY
	for t in kubectl k3sm launchctl df tmutil pgrep footprint; do
		printf '#!/bin/sh\nexec python3 -I %q %s "$@"\n' "$fpy" "$t" >"$bin/$t"
		chmod +x "$bin/$t"
	done
	printf '#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n' >"$bin/sudo"
	# ssh [-o opt]... host text: run the text as that host.
	cat >"$bin/ssh" <<'SH'
#!/bin/sh
while [ $# -gt 0 ]; do
	case "$1" in -o) shift 2 ;; -*) shift ;; *) break ;; esac
done
h="$1"; shift
FAKE_HOST="$h" exec /bin/bash -c "$*"
SH
	chmod +x "$bin/sudo" "$bin/ssh"
}

self_test() {
	local t bad=0 bin fpy rc out
	t="$(mktemp -d "${TMPDIR:-/tmp}/mst-self-test.XXXXXX")"
	bin="$t/bin" fpy="$t/fake.py"
	write_fakes "$bin" "$fpy"
	chk() { [ "$2" = "$3" ] || { echo "self-test FAIL: $1: got '$2', want '$3'"; bad=1; }; }
	has() { case "$2" in *"$3"*) ;; *) echo "self-test FAIL: $1: output lacks '$3'"; bad=1 ;; esac; }

	# The pure helpers.
	mkdir -p "$t/m/sub"
	printf '{"a":1}\n' >"$t/m/config.json"
	printf 'tok\n' >"$t/m/sub/tokenizer.json"
	head -c 204800 /dev/urandom >"$t/m/model.safetensors"
	(cd "$t/m" && shasum -a 256 config.json sub/tokenizer.json model.safetensors) >"$t/sums"
	out="$(verify_sums "$t/m" "$t/sums")" || { echo "self-test FAIL: verify_sums on a good dir"; bad=1; }
	chk "verify_sums: largest last" "$(tail -n 1 <<<"$out" | awk '{print $3}')" model.safetensors
	sed 's/^./0/' "$t/sums" >"$t/sums.bad"
	rc=0; verify_sums "$t/m" "$t/sums.bad" >/dev/null 2>&1 || rc=$?
	chk "verify_sums: a wrong hash refuses" "$rc" 1
	head -n 2 "$t/sums" >"$t/sums.short"
	rc=0; verify_sums "$t/m" "$t/sums.short" >/dev/null 2>&1 || rc=$?
	chk "verify_sums: an unlisted file refuses" "$rc" 1
	chk "quantity 4Gi" "$(quantity_bytes 4Gi)" 4294967296
	chk "quantity 512M" "$(quantity_bytes 512M)" 512000000
	printf 'x [1]: 64-bit    Footprint: 700 MB\nphys_footprint: 700 MB\nphys_footprint_peak: 1.5 GB\n' >"$t/fp1"
	chk "footprint: the peak line wins" "$(footprint_bytes "$t/fp1")" 1610612736
	printf 'x [1]: 64-bit    Footprint: 700 MB\n' >"$t/fp2"
	chk "footprint: the header when no peak" "$(footprint_bytes "$t/fp2")" 734003200
	: >"$t/fp3"
	chk "footprint: nothing read" "$(footprint_bytes "$t/fp3")" ""
	printf 'VIEWS 1\nF a 10 1 8 4096 444 0 | 11 1 8 4096\n' >"$t/v"
	rc=0; view_checks "$t/v" 0 >/dev/null || rc=$?
	chk "view: a clone" "$rc" 0
	printf 'VIEWS 1\nF a 11 1 8 4096 444 0 | 11 1 8 4096\n' >"$t/v"
	rc=0; view_checks "$t/v" 0 >/dev/null || rc=$?
	chk "view: a hardlink is refused" "$rc" 1
	printf 'VIEWS 1\nF a 10 2 8 4096 444 0 | 11 1 8 4096\n' >"$t/v"
	rc=0; view_checks "$t/v" 0 >/dev/null || rc=$?
	chk "view: another device is refused" "$rc" 1
	printf 'VIEWS 1\nF a 10 1 8 4096 644 0 | 11 1 8 4096\n' >"$t/v"
	rc=0; view_checks "$t/v" 0 >/dev/null || rc=$?
	chk "view: a writable mode is refused" "$rc" 1
	printf 'VIEWS 2\n' >"$t/v"
	rc=0; view_checks "$t/v" 0 >/dev/null || rc=$?
	chk "view: two views are refused" "$rc" 1
	TOL=1024
	rc=0; within 100 101 "$TOL" || rc=$?
	chk "within: 1 KiB" "$rc" 0
	rc=0; within 100 102 "$TOL" || rc=$?
	chk "within: 2 KiB" "$rc" 1

	# One full fake run. FAKE_BREAK names a mutant; want is the exit and the red rung.
	fake_run() { # <name> <break> <want-exit> <want-in-output> [evidence-dir]
		local name="$1" brk="$2" want="$3" grepfor="$4" ev="${5:-$t/runs/$1/ev}" r="$t/runs/$1" got=0 o
		mkdir -p "$r/state" "$r/srv/cache/blobs" "$r/wrk/cache/blobs" "$r/srv/registry"
		o="$(
			cd "$t" && env -u K3SM_LAB_TOLERATE_KEYS PATH="$bin:$PATH" K3SM_LAB=1 KUBECONFIG=/dev/null \
				FAKE_STATE="$r/state" FAKE_BREAK="$brk" FAKE_SERVER_HOST=srv FAKE_REG_ROOT="$r/srv/registry" \
				FAKE_NODES="srv=node-s=$r/srv/cache wrk=node-w=$r/wrk/cache" \
				K3SM_MST_SERVER_SSH=srv K3SM_MST_WORKER_SSH=wrk K3SM_MST_SERVER_NODE=node-s K3SM_MST_WORKER_NODE=node-w \
				K3SM_MST_SERVER_CACHE="$r/srv/cache" K3SM_MST_WORKER_CACHE="$r/wrk/cache" \
				K3SM_MST_SERVER_WORK="$r/srv/work" K3SM_MST_WORKER_WORK="$r/wrk/work" \
				K3SM_MST_REGISTRY_ROOT="$r/srv/registry" K3SM_MST_K3SM=k3sm K3SM_MST_LOCAL_K3SM=k3sm \
				K3SM_MST_VIEW_UID="$(id -u)" K3SM_MST_POLL=0.05 K3SM_MST_READY_TIMEOUT=20 \
				K3SM_MST_RECLAIM_TIMEOUT=2 K3SM_MST_STEP_TIMEOUT=30 \
				"$SELF" --lab --model-dir "$t/m" --model-sums "$t/sums" --evidence "$ev" 2>&1
		)" || got=$?
		printf '%s\n' "$o" >"$r/out"
		chk "run $name: exit" "$got" "$want"
		has "run $name" "$o" "$grepfor"
		RUN_DIR="$r"
	}
	# cleaned <name>: f.1 left nothing of the run.
	cleaned() {
		local s="$RUN_DIR/state"
		[ "$(py 'import json,sys; print(len(json.load(open(sys.argv[1]))["ns"]))' "$s/k8s.json")" = 0 ] || { echo "self-test FAIL: $1: a namespace is left"; bad=1; }
		[ ! -f "$s/reg.json" ] || [ "$(py 'import json,sys; print(json.load(open(sys.argv[1]))["tagged"])' "$s/reg.json")" = False ] || { echo "self-test FAIL: $1: the pushed tag is left"; bad=1; }
		[ ! -e "$RUN_DIR/srv/work" ] && [ ! -e "$RUN_DIR/wrk/work" ] || { echo "self-test FAIL: $1: a scratch dir is left"; bad=1; }
		grep -q 'f.1: PASS' "$RUN_DIR/out" || { echo "self-test FAIL: $1: f.1 did not pass"; bad=1; }
	}

	fake_run happy "" 0 "result: PASS"
	cleaned happy
	for out in t.0 t.1 t.2 t.3 t.3b t.4 t.5 t.6 t.7 f.1 t.8; do has "happy: $out passed" "$(cat "$RUN_DIR/out")" "$out: PASS"; done
	has "happy: cold rate recorded" "$(cat "$RUN_DIR/ev/measurements.tsv")" cold_fetch_bytes_per_second
	has "happy: warm time recorded" "$(cat "$RUN_DIR/ev/measurements.tsv")" warm_ready_seconds
	has "happy: footprint vs memory" "$(cat "$RUN_DIR/ev/measurements.tsv")" peak_footprint_over_spec_memory
	has "happy: the kickstart landed" "$(cat "$RUN_DIR/state/calls")" "wrk launchctl kickstart -k system/io.k3sm.agent"

	# Each rung's failure is caught, the run is red naming it, and f.1 still cleans.
	local row brk rung
	for row in \
		"version-fails|t.0" "push-digest|t.1" "push-bytes|t.1" "apply-refused|t.2" "create-refused|t.2" \
		"resolved-mismatch|t.3" "pvc|t.3" "egress-annotation|t.3" "trust-remote-code|t.3" \
		"no-partial|t.3b" "kick-truncates|t.3b" "empty-completion|t.4" \
		"egress-open|t.5" "control-blocked|t.5" "write-ok|t.5" "write-eacces|t.5" "exec-ok|t.5" "view-hardlink|t.5" "view-twice|t.5" \
		"scale-copies|t.6" "prune-keeps|t.7" "registry-keeps|t.7"; do
		brk="${row%|*}" rung="${row#*|}"
		fake_run "$brk" "$brk" 1 "result: FAIL ($rung)"
		cleaned "$brk"
	done
	# The case this tracer exists for: served (t.4 green) while egress is open is red.
	fake_run egress-open-again egress-open 1 "result: FAIL (t.5)"
	has "egress open: t.4 passed first" "$(cat "$RUN_DIR/out")" "t.4: PASS"
	has "egress open: later rungs not reached" "$(cat "$RUN_DIR/ev/result.tsv")" "$(printf 't.6\tNOT-REACHED')"

	# A cleanup that cannot remove the namespace fails a run whose rungs all passed.
	fake_run ns-stuck ns-stuck 1 "f.1: FAIL"
	has "ns-stuck: named" "$(cat "$RUN_DIR/out")" "result: FAIL (f.1)"

	# The evidence dir must be empty: refused with exit 3, nothing created.
	mkdir -p "$t/full-ev" && : >"$t/full-ev/old"
	fake_run full-ev "" 3 "is not empty" "$t/full-ev"
	if grep -Eq ' (apply|create|delete|patch|model push)' "$RUN_DIR/state/calls" 2>/dev/null; then echo "self-test FAIL: a refused run touched the rig"; bad=1; fi
	# A bad model dir is refused before anything is pushed.
	cp "$t/sums" "$t/sums.keep" && cp "$t/sums.bad" "$t/sums"
	fake_run bad-sums "" 3 "sha256 mismatch"
	cp "$t/sums.keep" "$t/sums"
	[ ! -f "$RUN_DIR/state/reg.json" ] || { echo "self-test FAIL: a bad sums file still pushed"; bad=1; }

	# Not a lab run: exit 3, never a pass.
	rc=0; env -u K3SM_LAB "$SELF" --lab >/dev/null 2>&1 || rc=$?
	chk "--lab without K3SM_LAB" "$rc" 3
	out="$("$SELF" --plan)"
	for rung in p.0 t.0 t.1 t.2 t.3 t.3b t.4 t.5 t.6 t.7 f.1 t.8; do has "--plan" "$out" "  $rung "; done

	rm -rf "$t"
	[ "$bad" = 0 ] || exit 1
	echo "$GATE self-test: PASS"
}

# ---- main -----------------------------------------------------------------------------

usage() {
	echo "usage: --plan | --self-test | --lab --model-dir DIR --model-sums FILE --evidence DIR" >&2
	exit 2
}

case "${1:-}" in
--plan) [ $# -eq 1 ] || usage; plan; exit 0 ;;
--self-test) [ $# -eq 1 ] || usage; self_test; exit 0 ;;
--lab) shift ;;
*) usage ;;
esac
while [ $# -gt 0 ]; do
	case "$1" in
	--model-dir) [ $# -ge 2 ] || usage; MODEL_DIR="$2"; shift 2 ;;
	--model-sums) [ $# -ge 2 ] || usage; MODEL_SUMS="$2"; shift 2 ;;
	--evidence) [ $# -ge 2 ] || usage; EV="$2"; shift 2 ;;
	*) usage ;;
	esac
done
lab
