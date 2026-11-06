#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's upgrade over a zot store and its rollback (docs/m23-plan.md
# resolutions 4 and 21).
#
# --lab is the gate: the rig leg against a live two-node cluster, through kubectl,
# k3sm, Pods and a buildx push only. `--plan` prints its steps and `--lab --help` its
# inputs: it installs the old (zot-era) set, pushes under zot, rolls the new set
# worker first, checks every recorded digest, the image verbs, the pods and a GC
# cycle, diffs the store, rolls back and has zot serve and GC the store. It runs
# --rollback-leg beside itself as its step e.5. --rollback-leg passing alone is not
# the gate passing.
#
# --rollback-leg: can zot take back a store the k3sm registry has deduped, with a
# crashed merge's temp left in it? The leg, on loopback, on a store under a fresh temp directory in --work. It
# reads and writes no other store, and removes everything it made when it exits.
#   1. The k3sm registry takes one image, tagged in two repositories with no
#      mount, and one unreferenced blob in each. The image's layer must be two
#      inodes.
#   2. It waits for a dedupe pass (registry-dedupe.sh: about 61 minutes from the
#      server's start, and no verb shortens that). The layer must then be one
#      inode, served with the right bytes from both repositories.
#   3. The server stops, and a .tmp-<uuid> link of that inode goes into the first
#      repository's .temps directory, which is what a crash between a merge's link
#      and its rename leaves. A temp in blobs/sha256, where earlier builds put it,
#      fails zot's GC of that repository, so only the k3sm GC can clear one, and the
#      leg does not plant one.
#   4. zot serves that store, with GC on. Its delay and interval are 1s and 10s
#      against the released 1h and 6h, so that a cycle fits in the leg.
#   5. After zot's GC has reported on both repositories, zot must answer, serve the
#      layer and the manifest from both, and keep the layer on one inode. Each
#      repository's GC must have succeeded and removed that repository's
#      unreferenced blob. The temp's fate is recorded, not judged.
#
# Exit 0 pass, 1 fail, 2 usage, 3 a precondition unmet (K3SM_LAB unset, a missing
# input): not a pass.
#
# Usage:
#   K3SM_LAB=1 hack/acceptance/B1027.sh --lab --old-set DIR --new-set DIR \
#       --server-ssh HOST --worker-ssh HOST --server-lan ADDR --evidence DIR [...]
#   K3SM_LAB=1 hack/acceptance/B1027.sh --rollback-leg --zot PATH --k3sm PATH --work DIR \
#       [--pass-wait SECONDS] [--zot-gc-wait SECONDS]
#   hack/acceptance/B1027.sh --plan
#   hack/acceptance/B1027.sh --self-test   # --lab over fake ssh, scp, sudo, k3sm, kubectl
# Requires: curl, python3, shasum, htpasswd, awk; --lab also ssh, scp, tar and go.
# shellcheck disable=SC2015 # `a && b || fail`: b failing is a failure of the step too
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=registry-dedupe.sh
. "$HERE/registry-dedupe.sh"

GATE_NAME=B1027
USER_NAME=k3sm
PASSWORD="b1027-$$-leg"
TEMP_REPO=rollback/one
CONTROL_REPO=rollback/two

# plant_temp <run dir> <blob path> - links the blob to .tmp-<uuid> in its repository's
# .temps directory and echoes the temp's path. Refuses a blob outside the run directory.
plant_temp() {
	local run="$1" blob="$2" temps tmp
	case "$blob" in "$run"/*) ;; *) echo "$GATE_NAME: refusing to plant a temp outside $run: $blob" >&2; return 1 ;; esac
	temps="$(dirname "$(dirname "$(dirname "$blob")")")/.temps"
	mkdir -p "$temps" || return 1
	tmp="$temps/.tmp-$(python3 -I -c 'import uuid; print(uuid.uuid4())')"
	ln "$blob" "$tmp" || return 1
	echo "$tmp"
}

# merge_went_through_temps <store> <repo...> - the pass's merges made .temps in some
# repository and left no temp among the blobs of any, so what the leg plants is where
# the store puts one.
merge_went_through_temps() {
	local store="$1" r seen=no
	shift
	for r in "$@"; do
		[ ! -d "$store/$r/.temps" ] || seen=yes
		[ -z "$(find "$store/$r/blobs" -name '.tmp-*' -print -quit)" ] || { echo "$GATE_NAME: a temp among the blobs of $r" >&2; return 1; }
	done
	[ "$seen" = yes ] || { echo "$GATE_NAME: no repository has a .temps directory after the pass" >&2; return 1; }
}

# temp_ok <temp path> <blob path> - the temp has a crashed merge's place, name and inode.
temp_ok() {
	local name; name="$(basename "$1")"
	[ "$(basename "$(dirname "$1")")" = .temps ] && [ "${#name}" -eq 41 ] && case "$name" in .tmp-*-*-*-*-*) ;; *) false ;; esac && rd_same_inode "$1" "$2"
}

# zot_gc_result <zot log> <repo> - ok, failed or none: zot's latest report of GC on
# the repository.
zot_gc_result() {
	[ -f "$1" ] || { echo none; return 0; }
	awk -v tail="/$2\"" '
		function endsrepo(s,   at) { at = index(s, tail); return at > 0 }
		/"gc successfully completed for / { line = $0; sub(/^.*gc successfully completed for /, "", line); sub(/",.*$/, "\"", line); if (endsrepo(line)) r = "ok" }
		/"gc unsuccessfully completed for / { line = $0; sub(/^.*gc unsuccessfully completed for /, "", line); sub(/",.*$/, "\"", line); if (endsrepo(line)) r = "failed" }
		END { print (r == "" ? "none" : r) }' "$1"
}

# zot_wait_gc <zot log> <deadline epoch> <zot pid> <repo...> - polls until zot has
# reported GC on every repository.
zot_wait_gc() {
	local log="$1" deadline="$2" pid="$3" r pending
	shift 3
	while :; do
		pending=""
		for r in "$@"; do [ "$(zot_gc_result "$log" "$r")" != none ] || pending="$pending $r"; done
		[ -n "$pending" ] || return 0
		kill -0 "$pid" 2>/dev/null || { echo "$GATE_NAME: zot exited before its GC reported on:$pending" >&2; return 1; }
		if [ "$(date +%s)" -ge "$deadline" ]; then echo "$GATE_NAME: zot's GC did not report in time on:$pending" >&2; return 1; fi
		sleep "$RD_POLL"
	done
}

# repo_collected <zot log> <store> <repo> <unreferenced digest> - zot's latest GC of
# the repository succeeded and the blob is gone.
repo_collected() {
	local got
	got="$(zot_gc_result "$1" "$3")"
	[ "$got" = ok ] || { echo "$GATE_NAME: zot's GC of $3: $got" >&2; return 1; }
	[ ! -e "$(rd_blob_path "$2" "$3" "$4")" ] || { echo "$GATE_NAME: zot's GC of $3 left the unreferenced blob $4" >&2; return 1; }
}

# rollback_checks <zot log> <store> <layer digest> <manifest digest> <temp repo's
# unreferenced digest> <control repo's unreferenced digest> - step 5.
rollback_checks() {
	local log="$1" store="$2" layer="$3" manifest="$4" orphan_temp="$5" orphan_control="$6" rc=0 r
	for r in "$TEMP_REPO" "$CONTROL_REPO"; do
		rd_serves "/v2/$r/blobs/$layer" "$layer" || { echo "$GATE_NAME: zot does not serve the layer from $r" >&2; rc=1; }
		rd_serves "/v2/$r/manifests/v1" "$manifest" || { echo "$GATE_NAME: zot does not serve the manifest from $r" >&2; rc=1; }
	done
	rd_same_inode "$(rd_blob_path "$store" "$TEMP_REPO" "$layer")" "$(rd_blob_path "$store" "$CONTROL_REPO" "$layer")" ||
		{ echo "$GATE_NAME: the layer is no longer one inode under zot" >&2; rc=1; }
	repo_collected "$log" "$store" "$CONTROL_REPO" "$orphan_control" || rc=1
	repo_collected "$log" "$store" "$TEMP_REPO" "$orphan_temp" || rc=1
	return "$rc"
}

self_test() {
	local t bad=0 d m o1 o2 blob tmp root rc=0
	exp() { local want="$1" name="$2" got=no; shift 2; if "$@" >/dev/null 2>&1; then got=ok; fi; [ "$got" = "$want" ] || { echo "self-test FAIL: $name: got $got, want $want"; bad=1; }; }
	chk() { [ "$2" = "$3" ] || { echo "self-test FAIL: $1: got $2, want $3"; bad=1; }; }

	rd_self_test || bad=1

	t="$(mktemp -d "${TMPDIR:-/tmp}/b1027-self-test.XXXXXX")"
	root="$t/store"
	RD_SERVED="$t/served"
	# The lines zot v2.1.22 writes, trimmed: read from a run over a store with a temp.
	ok_line() { echo "{\"level\":\"info\",\"message\":\"gc successfully completed for $root/$1\",\"module\":\"gc\"}"; }
	bad_line() { echo "{\"level\":\"info\",\"message\":\"gc unsuccessfully completed for $root/$1\",\"module\":\"gc\"}"; }

	# A clean fixture: the layer on one inode, both repositories' orphans gone, zot
	# serving the right bytes, and GC reported good on both.
	fixture() {
		rm -rf "$root" "$t/served"; : >"$t/zot.log"
		printf 'layer bytes\n' >"$t/layer"; printf '{"m":1}\n' >"$t/manifest"
		printf 'orphan one\n' >"$t/o1"; printf 'orphan two\n' >"$t/o2"
		d="$(rd_sha_of "$t/layer")"; m="$(rd_sha_of "$t/manifest")"; o1="$(rd_sha_of "$t/o1")"; o2="$(rd_sha_of "$t/o2")"
		local r first=""
		for r in "$TEMP_REPO" "$CONTROL_REPO"; do
			mkdir -p "$root/$r/blobs/sha256" "$t/served/v2/$r/blobs" "$t/served/v2/$r/manifests"
			if [ -z "$first" ]; then cp "$t/layer" "$(rd_blob_path "$root" "$r" "$d")"; first="$r"; else ln "$(rd_blob_path "$root" "$first" "$d")" "$(rd_blob_path "$root" "$r" "$d")"; fi
			cp "$t/layer" "$t/served/v2/$r/blobs/$d"; cp "$t/manifest" "$t/served/v2/$r/manifests/v1"
		done
		ok_line "$TEMP_REPO" >>"$t/zot.log"; ok_line "$CONTROL_REPO" >>"$t/zot.log"
	}
	# shellcheck disable=SC2329  # exp calls it
	checks() { rollback_checks "$t/zot.log" "$root" "$d" "$m" "$o1" "$o2"; }

	fixture
	exp ok "rollback: a clean store" checks

	# Mutant, and what zot v2.1.22 gives for a temp in blobs/sha256: GC of its repository fails.
	fixture; bad_line "$TEMP_REPO" >>"$t/zot.log"
	exp no "rollback: GC of the temp's repository failed" checks
	fixture; bad_line "$CONTROL_REPO" >>"$t/zot.log"
	exp no "rollback: GC of the control repository failed" checks
	fixture; : >"$t/zot.log"; ok_line "$CONTROL_REPO" >>"$t/zot.log"
	exp no "rollback: no GC report on the temp's repository" checks
	fixture; bad_line "$TEMP_REPO" >>"$t/zot.log"; ok_line "$TEMP_REPO" >>"$t/zot.log"
	exp ok "rollback: the latest report decides" checks
	# Mutants: an unreferenced blob stays.
	fixture; cp "$t/o1" "$(rd_blob_path "$root" "$TEMP_REPO" "$o1")"
	exp no "rollback: temp repository kept its unreferenced blob" checks
	fixture; cp "$t/o2" "$(rd_blob_path "$root" "$CONTROL_REPO" "$o2")"
	exp no "rollback: control repository kept its unreferenced blob" checks
	# Mutants: zot serves wrong bytes, or nothing.
	fixture; printf 'other\n' >"$t/served/v2/$TEMP_REPO/blobs/$d"
	exp no "rollback: temp repository serves a wrong layer" checks
	fixture; printf 'other\n' >"$t/served/v2/$CONTROL_REPO/blobs/$d"
	exp no "rollback: control repository serves a wrong layer" checks
	fixture; printf 'other\n' >"$t/served/v2/$TEMP_REPO/manifests/v1"
	exp no "rollback: temp repository serves a wrong manifest" checks
	fixture; rm "$t/served/v2/$CONTROL_REPO/manifests/v1"
	exp no "rollback: control repository serves no manifest" checks
	# Mutant: zot split the shared inode.
	fixture; blob="$(rd_blob_path "$root" "$TEMP_REPO" "$d")"; rm "$blob"; cp "$t/layer" "$blob"
	exp no "rollback: the layer is two inodes" checks

	# The zot log reader must not take one repository's report for another's.
	: >"$t/zot.log"; ok_line "$CONTROL_REPO" >>"$t/zot.log"; ok_line "$TEMP_REPO/deeper" >>"$t/zot.log"
	chk "gc result of another repository" "$(zot_gc_result "$t/zot.log" "$TEMP_REPO")" none
	chk "gc result, no log" "$(zot_gc_result "$t/absent.log" "$TEMP_REPO")" none
	: >"$t/zot.log"; bad_line "$TEMP_REPO" >>"$t/zot.log"
	chk "gc result, failed" "$(zot_gc_result "$t/zot.log" "$TEMP_REPO")" failed

	# zot_wait_gc ends on a report, on a deadline and on zot's exit.
	RD_POLL=0.1
	: >"$t/zot.log"; ok_line "$TEMP_REPO" >>"$t/zot.log"; ok_line "$CONTROL_REPO" >>"$t/zot.log"
	exp ok "wait: both reported" zot_wait_gc "$t/zot.log" "$(($(date +%s) + 30))" "$$" "$TEMP_REPO" "$CONTROL_REPO"
	: >"$t/zot.log"; ok_line "$CONTROL_REPO" >>"$t/zot.log"
	exp no "wait: one report short at the deadline" zot_wait_gc "$t/zot.log" "$(($(date +%s) + 1))" "$$" "$TEMP_REPO" "$CONTROL_REPO"
	local dead; (exit 0) & dead=$!; wait "$dead" || true
	exp no "wait: zot exited" zot_wait_gc "$t/zot.log" "$(($(date +%s) + 30))" "$dead" "$TEMP_REPO" "$CONTROL_REPO"
	RD_POLL=5

	# The temp: planted as a link inside the run, refused outside it.
	fixture; blob="$(rd_blob_path "$root" "$TEMP_REPO" "$d")"
	tmp="$(plant_temp "$t" "$blob")"
	exp ok "temp: a link with a temp's name" temp_ok "$tmp" "$blob"
	exp no "temp: a copy is not a crashed merge's link" temp_ok "$t/layer" "$blob"
	exp ok "temp: planted in the repository's .temps" test "$(dirname "$tmp")" = "$root/$TEMP_REPO/.temps"
	cp "$blob" "$(dirname "$tmp")/.tmp-11111111-2222-3333-4444-555555555555"
	exp no "temp: a copy with a temp's name" temp_ok "$(dirname "$tmp")/.tmp-11111111-2222-3333-4444-555555555555" "$blob"
	ln "$blob" "$(dirname "$tmp")/.tmp-short"
	exp no "temp: a link with a short name" temp_ok "$(dirname "$tmp")/.tmp-short" "$blob"
	ln "$blob" "$(dirname "$blob")/.tmp-22222222-3333-4444-5555-666666666666"
	exp no "temp: a link beside the blob" temp_ok "$(dirname "$blob")/.tmp-22222222-3333-4444-5555-666666666666" "$blob"
	exp no "temp: refused outside the run" plant_temp "$t/elsewhere" "$blob"
	# The store's own merges must have used the place the leg plants in.
	fixture; mkdir -p "$root/$CONTROL_REPO/.temps"
	exp ok "merge: .temps in one repository" merge_went_through_temps "$root" "$TEMP_REPO" "$CONTROL_REPO"
	fixture
	exp no "merge: no .temps anywhere" merge_went_through_temps "$root" "$TEMP_REPO" "$CONTROL_REPO"
	fixture; mkdir -p "$root/$CONTROL_REPO/.temps"; : >"$root/$TEMP_REPO/blobs/sha256/.tmp-22222222-3333-4444-5555-666666666666"
	exp no "merge: a temp among the blobs" merge_went_through_temps "$root" "$TEMP_REPO" "$CONTROL_REPO"
	[ -z "$(find "$t/elsewhere" -type f 2>/dev/null)" ] || { echo "self-test FAIL: a refused temp left a file"; bad=1; }

	# --lab with no inputs, with or without K3SM_LAB, is a precondition unmet, not a pass.
	K3SM_LAB=1 "$0" --lab >/dev/null 2>&1 || rc=$?
	chk "--lab with no inputs exits 3 with K3SM_LAB=1" "$rc" 3
	rc=0; env -u K3SM_LAB "$0" --lab >/dev/null 2>&1 || rc=$?
	chk "--lab exits 3 without K3SM_LAB" "$rc" 3
	rc=0; env -u K3SM_LAB "$0" --rollback-leg >/dev/null 2>&1 || rc=$?
	chk "--rollback-leg exits 3 without K3SM_LAB" "$rc" 3

	rm -rf "$t"
	lab_self_test || bad=1
	[ "$bad" = 0 ] || exit 1
	echo "$GATE_NAME self-test: PASS"
}

# ======================================================================================
# --lab: the rig leg. It drives a live two-node cluster through kubectl (as `sudo k3sm
# kubectl` on the server, so the admin token a server install rotates never strands the
# run), k3sm, Pods and a buildx push, and nothing else. It never runs on --self-test,
# which drives it over fake ssh, scp, sudo, k3sm and kubectl.
# ======================================================================================

SELF="$HERE/B1027.sh"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh disable=SC1091
. "$HERE/../lab/lib/tolerations.sh"

# The step table: `id|statement`. --plan prints it; a run logs every id, in this order.
LAB_STEPS=(
	"p.0|preconditions: inputs, sets, tools, hosts, sudo, both nodes Ready, nothing of this run there (exit 3, rig untouched)"
	"a.0|the old (zot) set installed: worker, then server; both Ready on it; zot serving"
	"a.1|under zot: an index with children, a Docker v2 image, two repositories sharing a layer; digests recorded"
	"a.2|the store as zot left it, snapshotted"
	"b.1|the new set rolled: worker, then server; both Ready on it; no zot process"
	"c.1|every recorded image survives by digest: ls, save by digest, each index child inspected by digest"
	"c.2|k3sm image ls, push, pull, tag, untag, inspect, save, prune (dry run)"
	"c.3|k3sm build with push (two variants) and a buildx push"
	"c.4|a pod on the worker pulls the built image"
	"c.5|a tag overwritten: Always runs the new digest, IfNotPresent keeps the cached one"
	"c.6|a pod on the worker pulls an index child by digest"
	"d.1|under the new release: a push and a cross-repository mount"
	"d.2|a GC cycle: a sweep finished after the server's start, none failed, nothing recorded reaped, all served"
	"d.3|store diff, zot's store against the new release's: no file that is not zot-shaped, the databases untouched"
	"e.1|rolled back to the old set: worker, then server; both Ready on it; zot serving"
	"e.2|zot serves every recorded image by digest"
	"e.3|zot GCs that store: a report in the window is judged (failed is red); none is recorded, and e.5 proves GC under zot"
	"e.4|store diff, zot's store against the store after the rollback: no file that is not zot-shaped"
	"e.5|the --rollback-leg (run beside the leg since p.0): zot takes back a deduped store"
	"f.1|cleanup: the namespace, every run tag and repository, the remote and local scratch"
)

lab_usage() {
	cat <<'EOF'
usage: K3SM_LAB=1 hack/acceptance/B1027.sh --lab \
         --old-set DIR --new-set DIR --server-ssh HOST --worker-ssh HOST \
         --server-lan ADDR --evidence DIR \
         [--server-work DIR] [--worker-work DIR] [--gc-wait S] [--zot-gc-wait S] \
         [--buildx-host HOST:PORT]
       hack/acceptance/B1027.sh --plan

  --old-set     stage.sh tree of the zot-era build (k3sm at its top, cp-payload/zot in it)
  --new-set     stage.sh tree of main (no zot member)
  --server-ssh  ssh name of the server, or `local` when this runs on it
  --worker-ssh  ssh name of the worker, or `local`
  --server-lan  the server's LAN address, which the worker joins (port 9345)
  --evidence    absolute, empty or absent: ../k3sm-io.scratch/B1027-evidence-<date>/
  --server-work / --worker-work  absolute scratch directory on that host, empty or
                absent (default /tmp/b1027-<run>-server and -worker); removed at the end
  --gc-wait     seconds from the new server's start to wait for its first GC sweep
                (default 4500: the sweep comes one grace plus a sixtieth after start)
  --zot-gc-wait seconds to wait, after the rollback, for zot's GC report (default 1800);
                no report in it is not a failure (see e.3 below)
  --buildx-host where the buildx push goes (default localhost:6451, the push gate)

The run installs the old set on both Macs (worker first), pushes under zot, rolls the
new set (worker first, then the server: the item and docs/m23-plan.md resolution 21
agree), checks the verbs, pods and a GC cycle, rolls back to the old set and has zot
serve the store. A zot GC report that appears within --zot-gc-wait is judged
(a failed GC or an error is red); the released zot collects every 6h, so when none
appears the run records "no zot GC cycle in the window; GC under zot is proven by
e.5" and e.3 passes on that basis. e.5 is the --rollback-leg, which runs zot's GC
with short intervals over a k3sm-written store; a red e.5 fails the leg. It cleans up everything it created, green or red, and LEAVES
THE RIG ON THE OLD SET (or wherever a red step stopped it). Restoring main is the
caller's step: install main's set on the worker, poll the join port, mint a 5m token,
rejoin, then the server, per .claude/rules/lab-rig.md.

Exit: 0 every step held; 1 a step failed (run.log names it; cleanup still ran);
3 a precondition is unmet (K3SM_LAB unset, a missing input, an unreachable host),
with the rig untouched. Never a silent skip.
EOF
}

lab_plan() {
	local row
	echo "B1027 rig leg: what a K3SM_LAB=1 --lab run does, in order."
	for row in "${LAB_STEPS[@]}"; do printf '  %-4s %s\n' "${row%%|*}" "${row#*|}"; done
}

# ---- pure helpers (the --self-test surface) -----------------------------------------

# LAB_PY: one helper program; the subcommand and the paths are its only arguments, and
# the JSON or log it reads is only ever data.
# shellcheck disable=SC2016
LAB_PY='
import gzip, hashlib, io, json, os, re, sys, tarfile
from datetime import datetime, timezone
cmd = sys.argv[1]
def sha(b): return "sha256:" + hashlib.sha256(b).hexdigest()
OCI_I = "application/vnd.oci.image.index.v1+json"
OCI_M = "application/vnd.oci.image.manifest.v1+json"
OCI_C = "application/vnd.oci.image.config.v1+json"
OCI_L = "application/vnd.oci.image.layer.v1.tar+gzip"
D_M = "application/vnd.docker.distribution.manifest.v2+json"
D_C = "application/vnd.docker.container.image.v1+json"
D_L = "application/vnd.docker.image.rootfs.diff.tar.gzip"

def layer(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data, mode in files:
            ti = tarfile.TarInfo(name); ti.size = len(data); ti.mode = mode; ti.mtime = 0
            t.addfile(ti, io.BytesIO(data))
    r = raw.getvalue(); z = io.BytesIO()
    with gzip.GzipFile(fileobj=z, mode="wb", mtime=0) as g: g.write(r)
    return z.getvalue(), sha(r)

class Layout:
    def __init__(s, out, name, run):
        s.dir = os.path.join(out, name); s.name = name; s.run = run
        os.makedirs(os.path.join(s.dir, "blobs", "sha256"), exist_ok=True)
        with open(os.path.join(s.dir, "oci-layout"), "w") as f: f.write("{\"imageLayoutVersion\":\"1.0.0\"}")
    def put(s, b):
        d = sha(b)
        with open(os.path.join(s.dir, "blobs", "sha256", d[7:]), "wb") as f: f.write(b)
        return d
    def image(s, docker, layers, osname, entry=None):
        cfg = {"architecture": "arm64", "os": osname, "rootfs": {"type": "layers", "diff_ids": [l[1] for l in layers]},
               "config": {"Labels": {"io.k3sm.b1027.run": s.run, "io.k3sm.b1027.layout": s.name}}}
        if entry: cfg["config"]["Entrypoint"] = entry
        cb = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
        m = {"schemaVersion": 2, "mediaType": D_M if docker else OCI_M,
             "config": {"mediaType": D_C if docker else OCI_C, "digest": s.put(cb), "size": len(cb)},
             "layers": [{"mediaType": D_L if docker else OCI_L, "digest": s.put(l[0]), "size": len(l[0])} for l in layers]}
        mb = json.dumps(m, separators=(",", ":")).encode()
        return {"mediaType": m["mediaType"], "digest": s.put(mb), "size": len(mb)}
    def top(s, desc):
        with open(os.path.join(s.dir, "index.json"), "w") as f:
            json.dump({"schemaVersion": 2, "mediaType": OCI_I, "manifests": [desc]}, f)

def tar_dir(src, dst):
    with tarfile.open(dst, "w") as t:
        for root, _, files in os.walk(src):
            for fn in sorted(files):
                p = os.path.join(root, fn); t.add(p, arcname=os.path.relpath(p, src))

if cmd == "gen":
    out, run, hello = sys.argv[2], sys.argv[3], sys.argv[4]
    with open(hello, "rb") as f: hb = f.read()
    rnd = lambda tag: os.urandom(262144) + (run + tag).encode()
    dig = {}
    L = Layout(out, "index", run)
    dar = L.image(False, [layer([("bin/hello-http", hb, 0o755)])], "darwin", ["/bin/hello-http", "--id", "b1027-index", "--addr", ":8080"])
    lin = L.image(False, [layer([("b1027/linux", rnd("linux"), 0o644)])], "linux")
    dar["platform"] = {"os": "darwin", "architecture": "arm64"}; lin["platform"] = {"os": "linux", "architecture": "arm64"}
    ib = json.dumps({"schemaVersion": 2, "mediaType": OCI_I, "manifests": [dar, lin]}, separators=(",", ":")).encode()
    L.top({"mediaType": OCI_I, "digest": L.put(ib), "size": len(ib)})
    dig["index"], dig["index.darwin"], dig["index.linux"] = sha(ib), dar["digest"], lin["digest"]
    tar_dir(L.dir, os.path.join(out, "index.tar"))
    D = Layout(out, "docker", run); d = D.image(True, [layer([("b1027/docker", rnd("docker"), 0o644)])], "linux"); D.top(d); dig["docker"] = d["digest"]
    shared = layer([("b1027/shared", rnd("shared"), 0o644)])
    for n in ("shared-a", "shared-b", "pushed", "gc"):
        X = Layout(out, n, run)
        x = X.image(False, [shared] if n.startswith("shared") else [layer([("b1027/" + n, rnd(n), 0o644)])], "linux")
        X.top(x); dig[n] = x["digest"]
    with open(os.path.join(out, "digests.txt"), "w") as f:
        for k in sorted(dig): f.write("%s %s\n" % (k, dig[k]))
elif cmd == "ls-pairs":
    d = json.load(sys.stdin)
    for i in d.get("images") or []:
        ref = i.get("reference") or ""
        pair = ref.split("/", 1)[1] if "/" in ref else "%s:%s" % (i.get("repository"), i.get("tag"))
        print(pair, i.get("digest") or "-")
elif cmd == "ls-reachable":
    d = json.load(sys.stdin); print("yes" if (d.get("registry") or {}).get("reachable") else "no")
elif cmd == "saved-digest":
    with tarfile.open(sys.argv[2]) as t:
        m = json.load(t.extractfile("index.json"))["manifests"]
    print(m[0]["digest"] if len(m) == 1 else "many")
elif cmd == "pod":
    d = json.load(sys.stdin); st = d.get("status") or {}
    ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions") or [])
    cs = st.get("containerStatuses") or [{}]
    print("ready" if ready else "notready", cs[0].get("imageID") or "-")
elif cmd == "nodes":
    d = json.load(sys.stdin); want = sys.argv[2]
    for i in d.get("items") or []:
        md, sp, stt = i["metadata"], i.get("spec") or {}, i.get("status") or {}
        cp = "node-role.kubernetes.io/control-plane" in (md.get("labels") or {})
        ready = any(c["type"] == "Ready" and c["status"] == "True" for c in stt.get("conditions") or []) and not sp.get("unschedulable")
        if want == "server" and cp or want == "worker" and not cp: print(md["name"])
        if want == "notready" and not ready: print(md["name"])
        if want == "taints":
            for t in sp.get("taints") or []: print("%s:%s" % (t["key"], t.get("effect", "")))
elif cmd == "gc-sweep":
    since = float(sys.argv[2]); last = None
    for line in sys.stdin:
        try: r = json.loads(line)
        except ValueError: continue
        if r.get("msg") != "registry gc: sweep finished": continue
        try: t = datetime.fromisoformat(str(r.get("time", "")).replace("Z", "+00:00")).timestamp()
        except ValueError: continue
        if t >= since: last = r
    if last is None: print("none")
    elif int(last.get("failed") or 0) == 0 and not last.get("err"): print("ok")
    else: print("failed")
elif cmd == "reaped":
    hexes = [l.split()[1].split(":")[-1] for l in open(sys.argv[2]) if len(l.split()) == 2]
    for line in sys.stdin:
        try: r = json.loads(line)
        except ValueError: continue
        if r.get("msg") in ("registry gc: would reap", "registry gc: reaped"):
            for h in hexes:
                if h and h in str(r.get("name", "")): print(r.get("msg"), r.get("repository"), r.get("name"))
elif cmd == "store-verdict":
    def load(p):
        S, H = {}, {}
        for line in open(p):
            f = line.rstrip("\n").split("\t")
            if f[0] == "S" and len(f) >= 7: S[f[6]] = {"type": f[1], "mode": f[2], "owner": f[3], "size": f[4], "mtime": f[5]}
            elif f[0] == "H" and len(f) >= 3: H[f[2]] = f[1]
        for k, v in S.items(): v["hash"] = H.get(k, "-")
        return S
    before, after, mode = load(sys.argv[2]), load(sys.argv[3]), sys.argv[4]
    HEX = re.compile(r"^[0-9a-f]{64}$")
    def repos(S): return {os.path.dirname(p) for p, v in S.items() if v["type"] != "Directory" and os.path.basename(p) in ("index.json", "oci-layout")}
    R = repos(before) | repos(after)
    def repo_of(p):
        d = os.path.dirname(p)
        while d not in ("", ".", "/"):
            if d in R: return d
            d = os.path.dirname(d)
        return None
    def shape(rel):
        parts = rel.split("/")
        if rel in ("index.json", "oci-layout"): return rel
        if len(parts) == 3 and parts[:2] == ["blobs", "sha256"] and HEX.match(parts[2]): return "blob"
        if len(parts) == 2 and parts[0] == ".uploads" and parts[1] and not parts[1].startswith("."): return "upload"
        return None
    seen = {}
    for p, v in before.items():
        r = repo_of(p)
        if v["type"] == "Directory" or r is None: continue
        k = shape(p[len(r) + 1:])
        if k: seen.setdefault(k, set()).add((v["mode"], v["owner"]))
    bad = 0
    for p in sorted(after):
        v, b = after[p], before.get(p)
        new = b is None
        if not new and all(b[x] == v[x] for x in ("type", "mode", "owner", "size", "hash")): continue
        r = repo_of(p); what = "new" if new else "changed"
        if v["type"] == "Directory":
            rel = p[len(r) + 1:] if r else None
            if r is not None and rel not in ("blobs", "blobs/sha256", ".uploads"):
                print("FACT a directory that is not zot-shaped (files are judged, directories recorded):", p)
            continue
        if r is None:
            print("FACT", what, "outside any repository:", p); continue
        k = shape(p[len(r) + 1:])
        if k is None:
            print("NONZOT", what, p); bad = 1; continue
        if k in seen:
            if v["mode"] not in {m for m, _ in seen[k]}: print("MODE", p, v["mode"], "zot wrote", sorted({m for m, _ in seen[k]})); bad = 1
            if v["owner"] not in {o for _, o in seen[k]}: print("OWNER", p, v["owner"], "zot wrote", sorted({o for _, o in seen[k]})); bad = 1
        else:
            print("FACT no zot-era", k, "to compare mode and owner with:", p)
    if mode == "k3sm":
        for db in ("./cache.db", "./meta.db"):
            if db not in before: print("FACT", db, "absent under zot"); continue
            a = after.get(db)
            if a is None or any(before[db][x] != a[x] for x in ("size", "mtime", "hash")): print("DB", db, "written or removed"); bad = 1
    print("verdict:", "FAIL" if bad else "PASS")
    sys.exit(bad)
else:
    sys.exit("unknown helper " + cmd)
'
lab_py() { python3 -I -c "$LAB_PY" "$@"; }

# digests_hold <recorded> <observed>: every `ref digest` line of recorded is in observed
# with the same digest. Prints MISSING and MISMATCH lines; 1 on any.
digests_hold() {
	awk 'NR == FNR { seen[$1] = $2; next }
		NF == 2 { if (!($1 in seen)) { print "MISSING " $1; bad = 1 } else if (seen[$1] != $2) { print "MISMATCH " $1 " want " $2 " got " seen[$1]; bad = 1 } }
		END { exit bad }' "$2" "$1"
}

# store_verdict <before> <after> <k3sm|zot>: resolution 4 over two snapshots.
store_verdict() { lab_py store-verdict "$1" "$2" "$3"; }

# snapshot_script <store>: the remote shell that lists the store, one S line per path
# (type, mode, owner, size, mtime, path) and one H line per index.json and oci-layout.
snapshot_script() {
	cat <<EOF
cd $(printf '%q' "$1") || exit 1
find . -mindepth 1 -print0 | xargs -0 stat -f 'S	%HT	%Lp	%Su:%Sg	%z	%m	%N'
find . -type f \\( -name index.json -o -name oci-layout -o -name cache.db -o -name meta.db \\) -print0 | xargs -0 shasum -a 256 | awk '{ h = \$1; sub(/^[0-9a-f]+  /, ""); printf "H\\t%s\\t%s\\n", h, \$0 }'
EOF
}

# ---- remote primitives (B1240's, the rig's one way to reach a Mac) ---------------------

# bounded <seconds> <cmd...>: run cmd, killing it after the budget (macOS has no timeout).
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
quoted() { printf '%q ' "$@"; }
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
rsh_raw() {
	if [ "$1" = local ]; then
		/bin/bash -c "$2"
	else
		# shellcheck disable=SC2029 # built to expand on this side, quoted
		ssh "${SSH_OPTS[@]}" "$1" "$2"
	fi
}
rsh() {
	local h="$1"
	shift
	bounded "$STEP_TIMEOUT" rsh_raw "$h" "$(quoted "$@")"
}
put() { if [ "$1" = local ]; then cp "$2" "$3"; else scp -q "${SSH_OPTS[@]}" "$2" "$1:$3"; fi; }
# root_run <host> <work> <name> <bound>: the script on stdin as a file under sudo (an
# `ssh host "sudo a && b"` runs only a as root); fd 3 is the root step's own stdin.
root_run() {
	local h="$1" work="$2" name="$3" bound="$4" f
	f="$EVIDENCE/scripts/$name.sh"
	{
		echo '#!/bin/bash'
		cat
	} >"$f"
	put "$h" "$f" "$work/$name.sh" </dev/null
	bounded "$bound" rsh_raw "$h" "$(quoted sudo /bin/bash "$work/$name.sh")" <&3
}
fetch() { bounded "$STEP_TIMEOUT" rsh_raw "$1" "$(quoted sudo /bin/cat "$2")" </dev/null; }

k() { rsh "$SERVER" sudo "$K3SM_BIN" "$@"; }
kc() { k kubectl "$@"; }
kw() { rsh "$WORKER" sudo "$K3SM_BIN" "$@"; }
# ki <verb> <args...>: an image verb as root on the server, with its push credential.
ki() { k image "$@" --work-dir "$SWD"; }
# ku <args...>: k3sm as the server's own user (ls, build: its merged kubeconfig).
ku() { rsh "$SERVER" "$K3SM_BIN" "$@"; }

# ---- the run ---------------------------------------------------------------------------

lab_refuse() {
	echo "$GATE_NAME lab: PRECONDITION UNMET (exit 3, not a pass, the rig untouched): $*" >&2
	[ -z "${RUNLOG:-}" ] || [ ! -f "$RUNLOG" ] || echo "PRECONDITION UNMET: $*" >>"$RUNLOG"
	exit 3
}
lab_log() { printf '%s\n' "$*" | tee -a "$RUNLOG"; }
why() {
	DETAIL="$*"
	echo "why: $*"
}
LAB_FAILED=""
# step <id> <function>: run one step, its output in <evidence>/<id>.log. After a red
# step every later one is NOT REACHED, which is a failure, and f.1 still runs.
step() {
	local id="$1" fn="$2"
	if [ -n "$LAB_FAILED" ] && [ "$id" != f.1 ]; then
		lab_log "NOT REACHED $id"
		return 0
	fi
	STEP_LOG="$EVIDENCE/$id.log"
	lab_log "STEP $id"
	DETAIL=""
	if "$fn" >>"$STEP_LOG" 2>&1 </dev/null; then
		lab_log "PASS $id ${DETAIL}"
	else
		lab_log "FAIL $id ${DETAIL}"
		[ -n "$LAB_FAILED" ] || LAB_FAILED="$id"
	fi
}

record() { echo "$1 $2" >>"$REC"; }
unrecord() { awk -v r="$1" '$1 != r' "$REC" >"$REC.tmp" && mv "$REC.tmp" "$REC"; }
gen_digest() { awk -v k="$1" '$1 == k { print $2 }' "$LOCAL_WORK/gen/digests.txt"; }
pushed_digest() { awk '$1 == "digest:" { print $2 }' "$1" | tail -1; }

# ls_pairs <name>: `image ls -o json` as the server's user, kept and turned to pairs.
ls_pairs() {
	ku image ls -o json >"$EVIDENCE/$1.json" 2>"$EVIDENCE/$1.err" || return 1
	[ "$(lab_py ls-reachable <"$EVIDENCE/$1.json")" = yes ] || return 1
	lab_py ls-pairs <"$EVIDENCE/$1.json" >"$EVIDENCE/$1.pairs"
}

nodes_doc() { kc get nodes -o json; }
wait_ready() {
	local deadline=$((SECONDS + READY_TIMEOUT)) doc
	while [ "$SECONDS" -lt "$deadline" ]; do
		if doc="$(nodes_doc 2>/dev/null)" && [ -n "$doc" ] && [ -z "$(printf '%s' "$doc" | lab_py nodes notready)" ]; then return 0; fi
		sleep "$POLL"
	done
	return 1
}
installed_version() { rsh "$1" sudo "$K3SM_BIN" version 2>/dev/null | sed -n 1p; }
# zot_running: a process on the server whose argv[0] is zot.
zot_running() { rsh "$SERVER" /bin/ps -axo comm= | awk '{ n = $1; sub(/.*\//, "", n); if (n == "zot") f = 1 } END { exit !f }'; }
# zot_started - the daemon starts zot some seconds after the install returns, so
# wait for it, bounded by ZOT_START_WAIT, polling every 5 s.
zot_started() {
	local deadline=$((SECONDS + ZOT_START_WAIT))
	while :; do
		zot_running && return 0
		[ "$SECONDS" -lt "$deadline" ] || return 1
		sleep 5
	done
}

# registry_settled - the registry starts listening some seconds after the install
# returns. Wait, bounded by REGISTRY_WAIT, until `image ls` answers. It never
# fails a step: the step that reads the registry next judges it.
registry_settled() {
	local deadline=$((SECONDS + REGISTRY_WAIT))
	while :; do
		ku image ls -o json 2>/dev/null | lab_py ls-reachable 2>/dev/null | grep -qx yes && return 0
		[ "$SECONDS" -lt "$deadline" ] || return 0
		sleep 5
	done
}

ship_set() {
	local h="$1" w="$2" name="$3"
	put "$h" "$LOCAL_WORK/$name.tar.gz" "$w/$name.tar.gz" </dev/null || return 1
	rsh "$h" /bin/mkdir -p "$w/$name" || return 1
	bounded "$INSTALL_TIMEOUT" rsh_raw "$h" "$(quoted /usr/bin/tar -xzf "$w/$name.tar.gz" -C "$w/$name")" </dev/null || return 1
	rsh "$h" /bin/rm -f "$w/$name.tar.gz"
}
install_server() {
	root_run "$SERVER" "$SERVER_WORK" "install-server-$1-$2" "$INSTALL_TIMEOUT" 3</dev/null <<EOF
exec $(quoted "$SERVER_WORK/$1/k3sm") install --start --user $(quoted "$SERVER_USER")
EOF
}
token_path() { printf '%s' "$WORKER_WORK/private/join-token"; }
install_worker() {
	local token i=0 rc=0
	# The join port opens about 20 s after the server reports Ready (lab-rig.md step 3).
	while [ "$i" -lt 40 ]; do
		rsh "$WORKER" nc -z -G 3 "$SERVER_LAN" 9345 >/dev/null 2>&1 && break
		sleep "$POLL"
		i=$((i + 1))
	done
	[ "$i" -lt 40 ] || {
		echo "the join port on $SERVER_LAN:9345 did not open"
		return 1
	}
	# A fresh, short-lived token for every rejoin (lab-rig.md step 4).
	token="$(k token create --ttl 5m --work-dir "$SWD" 2>/dev/null)" || return 1
	[ -n "$token" ] || return 1
	root_run "$WORKER" "$WORKER_WORK" "install-worker-$1-$2" "$INSTALL_TIMEOUT" 3< <(printf '%s\n' "$token") <<EOF || rc=$?
IFS= read -r token
tf=$(quoted "$(token_path)")
trap 'rm -f "\$tf"' EXIT
umask 077
mkdir -p "\$(dirname "\$tf")"
printf '%s\n' "\$token" >"\$tf"
$(quoted "$WORKER_WORK/$1/k3sm") install --agent --server $(quoted "$SERVER_LAN") --token-file "\$tf" --start --user $(quoted "$WORKER_USER")
EOF
	rsh "$WORKER" /bin/rm -f "$(token_path)" >/dev/null 2>&1 || true
	return "$rc"
}
# copy_kubeconfig: a server install rotates the admin token; the worker's copy is
# re-copied after a dated backup (lab-rig.md step 5), and never emptied.
KUBE_COPIES=0
copy_kubeconfig() {
	local cfg
	cfg="$(rsh "$SERVER" "$K3SM_BIN" kubectl config view --minify --flatten --raw --context k3sm 2>/dev/null)" || cfg=""
	[ -n "$cfg" ] || {
		echo "note: no admin context to copy; the worker's ~/.kube/config is stale"
		return 0
	}
	KUBE_COPIES=$((KUBE_COPIES + 1))
	printf '%s\n' "$cfg" | bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "umask 077; mkdir -p ~/.kube; if [ -f ~/.kube/config ]; then cp ~/.kube/config ~/.kube/config.b1027-$RUN-$KUBE_COPIES; fi; cat >~/.kube/config" ||
		echo "note: could not copy the admin kubeconfig to the worker"
}
# roll <set> <label>: the worker, then the server (resolution 21: workers first); both
# Ready, both reporting the set's version.
roll() {
	local set="$1" want got
	if [ "$set" = old ]; then want="$OLD_VER"; else want="$NEW_VER"; fi
	echo "== worker to $set ($want)"
	install_worker "$set" "$2" || {
		why "the worker's install of the $set set failed"
		return 1
	}
	got="$(installed_version "$WORKER")"
	[ "$got" = "$want" ] || {
		why "the worker reports '$got', not the $set set's '$want'"
		return 1
	}
	echo "== server to $set ($want)"
	ROLL_EPOCH="$(rsh "$SERVER" /bin/date +%s)"
	install_server "$set" "$2" || {
		why "the server's install of the $set set failed"
		return 1
	}
	got="$(installed_version "$SERVER")"
	[ "$got" = "$want" ] || {
		why "the server reports '$got', not the $set set's '$want'"
		return 1
	}
	copy_kubeconfig
	wait_ready || {
		why "both nodes not Ready and schedulable within ${READY_TIMEOUT}s on the $set set"
		return 1
	}
	echo "worker and server on $want, both Ready"
}

pod_yaml() { # <name> <image> <policy>
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS, labels: {app: b1027}}
spec:
  nodeName: $WORKER_NODE
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$TOLERATIONS]
  containers:
  - name: app
    image: $2
    imagePullPolicy: $3
EOF
}
# run_pod <name> <image> <policy>: the pod Ready on the worker; POD_ID is its imageID.
run_pod() {
	local deadline out
	pod_yaml "$1" "$2" "$3" >"$EVIDENCE/$1.yaml"
	kc apply -f - <"$EVIDENCE/$1.yaml" || return 1
	deadline=$((SECONDS + POD_TIMEOUT))
	while [ "$SECONDS" -lt "$deadline" ]; do
		out="$(kc get pod "$1" -n "$NS" -o json 2>/dev/null | lab_py pod 2>/dev/null)" || out=""
		case "$out" in ready\ *)
			POD_ID="${out#ready }"
			echo "$1 Ready, imageID $POD_ID"
			return 0
			;;
		esac
		sleep "$POLL"
	done
	kc get events -n "$NS" -o wide >"$EVIDENCE/$1.events" 2>&1 || true
	echo "$1 not Ready in ${POD_TIMEOUT}s (last: ${out:-none})"
	return 1
}
drop_pod() {
	local deadline=$((SECONDS + POD_TIMEOUT))
	kc delete pod "$1" -n "$NS" --wait=false >/dev/null 2>&1 || true
	while [ "$SECONDS" -lt "$deadline" ]; do
		kc get pod "$1" -n "$NS" >/dev/null 2>&1 || return 0
		sleep "$POLL"
	done
	return 1
}
has_digest() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
# saved_is <ref> <digest> <name>: save by reference; the saved layout names the digest.
saved_is() {
	local remote="$SERVER_WORK/save-$3.tar" got
	ki save -o "$remote" "$REG/$1" || return 1
	fetch "$SERVER" "$remote" >"$LOCAL_WORK/save-$3.tar" || return 1
	got="$(lab_py saved-digest "$LOCAL_WORK/save-$3.tar")" || return 1
	rm -f "$LOCAL_WORK/save-$3.tar"
	[ "$got" = "$2" ] || {
		echo "save of $1 holds $got, want $2"
		return 1
	}
}
snapshot() { # <name>
	snapshot_script "$STORE" | root_run "$SERVER" "$SERVER_WORK" "snapshot-$1" "$INSTALL_TIMEOUT" 3</dev/null >"$EVIDENCE/store-$1.txt" || return 1
	[ -s "$EVIDENCE/store-$1.txt" ]
}

# ---- the steps ----------------------------------------------------------------------------

s_a0() {
	ship_set "$WORKER" "$WORKER_WORK" old && ship_set "$WORKER" "$WORKER_WORK" new &&
		ship_set "$SERVER" "$SERVER_WORK" old && ship_set "$SERVER" "$SERVER_WORK" new || {
		why "could not ship the sets"
		return 1
	}
	roll old a0 || return 1
	zot_started || {
		why "no zot process on the server under the old set: it is not the zot-era build"
		return 1
	}
	registry_settled
	kc create namespace "$NS" || {
		why "could not create $NS"
		return 1
	}
	DETAIL="both on $OLD_VER, zot serving"
}
s_a1() {
	local n d got
	put "$SERVER" "$LOCAL_WORK/gen.tar.gz" "$SERVER_WORK/gen.tar.gz" || return 1
	rsh "$SERVER" /usr/bin/tar -xzf "$SERVER_WORK/gen.tar.gz" -C "$SERVER_WORK" || return 1
	ki import "$SERVER_WORK/gen/index.tar" --reference "$REG/$P/index:v1" >"$EVIDENCE/a.1-import-index.txt" 2>&1 || {
		why "image import of the index failed (a.1-import-index.txt)"
		return 1
	}
	record "$P/index:v1" "$(gen_digest index)"
	echo "$P/index@$(gen_digest index.darwin)" >"$CHILDREN"
	echo "$P/index@$(gen_digest index.linux)" >>"$CHILDREN"
	for n in docker shared-a shared-b; do
		d="$(gen_digest "$n")"
		ki push "$SERVER_WORK/gen/$n" "$REG/$P/$n:v1" >"$EVIDENCE/a.1-push-$n.txt" 2>&1 || {
			why "image push of $n failed (a.1-push-$n.txt)"
			return 1
		}
		got="$(pushed_digest "$EVIDENCE/a.1-push-$n.txt")"
		[ "$got" = "$d" ] || {
			why "push of $n printed $got, the layout's digest is $d: refused"
			return 1
		}
		record "$P/$n:v1" "$d"
	done
	ls_pairs a.1-ls || {
		why "image ls did not answer under zot"
		return 1
	}
	digests_hold "$REC" "$EVIDENCE/a.1-ls.pairs" || {
		why "zot does not list what was pushed at the pushed digests: refused"
		return 1
	}
	cp "$REC" "$EVIDENCE/a.1-recorded.txt"
	DETAIL="$(wc -l <"$REC" | tr -d ' ') tags and 2 index children recorded (a.1-recorded.txt)"
}
s_a2() { snapshot zot || { why "no snapshot of $STORE"; return 1; }; }
s_b1() {
	roll new b1 || return 1
	GC_SINCE="$ROLL_EPOCH"
	if zot_running; then
		why "a zot process still runs on the server under the new set"
		return 1
	fi
	registry_settled
	DETAIL="both on $NEW_VER, no zot"
}
s_c1() {
	local ref d n=0 c
	ls_pairs c.1-ls || {
		why "image ls did not answer under the new release"
		return 1
	}
	digests_hold "$REC" "$EVIDENCE/c.1-ls.pairs" || {
		why "a recorded image did not survive the upgrade by digest: refused"
		return 1
	}
	while read -r ref d; do
		n=$((n + 1))
		saved_is "${ref%:*}@$d" "$d" "c1-$n" </dev/null || {
			why "save of ${ref%:*}@$d did not return that manifest"
			return 1
		}
	done <"$REC"
	while read -r c; do
		ki inspect "$REG/$c" </dev/null || {
			why "the index child $c is not served by digest"
			return 1
		}
	done <"$CHILDREN"
	DETAIL="$n images by digest, $(wc -l <"$CHILDREN" | tr -d ' ') children by digest"
}
s_c2() {
	local d got
	ls_pairs c.2-ls || {
		why "ls"
		return 1
	}
	d="$(gen_digest pushed)"
	ki push "$SERVER_WORK/gen/pushed" "$REG/$P/pushed:v1" >"$EVIDENCE/c.2-push.txt" 2>&1 || {
		why "push (c.2-push.txt)"
		return 1
	}
	got="$(pushed_digest "$EVIDENCE/c.2-push.txt")"
	[ "$got" = "$d" ] || {
		why "push printed $got, the layout's digest is $d: refused"
		return 1
	}
	record "$P/pushed:v1" "$d"
	kw image pull --platform darwin/arm64 --no-mirror "$REG/$P/index:v1" || {
		why "pull of the index on the worker"
		return 1
	}
	ki tag "$REG/$P/pushed:v1" "$REG/$P/pushed:tagged" || {
		why "tag"
		return 1
	}
	ls_pairs c.2-ls-tagged && grep -qx "$P/pushed:tagged $d" "$EVIDENCE/c.2-ls-tagged.pairs" || {
		why "the new tag is not listed at $d"
		return 1
	}
	ki untag --digest "$d" "$REG/$P/pushed:tagged" || {
		why "untag"
		return 1
	}
	ls_pairs c.2-ls-untagged || return 1
	if grep -q "^$P/pushed:tagged " "$EVIDENCE/c.2-ls-untagged.pairs"; then
		why "untag left the tag listed"
		return 1
	fi
	digests_hold "$REC" "$EVIDENCE/c.2-ls-untagged.pairs" || {
		why "untag moved a recorded tag"
		return 1
	}
	ki inspect "$REG/$P/docker:v1" >"$EVIDENCE/c.2-inspect.txt" 2>&1 && grep -q "$(gen_digest docker)" "$EVIDENCE/c.2-inspect.txt" || {
		why "inspect of the Docker v2 image (c.2-inspect.txt)"
		return 1
	}
	saved_is "$P/shared-a:v1" "$(gen_digest shared-a)" c2-shared-a || {
		why "save"
		return 1
	}
	# Dry run only: the cache half of --force has no filter and evicts every image no
	# pod uses at that moment, another workload's included (one-image-store.sh).
	ki prune -o json >"$EVIDENCE/c.2-prune.json" 2>&1 || {
		why "prune dry run (c.2-prune.json)"
		return 1
	}
	ls_pairs c.2-ls-pruned && digests_hold "$REC" "$EVIDENCE/c.2-ls-pruned.pairs" || {
		why "a dry-run prune moved a recorded tag"
		return 1
	}
	DETAIL="ls push pull tag untag inspect save prune(dry run)"
}
# builder_ready - the buildx push needs the builder engine, a Pod a reinstall
# can remove. Start it when it is not running and remember that this run did,
# so f.1 stops it again and leaves the rig as it was found.
BUILDER_STARTED=0
builder_ready() {
	ku builder status >"$EVIDENCE/c.3-builder-status.txt" 2>&1 || true
	grep -q 'Running' "$EVIDENCE/c.3-builder-status.txt" && return 0
	bounded "$INSTALL_TIMEOUT" rsh_raw "$SERVER" "$(quoted "$K3SM_BIN" builder up)" >"$EVIDENCE/c.3-builder-up.txt" 2>&1 </dev/null || return 1
	BUILDER_STARTED=1
}
s_c3() {
	local v d
	put "$SERVER" "$LOCAL_WORK/ctx.tar.gz" "$SERVER_WORK/ctx.tar.gz" || return 1
	rsh "$SERVER" /usr/bin/tar -xzf "$SERVER_WORK/ctx.tar.gz" -C "$SERVER_WORK" || return 1
	for v in v1 v2; do
		bounded "$INSTALL_TIMEOUT" rsh_raw "$SERVER" "cd $(quoted "$SERVER_WORK/ctx-$v") && $(quoted "$K3SM_BIN" build --tag "$REG/$P/app:$v" --push .)" >"$EVIDENCE/c.3-build-$v.txt" 2>&1 || {
			why "k3sm build --push of app:$v (c.3-build-$v.txt)"
			return 1
		}
	done
	builder_ready || {
		why "the builder engine did not start (c.3-builder-up.txt)"
		return 1
	}
	rsh "$SERVER" /bin/mkdir -p "$SERVER_WORK/docker" || return 1
	rsh "$SERVER" /usr/bin/env "DOCKER_CONFIG=$SERVER_WORK/docker" "$K3SM_BIN" registry login >"$EVIDENCE/c.3-login.txt" 2>&1 || {
		why "registry login into the run's own DOCKER_CONFIG"
		return 1
	}
	bounded "$INSTALL_TIMEOUT" rsh_raw "$SERVER" "$(quoted /usr/bin/env "DOCKER_CONFIG=$SERVER_WORK/docker" "$K3SM_BIN" builder buildx build --push -t "$BUILDX_HOST/$P/buildx:v1" "$SERVER_WORK/ctx-v1")" >"$EVIDENCE/c.3-buildx.txt" 2>&1 || {
		why "buildx push to $BUILDX_HOST (c.3-buildx.txt)"
		return 1
	}
	ls_pairs c.3-ls || return 1
	for v in app:v1 app:v2 buildx:v1; do
		d="$(awk -v r="$P/$v" '$1 == r { print $2 }' "$EVIDENCE/c.3-ls.pairs")"
		[[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || {
			why "$P/$v is not listed with a digest after its push"
			return 1
		}
		record "$P/$v" "$d"
	done
	APP_A="$(awk -v r="$P/app:v1" '$1 == r { print $2 }' "$REC")"
	APP_B="$(awk -v r="$P/app:v2" '$1 == r { print $2 }' "$REC")"
	[ "$APP_A" != "$APP_B" ] || {
		why "the two app variants have one digest"
		return 1
	}
	DETAIL="app:v1 $APP_A, app:v2 $APP_B, buildx:v1 listed"
}
s_c4() {
	run_pod app-pull "$REG/$P/app:v1" Always || {
		why "the pod on the worker did not run app:v1"
		return 1
	}
	has_digest "$POD_ID" "$APP_A" || {
		why "imageID $POD_ID, want $APP_A"
		return 1
	}
	drop_pod app-pull
	DETAIL="pulled on $WORKER_NODE at $APP_A"
}
s_c5() {
	local live="$REG/$P/app:live" ifnp always
	ki tag "$REG/$P/app:v1" "$live" || return 1
	run_pod live-ifnp-1 "$live" IfNotPresent && has_digest "$POD_ID" "$APP_A" || {
		why "IfNotPresent before the overwrite: $POD_ID, want $APP_A"
		return 1
	}
	run_pod live-always-1 "$live" Always && has_digest "$POD_ID" "$APP_A" || {
		why "Always before the overwrite: $POD_ID, want $APP_A"
		return 1
	}
	drop_pod live-ifnp-1 && drop_pod live-always-1 || return 1
	ki tag --force "$REG/$P/app:v2" "$live" || {
		why "tag --force did not re-point app:live"
		return 1
	}
	ls_pairs c.5-ls && grep -qx "$P/app:live $APP_B" "$EVIDENCE/c.5-ls.pairs" || {
		why "app:live is not listed at $APP_B after the overwrite"
		return 1
	}
	record "$P/app:live" "$APP_B"
	# IfNotPresent first: an Always pull re-points the node's own copy of the tag.
	run_pod live-ifnp-2 "$live" IfNotPresent || return 1
	ifnp="$POD_ID"
	run_pod live-always-2 "$live" Always || return 1
	always="$POD_ID"
	drop_pod live-always-2
	drop_pod live-ifnp-2
	has_digest "$always" "$APP_B" || {
		why "Always after the overwrite ran $always, want the new $APP_B"
		return 1
	}
	has_digest "$ifnp" "$APP_A" || {
		why "IfNotPresent after the overwrite ran $ifnp, want the cached $APP_A"
		return 1
	}
	DETAIL="Always $APP_B, IfNotPresent kept $APP_A"
}
s_c6() {
	local child
	child="$(gen_digest index.darwin)"
	run_pod index-child "$REG/$P/index@$child" IfNotPresent || {
		why "a pod on the worker did not run the index child $child"
		return 1
	}
	has_digest "$POD_ID" "$child" || {
		why "imageID $POD_ID, want $child"
		return 1
	}
	drop_pod index-child
	DETAIL="the darwin child $child ran on $WORKER_NODE"
}
s_d1() {
	local d got
	d="$(gen_digest gc)"
	ki push "$SERVER_WORK/gen/gc" "$REG/$P/gc:v1" >"$EVIDENCE/d.1-push.txt" 2>&1 || {
		why "push (d.1-push.txt)"
		return 1
	}
	got="$(pushed_digest "$EVIDENCE/d.1-push.txt")"
	[ "$got" = "$d" ] || {
		why "push printed $got, want $d: refused"
		return 1
	}
	# A copy within the cluster registry mounts the blobs rather than sending them.
	d="$(gen_digest shared-a)"
	ki push "$REG/$P/shared-a:v1" "$REG/$P/mounted:v1" >"$EVIDENCE/d.1-mount.txt" 2>&1 || {
		why "the cross-repository copy (d.1-mount.txt)"
		return 1
	}
	got="$(pushed_digest "$EVIDENCE/d.1-mount.txt")"
	[ "$got" = "$d" ] || {
		why "mount printed $got, want $d: refused"
		return 1
	}
	record "$P/mounted:v1" "$d"
	# gc:v1 untagged leaves an untagged manifest for the sweep to see.
	ki untag "$REG/$P/gc:v1" || {
		why "untag of gc:v1"
		return 1
	}
	DETAIL="gc:v1 pushed and untagged, mounted:v1 at $d"
}
s_d2() {
	local deadline=$((GC_SINCE + GC_WAIT)) got=none
	echo "waiting for a sweep finished after $GC_SINCE (until $deadline)"
	while :; do
		fetch "$SERVER" "$RLOG" >"$EVIDENCE/d.2-registry.log" 2>/dev/null || true
		got="$(lab_py gc-sweep "$GC_SINCE" <"$EVIDENCE/d.2-registry.log")"
		[ "$got" = none ] || break
		[ "$(rsh "$SERVER" /bin/date +%s)" -lt "$deadline" ] || break
		sleep "$POLL"
	done
	[ "$got" = ok ] || {
		why "the GC sweep after the new server's start: $got"
		return 1
	}
	lab_py reaped "$REC" <"$EVIDENCE/d.2-registry.log" >"$EVIDENCE/d.2-reaped.txt"
	[ ! -s "$EVIDENCE/d.2-reaped.txt" ] || {
		why "the sweep names a recorded digest (d.2-reaped.txt)"
		return 1
	}
	ls_pairs d.2-ls && digests_hold "$REC" "$EVIDENCE/d.2-ls.pairs" || {
		why "a recorded image is not served at its digest after the sweep"
		return 1
	}
	DETAIL="a sweep finished with none failed; every recorded tag still at its digest"
}
s_d3() {
	snapshot k3sm || {
		why "no snapshot"
		return 1
	}
	store_verdict "$EVIDENCE/store-zot.txt" "$EVIDENCE/store-k3sm.txt" k3sm >"$EVIDENCE/d.3-verdict.txt" || {
		why "$(grep -E '^(NONZOT|MODE|OWNER|DB) ' "$EVIDENCE/d.3-verdict.txt" | head -3 | tr '\n' ';') (d.3-verdict.txt)"
		return 1
	}
	DETAIL="zot-shaped (d.3-verdict.txt)"
}
s_e1() {
	# zot's reports are read from the lines past this count; a log the install
	# truncated is read whole (s_e3).
	ZOT_SINCE_LINES="$(fetch "$SERVER" "$RLOG" | wc -l | tr -d ' ')"
	roll old e1 || return 1
	zot_started || {
		why "no zot process after the rollback"
		return 1
	}
	registry_settled
	DETAIL="both on $OLD_VER, zot serving"
}
s_e2() {
	local ref d n=0
	ls_pairs e.2-ls || {
		why "image ls did not answer under zot after the rollback"
		return 1
	}
	digests_hold "$REC" "$EVIDENCE/e.2-ls.pairs" || {
		why "zot does not serve a recorded image at its digest: refused"
		return 1
	}
	while read -r ref d; do
		n=$((n + 1))
		saved_is "${ref%:*}@$d" "$d" "e2-$n" </dev/null || {
			why "zot's save of ${ref%:*}@$d"
			return 1
		}
	done <"$REC"
	DETAIL="$n images by digest under zot"
}
s_e3() {
	local deadline=$((SECONDS + ZOT_GC_WAIT)) r pending bad=""
	while :; do
		fetch "$SERVER" "$RLOG" >"$LOCAL_WORK/registry.log" || true
		if [ "$(wc -l <"$LOCAL_WORK/registry.log" | tr -d ' ')" -lt "$ZOT_SINCE_LINES" ]; then ZOT_SINCE_LINES=0; fi
		tail -n +"$((ZOT_SINCE_LINES + 1))" "$LOCAL_WORK/registry.log" >"$EVIDENCE/e.3-registry.log"
		pending=""
		for r in $RUN_REPOS; do [ "$(zot_gc_result "$EVIDENCE/e.3-registry.log" "$P/$r")" != none ] || pending="$pending $r"; done
		[ -n "$pending" ] || break
		[ "$SECONDS" -lt "$deadline" ] || break
		sleep "$POLL"
	done
	# The released zot collects every 6h, so a window may hold no cycle. A report
	# that came is judged; none is recorded, and e.5 (short intervals) proves GC of a
	# k3sm-written store under zot. A red e.5 still fails the leg.
	local seen=""
	for r in $RUN_REPOS; do
		case "$(zot_gc_result "$EVIDENCE/e.3-registry.log" "$P/$r")" in
		ok) seen="$seen $r" ;;
		failed) bad="$bad $r" ;;
		esac
	done
	[ -z "$bad" ] || {
		why "zot's GC failed on:$bad"
		return 1
	}
	if grep -q '"level":"error"' "$EVIDENCE/e.3-registry.log"; then
		why "zot logged an error after the rollback (e.3-registry.log)"
		return 1
	fi
	if [ -z "$seen" ]; then
		DETAIL="no zot GC cycle in the window; GC under zot is proven by e.5"
		return 0
	fi
	DETAIL="zot GC ok on:$seen${pending:+; no report in the window on:$pending}"
}
s_e4() {
	snapshot rollback || return 1
	store_verdict "$EVIDENCE/store-zot.txt" "$EVIDENCE/store-rollback.txt" zot >"$EVIDENCE/e.4-verdict.txt" || {
		why "$(grep -E '^(NONZOT|MODE|OWNER) ' "$EVIDENCE/e.4-verdict.txt" | head -3 | tr '\n' ';') (e.4-verdict.txt)"
		return 1
	}
	DETAIL="zot-shaped (e.4-verdict.txt)"
}
s_e5() {
	local rc=0
	wait "$LEG_PID" || rc=$?
	LEG_PID=""
	[ "$rc" = 0 ] || {
		why "the rollback leg exited $rc (e.5-rollback-leg.log)"
		return 1
	}
	DETAIL="$(grep '^result:' "$EVIDENCE/e.5-rollback-leg.log" | tail -1)"
}
# f.1 runs on every way out: what the run made, and only that.
CLEANED=0
s_f1() {
	local ref rc=0
	[ "$CLEANED" = 0 ] || return 0
	CLEANED=1
	[ -z "${LEG_PID:-}" ] || {
		kill "$LEG_PID" 2>/dev/null || true
		wait "$LEG_PID" 2>/dev/null || true
	}
	kc delete namespace "$NS" --ignore-not-found --wait=true || rc=1
	if ls_pairs f.1-ls; then
		while read -r ref _; do
			case "$ref" in "$P"/*) ki untag "$REG/$ref" </dev/null || rc=1 ;; esac
		done <"$EVIDENCE/f.1-ls.pairs"
	else
		echo "note: no listing to untag from"
		rc=1
	fi
	case "$P" in b1027-[0-9]*) ;; *) return 1 ;; esac
	root_run "$SERVER" "$SERVER_WORK" cleanup-store "$STEP_TIMEOUT" 3</dev/null <<EOF || rc=1
rm -rf $(quoted "$STORE/$P")
EOF
	rsh "$SERVER" /bin/rm -rf "$SERVER_WORK/docker" || true
	[ "$BUILDER_STARTED" = 0 ] || ku builder down </dev/null || rc=1
	if [ "$KUBE_COPIES" -gt 0 ]; then
		local i=1 files=""
		while [ "$i" -le "$KUBE_COPIES" ]; do
			files="$files ~/.kube/config.b1027-$RUN-$i"
			i=$((i + 1))
		done
		bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "rm -f$files" </dev/null || rc=1
	fi
	bounded "$STEP_TIMEOUT" rsh_raw "$SERVER" "$(quoted sudo /bin/rm -rf "$SERVER_WORK")" </dev/null || rc=1
	bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "$(quoted sudo /bin/rm -rf "$WORKER_WORK")" </dev/null || rc=1
	rm -rf "$LOCAL_WORK"
	kc get ns >"$EVIDENCE/f.1-namespaces.txt" 2>&1 || true
	[ "$rc" = 0 ] || why "some cleanup failed; f.1.log names it"
	return "$rc"
}

lab_main() {
	local a v keys
	OLD_SET="" NEW_SET="" SERVER="" WORKER="" SERVER_LAN="" EVIDENCE="" SERVER_WORK="" WORKER_WORK=""
	GC_WAIT=4500 ZOT_GC_WAIT=1800 BUILDX_HOST=localhost:6451
	while [ $# -gt 0 ]; do
		a="$1"
		case "$a" in
		--old-set | --new-set | --server-ssh | --worker-ssh | --server-lan | --evidence | --server-work | --worker-work | --gc-wait | --zot-gc-wait | --buildx-host)
			[ $# -ge 2 ] || lab_refuse "$a needs a value"
			case "$a" in
			--old-set) OLD_SET="$2" ;; --new-set) NEW_SET="$2" ;;
			--server-ssh) SERVER="$2" ;; --worker-ssh) WORKER="$2" ;;
			--server-lan) SERVER_LAN="$2" ;; --evidence) EVIDENCE="$2" ;;
			--server-work) SERVER_WORK="$2" ;; --worker-work) WORKER_WORK="$2" ;;
			--gc-wait) GC_WAIT="$2" ;; --zot-gc-wait) ZOT_GC_WAIT="$2" ;; --buildx-host) BUILDX_HOST="$2" ;;
			esac
			shift 2
			;;
		-h | --help)
			lab_usage
			exit 0
			;;
		*) lab_refuse "unknown argument $a (see --lab --help)" ;;
		esac
	done

	# ---- p.0: everything read, nothing touched. ----
	[ "${K3SM_LAB:-}" = 1 ] || lab_refuse "K3SM_LAB=1 is not set"
	for a in OLD_SET:--old-set NEW_SET:--new-set SERVER:--server-ssh WORKER:--worker-ssh SERVER_LAN:--server-lan EVIDENCE:--evidence; do
		v="${a%%:*}"
		[ -n "${!v}" ] || lab_refuse "${a#*:} is required (see --lab --help)"
	done
	case "$EVIDENCE" in /*) ;; *) lab_refuse "--evidence must be absolute" ;; esac
	for a in "$GC_WAIT" "$ZOT_GC_WAIT"; do case "$a" in '' | *[!0-9]*) lab_refuse "a wait must be seconds (got '$a')" ;; esac; done
	for a in "$OLD_SET" "$NEW_SET"; do [ -x "$a/k3sm" ] || lab_refuse "$a/k3sm is not an executable: name a stage.sh tree"; done
	ZOT_BIN="$(find "$OLD_SET" -name zot -type f | head -1)"
	[ -n "$ZOT_BIN" ] || lab_refuse "the old set $OLD_SET has no zot member: it is not a zot-era build"
	[ -z "$(find "$NEW_SET" -name zot | head -1)" ] || lab_refuse "the new set $NEW_SET has a zot member: it is not main"
	OLD_VER="$("$OLD_SET/k3sm" version 2>/dev/null | sed -n 1p)"
	NEW_VER="$("$NEW_SET/k3sm" version 2>/dev/null | sed -n 1p)"
	[ -n "$OLD_VER" ] && [ -n "$NEW_VER" ] || lab_refuse "a set's k3sm does not report its version"
	[ "$OLD_VER" != "$NEW_VER" ] || lab_refuse "the two sets report one version ($OLD_VER), so a roll cannot be told from none"
	for a in python3 shasum tar curl htpasswd; do command -v "$a" >/dev/null 2>&1 || lab_refuse "$a not found"; done
	[ -n "${K3SM_B1027_HELLO:-}" ] || command -v go >/dev/null 2>&1 || lab_refuse "go not found; the pod fixture is built here"
	if [ "$SERVER" != local ] || [ "$WORKER" != local ]; then
		command -v ssh >/dev/null 2>&1 && command -v scp >/dev/null 2>&1 || lab_refuse "ssh and scp are required"
	fi

	RUN="$(date -u +%m%d%H%M%S)"
	P="b1027-$RUN"
	NS="b1027-$RUN"
	REG="registry-k3sm:6450"
	RUN_REPOS="index docker shared-a shared-b pushed app buildx mounted"
	: "${SERVER_WORK:=/tmp/b1027-$RUN-server}"
	: "${WORKER_WORK:=/tmp/b1027-$RUN-worker}"
	for a in "$SERVER_WORK" "$WORKER_WORK"; do
		case "$a" in *[!A-Za-z0-9_./-]* | "" | /) lab_refuse "a work directory must be a plain absolute path (got '$a')" ;; /*) ;; *) lab_refuse "a work directory must be absolute (got '$a')" ;; esac
		case "$a/" in "$EVIDENCE"/*) lab_refuse "a work directory must not be inside the evidence directory" ;; esac
	done
	if [ -d "$EVIDENCE" ] && [ -n "$(ls -A "$EVIDENCE")" ]; then lab_refuse "the evidence directory $EVIDENCE is not empty"; fi
	STEP_TIMEOUT="${K3SM_B1027_STEP_TIMEOUT:-120}"
	INSTALL_TIMEOUT="${K3SM_B1027_INSTALL_TIMEOUT:-900}"
	ZOT_START_WAIT="${K3SM_B1027_ZOT_START_WAIT:-180}"
	REGISTRY_WAIT="${K3SM_B1027_REGISTRY_WAIT:-180}"
	READY_TIMEOUT="${K3SM_B1027_READY_TIMEOUT:-240}"
	POD_TIMEOUT="${K3SM_B1027_POD_TIMEOUT:-240}"
	POLL="${K3SM_B1027_POLL:-3}"
	K3SM_BIN="${K3SM_B1027_K3SM:-/Library/k3sm/k3sm}"
	DATA_ROOT="${K3SM_B1027_DATA_ROOT:-/var/lib/k3sm}"
	SWD="$DATA_ROOT/server"
	STORE="$SWD/registry"
	RLOG="$SWD/registry.log"

	bounded "$STEP_TIMEOUT" rsh_raw "$SERVER" "sudo -n /usr/bin/true" </dev/null >/dev/null 2>&1 || lab_refuse "no passwordless sudo over ssh on the server ($SERVER)"
	bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "sudo -n /usr/bin/true" </dev/null >/dev/null 2>&1 || lab_refuse "no passwordless sudo over ssh on the worker ($WORKER)"
	for a in "$SERVER:$SERVER_WORK" "$WORKER:$WORKER_WORK"; do
		[ -z "$(bounded "$STEP_TIMEOUT" rsh_raw "${a%%:*}" "if [ -d $(quoted "${a#*:}") ]; then ls -A $(quoted "${a#*:}"); fi" </dev/null)" ] ||
			lab_refuse "${a#*:} on ${a%%:*} is not empty"
	done
	SERVER_USER="$(bounded "$STEP_TIMEOUT" rsh_raw "$SERVER" "id -un" </dev/null)" || lab_refuse "cannot read the server's account"
	WORKER_USER="$(bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "id -un" </dev/null)" || lab_refuse "cannot read the worker's account"
	DOC="$(nodes_doc </dev/null 2>/dev/null)" || lab_refuse "the cluster does not answer (sudo k3sm kubectl get nodes on the server)"
	SERVER_NODE="$(printf '%s' "$DOC" | lab_py nodes server)"
	WORKER_NODE="$(printf '%s' "$DOC" | lab_py nodes worker)"
	[ "$(printf '%s\n' "$SERVER_NODE" | grep -c .)" = 1 ] && [ "$(printf '%s\n' "$WORKER_NODE" | grep -c .)" = 1 ] ||
		lab_refuse "want one server and one worker node (got '$SERVER_NODE' and '$WORKER_NODE')"
	[ -z "$(printf '%s' "$DOC" | lab_py nodes notready)" ] || lab_refuse "a node is not Ready and schedulable"
	TOLERATIONS="$(lab_tolerations_yaml "")" || exit 3
	keys=" $(lab_tol_keys) "
	while IFS= read -r a; do
		[ -n "$a" ] || continue
		case "${a##*:}" in PreferNoSchedule) continue ;; esac
		case "${a%:*}" in k3sm.io/provider) continue ;; esac
		case "$keys" in *" ${a%:*} "*) continue ;; esac
		lab_refuse "the worker carries taint ${a%:*}, which a run pod does not tolerate (name it in K3SM_LAB_TOLERATE_KEYS)"
	done < <(printf '%s' "$DOC" | lab_py nodes taints)

	# The rig is not touched before this line; from here on, f.1 runs on every way out.
	mkdir -p "$EVIDENCE/scripts"
	LOCAL_WORK="$(mktemp -d "${TMPDIR:-/tmp}/b1027-lab.XXXXXX")"
	RUNLOG="$EVIDENCE/run.log"
	REC="$EVIDENCE/recorded.txt"
	CHILDREN="$EVIDENCE/children.txt"
	: >"$REC"
	# shellcheck disable=SC2034 # read by the sourced runlog.sh
	MODE=lab
	REPO_ROOT="$(cd "$HERE/../.." && pwd)"
	K3SM_ARTIFACT="$NEW_SET/k3sm"
	export K3SM_ARTIFACT
	# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/runlog.sh disable=SC1091
	. "$REPO_ROOT/hack/lab/lib/runlog.sh"
	emit_run_log_header FAIL >"$RUNLOG"
	{
		echo "run: $P (namespace $NS)"
		echo "old_set: $OLD_SET ($OLD_VER), zot $ZOT_BIN"
		echo "new_set: $NEW_SET ($NEW_VER)"
		echo "server: $SERVER ($SERVER_NODE, $SERVER_LAN), worker: $WORKER ($WORKER_NODE)"
		echo "roll order: worker, then server (the item and m23-plan resolution 21 agree)"
		echo "roll path: k3sm install in place from each set"
	} >>"$RUNLOG"
	lab_log "PASS p.0"
	trap 's_f1 >>"$EVIDENCE/f.1.log" 2>&1 </dev/null || true' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	# What the run ships: the sets, the image layouts and the build contexts.
	local s hello="${K3SM_B1027_HELLO:-}"
	for s in old new; do
		if [ "$s" = old ]; then a="$OLD_SET"; else a="$NEW_SET"; fi
		COPYFILE_DISABLE=1 tar -czf "$LOCAL_WORK/$s.tar.gz" -C "$a" . || lab_refuse "could not pack the $s set"
	done
	if [ -z "$hello" ]; then
		hello="$LOCAL_WORK/hello-http"
		(cd "$REPO_ROOT" && env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$hello" ./e2e/testdata/cmd/hello-http) >>"$RUNLOG" 2>&1 ||
			lab_refuse "could not build the hello-http fixture"
	fi
	mkdir -p "$LOCAL_WORK/gen"
	lab_py gen "$LOCAL_WORK/gen" "$P" "$hello" || lab_refuse "could not generate the image layouts"
	cp "$LOCAL_WORK/gen/digests.txt" "$EVIDENCE/generated-digests.txt"
	COPYFILE_DISABLE=1 tar -czf "$LOCAL_WORK/gen.tar.gz" -C "$LOCAL_WORK" gen
	for v in v1 v2; do
		mkdir -p "$LOCAL_WORK/ctx-$v"
		cp "$hello" "$LOCAL_WORK/ctx-$v/hello-http"
		printf 'FROM scratch\nCOPY hello-http /bin/hello-http\nENTRYPOINT ["/bin/hello-http", "--id", "b1027-app-%s", "--addr", ":8080"]\n' "$v" >"$LOCAL_WORK/ctx-$v/Dockerfile"
	done
	COPYFILE_DISABLE=1 tar -czf "$LOCAL_WORK/ctx.tar.gz" -C "$LOCAL_WORK" ctx-v1 ctx-v2
	bounded "$STEP_TIMEOUT" rsh_raw "$SERVER" "$(quoted mkdir -p "$SERVER_WORK")" </dev/null || lab_refuse "cannot make $SERVER_WORK"
	bounded "$STEP_TIMEOUT" rsh_raw "$WORKER" "$(quoted mkdir -p "$WORKER_WORK/private")" </dev/null || lab_refuse "cannot make $WORKER_WORK"

	# e.5 runs beside the leg: loopback only, its own temp store, about 61 minutes.
	mkdir -p "$LOCAL_WORK/rollback"
	K3SM_LAB=1 "${K3SM_B1027_ROLLBACK_LEG:-$SELF}" --rollback-leg --zot "$ZOT_BIN" --k3sm "$NEW_SET/k3sm" --work "$LOCAL_WORK/rollback" \
		>"$EVIDENCE/e.5-rollback-leg.log" 2>&1 </dev/null &
	LEG_PID=$!

	step a.0 s_a0
	step a.1 s_a1
	step a.2 s_a2
	step b.1 s_b1
	step c.1 s_c1
	step c.2 s_c2
	step c.3 s_c3
	step c.4 s_c4
	step c.5 s_c5
	step c.6 s_c6
	step d.1 s_d1
	step d.2 s_d2
	step d.3 s_d3
	step e.1 s_e1
	step e.2 s_e2
	step e.3 s_e3
	step e.4 s_e4
	step e.5 s_e5
	step f.1 s_f1
	trap - EXIT
	if [ -n "$LAB_FAILED" ]; then
		lab_log "first red step: $LAB_FAILED"
		emit_run_log_verdict FAIL | tee -a "$RUNLOG"
		return 1
	fi
	emit_run_log_verdict PASS | tee -a "$RUNLOG"
	return 0
}

# ---- the --lab fakes (--self-test) -----------------------------------------------------
# One cluster in a state directory: ssh runs the command here with FAKE_HOST set, sudo
# runs it as the caller, k3sm keeps the registry's tags in a file and writes zot-shaped
# files into a fake store, and kubectl runs pods whose imageID follows the kubelet's
# pull policy over a per-node cache. FAKE_MUTATE=digest makes the new release list
# another digest for the Docker v2 image; FAKE_MUTATE=store makes it write a file no
# zot writes into a repository; FAKE_GC_FAILED=1 makes its sweep report a failure.

fake_ssh() {
	cat <<'EOF'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in -o) shift 2 ;; -q | -T | -n) shift ;; *) break ;; esac; done
host="$1"
shift
cmd="$*"
echo "$host $cmd" >>"$FAKE_STATE/ssh.log"
case "$cmd" in
*"/bin/ps -axo comm="*)
	[ "$host" = "$FAKE_SERVER" ] && [ "$(cat "$FAKE_STATE/registry" 2>/dev/null)" = zot ] && echo /Library/k3sm/cp-payload/zot
	echo /Library/k3sm/k3sm
	exit 0
	;;
*"nc -z"*) exit 0 ;;
esac
FAKE_HOST="$host" exec /bin/bash -c "$cmd"
EOF
}
fake_scp() {
	cat <<'EOF'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in -o) shift 2 ;; -q | -r) shift ;; *) break ;; esac; done
exec cp "$1" "${2#*:}"
EOF
}
fake_sudo() {
	cat <<'EOF'
#!/bin/bash
[ "${1:-}" = -n ] && shift
exec "$@"
EOF
}
fake_kubectl() {
	cat <<'EOF'
#!/bin/bash
S="$FAKE_STATE"
mkdir -p "$S/pods" "$S/ns"
args=" $* "
pair_of() { local r="${1#*/}"; echo "$r"; }
case "$args" in
*" get nodes "*)
	cat <<J
{"items":[{"metadata":{"name":"k3sm-srv","labels":{"node-role.kubernetes.io/control-plane":"true"}},"spec":{},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
{"metadata":{"name":"k3sm-wrk","labels":{}},"spec":{"taints":[{"key":"k3sm.io/provider","effect":"NoSchedule"}]},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}
J
	;;
*" create namespace "*) : >"$S/ns/$3" ;;
*" delete namespace "*) rm -f "$S/ns/$3" ;;
*" get ns "*) ls "$S/ns" ;;
*" get events "*) : ;;
*" config view "*) echo "apiVersion: v1" ;;
*" apply -f - "*)
	y="$(cat)"
	name="$(printf '%s\n' "$y" | sed -n 's/^metadata: {name: \([^,]*\),.*/\1/p')"
	image="$(printf '%s\n' "$y" | sed -n 's/^    image: //p')"
	policy="$(printf '%s\n' "$y" | sed -n 's/^    imagePullPolicy: //p')"
	node="$(printf '%s\n' "$y" | sed -n 's/^  nodeName: //p')"
	cache="$S/cache.$node"
	touch "$cache"
	case "$image" in
	*@*) d="${image#*@}" ;;
	*)
		p="$(pair_of "$image")"
		cur="$(awk -v r="$p" '$1 == r { print $2 }' "$S/tags")"
		was="$(awk -v r="$p" '$1 == r { print $2 }' "$cache")"
		if [ "$policy" = IfNotPresent ] && [ -n "$was" ]; then d="$was"; else d="$cur"; fi
		{ awk -v r="$p" '$1 != r' "$cache"; echo "$p $d"; } >"$cache.tmp" && mv "$cache.tmp" "$cache"
		;;
	esac
	[ -n "$d" ] || exit 1
	echo "${image%%[:@]*}@$d" >"$S/pods/$name"
	echo "pod/$name created"
	;;
*" get pod "*)
	[ -f "$S/pods/$3" ] || exit 1
	case "$args" in *" -o json "*) printf '{"status":{"conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"imageID":"%s"}]}}\n' "$(cat "$S/pods/$3")" ;; esac
	;;
*" delete pod "*) rm -f "$S/pods/$3" ;;
*) echo "fake kubectl: unhandled: $*" >&2; exit 1 ;;
esac
EOF
}
fake_k3sm() {
	cat <<'EOF'
#!/bin/bash
S="$FAKE_STATE"
H="${FAKE_HOST:-local}"
touch "$S/tags"
srvver() { cat "$S/ver.$FAKE_SERVER" 2>/dev/null || echo main; }
n=$(($(cat "$S/ncalls" 2>/dev/null || echo 0) + 1))
echo "$n" >"$S/ncalls"
if [ -f "$S/gc-armed" ] && [ "$n" -ge "$(cat "$S/gc-armed")" ]; then
	rm -f "$S/gc-armed"
	printf '{"time":"%s","level":"INFO","msg":"registry gc: sweep finished","report_only":true,"failed":%s,"err":null}\n' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "${FAKE_GC_FAILED:-0}" >>"$FAKE_RLOG"
fi
if [ -f "$S/zot-armed" ]; then
	rm -f "$S/zot-armed"
	case "${FAKE_ZOT_GC:-ok}" in ok) w=successfully ;; failed) w=unsuccessfully ;; *) w="" ;; esac
	[ -z "$w" ] || for r in $(sed 's/:.* .*//' "$S/tags" | sort -u); do
		printf '{"level":"info","message":"gc %s completed for %s/%s","module":"gc"}\n' "$w" "$FAKE_STORE" "$r" >>"$FAKE_RLOG"
	done
fi
digest_of() { awk -v r="$1" '$1 == r { print $2 }' "$S/tags"; }
settag() { { awk -v r="$1" '$1 != r' "$S/tags"; echo "$1 $2"; } >"$S/tags.tmp" && mv "$S/tags.tmp" "$S/tags"; }
write_repo() { # <repo> <digest> [<layout dir>]
	local d="$FAKE_STORE/$1"
	mkdir -p "$d/blobs/sha256"
	echo '{"imageLayoutVersion":"1.0.0"}' >"$d/oci-layout"
	echo "{\"manifests\":[{\"digest\":\"$2\"}]}" >>"$d/index.json"
	[ -z "${3:-}" ] || cp "$3"/blobs/sha256/* "$d/blobs/sha256/"
	if [ "$(srvver)" = 0.0.1-old ]; then
		echo zot >>"$FAKE_STORE/cache.db"
	else
		echo id >"$FAKE_STORE/.k3sm-store-id"
		[ "${FAKE_MUTATE:-}" != store ] || echo x >"$d/.k3sm-extra"
	fi
}
verb1="${1:-}"
shift
[ "$verb1" != kubectl ] || exec "$FAKE_KUBECTL" "$@"
verb2=""
case "$verb1" in image | builder | token | registry) verb2="${1:-}"; shift ;; esac
pos=()
force=0 out="" ref="" tag=""
while [ $# -gt 0 ]; do
	case "$1" in
	--work-dir | -o | --platform | --digest | --reference | --tag | -t | --ttl | --server | --token-file | --user | --context) [ "$1" = -o ] && out="$2"; [ "$1" = --reference ] && ref="$2"; [ "$1" = --tag ] || [ "$1" = -t ] && tag="$2"; shift 2 ;;
	--force) force=1; shift ;;
	--*) shift ;;
	*) pos+=("$1"); shift ;;
	esac
done
case "$verb1" in
version) echo "k3sm ${FAKE_SET_VERSION:-$(cat "$S/ver.$H" 2>/dev/null || echo main)}"; exit 0 ;;
token) echo "K10fake::server:token"; exit 0 ;;
registry) exit 0 ;;
install)
	echo "install $H $FAKE_SET_VERSION" >>"$S/calls"
	echo "$FAKE_SET_VERSION" >"$S/ver.$H"
	if [ "$H" = "$FAKE_SERVER" ]; then
		if [ "$FAKE_SET_VERSION" = 0.0.1-old ]; then
			echo zot >"$S/registry"
			[ ! -f "$S/was-new" ] || : >"$S/zot-armed"
		else
			echo k3sm >"$S/registry"
			: >"$S/was-new"
			echo $((n + 5)) >"$S/gc-armed"
		fi
	fi
	exit 0
	;;
build)
	d="sha256:$(printf '%s' "$tag$(cat Dockerfile)" | shasum -a 256 | cut -d' ' -f1)"
	settag "${tag#*/}" "$d"
	write_repo "$(echo "${tag#*/}" | sed 's/:[^:]*$//')" "$d"
	exit 0
	;;
builder)
	case "$verb2" in
	status) echo "State: Running"; exit 0 ;;
	up | down) echo "builder $verb2" >>"$S/calls"; exit 0 ;;
	esac
	d="sha256:$(printf '%s' "$tag$(cat "${pos[1]}/Dockerfile")" | shasum -a 256 | cut -d' ' -f1)"
	settag "${tag#*/}" "$d"
	write_repo "$(echo "${tag#*/}" | sed 's/:[^:]*$//')" "$d"
	exit 0
	;;
image) ;;
*) echo "fake k3sm: unhandled $verb1" >&2; exit 1 ;;
esac
case "$verb2" in
ls)
	python3 -I -c '
import json, sys
m = sys.argv[2] == "digest" and sys.argv[3] != "0.0.1-old"
imgs = []
for line in open(sys.argv[1]):
    r, d = line.split()
    if m and "/docker:" in r: d = d[:-1] + ("0" if d[-1] != "0" else "1")
    imgs.append({"repository": r.rsplit(":", 1)[0], "tag": r.rsplit(":", 1)[1], "reference": "registry-k3sm:6450/" + r, "digest": d})
print(json.dumps({"registry": {"name": "registry-k3sm:6450", "reachable": True}, "images": imgs}))' "$S/tags" "${FAKE_MUTATE:-}" "$(srvver)"
	;;
push)
	src="${pos[0]}" dst="${pos[1]#*/}"
	if [ -d "$src" ]; then
		d="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]+"/index.json"))["manifests"][0]["digest"])' "$src")"
		write_repo "${dst%:*}" "$d" "$src"
	else
		d="$(digest_of "${src#*/}")"
		[ -n "$d" ] || exit 1
		write_repo "${dst%:*}" "$d"
	fi
	settag "$dst" "$d"
	printf 'pushed registry-k3sm:6450/%s\n  digest: %s\n' "$dst" "$d"
	;;
import)
	t="$(mktemp -d)"
	tar -xf "${pos[0]}" -C "$t"
	d="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]+"/index.json"))["manifests"][0]["digest"])' "$t")"
	dst="${ref#*/}"
	settag "$dst" "$d"
	write_repo "${dst%:*}" "$d" "$t"
	python3 -I -c '
import json, sys
i = json.load(open(sys.argv[1] + "/blobs/sha256/" + sys.argv[2][7:]))
for m in i["manifests"]: print(sys.argv[3] + "@" + m["digest"])' "$t" "$d" "${dst%:*}" >>"$S/children"
	rm -rf "$t"
	;;
tag)
	d="$(digest_of "${pos[0]#*/}")"
	[ -n "$d" ] || exit 1
	cur="$(digest_of "${pos[1]#*/}")"
	[ -z "$cur" ] || [ "$cur" = "$d" ] || [ "$force" = 1 ] || exit 1
	settag "${pos[1]#*/}" "$d"
	;;
untag)
	r="${pos[0]#*/}"
	[ -n "$(digest_of "$r")" ] || exit 1
	awk -v r="$r" '$1 != r' "$S/tags" >"$S/tags.tmp" && mv "$S/tags.tmp" "$S/tags"
	;;
inspect | save)
	r="${pos[0]#*/}"
	case "$r" in
	*@*) d="${r#*@}"; grep -q " $d\$" "$S/tags" || grep -qx "$r" "$S/children" 2>/dev/null || exit 1 ;;
	*) d="$(digest_of "$r")"; [ -n "$d" ] || exit 1 ;;
	esac
	if [ "$verb2" = inspect ]; then echo "digest: $d"; exit 0; fi
	python3 -I -c '
import io, json, sys, tarfile
b = json.dumps({"manifests": [{"digest": sys.argv[2]}]}).encode()
with tarfile.open(sys.argv[1], "w") as t:
    ti = tarfile.TarInfo("index.json"); ti.size = len(b); t.addfile(ti, io.BytesIO(b))' "$out" "$d"
	;;
pull) exit 0 ;;
prune) echo '{"registry":{"deleted":[]},"cache":{}}' ;;
*) echo "fake k3sm: unhandled image $verb2" >&2; exit 1 ;;
esac
EOF
}

# lab_fake_run <dir> <mutate> [env...]: one --lab run over the fakes; its exit code in
# <dir>/rc, its output in <dir>/out.
lab_fake_run() {
	local d="$1" mut="$2" f rc=0
	shift 2
	rm -rf "$d"
	mkdir -p "$d/bin" "$d/state" "$d/data/server/registry" "$d/home" "$d/sets/old/cp-payload" "$d/sets/new" "$d/tmp"
	fake_ssh >"$d/bin/ssh"
	fake_scp >"$d/bin/scp"
	fake_sudo >"$d/bin/sudo"
	fake_kubectl >"$d/bin/kubectl"
	fake_k3sm >"$d/bin/k3sm"
	# shellcheck disable=SC2016 # the fakes expand these when they run
	printf '#!/bin/bash\necho "result: PASS"\nexit "${FAKE_LEG_RC:-0}"\n' >"$d/bin/rollback-leg"
	printf 'zot\n' >"$d/sets/old/cp-payload/zot"
	# shellcheck disable=SC2016
	printf '#!/bin/bash\nFAKE_SET_VERSION=0.0.1-old exec "$FAKE_K3SM" "$@"\n' >"$d/sets/old/k3sm"
	# shellcheck disable=SC2016
	printf '#!/bin/bash\nFAKE_SET_VERSION=0.0.2-new exec "$FAKE_K3SM" "$@"\n' >"$d/sets/new/k3sm"
	printf 'not a binary\n' >"$d/hello"
	chmod +x "$d"/bin/* "$d/sets/old/k3sm" "$d/sets/new/k3sm"
	echo 0.0.2-new >"$d/state/ver.srv"
	echo 0.0.2-new >"$d/state/ver.wrk"
	: >"$d/data/server/registry.log"
	for f in "$@"; do
		case "$f" in --new-set-has-zot) printf 'zot\n' >"$d/sets/new/zot" ;; esac
	done
	env PATH="$d/bin:$PATH" HOME="$d/home" TMPDIR="$d/tmp" K3SM_LAB="${FAKE_LAB-1}" \
		FAKE_STATE="$d/state" FAKE_SERVER=srv FAKE_K3SM="$d/bin/k3sm" FAKE_KUBECTL="$d/bin/kubectl" \
		FAKE_STORE="$d/data/server/registry" FAKE_RLOG="$d/data/server/registry.log" FAKE_MUTATE="$mut" \
		FAKE_GC_FAILED="${FAKE_GC_FAILED:-0}" FAKE_LEG_RC="${FAKE_LEG_RC:-0}" FAKE_ZOT_GC="${FAKE_ZOT_GC:-ok}" \
		K3SM_B1027_K3SM="$d/bin/k3sm" K3SM_B1027_DATA_ROOT="$d/data" K3SM_B1027_HELLO="$d/hello" \
		K3SM_B1027_ROLLBACK_LEG="$d/bin/rollback-leg" K3SM_B1027_POLL=0.05 K3SM_B1027_STEP_TIMEOUT=60 \
		K3SM_B1027_READY_TIMEOUT=5 K3SM_B1027_POD_TIMEOUT=5 K3SM_B1027_ZOT_START_WAIT=0 K3SM_B1027_REGISTRY_WAIT=0 K3SM_LAB_TOLERATE_KEYS= \
		"$SELF" --lab --old-set "$d/sets/old" --new-set "$d/sets/new" --server-ssh srv --worker-ssh wrk \
		--server-lan 192.0.2.1 --evidence "$d/evidence" --server-work "$d/remote-server" --worker-work "$d/remote-worker" \
		--gc-wait 30 --zot-gc-wait 5 >"$d/out" 2>&1 </dev/null || rc=$?
	echo "$rc" >"$d/rc"
}

lab_self_test() {
	local t bad=0 d want got
	lchk() { [ "$2" = "$3" ] || { echo "self-test FAIL: $1: got '$2', want '$3'"; bad=1; }; }
	lexp() { local w="$1" n="$2" g=no; shift 2; if "$@" >/dev/null 2>&1; then g=ok; fi; [ "$g" = "$w" ] || { echo "self-test FAIL: $n: got $g, want $w"; bad=1; }; }
	t="$(mktemp -d "${TMPDIR:-/tmp}/b1027-lab-self-test.XXXXXX")"

	# digests_hold: the refusal on a digest that moved or a tag that went.
	printf 'r/a:v1 sha256:aa\nr/b:v1 sha256:bb\n' >"$t/rec"
	printf 'r/a:v1 sha256:aa\nr/b:v1 sha256:bb\nr/c:v1 sha256:cc\n' >"$t/obs"
	lexp ok "digests: all held, extra tags allowed" digests_hold "$t/rec" "$t/obs"
	printf 'r/a:v1 sha256:aa\nr/b:v1 sha256:b0\n' >"$t/obs"
	lexp no "digests: a moved digest is refused" digests_hold "$t/rec" "$t/obs"
	lchk "digests: the mismatch is named" "$(digests_hold "$t/rec" "$t/obs" || true)" "MISMATCH r/b:v1 want sha256:bb got sha256:b0"
	printf 'r/a:v1 sha256:aa\n' >"$t/obs"
	lchk "digests: a missing tag is named" "$(digests_hold "$t/rec" "$t/obs" || true)" "MISSING r/b:v1"

	# store_verdict: resolution 4 over snapshots.
	local h64 o
	h64="$(printf 'x' | shasum -a 256 | cut -d' ' -f1)"
	o="_k3sm:_k3sm"
	snap() { printf 'S\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }
	{
		snap Directory 700 "$o" 64 1 ./p/r
		snap "Regular File" 600 "$o" 30 1 ./p/r/index.json
		snap "Regular File" 600 "$o" 30 1 ./p/r/oci-layout
		snap "Regular File" 600 "$o" 9 1 "./p/r/blobs/sha256/$h64"
		snap "Regular File" 600 "$o" 4096 1 ./cache.db
		printf 'H\taa\t./p/r/index.json\nH\tdb\t./cache.db\n'
	} >"$t/before"
	cp "$t/before" "$t/after"
	lexp ok "store: unchanged" store_verdict "$t/before" "$t/after" k3sm
	{
		cat "$t/before"
		snap "Regular File" 600 "$o" 9 2 "./p/r/blobs/sha256/$(printf 'y' | shasum -a 256 | cut -d' ' -f1)"
		snap "Regular File" 600 "$o" 0 2 ./p/r/.uploads/0b5c0a4e-1111-2222-3333-444455556666
		snap "Regular File" 600 "$o" 8 2 ./.k3sm-store-id
		snap Directory 700 "$o" 64 2 ./p/r/.temps
		snap "Regular File" 600 "$o" 30 1 ./p/s/index.json
		snap "Regular File" 600 "$o" 30 1 ./p/s/oci-layout
	} >"$t/after"
	lexp ok "store: new blobs, an upload, a new repository, the root store id, an empty .temps" store_verdict "$t/before" "$t/after" k3sm
	lchk "store: the root id is a fact" "$(store_verdict "$t/before" "$t/after" k3sm | grep -c '^FACT .*k3sm-store-id')" 1
	{ cat "$t/before"; snap "Regular File" 600 "$o" 9 2 ./p/r/.temps/.tmp-0b5c0a4e-1111-2222-3333-444455556666; } >"$t/after"
	lexp no "store: a temp left in a repository" store_verdict "$t/before" "$t/after" k3sm
	{ cat "$t/before"; snap "Regular File" 600 "$o" 9 2 ./p/r/blobs/sha512/abc; } >"$t/after"
	lexp no "store: a blob outside blobs/sha256" store_verdict "$t/before" "$t/after" k3sm
	{ cat "$t/before"; snap "Regular File" 600 "$o" 9 2 ./p/r/blobs/sha256/short; } >"$t/after"
	lexp no "store: a blob not named by a digest" store_verdict "$t/before" "$t/after" k3sm
	sed "s#600	$o	30	1	./p/r/index.json#644	$o	31	2	./p/r/index.json#" "$t/before" >"$t/after"
	lexp no "store: index.json rewritten with another mode" store_verdict "$t/before" "$t/after" k3sm
	sed "s#600	$o	30	1	./p/r/index.json#600	root:wheel	31	2	./p/r/index.json#" "$t/before" >"$t/after"
	lexp no "store: index.json rewritten by another owner" store_verdict "$t/before" "$t/after" k3sm
	sed "s#600	$o	30	1	./p/r/index.json#600	$o	31	2	./p/r/index.json#" "$t/before" >"$t/after"
	lexp ok "store: index.json rewritten in zot's mode and owner" store_verdict "$t/before" "$t/after" k3sm
	sed "s#4096	1	./cache.db#4097	2	./cache.db#" "$t/before" >"$t/after"
	lexp no "store: cache.db written under the new release" store_verdict "$t/before" "$t/after" k3sm
	lexp ok "store: cache.db written by zot after the rollback" store_verdict "$t/before" "$t/after" zot
	grep -v cache.db "$t/before" >"$t/after"
	lexp no "store: cache.db removed under the new release" store_verdict "$t/before" "$t/after" k3sm

	# gc-sweep: only a sweep after the start counts, and only one with none failed.
	{
		echo '{"time":"2026-11-06T09:00:00.000-08:00","msg":"registry gc: sweep finished","failed":0,"err":null}'
		echo 'not json'
	} >"$t/log"
	lchk "gc: a sweep before the start" "$(lab_py gc-sweep 1793988000 <"$t/log")" none
	echo '{"time":"2026-11-06T10:30:00.123-08:00","msg":"registry gc: sweep finished","failed":0,"err":null}' >>"$t/log"
	lchk "gc: a sweep after the start" "$(lab_py gc-sweep 1793988000 <"$t/log")" ok
	echo '{"time":"2026-11-06T18:31:00Z","msg":"registry gc: sweep finished","failed":1,"err":"boom"}' >>"$t/log"
	lchk "gc: the latest sweep failed" "$(lab_py gc-sweep 1793988000 <"$t/log")" failed
	printf 'r/a:v1 sha256:%s\n' "$h64" >"$t/rec"
	echo "{\"msg\":\"registry gc: would reap\",\"repository\":\"r/a\",\"name\":\"sha256:$h64\"}" >"$t/log"
	lchk "gc: a recorded digest named by a sweep" "$(lab_py reaped "$t/rec" <"$t/log" | grep -c .)" 1

	# The run, over the fakes.
	d="$t/clean"
	lab_fake_run "$d" ""
	lchk "lab clean: exit" "$(cat "$d/rc")" 0
	want="install wrk 0.0.1-old|install srv 0.0.1-old|install wrk 0.0.2-new|install srv 0.0.2-new|install wrk 0.0.1-old|install srv 0.0.1-old"
	lchk "lab clean: roll order, workers first both ways" "$(paste -sd'|' "$d/state/calls")" "$want"
	want="$(for row in "${LAB_STEPS[@]}"; do printf '%s ' "${row%%|*}"; done)"
	got="p.0 $(awk '$1 == "STEP" { printf "%s ", $2 }' "$d/evidence/run.log")"
	lchk "lab clean: step order" "$got" "$want"
	lchk "lab clean: every step passed" "$(grep -c '^PASS ' "$d/evidence/run.log")" "${#LAB_STEPS[@]}"
	lchk "lab clean: the verdict" "$(tail -1 "$d/evidence/run.log")" "result: PASS"
	for row in "${LAB_STEPS[@]}"; do
		[ "${row%%|*}" = p.0 ] || [ -f "$d/evidence/${row%%|*}.log" ] || { echo "self-test FAIL: lab clean: no evidence for ${row%%|*}"; bad=1; }
	done
	lchk "lab clean: the store diff" "$(tail -1 "$d/evidence/d.3-verdict.txt")" "verdict: PASS"
	lchk "lab clean: run repositories removed" "$(find "$d/data/server/registry" -mindepth 1 -maxdepth 1 -name 'b1027-*' | grep -c .)" 0
	lchk "lab clean: no run tag left" "$(grep -c . "$d/state/tags")" 0
	lchk "lab clean: namespace removed" "$(find "$d/state/ns" -type f | grep -c .)" 0
	lchk "lab clean: no pod left" "$(find "$d/state/pods" -type f | grep -c .)" 0
	lchk "lab clean: remote scratch removed" "$(find "$d" -maxdepth 1 -name 'remote-*' | grep -c .)" 0
	lchk "lab clean: kubeconfig backups removed" "$(find "$d/home/.kube" -name 'config.b1027-*' | grep -c .)" 0
	lchk "lab clean: IfNotPresent kept the cached digest" "$(grep -c 'IfNotPresent kept' "$d/evidence/run.log")" 1
	lchk "lab clean: e.3 judged zot's reports" "$(grep -c '^PASS e.3 zot GC ok on:' "$d/evidence/run.log")" 1

	d="$t/digest"
	lab_fake_run "$d" digest
	lchk "lab digest mismatch: exit" "$(cat "$d/rc")" 1
	lchk "lab digest mismatch: c.1 refuses" "$(grep -c '^FAIL c.1 a recorded image did not survive' "$d/evidence/run.log")" 1
	lchk "lab digest mismatch: named in the evidence" "$(grep -c '^MISMATCH .*/docker:v1' "$d/evidence/c.1.log")" 1
	lchk "lab digest mismatch: later steps not reached" "$(grep -c '^NOT REACHED ' "$d/evidence/run.log")" 13
	lchk "lab digest mismatch: no rollback after the red step" "$(grep -c . "$d/state/calls")" 4
	lchk "lab digest mismatch: cleanup ran" "$(grep -c '^PASS f.1' "$d/evidence/run.log")" 1
	lchk "lab digest mismatch: the verdict" "$(tail -1 "$d/evidence/run.log")" "result: FAIL"

	d="$t/store"
	lab_fake_run "$d" store
	lchk "lab store: exit" "$(cat "$d/rc")" 1
	lchk "lab store: d.3 fails" "$(grep -c '^FAIL d.3 NONZOT' "$d/evidence/run.log")" 1
	lchk "lab store: the file is named" "$(grep -q '^NONZOT new .*/\.k3sm-extra' "$d/evidence/d.3-verdict.txt" && echo named)" named

	d="$t/gc"
	FAKE_GC_FAILED=1 lab_fake_run "$d" ""
	lchk "lab gc failed: exit" "$(cat "$d/rc")" 1
	lchk "lab gc failed: d.2 fails" "$(grep -c '^FAIL d.2' "$d/evidence/run.log")" 1

	d="$t/zotgc-failed"
	FAKE_ZOT_GC=failed lab_fake_run "$d" ""
	lchk "lab zot GC failed: exit" "$(cat "$d/rc")" 1
	lchk "lab zot GC failed: e.3 fails" "$(grep -c "^FAIL e.3 zot's GC failed on:" "$d/evidence/run.log")" 1

	d="$t/zotgc-none"
	FAKE_ZOT_GC=none lab_fake_run "$d" ""
	lchk "lab no zot GC in the window: exit" "$(cat "$d/rc")" 0
	lchk "lab no zot GC in the window: recorded" "$(grep -c '^PASS e.3 no zot GC cycle in the window; GC under zot is proven by e.5' "$d/evidence/run.log")" 1

	d="$t/leg"
	FAKE_LEG_RC=1 lab_fake_run "$d" ""
	lchk "lab rollback leg red: exit" "$(cat "$d/rc")" 1
	lchk "lab rollback leg red: e.5 fails" "$(grep -c '^FAIL e.5' "$d/evidence/run.log")" 1

	d="$t/pre"
	lab_fake_run "$d" "" --new-set-has-zot
	lchk "lab precondition: exit 3" "$(cat "$d/rc")" 3
	lchk "lab precondition: no install" "$(cat "$d/state/calls" 2>/dev/null | grep -c .)" 0
	lchk "lab precondition: said so" "$(grep -c 'PRECONDITION UNMET.*has a zot member' "$d/out")" 1

	d="$t/nolab"
	FAKE_LAB="" lab_fake_run "$d" ""
	lchk "lab without K3SM_LAB: exit 3" "$(cat "$d/rc")" 3
	lchk "lab without K3SM_LAB: no ssh" "$(cat "$d/state/ssh.log" 2>/dev/null | grep -c .)" 0

	if [ "$bad" = 0 ]; then rm -rf "$t"; else echo "self-test: the fake runs are kept in $t"; fi
	return "$bad"
}

if [ "${1:-}" = "--self-test" ] && [ $# -eq 1 ]; then self_test; exit 0; fi
if [ "${1:-}" = "--plan" ] && [ $# -eq 1 ]; then lab_plan; exit 0; fi
if [ "${1:-}" = "--lab" ]; then
	shift
	lab_main "$@"
	exit 0
fi

usage() { echo "usage: $0 --rollback-leg --zot PATH --k3sm PATH --work DIR [--pass-wait S] [--zot-gc-wait S] | --lab ... (--lab --help) | --plan | --self-test" >&2; exit 2; }
LEG=0; ZOT=""; K3SM=""; WORK=""; PASS_WAIT=4500; ZOT_GC_WAIT=120
while [ $# -gt 0 ]; do
	case "$1" in
	--rollback-leg) LEG=1; shift ;;
	--zot) [ $# -ge 2 ] || usage; ZOT="$2"; shift 2 ;;
	--k3sm) [ $# -ge 2 ] || usage; K3SM="$2"; shift 2 ;;
	--work) [ $# -ge 2 ] || usage; WORK="$2"; shift 2 ;;
	--pass-wait) [ $# -ge 2 ] || usage; PASS_WAIT="$2"; shift 2 ;;
	--zot-gc-wait) [ $# -ge 2 ] || usage; ZOT_GC_WAIT="$2"; shift 2 ;;
	*) usage ;;
	esac
done
[ "$LEG" = 1 ] || usage
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "$GATE_NAME leg: LAB-PENDING: not a pass (needs K3SM_LAB=1)" >&2
	exit 3
fi
[ -x "$ZOT" ] && [ -x "$K3SM" ] && [ -d "$WORK" ] || { echo "--zot and --k3sm must be executable and --work an existing directory" >&2; exit 2; }
case "$PASS_WAIT$ZOT_GC_WAIT" in *[!0-9]* | "") usage ;; esac
for t in curl python3 shasum htpasswd awk; do command -v "$t" >/dev/null || { echo "$GATE_NAME: $t is required" >&2; exit 2; }; done

WORK="$(cd "$WORK" && pwd)"
RUN="$(mktemp -d "$WORK/b1027.XXXXXX")"
PIDS=()
cleanup() {
	local p
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && wait "$p" 2>/dev/null || true; done
	rm -rf "$RUN"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log() { echo "[$GATE_NAME] $*"; }

CURL=(curl -sS -u "$USER_NAME:$PASSWORD")
BASE=""

# wait_up <pid> <name> <server log> - bounded wait for a 200 on /v2/.
wait_up() {
	local _
	for _ in $(seq 1 60); do
		kill -0 "$1" 2>/dev/null || { cat "$3" >&2; echo "$GATE_NAME: $2 exited at start" >&2; return 1; }
		[ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/v2/" 2>/dev/null || true)" = 200 ] && return 0
		sleep 0.5
	done
	echo "$GATE_NAME: $2 did not answer 200 on /v2/ in 30s" >&2
	return 1
}

K3SM_DIR="$RUN/k3sm"
STORE="$K3SM_DIR/registry"
K3SM_LOG="$K3SM_DIR/registry.log"
ZOT_DIR="$RUN/zot"
ZOT_LOG="$ZOT_DIR/server.log"
mkdir -p "$K3SM_DIR/registry-state" "$ZOT_DIR" "$RUN/data"
chmod 700 "$K3SM_DIR/registry-state"

# Step 1: the k3sm registry and its two repositories.
port="$(rd_free_port)"
BASE="http://127.0.0.1:$port"
secret="$(printf '%s' "$PASSWORD" | shasum -a 256 | awk '{print $1}')"
cat >"$K3SM_DIR/registry-state/serve.json" <<JSON
{"principals":[{"user":"k3sm","secretSHA256":"$secret"},{"user":"k3sm-gate","secretSHA256":"$secret"}],"listen":"127.0.0.1:$port"}
JSON
chmod 600 "$K3SM_DIR/registry-state/serve.json"
K3SM_START="$(date +%s)"
"$K3SM" registry serve --config "$K3SM_DIR/registry-state/serve.json" >"$K3SM_DIR/server.log" 2>&1 &
K3SM_PID=$!
PIDS+=("$K3SM_PID")
wait_up "$K3SM_PID" k3sm "$K3SM_DIR/server.log"

head -c 2097152 /dev/urandom >"$RUN/data/layer"
head -c 4096 /dev/urandom >"$RUN/data/orphan-temp"
head -c 4096 /dev/urandom >"$RUN/data/orphan-control"
LAYER="$(rd_sha_of "$RUN/data/layer")"
ORPHAN_TEMP="$(rd_sha_of "$RUN/data/orphan-temp")"
ORPHAN_CONTROL="$(rd_sha_of "$RUN/data/orphan-control")"
for r in "$TEMP_REPO" "$CONTROL_REPO"; do
	rd_upload "$r" "$RUN/data/layer" "$LAYER"
	rd_put_manifest "$RUN/data" "$r" v1 "$LAYER" 2097152
done
MANIFEST="$(rd_sha_of "$RUN/data/m.json")"
rd_upload "$TEMP_REPO" "$RUN/data/orphan-temp" "$ORPHAN_TEMP"
rd_upload "$CONTROL_REPO" "$RUN/data/orphan-control" "$ORPHAN_CONTROL"
from="$(rd_lines "$K3SM_LOG")"

# Step 2: the pass.
log "waiting for the first sweep and a dedupe pass (about 61 minutes from the server's start)"
if ! rd_dedupe_leg "$K3SM_LOG" "$STORE" "$TEMP_REPO" "$CONTROL_REPO" "$LAYER" "$from" "$((K3SM_START + PASS_WAIT))" "$K3SM_PID"; then
	echo "result: FAIL (no pass, or the pass did not hold, before the rollback)"
	exit 1
fi
log "pass finished: $(awk 'index($0, "\"msg\":\"registry dedupe: pass finished\"") {l=$0} END {print l}' "$K3SM_LOG")"

# Step 3: the rollback starts from a stopped server, and the crash's temp.
kill "$K3SM_PID" 2>/dev/null || true
wait "$K3SM_PID" 2>/dev/null || true
PIDS=()
merge_went_through_temps "$STORE" "$TEMP_REPO" "$CONTROL_REPO" || { echo "result: FAIL (the pass did not use .temps)"; exit 1; }
BLOB="$(rd_blob_path "$STORE" "$TEMP_REPO" "$LAYER")"
TEMP="$(plant_temp "$RUN" "$BLOB")"
temp_ok "$TEMP" "$BLOB" || { echo "result: FAIL (the planted temp is not a link of the layer)"; exit 1; }
log "planted $(basename "$TEMP") in $TEMP_REPO"

# Step 4: zot over the store.
port="$(rd_free_port)"
BASE="http://127.0.0.1:$port"
htpasswd -bBn "$USER_NAME" "$PASSWORD" >"$ZOT_DIR/htpasswd"
cat >"$ZOT_DIR/config.json" <<JSON
{"storage":{"rootDirectory":"$STORE","dedupe":true,"gc":true,"gcDelay":"1s","gcInterval":"10s"},
 "http":{"address":"127.0.0.1","port":"$port","compat":["docker2s2"],"readTimeout":"0s","writeTimeout":"0s",
  "auth":{"failDelay":1,"htpasswd":{"path":"$ZOT_DIR/htpasswd"}},
  "accessControl":{"repositories":{"**":{"policies":[{"users":["$USER_NAME"],"actions":["read","create","update","delete"]}],"defaultPolicy":[],"anonymousPolicy":["read"]}}}},
 "log":{"level":"info"}}
JSON
chmod 600 "$ZOT_DIR/config.json"
"$ZOT" serve "$ZOT_DIR/config.json" >"$ZOT_LOG" 2>&1 &
ZOT_PID=$!
PIDS+=("$ZOT_PID")
wait_up "$ZOT_PID" zot "$ZOT_LOG"

# Step 5.
if ! zot_wait_gc "$ZOT_LOG" "$(($(date +%s) + ZOT_GC_WAIT))" "$ZOT_PID" "$TEMP_REPO" "$CONTROL_REPO"; then
	echo "result: FAIL (zot's GC did not report on both repositories)"
	exit 1
fi
if [ -e "$TEMP" ]; then log "fact: zot left the temp in place"; else log "fact: zot removed the temp"; fi
log "fact: zot logged $(grep -c '"level":"error"' "$ZOT_LOG" || true) errors; its GC reports and errors:"
grep -E '"level":"error"|gc (un)?successfully completed for ' "$ZOT_LOG" | tail -n 12 || true
if rollback_checks "$ZOT_LOG" "$STORE" "$LAYER" "$MANIFEST" "$ORPHAN_TEMP" "$ORPHAN_CONTROL"; then
	echo "result: PASS"
else
	grep -E 'failed to run GC|invalid checksum' "$ZOT_LOG" | tail -n 3 >&2 || true
	echo "result: FAIL"
	exit 1
fi
