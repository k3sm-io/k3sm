#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's rollback, store leg: can zot take back a store the k3sm registry
# has deduped, with a crashed merge's temp left in it?
#
# Only this leg exists so far. The rest of the gate (the upgrade under zot, the
# image verbs, the buildx push, pod pulls and the store diff) is not built, so
# --lab says LAB-PENDING and exits 3 until it is. --rollback-leg passing is not the
# gate passing.
#
# The leg, on loopback, on a store under a fresh temp directory in --work. It
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
# Exit 0 pass, 1 fail, 2 usage, 3 LAB-PENDING: not a pass.
#
# Usage:
#   K3SM_LAB=1 hack/acceptance/B1027.sh --rollback-leg --zot PATH --k3sm PATH --work DIR \
#       [--pass-wait SECONDS] [--zot-gc-wait SECONDS]
#   hack/acceptance/B1027.sh --lab
#   hack/acceptance/B1027.sh --self-test
# Requires: curl, python3, shasum, htpasswd, awk.
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

	# --lab is not a pass while the rest of the gate is unbuilt, with or without K3SM_LAB.
	K3SM_LAB=1 "$0" --lab >/dev/null 2>&1 || rc=$?
	chk "--lab exits 3 with K3SM_LAB=1" "$rc" 3
	rc=0; env -u K3SM_LAB "$0" --lab >/dev/null 2>&1 || rc=$?
	chk "--lab exits 3 without K3SM_LAB" "$rc" 3
	rc=0; env -u K3SM_LAB "$0" --rollback-leg >/dev/null 2>&1 || rc=$?
	chk "--rollback-leg exits 3 without K3SM_LAB" "$rc" 3

	rm -rf "$t"
	[ "$bad" = 0 ] || exit 1
	echo "$GATE_NAME self-test: PASS"
}

if [ "${1:-}" = "--self-test" ] && [ $# -eq 1 ]; then self_test; exit 0; fi

usage() { echo "usage: $0 --rollback-leg --zot PATH --k3sm PATH --work DIR [--pass-wait S] [--zot-gc-wait S] | --lab | --self-test" >&2; exit 2; }
LEG=0; ZOT=""; K3SM=""; WORK=""; PASS_WAIT=4500; ZOT_GC_WAIT=120
while [ $# -gt 0 ]; do
	case "$1" in
	--lab)
		echo "$GATE_NAME gate: LAB-PENDING: not a pass (only --rollback-leg is built)" >&2
		exit 3
		;;
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
