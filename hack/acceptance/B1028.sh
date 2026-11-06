#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry baseline taken before zot leaves (docs/m23-plan.md resolution 20):
# zot and the k3sm registry measured on the SAME host, one at a time, each on a
# loopback port with its own temp store under --work.
#
# Measured (the pass rule reads the first three):
#   push / pull MB/s of one layer (default 1 GiB, --layer-mib)
#   RSS (KiB) idle and the peak under five concurrent pushes
#   manifest GET time to first byte (mean of 20)
#   `image ls` over 200 tags: tags/list plus one manifest HEAD per tag, the
#     requests the listing makes, timed end to end
# Recorded as facts, never judged:
#   store bytes after one blob is pushed to two repositories with no mount
#   a pull with the client held to 512 KiB/s (curl --limit-rate): time, curl
#     exit status, and whether the server still answers afterwards
#
# Before each measurement vm.loadavg (1 minute) is recorded; a measurement does
# not start above load 4: the gate waits up to --load-wait seconds, then refuses
# with exit 4 and measures nothing.
#
# Pass rule: k3sm push and pull MB/s each >= 0.8x zot's, and k3sm RSS lower than
# zot's at idle and under load. Exit 0 pass, 1 fail, 2 usage, 3 LAB-PENDING
# (K3SM_LAB unset: not a pass), 4 load refused.
#
# k3sm is started as `k3sm registry serve --config <work>/k3sm/registry-state/
# serve.json` (hidden verb): the config is mode 0600, holds the SHA-256 of the
# k3sm and k3sm-gate passwords and "listen": "127.0.0.1:<port>"; the server runs
# as the invoking non-root user, takes its store at <work>/k3sm/registry, and
# exits when its parent (this script) does. zot gets the former rendered config
# (git show 2d18dd3f^:pkg/registrysvc/config.go): dedupe, gc 1h/6h, docker2s2
# compat, read/write timeouts 0s, htpasswd auth, anonymous read, the k3sm user
# with read/create/update/delete.
#
# Usage:
#   K3SM_LAB=1 hack/acceptance/B1028.sh --lab --zot PATH --k3sm PATH --work DIR \
#       [--layer-mib N] [--load-wait SECONDS]
#   hack/acceptance/B1028.sh --self-test
# Requires: curl, python3 (free port), shasum, htpasswd, awk, ps, sysctl.
# shellcheck disable=SC2034,SC2153  # R_*, Z_* and K_* are set and read indirectly (bash 3.2 has no associative arrays)
set -euo pipefail

GATE_NAME=B1028
USER_NAME=k3sm
PASSWORD="b1028-$$-bench"
LOAD_MAX=4
CONC=5

# ratio_ok <k3sm> <zot> - 0 when k3sm >= 0.8 x zot.
ratio_ok() { awk -v k="$1" -v z="$2" 'BEGIN{exit !(z>0 && k>=0.8*z)}'; }
# lower <k3sm> <zot> - 0 when k3sm is strictly lower.
lower() { awk -v k="$1" -v z="$2" 'BEGIN{exit !(k>0 && z>0 && k<z)}'; }
# mbps <mib> <seconds> - MB/s (1 MiB = 1.048576 MB) to two places.
mbps() { awk -v m="$1" -v s="$2" 'BEGIN{ if (s<=0) {print 0; exit} printf "%.2f", m*1.048576/s }'; }
# verdict <zot push> <k3sm push> <zot pull> <k3sm pull> <zot idle> <k3sm idle> <zot peak> <k3sm peak>
verdict() {
	ratio_ok "$2" "$1" && ratio_ok "$4" "$3" && lower "$6" "$5" && lower "$8" "$7" && echo PASS || echo FAIL
}

self_test() {
	local bad=0
	chk() { [ "$2" = "$3" ] || { echo "self-test FAIL: $1: got $2, want $3"; bad=1; }; }
	chk "mbps 1024MiB in 10s" "$(mbps 1024 10)" "107.37"
	chk "mbps zero seconds" "$(mbps 10 0)" "0"
	exp() { local want="$1" name="$2"; shift 2; if "$@"; then [ "$want" = ok ] || { echo "self-test FAIL: $name"; bad=1; }; else [ "$want" = no ] || { echo "self-test FAIL: $name"; bad=1; }; fi; }
	exp ok "ratio at exactly 0.8" ratio_ok 80 100
	exp no "ratio just under 0.8" ratio_ok 79.9 100
	exp ok "lower" lower 5 6
	exp no "equal is not lower" lower 6 6
	chk "all good" "$(verdict 100 90 100 120 50 40 200 150)" PASS
	chk "push slow" "$(verdict 100 70 100 120 50 40 200 150)" FAIL
	chk "pull slow" "$(verdict 100 90 100 79 50 40 200 150)" FAIL
	chk "idle rss higher" "$(verdict 100 90 100 120 50 50 200 150)" FAIL
	chk "peak rss higher" "$(verdict 100 90 100 120 50 40 200 250)" FAIL
	chk "zero rss is no data" "$(verdict 100 90 100 120 50 0 200 150)" FAIL
	[ "$bad" = 0 ] || exit 1
	echo "$GATE_NAME self-test: PASS"
}

if [ "${1:-}" = "--self-test" ] && [ $# -eq 1 ]; then self_test; exit 0; fi

usage() { echo "usage: $0 --lab --zot PATH --k3sm PATH --work DIR [--layer-mib N] [--load-wait S] | --self-test" >&2; exit 2; }
LAB=0; ZOT=""; K3SM=""; WORK=""; LAYER_MIB=1024; LOAD_WAIT=120
while [ $# -gt 0 ]; do
	case "$1" in
	--lab) LAB=1; shift ;;
	--zot) [ $# -ge 2 ] || usage; ZOT="$2"; shift 2 ;;
	--k3sm) [ $# -ge 2 ] || usage; K3SM="$2"; shift 2 ;;
	--work) [ $# -ge 2 ] || usage; WORK="$2"; shift 2 ;;
	--layer-mib) [ $# -ge 2 ] || usage; LAYER_MIB="$2"; shift 2 ;;
	--load-wait) [ $# -ge 2 ] || usage; LOAD_WAIT="$2"; shift 2 ;;
	*) usage ;;
	esac
done
[ "$LAB" = 1 ] || usage
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "$GATE_NAME gate: LAB-PENDING: not a pass (needs K3SM_LAB=1)" >&2
	exit 3
fi
[ -x "$ZOT" ] && [ -x "$K3SM" ] && [ -d "$WORK" ] || { echo "--zot and --k3sm must be executable and --work an existing directory" >&2; exit 2; }
case "$LAYER_MIB$LOAD_WAIT" in *[!0-9]* | "") usage ;; esac
[ "$LAYER_MIB" -ge 1 ] || usage
for t in curl python3 shasum htpasswd awk ps; do command -v "$t" >/dev/null || { echo "$GATE_NAME: $t is required" >&2; exit 2; }; done

WORK="$(cd "$WORK" && pwd)"
RUN="$(mktemp -d "$WORK/b1028.XXXXXX")"
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

load1() {
	local l
	if l="$(sysctl -n vm.loadavg 2>/dev/null)"; then echo "$l" | awk '{print $2}'; else awk '{print $1}' /proc/loadavg; fi
}
# gate_load <what> - record the load, wait (bounded) for it to be <= 4, else refuse.
gate_load() {
	local waited=0 l
	while :; do
		l="$(load1)"
		log "vm.loadavg(1m)=$l before: $1"
		awk -v l="$l" -v m="$LOAD_MAX" 'BEGIN{exit !(l<=m)}' && return 0
		if [ "$waited" -ge "$LOAD_WAIT" ]; then
			echo "$GATE_NAME: LOAD-REFUSED: load $l > $LOAD_MAX after ${waited}s before: $1" >&2
			exit 4
		fi
		sleep 5; waited=$((waited + 5))
	done
}

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
sha_of() { shasum -a 256 "$1" | awk '{print "sha256:"$1}'; }
now() { python3 -c 'import time; print(time.time())'; }
rss_kib() { ps -o rss= -p "$1" | tr -d ' '; }
dir_bytes() { du -sk "$1" | awk '{print $1*1024}'; }
mkblob() { head -c "$(( $2 * 1048576 ))" /dev/urandom >"$1"; }

CURL=(curl -sS -u "$USER_NAME:$PASSWORD")
BASE=""
# upload <repo> <file> <digest> - POST, one PATCH of the whole body, PUT to close.
upload() {
	local repo="$1" file="$2" digest="$3" loc
	loc="$("${CURL[@]}" -D - -o /dev/null -X POST "$BASE/v2/$repo/blobs/uploads/" | awk 'tolower($1)=="location:"{gsub(/\r/,""); print $2}')"
	[ -n "$loc" ] || return 1
	case "$loc" in http*) ;; *) loc="$BASE$loc" ;; esac
	loc="$("${CURL[@]}" -D - -o /dev/null -X PATCH -H 'Content-Type: application/octet-stream' --data-binary "@$file" "$loc" | awk 'tolower($1)=="location:"{gsub(/\r/,""); print $2}')"
	[ -n "$loc" ] || return 1
	case "$loc" in http*) ;; *) loc="$BASE$loc" ;; esac
	case "$loc" in *\?*) loc="$loc&digest=$digest" ;; *) loc="$loc?digest=$digest" ;; esac
	"${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Length: 0' "$loc" | grep -q '^201$'
}
# put_manifest <repo> <tag> <layer digest> <layer size> - config blob + manifest; echoes nothing.
put_manifest() {
	local repo="$1" tag="$2" ld="$3" ls="$4" cfg="$RUN/cfg.json" cd m
	[ -f "$cfg" ] || printf '{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' >"$cfg"
	cd="$(sha_of "$cfg")"
	upload "$repo" "$cfg" "$cd" || return 1
	m="$(printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%s},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"%s","size":%s}]}' "$cd" "$(wc -c <"$cfg" | tr -d ' ')" "$ld" "$ls")"
	printf '%s' "$m" >"$RUN/m.json"
	"${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$RUN/m.json" "$BASE/v2/$repo/manifests/$tag" | grep -q '^201$'
}

# start_server <name> - sets BASE, SPID, STORE for the named server.
start_server() {
	local name="$1" dir="$RUN/$1" port
	mkdir -p "$dir"; port="$(free_port)"; BASE="http://127.0.0.1:$port"
	case "$name" in
	zot)
		STORE="$dir/store"; mkdir -p "$STORE"
		htpasswd -bBn "$USER_NAME" "$PASSWORD" >"$dir/htpasswd"
		cat >"$dir/config.json" <<JSON
{"storage":{"rootDirectory":"$STORE","dedupe":true,"gc":true,"gcDelay":"1h","gcInterval":"6h"},
 "http":{"address":"127.0.0.1","port":"$port","compat":["docker2s2"],"readTimeout":"0s","writeTimeout":"0s",
  "auth":{"failDelay":1,"htpasswd":{"path":"$dir/htpasswd"}},
  "accessControl":{"repositories":{"**":{"policies":[{"users":["$USER_NAME"],"actions":["read","create","update","delete"]}],"defaultPolicy":[],"anonymousPolicy":["read"]}}}},
 "log":{"level":"info"}}
JSON
		chmod 600 "$dir/config.json"
		"$ZOT" serve "$dir/config.json" >"$dir/server.log" 2>&1 &
		;;
	k3sm)
		STORE="$dir/registry"
		mkdir -p "$dir/registry-state"; chmod 700 "$dir/registry-state"
		local h; h="$(printf '%s' "$PASSWORD" | shasum -a 256 | awk '{print $1}')"
		cat >"$dir/registry-state/serve.json" <<JSON
{"principals":[{"user":"k3sm","secretSHA256":"$h"},{"user":"k3sm-gate","secretSHA256":"$h"}],"listen":"127.0.0.1:$port"}
JSON
		chmod 600 "$dir/registry-state/serve.json"
		"$K3SM" registry serve --config "$dir/registry-state/serve.json" >"$dir/server.log" 2>&1 &
		;;
	esac
	SPID=$!; PIDS+=("$SPID")
	local i
	for i in $(seq 1 60); do
		kill -0 "$SPID" 2>/dev/null || { cat "$dir/server.log" >&2; echo "$GATE_NAME: $name exited at start" >&2; return 1; }
		[ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/v2/" 2>/dev/null || true)" = 200 ] && return 0
		sleep 0.5
	done
	echo "$GATE_NAME: $name did not answer 200 on /v2/ in 30s" >&2; return 1
}
stop_server() {
	kill "$SPID" 2>/dev/null || true; wait "$SPID" 2>/dev/null || true
	PIDS=()
}

# measure <name> - runs every measurement against the named server, sets R_* values.
measure() {
	local name="$1" d="$RUN/data" t0 t1 ld ls i sum
	log "== $name"
	start_server "$name"
	sleep 2
	gate_load "$name idle RSS"; R_IDLE="$(rss_kib "$SPID")"

	ld="$(sha_of "$d/layer")"; ls="$(wc -c <"$d/layer" | tr -d ' ')"
	gate_load "$name push"
	t0="$(now)"; upload bench/a "$d/layer" "$ld"; t1="$(now)"
	R_PUSH="$(mbps "$LAYER_MIB" "$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}')")"
	put_manifest bench/a v1 "$ld" "$ls"

	gate_load "$name pull"
	t0="$(now)"; "${CURL[@]}" -o /dev/null "$BASE/v2/bench/a/blobs/$ld"; t1="$(now)"
	R_PULL="$(mbps "$LAYER_MIB" "$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}')")"

	gate_load "$name RSS under $CONC concurrent pushes"
	local peak=0 r pids=()
	for i in $(seq 1 $CONC); do
		( upload "conc/r$i" "$d/c$i" "$(sha_of "$d/c$i")" ) & pids+=($!)
	done
	while :; do
		local alive=0 p
		for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
		r="$(rss_kib "$SPID" || echo 0)"; [ "${r:-0}" -gt "$peak" ] && peak="$r"
		[ "$alive" = 1 ] || break
		sleep 0.2
	done
	for p in "${pids[@]}"; do wait "$p" || { echo "$GATE_NAME: $name: a concurrent push failed" >&2; return 1; }; done
	R_PEAK="$peak"

	gate_load "$name manifest GET TTFB"
	sum=0
	for i in $(seq 1 20); do
		sum="$(awk -v s="$sum" -v t="$("${CURL[@]}" -o /dev/null -w '%{time_starttransfer}' -H 'Accept: application/vnd.oci.image.manifest.v1+json' "$BASE/v2/bench/a/manifests/v1")" 'BEGIN{print s+t}')"
	done
	R_TTFB="$(awk -v s="$sum" 'BEGIN{printf "%.4f", s/20}')"

	gate_load "$name image ls over 200 tags"
	for i in $(seq 1 200); do
		"${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$RUN/m.json" "$BASE/v2/bench/tags/manifests/t$i" | grep -q '^201$'
	done
	t0="$(now)"
	"${CURL[@]}" "$BASE/v2/bench/tags/tags/list?n=1000" >"$RUN/tags.json"
	python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["tags"]))' "$RUN/tags.json" |
		while read -r tg; do "${CURL[@]}" -I -o /dev/null -H 'Accept: application/vnd.oci.image.manifest.v1+json' "$BASE/v2/bench/tags/manifests/$tg"; done
	t1="$(now)"
	R_LS="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", b-a}')"
	R_LSN="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["tags"]))' "$RUN/tags.json")"

	# Facts. One blob, two repositories, no mount: the second upload is a full upload.
	gate_load "$name store size, one blob in two repositories"
	local before after sd; sd="$(sha_of "$d/small")"
	before="$(dir_bytes "$STORE")"
	upload dup/one "$d/small" "$sd"; upload dup/two "$d/small" "$sd"
	after="$(dir_bytes "$STORE")"
	R_DUP="$((after - before))"

	gate_load "$name throttled pull"
	local rc=0 srv
	t0="$(now)"
	"${CURL[@]}" --limit-rate 512k --max-time 120 -o /dev/null "$BASE/v2/dup/one/blobs/$sd" || rc=$?
	t1="$(now)"
	R_THR_S="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')"; R_THR_RC="$rc"
	srv="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/v2/")"; R_THR_UP="$srv"
	stop_server
}

fields="IDLE PUSH PULL PEAK TTFB LS LSN DUP THR_S THR_RC THR_UP"

log "building inputs under $RUN/data"
mkdir -p "$RUN/data"
mkblob "$RUN/data/layer" "$LAYER_MIB"
mkblob "$RUN/data/small" 6
for i in $(seq 1 $CONC); do mkblob "$RUN/data/c$i" $(( LAYER_MIB / 4 > 256 ? 256 : (LAYER_MIB / 4 > 0 ? LAYER_MIB / 4 : 1) )); done

measure zot
for f in $fields; do v="R_$f"; printf -v "Z_$f" %s "${!v}"; done
measure k3sm
for f in $fields; do v="R_$f"; printf -v "K_$f" %s "${!v}"; done

row() { printf '%-44s %14s %14s\n' "$1" "$2" "$3"; }
echo
row "measurement ($LAYER_MIB MiB layer)" zot k3sm
row "push MB/s" "${Z_PUSH}" "${K_PUSH}"
row "pull MB/s" "${Z_PULL}" "${K_PULL}"
row "RSS idle (KiB)" "${Z_IDLE}" "${K_IDLE}"
row "RSS peak, $CONC concurrent pushes (KiB)" "${Z_PEAK}" "${K_PEAK}"
row "manifest GET TTFB, mean of 20 (s)" "${Z_TTFB}" "${K_TTFB}"
row "image ls, ${Z_LSN}/${K_LSN} tags (s)" "${Z_LS}" "${K_LS}"
row "fact: store growth, 1 blob in 2 repos (B)" "${Z_DUP}" "${K_DUP}"
row "fact: 512KiB/s 6MiB pull (s)" "${Z_THR_S}" "${K_THR_S}"
row "fact: 512KiB/s pull curl exit" "${Z_THR_RC}" "${K_THR_RC}"
row "fact: /v2/ after throttled pull (http)" "${Z_THR_UP}" "${K_THR_UP}"
echo
v="$(verdict "${Z_PUSH}" "${K_PUSH}" "${Z_PULL}" "${K_PULL}" "${Z_IDLE}" "${K_IDLE}" "${Z_PEAK}" "${K_PEAK}")"
echo "rule: push and pull >= 0.8x zot, RSS idle and peak lower than zot"
echo "result: $v"
[ "$v" = PASS ] || exit 1
