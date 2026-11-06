#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the registry acceptance scripts that wait for a dedupe pass. Each
# drives its own server on its own temp store; nothing here reads or writes any
# other store.
#
# When a pass can run. A server starts its first sweep 61 minutes after it starts
# (one grace plus a sixtieth, serve.go), and after that every 6 hours. No verb,
# signal or API starts a sweep. A pass rewrites only repositories a sweep has
# reviewed, runs no earlier than that first sweep, and follows it within seconds
# when the last commit is more than 2 minutes old. So a repository pushed before
# the first sweep is merged about 61 minutes after the server started, and one
# pushed after it waits up to 6 hours. rd_dedupe_leg refuses the second shape
# rather than wait that out.
#
# Where the answer is read. A server started directly has no registry-state.json
# (the daemon writes that record and the server only updates one), so its dedupe
# status never appears; registry.log has the same answer, one JSON record a line.
#
# The caller sets CURL (an array) and BASE, and runs under set -euo pipefail.

RD_POLL=5

rd_say() { echo "[registry-dedupe] $*" >&2; }

rd_sha_of() { shasum -a 256 "$1" | awk '{print "sha256:"$1}'; }
rd_free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

# rd_upload <repo> <file> <digest> - POST, one PATCH of the whole body, PUT to close.
# The body is streamed with -T: --data-binary @file reads the file into memory first.
rd_upload() {
	local repo="$1" file="$2" digest="$3" loc
	loc="$("${CURL[@]}" -D - -o /dev/null -X POST "$BASE/v2/$repo/blobs/uploads/" | awk 'tolower($1)=="location:"{gsub(/\r/,""); print $2}')"
	[ -n "$loc" ] || return 1
	case "$loc" in http*) ;; *) loc="$BASE$loc" ;; esac
	loc="$("${CURL[@]}" -D - -o /dev/null -X PATCH -H 'Content-Type: application/octet-stream' -T "$file" "$loc" | awk 'tolower($1)=="location:"{gsub(/\r/,""); print $2}')"
	[ -n "$loc" ] || return 1
	case "$loc" in http*) ;; *) loc="$BASE$loc" ;; esac
	case "$loc" in *\?*) loc="$loc&digest=$digest" ;; *) loc="$loc?digest=$digest" ;; esac
	"${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Length: 0' "$loc" | grep -q '^201$'
}

# rd_put_manifest <dir> <repo> <tag> <layer digest> <layer size> - uploads a config
# blob and tags a manifest naming it and the layer; leaves the manifest in <dir>/m.json.
rd_put_manifest() {
	local dir="$1" repo="$2" tag="$3" ld="$4" ls="$5" cfg="$1/cfg.json" cd
	[ -f "$cfg" ] || printf '{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' >"$cfg"
	cd="$(rd_sha_of "$cfg")"
	rd_upload "$repo" "$cfg" "$cd" || return 1
	printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%s},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"%s","size":%s}]}' "$cd" "$(wc -c <"$cfg" | tr -d ' ')" "$ld" "$ls" >"$dir/m.json"
	"${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$dir/m.json" "$BASE/v2/$repo/manifests/$tag" | grep -q '^201$'
}

# rd_lines <file> - its line count, 0 when it is not there.
rd_lines() { if [ -f "$1" ]; then wc -l <"$1" | tr -d ' '; else echo 0; fi; }

rd_blob_path() { echo "$1/$2/blobs/${3%%:*}/${3#*:}"; }

# rd_no_sweep_yet <log> - 0 when the server has logged no finished sweep.
rd_no_sweep_yet() {
	[ ! -f "$1" ] || ! awk 'index($0, "\"msg\":\"registry gc: sweep finished\"") {found=1} END {exit !found}' "$1"
}

# rd_pass_finished <log> <from line> - 0 when a pass no upload stopped was logged
# as finished past that line.
rd_pass_finished() {
	[ -f "$1" ] || return 1
	awk -v from="$2" 'NR > from && index($0, "\"msg\":\"registry dedupe: pass finished\"") && index($0, "\"stopped_by_upload\":false") {found=1} END {exit !found}' "$1"
}

# rd_wait_for_pass <log> <from line> <deadline epoch> <server pid> - polls the log.
rd_wait_for_pass() {
	local log="$1" from="$2" deadline="$3" pid="$4" polls=0
	while ! rd_pass_finished "$log" "$from"; do
		kill -0 "$pid" 2>/dev/null || { rd_say "the server exited while waiting for a dedupe pass"; return 1; }
		if [ "$(date +%s)" -ge "$deadline" ]; then
			rd_say "no dedupe pass finished by the deadline; last log lines:"
			[ ! -f "$log" ] || tail -n 3 "$log" >&2
			return 1
		fi
		polls=$((polls + 1))
		[ $((polls % 60)) -ne 0 ] || rd_say "still waiting for the first sweep and a dedupe pass, $((deadline - $(date +%s)))s left"
		sleep "$RD_POLL"
	done
}

# rd_same_inode <a> <b> - 0 when both are regular files on one inode. A missing
# file is not the same inode.
rd_same_inode() {
	python3 -I -c 'import os,stat,sys
a,b=os.lstat(sys.argv[1]),os.lstat(sys.argv[2])
sys.exit(0 if stat.S_ISREG(a.st_mode) and os.path.samestat(a,b) else 1)' "$1" "$2" 2>/dev/null
}

# rd_copies_separate <a> <b> - 0 when both exist as regular files on two inodes.
rd_copies_separate() { [ -f "$1" ] && [ ! -L "$1" ] && [ -f "$2" ] && [ ! -L "$2" ] && ! rd_same_inode "$1" "$2"; }

# rd_serves <url path> <digest> - 0 when a GET returns bytes that hash to the digest.
rd_serves() {
	local got
	got="$("${CURL[@]}" -f -H 'Accept: application/vnd.oci.image.manifest.v1+json' "$BASE$1" | shasum -a 256 | awk '{print "sha256:"$1}')" || return 1
	[ "$got" = "$2" ]
}

# rd_dedupe_holds <store> <repo a> <repo b> <digest> - the copies share an inode and
# each repository still serves the digest's bytes.
rd_dedupe_holds() {
	local store="$1" a="$2" b="$3" digest="$4"
	rd_same_inode "$(rd_blob_path "$store" "$a" "$digest")" "$(rd_blob_path "$store" "$b" "$digest")" ||
		{ rd_say "$a and $b do not share an inode for $digest"; return 1; }
	rd_serves "/v2/$a/blobs/$digest" "$digest" || { rd_say "$a does not serve $digest"; return 1; }
	rd_serves "/v2/$b/blobs/$digest" "$digest" || { rd_say "$b does not serve $digest"; return 1; }
}

# rd_dedupe_leg <log> <store> <repo a> <repo b> <digest> <from line> <deadline epoch> <server pid>
# Both repositories are tagged, and <from line> is the log's length after their last
# push. Exit 0 only when no sweep came before that push, the copies were two inodes
# before the pass, a pass finished, and rd_dedupe_holds is true after it.
rd_dedupe_leg() {
	local log="$1" store="$2" a="$3" b="$4" digest="$5" from="$6" deadline="$7" pid="$8"
	if ! rd_no_sweep_yet "$log"; then
		rd_say "a sweep ran before the pushes finished: $a and $b wait for the next sweep, up to 6 hours. Start again on a fresh server, or push sooner"
		return 1
	fi
	if ! rd_copies_separate "$(rd_blob_path "$store" "$a" "$digest")" "$(rd_blob_path "$store" "$b" "$digest")"; then
		rd_say "$a and $b were not two separate copies before a pass ran"
		return 1
	fi
	rd_wait_for_pass "$log" "$from" "$deadline" "$pid" || return 1
	rd_dedupe_holds "$store" "$a" "$b" "$digest"
}

# Self-test double for curl: serves the file under RD_SERVED named by the URL path.
_rd_fake_curl() {
	local url="" a
	for a in "$@"; do url="$a"; done
	[ -f "$RD_SERVED$url" ] || return 22
	cat "$RD_SERVED$url"
}

# _rd_expect <ok|no> <name> <command...> - counts a wrong answer in RD_BAD.
_rd_expect() {
	local want="$1" name="$2" got=no
	shift 2
	if "$@" >/dev/null 2>&1; then got=ok; fi
	[ "$got" = "$want" ] || { echo "self-test FAIL: $name: got $got, want $want"; RD_BAD=1; }
}

# _rd_fixture <dir> <repo a> <repo b> <digest file> - two separate copies of the bytes
# under <dir>/store, served faithfully by the fake curl.
_rd_fixture() {
	local dir="$1" a="$2" b="$3" body="$4" d r p
	rm -rf "$dir/store" "$dir/served"
	d="$(rd_sha_of "$body")"
	for r in "$a" "$b"; do
		p="$(rd_blob_path "$dir/store" "$r" "$d")"
		mkdir -p "$(dirname "$p")" "$dir/served/v2/$r/blobs"
		cp "$body" "$p"
		cp "$body" "$dir/served/v2/$r/blobs/$d"
	done
	: >"$dir/server.log"
}

RD_PASS_LINE='{"time":"2026-11-06T05:00:00-05:00","level":"INFO","msg":"registry dedupe: pass finished","why":"idle","stopped_by_upload":false,"merged":1}'
RD_STOPPED_LINE='{"time":"2026-11-06T05:00:00-05:00","level":"INFO","msg":"registry dedupe: pass finished","why":"idle","stopped_by_upload":true,"merged":0}'
RD_SWEEP_LINE='{"time":"2026-11-06T05:00:00-05:00","level":"INFO","msg":"registry gc: sweep finished","report_only":true}'

# rd_self_test - every assertion above, green on a good fixture and red on a mutant.
# Returns non-zero when one answers wrongly.
rd_self_test() {
	local t a=own/one b=own/two d dead pa pb bg far soon
	t="$(mktemp -d "${TMPDIR:-/tmp}/rd-self-test.XXXXXX")"
	RD_BAD=0
	RD_SERVED="$t/served"
	CURL=(_rd_fake_curl)
	BASE=""
	RD_POLL=0.1
	far=$(($(date +%s) + 30))
	soon=$(($(date +%s) + 1))
	(exit 0) &
	dead=$!
	wait "$dead" || true
	printf 'the right bytes\n' >"$t/body"
	d="$(rd_sha_of "$t/body")"
	pa="$(rd_blob_path "$t/store" "$a" "$d")"
	pb="$(rd_blob_path "$t/store" "$b" "$d")"

	_rd_fixture "$t" "$a" "$b" "$t/body"
	_rd_expect ok "two copies are separate" rd_copies_separate "$pa" "$pb"
	_rd_expect no "two copies do not share an inode" rd_same_inode "$pa" "$pb"
	_rd_expect no "a missing copy is not separate" rd_copies_separate "$pa" "$pb.gone"
	_rd_expect no "a missing copy is not the same inode" rd_same_inode "$pa" "$pb.gone"
	_rd_expect ok "no sweep in an empty log" rd_no_sweep_yet "$t/server.log"
	_rd_expect no "no pass in an empty log" rd_pass_finished "$t/server.log" 0
	_rd_expect ok "right bytes served" rd_serves "/v2/$a/blobs/$d" "$d"
	_rd_expect no "absent path served" rd_serves "/v2/$a/blobs/sha256:gone" "$d"

	# The good shape: separate, then a pass merges them and logs while the leg waits.
	(sleep 0.3; ln -f "$pa" "$pb"; echo "$RD_PASS_LINE" >>"$t/server.log") &
	bg=$!
	_rd_expect ok "leg: a pass merges the copies" rd_dedupe_leg "$t/server.log" "$t/store" "$a" "$b" "$d" 0 "$far" "$$"
	wait "$bg" || true
	_rd_expect ok "holds: shared inode and both serve" rd_dedupe_holds "$t/store" "$a" "$b" "$d"

	# Mutant: the pass ran and merged nothing.
	_rd_fixture "$t" "$a" "$b" "$t/body"
	echo "$RD_PASS_LINE" >>"$t/server.log"
	_rd_expect no "leg: a pass that merged nothing" rd_dedupe_leg "$t/server.log" "$t/store" "$a" "$b" "$d" 0 "$far" "$$"

	# Mutant: the copies were one inode before any pass, so the pass proved nothing.
	_rd_fixture "$t" "$a" "$b" "$t/body"
	ln -f "$pa" "$pb"
	echo "$RD_PASS_LINE" >>"$t/server.log"
	_rd_expect no "leg: shared before a pass" rd_dedupe_leg "$t/server.log" "$t/store" "$a" "$b" "$d" 0 "$far" "$$"

	# Mutant: a sweep came before the pushes, so the next is up to 6 hours away.
	_rd_fixture "$t" "$a" "$b" "$t/body"
	echo "$RD_SWEEP_LINE" >>"$t/server.log"
	_rd_expect no "a sweep is seen" rd_no_sweep_yet "$t/server.log"
	(sleep 0.3; ln -f "$pa" "$pb"; echo "$RD_PASS_LINE" >>"$t/server.log") &
	bg=$!
	_rd_expect no "leg: a sweep before the pushes, even with a good merge" rd_dedupe_leg "$t/server.log" "$t/store" "$a" "$b" "$d" 0 "$far" "$$"
	wait "$bg" || true

	# Mutants: no pass counts. Each must end at the deadline, or at the dead server.
	_rd_fixture "$t" "$a" "$b" "$t/body"
	_rd_expect no "leg: no pass by the deadline" rd_dedupe_leg "$t/server.log" "$t/store" "$a" "$b" "$d" 0 "$soon" "$$"
	_rd_expect no "leg: the server died" rd_dedupe_leg "$t/server.log" "$t/store" "$a" "$b" "$d" 0 "$far" "$dead"
	echo "$RD_STOPPED_LINE" >>"$t/server.log"
	_rd_expect no "a pass an upload stopped does not count" rd_pass_finished "$t/server.log" 0
	echo "$RD_PASS_LINE" >>"$t/server.log"
	_rd_expect no "a pass before the pushes does not count" rd_pass_finished "$t/server.log" 2
	_rd_expect ok "a pass after the pushes counts" rd_pass_finished "$t/server.log" 1

	# Mutants: merged, but a repository serves wrong bytes or nothing.
	_rd_fixture "$t" "$a" "$b" "$t/body"
	ln -f "$pa" "$pb"
	printf 'other bytes\n' >"$t/served/v2/$a/blobs/$d"
	_rd_expect no "holds: repo a serves wrong bytes" rd_dedupe_holds "$t/store" "$a" "$b" "$d"
	_rd_fixture "$t" "$a" "$b" "$t/body"
	ln -f "$pa" "$pb"
	printf 'other bytes\n' >"$t/served/v2/$b/blobs/$d"
	_rd_expect no "holds: repo b serves wrong bytes" rd_dedupe_holds "$t/store" "$a" "$b" "$d"
	_rd_fixture "$t" "$a" "$b" "$t/body"
	ln -f "$pa" "$pb"
	rm "$t/served/v2/$b/blobs/$d"
	_rd_expect no "holds: repo b serves nothing" rd_dedupe_holds "$t/store" "$a" "$b" "$d"

	rm -rf "$t"
	RD_POLL=5
	[ "$RD_BAD" = 0 ]
}
