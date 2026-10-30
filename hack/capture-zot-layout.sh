#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# capture-zot-layout.sh: capture the on-disk store the pinned zot leaves, so
# pkg/ociregistry/store is tested against what zot really writes rather than
# against a reading of its source.
#
# It starts the pinned zot (the version pkg/registrysvc pins, checked from the
# binary's Go build info) on a fresh root with k3sm's storage settings (dedupe
# on, GC off for the duration of the capture so nothing is reaped mid-run, basic
# authentication on, which is what makes zot create meta.db), and drives it over
# the distribution API with curl through a fixed push set:
#
#   dedupe/one, dedupe/two  the same config and layer pushed to both (zot
#                           hardlinks the second copy), an annotated OCI manifest
#                           tagged v1 and latest in one and latest in the other,
#                           a second manifest pushed by digest only (an untagged
#                           row), a tag overwrite in dedupe/two (latest moved to
#                           the second manifest), and a leftover upload session
#                           in dedupe/one
#   multi/app               two child manifests pushed by digest, then an OCI index
#                           naming them, tagged v1 and stable
#   docker/app              a Docker v2 schema2 image tagged latest
#   dangling/only           a repository holding only an unfinished upload
#
# Then it stops zot and writes the root (cache.db and meta.db included) as a
# gzipped tar archive, which keeps the hardlinks a git checkout would lose, plus a listing of
# every entry with its mode, size and link group.
#
# Usage:
#   hack/capture-zot-layout.sh [--zot <path>] [--out <dir>]
#       --zot  a zot binary built at the pin (default: build one from the
#              pkg/registrysvc/zotchild wrapper module, the way k3sm stages it)
#       --out  where the fixture goes (default pkg/ociregistry/store/testdata)
#   hack/capture-zot-layout.sh --serve-check <root> [--zot <path>]
#       serve an existing store root (a copy of it) with the pinned zot and read
#       every repository, tag, manifest and referenced blob back through the API,
#       checking each digest; exit 0 iff zot serves all of it
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

ZOT=""
OUT="$ROOT/pkg/ociregistry/store/testdata"
CHECK=""
while [ $# -gt 0 ]; do
	case "$1" in
	--zot) ZOT="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	--serve-check) CHECK="$2"; shift 2 ;;
	*) echo "usage: $0 [--zot <path>] [--out <dir>] | --serve-check <root> [--zot <path>]" >&2; exit 2 ;;
	esac
done

for t in curl shasum bsdtar jq go; do
	command -v "$t" >/dev/null || { echo "FAIL: $t not on PATH" >&2; exit 1; }
done

PIN="$(sed -n 's/^[[:space:]]*DefaultZotVersion = "\(v[^"]*\)"$/\1/p' "$ROOT/pkg/registrysvc/pin.go")"
[ -n "$PIN" ] || { echo "FAIL: cannot read DefaultZotVersion from pkg/registrysvc/pin.go" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zot-capture.XXXXXX")"
ZOT_PID=""
cleanup() {
	if [ -n "$ZOT_PID" ]; then kill "$ZOT_PID" 2>/dev/null || true; wait "$ZOT_PID" 2>/dev/null || true; fi
	rm -rf "$WORK"
}
trap cleanup EXIT

if [ -z "$ZOT" ]; then
	echo "building zot $PIN from the zotchild wrapper module"
	mkdir -p "$WORK/build"
	cp "$ROOT/pkg/registrysvc/zotchild/go.mod.txt" "$WORK/build/go.mod"
	cp "$ROOT/pkg/registrysvc/zotchild/go.sum.txt" "$WORK/build/go.sum"
	(cd "$WORK/build" && GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -o "$WORK/zot" zotregistry.dev/zot/v2/cmd/zot)
	ZOT="$WORK/zot"
fi
[ -x "$ZOT" ] || { echo "FAIL: $ZOT is not an executable" >&2; exit 1; }
got="$(go version -m "$ZOT" | awk '$1 == "mod" && $2 == "zotregistry.dev/zot/v2" {print $3}')"
[ "$got" = "$PIN" ] || { echo "FAIL: $ZOT is zot ${got:-<unknown>}; the pin is $PIN" >&2; exit 1; }

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
URL="http://127.0.0.1:$PORT"
USER_NAME=capture
PASS="capture-$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
STORE="$WORK/root"

start_zot() {
	htpasswd -bBc "$WORK/htpasswd" "$USER_NAME" "$PASS" >/dev/null 2>&1
	cat >"$WORK/config.json" <<EOF
{
  "storage": {"rootDirectory": "$STORE", "dedupe": true, "gc": false},
  "http": {
    "address": "127.0.0.1", "port": "$PORT", "compat": ["docker2s2"],
    "auth": {"htpasswd": {"path": "$WORK/htpasswd"}},
    "accessControl": {"repositories": {"**": {
      "policies": [{"users": ["$USER_NAME"], "actions": ["read", "create", "update", "delete"]}],
      "defaultPolicy": [], "anonymousPolicy": ["read"]}}}
  },
  "log": {"level": "info"}
}
EOF
	"$ZOT" serve "$WORK/config.json" >"$WORK/zot.log" 2>&1 &
	ZOT_PID=$!
	for _ in $(seq 1 100); do
		curl -fsS -o /dev/null "$URL/v2/" 2>/dev/null && return 0
		kill -0 "$ZOT_PID" 2>/dev/null || break
		sleep 0.1
	done
	echo "FAIL: zot did not come up; its log:" >&2
	cat "$WORK/zot.log" >&2
	exit 1
}

stop_zot() {
	kill "$ZOT_PID"
	wait "$ZOT_PID" 2>/dev/null || true
	ZOT_PID=""
}

# api <expected-status> <curl args...>: one authenticated request; prints the
# response headers' Location (if any) and fails on any other status.
api() {
	local want="$1"; shift
	local hdr="$WORK/hdr" code
	code="$(curl -sS -u "$USER_NAME:$PASS" -D "$hdr" -o "$WORK/body" -w '%{http_code}' "$@")"
	if [ "$code" != "$want" ]; then
		echo "FAIL: $* -> $code (want $want)" >&2
		cat "$WORK/body" >&2
		exit 1
	fi
	tr -d '\r' <"$hdr" | sed -n 's/^[Ll]ocation: //p'
}

digest_of() { printf 'sha256:%s' "$(shasum -a 256 "$1" | cut -d' ' -f1)"; }
size_of() { wc -c <"$1" | tr -d ' '; }

# blob <repo> <file>: a monolithic upload of file into repo.
blob() {
	api 201 -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$2" \
		"$URL/v2/$1/blobs/uploads/?digest=$(digest_of "$2")" >/dev/null
}

# manifest <repo> <ref> <media-type> <file>
manifest() {
	api 201 -X PUT -H "Content-Type: $3" --data-binary "@$4" "$URL/v2/$1/manifests/$2" >/dev/null
}

# leftover <repo> <bytes>: an upload session left unfinished after one chunk.
leftover() {
	local loc
	loc="$(api 202 -X POST "$URL/v2/$1/blobs/uploads/")"
	printf '%s' "$2" >"$WORK/chunk"
	api 202 -X PATCH -H 'Content-Type: application/octet-stream' \
		-H "Content-Range: 0-$(($(size_of "$WORK/chunk") - 1))" \
		--data-binary "@$WORK/chunk" "$URL$loc" >/dev/null
}

desc() { printf '{"mediaType":"%s","digest":"%s","size":%s}' "$1" "$(digest_of "$2")" "$(size_of "$2")"; }

capture() {
	start_zot
	local B="$WORK/b"
	mkdir -p "$B"
	local OCI_M=application/vnd.oci.image.manifest.v1+json
	local OCI_I=application/vnd.oci.image.index.v1+json
	local OCI_C=application/vnd.oci.image.config.v1+json
	local OCI_L=application/vnd.oci.image.layer.v1.tar+gzip
	local D_M=application/vnd.docker.distribution.manifest.v2+json
	local D_C=application/vnd.docker.container.image.v1+json
	local D_L=application/vnd.docker.image.rootfs.diff.tar.gzip

	printf 'shared layer bytes\n' >"$B/layer"
	printf 'second layer bytes\n' >"$B/layer2"
	printf '{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers","diff_ids":[]}}' >"$B/config"
	printf '{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s],"annotations":{"org.opencontainers.image.title":"capture"}}' \
		"$OCI_M" "$(desc "$OCI_C" "$B/config")" "$(desc "$OCI_L" "$B/layer")" >"$B/m1"
	printf '{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s,%s]}' \
		"$OCI_M" "$(desc "$OCI_C" "$B/config")" "$(desc "$OCI_L" "$B/layer")" "$(desc "$OCI_L" "$B/layer2")" >"$B/m2"

	for r in dedupe/one dedupe/two; do
		blob "$r" "$B/config"
		blob "$r" "$B/layer"
	done
	blob dedupe/one "$B/layer2"
	manifest dedupe/one v1 "$OCI_M" "$B/m1"
	manifest dedupe/one latest "$OCI_M" "$B/m1"
	manifest dedupe/two latest "$OCI_M" "$B/m1"
	manifest dedupe/one "$(digest_of "$B/m2")" "$OCI_M" "$B/m2"
	blob dedupe/two "$B/layer2"
	manifest dedupe/two latest "$OCI_M" "$B/m2"
	leftover dedupe/one 'partial upload bytes'

	printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' >"$B/config-amd64"
	printf '{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' >"$B/config-arm64"
	blob multi/app "$B/config-amd64"
	blob multi/app "$B/config-arm64"
	blob multi/app "$B/layer"
	for a in amd64 arm64; do
		printf '{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s]}' \
			"$OCI_M" "$(desc "$OCI_C" "$B/config-$a")" "$(desc "$OCI_L" "$B/layer")" >"$B/child-$a"
		manifest multi/app "$(digest_of "$B/child-$a")" "$OCI_M" "$B/child-$a"
	done
	printf '{"schemaVersion":2,"mediaType":"%s","manifests":[%s,%s]}' "$OCI_I" \
		"$(desc "$OCI_M" "$B/child-amd64" | sed 's/}$/,"platform":{"architecture":"amd64","os":"linux"}}/')" \
		"$(desc "$OCI_M" "$B/child-arm64" | sed 's/}$/,"platform":{"architecture":"arm64","os":"linux"}}/')" >"$B/index"
	manifest multi/app v1 "$OCI_I" "$B/index"
	manifest multi/app stable "$OCI_I" "$B/index"

	printf '{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}' >"$B/dconfig"
	printf 'docker layer bytes\n' >"$B/dlayer"
	blob docker/app "$B/dconfig"
	blob docker/app "$B/dlayer"
	printf '{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s]}' \
		"$D_M" "$(desc "$D_C" "$B/dconfig")" "$(desc "$D_L" "$B/dlayer")" >"$B/dmanifest"
	manifest docker/app latest "$D_M" "$B/dmanifest"

	leftover dangling/only 'dangling bytes'

	stop_zot
	for f in cache.db meta.db; do
		[ -f "$STORE/$f" ] || { echo "FAIL: zot left no $f" >&2; exit 1; }
	done

	mkdir -p "$OUT"
	local tarball="$OUT/zot-$PIN.tar.gz" listing="$OUT/zot-$PIN.txt"
	(cd "$STORE" && bsdtar --uid 0 --gid 0 --uname root --gname wheel -czf "$tarball" .)
	{
		echo "# zot $PIN store, captured by hack/capture-zot-layout.sh; do not edit."
		echo "# <mode> <size> <inode-group> <path>; an inode group above 1 entry is a hardlink set."
		(cd "$STORE" && find . -mindepth 1 \( -name cache.db -o -name meta.db \) -prune -o -print | LC_ALL=C sort | while read -r p; do
			stat -f '%Sp %z %i %N' "$p"
		done) | awk '{ if (!($3 in g)) g[$3] = ++n; $3 = "i" g[$3]; print }'
		(cd "$STORE" && for f in cache.db meta.db; do stat -f '%Sp - - %N' "./$f"; done)
	} >"$listing"
	echo "wrote $tarball and $listing"
}

# get <path> <out>: an anonymous read; fails on anything but 200.
get() {
	local code
	code="$(curl -sS -o "$2" -w '%{http_code}' -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' "$URL$1")"
	[ "$code" = 200 ] || { echo "FAIL: GET $1 -> $code" >&2; exit 1; }
}

serve_check() {
	[ -d "$CHECK" ] || { echo "FAIL: $CHECK is not a directory" >&2; exit 1; }
	mkdir -p "$STORE"
	cp -pR "$CHECK/." "$STORE/"
	start_zot
	local n=0 repo tag ref d
	get "/v2/_catalog" "$WORK/catalog"
	for repo in $(jq -r '.repositories[]' "$WORK/catalog"); do
		get "/v2/$repo/tags/list" "$WORK/tags"
		for tag in $(jq -r '.tags // [] | .[]' "$WORK/tags"); do
			get "/v2/$repo/manifests/$tag" "$WORK/m"
			for ref in $(jq -r '[.config.digest // empty] + [.layers[]?.digest] | .[]' "$WORK/m"); do
				get "/v2/$repo/blobs/$ref" "$WORK/blob"
				d="$(digest_of "$WORK/blob")"
				[ "$d" = "$ref" ] || { echo "FAIL: $repo blob $ref read back as $d" >&2; exit 1; }
				n=$((n + 1))
			done
			for ref in $(jq -r '.manifests[]?.digest' "$WORK/m"); do
				get "/v2/$repo/manifests/$ref" "$WORK/child"
				d="$(digest_of "$WORK/child")"
				[ "$d" = "$ref" ] || { echo "FAIL: $repo manifest $ref read back as $d" >&2; exit 1; }
				n=$((n + 1))
			done
			echo "ok $repo:$tag"
		done
	done
	stop_zot
	[ "$n" -gt 0 ] || { echo "FAIL: zot served no content from $CHECK" >&2; exit 1; }
	echo "zot $PIN served $n objects from $CHECK"
}

if [ -n "$CHECK" ]; then
	serve_check
else
	capture
fi
