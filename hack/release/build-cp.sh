#!/usr/bin/env bash
#
# build-cp.sh — build the control-plane binaries from pinned upstream source.
#
# A signed release signs only k3sm's own builds, never a third party's. So the
# four control-plane binaries the payload ships (kube-apiserver, kube-scheduler,
# kube-controller-manager, kubectl) are compiled here from the upstream
# Kubernetes source archive for exactly the tag the executor pins
# (pkg/executor.DefaultKubeVersion), instead of being taken from a prebuilt set.
# stage.sh --release accepts exactly this script's outputs as pinned-source files.
#
#   hack/release/build-cp.sh <out-dir>
#   hack/release/build-cp.sh --print-plan
#   hack/release/build-cp.sh --print-outputs
#   hack/release/build-cp.sh --self-test
#
#   <out-dir>        an empty or absent directory; receives exactly the four
#                    binaries, darwin/arm64, unsigned (signing is the release
#                    pipeline's step, after stage.sh --release)
#   --print-plan     print the exact `go build` environment and argv for each
#                    binary; no network, no source needed
#   --print-outputs  print the payload paths this script produces, one per line
#                    (cp-payload/<name>), the list stage.sh --release accepts
#   --self-test      hermetic checks: the tag pin against the executor, the pin
#                    shapes, the required build flags, no floating versions, the
#                    digest refusal over a tiny fixture tarball, the toolchain
#                    assert, a pin-less build refusing before any network, and
#                    the output list against stage.sh's pinned-source list
#
# The build, in order, failing closed at every step:
#   1. the pins below must be real (a placeholder refuses before any network);
#   2. kubernetes-src.tar.gz is downloaded from dl.k8s.io for KUBE_TAG and its
#      sha512 compared with KUBE_SRC_SHA512 BEFORE anything is extracted;
#   3. the source's own .go-version names the toolchain: the build runs with
#      GOTOOLCHAIN=local and refuses unless `go env GOVERSION` equals it;
#   4. each binary is built CGO_ENABLED=0 for darwin/arm64 with -trimpath
#      -buildvcs=false from the vendored source, SOURCE_DATE_EPOCH set to the
#      tag's commit time, and the version stamped through k8s.io/component-base/version.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ---- pins ---------------------------------------------------------------------
# KUBE_TAG must equal pkg/executor.DefaultKubeVersion (the self-test asserts it).
# The three tag facts below are copied from upstream for KUBE_TAG, and change with
# it, in the same commit:
#   KUBE_SRC_SHA512  the content of https://dl.k8s.io/release/<tag>/kubernetes-src.tar.gz.sha512
#   KUBE_TAG_COMMIT  the commit the tag names (git rev-parse <tag>^{commit})
#   KUBE_TAG_EPOCH   that commit's committer time, in seconds (git log -1 --format=%ct <tag>)
# Until they are filled in they hold the PLACEHOLDER below, and a real build
# refuses before it downloads anything.
PLACEHOLDER="UNPINNED-copy-from-upstream-for-the-tag"
KUBE_TAG="v1.37.1"
KUBE_SRC_SHA512="0bf390bf277b36767b8ad494f7f65ae5e3658a5ab2c62061ec4074cac6a26270f4c6beb08d828d3c2323c44e230d04769fdfa532806925333a64d6fcf130f2f4"
KUBE_TAG_COMMIT="f78e722310e50bcaca9276be22276d9e91d91308"
KUBE_TAG_EPOCH="1790183182"
KUBE_SRC_URL="https://dl.k8s.io/release/${KUBE_TAG}/kubernetes-src.tar.gz"

# The binaries, in payload order; each is built from ./cmd/<name>.
OUTPUTS=(kube-apiserver kube-scheduler kube-controller-manager kubectl)

die() { echo "build-cp: $*" >&2; exit 1; }

is_sha512() { printf '%s' "$1" | grep -Eq '^[0-9a-f]{128}$'; }
is_commit() { printf '%s' "$1" | grep -Eq '^[0-9a-f]{40}$'; }
is_epoch() { printf '%s' "$1" | grep -Eq '^[1-9][0-9]{8,10}$'; }

# require_pins: non-zero, naming each, unless every tag fact is a real value.
require_pins() {
	local bad=0
	is_sha512 "$KUBE_SRC_SHA512" || { echo "    KUBE_SRC_SHA512 is not a pinned sha512 ($KUBE_SRC_SHA512)"; bad=1; }
	is_commit "$KUBE_TAG_COMMIT" || { echo "    KUBE_TAG_COMMIT is not a pinned commit ($KUBE_TAG_COMMIT)"; bad=1; }
	is_epoch "$KUBE_TAG_EPOCH" || { echo "    KUBE_TAG_EPOCH is not a pinned commit time ($KUBE_TAG_EPOCH)"; bad=1; }
	return "$bad"
}

# tag_minor: the minor version of KUBE_TAG ("v1.37.1" -> "37").
tag_minor() { local m="${KUBE_TAG#v1.}"; printf '%s' "${m%%.*}"; }

# build_date <epoch>: the RFC 3339 UTC time upstream stamps as buildDate.
build_date() {
	if is_epoch "$1"; then date -u -r "$1" '+%Y-%m-%dT%H:%M:%SZ'; else printf '%s' "$1"; fi
}

# ldflags: -s -w (upstream's default GOLDFLAGS for release builds) and the
# component-base version stamps upstream's hack/lib/version.sh sets. gitTreeState
# is "archive": the build is from a source archive, not a git checkout.
ldflags() {
	local p="k8s.io/component-base/version"
	printf '%s' "-s -w -X $p.gitVersion=$KUBE_TAG -X $p.gitMajor=1 -X $p.gitMinor=$(tag_minor)"
	printf '%s' " -X $p.gitCommit=$KUBE_TAG_COMMIT -X $p.gitTreeState=archive -X $p.buildDate=$(build_date "$KUBE_TAG_EPOCH")"
}

# build_env <src>: the environment of every go build, one VAR=value per line.
# GOWORK names the source's own workspace file (k/k builds as a workspace over
# its staging modules); without one, workspace mode is off. Either way the
# caller's go.work (this repo's lane or workspace) is never used.
build_env() {
	local src="$1" gowork="off"
	[ -f "$src/go.work" ] && gowork="$src/go.work"
	cat <<-EOF
		GOTOOLCHAIN=local
		GOOS=darwin
		GOARCH=arm64
		CGO_ENABLED=0
		GOWORK=$gowork
		SOURCE_DATE_EPOCH=$KUBE_TAG_EPOCH
	EOF
}

# build_argv <out> <name>: the go build argv for one binary, one word per line.
# -mod=vendor builds from the archive's vendor tree and never fetches a module.
build_argv() {
	local out="$1" name="$2"
	printf '%s\n' go build -trimpath -buildvcs=false -mod=vendor -ldflags "$(ldflags)" -o "$out/$name" "./cmd/$name"
}

print_plan() {
	local src="${1:-<src>}" out="${2:-<out-dir>}" name
	echo "# build-cp plan for $KUBE_TAG from $KUBE_SRC_URL (sha512 $KUBE_SRC_SHA512)"
	echo "# toolchain: GOTOOLCHAIN=local, go env GOVERSION must equal go\$(cat <src>/.go-version)"
	echo "# run in: $src"
	for name in "${OUTPUTS[@]}"; do
		echo "## $name"
		build_env "$src" | sed 's/^/env /'
		printf 'argv'
		while IFS= read -r w; do printf ' %q' "$w"; done < <(build_argv "$out" "$name")
		echo
	done
}

print_outputs() {
	local name
	for name in "${OUTPUTS[@]}"; do echo "cp-payload/$name"; done
}

# verify_and_extract <tarball> <sha512> <dest>: refuse unless <sha512> is a real
# pin and the tarball's sha512 equals it; only then extract into <dest>, which
# must be empty. Nothing is extracted on any refusal.
verify_and_extract() {
	local tgz="$1" want="$2" dest="$3" got
	is_sha512 "$want" || { echo "build-cp: refusing to extract: no pinned sha512 for the source archive ($want)" >&2; return 1; }
	[ -f "$tgz" ] || { echo "build-cp: refusing to extract: $tgz is not a file" >&2; return 1; }
	got="$(shasum -a 512 "$tgz" | awk '{print $1}')"
	[ "$got" = "$want" ] || { echo "build-cp: refusing to extract: sha512 of $tgz is $got, pinned $want" >&2; return 1; }
	[ -d "$dest" ] && [ -z "$(ls -A "$dest")" ] || { echo "build-cp: refusing to extract into non-empty $dest" >&2; return 1; }
	# bsdtar refuses absolute and ".." member paths by default (no -P).
	tar -xzf "$tgz" -C "$dest" --no-same-owner || { echo "build-cp: extraction of $tgz failed" >&2; return 1; }
}

# source_root <dest>: the extracted tree's root, the directory holding go.mod and
# .go-version (the archive's top level, or its single top-level directory).
source_root() {
	local dest="$1" d
	if [ -f "$dest/go.mod" ] && [ -f "$dest/.go-version" ]; then printf '%s' "$dest"; return 0; fi
	for d in "$dest"/*/; do
		d="${d%/}"
		if [ -f "$d/go.mod" ] && [ -f "$d/.go-version" ]; then printf '%s' "$d"; return 0; fi
	done
	echo "build-cp: no go.mod and .go-version at the top of the extracted source" >&2
	return 1
}

# assert_toolchain <src>: refuse unless the local toolchain is exactly the one the
# source's .go-version names (GOTOOLCHAIN=local, so go never switches itself).
assert_toolchain() {
	local src="$1" want got
	want="go$(tr -d '[:space:]' <"$src/.go-version")"
	got="$(cd "$src" && GOTOOLCHAIN=local GOWORK=off go env GOVERSION)" || { echo "build-cp: go env GOVERSION failed" >&2; return 1; }
	[ "$got" = "$want" ] || { echo "build-cp: toolchain is $got, the source pins $want (.go-version); install $want and put it first on PATH" >&2; return 1; }
}

build() {
	local out="$1" work tgz src name
	local -a envv argv
	echo "==> build-cp $KUBE_TAG"
	if ! problems="$(require_pins)"; then
		printf '%s\n' "$problems" >&2
		die "refusing to build: the tag pins above are placeholders; copy them from upstream for $KUBE_TAG (see the pins block)"
	fi
	if [ -e "$out" ]; then
		[ -d "$out" ] && [ -z "$(ls -A "$out")" ] || die "$out exists and is not an empty directory"
	fi
	mkdir -p "$out"
	out="$(cd "$out" && pwd)"
	work="$(mktemp -d -t k3sm-build-cp)"
	# shellcheck disable=SC2064 # expand now: work is local
	trap "rm -rf '$work'" EXIT
	tgz="$work/kubernetes-src.tar.gz"
	mkdir "$work/src"

	echo "==> download $KUBE_SRC_URL"
	curl --proto '=https' --tlsv1.2 -fsSL -o "$tgz" "$KUBE_SRC_URL" || die "download of $KUBE_SRC_URL failed"
	echo "==> verify sha512, then extract"
	verify_and_extract "$tgz" "$KUBE_SRC_SHA512" "$work/src" || die "the source archive failed verification"
	src="$(source_root "$work/src")" || die "unrecognised source layout"
	assert_toolchain "$src" || die "toolchain mismatch"

	for name in "${OUTPUTS[@]}"; do
		echo "==> go build $name"
		envv=()
		while IFS= read -r e; do envv+=("$e"); done < <(build_env "$src")
		argv=()
		while IFS= read -r w; do argv+=("$w"); done < <(build_argv "$out" "$name")
		(cd "$src" && env "${envv[@]}" "${argv[@]}") || die "go build $name failed"
	done
	echo "==> built from $KUBE_TAG (sha512 $KUBE_SRC_SHA512):"
	(cd "$out" && shasum -a 256 -- "${OUTPUTS[@]}")
}

# ---- self-test ------------------------------------------------------------------
# Hermetic: no network, no credentials. The positive build path is NOT exercised
# here (it needs the real archive and its toolchain); the refusals are.
self_test() {
	local self="$HERE/build-cp.sh" tmp fails=0 out plan want name fix good dest
	tmp="$(mktemp -d -t k3sm-build-cp-selftest)"
	# shellcheck disable=SC2064 # expand now: tmp is local
	trap "rm -rf '$tmp'" EXIT
	ok() { echo "  ok    $*"; }
	bad() { echo "  FAIL  $*"; fails=$((fails + 1)); }

	echo "==> the tag pin is the executor's kube version"
	want="$(sed -n 's/^[[:space:]]*DefaultKubeVersion[[:space:]]*=[[:space:]]*"\(v[0-9.]*\)".*/\1/p' "$REPO_ROOT/pkg/executor/executor.go")"
	if [ -n "$want" ] && [ "$KUBE_TAG" = "$want" ]; then ok "KUBE_TAG $KUBE_TAG = DefaultKubeVersion"; else bad "KUBE_TAG $KUBE_TAG, DefaultKubeVersion '$want'"; fi
	case "$KUBE_SRC_URL" in
	"https://dl.k8s.io/release/$KUBE_TAG/kubernetes-src.tar.gz") ok "source URL names the exact tag" ;;
	*) bad "source URL $KUBE_SRC_URL" ;;
	esac

	echo "==> pin shapes"
	local v
	for v in KUBE_SRC_SHA512:is_sha512 KUBE_TAG_COMMIT:is_commit KUBE_TAG_EPOCH:is_epoch; do
		local var="${v%%:*}" check="${v#*:}" val
		val="${!var}"
		if "$check" "$val"; then
			ok "$var is a real pin"
		elif [ "$val" = "$PLACEHOLDER" ]; then
			ok "$var is the named placeholder (a real build refuses until it is pinned)"
		else
			bad "$var is neither a well-formed pin nor the placeholder: '$val'"
		fi
	done
	if is_sha512 "$(printf 'a%.0s' $(seq 1 127))"; then bad "a 127-digit sha512 passed the shape check"; else ok "a short sha512 fails the shape check"; fi
	if is_sha512 "$(printf 'A%.0s' $(seq 1 128))"; then bad "an uppercase sha512 passed the shape check"; else ok "an uppercase sha512 fails the shape check"; fi
	if (KUBE_SRC_SHA512="$PLACEHOLDER"; require_pins >/dev/null); then bad "require_pins accepted a placeholder"; else ok "require_pins refuses a placeholder"; fi

	echo "==> the plan carries the required flags"
	plan="$(print_plan)"
	for name in "${OUTPUTS[@]}"; do
		printf '%s\n' "$plan" | grep -q "^## $name\$" || bad "plan has no entry for $name"
	done
	local flag
	for flag in "env GOTOOLCHAIN=local" "env CGO_ENABLED=0" "env GOOS=darwin" "env GOARCH=arm64" "env SOURCE_DATE_EPOCH=$KUBE_TAG_EPOCH" \
		" -trimpath " " -buildvcs=false " " -mod=vendor " "k8s.io/component-base/version.gitVersion=$KUBE_TAG" \
		"k8s.io/component-base/version.gitMajor=1" "k8s.io/component-base/version.gitMinor=$(tag_minor)" \
		"k8s.io/component-base/version.buildDate=" "k8s.io/component-base/version.gitCommit="; do
		local n
		n="$(printf '%s\n' "$plan" | grep -cF -- "$flag" || true)"
		if [ "$n" -eq "${#OUTPUTS[@]}" ]; then ok "every build carries '$flag'"; else bad "'$flag' appears $n times, want ${#OUTPUTS[@]}"; fi
	done
	if printf '%s\n' "$plan" | grep -q "GOWORK=off"; then ok "a source without go.work builds with workspace mode off"; else bad "the plan does not isolate GOWORK"; fi
	mkdir -p "$tmp/wsrc" && : >"$tmp/wsrc/go.work"
	if build_env "$tmp/wsrc" | grep -qx "GOWORK=$tmp/wsrc/go.work"; then ok "a source with go.work builds as its own workspace"; else bad "GOWORK does not name the source's go.work"; fi

	echo "==> no floating versions"
	local floating="@""latest"
	if grep -n -- "$floating" "$self" >/dev/null; then bad "build-cp.sh names $floating"; else ok "no $floating in build-cp.sh"; fi

	echo "==> the digest gate over a fixture tarball"
	fix="$tmp/fixture"
	mkdir -p "$fix/kubernetes/cmd/kubectl"
	printf 'module k8s.io/kubernetes\n' >"$fix/kubernetes/go.mod"
	printf '1.0.0\n' >"$fix/kubernetes/.go-version"
	(cd "$fix" && COPYFILE_DISABLE=1 tar -czf "$tmp/src.tar.gz" kubernetes)
	good="$(shasum -a 512 "$tmp/src.tar.gz" | awk '{print $1}')"
	dest="$tmp/x-missing" && mkdir "$dest"
	if verify_and_extract "$tmp/src.tar.gz" "$PLACEHOLDER" "$dest" 2>/dev/null; then bad "extracted with no pinned digest"; else ok "a missing digest refuses"; fi
	if [ -z "$(ls -A "$dest")" ]; then ok "nothing extracted on a missing digest"; else bad "bytes extracted on a missing digest"; fi
	dest="$tmp/x-empty" && mkdir "$dest"
	if verify_and_extract "$tmp/src.tar.gz" "" "$dest" 2>/dev/null; then bad "extracted with an empty digest"; else ok "an empty digest refuses"; fi
	dest="$tmp/x-wrong" && mkdir "$dest"
	local wrong
	wrong="$(printf '%s' "$good" | tr '0-9a-f' '1-9a-f0')"
	if verify_and_extract "$tmp/src.tar.gz" "$wrong" "$dest" 2>/dev/null; then bad "extracted under a mismatched digest"; else ok "a mismatched digest refuses"; fi
	if [ -z "$(ls -A "$dest")" ]; then ok "nothing extracted on a mismatch"; else bad "bytes extracted on a mismatch"; fi
	dest="$tmp/x-good" && mkdir "$dest"
	if verify_and_extract "$tmp/src.tar.gz" "$good" "$dest" && [ "$(source_root "$dest")" = "$dest/kubernetes" ]; then
		ok "the pinned digest extracts and the source root is found"
	else
		bad "the pinned digest did not extract the fixture"
	fi

	echo "==> the toolchain assert"
	if assert_toolchain "$dest/kubernetes" 2>/dev/null; then bad "go 1.0.0 was accepted as the local toolchain"; else ok "a .go-version the local go is not refuses"; fi
	local cur
	cur="$(GOTOOLCHAIN=local GOWORK=off go env GOVERSION)"
	printf '%s\n' "${cur#go}" >"$dest/kubernetes/.go-version"
	if assert_toolchain "$dest/kubernetes"; then ok "the matching local toolchain passes"; else bad "the matching toolchain $cur was refused"; fi

	echo "==> a pin-less build refuses before any network"
	mkdir -p "$tmp/bin"
	printf '#!/bin/sh\necho called >>"%s"\nexit 1\n' "$tmp/curl.log" >"$tmp/bin/curl"
	chmod 0755 "$tmp/bin/curl"
	if ! require_pins >/dev/null; then
		if out="$(PATH="$tmp/bin:$PATH" "$self" "$tmp/out" 2>&1)"; then
			bad "build ran with placeholder pins"
		elif printf '%s\n' "$out" | grep -q "placeholders"; then
			ok "build refuses, naming the placeholder pins"
		else
			bad "build refused without naming the pins: $out"
		fi
		if [ ! -e "$tmp/curl.log" ]; then ok "nothing was downloaded"; else bad "curl ran before the pins were checked"; fi
	else
		ok "pins are real; the pin-less refusal is covered by require_pins above"
	fi

	echo "==> outputs equal stage.sh's pinned-source list"
	local mine theirs
	mine="$(print_outputs)"
	theirs="$("$HERE/stage.sh" --print-pinned-source-files)" || bad "stage.sh --print-pinned-source-files failed"
	if [ "$mine" = "$theirs" ]; then ok "build-cp outputs = stage.sh PINNED_SOURCE_FILES"; else bad "outputs '$mine' != stage.sh '$theirs'"; fi

	unset -f ok bad
	echo
	if [ "$fails" -ne 0 ]; then
		echo "build-cp self-test: $fails FAILED"
		return 1
	fi
	echo "build-cp self-test: all passed"
}

# ---- arguments --------------------------------------------------------------------
case "${1:-}" in
--self-test) [ $# -eq 1 ] || die "--self-test takes no arguments"; self_test ;;
--print-plan) [ $# -eq 1 ] || die "--print-plan takes no arguments"; print_plan ;;
--print-outputs) [ $# -eq 1 ] || die "--print-outputs takes no arguments"; print_outputs ;;
-h | --help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' ;;
"" | -*) die "usage: build-cp.sh <out-dir> | --print-plan | --print-outputs | --self-test" ;;
*) [ $# -eq 1 ] || die "usage: build-cp.sh <out-dir>"; build "$1" ;;
esac
