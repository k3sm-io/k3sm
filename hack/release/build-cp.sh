#!/usr/bin/env bash
#
# build-cp.sh — build the control-plane binaries from pinned upstream source.
#
# A signed release signs only k3sm's own builds, never a third party's. So the
# four control-plane binaries the payload ships (kube-apiserver, kube-scheduler,
# kube-controller-manager, kubectl) are compiled here from the upstream
# Kubernetes source archive for exactly the tag the executor pins
# (pkg/executor.DefaultKubeVersion), instead of being taken from a prebuilt set.
# stage.sh stages exactly this script's outputs as the pinned-source files: from
# --cp-build with --release, and from its own cache of this script's builds for
# lab staging, so a lab cluster runs the control plane a release ships.
#
#   hack/release/build-cp.sh <out-dir>
#   hack/release/build-cp.sh --print-plan
#   hack/release/build-cp.sh --print-outputs
#   hack/release/build-cp.sh --print-cache-key
#   hack/release/build-cp.sh --self-test
#
#   <out-dir>        an empty or absent directory; receives exactly the four
#                    binaries, darwin/arm64, unsigned (signing is a later
#                    step), and the build stamp STAMP_NAME beside them
#   --print-plan     print the exact `go build` environment and argv for each
#                    binary, and the raise list; no network, no source needed
#   --print-outputs  print the payload paths this script produces, one per line
#                    (cp-payload/<name>), the list stage.sh accepts
#   --print-cache-key
#                    print the key a cached build is valid for: the tag, the
#                    toolchain and the hash of the raise, removal and held lists.
#                    stage.sh keys its lab cache on it, so a change to any of them rebuilds
#   --print-raises   print the raise list as "<module> <version>" lines, the
#                    versions stage.sh requires the four binaries to link
#   --print-raise-list-hash
#                    print the sha256 of the raise, removal and held lists, which
#                    stage.sh requires the stamp's raise-list-sha256 to equal
#   --self-test      hermetic checks: the tag pin against the executor, the pin
#                    shapes, the required build flags, no floating versions, the
#                    digest refusal over a tiny fixture tarball, the payload
#                    toolchain assert, the raise list's shapes and cooldown, the
#                    re-vendor diff check, a pin-less build refusing before any
#                    network, and the output list against stage.sh's list
#
# The build, in order, failing closed at every step:
#   1. the pins below must be real (a placeholder refuses before any network);
#   2. kubernetes-src.tar.gz is downloaded from dl.k8s.io for KUBE_TAG and its
#      sha512 compared with KUBE_SRC_SHA512 BEFORE anything is extracted;
#   3. the toolchain is PAYLOAD_GO_VERSION (hack/release/lib/gochild.sh), the
#      one every Go child of the payload is built with, not the source's own
#      .go-version: a patch release of Kubernetes can trail Go's security fixes.
#      Every go command runs under `env -i` with an explicit minimal environment
#      (GOTOOLCHAIN=local, private HOME and caches, GOENV=off), so no caller
#      GOFLAGS, GOENV, GOROOT or GOTOOLCHAIN reaches it, and the build refuses
#      unless `go env GOVERSION` equals the pin and the pin is not older than
#      the source's .go-version;
#   4. the raise list below is checked (shapes, and every entry at least
#      COOLDOWN_DAYS old) before any network, and each entry's publish date is
#      checked against the module proxy before it is applied;
#   5. the raises are applied the way Kubernetes pins a dependency
#      (hack/pin-dependency.sh: `go mod edit -require` in the root go.mod and in
#      every staging go.mod that requires the module), then the source is
#      re-vendored with the minimal part of its hack/update-vendor.sh that
#      moves versions (`go work sync`, `go work vendor`). The build refuses
#      unless every raise lands at exactly its listed version, every other
#      changed module is required, at exactly its new version, by a raised or
#      already-explained module and is past its cooldown too, every module that
#      leaves vendor/modules.txt is on REMOVALS, and no replacement (=>) moves;
#   6. each binary is built CGO_ENABLED=0 for darwin/arm64 with -trimpath
#      -buildvcs=false from the re-vendored source, SOURCE_DATE_EPOCH set to the
#      tag's commit time, and the version stamped through k8s.io/component-base/version;
#   7. STAMP_NAME is written beside the binaries: tag, source sha512, toolchain,
#      cache key, the raise and removal lists, every vendor change, the findings
#      the raise list leaves open (HELD), and the sha256 of each binary, which
#      stage.sh rechecks before it uses a cached or handed-in build.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# PAYLOAD_GO_VERSION: the toolchain every Go child of the payload is built with.
# shellcheck source=hack/release/lib/gochild.sh
. "$HERE/lib/gochild.sh"

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

# The build stamp written beside the binaries (stage.sh reads it by this name).
STAMP_NAME="BUILD-STAMP"

# ---- the raise list -------------------------------------------------------------
# The modules the Kubernetes source vendors at a version with a vulnerability
# govulncheck finds reachable in these binaries, raised to fix every such
# finding for that module. One line per module:
#
#   <module> <version> <published> <advisories it fixes, comma-separated>
#
# <version> is the version the module LANDS at after the re-vendor: the first
# version that fixes its findings, or higher where another raise requires more
# (x/net v0.60.0 requires x/crypto v0.57.0 and x/text v0.42.0, so those two are
# listed at the versions they land at). The re-vendor refuses any other landing.
# <published> is the version's `Time` at
# https://proxy.golang.org/<module>/@v/<version>.info, in full; the build re-reads
# it and refuses on a mismatch. A version younger than COOLDOWN_DAYS is refused:
# such a module stays at its vendored version and goes on the HELD list until its
# fix is old enough. Only a module with a reachable finding is listed.
COOLDOWN_DAYS=14
RAISES="github.com/google/cel-go v0.30.0 2026-07-25T00:08:13Z GO-2026-6094
go.etcd.io/etcd/client/pkg/v3 v3.7.1 2026-07-23T19:30:42Z GO-2026-6107
golang.org/x/crypto v0.57.0 2026-09-08T18:05:01Z GO-2026-6303,GO-2026-6354,GO-2026-6355
golang.org/x/net v0.60.0 2026-10-08T17:22:58Z GO-2026-6603,GO-2026-6610,GO-2026-6611,GO-2026-6612,GO-2026-6617
golang.org/x/text v0.42.0 2026-09-08T16:29:55Z GO-2026-6629
google.golang.org/grpc v1.83.2 2026-08-25T15:47:16Z GO-2026-6348,GO-2026-6441,GO-2026-6443"

# The modules the re-vendor is expected to drop from vendor/modules.txt, one per
# line: <module> <vendored version> <the raise that drops it>. Any other removal
# is refused, so a module cannot leave the build unnoticed.
REMOVALS="go.opentelemetry.io/otel/sdk/metric v1.44.0 google.golang.org/grpc: v1.83.2 no longer imports it"

# The findings the raise list leaves open, one per line:
#   <module> <advisory> <why it is not raised>
# They are written into the stamp so a reader of the payload sees them.
HELD="golang.org/x/crypto GO-2026-5932 no fixed version: golang.org/x/crypto/openpgp is deprecated upstream and every release carries it"

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

# The extractor: the system bsdtar by absolute path, which refuses absolute and
# ".." member paths by default (no -P). A GNU tar earlier on PATH is never used.
TAR=/usr/bin/tar

# is_bsdtar [tar]: zero iff the tar (default TAR) is bsdtar.
is_bsdtar() { "${1:-$TAR}" --version 2>/dev/null | head -n 1 | grep -q '^bsdtar '; }

# go_dir: the directory of the go on the caller's PATH, the toolchain the build
# runs (assert_toolchain proves it is PAYLOAD_GO_VERSION). Empty if none.
go_dir() {
	local g
	g="$(command -v go 2>/dev/null)" || return 0
	(cd "$(dirname "$g")" && pwd -P)
}

# build_env <src> <work> <godir>: the WHOLE environment of every go command the
# build runs, one VAR=value per line, applied with `env -i` so nothing the caller
# exported (GOFLAGS, GOENV, GOROOT, GOTOOLCHAIN, GOPROXY, ...) can steer it. HOME,
# the caches and TMPDIR live in the build's own work dir, so no go env file or
# cache of the caller's is read either; GOENV=off makes that explicit. GOWORK
# names the source's own workspace file (k/k builds as a workspace over its
# staging modules); without one, workspace mode is off.
build_env() {
	local src="$1" work="$2" godir="$3" gowork="off"
	# The go command's cwd is the resolved path, so GOWORK must name the same
	# spelling or it does not match the workspace's `use .`.
	if [ -f "$src/go.work" ]; then
		src="$(cd "$src" && pwd -P)"
		gowork="$src/go.work"
	fi
	cat <<-EOF
		PATH=$godir:/usr/bin:/bin
		HOME=$work/home
		GOCACHE=$work/gocache
		GOPATH=$work/gopath
		GOMODCACHE=$work/gopath/pkg/mod
		TMPDIR=$work/tmp
		GOENV=off
		GOTOOLCHAIN=local
		GOOS=darwin
		GOARCH=arm64
		CGO_ENABLED=0
		GOWORK=$gowork
		SOURCE_DATE_EPOCH=$KUBE_TAG_EPOCH
	EOF
}

# cleanup_tree <dir>: remove a work tree even when it holds read-only
# directories (a Go module cache is written read-only).
cleanup_tree() { chmod -R u+w "$1" 2>/dev/null || true; rm -rf "$1"; }

# prepare_work <work>: create the directories build_env points into.
prepare_work() { mkdir -p "$1/home" "$1/gocache" "$1/gopath" "$1/tmp"; }

# build_argv <godir> <out> <name>: the go build argv for one binary, one word per
# line. go is named by absolute path. -mod=vendor builds from the archive's vendor
# tree and never fetches a module.
build_argv() {
	local godir="$1" out="$2" name="$3"
	printf '%s\n' "$godir/go" build -trimpath -buildvcs=false -mod=vendor -ldflags "$(ldflags)" -o "$out/$name" "./cmd/$name"
}

# plan_line <src> <work> <godir> <out> <name>: the exact command for one binary:
# env -i, the environment, the argv.
plan_line() {
	local src="$1" work="$2" godir="$3" out="$4" name="$5" w
	printf 'env -i'
	while IFS= read -r w; do printf ' %q' "$w"; done < <(build_env "$src" "$work" "$godir")
	while IFS= read -r w; do printf ' %q' "$w"; done < <(build_argv "$godir" "$out" "$name")
	echo
}

print_plan() {
	local src="<src>" work="<work>" out="<out-dir>" godir name
	godir="$(go_dir)"
	[ -n "$godir" ] || godir="<go-dir>"
	echo "# build-cp plan for $KUBE_TAG from $KUBE_SRC_URL (sha512 $KUBE_SRC_SHA512)"
	echo "# toolchain: $godir/go; under the same env, go env GOVERSION must equal $PAYLOAD_GO_VERSION (PAYLOAD_GO_VERSION)"
	echo "# run in: $src (the extracted source, after the raises below are applied and re-vendored); <work> is the build's private temp dir"
	echo "# cache key: $(cache_key)"
	local line
	while IFS= read -r line; do echo "# raise: $line"; done <<<"$RAISES"
	while IFS= read -r line; do [ -n "$line" ] && echo "# held: $line"; done <<<"$HELD"
	for name in "${OUTPUTS[@]}"; do
		echo "## $name"
		plan_line "$src" "$work" "$godir" "$out" "$name"
	done
}

# raise_list_hash: the sha256 of the raise, removal and held lists, the part of
# the cache key that moves when any of them changes.
raise_list_hash() { printf '%s\n--\n%s\n--\n%s\n' "$RAISES" "$REMOVALS" "$HELD" | shasum -a 256 | awk '{print $1}'; }

# cache_key: <tag>-<toolchain>-<first 16 hex of raise_list_hash>.
cache_key() { printf '%s-%s-%s\n' "$KUBE_TAG" "$PAYLOAD_GO_VERSION" "$(raise_list_hash | cut -c1-16)"; }

# ts_epoch <YYYY-MM-DDTHH:MM:SSZ>: a UTC timestamp, in seconds. Non-zero on any
# other form.
ts_epoch() {
	printf '%s' "$1" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || return 1
	date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" '+%s' 2>/dev/null
}

# now_ts: the current UTC time, in ts_epoch's form.
now_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# cooldown_problem <published> <now>: prints the problem and returns non-zero
# unless <published> is at least COOLDOWN_DAYS days (to the second) before <now>.
cooldown_problem() {
	local pub="$1" now="$2" p t
	p="$(ts_epoch "$pub")" || { echo "publish time '$pub' is not YYYY-MM-DDTHH:MM:SSZ"; return 1; }
	t="$(ts_epoch "$now")" || { echo "now '$now' is not YYYY-MM-DDTHH:MM:SSZ"; return 1; }
	[ $((t - p)) -ge $((COOLDOWN_DAYS * 86400)) ] ||
		{ echo "published $pub, inside its $COOLDOWN_DAYS-day cooldown at $now"; return 1; }
}

# raise_problems <raises> <now>: non-zero, one line per problem, unless every
# line of <raises> is "<module> v<semver> <YYYY-MM-DDTHH:MM:SSZ> GO-...[,GO-...]",
# names its module once, and is past its cooldown at <now>. No network.
raise_problems() {
	local list="$1" now="$2" mod ver pub ids extra bad=0 seen="" p
	[ -n "$list" ] || return 0
	while read -r mod ver pub ids extra; do
		[ -n "$mod" ] || continue
		if [ -n "$extra" ] || [ -z "$ids" ]; then echo "    raise '$mod': want '<module> <version> <published> <advisories>'"; bad=1; continue; fi
		printf '%s' "$mod" | grep -Eq '^[a-z0-9.-]+\.[a-z]+(/[A-Za-z0-9._~-]+)+$' || { echo "    raise '$mod': not a module path"; bad=1; }
		printf '%s' "$ver" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo "    raise $mod: '$ver' is not a release version"; bad=1; }
		printf '%s' "$ids" | grep -Eq '^GO-[0-9]{4}-[0-9]+(,GO-[0-9]{4}-[0-9]+)*$' || { echo "    raise $mod: '$ids' is not a list of advisory ids"; bad=1; }
		case " $seen " in *" $mod "*) echo "    raise $mod: listed twice"; bad=1 ;; esac
		seen="$seen $mod"
		p="$(cooldown_problem "$pub" "$now")" || { echo "    raise $mod $ver: $p"; bad=1; }
	done <<<"$list"
	return "$bad"
}

# proxy_time <module> <version>: the version's full Time (YYYY-MM-DDTHH:MM:SSZ)
# at the module proxy (an upper-case letter in the path is sent as "!" and its
# lower case, the proxy protocol's encoding). curl runs under env -i with a fixed
# PATH and -q, so no caller proxy, curlrc or CURL_* setting steers it. A Time with
# fractional seconds or any other form yields nothing, which every caller refuses.
proxy_time() {
	local mod ver enc t
	mod="$1" ver="$2"
	enc="$(printf '%s' "$mod" | sed -E 's/([A-Z])/!\1/g' | tr '[:upper:]' '[:lower:]')"
	t="$(env -i PATH=/usr/bin:/bin curl -q --proto '=https' --tlsv1.2 -fsSL "https://proxy.golang.org/$enc/@v/$ver.info")" || return 1
	printf '%s' "$t" | sed -n 's/.*"Time":"\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}T[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}Z\)".*/\1/p'
}

# verify_publish_dates <raises>: non-zero unless the proxy's Time for every raise
# equals, to the second, the time the list pins.
verify_publish_dates() {
	local mod ver pub ids got bad=0
	while read -r mod ver pub ids; do
		[ -n "$mod" ] || continue
		got="$(proxy_time "$mod" "$ver")" || { echo "    raise $mod $ver: the module proxy did not answer"; bad=1; continue; }
		[ "$got" = "$pub" ] || { echo "    raise $mod $ver: the proxy says published '$got', the list pins $pub"; bad=1; }
	done <<<"$1"
	return "$bad"
}

# vendored_modules <src>: every module line of the source's vendor/modules.txt
# without its "# ": "<module> <version>", or with a replacement
# "<module> <version> => <path> [<version>]", sorted.
vendored_modules() { sed -n 's/^# \([^ #][^ ]* v[^ ]*.*\)$/\1/p' "$1/vendor/modules.txt" | sed 's/[[:space:]]*$//' | LC_ALL=C sort; }

# requires_module <go.mod> <module>: zero iff the go.mod has a require line for
# <module> (in a block or on its own).
requires_module() {
	awk -v m="$2" '
		/^require[[:space:]]*\(/ { inreq = 1; next }
		inreq && /^\)/ { inreq = 0; next }
		inreq && $1 == m { found = 1 }
		/^require[[:space:]]/ && $2 == m { found = 1 }
		END { exit found ? 0 : 1 }
	' "$1"
}

# revendor_problems <before> <after> <graph> <mains> <raises> <removals>: the diff
# check. <before>/<after> are vendored_modules lists, <graph> is `go mod graph`
# output after the re-vendor, <mains> the workspace's main module paths, one per
# line. Prints "raise|pulled|removed <module> <old> -> <new>" for each change and
# "PROBLEM ..." for each change the lists do not explain:
#   - a raised module must land at exactly its listed version (semver compared,
#     so the message says whether it landed below or above);
#   - any other changed module must be required, at exactly its new version, by
#     a raised module or another explained change (an edge from a main module
#     explains nothing: `go work sync` writes those);
#   - a module may leave modules.txt only as <removals> names it, at its old
#     version;
#   - a replacement (=>) may not appear, change or go away, unless the raise or
#     removal list names the module.
# Returns non-zero iff there is a PROBLEM.
revendor_problems() {
	awk '
		# semver_cmp a b: -1, 0 or 1 for two vX.Y.Z[-pre] versions (a release
		# sorts above its pre-releases; pre-releases compare as strings).
		function semver_cmp(a, b,   pa, pb, ra, rb, xa, xb, i) {
			sub(/^v/, "", a); sub(/^v/, "", b)
			pa = a; ra = ""; if (index(a, "-")) { pa = substr(a, 1, index(a, "-") - 1); ra = substr(a, index(a, "-") + 1) }
			pb = b; rb = ""; if (index(b, "-")) { pb = substr(b, 1, index(b, "-") - 1); rb = substr(b, index(b, "-") + 1) }
			split(pa, xa, "."); split(pb, xb, ".")
			for (i = 1; i <= 3; i++) { if (xa[i] + 0 < xb[i] + 0) return -1; if (xa[i] + 0 > xb[i] + 0) return 1 }
			if (ra == rb) return 0
			if (ra == "") return 1
			if (rb == "") return -1
			return ra < rb ? -1 : 1
		}
		function rest(   r) { r = $0; sub(/^[^ ]+ /, "", r); return r }
		FNR == 1 { f++ }
		f == 1 { if ($1 != "") { before[$1] = rest(); bver[$1] = $2 } ; next }
		f == 2 { if ($1 != "") { after[$1] = rest(); aver[$1] = $2 } ; next }
		f == 3 { main[$1] = 1; next }
		f == 4 {
			src = $1; dst = $2
			sp = src; sub(/@.*/, "", sp)
			if (src !~ /@/ || (sp in main)) next
			edges[++ne] = src " " dst
			next
		}
		f == 5 { if ($1 != "") raised[$1] = $2; next }
		f == 6 { if ($1 != "") removal[$1] = $2; next }
		END {
			for (m in after) if (!(m in before) || before[m] != after[m]) changed[m] = aver[m]
			for (m in changed) {
				if (index(after[m], "=>") || ((m in before) && index(before[m], "=>"))) {
					if (!(m in raised) && !(m in removal)) {
						print "PROBLEM " m ": replacement changed: \"" ((m in before) ? before[m] : "(new)") "\" -> \"" after[m] "\""
						bad = 1
					}
				}
			}
			for (m in raised) {
				if (!(m in after)) { print "PROBLEM raise " m " is not vendored after the re-vendor"; bad = 1; continue }
				if (!(m in changed)) { print "PROBLEM raise " m " " raised[m] " did not move the vendored " aver[m]; bad = 1; continue }
				c = semver_cmp(aver[m], raised[m])
				if (c < 0) { print "PROBLEM raise " m " landed at " aver[m] ", below its listed " raised[m]; bad = 1; continue }
				if (c > 0) { print "PROBLEM raise " m " landed at " aver[m] ", above its listed " raised[m] " (list it at the version it lands at, with that version'\''s publish time)"; bad = 1; continue }
				ok[m] = 1
			}
			do {
				grew = 0
				for (i = 1; i <= ne; i++) {
					split(edges[i], e, " ")
					sm = e[1]; sv = e[1]; sub(/@.*/, "", sm); sub(/^[^@]*@/, "", sv)
					dm = e[2]; dv = e[2]; sub(/@.*/, "", dm); sub(/^[^@]*@/, "", dv)
					if (!(sm in ok) || changed[sm] != sv) continue
					if ((dm in changed) && !(dm in ok) && !(dm in raised) && changed[dm] == dv) { ok[dm] = 1; grew = 1 }
				}
			} while (grew)
			for (m in changed) {
				old = (m in before) ? bver[m] : "(new)"
				if (m in raised) { if (m in ok) print "raise " m " " old " -> " changed[m] }
				else if (m in ok) print "pulled " m " " old " -> " changed[m]
				else { print "PROBLEM " m " " old " -> " changed[m] " is not explained by the raise list"; bad = 1 }
			}
			for (m in before) if (!(m in after)) {
				if ((m in removal) && removal[m] == bver[m]) print "removed " m " " bver[m]
				else { print "PROBLEM " m " " bver[m] " left vendor/modules.txt and the removal list does not name it"; bad = 1 }
			}
			for (m in removal) if (!(m in before) || (m in after)) { print "PROBLEM removal " m " " removal[m] " is listed but was not removed"; bad = 1 }
			exit bad
		}
	' <(printf '%s\n' "$1") <(printf '%s\n' "$2") <(printf '%s\n' "$4") <(printf '%s\n' "$3") <(printf '%s\n' "$5") <(printf '%s\n' "$6") | LC_ALL=C sort
	return "${PIPESTATUS[0]}"
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
	is_bsdtar || { echo "build-cp: refusing to extract: $TAR is not bsdtar" >&2; return 1; }
	"$TAR" -xzf "$tgz" -C "$dest" --no-same-owner || { echo "build-cp: extraction of $tgz failed" >&2; return 1; }
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

# assert_toolchain <src> <work> <godir>: refuse unless <godir>/go, run under the
# build's own env -i environment (GOTOOLCHAIN=local, so go never switches
# itself), is exactly PAYLOAD_GO_VERSION, and that pin is not older than the
# toolchain the source's .go-version names.
assert_toolchain() {
	local src="$1" work="$2" godir="$3" want="$PAYLOAD_GO_VERSION" srcgo got e
	local -a envv=()
	[ -x "$godir/go" ] || { echo "build-cp: no go toolchain found on PATH" >&2; return 1; }
	while IFS= read -r e; do envv+=("$e"); done < <(build_env "$src" "$work" "$godir")
	got="$(cd "$src" && env -i "${envv[@]}" "$godir/go" env GOVERSION)" || { echo "build-cp: go env GOVERSION failed" >&2; return 1; }
	[ "$got" = "$want" ] || { echo "build-cp: toolchain is $got, the payload pins $want (PAYLOAD_GO_VERSION); install $want and put it first on PATH" >&2; return 1; }
	srcgo="go$(tr -d '[:space:]' <"$src/.go-version")"
	[ "$(printf '%s\n%s\n' "${srcgo#go}" "${want#go}" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)" = "${want#go}" ] ||
		{ echo "build-cp: the payload pin $want is older than the source's $srcgo (.go-version); move PAYLOAD_GO_VERSION first" >&2; return 1; }
}

# go_in <src> <work> <godir> <go args...>: one go command of the re-vendor in
# <src>, under the build's env -i environment in the source's workspace, with no
# GOFLAGS: Kubernetes' hack/update-vendor.sh unsets GOFLAGS for its go work
# commands, and a workspace refuses -mod=mod. The module proxy and the checksum
# database are the go command's defaults (env -i leaves them unset).
go_in() {
	local src="$1" work="$2" godir="$3" e
	shift 3
	local -a envv=()
	while IFS= read -r e; do envv+=("$e"); done < <(build_env "$src" "$work" "$godir")
	(cd "$src" && env -i "${envv[@]}" LC_ALL=C "$godir/go" "$@")
}

# apply_raises <src> <work> <godir>: pin every raise (root go.mod always, as
# hack/pin-dependency.sh does; a staging go.mod only where it already requires
# the module), propagate with `go work sync`, re-vendor with `go work vendor`,
# then check the diff (revendor_problems) and the cooldown of every pulled-in
# version. Writes the change report to <work>/revendor.txt. Non-zero on any
# failure or unexplained change.
apply_raises() {
	local src="$1" work="$2" godir="$3" mod ver pub ids f before after graph mains report kind m new p bad=0
	[ -f "$src/go.work" ] || { echo "build-cp: the source has no go.work; the re-vendor needs the workspace" >&2; return 1; }
	before="$(vendored_modules "$src")"
	while read -r mod ver pub ids; do
		[ -n "$mod" ] || continue
		go_in "$src" "$work" "$godir" mod edit "-require=$mod@$ver" go.mod || return 1
		for f in "$src"/staging/src/k8s.io/*/go.mod; do
			requires_module "$f" "$mod" || continue
			go_in "$src" "$work" "$godir" mod edit "-require=$mod@$ver" "$f" || return 1
		done
	done <<<"$RAISES"
	echo "==> go work sync"
	go_in "$src" "$work" "$godir" work sync || { echo "build-cp: go work sync failed" >&2; return 1; }
	echo "==> go work vendor"
	go_in "$src" "$work" "$godir" work vendor || { echo "build-cp: go work vendor failed" >&2; return 1; }
	after="$(vendored_modules "$src")"
	graph="$(go_in "$src" "$work" "$godir" mod graph)" || { echo "build-cp: go mod graph failed" >&2; return 1; }
	mains="$(go_in "$src" "$work" "$godir" list -m -f '{{.Path}}')" || { echo "build-cp: go list -m failed" >&2; return 1; }
	report="$(revendor_problems "$before" "$after" "$graph" "$mains" "$RAISES" "$REMOVALS")" || bad=1
	printf '%s\n' "$report" >"$work/revendor.txt"
	printf '%s\n' "$report" | sed 's/^/    /'
	[ "$bad" = 0 ] || { echo "build-cp: the re-vendor changed modules the raise list does not explain (PROBLEM lines above)" >&2; return 1; }
	while read -r kind m _ _ new; do
		[ "$kind" = pulled ] || continue
		pub="$(proxy_time "$m" "$new")" || { echo "build-cp: the module proxy did not answer for pulled-in $m $new" >&2; return 1; }
		p="$(cooldown_problem "$pub" "$(now_ts)")" || { echo "build-cp: pulled-in $m $new: $p" >&2; bad=1; }
	done <<<"$report"
	[ "$bad" = 0 ] || { echo "build-cp: a pulled-in version is inside its cooldown" >&2; return 1; }
}

# write_stamp <out> <src> <work>: the build stamp beside the binaries.
write_stamp() {
	local out="$1" src="$2" work="$3" line tmp
	tmp="$out/.$STAMP_NAME.tmp"
	{
		echo "build-cp stamp"
		echo "tag: $KUBE_TAG (commit $KUBE_TAG_COMMIT)"
		echo "source: $KUBE_SRC_URL sha512 $KUBE_SRC_SHA512"
		echo "toolchain: $PAYLOAD_GO_VERSION (the source's .go-version: go$(tr -d '[:space:]' <"$src/.go-version"))"
		echo "cache-key: $(cache_key)"
		echo "raise-list-sha256: $(raise_list_hash)"
		while IFS= read -r line; do [ -n "$line" ] && echo "raise-list: $line"; done <<<"$RAISES"
		while IFS= read -r line; do [ -n "$line" ] && echo "removal-list: $line"; done <<<"$REMOVALS"
		while IFS= read -r line; do [ -n "$line" ] && echo "vendor: $line"; done <"$work/revendor.txt"
		while IFS= read -r line; do [ -n "$line" ] && echo "held: $line"; done <<<"$HELD"
		(cd "$out" && shasum -a 256 -- "${OUTPUTS[@]}") | awk '{print "sha256: " $1 " " $2}'
	} >"$tmp" || return 1
	chmod 0644 "$tmp" && mv "$tmp" "$out/$STAMP_NAME"
}

build() {
	local out="$1" work tgz src name godir
	local -a envv argv
	echo "==> build-cp $KUBE_TAG with $PAYLOAD_GO_VERSION (cache key $(cache_key))"
	if ! problems="$(require_pins)"; then
		printf '%s\n' "$problems" >&2
		die "refusing to build: the tag pins above are placeholders; copy them from upstream for $KUBE_TAG (see the pins block)"
	fi
	if ! problems="$(raise_problems "$RAISES" "$(now_ts)")"; then
		printf '%s\n' "$problems" >&2
		die "refusing to build: the raise list is malformed or an entry is inside its cooldown (move such a module to HELD until its fix is old enough)"
	fi
	if [ -e "$out" ]; then
		[ -d "$out" ] && [ -z "$(ls -A "$out")" ] || die "$out exists and is not an empty directory"
	fi
	mkdir -p "$out"
	out="$(cd "$out" && pwd)"
	work="$(mktemp -d -t k3sm-build-cp)"
	# shellcheck disable=SC2064 # expand now: work is local
	trap "cleanup_tree '$work'" EXIT
	work="$(cd "$work" && pwd -P)"
	tgz="$work/kubernetes-src.tar.gz"
	mkdir "$work/src"
	prepare_work "$work"
	godir="$(go_dir)"

	echo "==> download $KUBE_SRC_URL"
	curl --proto '=https' --tlsv1.2 -fsSL -o "$tgz" "$KUBE_SRC_URL" || die "download of $KUBE_SRC_URL failed"
	echo "==> verify sha512, then extract"
	verify_and_extract "$tgz" "$KUBE_SRC_SHA512" "$work/src" || die "the source archive failed verification"
	src="$(source_root "$work/src")" || die "unrecognised source layout"
	src="$(cd "$src" && pwd -P)"
	assert_toolchain "$src" "$work" "$godir" || die "toolchain mismatch"
	echo "==> check the raise list's publish dates at the module proxy"
	if ! problems="$(verify_publish_dates "$RAISES")"; then
		printf '%s\n' "$problems" >&2
		die "a raise's publish date does not match the module proxy"
	fi
	echo "==> apply the raise list and re-vendor"
	apply_raises "$src" "$work" "$godir" || die "the raise list could not be applied"

	for name in "${OUTPUTS[@]}"; do
		echo "==> go build $name"
		envv=()
		while IFS= read -r e; do envv+=("$e"); done < <(build_env "$src" "$work" "$godir")
		argv=()
		while IFS= read -r w; do argv+=("$w"); done < <(build_argv "$godir" "$out" "$name")
		(cd "$src" && env -i "${envv[@]}" "${argv[@]}") || die "go build $name failed"
	done
	write_stamp "$out" "$src" "$work" || die "could not write $out/$STAMP_NAME"
	echo "==> built from $KUBE_TAG (sha512 $KUBE_SRC_SHA512) with $PAYLOAD_GO_VERSION:"
	(cd "$out" && shasum -a 256 -- "${OUTPUTS[@]}")
	echo "==> stamp $out/$STAMP_NAME"
}

# ---- self-test ------------------------------------------------------------------
# Hermetic: no network, no credentials. The positive build path is NOT exercised
# here (it needs the real archive and its toolchain); the refusals are.
self_test() {
	local self="$HERE/build-cp.sh" tmp fails=0 rs out plan want name fix good dest
	tmp="$(mktemp -d -t k3sm-build-cp-selftest)"
	# shellcheck disable=SC2064 # expand now: tmp is local
	trap "cleanup_tree '$tmp'" EXIT
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

	echo "==> the plan runs every build under env -i with the required flags"
	plan="$(print_plan)"
	for name in "${OUTPUTS[@]}"; do
		printf '%s\n' "$plan" | grep -q "^## $name\$" || bad "plan has no entry for $name"
	done
	local n
	n="$(printf '%s\n' "$plan" | grep -c '^env -i ' || true)"
	if [ "$n" -eq "${#OUTPUTS[@]}" ]; then ok "every build line starts with env -i"; else bad "$n build lines start with env -i, want ${#OUTPUTS[@]}"; fi
	if printf '%s\n' "$plan" | grep -q 'GOFLAGS'; then bad "the plan names GOFLAGS"; else ok "no GOFLAGS in the plan"; fi
	if printf '%s\n' "$plan" | grep -q 'GOROOT'; then bad "the plan sets GOROOT"; else ok "no GOROOT in the plan (go finds its own)"; fi
	local flag
	for flag in " PATH=" " HOME=" " GOCACHE=" " GOPATH=" " GOMODCACHE=" " TMPDIR=" " GOENV=off " \
		" GOTOOLCHAIN=local " " CGO_ENABLED=0 " " GOOS=darwin " " GOARCH=arm64 " " GOWORK=" " SOURCE_DATE_EPOCH=$KUBE_TAG_EPOCH " \
		" -trimpath " " -buildvcs=false " " -mod=vendor " "k8s.io/component-base/version.gitVersion=$KUBE_TAG" \
		"k8s.io/component-base/version.gitMajor=1" "k8s.io/component-base/version.gitMinor=$(tag_minor)" \
		"k8s.io/component-base/version.buildDate=" "k8s.io/component-base/version.gitCommit="; do
		n="$(printf '%s\n' "$plan" | grep '^env -i ' | grep -cF -- "$flag" || true)"
		if [ "$n" -eq "${#OUTPUTS[@]}" ]; then ok "every build carries '$flag'"; else bad "'$flag' appears in $n build lines, want ${#OUTPUTS[@]}"; fi
	done
	if build_env "<src>" "<work>" "<go-dir>" | grep -qx "GOWORK=off"; then ok "a source without go.work builds with workspace mode off"; else bad "the plan does not isolate GOWORK"; fi
	mkdir -p "$tmp/wsrc" && : >"$tmp/wsrc/go.work"
	if build_env "$tmp/wsrc" "$tmp/w" "/g" | grep -qx "GOWORK=$(cd "$tmp/wsrc" && pwd -P)/go.work"; then ok "a source with go.work builds as its own workspace"; else bad "GOWORK does not name the source's go.work"; fi

	# GOWORK: a src reached through a symlinked parent must yield the resolved GOWORK.
	mkdir -p "$tmp/real/s" && : >"$tmp/real/s/go.work" && ln -s "$tmp/real" "$tmp/link"
	rs="$(cd "$tmp/real/s" && pwd -P)"
	if build_env "$tmp/link/s" "$tmp/w" "/g" | grep -qx "GOWORK=$rs/go.work"; then ok "GOWORK names the resolved path through a symlinked parent"; else bad "GOWORK keeps the symlinked spelling"; fi
	# GOWORK: cleanup removes a tree holding a read-only subtree.
	mkdir -p "$tmp/ro/a/b" && : >"$tmp/ro/a/b/f" && chmod -R a-w "$tmp/ro/a"
	cleanup_tree "$tmp/ro"
	if [ ! -e "$tmp/ro" ]; then ok "cleanup removes a work dir with a read-only subtree"; else chmod -R u+w "$tmp/ro"; bad "a read-only subtree survived cleanup"; fi

	echo "==> the extractor is the system bsdtar"
	if [ "$TAR" = /usr/bin/tar ] && is_bsdtar; then ok "$TAR is bsdtar"; else bad "$TAR is not bsdtar"; fi
	if is_bsdtar /usr/bin/false; then bad "a non-bsdtar extractor passed the check"; else ok "a non-bsdtar extractor is refused"; fi

	echo "==> no floating versions"
	local floating="@""latest"
	if grep -n -- "$floating" "$self" >/dev/null; then bad "build-cp.sh names $floating"; else ok "no $floating in build-cp.sh"; fi

	echo "==> the digest gate over a fixture tarball"
	fix="$tmp/fixture"
	mkdir -p "$fix/kubernetes/cmd/kubectl"
	printf 'module k8s.io/kubernetes\n' >"$fix/kubernetes/go.mod"
	printf '1.0.0\n' >"$fix/kubernetes/.go-version"
	(cd "$fix" && COPYFILE_DISABLE=1 "$TAR" -czf "$tmp/src.tar.gz" kubernetes)
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

	echo "==> the toolchain assert: PAYLOAD_GO_VERSION, under the build's own env -i environment"
	local gd wk="$tmp/work" cur
	gd="$(go_dir)"
	prepare_work "$wk"
	if grep -q '^PAYLOAD_GO_VERSION="go[0-9][0-9.]*"$' "$HERE/lib/gochild.sh" && [ -n "$PAYLOAD_GO_VERSION" ]; then ok "the toolchain pin is gochild.sh's PAYLOAD_GO_VERSION ($PAYLOAD_GO_VERSION)"; else bad "PAYLOAD_GO_VERSION is not read from gochild.sh"; fi
	cur="$(env -i PATH="$gd:/usr/bin:/bin" HOME="$wk/home" GOENV=off GOTOOLCHAIN=local GOWORK=off "$gd/go" env GOVERSION)"
	# The fixture's .go-version is 1.0.0, older than any real toolchain: the
	# assert must follow the payload pin, never the source's file.
	if (PAYLOAD_GO_VERSION="$cur" assert_toolchain "$dest/kubernetes" "$wk" "$gd"); then ok "the payload pin passes whatever the source's .go-version names"; else bad "the local toolchain $cur was refused although it is the payload pin"; fi
	if (PAYLOAD_GO_VERSION=go1.0.1 assert_toolchain "$dest/kubernetes" "$wk" "$gd" 2>/dev/null); then bad "a local go that is not the payload pin was accepted"; else ok "a local go other than the payload pin refuses"; fi
	printf '%s\n' "${cur#go}" >"$dest/kubernetes/.go-version"
	if (PAYLOAD_GO_VERSION=go1.0.1 assert_toolchain "$dest/kubernetes" "$wk" "$gd" 2>/dev/null); then bad "a local go matching only the source's .go-version was accepted"; else ok "matching the source's .go-version alone is not enough"; fi
	printf '99.0.0\n' >"$dest/kubernetes/.go-version"
	if out="$(PAYLOAD_GO_VERSION="$cur" assert_toolchain "$dest/kubernetes" "$wk" "$gd" 2>&1)"; then
		bad "a payload pin older than the source's .go-version was accepted"
	elif printf '%s\n' "$out" | grep -q "older than the source"; then ok "a payload pin older than the source's .go-version refuses"; else bad "the old-pin refusal did not say why: $out"; fi
	printf '1.0.0\n' >"$dest/kubernetes/.go-version"
	# A hostile caller environment must not steer the go commands the build runs.
	if (export GOFLAGS=-mod=mod GOTOOLCHAIN=go1.0.0 GOROOT=/nonexistent GOENV="$tmp/hostile.env"
		printf 'GOTOOLCHAIN=go1.0.0\n' >"$GOENV"
		PAYLOAD_GO_VERSION="$cur" assert_toolchain "$dest/kubernetes" "$wk" "$gd"); then
		ok "caller GOFLAGS, GOTOOLCHAIN, GOROOT and GOENV do not reach the build"
	else
		bad "a caller environment variable steered the toolchain check"
	fi

	echo "==> the raise list"
	local today now d14 d14m1 t0="2026-01-01T00:00:00Z"
	now="$(now_ts)"
	today="${now%%T*}"
	if out="$(raise_problems "$RAISES" "$now")"; then ok "the committed raise list is well-formed and past its cooldown"; else bad "the committed raise list: $out"; fi
	d14="$(date -u -j -v-14d -f '%Y-%m-%dT%H:%M:%SZ' "$now" +%Y-%m-%dT%H:%M:%SZ)"
	d14m1="$(date -u -j -v-14d -v+1S -f '%Y-%m-%dT%H:%M:%SZ' "$now" +%Y-%m-%dT%H:%M:%SZ)"
	if raise_problems "example.com/mod v1.2.3 $d14 GO-2026-0001" "$now" >/dev/null; then ok "a raise published exactly $COOLDOWN_DAYS days ago passes"; else bad "a raise $COOLDOWN_DAYS days old was refused"; fi
	if out="$(raise_problems "example.com/mod v1.2.3 $d14m1 GO-2026-0001" "$now")"; then
		bad "a raise inside its cooldown was accepted"
	elif printf '%s\n' "$out" | grep -q "inside its $COOLDOWN_DAYS-day cooldown"; then ok "a raise one second short of $COOLDOWN_DAYS days is refused (the cooldown compares full timestamps)"; else bad "the cooldown refusal did not say why: $out"; fi
	if raise_problems "example.com/mod v1.2.3 $now GO-2026-0001" "$now" >/dev/null; then bad "a raise published now was accepted"; else ok "a raise published now is refused"; fi
	local shape
	for shape in "example.com/mod 1.2.3 $t0 GO-2026-0001" "example.com/mod v1.2.3 2026-01-01 GO-2026-0001" \
		"example.com/mod v1.2.3 2026-01-01T00:00:00.5Z GO-2026-0001" \
		"example.com/mod v1.2.3 $t0 CVE-2026-1" "example.com/mod v1.2.3 $t0" "nodot v1.2.3 $t0 GO-2026-0001" \
		"example.com/mod v1.2.3-rc.1 $t0 GO-2026-0001" "example.com/mod v1.2.3 $t0 GO-2026-0001 extra"; do
		if raise_problems "$shape" "$now" >/dev/null; then bad "a malformed raise passed: '$shape'"; else ok "malformed raise refused: '$shape'"; fi
	done
	if raise_problems "$(printf 'example.com/mod v1.2.3 %s GO-2026-0001\nexample.com/mod v1.2.4 %s GO-2026-0002' "$t0" "$t0")" "$now" >/dev/null; then bad "a module listed twice passed"; else ok "a module listed twice is refused"; fi
	local k1 k2
	k1="$(cache_key)"
	k2="$(RAISES="$RAISES
example.com/mod v1.2.3 $t0 GO-2026-0001" cache_key)"
	case "$k1" in "$KUBE_TAG-$PAYLOAD_GO_VERSION-"????????????????) ok "the cache key names the tag and the toolchain ($k1)" ;; *) bad "cache key '$k1'" ;; esac
	if [ "$k1" != "$k2" ]; then ok "a raise list change moves the cache key"; else bad "the cache key ignores the raise list"; fi
	if [ "$k1" != "$(PAYLOAD_GO_VERSION=go1.0.1 cache_key)" ]; then ok "a toolchain change moves the cache key"; else bad "the cache key ignores the toolchain"; fi
	if [ "$k1" != "$(REMOVALS="" cache_key)" ]; then ok "a removal list change moves the cache key"; else bad "the cache key ignores the removal list"; fi
	if [ "$("$self" --print-raises)" = "$(printf '%s\n' "$RAISES" | awk '{print $1, $2}')" ] && [ "$("$self" --print-raises | wc -l | tr -d ' ')" = "$(printf '%s\n' "$RAISES" | wc -l | tr -d ' ')" ]; then ok "--print-raises prints each raise as <module> <version>"; else bad "--print-raises: $("$self" --print-raises)"; fi
	if [ "$("$self" --print-raise-list-hash)" = "$(raise_list_hash)" ] && [ "$(raise_list_hash | cut -c1-16)" = "${k1##*-}" ]; then ok "--print-raise-list-hash is the hash the cache key abbreviates"; else bad "--print-raise-list-hash: $("$self" --print-raise-list-hash)"; fi

	echo "==> requires_module reads both require forms"
	printf 'module x\n\nrequire a.example/one v1.0.0\n\nrequire (\n\tb.example/two v1.0.0 // indirect\n)\n' >"$tmp/req.mod"
	if requires_module "$tmp/req.mod" a.example/one && requires_module "$tmp/req.mod" b.example/two; then ok "a single-line and a block require are both found"; else bad "a require was missed"; fi
	if requires_module "$tmp/req.mod" a.example/on; then bad "a prefix matched as a module"; else ok "a module path prefix does not match"; fi

	echo "==> the re-vendor diff check"
	local rb ra rg rg2 rg3 rmains rr
	rb="$(printf 'a.example/raised v1.0.0\nb.example/dep v1.0.0\nc.example/same v1.0.0\nd.example/gone v1.0.0')"
	ra="$(printf 'a.example/raised v1.2.0\nb.example/dep v1.1.0\nc.example/same v1.0.0\ne.example/new v0.1.0')"
	rmains="$(printf 'k8s.io/kubernetes\nk8s.io/api')"
	rr="a.example/raised v1.2.0 $t0 GO-2026-0001"
	local rx="d.example/gone v1.0.0 a.example/raised drops it"
	rg="$(printf 'k8s.io/kubernetes a.example/raised@v1.2.0\na.example/raised@v1.2.0 b.example/dep@v1.1.0\nb.example/dep@v1.1.0 e.example/new@v0.1.0')"
	if out="$(revendor_problems "$rb" "$ra" "$rg" "$rmains" "$rr" "$rx")"; then
		if printf '%s\n' "$out" | grep -qx "pulled b.example/dep v1.0.0 -> v1.1.0" && printf '%s\n' "$out" | grep -qx "pulled e.example/new (new) -> v0.1.0" &&
			printf '%s\n' "$out" | grep -qx "removed d.example/gone v1.0.0"; then
			ok "changes required by a raise (directly and through another) pass and are reported"
		else
			bad "the explained change report: $out"
		fi
	else
		bad "an explained re-vendor was refused: $out"
	fi
	rg2="$(printf 'k8s.io/kubernetes a.example/raised@v1.2.0\nk8s.io/api b.example/dep@v1.1.0\nk8s.io/api e.example/new@v0.1.0')"
	if out="$(revendor_problems "$rb" "$ra" "$rg2" "$rmains" "$rr" "$rx")"; then
		bad "a change required only by a main module passed"
	elif printf '%s\n' "$out" | grep -q "PROBLEM b.example/dep v1.0.0 -> v1.1.0 is not explained"; then ok "a change only a main module requires is refused"; else bad "the unexplained change was not named: $out"; fi
	rg3="$(printf 'a.example/raised@v1.2.0 b.example/dep@v1.0.5\nb.example/dep@v1.1.0 e.example/new@v0.1.0')"
	if revendor_problems "$rb" "$ra" "$rg3" "$rmains" "$rr" >/dev/null; then bad "a change at a version no raise requires passed"; else ok "a change to a version no raise requires is refused"; fi
	if out="$(revendor_problems "$rb" "$rb" "" "$rmains" "$rr" "")"; then bad "a raise that moved nothing passed"; elif printf '%s\n' "$out" | grep -q "did not move"; then ok "a raise that did not move its module is refused"; else bad "the unmoved raise was not named: $out"; fi
	# A raise that lands above its listed version (another module required more).
	local rabove rbelow
	rabove="$(printf '%s\n' "$ra" | sed 's|^a.example/raised v1.2.0$|a.example/raised v1.10.0|')"
	if out="$(revendor_problems "$rb" "$rabove" "$rg" "$rmains" "$rr" "$rx")"; then
		bad "a raise landing above its listed version passed"
	elif printf '%s\n' "$out" | grep -q "PROBLEM raise a.example/raised landed at v1.10.0, above its listed v1.2.0"; then ok "a raise landing above its listed version is refused (semver: v1.10.0 > v1.2.0)"; else bad "the above-listed landing was not named: $out"; fi
	rbelow="$(printf '%s\n' "$ra" | sed 's|^a.example/raised v1.2.0$|a.example/raised v1.1.9|')"
	if out="$(revendor_problems "$rb" "$rbelow" "$rg" "$rmains" "$rr" "$rx")"; then
		bad "a raise landing below its listed version passed"
	elif printf '%s\n' "$out" | grep -q "landed at v1.1.9, below its listed v1.2.0"; then ok "a raise landing below its listed version is refused"; else bad "the below-listed landing was not named: $out"; fi
	if out="$(revendor_problems "$rb" "$ra" "$rg" "$rmains" "$rr" "")"; then
		bad "a removal the list does not name passed"
	elif printf '%s\n' "$out" | grep -q "PROBLEM d.example/gone v1.0.0 left vendor/modules.txt"; then ok "a removal the removal list does not name is refused"; else bad "the unnamed removal was not named: $out"; fi
	if out="$(revendor_problems "$rb" "$ra" "$rg" "$rmains" "$rr" "$rx
f.example/stays v1.0.0 nothing")"; then bad "a listed removal that did not happen passed"; elif printf '%s\n' "$out" | grep -q "PROBLEM removal f.example/stays"; then ok "a listed removal that did not happen is refused"; else bad "the stale removal was not named: $out"; fi
	local rbr rar
	rbr="$(printf '%s\n' "$rb" "g.example/repl v1.0.0 => ./local/repl")"
	rar="$(printf '%s\n' "$ra" "g.example/repl v1.0.0 => ./elsewhere")"
	if out="$(revendor_problems "$rbr" "$rar" "$rg" "$rmains" "$rr" "$rx")"; then
		bad "a changed replacement passed"
	elif printf '%s\n' "$out" | grep -q "PROBLEM g.example/repl: replacement changed"; then ok "a changed replacement (=>) is refused"; else bad "the replacement change was not named: $out"; fi
	rar="$(printf '%s\n' "$ra" "g.example/repl v1.0.0 => ./local/repl")"
	if revendor_problems "$rbr" "$rar" "$rg" "$rmains" "$rr" "$rx" >/dev/null; then ok "an unchanged replacement passes"; else bad "an unchanged replacement was refused"; fi
	rar="$(printf '%s\n' "$ra" "g.example/repl v1.0.0")"
	if revendor_problems "$rbr" "$rar" "$rg" "$rmains" "$rr" "$rx" >/dev/null; then bad "a dropped replacement passed"; else ok "a dropped replacement is refused"; fi
	printf '# a.example/one v1.0.0\n## explicit\na.example/one/pkg\n# k8s.io/api v0.0.0 => ./staging/src/k8s.io/api\n## explicit\n' >"$tmp/mtxt"
	mkdir -p "$tmp/mt/vendor" && cp "$tmp/mtxt" "$tmp/mt/vendor/modules.txt"
	if [ "$(vendored_modules "$tmp/mt")" = "$(printf 'a.example/one v1.0.0\nk8s.io/api v0.0.0 => ./staging/src/k8s.io/api')" ]; then ok "vendored_modules keeps replacement lines"; else bad "vendored_modules: $(vendored_modules "$tmp/mt")"; fi

	echo "==> a pin-less build refuses before any network"
	# A copy of this script with the digest pin reset to the placeholder, so the
	# refusal is exercised whatever the real pins hold.
	mkdir -p "$tmp/bin" "$tmp/pinless/lib"
	printf '#!/bin/sh\necho called >>"%s"\nexit 1\n' "$tmp/curl.log" >"$tmp/bin/curl"
	chmod 0755 "$tmp/bin/curl"
	cp "$HERE/lib/gochild.sh" "$tmp/pinless/lib/"
	# shellcheck disable=SC2016 # the copy must read the literal "$PLACEHOLDER"
	sed 's/^KUBE_SRC_SHA512=.*/KUBE_SRC_SHA512="$PLACEHOLDER"/' "$self" >"$tmp/pinless/build-cp.sh"
	chmod 0755 "$tmp/pinless/build-cp.sh"
	if out="$(PATH="$tmp/bin:$PATH" "$tmp/pinless/build-cp.sh" "$tmp/out" 2>&1)"; then
		bad "build ran with a placeholder digest"
	elif printf '%s\n' "$out" | grep -q "KUBE_SRC_SHA512 is not a pinned sha512"; then
		ok "build refuses, naming the placeholder digest"
	else
		bad "build refused without naming the digest pin: $out"
	fi
	if [ ! -e "$tmp/curl.log" ]; then ok "nothing was downloaded"; else bad "curl ran before the pins were checked"; fi

	echo "==> a raise inside its cooldown refuses the build before any network"
	mkdir -p "$tmp/young/lib"
	cp "$HERE/lib/gochild.sh" "$tmp/young/lib/"
	awk -v d="$now" '/^RAISES="/ { print "RAISES=\"example.com/young v1.0.0 " d " GO-2026-0001"; next } { print }' "$self" >"$tmp/young/build-cp.sh"
	chmod 0755 "$tmp/young/build-cp.sh"
	if out="$(PATH="$tmp/bin:$PATH" "$tmp/young/build-cp.sh" "$tmp/out-young" 2>&1)"; then
		bad "build ran with a raise published today"
	elif printf '%s\n' "$out" | grep -q "raise example.com/young v1.0.0: published $today"'T.*'", inside its $COOLDOWN_DAYS-day cooldown"; then
		ok "build refuses, naming the raise inside its cooldown"
	else
		bad "build refused without naming the young raise: $out"
	fi
	if [ ! -e "$tmp/curl.log" ]; then ok "nothing was downloaded for the young raise"; else bad "curl ran before the raise list was checked"; fi

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
--print-cache-key) [ $# -eq 1 ] || die "--print-cache-key takes no arguments"; cache_key ;;
--print-raises) [ $# -eq 1 ] || die "--print-raises takes no arguments"; printf '%s\n' "$RAISES" | awk 'NF { print $1, $2 }' ;;
--print-raise-list-hash) [ $# -eq 1 ] || die "--print-raise-list-hash takes no arguments"; raise_list_hash ;;
-h | --help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' ;;
"" | -*) die "usage: build-cp.sh <out-dir> | --print-plan | --print-outputs | --print-cache-key | --print-raises | --print-raise-list-hash | --self-test" ;;
*) [ $# -eq 1 ] || die "usage: build-cp.sh <out-dir>"; build "$1" ;;
esac
