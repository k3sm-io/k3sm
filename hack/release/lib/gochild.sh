# shellcheck shell=bash
#
# gochild.sh: the toolchain pin and the build checks for every binary k3sm builds
# from a pinned Go module OUTSIDE its own go.mod. Sourced, never run. Its callers
# are hack/release/stage.sh (kine, etcd, etcdutl and zot, which `k3sm payload`
# builds) and hack/images/metrics-server/build.sh (the native metrics-server
# image). One home, so a recipe cannot drift from the payload's discipline:
#
#   PAYLOAD_GO_VERSION   the exact Go release every such build runs under
#   toolchain_problems   the go on PATH, under GOTOOLCHAIN=local, is that release
#   buildinfo_problems   the build info Go records in the binary names the pinned
#                        toolchain, main package, module version, no replace,
#                        the pinned build settings, and (kine, zot) the raised
#                        golang.org/x/net at XNET_FLOOR or newer
#   buildinfo_settings   the `build` lines, as one line, for a record
#   marker_problems      the version marker beside a binary names its pin
#
# The caller sets `set -euo pipefail`; nothing here changes shell options.

# The Go toolchain the source-built children are built with. `k3sm payload` and
# the image recipes run those builds with GOTOOLCHAIN=local, so the go on PATH is
# the compiler; each caller refuses any other version before it builds anything.
# Bump it deliberately, with the Go toolchain the repos move to.
# shellcheck disable=SC2034 # read by the sourcing script
PAYLOAD_GO_VERSION="go1.27.3"

# The go command the toolchain assert asks. Overridable for the self-tests only.
GO="${GO:-go}"

# toolchain_problems <pin>: non-zero, naming the problem, unless `go env GOVERSION`
# under GOTOOLCHAIN=local (the setting the pinned builds run under) is <pin>.
toolchain_problems() {
	local want="$1" got
	got="$(GOTOOLCHAIN=local "$GO" env GOVERSION 2>/dev/null)" || { echo "no usable go toolchain on PATH (the pinned builds pin $want)"; return 1; }
	[ "$got" = "$want" ] || { echo "the go on PATH is $got; k3sm's out-of-module builds pin $want (PAYLOAD_GO_VERSION): put $want first on PATH"; return 1; }
}

# XNET_FLOOR is the lowest golang.org/x/net a staged kine or zot may link: the
# version both are built against (internal/childreq XNetVersion). The caller sets
# it from that source after sourcing this file; an unset floor is itself a
# problem for kine and zot. It starts empty, never from the environment, so an
# ambient XNET_FLOOR cannot lower the floor a caller forgot to set.
XNET_FLOOR=""

# release_less <a> <b>: true when release version a ("vX.Y.Z") sorts below b. A
# version of any other shape (a pseudo-version, a prerelease) never compares as
# at-or-above a floor, so it is reported rather than passed.
release_less() {
	awk -v a="$1" -v b="$2" 'BEGIN {
		if (a !~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ || b !~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) exit 0
		split(substr(a, 2), x, "."); split(substr(b, 2), y, ".")
		for (i = 1; i <= 3; i++) { if (x[i] + 0 < y[i] + 0) exit 0; if (x[i] + 0 > y[i] + 0) exit 1 }
		exit 1
	}'
}

# buildinfo_problems <kind> <want-version> <go-pin>  (stdin: `go version -m` text)
# The build stamp of one out-of-module binary, from the build info Go records in
# it (read, never executed): the toolchain, the main package, the pinned module
# version (etcd: the server module; etcdutl, zot and metrics-server: their own;
# kine: built from patched source, so its version is the marker's and the
# stamped string's), no replaced module, the build settings: CGO_ENABLED=0,
# darwin/arm64 and -trimpath, and for kine and zot the raised golang.org/x/net,
# at XNET_FLOOR or newer. Prints one line per problem; returns 0 only when there
# are none.
buildinfo_problems() {
	local kind="$1" want="$2" pin="$3" text path mod gov xnet bad=0
	text="$(cat)"
	case "$kind" in
	kine) path="github.com/k3s-io/kine"; mod="" ;;
	etcd) path="k3sm.io/etcd-child"; mod="go.etcd.io/etcd/server/v3" ;;
	etcdutl) path="go.etcd.io/etcd/etcdutl/v3"; mod="go.etcd.io/etcd/etcdutl/v3" ;;
	zot) path="zotregistry.dev/zot/v2/cmd/zot"; mod="zotregistry.dev/zot/v2" ;;
	metrics-server) path="sigs.k8s.io/metrics-server/cmd/metrics-server"; mod="sigs.k8s.io/metrics-server" ;;
	*) echo "unknown child $kind"; return 1 ;;
	esac
	local settings="CGO_ENABLED=0 -trimpath=true GOOS=darwin GOARCH=arm64"
	problem() { echo "$kind: $*"; bad=1; }
	gov="$(printf '%s\n' "$text" | sed -n '1s/^.*: \(go[0-9][^[:space:]]*\)$/\1/p')"
	[ "$gov" = "$pin" ] || problem "built with '${gov:-?}', the payload pins $pin"
	grep -qx "[[:space:]]*path[[:space:]]$path" <<<"$text" || problem "main package is not $path"
	if [ -n "$mod" ]; then
		grep -Eq "^[[:space:]]*(mod|dep)[[:space:]]${mod}[[:space:]]${want}([[:space:]]|\$)" <<<"$text" || problem "module $mod is not at $want"
	fi
	# Every child, kine included (it names no module version to check).
	grep -Eq "^[[:space:]]*=>" <<<"$text" && problem "a module is replaced"
	case "$kind" in
	kine | zot)
		xnet="$(awk '$1 == "dep" && $2 == "golang.org/x/net" { print $3; exit }' <<<"$text")"
		if [ -z "$XNET_FLOOR" ]; then
			problem "no golang.org/x/net floor is set (XNET_FLOOR)"
		elif [ -z "$xnet" ]; then
			problem "golang.org/x/net is not in the build info (want $XNET_FLOOR or newer)"
		elif release_less "$xnet" "$XNET_FLOOR"; then
			problem "golang.org/x/net is $xnet, below the raised $XNET_FLOOR"
		fi
		;;
	esac
	local setting
	for setting in $settings; do
		grep -qx "[[:space:]]*build[[:space:]]$setting" <<<"$text" || problem "build setting $setting is missing"
	done
	unset -f problem
	return "$bad"
}

# buildinfo_settings: the `build` lines of `go version -m` text on stdin, as one
# space-separated line (the manifest's record of how a child was built).
buildinfo_settings() {
	sed -n 's/^[[:space:]]*build[[:space:]]\(.*\)$/\1/p' | tr '\n' ' ' | sed 's/ $//'
}

# marker_problems <dir> <kind> <want-version> <variant>: the version marker
# <dir>/<kind>.version, written beside the binary by the build that produced it,
# reads exactly "<want-version> <variant>". A marker naming another pin means the
# binary beside it is not the pinned build, whatever its name says. Prints the
# problem; returns 0 only when the marker matches.
marker_problems() {
	local dir="$1" kind="$2" want="$3" variant="$4"
	[ "$(cat "$dir/$kind.version" 2>/dev/null)" = "$want $variant" ] ||
		{ echo "$kind: marker $kind.version is not '$want $variant'"; return 1; }
}
