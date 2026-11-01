#!/usr/bin/env bash
#
# metrics-server: build k3sm's native darwin/arm64 metrics-server image.
#
# The embedded add-on (pkg/addons/manifests/metrics-server.yaml) runs upstream
# metrics-server as a native pod. Upstream publishes Linux images only, so this
# recipe builds the binary from the pinned upstream module and packages it with
# `k3sm build`: FROM scratch, one COPY, the ENTRYPOINT. Nothing enters any k3sm
# go.mod; the module is built out of module, the way `k3sm payload` builds kine
# and etcd, and with the same checks (hack/release/lib/gochild.sh):
#
#   source      `go mod download -json` of the pinned version in a clean env -i
#               (private GOPATH, GOMODCACHE and GOCACHE, GOTOOLCHAIN=local,
#               GOENV=off; GOPROXY and GOSUMDB at their defaults). The reported
#               Sum must equal MS_H1: the module zip is the digest-pinned source.
#   toolchain   the go on PATH is PAYLOAD_GO_VERSION.
#   graph       go.mod and go.sum beside this script: upstream's module graph
#               with golang.org/x/net at MS_XNET (an HTTP/2 server fix upstream
#               has not released) and the MS_FIXES security fixes, so the build
#               is upstream's source over a reviewed graph. It must require the
#               pinned module and each fix, and its go.sum must hold MS_H1 for
#               the pinned module.
#   build       `go build -mod=readonly` of the upstream main package from that
#               graph: CGO_ENABLED=0 darwin/arm64 -trimpath, upstream's ldflags
#               (-w and the client-go version stamps), buildDate from MS_EPOCH,
#               never the wall clock.
#   build info  `go version -m` passes buildinfo_problems and equals the
#               committed buildinfo.lock; a differing rebuild is refused.
#   modules     every module in buildinfo.lock passes the 14-day cooldown and
#               the OSV malicious-package check (hack/verify-deps.sh --modules),
#               and govulncheck -mode=binary (the pin hack/ci.sh carries) runs on
#               the binary: a finding not accepted, by id, module and found
#               version and unexpired, in govulncheck.accepted is refused. A
#               network failure is a failure, never a skip.
#   image       `k3sm build --format oci` of a COPY-only Dockerfile, darwin/arm64
#               only, unsigned in the image (runtimed signs at pre-exec).
#
# Usage:
#   hack/images/metrics-server/build.sh --work <dir>          build and verify
#   hack/images/metrics-server/build.sh --work <dir> --update-lock
#                                    rewrite buildinfo.lock from this build
#   hack/images/metrics-server/build.sh --work <dir> --regen-graph
#                                    regenerate go.mod and go.sum (the pinned
#                                    module, then golang.org/x/net at MS_XNET,
#                                    then the MS_FIXES security fixes);
#                                    review the diff as a dependency change
#   hack/images/metrics-server/build.sh --work <dir> --tag <ref>
#                                    name the built image <ref> instead of the
#                                    default ghcr.io/k3sm-io/metrics-server:<version>
#   hack/images/metrics-server/build.sh --live                anonymous resolve
#                                    of image.yaml's ref in the registry
#   hack/images/metrics-server/build.sh --print-dockerfile
#   hack/images/metrics-server/build.sh --print-ldflags
#   hack/images/metrics-server/build.sh --check-pins
#   hack/images/metrics-server/build.sh --check-download <go-mod-download.json>
#   hack/images/metrics-server/build.sh --check-graph [<dir>]
#   hack/images/metrics-server/build.sh --check-vulns <exit> <govulncheck output>
#
# Requires macOS on Apple silicon, the pinned go, python3, curl, govulncheck at
# the pin, and a `k3sm` binary (K3SM_BIN or on PATH). It writes only under
# --work and pushes nothing; the operator publishes (README.md).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=hack/release/lib/gochild.sh
. "$REPO_ROOT/hack/release/lib/gochild.sh"

# ---- pins ---------------------------------------------------------------------
# The upstream release, pinned four ways: the version, the tag commit the module
# proxy records for it, the checksum database hash of its module zip, and the
# tag commit's time (the reproducible buildDate). MS_VERSION equals the version
# the manifest header vendors; selftest.sh asserts it.
MS_MODULE="sigs.k8s.io/metrics-server"
MS_PACKAGE="$MS_MODULE/cmd/metrics-server"
MS_VERSION="v0.9.0"
MS_COMMIT="df0ca06314dd3b367974d01bf3f9f6f3921256bf"
MS_H1="h1:nlqqZ2H0Xfko8eJC/1qaNVVT17hu4rxndkOi22KTZ4w="
MS_EPOCH="2026-07-13T09:28:19Z"
# The x/net the graph moves to: upstream v0.9.0 links v0.56.0, which carries
# HTTP/2 server advisories reachable on the serving port.
MS_XNET="v0.60.0"
# The security fixes the graph also takes, each at the lowest version that fixes
# every advisory open against upstream v0.9.0's own version: grpc for
# GHSA-hrxh-6v49-42gf, GHSA-2v4p-qf9q-27wj, GHSA-vp52-pcj8-j9qc and
# GHSA-qc2q-p7wx-3px3; cel-go for GHSA-gcjh-h69q-9w9g (GO-2026-6094, fixed only
# in v0.30.0; v0.29.x is still affected); otel/sdk and the two
# otlptrace exporters for GHSA-8wmf-6v46-5gfg. Minimal version selection moves
# otel, otel/metric, otel/trace, otlp proto, go-logr/logr and genproto with them.
MS_FIXES="google.golang.org/grpc@v1.83.2 github.com/google/cel-go@v0.30.0 go.opentelemetry.io/otel/sdk@v1.45.0 go.opentelemetry.io/otel/exporters/otlp/otlptrace@v1.45.0 go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.45.0"
# The version marker's variant: a pure-Go build over the patched graph.
MS_VARIANT="nocgo+xnet-$MS_XNET"
# The tag the operator pushes; consumers pin the digest image.yaml records.
DEFAULT_TAG="ghcr.io/k3sm-io/metrics-server:$MS_VERSION"

die() { echo "metrics-server: $*" >&2; exit 2; }

# pins_problems: every pin has its real shape. A placeholder or an empty pin is
# refused here, before anything touches the network.
pins_problems() {
	local bad=0
	grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+' <<<"$MS_VERSION" || { echo "MS_VERSION '$MS_VERSION' is not an exact vX.Y.Z"; bad=1; }
	grep -Eqx '[0-9a-f]{40}' <<<"$MS_COMMIT" || { echo "MS_COMMIT '$MS_COMMIT' is not a 40-hex commit"; bad=1; }
	grep -Eqx 'h1:[A-Za-z0-9+/]{43}=' <<<"$MS_H1" || { echo "MS_H1 '$MS_H1' is not an h1: checksum database hash"; bad=1; }
	grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' <<<"$MS_EPOCH" || { echo "MS_EPOCH '$MS_EPOCH' is not an RFC 3339 UTC time"; bad=1; }
	return "$bad"
}

# ldflags: upstream's (Makefile LDFLAGS), with every stamp taken from a pin.
ldflags() {
	local pkg="k8s.io/client-go/pkg/version"
	printf '%s\n' "-w -X $pkg.gitVersion=$MS_VERSION -X $pkg.gitCommit=$MS_COMMIT -X $pkg.buildDate=$MS_EPOCH"
}

# The Dockerfile: COPY-only by construction, written outside the build context.
print_dockerfile() {
	cat <<EOF
# Generated by hack/images/metrics-server/build.sh; do not edit by hand.
FROM scratch
COPY metrics-server /metrics-server
ENTRYPOINT ["/metrics-server"]
EOF
}

# download_problems <go-mod-download.json>: the module the go command fetched is
# the pinned one: the version, the checksum database hash and, when the proxy
# reports one, the tag commit.
download_problems() {
	python3 -I - "$1" "$MS_MODULE" "$MS_VERSION" "$MS_H1" "$MS_COMMIT" <<'PY'
import json, sys
path, mod, ver, h1, commit = sys.argv[1:]
try:
    with open(path) as f:
        d = json.load(f)
except (OSError, ValueError) as e:
    print("unreadable go mod download output %s: %s" % (path, e)); sys.exit(1)
bad = []
if d.get("Error"):
    bad.append("the download failed: %s" % d["Error"])
if d.get("Path") != mod or d.get("Version") != ver:
    bad.append("downloaded %s@%s, the pin is %s@%s" % (d.get("Path"), d.get("Version"), mod, ver))
if d.get("Sum") != h1:
    bad.append("the module zip's Sum is %r, the pin is %s: refusing a source that is not the pinned one" % (d.get("Sum"), h1))
got = (d.get("Origin") or {}).get("Hash")
if got and got != commit:
    bad.append("the proxy maps %s to commit %s, the pin is %s" % (ver, got, commit))
for b in bad:
    print(b)
sys.exit(1 if bad else 0)
PY
}

# go_mod_requires <go.mod> <module> <version>: the go.mod requires <module> at
# <version>, in a require block or a one-line require. The path and version are
# compared as literal fields, never as a pattern, and exclude and retract
# directives do not count.
go_mod_requires() {
	awk -v mod="$2" -v ver="$3" '
		{ sub(/\/\/.*/, "") }
		inreq && $1 == ")" { inreq = 0; next }
		inreq && $1 == mod && $2 == ver { found = 1 }
		!inreq && $1 == "require" && $2 == "(" { inreq = 1; next }
		!inreq && $1 == "require" && $2 == mod && $3 == ver { found = 1 }
		END { exit found ? 0 : 1 }
	' "$1"
}

# graph_problems <dir>: go.mod and go.sum in <dir> are a graph this recipe may
# build: they require the pinned module at MS_VERSION, x/net at MS_XNET and
# every MS_FIXES module at its version, carry no replace, and go.sum holds MS_H1
# for the pinned module's zip.
graph_problems() {
	local dir="$1" bad=0 fix
	go_mod_requires "$dir/go.mod" "$MS_MODULE" "$MS_VERSION" || { echo "go.mod does not require $MS_MODULE $MS_VERSION"; bad=1; }
	go_mod_requires "$dir/go.mod" golang.org/x/net "$MS_XNET" || { echo "go.mod does not require golang.org/x/net $MS_XNET"; bad=1; }
	for fix in $MS_FIXES; do
		go_mod_requires "$dir/go.mod" "${fix%@*}" "${fix#*@}" || { echo "go.mod does not require ${fix%@*} ${fix#*@}"; bad=1; }
	done
	grep -Eq '^[[:space:]]*replace([[:space:]]|\()' "$dir/go.mod" && { echo "go.mod carries a replace"; bad=1; }
	grep -qxF "$MS_MODULE $MS_VERSION $MS_H1" "$dir/go.sum" || { echo "go.sum does not hold $MS_H1 for $MS_MODULE $MS_VERSION"; bad=1; }
	return "$bad"
}

# buildinfo_normalized <binary>: `go version -m` with the binary's own path
# replaced by its name, so the text is comparable across work dirs.
buildinfo_normalized() {
	"$GO" version -m "$1" | sed "1s#^.*: #metrics-server: #"
}

# modules_list <buildinfo text file>: "<module> <version>" for the main module
# and every dependency the binary links.
modules_list() {
	awk '$1 == "mod" || $1 == "dep" { print $2, $3 }' "$1"
}

# govulncheck_pinned: the govulncheck hack/ci.sh pins, or a refusal.
govulncheck_pinned() {
	local want c ver
	want="$(sed -n 's/^GOVULNCHECK_VERSION=\([^[:space:]]*\).*/\1/p' "$REPO_ROOT/hack/ci.sh")"
	[ -n "$want" ] || die "cannot read GOVULNCHECK_VERSION from hack/ci.sh"
	for c in "$(command -v govulncheck 2>/dev/null || true)" "$("$GO" env GOPATH)/bin/govulncheck"; do
		[ -n "$c" ] && [ -x "$c" ] || continue
		ver="$("$c" -version 2>/dev/null | sed -n 's/^Scanner: govulncheck@//p' | sed -n 1p)" || ver=""
		[ "$ver" = "$want" ] && { echo "$c"; return 0; }
	done
	die "govulncheck $want is required (go install golang.org/x/vuln/cmd/govulncheck@$want)"
}

# vuln_problems <govulncheck exit> <govulncheck text> <accepted list>: exit 0 is
# clean and exit 3 is findings; anything else (a network failure, a bad binary)
# is a failure, never a skip. Every finding, read as (id, module, found version)
# from each "Found in:" line, must match a line of the accepted list on all three,
# and that line must not have expired: its until= date has not passed (today is
# VULN_TODAY when set, for the self-test) and its pin= is still MS_VERSION. Prints
# the problems and returns 1, or prints notes for accepted lines that matched
# nothing and returns 0.
vuln_problems() {
	python3 -I - "$1" "$2" "$3" "$MS_VERSION" "${VULN_TODAY:-}" <<'PY'
import datetime, os, re, sys
rc, text, accepted, pin, today = sys.argv[1:]
name = os.path.basename(accepted)
if rc not in ("0", "3"):
    print("govulncheck failed (exit %s), so the binary was not checked" % rc); sys.exit(1)
today = datetime.date.fromisoformat(today) if today else datetime.datetime.now(datetime.timezone.utc).date()
found, vid = [], None
for line in open(text):
    m = re.match(r"^Vulnerability #\d+: (GO-\d+-\d+)", line)
    if m:
        vid = m.group(1); continue
    m = re.match(r"^\s+Found in: (\S+)@(\S+)$", line)
    if m and vid:
        found.append((vid, m.group(1), m.group(2)))
found = sorted(set(found))
if rc == "3" and not found:
    print("govulncheck reported findings this script could not read"); sys.exit(1)
entries = {}
for n, raw in enumerate(open(accepted), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    t = line.split(None, 6)
    if len(t) < 7 or not t[4].startswith("until=") or not t[5].startswith("pin="):
        print("%s:%d: want '<id> <module> <found> <fixed> until=<date> pin=<version> <reason>'" % (name, n)); sys.exit(1)
    try:
        until = datetime.date.fromisoformat(t[4][len("until="):])
    except ValueError:
        print("%s:%d: until= is not a YYYY-MM-DD date" % (name, n)); sys.exit(1)
    entries[(t[0], t[1], t[2])] = (n, until, t[5][len("pin="):])
bad, used = [], set()
for f in found:
    e = entries.get(f)
    if e is None:
        bad.append("finding %s in %s@%s is not accepted in %s (id, module and found version must all match): fix it or record it there with a reason" % (f[0], f[1], f[2], name))
        continue
    n, until, epin = e
    used.add(f)
    if today > until:
        bad.append("%s:%d: the acceptance of %s in %s@%s expired on %s" % (name, n, f[0], f[1], f[2], until))
    elif epin != pin:
        bad.append("%s:%d: the acceptance of %s in %s@%s was for metrics-server %s, the pin is now %s" % (name, n, f[0], f[1], f[2], epin, pin))
for b in bad:
    print(b)
if bad:
    sys.exit(1)
for k in sorted(set(entries) - used):
    print("  note: %s:%d (%s %s %s) matches no finding; delete it" % (name, entries[k][0], k[0], k[1], k[2]))
print("  %d findings, every one accepted in %s" % (len(found), name))
PY
}

# image_digests <oci layout>: the darwin/arm64 manifest digest and the image
# index digest ("" when the layout holds one single-platform manifest, which is
# what `k3sm build` writes for one platform and `k3sm image push` publishes).
image_digests() {
	python3 -I - "$1" <<'PY'
import json, os, sys
root = sys.argv[1]
def blob(d):
    algo, hexd = d.split(":", 1)
    with open(os.path.join(root, "blobs", algo, hexd)) as f:
        return json.load(f)
idx = json.load(open(os.path.join(root, "index.json")))
ms = idx.get("manifests") or []
if len(ms) != 1:
    sys.exit("the layout holds %d manifests, want one" % len(ms))
top = ms[0]
index = ""
man = top
if top.get("mediaType", "").endswith("image.index.v1+json") or top.get("mediaType", "").endswith("manifest.list.v2+json"):
    index = top["digest"]
    inner = blob(top["digest"]).get("manifests") or []
    if len(inner) != 1:
        sys.exit("the index lists %d manifests, want darwin/arm64 only" % len(inner))
    man = inner[0]
cfg = blob(blob(man["digest"])["config"]["digest"])
plat = "%s/%s" % (cfg.get("os"), cfg.get("architecture"))
if plat != "darwin/arm64":
    sys.exit("the image is %s, want darwin/arm64" % plat)
print(man["digest"], index)
PY
}

# live: resolve image.yaml's ref anonymously in the registry (no credential at
# all), the proof that the record names a published, public artifact.
live() {
	local ref repo digest host name token code
	ref="$(sed -n 's/^[[:space:]]*ref:[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$HERE/image.yaml" | sed -n 1p)"
	repo="${ref%@*}"; digest="${ref#*@}"
	host="${repo%%/*}"; name="${repo#*/}"
	[ "$host" = ghcr.io ] || die "--live resolves ghcr.io refs only (image.yaml names $host)"
	token="$(curl -fsS --max-time 30 "https://ghcr.io/token?scope=repository:$name:pull" |
		python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])')" ||
		die "--live: could not obtain an anonymous pull token for $name (network, or the package is not public)"
	code="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -I \
		-H "Authorization: Bearer $token" \
		-H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json' \
		"https://ghcr.io/v2/$name/manifests/$digest")" || die "--live: network failure resolving $ref"
	[ "$code" = 200 ] || die "--live: $ref answered HTTP $code to an anonymous resolve (want 200: published and public)"
	echo "live: $ref resolves anonymously"
}

# ---- main -------------------------------------------------------------------
WORK=""
UPDATE_LOCK=0
REGEN=0
TAG="$DEFAULT_TAG"
K3SM_BIN="${K3SM_BIN:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	--work) WORK="${2:-}"; [ -n "$WORK" ] || die "--work needs a value"; shift 2 ;;
	--update-lock) UPDATE_LOCK=1; shift ;;
	--regen-graph) REGEN=1; shift ;;
	--tag) TAG="${2:-}"; [ -n "$TAG" ] || die "--tag needs a value"; shift 2 ;;
	--live) live; exit 0 ;;
	--print-dockerfile) print_dockerfile; exit 0 ;;
	--print-ldflags) ldflags; exit 0 ;;
	--check-pins) pins_problems; exit $? ;;
	--check-download) download_problems "${2:?--check-download needs a file}"; exit $? ;;
	--check-graph) graph_problems "${2:-$HERE}"; exit $? ;;
	--check-vulns) vuln_problems "${2:?--check-vulns needs an exit code}" "${3:?--check-vulns needs a govulncheck text file}" "$HERE/govulncheck.accepted"; exit $? ;;
	-h | --help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
	*) die "unknown flag: $1 (try --help)" ;;
	esac
done

echo "==> pins"
p="$(pins_problems)" || die "$p"
[ -n "$WORK" ] || die "--work <dir> is required (a scratch directory outside any repo)"

echo "==> preflight"
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || die "build on an Apple silicon Mac from a native arm64 shell (uname: $(uname -s) $(uname -m))"
p="$(toolchain_problems "$PAYLOAD_GO_VERSION")" || die "$p"
[ -n "$K3SM_BIN" ] || K3SM_BIN="$(command -v k3sm 2>/dev/null || true)"
[ -n "$K3SM_BIN" ] && [ -x "$K3SM_BIN" ] || die "no k3sm binary: build one (CGO_ENABLED=1 go build -o <dir>/k3sm ./cmd/k3sm) and pass it as K3SM_BIN"
GV="$(govulncheck_pinned)"
GOBIN_PATH="$(dirname "$(command -v "$GO")")"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
case "$WORK/" in "$REPO_ROOT/"*) die "--work must be outside the repo tree" ;; esac

# The clean build environment: nothing from the caller's go env reaches it.
goenv() {
	env -i HOME="$WORK" PATH="$GOBIN_PATH:/usr/bin:/bin" \
		GOPATH="$WORK/gopath" GOMODCACHE="$WORK/modcache" GOCACHE="$WORK/gocache" \
		GOTOOLCHAIN=local GOENV=off CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 "$@"
}

echo "==> source: $MS_MODULE@$MS_VERSION"
goenv "$GO" mod download -json "$MS_MODULE@$MS_VERSION" >"$WORK/download.json" ||
	die "go mod download failed (see $WORK/download.json)"
p="$(download_problems "$WORK/download.json")" || die "$p"
echo "  Sum $MS_H1, commit $MS_COMMIT"

echo "==> graph: $MS_MODULE $MS_VERSION with golang.org/x/net $MS_XNET and $MS_FIXES"
rm -rf "${WORK:?}/graph"
mkdir -p "$WORK/graph"
if [ "$REGEN" = 1 ]; then
	(cd "$WORK/graph" &&
		goenv "$GO" mod init k3sm.io/metrics-server-image &&
		goenv "$GO" get "$MS_PACKAGE@$MS_VERSION" &&
		goenv "$GO" get "golang.org/x/net@$MS_XNET" &&
		# shellcheck disable=SC2086 # MS_FIXES is a space-separated list
		goenv "$GO" get $MS_FIXES) || die "could not regenerate the graph"
	{ sed -n '/^\/\//p' "$HERE/go.mod"; cat "$WORK/graph/go.mod"; } >"$WORK/graph/go.mod.new"
	mv "$WORK/graph/go.mod.new" "$WORK/graph/go.mod"
	cp "$WORK/graph/go.mod" "$WORK/graph/go.sum" "$HERE/"
	echo "  wrote go.mod and go.sum; review the diff as a dependency change"
else
	cp "$HERE/go.mod" "$HERE/go.sum" "$WORK/graph/"
fi
p="$(graph_problems "$WORK/graph")" || die "$p"

echo "==> build (CGO_ENABLED=0 darwin/arm64 -trimpath -mod=readonly, $PAYLOAD_GO_VERSION)"
rm -rf "${WORK:?}/bin"
mkdir -p "$WORK/bin"
BIN="$WORK/bin/metrics-server"
(cd "$WORK/graph" && goenv "$GO" build -mod=readonly -trimpath -ldflags "$(ldflags)" -o "$BIN" "$MS_PACKAGE")
printf '%s %s\n' "$MS_VERSION" "$MS_VARIANT" >"$WORK/bin/metrics-server.version"

echo "==> build info"
buildinfo_normalized "$BIN" >"$WORK/buildinfo.txt"
p="$(buildinfo_problems metrics-server "$MS_VERSION" "$PAYLOAD_GO_VERSION" <"$WORK/buildinfo.txt")" || die "$p"
p="$(marker_problems "$WORK/bin" metrics-server "$MS_VERSION" "$MS_VARIANT")" || die "$p"
if ! grep -aqF -- "$MS_COMMIT" "$BIN" || ! grep -aqF -- "$MS_EPOCH" "$BIN"; then
	die "the binary does not carry the pinned commit and build date stamps"
fi
if [ "$UPDATE_LOCK" = 1 ]; then
	cp "$WORK/buildinfo.txt" "$HERE/buildinfo.lock"
	echo "  wrote buildinfo.lock; review the diff and commit it"
elif ! diff -u "$HERE/buildinfo.lock" "$WORK/buildinfo.txt"; then
	die "this build's go version -m differs from buildinfo.lock (above): a different toolchain, module graph or build setting"
fi

echo "==> modules: cooldown and malicious-package check"
modules_list "$HERE/buildinfo.lock" >"$WORK/modules.txt"
"$REPO_ROOT/hack/verify-deps.sh" --modules "$WORK/modules.txt"

echo "==> govulncheck -mode=binary ($GV)"
rc=0
"$GV" -mode=binary "$BIN" >"$WORK/govulncheck.txt" 2>&1 || rc=$?
p="$(vuln_problems "$rc" "$WORK/govulncheck.txt" "$HERE/govulncheck.accepted")" || { cat "$WORK/govulncheck.txt" >&2; die "$p"; }
[ -z "$p" ] || printf '%s\n' "$p"

echo "==> package (k3sm build --format oci)"
rm -rf "${WORK:?}/stage" "${WORK:?}/oci"
mkdir -p "$WORK/stage"
cp "$BIN" "$WORK/stage/metrics-server"
print_dockerfile >"$WORK/Dockerfile"
"$K3SM_BIN" build --file "$WORK/Dockerfile" --tag "$TAG" --format oci --output "$WORK/oci" "$WORK/stage"
read -r ARM64 INDEX <<<"$(image_digests "$WORK/oci")"
BIN_SHA="$(shasum -a 256 "$BIN" | awk '{print $1}')"
REPO="${TAG%:*}"
PIN="${INDEX:-$ARM64}"
cat >"$WORK/digests.txt" <<EOF
binary-sha256 $BIN_SHA
darwin/arm64 $ARM64
index ${INDEX:-none}
ref $REPO@$PIN
EOF

cat <<EOF

==> built
  binary sha256:  $BIN_SHA
  darwin/arm64:   $ARM64
  index:          ${INDEX:-none (one single-platform manifest)}
  ref:            $REPO@$PIN
  layout:         $WORK/oci

Publish it (the credential is read from the environment, never from argv):

  K3SM_REGISTRY_TOKEN=<token> k3sm image push $WORK/oci $TAG

then make the package public, re-derive the digest from the published
artifact, record it in image.yaml, and run '$0 --live'. See README.md.
EOF
