#!/usr/bin/env bash
#
# selftest.sh: the hermetic checks on the metrics-server image recipe. No
# network, no build, no credentials: it reads the recipe, its records and
# fixtures it writes to a temp dir. hack/ci.sh runs it.
#
#   - the pins are real (no placeholder) and agree with the manifest header,
#     image.yaml and buildinfo.lock
#   - a placeholder pin is refused before any go or curl runs
#   - the Dockerfile is COPY-only, FROM scratch
#   - a module download whose Sum, version or commit is not the pin is refused
#   - the ldflags carry the pinned build date, and the recipe reads no clock
#   - the committed build info passes the shared buildinfo_problems check
#   - a govulncheck finding not accepted by id, module and found version, an
#     expired or other-release acceptance, or a failed run, is refused
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build.sh"
MANIFEST="$REPO_ROOT/pkg/addons/manifests/metrics-server.yaml"
RECORD="$HERE/image.yaml"
LOCK="$HERE/buildinfo.lock"

fails=0
ok() { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; fails=$((fails + 1)); }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/ms-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

pin() { sed -n "s/^$1=\"\\([^\"]*\\)\".*/\\1/p" "$BUILD"; }
record() { sed -n "s/^[[:space:]]*$1:[[:space:]]*\\([^[:space:]#]*\\).*/\\1/p" "$RECORD" | sed -n 1p; }
MS_VERSION="$(pin MS_VERSION)"
MS_COMMIT="$(pin MS_COMMIT)"
MS_H1="$(pin MS_H1)"
MS_EPOCH="$(pin MS_EPOCH)"

echo "==> pins"
if "$BUILD" --check-pins >/dev/null; then ok "every pin has its real shape"; else bad "build.sh --check-pins: $("$BUILD" --check-pins)"; fi
header="$(sed -n 's/^# Vendored from upstream metrics-server \(v[0-9.]*\):$/\1/p' "$MANIFEST")"
if [ -n "$MS_VERSION" ] && [ "$MS_VERSION" = "$header" ]; then ok "MS_VERSION $MS_VERSION equals the manifest header's"; else bad "MS_VERSION '$MS_VERSION', manifest header '$header'"; fi
if [ "$(record version)" = "$MS_VERSION" ] && [ "$(record commit)" = "$MS_COMMIT" ] && [ "$(record sum)" = "$MS_H1" ]; then
	ok "image.yaml's source is the pinned version, commit and Sum"
else
	bad "image.yaml source $(record version) $(record commit) $(record sum) is not the pin"
fi
if [ "$(record tag)" = "ghcr.io/k3sm-io/metrics-server:$MS_VERSION" ]; then ok "image.yaml's tag names the pinned version"; else bad "image.yaml tag '$(record tag)'"; fi
if grep -qxF "	mod	sigs.k8s.io/metrics-server	${MS_VERSION}	${MS_H1}" "$LOCK"; then
	ok "buildinfo.lock records the pinned module and Sum"
else
	bad "buildinfo.lock does not record sigs.k8s.io/metrics-server $MS_VERSION $MS_H1"
fi

echo "==> the committed module graph"
if "$BUILD" --check-graph >/dev/null; then ok "go.mod and go.sum require the pinned module, x/net and the security fixes, with the pinned Sum"; else bad "build.sh --check-graph: $("$BUILD" --check-graph)"; fi
MS_XNET="$(pin MS_XNET)"
if grep -qxF "	dep	golang.org/x/net	${MS_XNET}	$(awk -v v="$MS_XNET" '$1 == "golang.org/x/net" && $2 == v { print $3 }' "$HERE/go.sum")" "$LOCK"; then
	ok "buildinfo.lock links golang.org/x/net $MS_XNET"
else
	bad "buildinfo.lock does not link golang.org/x/net $MS_XNET"
fi
mkdir -p "$tmp/graph"
for f in go.mod go.sum; do cp "$HERE/$f" "$tmp/graph/"; done
sed -i.bak "s/^\(sigs.k8s.io\/metrics-server $MS_VERSION \)h1:.*/\1h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=/" "$tmp/graph/go.sum"
if "$BUILD" --check-graph "$tmp/graph" >/dev/null; then bad "a go.sum with another Sum passed"; else ok "a go.sum with another Sum for the pinned module is refused"; fi
MS_FIXES="$(pin MS_FIXES)"
[ -n "$MS_FIXES" ] || bad "build.sh pins no MS_FIXES"
# Each fix in turn: downgraded in the require block; present only as a literal
# lookalike path (each dot a different byte, which a regex dot would match); and
# present at its version only inside an exclude block. Every one is refused,
# naming the module.
for fix in $MS_FIXES; do
	fmod="${fix%@*}" fver="${fix#*@}"
	look="$(printf '%s' "$fmod" | tr . X)"
	for variant in downgraded lookalike exclude-only; do
		cp "$HERE/go.mod" "$HERE/go.sum" "$tmp/graph/"
		awk -v mod="$fmod" -v ver="$fver" -v look="$look" -v how="$variant" '
			$1 == mod && $2 == ver {
				if (how == "downgraded") { sub(ver, "v0.0.0") }
				else if (how == "lookalike") { $1 = "\t" look; sub(/^ /, "") }
				else { next }
			}
			{ print }
			END { if (how == "exclude-only") printf "exclude (\n\t%s %s\n)\n", mod, ver }
		' "$HERE/go.mod" >"$tmp/graph/go.mod"
		if out="$("$BUILD" --check-graph "$tmp/graph")"; then
			bad "a go.mod with $fmod $variant passed"
		elif grep -qF "require $fmod $fver" <<<"$out"; then
			ok "a go.mod with $fmod $variant is refused, naming it"
		else
			bad "$fmod $variant not named: $out"
		fi
	done
done
cp "$HERE/go.mod" "$HERE/go.sum" "$tmp/graph/"
printf 'replace golang.org/x/net => example.com/net v0.0.1\n' >>"$tmp/graph/go.mod"
if "$BUILD" --check-graph "$tmp/graph" >/dev/null; then bad "a go.mod with a replace passed"; else ok "a go.mod with a replace is refused"; fi

echo "==> a placeholder pin refuses before any go or curl runs"
mkdir -p "$tmp/tree/hack/images/metrics-server" "$tmp/tree/hack/release/lib" "$tmp/bin"
cp "$REPO_ROOT/hack/release/lib/gochild.sh" "$tmp/tree/hack/release/lib/"
sed 's/^MS_H1=".*"/MS_H1="@PLACEHOLDER@"/' "$BUILD" >"$tmp/tree/hack/images/metrics-server/build.sh"
chmod +x "$tmp/tree/hack/images/metrics-server/build.sh"
for tool in go curl k3sm govulncheck; do
	printf '#!/bin/sh\necho "%s $*" >>"%s/ran"\nexit 1\n' "$tool" "$tmp" >"$tmp/bin/$tool"
	chmod +x "$tmp/bin/$tool"
done
if out="$(PATH="$tmp/bin:/usr/bin:/bin" "$tmp/tree/hack/images/metrics-server/build.sh" --work "$tmp/w" 2>&1)"; then
	bad "a placeholder MS_H1 built"
elif grep -q "MS_H1 '@PLACEHOLDER@'" <<<"$out" && [ ! -e "$tmp/ran" ] && [ ! -e "$tmp/w" ]; then
	ok "a placeholder MS_H1 is refused, naming it, before any tool runs or anything is written"
else
	bad "placeholder not refused first: $out $(cat "$tmp/ran" 2>/dev/null)"
fi

echo "==> the Dockerfile is COPY-only"
df="$("$BUILD" --print-dockerfile)"
instr="$(printf '%s\n' "$df" | grep -Ev '^[[:space:]]*(#|$)' | awk '{print toupper($1)}' | sort -u | tr '\n' ' ')"
if [ "$instr" = "COPY ENTRYPOINT FROM " ] && grep -qx 'FROM scratch' <<<"$df"; then
	ok "FROM scratch, COPY and ENTRYPOINT only"
else
	bad "Dockerfile instructions: $instr"
fi

echo "==> the module download must be the pinned one"
good="$tmp/download.json"
cat >"$good" <<EOF
{"Path":"sigs.k8s.io/metrics-server","Version":"$MS_VERSION","Sum":"$MS_H1","Origin":{"VCS":"git","Hash":"$MS_COMMIT"}}
EOF
if "$BUILD" --check-download "$good" >/dev/null; then ok "the pinned download passes"; else bad "the pinned download was refused: $("$BUILD" --check-download "$good")"; fi
sed 's/"Sum":"[^"]*"/"Sum":"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="/' "$good" >"$tmp/badsum.json"
if out="$("$BUILD" --check-download "$tmp/badsum.json")"; then bad "a Sum mismatch passed"; elif grep -q "Sum" <<<"$out"; then ok "a Sum mismatch is refused, naming it"; else bad "Sum mismatch not named: $out"; fi
sed "s/\"Version\":\"$MS_VERSION\"/\"Version\":\"v0.0.1\"/" "$good" >"$tmp/badver.json"
if "$BUILD" --check-download "$tmp/badver.json" >/dev/null; then bad "another version passed"; else ok "another version is refused"; fi
sed "s/$MS_COMMIT/0000000000000000000000000000000000000000/" "$good" >"$tmp/badcommit.json"
if "$BUILD" --check-download "$tmp/badcommit.json" >/dev/null; then bad "another commit passed"; else ok "another tag commit is refused"; fi

echo "==> no wall clock in the build"
if grep -q -- "-X k8s.io/client-go/pkg/version.buildDate=$MS_EPOCH\$" <<<"$("$BUILD" --print-ldflags)"; then ok "buildDate is the pinned MS_EPOCH"; else bad "ldflags: $("$BUILD" --print-ldflags)"; fi
# A command substitution of date, or date at the start of a command.
if grep -Eq '\$\([[:space:]]*date|`[[:space:]]*date|(^|[;&|][[:space:]]*)date[[:space:]]' "$BUILD"; then bad "build.sh runs date"; else ok "build.sh never runs date"; fi

echo "==> the committed build info passes the shared check"
# shellcheck source=hack/release/lib/gochild.sh
. "$REPO_ROOT/hack/release/lib/gochild.sh"
if out="$(buildinfo_problems metrics-server "$MS_VERSION" "$PAYLOAD_GO_VERSION" <"$LOCK")"; then ok "buildinfo.lock passes buildinfo_problems at $PAYLOAD_GO_VERSION"; else bad "buildinfo.lock: $out"; fi
if out="$(sed "s/^\(	mod	sigs.k8s.io\/metrics-server	\)$MS_VERSION/\1v0.8.0/" "$LOCK" | buildinfo_problems metrics-server "$MS_VERSION" "$PAYLOAD_GO_VERSION")"; then bad "another module version passed"; else ok "another module version is refused"; fi
if out="$(sed 's/CGO_ENABLED=0/CGO_ENABLED=1/' "$LOCK" | buildinfo_problems metrics-server "$MS_VERSION" "$PAYLOAD_GO_VERSION")"; then bad "a cgo build passed"; else ok "a cgo build is refused"; fi
mkdir -p "$tmp/marker"
echo "$MS_VERSION nocgo" >"$tmp/marker/metrics-server.version"
if marker_problems "$tmp/marker" metrics-server "$MS_VERSION" nocgo >/dev/null; then ok "a marker naming the pin passes"; else bad "the pinned marker was refused"; fi
if marker_problems "$tmp/marker" metrics-server v0.8.0 nocgo >/dev/null; then bad "a marker naming another pin passed"; else ok "a marker naming another pin is refused"; fi

echo "==> govulncheck findings: matched by id, module and found version, never expired"
# The checks run on a copy of the recipe with a fixture acceptance, so they hold
# whether or not the committed list accepts anything.
mkdir -p "$tmp/vt/hack/images/metrics-server"
cp "$BUILD" "$tmp/vt/hack/images/metrics-server/build.sh"
cp -R "$tmp/tree/hack/release" "$tmp/vt/hack/"
vid=GO-2099-0002 vmod=example.com/accepted vver=v1.0.0
printf '%s %s %s v1.0.1 until=2026-11-14 pin=%s fixture acceptance for the self-test\n' "$vid" "$vmod" "$vver" "$MS_VERSION" >"$tmp/vt/hack/images/metrics-server/govulncheck.accepted"
if out="$(VULN_TODAY=2026-10-15 "$BUILD" --check-vulns 0 /dev/null)"; then ok "the committed govulncheck.accepted parses"; else bad "govulncheck.accepted: $out"; fi
finding() { printf 'Vulnerability #1: %s\n  Module: %s\n    Found in: %s@%s\n' "$1" "$2" "$2" "$3"; }
finding "$vid" "$vmod" "$vver" >"$tmp/vuln-known.txt"
{ finding "$vid" "$vmod" "$vver"; finding GO-2099-0001 example.com/new v1.0.0; } >"$tmp/vuln-new.txt"
finding "$vid" example.com/other "$vver" >"$tmp/vuln-module.txt"
finding "$vid" "$vmod" v99.0.0 >"$tmp/vuln-version.txt"
check() { VULN_TODAY="${VULN_TODAY:-2026-10-15}" bash "$tmp/vt/hack/images/metrics-server/build.sh" --check-vulns "$@"; }
if check 3 "$tmp/vuln-known.txt" >/dev/null; then ok "an accepted finding passes"; else bad "an accepted finding was refused: $(check 3 "$tmp/vuln-known.txt")"; fi
if out="$(check 3 "$tmp/vuln-new.txt")"; then bad "a new finding passed"; elif grep -q "GO-2099-0001" <<<"$out"; then ok "a new finding is refused, naming it"; else bad "new finding not named: $out"; fi
if check 3 "$tmp/vuln-module.txt" >/dev/null; then bad "an accepted id in another module passed"; else ok "an accepted id found in another module is refused"; fi
if check 3 "$tmp/vuln-version.txt" >/dev/null; then bad "an accepted id at another found version passed"; else ok "an accepted id at another found version is refused"; fi
if out="$(VULN_TODAY=2099-01-01 check 3 "$tmp/vuln-known.txt")"; then bad "an expired acceptance passed"; elif grep -q "expired" <<<"$out"; then ok "an expired acceptance is refused"; else bad "expiry not named: $out"; fi
mkdir -p "$tmp/pin/hack/images/metrics-server"
sed 's/^MS_VERSION=".*"/MS_VERSION="v9.9.9"/' "$BUILD" >"$tmp/pin/hack/images/metrics-server/build.sh"
cp "$tmp/vt/hack/images/metrics-server/govulncheck.accepted" "$tmp/pin/hack/images/metrics-server/"
cp -R "$tmp/tree/hack/release" "$tmp/pin/hack/"
if out="$(VULN_TODAY=2026-10-15 bash "$tmp/pin/hack/images/metrics-server/build.sh" --check-vulns 3 "$tmp/vuln-known.txt")"; then bad "an acceptance for another upstream release passed"; elif grep -q "was for metrics-server" <<<"$out"; then ok "an acceptance for another upstream release is refused"; else bad "pin mismatch not named: $out"; fi
if check 1 "$tmp/vuln-known.txt" >/dev/null; then bad "a failed govulncheck run passed"; else ok "a failed govulncheck run (a network error) is refused"; fi
if check 3 /dev/null >/dev/null; then bad "unreadable findings passed"; else ok "findings the script cannot read are refused"; fi

if [ "$fails" -eq 0 ]; then
	echo "metrics-server selftest: all passed"
else
	echo "metrics-server selftest: $fails failed"
	exit 1
fi
