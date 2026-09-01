#!/usr/bin/env bash
#
# stage.sh — assemble the complete set of artifacts a k3sm install needs.
#
# `k3sm install` resolves four classes of supporting artifact relative to the
# directory holding the running binary, and fail-fasts on each: the Seatbelt exec
# shim, two DYLD shims, and the control-plane payload. This script is the ONE
# producer of that tree. Both the release archive and the M2 acceptance gate
# consume it, so the thing that ships and the thing that is proven to install are
# assembled by the same recipe rather than by two copies that drift.
#
# The expected set is not hardcoded here: it comes from the binary's own
# contract, `k3sm install --print-required-artifacts` (pkg/install.RequiredSiblings),
# and staging fails if anything it names is missing at the end.
#
#   hack/release/stage.sh <out-dir> [--binary-name <name>] [--stub-payload]
#                         [--ldflags <flags>]
#
#   <out-dir>        directory to assemble into (created; must not be under dist/,
#                    which goreleaser empties with --clean)
#   --binary-name    name for the k3sm binary in <out-dir> (default: k3sm)
#   --stub-payload   write placeholder payload files instead of downloading the
#                    real ~250 MB control-plane set; for shape/layout checks only,
#                    never for anything published
#   --ldflags        -ldflags value for the k3sm build, e.g. the pkg/version -X
#                    stamps. Empty (the default) leaves an unstamped dev build,
#                    which reports its version from the embedded VCS build info.
#   (k3sm-vmhost is always built and signed with
#   cmd/k3sm-vmhost/vmhost.entitlements: pkg/install.RequiredSiblings names it,
#   so a stage without it fails the required-artifact loop.)
#
# ARCHITECTURE PIN: everything here is darwin/arm64. That is not decoration — a
# Mac whose Go toolchain runs under Rosetta defaults to GOARCH=amd64, so an
# unpinned `go build` here silently produces x86_64 artifacts, and dyld
# HARD-TERMINATES a process whose inserted library is the wrong architecture.
# Every Go build below pins GOARCH, and the arch of every Mach-O is asserted.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$REPO_ROOT/.." && pwd)"

BINARY_NAME="k3sm"
STUB_PAYLOAD=0
LDFLAGS=""
OUT=""

die() { echo "stage: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--binary-name) BINARY_NAME="${2:?--binary-name needs a value}"; shift 2 ;;
	--stub-payload) STUB_PAYLOAD=1; shift ;;
	--ldflags) LDFLAGS="${2?--ldflags needs a value}"; shift 2 ;;
	-h | --help) sed -n '2,35p' "$0"; exit 0 ;;
	-*) die "unknown flag: $1" ;;
	*)
		[ -z "$OUT" ] || die "only one output directory may be given (got '$OUT' and '$1')"
		OUT="$1"; shift ;;
	esac
done
[ -n "$OUT" ] || die "usage: stage.sh <out-dir> [--binary-name <name>] [--stub-payload]"

case "$OUT" in
*/dist | */dist/*) die "refusing to stage under dist/ — goreleaser owns it and --clean empties it before the archive globs run" ;;
esac

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
BIN="$OUT/$BINARY_NAME"
PAYLOAD_DIR="$OUT/cp-payload"

# Every Go build in this script targets the shipped platform, never the host's.
export GOOS=darwin GOARCH=arm64 CGO_ENABLED=1

echo "==> staging into $OUT (darwin/arm64)"

# The k3sm binary. Built from the repo with the workspace active so the sibling
# modules resolve to these checkouts.
echo "==> build $BINARY_NAME"
build_flags=(-trimpath)
[ -n "$LDFLAGS" ] && build_flags+=(-ldflags "$LDFLAGS")
( cd "$REPO_ROOT" && go build "${build_flags[@]}" -o "$BIN" ./cmd/k3sm )

# The Seatbelt exec helper. Built from the WORKSPACE root because go.work is what
# spans the runtimed module; without this helper the server dies at boot.
echo "==> build k3sm-execshim (runtimed)"
( cd "$WS_ROOT" && go build -trimpath -o "$OUT/k3sm-execshim" k3sm.io/runtimed/cmd/k3sm-execshim )

# The two DYLD interposers. Plain clang C dylibs (NOT cgo): a DYLD interposer
# needs a __DATA,__interpose section, and keeping them out of Go lets both
# modules stay CGO-free.
echo "==> build DYLD shims (runtimed path-rebase, darwin-net getaddrinfo)"
"$WS_ROOT/runtimed/hack/build-pathshim.sh" "$OUT" >/dev/null
"$WS_ROOT/darwin-net/hack/build-shim.sh" "$OUT" >/dev/null

# The per-pod VM host helper. Built from the workspace root for the same reason
# as the exec shim, and signed separately below: it is the ONLY k3sm binary that
# carries com.apple.security.virtualization, which is the whole point of it being
# a separate process (runtimed/pkg/sandbox.VMHostName).
VMHOST_ENTITLEMENTS="$WS_ROOT/runtimed/cmd/k3sm-vmhost/vmhost.entitlements"
echo "==> build k3sm-vmhost (runtimed)"
[ -f "$VMHOST_ENTITLEMENTS" ] || die "vmhost entitlements plist not found at $VMHOST_ENTITLEMENTS"
( cd "$WS_ROOT" && go build -trimpath -o "$OUT/k3sm-vmhost" k3sm.io/runtimed/cmd/k3sm-vmhost )

# The control-plane payload. `k3sm payload` downloads the pinned kwok-ci/k8s
# binaries, builds kine, and — on this path — verifies every downloaded binary
# against its pinned sha256, failing closed on a mismatch or an unexpected file.
if [ "$STUB_PAYLOAD" = 1 ]; then
	echo "==> stage cp-payload (STUBS — shape only, never publish this tree)"
	mkdir -p "$PAYLOAD_DIR"
	for rel in $("$BIN" install --print-required-artifacts); do
		case "$rel" in
		cp-payload/*) printf 'stub\n' >"$OUT/$rel" ;;
		esac
	done
else
	echo "==> stage cp-payload (pinned download + digest verify)"
	"$BIN" payload "$PAYLOAD_DIR"
fi

# Ad-hoc sign every Mach-O, then VERIFY. The signature is load-bearing even
# unsigned-by-Developer-ID: AMFI requires *some* signature on darwin/arm64. A
# signer whose exit status is discarded proves nothing, so each is checked.
echo "==> ad-hoc sign + verify"
sign_and_verify() {
	local f="$1" ents="${2:-}"
	if [ -n "$ents" ]; then
		codesign -s - -f --entitlements "$ents" "$f" >/dev/null 2>&1 || die "codesign failed for $f"
	else
		codesign -s - -f "$f" >/dev/null 2>&1 || die "codesign failed for $f"
	fi
	codesign --verify --strict "$f" >/dev/null 2>&1 || die "codesign --verify failed for $f"
	# An entitled binary needs a SECOND assertion, because the first one cannot
	# fail for the reason that matters: AMFI's plist parser is stricter than
	# plutil's, and codesign attaches NO entitlements when it balks — while still
	# producing a signature that verifies as valid. The only symptom downstream is
	# VMBackend.Available() reporting false on a capable Mac, with nothing saying
	# why (runtimed cmd/k3sm-vmhost/entitlements_test.go). So read the entitlement
	# back off the signed Mach-O and require it to be there.
	if [ -n "$ents" ]; then
		codesign -d --entitlements - "$f" 2>/dev/null | grep -q "com.apple.security.virtualization" ||
			die "$f signed but carries no com.apple.security.virtualization entitlement (AMFI rejected $ents?)"
	fi
}
# Stubs are not Mach-Os, so signing is skipped for them by construction.
if [ "$STUB_PAYLOAD" = 1 ]; then
	for f in "$BIN" "$OUT/k3sm-execshim" "$OUT/libk3sm_pathrebase_shim.dylib" "$OUT/libk3sm_getaddrinfo_shim.dylib"; do
		sign_and_verify "$f"
	done
else
	for f in "$BIN" "$OUT/k3sm-execshim" "$OUT/libk3sm_pathrebase_shim.dylib" "$OUT/libk3sm_getaddrinfo_shim.dylib" "$PAYLOAD_DIR"/*; do
		sign_and_verify "$f"
	done
fi
sign_and_verify "$OUT/k3sm-vmhost" "$VMHOST_ENTITLEMENTS"

# Completeness, derived from the binary's own contract rather than this script's
# memory of it: adding an artifact to pkg/install.RequiredSiblings reddens here
# until the producer above learns to make it.
echo "==> verify completeness against the install contract"
missing=0
for rel in $("$BIN" install --print-required-artifacts); do
	[ -e "$OUT/$rel" ] || { echo "    MISSING: $rel"; missing=1; }
done
[ "$missing" = 0 ] || die "staged tree is incomplete — 'k3sm install' would fail-fast on the above"

# Architecture, asserted per Mach-O. See the ARCHITECTURE PIN note above: this is
# the check that catches a Rosetta-defaulted toolchain before the bytes ship.
if [ "$STUB_PAYLOAD" != 1 ]; then
	echo "==> verify every Mach-O is arm64"
	badarch=0
	while IFS= read -r f; do
		case "$(file -b "$f")" in
		*arm64*) ;;
		*) echo "    WRONG ARCH: $f -> $(file -b "$f")"; badarch=1 ;;
		esac
	done < <(find "$OUT" -type f -perm -u+x)
	[ "$badarch" = 0 ] || die "non-arm64 artifact staged (a Rosetta-defaulted toolchain? every build here pins GOARCH=arm64)"
fi

echo "==> staged $(find "$OUT" -type f | wc -l | tr -d ' ') files into $OUT"
