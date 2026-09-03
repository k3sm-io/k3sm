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
#   hack/release/stage.sh <dir> --verify-only [--binary-name <name>]
#
#   <out-dir>        directory to assemble into (created; must not be under dist/,
#                    which goreleaser empties with --clean)
#   --verify-only    build and sign NOTHING; run only the verification block
#                    (completeness against the install contract, codesign --verify
#                    on every Mach-O, the arm64 arch assert, and the k3sm-vmhost
#                    virtualization-entitlement read-back) over a tree that already
#                    exists. This is the seam the workspace's hack/release-gate.sh
#                    drives so the artifact-quality tier re-uses THESE checks over
#                    the extracted archive rather than growing a second copy of
#                    them that can drift from what staging asserts.
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
VERIFY_ONLY=0
LDFLAGS=""
OUT=""

die() { echo "stage: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--binary-name) BINARY_NAME="${2:?--binary-name needs a value}"; shift 2 ;;
	--stub-payload) STUB_PAYLOAD=1; shift ;;
	--verify-only) VERIFY_ONLY=1; shift ;;
	--ldflags) LDFLAGS="${2?--ldflags needs a value}"; shift 2 ;;
	-h | --help) sed -n '2,44p' "$0"; exit 0 ;;
	-*) die "unknown flag: $1" ;;
	*)
		[ -z "$OUT" ] || die "only one output directory may be given (got '$OUT' and '$1')"
		OUT="$1"; shift ;;
	esac
done
[ -n "$OUT" ] || die "usage: stage.sh <out-dir> [--binary-name <name>] [--stub-payload]"

if [ "$VERIFY_ONLY" = 1 ]; then
	[ "$STUB_PAYLOAD" = 0 ] || die "--verify-only and --stub-payload are mutually exclusive (nothing is produced to stub)"
	[ -z "$LDFLAGS" ] || die "--verify-only builds nothing, so --ldflags has no meaning"
	[ -d "$OUT" ] || die "--verify-only: $OUT is not a directory"
else
	case "$OUT" in
	*/dist | */dist/*) die "refusing to stage under dist/ — goreleaser owns it and --clean empties it before the archive globs run" ;;
	esac
	mkdir -p "$OUT"
fi

OUT="$(cd "$OUT" && pwd)"
BIN="$OUT/$BINARY_NAME"
PAYLOAD_DIR="$OUT/cp-payload"

# Every Go build in this script targets the shipped platform, never the host's.
export GOOS=darwin GOARCH=arm64 CGO_ENABLED=1

# The per-pod VM host helper is the ONLY k3sm binary that carries
# com.apple.security.virtualization (runtimed/pkg/sandbox.VMHostName), which is
# why it is signed separately below and why its entitlement is read back in
# verify_tree: a dev-staged k3sm-vmhost without it installs cleanly and then
# breaks every vm-RuntimeClass pod, with the only symptom being the node losing
# its k3sm.io/virtualization label.
VMHOST_ENTITLEMENTS="$WS_ROOT/runtimed/cmd/k3sm-vmhost/vmhost.entitlements"

# ---- verification ------------------------------------------------------------
# ONE implementation, driven from two directions: the staging path calls it after
# it builds and signs, and --verify-only calls it over a tree somebody else
# produced (an extracted release archive, a set about to be installed). Keeping
# it a function rather than a second script is the point — the checks that decide
# whether a staged tree is shippable must not have a second copy that drifts.
#
# Every set below is DERIVED, never listed: the required members come from the
# binary's own `install --print-required-artifacts` contract, and the Mach-O set
# comes from file(1) rather than a name list, so an artifact added to
# pkg/install.RequiredSiblings is checked here without this script being edited.
verify_tree() {
	local rel missing=0 f desc bad_sign=0 bad_arch=0 n_macho=0

	echo "==> verify completeness against the install contract"
	[ -x "$BIN" ] || die "$BIN is missing or not executable — cannot ask it what the set must contain"
	for rel in $("$BIN" install --print-required-artifacts); do
		[ -e "$OUT/$rel" ] || { echo "    MISSING: $rel"; missing=1; }
	done
	[ "$missing" = 0 ] || die "tree is incomplete — 'k3sm install' would fail-fast on the above"

	# codesign + architecture, per Mach-O. The signature is load-bearing even
	# without a Developer ID: AMFI requires *some* signature on darwin/arm64. The
	# arch assert is the ARCHITECTURE PIN check — a Mac whose Go toolchain runs
	# under Rosetta defaults to GOARCH=amd64, and dyld HARD-TERMINATES a process
	# whose inserted library is the wrong architecture.
	echo "==> verify codesign + arm64 over every Mach-O"
	while IFS= read -r f; do
		desc="$(file -b "$f" 2>/dev/null || echo '?')"
		case "$desc" in
		*Mach-O*) ;;
		*) continue ;;
		esac
		n_macho=$((n_macho + 1))
		codesign --verify --strict "$f" >/dev/null 2>&1 || { echo "    UNSIGNED/INVALID: $f"; bad_sign=1; }
		case "$desc" in
		*arm64*) ;;
		*) echo "    WRONG ARCH: $f -> $desc"; bad_arch=1 ;;
		esac
	done < <(find "$OUT" -type f)
	[ "$bad_sign" = 0 ] || die "a staged Mach-O fails codesign --verify — launchd refuses it with OS_REASON_CODESIGNING"
	[ "$bad_arch" = 0 ] || die "non-arm64 artifact staged (a Rosetta-defaulted toolchain? every build here pins GOARCH=arm64)"
	[ "$n_macho" -ge 4 ] || die "only $n_macho Mach-O(s) found under $OUT — the set cannot be complete"

	# The entitlement, read back off the signed Mach-O. codesign attaches NO
	# entitlements when AMFI's plist parser balks — while still producing a
	# signature that verifies as valid — so the check above cannot fail for the
	# reason that matters (runtimed cmd/k3sm-vmhost/entitlements_test.go).
	echo "==> verify k3sm-vmhost carries com.apple.security.virtualization"
	[ -f "$OUT/k3sm-vmhost" ] || die "k3sm-vmhost is not in the tree"
	codesign -d --entitlements - "$OUT/k3sm-vmhost" 2>/dev/null | grep -q "com.apple.security.virtualization" ||
		die "k3sm-vmhost carries no com.apple.security.virtualization entitlement — every vm-RuntimeClass pod would go Pending on the node's missing k3sm.io/virtualization label"

	echo "    $n_macho Mach-O(s) verified"
}

if [ "$VERIFY_ONLY" = 1 ]; then
	echo "==> verify-only over $OUT (nothing built, nothing downloaded, nothing signed)"
	verify_tree
	echo "==> verified $(find "$OUT" -type f | wc -l | tr -d ' ') files in $OUT"
	exit 0
fi

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
# as the exec shim, and signed separately below (see VMHOST_ENTITLEMENTS above).
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

# Ad-hoc sign every Mach-O. The signature is load-bearing even without a
# Developer ID: AMFI requires *some* signature on darwin/arm64. Signing is all
# that happens here — the assertions live in verify_tree above, which runs over
# the finished tree, so the thing checked is the thing that ships rather than the
# thing each step believed it had just made.
echo "==> ad-hoc sign"
sign_one() {
	local f="$1" ents="${2:-}"
	if [ -n "$ents" ]; then
		codesign -s - -f --entitlements "$ents" "$f" >/dev/null 2>&1 || die "codesign failed for $f"
	else
		codesign -s - -f "$f" >/dev/null 2>&1 || die "codesign failed for $f"
	fi
}
# Stubs are not Mach-Os, so signing is skipped for them by construction.
if [ "$STUB_PAYLOAD" = 1 ]; then
	for f in "$BIN" "$OUT/k3sm-execshim" "$OUT/libk3sm_pathrebase_shim.dylib" "$OUT/libk3sm_getaddrinfo_shim.dylib"; do
		sign_one "$f"
	done
else
	for f in "$BIN" "$OUT/k3sm-execshim" "$OUT/libk3sm_pathrebase_shim.dylib" "$OUT/libk3sm_getaddrinfo_shim.dylib" "$PAYLOAD_DIR"/*; do
		sign_one "$f"
	done
fi
sign_one "$OUT/k3sm-vmhost" "$VMHOST_ENTITLEMENTS"

verify_tree

echo "==> staged $(find "$OUT" -type f | wc -l | tr -d ' ') files into $OUT"
