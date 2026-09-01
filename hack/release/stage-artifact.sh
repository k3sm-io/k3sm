#!/usr/bin/env bash
#
# stage-artifact.sh — build ONE downloadable k3sm artifact set from this tree.
#
# hack/release/stage.sh produces the tree `k3sm install` reads. This script wraps
# it into the thing a person can actually download: a version-stamped, ad-hoc
# signed, checksummed darwin/arm64 tarball, plus the extracted set beside it.
#
# It is deliberately NOT the release ceremony. The workspace's hack/release.sh is
# that: it refuses a dirty or unsynced repo, steps the version by semver, drives
# goreleaser, and produces an artifact meant to be tagged and published. This one
# builds from whatever is checked out, stamps a `-dev.<sha>` version, and
# publishes nothing — it is for proving the curl channel end to end before a tag
# exists, and for handing someone a binary today.
#
#   hack/release/stage-artifact.sh [--version <v>] [--out <dir>] [--stub-payload]
#                                 [--no-vmhost]
#
#   --version        version to stamp and name the archive with
#                    (default: 0.1.0-dev.<short sha of this repo's HEAD>, with
#                    ".dirty" appended when the tree has uncommitted changes)
#   --out            output directory (default: hack/release/out, git-ignored)
#   --stub-payload   stage placeholder control-plane files instead of downloading
#                    the real ~250 MB pinned set. Shape checks only — the result
#                    cannot install, and must never be handed to anyone.
#   --no-vmhost      omit the k3sm-vmhost helper (and with it the vm backend)
#
# ARCHIVE NAMING is not free: install.sh resolves
#   k3sm_<version>_darwin_arm64.tar.gz  and  k3sm_<version>_checksums.txt
# from a GitHub release and verifies the first against the second with
# `shasum -a 256 -c`. Both files are produced here under exactly those names, in
# exactly that format, so an artifact staged by this script can be uploaded to a
# release and installed by the published installer with no translation step.
#
# SIGNING is ad-hoc (`codesign -s -`), which is AMFI-satisfying but carries no
# publisher identity: Gatekeeper will quarantine this archive if it is downloaded
# by a browser. Developer-ID signing and notarization are a separate, human-held
# step. The one exception to "ad-hoc and nothing else" is k3sm-vmhost, which is
# additionally signed with com.apple.security.virtualization — an entitlement,
# not an identity, and the only way the vm backend can create a guest at all.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$REPO_ROOT/.." && pwd)"

VERSION=""
OUT="$REPO_ROOT/hack/release/out"
STUB_PAYLOAD=0
WITH_VMHOST=1

die() { echo "stage-artifact: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION="${2:?--version needs a value}"; shift 2 ;;
	--out) OUT="${2:?--out needs a value}"; shift 2 ;;
	--stub-payload) STUB_PAYLOAD=1; shift ;;
	--no-vmhost) WITH_VMHOST=0; shift ;;
	-h | --help) sed -n '2,40p' "$0"; exit 0 ;;
	*) die "unknown flag: $1 (see --help)" ;;
	esac
done

for t in git go clang codesign shasum tar; do
	command -v "$t" >/dev/null 2>&1 || die "$t is not installed"
done

# ---- version + provenance ----------------------------------------------------
# The three sibling SHAs are stamped rather than recovered because they CANNOT be
# recovered: k3sm's go.mod carries filesystem `replace` directives onto the
# sibling checkouts, and a directory replacement has no module version, so
# debug.ReadBuildInfo can only ever report "(devel)" for them (pkg/version).
sha_of() { git -C "$1" rev-parse HEAD 2>/dev/null || echo unknown; }

COMMIT="$(sha_of "$REPO_ROOT")"
if [ -z "$VERSION" ]; then
	short="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
	VERSION="0.1.0-dev.$short"
	if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]; then
		VERSION="$VERSION.dirty"
	fi
fi
VERSION="${VERSION#v}"   # the archive name carries the bare version; install.sh strips it too
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

APIS_COMMIT="$(sha_of "$WS_ROOT/apis")"
DARWIN_NET_COMMIT="$(sha_of "$WS_ROOT/darwin-net")"
RUNTIMED_COMMIT="$(sha_of "$WS_ROOT/runtimed")"

V="k3sm.io/k3sm/pkg/version"
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X $V.Version=$VERSION -X $V.Commit=$COMMIT -X $V.Date=$DATE"
LDFLAGS="$LDFLAGS -X $V.APISCommit=$APIS_COMMIT"
LDFLAGS="$LDFLAGS -X $V.DarwinNetCommit=$DARWIN_NET_COMMIT"
LDFLAGS="$LDFLAGS -X $V.RuntimedCommit=$RUNTIMED_COMMIT"

ARCHIVE="k3sm_${VERSION}_darwin_arm64.tar.gz"
CHECKSUMS="k3sm_${VERSION}_checksums.txt"

echo "==> k3sm $VERSION (darwin/arm64, ad-hoc signed)"

# ---- stage -------------------------------------------------------------------
# A full rebuild every time: a stale binary left from a previous version would be
# re-signed, re-checksummed and shipped without a single check noticing, because
# every check downstream asks about the bytes present rather than their age.
rm -rf "$OUT"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

stage_flags=()
if [ "$STUB_PAYLOAD" = 1 ]; then stage_flags+=(--stub-payload); fi
if [ "$WITH_VMHOST" = 1 ]; then stage_flags+=(--vmhost); fi
# ${a[@]+"${a[@]}"}: an empty array expanded plainly is an unbound-variable error
# under `set -u` on the bash macOS ships (3.2).
"$HERE/stage.sh" "$OUT" --ldflags "$LDFLAGS" ${stage_flags[@]+"${stage_flags[@]}"}

cp "$REPO_ROOT/LICENSE" "$REPO_ROOT/NOTICE" "$OUT/"

# ---- the stamp, read back off the built binary -------------------------------
# Asking the artifact rather than the variable: an ldflags typo (a misspelled
# symbol path) is silently ignored by the linker, and the binary would report
# "dev" while every log line here said otherwise.
got="$("$OUT/k3sm" version | head -1 | awk '{print $2}')"
[ "$got" = "$VERSION" ] || die "staged binary reports version '$got', expected '$VERSION' — the -X stamps did not take"
echo "==> version stamp verified: $("$OUT/k3sm" version | head -1)"

# ---- INSTALL.txt -------------------------------------------------------------
cat >"$OUT/INSTALL.txt" <<TXT
k3sm $VERSION — macOS 26+ on Apple silicon (darwin/arm64)

Install:

    tar -xzf $ARCHIVE
    chmod +x k3sm
    sudo ./k3sm install

\`sudo ./k3sm install\` creates /Library/k3sm, the _k3sm service user, the
LaunchDaemons io.k3sm.netd and io.k3sm.server, and an admin kubeconfig in your
home directory. It copies the binary, the two shim libraries, k3sm-execshim and
cp-payload/ into /Library/k3sm, so this directory can be deleted afterwards.
Until then those files must stay beside k3sm — the installer resolves them
relative to the binary and stops if one is missing.

k3sm-vmhost ships here but is not one of the files install copies. Pods that ask
for the Linux vm runtime cannot start until it is placed in /Library/k3sm by
hand; everything else works without it.

Verify before installing:

    shasum -a 256 -c $CHECKSUMS

Check the install:

    k3sm doctor
    k3sm kubectl get nodes

Remove it:

    sudo k3sm uninstall

This build is ad-hoc signed. It carries no Developer ID and is not notarized, so
macOS quarantines it if a browser downloaded it; fetch it with curl, or clear the
quarantine attribute yourself. Logs are under /var/log/k3sm/.
TXT

# ---- manifest ----------------------------------------------------------------
# Every regular file in the set, one sha256 each, in `shasum -c` format so the
# manifest is checkable and not merely readable. Built before the archive so the
# archive can carry it.
( cd "$OUT" && find . -type f ! -name sha256sums | sed 's|^\./||' | sort |
	while IFS= read -r f; do shasum -a 256 "$f"; done >sha256sums )

# ---- archive -----------------------------------------------------------------
# An explicit member list, not `tar czf . `: the archive is written into the very
# directory being archived, and a self-referential member is both a corrupt file
# and an unstable checksum.
members=()
while IFS= read -r m; do members+=("$m"); done < <(cd "$OUT" && find . -type f | sed 's|^\./||' | sort)
( cd "$OUT" && tar -czf "$ARCHIVE.tmp" "${members[@]}" && mv "$ARCHIVE.tmp" "$ARCHIVE" )
( cd "$OUT" && shasum -a 256 "$ARCHIVE" >"$CHECKSUMS" )

# ---- verify what would ship --------------------------------------------------
# Extract into a scratch directory and interrogate THAT, so the checks run
# against the bytes a user receives rather than the tree they were made from.
echo "==> verify the extracted archive"
vdir="$(mktemp -d)"
trap 'rm -rf "$vdir"' EXIT
tar -xzf "$OUT/$ARCHIVE" -C "$vdir"

missing=0
for rel in $("$vdir/k3sm" install --print-required-artifacts); do
	[ -e "$vdir/$rel" ] || { echo "    MISSING: $rel"; missing=1; }
done
[ "$missing" = 0 ] || die "the archive is missing artifacts 'k3sm install' requires — it would fail-fast on a user's Mac"

( cd "$vdir" && shasum -a 256 -c sha256sums >/dev/null ) || die "extracted files do not match sha256sums"
( cd "$OUT" && shasum -a 256 -c "$CHECKSUMS" >/dev/null ) || die "$ARCHIVE does not match $CHECKSUMS"

codesign --verify --strict "$vdir/k3sm" >/dev/null 2>&1 || die "the archived k3sm fails codesign --verify"
if [ "$WITH_VMHOST" = 1 ]; then
	codesign -d --entitlements - "$vdir/k3sm-vmhost" 2>/dev/null | grep -q com.apple.security.virtualization ||
		die "the archived k3sm-vmhost carries no virtualization entitlement"
fi

echo "----------------------------------------"
echo "staged $VERSION into $OUT"
echo "  archive:   $ARCHIVE ($(du -h "$OUT/$ARCHIVE" | cut -f1))"
echo "  sha256:    $(cut -d' ' -f1 <"$OUT/$CHECKSUMS")"
echo "  checksums: $CHECKSUMS"
echo "  sources:   apis@${APIS_COMMIT:0:12} darwin-net@${DARWIN_NET_COMMIT:0:12} runtimed@${RUNTIMED_COMMIT:0:12} k3sm@${COMMIT:0:12}"
echo "  signing:   ad-hoc (no Developer ID, not notarized)"
if [ "$STUB_PAYLOAD" = 1 ]; then
	echo "  WARNING:   --stub-payload — this set CANNOT install; do not distribute it"
fi
echo "  publish:   nothing was tagged, pushed or uploaded"
