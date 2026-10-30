#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# k3sm root-updater spike: does the Security framework, called directly (no
# codesign text parsing), give the verdicts the root updater's Apple check needs
# on bare Developer ID signed Mach-O files?
#
# Fixtures are the INSTALLED binaries under /Library/k3sm and copies extracted
# from the published v0.2.3 disk image. Nothing under /Library/k3sm or
# /Applications is modified, re-signed or moved; the ad-hoc leg signs a COPY in
# the work dir. No sudo, no network settings change.
#
# Legs (each prints its verdict and the wall time of each framework call):
#   (a) the pinned Developer ID requirement passes, and again with `and notarized`
#   (b) the same requirement with a foreign team OU fails
#   (c) an ad-hoc signed copy fails
#   (d) stapler validate and spctl (primary signature) on the disk image
#   (e) identifier, team, hardened runtime, entitlements and info-plist per binary
# Offline legs need the network off, a host setting this script never changes;
# they are printed as owed.
#
# Exit non-zero iff (a) online, (b) or (c) gives the wrong verdict, or setup fails.
#
# Usage:  hack/acceptance/B995.sh
#   B995_EVIDENCE  evidence dir (default: the nearest k3sm-io.scratch above the
#                  repo, B995-evidence-<local date>)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
TAG=v0.2.3
VER=0.2.3
DMG_NAME="k3sm_${VER}_darwin_arm64.dmg"
SUMS_NAME="k3sm_${VER}_checksums.txt"
TEAM=L578HWC325
FOREIGN_TEAM=AAAAAAAAAA
INSTALLED=/Library/k3sm
BINS=(k3sm k3sm-execshim k3sm-vmhost libk3sm_getaddrinfo_shim.dylib libk3sm_pathrebase_shim.dylib)
BASE_REQ='anchor apple generic and certificate leaf[subject.OU] = "'"$TEAM"'" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
FOREIGN_REQ="${BASE_REQ/$TEAM/$FOREIGN_TEAM}"

# The scratch root is the nearest ancestor's k3sm-io.scratch sibling (a primary
# checkout and a lane sit at different depths).
scratch_root() {
	local d="$K3SM_ROOT"
	while [ "$d" != / ]; do
		[ -d "$d/k3sm-io.scratch" ] && { echo "$d/k3sm-io.scratch"; return; }
		d="$(dirname "$d")"
	done
	return 1
}
if [ -z "${B995_EVIDENCE:-}" ]; then
	SCR="$(scratch_root)" || { echo "FAIL: no k3sm-io.scratch above $K3SM_ROOT; set B995_EVIDENCE"; exit 1; }
	B995_EVIDENCE="$SCR/B995-evidence-$(date +%Y-%m-%d)"
fi
E="$B995_EVIDENCE"
mkdir -p "$E"
DL="$E/dl"; WORK="$E/work"; MNT="$E/mnt"
LOG="$E/run-$(date -u +%Y%m%dT%H%M%SZ).log"
FINDINGS="$E/findings.txt"
PROBE="$WORK/B995-probe"
ATTACHED=0

cleanup() {
	if [ "$ATTACHED" = 1 ]; then hdiutil detach "$MNT" -quiet || hdiutil detach "$MNT" -force -quiet || true; fi
	rmdir "$MNT" 2>/dev/null || true
	rm -rf "$DL" "$WORK"
}
trap cleanup EXIT

exec > >(tee "$LOG") 2>&1

FAIL=0
F=()   # findings lines
note() { F+=("$*"); }
bad()  { echo "FAIL: $*"; FAIL=1; note "FAIL: $*"; }

[ "$(uname -s)" = Darwin ] || { echo "FAIL: darwin only"; exit 1; }
mkdir -p "$DL" "$WORK" "$MNT"

echo "== build the probe"
( cd "$K3SM_ROOT" && CGO_ENABLED=1 go build -o "$PROBE" ./hack/acceptance/B995 )

echo "== fetch $DMG_NAME ($TAG) and verify its sha256"
gh release download "$TAG" --repo k3sm-io/k3sm --pattern "$DMG_NAME" --pattern "$SUMS_NAME" --dir "$DL" --clobber
want=$(awk -v n="$DMG_NAME" '$2 == n {print $1}' "$DL/$SUMS_NAME")
[ -n "$want" ] || { echo "FAIL: $SUMS_NAME has no line for $DMG_NAME"; exit 1; }
printf '%s  %s\n' "$want" "$DL/$DMG_NAME" | shasum -a 256 -c -
note "online: yes (the release download succeeded)"

echo "== attach read-only and copy the payload out"
hdiutil attach -nobrowse -readonly -mountpoint "$MNT" "$DL/$DMG_NAME" >/dev/null
ATTACHED=1
PAY="$MNT/k3sm.app/Contents/Resources/payload"
mkdir -p "$WORK/dmg"
for b in "${BINS[@]}"; do cp -p "$PAY/$b" "$WORK/dmg/$b"; done

# check <label> <path> <req> <want: pass|fail> [judged]; records the verdict and wall time.
check() {
	local label="$1" path="$2" req="$3" want="$4" judged="${5:-}" out rc got ms
	set +e; out=$("$PROBE" check "$path" "$req"); rc=$?; set -e
	echo "$out"
	case $rc in 0) got=pass ;; 1) got=fail ;; *) bad "$label: probe error (exit $rc)"; return ;; esac
	ms=$(printf '%s' "$out" | sed -n 's/.*"wall_ms":\([0-9.]*\).*/\1/p')
	note "$label: $got (${ms} ms)"
	if [ -n "$judged" ] && [ "$got" != "$want" ]; then bad "$label: want $want, got $got"; fi
}

for src in installed dmg; do
	dir=$INSTALLED; [ "$src" = dmg ] && dir="$WORK/dmg"
	echo "== (a) pinned requirement, $src"
	for b in "${BINS[@]}"; do
		check "(a) $src $b base" "$dir/$b" "$BASE_REQ" pass judged
		check "(a) $src $b notarized #1" "$dir/$b" "$BASE_REQ and notarized" pass judged
		check "(a) $src $b notarized #2" "$dir/$b" "$BASE_REQ and notarized" pass judged
	done
	echo "== (b) foreign team, $src"
	for b in "${BINS[@]}"; do check "(b) $src $b foreign OU" "$dir/$b" "$FOREIGN_REQ" fail judged; done
done

echo "== (c) ad-hoc signed copies"
for src in installed dmg; do
	dir=$INSTALLED; [ "$src" = dmg ] && dir="$WORK/dmg"
	mkdir -p "$WORK/adhoc-$src"
	cp "$dir/k3sm" "$WORK/adhoc-$src/k3sm"
	codesign -s - -f "$WORK/adhoc-$src/k3sm"
	check "(c) $src k3sm ad-hoc base" "$WORK/adhoc-$src/k3sm" "$BASE_REQ" fail judged
	check "(c) $src k3sm ad-hoc notarized" "$WORK/adhoc-$src/k3sm" "$BASE_REQ and notarized" fail judged
done

echo "== (d) the disk image as a stapled container"
set +e
st_out=$(xcrun stapler validate "$DL/$DMG_NAME" 2>&1); st_rc=$?
sp_out=$(spctl -a -vv -t open --context context:primary-signature "$DL/$DMG_NAME" 2>&1); sp_rc=$?
app_out=$(xcrun stapler validate "$MNT/k3sm.app" 2>&1); app_rc=$?
bare_out=$(xcrun stapler validate "$WORK/dmg/k3sm" 2>&1); bare_rc=$?
set -e
printf '%s\n' "$st_out" "$sp_out" "$app_out" "$bare_out"
note "(d) stapler validate dmg: exit $st_rc ($( [ $st_rc = 0 ] && echo stapled || echo not stapled ))"
note "(d) spctl open primary-signature dmg: exit $sp_rc: $(printf '%s' "$sp_out" | tr '\n' ' ' | sed -e "s|$DL/||g" -e 's/origin=[^(]*(/origin=team (/')"
note "(d) stapler validate k3sm.app inside the dmg: exit $app_rc"
note "(d) stapler validate bare Mach-O copy: exit $bare_rc: $(printf '%s' "$bare_out" | tail -1)"

echo "== (e) signing information"
for src in installed dmg; do
	dir=$INSTALLED; [ "$src" = dmg ] && dir="$WORK/dmg"
	for b in "${BINS[@]}"; do
		out=$("$PROBE" info "$dir/$b")
		echo "$out"
		note "(e) $src $b: $(printf '%s' "$out" | sed 's/^{"path":"[^"]*",//; s/}$//')"
	done
done

note "owed (attended, network off; the plan's questions b, c and e): the offline result, whether a prior online check is cached and for how long, the time a hung ticket lookup takes, all from a root LaunchDaemon on macOS 26 and 27"
note "host: macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m), run as uid $(id -u) from a login session (not a LaunchDaemon)"

{
	echo "---- B995 findings ----"
	printf '%s\n' "${F[@]}"
	echo "verdict: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
	echo "---- end ----"
} | tee "$FINDINGS"
exit "$FAIL"
