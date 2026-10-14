#!/usr/bin/env bash
#
# sign.sh — Developer ID signing and notarization of a staged release tree.
#
#   hack/release/sign.sh --identity <identity> --team-id <TEAMID> <tree>
#
#   --identity   the Developer ID Application signing identity, as codesign
#                accepts it: the full certificate name, which must end in
#                "(<TEAMID>)", or its 40-hex SHA-1 hash. No default.
#   --team-id    the 10-character Apple Team ID the release is signed for. No
#                default; the operator also types it back at a terminal prompt.
#   <tree>       a tree staged by `hack/release/stage.sh <tree> --release`, which
#                carries the PAYLOAD-SHA256 manifest naming every file in it.
#
# What it does, in order:
#   1. Takes the file list from the tree's PAYLOAD-SHA256 manifest and keeps the
#      Mach-Os among them (file(1)). Signing only what the manifest names keeps
#      this script's view of the tree identical to stage.sh's. `stage.sh
#      --release` refuses any control-plane file that k3sm did not build from
#      pinned source, so every Mach-O signed here is a k3sm build; no third-party
#      build is ever signed with the Developer ID.
#   2. Signs inside out: deeper paths first, and at one depth libraries before
#      executables, with `--options runtime --timestamp`. The identifier and the
#      entitlements stage.sh gave each file are preserved.
#   3. Verifies every signature (`codesign --verify --strict`).
#   4. Zips the signed Mach-Os (ditto) and submits the zip with
#      `xcrun notarytool submit --keychain-profile k3sm-notary --wait`, and
#      fails unless the result is Accepted. A bare Mach-O cannot be stapled; its
#      ticket is looked up online by Gatekeeper.
#
# It does not rewrite the manifest or run the release verification: the driver,
# hack/release/publish.sh, runs `stage.sh --rewrite-manifest` and then
# `stage.sh --verify-release <TEAMID>` after this script.
#
# THE REFUSAL. Before it parses an argument or looks up any tool, this script
# refuses when CLAUDECODE or K3SM_AUTO is set at all (set but empty counts), when
# /dev/tty cannot be opened, and, right after parsing and still before any tool
# lookup, when the operator does not type the Team ID back at a /dev/tty prompt.
# Every refusal prints a stable `REFUSE: <token>` line and exits 2.
#
# The refusal is a guard against accident, NOT a security boundary: anything
# that can run this script can also unset a variable, allocate a terminal or
# call codesign directly. The real control is the credential itself: the
# Developer ID identity is human-held and prompts on use, and it lives in a
# keychain that unattended automation never unlocks. This guard only stops an
# automated run from reaching that prompt by mistake.
#
# Every tool is called by its bare name on PATH, never by an absolute path, so
# the self-test (hack/release/publish.sh --self-test) can shadow each one with a
# fake that records its arguments.
set -euo pipefail

refuse() {
	printf 'sign: REFUSE: %s\n' "$1" >&2
	shift
	printf 'sign: %s\n' "$@" >&2
	exit 2
}

# ---- the refusal: shell builtins only, before any argument or tool -----------
if [ -n "${CLAUDECODE+x}" ] || [ -n "${K3SM_AUTO+x}" ]; then
	refuse automation-env \
		"CLAUDECODE or K3SM_AUTO is set in the environment." \
		"Signing runs attended only, from an operator's terminal."
fi
if ! (exec 3<>/dev/tty) 2>/dev/null; then
	refuse no-tty "/dev/tty cannot be opened; signing needs an operator at a terminal."
fi
exec 3<>/dev/tty
printf 'sign: type the Apple Team ID this release is signed for: ' >&3
TYPED_TEAM=""
IFS= read -r TYPED_TEAM <&3 || TYPED_TEAM=""
exec 3>&-

die() { echo "sign: $*" >&2; exit 1; }

# ---- arguments ----------------------------------------------------------------
IDENTITY=""
TEAM_ID=""
TREE=""
while [ $# -gt 0 ]; do
	case "$1" in
	--identity) IDENTITY="${2:?--identity needs a value}"; shift 2 ;;
	--team-id) TEAM_ID="${2:?--team-id needs a value}"; shift 2 ;;
	-h | --help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
	-*) die "unknown flag: $1" ;;
	*)
		[ -z "$TREE" ] || die "only one tree may be given (got '$TREE' and '$1')"
		TREE="$1"; shift ;;
	esac
done

[ -n "$TEAM_ID" ] || die "usage: sign.sh --identity <identity> --team-id <TEAMID> <tree>"
if [ "$TYPED_TEAM" != "$TEAM_ID" ]; then
	refuse team-id-mismatch "the Team ID typed at the prompt does not match --team-id."
fi
[ -n "$IDENTITY" ] || die "usage: sign.sh --identity <identity> --team-id <TEAMID> <tree>"
[ -n "$TREE" ] || die "usage: sign.sh --identity <identity> --team-id <TEAMID> <tree>"
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || die "--team-id '$TEAM_ID' is not a 10-character Team ID"
if ! [[ "$IDENTITY" =~ ^[0-9A-Fa-f]{40}$ ]]; then
	case "$IDENTITY" in
	"Developer ID Application: "*"($TEAM_ID)") ;;
	*) die "--identity must be a 'Developer ID Application: ... ($TEAM_ID)' name or a 40-hex certificate hash" ;;
	esac
fi
[ -d "$TREE" ] || die "$TREE is not a directory"
TREE="$(cd "$TREE" && pwd)"
MANIFEST="$TREE/PAYLOAD-SHA256"
[ -f "$MANIFEST" ] || die "$TREE has no PAYLOAD-SHA256; stage it with hack/release/stage.sh --release first"

# ---- the Mach-Os, inside out ----------------------------------------------------
# Manifest lines are `<sha256>  <relpath>` after `#` comment lines. Each Mach-O
# is printed as `<depth> <rank> <relpath>`, rank 0 for a library and 1 for
# anything else, then sorted deepest first, libraries first, then by name.
order=""
while IFS= read -r line; do
	case "$line" in '#'* | '') continue ;; esac
	rel="${line#*  }"
	[ -f "$TREE/$rel" ] || die "the manifest names $rel, which is not in $TREE"
	kind="$(file -b "$TREE/$rel")"
	case "$kind" in *Mach-O*) ;; *) continue ;; esac
	slashes="${rel//[!\/]/}"
	rank=1
	case "$kind" in *"shared library"* | *bundle*) rank=0 ;; esac
	order+="${#slashes} $rank $rel"$'\n'
done <"$MANIFEST"
[ -n "$order" ] || die "the manifest of $TREE names no Mach-O"
MACHOS=()
while IFS= read -r rel; do
	MACHOS+=("$rel")
done < <(printf '%s' "$order" | LC_ALL=C sort -k1,1nr -k2,2n -k3 | cut -d' ' -f3-)

# ---- sign, verify ---------------------------------------------------------------
# codesign writes the signed copy beside the file and renames it into place, and
# nothing in a staged tree is executing, so signing the staged files in place
# never touches a mapped image.
echo "==> sign ${#MACHOS[@]} Mach-Os in $TREE (inside out)"
for rel in "${MACHOS[@]}"; do
	echo "    $rel"
	codesign --force --sign "$IDENTITY" --options runtime --timestamp \
		--preserve-metadata=identifier,entitlements "$TREE/$rel" ||
		die "codesign failed on $rel"
done
for rel in "${MACHOS[@]}"; do
	codesign --verify --strict "$TREE/$rel" || die "$rel fails codesign --verify after signing"
done

# ---- notarize -------------------------------------------------------------------
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/k3sm-notarize"
for rel in "${MACHOS[@]}"; do
	mkdir -p "$work/k3sm-notarize/$(dirname "$rel")"
	cp -p "$TREE/$rel" "$work/k3sm-notarize/$rel"
done
ditto -c -k --keepParent "$work/k3sm-notarize" "$work/k3sm-notarize.zip" ||
	die "could not zip the signed Mach-Os"

echo "==> notarize (keychain profile k3sm-notary; this waits for Apple)"
xcrun notarytool submit "$work/k3sm-notarize.zip" --keychain-profile k3sm-notary --wait \
	--output-format json >"$work/notary.json" ||
	die "notarytool submit failed"
status="$(jq -r '.status // ""' "$work/notary.json")" || die "unreadable notarytool output"
id="$(jq -r '.id // ""' "$work/notary.json")" || id=""
if [ "$status" != "Accepted" ]; then
	die "notarization status is '$status', not Accepted; read the log with: xcrun notarytool log $id --keychain-profile k3sm-notary"
fi
echo "==> signed and notarized (submission $id)"
