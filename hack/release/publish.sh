#!/usr/bin/env bash
#
# publish.sh — the attended release driver: stage, sign, verify, then a
# draft-then-promote upload.
#
#   hack/release/publish.sh --version vX.Y.Z --stage-dir <dir> --cp-build <dir>
#                           --ldflags <flags> --identity <identity>
#                           --team-id <TEAMID> --notes-file <file>
#                           [--repo <owner/name>]
#   hack/release/publish.sh --through-verify --version vX.Y.Z --stage-dir <dir>
#                           --cp-build <dir> --ldflags <flags>
#                           --identity <identity> --team-id <TEAMID>
#   hack/release/publish.sh --upload --version vX.Y.Z --stage-dir <dir>
#                           --team-id <TEAMID> --notes-file <file>
#                           [--disk-image <file>] [--repo <owner/name>]
#   hack/release/publish.sh --self-test
#
# Three ways to run it. With neither phase flag it is the one-shot,
# tarball-only release: steps 0 to 8 below in one run. A release that also
# ships a disk image of the macOS app runs it in two phases, and builds the
# image from the verified stage tree in between:
#   --through-verify  steps 0 to 5, then writes the seal (below) and stops.
#                     The verified stage tree, <stage-dir>.assets and
#                     <stage-dir>.seal are left for --upload.
#   --upload          checks the seal and re-checks the tree and assets, checks
#                     and adds the disk image if one is given, then steps 6 to 8.
#                     It builds and signs nothing.
#
#   --version     the release tag, which must already exist on the repo
#                 (vMAJOR.MINOR.PATCH or ...-rc.N); this script never creates one
#   --stage-dir   where stage.sh assembles the tree (must not exist yet, and
#                 must sit outside the k3sm worktree, which has to stay clean);
#                 the upload assets are written beside it, in <stage-dir>.assets.
#                 With --upload, the tree --through-verify left.
#   --cp-build    the output directory of hack/release/build-cp.sh
#   --ldflags     the -ldflags for the k3sm build; must stamp
#                 k3sm.io/k3sm/pkg/version.Version, which is checked against
#                 --version before anything is uploaded
#   --identity    the Developer ID Application identity (see sign.sh). No default.
#   --team-id     the Apple Team ID. No default.
#   --notes-file  the release notes body
#   --repo        the GitHub repository (default k3sm-io/k3sm)
#   --disk-image  (--upload only) the app's disk image, named exactly
#                 k3sm_<version>_darwin_arm64.dmg (the version without its
#                 leading v). It is checked as described below, never trusted
#                 for its name.
#   --self-test   hermetic test of the refusals and the promote check, with
#                 every signing, notary, keychain and GitHub tool replaced by a
#                 fake on PATH (no network, no credentials, no keychain)
#
# The flow, each step refusing to continue on any failure:
#   0. the k3sm worktree is clean and the tag's commit is HEAD, so what is
#      built is exactly what the tag names
#   1. hack/release/stage.sh <stage-dir> --release --cp-build <dir> --ldflags ...
#   2. hack/release/sign.sh --identity ... --team-id ... <stage-dir>
#      (prompts for the Team ID at the terminal; signs and notarizes), then the
#      entitlements of every signed Mach-O are read back against an exact
#      allowlist: k3sm-vmhost carries com.apple.security.virtualization and
#      nothing else, every other binary carries none
#   3. hack/release/stage.sh --rewrite-manifest <stage-dir>
#      (signing changed the bytes; the manifest is recomputed over them)
#   4. hack/release/stage.sh <stage-dir> --verify-release <TEAMID>
#   5. package <stage-dir>.assets: the tarball of exactly the verified tree plus
#      LICENSE and NOTICE, the tree's PAYLOAD-SHA256 manifest, and a checksums
#      file over both; then the tarball is extracted into a private directory
#      and every file in it is checked against PAYLOAD-SHA256, so the bytes that
#      ship are the bytes that were verified
#   6. immediately before the draft, every file about to be uploaded is
#      checked again: the stage tree and the tarball against PAYLOAD-SHA256,
#      the tarball's SHA-256 against the one step 5 checked (the seal's under
#      --upload), the disk image copy against the hash taken at its checks,
#      and the checksums file against all of them; then
#      gh release create <tag> --draft --verify-tag with those assets
#      (--prerelease for an -rc.N tag)
#   7. read the draft back (gh release view --json) and check it: still a draft,
#      exactly the expected asset names, each fully uploaded, with the local
#      size and SHA-256 (the asset digest GitHub reports, or a download when it
#      reports none), and the tarball's and image's digests also equal the
#      hashes checked before the upload
#   8. only then promote: gh release edit <tag> --draft=false, with --latest
#      for a final version and --latest=false for a release candidate
#
# THE TARBALL'S SHAPE is the one install.sh (at the repo root) consumes: the
# assets k3sm_<version>_darwin_arm64.tar.gz and k3sm_<version>_checksums.txt
# (the version without its leading v), a checksums line `<sha256>  <name>`
# whose second field is exactly the archive name, and `k3sm` at the archive
# root, which install.sh runs as `k3sm install`. This is also the naming the
# goreleaser config uses. Two differences from the goreleaser archive: there is
# no k3sm-netd copy, because the install contract (`k3sm install
# --print-required-artifacts`) does not name one, and the checksums file also
# lists the PAYLOAD-SHA256 asset, which install.sh's exact-field match ignores.
#
# THE SEAL. --through-verify writes <stage-dir>.seal, key=value lines: tag,
# head (the commit HEAD and the tag named), payload_manifest_sha256 (the
# SHA-256 of the tree's PAYLOAD-SHA256), tarball_sha256, and team_id (the Team
# ID --verify-release checked). --upload refuses without it, on a malformed
# one, or when any field differs from what it recomputes, and then runs every
# check again rather than trusting the seal: the tag binding (step 0),
# stage.sh --verify-release with the sealed Team ID, the stage tree and the
# tarball against PAYLOAD-SHA256, and the checksums file against the tarball
# and manifest assets. An unsigned rehearsal tree, or a tree edited in step
# with its manifest, therefore never reaches gh.
#
# THE DISK IMAGE (--upload --disk-image). The file is copied, mode 0444, into
# a private 0700 directory, <stage-dir>.assets/disk-image, and that copy is
# what is checked, hashed once, re-hashed right before the draft, and uploaded:
#   - its basename is exactly k3sm_<version>_darwin_arm64.dmg, checked before
#     anything else (no other extra asset is accepted, and --disk-image is
#     given at most once)
#   - codesign --verify --strict against the Developer ID Application
#     requirement for the Team ID, xcrun stapler validate, and spctl -a -t open
#     --context context:primary-signature, accept the image
#   - hdiutil attach -readonly -nobrowse -noautoopen at a private mount point,
#     detached on every exit (EXIT, HUP, INT, TERM); the image root holds only
#     k3sm.app, an Applications symlink to /Applications, and at most a
#     .fseventsd directory (the filesystem metadata an APFS image can carry);
#     any other entry, hidden or not, refuses
#   - k3sm.app/Contents/Resources/payload holds exactly the files
#     PAYLOAD-SHA256 lists, with its hashes, and the manifest itself, unchanged
#     (no .DS_Store, no symlink)
#   - CFBundleShortVersionString equals the tag's version: X.Y.Z for vX.Y.Z,
#     and the X.Y.Z core for vX.Y.Z-rc.N (the key takes only a plain x.y.z)
#   - codesign --verify --strict --deep against the Developer ID Application
#     requirement for the Team ID, and xcrun stapler validate, accept the app
# Then this script computes the image's SHA-256 and appends `<sha256>  <name>`
# to the checksums file before the draft is created, so the draft carries four
# assets instead of three and step 7 checks all four. install.sh selects its
# checksums line by exact archive name, so the image's line does not affect it.
# This script names no other repository: it only takes the image file.
#
# A draft whose assets fail step 7 is never promoted, so a failed or partial
# upload of a large asset cannot become the latest release that an install
# script fetches. The draft is left for the operator to inspect and delete.
#
# THE REFUSAL. Outside --self-test this script refuses, in every mode
# (one-shot, --through-verify and --upload), before it parses an argument, when CLAUDECODE or K3SM_AUTO is set at all or when /dev/tty cannot
# be opened, and sign.sh repeats the full check. Like sign.sh's, it is a guard
# against accident, not a security boundary: the real controls are the
# human-held, prompt-on-use signing identity, the keychain unattended
# automation never unlocks, and the GitHub credential the operator holds.
#
# Every tool is called by its bare name on PATH, never by an absolute path.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

refuse() {
	printf 'publish: REFUSE: %s\n' "$1" >&2
	shift
	printf 'publish: %s\n' "$@" >&2
	exit 2
}
die() { echo "publish: $*" >&2; exit 1; }

valid_version() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; }
is_rc() { [[ "$1" =~ -rc\.[0-9]+$ ]]; }

# tag_binding_problems <repo-dir> <ref>: zero when the worktree is clean
# (untracked files included) and <ref>'s commit is HEAD. Called with
# refs/tags/<version>; the ref is a parameter only so the self-test can drive
# it with a fixture branch instead of creating a tag.
tag_binding_problems() {
	local repo="$1" ref="$2" dirty want head
	dirty="$(git -C "$repo" status --porcelain 2>/dev/null)" || { echo "    $repo is not a git worktree"; return 1; }
	[ -z "$dirty" ] || { echo "    the worktree at $repo is not clean:"; printf '%s\n' "$dirty" | sed 's/^/      /'; return 1; }
	want="$(git -C "$repo" rev-parse --verify --quiet "$ref^{commit}")" || { echo "    $ref does not exist"; return 1; }
	head="$(git -C "$repo" rev-parse --verify HEAD)" || { echo "    no HEAD in $repo"; return 1; }
	[ "$want" = "$head" ] || { echo "    $ref is $want but HEAD is $head"; return 1; }
}

# tree_manifest_problems <dir> <manifest> [extra-allowed...]: zero when the
# regular files under <dir> are exactly the manifest's paths (plus the manifest
# itself, .DS_Store, and any extra-allowed top-level names) with the manifest's
# SHA-256 each, and nothing in <dir> is a symlink. Prints every problem.
tree_manifest_problems() {
	local dir="$1" manifest="$2" problems=0 want got sum rel line extra
	shift 2
	[ -f "$manifest" ] || { echo "    no manifest $manifest"; return 1; }
	if [ -n "$(cd "$dir" && find . -type l | head -1)" ]; then
		echo "    $dir holds a symlink"; problems=1
	fi
	want="$(grep -v '^#' "$manifest" | sed '/^$/d' | sed 's/^[0-9a-f]\{64\}  //' | LC_ALL=C sort)"
	got="$(cd "$dir" && find . -type f ! -name .DS_Store | sed 's|^\./||' | LC_ALL=C sort)"
	got="$(printf '%s\n' "$got" | grep -vxF "PAYLOAD-SHA256" || true)"
	for extra in "$@"; do got="$(printf '%s\n' "$got" | grep -vxF "$extra" || true)"; done
	if [ "$want" != "$got" ]; then
		echo "    the file set of $dir differs from the manifest:"
		diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed -n 's/^\([<>]\)/      \1/p'
		problems=1
	fi
	# `|| [ -n "$line" ]` keeps a last line that has no trailing newline.
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in '#'* | '') continue ;; esac
		sum="${line%%  *}"
		rel="${line#*  }"
		[ -f "$dir/$rel" ] || continue
		[ "$(shasum -a 256 "$dir/$rel" | cut -d' ' -f1)" = "$sum" ] || { echo "    $rel: sha256 differs from the manifest"; problems=1; }
	done <"$manifest"
	return "$problems"
}

# tarball_problems <tarball> <manifest>: extract into a private directory and
# check the payload against the manifest; LICENSE and NOTICE are the only
# extra files allowed, and the archived manifest must be byte-identical.
tarball_problems() {
	local tarball="$1" manifest="$2" x rc=0
	x="$(mktemp -d)"
	chmod 700 "$x"
	if ! tar -xzf "$tarball" -C "$x" 2>/dev/null; then
		echo "    cannot extract $tarball"; rm -rf "$x"; return 1
	fi
	cmp -s "$x/PAYLOAD-SHA256" "$manifest" || { echo "    the archived PAYLOAD-SHA256 differs from the staged one"; rc=1; }
	tree_manifest_problems "$x" "$manifest" LICENSE NOTICE || rc=1
	rm -rf "$x"
	return "$rc"
}

# entitlement_problems <relpath> <entitlements-xml>: the decision over one
# signed Mach-O's `codesign -d --entitlements - --xml` output. k3sm-vmhost must
# carry exactly com.apple.security.virtualization = true; every other binary
# must carry no entitlement at all. Empty output means none.
entitlement_problems() {
	local rel="$1" xml="$2" got want=""
	[ "$(basename "$rel")" = "k3sm-vmhost" ] && want="com.apple.security.virtualization=true"
	if [ -z "$xml" ]; then
		got=""
	else
		got="$(plutil -convert json -o - - <<<"$xml" 2>/dev/null | jq -r 'if type == "object" then to_entries[] | "\(.key)=\(.value | tojson)" else error("not a dictionary") end' 2>/dev/null)" ||
			{ echo "    $rel: unreadable entitlements"; return 1; }
		got="$(printf '%s' "$got" | LC_ALL=C sort)"
	fi
	[ "$got" = "$want" ] || {
		echo "    $rel: entitlements [${got//$'\n'/, }] are not exactly [${want}]"
		return 1
	}
}

# entitlements_problems <tree>: read back every manifest-listed Mach-O's
# entitlements and apply entitlement_problems to each.
entitlements_problems() {
	local tree="$1" line rel xml rc=0 seen=0
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in '#'* | '') continue ;; esac
		rel="${line#*  }"
		case "$(file -b "$tree/$rel")" in *Mach-O*) ;; *) continue ;; esac
		seen=1
		xml="$(codesign -d --entitlements - --xml "$tree/$rel" 2>/dev/null)" ||
			{ echo "    $rel: codesign could not read its entitlements"; rc=1; continue; }
		entitlement_problems "$rel" "$xml" || rc=1
	done <"$tree/PAYLOAD-SHA256"
	[ "$seen" = 1 ] || { echo "    the manifest of $tree names no Mach-O"; return 1; }
	return "$rc"
}

# asset names for a tag; the checksums file lists the other two
asset_base() { printf 'k3sm_%s_darwin_arm64' "${1#v}"; }
checksums_name() { printf 'k3sm_%s_checksums.txt' "${1#v}"; }

# package_assets <tree> <tag> <outdir>: write the three upload assets.
package_assets() {
	local tree="$1" tag="$2" out="$3" base files
	base="$(asset_base "$tag")"
	[ -f "$tree.PAYLOAD-SHA256" ] || die "$tree.PAYLOAD-SHA256 is missing; stage.sh writes it beside the tree"
	[ -f "$REPO_ROOT/LICENSE" ] && [ -f "$REPO_ROOT/NOTICE" ] || die "LICENSE or NOTICE is missing from $REPO_ROOT"
	mkdir "$out" || die "$out already exists; remove it or choose another --stage-dir"
	files=()
	while IFS= read -r f; do files+=("$f"); done < <(cd "$tree" && find . -mindepth 1 -maxdepth 1 | sed 's|^\./||' | LC_ALL=C sort)
	COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$out/$base.tar.gz" \
		-C "$tree" "${files[@]}" -C "$REPO_ROOT" LICENSE NOTICE || die "could not write the tarball"
	cp "$tree.PAYLOAD-SHA256" "$out/$base.PAYLOAD-SHA256"
	(cd "$out" && shasum -a 256 "$base.tar.gz" "$base.PAYLOAD-SHA256" >"$(checksums_name "$tag")") ||
		die "could not write the checksums file"
	local problems
	if ! problems="$(tarball_problems "$out/$base.tar.gz" "$tree/PAYLOAD-SHA256")"; then
		printf '%s\n' "$problems" >&2
		refuse tarball-mismatch "the packaged tarball does not hold exactly the verified tree; nothing was uploaded."
	fi
}

# The disk image's private directory under the assets (0700, the image 0444).
IMAGE_DIR_NAME=disk-image

# asset_path <assetdir> <tag> <name>: the local file behind an asset name.
asset_path() {
	if [ "$3" = "$(image_name "$2")" ]; then printf '%s/%s/%s' "$1" "$IMAGE_DIR_NAME" "$3"; else printf '%s/%s' "$1" "$3"; fi
}

# expected_assets <tag> <assetdir>: the asset names a complete draft carries,
# read from the local checksums file, plus that file itself.
expected_assets() {
	local sums
	sums="$2/$(checksums_name "$1")"
	[ -f "$sums" ] || return 1
	{ sed 's/^[0-9a-f]*  //' "$sums"; checksums_name "$1"; echo; } | sed '/^$/d' | LC_ALL=C sort
}

# verify_draft <tag> <repo> <assetdir> [tarball-sha256] [image-sha256]: zero
# only when the release is still a draft and its assets are exactly the local
# ones, fully uploaded, byte for byte. A given tarball or image hash (the
# sealed one, the one computed at the image's check) must also equal the
# read-back digest, so a local file swapped after it was checked is caught too.
# Prints every problem it finds.
verify_draft() {
	local tag="$1" repo="$2" dir="$3" tsha="${4:-}" isha="${5:-}" json want got n problems=0 state size digest local_sum tmp f pinned
	json="$(gh release view "$tag" --repo "$repo" --json isDraft,assets)" || { echo "    cannot read the release $tag"; return 1; }
	jq -e 'type == "object" and (.assets | type == "array")' >/dev/null 2>&1 <<<"$json" ||
		{ echo "    the release JSON is not readable"; return 1; }
	[ "$(jq -r '.isDraft' <<<"$json")" = "true" ] || { echo "    $tag is not a draft"; problems=1; }
	want="$(expected_assets "$tag" "$dir")" || { echo "    no local checksums file in $dir"; return 1; }
	got="$(jq -r '.assets[].name' <<<"$json" | LC_ALL=C sort)"
	if [ "$want" != "$got" ]; then
		echo "    asset names differ from the local set:"
		diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed -n 's/^\([<>]\)/      \1/p'
		problems=1
	fi
	tmp="$(mktemp -d)"
	while IFS= read -r n; do
		[ -n "$n" ] || continue
		jq -e --arg n "$n" 'any(.assets[]; .name == $n)' >/dev/null <<<"$json" || continue
		state="$(jq -r --arg n "$n" 'first(.assets[] | select(.name == $n)) | .state // ""' <<<"$json")"
		size="$(jq -r --arg n "$n" 'first(.assets[] | select(.name == $n)) | .size // ""' <<<"$json")"
		digest="$(jq -r --arg n "$n" 'first(.assets[] | select(.name == $n)) | .digest // ""' <<<"$json")"
		f="$(asset_path "$dir" "$tag" "$n")"
		local_sum="sha256:$(shasum -a 256 "$f" | cut -d' ' -f1)"
		[ "$state" = "uploaded" ] || { echo "    $n: upload state '$state', not uploaded"; problems=1; }
		[ "$size" = "$(stat -f %z "$f")" ] || { echo "    $n: size $size differs from the local file"; problems=1; }
		if [ -z "$digest" ]; then
			if gh release download "$tag" --repo "$repo" --pattern "$n" --dir "$tmp" >/dev/null 2>&1 && [ -f "$tmp/$n" ]; then
				digest="sha256:$(shasum -a 256 "$tmp/$n" | cut -d' ' -f1)"
			else
				echo "    $n: no digest reported and the download failed"; problems=1; continue
			fi
		fi
		[ "$digest" = "$local_sum" ] || { echo "    $n: digest $digest differs from the local $local_sum"; problems=1; }
		pinned=""
		[ "$n" = "$(asset_base "$tag").tar.gz" ] && pinned="$tsha"
		[ "$n" = "$(image_name "$tag")" ] && pinned="$isha"
		if [ -n "$pinned" ] && [ "$digest" != "sha256:$pinned" ]; then
			echo "    $n: digest $digest differs from the checked sha256:$pinned"; problems=1
		fi
	done <<<"$want"
	rm -rf "$tmp"
	return "$problems"
}

# promote <tag> <repo> <assetdir> [tarball-sha256] [image-sha256]: publish the
# draft, only if verify_draft passes.
promote() {
	local tag="$1" repo="$2" dir="$3" tsha="${4:-}" isha="${5:-}" out
	if ! out="$(verify_draft "$tag" "$repo" "$dir" "$tsha" "$isha")"; then
		printf '%s\n' "$out" >&2
		refuse draft-unverified \
			"the draft release $tag does not match the staged assets; it was NOT promoted." \
			"Inspect it on GitHub, delete it (gh release delete $tag --repo $repo), and publish again."
	fi
	echo "==> draft $tag verified; promoting"
	# A release candidate must never become the latest release install.sh
	# resolves; a final version always does.
	local latest="--latest"
	is_rc "$tag" && latest="--latest=false"
	gh release edit "$tag" --repo "$repo" --draft=false "$latest" || die "promoting $tag failed; the verified draft is still in place"
}

# upload <tag> <repo> <notes> <assetdir> <stage-tree> <tarball-sha256>
# [image-sha256]: immediately before the draft is created, re-check every file
# about to be uploaded: the stage tree and the tarball against PAYLOAD-SHA256,
# the tarball against the expected hash (the seal's under --upload), the image
# copy against the hash taken when it was checked, and the checksums file
# against all of them. Then create the draft and promote. Three assets
# (tarball, manifest, checksums), or four with the image.
upload() {
	local tag="$1" repo="$2" notes="$3" dir="$4" tree="$5" tsha="$6" isha="${7:-}" count=3 names=() n problems pre=() base img
	base="$(asset_base "$tag")"
	[ -n "$tsha" ] || die "upload needs the expected tarball hash"
	[ -z "$isha" ] || count=4
	if ! problems="$(tree_manifest_problems "$tree" "$tree/PAYLOAD-SHA256")"; then
		printf '%s\n' "$problems" >&2
		refuse tree-changed "the stage tree no longer matches its PAYLOAD-SHA256; nothing was uploaded."
	fi
	if ! problems="$(tarball_problems "$dir/$base.tar.gz" "$tree/PAYLOAD-SHA256")"; then
		printf '%s\n' "$problems" >&2
		refuse tarball-mismatch "the tarball does not hold exactly the verified tree; nothing was uploaded."
	fi
	[ "$(sha256_of "$dir/$base.tar.gz")" = "$tsha" ] ||
		refuse tarball-changed "the tarball is not the one that was verified (sha256 $tsha); nothing was uploaded."
	if [ -n "$isha" ]; then
		img="$(asset_path "$dir" "$tag" "$(image_name "$tag")")"
		[ -f "$img" ] && [ ! -L "$img" ] && [ "$(sha256_of "$img")" = "$isha" ] ||
			refuse image-changed "the disk image changed after its checks (sha256 $isha); nothing was uploaded."
	fi
	if ! problems="$(checksums_problems "$tag" "$dir" "$isha")"; then
		printf '%s\n' "$problems" >&2
		refuse checksums "the checksums file or the assets directory changed after the checks; nothing was uploaded."
	fi
	while IFS= read -r n; do names+=("$(asset_path "$dir" "$tag" "$n")"); done < <(expected_assets "$tag" "$dir")
	[ "${#names[@]}" -eq "$count" ] || die "expected $count assets in $dir, the checksums file names ${#names[@]}"
	is_rc "$tag" && pre=(--prerelease)
	echo "==> create the draft release $tag on $repo"
	gh release create "$tag" --repo "$repo" --draft ${pre[@]+"${pre[@]}"} --verify-tag --title "$tag" --notes-file "$notes" "${names[@]}" ||
		die "creating the draft failed; any partial draft is left unpublished for inspection"
	promote "$tag" "$repo" "$dir" "$tsha" "$isha"
}

# ---- the two phases: --through-verify seals, --upload checks ---------------------

image_name() { printf '%s.dmg' "$(asset_base "$1")"; }
sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }

# The seal's keys, in the order write_seal writes them.
SEAL_KEYS="tag head payload_manifest_sha256 tarball_sha256 team_id"

# write_seal <seal> <tag> <head> <manifest> <tarball> <team>: written once,
# through a temporary file, so a partial seal never exists under its name.
write_seal() {
	local seal="$1" tmp
	[ ! -e "$seal" ] || die "$seal already exists"
	tmp="$seal.tmp.$$"
	{
		echo "# k3sm publish seal v1: written by --through-verify, checked by --upload"
		echo "tag=$2"
		echo "head=$3"
		echo "payload_manifest_sha256=$(sha256_of "$4")"
		echo "tarball_sha256=$(sha256_of "$5")"
		echo "team_id=$6"
	} >"$tmp" || die "could not write $seal"
	mv "$tmp" "$seal"
}

# seal_problems <seal>: zero when the seal is a regular file holding each of
# SEAL_KEYS exactly once and nothing else (comment and blank lines aside).
seal_problems() {
	local seal="$1" line key seen=" " k
	if [ -L "$seal" ] || [ ! -f "$seal" ]; then
		echo "    no seal at $seal; --through-verify writes it"; return 1
	fi
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in '#'* | '') continue ;; esac
		key="${line%%=*}"
		[ "$key" != "$line" ] || { echo "    seal line without '=': $line"; return 1; }
		case " $SEAL_KEYS " in *" $key "*) ;; *) echo "    unknown seal key: $key"; return 1 ;; esac
		case "$seen" in *" $key "*) echo "    duplicate seal key: $key"; return 1 ;; esac
		seen="$seen$key "
	done <"$seal"
	for k in $SEAL_KEYS; do
		case "$seen" in *" $k "*) ;; *) echo "    the seal has no $k"; return 1 ;; esac
	done
}
seal_value() { sed -n "s/^$2=//p" "$1"; }

# checksums_problems <tag> <assetdir> [image-sha256]: zero when the checksums
# file holds exactly the lines shasum writes for the tarball and manifest
# assets now, followed, when an image hash is given, by exactly that image's
# line; and the directory holds nothing but those assets (the image only in
# its private directory, and only when a hash is given).
checksums_problems() {
	local tag="$1" dir="$2" isha="${3:-}" base sums img want got extra allowed
	base="$(asset_base "$tag")"
	sums="$(checksums_name "$tag")"
	img="$(image_name "$tag")"
	[ -f "$dir/$sums" ] || { echo "    no checksums file $dir/$sums"; return 1; }
	want="$(cd "$dir" && shasum -a 256 "$base.tar.gz" "$base.PAYLOAD-SHA256" 2>/dev/null)" ||
		{ echo "    the tarball or manifest asset is missing from $dir"; return 1; }
	[ -z "$isha" ] || want="$want"$'\n'"$isha  $img"
	got="$(cat "$dir/$sums")"
	if [ "$want" != "$got" ]; then
		echo "    $sums does not hold exactly the expected lines:"
		diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed -n 's/^\([<>]\)/      \1/p'
		return 1
	fi
	allowed=(-e "$base.tar.gz" -e "$base.PAYLOAD-SHA256" -e "$sums")
	[ -z "$isha" ] || allowed+=(-e "$IMAGE_DIR_NAME" -e "$IMAGE_DIR_NAME/$img")
	extra="$(cd "$dir" && find . -mindepth 1 | sed 's|^\./||' | grep -vxF "${allowed[@]}" || true)"
	[ -z "$extra" ] || { echo "    $dir holds files that are not release assets:"; printf '%s\n' "$extra" | sed 's/^/      /'; return 1; }
	if [ -n "$isha" ] && { [ -L "$dir/$IMAGE_DIR_NAME" ] || [ ! -d "$dir/$IMAGE_DIR_NAME" ]; }; then
		echo "    $dir/$IMAGE_DIR_NAME is not a directory"; return 1
	fi
}

# reset_checksums <tag> <assetdir>: drop any disk image line and image copy an
# earlier --upload (or anyone else) left, so the file again holds only the
# sealed two lines. An image reaches the upload only through --disk-image.
reset_checksums() {
	local tag="$1" dir="$2" sums img
	sums="$dir/$(checksums_name "$tag")"
	img="$(image_name "$tag")"
	[ -f "$sums" ] || return 0
	if ! { awk -v f="$img" '$2 != f' "$sums" >"$sums.tmp" && mv "$sums.tmp" "$sums"; }; then die "could not rewrite $sums"; fi
	rm -f "$dir/$img"
	rm -rf "${dir:?}/$IMAGE_DIR_NAME"
}

# verify_release <tree> <team>: stage.sh's Developer ID policy over the tree.
# A function so the self-test can stand in for it.
verify_release() { "$HERE/stage.sh" "$1" --verify-release "$2"; }

# upload_checks <repo-dir> <ref> <tag> <team> <stage-tree> <assetdir> <seal>:
# everything --upload proves before it touches gh, each failure a refusal.
# <ref> is refs/tags/<tag> outside the self-test, as for tag_binding_problems.
upload_checks() {
	local repo="$1" ref="$2" tag="$3" team="$4" tree="$5" dir="$6" seal="$7" problems="" base head k want got
	base="$(asset_base "$tag")"
	if ! problems="$(seal_problems "$seal")"; then
		printf '%s\n' "$problems" >&2
		refuse seal "--upload needs the seal --through-verify writes beside the assets; nothing was uploaded."
	fi
	if ! problems="$(tag_binding_problems "$repo" "$ref")"; then
		printf '%s\n' "$problems" >&2
		refuse tag-binding "the release must be uploaded from a clean worktree at exactly the commit $tag names."
	fi
	head="$(git -C "$repo" rev-parse --verify HEAD)"
	problems=""
	for k in $SEAL_KEYS; do
		case "$k" in
		tag) got="$tag" ;;
		head) got="$head" ;;
		payload_manifest_sha256) got="$(sha256_of "$tree/PAYLOAD-SHA256" 2>/dev/null || true)" ;;
		tarball_sha256) got="$(sha256_of "$dir/$base.tar.gz" 2>/dev/null || true)" ;;
		team_id) got="$team" ;;
		esac
		want="$(seal_value "$seal" "$k")"
		if [ -z "$got" ] || [ "$want" != "$got" ]; then
			problems="$problems    the seal's $k is '$want'; this run has '$got'"$'\n'
		fi
	done
	cmp -s "$tree/PAYLOAD-SHA256" "$dir/$base.PAYLOAD-SHA256" ||
		problems="$problems    the PAYLOAD-SHA256 asset differs from the stage tree's manifest"$'\n'
	if [ -n "$problems" ]; then
		printf '%s' "$problems" >&2
		refuse seal-mismatch "the tag, tree, assets or Team ID are not the ones --through-verify verified; nothing was uploaded."
	fi
	if ! problems="$(tree_manifest_problems "$tree" "$tree/PAYLOAD-SHA256")"; then
		printf '%s\n' "$problems" >&2
		refuse tree-changed "the stage tree no longer matches its PAYLOAD-SHA256; nothing was uploaded."
	fi
	if ! problems="$(tarball_problems "$dir/$base.tar.gz" "$tree/PAYLOAD-SHA256")"; then
		printf '%s\n' "$problems" >&2
		refuse tarball-mismatch "the tarball does not hold exactly the verified tree; nothing was uploaded."
	fi
	# An image line or copy left by an earlier run is never trusted: dropped
	# here, and only --disk-image adds one back, after its checks.
	reset_checksums "$tag" "$dir"
	if ! problems="$(checksums_problems "$tag" "$dir")"; then
		printf '%s\n' "$problems" >&2
		refuse checksums "the assets directory is not the one --through-verify packaged; nothing was uploaded."
	fi
	verify_release "$tree" "$team" ||
		refuse verify-release "stage.sh --verify-release $team fails on the stage tree; nothing was uploaded."
}

# developer_id_requirement <team>: the designated requirement the app's copy-out
# pins (Developer ID Application leaf, under Apple's Developer ID CA, for the
# Team ID).
developer_id_requirement() {
	printf 'anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "%s"' "$1"
}

# image_root_problems <mount> <tag> <team> <manifest>: the checks on the
# mounted image's contents. Prints every problem.
image_root_problems() {
	# set -e is inert here by design: callers run this in a command
	# substitution and test its status, so every check runs and reports, and
	# each failure fails closed through rc.
	local root="$1" tag="$2" team="$3" manifest="$4" app payload entries v rc=0
	app="$root/k3sm.app"
	entries="$(cd "$root" && find . -mindepth 1 -maxdepth 1 | sed 's|^\./||' | LC_ALL=C sort)"
	# .fseventsd is the one extra entry allowed, and only as a real directory.
	if [ -e "$root/.fseventsd" ] || [ -L "$root/.fseventsd" ]; then
		if [ -L "$root/.fseventsd" ] || [ ! -d "$root/.fseventsd" ]; then
			echo "    .fseventsd in the image is not a directory"; rc=1
		fi
		entries="$(printf '%s\n' "$entries" | grep -vxF .fseventsd || true)"
	fi
	[ "$entries" = $'Applications\nk3sm.app' ] ||
		{ echo "    the image root holds [${entries//$'\n'/, }], not exactly [Applications, k3sm.app] (and at most .fseventsd)"; rc=1; }
	if [ ! -L "$root/Applications" ] || [ "$(readlink "$root/Applications")" != /Applications ]; then
		echo "    Applications in the image is not a symlink to /Applications"; rc=1
	fi
	if [ -L "$app" ] || [ ! -d "$app" ]; then
		echo "    the image holds no k3sm.app directory"; return 1
	fi
	payload="$app/Contents/Resources/payload"
	if [ -L "$payload" ] || [ ! -d "$payload" ]; then
		echo "    k3sm.app has no Contents/Resources/payload directory"; rc=1
	else
		cmp -s "$payload/PAYLOAD-SHA256" "$manifest" ||
			{ echo "    the app's payload/PAYLOAD-SHA256 differs from the stage tree's manifest"; rc=1; }
		# tree_manifest_problems tolerates a Finder .DS_Store in a stage tree; the
		# app's payload is a sealed copy and must hold exactly the manifest's files.
		[ -z "$(find "$payload" -name .DS_Store | head -1)" ] ||
			{ echo "    k3sm.app's payload holds a .DS_Store"; rc=1; }
		tree_manifest_problems "$payload" "$manifest" || rc=1
	fi
	# CFBundleShortVersionString is a plain x.y.z, so a release candidate's app
	# carries the tag's core version; a final tag compares exactly.
	local want="${tag#v}"
	want="${want%-rc.*}"
	v="$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist" 2>/dev/null || true)"
	[ "$v" = "$want" ] || { echo "    the app's CFBundleShortVersionString is '$v', not '$want'"; rc=1; }
	codesign --verify --strict --deep -R="$(developer_id_requirement "$team")" "$app" >/dev/null 2>&1 ||
		{ echo "    codesign --verify --strict --deep rejects k3sm.app against the Developer ID requirement for $team"; rc=1; }
	xcrun stapler validate "$app" >/dev/null 2>&1 || { echo "    stapler validate rejects k3sm.app"; rc=1; }
	return "$rc"
}

# detach_image: detach and remove the private mount point, if any.
IMAGE_MNT="" IMAGE_ATTACHED=0
detach_image() {
	[ -n "$IMAGE_MNT" ] || return 0
	if [ "$IMAGE_ATTACHED" = 1 ]; then
		hdiutil detach "$IMAGE_MNT" >/dev/null 2>&1 || hdiutil detach -force "$IMAGE_MNT" >/dev/null 2>&1 ||
			echo "publish: could not detach $IMAGE_MNT" >&2
	fi
	rmdir "$IMAGE_MNT" 2>/dev/null || true
	IMAGE_MNT="" IMAGE_ATTACHED=0
}

# disk_image_problems <image> <tag> <team> <manifest>: the image-level checks,
# then the contents mounted read-only at a private mount point. Call it only
# inside a command substitution: it sets EXIT, HUP, INT and TERM traps that
# detach the image, and those must not replace the caller's.
disk_image_problems() {
	# set -e is inert here by design (the caller tests this function's status
	# from a command substitution): every check runs, and each failure fails
	# closed through rc.
	local img="$1" tag="$2" team="$3" manifest="$4" rc=0
	codesign --verify --strict -R="$(developer_id_requirement "$team")" "$img" >/dev/null 2>&1 ||
		{ echo "    codesign --verify --strict rejects the image against the Developer ID requirement for $team"; rc=1; }
	xcrun stapler validate "$img" >/dev/null 2>&1 || { echo "    stapler validate rejects the image"; rc=1; }
	spctl -a -t open --context context:primary-signature "$img" >/dev/null 2>&1 ||
		{ echo "    spctl -a -t open --context context:primary-signature rejects the image"; rc=1; }
	IMAGE_MNT="$(mktemp -d)"
	chmod 700 "$IMAGE_MNT"
	trap detach_image EXIT
	trap 'detach_image; exit 129' HUP
	trap 'detach_image; exit 130' INT TERM
	if hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$IMAGE_MNT" "$img" >/dev/null 2>&1; then
		IMAGE_ATTACHED=1
		image_root_problems "$IMAGE_MNT" "$tag" "$team" "$manifest" || rc=1
	else
		echo "    hdiutil cannot attach $img read-only"; rc=1
	fi
	detach_image
	trap - EXIT HUP INT TERM
	return "$rc"
}

# add_disk_image <file> <tag> <team> <manifest> <assetdir>: copy the image,
# mode 0444, into a private 0700 directory under the assets, run every check
# on that copy, hash it once into IMAGE_SHA256, and append its checksums line.
# upload re-hashes the same copy right before the draft and uploads exactly it.
IMAGE_SHA256=""
add_disk_image() {
	local src="$1" tag="$2" team="$3" manifest="$4" dir="$5" name idir copy problems
	name="$(image_name "$tag")"
	check_image_name "$src" "$tag"
	if [ -L "$src" ] || [ ! -f "$src" ]; then die "--disk-image $src is not a regular file"; fi
	idir="$dir/$IMAGE_DIR_NAME"
	copy="$idir/$name"
	[ ! -e "$idir" ] || die "$idir already exists"
	if ! { mkdir -m 700 "$idir" && cp "$src" "$copy.tmp" && chmod 444 "$copy.tmp" && mv "$copy.tmp" "$copy"; }; then
		die "could not copy the disk image into $idir"
	fi
	if ! problems="$(disk_image_problems "$copy" "$tag" "$team" "$manifest")"; then
		printf '%s\n' "$problems" >&2
		rm -rf "$idir"
		refuse image-unverified "the disk image failed its checks; nothing was uploaded."
	fi
	IMAGE_SHA256="$(sha256_of "$copy")"
	printf '%s  %s\n' "$IMAGE_SHA256" "$name" >>"$dir/$(checksums_name "$tag")" ||
		die "could not append the disk image to the checksums file"
}

# check_image_name <file> <tag>: the closed name, checked before anything else.
check_image_name() {
	local name
	name="$(image_name "$2")"
	[ "$(basename "$1")" = "$name" ] ||
		refuse image-name "the disk image must be named exactly $name, not $(basename "$1"); nothing was uploaded."
}

# run_upload <repo-dir> <ref> <tag> <team> <stage-tree> <repo> <notes> [image]:
# the whole --upload phase. <ref> is refs/tags/<tag> outside the self-test.
run_upload() {
	local rdir="$1" ref="$2" tag="$3" team="$4" tree="$5" repo="$6" notes="$7" img="${8:-}" assets
	assets="$tree.assets"
	[ -z "$img" ] || check_image_name "$img" "$tag"
	echo "==> check the seal, the tag binding, the tree and the assets"
	upload_checks "$rdir" "$ref" "$tag" "$team" "$tree" "$assets" "$tree.seal"
	IMAGE_SHA256=""
	if [ -n "$img" ]; then
		echo "==> check the disk image and add it to the assets"
		add_disk_image "$img" "$tag" "$team" "$tree/PAYLOAD-SHA256" "$assets"
	fi
	echo "==> upload: draft, verify, promote"
	upload "$tag" "$repo" "$notes" "$assets" "$tree" "$(seal_value "$tree.seal" tarball_sha256)" "$IMAGE_SHA256"
}

# ---- self-test ------------------------------------------------------------------
self_test() {
	local fails=0 passes=0 skips=0 T log out rc sign="$HERE/sign.sh" tag=v0.0.0 repo=example/k3sm
	# A case that gets PAST a refusal runs only when this self-test was itself
	# started attended (neither variable set). The self-test never unsets or
	# overrides CLAUDECODE or K3SM_AUTO to get past a refusal; under automation
	# such a case prints a SKIP line and counts as neither a pass nor a fail.
	# Every refusal case runs everywhere.
	local attended=0
	if [ -z "${CLAUDECODE+x}" ] && [ -z "${K3SM_AUTO+x}" ]; then attended=1; fi
	T="$(mktemp -d)"
	SELFTEST_TMP="$T"
	trap 'rm -rf "$SELFTEST_TMP"' EXIT
	log="$T/tool.log"
	ok() { echo "  ok   $1"; passes=$((passes + 1)); }
	bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
	skip_attended() { echo "  SKIP (attended only): $1"; skips=$((skips + 1)); }

	# Fakes: record argv and exit 97. gh answers `release view` from
	# $FAKE_GH_VIEW and, with FAKE_GH_CREATE_OK=1, accepts `release create`.
	# codesign --verify, xcrun stapler validate and spctl succeed only with
	# FAKE_CODESIGN_VERIFY_OK, FAKE_STAPLER_OK and FAKE_SPCTL_OK set to 1, and
	# codesign only against a -R requirement naming its fake signer's team.
	# hdiutil attach "mounts" an image file whose first line is
	# `FIXTURE <dir>` by copying <dir> to the mount point; detach empties it.
	mkdir "$T/fakes"
	for tool in notarytool security ditto; do
		# shellcheck disable=SC2016 # the $* and $FAKE_TOOL_LOG belong to the fake
		printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s $*" >>"$FAKE_TOOL_LOG"\nexit 97\n' "$tool" >"$T/fakes/$tool"
	done
	cat >"$T/fakes/codesign" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "codesign $*" >>"$FAKE_TOOL_LOG"
{ [ "$1" = --verify ] && [ "${FAKE_CODESIGN_VERIFY_OK:-}" = 1 ]; } || exit 97
# The fake signer's Team ID: FAKE_CODESIGN_TEAM, or FAKE_CODESIGN_IMAGE_TEAM
# for a .dmg; a -R requirement naming another team fails as codesign does.
signer="${FAKE_CODESIGN_TEAM:-ABCDE12345}"
case "${!#}" in *.dmg) signer="${FAKE_CODESIGN_IMAGE_TEAM:-$signer}" ;; esac
for a in "$@"; do
	case "$a" in -R=*) [[ "$a" == *"subject.OU] = \"$signer\""* ]] || exit 3 ;; esac
done
exit 0
EOF
	cat >"$T/fakes/xcrun" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "xcrun $*" >>"$FAKE_TOOL_LOG"
[ "$1 $2" = "stapler validate" ] && [ "${FAKE_STAPLER_OK:-}" = 1 ] && exit 0
exit 97
EOF
	cat >"$T/fakes/spctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "spctl $*" >>"$FAKE_TOOL_LOG"
[ "${FAKE_SPCTL_OK:-}" = 1 ] && exit 0
exit 97
EOF
	cat >"$T/fakes/hdiutil" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "hdiutil $*" >>"$FAKE_TOOL_LOG"
case "$1" in
attach)
	shift
	mnt="" img=""
	while [ $# -gt 0 ]; do
		case "$1" in -mountpoint) mnt="$2"; shift 2 ;; -*) shift ;; *) img="$1"; shift ;; esac
	done
	src="$(sed -n '1s/^FIXTURE //p' "$img" 2>/dev/null)"
	[ -n "$mnt" ] && [ -d "$mnt" ] && [ -n "$src" ] && [ -d "$src" ] || exit 1
	cp -R "$src/." "$mnt/" || exit 1
	exit 0
	;;
detach)
	mnt="${!#}"
	[ -d "$mnt" ] || exit 1
	find "$mnt" -mindepth 1 -delete
	exit 0
	;;
esac
exit 97
EOF
	# With FAKE_GH_UPLOADED set, `release create` records the asset files it was
	# given there, and `release view` (when FAKE_GH_VIEW is unset) answers with
	# exactly those assets, filtered through the jq program FAKE_GH_VIEW_JQ.
	cat >"$T/fakes/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "gh $*" >>"$FAKE_TOOL_LOG"
case "$1 $2" in
"release view")
	[ -n "${FAKE_GH_VIEW:-}" ] && cat "$FAKE_GH_VIEW" && exit 0
	if [ -n "${FAKE_GH_UPLOADED:-}" ] && [ -f "$FAKE_GH_UPLOADED" ]; then
		a="[]"
		while IFS= read -r f; do
			a="$(jq -c --arg n "$(basename "$f")" --argjson s "$(stat -f %z "$f")" --arg d "sha256:$(shasum -a 256 "$f" | cut -d' ' -f1)" \
				'. + [{name: $n, state: "uploaded", size: $s, digest: $d}]' <<<"$a")"
		done <"$FAKE_GH_UPLOADED"
		jq -c "${FAKE_GH_VIEW_JQ:-.}" <<<"{\"isDraft\":true,\"assets\":$a}" && exit 0
	fi
	;;
"release create")
	if [ "${FAKE_GH_CREATE_OK:-}" = 1 ]; then
		prev=""
		for a in "$@"; do
			[ "$prev" != --notes-file ] && [ -f "$a" ] && [ -n "${FAKE_GH_UPLOADED:-}" ] && printf '%s\n' "$a" >>"$FAKE_GH_UPLOADED"
			prev="$a"
		done
		exit 0
	fi
	;;
"release edit") [ "${FAKE_GH_EDIT_OK:-}" = 1 ] && exit 0 ;;
esac
exit 97
EOF
	chmod +x "$T/fakes/"*
	export FAKE_TOOL_LOG="$log"
	local FPATH="$T/fakes:$PATH"

	# Run sign.sh on a pty that answers every prompt with $1, so /dev/tty opens
	# and the typed Team ID is controlled. The feeder repeats the line until
	# script(1) exits, because input written before the pty is set up is lost.
	on_pty() {
		local answer="$1"; shift
		{
			local i=0
			while [ "$i" -lt 100 ]; do
				printf '%s\n' "$answer" || break
				perl -e 'select(undef, undef, undef, 0.1)'
				i=$((i + 1))
			done
		} 2>/dev/null | script -q /dev/null "$@" 2>&1 | tr -d '\r'
		return "${PIPESTATUS[1]}"
	}
	# Run a command in a new session with no controlling terminal.
	no_tty() { perl -MPOSIX -e 'my $p = fork; if ($p) { waitpid($p, 0); exit($? >> 8) } POSIX::setsid(); exec @ARGV' "$@" </dev/null 2>&1; }

	local ID="Developer ID Application: Example (ABCDE12345)" TEAM=ABCDE12345
	mkdir "$T/tree"

	# expect_refusal <name> <token> <output> <rc>
	expect_refusal() {
		if [ "$4" -ne 0 ] && grep -q "REFUSE: $2" <<<"$3" && [ ! -s "$log" ]; then
			ok "$1"
		else
			bad "$1 (rc=$4, log: $(tr '\n' ';' <"$log" 2>/dev/null))"; printf '%s\n' "$3" | sed 's/^/       /'
		fi
		: >"$log"
	}

	echo "sign.sh refusals"
	: >"$log"
	rc=0; out="$(on_pty "$TEAM" env -u K3SM_AUTO CLAUDECODE=1 PATH="$FPATH" bash "$sign" --identity "$ID" --team-id "$TEAM" "$T/tree")" || rc=$?
	expect_refusal "CLAUDECODE=1 refuses on a terminal with the right Team ID typed" automation-env "$out" "$rc"
	rc=0; out="$(on_pty "$TEAM" env -u CLAUDECODE K3SM_AUTO= PATH="$FPATH" bash "$sign" --identity "$ID" --team-id "$TEAM" "$T/tree")" || rc=$?
	expect_refusal "K3SM_AUTO set but empty refuses" automation-env "$out" "$rc"
	rc=0; out="$(on_pty "$TEAM" env -u CLAUDECODE K3SM_AUTO=1 PATH="$FPATH" bash "$sign" --self-test)" || rc=$?
	expect_refusal "the refusal precedes argument parsing (even --self-test is refused)" automation-env "$out" "$rc"
	rc=0; out="$(no_tty env -u CLAUDECODE -u K3SM_AUTO PATH="$FPATH" bash "$sign" --identity "$ID" --team-id "$TEAM" "$T/tree")" || rc=$?
	expect_refusal "no controlling terminal refuses" no-tty "$out" "$rc"
	rc=0; out="$(on_pty "ZYXWV98765" env -u CLAUDECODE -u K3SM_AUTO PATH="$FPATH" bash "$sign" --identity "$ID" --team-id "$TEAM" "$T/tree")" || rc=$?
	expect_refusal "a wrong typed Team ID refuses" team-id-mismatch "$out" "$rc"
	rc=0; out="$(on_pty "" env -u CLAUDECODE -u K3SM_AUTO PATH="$FPATH" bash "$sign" --identity "$ID" --team-id "$TEAM" "$T/tree")" || rc=$?
	expect_refusal "an empty typed Team ID refuses" team-id-mismatch "$out" "$rc"
	# Positive control: with the right answer the guard passes and the script
	# stops at its first post-guard check (no manifest), still before any tool.
	# Without this, every refusal above could be passing for an unrelated reason.
	# It runs past the refusal, so it runs attended only, with the environment
	# exactly as the self-test inherited it.
	local control="control: the typed Team ID passes the guard, which then stops before any tool"
	if [ "$attended" = 1 ]; then
		rc=0; out="$(on_pty "$TEAM" env PATH="$FPATH" bash "$sign" --identity "$ID" --team-id "$TEAM" "$T/tree")" || rc=$?
		if [ "$rc" -ne 0 ] && ! grep -q REFUSE <<<"$out" && grep -q "has no PAYLOAD-SHA256" <<<"$out" && [ ! -s "$log" ]; then
			ok "$control"
		else
			bad "$control (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
	else
		skip_attended "$control"
	fi
	: >"$log"

	echo "publish.sh refusals"
	rc=0; out="$(env -u K3SM_AUTO CLAUDECODE=1 PATH="$FPATH" bash "$HERE/publish.sh" --version "$tag" 2>&1)" || rc=$?
	expect_refusal "CLAUDECODE=1 refuses before staging" automation-env "$out" "$rc"
	rc=0; out="$(env -u CLAUDECODE K3SM_AUTO= PATH="$FPATH" bash "$HERE/publish.sh" --version "$tag" 2>&1)" || rc=$?
	expect_refusal "K3SM_AUTO set but empty refuses" automation-env "$out" "$rc"
	rc=0; out="$(no_tty env -u CLAUDECODE -u K3SM_AUTO PATH="$FPATH" bash "$HERE/publish.sh" --version "$tag")" || rc=$?
	expect_refusal "no controlling terminal refuses" no-tty "$out" "$rc"
	local phase
	for phase in --through-verify --upload; do
		rc=0; out="$(env -u K3SM_AUTO CLAUDECODE=1 PATH="$FPATH" bash "$HERE/publish.sh" "$phase" --version "$tag" 2>&1)" || rc=$?
		expect_refusal "$phase: CLAUDECODE=1 refuses" automation-env "$out" "$rc"
		rc=0; out="$(env -u CLAUDECODE K3SM_AUTO=1 PATH="$FPATH" bash "$HERE/publish.sh" "$phase" --version "$tag" 2>&1)" || rc=$?
		expect_refusal "$phase: K3SM_AUTO=1 refuses" automation-env "$out" "$rc"
		rc=0; out="$(no_tty env -u CLAUDECODE -u K3SM_AUTO PATH="$FPATH" bash "$HERE/publish.sh" "$phase" --version "$tag")" || rc=$?
		expect_refusal "$phase: no controlling terminal refuses" no-tty "$out" "$rc"
	done

	# ---- the shipped bytes against the verified tree ----
	echo "tarball and tree against PAYLOAD-SHA256"
	# mk_payload <tree>: a small tree, its manifest inside, and the copy beside it
	mk_payload() {
		local d="$1"
		mkdir -p "$d/cp-payload"
		printf 'k3sm binary\n' >"$d/k3sm"
		printf 'apiserver binary\n' >"$d/cp-payload/kube-apiserver"
		{
			echo "# go1.0 (fixture)"
			(cd "$d" && find . -type f ! -name PAYLOAD-SHA256 | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done)
		} >"$d.manifest.tmp"
		mv "$d.manifest.tmp" "$d/PAYLOAD-SHA256"
		cp "$d/PAYLOAD-SHA256" "$d.PAYLOAD-SHA256"
	}
	# package_case <name> <tree> <tag> <outdir> <want: pass|refuse>
	package_case() {
		rc=0
		out="$( (PATH="$FPATH" package_assets "$2" "$3" "$4") 2>&1)" || rc=$?
		if [ "$5" = pass ]; then
			if [ "$rc" -eq 0 ] && [ "$(find "$4" -type f | wc -l | tr -d ' ')" = 3 ]; then ok "$1"; else
				bad "$1 (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
			fi
		elif [ "$rc" -ne 0 ] && grep -q "REFUSE: tarball-mismatch" <<<"$out"; then ok "$1"; else
			bad "$1 (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
	}
	local P="$T/payload/tree" Q
	mk_payload "$P"
	package_case "control: a tarball of the verified tree passes the extract-and-compare" "$P" "$tag" "$T/assets" pass
	Q="$T/tampered/tree"; mk_payload "$Q"; printf 'changed\n' >"$Q/k3sm"
	package_case "a file changed after the manifest refuses" "$Q" "$tag" "$T/tampered.assets" refuse
	Q="$T/extra/tree"; mk_payload "$Q"; printf 'stray\n' >"$Q/cp-payload/unlisted"
	package_case "a file the manifest does not list refuses" "$Q" "$tag" "$T/extra.assets" refuse
	Q="$T/missing/tree"; mk_payload "$Q"; rm "$Q/cp-payload/kube-apiserver"
	package_case "a manifest-listed file missing from the tree refuses" "$Q" "$tag" "$T/missing.assets" refuse
	Q="$T/link/tree"; mk_payload "$Q"; ln -s k3sm "$Q/k3sm-link"
	package_case "a symlink in the tree refuses" "$Q" "$tag" "$T/link.assets" refuse
	# A tree changed after packaging is caught again right before upload,
	# before any gh call.
	Q="$T/late/tree"; mk_payload "$Q"
	(PATH="$FPATH" package_assets "$Q" "$tag" "$T/late.assets") >/dev/null 2>&1
	printf 'changed late\n' >"$Q/cp-payload/kube-apiserver"
	printf 'notes\n' >"$T/notes.md"
	: >"$log"
	rc=0
	out="$( (PATH="$FPATH" FAKE_GH_CREATE_OK=1 upload "$tag" "$repo" "$T/notes.md" "$T/late.assets" "$Q" "$(sha256_of "$T/late.assets/$(asset_base "$tag").tar.gz")") 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ] && grep -q "REFUSE: tree-changed" <<<"$out" && [ ! -s "$log" ]; then
		ok "a stage tree changed after packaging refuses before any upload"
	else
		bad "late tree change (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	# A manifest whose last line has no trailing newline still has that line
	# checked: an edited last file refuses.
	E="$T/eol"; mkdir -p "$E"
	printf 'first\n' >"$E/a"; printf 'last\n' >"$E/b"
	printf '%s  a\n%s  b' "$(sha256_of "$E/a")" "$(sha256_of "$E/b")" >"$T/eol.manifest"
	if tree_manifest_problems "$E" "$T/eol.manifest" >/dev/null 2>&1; then
		printf 'edited\n' >"$E/b"
		if ! tree_manifest_problems "$E" "$T/eol.manifest" >/dev/null 2>&1; then
			ok "a manifest without a trailing newline still checks its last file"
		else
			bad "an edited last file passed a manifest without a trailing newline"
		fi
	else
		bad "an untouched tree failed a manifest without a trailing newline"
	fi

	# ---- entitlements, against canned codesign output ----
	echo "entitlements allowlist"
	local plist_head='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>'
	local virt='<key>com.apple.security.virtualization</key><true/>'
	# ent_case <name> <relpath> <dict-body|-none-|raw:<text>> <want: pass|refuse>
	ent_case() {
		local xml
		case "$3" in
		-none-) xml="" ;;
		raw:*) xml="${3#raw:}" ;;
		*) xml="$plist_head$3</dict></plist>" ;;
		esac
		rc=0
		out="$(entitlement_problems "$2" "$xml")" || rc=$?
		if { [ "$4" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$4" = refuse ] && [ "$rc" -ne 0 ]; }; then ok "$1"; else
			bad "$1 (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
	}
	ent_case "control: k3sm-vmhost with exactly the virtualization entitlement passes" k3sm-vmhost "$virt" pass
	ent_case "k3sm-vmhost without it refuses" k3sm-vmhost -none- refuse
	ent_case "k3sm-vmhost with an extra entitlement refuses" k3sm-vmhost "$virt<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>" refuse
	ent_case "k3sm-vmhost with virtualization false refuses" k3sm-vmhost '<key>com.apple.security.virtualization</key><false/>' refuse
	ent_case "control: k3sm with no entitlements passes" k3sm -none- pass
	ent_case "control: a dylib with an empty entitlement dictionary passes" libk3sm_getaddrinfo_shim.dylib "" pass
	ent_case "k3sm with the virtualization entitlement refuses" k3sm "$virt" refuse
	ent_case "a cp-payload binary with library validation disabled refuses" cp-payload/kube-apiserver '<key>com.apple.security.cs.disable-library-validation</key><true/>' refuse
	ent_case "unreadable entitlements output refuses" k3sm "raw:not a plist <" refuse
	# The walk fails closed when codesign cannot read a Mach-O's entitlements
	# (the fake codesign exits 97). A copy of bash stands in for a Mach-O.
	Q="$T/ent/tree"; mkdir -p "$Q"
	cp "$(command -v bash)" "$Q/k3sm"
	(cd "$Q" && shasum -a 256 k3sm >PAYLOAD-SHA256)
	: >"$log"
	rc=0
	out="$( (PATH="$FPATH" entitlements_problems "$Q") 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ] && grep -q "could not read its entitlements" <<<"$out" && grep -q "^codesign -d --entitlements - --xml $Q/k3sm\$" "$log"; then
		ok "a failed entitlements read-back refuses"
	else
		bad "entitlements walk (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	: >"$log"

	# ---- the tag binding, against a fixture repository ----
	echo "tag binding"
	local G="$T/repo"
	gitf() { git -C "$G" -c user.name=fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false "$@"; }
	git init -q "$G"
	printf 'one\n' >"$G/f"
	gitf add f && gitf commit -q -m one
	gitf branch fixture
	# bind_case <name> <ref> <want: pass|refuse>
	bind_case() {
		rc=0
		out="$(tag_binding_problems "$G" "$2")" || rc=$?
		if { [ "$3" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$3" = refuse ] && [ "$rc" -ne 0 ]; }; then ok "$1"; else
			bad "$1 (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
	}
	bind_case "control: a clean worktree with the ref at HEAD passes" refs/heads/fixture pass
	bind_case "a ref that does not exist refuses" refs/heads/no-such-ref refuse
	printf 'untracked\n' >"$G/new"
	bind_case "an untracked file refuses" refs/heads/fixture refuse
	rm "$G/new"
	printf 'edited\n' >"$G/f"
	bind_case "a modified tracked file refuses" refs/heads/fixture refuse
	gitf commit -q -am two
	bind_case "a ref behind HEAD refuses" refs/heads/fixture refuse

	# ---- the draft check and promote, against canned gh JSON ----
	echo "draft-then-promote"
	local A="$T/assets" rctag=v0.0.1-rc.1 A2="$T/rc.assets"
	(PATH="$FPATH" package_assets "$P" "$rctag" "$A2") >/dev/null 2>&1
	# draft_json <assetdir> <tag> [jq filter applied to the good draft]
	draft_json() {
		local d="$1" t="$2" n f=()
		while IFS= read -r n; do
			f+=("{\"name\":\"$n\",\"state\":\"uploaded\",\"size\":$(stat -f %z "$(asset_path "$d" "$t" "$n")"),\"digest\":\"sha256:$(shasum -a 256 "$(asset_path "$d" "$t" "$n")" | cut -d' ' -f1)\"}")
		done < <(expected_assets "$t" "$d")
		local IFS=,
		jq -c "${3:-.}" <<<"{\"isDraft\":true,\"assets\":[${f[*]}]}"
	}
	# promote_case <name> <json> <want: pass|refuse> [tag] [assetdir] [expected latest flag]
	promote_case() {
		local t="${4:-$tag}" d="${5:-$A}" latest="${6:---latest}"
		printf '%s\n' "$2" >"$T/view.json"
		: >"$log"
		rc=0
		out="$( (PATH="$FPATH" FAKE_GH_VIEW="$T/view.json" FAKE_GH_EDIT_OK=1 promote "$t" "$repo" "$d") 2>&1)" || rc=$?
		if [ "$3" = pass ]; then
			if [ "$rc" -eq 0 ] && grep -qx -- "gh release edit $t --repo $repo --draft=false $latest" "$log"; then ok "$1"; else
				bad "$1 (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
			fi
		else
			if [ "$rc" -ne 0 ] && grep -q "REFUSE: draft-unverified" <<<"$out" && ! grep -q -- '--draft=false' "$log" &&
				! grep -q '^gh release edit' "$log"; then ok "$1"; else
				bad "$1 (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
			fi
		fi
	}
	promote_case "control: a complete, matching final draft is promoted with --latest" "$(draft_json "$A" "$tag")" pass
	promote_case "a release candidate is promoted with --latest=false" "$(draft_json "$A2" "$rctag")" pass "$rctag" "$A2" --latest=false
	promote_case "a wrong asset digest refuses" "$(draft_json "$A" "$tag" '.assets[0].digest = "sha256:0000"')" refuse
	promote_case "a missing asset refuses" "$(draft_json "$A" "$tag" 'del(.assets[1])')" refuse
	promote_case "an extra asset refuses" "$(draft_json "$A" "$tag" '.assets += [.assets[0] | .name = "extra.bin"]')" refuse
	promote_case "a partially uploaded asset refuses" "$(draft_json "$A" "$tag" '.assets[0].state = "starter"')" refuse
	promote_case "a size mismatch refuses" "$(draft_json "$A" "$tag" '.assets[2].size = 1')" refuse
	promote_case "a release that is no longer a draft refuses" "$(draft_json "$A" "$tag" '.isDraft = false')" refuse
	promote_case "no digest and a failed download refuses" "$(draft_json "$A" "$tag" 'del(.assets[0].digest)')" refuse
	if grep -q "^gh release download $tag" "$log"; then ok "a missing digest falls back to downloading the asset"; else bad "no download fallback"; fi
	promote_case "unreadable JSON refuses" "not json" refuse

	# upload_case <name> <tag> <assetdir> <view-json> -> sets rc, out; log holds the gh calls
	upload_case() {
		printf '%s\n' "$4" >"$T/view.json"
		: >"$log"
		rc=0
		out="$( (PATH="$FPATH" FAKE_GH_VIEW="$T/view.json" FAKE_GH_CREATE_OK=1 FAKE_GH_EDIT_OK=1 upload "$2" "$repo" "$T/notes.md" "$3" "$P" "$(sha256_of "$3/$(asset_base "$2").tar.gz")") 2>&1)" || rc=$?
	}
	# The full upload: the create succeeds, the draft read back is bad.
	upload_case x "$tag" "$A" "$(draft_json "$A" "$tag" '.assets[0].digest = "sha256:0000"')"
	if [ "$rc" -ne 0 ] && grep -q -- "^gh release create $tag .*--draft" "$log" &&
		! grep '^gh release create' "$log" | grep -qv -- ' --draft ' && ! grep -q -- '--draft=false' "$log"; then
		ok "upload creates only a draft and does not promote a bad one"
	else
		bad "upload with a bad draft (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	upload_case x "$tag" "$A" "$(draft_json "$A" "$tag")"
	if [ "$rc" -eq 0 ] && grep -q "^gh release create $tag .* --draft --verify-tag " "$log" && ! grep -q -- '--prerelease' "$log" &&
		grep -qx -- "gh release edit $tag --repo $repo --draft=false --latest" "$log"; then
		ok "a final version is created without --prerelease and promoted with --latest"
	else
		bad "final upload (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	upload_case x "$rctag" "$A2" "$(draft_json "$A2" "$rctag")"
	if [ "$rc" -eq 0 ] && grep -q "^gh release create $rctag .* --draft --prerelease --verify-tag " "$log" &&
		grep -qx -- "gh release edit $rctag --repo $repo --draft=false --latest=false" "$log"; then
		ok "a release candidate is created with --prerelease and promoted with --latest=false"
	else
		bad "rc upload (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	: >"$log"
	rc=0
	out="$( (PATH="$FPATH" FAKE_GH_VIEW="$T/view.json" upload "$tag" "$repo" "$T/notes.md" "$A" "$P" "$(sha256_of "$A/$(asset_base "$tag").tar.gz")") 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ] && [ "$(grep -c . "$log")" -eq 1 ] && grep -q '^gh release create' "$log"; then
		ok "a failed create stops before any read-back or promote"
	else
		bad "failed create (rc=$rc, log: $(tr '\n' ';' <"$log"))"
	fi
	: >"$log"

	# ---- the two phases: the seal, --upload, and the disk image ----
	echo "two phases: the seal, --upload and the disk image"
	# A fresh fixture repository, clean, with the fixture ref at HEAD; it stands
	# in for the tag as in the tag binding cases.
	local G2="$T/repo2" ref2=refs/heads/fixture head2
	git init -q "$G2"
	printf 'one\n' >"$G2/f"
	git -C "$G2" -c user.name=fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false add f
	git -C "$G2" -c user.name=fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -q -m one
	git -C "$G2" branch fixture
	head2="$(git -C "$G2" rev-parse HEAD)"
	# mk_sealed <dir>: what --through-verify leaves: <dir>/tree, its assets and seal
	mk_sealed() {
		mk_payload "$1/tree"
		(PATH="$FPATH" package_assets "$1/tree" "$tag" "$1/tree.assets") >/dev/null 2>&1
		write_seal "$1/tree.seal" "$tag" "$head2" "$1/tree/PAYLOAD-SHA256" "$1/tree.assets/$(asset_base "$tag").tar.gz" "$TEAM"
	}
	# mk_image <dir> <tree> [version]: a fixture image of k3sm.app around <tree>,
	# at <dir>/out/<the closed name>; the fake hdiutil mounts <dir>/root
	mk_image() {
		local r="$1/root" v="${3:-${tag#v}}"
		mkdir -p "$r/k3sm.app/Contents/Resources" "$1/out"
		cp -R "$2" "$r/k3sm.app/Contents/Resources/payload"
		printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>%s</string></dict></plist>\n' "$v" >"$r/k3sm.app/Contents/Info.plist"
		ln -s /Applications "$r/Applications"
		printf 'FIXTURE %s\n' "$r" >"$1/out/$(image_name "$tag")"
	}
	# run_up <tree> [image]: the whole --upload phase, every fake accepting
	# unless the caller sets cs=0, st=0 or sp=0; vr=real runs stage.sh's own
	# --verify-release, otherwise a stand-in accepts. view_jq filters the
	# read-back. Sets rc and out; log holds the tool calls.
	run_up() {
		: >"$log"; rm -f "$T/uploaded"
		rc=0
		out="$( (
			if [ "${vr:-}" != real ]; then verify_release() { :; }; fi
			PATH="$FPATH" FAKE_GH_UPLOADED="$T/uploaded" FAKE_GH_VIEW_JQ="${view_jq:-.}" FAKE_GH_CREATE_OK=1 FAKE_GH_EDIT_OK=1 \
				FAKE_CODESIGN_VERIFY_OK="${cs:-1}" FAKE_STAPLER_OK="${st:-1}" FAKE_SPCTL_OK="${sp:-1}" \
				run_upload "$G2" "$ref2" "$tag" "${team:-$TEAM}" "$1" "$repo" "$T/notes.md" "${2:-}"
		) 2>&1)" || rc=$?
	}
	# up_refuses <name> <token>: the last run_up refused with <token> and made no gh call
	up_refuses() {
		if [ "$rc" -ne 0 ] && grep -q "REFUSE: $2" <<<"$out" && ! grep -q '^gh ' "$log"; then ok "$1"; else
			bad "$1 (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
	}
	# up_promoted <name> <asset-count>: the last run_up created a draft of exactly
	# that many assets and promoted it
	up_promoted() {
		if [ "$rc" -eq 0 ] && [ "$(grep -c . "$T/uploaded" 2>/dev/null)" = "$2" ] &&
			grep -qx -- "gh release edit $tag --repo $repo --draft=false --latest" "$log"; then ok "$1"; else
			bad "$1 (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
	}
	local W n=0 k img mnt
	# fresh <var>: a new sealed fixture directory in <var>
	fresh() { n=$((n + 1)); W="$T/ph$n"; mk_sealed "$W"; }

	fresh
	if [ -z "$(seal_problems "$W/tree.seal")" ] && [ "$(seal_value "$W/tree.seal" tag)" = "$tag" ] &&
		[ "$(seal_value "$W/tree.seal" head)" = "$head2" ] && [ "$(seal_value "$W/tree.seal" team_id)" = "$TEAM" ] &&
		[ "$(seal_value "$W/tree.seal" payload_manifest_sha256)" = "$(sha256_of "$W/tree/PAYLOAD-SHA256")" ] &&
		[ "$(seal_value "$W/tree.seal" tarball_sha256)" = "$(sha256_of "$W/tree.assets/$(asset_base "$tag").tar.gz")" ]; then
		ok "control: the seal holds the tag, HEAD, manifest hash, tarball hash and Team ID"
	else
		bad "seal contents: $(tr '\n' ';' <"$W/tree.seal")"
	fi
	run_up "$W/tree"
	up_promoted "control: --upload without an image uploads three assets and promotes" 3

	fresh; mk_image "$W/img" "$W/tree"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_promoted "control: --upload with a good image uploads four assets and promotes" 4
	img="$W/tree.assets/$IMAGE_DIR_NAME/$(image_name "$tag")"
	if [ "$(stat -f %Lp "$W/tree.assets/$IMAGE_DIR_NAME")" = 700 ] && [ "$(stat -f %Lp "$img")" = 444 ]; then
		ok "the image is checked and uploaded from a mode 0444 copy in a private 0700 directory"
	else
		bad "image copy modes: dir $(stat -f %Lp "$W/tree.assets/$IMAGE_DIR_NAME" 2>&1), file $(stat -f %Lp "$img" 2>&1)"
	fi
	if [ "$(grep -c . "$W/tree.assets/$(checksums_name "$tag")")" = 3 ] &&
		grep -qx "$(sha256_of "$img")  $(image_name "$tag")" "$W/tree.assets/$(checksums_name "$tag")" &&
		grep -qxF "$img" "$T/uploaded"; then
		ok "the image's checksums line is computed by publish.sh and the image is uploaded"
	else
		bad "image checksums line: $(tr '\n' ';' <"$W/tree.assets/$(checksums_name "$tag")")"
	fi
	mnt="$(sed -n 's/^hdiutil attach -readonly -nobrowse -noautoopen -mountpoint \([^ ]*\) .*/\1/p' "$log")"
	if [ -n "$mnt" ] && grep -qx "hdiutil attach -readonly -nobrowse -noautoopen -mountpoint $mnt $img" "$log" &&
		grep -qx "hdiutil detach $mnt" "$log" && [ ! -e "$mnt" ]; then
		ok "the image is attached read-only, -nobrowse -noautoopen, at a private mount point, then detached and removed"
	else
		bad "hdiutil calls (mnt=$mnt, log: $(tr '\n' ';' <"$log"))"
	fi
	if grep -qxF "codesign --verify --strict --deep -R=$(developer_id_requirement "$TEAM") $mnt/k3sm.app" "$log" &&
		grep -qxF "codesign --verify --strict -R=$(developer_id_requirement "$TEAM") $img" "$log" &&
		grep -qxF "xcrun stapler validate $mnt/k3sm.app" "$log" && grep -qxF "xcrun stapler validate $img" "$log" &&
		grep -qxF "spctl -a -t open --context context:primary-signature $img" "$log"; then
		ok "codesign checks app and image against the Developer ID requirement for the Team ID; stapler and spctl too"
	else
		bad "signature checks (log: $(tr '\n' ';' <"$log"))"
	fi

	fresh; mk_image "$W/img" "$W/tree"
	mv "$W/img/out/$(image_name "$tag")" "$W/img/out/k3sm.dmg"
	run_up "$W/tree" "$W/img/out/k3sm.dmg"
	up_refuses "an image not named k3sm_<version>_darwin_arm64.dmg refuses" image-name
	grep -q '^hdiutil ' "$log" && bad "a misnamed image was mounted"

	fresh; rm "$W/tree.seal"
	run_up "$W/tree"
	up_refuses "a missing seal refuses" seal
	fresh; echo "team_id=$TEAM" >>"$W/tree.seal"
	run_up "$W/tree"
	up_refuses "a seal with a duplicate key refuses" seal
	for k in $SEAL_KEYS; do
		fresh
		sed "s/^$k=.*/$k=0000000000/" "$W/tree.seal" >"$W/seal.tmp" && mv "$W/seal.tmp" "$W/tree.seal"
		run_up "$W/tree"
		up_refuses "a seal whose $k differs refuses" seal-mismatch
	done
	fresh
	team=ZYXWV98765 run_up "$W/tree"
	up_refuses "an --upload with another Team ID than the sealed one refuses" seal-mismatch

	fresh; printf 'changed between the phases\n' >"$W/tree/k3sm"
	run_up "$W/tree"
	up_refuses "a stage tree changed between the phases refuses" tree-changed
	fresh; printf 'changed in step\n' >"$W/tree/k3sm"
	(cd "$W/tree" && find . -type f ! -name PAYLOAD-SHA256 | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done) >"$W/m.tmp"
	mv "$W/m.tmp" "$W/tree/PAYLOAD-SHA256"
	run_up "$W/tree"
	up_refuses "a stage tree edited in step with its manifest refuses" seal-mismatch
	fresh
	vr=real run_up "$W/tree"
	up_refuses "an unsigned tree fails the re-run of stage.sh --verify-release" verify-release
	fresh; printf 'dirty\n' >"$G2/untracked"
	run_up "$W/tree"
	up_refuses "a dirty worktree fails the re-run of the tag binding" tag-binding
	rm "$G2/untracked"
	fresh; printf 'stray\n' >"$W/tree.assets/stray.bin"
	run_up "$W/tree"
	up_refuses "a file in the assets that is not a release asset refuses" checksums
	fresh; echo "$(printf '0%.0s' $(seq 64))  extra.bin" >>"$W/tree.assets/$(checksums_name "$tag")"
	run_up "$W/tree"
	up_refuses "a checksums line added after packaging refuses" checksums
	# An image dropped into the assets with its line after --through-verify is
	# discarded, never uploaded: only --disk-image adds one, and checks it.
	fresh; printf 'unchecked image\n' >"$W/tree.assets/$(image_name "$tag")"
	(cd "$W/tree.assets" && shasum -a 256 "$(image_name "$tag")" >>"$(checksums_name "$tag")")
	run_up "$W/tree"
	up_promoted "an image added to the assets after the checksums were written is not uploaded" 3

	fresh; mk_image "$W/img" "$W/tree"; printf 'stray\n' >"$W/img/root/k3sm.app/Contents/Resources/payload/extra"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image whose app payload holds an extra file refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"; printf 'changed\n' >"$W/img/root/k3sm.app/Contents/Resources/payload/cp-payload/kube-apiserver"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image whose app payload holds a changed file refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"; printf 'finder\n' >"$W/img/root/k3sm.app/Contents/Resources/payload/.DS_Store"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image whose app payload holds a .DS_Store refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree" 9.9.9
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image whose app version differs from the tag refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"; printf 'readme\n' >"$W/img/root/README"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image holding more than k3sm.app and the Applications link refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"; mkdir "$W/img/root/.fseventsd"; printf 'log\n' >"$W/img/root/.fseventsd/fseventsd-uuid"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_promoted "an image root with a .fseventsd directory is accepted" 4
	fresh; mk_image "$W/img" "$W/tree"; printf 'hidden\n' >"$W/img/root/.hidden"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image root with another hidden entry refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"; printf 'not a directory\n' >"$W/img/root/.fseventsd"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image root whose .fseventsd is not a directory refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"; rm "$W/img/root/Applications"; ln -s /tmp "$W/img/root/Applications"
	run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an Applications link that is not /Applications refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"
	cs=0 run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an app codesign rejects refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"
	st=0 run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image stapler rejects refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"
	sp=0 run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	up_refuses "an image spctl rejects refuses" image-unverified
	fresh; mk_image "$W/img" "$W/tree"
	view_jq='.assets |= map(select(.name | endswith(".dmg") | not))' run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	if [ "$rc" -ne 0 ] && grep -q "REFUSE: draft-unverified" <<<"$out" && grep -q '^gh release create' "$log" &&
		! grep -q '^gh release edit' "$log"; then
		ok "an image missing from the draft read-back refuses before promote"
	else
		bad "image missing from the read-back (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi

	# A release candidate's app carries the tag's x.y.z core. The version
	# check runs on a mounted root directly, with the signature fakes accepting.
	# rc_root_case <name> <app-version> <want: pass|refuse>
	rc_root_case() {
		fresh; mk_image "$W/img" "$W/tree" "$2"
		rc=0
		out="$(PATH="$FPATH" FAKE_CODESIGN_VERIFY_OK=1 FAKE_STAPLER_OK=1 image_root_problems "$W/img/root" "$rctag" "$TEAM" "$W/tree/PAYLOAD-SHA256")" || rc=$?
		if { [ "$3" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$3" = refuse ] && [ "$rc" -ne 0 ] && grep -q CFBundleShortVersionString <<<"$out"; }; then ok "$1"; else
			bad "$1 (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
		: >"$log"
	}
	rc_root_case "a release candidate's app with the tag's x.y.z core passes" "$(printf '%s' "${rctag#v}" | sed 's/-rc\.[0-9]*$//')" pass
	rc_root_case "a release candidate's app carrying the -rc.N suffix refuses" "${rctag#v}" refuse
	rc_root_case "a release candidate's app with another x.y.z refuses" 0.0.2 refuse

	# ---- re-verified right before the irreversible step ----
	# between <tree> <image|""> <mutation>: run upload_checks (and the image's
	# checks) as run_upload does, then the mutation function (given the tree
	# and the assets directory), then upload. Sets rc, out.
	between_body() {
		local tr="$1" a="$1.assets"
		verify_release() { :; }
		upload_checks "$G2" "$ref2" "$tag" "$TEAM" "$tr" "$a" "$tr.seal"
		IMAGE_SHA256=""
		[ -z "$2" ] || add_disk_image "$2" "$tag" "$TEAM" "$tr/PAYLOAD-SHA256" "$a"
		"$3" "$tr" "$a"
		upload "$tag" "$repo" "$T/notes.md" "$a" "$tr" "$(seal_value "$tr.seal" tarball_sha256)" "$IMAGE_SHA256"
	}
	between() {
		: >"$log"; rm -f "$T/uploaded"
		rc=0
		out="$( (PATH="$FPATH" FAKE_GH_UPLOADED="$T/uploaded" FAKE_GH_CREATE_OK=1 FAKE_GH_EDIT_OK=1 \
			FAKE_CODESIGN_VERIFY_OK=1 FAKE_STAPLER_OK=1 FAKE_SPCTL_OK=1 between_body "$@") 2>&1)" || rc=$?
	}
	# The swapped tarball holds the same verified tree (repacked after a touch,
	# so its bytes differ) and the checksums file is rewritten to match it, so
	# only the comparison with the sealed hash can catch it.
	# shellcheck disable=SC2329 # invoked by name through between
	swap_tarball() {
		local b
		b="$(asset_base "$tag")"
		touch -t 200001010000 "$1/k3sm"
		(cd "$1" && COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$2/$b.tar.gz" k3sm cp-payload PAYLOAD-SHA256 -C "$REPO_ROOT" LICENSE NOTICE)
		(cd "$2" && shasum -a 256 "$b.tar.gz" "$b.PAYLOAD-SHA256" >"$(checksums_name "$tag")")
	}
	# shellcheck disable=SC2329 # invoked by name through between
	change_image() {
		local f
		f="$2/$IMAGE_DIR_NAME/$(image_name "$tag")"
		chmod u+w "$f"
		printf 'x' >>"$f"
	}
	fresh
	between "$W/tree" "" swap_tarball
	up_refuses "a tarball swapped after the upload checks, with a matching checksums line, refuses before create" tarball-changed
	fresh; mk_image "$W/img" "$W/tree"
	between "$W/tree" "$W/img/out/$(image_name "$tag")" change_image
	up_refuses "an image copy changed after its checks refuses before upload" image-changed
	fresh; mk_image "$W/img" "$W/tree"
	FAKE_CODESIGN_IMAGE_TEAM=ZYXWV98765 run_up "$W/tree" "$W/img/out/$(image_name "$tag")"
	if [ "$rc" -ne 0 ] && grep -q "REFUSE: image-unverified" <<<"$out" && grep -q "codesign --verify --strict rejects the image" <<<"$out" &&
		! grep -q '^gh ' "$log"; then
		ok "an image signed by another team refuses"
	else
		bad "image of another team (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	# The read-back digest is compared with the sealed tarball hash too, not
	# only with the local file.
	promote_seal_case() {
		printf '%s\n' "$(draft_json "$A" "$tag")" >"$T/view.json"
		: >"$log"; rc=0
		out="$( (PATH="$FPATH" FAKE_GH_VIEW="$T/view.json" FAKE_GH_EDIT_OK=1 promote "$tag" "$repo" "$A" "$1") 2>&1)" || rc=$?
	}
	promote_seal_case "$(sha256_of "$A/$(asset_base "$tag").tar.gz")"
	if [ "$rc" -eq 0 ] && grep -q '^gh release edit' "$log"; then ok "control: a read-back tarball digest equal to the sealed hash is promoted"; else
		bad "read-back with the sealed hash (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	promote_seal_case "$(printf '0%.0s' $(seq 64))"
	if [ "$rc" -ne 0 ] && grep -q "REFUSE: draft-unverified" <<<"$out" && grep -q "differs from the checked" <<<"$out" &&
		! grep -q '^gh release edit' "$log"; then
		ok "a read-back tarball digest that differs from the sealed hash refuses"
	else
		bad "read-back against the sealed hash (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	: >"$log"

	# The one-shot run uploads three assets and never an image: its upload
	# refuses, before any gh call, a checksums file that names a fourth.
	fresh; printf 'image\n' >"$W/tree.assets/$(image_name "$tag")"
	(cd "$W/tree.assets" && shasum -a 256 "$(image_name "$tag")" >>"$(checksums_name "$tag")")
	: >"$log"; rc=0
	out="$( (PATH="$FPATH" FAKE_GH_CREATE_OK=1 upload "$tag" "$repo" "$T/notes.md" "$W/tree.assets" "$W/tree" "$(seal_value "$W/tree.seal" tarball_sha256)") 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ] && grep -q "REFUSE: checksums" <<<"$out" && ! grep -q '^gh ' "$log"; then
		ok "the one-shot upload ships exactly three assets"
	else
		bad "one-shot asset count (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	: >"$log"

	# ---- install.sh selects its checksums line by the archive's exact name ----
	echo "install.sh and the image's checksums line"
	local I="$T/install" iv=0.0.0
	mkdir -p "$I/fakes" "$I/srv" "$I/cwd"
	for tool in uname sysctl sw_vers sudo curl; do
		cat >"$I/fakes/$tool" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$(basename "$0") $*" >>"$FAKE_TOOL_LOG"
case "$(basename "$0")" in
uname) echo Darwin ;;
sysctl) echo 1 ;;
sw_vers) echo 26.0 ;;
curl)
	o="" u=""
	while [ $# -gt 0 ]; do case "$1" in -o) o="$2"; shift 2 ;; -*) shift ;; *) u="$1"; shift ;; esac; done
	f="$FAKE_SRV/${u##*/}"
	[ -n "$o" ] && [ -f "$f" ] && cp "$f" "$o" && exit 0
	exit 22
	;;
esac
exit 97
EOF
	done
	chmod +x "$I/fakes/"*
	mkdir "$I/pkg"; printf 'k3sm fixture\n' >"$I/pkg/k3sm"; chmod +x "$I/pkg/k3sm"
	tar -czf "$I/srv/k3sm_${iv}_darwin_arm64.tar.gz" -C "$I/pkg" k3sm
	printf 'not served\n' >"$I/image.dmg"
	# install_case <name> <checksums-file-content> <want: pass|refuse>
	install_case() {
		printf '%s\n' "$2" >"$I/srv/k3sm_${iv}_checksums.txt"
		rm -f "$I/cwd/"*; : >"$log"; rc=0
		out="$(cd "$I/cwd" && PATH="$I/fakes:$PATH" FAKE_SRV="$I/srv" TMPDIR="$I" K3SM_INSTALL_VERSION="v$iv" \
			K3SM_INSTALL_BASE_URL=https://example.invalid/releases K3SM_INSTALL_DOWNLOAD_ONLY=1 sh "$REPO_ROOT/install.sh" 2>&1)" || rc=$?
		if [ "$3" = pass ]; then
			if [ "$rc" -eq 0 ] && [ -f "$I/cwd/k3sm_${iv}_darwin_arm64.tar.gz" ] && ! grep -q '\.dmg' "$log" && ! grep -q '^sudo' "$log"; then ok "$1"; else
				bad "$1 (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
			fi
		elif [ "$rc" -ne 0 ] && grep -q "no entry for k3sm_${iv}_darwin_arm64.tar.gz" <<<"$out"; then ok "$1"; else
			bad "$1 (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
		fi
	}
	local tarline imgline
	tarline="$(cd "$I/srv" && shasum -a 256 "k3sm_${iv}_darwin_arm64.tar.gz")"
	imgline="$(sha256_of "$I/image.dmg")  k3sm_${iv}_darwin_arm64.dmg"
	install_case "install.sh verifies the tarball and ignores the image's checksums line" "$imgline"$'\n'"$tarline" pass
	install_case "control: install.sh does not take the image's line for the tarball's" "$imgline" refuse
	: >"$log"

	# ---- static checks ----
	echo "static"
	local s
	# An absolute tool path would bypass PATH, and with it these fakes.
	local abs='/(usr/)?s?bin/[[:alnum:]_.-]|/opt/home''brew|/Library/Dev''eloper|/Applications/X''code'
	for s in "$HERE/publish.sh" "$sign"; do
		if sed 's|#!/usr/bin/env bash||g' "$s" | grep -nE "$abs" | grep -q .; then
			bad "$(basename "$s") names a tool by absolute path:"; sed 's|#!/usr/bin/env bash||g' "$s" | grep -nE "$abs" | sed 's/^/       /'
		else
			ok "$(basename "$s") calls no tool by absolute path"
		fi
		if bash -n "$s"; then ok "$(basename "$s") parses (bash -n)"; else bad "$(basename "$s") bash -n"; fi
	done
	local guard_line parse_line
	guard_line="$(grep -n 'CLAUDECODE+x' "$sign" | head -1 | cut -d: -f1)"
	parse_line="$(grep -n '^while \[ \$# -gt 0 \]' "$sign" | head -1 | cut -d: -f1)"
	if [ -n "$guard_line" ] && [ -n "$parse_line" ] && [ "$guard_line" -lt "$parse_line" ]; then
		ok "sign.sh tests the environment before its argument loop"
	else
		bad "sign.sh guard order (guard=$guard_line parse=$parse_line)"
	fi
	# shellcheck disable=SC2016 # a literal line of sign.sh, not an expansion
	if grep -q -- 'codesign --force --sign "$IDENTITY" --options runtime --timestamp' "$sign" &&
		grep -q -- 'notarytool submit .* --keychain-profile k3sm-notary --wait' "$sign"; then
		ok "sign.sh signs with the hardened runtime and a timestamp, and notarizes with the k3sm-notary profile"
	else
		bad "sign.sh codesign/notarytool flags"
	fi
	if command -v shellcheck >/dev/null 2>&1; then
		if shellcheck "$HERE/publish.sh" "$sign"; then ok "shellcheck"; else bad "shellcheck"; fi
	else
		echo "  skip shellcheck (not installed)"
	fi

	unset -f ok bad skip_attended on_pty no_tty expect_refusal draft_json promote_case mk_payload package_case ent_case gitf bind_case upload_case \
		mk_sealed mk_image run_up up_refuses up_promoted fresh install_case rc_root_case between between_body swap_tarball change_image promote_seal_case
	unset FAKE_TOOL_LOG
	echo
	echo "publish self-test: $passes passed, $fails failed, $skips skipped (attended only)"
	if [ "$fails" -ne 0 ]; then
		echo "publish self-test: $fails FAILED"
		return 1
	fi
	echo "publish self-test: all passed"
}

if [ "$#" -eq 1 ] && [ "$1" = "--self-test" ]; then
	self_test
	exit $?
fi

# ---- the refusal: before any argument -------------------------------------------
if [ -n "${CLAUDECODE+x}" ] || [ -n "${K3SM_AUTO+x}" ]; then
	refuse automation-env \
		"CLAUDECODE or K3SM_AUTO is set in the environment." \
		"Publishing signs and uploads with the operator's credentials; it runs attended only."
fi
if ! (exec 3<>/dev/tty) 2>/dev/null; then
	refuse no-tty "/dev/tty cannot be opened; publishing needs an operator at a terminal."
fi

# ---- arguments ------------------------------------------------------------------
MODE=one-shot
VERSION="" STAGE="" CP_BUILD="" LDFLAGS="" IDENTITY="" TEAM_ID="" NOTES="" REPO="k3sm-io/k3sm" DISK_IMAGE=""
while [ $# -gt 0 ]; do
	case "$1" in
	--through-verify) [ "$MODE" = one-shot ] || die "--through-verify and --upload are separate runs"; MODE=through-verify; shift ;;
	--upload) [ "$MODE" = one-shot ] || die "--through-verify and --upload are separate runs"; MODE=upload; shift ;;
	--version) VERSION="${2:?--version needs a value}"; shift 2 ;;
	--stage-dir) STAGE="${2:?--stage-dir needs a value}"; shift 2 ;;
	--cp-build) CP_BUILD="${2:?--cp-build needs a value}"; shift 2 ;;
	--ldflags) LDFLAGS="${2:?--ldflags needs a value}"; shift 2 ;;
	--identity) IDENTITY="${2:?--identity needs a value}"; shift 2 ;;
	--team-id) TEAM_ID="${2:?--team-id needs a value}"; shift 2 ;;
	--notes-file) NOTES="${2:?--notes-file needs a value}"; shift 2 ;;
	--repo) REPO="${2:?--repo needs a value}"; shift 2 ;;
	--disk-image) [ -z "$DISK_IMAGE" ] || die "--disk-image is given once"; DISK_IMAGE="${2:?--disk-image needs a value}"; shift 2 ;;
	-h | --help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done
case "$MODE" in
one-shot) required="VERSION STAGE CP_BUILD LDFLAGS IDENTITY TEAM_ID NOTES" unused="DISK_IMAGE" ;;
through-verify) required="VERSION STAGE CP_BUILD LDFLAGS IDENTITY TEAM_ID" unused="NOTES DISK_IMAGE" ;;
upload) required="VERSION STAGE TEAM_ID NOTES" unused="CP_BUILD LDFLAGS IDENTITY" ;;
esac
for v in $required; do
	[ -n "${!v}" ] || die "missing a required flag (see --help): $v"
done
for v in $unused; do
	[ -z "${!v}" ] || die "$v is not used by the $MODE run (see --help)"
done
valid_version "$VERSION" || die "--version '$VERSION' is not vMAJOR.MINOR.PATCH[-rc.N]"
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || die "--team-id '$TEAM_ID' is not a 10-character Team ID"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo '$REPO' is not owner/name"
[ -z "$NOTES" ] || [ -f "$NOTES" ] || die "--notes-file $NOTES is not a file"
STAGE="${STAGE%/}"

if [ "$MODE" = upload ]; then
	[ -d "$STAGE" ] || die "--stage-dir $STAGE is not a directory; --through-verify leaves it"
	STAGE="$(cd "$STAGE" && pwd)"
	ASSETS="$STAGE.assets"
	[ -d "$ASSETS" ] || die "$ASSETS is not a directory; --through-verify leaves it"
	run_upload "$REPO_ROOT" "refs/tags/$VERSION" "$VERSION" "$TEAM_ID" "$STAGE" "$REPO" "$NOTES" "$DISK_IMAGE"
	echo "==> released $VERSION on $REPO"
	exit 0
fi

[ ! -e "$STAGE" ] || die "--stage-dir $STAGE already exists; a release stages into a fresh directory"
ASSETS="$STAGE.assets"
[ ! -e "$ASSETS" ] || die "$ASSETS already exists"
[ ! -e "$STAGE.seal" ] || die "$STAGE.seal already exists"

echo "==> 0/6 bind the build to the tag"
if ! problems="$(tag_binding_problems "$REPO_ROOT" "refs/tags/$VERSION")"; then
	printf '%s\n' "$problems" >&2
	refuse tag-binding "the release must be built from a clean worktree at exactly the commit $VERSION names."
fi
HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse --verify HEAD)"

echo "==> 1/6 stage (release)"
"$HERE/stage.sh" "$STAGE" --release --cp-build "$CP_BUILD" --ldflags "$LDFLAGS"
STAGE="$(cd "$STAGE" && pwd)"
ASSETS="$STAGE.assets"

echo "==> 2/6 sign and notarize"
"$HERE/sign.sh" --identity "$IDENTITY" --team-id "$TEAM_ID" "$STAGE"
if ! problems="$(entitlements_problems "$STAGE")"; then
	printf '%s\n' "$problems" >&2
	refuse entitlements "a signed Mach-O carries entitlements outside the allowlist; nothing was uploaded."
fi

echo "==> 3/6 rewrite the manifest over the signed bytes"
"$HERE/stage.sh" --rewrite-manifest "$STAGE"

echo "==> 4/6 verify the release signatures"
verify_release "$STAGE" "$TEAM_ID"
got_version="$("$STAGE/k3sm" version | head -1 | awk '{print $2}')"
[ "$got_version" = "${VERSION#v}" ] ||
	die "the staged k3sm reports version '$got_version', expected '${VERSION#v}'; stamp it through --ldflags"

echo "==> 5/6 package the assets into $ASSETS"
package_assets "$STAGE" "$VERSION" "$ASSETS"
# The tarball step 5 checked; upload refuses if the file is any other by then.
TARBALL_SHA256="$(sha256_of "$ASSETS/$(asset_base "$VERSION").tar.gz")"

if [ "$MODE" = through-verify ]; then
	write_seal "$STAGE.seal" "$VERSION" "$HEAD_SHA" "$STAGE/PAYLOAD-SHA256" "$ASSETS/$(asset_base "$VERSION").tar.gz" "$TEAM_ID"
	echo "==> verified and sealed: $STAGE, $ASSETS, $STAGE.seal"
	echo "    build the disk image from $STAGE, then run:"
	echo "    $0 --upload --version $VERSION --stage-dir $STAGE --team-id $TEAM_ID --notes-file <file> [--disk-image <dir>/$(image_name "$VERSION")] [--repo $REPO]"
	exit 0
fi

echo "==> 6/6 upload: draft, verify, promote"
upload "$VERSION" "$REPO" "$NOTES" "$ASSETS" "$STAGE" "$TARBALL_SHA256"
echo "==> released $VERSION on $REPO"
