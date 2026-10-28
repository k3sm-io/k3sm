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
#                         [--ldflags <flags>] [--release --cp-build <dir>]
#   hack/release/stage.sh <dir> --verify-only [--binary-name <name>]
#   hack/release/stage.sh <dir> --verify-release <TEAMID> [--binary-name <name>]
#   hack/release/stage.sh --from-captured <file> --verify-release <TEAMID>
#   hack/release/stage.sh --rewrite-manifest <tree>
#   hack/release/stage.sh --print-pinned-source-files
#   hack/release/stage.sh --self-test
#
#   <out-dir>        directory to assemble into (created; must not be under dist/,
#                    which goreleaser empties with --clean)
#   --verify-only    build and sign NOTHING; run only the verification block
#                    (completeness against the install contract, codesign --verify
#                    on every Mach-O, the arm64 arch assert, and the k3sm-vmhost
#                    virtualization-entitlement read-back) over a tree that already
#                    exists. This is the seam a release gate run from the parent
#                    checkout of all the repos drives so the artifact-quality tier re-uses THESE checks over
#                    the extracted archive rather than growing a second copy of
#                    them that can drift from what staging asserts. Ad-hoc
#                    signatures pass.
#   --verify-release <TEAMID>
#                    inspection only, never signs: every check --verify-only makes,
#                    plus, for every Mach-O file(1) finds (each slice of a universal
#                    binary), a Developer ID signature: the hardened-runtime flag,
#                    a secure timestamp, TeamIdentifier equal to <TEAMID>, and a
#                    "Developer ID Application" leaf authority, checked in the
#                    display text and as a codesign designated requirement
#                    anchored at Apple's roots. Ad-hoc fails. It ends by checking
#                    PAYLOAD-SHA256 (see below) against the tree. The signing
#                    pipeline runs it after it signs and rewrites the manifest.
#   --rewrite-manifest <tree>
#                    recompute PAYLOAD-SHA256 over <tree>, in the tree and beside
#                    it, keeping its comment lines. Signing rewrites bytes, so the
#                    signing pipeline runs this after Developer ID signing and
#                    before --verify-release. Requires an existing manifest.
#   --from-captured <file>
#                    with --verify-release: apply the signature policy to captured
#                    `codesign -dvvv` text instead of a tree (no codesign is run).
#   --release        release staging: refuse to sign any cp-payload file that was
#                    not built from pinned upstream source. Requires --cp-build.
#                    The control-plane binaries are taken from --cp-build, and
#                    every cp-payload file must be
#                    one of PINNED_SOURCE_FILES, byte-identical to its --cp-build
#                    copy. kine, etcd, etcdutl, zot and helm and their version
#                    markers are accepted too (K3SM_BUILT_FILES, helm under its
#                    versioned name): k3sm builds them itself from pinned module
#                    source in `k3sm payload`, with the toolchain
#                    PAYLOAD_GO_VERSION pins, and staging proves each is the
#                    pinned build. The control-plane marker kube.version
#                    (KUBE_MARKER_FILE) is accepted only with a content proof:
#                    a regular file whose bytes are exactly "<tag>\n", where
#                    <tag> is the Kubernetes tag the --cp-build BUILD-STAMP
#                    records and equals the executor's DefaultKubeVersion
#                    (kube_marker_problems). Signing any of
#                    this with a Developer ID is the attended signing pipeline's
#                    job, never this script's. Without --release (the default)
#                    staging is the ad-hoc lab staging, with the same
#                    control-plane binaries (see "The control-plane binaries").
#   --cp-build <dir> with --release: the output directory of
#                    hack/release/build-cp.sh <dir>; it must hold exactly the
#                    files build-cp.sh produces and pass the same check lab
#                    staging runs on its cache (cp_build_check: the stamp's cache
#                    key, toolchain and tag, each binary's recorded sha256 and its
#                    build info).
#   --print-pinned-source-files
#                    print PINNED_SOURCE_FILES, one per line (build-cp.sh's
#                    self-test compares it with its own output list)
#   --binary-name    name for the k3sm binary in <out-dir> (default: k3sm)
#   --stub-payload   write placeholder payload files instead of downloading the
#                    real ~250 MB control-plane set; for shape/layout checks only,
#                    never for anything published
#   --ldflags        -ldflags value for the k3sm build, e.g. the pkg/version -X
#                    stamps. Empty (the default) leaves an unstamped dev build,
#                    which reports its version from the embedded VCS build info.
#   --self-test      hermetic self-test of the manifest, the signature parser, the
#                    release refusal, the toolchain pin, the source-built children's
#                    build-stamp checks, the needs-network report and the
#                    children vuln scan, against a planted local vulnerability
#                    database (no network, no credentials, no keychain)
#   (k3sm-vmhost is always built and signed with
#   cmd/k3sm-vmhost/vmhost.entitlements: pkg/install.RequiredSiblings names it,
#   so a stage without it fails the required-artifact loop.)
#
# The control-plane binaries (kube-apiserver, kube-scheduler,
# kube-controller-manager, kubectl) are always hack/release/build-cp.sh's
# outputs: built from the digest-pinned Kubernetes source on PAYLOAD_GO_VERSION
# with build-cp's raise list, so the lab runs what a release ships. `k3sm payload`
# still downloads its prebuilt set (its marker and its digest checks are its own);
# staging replaces the four with build-cp's and checks each was built with
# PAYLOAD_GO_VERSION. --release takes them from --cp-build. Lab staging builds them
# itself into a cache, $K3SM_CP_CACHE (default <repo>/.cp-build-cache, git-ignored),
# one directory per `build-cp.sh --print-cache-key` (tag, toolchain, raise list):
# a cached build is reused only when it passes cp_build_check (stamp key, every
# binary's recorded sha256, build info), anything else builds afresh (a long
# build) and replaces the cache's older keys. The cache root must be owned by the
# effective uid and not writable by group or other. The build
# stamp's lines are recorded in UPSTREAM-DIGESTS' note and in PAYLOAD-SHA256's
# comments.
#
# Staging scans every staged Go child with govulncheck (-mode=binary, the version
# hack/ci.sh pins) after the payload is final and before signing: a finding whose
# trace reaches a vulnerable symbol is a red unless hack/release/govulncheck.allow
# names it (that file states its rules); a scan that cannot be trusted is a red,
# named. It needs the vulnerability database (vuln.go.dev).
#
# Staging writes two digest files into the tree, and copies the manifest beside it:
#   UPSTREAM-DIGESTS  sha256 of every cp-payload file BEFORE any signing, i.e. the
#                     bytes `k3sm payload` checked against its pinned digests.
#   PAYLOAD-SHA256    written AFTER signing: `<sha256>  <relpath>` for every
#                     regular file in the tree (LC_ALL=C order, no ./ prefix, the
#                     manifest itself and .DS_Store excluded), after `#` comment
#                     lines recording the pinned toolchain and, for kine, etcd,
#                     etcdutl, zot and helm, the module version, the patch-set id,
#                     the build variant and the build flags (kine and zot: also
#                     the raised golang.org/x/net; helm: its raised modules). After
#                     signing it is the authority for the payload's bytes; check it
#                     with `shasum -a 256 -c PAYLOAD-SHA256` inside the tree. Also
#                     written to <out-dir>.PAYLOAD-SHA256. A symlink anywhere in the
#                     tree is a hard error. --verify-release requires both copies,
#                     byte-identical, listing exactly the tree's files.
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

# The binary used to READ signatures (`codesign -dvvv`). Overridable so the
# self-test can feed captured text through the same walk; signing always uses
# the system codesign.
CODESIGN="${CODESIGN:-codesign}"

# The control-plane build lab staging runs: always the script beside this one.
BUILD_CP="$HERE/build-cp.sh"

MANIFEST_NAME="PAYLOAD-SHA256"
UPSTREAM_NAME="UPSTREAM-DIGESTS"
# A backstop, not the completeness check: verify_tree's required-artifact loop
# (k3sm install --print-required-artifacts) is what proves the set is complete.
# The floor only catches a walk that found almost nothing (a wrong directory, a
# file(1) that stopped saying "Mach-O"). It stays below the five Mach-Os the
# install contract names (k3sm, the exec shim, two DYLD shims, k3sm-vmhost) so a
# stub-payload tree, whose control-plane files are not Mach-Os, still passes.
MACHO_FLOOR=4
# The hardened-runtime bit of the CodeDirectory flags (CS_RUNTIME) and the
# ad-hoc bit (CS_ADHOC), tested numerically, never by the parenthesised names.
CS_RUNTIME=$((0x10000))
CS_ADHOC=$((0x2))

die() { echo "stage: $*" >&2; exit 1; }

# ---- the Mach-O walk ----------------------------------------------------------
# ONE walk for every check that is "per Mach-O": the set comes from file(1)
# rather than a name list, so an artifact added to pkg/install.RequiredSiblings
# is checked without this script being edited. Universal binaries match too
# ("Mach-O universal binary ..."). Prints one path per line, LC_ALL=C order.
macho_files() {
	local f desc
	while IFS= read -r f; do
		desc="$(file -b "$f" 2>/dev/null || echo '?')"
		case "$desc" in
		*Mach-O*) printf '%s\n' "$f" ;;
		esac
	done < <(find "$1" -type f | LC_ALL=C sort)
}

# ---- the codesign -dvvv parser -------------------------------------------------
# release_sig_problems <TEAMID>  (stdin: the stderr of `codesign -dvvv`)
#
# The ONE parser of codesign's display output, a strict allowlist that fails
# closed: every field below must be present and exactly right, and anything
# missing is a problem in its own right. Prints one line per problem; returns 0
# only when there are none.
#   flags=0x...     exactly one CodeDirectory line; CS_RUNTIME set and CS_ADHOC
#                   clear, tested on the number
#   Timestamp=<d>   exactly one, not "none"; a "Signed Time=" line means the
#                   signature carries only the signer's clock, not a secure
#                   timestamp, and fails
#   TeamIdentifier  exactly one, equal to <TEAMID>
#   Authority=      the first (leaf) authority is
#                   "Developer ID Application: <name> (<TEAMID>)"
#   Signature=adhoc fails
release_sig_problems() {
	local team="$1" line v
	local n_cd=0 flags="" n_ts=0 ts="" signed_time=0 n_team=0 teamid="" leaf="" adhoc=0
	while IFS= read -r line; do
		case "$line" in
		"CodeDirectory "*)
			n_cd=$((n_cd + 1))
			case "$line" in
			*" flags="*) v="${line##* flags=}"; flags="${v%%[!0-9a-fA-Fx]*}" ;;
			*) flags="" ;;
			esac ;;
		"Signed Time="*) signed_time=1 ;;
		Timestamp=*) n_ts=$((n_ts + 1)); ts="${line#Timestamp=}" ;;
		TeamIdentifier=*) n_team=$((n_team + 1)); teamid="${line#TeamIdentifier=}" ;;
		Authority=*) [ -n "$leaf" ] || leaf="${line#Authority=}" ;;
		Signature=adhoc) adhoc=1 ;;
		esac
	done

	local bad=0
	problem() { echo "$*"; bad=1; }

	if [ "$n_cd" != 1 ]; then
		problem "flags: want exactly one CodeDirectory line, found $n_cd"
	elif ! printf '%s' "$flags" | grep -Eq '^0x[0-9a-fA-F]{1,8}$'; then
		problem "flags: CodeDirectory flags missing or malformed ('$flags')"
	else
		# Validated as 1-8 hex digits above, so the arithmetic is safe.
		[ $((flags & CS_RUNTIME)) -ne 0 ] || problem "flags: $flags lacks the hardened runtime bit 0x10000"
		[ $((flags & CS_ADHOC)) -eq 0 ] || problem "flags: $flags has the ad-hoc bit 0x2"
	fi

	if [ "$signed_time" = 1 ]; then
		problem "timestamp: 'Signed Time=' present, so there is no secure timestamp"
	fi
	if [ "$n_ts" != 1 ]; then
		problem "timestamp: want exactly one Timestamp= line, found $n_ts"
	elif [ -z "$ts" ] || [ "$ts" = none ]; then
		problem "timestamp: Timestamp='$ts' is not a secure timestamp"
	fi

	if [ "$n_team" != 1 ]; then
		problem "team: want exactly one TeamIdentifier= line, found $n_team"
	elif [ "$teamid" != "$team" ]; then
		problem "team: TeamIdentifier='$teamid', want '$team'"
	fi

	case "$leaf" in
	"Developer ID Application: "*" ($team)") ;;
	"") problem "authority: no Authority= line" ;;
	*) problem "authority: leaf is '$leaf', want 'Developer ID Application: <name> ($team)'" ;;
	esac

	[ "$adhoc" = 0 ] || problem "signature: Signature=adhoc"

	unset -f problem
	return "$bad"
}

valid_team() { printf '%s' "$1" | grep -Eq '^[A-Z0-9]{10}$'; }

# verify_release_signatures <dir> <TEAMID>
# The Developer ID policy over every Mach-O under <dir>, every slice of a
# universal binary separately. Two checks per slice: the display text through
# release_sig_problems, and the chain of trust, which the text alone cannot
# prove (anyone can print "Authority=Developer ID Application"): codesign must
# validate the signature against a designated requirement anchored at Apple's
# roots whose leaf certificate's OU is <TEAMID>. Reports every problem, then
# returns non-zero if there was any (including fewer than MACHO_FLOOR Mach-Os).
verify_release_signatures() {
	local dir="$1" team="$2" f a archs out probs n=0 bad=0
	local req="anchor apple generic and certificate leaf[subject.OU] = \"$team\""
	while IFS= read -r f; do
		n=$((n + 1))
		archs="$(lipo -archs "$f" 2>/dev/null || true)"
		if [ -z "$archs" ]; then
			echo "    $f: lipo cannot read its architectures"; bad=1; continue
		fi
		for a in $archs; do
			out="$("$CODESIGN" -dvvv --arch "$a" "$f" 2>&1 >/dev/null || true)"
			if ! probs="$(printf '%s\n' "$out" | release_sig_problems "$team")"; then
				printf '%s\n' "$probs" | sed "s|^|    $f [$a]: |"
				bad=1
			fi
			if ! "$CODESIGN" --verify --strict -R="$req" --arch "$a" "$f" >/dev/null 2>&1; then
				echo "    $f [$a]: chain: codesign --verify --strict -R='$req' fails"
				bad=1
			fi
		done
	done < <(macho_files "$dir")
	if [ "$n" -lt "$MACHO_FLOOR" ]; then
		echo "    only $n Mach-O(s) under $dir (floor $MACHO_FLOOR) — the set cannot be complete"; bad=1
	fi
	[ "$bad" = 0 ] && echo "    $n Mach-O(s) carry a timestamped, hardened Developer ID signature for $team"
	return "$bad"
}

# ---- the payload manifest -----------------------------------------------------
# tree_shape_problems <tree>: the tree holds only regular files and directories
# (a symlink is refused: every walk here uses `find -type f`, which would step
# past a symlinked Mach-O unverified), and no name carries a newline or a
# backslash (both break the line-oriented walks and shasum's output format).
# Run first by the manifest and by both verify modes.
tree_shape_problems() {
	local tree="$1" odd bad=0
	[ -d "$tree" ] || { echo "stage: $tree is not a directory"; return 1; }
	odd="$(cd "$tree" && find . ! -type f ! -type d)"
	[ -z "$odd" ] || { echo "stage: refusing non-regular entries (symlinks are not allowed in the tree):"; printf '%s\n' "$odd" | sed 's/^/    /'; bad=1; }
	odd="$(cd "$tree" && find . -name "*"$'\n'"*" -o -name '*\\*')"
	[ -z "$odd" ] || { echo "stage: refusing names with a newline or backslash:"; printf '%s\n' "$odd" | sed 's/^/    /'; bad=1; }
	return "$bad"
}

# manifest_body <tree>  ->  `<sha256>  <relpath>` lines on stdout.
# Regular files only; a symlink (or any other non-regular, non-directory entry)
# is a hard error, as is a name shasum would escape (newline, backslash).
# A .DS_Store is skipped only when it is not a Mach-O: the name is Finder's, but
# a binary under that name is still code in the payload and stays hashed.
manifest_body() {
	local tree="$1"
	tree_shape_problems "$tree" >&2 || return 1
	(
		cd "$tree"
		find . -type f ! -path "./$MANIFEST_NAME" | sed 's|^\./||' | LC_ALL=C sort |
			while IFS= read -r p; do
				case "${p##*/}" in
				.DS_Store)
					case "$(file -b "$p" 2>/dev/null || echo '?')" in
					*Mach-O*) ;;
					*) continue ;;
					esac ;;
				esac
				printf '%s\0' "$p"
			done | xargs -0 shasum -a 256 --
	)
}

# manifest_write <tree> <comment-text>
# Writes <tree>/PAYLOAD-SHA256 and <tree>.PAYLOAD-SHA256. The comment text (may
# be empty) is emitted as leading `# ` lines, outside the hashed set.
manifest_write() {
	local tree="$1" comments="$2" tmp line n
	tmp="$(mktemp -t k3sm-manifest)"
	{
		if [ -n "$comments" ]; then
			while IFS= read -r line; do printf '# %s\n' "$line"; done <<<"$comments"
		fi
		manifest_body "$tree"
	} >"$tmp" || { rm -f "$tmp"; return 1; }
	n="$(grep -vc '^#' "$tmp" || true)"
	[ "$n" -gt 0 ] || { rm -f "$tmp"; echo "stage: manifest: no files under $tree" >&2; return 1; }
	if grep -v '^#' "$tmp" | grep -Evq '^[0-9a-f]{64}  [^/].*$'; then
		rm -f "$tmp"; echo "stage: manifest: a line is not '<sha256>  <relpath>'" >&2; return 1
	fi
	chmod 0644 "$tmp"
	cp "$tmp" "$tree.$MANIFEST_NAME"
	mv "$tmp" "$tree/$MANIFEST_NAME"
}

# manifest_rewrite <tree>: recompute the manifest over a tree whose bytes changed
# (Developer ID signing), keeping the leading comment lines of the old one, which
# describe the build rather than the host doing the rewrite.
manifest_rewrite() {
	local tree="$1" comments
	[ -f "$tree/$MANIFEST_NAME" ] || { echo "stage: --rewrite-manifest: $tree/$MANIFEST_NAME is missing (stage the tree first)" >&2; return 1; }
	comments="$(awk '/^# /{sub(/^# /, ""); print; next} {exit}' "$tree/$MANIFEST_NAME")"
	manifest_write "$tree" "$comments"
}

# verify_manifest <tree>: both manifest copies exist and are byte-identical,
# `shasum -a 256 -c` passes inside the tree, and the recorded list is exactly
# the tree's current file set (shasum -c alone would miss an added file).
verify_manifest() {
	local tree="$1" m="$1/$MANIFEST_NAME" beside="$1.$MANIFEST_NAME" now bad=0
	[ -f "$m" ] || { echo "    manifest: $m is missing"; return 1; }
	[ -f "$beside" ] || { echo "    manifest: $beside is missing"; return 1; }
	cmp -s "$m" "$beside" || { echo "    manifest: $m and $beside differ"; bad=1; }
	if ! now="$( (cd "$tree" && shasum -a 256 -c "$MANIFEST_NAME") 2>&1)"; then
		printf '%s\n' "$now" | grep -v ': OK$' | sed 's/^/    manifest: /'
		bad=1
	fi
	if ! now="$(manifest_body "$tree")"; then
		bad=1
	elif [ "$now" != "$(grep -v '^#' "$m")" ]; then
		echo "    manifest: the tree's file set or bytes differ from $MANIFEST_NAME (a file added, removed or changed since it was written)"
		bad=1
	fi
	return "$bad"
}

# ---- the source-built children: pins, toolchain, build stamps ------------------
# kine, etcd, etcdutl, zot and helm are k3sm's own builds from pinned module
# source: the staged k3sm builds them in `k3sm payload` (pkg/executor StagePayload,
# the same patched kine build, etcd wrapper, zot build and helm wrapper the daemon
# would otherwise run on demand).
# This script pins the toolchain that build runs under, proves the staged binaries
# are the pinned builds, and records how they were built in the manifest header.

# The Go toolchain pin and the out-of-module build checks (toolchain_problems,
# buildinfo_problems, buildinfo_settings, marker_problems) live in ONE sourced
# library, shared with every other recipe that builds a pinned module outside
# k3sm's go.mod (hack/images/metrics-server/build.sh). Never copy them.
# shellcheck source=hack/release/lib/gochild.sh
. "$HERE/lib/gochild.sh"

# govulncheck: the pin (read from hack/ci.sh), the tool lookup, the JSON-stream
# reader and the allow-file check live in ONE sourced library, shared with
# hack/ci.sh and hack/etcd-wrapper.sh. Never copy them.
# shellcheck source=hack/lib/govulncheck.sh
. "$REPO_ROOT/hack/lib/govulncheck.sh"
# The reviewed exemptions for the children scan (format and rules in the file).
GV_ALLOW="$HERE/govulncheck.allow"

# read_pins: KUBE_VERSION (the control-plane release), KINE_VERSION, ETCD_VERSION,
# KINE_VARIANT, ETCD_VARIANT and KINE_PATCH
# (the patch-set id, "none" without one), ZOT_VERSION and ZOT_VARIANT,
# HELM_VERSION, HELM_VARIANT, HELM_RAISED (the raised modules, space-separated
# path@version), HELM_COMMIT (the tag's commit the build stamps) and HELM_BINARY,
# and XNET_FLOOR (the golang.org/x/net kine and zot are built against), read from
# the source the staged k3sm is built from, so the checks below compare against
# that build's own pins.
read_pins() {
	local ex="$REPO_ROOT/pkg/executor" rs="$REPO_ROOT/pkg/registrysvc/pin.go" hc="$REPO_ROOT/pkg/helmchart/pin.go" cr="$REPO_ROOT/internal/childreq/childreq.go"
	KINE_VERSION="$(sed -n 's/^[[:space:]]*DefaultKineVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ex/executor.go")"
	ETCD_VERSION="$(sed -n 's/^[[:space:]]*DefaultEtcdVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ex/executor.go")"
	KINE_VARIANT="$(sed -n 's/^[[:space:]]*kineBuildVariant[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ex/setup.go")"
	ETCD_VARIANT="$(sed -n 's/^[[:space:]]*etcdBuildVariant[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ex/etcdstage.go")"
	KUBE_VERSION="$(sed -n 's/^[[:space:]]*DefaultKubeVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ex/executor.go")"
	[ -n "$KINE_VERSION" ] && [ -n "$ETCD_VERSION" ] && [ -n "$KINE_VARIANT" ] && [ -n "$ETCD_VARIANT" ] && [ -n "$KUBE_VERSION" ] ||
		die "cannot read the kube/kine/etcd pins and build variants from $ex"
	case "$KINE_VARIANT" in
	*+*) KINE_PATCH="${KINE_VARIANT#*+}" ;;
	*) KINE_PATCH=none ;;
	esac
	ZOT_VERSION="$(sed -n 's/^[[:space:]]*DefaultZotVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$rs")"
	ZOT_VARIANT="$(sed -n 's/^[[:space:]]*zotBuildVariant[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$rs")"
	HELM_VERSION="$(sed -n 's/^[[:space:]]*HelmVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$hc")"
	HELM_VARIANT="$(sed -n 's/^[[:space:]]*HelmBuildVariant[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$hc")"
	HELM_RAISED="$(sed -n 's/^[[:space:]]*HelmRaisedModules[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$hc")"
	HELM_COMMIT="$(sed -n 's/^[[:space:]]*HelmGitCommit[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$hc")"
	HELM_MIN_GO="$(sed -n 's/^[[:space:]]*HelmMinGoVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$hc")"
	[ -n "$ZOT_VERSION" ] && [ -n "$ZOT_VARIANT" ] && [ -n "$HELM_VERSION" ] && [ -n "$HELM_VARIANT" ] && [ -n "$HELM_RAISED" ] && [ -n "$HELM_COMMIT" ] && [ -n "$HELM_MIN_GO" ] ||
		die "cannot read the zot and helm pins from $rs and $hc"
	HELM_BINARY="helm-$HELM_VERSION"
	XNET_FLOOR="$(sed -n 's/^[[:space:]]*const XNetVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$cr")"
	[ -n "$XNET_FLOOR" ] || die "cannot read the raised golang.org/x/net (XNetVersion) from $cr"
}

# helm_buildinfo_problems <want-version> <go-pin> <raised>  (stdin: `go version -m`)
# helm's build stamp, the check buildinfo_problems makes for the other children
# (kept here, beside the one caller): the toolchain, helm's main package, the helm
# module at <want-version>, no replaced module, CGO_ENABLED=0 -trimpath
# darwin/arm64, and every <raised> path@version as a linked module, so a helm
# built from helm's own go.mod (or the upstream tarball) is refused. Prints one
# line per problem; returns 0 only when there are none.
helm_buildinfo_problems() {
	local want="$1" pin="$2" raised="$3" text gov bad=0 setting pv
	text="$(cat)"
	gov="$(sed -n '1s/^.*: \(go[0-9][^[:space:]]*\)$/\1/p' <<<"$text")"
	[ "$gov" = "$pin" ] || { echo "helm: built with '${gov:-?}', the payload pins $pin"; bad=1; }
	grep -qx "[[:space:]]*path[[:space:]]helm.sh/helm/v4/cmd/helm" <<<"$text" || { echo "helm: main package is not helm.sh/helm/v4/cmd/helm"; bad=1; }
	grep -Eq "^[[:space:]]*(mod|dep)[[:space:]]helm.sh/helm/v4[[:space:]]${want}([[:space:]]|\$)" <<<"$text" || { echo "helm: module helm.sh/helm/v4 is not at $want"; bad=1; }
	if grep -Eq "^[[:space:]]*=>" <<<"$text"; then echo "helm: a module is replaced"; bad=1; fi
	for setting in CGO_ENABLED=0 -trimpath=true GOOS=darwin GOARCH=arm64; do
		grep -qx "[[:space:]]*build[[:space:]]$setting" <<<"$text" || { echo "helm: build setting $setting is missing"; bad=1; }
	done
	[ -n "$raised" ] || { echo "helm: no raised modules to check (HELM_RAISED unset)"; bad=1; }
	for pv in $raised; do
		grep -Eq "^[[:space:]]*dep[[:space:]]${pv%@*}[[:space:]]${pv#*@}([[:space:]]|\$)" <<<"$text" || { echo "helm: module ${pv%@*} is not at the raised ${pv#*@}"; bad=1; }
	done
	return "$bad"
}

# child_problems <payload-dir> <go-pin>: the staged kine, etcd, etcdutl, zot and
# helm are the pinned builds: each marker names the pin and variant, each build
# info passes buildinfo_problems (helm: helm_buildinfo_problems) against <go-pin>
# (kine and zot: with x/net at XNET_FLOOR or newer), kine carries its stamped
# version (pin+patch set) in its bytes, and helm carries the version and the tag's
# commit its release build stamps with -X (the build info cannot show them:
# -trimpath keeps -ldflags out of it, and -s strips the symbols the daemon could
# read them from). The commit is in no helm source file, so its presence proves
# the -X flags were applied. Prints one
# line per problem; returns 0 only when there are none.
child_problems() {
	local dir="$1" pin="$2" bad=0 kind want variant
	for kind in kine etcd etcdutl zot; do
		case "$kind" in
		kine) want="$KINE_VERSION"; variant="$KINE_VARIANT" ;;
		zot) want="$ZOT_VERSION"; variant="$ZOT_VARIANT" ;;
		*) want="$ETCD_VERSION"; variant="$ETCD_VARIANT" ;;
		esac
		[ -f "$dir/$kind" ] || { echo "$kind: not staged in $dir"; bad=1; continue; }
		marker_problems "$dir" "$kind" "$want" "$variant" || bad=1
		"$GO" version -m "$dir/$kind" 2>/dev/null | buildinfo_problems "$kind" "$want" "$pin" || bad=1
	done
	if [ -f "$dir/kine" ] && [ "$KINE_PATCH" != none ] && ! grep -aqF -- "$KINE_VERSION+$KINE_PATCH" "$dir/kine"; then
		echo "kine: the stamped version $KINE_VERSION+$KINE_PATCH is not in the binary"; bad=1
	fi
	if [ -f "$dir/$HELM_BINARY" ]; then
		marker_problems "$dir" helm "$HELM_VERSION" "$HELM_VARIANT" || bad=1
		"$GO" version -m "$dir/$HELM_BINARY" 2>/dev/null | helm_buildinfo_problems "$HELM_VERSION" "$pin" "$HELM_RAISED" || bad=1
		local s
		for s in "$HELM_VERSION" "$HELM_COMMIT"; do
			LC_ALL=C grep -aqF -- "$s" "$dir/$HELM_BINARY" || { echo "helm: the stamped string $s is not in the binary (built without helm's -X version flags?)"; bad=1; }
		done
	else
		echo "$HELM_BINARY: not staged in $dir"; bad=1
	fi
	return "$bad"
}

# needs_network_modules  (stdin: the output of a failed `k3sm payload`)
# The modules a Go command failed to fetch because the network was not reachable:
# one `<module>@<version>` per line, deduplicated, in first-seen order. A line is a
# network failure when it carries one of the net/http or resolver error texts below;
# the module is the first `<path>@<version>` on it, else the one in a module-proxy
# URL. A network failure naming no module prints `?`. Prints nothing when the
# failure was not a network one.
needs_network_modules() {
	local line m
	while IFS= read -r line; do
		case "$line" in
		*"dial tcp"* | *"no such host"* | *"i/o timeout"* | *"connection refused"* | *"network is unreachable"* | *"TLS handshake timeout"* | *"connection reset by peer"* | *"proxyconnect"* | *"Client.Timeout exceeded"* | *"server misbehaving"*) ;;
		*) continue ;;
		esac
		m="$(printf '%s\n' "$line" | grep -Eo '[A-Za-z0-9][A-Za-z0-9._~!/-]*\.[A-Za-z0-9._~!/-]*@v[0-9][^:[:space:]"]*' | head -1 || true)"
		m="${m%/go.mod}"
		if [ -z "$m" ]; then
			m="$(printf '%s\n' "$line" | sed -E -n 's#.*https://[^/]*/([^"[:space:]]+)/@v/(v[^"[:space:]]+)\.(info|mod|zip).*#\1@\2#p' | head -1 || true)"
		fi
		# A module path in a proxy URL is case-encoded ("!x" is "X").
		m="$(printf '%s\n' "${m:-?}" | unbang)"
		printf '%s\n' "$m"
	done | awk '!seen[$0]++'
}

# unbang: decode the module proxy's case encoding on stdin ("!x" is "X").
unbang() {
	awk '{ o = ""; while ((i = index($0, "!")) > 0) { o = o substr($0, 1, i - 1) toupper(substr($0, i + 1, 1)); $0 = substr($0, i + 2) } print o $0 }'
}

# manifest_comments [stub]: the manifest's header lines. The toolchain pin, then,
# per source-built child, its module version, patch-set id, build variant and the
# build settings its own build info records, and for kine and zot the raised
# golang.org/x/net they are built against (kine's -ldflags stamp is added
# explicitly: -trimpath keeps ldflags out of Go's build info). With "stub" the
# children were not built, and the header says so.
manifest_comments() {
	local stub="${1:-}" dir="$PAYLOAD_DIR" kind
	printf 'k3sm payload manifest; verify inside the tree with: shasum -a 256 -c %s\n' "$MANIFEST_NAME"
	printf 'toolchain: %s %s/%s (pinned: PAYLOAD_GO_VERSION %s)\n' "$("$GO" env GOVERSION)" "$GOOS" "$GOARCH" "$PAYLOAD_GO_VERSION"
	printf 'kine: github.com/k3s-io/kine %s patch-set %s variant %s (stamped %s+%s) raises golang.org/x/net %s\n' "$KINE_VERSION" "$KINE_PATCH" "$KINE_VARIANT" "$KINE_VERSION" "$KINE_PATCH" "$XNET_FLOOR"
	printf 'etcd: go.etcd.io/etcd/server/v3 %s patch-set none variant %s\n' "$ETCD_VERSION" "$ETCD_VARIANT"
	printf 'etcdutl: go.etcd.io/etcd/etcdutl/v3 %s patch-set none variant %s\n' "$ETCD_VERSION" "$ETCD_VARIANT"
	printf 'zot: zotregistry.dev/zot/v2 %s patch-set none variant %s raises golang.org/x/net %s\n' "$ZOT_VERSION" "$ZOT_VARIANT" "$XNET_FLOOR"
	printf 'helm: helm.sh/helm/v4 %s patch-set none variant %s raises %s (staged as %s)\n' "$HELM_VERSION" "$HELM_VARIANT" "$HELM_RAISED" "$HELM_BINARY"
	if [ "$stub" = stub ]; then
		echo "control plane: STUB payload, not built"
		echo "build: STUB payload, the source-built children were not built"
		return 0
	fi
	for kind in kine etcd etcdutl zot; do
		printf '%s build: %s' "$kind" "$("$GO" version -m "$dir/$kind" | buildinfo_settings)"
		[ "$kind" = kine ] && printf ' -ldflags=-X github.com/k3s-io/kine/pkg/version.Version=%s+%s' "$KINE_VERSION" "$KINE_PATCH"
		printf '\n'
	done
	# helm's -ldflags (its release build's version stamp) are kept out of the build
	# info by -trimpath, like kine's; pkg/helmchart.HelmLDFlags is their one home.
	printf 'helm build: %s\n' "$("$GO" version -m "$dir/$HELM_BINARY" | buildinfo_settings)"
	[ -n "${CP_STAMP:-}" ] || return 0
	echo "control plane: kube-apiserver, kube-scheduler, kube-controller-manager and kubectl built by hack/release/build-cp.sh; its $CP_STAMP_NAME follows"
	printf '%s\n' "$CP_STAMP" | sed 's/^/control plane: /'
}

# upstream_digests_write <tree> <note>
# The pre-sign digests of every cp-payload file, written before any signing so
# they describe the bytes the pinned check verified, not the re-signed ones.
upstream_digests_write() {
	local tree="$1" note="$2" tmp
	tmp="$(mktemp -t k3sm-upstream)"
	{
		echo "# pre-sign sha256 of every cp-payload file, recorded before any signing"
		echo "# $note"
		echo "# after signing, $MANIFEST_NAME is the authority"
		( cd "$tree" && find cp-payload -type f | LC_ALL=C sort | tr '\n' '\0' | xargs -0 shasum -a 256 -- )
	} >"$tmp" || { rm -f "$tmp"; return 1; }
	chmod 0644 "$tmp"
	mv "$tmp" "$tree/$UPSTREAM_NAME"
}

# ---- the release refusal --------------------------------------------------------
# Newline-separated cp-payload/<name> entries produced by the pinned-source
# control-plane build, hack/release/build-cp.sh: exactly its outputs, in its
# order. Written out rather than derived, so the two self-tests comparing this
# list with `build-cp.sh --print-outputs` catch either side drifting.
PINNED_SOURCE_FILES="cp-payload/kube-apiserver
cp-payload/kube-scheduler
cp-payload/kube-controller-manager
cp-payload/kubectl"

# The stamp build-cp.sh writes beside its outputs (its STAMP_NAME).
CP_STAMP_NAME="BUILD-STAMP"

# Newline-separated cp-payload/<name> entries k3sm builds itself from pinned
# module source in `k3sm payload` (child_problems proves each is the pinned build),
# with their version markers. Release staging accepts them beside
# PINNED_SOURCE_FILES: they are k3sm's own builds, and a release signs only those.
# helm belongs here too; its binary carries the version in its name, so
# release_payload_files adds it from read_pins, beside its marker below.
K3SM_BUILT_FILES="cp-payload/kine
cp-payload/kine.version
cp-payload/etcd
cp-payload/etcd.version
cp-payload/etcdutl
cp-payload/etcdutl.version
cp-payload/zot
cp-payload/zot.version
cp-payload/helm.version"

# The control-plane version marker `k3sm payload` writes beside the four
# control-plane binaries (pkg/executor KubeMarkerName). A text marker, not code:
# release staging accepts it only when kube_marker_problems proves its content.
KUBE_MARKER_FILE="cp-payload/kube.version"

# release_payload_files: every cp-payload entry release staging accepts, one per
# line: PINNED_SOURCE_FILES, KUBE_MARKER_FILE, K3SM_BUILT_FILES, and the
# k3sm-built helm under its versioned name. Needs read_pins.
release_payload_files() {
	printf '%s\n%s\n%s\ncp-payload/%s\n' "$PINNED_SOURCE_FILES" "$KUBE_MARKER_FILE" "$K3SM_BUILT_FILES" "$HELM_BINARY"
}

# kube_marker_problems <tree> <stamp-text> <kube-version>: non-zero, naming the
# file and the expected content, unless <tree>/KUBE_MARKER_FILE is a regular file
# (not a symlink) whose bytes are exactly "<tag>\n", where <tag> is the one
# `tag: <tag> (commit ...)` line of <stamp-text> (the --cp-build BUILD-STAMP) and
# equals <kube-version> (read_pins' DefaultKubeVersion).
kube_marker_problems() {
	local tree="$1" stamp="$2" kv="$3" f tags tag
	f="$tree/$KUBE_MARKER_FILE"
	tags="$(printf '%s\n' "$stamp" | sed -n 's/^tag: \([^[:space:]]*\) .*/\1/p')"
	if [ -z "$tags" ] || [ "$(printf '%s\n' "$tags" | wc -l | tr -d ' ')" != 1 ]; then
		echo "    $KUBE_MARKER_FILE: $CP_STAMP_NAME does not record exactly one tag line, so the marker has no expected content"
		return 1
	fi
	tag="$tags"
	if [ -z "$kv" ] || [ "$tag" != "$kv" ]; then
		echo "    $KUBE_MARKER_FILE: $CP_STAMP_NAME records tag $tag, the executor's DefaultKubeVersion is '${kv}'"
		return 1
	fi
	if [ -L "$f" ] || [ ! -f "$f" ]; then
		printf '    %s: missing or not a regular file; expected exactly "%s\\n"\n' "$KUBE_MARKER_FILE" "$tag"
		return 1
	fi
	cmp -s "$f" <(printf '%s\n' "$tag") || { printf '    %s: content is not exactly "%s\\n"\n' "$KUBE_MARKER_FILE" "$tag"; return 1; }
	return 0
}

# cp_build_problems <dir>: non-zero, naming each problem, unless <dir> holds
# exactly the regular files PINNED_SOURCE_FILES names (by base name) and the
# build stamp CP_STAMP_NAME, no more.
cp_build_problems() {
	local dir="$1" rel name bad=0 f
	[ -d "$dir" ] || { echo "    --cp-build $dir is not a directory"; return 1; }
	while IFS= read -r rel; do
		name="${rel#cp-payload/}"
		[ -f "$dir/$name" ] && [ ! -L "$dir/$name" ] || { echo "    --cp-build lacks $name"; bad=1; }
	done <<<"$PINNED_SOURCE_FILES"
	[ -f "$dir/$CP_STAMP_NAME" ] && [ ! -L "$dir/$CP_STAMP_NAME" ] || { echo "    --cp-build lacks $CP_STAMP_NAME"; bad=1; }
	for f in "$dir"/* "$dir"/.[!.]*; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		[ "$(basename "$f")" = "$CP_STAMP_NAME" ] && continue
		printf '%s\n' "$PINNED_SOURCE_FILES" | grep -qxF -- "cp-payload/$(basename "$f")" || { echo "    --cp-build holds an unexpected $(basename "$f")"; bad=1; }
	done
	return "$bad"
}

# cp_binary_problems <name> <tag> <raises>  (stdin: `go version -m` text)
# The build info of one control-plane binary (read, never executed): built with
# PAYLOAD_GO_VERSION, main package k8s.io/kubernetes/cmd/<name>, main module
# k8s.io/kubernetes as a source-archive build records it ("(devel)": the tag is
# not in the build info, it is stamped by -X, which cp_build_check reads off the
# bytes), CGO_ENABLED=0 darwin/arm64 -trimpath, no replaced module, and every
# raise-list module the binary links at exactly its listed version. <raises> is
# "<module> <version>" per line. Prints, one per line, "PROBLEM ..." for each
# problem and "LINKS <module>" for each raised module the binary links. Returns
# non-zero iff there is a PROBLEM.
cp_binary_problems() {
	local name="$1" text gov bad=0 setting mod ver got
	text="$(cat)"
	gov="$(printf '%s\n' "$text" | sed -n '1s/^.*: \(go[0-9][^[:space:]]*\)$/\1/p')"
	[ "$gov" = "$PAYLOAD_GO_VERSION" ] || { echo "PROBLEM $name: built with '${gov:-?}', the payload pins $PAYLOAD_GO_VERSION"; bad=1; }
	printf '%s\n' "$text" | grep -Eqx "[[:space:]]*path[[:space:]]+k8s\.io/kubernetes/cmd/$name" || { echo "PROBLEM $name: main package is not k8s.io/kubernetes/cmd/$name"; bad=1; }
	printf '%s\n' "$text" | grep -Eqx '[[:space:]]*mod[[:space:]]+k8s\.io/kubernetes[[:space:]]+\(devel\)[[:space:]]*' || { echo "PROBLEM $name: main module is not the k8s.io/kubernetes source build"; bad=1; }
	for setting in CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 -trimpath=true; do
		printf '%s\n' "$text" | grep -qx "[[:space:]]*build[[:space:]]$setting" || { echo "PROBLEM $name: build setting $setting is missing"; bad=1; }
	done
	printf '%s\n' "$text" | grep -Eq '^[[:space:]]*=>' && { echo "PROBLEM $name: a module is replaced"; bad=1; }
	while read -r mod ver; do
		[ -n "$mod" ] || continue
		got="$(printf '%s\n' "$text" | awk -v m="$mod" '$1 == "dep" && $2 == m { print $3 }')"
		[ -n "$got" ] || continue
		echo "LINKS $mod"
		[ "$got" = "$ver" ] || { echo "PROBLEM $name: links $mod $got, the raise list lands it at $ver"; bad=1; }
	done <<<"$3"
	return "$bad"
}

# cp_set_check <dir> <tag> <raises> <stamp-text>: the per-binary check, run on a
# build-cp output and again on the copies placed into the payload. Non-zero,
# naming each problem, unless each of the four binaries in <dir> has the sha256
# <stamp-text> records (exactly one line each), carries the tag's -X version
# string, and passes cp_binary_problems against <raises> ("<module> <version>"
# per line, build-cp.sh's live list); and every raised module is linked by at
# least one of the four. <stamp-text> is a snapshot taken once, so bytes or a
# stamp rewritten later cannot pass a later run of this check.
cp_set_check() {
	local dir="$1" tag="$2" raises="$3" stamp="$4" bad=0 rel name want got links="" out mod
	while IFS= read -r rel; do
		name="${rel#cp-payload/}"
		want="$(printf '%s\n' "$stamp" | awk -v n="$name" '$1 == "sha256:" && $3 == n { print $2; c++ } END { if (c != 1) print "" }' | tail -n 1)"
		got="$(shasum -a 256 "$dir/$name" 2>/dev/null | awk '{print $1}')"
		[ -n "$want" ] && [ "$got" = "$want" ] || { echo "    $dir/$name: sha256 ${got:-?} is not the one $CP_STAMP_NAME records (${want:-none, or more than one})"; bad=1; }
		LC_ALL=C grep -aqF -- "$tag" "$dir/$name" 2>/dev/null || { echo "    $dir/$name: carries no $tag version string"; bad=1; }
		if ! out="$("$GO" version -m "$dir/$name" 2>/dev/null | cp_binary_problems "$name" "$tag" "$raises")"; then
			printf '%s\n' "$out" | sed -n 's/^PROBLEM /    /p'
			bad=1
		fi
		links="$links $(printf '%s\n' "$out" | sed -n 's/^LINKS //p' | tr '\n' ' ')"
	done <<<"$PINNED_SOURCE_FILES"
	while read -r mod _; do
		[ -n "$mod" ] || continue
		case " $links " in *" $mod "*) ;; *) echo "    no control-plane binary links raised $mod"; bad=1 ;; esac
	done <<<"$raises"
	return "$bad"
}

# cp_build_check <dir> <key> <raises> <raise-hash> <stamp-text>: the one check of
# a build-cp output, run on the lab cache before reuse, on a fresh lab build, and
# on --release --cp-build. <key>, <raises> and <raise-hash> are build-cp.sh's own
# (--print-cache-key, --print-raises, --print-raise-list-hash); <stamp-text> is
# the snapshot of <dir>'s stamp the caller took. Non-zero, naming each problem,
# unless <dir> is exactly build-cp's file set (cp_build_problems); the stamp
# names cache key <key>, the payload toolchain, the key's tag and raise-list
# sha256 <raise-hash>, and its raise-list lines are exactly <raises>; and the
# four binaries pass cp_set_check against that snapshot.
cp_build_check() {
	local dir="$1" key="$2" raises="$3" rhash="$4" stamp="$5" tag bad=0 stamped
	tag="${key%%-go[0-9]*}"
	cp_build_problems "$dir" || return 1
	printf '%s\n' "$stamp" | grep -qxF -- "cache-key: $key" || { echo "    $CP_STAMP_NAME does not name cache key $key (built from another tag, toolchain or raise list)"; bad=1; }
	printf '%s\n' "$stamp" | grep -qF -- "toolchain: $PAYLOAD_GO_VERSION " || { echo "    $CP_STAMP_NAME does not name toolchain $PAYLOAD_GO_VERSION"; bad=1; }
	printf '%s\n' "$stamp" | grep -qF -- "tag: $tag " || { echo "    $CP_STAMP_NAME does not name tag $tag"; bad=1; }
	printf '%s\n' "$stamp" | grep -qxF -- "raise-list-sha256: $rhash" || { echo "    $CP_STAMP_NAME does not name raise-list-sha256 $rhash (build-cp.sh's live raise list)"; bad=1; }
	stamped="$(printf '%s\n' "$stamp" | sed -n 's/^raise-list: \([^ ]*\) \([^ ]*\) .*/\1 \2/p' | LC_ALL=C sort)"
	[ "$stamped" = "$(printf '%s\n' "$raises" | sed '/^$/d' | LC_ALL=C sort)" ] || { echo "    $CP_STAMP_NAME's raise-list lines are not build-cp.sh's live raise list"; bad=1; }
	cp_set_check "$dir" "$tag" "$raises" "$stamp" || bad=1
	return "$bad"
}

# cp_live <build-cp>: build-cp.sh's live key, raise list and raise-list hash, as
# three assignments the caller evals (CP_KEY, CP_RAISES, CP_RHASH). Non-zero if
# build-cp.sh cannot print them or prints a malformed key or hash.
cp_live() {
	local bcp="$1" key raises rhash
	key="$("$bcp" --print-cache-key)" || { echo "stage: $bcp --print-cache-key failed" >&2; return 1; }
	printf '%s' "$key" | grep -Eq '^v[0-9][0-9A-Za-z.+-]*-go[0-9][0-9.]*-[0-9a-f]{16}$' || { echo "stage: unexpected cache key '$key'" >&2; return 1; }
	raises="$("$bcp" --print-raises)" || { echo "stage: $bcp --print-raises failed" >&2; return 1; }
	rhash="$("$bcp" --print-raise-list-hash)" || { echo "stage: $bcp --print-raise-list-hash failed" >&2; return 1; }
	printf '%s' "$rhash" | grep -Eq '^[0-9a-f]{64}$' || { echo "stage: unexpected raise-list hash '$rhash'" >&2; return 1; }
	printf 'CP_KEY=%q\nCP_RAISES=%q\nCP_RHASH=%q\n' "$key" "$raises" "$rhash"
}

# cache_root_problems <dir> [<what>]: non-zero, naming the problem, unless <dir>
# is a directory (not a symlink) owned by the effective uid and not writable by
# group or other: another user who could write it could plant or swap a build.
# Run on the lab cache root, and on --cp-build and its parent.
cache_root_problems() {
	local root="$1" what="${2:-cache root}" owner mode
	[ -d "$root" ] && [ ! -L "$root" ] || { echo "stage: $what $root is not a directory"; return 1; }
	owner="$(stat -f '%u' "$root")" mode="$(stat -f '%Lp' "$root")"
	[ "$owner" = "$(id -u)" ] || { echo "stage: $what $root is owned by uid $owner, not $(id -u)"; return 1; }
	[ $((8#$mode & 8#022)) = 0 ] || { echo "stage: $what $root is writable by group or other (mode $mode)"; return 1; }
}

# lab_cp_build <cache-root> <build-cp>: print the directory of a build-cp output
# for the key `<build-cp> --print-cache-key` prints today, building it into
# <cache-root>/<key> first unless one there passes cp_build_check for that key.
# A fresh build goes to a mktemp directory under the root and is renamed into
# place only once it passes; the cache's directories for other keys are then
# removed (a run's temp directory never matches that sweep). Progress goes to
# stderr.
lab_cp_build() (
	local root="$1" bcp="$2" key dir old part live CP_KEY CP_RAISES CP_RHASH
	live="$(cp_live "$bcp")" || return 1
	eval "$live"
	key="$CP_KEY"
	(umask 077 && mkdir -p "$root") || return 1
	root="$(cd "$root" && pwd -P)"
	cache_root_problems "$root" >&2 || return 1
	dir="$root/$key"
	if [ -d "$dir" ] && cp_build_check "$dir" "$key" "$CP_RAISES" "$CP_RHASH" "$(cat "$dir/$CP_STAMP_NAME" 2>/dev/null)" >/dev/null 2>&1; then
		echo "==> control-plane binaries: reusing the build-cp cache $dir (stamp, digests and build info checked)" >&2
		printf '%s\n' "$dir"
		return 0
	fi
	echo "==> control-plane binaries: no valid cached build for $key; running build-cp.sh (a full Kubernetes build)" >&2
	part="$(mktemp -d "$root/.partial.XXXXXX")" || return 1
	# A fresh build that fails, is refused or is interrupted leaves no partial
	# directory behind. The function body is a subshell, so these traps are its
	# own and never replace a caller's.
	# shellcheck disable=SC2064 # expand now: part is local
	trap "cleanup_dir '$part'" EXIT
	# shellcheck disable=SC2064 # expand now: part is local
	trap "cleanup_dir '$part'; exit 1" INT TERM HUP
	"$bcp" "$part" >&2 || { echo "stage: build-cp.sh failed" >&2; return 1; }
	if ! cp_build_check "$part" "$key" "$CP_RAISES" "$CP_RHASH" "$(cat "$part/$CP_STAMP_NAME" 2>/dev/null)" >&2; then
		echo "stage: build-cp.sh's output in $part is not a valid build for $key" >&2
		return 1
	fi
	cleanup_dir "$dir"
	mv "$part" "$dir" || return 1
	for old in "$root"/v*-go*-*; do
		[ -d "$old" ] && [ "$old" != "$dir" ] || continue
		cleanup_dir "$old"
	done
	printf '%s\n' "$dir"
)

# cleanup_dir <dir>: remove a directory tree, read-only parts included.
cleanup_dir() { [ -e "$1" ] || return 0; chmod -R u+w "$1" 2>/dev/null || true; rm -rf "$1"; }

# place_cp_build <cp-build> <payload-dir>: put each pinned-source file into the
# payload dir as a new file (copy into a fresh mktemp file there, then rename),
# replacing what the payload step staged under that name.
place_cp_build() {
	local src="$1" dst="$2" rel name t
	while IFS= read -r rel; do
		name="${rel#cp-payload/}"
		t="$(mktemp "$dst/.$name.XXXXXX")" || return 1
		if ! { cp "$src/$name" "$t" && chmod 0755 "$t" && mv -f "$t" "$dst/$name"; }; then
			rm -f "$t"
			return 1
		fi
	done <<<"$PINNED_SOURCE_FILES"
}

# pinned_content_problems <tree> <cp-build>: non-zero, naming each, unless every
# pinned-source file in the tree is byte-identical to its --cp-build copy.
pinned_content_problems() {
	local tree="$1" src="$2" rel bad=0
	while IFS= read -r rel; do
		cmp -s "$tree/$rel" "$src/${rel#cp-payload/}" || { echo "    NOT THE PINNED-SOURCE BUILD: $rel"; bad=1; }
	done <<<"$PINNED_SOURCE_FILES"
	return "$bad"
}

# refuse_unpinned_payload <tree> <pinned-list>: non-zero, naming each file, if
# any cp-payload file is absent from the pinned-source list.
refuse_unpinned_payload() {
	local tree="$1" list="$2" rel bad=0
	while IFS= read -r rel; do
		printf '%s\n' "$list" | grep -qxF -- "$rel" || { echo "    NOT BUILT FROM PINNED SOURCE: $rel"; bad=1; }
	done < <(cd "$tree" && find cp-payload -type f | LC_ALL=C sort)
	return "$bad"
}

# ---- the children vuln scan ------------------------------------------------------
# Every Go binary in the payload is scanned with govulncheck before anything is
# signed. The set is release_payload_files, the one list release staging accepts
# (and refuses everything else against), so a child added to the payload is
# scanned the moment it is added there; a name with no version mapping below is
# a red, never a skip.

# child_scan_version <name>: the pin a staged cp-payload file was built or
# downloaded at, the version the allow file keys on. Needs read_pins. Returns 1
# for a name with no mapping, and 2, the child named on stderr, when the mapping
# resolves to an empty version (read_pins not run, or the pin unset).
child_scan_version() {
	local v
	case "$1" in
	kube-apiserver | kube-scheduler | kube-controller-manager | kubectl) v="$KUBE_VERSION" ;;
	kine) v="$KINE_VERSION" ;;
	etcd | etcdutl) v="$ETCD_VERSION" ;;
	zot) v="$ZOT_VERSION" ;;
	"$HELM_BINARY") v="$HELM_VERSION" ;;
	*) return 1 ;;
	esac
	[ -n "$v" ] || { echo "child_scan_version: $1 resolves to an empty version (read_pins not run, or its pin unset)" >&2; return 2; }
	printf '%s\n' "$v"
}

# child_scan_set <payload-dir>: `<child> <version> <path>` per Go binary of
# release_payload_files (version markers skipped; helm under its unversioned
# name, as the allow file writes it). A listed file that is missing, has no
# version mapping or an empty version, or that `go version` cannot read as a Go
# binary is named on stdout and returns 1.
child_scan_set() {
	local dir="$1" rel name child ver bad=0 vrc
	while IFS= read -r rel; do
		case "$rel" in *.version | "") continue ;; esac
		name="${rel#cp-payload/}"
		child="$name"
		[ "$name" = "$HELM_BINARY" ] && child=helm
		vrc=0
		ver="$(child_scan_version "$name")" || vrc=$?
		if [ "$vrc" = 1 ]; then
			echo "PROBLEM $name: no version mapping in child_scan_version (add one so the scan can key the allow file)"
			bad=1
			continue
		elif [ "$vrc" != 0 ]; then
			echo "PROBLEM $name: empty version (read_pins not run, or its pin unset)"
			bad=1
			continue
		fi
		[ -f "$dir/$name" ] || { echo "PROBLEM $name: not staged in $dir"; bad=1; continue; }
		# `go version <file>` exits 0 even for a file it cannot read, so the verdict
		# is its stdout: "<file>: go<version>" for a Go binary, nothing otherwise.
		case "$("$GO" version "$dir/$name" 2>/dev/null)" in
		"$dir/$name: go"[0-9]*) ;;
		*) echo "PROBLEM $name: not a readable Go binary; every entry of release_payload_files must be one"; bad=1; continue ;;
		esac
		printf '%s %s %s\n' "$child" "$ver" "$dir/$name"
	done < <(release_payload_files)
	return "$bad"
}

# children_vuln_scan <payload-dir> [<db-url>]: the children scan. Red on a
# missing or wrong-version govulncheck, an untrustworthy scan (named), an
# unallowed symbol-level finding, or an expired or stale allow entry.
children_vuln_scan() {
	local dir="$1" db="${2:-}" pin gv scanset line args=() c v p
	pin="$(gv_pin)" || return 1
	gv="$(gv_find "$pin")" || return 1
	if ! scanset="$(child_scan_set "$dir")"; then
		printf '%s\n' "$scanset" | sed -n 's/^PROBLEM /    /p'
		return 1
	fi
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		read -r c v p <<<"$line"
		args+=("$c" "$v" "$p")
	done <<<"$scanset"
	[ "${#args[@]}" -gt 0 ] || { echo "    no Go child found in $dir"; return 1; }
	gv_scan_children "$gv" "$pin" "$GV_ALLOW" "$(date -u +%Y-%m-%d)" "$db" "${args[@]}"
}

# gv_self_test <tmp>: the children vuln scan, hermetically. A tiny Go program
# is built with the flags the stripped children use (-trimpath -ldflags "-s -w",
# as hack/release/build-cp.sh builds the control-plane binaries),
# and govulncheck reads a planted local database (-db file://...), so no case
# touches the network. Uses self_test's ok/bad.
gv_self_test() {
	local t="$1/gv" pin gv today soon far o rc probe plain
	local plant="$t/db-plant" info="$t/db-info"
	today="$(date -u +%Y-%m-%d)"
	soon="$(date -u -v+30d +%Y-%m-%d)" far="$(date -u -v+200d +%Y-%m-%d)"
	mkdir -p "$t/prog" "$plant" "$info"
	printf 'module example.com/gvprobe\n\ngo 1.26\n' >"$t/prog/go.mod"
	cat >"$t/prog/main.go" <<'GO'
package main

import (
	"fmt"
	"os"
)

func main() { fmt.Fprintln(os.Stdout, fmt.Sprintf("%d", len(os.Args))) }
GO
	probe="$t/probe" plain="$t/probe-unstripped"
	echo "==> children vuln scan: build the probe child (stripped, like the -s -w control-plane builds) and plant a database"
	if ! (cd "$t/prog" && GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 "$GO" build -trimpath -ldflags "-s -w" -o "$probe" . &&
		GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 "$GO" build -trimpath -o "$plain" .); then
		bad "children vuln scan: could not build the probe program"
		return 0
	fi
	# One entry on a symbol the probe calls (fmt.Sprintf), one on a symbol it
	# does not link (net/smtp.SendMail). The stdlib range is open, so it matches
	# whatever toolchain built the probe.
	gv_osv() {
		printf '{"schema_version":"1.3.1","id":"%s","modified":"2099-01-01T00:00:00Z","published":"2099-01-01T00:00:00Z","summary":"synthetic","details":"synthetic self-test entry","affected":[{"package":{"name":"stdlib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],"ecosystem_specific":{"imports":[{"path":"%s","symbols":["%s"]}]}}]}\n' "$1" "$2" "$3"
	}
	gv_osv GO-2099-0001 fmt Sprintf >"$plant/GO-2099-0001.json"
	gv_osv GO-2099-0002 net/smtp SendMail >"$info/GO-2099-0002.json"
	unset -f gv_osv

	if ! pin="$(gv_pin)"; then bad "children vuln scan: no pin in hack/ci.sh"; return 0; fi
	if ! gv="$(gv_find "$pin")"; then
		bad "children vuln scan: govulncheck $pin is needed for the scan cases (go install golang.org/x/vuln/cmd/govulncheck@$pin)"
		return 0
	fi
	# scan <allow-text> <db-dir> <binary>: run the scan, set o (output) and rc.
	scan() {
		printf '%s\n' "$1" >"$t/allow"
		rc=0
		o="$(gv_scan_children "$gv" "$pin" "$t/allow" "$today" "file://$2" probe v0.0.1 "$3" 2>&1)" || rc=$?
	}
	# expect <case> <want-rc> <want-substring>...
	expect() {
		local name="$1" want="$2" s miss=""
		shift 2
		for s in "$@"; do printf '%s\n' "$o" | grep -qF -- "$s" || miss="$miss '$s'"; done
		if [ "$rc" = "$want" ] && [ -z "$miss" ]; then
			ok "$name"
		else
			bad "$name: exit $rc (want $want)${miss:+, missing$miss}: $o"
		fi
	}

	scan "" "$plant" "$probe"
	expect "vuln scan: a planted finding in a stripped binary is red" 1 "FINDING  probe v0.0.1: GO-2099-0001" "fmt.Sprintf"
	scan "GO-2099-0001 probe v0.0.1 synthetic self-test reason $soon" "$plant" "$probe"
	expect "vuln scan: a matching allow entry turns it green" 0 "allowed  probe v0.0.1: GO-2099-0001"
	scan "GO-2099-0001 probe v0.0.1 synthetic self-test reason 2000-01-01" "$plant" "$probe"
	expect "vuln scan: an expired allow entry is red" 1 "EXPIRED 2000-01-01"
	scan "GO-2099-0001 probe v0.0.1 synthetic self-test reason $soon
GO-2099-0009 probe v0.0.1 matches nothing in this scan $soon" "$plant" "$probe"
	expect "vuln scan: a stale allow entry matching no finding is red" 1 "STALE, GO-2099-0009 probe v0.0.1"
	scan "GO-2099-0001 probe v0.0.0 keyed on the previous pin $soon" "$plant" "$probe"
	expect "vuln scan: an entry keyed on another child version does not allow (a pin bump re-reviews)" 1 "FINDING  probe v0.0.1: GO-2099-0001" "STALE, GO-2099-0001 probe v0.0.0"
	scan "" "$info" "$plain"
	expect "vuln scan: a finding with no vulnerable symbol in the binary is informational" 0 "info     probe v0.0.1: GO-2099-0002"
	scan "" "$info" "$probe"
	expect "vuln scan: a stripped binary is read conservatively (every symbol of the package counts)" 1 "FINDING  probe v0.0.1: GO-2099-0002"
	scan "" "$t/no-such-db" "$probe"
	expect "vuln scan: an unreachable vulnerability database is a named red" 1 "vuln DB unreachable"
	scan "GO-2099-0001 probe v0.0.1 $soon" "$plant" "$probe"
	expect "vuln scan: a malformed allow entry is red" 1 "want <GO-id> <child> <child-version> <reason> <expiry>"
	scan "GO-2099-0001 probe v0.0.1 synthetic self-test reason $far" "$plant" "$probe"
	expect "vuln scan: an allow expiry more than 120 days out is red" 1 "is more than 120 days after"
	scan "GO-2099-0001 probe v0.0.1 too short $soon" "$plant" "$probe"
	expect "vuln scan: an allow reason under 20 characters is red" 1 "is shorter than 20 characters"
	scan "GO-2099-0002 probe v0.0.1 informational finding only, not a symbol hit $soon" "$info" "$plain"
	expect "vuln scan: an entry matching only an informational finding is stale" 1 "STALE, GO-2099-0002 probe v0.0.1"
	printf 'probe v0.0.1 symbol\n' >"$t/findings-short"
	printf '' >"$t/allow"
	rc=0
	o="$(gv_allow_check "$t/allow" "$today" "$t/findings-short" 2>&1)" || rc=$?
	expect "vuln scan: a findings line with fewer than 5 fields is red" 1 "malformed findings line"

	# Fake tools: absent, the wrong version, a stream with no config, a stream
	# cut short. The fakes report the pin on -version where the case needs it.
	mkdir -p "$t/nogv/bin" "$t/nogv/gopath" "$t/fake"
	ln -s "$(command -v "$GO")" "$t/nogv/bin/go"
	rc=0
	o="$(PATH="$t/nogv/bin:/usr/bin:/bin" GOPATH="$t/nogv/gopath" gv_find "$pin" 2>&1)" || rc=$?
	expect "vuln scan: an absent govulncheck is a named red" 1 "govulncheck missing or wrong version"
	# fake <name> <version>  (stdin: the body run for a scan)
	fake() {
		{ printf '#!/bin/sh\nif [ "$1" = -version ]; then echo "Scanner: govulncheck@%s"; exit 0; fi\n' "$2"; cat; } >"$t/fake/$1"
		chmod 0755 "$t/fake/$1"
	}
	mkdir -p "$t/fake-old/bin"
	fake govulncheck v0.0.0 <<<'exit 0'
	mv "$t/fake/govulncheck" "$t/fake-old/bin/govulncheck"
	rc=0
	o="$(PATH="$t/fake-old/bin:$t/nogv/bin:/usr/bin:/bin" GOPATH="$t/nogv/gopath" gv_find "$pin" 2>&1)" || rc=$?
	expect "vuln scan: a govulncheck at another version is a named red" 1 "govulncheck missing or wrong version" "reports v0.0.0"
	fake noconfig "$pin" <<'SH'
echo '{"progress":{"message":"x"}}'
SH
	rc=0
	o="$(gv_scan_children "$t/fake/noconfig" "$pin" "$t/allow" "$today" "" probe v0.0.1 "$probe" 2>&1)" || rc=$?
	expect "vuln scan: a stream with no config message is a named red" 1 "no config message"
	fake truncated "$pin" <<SH
printf '%s\n' '{"config":{"scanner_version":"$pin","scan_mode":"binary"}}' '{"finding": {"osv": "GO-2099-0001"'
SH
	rc=0
	o="$(gv_scan_children "$t/fake/truncated" "$pin" "$t/allow" "$today" "" probe v0.0.1 "$probe" 2>&1)" || rc=$?
	expect "vuln scan: a stream that does not end cleanly is a named red" 1 "malformed JSON stream"
	fake otherdb "$pin" <<SH
printf '%s\n' '{"config":{"scanner_version":"$pin","scan_mode":"binary","db":"https://mirror.example.com/vulndb","db_last_modified":"${today}T00:00:00Z"}}'
SH
	rc=0
	o="$(gv_scan_children "$t/fake/otherdb" "$pin" "$t/allow" "$today" "" probe v0.0.1 "$probe" 2>&1)" || rc=$?
	expect "vuln scan: a config naming another database is a named red" 1 "vulnerability database is not the production one" "mirror.example.com"
	fake staledb "$pin" <<SH
printf '%s\n' '{"config":{"scanner_version":"$pin","scan_mode":"binary","db":"https://vuln.go.dev","db_last_modified":"2000-01-01T00:00:00Z"}}'
SH
	rc=0
	o="$(gv_scan_children "$t/fake/staledb" "$pin" "$t/allow" "$today" "" probe v0.0.1 "$probe" 2>&1)" || rc=$?
	expect "vuln scan: a stale database (db_last_modified over 30 days old) is a named red" 1 "vulnerability database is stale" "2000-01-01"
	fake proddb "$pin" <<SH
printf '%s\n' '{"config":{"scanner_version":"$pin","scan_mode":"binary","db":"https://vuln.go.dev","db_last_modified":"${today}T00:00:00Z"}}'
SH
	rc=0
	o="$(gv_scan_children "$t/fake/proddb" "$pin" "$t/allow" "$today" "" probe v0.0.1 "$probe" 2>&1)" || rc=$?
	expect "vuln scan: a fresh production database with no findings is green" 0 "scan probe v0.0.1"
	unset -f fake

	# The scan set is release_payload_files: every listed Go binary is scanned
	# under its pin, and a listed name with no version mapping is a red.
	(
		read_pins
		pd="$t/payload"
		mkdir -p "$pd"
		while IFS= read -r rel; do
			case "$rel" in *.version) echo marker >"$pd/${rel#cp-payload/}" ;; *) cp "$probe" "$pd/${rel#cp-payload/}" ;; esac
		done < <(release_payload_files)
		want="$(release_payload_files | grep -vc '\.version$')"
		if o="$(child_scan_set "$pd" 2>/dev/null)" && [ "$(printf '%s\n' "$o" | grep -c .)" = "$want" ] &&
			printf '%s\n' "$o" | grep -q "^helm $HELM_VERSION $pd/$HELM_BINARY\$" &&
			printf '%s\n' "$o" | grep -q "^kube-apiserver $KUBE_VERSION " && printf '%s\n' "$o" | grep -q "^zot $ZOT_VERSION "; then
			echo "  ok    vuln scan set: every Go binary of release_payload_files ($want), each under its pin"
		else
			echo "  FAIL  vuln scan set: $o"; exit 1
		fi
		echo "not a Go binary" >"$pd/kine"
		if o="$(child_scan_set "$pd" 2>/dev/null)"; then
			echo "  FAIL  a listed payload file that is not a Go binary was skipped, not red"; exit 1
		elif printf '%s\n' "$o" | grep -q "PROBLEM kine: not a readable Go binary"; then
			echo "  ok    vuln scan set: a listed payload file that is not a Go binary is red"
		else
			echo "  FAIL  vuln scan set: the non-Go kine not named: $o"; exit 1
		fi
		cp "$probe" "$pd/kine"
		if o="$(ZOT_VERSION="" child_scan_set "$pd" 2>/dev/null)"; then
			echo "  FAIL  a child whose pin resolves empty was scanned"; exit 1
		elif printf '%s\n' "$o" | grep -q "PROBLEM zot: empty version"; then
			echo "  ok    vuln scan set: a child whose version resolves empty is red, named"
		else
			echo "  FAIL  vuln scan set: the empty zot version not named: $o"; exit 1
		fi
		K3SM_BUILT_FILES="$K3SM_BUILT_FILES
cp-payload/newchild"
		cp "$probe" "$pd/newchild"
		if o="$(child_scan_set "$pd" 2>/dev/null)"; then
			echo "  FAIL  a payload child with no version mapping was scanned without a pin"; exit 1
		elif printf '%s\n' "$o" | grep -q "PROBLEM newchild: no version mapping"; then
			echo "  ok    vuln scan set: a new payload child with no version mapping is red"
		else
			echo "  FAIL  vuln scan set: newchild not named: $o"; exit 1
		fi
	) || fails=$((fails + 1))
	unset -f scan expect
}

# ---- self-test --------------------------------------------------------------------
# Hermetic: no network, no credentials, no keychain, no Developer ID identity.
#
# Fixtures (testdata/):
#   codesign-adhoc-*.txt        real `codesign -dvvv` output, captured on a
#                               macOS 27 host from clang-built binaries signed
#                               with `codesign -s -` (the Executable= path is
#                               rewritten to /fixture/<name>).
#   codesign-devid-synthetic.txt SYNTHETIC text in codesign's documented
#                               Developer ID display format. The positive path
#                               of the parser, and of the chain-of-trust check
#                               (via a CODESIGN override), is therefore
#                               TEXT-PROVEN ONLY here. Outside the self-test,
#                               verify_release_signatures was run once by hand
#                               over standalone third-party Developer ID
#                               binaries on a dev Mac and accepted them; the
#                               first run against a k3sm signature is the
#                               signing pipeline's post-sign --verify-release.
self_test() {
	local td="$HERE/testdata" self="$HERE/stage.sh" tmp fails=0 out
	local team=ABCDE12345 pos="$HERE/testdata/codesign-devid-synthetic.txt"
	tmp="$(mktemp -d -t k3sm-stage-selftest)"
	# shellcheck disable=SC2064 # expand now: tmp is local
	trap "rm -rf '$tmp'" EXIT

	ok() { echo "  ok    $*"; }
	bad() { echo "  FAIL  $*"; fails=$((fails + 1)); }
	# expect_fail <name> <want-substring> <text>: the parser must reject <text>
	# and name <want-substring> among the problems.
	expect_fail() {
		local name="$1" want="$2" text="$3" o
		if o="$(printf '%s\n' "$text" | release_sig_problems "$team")"; then
			bad "$name: parser ACCEPTED it"
		elif printf '%s\n' "$o" | grep -q -- "$want"; then
			ok "$name: rejected ($want)"
		else
			bad "$name: rejected but '$want' not named: $o"
		fi
	}

	command -v clang >/dev/null 2>&1 || die "self-test needs clang (Command Line Tools) to build its ad-hoc fixtures"

	echo "==> parser: synthetic Developer ID positive (text-proven only)"
	if out="$(release_sig_problems "$team" <"$pos")"; then ok "positive fixture accepted"; else bad "positive fixture rejected: $out"; fi
	if out="$(release_sig_problems ZZZZZ99999 <"$pos")"; then
		bad "positive fixture accepted for another team"
	elif printf '%s\n' "$out" | grep -q "^team:" && printf '%s\n' "$out" | grep -q "^authority:"; then
		ok "positive fixture rejected for another team (team, authority)"
	else
		bad "positive fixture, other team: problems not named: $out"
	fi

	echo "==> parser: single-field failures derived from the positive fixture"
	local P; P="$(cat "$pos")"
	expect_fail "no runtime flag" "hardened runtime" "$(printf '%s\n' "$P" | sed 's/flags=0x10000(runtime)/flags=0x0(none)/')"
	expect_fail "runtime name, no runtime bit" "hardened runtime" "$(printf '%s\n' "$P" | sed 's/flags=0x10000(runtime)/flags=0x20000(runtime)/')"
	expect_fail "ad-hoc flag bit" "ad-hoc bit" "$(printf '%s\n' "$P" | sed 's/flags=0x10000(runtime)/flags=0x10002(adhoc,runtime)/')"
	expect_fail "malformed flags" "malformed" "$(printf '%s\n' "$P" | sed 's/flags=0x10000(runtime)/flags=0xZZ(runtime)/')"
	expect_fail "missing CodeDirectory" "CodeDirectory" "$(printf '%s\n' "$P" | sed '/^CodeDirectory /d')"
	expect_fail "Signed Time instead of Timestamp" "Signed Time" "$(printf '%s\n' "$P" | sed 's/^Timestamp=/Signed Time=/')"
	expect_fail "Timestamp=none" "not a secure timestamp" "$(printf '%s\n' "$P" | sed 's/^Timestamp=.*/Timestamp=none/')"
	expect_fail "missing Timestamp" "Timestamp= line" "$(printf '%s\n' "$P" | sed '/^Timestamp=/d')"
	expect_fail "wrong TeamIdentifier" "TeamIdentifier='ZZZZZ99999'" "$(printf '%s\n' "$P" | sed 's/^TeamIdentifier=.*/TeamIdentifier=ZZZZZ99999/')"
	expect_fail "TeamIdentifier=not set" "TeamIdentifier='not set'" "$(printf '%s\n' "$P" | sed 's/^TeamIdentifier=.*/TeamIdentifier=not set/')"
	expect_fail "missing TeamIdentifier" "TeamIdentifier= line" "$(printf '%s\n' "$P" | sed '/^TeamIdentifier=/d')"
	expect_fail "Apple Development leaf" "authority" "$(printf '%s\n' "$P" | sed 's/Authority=Developer ID Application:/Authority=Apple Development:/')"
	expect_fail "leaf of another team" "authority" "$(printf '%s\n' "$P" | sed 's/Example Corp (ABCDE12345)/Example Corp (ZZZZZ99999)/')"
	expect_fail "missing Authority" "no Authority" "$(printf '%s\n' "$P" | sed '/^Authority=/d')"
	expect_fail "Signature=adhoc" "Signature=adhoc" "$(printf '%s\nSignature=adhoc\n' "$P")"
	expect_fail "empty input" "flags" ""
	expect_fail "unsigned file" "flags" "x: code object is not signed at all"

	echo "==> parser: real ad-hoc captures fail on flags, timestamp and team"
	local fx
	for fx in "$td"/codesign-adhoc-*.txt; do
		for want in "flags:" "timestamp:" "team:"; do
			expect_fail "$(basename "$fx")" "$want" "$(cat "$fx")"
		done
	done

	echo "==> --from-captured drives the same parser"
	if "$self" --from-captured "$pos" --verify-release "$team" >/dev/null 2>&1; then ok "--from-captured positive"; else bad "--from-captured positive rejected"; fi
	if "$self" --from-captured "$td/codesign-adhoc-thin.txt" --verify-release "$team" >/dev/null 2>&1; then bad "--from-captured accepted an ad-hoc capture"; else ok "--from-captured rejects ad-hoc"; fi
	if "$self" --from-captured "$pos" --verify-release abcde12345 >/dev/null 2>&1; then bad "a malformed TEAMID was accepted"; else ok "malformed TEAMID refused"; fi

	echo "==> live ad-hoc tree (codesign -s -) fails --verify-release"
	local tree="$tmp/adhoc"
	mkdir -p "$tree/cp-payload"
	printf 'int main(void){return 0;}\n' >"$tmp/m.c"
	clang -arch arm64 -o "$tree/k3sm" "$tmp/m.c"
	cp "$tree/k3sm" "$tree/k3sm-execshim"
	cp "$tree/k3sm" "$tree/cp-payload/kube-apiserver"
	clang -arch arm64 -arch x86_64 -o "$tree/universal" "$tmp/m.c"
	printf 'not a Mach-O\n' >"$tree/README"
	local f n
	for f in "$tree/k3sm" "$tree/cp-payload/kube-apiserver" "$tree/universal"; do
		codesign -s - -f "$f" >/dev/null 2>&1 || die "self-test: ad-hoc codesign failed for $f"
	done
	# One carries the runtime flag, so its failure must come from the timestamp
	# and the team, not the flags.
	codesign -s - -f -o runtime "$tree/k3sm-execshim" >/dev/null 2>&1 || die "self-test: ad-hoc codesign failed"
	if out="$(verify_release_signatures "$tree" "$team")"; then
		bad "ad-hoc tree PASSED the release policy"
	else
		for want in "flags: .* lacks the hardened runtime" "ad-hoc bit" "timestamp:" "team:" "authority:" "universal \[x86_64\]" "universal \[arm64\]"; do
			if printf '%s\n' "$out" | grep -q -- "$want"; then ok "ad-hoc tree: '$want' reported"; else bad "ad-hoc tree: '$want' not reported"; fi
		done
		if printf '%s\n' "$out" | grep -q "k3sm-execshim \[arm64\]: flags:.*runtime"; then
			bad "runtime-signed ad-hoc binary reported as lacking runtime"
		else
			ok "runtime-signed ad-hoc binary fails on the other fields only"
		fi
		# The real codesign, not an override: every ad-hoc slice (3 thin + 2
		# universal) must fail the designated-requirement check.
		n="$(printf '%s\n' "$out" | grep -c ": chain: " || true)"
		if [ "$n" = 5 ]; then ok "ad-hoc tree: the chain-of-trust requirement fails on all 5 slices"; else bad "ad-hoc tree: chain failure on $n of 5 slices"; fi
	fi
	if out="$("$self" "$tree" --verify-release "$team" 2>&1)"; then
		bad "stage.sh <ad-hoc tree> --verify-release exited 0"
	elif printf '%s\n' "$out" | grep -q "timestamp:"; then
		ok "stage.sh <ad-hoc tree> --verify-release exits non-zero, naming the signature problems"
	else
		bad "stage.sh --verify-release failed without naming the signature problems"
	fi

	echo "==> the walk accepts a tree whose every slice reads as the positive fixture"
	printf '#!/bin/sh\ncat "%s" >&2\n' "$pos" >"$tmp/fake-codesign"
	chmod +x "$tmp/fake-codesign"
	# In this self-test the chain-of-trust check's positive path is proven only
	# through this override (it exits 0 for --verify too): a hermetic test has
	# no real Developer ID signature. See the fixture note above self_test.
	if out="$(CODESIGN="$tmp/fake-codesign" verify_release_signatures "$tree" "$team")"; then ok "walk + parser + chain accept (5 slices over 4 Mach-Os, override)"; else bad "walk rejected the positive text: $out"; fi
	# Perfect display text but a failing chain must still fail.
	printf '#!/bin/sh
case "$1" in --verify) exit 1 ;; esac
cat "%s" >&2
' "$pos" >"$tmp/fake-codesign-badchain"
	chmod +x "$tmp/fake-codesign-badchain"
	if out="$(CODESIGN="$tmp/fake-codesign-badchain" verify_release_signatures "$tree" "$team")"; then
		bad "a failing chain-of-trust check was ignored"
	elif printf '%s\n' "$out" | grep -q ": chain: "; then ok "a failing chain-of-trust check fails the walk"; else bad "chain failure not named: $out"; fi
	rm "$tree/universal"
	if out="$(CODESIGN="$tmp/fake-codesign" verify_release_signatures "$tree" "$team")"; then
		bad "a 3-Mach-O tree passed the floor"
	elif printf '%s\n' "$out" | grep -q "floor"; then ok "Mach-O floor enforced"; else bad "floor failure not named: $out"; fi

	echo "==> payload manifest"
	local m1="$tmp/m1" m2="$tmp/m2" d
	for d in "$m1" "$m2"; do mkdir -p "$d/a" "$d/sub"; done
	# The same content, created in opposite orders.
	for f in B a-b a/b aa .hidden sub/.DS_Store .DS_Store "-dash"; do printf '%s\n' "$f" >"$m1/$f"; done
	for f in "-dash" .DS_Store sub/.DS_Store .hidden aa a/b a-b B; do printf '%s\n' "$f" >"$m2/$f"; done
	printf 'stale\n' >"$m1/$MANIFEST_NAME"
	if ( manifest_write "$m1" "toolchain: test" ) && ( manifest_write "$m2" "toolchain: test" ); then
		ok "manifest written"
	else
		bad "manifest_write failed"
	fi
	if cmp -s "$m1/$MANIFEST_NAME" "$m2/$MANIFEST_NAME"; then ok "reproducible across creation order"; else bad "manifests differ across creation order"; fi
	if cmp -s "$m1/$MANIFEST_NAME" "$m1.$MANIFEST_NAME"; then ok "copy beside the tree is identical"; else bad "beside copy differs"; fi
	out="$(grep -v '^#' "$m1/$MANIFEST_NAME" | sed 's/^[0-9a-f]\{64\}  //' | tr '\n' ' ')"
	if [ "$out" = "-dash .hidden B a-b a/b aa " ]; then ok "LC_ALL=C order, no ./, .DS_Store and the manifest excluded"; else bad "unexpected path list: '$out'"; fi
	if [ "$(head -1 "$m1/$MANIFEST_NAME")" = "# toolchain: test" ]; then ok "comment line leads, outside the hashed set"; else bad "comment line missing"; fi
	if ( cd "$m1" && shasum -a 256 -c "$MANIFEST_NAME" >/dev/null 2>&1 ); then ok "shasum -a 256 -c passes"; else bad "shasum -a 256 -c fails on a fresh manifest"; fi
	printf 'tampered\n' >"$m1/aa"
	if ( cd "$m1" && shasum -a 256 -c "$MANIFEST_NAME" >/dev/null 2>&1 ); then bad "shasum -c passed a tampered file"; else ok "shasum -c catches a tampered file"; fi
	ln -s aa "$m2/link"
	if ( manifest_write "$m2" "" ) 2>/dev/null; then bad "a symlink in the tree was accepted"; else ok "symlink refused"; fi
	if ( manifest_write "$tmp/m-empty-$$" "" ) 2>/dev/null; then bad "a missing tree produced a manifest"; else ok "missing tree refused"; fi

	echo "==> .DS_Store exclusion is for non-Mach-O files only"
	local ds="$tmp/ds"
	mkdir -p "$ds/sub"
	printf 'finder\n' >"$ds/.DS_Store"
	cp "$tree/k3sm" "$ds/sub/.DS_Store"
	( manifest_write "$ds" "" ) || bad "manifest_write failed on the .DS_Store tree"
	out="$(grep -v '^#' "$ds/$MANIFEST_NAME" | sed 's/^[0-9a-f]\{64\}  //' | tr '\n' ' ')"
	if [ "$out" = "sub/.DS_Store " ]; then ok "a Mach-O named .DS_Store is hashed, a Finder .DS_Store is not"; else bad "unexpected .DS_Store handling: '$out'"; fi

	echo "==> both verify modes refuse a symlink or an odd name before anything else"
	local st="$tmp/shape-link" sn="$tmp/shape-name" sb="$tmp/shape-bslash" mode
	mkdir -p "$st" "$sn" "$sb"
	ln -s /usr/bin/true "$st/k3sm"
	printf 'x\n' >"$sn/bad"$'\n'"name"
	printf 'x\n' >"$sb/bad\\name"
	for mode in --verify-only "--verify-release $team"; do
		# shellcheck disable=SC2086 # mode is two words on purpose
		if out="$("$self" "$st" $mode 2>&1)"; then bad "$mode accepted a symlink"; elif printf '%s\n' "$out" | grep -q "symlinks are not allowed"; then ok "$mode refuses a symlink"; else bad "$mode symlink refusal not named: $out"; fi
		# shellcheck disable=SC2086
		if out="$("$self" "$sn" $mode 2>&1)"; then bad "$mode accepted a newline name"; elif printf '%s\n' "$out" | grep -q "newline or backslash"; then ok "$mode refuses a newline in a name"; else bad "$mode newline refusal not named: $out"; fi
		# shellcheck disable=SC2086
		if out="$("$self" "$sb" $mode 2>&1)"; then bad "$mode accepted a backslash name"; elif printf '%s\n' "$out" | grep -q "newline or backslash"; then ok "$mode refuses a backslash in a name"; else bad "$mode backslash refusal not named: $out"; fi
	done

	echo "==> manifest rewrite and verification (the release gate's manifest check)"
	local mt="$tmp/mt"
	mkdir -p "$mt/cp-payload"
	printf 'bin\n' >"$mt/k3sm"
	printf 'cp\n' >"$mt/cp-payload/kine"
	( manifest_write "$mt" "toolchain: test" ) || bad "manifest_write failed on the verify tree"
	if out="$(verify_manifest "$mt")"; then ok "a fresh manifest verifies"; else bad "a fresh manifest failed: $out"; fi
	printf 'signed\n' >>"$mt/k3sm"
	if out="$(verify_manifest "$mt")"; then bad "a tampered file verified"; elif printf '%s\n' "$out" | grep -q "k3sm: FAILED"; then ok "a tampered file fails, named by shasum -c"; else bad "tamper failure not named: $out"; fi
	if "$self" --rewrite-manifest "$mt" >/dev/null && out="$(verify_manifest "$mt")"; then ok "--rewrite-manifest after a byte change verifies"; else bad "rewrite then verify failed: $out"; fi
	if [ "$(head -1 "$mt/$MANIFEST_NAME")" = "# toolchain: test" ]; then ok "the rewrite keeps the comment lines"; else bad "the rewrite dropped the comment lines"; fi
	printf 'new\n' >"$mt/added"
	if out="$(verify_manifest "$mt")"; then bad "an added file verified"; elif printf '%s\n' "$out" | grep -q "file set"; then ok "an added file fails"; else bad "added-file failure not named: $out"; fi
	rm "$mt/added"
	printf '# edited\n' >>"$mt.$MANIFEST_NAME"
	if out="$(verify_manifest "$mt")"; then bad "differing manifest copies verified"; elif printf '%s\n' "$out" | grep -q "differ"; then ok "differing in-tree and beside copies fail"; else bad "copy mismatch not named: $out"; fi
	rm "$mt.$MANIFEST_NAME"
	if verify_manifest "$mt" >/dev/null; then bad "a missing beside copy verified"; else ok "a missing beside copy fails"; fi
	"$self" --rewrite-manifest "$mt" >/dev/null
	rm "$mt/$MANIFEST_NAME"
	if verify_manifest "$mt" >/dev/null; then bad "a missing manifest verified"; else ok "a missing manifest fails"; fi
	if "$self" --rewrite-manifest "$mt" >/dev/null 2>&1; then bad "--rewrite-manifest invented a manifest"; else ok "--rewrite-manifest refuses a tree without one"; fi

	echo "==> upstream digests and the release refusal"
	local rt="$tmp/rel"
	mkdir -p "$rt/cp-payload"
	printf 'one\n' >"$rt/cp-payload/kube-apiserver"
	printf 'two\n' >"$rt/cp-payload/kine"
	printf 'k3sm\n' >"$rt/k3sm"
	( upstream_digests_write "$rt" "test" ) || bad "upstream_digests_write failed"
	out="$(grep -v '^#' "$rt/$UPSTREAM_NAME" | sed 's/^[0-9a-f]\{64\}  //' | tr '\n' ' ')"
	if [ "$out" = "cp-payload/kine cp-payload/kube-apiserver " ]; then ok "upstream digests cover exactly cp-payload"; else bad "upstream digest paths: '$out'"; fi
	if out="$(refuse_unpinned_payload "$rt" "$PINNED_SOURCE_FILES")"; then
		bad "release refusal let an unpinned payload through"
	elif printf '%s\n' "$out" | grep -q "cp-payload/kine" && ! printf '%s\n' "$out" | grep -q "cp-payload/kube-apiserver"; then
		ok "the unpinned kine is refused, the pinned-source kube-apiserver is not"
	else
		bad "refusal did not name exactly the unpinned file: $out"
	fi
	if refuse_unpinned_payload "$rt" "$(printf 'cp-payload/kine\ncp-payload/kube-apiserver')" >/dev/null; then ok "a fully pinned-source payload passes"; else bad "a pinned-source payload was refused"; fi

	echo "==> the pinned-source list is build-cp.sh's output list"
	if [ "$PINNED_SOURCE_FILES" = "$("$HERE/build-cp.sh" --print-outputs)" ]; then ok "PINNED_SOURCE_FILES = build-cp.sh --print-outputs"; else bad "PINNED_SOURCE_FILES differs from build-cp.sh --print-outputs"; fi
	if out="$("$self" "$tmp/release-out" --release 2>&1)"; then
		bad "--release staging without --cp-build did not refuse"
	elif printf '%s\n' "$out" | grep -q "build-cp.sh"; then ok "--release without --cp-build refuses, naming build-cp.sh"; else bad "--release refused without naming build-cp.sh: $out"; fi
	local cb="$tmp/cp-build" rel
	mkdir -p "$cb"
	while IFS= read -r rel; do printf 'built-%s\n' "${rel#cp-payload/}" >"$cb/${rel#cp-payload/}"; done <<<"$PINNED_SOURCE_FILES"
	if out="$(cp_build_problems "$cb")"; then bad "a --cp-build without its stamp passed"; elif printf '%s\n' "$out" | grep -q "lacks $CP_STAMP_NAME"; then ok "a --cp-build without $CP_STAMP_NAME is refused"; else bad "the missing stamp was not named: $out"; fi
	printf 'cache-key: vX-goY-0000000000000000\ntoolchain: %s (fixture)\n' "$PAYLOAD_GO_VERSION" >"$cb/$CP_STAMP_NAME"
	if cp_build_problems "$cb" >/dev/null; then ok "a complete --cp-build passes"; else bad "a complete --cp-build was refused"; fi
	printf 'x\n' >"$cb/extra"
	if out="$(cp_build_problems "$cb")"; then bad "an extra file in --cp-build passed"; elif printf '%s\n' "$out" | grep -q "unexpected extra"; then ok "an extra --cp-build file is refused"; else bad "extra file not named: $out"; fi
	rm "$cb/extra" "$cb/kubectl"
	if out="$(cp_build_problems "$cb")"; then bad "a --cp-build missing kubectl passed"; elif printf '%s\n' "$out" | grep -q "lacks kubectl"; then ok "a missing --cp-build file is refused"; else bad "missing file not named: $out"; fi
	if out="$("$self" "$tmp/release-out2" --release --cp-build "$cb" 2>&1)"; then
		bad "--release with an incomplete --cp-build did not refuse"
	elif printf '%s\n' "$out" | grep -q "lacks kubectl"; then ok "--release refuses an incomplete --cp-build before building"; else bad "--release did not name the incomplete --cp-build: $out"; fi
	printf 'built-kubectl\n' >"$cb/kubectl"
	local pt="$tmp/placed"
	mkdir -p "$pt/cp-payload"
	while IFS= read -r rel; do printf 'downloaded\n' >"$pt/$rel"; done <<<"$PINNED_SOURCE_FILES"
	if pinned_content_problems "$pt" "$cb" >/dev/null; then bad "downloaded bytes passed as the pinned-source build"; else ok "bytes other than the pinned-source build are refused"; fi
	place_cp_build "$cb" "$pt/cp-payload" || bad "place_cp_build failed"
	if pinned_content_problems "$pt" "$cb" >/dev/null; then ok "the placed pinned-source build passes the content check"; else bad "the placed build failed the content check"; fi
	if refuse_unpinned_payload "$pt" "$PINNED_SOURCE_FILES" >/dev/null; then ok "a payload of exactly build-cp's outputs passes the release refusal"; else bad "build-cp's outputs were refused"; fi
	if [ ! -e "$pt/cp-payload/$CP_STAMP_NAME" ]; then ok "the stamp is not placed into the payload"; else bad "the stamp was placed into cp-payload"; fi
	local pdir
	pdir="$(mktemp -d "$tmp/place.XXXXXX")"
	printf 'old\n' >"$pdir/kubectl" && printf 'planted\n' >"$pdir/.kubectl.cp-build"
	if place_cp_build "$cb" "$pdir" && cmp -s "$cb/kubectl" "$pdir/kubectl" && [ -z "$(find "$pdir" -name '.kubectl.??????')" ]; then ok "place_cp_build copies through a fresh temp file and leaves none behind"; else bad "place_cp_build did not place kubectl cleanly"; fi
	if [ "$(cat "$pdir/.kubectl.cp-build")" = planted ]; then ok "place_cp_build never writes through a predictable temp name"; else bad "place_cp_build used the predictable temp name"; fi

	echo "==> the build-cp stamp and toolchain checks"
	if grep -qx "STAMP_NAME=\"$CP_STAMP_NAME\"" "$HERE/build-cp.sh"; then ok "CP_STAMP_NAME = build-cp.sh's STAMP_NAME"; else bad "build-cp.sh does not write $CP_STAMP_NAME"; fi
	if out="$("$self" "$tmp/release-out3" --release --cp-build "$cb" 2>&1)"; then
		bad "--release with a stale --cp-build stamp did not refuse"
	elif printf '%s\n' "$out" | grep -q "is not build-cp.sh's build for"; then ok "--release refuses a --cp-build built for another cache key"; else bad "--release did not name the stale stamp: $out"; fi
	chmod 0775 "$cb"
	if out="$("$self" "$tmp/release-out4" --release --cp-build "$cb/" 2>&1)"; then
		bad "--release with a group-writable --cp-build did not refuse"
	elif printf '%s\n' "$out" | grep -q -- "--cp-build $cb is writable by group or other"; then ok "--release refuses a group-writable --cp-build directory"; else bad "--release did not name the group-writable --cp-build: $out"; fi
	chmod 0755 "$cb"
	local cbp
	cbp="$(mktemp -d "$tmp/cbparent.XXXXXX")"
	cp -R "$cb" "$cbp/build" && chmod 0757 "$cbp"
	if out="$("$self" "$tmp/release-out5" --release --cp-build "$cbp/build" 2>&1)"; then
		bad "--release with an other-writable --cp-build parent did not refuse"
	elif printf '%s\n' "$out" | grep -q -- "--cp-build's parent $cbp is writable by group or other"; then ok "--release refuses a --cp-build whose parent is writable by others"; else bad "--release did not name the writable parent: $out"; fi
	chmod 0700 "$cbp"
	ln -s "$cb" "$tmp/cb-link"
	if "$self" "$tmp/release-out6" --release --cp-build "$tmp/cb-link" >/dev/null 2>&1; then bad "--release accepted a symlinked --cp-build"; else ok "--release refuses a symlinked --cp-build"; fi
	echo "==> the build info of a control-plane binary (cp_binary_problems over go version -m text)"
	local bi raisesx
	raisesx="$(printf 'golang.org/x/net v0.60.0\nexample.com/notlinked v1.0.0')"
	bi="$(printf '%s: %s\n\tpath\tk8s.io/kubernetes/cmd/kubectl\n\tmod\tk8s.io/kubernetes\t(devel)\t\n\tdep\tgolang.org/x/net\tv0.60.0\t\n\tbuild\t-trimpath=true\n\tbuild\tCGO_ENABLED=0\n\tbuild\tGOARCH=arm64\n\tbuild\tGOOS=darwin\n' kubectl "$PAYLOAD_GO_VERSION")"
	if out="$(printf '%s\n' "$bi" | cp_binary_problems kubectl v1.0.0 "$raisesx")" && [ "$out" = "LINKS golang.org/x/net" ]; then ok "a source-archive build info passes and names the raised modules it links"; else bad "the good build info: $out"; fi
	local case_name case_sed
	while IFS='|' read -r case_name case_sed; do
		if printf '%s\n' "$bi" | sed "$case_sed" | cp_binary_problems kubectl v1.0.0 "$raisesx" >/dev/null; then bad "build info passed with $case_name"; else ok "build info refused: $case_name"; fi
	done <<'CASES'
another toolchain|1s/: go.*/: go1.0.1/
another main package|s|cmd/kubectl|cmd/other|
another main module|s|k8s.io/kubernetes	(devel)|example.com/fork	v1.0.0|
a raised module at another version|s|golang.org/x/net	v0.60.0|golang.org/x/net	v0.59.0|
a cgo build|s|CGO_ENABLED=0|CGO_ENABLED=1|
no -trimpath|/-trimpath=true/d
an amd64 build|s|GOARCH=arm64|GOARCH=amd64|
CASES
	if printf '%s\n\t=>\texample.com/fork\tv0.0.1\t\n' "$bi" | cp_binary_problems kubectl v1.0.0 "$raisesx" >/dev/null; then bad "build info passed with a replaced module"; else ok "build info refused: a replaced module"; fi

	# A fake toolchain for whole-directory checks: a fake binary is a text file
	# whose "FAKEBIN <go>" line is its toolchain and whose "dep" lines are its deps.
	local fgo="$tmp/fake-go"
	cat >"$fgo" <<'FAKEGO'
#!/bin/bash
[ "$1" = version ] || exit 2
m=0; [ "$2" = -m ] && { m=1; shift; }
f="$2"; g="$(sed -n 's/^FAKEBIN //p' "$f")"
[ -n "$g" ] || exit 0
echo "$f: $g"
[ "$m" = 1 ] || exit 0
printf '\tpath\tk8s.io/kubernetes/cmd/%s\n\tmod\tk8s.io/kubernetes\t(devel)\t\n' "$(basename "$f")"
sed -n 's/^dep \([^ ]*\) \([^ ]*\)$/	dep	\1	\2	/p' "$f"
printf '\tbuild\t-trimpath=true\n\tbuild\tCGO_ENABLED=0\n\tbuild\tGOARCH=arm64\n\tbuild\tGOOS=darwin\n'
FAKEGO
	chmod 0755 "$fgo"
	# fake_cp_build <dir> <key> [<go>]: what build-cp writes, with fake binaries.
	fake_cp_build() {
		local d="$1" k="$2" g="${3:-$PAYLOAD_GO_VERSION}" n
		mkdir -p "$d"
		for n in kube-apiserver kube-scheduler kube-controller-manager kubectl; do
			printf 'FAKEBIN %s\nversion %s\nbuilt %s %s\ndep example.com/raised v1.2.0\n' "$g" "${k%%-go[0-9]*}" "$n" "$k" >"$d/$n"
		done
		{
			printf 'build-cp stamp\ntag: %s (commit 0)\ntoolchain: %s (the source'"'"'s .go-version: go1.0.0)\ncache-key: %s\n' "${k%%-go[0-9]*}" "$g" "$k"
			printf 'raise-list-sha256: %s\n' "$(printf 'f%.0s' $(seq 1 64))"
			printf 'raise-list: example.com/raised v1.2.0 2026-01-01T00:00:00Z GO-2026-0001\n'
			(cd "$d" && shasum -a 256 kube-apiserver kube-scheduler kube-controller-manager kubectl) | awk '{print "sha256: " $1 " " $2}'
		} >"$d/$CP_STAMP_NAME"
	}
	local fx="$tmp/fx" fkey="v1.0.0-go1.0.0-0123456789abcdef"
	fake_cp_build "$fx" "$fkey"
	echo "==> cp_build_check binds a build-cp output to its stamp, digests and build info"
	local fhash fraises
	fhash="$(printf 'f%.0s' $(seq 1 64))" fraises="example.com/raised v1.2.0"
	# cbc <dir> <key> [<live raises>] [<live hash>]: cp_build_check over a fresh
	# snapshot of <dir>'s stamp, with the fake toolchain.
	cbc() { GO="$fgo" cp_build_check "$1" "$2" "${3-$fraises}" "${4:-$fhash}" "$(cat "$1/$CP_STAMP_NAME")"; }
	if out="$(cbc "$fx" "$fkey")"; then ok "a build matching its stamp passes"; else bad "a matching build was refused: $out"; fi
	if out="$(cbc "$fx" "v1.0.0-go1.0.0-1111111111111111")"; then bad "a stamp for another cache key passed"; elif printf '%s\n' "$out" | grep -q "does not name cache key"; then ok "a stamp for another cache key is refused"; else bad "the key mismatch was not named: $out"; fi
	if (PAYLOAD_GO_VERSION=go1.0.1 cbc "$fx" "$fkey" >/dev/null); then bad "a build for another toolchain passed"; else ok "a stamp and binaries for another toolchain are refused"; fi
	if out="$(cbc "$fx" "$fkey" "$fraises" "$(printf 'e%.0s' $(seq 1 64))")"; then bad "a stamp whose raise-list-sha256 is not build-cp's passed"; elif printf '%s\n' "$out" | grep -q "does not name raise-list-sha256"; then ok "a stamp whose raise-list-sha256 is not build-cp.sh's live hash is refused"; else bad "the raise hash mismatch was not named: $out"; fi
	if out="$(cbc "$fx" "$fkey" "example.com/raised v1.3.0")"; then
		bad "a stamp whose raise lines differ from the live RAISES passed"
	elif printf '%s\n' "$out" | grep -q "raise-list lines are not build-cp.sh's live raise list"; then ok "a stamp whose raise lines differ from build-cp.sh's live RAISES is refused"; else bad "the raise-line mismatch was not named: $out"; fi
	cp "$fx/kubectl" "$tmp/kubectl.keep" && printf 'tampered\n' >>"$fx/kubectl"
	if out="$(cbc "$fx" "$fkey")"; then bad "a binary whose bytes moved after the stamp passed"; elif printf '%s\n' "$out" | grep -q "kubectl: sha256 .* is not the one $CP_STAMP_NAME records"; then ok "a binary whose sha256 is not the stamp's is refused"; else bad "the digest mismatch was not named: $out"; fi
	cp "$tmp/kubectl.keep" "$fx/kubectl"
	grep '^sha256: .* kubectl$' "$fx/$CP_STAMP_NAME" >"$tmp/dup-line" && cat "$tmp/dup-line" >>"$fx/$CP_STAMP_NAME"
	if cbc "$fx" "$fkey" >/dev/null; then bad "a stamp recording kubectl twice passed"; else ok "a stamp recording a binary twice is refused"; fi
	fake_cp_build "$fx" "$fkey"
	sed -i '' -e 's/^version v1.0.0$/version vX/' -e '/^built /d' "$fx/kube-scheduler"
	(cd "$fx" && awk -v s="$(shasum -a 256 kube-scheduler | awk '{print $1}')" '$1 == "sha256:" && $3 == "kube-scheduler" { $2 = s } { print }' "$CP_STAMP_NAME" >"$CP_STAMP_NAME.n" && mv "$CP_STAMP_NAME.n" "$CP_STAMP_NAME")
	if out="$(cbc "$fx" "$fkey")"; then bad "a binary without the tag's version string passed"; elif printf '%s\n' "$out" | grep -q "kube-scheduler: carries no v1.0.0 version string"; then ok "a binary without the tag's version string is refused"; else bad "the missing tag was not named: $out"; fi
	fake_cp_build "$fx" "$fkey"
	printf 'raise-list: example.com/unlinked v1.0.0 2026-01-01T00:00:00Z GO-2026-0002\n' >>"$fx/$CP_STAMP_NAME"
	if out="$(cbc "$fx" "$fkey" "$(printf '%s\nexample.com/unlinked v1.0.0' "$fraises")")"; then bad "a raised module no binary links passed"; elif printf '%s\n' "$out" | grep -q "no control-plane binary links raised example.com/unlinked"; then ok "a raised module that no binary links is refused"; else bad "the unlinked raise was not named: $out"; fi
	fake_cp_build "$fx" "$fkey"
	sed -i '' 's|^raise-list: example.com/raised v1.2.0|raise-list: example.com/raised v1.3.0|' "$fx/$CP_STAMP_NAME"
	if out="$(cbc "$fx" "$fkey" "example.com/raised v1.3.0")"; then bad "a raised module linked at another version passed"; elif printf '%s\n' "$out" | grep -q "links example.com/raised v1.2.0, the raise list lands it at v1.3.0"; then ok "a raised module linked at another version than the live raise list is refused"; else bad "the raise version mismatch was not named: $out"; fi

	echo "==> a binary swapped in the build after its check never reaches the payload"
	fake_cp_build "$fx" "$fkey"
	local snap swp="$tmp/swap-payload"
	snap="$(cat "$fx/$CP_STAMP_NAME")"
	if GO="$fgo" cp_build_check "$fx" "$fkey" "$fraises" "$fhash" "$snap" >/dev/null; then ok "the build passes its check (the stamp snapshot is taken)"; else bad "the swap fixture failed its first check"; fi
	# The swap: new bytes for kubectl, and a stamp rewritten to match them.
	printf 'FAKEBIN %s\nversion v1.0.0\nswapped\ndep example.com/raised v1.2.0\n' "$PAYLOAD_GO_VERSION" >"$fx/kubectl"
	(cd "$fx" && awk -v s="$(shasum -a 256 kubectl | awk '{print $1}')" '$1 == "sha256:" && $3 == "kubectl" { $2 = s } { print }' "$CP_STAMP_NAME" >"$CP_STAMP_NAME.n" && mv "$CP_STAMP_NAME.n" "$CP_STAMP_NAME")
	mkdir -p "$swp"
	place_cp_build "$fx" "$swp" || bad "place_cp_build failed on the swap fixture"
	if out="$(GO="$fgo" cp_set_check "$swp" v1.0.0 "$fraises" "$snap")"; then
		bad "a binary swapped after the check passed the placed-copy check"
	elif printf '%s\n' "$out" | grep -q "$swp/kubectl: sha256 .* is not the one $CP_STAMP_NAME records"; then ok "the placed copy of a binary swapped after the check is refused against the snapshot"; else bad "the swapped placed copy was not named: $out"; fi
	if GO="$fgo" cp_set_check "$swp" v1.0.0 "$fraises" "$(cat "$fx/$CP_STAMP_NAME")" >/dev/null; then ok "(the rewritten stamp alone would have passed it: the snapshot is what refuses)"; else bad "the swap fixture is not a consistent rewrite"; fi
	fake_cp_build "$fx" "$fkey"
	rm -rf "$swp" && mkdir -p "$swp" && place_cp_build "$fx" "$swp"
	if GO="$fgo" cp_set_check "$swp" v1.0.0 "$fraises" "$(cat "$fx/$CP_STAMP_NAME")" >/dev/null; then ok "untouched placed copies pass the placed-copy check"; else bad "untouched placed copies were refused"; fi

	echo "==> the cache root must be the effective uid's and not group- or other-writable"
	local croot="$tmp/croot"
	mkdir -p "$croot" && chmod 0700 "$croot"
	if cache_root_problems "$croot" >/dev/null; then ok "a 0700 cache root of the effective uid passes"; else bad "a private cache root was refused"; fi
	chmod 0775 "$croot"
	if out="$(cache_root_problems "$croot")"; then bad "a group-writable cache root passed"; elif printf '%s\n' "$out" | grep -q "writable by group or other"; then ok "a group-writable cache root is refused"; else bad "the group-writable root was not named: $out"; fi
	chmod 0757 "$croot"
	if cache_root_problems "$croot" >/dev/null; then bad "an other-writable cache root passed"; else ok "an other-writable cache root is refused"; fi
	if cache_root_problems /usr >/dev/null; then bad "a root-owned cache root passed"; else ok "a cache root owned by another uid is refused"; fi
	ln -s "$croot" "$tmp/croot-link"
	if cache_root_problems "$tmp/croot-link" >/dev/null; then bad "a symlinked cache root passed"; else ok "a symlinked cache root is refused"; fi

	echo "==> lab staging selects build-cp's outputs, through a cache keyed by build-cp --print-cache-key"
	local fb="$tmp/fake-build-cp" cache="$tmp/cp-cache" lab key1 key2
	key1="v1.0.0-go1.0.0-0123456789abcdef" key2="v1.0.0-go1.0.0-fedcba9876543210"
	# The fake writes what build-cp writes: the four binaries and the stamp.
	# shellcheck disable=SC2016 # the fake's own "$1" is written literally
	{
		printf '#!/bin/bash\nset -euo pipefail\n'
		printf 'if [ "$1" = --print-cache-key ]; then cat %q; exit 0; fi\n' "$tmp/fake-key"
		printf 'if [ "$1" = --print-raises ]; then echo %q; exit 0; fi\n' "$fraises"
		printf 'if [ "$1" = --print-raise-list-hash ]; then echo %s; exit 0; fi\n' "$fhash"
		printf 'echo "$1" >>%q\n' "$tmp/fake-builds"
		printf '. %q\n' "$tmp/fake-build.sh"
		printf 'fake_cp_build "$1" "$(cat %q)" "${FAKE_TOOLCHAIN:-%s}"\n' "$tmp/fake-key" "$PAYLOAD_GO_VERSION"
	} >"$fb"
	{ printf 'CP_STAMP_NAME=%q\n' "$CP_STAMP_NAME"; declare -f fake_cp_build; } >"$tmp/fake-build.sh"
	chmod 0755 "$fb"
	printf '%s' "$key1" >"$tmp/fake-key"
	nbuilds() { if [ -f "$tmp/fake-builds" ]; then wc -l <"$tmp/fake-builds" | tr -d ' '; else echo 0; fi; }
	if lab="$(GO="$fgo" lab_cp_build "$cache" "$fb" 2>/dev/null)" && [ "$lab" = "$(cd "$cache" && pwd -P)/$key1" ] && [ "$(nbuilds)" = 1 ] && cp_build_problems "$lab" >/dev/null; then
		ok "an empty cache runs build-cp once, into <cache>/<key>"
	else
		bad "the first lab build: dir '$lab', builds $(nbuilds)"
	fi
	case "$(cat "$tmp/fake-builds")" in "$(cd "$cache" && pwd -P)/.partial."??????) ok "the fresh build ran in a mktemp directory under the cache root" ;; *) bad "build-cp ran into '$(cat "$tmp/fake-builds")'" ;; esac
	if [ -z "$(find "$cache" -maxdepth 1 -name '.partial.*')" ]; then ok "no partial build is left behind"; else bad "a partial build was left in the cache"; fi
	if [ "$(stat -f '%Lp' "$cache")" = 700 ]; then ok "a cache root the stage creates is 0700"; else bad "the created cache root is mode $(stat -f '%Lp' "$cache")"; fi
	if lab="$(GO="$fgo" lab_cp_build "$cache" "$fb" 2>/dev/null)" && [ "$(nbuilds)" = 1 ] && grep -q "built kubectl $key1" "$lab/kubectl"; then ok "the same key reuses the cached build"; else bad "the same key rebuilt (builds $(nbuilds))"; fi
	printf 'tampered\n' >>"$lab/kube-apiserver"
	if lab="$(GO="$fgo" lab_cp_build "$cache" "$fb" 2>/dev/null)" && [ "$(nbuilds)" = 2 ] && cbc "$lab" "$key1" >/dev/null; then ok "a cached binary whose bytes moved is rebuilt, not reused"; else bad "a tampered cache was reused (builds $(nbuilds))"; fi
	sed -i '' "s/^cache-key: .*/cache-key: $key2/" "$lab/$CP_STAMP_NAME"
	if lab="$(GO="$fgo" lab_cp_build "$cache" "$fb" 2>/dev/null)" && [ "$(nbuilds)" = 3 ] && cbc "$lab" "$key1" >/dev/null; then ok "a cached build whose stamp names another key is rebuilt"; else bad "a mismatched stamp was reused (builds $(nbuilds))"; fi
	mkdir "$cache/.partial.otherrun"
	printf '%s' "$key2" >"$tmp/fake-key"
	if lab="$(GO="$fgo" lab_cp_build "$cache" "$fb" 2>/dev/null)" && [ "$(nbuilds)" = 4 ] && [ "$lab" = "$(cd "$cache" && pwd -P)/$key2" ] && grep -q "built kubectl $key2" "$lab/kubectl"; then ok "a new key (tag, toolchain or raise list) rebuilds"; else bad "a new key did not rebuild (builds $(nbuilds), dir '$lab')"; fi
	if [ ! -e "$cache/$key1" ]; then ok "the cache drops the build for the old key"; else bad "the old key's build stayed in the cache"; fi
	if [ -d "$cache/.partial.otherrun" ]; then ok "the old-key sweep leaves another run's partial build alone"; else bad "the sweep removed another run's partial build"; fi
	rm -rf "${cache:?}/$key2"
	if (export FAKE_TOOLCHAIN=go1.0.1; GO="$fgo" lab_cp_build "$cache" "$fb" >/dev/null 2>&1); then bad "a build-cp output for another toolchain was accepted"; else ok "a fresh build-cp output that names another toolchain is refused"; fi
	if [ -z "$(find "$cache" -maxdepth 1 -name '.partial.??????')" ]; then ok "a refused fresh build's partial directory is swept"; else bad "a refused fresh build left $(find "$cache" -maxdepth 1 -name '.partial.??????')"; fi
	cat >"$tmp/failing-build-cp" <<FAILCP
#!/bin/bash
if [ "\$1" = --print-cache-key ]; then echo $key1; exit 0; fi
if [ "\$1" = --print-raises ]; then echo "$fraises"; exit 0; fi
if [ "\$1" = --print-raise-list-hash ]; then echo $fhash; exit 0; fi
mkdir -p "\$1"; echo half >"\$1/kubectl"; exit 4
FAILCP
	chmod 0755 "$tmp/failing-build-cp"
	if GO="$fgo" lab_cp_build "$cache" "$tmp/failing-build-cp" >/dev/null 2>&1; then bad "a failing build-cp was accepted"; elif [ -z "$(find "$cache" -maxdepth 1 -name '.partial.??????')" ]; then ok "a failed fresh build's partial directory is swept"; else bad "a failed fresh build left its partial directory"; fi
	printf 'bogus key' >"$tmp/fake-key"
	if GO="$fgo" lab_cp_build "$cache" "$fb" >/dev/null 2>&1; then bad "a malformed cache key was accepted"; else ok "a malformed cache key is refused"; fi
	printf '%s' "$key1" >"$tmp/fake-key"
	chmod 0770 "$cache"
	if out="$(GO="$fgo" lab_cp_build "$cache" "$fb" 2>&1)"; then bad "lab staging used a group-writable cache root"; elif printf '%s\n' "$out" | grep -q "writable by group or other"; then ok "lab staging refuses a group-writable cache root"; else bad "the cache root refusal: $out"; fi
	chmod 0700 "$cache"

	# End to end: lab staging runs the build-cp.sh beside it (no override exists,
	# so the run is a copy of this script in a scratch tree with a failing fake
	# build-cp.sh there); a fake go answers the toolchain assert.
	local tree="$tmp/tree" fbin="$tmp/fake-go-bin" e2e="$tmp/e2e-builds"
	mkdir -p "$tree/hack/release/lib" "$tree/hack/lib" "$tree/pkg/executor" "$tree/pkg/registrysvc" "$tree/pkg/helmchart" "$tree/internal/childreq" "$fbin"
	cp "$self" "$tree/hack/release/stage.sh" && cp "$HERE/lib/gochild.sh" "$tree/hack/release/lib/" && cp "$REPO_ROOT/hack/lib/govulncheck.sh" "$tree/hack/lib/"
	cp "$REPO_ROOT/pkg/executor/executor.go" "$REPO_ROOT/pkg/executor/setup.go" "$REPO_ROOT/pkg/executor/etcdstage.go" "$tree/pkg/executor/"
	cp "$REPO_ROOT/pkg/registrysvc/pin.go" "$tree/pkg/registrysvc/" && cp "$REPO_ROOT/pkg/helmchart/pin.go" "$tree/pkg/helmchart/"
	cp "$REPO_ROOT/internal/childreq/childreq.go" "$tree/internal/childreq/"
	# shellcheck disable=SC2016 # the fakes' own "$1" and "$2" are written literally
	{
		printf '#!/bin/bash\nif [ "$1" = --print-cache-key ]; then echo %s; exit 0; fi\n' "$key1"
		printf 'if [ "$1" = --print-raises ]; then echo %q; exit 0; fi\n' "$fraises"
		printf 'if [ "$1" = --print-raise-list-hash ]; then echo %s; exit 0; fi\n' "$fhash"
		printf 'echo "$1" >>%q\nexit 3\n' "$e2e"
	} >"$tree/hack/release/build-cp.sh"
	# shellcheck disable=SC2016 # the fake's own "$1 $2" is written literally
	printf '#!/bin/bash\nif [ "$1 $2" = "env GOVERSION" ]; then echo %s; exit 0; fi\nexit 1\n' "$PAYLOAD_GO_VERSION" >"$fbin/go"
	chmod 0755 "$fbin/go" "$tree/hack/release/build-cp.sh" "$tree/hack/release/stage.sh"
	if out="$(PATH="$fbin:$PATH" GO=go BUILD_CP=/usr/bin/false K3SM_CP_CACHE="$tmp/e2e-cache" "$tree/hack/release/stage.sh" "$tmp/lab-out" 2>&1)"; then
		bad "lab staging went on after build-cp failed"
	elif printf '%s\n' "$out" | grep -q "could not produce the control-plane binaries with hack/release/build-cp.sh"; then
		case "$(cat "$e2e" 2>/dev/null)" in
		"$(cd "$tmp/e2e-cache" && pwd -P)/.partial."??????) ok "lab staging runs the build-cp.sh beside it into its cache, ignores a BUILD_CP override, and stops when it fails" ;;
		*) bad "lab staging ran build-cp into '$(cat "$e2e" 2>/dev/null)'" ;;
		esac
	else
		bad "lab staging did not take its control-plane binaries from build-cp: $out"
	fi
	if [ ! -e "$tmp/lab-out/k3sm" ]; then ok "nothing was built before the control-plane binaries were in hand"; else bad "k3sm was built before build-cp ran"; fi

	echo "==> --release accepts k3sm's own kine/etcd/etcdutl/zot/helm builds and a proven kube.version"
	read_pins
	local kb="$tmp/k3sm-built" rpf kstamp
	rpf="$(release_payload_files)"
	mkdir -p "$kb/cp-payload"
	while IFS= read -r rel; do printf 'x\n' >"$kb/$rel"; done <<<"$rpf"
	printf '%s\n' "$KUBE_VERSION" >"$kb/$KUBE_MARKER_FILE"
	kstamp="$(printf 'build-cp stamp\ntag: %s (commit 0)\ntoolchain: %s (the source'"'"'s .go-version: go1.0.0)\n' "$KUBE_VERSION" "$PAYLOAD_GO_VERSION")"
	if printf '%s\n' "$rpf" | grep -qxF "cp-payload/$HELM_BINARY" && printf '%s\n' "$rpf" | grep -qxF cp-payload/helm.version && printf '%s\n' "$rpf" | grep -qxF cp-payload/zot && printf '%s\n' "$rpf" | grep -qxF cp-payload/zot.version && printf '%s\n' "$rpf" | grep -qxF cp-payload/kube.version; then
		ok "the release list names $HELM_BINARY, helm.version, zot, zot.version and kube.version"
	else
		bad "the release list lacks helm, zot or kube.version: $rpf"
	fi
	if out="$(refuse_unpinned_payload "$kb" "$rpf")"; then ok "kine, etcd, etcdutl, zot, helm, kube.version and their markers pass the release refusal"; else bad "k3sm's own builds, kube.version or the pinned helm were refused: $out"; fi
	if out="$(kube_marker_problems "$kb" "$kstamp" "$KUBE_VERSION")"; then ok "a kube.version of exactly \"$KUBE_VERSION\\n\" passes the content proof"; else bad "a correct kube.version was refused: $out"; fi
	local kc
	for kc in 'v1.36.0\n' 'x\n' "$KUBE_VERSION" "$KUBE_VERSION\\n$KUBE_VERSION\\n" "$KUBE_VERSION\\n\\n"; do
		# shellcheck disable=SC2059 # the case is the format: it carries the escapes
		printf "$kc" >"$kb/$KUBE_MARKER_FILE"
		if out="$(kube_marker_problems "$kb" "$kstamp" "$KUBE_VERSION")"; then
			bad "a kube.version of '$kc' passed the content proof"
		elif printf '%s\n' "$out" | grep -qF "cp-payload/kube.version: content is not exactly \"$KUBE_VERSION\\n\""; then
			ok "a kube.version of '$kc' is refused, naming the file and the expected content"
		else
			bad "a kube.version of '$kc' was refused for the wrong reason: $out"
		fi
	done
	rm -f "$kb/$KUBE_MARKER_FILE"
	ln -s "$kb/cp-payload/kine.version" "$kb/$KUBE_MARKER_FILE"
	if out="$(kube_marker_problems "$kb" "$kstamp" "$KUBE_VERSION")"; then bad "a symlinked kube.version passed the content proof"; elif printf '%s\n' "$out" | grep -qF "cp-payload/kube.version: missing or not a regular file"; then ok "a symlinked kube.version is refused"; else bad "a symlinked kube.version was refused for the wrong reason: $out"; fi
	rm -f "$kb/$KUBE_MARKER_FILE"
	if out="$(kube_marker_problems "$kb" "$kstamp" "$KUBE_VERSION")"; then bad "a missing kube.version passed the content proof"; else ok "a missing kube.version is refused"; fi
	printf '%s\n' "$KUBE_VERSION" >"$kb/$KUBE_MARKER_FILE"
	if out="$(kube_marker_problems "$kb" "$kstamp" "v0.0.0")"; then bad "a stamp tag other than DefaultKubeVersion passed the content proof"; elif printf '%s\n' "$out" | grep -qF "DefaultKubeVersion is 'v0.0.0'"; then ok "a --cp-build tag other than DefaultKubeVersion is refused"; else bad "a tag mismatch was refused for the wrong reason: $out"; fi
	if out="$(kube_marker_problems "$kb" "build-cp stamp" "$KUBE_VERSION")"; then bad "a stamp without a tag line passed the content proof"; else ok "a stamp without a tag line is refused"; fi
	printf 'x\n' >"$kb/cp-payload/helm-v0.0.0"
	if out="$(refuse_unpinned_payload "$kb" "$rpf")"; then
		bad "an unpinned helm passed the release refusal"
	elif printf '%s\n' "$out" | grep -q "helm-v0.0.0" && ! printf '%s\n' "$out" | grep -Eq "cp-payload/(kine|etcd|zot|kube\.version|$HELM_BINARY)\$"; then
		ok "a helm at another version is refused, the pinned set and kube.version are not"
	else
		bad "release refusal named the wrong files: $out"
	fi

	echo "==> the pins and the toolchain pin"
	(
		read_pins
		if [ -n "$KINE_VERSION" ] && [ -n "$ETCD_VERSION" ] && [ "$KINE_VARIANT" = "nocgo+$KINE_PATCH" ] && [ "$ETCD_VARIANT" = nocgo ]; then
			echo "  ok    read_pins: kine $KINE_VERSION $KINE_VARIANT (patch set $KINE_PATCH), etcd $ETCD_VERSION $ETCD_VARIANT"
		else
			echo "  FAIL  read_pins: kine '$KINE_VERSION' '$KINE_VARIANT' '$KINE_PATCH', etcd '$ETCD_VERSION' '$ETCD_VARIANT'"; exit 1
		fi
		if printf '%s' "$ZOT_VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' && [ "$ZOT_VARIANT" = "minimal+r1" ] && [ "$HELM_BINARY" = "helm-$HELM_VERSION" ] &&
			printf '%s' "$HELM_VARIANT" | grep -Eq '^nocgo\+deps[0-9]+$' && printf '%s' "$HELM_RAISED" | tr ' ' '\n' | grep -qx 'golang.org/x/crypto@v[0-9.]*' && printf '%s' "$HELM_RAISED" | tr ' ' '\n' | grep -qx 'golang.org/x/net@v[0-9.]*'; then
			echo "  ok    read_pins: zot $ZOT_VERSION $ZOT_VARIANT, $HELM_BINARY $HELM_VARIANT raised $HELM_RAISED"
		else
			echo "  FAIL  read_pins: zot '$ZOT_VERSION' '$ZOT_VARIANT', helm '$HELM_BINARY' '$HELM_VARIANT' '$HELM_RAISED'"; exit 1
		fi
		if printf '%s' "$XNET_FLOOR" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
			echo "  ok    read_pins: kine and zot raise golang.org/x/net to $XNET_FLOOR"
		else
			echo "  FAIL  read_pins: XNET_FLOOR '$XNET_FLOOR'"; exit 1
		fi
		if printf '%s' "$HELM_COMMIT" | grep -Eq '^[0-9a-f]{40}$' && [ "$(printf '%s\n%s\n' "$HELM_MIN_GO" "$PAYLOAD_GO_VERSION" | sort -V | head -1)" = "$HELM_MIN_GO" ]; then
			echo "  ok    read_pins: helm commit $HELM_COMMIT; PAYLOAD_GO_VERSION $PAYLOAD_GO_VERSION is not older than HelmMinGoVersion $HELM_MIN_GO"
		else
			echo "  FAIL  read_pins: helm commit '$HELM_COMMIT', HelmMinGoVersion '$HELM_MIN_GO' newer than PAYLOAD_GO_VERSION $PAYLOAD_GO_VERSION?"; exit 1
		fi
	) || fails=$((fails + 1))
	if printf '%s\n' "$PAYLOAD_GO_VERSION" | grep -Eq '^go[0-9]+\.[0-9]+\.[0-9]+$'; then ok "PAYLOAD_GO_VERSION is an exact release ($PAYLOAD_GO_VERSION)"; else bad "PAYLOAD_GO_VERSION '$PAYLOAD_GO_VERSION' is not an exact goX.Y.Z"; fi
	# A fake go: `env GOVERSION` prints $FAKE_GOVERSION (and records GOTOOLCHAIN),
	# `version -m <f>` prints the fixture for <f>'s base name.
	local fgo="$tmp/fake-go"
	cat >"$fgo" <<FAKE
#!/bin/sh
case "\$1 \$2" in
"env GOVERSION") [ -n "\$FAKE_GOVERSION" ] || exit 1; echo "\$GOTOOLCHAIN" >"$tmp/fake-go.toolchain"; echo "\$FAKE_GOVERSION" ;;
"version -m") cat "$td/goversion-\$(basename "\$3").txt" ;;
*) exit 2 ;;
esac
FAKE
	chmod +x "$fgo"
	if GO="$fgo" FAKE_GOVERSION=go1.27.3 toolchain_problems go1.27.3 >/dev/null; then ok "the pinned toolchain passes"; else bad "the pinned toolchain was refused"; fi
	if [ "$(cat "$tmp/fake-go.toolchain")" = local ]; then ok "the assert asks with GOTOOLCHAIN=local, as the payload build runs"; else bad "the assert did not set GOTOOLCHAIN=local"; fi
	if out="$(GO="$fgo" FAKE_GOVERSION=go1.27.1 toolchain_problems go1.27.3)"; then bad "another toolchain passed"; elif printf '%s\n' "$out" | grep -q "go1.27.1.*pin go1.27.3"; then ok "another toolchain is refused, naming both"; else bad "toolchain refusal not named: $out"; fi
	if GO="$fgo" FAKE_GOVERSION='' toolchain_problems go1.27.3 >/dev/null; then bad "a failing go passed"; else ok "a go that cannot report its version is refused"; fi
	# PATH holds no go, so even a broken assert could not build anything here.
	if out="$(PATH=/usr/bin:/bin GO="$fgo" FAKE_GOVERSION=go1.0.0 "$self" "$tmp/stage-oldgo" 2>&1)"; then
		bad "staging with a non-pinned go exited 0"
	elif printf '%s\n' "$out" | grep -q "go1.0.0.*pin $PAYLOAD_GO_VERSION" && [ -z "$(ls -A "$tmp/stage-oldgo")" ]; then
		ok "staging refuses a non-pinned go before building anything"
	else
		bad "staging with a non-pinned go did not refuse before building: $out"
	fi

	echo "==> the build stamp of kine, etcd, etcdutl and zot (go version -m captures; dep lists trimmed)"
	local kind want fx2
	# The floor the fixtures are captured at; read_pins sets it from the source, and
	# the read_pins check above proves that read.
	# shellcheck disable=SC2016 # expanded by the inner shell
	if [ -z "$(XNET_FLOOR=v0.0.1 bash -c '. "$1"; printf %s "$XNET_FLOOR"' _ "$HERE/lib/gochild.sh")" ]; then ok "an ambient XNET_FLOOR does not set the floor"; else bad "gochild.sh took XNET_FLOOR from the environment"; fi
	XNET_FLOOR=v0.60.0
	for kind in kine etcd etcdutl zot; do
		case "$kind" in kine) want=v0.17.2 ;; zot) want=v2.1.22 ;; *) want=v3.6.15 ;; esac
		fx2="$td/goversion-$kind.txt"
		if out="$(buildinfo_problems "$kind" "$want" go1.27.3 <"$fx2")"; then ok "$kind capture passes"; else bad "$kind capture rejected: $out"; fi
		if out="$(buildinfo_problems "$kind" "$want" go1.27.9 <"$fx2")"; then bad "$kind: another toolchain passed"; elif printf '%s\n' "$out" | grep -q "built with 'go1.27.3'"; then ok "$kind: another toolchain is refused"; else bad "$kind: toolchain not named: $out"; fi
		if out="$(sed 's/CGO_ENABLED=0/CGO_ENABLED=1/' "$fx2" | buildinfo_problems "$kind" "$want" go1.27.3)"; then bad "$kind: a cgo build passed"; elif printf '%s\n' "$out" | grep -q "CGO_ENABLED=0"; then ok "$kind: a cgo build is refused"; else bad "$kind: cgo not named: $out"; fi
		if out="$(grep -v -- '-trimpath' "$fx2" | buildinfo_problems "$kind" "$want" go1.27.3)"; then bad "$kind: a build without -trimpath passed"; else ok "$kind: a build without -trimpath is refused"; fi
		case "$kind" in
		kine | zot)
			if out="$(sed 's/\(golang\.org\/x\/net[[:space:]]\)v0\.60\.0/\1v0.59.0/' "$fx2" | buildinfo_problems "$kind" "$want" go1.27.3)"; then bad "$kind: x/net v0.59.0 passed"; elif printf '%s\n' "$out" | grep -q "golang.org/x/net is v0.59.0, below the raised v0.60.0"; then ok "$kind: x/net v0.59.0 is reported"; else bad "$kind: x/net v0.59.0 not named: $out"; fi
			if out="$(sed 's/\(golang\.org\/x\/net[[:space:]]\)v0\.60\.0/\1v0.61.0/' "$fx2" | buildinfo_problems "$kind" "$want" go1.27.3)"; then ok "$kind: a newer x/net passes"; else bad "$kind: a newer x/net was refused: $out"; fi
			if out="$(grep -v 'golang\.org/x/net' "$fx2" | buildinfo_problems "$kind" "$want" go1.27.3)"; then bad "$kind: a build info without x/net passed"; elif printf '%s\n' "$out" | grep -q "golang.org/x/net is not in the build info"; then ok "$kind: a missing x/net is reported"; else bad "$kind: missing x/net not named: $out"; fi
			if out="$(XNET_FLOOR='' buildinfo_problems "$kind" "$want" go1.27.3 <"$fx2")"; then bad "$kind: passed with no x/net floor set"; elif printf '%s\n' "$out" | grep -q "no golang.org/x/net floor"; then ok "$kind: an unset x/net floor is refused"; else bad "$kind: unset floor not named: $out"; fi
			;;
		esac
		if out="$(sed 's/GOARCH=arm64/GOARCH=amd64/' "$fx2" | buildinfo_problems "$kind" "$want" go1.27.3)"; then bad "$kind: an amd64 build passed"; else ok "$kind: an amd64 build is refused"; fi
		if out="$(printf '%s\n\t=>\texample.com/fork\tv0.0.1\th1:x=\n' "$(cat "$fx2")" | buildinfo_problems "$kind" "$want" go1.27.3)"; then bad "$kind: a replaced module passed"; elif printf '%s\n' "$out" | grep -q "$kind: a module is replaced"; then ok "$kind: a replaced module is refused"; else bad "$kind: replace not named: $out"; fi
		if out="$(sed 's/^\([[:space:]]*path[[:space:]]\).*/\1example.com\/other/' "$fx2" | buildinfo_problems "$kind" "$want" go1.27.3)"; then bad "$kind: another main package passed"; else ok "$kind: another main package is refused"; fi
	done
	if out="$(buildinfo_problems etcd v3.6.14 go1.27.3 <"$td/goversion-etcd.txt")"; then bad "etcd at another version passed"; elif printf '%s\n' "$out" | grep -q "server/v3 is not at v3.6.14"; then ok "etcd at another version is refused"; else bad "etcd version not named: $out"; fi
	if out="$(buildinfo_problems etcd v3.6.15 go1.27.3 <"$td/goversion-etcdutl.txt")"; then bad "etcdutl passed as etcd"; else ok "etcdutl does not pass as etcd"; fi
	if out="$(buildinfo_problems zot v2.1.21 go1.27.3 <"$td/goversion-zot.txt")"; then bad "zot at another version passed"; elif printf '%s\n' "$out" | grep -q "zot/v2 is not at v2.1.21"; then ok "zot at another version is refused"; else bad "zot version not named: $out"; fi
	if out="$(printf '%s\n\t=>\texample.com/fork\tv0.0.1\th1:x=\n' "$(cat "$td/goversion-etcd.txt")" | buildinfo_problems etcd v3.6.15 go1.27.3)"; then bad "a replaced module passed"; elif printf '%s\n' "$out" | grep -q "replaced"; then ok "a replaced module is refused"; else bad "replace not named: $out"; fi
	echo "==> the build stamp of helm (go version -m capture of the wrapper build; dep list trimmed)"
	local hraised="golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.62.0" hfx="$td/goversion-helm-v4.3.0.txt"
	if out="$(helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised" <"$hfx")"; then ok "helm capture passes"; else bad "helm capture rejected: $out"; fi
	if out="$(helm_buildinfo_problems v4.3.0 go1.27.9 "$hraised" <"$hfx")"; then bad "helm: another toolchain passed"; elif printf '%s\n' "$out" | grep -q "helm: built with 'go1.27.3', the payload pins go1.27.9"; then ok "helm: a build on another toolchain is refused, naming both"; else bad "helm: toolchain not named: $out"; fi
	if out="$(sed '1s/go1.27.3$/go1.27.1/' "$hfx" | helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised")"; then bad "helm: the upstream release's go1.27.1 passed"; elif printf '%s\n' "$out" | grep -q "built with 'go1.27.1'"; then ok "helm: a build-info line on go1.27.1 (the upstream tarball's toolchain) is refused"; else bad "helm: go1.27.1 not named: $out"; fi
	if out="$(sed 's/v0.62.0/v0.60.0/' "$hfx" | helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised")"; then bad "helm: helm's own x/net passed"; elif printf '%s\n' "$out" | grep -q "golang.org/x/net is not at the raised v0.62.0"; then ok "helm: a build without the raised x/net is refused"; else bad "helm: raised x/net not named: $out"; fi
	if out="$(grep -v 'golang.org/x/crypto' "$hfx" | helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised")"; then bad "helm: a build without x/crypto passed"; elif printf '%s\n' "$out" | grep -q "golang.org/x/crypto is not at the raised v0.58.0"; then ok "helm: a build without the raised x/crypto is refused"; else bad "helm: raised x/crypto not named: $out"; fi
	if out="$(helm_buildinfo_problems v4.3.1 go1.27.3 "$hraised" <"$hfx")"; then bad "helm at another version passed"; elif printf '%s\n' "$out" | grep -q "helm.sh/helm/v4 is not at v4.3.1"; then ok "helm at another version is refused"; else bad "helm version not named: $out"; fi
	if out="$(sed 's/CGO_ENABLED=0/CGO_ENABLED=1/' "$hfx" | helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised")"; then bad "helm: a cgo build passed"; else ok "helm: a cgo build is refused"; fi
	if out="$(grep -v -- '-trimpath' "$hfx" | helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised")"; then bad "helm: a build without -trimpath passed"; else ok "helm: a build without -trimpath is refused"; fi
	if out="$(sed 's/GOARCH=arm64/GOARCH=amd64/' "$hfx" | helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised")"; then bad "helm: an amd64 build passed"; else ok "helm: an amd64 build is refused"; fi
	if out="$(printf '%s\n\t=>\texample.com/fork\tv0.0.1\th1:x=\n' "$(cat "$hfx")" | helm_buildinfo_problems v4.3.0 go1.27.3 "$hraised")"; then bad "helm: a replaced module passed"; elif printf '%s\n' "$out" | grep -q "replaced"; then ok "helm: a replaced module is refused"; else bad "helm: replace not named: $out"; fi
	if out="$(helm_buildinfo_problems v4.3.0 go1.27.3 "" <"$hfx")"; then bad "helm: an empty raised set passed"; else ok "helm: an empty raised set is refused, never a vacuous pass"; fi
	if [ "$(buildinfo_settings <"$td/goversion-kine.txt" | tr ' ' '\n' | grep -c .)" = 8 ]; then ok "the build settings are recorded from the build info"; else bad "buildinfo_settings: $(buildinfo_settings <"$td/goversion-kine.txt")"; fi

	echo "==> child_problems over a staged payload (fake go, real-shaped build info)"
	local cpd="$tmp/children"
	mkdir -p "$cpd"
	(
		KINE_VERSION=v0.17.2 KINE_VARIANT=nocgo+p2 KINE_PATCH=p2 ETCD_VERSION=v3.6.15 ETCD_VARIANT=nocgo GO="$fgo"
		ZOT_VERSION=v2.1.22 ZOT_VARIANT=minimal+r1 HELM_BINARY=helm-v4.3.0 HELM_VERSION=v4.3.0 HELM_VARIANT=nocgo+deps2 XNET_FLOOR=v0.60.0
		HELM_RAISED="golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.62.0" HELM_COMMIT=bec5b06ed841fe5269972d864d5177944fd5970f
		printf 'zot\n' >"$cpd/zot"; echo "v2.1.22 minimal+r1" >"$cpd/zot.version"
		printf 'mach-o...v4.3.0...bec5b06ed841fe5269972d864d5177944fd5970f...\n' >"$cpd/helm-v4.3.0"; echo "v4.3.0 nocgo+deps2" >"$cpd/helm.version"
		printf 'mach-o...v0.17.2+p2...\n' >"$cpd/kine"; echo "v0.17.2 nocgo+p2" >"$cpd/kine.version"
		printf 'etcd\n' >"$cpd/etcd"; echo "v3.6.15 nocgo" >"$cpd/etcd.version"
		printf 'etcdutl\n' >"$cpd/etcdutl"; echo "v3.6.15 nocgo" >"$cpd/etcdutl.version"
		r=0
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  ok    the pinned children pass"; else echo "  FAIL  the pinned children were refused: $o"; r=1; fi
		echo "v0.17.2 nocgo+p0" >"$cpd/kine.version"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a patch-set mismatch passed"; r=1; elif printf '%s\n' "$o" | grep -q "kine.version"; then echo "  ok    a marker naming another patch set is refused"; else echo "  FAIL  marker not named: $o"; r=1; fi
		echo "v0.17.2 nocgo+p2" >"$cpd/kine.version"
		printf 'mach-o...v0.17.2...\n' >"$cpd/kine"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a kine without the stamped version passed"; r=1; elif printf '%s\n' "$o" | grep -q "stamped version"; then echo "  ok    a kine without its stamp is refused"; else echo "  FAIL  stamp not named: $o"; r=1; fi
		printf 'mach-o...v0.17.2+p2...\n' >"$cpd/kine"
		rm "$cpd/etcdutl"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a payload without etcdutl passed"; r=1; elif printf '%s\n' "$o" | grep -q "etcdutl: not staged"; then echo "  ok    a missing etcdutl is refused"; else echo "  FAIL  missing etcdutl not named: $o"; r=1; fi
		printf 'etcdutl\n' >"$cpd/etcdutl"
		echo "v2.1.20 minimal+r1" >"$cpd/zot.version"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a zot marker at another pin passed"; r=1; elif printf '%s\n' "$o" | grep -q "zot.version"; then echo "  ok    a zot marker naming another pin is refused"; else echo "  FAIL  zot marker not named: $o"; r=1; fi
		echo "v2.1.22 minimal+r1" >"$cpd/zot.version"
		echo "v4.3.0 tarball" >"$cpd/helm.version"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a helm marker naming another variant passed"; r=1; elif printf '%s\n' "$o" | grep -q "helm.version is not 'v4.3.0 nocgo+deps2'"; then echo "  ok    a helm marker naming another build variant is refused"; else echo "  FAIL  helm marker not named: $o"; r=1; fi
		echo "v4.3.0 nocgo+deps2" >"$cpd/helm.version"
		printf 'mach-o...v4.3.0...\n' >"$cpd/helm-v4.3.0"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a helm without its stamped commit passed"; r=1; elif printf '%s\n' "$o" | grep -q "helm: the stamped string bec5b06ed841fe5269972d864d5177944fd5970f is not in the binary"; then echo "  ok    a helm built without its -X stamp (no commit in the bytes) is refused"; else echo "  FAIL  helm stamp not named: $o"; r=1; fi
		printf 'mach-o...bec5b06ed841fe5269972d864d5177944fd5970f...\n' >"$cpd/helm-v4.3.0"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a helm without its stamped version passed"; r=1; elif printf '%s\n' "$o" | grep -q "helm: the stamped string v4.3.0 is not in the binary"; then echo "  ok    a helm without its stamped version is refused"; else echo "  FAIL  helm version stamp not named: $o"; r=1; fi
		printf 'mach-o...v4.3.0...bec5b06ed841fe5269972d864d5177944fd5970f...\n' >"$cpd/helm-v4.3.0"
		if o="$(child_problems "$cpd" go1.27.9)"; then echo "  FAIL  a helm built on another toolchain passed child_problems"; r=1; elif printf '%s\n' "$o" | grep -q "^helm: built with 'go1.27.3', the payload pins go1.27.9"; then echo "  ok    child_problems names a helm built on another toolchain"; else echo "  FAIL  helm toolchain not named by child_problems: $o"; r=1; fi
		rm "$cpd/zot" "$cpd/helm-v4.3.0"
		if o="$(child_problems "$cpd" go1.27.3)"; then echo "  FAIL  a payload without zot and helm passed"; r=1; elif printf '%s\n' "$o" | grep -q "zot: not staged" && printf '%s\n' "$o" | grep -q "helm-v4.3.0: not staged"; then echo "  ok    a missing zot and a missing helm are refused"; else echo "  FAIL  missing zot or helm not named: $o"; r=1; fi
		exit "$r"
	) || fails=$((fails + 1))

	echo "==> needs network: the modules a failed payload build could not fetch"
	local nn
	nn="$(needs_network_modules <<'LOG'
go: downloading github.com/k3s-io/kine v0.17.2
go mod download github.com/k3s-io/kine@v0.17.2: exit status 1
go: github.com/k3s-io/kine@v0.17.2: Get "https://proxy.golang.org/github.com/k3s-io/kine/@v/v0.17.2.info": dial tcp: lookup proxy.golang.org: no such host
verifying github.com/!burnt!sushi/toml@v1.4.0/go.mod: github.com/!burnt!sushi/toml@v1.4.0/go.mod: Get "https://sum.golang.org/lookup/github.com/!burnt!sushi/toml@v1.4.0": dial tcp: lookup sum.golang.org: no such host
pkg/x.go:5:2: Get "https://proxy.golang.org/go.etcd.io/bbolt/@v/v1.4.3.zip": dial tcp 142.250.0.1:443: i/o timeout
again: github.com/k3s-io/kine@v0.17.2: Get "https://proxy.golang.org/x": dial tcp: lookup proxy.golang.org: no such host
gh: error connecting to api.github.com: dial tcp: lookup api.github.com: no such host
pkg/y.go:1:1: undefined: Foo
LOG
)"
	if [ "$nn" = "$(printf 'github.com/k3s-io/kine@v0.17.2\ngithub.com/BurntSushi/toml@v1.4.0\ngo.etcd.io/bbolt@v1.4.3\n?')" ]; then
		ok "proxy, sumdb and build-download failures each name their module once, case-decoded; an unnamed one is '?'"
	else
		bad "needs_network_modules = '$nn'"
	fi
	if [ -z "$(printf 'pkg/y.go:1:1: undefined: Foo\nexit status 1\n' | needs_network_modules)" ]; then ok "a non-network failure names nothing"; else bad "a compile error was reported as needs network"; fi

	gv_self_test "$tmp"

	unset -f ok bad expect_fail
	echo
	if [ "$fails" -ne 0 ]; then
		echo "stage self-test: $fails FAILED"
		return 1
	fi
	echo "stage self-test: all passed"
}

# ---- arguments ----------------------------------------------------------------
BINARY_NAME="k3sm"
STUB_PAYLOAD=0
VERIFY_ONLY=0
VERIFY_RELEASE=""
FROM_CAPTURED=""
RELEASE=0
CP_BUILD=""
CP_STAMP=""
CP_KEY=""
CP_RAISES=""
CP_RHASH=""
PRINT_PINNED=0
REWRITE_MANIFEST=""
SELF_TEST=0
LDFLAGS=""
OUT=""

while [ $# -gt 0 ]; do
	case "$1" in
	--binary-name) BINARY_NAME="${2:?--binary-name needs a value}"; shift 2 ;;
	--stub-payload) STUB_PAYLOAD=1; shift ;;
	--verify-only) VERIFY_ONLY=1; shift ;;
	--verify-release) VERIFY_RELEASE="${2:?--verify-release needs a TEAMID}"; shift 2 ;;
	--from-captured) FROM_CAPTURED="${2:?--from-captured needs a file}"; shift 2 ;;
	--release) RELEASE=1; shift ;;
	--cp-build) CP_BUILD="${2:?--cp-build needs a directory}"; shift 2 ;;
	--print-pinned-source-files) PRINT_PINNED=1; shift ;;
	--self-test) SELF_TEST=1; shift ;;
	--rewrite-manifest) REWRITE_MANIFEST="${2:?--rewrite-manifest needs a tree}"; shift 2 ;;
	--ldflags) LDFLAGS="${2?--ldflags needs a value}"; shift 2 ;;
	-h | --help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
	-*) die "unknown flag: $1" ;;
	*)
		[ -z "$OUT" ] || die "only one output directory may be given (got '$OUT' and '$1')"
		OUT="$1"; shift ;;
	esac
done

if [ "$SELF_TEST" = 1 ]; then
	self_test
	exit $?
fi

if [ "$PRINT_PINNED" = 1 ]; then
	printf '%s\n' "$PINNED_SOURCE_FILES"
	exit 0
fi
[ -z "$CP_BUILD" ] || [ "$RELEASE" = 1 ] || die "--cp-build is only meaningful with --release"

if [ -n "$VERIFY_RELEASE" ]; then
	valid_team "$VERIFY_RELEASE" || die "--verify-release: '$VERIFY_RELEASE' is not a 10-character Team ID"
	[ "$VERIFY_ONLY" = 0 ] || die "--verify-release and --verify-only are mutually exclusive (--verify-release runs every --verify-only check)"
	[ "$RELEASE" = 0 ] && [ "$STUB_PAYLOAD" = 0 ] && [ -z "$LDFLAGS" ] || die "--verify-release inspects; it builds and signs nothing"
fi
if [ -n "$FROM_CAPTURED" ]; then
	[ -n "$VERIFY_RELEASE" ] || die "--from-captured needs --verify-release <TEAMID>"
	[ -z "$OUT" ] || die "--from-captured reads a file, not a tree"
	[ -f "$FROM_CAPTURED" ] || die "--from-captured: $FROM_CAPTURED is not a file"
	if out="$(release_sig_problems "$VERIFY_RELEASE" <"$FROM_CAPTURED")"; then
		echo "==> $FROM_CAPTURED: timestamped, hardened Developer ID signature for $VERIFY_RELEASE"
		exit 0
	fi
	printf '%s\n' "$out" | sed 's/^/    /' >&2
	die "$FROM_CAPTURED fails the release signature policy"
fi

if [ -n "$REWRITE_MANIFEST" ]; then
	[ -z "$OUT" ] && [ -z "$VERIFY_RELEASE" ] && [ "$VERIFY_ONLY" = 0 ] && [ "$RELEASE" = 0 ] && [ "$STUB_PAYLOAD" = 0 ] && [ -z "$LDFLAGS" ] ||
		die "--rewrite-manifest <tree> takes no other mode or output directory"
	[ -d "$REWRITE_MANIFEST" ] || die "--rewrite-manifest: $REWRITE_MANIFEST is not a directory"
	tree="$(cd "$REWRITE_MANIFEST" && pwd)"
	manifest_rewrite "$tree" || die "could not rewrite the manifest of $tree"
	echo "==> rewrote $tree/$MANIFEST_NAME and $tree.$MANIFEST_NAME"
	exit 0
fi

[ -n "$OUT" ] || die "usage: stage.sh <out-dir> [--binary-name <name>] [--stub-payload] [--release]"

if [ "$VERIFY_ONLY" = 1 ] || [ -n "$VERIFY_RELEASE" ]; then
	[ "$STUB_PAYLOAD" = 0 ] || die "--verify-only and --stub-payload are mutually exclusive (nothing is produced to stub)"
	[ -z "$LDFLAGS" ] || die "--verify-only builds nothing, so --ldflags has no meaning"
	[ "$RELEASE" = 0 ] || die "--release stages; it cannot be combined with a verify mode"
	[ -d "$OUT" ] || die "verify: $OUT is not a directory"
else
	case "$OUT" in
	*/dist | */dist/*) die "refusing to stage under dist/ — goreleaser owns it and --clean empties it before the archive globs run" ;;
	esac
	if [ "$RELEASE" = 1 ]; then
		# Fail before building or downloading anything. A release never signs a
		# third-party build: the control-plane binaries must come from k3sm's own
		# pinned-source build, hack/release/build-cp.sh, handed in as --cp-build.
		[ "$STUB_PAYLOAD" = 0 ] || die "--release cannot stage stub payload files"
		[ -x "$HERE/build-cp.sh" ] || die "--release: hack/release/build-cp.sh is missing or not executable"
		[ -n "$CP_BUILD" ] ||
			die "--release needs --cp-build <dir>, the output of hack/release/build-cp.sh <dir>: the control-plane payload is signed only when built from pinned source"
		while [ "${CP_BUILD%/}" != "$CP_BUILD" ] && [ "$CP_BUILD" != / ]; do CP_BUILD="${CP_BUILD%/}"; done
		# Nobody but the effective uid may be able to swap a file in the build or
		# rename the build directory itself.
		cache_root_problems "$CP_BUILD" "--cp-build" >&2 || die "--release: refusing --cp-build $CP_BUILD"
		cache_root_problems "$(dirname "$CP_BUILD")" "--cp-build's parent" >&2 || die "--release: refusing --cp-build $CP_BUILD"
		if ! cp_problems="$(cp_build_problems "$CP_BUILD")"; then
			printf '%s\n' "$cp_problems" >&2
			die "--release: --cp-build $CP_BUILD is not exactly the output of hack/release/build-cp.sh"
		fi
		cp_live_out="$(cp_live "$HERE/build-cp.sh")" || die "--release: build-cp.sh cannot print its cache key and raise list"
		eval "$cp_live_out"
		# The stamp is read ONCE; every later check of the build, and of the
		# copies placed into the payload, runs against this snapshot.
		CP_STAMP="$(cat "$CP_BUILD/$CP_STAMP_NAME")" || die "--release: cannot read $CP_BUILD/$CP_STAMP_NAME"
		if ! cp_problems="$(cp_build_check "$CP_BUILD" "$CP_KEY" "$CP_RAISES" "$CP_RHASH" "$CP_STAMP")"; then
			printf '%s\n' "$cp_problems" >&2
			die "--release: --cp-build $CP_BUILD is not build-cp.sh's build for $CP_KEY; rebuild it"
		fi
		CP_BUILD="$(cd "$CP_BUILD" && pwd)"
	fi
	mkdir -p "$OUT"
fi

OUT="$(cd "$OUT" && pwd)"
BIN="$OUT/$BINARY_NAME"
PAYLOAD_DIR="$OUT/cp-payload"

# Every Go build in this script targets the shipped platform, never the host's.
export GOOS=darwin GOARCH=arm64 CGO_ENABLED=1
read_pins

# The per-pod VM host helper is the ONLY k3sm binary that carries
# com.apple.security.virtualization (runtimed/pkg/sandbox.VMHostName), which is
# why it is signed separately below and why its entitlement is read back in
# verify_tree: a dev-staged k3sm-vmhost without it installs cleanly and then
# breaks every vm-RuntimeClass pod, with the only symptom being the node losing
# its k3sm.io/virtualization label.
VMHOST_ENTITLEMENTS="$WS_ROOT/runtimed/cmd/k3sm-vmhost/vmhost.entitlements"

# ---- verification ------------------------------------------------------------
# ONE implementation, driven from three directions: the staging path calls it
# after it builds and signs, and --verify-only and --verify-release call it over
# a tree somebody else produced (an extracted release archive, a set about to be
# installed, a tree the signing pipeline just signed). Keeping it a function
# rather than a second script is the point — the checks that decide whether a
# staged tree is shippable must not have a second copy that drifts.
#
# Every set below is DERIVED, never listed: the required members come from the
# binary's own `install --print-required-artifacts` contract, and the Mach-O set
# comes from file(1) (macho_files) rather than a name list.
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
		n_macho=$((n_macho + 1))
		codesign --verify --strict "$f" >/dev/null 2>&1 || { echo "    UNSIGNED/INVALID: $f"; bad_sign=1; }
		case "$desc" in
		*arm64*) ;;
		*) echo "    WRONG ARCH: $f -> $desc"; bad_arch=1 ;;
		esac
	done < <(macho_files "$OUT")
	[ "$bad_sign" = 0 ] || die "a staged Mach-O fails codesign --verify — launchd refuses it with OS_REASON_CODESIGNING"
	[ "$bad_arch" = 0 ] || die "non-arm64 artifact staged (a Rosetta-defaulted toolchain? every build here pins GOARCH=arm64)"
	[ "$n_macho" -ge "$MACHO_FLOOR" ] || die "only $n_macho Mach-O(s) found under $OUT — the set cannot be complete"

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

if [ -n "$VERIFY_RELEASE" ]; then
	echo "==> verify-release over $OUT for team $VERIFY_RELEASE (inspection only: nothing built, downloaded or signed)"
	tree_shape_problems "$OUT" || die "$OUT is not a plain tree of regular files"
	echo "==> verify the Developer ID signature on every Mach-O"
	verify_release_signatures "$OUT" "$VERIFY_RELEASE" || die "a Mach-O under $OUT fails the release signature policy (above)"
	verify_tree
	echo "==> verify $MANIFEST_NAME against the tree"
	verify_manifest "$OUT" || die "the payload manifest does not match $OUT (run --rewrite-manifest after signing)"
	echo "==> release-verified $(find "$OUT" -type f | wc -l | tr -d ' ') files in $OUT"
	exit 0
fi

if [ "$VERIFY_ONLY" = 1 ]; then
	echo "==> verify-only over $OUT (nothing built, nothing downloaded, nothing signed)"
	tree_shape_problems "$OUT" || die "$OUT is not a plain tree of regular files"
	verify_tree
	echo "==> verified $(find "$OUT" -type f | wc -l | tr -d ' ') files in $OUT"
	exit 0
fi

echo "==> staging into $OUT (darwin/arm64)"

# The pinned toolchain, before anything is built: `k3sm payload` builds kine,
# etcd, etcdutl, zot and helm with the go on PATH (GOTOOLCHAIN=local), and the
# manifest records it. Stub staging builds none of them and is exempt.
if [ "$STUB_PAYLOAD" = 0 ]; then
	echo "==> assert the pinned Go toolchain ($PAYLOAD_GO_VERSION)"
	tc_problem="$(toolchain_problems "$PAYLOAD_GO_VERSION")" || die "$tc_problem"
fi

# The control-plane binaries for lab staging: build-cp.sh's outputs, from the
# cache when it holds this key (see "The control-plane binaries" above). Release
# staging was handed them (--cp-build); stubs need none.
if [ "$STUB_PAYLOAD" = 0 ] && [ "$RELEASE" = 0 ]; then
	CP_BUILD="$(lab_cp_build "${K3SM_CP_CACHE:-$REPO_ROOT/.cp-build-cache}" "$BUILD_CP")" ||
		die "could not produce the control-plane binaries with hack/release/build-cp.sh (above)"
	cp_live_out="$(cp_live "$BUILD_CP")" || die "build-cp.sh cannot print its cache key and raise list"
	eval "$cp_live_out"
	# The stamp is read ONCE, as on the release path, and the build rechecked
	# against that snapshot; the placed copies are checked against it too.
	CP_STAMP="$(cat "$CP_BUILD/$CP_STAMP_NAME")" || die "cannot read $CP_BUILD/$CP_STAMP_NAME"
	if ! cp_problems="$(cp_build_check "$CP_BUILD" "$CP_KEY" "$CP_RAISES" "$CP_RHASH" "$CP_STAMP")"; then
		printf '%s\n' "$cp_problems" >&2
		die "the cached build-cp output $CP_BUILD changed after it was selected"
	fi
fi

# The k3sm binary. Built from the repo with go.work active (the sibling-checkout layout)
# so the sibling modules resolve to these checkouts.
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

# The per-pod VM host helper. Built from the parent of the repo checkouts for the same reason
# as the exec shim, and signed separately below (see VMHOST_ENTITLEMENTS above).
echo "==> build k3sm-vmhost (runtimed)"
[ -f "$VMHOST_ENTITLEMENTS" ] || die "vmhost entitlements plist not found at $VMHOST_ENTITLEMENTS"
( cd "$WS_ROOT" && go build -trimpath -o "$OUT/k3sm-vmhost" k3sm.io/runtimed/cmd/k3sm-vmhost )

# The control-plane payload. `k3sm payload` downloads the pinned kwok-ci/k8s
# binaries, builds kine (the patched build), etcd and etcdutl (the wrapper module),
# zot and helm from pinned module source, exactly the builds the daemon would
# otherwise run on demand, and — on this path — verifies every downloaded binary
# against its pinned sha256, failing closed on a mismatch or an unexpected file. A module the cache
# lacks with no network reachable is reported as "needs network: <module>". The
# four downloaded control-plane binaries are then replaced with build-cp.sh's.
if [ "$STUB_PAYLOAD" = 1 ]; then
	echo "==> stage cp-payload (STUBS — shape only, never publish this tree)"
	mkdir -p "$PAYLOAD_DIR"
	for rel in $("$BIN" install --print-required-artifacts); do
		case "$rel" in
		cp-payload/*) printf 'stub\n' >"$OUT/$rel" ;;
		esac
	done
	upstream_note="STUB payload: placeholder bytes, never publish this tree"
else
	echo "==> stage cp-payload (pinned download + digest verify; kine, etcd, etcdutl, zot and helm built from pinned source)"
	payload_log="$(mktemp -t k3sm-payload)"
	if ! "$BIN" payload "$PAYLOAD_DIR" 2>&1 | tee "$payload_log"; then
		missing="$(needs_network_modules <"$payload_log")"
		rm -f "$payload_log"
		if [ -n "$missing" ]; then
			printf '%s\n' "$missing" | sed -e 's/^?$/(a fetch that names no module; see the output above)/' -e 's/^/needs network: /' >&2
			die "needs network: the Go module cache does not hold what the payload build needs and the network is unreachable; reconnect (or warm the cache on a connected host) and re-run"
		fi
		die "'$BINARY_NAME payload' failed (output above)"
	fi
	rm -f "$payload_log"
	echo "==> verify kine, etcd, etcdutl, zot and helm are the pinned builds"
	if ! child_out="$(child_problems "$PAYLOAD_DIR" "$PAYLOAD_GO_VERSION")"; then
		printf '%s\n' "$child_out" | sed 's/^/    /' >&2
		die "the staged source-built children are not the pinned builds (above)"
	fi
	upstream_note="as produced by '$BINARY_NAME payload': downloads checked against their pinned sha256, kine, etcd, etcdutl, zot and helm built from their pinned modules with $PAYLOAD_GO_VERSION"
	echo "==> replace the control-plane binaries with the pinned-source build ($CP_BUILD)"
	place_cp_build "$CP_BUILD" "$PAYLOAD_DIR" || die "could not place the pinned-source build into $PAYLOAD_DIR"
	# The PLACED copies are what gets signed: check them, against the snapshot
	# taken when the build was checked, never against $CP_BUILD again.
	if ! cp_out="$(cp_set_check "$PAYLOAD_DIR" "${CP_KEY%%-go[0-9]*}" "$CP_RAISES" "$CP_STAMP")"; then
		printf '%s\n' "$cp_out" >&2
		die "the staged control-plane binaries are not the build checked from $CP_BUILD (above)"
	fi
	upstream_note="$upstream_note; the control-plane binaries replaced by hack/release/build-cp.sh output, build $CP_KEY"
fi

# The children vuln scan: every staged Go child, after the payload is final and
# before anything is signed. Stubs are not binaries and are not scanned.
if [ "$STUB_PAYLOAD" = 1 ]; then
	echo "==> children vuln scan: skipped (stub payload, nothing to scan)"
else
	echo "==> children vuln scan (govulncheck -mode=binary over every staged Go child; allow file $GV_ALLOW)"
	children_vuln_scan "$PAYLOAD_DIR" ||
		die "children vuln scan: a staged child carries an unallowed vulnerability (bump the child's pin (pkg/executor for kubernetes, the pin files read_pins reads for the rest) or name it in hack/release/govulncheck.allow with a reason and an expiry), the allow file has an expired or stale entry, or the scan could not run (above)"
fi

# The pre-sign digests, recorded before ANY signing: the pinned digests describe
# upstream bytes, and re-signing rewrites them.
echo "==> record pre-sign upstream digests ($UPSTREAM_NAME)"
upstream_digests_write "$OUT" "$upstream_note" || die "could not write $OUT/$UPSTREAM_NAME"

# Release staging signs only k3sm's own pinned-source builds (checked again here,
# per file, right before the first signature).
if [ "$RELEASE" = 1 ]; then
	pinned_content_problems "$OUT" "$CP_BUILD" ||
		die "--release: the staged control-plane binaries are not the pinned-source build in $CP_BUILD"
	kube_marker_problems "$OUT" "$CP_STAMP" "$KUBE_VERSION" ||
		die "--release: the staged $KUBE_MARKER_FILE does not vouch for the --cp-build tag (above)"
	refuse_unpinned_payload "$OUT" "$(release_payload_files)" ||
		die "--release: refusing to sign cp-payload files not built from pinned source (hack/release/build-cp.sh, or k3sm's own kine/etcd/zot/helm build)"
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

# The manifest, AFTER signing: from here on it is the authority for every byte
# in the tree.
echo "==> write the payload manifest ($MANIFEST_NAME)"
if [ "$STUB_PAYLOAD" = 1 ]; then
	comments="$(manifest_comments stub)"
else
	comments="$(manifest_comments)"
fi
manifest_write "$OUT" "$comments" || die "could not write the payload manifest"

echo "==> staged $(find "$OUT" -type f | wc -l | tr -d ' ') files into $OUT"
