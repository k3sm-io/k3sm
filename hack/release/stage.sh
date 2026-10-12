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
#                    exists. This is the seam the workspace's hack/release-gate.sh
#                    drives so the artifact-quality tier re-uses THESE checks over
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
#                    The control-plane binaries are taken from --cp-build instead
#                    of the prebuilt download, and every cp-payload file must be
#                    one of PINNED_SOURCE_FILES, byte-identical to its --cp-build
#                    copy. kine, etcd, etcdutl, helm and the version markers are
#                    not on that list yet, so today --release still refuses,
#                    naming them. Without it (the default) the ad-hoc lab staging
#                    below is unchanged.
#   --cp-build <dir> with --release: the output directory of
#                    hack/release/build-cp.sh <dir>; it must hold exactly the
#                    files build-cp.sh produces.
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
#   --self-test      hermetic self-test of the manifest, the signature parser and
#                    the release refusal (no network, no credentials, no keychain)
#   (k3sm-vmhost is always built and signed with
#   cmd/k3sm-vmhost/vmhost.entitlements: pkg/install.RequiredSiblings names it,
#   so a stage without it fails the required-artifact loop.)
#
# Staging writes two digest files into the tree, and copies the manifest beside it:
#   UPSTREAM-DIGESTS  sha256 of every cp-payload file BEFORE any signing, i.e. the
#                     bytes `k3sm payload` checked against its pinned digests.
#   PAYLOAD-SHA256    written AFTER signing: `<sha256>  <relpath>` for every
#                     regular file in the tree (LC_ALL=C order, no ./ prefix, the
#                     manifest itself and .DS_Store excluded), after `#` comment
#                     lines recording the toolchain and the kine/etcd pins. After
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

# manifest_comments: the toolchain and the kine/etcd pins, read from the source
# the staged binary was built from.
manifest_comments() {
	local src="$REPO_ROOT/pkg/executor/executor.go" kv ev
	kv="$(sed -n 's/^[[:space:]]*DefaultKineVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$src")"
	ev="$(sed -n 's/^[[:space:]]*DefaultEtcdVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$src")"
	[ -n "$kv" ] && [ -n "$ev" ] || die "cannot read DefaultKineVersion/DefaultEtcdVersion from $src"
	printf 'k3sm payload manifest; verify inside the tree with: shasum -a 256 -c %s\n' "$MANIFEST_NAME"
	printf 'toolchain: %s %s/%s\n' "$(go env GOVERSION)" "$GOOS" "$GOARCH"
	printf 'kine: github.com/k3s-io/kine %s\n' "$kv"
	printf 'etcd: go.etcd.io/etcd %s\n' "$ev"
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

# cp_build_problems <dir>: non-zero, naming each problem, unless <dir> holds
# exactly the regular files PINNED_SOURCE_FILES names (by base name), no more.
cp_build_problems() {
	local dir="$1" rel name bad=0 f
	[ -d "$dir" ] || { echo "    --cp-build $dir is not a directory"; return 1; }
	while IFS= read -r rel; do
		name="${rel#cp-payload/}"
		[ -f "$dir/$name" ] && [ ! -L "$dir/$name" ] || { echo "    --cp-build lacks $name"; bad=1; }
	done <<<"$PINNED_SOURCE_FILES"
	for f in "$dir"/* "$dir"/.[!.]*; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		printf '%s\n' "$PINNED_SOURCE_FILES" | grep -qxF -- "cp-payload/$(basename "$f")" || { echo "    --cp-build holds an unexpected $(basename "$f")"; bad=1; }
	done
	return "$bad"
}

# place_cp_build <cp-build> <payload-dir>: put each pinned-source file into the
# payload dir as a new file (copy to a temp, then rename), replacing what the
# payload step staged under that name.
place_cp_build() {
	local src="$1" dst="$2" rel name
	while IFS= read -r rel; do
		name="${rel#cp-payload/}"
		cp "$src/$name" "$dst/.$name.cp-build" && chmod 0755 "$dst/.$name.cp-build" && mv -f "$dst/.$name.cp-build" "$dst/$name" || return 1
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
		# pinned-source build, which does not exist yet.
		[ "$STUB_PAYLOAD" = 0 ] || die "--release cannot stage stub payload files"
		[ -x "$HERE/build-cp.sh" ] || die "--release: hack/release/build-cp.sh is missing or not executable"
		[ -n "$CP_BUILD" ] ||
			die "--release needs --cp-build <dir>, the output of hack/release/build-cp.sh <dir>: the control-plane payload is signed only when built from pinned source"
		if ! cp_problems="$(cp_build_problems "$CP_BUILD")"; then
			printf '%s\n' "$cp_problems" >&2
			die "--release: --cp-build $CP_BUILD is not exactly the output of hack/release/build-cp.sh"
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
	upstream_note="STUB payload: placeholder bytes, never publish this tree"
else
	echo "==> stage cp-payload (pinned download + digest verify)"
	"$BIN" payload "$PAYLOAD_DIR"
	upstream_note="as produced by '$BINARY_NAME payload': downloads checked against their pinned sha256, kine built from its pinned module"
	if [ "$RELEASE" = 1 ]; then
		echo "==> replace the control-plane binaries with the pinned-source build ($CP_BUILD)"
		place_cp_build "$CP_BUILD" "$PAYLOAD_DIR" || die "could not place the pinned-source build into $PAYLOAD_DIR"
		upstream_note="$upstream_note; the control-plane binaries replaced by hack/release/build-cp.sh output"
	fi
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
	refuse_unpinned_payload "$OUT" "$PINNED_SOURCE_FILES" ||
		die "--release: refusing to sign cp-payload files not built from pinned source (hack/release/build-cp.sh)"
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
manifest_write "$OUT" "$(manifest_comments)" || die "could not write the payload manifest"

echo "==> staged $(find "$OUT" -type f | wc -l | tr -d ' ') files into $OUT"
