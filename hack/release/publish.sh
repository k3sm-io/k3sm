#!/usr/bin/env bash
#
# publish.sh — the attended release driver: stage, sign, verify, then a
# draft-then-promote upload.
#
#   hack/release/publish.sh --version vX.Y.Z --stage-dir <dir> --cp-build <dir>
#                           --ldflags <flags> --identity <identity>
#                           --team-id <TEAMID> --notes-file <file>
#                           [--repo <owner/name>]
#   hack/release/publish.sh --self-test
#
#   --version     the release tag, which must already exist on the repo
#                 (vMAJOR.MINOR.PATCH or ...-rc.N); this script never creates one
#   --stage-dir   where stage.sh assembles the tree (must not exist yet); the
#                 upload assets are written beside it, in <stage-dir>.assets
#   --cp-build    the output directory of hack/release/build-cp.sh
#   --ldflags     the -ldflags for the k3sm build; must stamp
#                 k3sm.io/k3sm/pkg/version.Version, which is checked against
#                 --version before anything is uploaded
#   --identity    the Developer ID Application identity (see sign.sh). No default.
#   --team-id     the Apple Team ID. No default.
#   --notes-file  the release notes body
#   --repo        the GitHub repository (default k3sm-io/k3sm)
#   --self-test   hermetic test of the refusals and the promote check, with
#                 every signing, notary, keychain and GitHub tool replaced by a
#                 fake on PATH (no network, no credentials, no keychain)
#
# The flow, each step refusing to continue on any failure:
#   1. hack/release/stage.sh <stage-dir> --release --cp-build <dir> --ldflags ...
#   2. hack/release/sign.sh --identity ... --team-id ... <stage-dir>
#      (prompts for the Team ID at the terminal; signs and notarizes)
#   3. hack/release/stage.sh --rewrite-manifest <stage-dir>
#      (signing changed the bytes; the manifest is recomputed over them)
#   4. hack/release/stage.sh <stage-dir> --verify-release <TEAMID>
#   5. package <stage-dir>.assets: the tarball of exactly the verified tree plus
#      LICENSE and NOTICE, the tree's PAYLOAD-SHA256 manifest, and a checksums
#      file over both
#   6. gh release create <tag> --draft --verify-tag with those assets
#   7. read the draft back (gh release view --json) and check it: still a draft,
#      exactly the expected asset names, each fully uploaded, with the local
#      size and SHA-256 (the asset digest GitHub reports, or a download when it
#      reports none)
#   8. only then promote: gh release edit <tag> --draft=false
#
# A draft whose assets fail step 7 is never promoted, so a failed or partial
# upload of a large asset cannot become the latest release that an install
# script fetches. The draft is left for the operator to inspect and delete.
#
# THE REFUSAL. Outside --self-test this script refuses, before it parses an
# argument, when CLAUDECODE or K3SM_AUTO is set at all or when /dev/tty cannot
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
}

# expected_assets <tag> <assetdir>: the asset names a complete draft carries,
# read from the local checksums file, plus that file itself.
expected_assets() {
	local sums="$2/$(checksums_name "$1")"
	[ -f "$sums" ] || return 1
	{ sed 's/^[0-9a-f]*  //' "$sums"; checksums_name "$1"; echo; } | sed '/^$/d' | LC_ALL=C sort
}

# verify_draft <tag> <repo> <assetdir>: zero only when the release is still a
# draft and its assets are exactly the local ones, fully uploaded, byte for byte.
# Prints every problem it finds.
verify_draft() {
	local tag="$1" repo="$2" dir="$3" json want got n problems=0 state size digest local_sum tmp
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
		local_sum="sha256:$(shasum -a 256 "$dir/$n" | cut -d' ' -f1)"
		[ "$state" = "uploaded" ] || { echo "    $n: upload state '$state', not uploaded"; problems=1; }
		[ "$size" = "$(stat -f %z "$dir/$n")" ] || { echo "    $n: size $size differs from the local file"; problems=1; }
		if [ -z "$digest" ]; then
			if gh release download "$tag" --repo "$repo" --pattern "$n" --dir "$tmp" >/dev/null 2>&1 && [ -f "$tmp/$n" ]; then
				digest="sha256:$(shasum -a 256 "$tmp/$n" | cut -d' ' -f1)"
			else
				echo "    $n: no digest reported and the download failed"; problems=1; continue
			fi
		fi
		[ "$digest" = "$local_sum" ] || { echo "    $n: digest $digest differs from the local $local_sum"; problems=1; }
	done <<<"$want"
	rm -rf "$tmp"
	return "$problems"
}

# promote <tag> <repo> <assetdir>: publish the draft, only if verify_draft passes.
promote() {
	local tag="$1" repo="$2" dir="$3" out
	if ! out="$(verify_draft "$tag" "$repo" "$dir")"; then
		printf '%s\n' "$out" >&2
		refuse draft-unverified \
			"the draft release $tag does not match the staged assets; it was NOT promoted." \
			"Inspect it on GitHub, delete it (gh release delete $tag --repo $repo), and publish again."
	fi
	echo "==> draft $tag verified; promoting"
	gh release edit "$tag" --repo "$repo" --draft=false || die "promoting $tag failed; the verified draft is still in place"
}

# upload <tag> <repo> <notes> <assetdir>: create the draft, then promote.
upload() {
	local tag="$1" repo="$2" notes="$3" dir="$4" names=() n
	while IFS= read -r n; do names+=("$dir/$n"); done < <(expected_assets "$tag" "$dir")
	[ "${#names[@]}" -eq 3 ] || die "expected three assets in $dir"
	echo "==> create the draft release $tag on $repo"
	gh release create "$tag" --repo "$repo" --draft --verify-tag --title "$tag" --notes-file "$notes" "${names[@]}" ||
		die "creating the draft failed; any partial draft is left unpublished for inspection"
	promote "$tag" "$repo" "$dir"
}

# ---- self-test ------------------------------------------------------------------
self_test() {
	local fails=0 T log out rc sign="$HERE/sign.sh" tag=v0.0.0 repo=example/k3sm
	T="$(mktemp -d)"
	SELFTEST_TMP="$T"
	trap 'rm -rf "$SELFTEST_TMP"' EXIT
	log="$T/tool.log"
	ok() { echo "  ok   $1"; }
	bad() { echo "  FAIL $1"; fails=$((fails + 1)); }

	# Fakes: record argv and exit 97. gh answers `release view` from
	# $FAKE_GH_VIEW and, with FAKE_GH_CREATE_OK=1, accepts `release create`.
	mkdir "$T/fakes"
	for tool in codesign xcrun notarytool security ditto; do
		printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s $*" >>"$FAKE_TOOL_LOG"\nexit 97\n' "$tool" >"$T/fakes/$tool"
	done
	cat >"$T/fakes/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "gh $*" >>"$FAKE_TOOL_LOG"
case "$1 $2" in
"release view") [ -n "${FAKE_GH_VIEW:-}" ] && cat "$FAKE_GH_VIEW" && exit 0 ;;
"release create") [ "${FAKE_GH_CREATE_OK:-}" = 1 ] && exit 0 ;;
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
	rc=0; out="$(on_pty "$TEAM" env -u CLAUDECODE -u K3SM_AUTO PATH="$FPATH" bash "$sign" --identity "$ID" --team-id "$TEAM" "$T/tree")" || rc=$?
	if [ "$rc" -ne 0 ] && ! grep -q REFUSE <<<"$out" && grep -q "has no PAYLOAD-SHA256" <<<"$out" && [ ! -s "$log" ]; then
		ok "control: the typed Team ID passes the guard, which then stops before any tool"
	else
		bad "control: guard pass (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	: >"$log"

	echo "publish.sh refusals"
	rc=0; out="$(env -u K3SM_AUTO CLAUDECODE=1 PATH="$FPATH" bash "$HERE/publish.sh" --version "$tag" 2>&1)" || rc=$?
	expect_refusal "CLAUDECODE=1 refuses before staging" automation-env "$out" "$rc"
	rc=0; out="$(env -u CLAUDECODE K3SM_AUTO= PATH="$FPATH" bash "$HERE/publish.sh" --version "$tag" 2>&1)" || rc=$?
	expect_refusal "K3SM_AUTO set but empty refuses" automation-env "$out" "$rc"
	rc=0; out="$(no_tty env -u CLAUDECODE -u K3SM_AUTO PATH="$FPATH" bash "$HERE/publish.sh" --version "$tag")" || rc=$?
	expect_refusal "no controlling terminal refuses" no-tty "$out" "$rc"

	# ---- the draft check and promote, against canned gh JSON ----
	echo "draft-then-promote"
	local A="$T/assets" base sums
	base="$(asset_base "$tag")"; sums="$(checksums_name "$tag")"
	mkdir "$A"
	printf 'tarball bytes\n' >"$A/$base.tar.gz"
	printf 'manifest bytes\n' >"$A/$base.PAYLOAD-SHA256"
	(cd "$A" && shasum -a 256 "$base.tar.gz" "$base.PAYLOAD-SHA256" >"$sums")
	# good_json [jq filter applied to the good draft]
	draft_json() {
		local n f=()
		for n in "$base.tar.gz" "$base.PAYLOAD-SHA256" "$sums"; do
			f+=("{\"name\":\"$n\",\"state\":\"uploaded\",\"size\":$(stat -f %z "$A/$n"),\"digest\":\"sha256:$(shasum -a 256 "$A/$n" | cut -d' ' -f1)\"}")
		done
		local IFS=,
		jq -c "${1:-.}" <<<"{\"isDraft\":true,\"assets\":[${f[*]}]}"
	}
	# promote_case <name> <json> <want: pass|refuse>
	promote_case() {
		printf '%s\n' "$2" >"$T/view.json"
		: >"$log"
		rc=0
		out="$( (PATH="$FPATH" FAKE_GH_VIEW="$T/view.json" FAKE_GH_EDIT_OK=1 promote "$tag" "$repo" "$A") 2>&1)" || rc=$?
		if [ "$3" = pass ]; then
			if [ "$rc" -eq 0 ] && grep -q -- "^gh release edit $tag --repo $repo --draft=false\$" "$log"; then ok "$1"; else
				bad "$1 (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/       /'
			fi
		else
			if [ "$rc" -ne 0 ] && grep -q "REFUSE: draft-unverified" <<<"$out" && ! grep -q -- '--draft=false' "$log" &&
				! grep -q '^gh release edit' "$log"; then ok "$1"; else
				bad "$1 (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
			fi
		fi
	}
	promote_case "control: a complete, matching draft is promoted" "$(draft_json)" pass
	promote_case "a wrong asset digest refuses" "$(draft_json '.assets[0].digest = "sha256:0000"')" refuse
	promote_case "a missing asset refuses" "$(draft_json 'del(.assets[1])')" refuse
	promote_case "an extra asset refuses" "$(draft_json '.assets += [.assets[0] | .name = "extra.bin"]')" refuse
	promote_case "a partially uploaded asset refuses" "$(draft_json '.assets[0].state = "starter"')" refuse
	promote_case "a size mismatch refuses" "$(draft_json '.assets[2].size = 1')" refuse
	promote_case "a release that is no longer a draft refuses" "$(draft_json '.isDraft = false')" refuse
	promote_case "no digest and a failed download refuses" "$(draft_json 'del(.assets[0].digest)')" refuse
	if grep -q "^gh release download $tag" "$log"; then ok "a missing digest falls back to downloading the asset"; else bad "no download fallback"; fi
	promote_case "unreadable JSON refuses" "not json" refuse

	# The full upload: the create succeeds, the draft read back is bad.
	printf '%s\n' "$(draft_json '.assets[0].digest = "sha256:0000"')" >"$T/view.json"
	printf 'notes\n' >"$T/notes.md"
	: >"$log"
	rc=0
	out="$( (PATH="$FPATH" FAKE_GH_VIEW="$T/view.json" FAKE_GH_CREATE_OK=1 FAKE_GH_EDIT_OK=1 upload "$tag" "$repo" "$T/notes.md" "$A") 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ] && grep -q -- "^gh release create $tag .*--draft" "$log" &&
		! grep '^gh release create' "$log" | grep -qv -- ' --draft ' && ! grep -q -- '--draft=false' "$log"; then
		ok "upload creates only a draft and does not promote a bad one"
	else
		bad "upload with a bad draft (rc=$rc, log: $(tr '\n' ';' <"$log"))"; printf '%s\n' "$out" | sed 's/^/       /'
	fi
	: >"$log"
	rc=0
	out="$( (PATH="$FPATH" FAKE_GH_VIEW="$T/view.json" upload "$tag" "$repo" "$T/notes.md" "$A") 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ] && [ "$(grep -c . "$log")" -eq 1 ] && grep -q '^gh release create' "$log"; then
		ok "a failed create stops before any read-back or promote"
	else
		bad "failed create (rc=$rc, log: $(tr '\n' ';' <"$log"))"
	fi

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

	unset -f ok bad on_pty no_tty expect_refusal draft_json promote_case
	unset FAKE_TOOL_LOG
	echo
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
VERSION="" STAGE="" CP_BUILD="" LDFLAGS="" IDENTITY="" TEAM_ID="" NOTES="" REPO="k3sm-io/k3sm"
while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION="${2:?--version needs a value}"; shift 2 ;;
	--stage-dir) STAGE="${2:?--stage-dir needs a value}"; shift 2 ;;
	--cp-build) CP_BUILD="${2:?--cp-build needs a value}"; shift 2 ;;
	--ldflags) LDFLAGS="${2:?--ldflags needs a value}"; shift 2 ;;
	--identity) IDENTITY="${2:?--identity needs a value}"; shift 2 ;;
	--team-id) TEAM_ID="${2:?--team-id needs a value}"; shift 2 ;;
	--notes-file) NOTES="${2:?--notes-file needs a value}"; shift 2 ;;
	--repo) REPO="${2:?--repo needs a value}"; shift 2 ;;
	-h | --help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done
for v in VERSION STAGE CP_BUILD LDFLAGS IDENTITY TEAM_ID NOTES; do
	[ -n "${!v}" ] || die "missing a required flag (see --help): $v"
done
valid_version "$VERSION" || die "--version '$VERSION' is not vMAJOR.MINOR.PATCH[-rc.N]"
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || die "--team-id '$TEAM_ID' is not a 10-character Team ID"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo '$REPO' is not owner/name"
[ -f "$NOTES" ] || die "--notes-file $NOTES is not a file"
[ ! -e "$STAGE" ] || die "--stage-dir $STAGE already exists; a release stages into a fresh directory"
STAGE="${STAGE%/}"
ASSETS="$STAGE.assets"
[ ! -e "$ASSETS" ] || die "$ASSETS already exists"

echo "==> 1/6 stage (release)"
"$HERE/stage.sh" "$STAGE" --release --cp-build "$CP_BUILD" --ldflags "$LDFLAGS"
STAGE="$(cd "$STAGE" && pwd)"
ASSETS="$STAGE.assets"

echo "==> 2/6 sign and notarize"
"$HERE/sign.sh" --identity "$IDENTITY" --team-id "$TEAM_ID" "$STAGE"

echo "==> 3/6 rewrite the manifest over the signed bytes"
"$HERE/stage.sh" --rewrite-manifest "$STAGE"

echo "==> 4/6 verify the release signatures"
"$HERE/stage.sh" "$STAGE" --verify-release "$TEAM_ID"
got_version="$("$STAGE/k3sm" version | head -1 | awk '{print $2}')"
[ "$got_version" = "${VERSION#v}" ] ||
	die "the staged k3sm reports version '$got_version', expected '${VERSION#v}'; stamp it through --ldflags"

echo "==> 5/6 package the assets into $ASSETS"
package_assets "$STAGE" "$VERSION" "$ASSETS"

echo "==> 6/6 upload: draft, verify, promote"
upload "$VERSION" "$REPO" "$NOTES" "$ASSETS"
echo "==> released $VERSION on $REPO"
