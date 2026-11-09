# shellcheck shell=bash
# shellcheck disable=SC2154  # sourced: gate_repo, pkg_file and the rest are the caller's
# hack/lib/affected-mode.sh -- the gate's --packages mode: the strict k3sm-affected/v1
# reader and the mode resolution it feeds. The k3sm repositories carry this file
# byte-identical; change it in all of them together. Everything specific to a repository
# is a variable its hack/ci.sh sets before sourcing it.
#
# Sourced from hack/ci.sh, never executed, with the working directory at the repo root.
# It defines read_packages and resolve_gate_mode and runs nothing on its own.
#
# The caller sets:
#   gate_repo      the repository name in log lines and in @full and @check lines
#   gate_lang      go (the default when unset) or swift
#   gate_module    the Go module path; a list narrows the gate to this module's packages.
#                  Empty for a Swift gate.
#   pkg_file_set   1 when --packages was given, else 0
#   pkg_file       the --packages file
#   diff_base      the --base sha, or empty for the merge base with origin/main
#   dry_run        1 to print the plan and exit, else 0
#   ci_tmp         a scratch directory the caller removes
#
# resolve_gate_mode sets mode, mode_reason, vet_set and test_set.
#
# A Swift gate (gate_lang=swift) has no selector to narrow it: no k3sm-affected/v1 line
# names a Swift target. It validates the list all the same and runs its full suite for
# every list, with one exception it shares with a Go gate whose list names none of its
# packages: when the diff holds only doc files, vet and test are skipped. vet_set and
# test_set are then empty; otherwise they stay ./..., which a Swift gate reads as its
# whole `swift test`. Any other gate_lang answers full.

# read_packages <file>: the strict k3sm-affected/v1 reader. Line 1 is exactly
# k3sm-affected/v1; then sorted, unique import paths; then `@full <repo> <reason>`
# lines; then `@check <repo> <name> [<arg>]` lines with <name> from the closed set;
# the last line is exactly @end, followed by a final newline. No blank lines, no
# comments. Fields are separated by exactly one space, as the writer emits them,
# and the file is UTF-8 with no NUL byte. Any deviation sets pf_reason and returns 1
# (the caller runs full).
# On success: pf_pkgs (every package line), pf_full (the @full reason for $gate_repo, or
# empty), pf_checks (the @check lines for $gate_repo).
pf_pkgs=() pf_checks=() pf_full="" pf_reason=""
read_packages() {
	local f="$1" line n=0 phase=0 prev="" seen_end=0 name rest LC_ALL=C
	local -a w
	pf_pkgs=() pf_checks=() pf_full="" pf_reason=""
	[ -e "$f" ] || { pf_reason="$f does not exist"; return 1; }
	[ -f "$f" ] && [ -r "$f" ] || { pf_reason="$f is not a readable file"; return 1; }
	if [ ! -s "$f" ] || [ "$(tail -c 1 "$f" | od -An -c | tr -d ' ')" != '\n' ]; then
		pf_reason="$f is empty or does not end with a newline"; return 1
	fi
	# read drops a NUL byte and the line regexes never see an invalid byte in a
	# reason, so both are refused here, as the selector's own reader refuses them.
	[ "$(tr -d '\000' < "$f" | wc -c)" -eq "$(wc -c < "$f")" ] || { pf_reason="$f holds a NUL byte"; return 1; }
	iconv -f UTF-8 -t UTF-8 "$f" >/dev/null 2>&1 || { pf_reason="$f is not UTF-8"; return 1; }
	while IFS= read -r line; do
		n=$((n + 1))
		[ "$seen_end" = 0 ] || { pf_reason="line $n: text after @end"; return 1; }
		if [ "$n" = 1 ]; then
			[ "$line" = "k3sm-affected/v1" ] || { pf_reason="line 1 is not k3sm-affected/v1"; return 1; }
			continue
		fi
		case "$line" in
			@end) seen_end=1 ;;
			"@full "*)
				[ "$phase" -le 1 ] || { pf_reason="line $n: @full after @check"; return 1; }
				phase=1
				# @full <repo> <reason>: the repo ends at the next single space, and the
				# reason is the rest, which must hold a non-space character.
				rest="${line#@full }" name="${rest%% *}"
				[ "$name" != "$rest" ] && [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] && [[ "${rest#* }" =~ [^[:space:]] ]] \
					|| { pf_reason="line $n: bad @full"; return 1; }
				if [ "$name" = "$gate_repo" ]; then pf_full="${rest#* }"; fi
				;;
			"@check "*)
				phase=2
				# @check <repo> <name> [<arg>]: split on every single space, keeping empty
				# fields, so a doubled space or a tab is refused, not collapsed.
				rest="${line#@check }" w=()
				while :; do
					case "$rest" in
						*" "*) w+=("${rest%% *}"); rest="${rest#* }" ;;
						*) w+=("$rest"); break ;;
					esac
				done
				{ [ ${#w[@]} = 2 ] || [ ${#w[@]} = 3 ]; } && [[ "${w[0]}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { pf_reason="line $n: bad @check"; return 1; }
				name="${w[1]}"
				case "$name" in buf|verify-deps|govulncheck|tidy|gofmt|boilerplate|vet-tags|script) ;; *) pf_reason="line $n: unknown @check $name"; return 1 ;; esac
				if [ "${w[0]}" = "$gate_repo" ]; then pf_checks+=("${line#"@check $gate_repo "}"); fi
				;;
			*)
				[[ "$line" =~ ^[A-Za-z0-9][A-Za-z0-9._~/-]*$ ]] || { pf_reason="line $n: unrecognised line"; return 1; }
				[ "$phase" = 0 ] || { pf_reason="line $n: package after a keyed line"; return 1; }
				if [ -n "$prev" ] && ! [[ "$prev" < "$line" ]]; then pf_reason="line $n: packages are not sorted and unique"; return 1; fi
				prev="$line"
				pf_pkgs+=("$line")
				;;
		esac
	done < "$f"
	[ "$seen_end" = 1 ] || { pf_reason="missing @end (truncated?)"; return 1; }
	return 0
}

# resolve_gate_mode: the mode and the go vet and go test package sets. A --dry-run prints
# the plan and exits 0 here; a list the diff contradicts exits 1 here.
resolve_gate_mode() {
	# Mode resolution. vet_set and test_set default to the full gate; only an explicit
	# mode flag with a valid list narrows them, and every doubt answers full.
	mode=full mode_reason="no mode flag (the default)"
	vet_set=(./...) test_set=(./...)
	if [ "$pkg_file_set" = 1 ]; then
		if [ "${gate_lang:-go}" != go ] && [ "${gate_lang:-go}" != swift ]; then
			mode_reason="--packages: unknown gate_lang '$gate_lang'; full gate"
		elif ! read_packages "$pkg_file"; then
			mode_reason="--packages: $pf_reason; full gate"
		elif [ -n "$pf_full" ]; then
			mode_reason="--packages: @full $gate_repo $pf_full"
		else
			own=()
			if [ "${gate_lang:-go}" = go ]; then
				for p in ${pf_pkgs[@]+"${pf_pkgs[@]}"}; do
					case "$p" in "$gate_module"|"$gate_module"/*) own+=("$p") ;; esac
				done
			fi
			if [ "${gate_lang:-go}" = swift ]; then
				# No package line can name a Swift target, so the list never narrows the
				# suite; only a doc-only diff skips it, as for a Go gate's empty list.
				base="$diff_base"
				[ -n "$base" ] || base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
				if [ -z "$base" ] || ! git rev-parse -q --verify "$base^{commit}" >/dev/null 2>&1; then
					mode_reason="--packages: no Swift selector and the diff base does not resolve; full gate"
				# --no-renames lists both sides of a rename, so a Swift file moved into docs/
				# still counts as changed.
				elif changed="$( { git diff --no-renames --name-only "$base" -- && git ls-files --others --exclude-standard; } 2>"$ci_tmp/diff.err")"; then
					# Markdown under Sources/ or Tests/, or anything in a .docc catalog, can be a
					# SwiftPM resource, fixture or documentation catalog the build reads: not a doc.
					unmapped="$(printf '%s\n' "$changed" | awk '/^$/ { next } /^(Sources|Tests)\// || /\.docc\// { print; next } /\.md$/ || /^docs\// || /^(LICENSE|NOTICE|DCO)$/ { next } { print }')"
					if [ -n "$unmapped" ]; then
						mode_reason="--packages: no Swift selector; full gate (the diff against $base changes $(printf '%s\n' "$unmapped" | head -1))"
					else
						mode=packages mode_reason="--packages: no Swift selector and only doc files changed against $base; vet and test skipped"
						vet_set=() test_set=()
					fi
				else
					mode_reason="--packages: git diff against $base failed; full gate"
				fi
			elif [ ${#own[@]} -gt 0 ]; then
				mode=packages mode_reason="--packages: ${#own[@]} $gate_module package(s) from $pkg_file"
				vet_set=("${own[@]}") test_set=("${own[@]}")
			else
				# An empty selection is legitimate only when the change holds no Go file.
				base="$diff_base"
				[ -n "$base" ] || base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
				if [ -z "$base" ] || ! git rev-parse -q --verify "$base^{commit}" >/dev/null 2>&1; then
					mode_reason="--packages: no $gate_module package listed and the diff base does not resolve; full gate"
				elif changed="$( { git diff --name-only "$base" -- && git ls-files --others --exclude-standard; } 2>"$ci_tmp/diff.err")"; then
					if printf '%s\n' "$changed" | grep -q '\.go$'; then
						echo "FAIL: [$gate_repo] --packages lists no $gate_module package, but the diff against $base holds Go changes:" >&2
						printf '%s\n' "$changed" | grep '\.go$' | sed 's/^/    /' >&2
						echo "    the selector cannot legitimately answer that; refusing a silent green" >&2
						exit 1
					fi
					# Only a doc file is known to reach no package. Any other change (a cgo or
					# assembly source, an embed asset, testdata, go.mod, go.sum) can, and an
					# empty list cannot say which, so it runs the full gate.
					unmapped="$(printf '%s\n' "$changed" | grep -v -e '^$' -e '\.md$' -e '^docs/' -e '^LICENSE$' -e '^NOTICE$' -e '^DCO$' || true)"
					if [ -n "$unmapped" ]; then
						mode_reason="--packages: no $gate_module package listed and the diff against $base changes a non-doc file the gate cannot map ($(printf '%s\n' "$unmapped" | head -1)); full gate"
					else
						mode=packages mode_reason="--packages: no $gate_module package listed and only doc files changed against $base; vet and test skipped"
						vet_set=() test_set=()
					fi
				else
					mode_reason="--packages: git diff against $base failed; full gate"
				fi
			fi
			for c in ${pf_checks[@]+"${pf_checks[@]}"}; do echo "==> [$gate_repo] keyed check owed: $c (its stage runs in every mode)"; done
		fi
	fi
	if [ "$pkg_file_set" = 1 ]; then
		echo "==> [$gate_repo] gate mode: $mode ($mode_reason)"
	fi
	if [ "$dry_run" = 1 ]; then
		echo "mode: $mode"
		echo "reason: $mode_reason"
		echo "vet: ${vet_set[*]+${vet_set[*]}}"
		echo "test: ${test_set[*]+${test_set[*]}}"
		# A deliberate success: tell the caller's EXIT handler (hack/ci.sh ci_done) so it is not read as a crash.
		# shellcheck disable=SC2034  # read by the caller's EXIT handler
		ci_done=1
		exit 0
	fi
}
