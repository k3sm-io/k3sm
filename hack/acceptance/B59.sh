#!/usr/bin/env bash
# k3sm no-hosted-CI acceptance gate — the cross-repo proof that no Go repo carries a
# GitHub Actions workflow, and that each repo's own gate carries its CGO posture.
#
# There is no CI on GitHub: no GitHub Actions workflows, ever, and Actions stays
# disabled; every gate runs locally in k3sm pods, through Yureisha CI (the yureisha/ci
# commit status) or the repo's own hack/ci.sh. This gate once asserted the content of a
# per-repo ci.yml; those files are deleted, so it now proves their absence:
#
#   * no file exists under <repo>/.github/workflows/ in apis, runtimed, darwin-net or
#     k3sm: of any name, commented out or not, dotfiles, nested files and symlinks
#     included (the predicate is "the directory holds nothing");
#   * each repo's hack/ci.sh exists and carries the expected CGO posture (read from its
#     `CGO=` line, single-sourced there);
#   * each repo's hack/ci.sh carries the DCO sign-off stage that replaced the PR check.
#
# A red-path self-check runs first, so a predicate edit that stopped detecting a file
# reds here instead of passing vacuously.
#
# Exit 0 iff every assertion passes. Matches hack/acceptance/m*.sh conventions.
#
# Usage: hack/acceptance/B59.sh  (runnable from anywhere; discovers the workspace root)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# --- Discover the workspace root robustly ----------------------------------
# Walk up from the script dir until we find a dir that contains all four repos
# (apis/ runtimed/ darwin-net/ k3sm/) or a go.work. Do NOT hardcode `../`.
find_workspace_root() {
	local d="$1"
	while [ "$d" != "/" ]; do
		if [ -f "$d/go.work" ] || { [ -d "$d/apis" ] && [ -d "$d/runtimed" ] && [ -d "$d/darwin-net" ] && [ -d "$d/k3sm" ]; }; then
			printf '%s\n' "$d"
			return 0
		fi
		d="$(dirname "$d")"
	done
	return 1
}

if ! WS="$(find_workspace_root "$HERE")"; then
	echo "FAIL  could not locate the k3sm workspace root (a dir with apis/ runtimed/ darwin-net/ k3sm/ or go.work) walking up from $HERE" >&2
	exit 1
fi
echo "==> cross-repo no-hosted-CI gate (workspace: $WS)"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

# workflows_present <dir>: print each entry under a workflows dir; exit 0 iff any exist.
# A workflows path that is a plain file counts as present too.
workflows_present() {
	[ -e "$1" ] || [ -L "$1" ] || return 1
	[ -d "$1" ] || { printf '%s\n' "$1"; return 0; }
	find "$1" -mindepth 1 \( -type f -o -type l \) | grep .
}

# --- red-path self-check -----------------------------------------------------
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/a/.github/workflows" && printf '# every line commented\n' > "$t/a/.github/workflows/.ci.yml"
mkdir -p "$t/b/.github/workflows/sub" && : > "$t/b/.github/workflows/sub/x.yaml"
mkdir -p "$t/c/.github/workflows"
mkdir -p "$t/d/.github" && : > "$t/d/.github/dependabot.yml"
if workflows_present "$t/a/.github/workflows" >/dev/null \
	&& workflows_present "$t/b/.github/workflows" >/dev/null \
	&& ! workflows_present "$t/c/.github/workflows" >/dev/null \
	&& ! workflows_present "$t/d/.github/workflows" >/dev/null; then
	ladder ok "self-check: a commented dotfile and a nested file are red; an empty dir and dependabot.yml pass"
else
	ladder no "self-check: the absence predicate no longer separates present from absent"
fi

REPOS="apis runtimed darwin-net k3sm"

# expected CGO posture per repo (documented in GO-STANDARDS.md; single-sourced here
# only as the *expected* value — the actual value is read from each repo's ci.sh).
expected_cgo() {
	case "$1" in
		apis)        echo 0 ;;
		darwin-net)  echo 0 ;;
		runtimed)    echo 1 ;;
		k3sm)        echo 1 ;;
		*)           echo "?" ;;
	esac
}

for repo in $REPOS; do
	wf="$WS/$repo/.github/workflows"
	cish="$WS/$repo/hack/ci.sh"

	if found="$(workflows_present "$wf")"; then
		ladder no "$repo: no workflow files (found: $(printf '%s' "$found" | tr '\n' ' '))"
	else
		ladder ok "$repo: no workflow files under .github/workflows/"
	fi

	if [ ! -f "$cish" ]; then
		ladder no "$repo: hack/ci.sh present"
		continue
	fi
	want="$(expected_cgo "$repo")"
	got="$(grep -oE '^[[:space:]]*CGO=[0-9]' "$cish" | sed -n 1p | grep -oE '[0-9]$' || true)"
	if [ -n "$got" ] && [ "$got" = "$want" ]; then
		ladder ok "$repo: hack/ci.sh CGO=$got (expected $want)"
	else
		ladder no "$repo: hack/ci.sh CGO='${got:-unset}' (expected $want)"
	fi
	if grep -q 'DCO sign-off' "$cish" && grep -qF 'grep -qiF' "$cish"; then
		ladder ok "$repo: hack/ci.sh carries the DCO sign-off stage (fixed-string email match)"
	else
		ladder no "$repo: hack/ci.sh carries the DCO sign-off stage (fixed-string email match)"
	fi
done

echo "----------------------------------------"
echo "no-hosted-CI: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ no-hosted-CI GREEN ================"
