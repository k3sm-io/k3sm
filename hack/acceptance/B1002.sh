#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Install-root path consumers follow the versioned layout.
#
# The install tree is moving its binaries from flat files under /Library/k3sm
# into versions/<v>/, reached through current and flat compatibility links.
# Every consumer of an installed binary's path must work on both layouts: a
# path a peer reports or a Seatbelt rule matches is compared resolved, and a
# path a running pod captured stays valid across a flip.
#
# --check runs:
#   b1002.1  no unlisted install-root path consumer in the non-test Go of
#            runtimed, darwin-net and k3sm: every hit of the scan matches an
#            entry of testdata/B1002/literal-paths.allow (with a reason), every
#            entry matches a hit, and every hack/ shell file naming the root
#            matches an exclude line
#   b1002.2  each Seatbelt allowance resolves the versioned path: runtimed's
#            TestShadowAllowFollowsVersionedDir, and k3sm's
#            TestPodPathsResolveIntoTheVersionDir (the shadow dir and the DYLD
#            shims the node hands runtimed are the resolved versions/<v>/ paths)
#   b1002.3  the vm helper peer identity check accepts the helper flat, through
#            current and under versions/<v>/, and refuses a path outside
#            versions/ or another name (TestVerifyVMHelperFollowsVersionedLayout,
#            TestVersionedBinary)
#   b1002.4  a running pod's shim paths, captured at pod start, name the version
#            directory and stay valid across a flip while that version is
#            retained as previous (TestPodShimPathSurvivesAFlip)
#
# Unit tests only, under -race: no launchd, no privilege. The sibling modules
# are the ones the k3sm build resolves (go list -m), so a workspace build checks
# the workspace's checkouts.
#
# Usage: hack/acceptance/B1002.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
ALLOW="$HERE/testdata/B1002/literal-paths.allow"

check=0
while [ $# -gt 0 ]; do
	case "$1" in
	--check) check=1; shift ;;
	*) echo "usage: $0 --check" >&2; exit 2 ;;
	esac
done
[ "$check" = 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

# runtest <package> <test>...: every named test must run and pass under -race.
runtest() {
	local pkg="$1"; shift
	local re out t
	re="^($(IFS='|'; echo "$*"))\$"
	if ! out="$(go test -race -count=1 -v -run "$re" "$pkg" 2>&1)"; then
		printf '%s\n' "$out" | grep -E '^(--- FAIL|FAIL|panic|.*_test\.go:[0-9]+:)' | head -40 >&2
		echo no; return
	fi
	for t in "$@"; do
		printf '%s\n' "$out" | grep -q -- "--- PASS: $t " || { echo "    $t did not run in $pkg" >&2; echo no; return; }
	done
	echo ok
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/b1002.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echo "==> install-root path consumers follow the versioned layout"

# ---- b1002.1: the scan ------------------------------------------------------
b1=ok
[ -f "$ALLOW" ] || { echo "    missing $ALLOW" >&2; b1=no; }
RUNTIMED_DIR="$(go list -m -f '{{.Dir}}' k3sm.io/runtimed 2>/dev/null || true)"
DARWINNET_DIR="$(go list -m -f '{{.Dir}}' k3sm.io/darwin-net 2>/dev/null || true)"
for d in "$RUNTIMED_DIR" "$DARWINNET_DIR"; do
	[ -n "$d" ] && [ -d "$d" ] || { echo "    could not locate a sibling module (go list -m said '${d:-<nothing>}')" >&2; b1=no; }
done

# gofiles <dir>: the non-test Go files of a module, relative, outside testdata.
gofiles() {
	if git -C "$1" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		git -C "$1" ls-files -- '*.go'
	else
		( cd "$1" && find . -name '*.go' -type f | sed 's|^\./||' )
	fi | grep -v '_test\.go$' | grep -v '/testdata/' | grep -v '^testdata/' || true
}

PATTERN='"/Library/k3sm(/[^"]*)?"|filepath\.Join\((install\.|cfg\.|c\.)?(Default)?InstallDir,|(Default)?InstallDir \+ "/"'
: > "$tmp/hits"
if [ "$b1" = ok ]; then
	for pair in "runtimed=$RUNTIMED_DIR" "darwin-net=$DARWINNET_DIR" "k3sm=$K3SM_ROOT"; do
		repo="${pair%%=*}"; dir="${pair#*=}"
		gofiles "$dir" > "$tmp/files.$repo"
		[ -s "$tmp/files.$repo" ] || { echo "    no Go files found in $repo ($dir)" >&2; b1=no; continue; }
		( cd "$dir" && tr '\n' '\0' < "$tmp/files.$repo" | xargs -0 grep -nE "$PATTERN" /dev/null || true ) |
			grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' | sed "s|^|$repo:|" >> "$tmp/hits" || true
	done
fi

# The allowlist: allow <repo>:<path> | <needle> | <reason>; exclude <repo>:<glob> | <reason>.
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }
allow_where=(); allow_needle=(); allow_used=()
excl_glob=(); excl_used=()
if [ "$b1" = ok ]; then
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in ''|'#'*) continue ;; esac
		kind="${line%% *}"; rest="${line#* }"
		case "$kind" in
		allow)
			where="$(trim "${rest%%|*}")"; rest="${rest#*|}"
			needle="$(trim "${rest%%|*}")"
			reason=""; [ "$rest" != "${rest#*|}" ] && reason="$(trim "${rest#*|}")"
			if [ -z "$where" ] || [ -z "$needle" ] || [ -z "$reason" ]; then
				echo "    allowlist line without a path, a needle and a reason: $line" >&2; b1=no; continue
			fi
			allow_where+=("$where"); allow_needle+=("$needle"); allow_used+=(0) ;;
		exclude)
			glob="$(trim "${rest%%|*}")"
			reason=""; [ "$rest" != "${rest#*|}" ] && reason="$(trim "${rest#*|}")"
			if [ -z "$glob" ] || [ -z "$reason" ]; then
				echo "    exclude line without a glob and a reason: $line" >&2; b1=no; continue
			fi
			excl_glob+=("$glob"); excl_used+=(0) ;;
		*) echo "    allowlist line of unknown kind: $line" >&2; b1=no ;;
		esac
	done < "$ALLOW"
fi

nhits=0
if [ "$b1" = ok ]; then
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		nhits=$((nhits+1))
		repo="${hit%%:*}"; r="${hit#*:}"; path="${r%%:*}"; r="${r#*:}"; text="${r#*:}"
		matched=no
		for i in "${!allow_where[@]}"; do
			if [ "${allow_where[$i]}" = "$repo:$path" ] && [[ "$text" == *"${allow_needle[$i]}"* ]]; then
				allow_used[$i]=1; matched=yes
			fi
		done
		[ "$matched" = yes ] || { echo "    unlisted install-root path consumer: $hit" >&2; b1=no; }
	done < "$tmp/hits"
	[ "$nhits" -gt 0 ] || { echo "    the scan found nothing; it cannot be checking anything" >&2; b1=no; }
	for i in "${!allow_where[@]}"; do
		[ "${allow_used[$i]}" = 1 ] || { echo "    stale allowlist entry (matches nothing): ${allow_where[$i]} | ${allow_needle[$i]}" >&2; b1=no; }
	done

	# hack/ shell files naming an installed path must sit under an exclude glob.
	while IFS= read -r sh; do
		[ -n "$sh" ] || continue
		matched=no
		for i in "${!excl_glob[@]}"; do
			# shellcheck disable=SC2053 # the glob is the point
			if [[ "k3sm:$sh" == ${excl_glob[$i]} ]]; then excl_used[$i]=1; matched=yes; fi
		done
		[ "$matched" = yes ] || { echo "    hack/ shell file names the install root and is not excluded: $sh" >&2; b1=no; }
	done < <(git ls-files -- 'hack/*.sh' 'hack/**/*.sh' | sort -u | while IFS= read -r f; do grep -q '/Library/k3sm/' "$f" && echo "$f"; done || true)
	for i in "${!excl_glob[@]}"; do
		[ "${excl_used[$i]}" = 1 ] || { echo "    stale exclude (matches no shell file): ${excl_glob[$i]}" >&2; b1=no; }
	done
	echo "    scanned: $nhits hits, ${#allow_where[@]} allow entries, ${#excl_glob[@]} excludes"
fi
ladder "$b1" "b1002.1  no unlisted install-root path consumer in runtimed, darwin-net, k3sm"

# ---- b1002.2: Seatbelt allowances resolve the versioned path -----------------
b2=ok
if [ -z "$RUNTIMED_DIR" ] || ! grep -qs 'func TestShadowAllowFollowsVersionedDir(' "$RUNTIMED_DIR"/pkg/sandbox/*_test.go; then
	echo "    runtimed's TestShadowAllowFollowsVersionedDir is absent from ${RUNTIMED_DIR:-<runtimed>}/pkg/sandbox" >&2
	b2=no
else
	[ "$(runtest k3sm.io/runtimed/pkg/sandbox TestShadowAllowFollowsVersionedDir)" = ok ] || b2=no
fi
[ "$(runtest ./cmd/k3sm/ TestPodPathsResolveIntoTheVersionDir)" = ok ] || b2=no
ladder "$b2" "b1002.2  each Seatbelt allowance resolves the versioned path"

# ---- b1002.3: peer identity -------------------------------------------------
b3=ok
[ "$(runtest ./pkg/install/ TestVerifyVMHelperFollowsVersionedLayout)" = ok ] || b3=no
[ "$(runtest ./pkg/updater/layout/ TestVersionedBinary)" = ok ] || b3=no
ladder "$b3" "b1002.3  vm helper identity: accepted flat, through current, under versions/; refused elsewhere"

# ---- b1002.4: a running pod's mapped shim survives a flip --------------------
ladder "$(runtest ./pkg/install/ TestPodShimPathSurvivesAFlip)" "b1002.4  a running pod's captured shim paths name the version dir and survive a flip"

echo "----------------------------------------"
echo "install-root path consumers: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
