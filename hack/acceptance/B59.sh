#!/usr/bin/env bash
# k3sm B59 acceptance gate — the cross-repo public-CI manifest proof.
#
# B59 adds an INTERIM M7-bootstrap per-repo GitHub Actions CI workflow
# (.github/workflows/ci.yml) to each of the four k3sm code repos. This gate is the
# runnable red->green proof that every repo's workflow exists and holds the required
# security + build posture:
#
#   * runs the repo's hack/ci.sh gate,
#   * has a `go test -race` step,
#   * runs on the GitHub-hosted ephemeral `macos-15` runner (never self-hosted,
#     never the pull_request_target trigger),
#   * carries the correct per-repo CGO posture (read from that repo's hack/ci.sh
#     `CGO=` line — single-sourced, never asserted off the yml),
#   * runtimed's workflow keeps its `spicanary` step; apis's installs `buf`.
#
# The assertion is tool-independent (grep + file existence), so it is meaningful
# without a live runner. When `actionlint` is present it additionally lints every
# workflow; when it is absent the lint is deferred (never faked green, never skips
# the manifest assertions).
#
# Exit 0 iff every manifest assertion passes. Match hack/acceptance/m*.sh conventions.
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
echo "==> B59 cross-repo public-CI manifest gate (workspace: $WS)"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

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

YMLS=""   # collected for actionlint

for repo in $REPOS; do
	yml="$WS/$repo/.github/workflows/ci.yml"
	cish="$WS/$repo/hack/ci.sh"

	# (a) the workflow exists
	if [ -f "$yml" ]; then
		ladder ok "$repo: .github/workflows/ci.yml exists"
		YMLS="$YMLS $yml"
	else
		ladder no "$repo: .github/workflows/ci.yml exists"
		continue   # nothing more to assert for a missing workflow
	fi

	# Assert against the workflow's actual config, not its prose: strip YAML
	# comments (# to end of line) so a word like "self-hosted" or
	# "pull_request_target" mentioned in an explanatory comment can't false-trip
	# a negative assertion. Workflow values carry no literal '#', so this is safe.
	cfg="$(sed 's/#.*//' "$yml")"

	# (b) invokes hack/ci.sh
	if printf '%s\n' "$cfg" | grep -q 'hack/ci.sh'; then
		ladder ok "$repo: workflow runs hack/ci.sh"
	else
		ladder no "$repo: workflow runs hack/ci.sh"
	fi

	# (c) has a -race step that carries CGO_ENABLED=1 (the race detector needs cgo,
	# even for the CGO=0 repos apis/darwin-net — a race step without cgo fails in real
	# CI but would pass a bare 'go test -race' grep).
	if printf '%s\n' "$cfg" | grep -qE 'CGO_ENABLED=1[[:space:]]+go test -race'; then
		ladder ok "$repo: workflow has a 'CGO_ENABLED=1 go test -race' step"
	else
		ladder no "$repo: workflow has a 'CGO_ENABLED=1 go test -race' step"
	fi

	# (d) runs on macos-15, not self-hosted, not pull_request_target
	if printf '%s\n' "$cfg" | grep -q 'runs-on: macos-15'; then
		ladder ok "$repo: runs-on macos-15 (GitHub-hosted)"
	else
		ladder no "$repo: runs-on macos-15 (GitHub-hosted)"
	fi
	if printf '%s\n' "$cfg" | grep -q 'self-hosted'; then
		ladder no "$repo: no self-hosted runner"
	else
		ladder ok "$repo: no self-hosted runner"
	fi
	if printf '%s\n' "$cfg" | grep -q 'pull_request_target'; then
		ladder no "$repo: no pull_request_target trigger"
	else
		ladder ok "$repo: no pull_request_target trigger"
	fi

	# (f) least-privilege token: contents: read present, and no write grant.
	if printf '%s\n' "$cfg" | grep -qE 'contents:[[:space:]]*read'; then
		ladder ok "$repo: permissions contents: read"
	else
		ladder no "$repo: permissions contents: read"
	fi
	if printf '%s\n' "$cfg" | grep -qE 'contents:[[:space:]]*write|write-all'; then
		ladder no "$repo: no write token grant"
	else
		ladder ok "$repo: no write token grant"
	fi

	# (g) every 'uses:' third-party action pinned to a full 40-hex commit SHA (no
	# floating tag) — a supply-chain regression guard the interim gate must enforce.
	unpinned="$(printf '%s\n' "$cfg" | grep -E '(^|[[:space:]])uses:' | grep -vE '@[0-9a-f]{40}([[:space:]]|$)' || true)"
	if [ -z "$unpinned" ]; then
		ladder ok "$repo: all 'uses:' actions SHA-pinned"
	else
		ladder no "$repo: unpinned action(s): $(printf '%s' "$unpinned" | tr -s ' \t' ' ')"
	fi

	# (h) sibling-checkout set matches this repo's go.mod relative replaces — the
	# layout that makes the ../<repo> replaces resolve in a lone CI checkout.
	gomod="$WS/$repo/go.mod"
	if [ -f "$gomod" ]; then
		miss=""
		for sib in apis runtimed darwin-net; do
			if grep -qE "replace[[:space:]]+k3sm\.io/$sib[[:space:]]*=>[[:space:]]*\.\./$sib" "$gomod"; then
				printf '%s\n' "$cfg" | grep -qE "repository:[[:space:]]*k3sm-io/$sib" || miss="$miss $sib"
			fi
		done
		if [ -z "$miss" ]; then
			ladder ok "$repo: sibling checkouts match go.mod replaces"
		else
			ladder no "$repo: missing sibling checkout(s):$miss"
		fi
	fi

	# (e) CGO posture — read from THAT repo's hack/ci.sh CGO= line (single source).
	want="$(expected_cgo "$repo")"
	if [ -f "$cish" ]; then
		# grep the `CGO=<n>` assignment (tolerate surrounding whitespace/comment).
		got="$(grep -oE '^[[:space:]]*CGO=[0-9]' "$cish" | head -n1 | grep -oE '[0-9]$' || true)"
		if [ -n "$got" ] && [ "$got" = "$want" ]; then
			ladder ok "$repo: hack/ci.sh CGO=$got (expected $want)"
		else
			ladder no "$repo: hack/ci.sh CGO='${got:-unset}' (expected $want)"
		fi
	else
		ladder no "$repo: hack/ci.sh present (to read CGO posture)"
	fi

	# repo-specific extra steps
	case "$repo" in
		runtimed)
			if printf '%s\n' "$cfg" | grep -q 'spicanary'; then
				ladder ok "$repo: workflow has the spicanary step"
			else
				ladder no "$repo: workflow has the spicanary step"
			fi
			;;
		apis)
			if printf '%s\n' "$cfg" | grep -q 'buf'; then
				ladder ok "$repo: workflow installs buf"
			else
				ladder no "$repo: workflow installs buf"
			fi
			# buf/protoc-gen pins must stay in lockstep with hack/gen.sh (the canonical
			# source) — an interim guard against the two drifting (a gen.sh bump not
			# mirrored into ci.yml installs a different buf than generated the code).
			gen="$WS/apis/hack/gen.sh"
			if [ -f "$gen" ]; then
				lockstep=ok
				for var in BUF_VERSION PROTOC_GEN_GO_VERSION PROTOC_GEN_GO_GRPC_VERSION; do
					ver="$(grep -oE "^${var}=v[0-9.]+" "$gen" | head -n1 | cut -d= -f2 || true)"
					[ -n "$ver" ] && { printf '%s\n' "$cfg" | grep -q "@$ver" || lockstep=no; }
				done
				if [ "$lockstep" = ok ]; then
					ladder ok "$repo: buf/protoc pins in lockstep with hack/gen.sh"
				else
					ladder no "$repo: buf/protoc pins DIVERGE from hack/gen.sh"
				fi
			fi
			;;
	esac
done

# --- actionlint (optional; deferred if absent, never faked green) ----------
if command -v actionlint >/dev/null 2>&1; then
	lint_fail=0
	for yml in $YMLS; do
		if ! actionlint "$yml"; then
			lint_fail=1
		fi
	done
	if [ "$lint_fail" -eq 0 ]; then
		ladder ok "actionlint clean over all present ci.yml"
	else
		ladder no "actionlint reported errors"
	fi
else
	echo "NOTE  actionlint not installed — lint deferred to CI (manifest assertions still enforced)"
fi

echo "----------------------------------------"
echo "B59: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B59 GREEN ================"
