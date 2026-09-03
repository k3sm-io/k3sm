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
# DORMANCY (2026-09-03). Every workflow in these repos is currently DISABLED by
# operator directive: the files are retained but each carries the two-line
# `WORKFLOWS DISABLED 2026-07-20 — CI is intentionally inactive for this
# repository. Every line below is commented out` header with the whole body
# commented out. Against such a file the content assertions below are not merely
# red, they are UNSATISFIABLE — and worse, DISHONEST in both directions: the
# positive ones ("runs hack/ci.sh") fail for a file that would satisfy them the
# moment it is uncommented, while every negative one ("no self-hosted runner",
# "all uses: SHA-pinned") passes VACUOUSLY over an empty config, which is the
# failure mode this gate exists to prevent.
#
# So a workflow proven dormant is RECORDED, not run: its content rungs are
# reported DORMANT and neither counted as passed nor as failed. This is scoped as
# narrowly as it can be:
#   * The skip is conditioned on the dormancy predicate itself, evaluated per
#     file at run time — never on a hardcoded list, a date, or an env var. A
#     workflow that comes back reddens this gate on the NEXT run with no edit
#     here, because it simply stops being dormant.
#   * It covers ONLY the rungs that read the workflow. The per-repo CGO posture
#     is read from that repo's hack/ci.sh and is asserted for real either way, so
#     an all-dormant run still makes live claims and cannot pass vacuously.
#   * A file that is PARTIALLY uncommented is NOT dormant, and is asserted in
#     full — the interesting case is exactly the one that must not be skipped.
# The re-enable check therefore rides the re-enable itself, which is where it
# belongs: uncommenting a workflow is what re-arms these assertions.
#
# Exit 0 iff every manifest assertion that RAN passes. Match hack/acceptance/m*.sh
# conventions.
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

PASS=0; FAIL=0; DORMANT=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
# record() is neither a pass nor a fail: it names a claim this run did not test,
# and why. Counted separately so the summary can never present a dormant run as a
# proven one.
record() { echo "DORMANT  $1"; DORMANT=$((DORMANT+1)); }

# is_dormant <file> — true iff the file has NO line that is neither blank nor a
# comment. That is the whole predicate: a file whose every meaningful line is
# commented out cannot configure anything, so there is no configuration to assert
# against. Deliberately strict — a file carrying even one live line (a stray
# `---`, a half-finished re-enable) is NOT dormant and gets the full treatment.
is_dormant() {
	! grep -qEv '^[[:space:]]*(#|$)' "$1"
}

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

	# (a) the workflow exists — true and provable whether or not it is dormant.
	if [ -f "$yml" ]; then
		ladder ok "$repo: .github/workflows/ci.yml exists"
	else
		ladder no "$repo: .github/workflows/ci.yml exists"
		continue   # nothing more to assert for a missing workflow
	fi

	# Dormant? Then the content rungs (b)-(h) and the repo-specific extras have no
	# configuration to read: record them and move on. The CGO posture rung is NOT
	# in that set — it reads hack/ci.sh, not the workflow — so it still runs below.
	if is_dormant "$yml"; then
		record "$repo: workflow content NOT ASSERTED — CI is intentionally inactive for this repository (every line of ci.yml is commented out). These rungs re-arm automatically when the workflow is uncommented."
		# (e) CGO posture — dormancy-independent (read from THAT repo's hack/ci.sh).
		want="$(expected_cgo "$repo")"
		if [ -f "$cish" ]; then
			got="$(grep -oE '^[[:space:]]*CGO=[0-9]' "$cish" | head -n1 | grep -oE '[0-9]$' || true)"
			if [ -n "$got" ] && [ "$got" = "$want" ]; then
				ladder ok "$repo: hack/ci.sh CGO=$got (expected $want)"
			else
				ladder no "$repo: hack/ci.sh CGO='${got:-unset}' (expected $want)"
			fi
		else
			ladder no "$repo: hack/ci.sh present (to read CGO posture)"
		fi
		continue
	fi

	# Live workflow: assert it in full, and hand it to actionlint. A dormant file
	# is deliberately NOT collected — linting a fully-commented file lints nothing.
	YMLS="$YMLS $yml"

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
if [ "$DORMANT" -ne 0 ]; then
	echo "B59: $PASS passed, $FAIL failed, $DORMANT recorded-not-run"
	echo "  NOT PROVEN HERE: the workflow CONTENT posture (runs hack/ci.sh, the"
	echo "  CGO_ENABLED=1 -race step, macos-15, least-privilege token, SHA-pinned"
	echo "  actions, sibling checkouts) for $DORMANT repo(s) whose ci.yml is fully"
	echo "  commented out. Nothing about those repos' CI posture is claimed by a"
	echo "  green B59 today; the assertions re-arm on the run after a workflow is"
	echo "  uncommented, which is when they can mean anything again."
else
	echo "B59: $PASS passed, $FAIL failed"
fi
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B59 GREEN ================"
