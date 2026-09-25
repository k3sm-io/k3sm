#!/usr/bin/env bash
#
# k3sm B375 acceptance gate — the runnable proof that docs/PHASES.md's retroactive
# datavol record is TRUTHFUL, not merely present.
#
# The defect this documents against: pkg/datavol (the `k3sm datavol mount|status|delete`
# subcommands, the `k3sm install --data-volume` path, and the `k3sm status` datavol row
# — ~2,600 LOC across three shipped, reviewed PRs) had NO docs/PHASES.md entry at all. A
# reader of the ledger had no way to learn the feature existed, what it does, which
# commits shipped it, what its 23 tests actually prove, or that every one of those tests
# is unit-tier only.
#
# THREE RUNGS, each strictly stronger than the last:
#
#   b375.1  the record section exists and names the three subcommands (a heading with no
#           content would pass a naive grep for the section title alone).
#
#   b375.2  every `TestXxx` name the section CITES as evidence is extracted from the
#           section text itself (never hard-coded here) and checked against the real
#           source: a `func <Name>(` in a datavol-adjacent _test.go. A citation that names
#           a renamed, deleted, or never-existed test FAILS this rung.
#
#   b375.3  every cited name that rung 2 located is then RUN LIVE, grouped by the package
#           it lives in (`go test -run '^(Name1|Name2|...)$'` per package), and the rung
#           fails on any red or on a zero-match filter (a renamed test reading as a false
#           PASS).
#
# CI TIER ONLY — no rig, no cluster, no root. This gate proves the LEDGER's honesty; it
# does not re-prove the feature (that is what the 23 tests it runs already do, and the
# record says plainly they are unit-tier only — see the "Method, honestly" paragraph the
# section carries).
#
# RED BEFORE: on the unmodified docs/PHASES.md there is no "## Retroactive record" section
# at all, so b375.1 fails immediately and the ladder halts before b375.2/b375.3 ever run.
#
# Usage:  hack/acceptance/B375.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B375.sh"
DOC="$K3SM_ROOT/docs/PHASES.md"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B375 acceptance (docs/PHASES.md: the retroactive datavol record is truthful)"

# ---- b375.0 — the gate parses and its source exists -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$DOC" ] || b0=no
[ -d "$K3SM_ROOT/pkg/datavol" ] || b0=no
ladder "$b0" "b375.0  gate parses (bash -n) + docs/PHASES.md and pkg/datavol present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B375: the gate or its source is missing/unparseable — nothing else can run" >&2
	echo "B375: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# The four package roots the record's cited tests may live in.
SEARCH_DIRS=("$K3SM_ROOT/pkg/datavol" "$K3SM_ROOT/cmd/k3sm" "$K3SM_ROOT/pkg/install" "$K3SM_ROOT/pkg/status")

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
SECTION_FILE="$WORKDIR/section.md"
CITED_FILE="$WORKDIR/cited.txt"
PAIRS_FILE="$WORKDIR/pairs.txt"

# ---- b375.1 — the record section exists and names the three subcommands ----
# Bounded from the section's own heading to the next top-level "## " heading (or EOF), so
# a later, unrelated section can never leak into the citation/test extraction below.
awk '
	/^## Retroactive record/ { flag=1 }
	flag && /^## / && !/^## Retroactive record/ { exit }
	flag { print }
' "$DOC" > "$SECTION_FILE"

b1=ok
[ -s "$SECTION_FILE" ] || b1=no
if [ -s "$SECTION_FILE" ]; then
	grep -qi 'retroactive' "$SECTION_FILE" || b1=no
	grep -qi 'no forward\|not a forward-planned\|no plan document\|no milestone number' "$SECTION_FILE" || b1=no
	grep -q 'datavol mount' "$SECTION_FILE" || b1=no
	grep -q 'datavol status' "$SECTION_FILE" || b1=no
	grep -q 'datavol delete' "$SECTION_FILE" || b1=no
	grep -qi 'unit-tier' "$SECTION_FILE" || b1=no
	grep -qi 'storage.md' "$SECTION_FILE" || b1=no
fi
ladder "$b1" "b375.1  the retroactive record section exists, names datavol mount/status/delete, and states unit-tier + the storage.md cross-link"
if [ "$b1" != ok ]; then
	echo "----------------------------------------"
	echo "B375: the record section is missing or incomplete — nothing else can be checked" >&2
	echo "B375: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b375.2 — every cited TestXxx name exists as `func Name(` in real source -----------
# Names are extracted from the SECTION TEXT ITSELF, never hard-coded here, so a future edit
# that adds, removes or renames a citation is checked against whatever it actually says.
grep -oE '`Test[A-Za-z0-9_]+`' "$SECTION_FILE" | tr -d '`' | sort -u > "$CITED_FILE"

CITED_COUNT=$(wc -l < "$CITED_FILE" | tr -d ' ')
b2=ok
if [ "$CITED_COUNT" -eq 0 ]; then
	b2=no
	echo "  the section cites no \`TestXxx\` name at all"
fi

: > "$PAIRS_FILE"
while IFS= read -r name; do
	[ -n "$name" ] || continue
	file="$(grep -rlE "^func ${name}\(" --include='*_test.go' "${SEARCH_DIRS[@]}" 2>/dev/null | head -1 || true)"
	if [ -z "$file" ]; then
		b2=no
		echo "  cited test not found in source: $name"
		continue
	fi
	pkgdir="$(dirname "$file")"
	pkgrel="./${pkgdir#"$K3SM_ROOT"/}"
	echo "${name} ${pkgrel}" >> "$PAIRS_FILE"
done < "$CITED_FILE"
ladder "$b2" "b375.2  every cited test name ($CITED_COUNT) exists as \`func Name(\` in a datavol-adjacent _test.go"
if [ "$b2" != ok ]; then
	echo "----------------------------------------"
	echo "B375: at least one cited test does not exist in source — the record is not truthful" >&2
	echo "B375: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b375.3 — every cited, located test actually passes, run live ----------------------
# Grouped per package: one `go test -run '^(Name1|Name2|...)$'` per distinct package the
# citations resolved to in rung 2, so each named test is exercised by its own real `go test`
# rather than trusted on the strength of grep alone.
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

b3=ok
cut -d' ' -f2 "$PAIRS_FILE" | sort -u > "$WORKDIR/pkgs.txt"
while IFS= read -r pkgrel; do
	[ -n "$pkgrel" ] || continue
	names="$(awk -v p="$pkgrel" '$2==p{print $1}' "$PAIRS_FILE" | paste -sd'|' -)"
	filter="^(${names})\$"
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v -run "$filter" "$pkgrel" 2>&1)" || {
		b3=no
		echo "  ---- $pkgrel (filter $filter) FAILED ----"
		printf '%s\n' "$out" | tail -40
		continue
	}
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		b3=no
		echo "  $pkgrel matched no tests for filter $filter (renamed test?)"
		continue
	fi
	ran="$(printf '%s\n' "$out" | grep -cE '^--- PASS: Test' || true)"
	echo "  $pkgrel: $ran named test(s) passed (filter $filter)"
done < "$WORKDIR/pkgs.txt"
ladder "$b3" "b375.3  every cited test passes live (per-package go test -run alternation)"

echo "----------------------------------------"
echo "B375: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B375 GREEN ================"
