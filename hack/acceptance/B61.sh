#!/usr/bin/env bash
# k3sm B61 acceptance gate — the unit-tier structure proof for the docs/user/*
# user-documentation IA skeleton (backlog item B61). It is offline and hermetic:
# no network, no markdown linter, no control plane. It asserts, red-at-main
# (docs/user/ absent) via an explicit ladder FAIL line and green-after:
#
#   1. exact-set manifest — the 15 required files + README.md present, and
#      mlx-quickstart.md ABSENT (it is m8-gated; this decouples B61 from m8).
#   2. offline relative-link check — every in-repo markdown link in docs/user/*
#      resolves to a file that exists (dangling -> red). http(s)/mailto/#-anchors
#      are skipped; a trailing #anchor is stripped before resolving.
#   3. honest-gaps matrix — limitations.md carries each required gap token AND
#      names both conformance registers (the citation-presence check).
#   4. stale-string denylist — no `Pre-M0` / `private development` anywhere.
#
# The register citations in limitations.md are BY NAME (plain text), not
# relative links: UPSTREAM-ALIGNMENT.md / conformance-profile.md live at the
# WORKSPACE-root docs/ dir, OUTSIDE the k3sm repo, so a relative link would
# dangle in a standalone checkout / on the published site. The offline
# link-check therefore covers only IN-repo docs/user/* targets.
#
# Exit 0 iff every check passes. Mirrors hack/acceptance/m1.sh conventions.
#
# Usage: hack/acceptance/B61.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
USERDIR="$REPO_ROOT/docs/user"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B61 acceptance (docs/user IA skeleton + structure/link lint)"

# --- Check 0: docs/user/ present (explicit red-at-main FAIL line) -------------
if [ -d "$USERDIR" ]; then
	ladder ok "B61.0  docs/user/ directory present"
else
	ladder no "B61.0  docs/user/ directory present (absent at main)"
fi

# --- Check 1: exact-set manifest ---------------------------------------------
REQUIRED=(
	quickstart.md install.md concepts.md limitations.md images.md
	multi-node.md vm-runtimeclass.md ha.md storage.md kubectl-access.md
	troubleshooting.md faq.md versions.md upgrade.md backup-restore.md
)
for f in "${REQUIRED[@]}"; do
	if [ -f "$USERDIR/$f" ]; then
		ladder ok "B61.1  required file present: $f"
	else
		ladder no "B61.1  required file MISSING: $f"
	fi
done
# README index is the link hub / front door.
if [ -f "$USERDIR/README.md" ]; then
	ladder ok "B61.1  README.md index present"
else
	ladder no "B61.1  README.md index MISSING"
fi
# mlx-quickstart.md is m8-gated: it MUST be absent (present -> red).
if [ -e "$USERDIR/mlx-quickstart.md" ]; then
	ladder no "B61.1  mlx-quickstart.md present (must be absent — m8-gated)"
else
	ladder ok "B61.1  mlx-quickstart.md absent (m8-gated, decoupled)"
fi

# --- Check 2: offline relative-link check ------------------------------------
# For every markdown [text](target) in docs/user/*.md: skip http(s)://, mailto:,
# and pure #anchors; strip a trailing #anchor; resolve relative to the file's
# own dir; assert the target exists. No network.
dangling=0
if [ -d "$USERDIR" ]; then
	shopt -s nullglob
	for f in "$USERDIR"/*.md; do
		fdir="$(dirname "$f")"
		# extract each ](target) occurrence, strip the ]( prefix and ) suffix.
		while IFS= read -r raw; do
			target="${raw#](}"; target="${target%)}"
			case "$target" in
				http://*|https://*|mailto:*) continue ;;
				\#*) continue ;;
			esac
			t="${target%%#*}"            # strip trailing #anchor
			[ -n "$t" ] || continue      # was a pure anchor
			if [ ! -e "$fdir/$t" ]; then
				echo "      dangling link in $(basename "$f"): $target -> $fdir/$t"
				dangling=$((dangling+1))
			fi
		done < <(grep -oE '\]\([^)]+\)' "$f" || true)
	done
	shopt -u nullglob
fi
if [ "$dangling" -eq 0 ] && [ -d "$USERDIR" ]; then
	ladder ok "B61.2  all in-repo relative links resolve (offline)"
else
	ladder no "B61.2  $dangling dangling relative link(s) in docs/user/*"
fi

# --- Check 3: honest-gaps matrix + citation presence in limitations.md -------
LIM="$USERDIR/limitations.md"
# each required gap token (case-insensitive). Family fails independently.
declare -a GAP_LABELS=(
	"no per-pod uid isolation"
	"DNS gap"
	"UDP Services deferred"
	"vm/HA EXPERIMENTAL"
	"single-node watch-staleness (B28)"
)
declare -a GAP_PATTERNS=(
	"no per-pod uid"
	"dns"
	"udp"
	"experimental"
	"watch-staleness|watch staleness|b28"
)
if [ -f "$LIM" ]; then
	for i in "${!GAP_PATTERNS[@]}"; do
		if grep -iEq "${GAP_PATTERNS[$i]}" "$LIM"; then
			ladder ok "B61.3  limitations gap present: ${GAP_LABELS[$i]}"
		else
			ladder no "B61.3  limitations gap MISSING: ${GAP_LABELS[$i]}"
		fi
	done
	# citation-presence (the conformance CRITICAL): both registers named.
	if grep -iq "UPSTREAM-ALIGNMENT" "$LIM"; then
		ladder ok "B61.3  limitations cites UPSTREAM-ALIGNMENT register"
	else
		ladder no "B61.3  limitations MISSING UPSTREAM-ALIGNMENT citation"
	fi
	if grep -iq "conformance-profile" "$LIM"; then
		ladder ok "B61.3  limitations cites conformance-profile register"
	else
		ladder no "B61.3  limitations MISSING conformance-profile citation"
	fi
else
	ladder no "B61.3  limitations.md absent (gaps + citations uncheckable)"
fi

# --- Check 4: stale-string denylist ------------------------------------------
stale=0
if [ -d "$USERDIR" ]; then
	for pat in "Pre-M0" "private development"; do
		if grep -riq "$pat" "$USERDIR"; then
			echo "      stale string found: $pat"
			stale=$((stale+1))
		fi
	done
fi
if [ "$stale" -eq 0 ] && [ -d "$USERDIR" ]; then
	ladder ok "B61.4  no stale strings (Pre-M0 / private development)"
else
	ladder no "B61.4  $stale stale string(s) present in docs/user/*"
fi

echo "----------------------------------------"
echo "B61: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B61 GREEN ================"
