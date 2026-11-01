#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The unreleased release notes and the budget page note say what the code does.
#
# --check greps CHANGELOG.md (or the file named by K3SM_CHANGELOG, for a red proof against
# another copy) and the apis budget doc for each corrected sentence:
#   - the sharded MLXModel served-name bullet occurs exactly once, naming mlx-serve 0.5.0-k3sm.3
#   - the server fills MeshPeer status.lastHandshakeTime
#   - uninstall names an unretained vm helper and prints the manual kill hint
#   - a plain install accepts any Developer ID team, an app update needs one team
#   - a first GC sweep stopped by the brake still records that it ran
#   - the magic-word note says a same-major resume stays recognised, which is why readers retry
#
# Usage: hack/acceptance/B1068.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

CL="${K3SM_CHANGELOG:-$K3SM_ROOT/CHANGELOG.md}"
DOC="${K3SM_BUDGET_DOC:-$K3SM_ROOT/../apis/budget/v1alpha1/doc.go}"
# A lone clone of this repo has no apis sibling; only then is the budget-doc assertion skipped.
SKIP_DOC=0
[ -z "${K3SM_BUDGET_DOC:-}" ] && [ ! -f "$DOC" ] && SKIP_DOC=1
fail=0
miss() { echo "B1068: FAIL: $1"; fail=1; }

# Each pattern is matched against the whole file with newlines folded to spaces.
has() { # file pattern label
	tr '\n' ' ' <"$1" | tr -s ' ' | grep -qE -- "$2" || miss "$3"
}

n="$(grep -c 'A pinned sharded `MLXModel` answers to its `spec.model` name too' "$CL" || true)"
[ "$n" -eq 1 ] || miss "served-name heading occurs $n times, want 1"
has "$CL" 'answers to its `spec.model` name too\.\*\* .*mlx-serve:0\.5\.0-k3sm\.3' "served-name bullet does not name mlx-serve:0.5.0-k3sm.3"
has "$CL" "fills each MeshPeer's \`status.lastHandshakeTime\`" "server MeshPeer lastHandshakeTime line missing"
has "$CL" 'Uninstall names a vm helper still running from a k3sm version the install no longer keeps.{0,200}sudo kill -TERM' "unretained vm helper line missing"
has "$CL" 'A plain `k3sm install` turns it off when the `k3sm` doing the install carries a Developer ID signature, from any team\. A k3sm\.app update turns it off only when every program in it is signed by one Developer ID team' "developer-mode sentence not split"
has "$CL" 'A first sweep that the brake stops still records that it ran, so the next sweep deletes' "first-sweep marker line missing"
if [ "$SKIP_DOC" -eq 1 ]; then
	echo "B1068: note: budget doc assertion skipped, no ../apis sibling and K3SM_BUDGET_DOC unset"
elif [ -f "$DOC" ]; then
	tr '\n' ' ' <"$DOC" | sed 's#// ##g' | tr -s ' ' | grep -q 'On a same-major resume the magic word already holds, so the page stays recognised while the other header words are rewritten, which is why readers retry' || miss "budget doc magic-word note not narrowed"
	tr '\n' ' ' <"$DOC" | sed 's#// ##g' | tr -s ' ' | grep -q 'so a page whose header is mid-rewrite is not yet recognised' && miss "budget doc keeps the broad magic-word sentence"
else
	miss "budget doc not found: $DOC"
fi

[ "$fail" -eq 0 ] || exit 1
echo "B1068: ok"
