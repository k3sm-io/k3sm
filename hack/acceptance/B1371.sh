#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# `k3sm model import hf://<org>/<repo>[@<revision>]`: a Hugging Face
# repository imported at a pinned commit into the cluster registry.
#
#   b1371.1  pkg/modelpack/hf: a branch or tag is resolved to its 40-hex
#            commit once, every later request names the commit, and the
#            manifest records it (org.opencontainers.image.revision).
#   b1371.2  pkg/modelpack/hf: an LFS file is verified against the Hub's
#            sha256; one corrupted byte refuses the import before any push.
#   b1371.3  pkg/modelpack/hf: a small (non-LFS) file is verified against its
#            git blob id.
#   b1371.4  pkg/modelpack/hf: a second import of the same commit uploads zero
#            bytes and names the same digest.
#   b1371.5  pkg/modelpack/hf: a gated repository is refused by name, before
#            any file is downloaded.
#   b1371.6  pkg/modelpack/hf: FuzzHubTreeListing over its committed seeds
#            (the tree listing is untrusted internet input).
#
# Unit tests only, under -race, against an httptest Hub: no cluster, no
# network, no privilege. A listed test that does not exist yet is PENDING,
# not a pass.
#
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING (everything present passed, and at
# least one listed test does not exist yet).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B1371.sh"
export CGO_ENABLED=1

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

PASS=0; FAIL=0; PENDING=0
ladder() {
	case "$1" in
	ok) echo "PASS     $2"; PASS=$((PASS+1)) ;;
	pending) echo "PENDING  $2"; PENDING=$((PENDING+1)) ;;
	*) echo "FAIL     $2"; FAIL=$((FAIL+1)) ;;
	esac
}
# run PKG NAME...: pending when any named test is not in PKG yet, else the
# result of running exactly those tests (a Fuzz target runs its seed corpus).
run() {
	local pkg="$1"; shift
	local listed n re
	[ -d "$K3SM_ROOT/$pkg" ] || { echo pending; return; }
	listed="$(cd "$K3SM_ROOT" && go test -list '.*' "$pkg" 2>/dev/null)" || { echo no; return; }
	for n in "$@"; do grep -qx "$n" <<<"$listed" || { echo pending; return; }; done
	re="^($(IFS='|'; echo "$*"))\$"
	( cd "$K3SM_ROOT" && go test -race -count=1 -run "$re" "$pkg" >/dev/null 2>&1 ) && echo ok || echo no
}

echo "==> B1371 acceptance (Hugging Face import at a pinned commit)"

b0=ok
bash -n "$SELF" || b0=no
[ -f "$K3SM_ROOT/cmd/k3sm/model.go" ] || b0=no
ladder "$b0" "b1371.0  gate parses (bash -n) + cmd/k3sm/model.go exists"
if [ "$b0" != ok ]; then
	echo "B1371: $PASS passed, $FAIL failed, $PENDING pending" >&2
	exit 1
fi

seeds=pending
if [ -d "$K3SM_ROOT/pkg/modelpack/hf/testdata/fuzz/FuzzHubTreeListing" ]; then
	n="$(find "$K3SM_ROOT/pkg/modelpack/hf/testdata/fuzz/FuzzHubTreeListing" -type f | wc -l | tr -d ' ')"
	[ "$n" -gt 0 ] && seeds="$(run ./pkg/modelpack/hf/ FuzzHubTreeListing)" || seeds=no
fi

ladder "$(run ./pkg/modelpack/hf/ TestImportPinsCommit)" "b1371.1  hf: the revision is pinned to its commit, and the manifest records it"
ladder "$(run ./pkg/modelpack/hf/ TestImportVerifiesLFSSha256)" "b1371.2  hf: an LFS file is verified by sha256; a corrupted byte refuses before push"
ladder "$(run ./pkg/modelpack/hf/ TestImportVerifiesGitBlobForSmallFiles)" "b1371.3  hf: a small file is verified by its git blob id"
ladder "$(run ./pkg/modelpack/hf/ TestImportIsIdempotent)" "b1371.4  hf: a second import uploads zero bytes, same digest"
ladder "$(run ./pkg/modelpack/hf/ TestImportRefusesGatedRepoLegibly)" "b1371.5  hf: a gated repository is refused by name"
ladder "$seeds" "b1371.6  hf: FuzzHubTreeListing over its committed seeds"

echo "----------------------------------------"
echo "B1371: $PASS passed, $FAIL failed, $PENDING pending"
[ "$FAIL" = 0 ] || exit 1
[ "$PENDING" = 0 ] || { echo "B1371: PENDING: not a pass" >&2; exit 3; }
