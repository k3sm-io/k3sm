#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Model metadata: `k3sm model ls [-o json]` reads each model's format, size,
# file and shard counts, quantization and parameter size from its manifest
# and ModelPack config, which push fills from the model's own config.json.
#
#   b1382.1  cmd/k3sm: model ls lists the ModelPack tags under models/ with
#            their metadata, from the manifest and config alone (no file
#            fetched); a non-model is not listed, and a model whose config
#            does not decode is listed without metadata.
#   b1382.2  cmd/k3sm: model ls -o json is a versioned document, pinned key
#            for key.
#   b1382.3  pkg/modelpack: config.json is read bounded and fail-closed (a
#            malformed or oversized one gives no metadata, not a failed
#            push; a value outside the closed set is dropped), and the
#            listing's metadata comes from the manifest and config.
#   b1382.4  pkg/modelpack: the config.json reader's fuzz target over its
#            committed seed corpus.
#
# Unit tests only, under -race: no cluster, no network, no privilege. A
# listed test that does not exist yet is PENDING, not a pass.
#
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING (everything present passed, and at
# least one listed test does not exist yet).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B1382.sh"
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
# result of running exactly those tests (a fuzz target runs its seeds).
run() {
	local pkg="$1"; shift
	local listed n re
	listed="$(cd "$K3SM_ROOT" && go test -list '.*' "$pkg" 2>/dev/null)" || { echo no; return; }
	for n in "$@"; do grep -qx "$n" <<<"$listed" || { echo pending; return; }; done
	re="^($(IFS='|'; echo "$*"))\$"
	( cd "$K3SM_ROOT" && go test -race -count=1 -run "$re" "$pkg" >/dev/null 2>&1 ) && echo ok || echo no
}

echo "==> B1382 acceptance (model metadata for k3sm model ls)"

b0=ok
bash -n "$SELF" || b0=no
for f in pkg/modelpack/modelpack.go cmd/k3sm/model.go; do [ -f "$K3SM_ROOT/$f" ] || b0=no; done
[ -n "$(ls -A "$K3SM_ROOT/pkg/modelpack/testdata/fuzz/FuzzReadModelConfig" 2>/dev/null)" ] || b0=no
ladder "$b0" "b1382.0  gate parses (bash -n), the sources exist, the fuzz seeds are committed"
if [ "$b0" != ok ]; then
	echo "B1382: $PASS passed, $FAIL failed, $PENDING pending" >&2
	exit 1
fi

ladder "$(run ./cmd/k3sm/ TestModelLsReadsManifestAndConfig)" "b1382.1  model ls reads the manifest and config"
ladder "$(run ./cmd/k3sm/ TestModelLsJSONShape)" "b1382.2  model ls -o json shape"
ladder "$(run ./pkg/modelpack/ TestModelConfigJSONMetadata TestMalformedConfigJSONGivesNoMetadata TestDescribeReadsManifestAndConfig)" "b1382.3  modelpack: bounded, fail-closed config.json; metadata from manifest and config"
ladder "$(run ./pkg/modelpack/ FuzzReadModelConfig)" "b1382.4  modelpack: config.json reader fuzz seeds"

echo "----------------------------------------"
echo "B1382: $PASS passed, $FAIL failed, $PENDING pending"
[ "$FAIL" = 0 ] || exit 1
[ "$PENDING" = 0 ] || { echo "B1382: PENDING: not a pass" >&2; exit 3; }
