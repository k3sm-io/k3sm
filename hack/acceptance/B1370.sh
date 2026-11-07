#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Models as OCI artifacts: the ModelPack layout, `k3sm model push` and `rm`,
# and MLXModel.spec.artifact rendered as an image volume.
#
#   b1370.1  pkg/modelpack: one raw layer per file, typed and annotated with
#            its path (org.cncf.model.filepath and the OCI title); the
#            ModelPack artifactType and config.
#   b1370.2  pkg/modelpack: split safetensors and split GGUF are one layer per
#            split in one artifact, refused when incomplete.
#   b1370.3  pkg/modelpack: the same files make the same manifest digest.
#   b1370.4  pkg/modelpack: case-colliding paths are refused, and code files
#            are refused by name before any byte is read.
#   b1370.5  cmd/k3sm: model push round-trips through the registry over the
#            push gate; a second push uploads no blob.
#   b1370.6  pkg/mlx, pkg/mlx/operator: the render of spec.artifact (an image
#            volume by digest, no cache PVC, no egress; an unresolved digest
#            or a reference off the cluster registry refused; the digest
#            resolved once per generation).
#
# Unit tests only, under -race: no cluster, no network, no privilege. A
# listed test that does not exist yet is PENDING, not a pass.
#
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING (everything present passed, and at
# least one listed test does not exist yet).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B1370.sh"
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
# result of running exactly those tests.
run() {
	local pkg="$1"; shift
	local listed n re
	listed="$(cd "$K3SM_ROOT" && go test -list '.*' "$pkg" 2>/dev/null)" || { echo no; return; }
	for n in "$@"; do grep -qx "$n" <<<"$listed" || { echo pending; return; }; done
	re="^($(IFS='|'; echo "$*"))\$"
	( cd "$K3SM_ROOT" && go test -race -count=1 -run "$re" "$pkg" >/dev/null 2>&1 ) && echo ok || echo no
}

echo "==> B1370 acceptance (models as OCI artifacts)"

b0=ok
bash -n "$SELF" || b0=no
for f in pkg/modelpack/modelpack.go cmd/k3sm/model.go; do [ -f "$K3SM_ROOT/$f" ] || b0=no; done
ladder "$b0" "b1370.0  gate parses (bash -n) + pkg/modelpack and cmd/k3sm/model.go exist"
if [ "$b0" != ok ]; then
	echo "B1370: $PASS passed, $FAIL failed, $PENDING pending" >&2
	exit 1
fi

ladder "$(run ./pkg/modelpack/ TestManifestOneRawLayerPerFile)" "b1370.1  modelpack: one raw layer per file, ModelPack types and annotations"
ladder "$(run ./pkg/modelpack/ TestSplitSafetensorsIsNLayers TestSplitGGUFIsNLayers)" "b1370.2  modelpack: split safetensors and split GGUF are N layers"
ladder "$(run ./pkg/modelpack/ TestManifestIsDeterministic)" "b1370.3  modelpack: deterministic manifest"
ladder "$(run ./pkg/modelpack/ TestRefusesCaseCollidingPaths TestRefusesCodeFilesBeforeReading)" "b1370.4  modelpack: case collisions and code files refused before reading"
ladder "$(run ./cmd/k3sm/ TestModelPushRoundTripsThroughTheRegistry)" "b1370.5  model push round-trips through the registry; a second push uploads no blob"
ladder "$(run ./pkg/mlx/ TestRenderArtifactModelAsImageVolume TestRenderArtifactModelHasNoCachePVCOrEgress TestRenderRefusesUnresolvedOrForeignArtifact)" "b1370.6a mlx: spec.artifact renders an image volume, no cache PVC, no egress; unresolved or foreign refused"
ladder "$(run ./pkg/mlx/operator/ TestResolvesArtifactDigestOncePerGeneration)" "b1370.6b mlx operator: the artifact digest is resolved once per generation"

echo "----------------------------------------"
echo "B1370: $PASS passed, $FAIL failed, $PENDING pending"
[ "$FAIL" = 0 ] || exit 1
[ "$PENDING" = 0 ] || { echo "B1370: PENDING: not a pass" >&2; exit 3; }
