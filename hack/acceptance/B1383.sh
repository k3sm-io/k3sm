#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Spike: how much of a model family dedupes below the file level, across
# quantizations and fine-tunes. A measurement, not a behaviour: the gate
# proves the measurement ran and is not vacuous, and gates on no number.
#
#   b1383.0  the gate parses (bash -n) and the spike command builds.
#   b1383.1  hack/spike/dedupe: the chunkers and the tensor method detect
#            what they claim to (fixed chunks lose a shifted buffer, CDC
#            resyncs; a LoRA fine-tune adds only its q and v tensors).
#   b1383.2  the spike runs on the generated family and writes report.md
#            and report.json to the evidence directory.
#
# Inputs are generated from a fixed seed: no download, no network, no
# cluster, no privilege. The report states the limits of synthetic data.
#
# Usage: B1383.sh --measure [--evidence DIR]
#   --evidence  where the report goes (created). Default: a new temp dir,
#               printed on the last ladder line.
# Exit 0 pass, 1 fail, 2 usage.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B1383.sh"
GATE=b1383

[ "${1:-}" = "--measure" ] || { echo "usage: $0 --measure [--evidence DIR]" >&2; exit 2; }
shift
EVIDENCE=""
case "${1:-}" in
"") ;;
--evidence) [ $# -eq 2 ] || { echo "usage: $0 --measure [--evidence DIR]" >&2; exit 2; }; EVIDENCE="$2" ;;
*) echo "usage: $0 --measure [--evidence DIR]" >&2; exit 2 ;;
esac
[ -n "$EVIDENCE" ] || EVIDENCE="$(mktemp -d)"

PASS=0; FAIL=0
ladder() {
	case "$1" in
	ok) echo "PASS     $2"; PASS=$((PASS+1)) ;;
	*) echo "FAIL     $2"; FAIL=$((FAIL+1)) ;;
	esac
}

echo "==> $GATE acceptance (sub-file dedupe spike, measure only)"
b0=ok
bash -n "$SELF" || b0=no
[ -f "$K3SM_ROOT/hack/spike/dedupe/main.go" ] || b0=no
[ "$b0" = ok ] && { ( cd "$K3SM_ROOT" && go build -o /dev/null ./hack/spike/dedupe ) || b0=no; }
ladder "$b0" "$GATE.0  gate parses, the spike command builds"
if [ "$b0" != ok ]; then
	echo "$GATE: $PASS passed, $FAIL failed" >&2
	exit 1
fi

b1=ok
( cd "$K3SM_ROOT" && go test -count=1 -run '^(TestChunkersDetectShiftedContent|TestTensorMethodSeesUnchangedTensors)$' ./hack/spike/dedupe/ ) >/dev/null 2>&1 || b1=no
ladder "$b1" "$GATE.1  the chunkers and the tensor method are not vacuous"

b2=ok
( cd "$K3SM_ROOT" && go run ./hack/spike/dedupe -out "$EVIDENCE" ) >/dev/null || b2=no
[ -s "$EVIDENCE/report.md" ] && [ -s "$EVIDENCE/report.json" ] || b2=no
ladder "$b2" "$GATE.2  the spike wrote its report to $EVIDENCE"

echo "----------------------------------------"
echo "$GATE: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
