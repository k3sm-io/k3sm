#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's garbage collector keeps every blob a manifest of a format it
# does not know may reference: such a manifest stops the repository's sweep
# as unreadable instead of parsing as no references.
#
# --check runs, by name, with the race detector on:
#   TestKeepsBlobsOfAnUnknownManifest  a tagged Docker schema1 manifest, and one
#                                      of an unknown media type, beside an
#                                      ordinary image: the sweep stops with
#                                      ErrUnreadable and every blob survives
#                                      (red before the fix: the legacy layers
#                                      were reaped)
#   TestParseRefsFailsClosed           schema1, unknown media types, a body with
#                                      no mediaType and no known shape, a wrong
#                                      or missing schemaVersion, a manifest
#                                      without a config, malformed JSON: each is
#                                      ErrUnreadable
#   TestParseRefsKnownTypes            OCI and Docker v2 image manifests, indexes
#                                      and manifest lists, with and without a
#                                      mediaType, yield their references
#   FuzzParseRefs                      the committed seed corpus
# then the whole gc package, also under -race.
#
# Usage: hack/acceptance/B1053.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
pkg=./pkg/ociregistry/gc/
tests=(TestKeepsBlobsOfAnUnknownManifest TestParseRefsFailsClosed TestParseRefsKnownTypes FuzzParseRefs)
re="^($(IFS='|'; echo "${tests[*]}"))\$"
out="$(go test -race -count=1 -v -run "$re" "$pkg" 2>&1)" || {
	printf '%s\n' "$out"; echo "B1053: FAIL: named tests"; exit 1; }
printf '%s\n' "$out" | grep -E '^(--- |ok|PASS)'
# A test that does not run is not a pass.
for t in "${tests[@]}"; do
	printf '%s\n' "$out" | grep -q -- "^--- PASS: $t " || { echo "B1053: FAIL: $t did not run"; exit 1; }
done
# The fuzz corpus must be the committed one, not only the in-code seed.
n="$(printf '%s\n' "$out" | grep -c -- '^    --- PASS: FuzzParseRefs/seed-' || true)"
[ "$n" -ge 10 ] || { echo "B1053: FAIL: FuzzParseRefs ran $n committed seeds, want at least 10"; exit 1; }
go test -race -count=1 "$pkg" || { echo "B1053: FAIL: package tests"; exit 1; }
echo "B1053: PASS"
