#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The docs describe the cluster registry as k3sm's own.
#
# --check asserts that docs/DESIGN.md, docs/user/** and README.md say what the
# registry serves, that it collects its own garbage, and that the push gate fronts
# its writes, with no mention of the third-party registry it replaces, and that
# CHANGELOG.md has an Unreleased entry saying so (history below it may still name
# the old one).
#
# Usage: hack/acceptance/B1025.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
fail() { echo "B1025: FAIL: $1"; exit 1; }

if grep -rniE '\bzot\b' docs/DESIGN.md docs/user README.md; then
	fail "a doc still names zot"
fi
grep -qi "k3sm's own" docs/DESIGN.md || fail "DESIGN.md does not call the registry k3sm's own"
grep -qiE 'registry.*(OCI|distribution)|(OCI|distribution).*registry' docs/DESIGN.md || fail "DESIGN.md does not say what the registry serves"
grep -qi 'garbage' docs/DESIGN.md || fail "DESIGN.md does not describe registry GC"
grep -qi 'push gate' docs/DESIGN.md || fail "DESIGN.md does not describe the push gate"
grep -qi "k3sm's own" docs/user/registry.md || fail "registry.md does not call the registry k3sm's own"
grep -qi 'garbage collection' docs/user/registry.md || fail "registry.md does not describe GC"
grep -qi 'push gate' docs/user/registry.md || fail "registry.md does not describe the push gate"
grep -qi "registry" README.md || fail "README.md does not mention the registry"

unrel="$(awk '/^## Unreleased/{f=1;next} /^## /{f=0} f' CHANGELOG.md)"
grep -qi "registry" <<<"$unrel" && grep -qi "k3sm's own" <<<"$unrel" ||
	fail "CHANGELOG.md Unreleased has no entry saying the registry is k3sm's own"
echo "B1025: PASS"
