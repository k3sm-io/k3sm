#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's authentication and its three-principal access model.
#
# --check runs, under -race:
#   TestAccessControl   (pkg/ociregistry/auth) every endpoint of the server by
#                       verb, for anonymous, k3sm, k3sm-gate, a wrong secret and
#                       an unknown user, with the expected status and error code
#   TestAuthenticate    (pkg/ociregistry/auth) the Authorization header limits
#                       and the fail-closed parsing
#   TestFailureBucket   (pkg/ociregistry/auth) the per-source token bucket (429)
#   TestNewRefuses      (pkg/ociregistry/auth) the principal set New accepts
#   FuzzAuthorization   (pkg/ociregistry/auth) over its committed seeds
#   TestServeConfig     (pkg/registrysvc) the daemon writes both principals'
#                       SHA-256 secret hashes, 0600, and no plaintext secret
#
# Usage: hack/acceptance/B1019.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1
for f in pkg/ociregistry/auth/testdata/fuzz/FuzzAuthorization; do
	[ -e "$f" ] || { echo "B1019: FAIL: $f is missing"; exit 1; }
done

# run <package> <regexp> <test>... runs the tests and requires each to pass by name.
run() {
	local pkg="$1" re="$2"
	shift 2
	local out
	out="$(go test -race -count=1 -v -run "$re" "$pkg" 2>&1)" || {
		printf '%s\n' "$out"; echo "B1019: FAIL: $pkg"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |ok)'
	# A test that does not run is not a pass.
	local t
	for t in "$@"; do
		grep -q -- "--- PASS: $t " <<<"$out" || { echo "B1019: FAIL: $t did not run"; exit 1; }
	done
}

run ./pkg/ociregistry/auth/ '^(TestAccessControl|TestAuthenticate|TestFailureBucket|TestNewRefuses|FuzzAuthorization)$' \
	TestAccessControl TestAuthenticate TestFailureBucket TestNewRefuses FuzzAuthorization
run ./pkg/registrysvc/ '^TestServeConfig$' TestServeConfig

# The table must cover the matrix, not a sample of it: five principals across
# every endpoint.
out="$(go test -count=1 -v -run '^TestAccessControl$' ./pkg/ociregistry/auth/ 2>&1)"
n="$(printf '%s\n' "$out" | grep -c -- '--- PASS: TestAccessControl/')"
[ "$n" -ge 80 ] || { echo "B1019: FAIL: only $n TestAccessControl subtests passed"; exit 1; }

# The server compares SHA-256 hashes: it links no bcrypt and reads no
# htpasswd file (the store's reserved-name list may still name the file).
if grep -rlE 'golang\.org/x/crypto|HTPasswdPath|registrysvc' --include='*.go' pkg/ociregistry | grep -v '_test\.go$'; then
	echo "B1019: FAIL: pkg/ociregistry imports x/crypto or reads the htpasswd file"; exit 1
fi
deps=$(go list -deps ./pkg/ociregistry/...)
if grep -q 'golang.org/x/crypto/bcrypt' <<<"$deps"; then
	echo "B1019: FAIL: pkg/ociregistry links bcrypt"; exit 1
fi
echo "B1019: PASS"
