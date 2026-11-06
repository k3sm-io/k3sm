#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The registry's zot child is gone from the build, the payload and the locks.
#
# --check:
#   b1024.1  go list -deps of the Go mains built from this workspace (k3sm, the
#            exec shim, the VM host) holds no zotregistry.dev, AWS, Azure, GCS,
#            ginkgo or conformance package. The children built outside the module
#            (kine, etcd, etcdutl, helm) have their own locks and are not listed.
#   b1024.2  no zot in hack/release/stage.sh, hack/release/lib/gochild.sh,
#            hack/release/govulncheck.allow, hack/deps.cooldown-exempt or
#            hack/deps.wrappers
#   b1024.3  no zotchild directory, wrapper lock, pin.go or zot fixture of the build
#   b1024.4  no zot in a stub-staged tree's PAYLOAD-SHA256, header or members, and
#            that staging passes staging's own completeness and shipped-main checks
#   b1024.5  grep -ri zot over cmd, pkg and hack, contents and file names, is empty
#            outside ALLOWED below
#   b1024.6  stage.sh --from-captured <Developer ID capture> --verify-release
#            passes, an ad-hoc capture is refused, and stage.sh --self-test passes.
#            A tree really signed with a Developer ID needs the attended signing
#            pipeline, which runs the same mode over the same policy.
#
# Usage: hack/acceptance/B1024.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

if [ "${1:-}" != "--check" ] || [ $# -ne 1 ]; then
	echo "usage: $0 --check" >&2
	exit 2
fi

# ALLOWED: every file under cmd, pkg and hack that may still say zot, by exact
# path, grouped by why. A row whose file no longer mentions zot is printed as a
# note and stays harmless, so a later removal does not red this gate.
ALLOWED="
# docs/m23-plan.md resolution 3: the legacy child is reclaimed and tolerated for
# one release.
pkg/registrysvc/orphan.go
pkg/registrysvc/orphan_darwin_test.go
pkg/registrysvc/orphan_integration_test.go
pkg/registrysvc/service.go
pkg/registrysvc/servicechild_test.go
pkg/executor/orphanreap.go
pkg/executor/orphanreap_test.go
pkg/executor/payload_digests.go
pkg/executor/payload_digests_test.go
pkg/install/install.go
pkg/install/install_test.go
pkg/install/removezot_darwin_test.go
hack/acceptance/B1022.sh
"

fails=0
fail() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
ok() { echo "ok   $1: $2"; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1

work="$(mktemp -d -t b1024)"
trap 'rm -rf "$work"' EXIT

# ---- b1024.1 ----------------------------------------------------------------
forbidden='^zotregistry\.dev/|^github\.com/aws/|^github\.com/Azure/|^cloud\.google\.com/go/storage|ginkgo|gomega|(^|/)conformance(/|$)'
if go list -deps k3sm.io/k3sm/cmd/k3sm k3sm.io/runtimed/cmd/k3sm-execshim k3sm.io/runtimed/cmd/k3sm-vmhost >"$work/deps" 2>"$work/deps.err"; then
	if ! grep -qx 'k3sm.io/k3sm/pkg/registrysvc' "$work/deps"; then
		fail b1024.1 "the listing does not hold pkg/registrysvc, so it read nothing"
	elif hits="$(grep -E "$forbidden" "$work/deps")"; then
		fail b1024.1 "the shipped binaries link: $hits"
	else
		ok b1024.1 "$(wc -l <"$work/deps" | tr -d ' ') packages, none of zot, a cloud SDK, ginkgo or a conformance suite"
	fi
else
	fail b1024.1 "go list -deps failed: $(cat "$work/deps.err")"
fi

# ---- b1024.2 ----------------------------------------------------------------
for f in hack/release/stage.sh hack/release/lib/gochild.sh hack/release/govulncheck.allow hack/deps.cooldown-exempt hack/deps.wrappers; do
	if [ ! -f "$f" ]; then
		fail b1024.2 "$f is missing"
	elif n="$(grep -ic zot "$f")"; then
		fail b1024.2 "$f says zot on $n lines"
	else
		ok b1024.2 "$f"
	fi
done

# ---- b1024.3 ----------------------------------------------------------------
for p in pkg/registrysvc/zotchild hack/deps-zotchild.lock pkg/registrysvc/pin.go pkg/registrysvc/testdata/zot-v2.1.22.go.mod hack/release/testdata/goversion-zot.txt; do
	if [ -e "$p" ]; then fail b1024.3 "$p still exists"; else ok b1024.3 "$p is gone"; fi
done

# ---- b1024.4 ----------------------------------------------------------------
if hack/release/stage.sh "$work/stub" --stub-payload >"$work/stub.log" 2>&1; then
	m="$work/stub/PAYLOAD-SHA256"
	if ! grep -q 'cp-payload/kine$' "$m"; then
		fail b1024.4 "the manifest lists no cp-payload/kine, so it read nothing"
	elif hits="$(grep -i zot "$m")"; then
		fail b1024.4 "PAYLOAD-SHA256 says: $hits"
	elif hits="$(find "$work/stub" -iname '*zot*')" && [ -n "$hits" ]; then
		fail b1024.4 "the staged tree holds: $hits"
	else
		ok b1024.4 "a staged tree's PAYLOAD-SHA256 and members hold no zot"
	fi
else
	fail b1024.4 "stub staging failed: $(tail -5 "$work/stub.log")"
fi

# ---- b1024.5 ----------------------------------------------------------------
allowed_rows="$(printf '%s\n' "$ALLOWED" | grep -v -e '^#' -e '^$')"
self="hack/acceptance/B1024.sh"
{
	rc=0
	grep -rIil zot cmd pkg hack || rc=$?
	[ "$rc" -le 1 ] || fail b1024.5 "grep over cmd, pkg and hack failed ($rc)"
	find cmd pkg hack -iname '*zot*' ! -type d
} | sort -u >"$work/mentions"
stray=""
while IFS= read -r f; do
	[ "$f" = "$self" ] && continue
	grep -qxF "$f" <<<"$allowed_rows" || stray="$stray$f"$'\n'
done <"$work/mentions"
if [ -n "$stray" ]; then
	fail b1024.5 "zot outside the allowlist in $(grep -c . <<<"$stray") files:"
	printf '%s' "$stray" | sed 's/^/    /'
else
	ok b1024.5 "$(grep -c . "$work/mentions") files mention zot, every one allowlisted"
fi
while IFS= read -r f; do
	grep -qxF "$f" "$work/mentions" || echo "note: $f is allowlisted and no longer mentions zot"
done <<<"$allowed_rows"

# ---- b1024.6 ----------------------------------------------------------------
td=hack/release/testdata
if hack/release/stage.sh --from-captured "$td/codesign-devid-synthetic.txt" --verify-release ABCDE12345 >"$work/vr.log" 2>&1; then
	ok b1024.6 "--verify-release accepts the Developer ID capture"
else
	fail b1024.6 "--verify-release refused the Developer ID capture: $(tail -3 "$work/vr.log")"
fi
if hack/release/stage.sh --from-captured "$td/codesign-adhoc-thin.txt" --verify-release ABCDE12345 >/dev/null 2>&1; then
	fail b1024.6 "--verify-release accepted an ad-hoc capture"
else
	ok b1024.6 "--verify-release refuses an ad-hoc capture"
fi
if hack/release/stage.sh --self-test >"$work/selftest.log" 2>&1; then
	ok b1024.6 "stage.sh --self-test"
else
	fail b1024.6 "stage.sh --self-test: $(grep -m5 FAIL "$work/selftest.log" || tail -3 "$work/selftest.log")"
fi

if [ "$fails" -ne 0 ]; then
	echo "B1024: $fails failed"
	exit 1
fi
echo "B1024: the zot child is gone from the build, the payload and the locks: ok"
