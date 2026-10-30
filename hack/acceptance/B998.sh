#!/usr/bin/env bash
# k3sm updater leaf packages acceptance gate.
#
# The root updater and the installer share two things that must not drift: the
# order launchd jobs are stopped and started in, and the versioned layout under
# /Library/k3sm. Both live in standard-library-only leaf packages so the updater
# can import them without the installer's launchd renderer or client-go:
#
#   b998.1  pkg/updater/layout: the contract table test. The restart order is
#           the one the installer uses today; neither leaf imports anything
#           outside the standard library (go list -deps, CGO_ENABLED=1); an
#           ancestor writable by group or other is refused; an ancestor not
#           owned by root is refused; every label gets the frozen program
#           arguments; a release that requires the installer is refused.
#   b998.2  pkg/updater/layout: version names, active-version resolution and
#           the atomic flip plan.
#   b998.3  pkg/install/order: start and stop order per role.
#   b998.4  pkg/install: the manifest's daemon order is order.Start's.
#
# Unit tests only, under -race: no launchd, no privilege. Red before the two
# packages exist.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B998.sh"
export CGO_ENABLED=1

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
run() { ( cd "$K3SM_ROOT" && go test -race -count=1 -run "$2" "$1" >/dev/null 2>&1 ) && echo ok || echo no; }

echo "==> k3sm updater leaf packages acceptance (restart order, versioned layout)"

b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in pkg/install/order/order.go pkg/updater/layout/doc.go pkg/updater/layout/layout.go; do [ -f "$K3SM_ROOT/$f" ] || b0=no; done
ladder "$b0" "b998.0  gate parses (bash -n) + the two leaf packages exist"
if [ "$b0" != ok ]; then
	echo "updater leaf packages: $PASS passed, $FAIL failed" >&2
	exit 1
fi

ladder "$(run ./pkg/updater/layout/ '^TestLeafContract$')" "b998.1  layout contract: order unchanged, stdlib only, ancestor checks, frozen arguments, requiresInstaller"
ladder "$(run ./pkg/updater/layout/ '^(TestValidateVersion|TestResolveActive|TestPlanFlip|TestPaths)$')" "b998.2  layout: version names, active resolution, flip plan, paths"
ladder "$(run ./pkg/install/order/ '^(TestStart|TestStop|TestNodeDaemon)')" "b998.3  order: start and stop order per role"
ladder "$(run ./pkg/install/ '^TestManifestDaemonOrderIsOrderStart$')" "b998.4  install: the manifest's daemon order is order.Start"

echo "----------------------------------------"
echo "updater leaf packages: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
