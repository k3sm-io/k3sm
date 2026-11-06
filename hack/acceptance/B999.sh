#!/usr/bin/env bash
# k3sm root updater stage path and swap state machine acceptance gate.
#
#   b999.1  pkg/updater TestSwap and TestStagePath pass under -race, and every
#           subtest the backlog item requires ran and passed: a renamed or
#           deleted subtest fails the gate rather than passing silently.
#   b999.2  pkg/updater/layout: the flip plan moves previous before current and
#           the leaf contract still holds.
#
# Unit tests only, on temporary roots: a fake filesystem owner, a fake
# launchctl, fake health and a clock seam. Nothing runs as root.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B999.sh"
export CGO_ENABLED=1

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm root updater acceptance (stage path, swap marker, health, rollback)"

b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in pkg/updater/stage.go pkg/updater/machine.go pkg/updater/machine_test.go pkg/updater/stage_test.go; do [ -f "$K3SM_ROOT/$f" ] || b0=no; done
ladder "$b0" "b999.0  gate parses (bash -n) + the stage path and state machine exist"
if [ "$b0" != ok ]; then
	echo "root updater: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# The subtests the item's notes require, as go test names them.
required=(
	"TestSwap/resumes an unfinished flipped and restarting from the marker"
	"TestSwap/rolls back a health-wait past its deadline"
	"TestSwap/re-arms the deadline from the marker at start and restarts the window after a reboot"
	"TestSwap/data root unmounted gives data-root-unmounted with no rollback"
	"TestSwap/server health needs /readyz and one kine read"
	"TestSwap/commit sets previous, raises the high-water mark and commits updater/current"
	"TestSwap/rollback re-runs the Apple leg on previous and refuses the flip when it fails"
	"TestSwap/ad-hoc tree has no automatic rollback"
	"TestSwap/bad version refused until repair --clear-bad"
	"TestSwap/downgrade refused except the rollback to previous"
	"TestSwap/a fourth staged version refused"
	"TestSwap/older versions removed after commit"
	"TestSwap/every marker write flushed with F_FULLFSYNC"
	"TestSwap/remove-stale unlinks a link and refuses a directory"
	"TestStagePath/a fourth staged version refused"
	"TestStagePath/source archive not a regular file owned by _k3sm"
	"TestStagePath/source swapped after the copy"
	"TestStagePath/updater-work and stale partials emptied at start"
	"TestStagePath/manifest version not a directory name refused"
	"TestStagePath/the root CA copy must be root-owned and read-only to others"
)

out="$(cd "$K3SM_ROOT" && go test -race -count=1 -v -run '^(TestSwap|TestStagePath)$' ./pkg/updater/ 2>&1)" && b1=ok || b1=no
for name in "${required[@]}"; do
	if ! grep -qF -- "--- PASS: ${name// /_} (" <<<"$out"; then
		echo "      missing or not passing: $name"
		b1=no
	fi
done
[ "$b1" = ok ] || grep -E -- '--- FAIL|^FAIL|panic' <<<"$out" | head -20 || true
ladder "$b1" "b999.1  updater: TestSwap + TestStagePath, all ${#required[@]} required subtests ran and passed"

( cd "$K3SM_ROOT" && go test -race -count=1 -run '^(TestPlanFlip|TestPlanLinks|TestLeafContract)$' ./pkg/updater/layout/ >/dev/null 2>&1 ) && b2=ok || b2=no
ladder "$b2" "b999.2  layout: previous flips before current; leaf contract holds"

echo "----------------------------------------"
echo "root updater: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
