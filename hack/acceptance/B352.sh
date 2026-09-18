#!/usr/bin/env bash
#
# k3sm B352 acceptance gate — the runnable proof that `k3sm install` builds the
# whole install root in a sibling directory and publishes it in ONE step, so no
# failure part-way through can leave a tree the daemon supervisor will execute.
#
# The defect: Install copied about ten artifacts — the binary, four sibling
# helpers, the control-plane payload and its version marker — straight into the
# live /Library/k3sm, one after another. A full disk, an I/O error, a signal or
# a power loss part-way through left the NEW binary beside the OLD helpers while
# the daemons still ran the previous build, and launchd's KeepAlive re-execs
# whatever is at the fixed paths the plists name — so a crash in that window
# promoted a combination nothing had ever tested. B349 moved every input-only
# refusal ahead of the first write, which closed the refusals; it did not make
# the copies themselves all-or-nothing.
#
# The fix, in the order that makes rollback possible: stage every install-root
# artifact into <InstallDir>.staging, publish the tree with one
# renamex_np(RENAME_SWAP), then write the launcher link and the plists, restart,
# verify, and only THEN remove the previous tree — which has been sitting intact
# at the staging path the whole time, and is what a failure in that window is
# swapped back to. An install-wide flock makes two concurrent installs a clean
# refusal rather than two versions interleaved into one staging tree.
#
# TWO TIERS, split by what a Mac can prove without being reinstalled:
#
#   CI TIER (always runs, CGO_ENABLED=1 — k3sm's posture) — the whole
#   orchestration, over the fake System: that a failure part-way through staging
#   leaves the live root byte-identical and records no write to it, that the
#   publish happens exactly once and after every staged write, that a first
#   install takes the plain-rename branch, that the reap waits for the
#   verification, that a post-publish failure reverse-swaps back to the original
#   tree, that a second concurrent install is refused, that a symlink at the
#   staging path is refused rather than removed, and that the data volume's own
#   staging mount point is never routed through the redirection. Plus the two
#   primitives against a REAL filesystem, unprivileged in a t.TempDir():
#   RENAME_SWAP exchanging two directories in one step, and flock refusing the
#   second holder. Plus the structural pins a later edit would quietly undo.
#
#   LAB TIER (K3SM_LAB=1, ONE Mac, root, a REAL install) — the rungs that need
#   hardware: a live upgrade over running daemons, a daemon surviving both the
#   swap and the removal of the tree it was executing out of, the two paths
#   proven to be on one filesystem, and a kill mid-copy. They are announced
#   LAB-PENDING below and are NEVER counted as a pass.
#
# RED BEFORE: on the unmodified tree stage.go does not exist, the copy block
# names cfg.installedBinary() and its siblings (the LIVE paths), and there is no
# swap, lock or reap at all — so every b352.1 wiring rung fails and every Go leg
# reports "no tests to run".
#
# Usage:  hack/acceptance/B352.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B352.sh # + the one-Mac lab tier (announced only)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B352.sh"
STAGE_GO="$K3SM_ROOT/pkg/install/stage.go"
INSTALL_GO="$K3SM_ROOT/pkg/install/install.go"
DARWIN_GO="$K3SM_ROOT/pkg/install/install_darwin.go"
RESTART_GO="$K3SM_ROOT/pkg/install/restart.go"
DATAVOL_GO="$K3SM_ROOT/pkg/install/datavol.go"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
lab_pending() { echo "LAB-PENDING  $1"; }

echo "==> k3sm B352 acceptance (the install root is staged and published in one step)"

# ---- b352.0 — the gate parses and its sources exist -------------------------
# stage.go is deliberately NOT required here: it is the file this item ADDS, so
# asserting it at rung 0 would short-circuit the whole ladder on the unmodified
# tree and report one uninformative line instead of naming what is missing.
# b352.1 below asserts it, rung by rung.
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$INSTALL_GO" "$DARWIN_GO" "$RESTART_GO" "$DATAVOL_GO"; do
	[ -f "$f" ] || b0=no
done
ladder "$b0" "b352.0  gate parses (bash -n) + pkg/install/{install,install_darwin,restart,datavol}.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B352: the gate or its sources are missing — nothing else can run" >&2
	echo "B352: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b352.1 — the WIRING, read straight out of the source ------------------
# Facts about WHERE a literal lives, which no unit test can pin.

# The staging machinery has one home: stage.go. Asserted first, so a tree
# without it names that fact rather than failing five greps in a row.
p=ok
[ -f "$STAGE_GO" ] || p=no
ladder "$p" "b352.1  the staged-install-root machinery lives in pkg/install/stage.go"

# The publish primitive. renamex_np with RENAME_SWAP is the only darwin call
# that puts a directory over an existing one in a single step; a
# remove-then-rename would leave a window with no install root at all.
w=ok
grep -q 'unix\.RenamexNp(staging, live, unix\.RENAME_SWAP)' "$DARWIN_GO" || w=no
grep -q 'unix\.EXDEV' "$DARWIN_GO" || w=no
grep -q 'ErrInstallRootCrossDevice' "$STAGE_GO" || w=no
ladder "$w" "b352.1  the publish is unix.RenamexNp(...RENAME_SWAP) with EXDEV named as its own error"

# The lock. flock, not an O_CREAT|O_EXCL sentinel: a sentinel outlives the
# process that made it, so a ^C'd install would lock every later one out.
l=ok
grep -q 'unix\.Flock(fd, unix\.LOCK_EX|unix\.LOCK_NB)' "$DARWIN_GO" || l=no
grep -q 'ErrInstallInProgress' "$STAGE_GO" || l=no
grep -q 'sys\.LockInstall(cfg\.installLockPath())' "$INSTALL_GO" || l=no
ladder "$l" "b352.1  the install-wide lock is a non-blocking flock and Install takes it"

# The honesty clause: crash/power-loss atomicity is documented for plain
# rename(2) and is NOT restated for the swap variant, so nothing may claim it as
# a guarantee. This rung fails if the word "guarantee" is ever attached to the
# crash case, and requires the inference to be named as one.
h=ok
grep -qi 'inference' "$STAGE_GO" || h=no
grep -qiE 'guarantee[sd]? (crash|power|durab)' "$STAGE_GO" "$DARWIN_GO" && h=no
grep -qiE '(crash|power)-?(loss)?.{0,40}(is|are) (documented|guaranteed)' "$STAGE_GO" "$DARWIN_GO" && h=no
ladder "$h" "b352.1  the atomicity claim is stated as an inference, never as a documented guarantee"

# The copy block writes STAGED paths and no live ones. A single
# CopyToRootOwned(..., cfg.installed*) would be a hole straight back into the
# defect.
c=ok
for s in stagedBinary stagedExecShim stagedPathShim stagedDNSShim stagedVMHost; do
	grep -q "sys\.CopyToRootOwned(.*cfg\.$s(" "$INSTALL_GO" || c=no
done
# The payload loop and the kine marker reach the staged path through a `dst`
# binding and a wrapped call, so they are asserted by their own accessor.
[ "$(grep -c 'cfg\.stagedPayloadFile(' "$INSTALL_GO" || true)" = 2 ] || c=no
# ...and NO copy names a live path. This is the negative that matters: one
# CopyToRootOwned(..., cfg.installed*) would be a hole straight back into the
# defect, and it would pass every positive rung above.
grep -qE 'sys\.CopyToRootOwned\([^)]*cfg\.installed' "$INSTALL_GO" && c=no
[ "$(grep -c 'sys\.CopyToRootOwned(' "$INSTALL_GO" || true)" = 7 ] || c=no
ladder "$c" "b352.1  all 7 CopyToRootOwned calls in Install name a staged destination, none an installed one"

# The ORDER, by line number: stage, publish, wire, reap. This is the single
# choice that makes rollback possible — a reap before the verification would
# throw the rollback target away while it is still needed.
o=ok
# Tolerant by construction: a pattern that does not match yields an EMPTY line
# number, which the comparisons below read as a failed rung. Without the
# `|| true` the unmatched grep would take `set -e` out of the script and the
# remaining rungs would never be reported at all.
ln() { grep -n "$1" "$2" 2>/dev/null | head -1 | cut -d: -f1 || true; }
prep_l="$(ln 'prepareStagingDir(sys, cfg)' "$INSTALL_GO")"
copy_l="$(ln 'sys\.CopyToRootOwned(cfg\.BinarySource, cfg\.stagedBinary())' "$INSTALL_GO")"
pub_l="$(ln 'publishStagedRoot(sys, cfg)' "$INSTALL_GO")"
wire_l="$(ln 'publishedWiring(ctx, sys, cfg, m, startedAt)' "$INSTALL_GO")"
reap_l="$(ln 'reapPreviousRoot(sys, cfg)' "$INSTALL_GO")"
for pair in "$prep_l $copy_l" "$copy_l $pub_l" "$pub_l $wire_l" "$wire_l $reap_l"; do
	set -- $pair
	if [ -z "${1:-}" ] || [ -z "${2:-}" ] || [ "$1" -ge "$2" ]; then o=no; fi
done
ladder "$o" "b352.1  Install's order is stage($prep_l) -> copy($copy_l) -> publish($pub_l) -> wire($wire_l) -> reap($reap_l)"

# ...and inside the wiring, the link and the plists precede the restart, which
# precedes the verification the reap waits on.
i=ok
link_l="$(ln 'sys\.EnsureSymlink(a\.target, a\.path)' "$INSTALL_GO")"
plist_l="$(ln 'sys\.WriteLaunchDaemon(a\.path, content, plistMode(a\.label))' "$INSTALL_GO")"
rest_l="$(ln 'restartDaemons(ctx, sys, cfg, m)' "$INSTALL_GO")"
ver_l="$(ln 'verifyDaemons(ctx, sys, cfg, m, startedAt)' "$INSTALL_GO")"
# Compared within publishedWiring, which is a separate function below Install —
# the reap's position relative to it is the previous rung's wire -> reap pair.
for pair in "$link_l $plist_l" "$plist_l $rest_l" "$rest_l $ver_l"; do
	set -- $pair
	if [ -z "${1:-}" ] || [ -z "${2:-}" ] || [ "$1" -ge "$2" ]; then i=no; fi
done
ladder "$i" "b352.1  inside the published wiring: link($link_l) -> plists($plist_l) -> restart($rest_l) -> verify($ver_l)"

# The publish log line: emitted the instant the swap returns and BEFORE the plist
# writes, because after an interrupted upgrade it is the only artifact that says
# which side of the swap the Mac is on.
g=ok
grep -q 'published the staged install root' "$STAGE_GO" || g=no
grep -q 'previous-tree-pending-removal' "$STAGE_GO" || g=no
ladder "$g" "b352.1  the publish logs which path is live and which holds the previous tree"

# The rollback lives in restart.go and reuses its reporting shape rather than
# inventing a second error vocabulary.
r=ok
grep -q 'func revertInstallRoot(' "$RESTART_GO" || r=no
grep -q 'daemonStates(sys, longRunningDaemonLabels(m))' "$RESTART_GO" || r=no
grep -q 'revertInstallRoot(ctx, sys, cfg, m, previous, err)' "$INSTALL_GO" || r=no
ladder "$r" "b352.1  the post-publish rollback is revertInstallRoot, in restart.go's own reporting shape"

# The trust check before any privileged removal of the staging path.
t=ok
grep -q 'func stagingTrustVerdict(' "$STAGE_GO" || t=no
grep -q 'trustedStagingPath(sys, staging)' "$STAGE_GO" || t=no
ladder "$t" "b352.1  the staging path is trust-checked before root is asked to remove it"

# The data volume's own staging mount point is a real transient APFS mount
# NESTED in the install root. It runs and tears down at step 0, before the
# install root is staged at all, and it must never be routed through the
# redirection.
d=ok
grep -q 'staging := cfg\.datavolStaging()' "$DATAVOL_GO" || d=no
grep -q 'staged' "$DATAVOL_GO" && d=no
dv_l="$(ln 'ensureDataVolume(ctx, sys, cfg, m, st)' "$INSTALL_GO")"
if [ -z "$dv_l" ] || [ -z "$prep_l" ] || [ "$dv_l" -ge "$prep_l" ]; then d=no; fi
ladder "$d" "b352.1  the data-volume mount point is not redirected and runs ($dv_l) before staging begins ($prep_l)"

# ---- Go leg runner ---------------------------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-
# Rosetta would otherwise build the wrong arch for a darwin/arm64-only product.
#
# run_test <id> <min-subtests> <TestName> <pkg> <dir> <cgo>
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever. Each leg fails unless the
# top-level `--- PASS: <TestName>` line is present and the subtest count meets
# the pinned minimum (0 for a leg with no subtests). The minimums are the counts
# the branch actually carries, so DELETING a case reddens the gate.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" dir="$5" cgo="$6" out rc=0 ran
	out="$(cd "$dir" && env GOARCH=arm64 CGO_ENABLED="$cgo" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name}( |\$)"; then
		ladder no "$id  $name ($pkg) actually RAN — no top-level --- PASS line"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- b352.2 — the staged root, over the fake System ------------------------
# The spine: every artifact staged, the publish exactly once and after the last
# staged write, the link and plists after it, the reap after the verification,
# the lock held across the whole run.
run_test "b352.2" 7 TestInstallStagesTheRootAndPublishesItOnce ./pkg/install/ "$K3SM_ROOT" 1
# The defect itself: a copy that fails part-way leaves the live root untouched.
run_test "b352.2" 0 TestInstallStagingFailureLeavesTheLiveRootUntouched ./pkg/install/ "$K3SM_ROOT" 1
# The other publish branch: no install root on the Mac, so a plain rename and no reap.
run_test "b352.2" 0 TestInstallFirstInstallRenamesTheStagedRootIntoPlace ./pkg/install/ "$K3SM_ROOT" 1
# The rollback: a failure after the publish swaps the previous tree back.
run_test "b352.2" 0 TestInstallRevertsTheSwapWhenTheWiringFails ./pkg/install/ "$K3SM_ROOT" 1

# ---- b352.3 — the two refusals ---------------------------------------------
run_test "b352.3" 0 TestInstallRefusesASecondConcurrentInstall ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.3" 4 TestInstallRefusesAnUntrustedStagingPath ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.3" 6 TestStagingTrustVerdict ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.3" 0 TestStaleStagingTreeIsRemovedBeforeStaging ./pkg/install/ "$K3SM_ROOT" 1

# ---- b352.4 — the redirection and the free-space preflight -----------------
run_test "b352.4" 0 TestStagedPath ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.4" 0 TestDataVolumeStagingIsNeverRedirected ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.4" 3 TestFreeSpacePreflight ./pkg/install/ "$K3SM_ROOT" 1

# ---- b352.5 — the primitives, against a real filesystem --------------------
# Unprivileged, in a t.TempDir() on the Data volume — the same filesystem
# /Library is firmlinked onto, so the same-volume posture is the real one.
run_test "b352.5" 3 TestSwapInstallRootOnDisk ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.5" 0 TestLockInstallOnDisk ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.5" 0 TestInstallSpaceOnDisk ./pkg/install/ "$K3SM_ROOT" 1

# ---- b352.6 — nothing the change was not allowed to break ------------------
# The full call-sequence pin, the manifest-coverage gate (which now maps a
# staged copy back through the publish), and the launcher link.
run_test "b352.6" 0 TestInstallOrchestration ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.6" 7 TestUninstallManifestCoversInstall ./pkg/install/ "$K3SM_ROOT" 1
run_test "b352.6" 3 TestInstallLinksK3smOntoPath ./pkg/install/ "$K3SM_ROOT" 1

# ---- b352.7 — the package is formatted and vet-clean -----------------------
f=ok
unformatted="$(cd "$K3SM_ROOT" && gofmt -l pkg/install 2>&1 || true)"
[ -z "$unformatted" ] || { printf '%s\n' "$unformatted"; f=no; }
ladder "$f" "b352.7  gofmt -l is empty over pkg/install"

v=ok
vetout="$(cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=1 go vet ./pkg/install/ 2>&1)" || v=no
[ "$v" = ok ] || printf '%s\n' "$vetout" | tail -20
ladder "$v" "b352.7  go vet is clean over pkg/install (CGO_ENABLED=1)"

# ============================================================================
# LAB TIER — ONE MAC, ROOT, A REAL INSTALL (K3SM_LAB=1).
#
# These four rungs are the ones no fake can reach. They are ANNOUNCED here and
# never executed by this script, because each of them reinstalls or interrupts
# a real k3sm on the Mac it runs on: running them is a human lab session, and a
# gate that did it unattended would take a cluster down to prove a point.
# ============================================================================
echo "----------------------------------------"
lab_pending "b352.L1  a live upgrade over RUNNING daemons: \`sudo k3sm install\` on a Mac with a healthy cluster publishes the new root, both daemons come back on the new binary, and /Library/k3sm.staging is gone afterwards"
lab_pending "b352.L2  a running daemon survives the publish AND the reap: the server keeps serving across the swap and across the removal of the tree it was executing out of, including further code-page faults into that binary"
lab_pending "b352.L3  /Library/k3sm and /Library/k3sm.staging report the same filesystem (statfs f_fsid): the same-volume premise EXDEV would violate, measured rather than assumed"
lab_pending "b352.L4  a second \`sudo k3sm install\` started while the first is copying is refused immediately, naming the lock at /Library/k3sm.lock — never queued behind a run the operator cannot see"
lab_pending "b352.L5  an install killed mid-copy (SIGKILL during the payload) leaves /Library/k3sm byte-identical and both daemons still running the previous build; the next install removes the abandoned staging tree and succeeds"
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "B352: K3SM_LAB=1 is set, but the lab rungs above are human-run by design (each one reinstalls or interrupts a real cluster). Nothing was executed." >&2
fi

echo "----------------------------------------"
echo "B352: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B352 GREEN (CI tier; the five lab rungs are human-run) ================"
