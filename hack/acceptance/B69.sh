#!/usr/bin/env bash
#
# k3sm B69 acceptance gate — the kine single-pin collapse.
#
# What it proves, in seven legs:
#
#   b69.1 LINT       ONE kine pin, >=0.16.x, built CGO_ENABLED=0, with the startup-VACUUM
#                    opt-out on the shipped SQLite DSN.
#   b69.2 FORWARD    a production-shaped datastore written and CHURNED by the superseded
#                    pin is fully readable — and writable — by the new one.
#   b69.3 DOWNGRADE  the superseded pin can still read a datastore the new pin created
#                    and migrated (the rollback half; not implied by FORWARD).
#   b69.4 SNAPSHOT   the pre-migration backup drains the WAL, verifies the copy, is
#                    write-once across re-boots, and REFUSES on a nearly-full volume.
#   b69.5 DEP-LINT   the shipped kine binary links no mattn/go-sqlite3.
#   b69.6 MARKER     a kine staged with a stale/absent version marker is RE-STAGED, and
#                    the new marker records the nocgo variant.
#   b69.7 REAP       no kine the legs above started is still alive when they are done.
#
# red-at-main: pkg/executor/executor.go carries TWO pins (DefaultKineVersion v1.14.2 +
# DefaultKineVersionHA v0.16.3), ensureKineInto builds CGO_ENABLED=1 and short-circuits
# on file PRESENCE, the DSN has no vacuum opt-out, and there is no snapshot path at all —
# so legs 1, 4 and 6 cannot pass, and 2/3/5 do not exist to be run. Leg 7 is red on any
# tree whose fixtures reap their kine children only through a `defer` the failing,
# interrupted, or timed-out paths never reach.
#
# TIER: integration. It builds TWO real kine binaries and runs them, so it needs a Go
# toolchain and network.
#
#   *** GOPROXY REQUIREMENT (not optional) ***
# The superseded pin, kine v1.14.2, has NO corresponding upstream git tag: it resolves
# only through a module proxy that already carries it (the B38 provenance finding). With
# GOPROXY=direct — or a cold proxy — the b69.2/b69.3 fixture build CANNOT succeed, and
# this script says so explicitly rather than surfacing an opaque resolution error.
#
# Usage: hack/acceptance/B69.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
EXEC_PKG="$REPO_ROOT/pkg/executor"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B69 acceptance (kine single-pin collapse: >=0.16.x, CGO_ENABLED=0, migration-safe)"

WORK="$(mktemp -d /tmp/b69.XXXXXX)"
# The scratch GOPATHs below hold only bin/ — GOMODCACHE stays on the shared, already
# warm module cache, so the two fixture builds do not re-download the world AND the
# cleanup does not have to fight the module cache's read-only trees.
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
cleanup() { chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# fixture_kine_pids prints the pids of every kine serving a datastore under this host's
# TEMP directory. That endpoint — not the process name — is the discriminator, and it is
# exact: a t.TempDir() database is by construction a Go test fixture's, because a real
# k3sm server keeps its datastore under its workdir (~/.k3sm/... or /var/lib/k3sm) and
# never under $TMPDIR. It is what keeps this gate from ever naming, let alone telling a
# human to kill, an operator's live cluster on the same Mac.
TMP_PREFIX="${TMPDIR:-/tmp}"; TMP_PREFIX="${TMP_PREFIX%/}"
fixture_kine_pids() {
	ps -Ao pid=,command= | awk -v pfx="sqlite://$TMP_PREFIX" '
		/--endpoint/ && index($0, pfx) { print $1 }' | sort -u
}

# name_pids prints a one-line ps for each pid, truncated so a long argv cannot bury the
# verdict.
name_pids() {
	for p in $1; do ps -o pid=,args= -p "$p" 2>/dev/null | cut -c1-200 >&2 || true; done
}

# The host Go toolchain on a Mac can be an amd64 build running under Rosetta, in which
# case an unpinned `go install` silently emits x86_64 binaries. Every build below pins
# the target explicitly so the gate measures the architecture k3sm actually ships.
export GOOS=darwin GOARCH=arm64

# ---- b69.1 — LINT: one pin, >=0.16.x, nocgo, vacuum opt-out ------------------
lint_ok=true

pins="$(grep -nE '^\s*DefaultKineVersion[A-Za-z]*\s*=' "$EXEC_PKG/executor.go" || true)"
pin_count="$(printf '%s\n' "$pins" | grep -c . || true)"
if [ "$pin_count" -ne 1 ]; then
	echo "  expected exactly ONE kine pin constant, found $pin_count:" >&2
	printf '%s\n' "$pins" >&2
	lint_ok=false
fi
if grep -rqE 'DefaultKineVersionHA' "$REPO_ROOT/pkg" "$REPO_ROOT/cmd"; then
	echo "  DefaultKineVersionHA still referenced — the two-pin split was not collapsed" >&2
	lint_ok=false
fi

KINE_PIN="$(sed -nE 's/^[[:space:]]*DefaultKineVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$EXEC_PKG/executor.go" | head -1)"
if [ -z "$KINE_PIN" ]; then
	echo "  could not read DefaultKineVersion out of pkg/executor/executor.go" >&2
	lint_ok=false
else
	# >=0.16.x. The superseded v1.14.x line is a higher NUMBER but older CODE (v1.14.2 =
	# 2025-09-24, v0.17.0 = 2026-08-26), so the check is on the v0.<minor> shape, not on a
	# naive version sort that would happily accept the pin this item exists to retire.
	case "$KINE_PIN" in
		v0.*)
			minor="$(printf '%s' "$KINE_PIN" | cut -d. -f2)"
			if [ "$minor" -lt 16 ]; then
				echo "  kine pin $KINE_PIN is below the v0.16 floor (kine#577 watch-progress)" >&2
				lint_ok=false
			fi
			;;
		*)
			echo "  kine pin $KINE_PIN is not a v0.x release — the orphan v1.14.x line is retired (B38)" >&2
			lint_ok=false
			;;
	esac
fi

# The child build must be CGO_ENABLED=0 (kine's pure-Go modernc.org/sqlite backend).
if ! grep -q 'CGO_ENABLED=0' "$EXEC_PKG/setup.go"; then
	echo "  ensureKineInto does not build kine with CGO_ENABLED=0" >&2
	lint_ok=false
fi
if grep -q '"CGO_ENABLED=1"' "$EXEC_PKG/setup.go"; then
	echo "  a CGO_ENABLED=1 child build survives in pkg/executor/setup.go" >&2
	lint_ok=false
fi
# The staging predicate must not be presence-only (the marker is what reaches a booted node).
if ! grep -q 'kineStaged(bd, kineVersion)' "$EXEC_PKG/setup.go"; then
	echo "  ensureKineInto no longer gates on the version marker (kineStaged)" >&2
	lint_ok=false
fi
# The startup-VACUUM opt-out must be on the shipped DSN.
if ! grep -q '_kine_disable_startup_vacuum' "$EXEC_PKG/datastore.go"; then
	echo "  the SQLite DSN does not disable kine's every-boot startup VACUUM" >&2
	lint_ok=false
fi
# The acceptance cluster harness must not stage a DIFFERENT kine than the product.
if grep -q 'KINE_VERSION:=v1.14.2' "$REPO_ROOT/hack/lib/clusterup.sh"; then
	echo "  hack/lib/clusterup.sh still pins the superseded kine — the m*.sh gates would run a different datastore" >&2
	lint_ok=false
fi

if $lint_ok; then
	ladder ok "b69.1  ONE kine pin ($KINE_PIN, >=0.16.x), CGO_ENABLED=0 child build, marker-gated staging, VACUUM opt-out"
else
	ladder no "b69.1  ONE kine pin (>=0.16.x), CGO_ENABLED=0 child build, marker-gated staging, VACUUM opt-out"
	echo "----------------------------------------"
	echo "B69: the lint leg is red — the compat legs below would measure the wrong build" >&2
	echo "B69: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- pre-flight: nothing left over from an EARLIER run -----------------------
# The same fail-closed shape bring-up has for a held datastore port, and for the same
# reason: an orphan is only diagnosable BEFORE anything else starts. After that, its
# held port and its half-written database surface as some unrelated downstream error.
PRE_ORPHANS="$(fixture_kine_pids)"
if [ -n "$PRE_ORPHANS" ]; then
	echo "----------------------------------------" >&2
	echo "B69: REFUSING to run — kine process(es) from an EARLIER run of these fixtures are still alive:" >&2
	name_pids "$PRE_ORPHANS"
	echo "B69: each holds a TCP port and a temp-dir datastore, and bring-up refuses a datastore port" >&2
	echo "B69: it finds held — so a later run fails for a reason that has nothing to do with it." >&2
	echo "B69: stop them by hand (kill $(echo "$PRE_ORPHANS" | tr "\n" " ")) and re-run." >&2
	echo "B69: this gate never kills a process it did not start: only the run that started one" >&2
	echo "B69: knows it is finished with it." >&2
	echo "B69: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- fixture: the two real kine binaries -------------------------------------
OLD_PIN="v1.14.2"
NEW_PIN="$KINE_PIN"
GOPATH_OLD="$WORK/gopath-old"; GOPATH_NEW="$WORK/gopath-new"

build_kine() { # build_kine <version> <cgo 0|1> <gopath> -> prints the binary path
	local ver="$1" cgo="$2" gp="$3"
	env CGO_ENABLED="$cgo" GOWORK=off GOBIN= GOPATH="$gp" \
		go install "github.com/k3s-io/kine@$ver" >"$gp.log" 2>&1 || return 1
	local built="$gp/bin/${GOOS}_${GOARCH}/kine"
	[ -x "$built" ] || built="$gp/bin/kine"
	[ -x "$built" ] || return 1
	printf '%s' "$built"
}

# run_test writes a `go test` run to a log and returns its exit status. It deliberately
# does NOT pipe into grep: under `set -o pipefail` a `grep -q` that matches early closes
# the pipe, SIGPIPEs the test, and turns a PASSING run into a failed pipeline — a
# false-RED that is indistinguishable from a real incompatibility, which is the one
# verdict this gate must never get wrong.
run_test() { # run_test <logfile> <go-test-args...>
	local log="$1"; shift
	( cd "$REPO_ROOT" && CGO_ENABLED=1 go test "$@" ) >"$log" 2>&1
}

echo "==> building the superseded pin ($OLD_PIN, CGO_ENABLED=1) — the migration fixture"
if ! KINE_OLD="$(build_kine "$OLD_PIN" 1 "$GOPATH_OLD")"; then
	echo "----------------------------------------" >&2
	echo "B69: could not build kine $OLD_PIN — the FORWARD/DOWNGRADE fixture cannot be created." >&2
	echo "B69: This pin has NO upstream git tag (the B38 provenance finding); it resolves ONLY" >&2
	echo "B69: through a module proxy that already carries it. Re-run with the public proxy" >&2
	echo "B69: reachable (GOPROXY=https://proxy.golang.org,direct) — GOPROXY=direct CANNOT" >&2
	echo "B69: resolve it, and no amount of retrying will change that." >&2
	echo "B69: go install output:" >&2
	tail -20 "$GOPATH_OLD.log" >&2 || true
	ladder no "b69.2  FORWARD: old-pin datastore served by the new pin"
	ladder no "b69.3  DOWNGRADE: new-pin datastore served by the old pin"
	echo "----------------------------------------"
	echo "B69: $PASS passed, $FAIL failed" >&2
	exit 1
fi

echo "==> building the target pin ($NEW_PIN, CGO_ENABLED=0) — the shipped build"
if ! KINE_NEW="$(build_kine "$NEW_PIN" 0 "$GOPATH_NEW")"; then
	echo "B69: could not build kine $NEW_PIN (CGO_ENABLED=0):" >&2
	tail -20 "$GOPATH_NEW.log" >&2 || true
	ladder no "b69.2  FORWARD: old-pin datastore served by the new pin"
	ladder no "b69.3  DOWNGRADE: new-pin datastore served by the old pin"
	echo "----------------------------------------"
	echo "B69: $PASS passed, $FAIL failed" >&2
	exit 1
fi
export K3SM_KINE_OLD="$KINE_OLD" K3SM_KINE_NEW="$KINE_NEW"
echo "    old: $KINE_OLD"
echo "    new: $KINE_NEW"

# ---- b69.2 — FORWARD ---------------------------------------------------------
# A HARD STOP, not just a red leg: a genuine forward incompatibility means the collapse
# must escalate to the phased additive cycle, and running the remaining legs would only
# bury that verdict under other output.
if run_test "$WORK/forward.log" -tags kinecompat ./pkg/executor/ -run TestKineCompatForward -count=1 -v \
		&& grep -q '^--- PASS: TestKineCompatForward' "$WORK/forward.log"; then
	ladder ok "b69.2  FORWARD: production-shaped old-pin datastore (churn + tombstones) round-trips on $NEW_PIN"
else
	ladder no "b69.2  FORWARD: production-shaped old-pin datastore round-trips on $NEW_PIN"
	echo "----------------------------------------" >&2
	echo "B69: FORWARD compatibility FAILED. If this is not a harness bug, the collapse HALTS:" >&2
	echo "B69: it escalates to the phased additive cycle (ADD -> dual-read -> CUT -> DROP)." >&2
	tail -40 "$WORK/forward.log" >&2 || true
	echo "----------------------------------------"
	echo "B69: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b69.3 — DOWNGRADE -------------------------------------------------------
if run_test "$WORK/downgrade.log" -tags kinecompat ./pkg/executor/ -run TestKineCompatDowngrade -count=1 -v \
		&& grep -q '^--- PASS: TestKineCompatDowngrade' "$WORK/downgrade.log"; then
	ladder ok "b69.3  DOWNGRADE: a $NEW_PIN-written+migrated datastore still round-trips on $OLD_PIN"
else
	ladder no "b69.3  DOWNGRADE: a $NEW_PIN-written+migrated datastore still round-trips on $OLD_PIN"
	tail -40 "$WORK/downgrade.log" >&2 || true
fi

# ---- b69.4 — SNAPSHOT --------------------------------------------------------
# The pre-migration backup: WAL drained (TRUNCATE, asserted), copy integrity-checked
# before it takes the final name, write-once across re-boots, old kine binary preserved,
# and the free-space floor REFUSING rather than half-writing.
if run_test "$WORK/snapshot.log" ./pkg/executor/ -run 'TestKineSnapshot|TestRecordKinePin' -count=1 -v \
		&& grep -q '^--- PASS: TestKineSnapshotDrainsWALAndVerifies' "$WORK/snapshot.log"; then
	snap_ok=true
	for want in TestKineSnapshotWriteOnce TestKineSnapshotSkips TestKineSnapshotFreeSpaceRefusal \
		TestKineSnapshotPreservesOldBinary TestKineSnapshotRequiresSQLite3 TestRecordKinePinRoundTrip; do
		grep -q "^--- PASS: $want" "$WORK/snapshot.log" || { echo "  $want did not pass" >&2; snap_ok=false; }
	done
	# Non-vacuity: a skipped fixture (no /usr/bin/sqlite3) must not read as a pass.
	if grep -q '^--- SKIP' "$WORK/snapshot.log"; then
		echo "  a snapshot test SKIPPED — the leg proves nothing" >&2
		snap_ok=false
	fi
	if $snap_ok; then
		ladder ok "b69.4  SNAPSHOT: WAL drained + copy integrity-checked + write-once + old kine preserved + free-space refusal"
	else
		ladder no "b69.4  SNAPSHOT: WAL drained + copy integrity-checked + write-once + old kine preserved + free-space refusal"
	fi
else
	ladder no "b69.4  SNAPSHOT: WAL drained + copy integrity-checked + write-once + old kine preserved + free-space refusal"
	tail -40 "$WORK/snapshot.log" >&2 || true
fi

# ---- b69.5 — DEP-LINT --------------------------------------------------------
# The whole point of the collapse: the unmaintained cgo mattn/go-sqlite3 is gone from
# every shipped artifact. Read the BUILT binary's module list, not the source.
mods="$(go version -m "$KINE_NEW" || true)"
dep_ok=true
if printf '%s' "$mods" | grep -q 'github.com/mattn/go-sqlite3'; then
	echo "  the shipped kine still links github.com/mattn/go-sqlite3" >&2
	dep_ok=false
fi
if ! printf '%s' "$mods" | grep -q 'modernc.org/sqlite'; then
	echo "  the shipped kine links no modernc.org/sqlite — it has NO SQLite backend" >&2
	dep_ok=false
fi
# ...and it must be gone from k3sm's own module graph too.
if (cd "$REPO_ROOT" && go list -deps ./... 2>/dev/null | grep -q 'github.com/mattn/go-sqlite3'); then
	echo "  k3sm itself imports github.com/mattn/go-sqlite3" >&2
	dep_ok=false
fi
if $dep_ok; then
	ladder ok "b69.5  DEP-LINT: the shipped kine links modernc.org/sqlite and NO mattn/go-sqlite3"
else
	ladder no "b69.5  DEP-LINT: the shipped kine links modernc.org/sqlite and NO mattn/go-sqlite3"
fi

# ---- b69.6 — MARKER ----------------------------------------------------------
# A real ensureKineInto over a stale staging: the binary is replaced by a fresh nocgo
# build and the marker records the pin + variant. This is the leg that proves the
# collapse REACHES a node that has already booted.
if run_test "$WORK/marker.log" -tags kinecompat ./pkg/executor/ -run TestEnsureKineIntoRestagesStaleMarker -count=1 -v -timeout 15m \
		&& grep -q '^--- PASS: TestEnsureKineIntoRestagesStaleMarker' "$WORK/marker.log"; then
	ladder ok "b69.6  MARKER: a stale/unmarked kine is re-staged; the new marker records $NEW_PIN nocgo"
else
	ladder no "b69.6  MARKER: a stale/unmarked kine is re-staged; the new marker records $NEW_PIN nocgo"
	tail -40 "$WORK/marker.log" >&2 || true
fi

# ---- b69.7 — REAP ------------------------------------------------------------
# Every kine the legs above started must be gone now. A leaked one holds its port and
# its temp-dir datastore for as long as the machine stays up, and bring-up refuses a
# datastore port it finds held — so one run's leftover becomes the next run's
# unexplained boot refusal, reported against a port nobody in that run chose.
#
# The pre-flight above already established that NO fixture-shaped kine was running when
# this gate started, so anything found here was started by this run. Nothing is killed:
# the gate reports what it found and leaves the decision to the human, exactly as the
# pre-flight does.
POST_ORPHANS="$(fixture_kine_pids)"
if [ -z "$POST_ORPHANS" ]; then
	ladder ok "b69.7  REAP: every kine the compat legs started was reaped with the test that started it"
else
	ladder no "b69.7  REAP: every kine the compat legs started was reaped with the test that started it"
	echo "  these outlived the test binary that spawned them:" >&2
	name_pids "$POST_ORPHANS"
	echo "  kill them by hand ($(echo "$POST_ORPHANS" | tr "\n" " ")); this gate does not reap what it cannot attribute" >&2
fi

echo "----------------------------------------"
echo "B69: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B69 GREEN ================"
