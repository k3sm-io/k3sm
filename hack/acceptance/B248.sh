#!/usr/bin/env bash
#
# k3sm B248 acceptance gate — the runnable proof that k3sm's data root can live
# on an APFS volume k3sm creates, bounds, mounts, migrates onto and destroys.
#
# The problem it closes: /var/lib/k3sm is a directory on the boot volume, so a
# cluster's images, volumes and datastore compete with the operator's disk for
# the same free space and are bounded by nothing. A k3sm-owned APFS volume with
# a quota gives the data root a ceiling that is enforced by the filesystem, a
# mount posture (nobrowse,nosuid,nodev) Finder and workloads cannot undo, and a
# lifecycle — create, adopt, mount at boot, migrate onto, delete — that is one
# code path (pkg/datavol) rather than a runbook.
#
# TWO TIERS, split by what a single Mac can prove without touching its disk:
#
#   CI TIER (always runs, CGO_ENABLED=1 — k3sm's posture) — the unit-provable
#   halves: the record and its precedence over /etc/fstab, the create/adopt
#   decision table, the idempotent mount, the fail-safe migration, the delete
#   refusals and ordering, the install sequencing, the status rows, the CLI.
#   Plus the structural pins that a later edit would quietly undo: the daemon
#   label and its position in the artifact manifest, the mount-option literal,
#   the refusal text that names the repair command.
#
#   LAB TIER (K3SM_LAB=1, ONE Mac, root) — the only tier that can prove the
#   thing the feature is about: a real APFS volume. It creates its own small
#   scratch volumes under /Library/k3sm-acceptance-datavol/ and destroys them
#   again. It NEVER touches /var/lib/k3sm, /Library/k3sm or /etc/fstab — the
#   rig's real data volume, its record and its fstab line are out of scope by
#   construction, and the helper it drives refuses any path outside the scratch
#   root before it does any disk work. Announced LAB-PENDING when K3SM_LAB is
#   unset; never silently passed.
#
# Usage:  hack/acceptance/B248.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B248.sh # + the one-Mac lab tier (root; prompts for sudo)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B248.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
lab_pending() { echo "LAB-PENDING  $1"; }

echo "==> k3sm B248 acceptance (the data root on a k3sm-owned APFS volume)"

# ---- b248.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$K3SM_ROOT/pkg/datavol/seams.go" ] || b0=no
[ -f "$K3SM_ROOT/cmd/k3sm/datavol.go" ] || b0=no
[ -f "$K3SM_ROOT/hack/acceptance/b248helper/main.go" ] || b0=no
ladder "$b0" "b248.0  gate parses (bash -n) + pkg/datavol/seams.go + cmd/k3sm/datavol.go + b248helper present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B248: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B248: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b248.1 — the WIRING, read straight out of the source ------------------
# Six properties no unit test can pin, because each is a fact about where a
# literal or a line lives rather than about a function's behaviour.
w=ok
grep -qE 'DatavolLabel[[:space:]]*=[[:space:]]*"io\.k3sm\.datavol"' "$K3SM_ROOT/pkg/install/install.go" || w=no
grep -qE '^[[:space:]]*case DatavolLabel:' "$K3SM_ROOT/pkg/install/install.go" || w=no
grep -q 'SuccessfulExit' "$K3SM_ROOT/pkg/install/install.go" || w=no
ladder "$w" "b248.1  io.k3sm.datavol is a labelled daemon with a plistContent case and a KeepAlive SuccessfulExit dict"

# The mount daemon must be TORN DOWN LAST and BROUGHT UP FIRST, which the
# manifest expresses as an ordering: the data volume carries everything netd and
# the server write, so a manifest that put netd first would unmount the volume
# out from under the daemons still using it.
o=ok
dv_line="$(grep -nE 'label: DatavolLabel' "$K3SM_ROOT/pkg/install/install.go" | head -1 | cut -d: -f1)"
nd_line="$(grep -nE 'label: NetdLabel' "$K3SM_ROOT/pkg/install/install.go" | head -1 | cut -d: -f1)"
if [ -z "$dv_line" ] || [ -z "$nd_line" ] || [ "$dv_line" -ge "$nd_line" ]; then o=no; fi
ladder "$o" "b248.1  the datavol artifact precedes the netd artifact in artifactManifest (lines ${dv_line:-?} < ${nd_line:-?})"

r=ok
grep -A4 'func Refusal' "$K3SM_ROOT/pkg/dataroot/dataroot.go" | grep -q 'k3sm datavol mount' || r=no
grep -q '/Library/Preferences/io\.k3sm\.datavol\.json' "$K3SM_ROOT/pkg/dataroot/record.go" || r=no
ladder "$r" "b248.1  the shadowed-root refusal names \`sudo k3sm datavol mount\` + the record path literal is pkg/dataroot's"

# The helper is a `go run` tool in hack/, deliberately NOT hidden verbs on the
# shipped binary: a privileged create/migrate primitive reachable from the
# product's argv is a primitive an operator can reach by accident.
h=ok
if grep -rq '_ensure\|_migrate' "$K3SM_ROOT/cmd/"; then h=no; fi
ladder "$h" "b248.1  no hidden _ensure/_migrate verb leaked into cmd/ (the gate drives pkg/datavol through hack/acceptance/b248helper)"

m=ok
grep -q 'nobrowse,nosuid,nodev' "$K3SM_ROOT/pkg/datavol/seams.go" || m=no
grep -q '"crypto/rand"' "$K3SM_ROOT/pkg/datavol/ensure.go" || m=no
ladder "$m" "b248.1  MountOptions is the one nobrowse,nosuid,nodev literal + the passphrase comes from crypto/rand"

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

# ---- b248.2 — the declaration: the record and its precedence ---------------
run_test "b248.2" 7 TestReadDeclaresFromRecord ./pkg/dataroot/ "$K3SM_ROOT" 1

# ---- b248.3 — pkg/datavol: the volume lifecycle ----------------------------
# TestEnsureCreatesOrAdopts is the leg that matters most: it is the decision
# table for "is this volume k3sm's", and every wrong answer in it either adopts
# a stranger's volume or creates a second one over a live data root.
run_test "b248.3" 17 TestEnsureCreatesOrAdopts ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 7 TestMountRecordedIsIdempotent ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 3 TestMountRecordedRefuses ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 9 TestMigrateFailsSafe ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 5 TestEnsureFstabLine ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 4 TestRemoveFstabLine ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 8 TestDeleteRefuses ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 6 TestDeleteSequence ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 14 TestParseSize ./pkg/datavol/ "$K3SM_ROOT" 1
run_test "b248.3" 7 TestPlistDictReader ./pkg/datavol/ "$K3SM_ROOT" 1

# ---- b248.4 — pkg/install: the sequencing -----------------------------------
run_test "b248.4" 6 TestInstallWithDataVolumeSequencing ./pkg/install/ "$K3SM_ROOT" 1
run_test "b248.4" 0 TestDatavolPlist ./pkg/install/ "$K3SM_ROOT" 1

# ---- b248.5 — pkg/status and the CLI ---------------------------------------
run_test "b248.5" 8 TestDataRootRowNamesVolume ./pkg/status/ "$K3SM_ROOT" 1
run_test "b248.5" 4 TestInstallRowCountsDatavolPlist ./pkg/status/ "$K3SM_ROOT" 1
run_test "b248.5" 5 TestOneshotRow ./pkg/status/ "$K3SM_ROOT" 1
run_test "b248.5" 6 TestInstallFlagsDataVolume ./cmd/k3sm/ "$K3SM_ROOT" 1
run_test "b248.5" 3 TestDatavolStatusJSONShape ./cmd/k3sm/ "$K3SM_ROOT" 1
run_test "b248.5" 4 TestDatavolStatusUsedSource ./cmd/k3sm/ "$K3SM_ROOT" 1

# ---- b248.6 — the packages are formatted and vet-clean ---------------------
DATAVOL_PKGS="./pkg/dataroot/... ./pkg/datavol/... ./pkg/install/... ./pkg/status/... ./cmd/k3sm/... ./hack/acceptance/b248helper/..."
f=ok
unformatted="$(cd "$K3SM_ROOT" && gofmt -l pkg/dataroot pkg/datavol pkg/install pkg/status cmd/k3sm hack/acceptance/b248helper 2>&1 || true)"
[ -z "$unformatted" ] || { printf '%s\n' "$unformatted"; f=no; }
ladder "$f" "b248.6  gofmt -l is empty over the data-volume packages"

v=ok
vetout="$(cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=1 go vet $DATAVOL_PKGS 2>&1)" || v=no
[ "$v" = ok ] || printf '%s\n' "$vetout" | tail -20
ladder "$v" "b248.6  go vet is clean over the data-volume packages (CGO_ENABLED=1)"

# ============================================================================
# LAB TIER — ONE MAC, ROOT, REAL APFS VOLUMES (K3SM_LAB=1).
# ============================================================================
SCRATCH_ROOT=/Library/k3sm-acceptance-datavol

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B248 LAB tier (ONE Mac, root; set K3SM_LAB=1 to run — it creates and destroys real APFS volumes under $SCRATCH_ROOT):"
	lab_pending "b248.L0  the boot APFS container is discoverable and has >= 4 GiB free"
	lab_pending "b248.L1  a created volume is case-sensitive APFS, quota-capped, mounted nobrowse,nosuid,nodev, un-indexed and Time-Machine-excluded"
	lab_pending "b248.L2  statfs reports the quota, a 1 GiB write lands on the volume, and a write past the cap fails with ENOSPC"
	lab_pending "b248.L3  after an unmount, \`k3sm datavol mount --record\` remounts it and hands it to _k3sm"
	lab_pending "b248.L4  an encrypted volume's passphrase is in the System keychain and \`datavol mount\` unlocks a locked volume"
	lab_pending "b248.L5  \`k3sm datavol delete --yes\` destroys the volume, the record, the mount point and the keychain item"
	lab_pending "b248.L6  a plain data root migrates onto a volume with every file and the datastore's bytes intact, leaving .pre-volume behind"
	echo
	echo "  It runs on ONE Mac and needs root. Nothing it touches is the rig's: every"
	echo "  path lives under $SCRATCH_ROOT, and /var/lib/k3sm, /Library/k3sm and"
	echo "  /etc/fstab are never read or written (the helper refuses any other path)."
else
	echo "----------------------------------------"
	echo "B248 LAB tier: creating real APFS volumes under $SCRATCH_ROOT (root; each step prompts sudo as needed)"

	GATE_DIR="$SCRATCH_ROOT/gate-$$"
	MP="$GATE_DIR/mnt"
	REC="$GATE_DIR/record.json"
	MP_E="$GATE_DIR/mnt-e"
	REC_E="$GATE_DIR/record-e.json"
	SRC="$GATE_DIR/src"
	REC_M="$GATE_DIR/record-m.json"
	STAGING="$GATE_DIR/staging"
	K3SM_BIN="$GATE_DIR/k3sm"
	VOL="k3sm-gate-$$"
	VOL_E="k3sm-gate-${$}e"
	VOL_M="k3sm-gate-${$}m"
	GO_BIN="$(command -v go)"
	GOWORK_FILE="${GOWORK:-$(go env GOWORK)}"
	CREATED_UUIDS=""

	# Registered BEFORE the first mutation. It unmounts and destroys every
	# volume this run created (by UUID, and by name for one that was created
	# but whose UUID never reached us), drops the keychain items, and removes
	# the scratch tree. It never names a path outside $SCRATCH_ROOT.
	cleanup() {
		echo "--- b248 cleanup: removing this run's volumes, records and directories"
		for u in $CREATED_UUIDS; do
			sudo diskutil unmount force "$u" >/dev/null 2>&1 || true
			sudo diskutil apfs deleteVolume "$u" >/dev/null 2>&1 || true
			sudo security delete-generic-password -s "$u" /Library/Keychains/System.keychain >/dev/null 2>&1 || true
		done
		for n in "$VOL" "$VOL_E" "$VOL_M"; do
			sudo diskutil unmount force "$n" >/dev/null 2>&1 || true
			sudo diskutil apfs deleteVolume "$n" >/dev/null 2>&1 || true
		done
		for d in "$MP" "$MP_E" "$SRC" "$STAGING"; do
			sudo diskutil unmount force "$d" >/dev/null 2>&1 || true
		done
		sudo rm -rf "$GATE_DIR"
	}
	trap cleanup EXIT

	# helper_uuid <verb> <args...> — runs b248helper under sudo with the
	# toolchain environment passed through explicitly (sudo drops it), echoes
	# its output, and records the UUID it printed so cleanup can destroy the
	# volume even if a later rung fails.
	HELPER_OUT=""
	HELPER_UUID=""
	helper() {
		local rc=0
		HELPER_OUT="$(cd "$K3SM_ROOT" && sudo env GOWORK="$GOWORK_FILE" GOARCH=arm64 CGO_ENABLED=1 \
			"$GO_BIN" run ./hack/acceptance/b248helper "$@" 2>&1)" || rc=$?
		printf '%s\n' "$HELPER_OUT" | sed 's/^/    | /'
		HELPER_UUID="$(printf '%s\n' "$HELPER_OUT" | sed -n 's/^uuid=//p' | head -1)"
		if [ -n "$HELPER_UUID" ]; then CREATED_UUIDS="$CREATED_UUIDS $HELPER_UUID"; fi
		return $rc
	}

	# plist_volume <key> <uuid> — one volume's field from the container listing.
	plist_volume() {
		diskutil apfs list -plist "$CONTAINER" | plutil -convert json -o - - | python3 -c '
import json,sys
key,want=sys.argv[1],sys.argv[2].upper()
for c in json.load(sys.stdin).get("Containers",[]):
    for v in c.get("Volumes",[]):
        if str(v.get("APFSVolumeUUID","")).upper()==want:
            print(v.get(key,"")); raise SystemExit(0)
raise SystemExit(1)' "$1" "$2"
	}

	# mountedAt <dir> — a mount point is a directory whose device differs from
	# its parent's. The one test that survives macOS printing resolved paths.
	mountedAt() { [ "$(stat -f %d "$1" 2>/dev/null)" != "$(stat -f %d "$(dirname "$1")" 2>/dev/null)" ]; }

	# json_field <dotted.path> — one number out of `datavol status -o json`, on
	# stdin. A missing key reads 0 so a malformed report reddens the rung below
	# rather than aborting the gate on an integer compare.
	json_field() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d.get(k) if isinstance(d, dict) else None
print(d if isinstance(d, int) else 0)' "$1"; }

	# ---- b248.L0 — the rig can host the tier at all ------------------------
	# A missing diskutil or a full container is a HARD FAIL, never a skip: a
	# green B248 that quietly ran no lab rung would mean "B248 was not checked".
	CONTAINER=""
	FREE=0
	l0=ok
	command -v diskutil >/dev/null 2>&1 || l0=no
	command -v python3 >/dev/null 2>&1 || l0=no
	if [ "$l0" = ok ]; then
		CONTAINER="$(diskutil info -plist / | plutil -extract APFSContainerReference raw -o - - 2>/dev/null || true)"
		[ -n "$CONTAINER" ] || l0=no
	fi
	if [ "$l0" = ok ]; then
		FREE="$(diskutil apfs list -plist "$CONTAINER" | plutil -extract Containers.0.CapacityFree raw -o - - 2>/dev/null || echo 0)"
		[ "$FREE" -ge $((4 * 1024 * 1024 * 1024)) ] || l0=no
	fi
	ladder "$l0" "b248.L0  boot APFS container ${CONTAINER:-<unknown>} has $FREE bytes free (>= 4 GiB) and diskutil/python3 are present"
	if [ "$l0" != ok ]; then
		echo "----------------------------------------"
		echo "B248: the lab tier cannot run on this Mac (no diskutil/python3, or < 4 GiB free) — nothing below was checked" >&2
		echo "B248: $PASS passed, $FAIL failed" >&2
		exit 1
	fi

	sudo mkdir -p "$GATE_DIR"

	# The lane's own binary, built to the scratch tree. Every `k3sm datavol`
	# rung below runs THIS build, never whatever is installed at /usr/local/bin.
	b=ok
	BUILD_TMP="$(mktemp -d)"
	(cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=1 go build -o "$BUILD_TMP/k3sm" ./cmd/k3sm) || b=no
	if [ "$b" = ok ]; then sudo cp "$BUILD_TMP/k3sm" "$K3SM_BIN" || b=no; fi
	rm -rf "$BUILD_TMP"
	ladder "$b" "b248.Lb  the lane's cmd/k3sm builds and is staged at $K3SM_BIN"

	# ---- b248.L1 — a created volume has every property k3sm claims ---------
	QUOTA=$((2 * 1024 * 1024 * 1024))
	l1=ok
	helper ensure --name "$VOL" --size 2g --mountpoint "$MP" --record "$REC" || l1=no
	UUID="$HELPER_UUID"
	[ -n "$UUID" ] || l1=no
	if [ "$l1" = ok ]; then
		fsname="$(diskutil info -plist "$UUID" | plutil -extract FilesystemName raw -o - - 2>/dev/null || true)"
		[ "$fsname" = "Case-sensitive APFS" ] || { echo "    FilesystemName=$fsname"; l1=no; }
		gotquota="$(plist_volume CapacityQuota "$UUID" 2>/dev/null || echo 0)"
		[ "$gotquota" = "$QUOTA" ] || { echo "    CapacityQuota=$gotquota want $QUOTA"; l1=no; }
		mountline="$(mount | grep -F " on $MP " || true)"
		for opt in nobrowse nosuid nodev; do
			printf '%s' "$mountline" | grep -q "$opt" || { echo "    mount line lacks $opt: $mountline"; l1=no; }
		done
		# The scratch mount point is root-owned 0700, so both of these answer
		# [UNKNOWN] / "invalid path" when run unprivileged — they are asked as
		# root, which is also how the installer asks them.
		sudo test -f "$MP/.metadata_never_index" || { echo "    no .metadata_never_index marker"; l1=no; }
		md="$(sudo mdutil -s "$MP" 2>&1 || true)"
		printf '%s' "$md" | grep -qiE 'indexing disabled|unknown indexing state' || { echo "    mdutil -s: $md"; l1=no; }
		# A nobrowse volume is not tracked by Spotlight at all, so "unknown
		# indexing state" and "Indexing disabled" both mean not indexed.
		tm="$(sudo tmutil isexcluded "$MP" 2>&1 || true)"
		printf '%s' "$tm" | grep -q '\[Excluded\]' || { echo "    tmutil isexcluded: $tm"; l1=no; }
	fi
	ladder "$l1" "b248.L1  $VOL is case-sensitive APFS, quota $QUOTA, mounted nobrowse/nosuid/nodev at $MP, un-indexed and TM-excluded"

	# ---- b248.L2 — the quota is real, and it bounds THIS volume ------------
	l2=ok
	st_json="$(sudo "$K3SM_BIN" datavol status --record "$REC" -o json 2>&1)" || l2=no
	if [ "$l2" = ok ]; then
		total="$(printf '%s' "$st_json" | json_field statfs.totalBytes)"
		if [ "$total" -gt $((QUOTA + 64 * 1024 * 1024)) ]; then
			echo "    statfs.totalBytes=$total exceeds the quota by more than 64 MiB"; l2=no
		fi
		avail_before="$(printf '%s' "$st_json" | json_field statfs.availBytes)"
		boot_used_before="$(df -k / | awk 'NR==2 {print $3}')"
		boot_avail_before="$(df -k / | awk 'NR==2 {print $4}')"
		sudo dd if=/dev/zero of="$MP/fill" bs=1m count=1024 status=none 2>/dev/null || { echo "    the 1 GiB write failed"; l2=no; }
		avail_after="$(sudo "$K3SM_BIN" datavol status --record "$REC" -o json | json_field statfs.availBytes)"
		boot_used_after="$(df -k / | awk 'NR==2 {print $3}')"
		boot_avail_after="$(df -k / | awk 'NR==2 {print $4}')"
		dropped=$((avail_before - avail_after))
		[ "$dropped" -ge $((1024 * 1024 * 1024)) ] || { echo "    the volume's availBytes fell by only $dropped"; l2=no; }
		# The BOOT VOLUME'S OWN USAGE is what must not move: an APFS volume's
		# bytes come out of the shared container, so `df /`'s AVAILABLE column
		# necessarily follows this write down (it reports container free space).
		# Used is the discriminator — it is per-volume, and the whole claim is
		# that the gigabyte landed on the data volume and not on the system one.
		boot_used_delta=$(((boot_used_after - boot_used_before) * 1024))
		[ "${boot_used_delta#-}" -lt $((256 * 1024 * 1024)) ] || { echo "    the boot volume's used bytes moved by $boot_used_delta"; l2=no; }
		echo "    NOTE  df / avail went $boot_avail_before KiB -> $boot_avail_after KiB (shared container free space, expected to follow the write)"
		# Past the cap: the quota is enforced by the filesystem, not by k3sm.
		dd_err="$(sudo dd if=/dev/zero of="$MP/overflow" bs=1m count=2048 2>&1 >/dev/null || true)"
		printf '%s' "$dd_err" | grep -q 'No space left on device' || { echo "    a write past the cap did not report ENOSPC: $dd_err"; l2=no; }
		sudo rm -f "$MP/fill" "$MP/overflow"
	fi
	ladder "$l2" "b248.L2  statfs reports the quota, a 1 GiB write lands on the volume, and a write past the cap fails with ENOSPC"

	# ---- b248.L3 — the mount verb is the boot path -------------------------
	l3=ok
	sudo diskutil unmount "$MP" >/dev/null 2>&1 || { echo "    could not unmount $MP"; l3=no; }
	if mountedAt "$MP"; then echo "    $MP is still a mount point after the unmount"; l3=no; fi
	sudo "$K3SM_BIN" datavol mount --record "$REC" || { echo "    k3sm datavol mount failed"; l3=no; }
	mountedAt "$MP" || { echo "    $MP is not a mount point after k3sm datavol mount"; l3=no; }
	if id -u _k3sm >/dev/null 2>&1; then
		owner="$(stat -f %Su "$MP" 2>/dev/null || true)"
		[ "$owner" = "_k3sm" ] || { echo "    $MP is owned by ${owner:-<unknown>}, want _k3sm"; l3=no; }
	else
		echo "    NOTE  the _k3sm service user does not exist on this Mac; the ownership assertion is skipped"
	fi
	ladder "$l3" "b248.L3  after an unmount, \`k3sm datavol mount --record\` remounts $MP by device id and hands it to _k3sm"

	# ---- b248.L4 — encryption: the keychain holds the only copy ------------
	l4=ok
	helper ensure --name "$VOL_E" --size 2g --mountpoint "$MP_E" --record "$REC_E" --encrypt || l4=no
	UUID_E="$HELPER_UUID"
	[ -n "$UUID_E" ] || l4=no
	if [ "$l4" = ok ]; then
		sudo security find-generic-password -s "$UUID_E" /Library/Keychains/System.keychain >/dev/null 2>&1 || { echo "    no System-keychain item for $UUID_E"; l4=no; }
		sudo diskutil unmount "$MP_E" >/dev/null 2>&1 || { echo "    could not unmount $MP_E"; l4=no; }
		# Unmounting an encrypted APFS volume locks it on macOS 26 (proven on the
		# rig: lockVolume afterwards answers "already locked" and exits 1), so the
		# explicit lock is best-effort and the Locked= read below is the assertion.
		sudo diskutil apfs lockVolume "$UUID_E" >/dev/null 2>&1 || true
		locked="$(diskutil info -plist "$UUID_E" | plutil -extract Locked raw -o - - 2>/dev/null || true)"
		[ "$locked" = "true" ] || { echo "    Locked=$locked after apfs lockVolume"; l4=no; }
		sudo "$K3SM_BIN" datavol mount --record "$REC_E" || { echo "    k3sm datavol mount did not unlock and mount $UUID_E"; l4=no; }
		mountedAt "$MP_E" || { echo "    $MP_E is not a mount point after the unlock"; l4=no; }
	fi
	ladder "$l4" "b248.L4  an encrypted volume's passphrase lives in the System keychain and \`datavol mount\` unlocks a locked volume"

	# ---- b248.L5 — delete removes every trace ------------------------------
	l5=ok
	sudo "$K3SM_BIN" datavol delete --yes --record "$REC" || { echo "    delete failed for $REC"; l5=no; }
	sudo "$K3SM_BIN" datavol delete --yes --record "$REC_E" || { echo "    delete failed for $REC_E"; l5=no; }
	for u in "$UUID" "$UUID_E"; do
		if diskutil info "$u" >/dev/null 2>&1; then echo "    volume $u survived the delete"; l5=no; fi
	done
	for f in "$REC" "$REC_E"; do
		if sudo test -e "$f"; then echo "    record $f survived the delete"; l5=no; fi
	done
	for d in "$MP" "$MP_E"; do
		if sudo test -e "$d"; then echo "    mount point $d survived the delete"; l5=no; fi
	done
	if sudo security find-generic-password -s "$UUID_E" /Library/Keychains/System.keychain >/dev/null 2>&1; then
		echo "    the keychain item for $UUID_E survived the delete"; l5=no
	fi
	ladder "$l5" "b248.L5  \`k3sm datavol delete --yes\` destroyed both volumes, their records, their mount points and the keychain item"

	# ---- b248.L6 — the migration carries the datastore across --------------
	# 200 files, one of them the kine datastore: Migrate verifies counts, sizes,
	# modes and ownership for the tree and the sha256 of server/db/state.db, so
	# the rung asserts the same two facts from outside the code under test.
	l6=ok
	sudo /bin/bash -c 'set -e; src="$1"; mkdir -p "$src/server/db"
		for i in $(seq 1 199); do printf "b248 fixture file %s\n" "$i" > "$src/f$i.txt"; done
		dd if=/dev/urandom of="$src/server/db/state.db" bs=1024 count=64 status=none' _ "$SRC" || l6=no
	want_sha="$(sudo shasum -a 256 "$SRC/server/db/state.db" | awk '{print $1}')"
	want_files="$(sudo find "$SRC" -type f | wc -l | tr -d ' ')"
	helper migrate --name "$VOL_M" --size 2g --from "$SRC" --record "$REC_M" --staging "$STAGING" || l6=no
	stats_line="$(printf '%s\n' "$HELPER_OUT" | grep -E '^files=' | head -1 || true)"
	if [ "$l6" = ok ]; then
		mountedAt "$SRC" || { echo "    $SRC is not a mount point after the migration"; l6=no; }
		sudo test -d "$SRC.pre-volume" || { echo "    $SRC.pre-volume is missing — the old data root was not preserved"; l6=no; }
		# The migrated tree is now a mounted volume, and macOS puts .Trashes,
		# .fseventsd and friends at its root; .Trashes is unreadable even by
		# root (EPERM), which under set -e would abort the gate mid-rung. Prune
		# the metadata entries the product's verify walk also ignores.
		got_files="$(sudo find "$SRC" \( -name .Trashes -o -name .fseventsd -o -name .Spotlight-V100 -o -name .TemporaryItems -o -name .DocumentRevisions-V100 \) -prune -o -type f ! -name .k3sm-datavol ! -name .metadata_never_index ! -name .DS_Store -print 2>/dev/null | wc -l | tr -d ' ')"
		[ "$got_files" = "$want_files" ] || { echo "    $got_files files on the volume, $want_files at the source"; l6=no; }
		got_sha="$(sudo shasum -a 256 "$SRC/server/db/state.db" | awk '{print $1}')"
		[ "$got_sha" = "$want_sha" ] || { echo "    state.db hashes $got_sha on the volume, $want_sha at the source"; l6=no; }
		printf '%s' "$stats_line" | grep -q 'copy=' || { echo "    the stats line does not name a copy duration: $stats_line"; l6=no; }
		printf '%s' "$stats_line" | grep -q 'verify=' || { echo "    the stats line does not name a verify duration: $stats_line"; l6=no; }
	fi
	ladder "$l6" "b248.L6  $want_files files and the datastore's bytes migrated onto $VOL_M, .pre-volume preserved ($stats_line)"

	trap - EXIT
	cleanup
fi

echo "----------------------------------------"
echo "B248: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ B248 GREEN (CI + lab tiers) ================"
else
	echo "================ B248 GREEN (CI tier; the lab tier needs K3SM_LAB=1 and root) ================"
fi
