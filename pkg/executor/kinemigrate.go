/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The pre-migration datastore snapshot.
//
// Moving an existing single-node state.db from one kine pin to another is a ONE-WAY
// operation in the general case: the new pin re-runs its schema migrations against the
// existing tables, and nothing undoes that. The mitigation is not a promise that the
// downgrade works — it is a verified copy of the database as it was, taken while the
// control plane is stopped, before the new pin has opened it once.
//
// The window this runs in is what makes a plain file copy sound: provision() runs before
// bringUp() starts kine, so there is no writer. The only reason a copy could still be
// short is SQLite's WAL — committed transactions can live entirely in state.db-wal, and
// a copy of state.db alone would silently omit them. So the WAL is drained with a
// TRUNCATE checkpoint first, and the drain is ASSERTED, not assumed.
//
// Ordering rules this file depends on, both enforced by the call site in provision():
//   - it runs BEFORE seedBinDir and ensureKine, which are exactly the two steps that
//     replace the old kine binary the rollback path needs;
//   - the pin stamp is written only AFTER kine has come up healthy on the new pin
//     (recordKinePin from bringUp), so a boot that dies before kine serves does not
//     record a migration that did not happen, and the next boot still snapshots.

// sqlite3Bin is the macOS-bundled SQLite CLI. k3sm deliberately links NO SQLite driver
// of its own: adding one (cgo mattn/go-sqlite3, or the ~5MB pure-Go modernc.org/sqlite)
// to a k3sm.io module is precisely the dependency this whole change removes, and
// `k3sm doctor` already reads datastore posture without one. The two PRAGMAs this file
// runs are the only SQLite k3sm itself ever needs, they run once per pin change, and
// macOS has shipped this binary for the life of the platform. It is REQUIRED, not
// optional: without it the WAL drain cannot be performed or verified, and an
// unverifiable backup is worse than a refusal.
//
// It is a var only so the fail-closed behaviour on a host WITHOUT it is testable; no
// production path reassigns it.
var sqlite3Bin = "/usr/bin/sqlite3"

const (
	// snapshotFreeSpaceFactor is the multiple of the live database size that must be
	// free before a snapshot is attempted. The copy itself needs 1x; the extra 1x is
	// the margin for the checkpointed pages, the new pin's own startup writes, and the
	// fact that this volume is shared with the image store, pod dirs, and PV data.
	snapshotFreeSpaceFactor = 2
	// kinePinStampName is the basename of the marker recording which kine pin last
	// OPENED this datastore successfully. It sits beside state.db (not in bin/) because
	// it describes the database, not the binary — moving the work dir's db elsewhere
	// takes its provenance with it.
	kinePinStampName = "state.db.kine-pin"
)

// ErrKineSnapshotSpace is returned when the volume holding the datastore does not have
// snapshotFreeSpaceFactor x the database size free. It is a REFUSAL, not a warning: a
// half-written backup on a full volume is the worst of both outcomes, and the operator
// can free space and re-run the boot with nothing lost.
var ErrKineSnapshotSpace = errors.New("executor: not enough free space for the pre-migration datastore snapshot")

// ErrKineSnapshotWAL is returned when the write-ahead log is still non-empty after a
// TRUNCATE checkpoint. Copying then would omit committed writes, so the boot stops.
var ErrKineSnapshotWAL = errors.New("executor: datastore WAL was not drained by the TRUNCATE checkpoint")

// kinePinStampPath names the pin stamp for a work dir.
func kinePinStampPath(workDir string) string {
	return filepath.Join(dbDir(workDir), kinePinStampName)
}

// kineBackupPath names the pre-migration backup for a target pin, e.g.
// <workdir>/db/state.db.pre-v0.17.0.bak. It is per-target on purpose: a node that
// migrates twice keeps one verified backup per pin it left behind.
func kineBackupPath(workDir, targetVersion string) string {
	return StateDBPath(workDir) + ".pre-" + targetVersion + ".bak"
}

// kineBinaryBackupPath names the preserved old kine binary, kept beside the backup it
// belongs with. Rebuilding a superseded pin is NOT guaranteed — the previous pin
// (v1.14.2) has no corresponding upstream tag and resolves only from a warmed module
// proxy — so the rollback path preserves the bytes rather than assuming they can be
// rebuilt.
func kineBinaryBackupPath(workDir, targetVersion string) string {
	return filepath.Join(dbDir(workDir), kineBinaryName+".pre-"+targetVersion)
}

// readKinePin returns the kine (version, variant) that last opened this datastore
// successfully. ok is false when no stamp exists — which is the state of EVERY
// datastore created before stamping existed, and is deliberately read as "an older
// pin", not as "unknown, carry on".
func readKinePin(workDir string) (version, variant string, ok bool) {
	b, err := os.ReadFile(kinePinStampPath(workDir))
	if err != nil {
		return "", "", false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return "", "", false
	}
	if len(f) == 1 {
		return f[0], "", true
	}
	return f[0], f[1], true
}

// recordKinePin stamps the datastore with the pin that just opened it. Called from
// bringUp AFTER kine is serving, so the stamp means "this pin has successfully opened
// this database", not "we intended to run this pin".
func recordKinePin(workDir, version string) error {
	if _, err := os.Stat(StateDBPath(workDir)); err != nil {
		return nil // no SQLite datastore here (Postgres posture, or nothing written yet)
	}
	path := kinePinStampPath(workDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(kineMarkerContent(version)), 0o600); err != nil {
		return fmt.Errorf("write kine pin stamp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("install kine pin stamp: %w", err)
	}
	return nil
}

// snapshotBeforeKineUpgrade takes the verified pre-migration backup when this boot is
// about to open an EXISTING datastore with a kine pin that has not opened it before.
//
// The detection is deliberately coarse and fails toward taking a backup:
//
//	no state.db                      -> nothing to protect (fresh node)   -> skip
//	stamp says targetVersion         -> this pin already opened it        -> skip
//	backup for targetVersion exists  -> already taken AND verified        -> skip
//	otherwise (incl. NO stamp)       -> an older pin wrote this database  -> snapshot
//
// The "no stamp" case is the installed base: every k3sm before this change wrote no
// stamp, so its databases are correctly treated as pre-migration. The cost of the
// false positive (a database that happens to already be fine) is one verified copy.
//
// The backup is write-once by final name, and that is sound BECAUSE of the rename:
// the copy is built at a .tmp name, integrity-checked there, and only then renamed, so
// the final name existing IMPLIES a complete, verified file. A launchd crash-respawn
// loop therefore cannot overwrite a good backup with a partial one, nor with a copy of
// a database the new pin has since migrated.
func snapshotBeforeKineUpgrade(ctx context.Context, logger *slog.Logger, workDir, targetVersion string) error {
	db := StateDBPath(workDir)
	fi, err := os.Stat(db)
	if err != nil {
		return nil // fresh node — born on the target pin, nothing to migrate
	}
	if v, _, ok := readKinePin(workDir); ok && v == targetVersion {
		return nil
	}
	backup := kineBackupPath(workDir, targetVersion)
	if _, err := os.Stat(backup); err == nil {
		return nil // exists => complete and integrity-checked (see the rename below)
	}

	prev, _, _ := readKinePin(workDir)
	if prev == "" {
		prev = "unstamped (pre-migration k3sm)"
	}
	logger.Info("datastore kine pin changed; taking a verified pre-migration snapshot",
		"previous", prev, "target", targetVersion, "db", db, "backup", backup)

	// 1. Free-space floor, before anything is written.
	if err := requireFreeSpace(dbDir(workDir), uint64(fi.Size())*snapshotFreeSpaceFactor); err != nil {
		return err
	}
	// 2. Drain the WAL into the main database, and PROVE it drained.
	if err := checkpointTruncate(ctx, db); err != nil {
		return err
	}
	if err := requireWALDrained(db); err != nil {
		return err
	}
	// 3. Copy -> integrity-check the copy -> atomic rename.
	tmp := backup + ".tmp"
	_ = os.Remove(tmp)
	if err := copyFile(db, tmp, 0o600); err != nil {
		return fmt.Errorf("copy datastore for pre-migration snapshot: %w", err)
	}
	if err := integrityCheck(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, backup); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install pre-migration snapshot %s: %w", backup, err)
	}
	// 4. Preserve the kine binary that wrote this database. Restoring the backup is
	//    only half a rollback if the binary that can read it no longer exists.
	if err := preserveKineBinary(workDir, targetVersion); err != nil {
		return err
	}
	logger.Info("pre-migration datastore snapshot complete", "backup", backup,
		"kine-binary", kineBinaryBackupPath(workDir, targetVersion))
	return nil
}

// preserveKineBinary copies the currently staged kine binary (the OLD pin's, since this
// runs before ensureKine re-stages) beside the backup. A missing binary is not an error:
// a node whose workdir bin was cleared has nothing to preserve, and that must not stop a
// boot whose datastore backup already succeeded.
func preserveKineBinary(workDir, targetVersion string) error {
	src := kinePath(binDir(workDir))
	if !fileExists(src) {
		return nil
	}
	dst := kineBinaryBackupPath(workDir, targetVersion)
	if fileExists(dst) {
		return nil // write-once, like the backup it belongs to
	}
	tmp := dst + ".tmp"
	if err := copyFile(src, tmp, 0o755); err != nil {
		return fmt.Errorf("preserve pre-migration kine binary: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install preserved kine binary %s: %w", dst, err)
	}
	return nil
}

// requireFreeSpace fails closed when dir's filesystem has less than want bytes
// available to an unprivileged writer (Bavail, not Bfree — the reserve is not ours).
func requireFreeSpace(dir string, want uint64) error {
	avail, err := freeSpace(dir)
	if err != nil {
		return err
	}
	if avail < want {
		return fmt.Errorf("%w: %s has %d bytes available, need %d (%dx the database size) — free space and restart",
			ErrKineSnapshotSpace, dir, avail, want, snapshotFreeSpaceFactor)
	}
	return nil
}

// freeSpace is the statfs seam. It is a var so the free-space REFUSAL can be tested
// without filling a real volume — the one behaviour whose failure mode (a truncated
// backup on a full disk) is untestable any other way.
var freeSpace = func(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// checkpointTruncate folds the write-ahead log back into the main database and
// truncates it to zero length.
//
// TRUNCATE, not the default PASSIVE: a PASSIVE checkpoint gives up on any frame a
// reader still holds and reports success anyway, so it does NOT guarantee a drained
// WAL — which is exactly the guarantee a file copy of state.db alone depends on. The
// pinned no-cgo kine even checkpoints PASSIVE by design (its post-compact hook), so
// "kine checkpoints, therefore the WAL is empty" is not an inference available here.
//
// This is the one write this function makes, and it must be one: a checkpoint writes
// the main database and the WAL, so a read-only connection cannot perform it. It is
// content-preserving — the same committed transactions, relocated from the WAL into
// the database — and the control plane is stopped, so there is no concurrent writer.
func checkpointTruncate(ctx context.Context, db string) error {
	out, err := sqlite3(ctx, db, "PRAGMA wal_checkpoint(TRUNCATE);")
	if err != nil {
		return err
	}
	// Columns: busy|log|checkpointed. busy=1 means the checkpoint could not complete.
	if fields := strings.Split(strings.TrimSpace(out), "|"); len(fields) > 0 && fields[0] != "0" {
		return fmt.Errorf("%w: wal_checkpoint(TRUNCATE) reported busy (%s)", ErrKineSnapshotWAL, strings.TrimSpace(out))
	}
	return nil
}

// requireWALDrained asserts the -wal sidecar is gone or zero-length. This is the
// assertion the whole snapshot rests on: with it, `cp state.db` is complete; without
// it, the copy silently omits every transaction still living in the log.
func requireWALDrained(db string) error {
	fi, err := os.Stat(db + "-wal")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat datastore WAL: %w", err)
	}
	if fi.Size() != 0 {
		return fmt.Errorf("%w: %s is still %d bytes after the checkpoint", ErrKineSnapshotWAL, db+"-wal", fi.Size())
	}
	return nil
}

// integrityCheck runs PRAGMA integrity_check against a copy so the file that takes the
// final backup name has been proven READABLE AS A DATABASE — not merely proven to be
// the right number of bytes.
//
// It opens the copy as immutable (`file:<path>?immutable=1`, plus -readonly), which is
// both the strictest and the most honest mode available here. Strictest: SQLite creates
// no -shm and no -wal, so verifying the backup cannot modify it or leave sidecars beside
// it. Most honest: immutable tells SQLite to ignore any write-ahead log, and the backup
// IS a single-file database by construction (the source's WAL was drained and asserted
// before the copy) — so this checks exactly the bytes a restore would put back. A plain
// read-only open is not an option: SQLite cannot open a WAL-mode database read-only
// without being able to create its -shm, and fails SQLITE_CANTOPEN.
func integrityCheck(ctx context.Context, db string) error {
	uri := (&url.URL{Scheme: "file", Path: db}).String() + "?immutable=1"
	out, err := sqlite3(ctx, uri, "PRAGMA integrity_check;", "-readonly")
	if err != nil {
		return err
	}
	if got := strings.TrimSpace(out); got != "ok" {
		return fmt.Errorf("pre-migration snapshot %s failed integrity_check: %s", db, got)
	}
	return nil
}

// sqlite3 runs one statement through the bundled SQLite CLI. Both call sites pass a
// PRAGMA and a path this package composed, never operator input.
func sqlite3(ctx context.Context, db, stmt string, flags ...string) (string, error) {
	if !fileExists(sqlite3Bin) {
		return "", fmt.Errorf("%s not found: it is required to take a verified pre-migration datastore snapshot", sqlite3Bin)
	}
	out, err := exec.CommandContext(ctx, sqlite3Bin, append(append([]string{}, flags...), db, stmt)...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlite3 %q on %s: %w: %s", stmt, db, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
