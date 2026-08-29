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
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// discardLogger is a logger whose output goes nowhere — the snapshot path logs at Info
// and the tests care about its effects on disk, not its lines.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// needSQLite skips a test on a host without the bundled SQLite CLI. macOS ships it; the
// production path REFUSES rather than skipping, which TestKineSnapshotRequiresSQLite3
// pins separately.
func needSQLite(t *testing.T) {
	t.Helper()
	if !fileExists(sqlite3Bin) {
		t.Skipf("%s absent — cannot build a real SQLite fixture", sqlite3Bin)
	}
}

// newWALFixture builds a real WAL-mode SQLite database under a fresh work dir and
// leaves COMMITTED DATA IN THE -wal FILE, not in state.db. That last part is the whole
// point: a `cp state.db` of this fixture, without a TRUNCATE checkpoint first, silently
// loses the rows.
//
// Getting there needs a writer that DIES rather than closes: SQLite checkpoints the WAL
// when the last connection closes cleanly, so a well-behaved `sqlite3 db "INSERT …"`
// leaves an empty log and would make every assertion here vacuous. The fixture therefore
// commits its rows through a live session and SIGKILLs it — which is also exactly the
// state a `launchctl kickstart`-killed kine leaves behind, i.e. the state the snapshot
// path actually has to handle. It returns the work dir.
func newWALFixture(t *testing.T, rows int) string {
	t.Helper()
	needSQLite(t)
	work := t.TempDir()
	if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
		t.Fatal(err)
	}
	db := StateDBPath(work)
	if out, err := exec.Command(sqlite3Bin, db,
		"PRAGMA journal_mode=WAL; CREATE TABLE kine (id INTEGER PRIMARY KEY, name TEXT, value BLOB);").CombinedOutput(); err != nil {
		t.Fatalf("build fixture db: %v: %s", err, out)
	}

	cmd := exec.Command(sqlite3Bin, db)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("PRAGMA wal_autocheckpoint=0;\n")
	for i := range rows {
		b.WriteString("INSERT INTO kine (name, value) VALUES ('/registry/pods/default/p" + strconv.Itoa(i) + "', randomblob(4096));\n")
	}
	// The SELECT is the sync point: reading its answer proves every INSERT above has
	// committed (into the WAL) before the process is killed.
	b.WriteString("SELECT 'committed:' || count(*) FROM kine;\n")
	if _, err := io.WriteString(stdin, b.String()); err != nil {
		t.Fatal(err)
	}
	want, confirmed := "committed:"+strconv.Itoa(rows), false
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		if strings.Contains(sc.Text(), "committed:") {
			if sc.Text() != want {
				t.Fatalf("fixture writer reported %q, want %q", sc.Text(), want)
			}
			confirmed = true
			break
		}
	}
	if !confirmed {
		t.Fatalf("fixture writer never confirmed its commits: %v", sc.Err())
	}
	_ = cmd.Process.Kill() // die, do NOT close: the WAL must survive
	_ = cmd.Wait()

	fi, err := os.Stat(db + "-wal")
	if err != nil || fi.Size() == 0 {
		t.Fatalf("fixture did not leave data in the WAL (stat=%v) — the test would prove nothing", err)
	}
	return work
}

// countRows reads the fixture table back through the SQLite CLI.
func countRows(t *testing.T, db string) int {
	t.Helper()
	// Immutable, like integrityCheck: read the backup exactly as a restore would, and
	// without letting the read create -wal/-shm sidecars beside it.
	uri := (&url.URL{Scheme: "file", Path: db}).String() + "?immutable=1"
	out, err := exec.Command(sqlite3Bin, "-readonly", uri, "SELECT count(*) FROM kine;").CombinedOutput()
	if err != nil {
		t.Fatalf("count rows in %s: %v: %s", db, err, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("parse row count %q: %v", out, err)
	}
	return n
}

// TestKineSnapshotDrainsWALAndVerifies is the load-bearing snapshot test. The fixture's
// committed rows live ONLY in the -wal, so every assertion below fails if the WAL drain
// is weakened (a PASSIVE checkpoint, or no checkpoint at all): the backup would be a
// valid but SHORT database, which no size or integrity check alone would catch.
func TestKineSnapshotDrainsWALAndVerifies(t *testing.T) {
	const rows = 40
	work := newWALFixture(t, rows)

	if err := snapshotBeforeKineUpgrade(t.Context(), discardLogger(), work, DefaultKineVersion); err != nil {
		t.Fatalf("snapshotBeforeKineUpgrade: %v", err)
	}

	// The WAL was drained (this is what makes a plain copy sound).
	if fi, err := os.Stat(StateDBPath(work) + "-wal"); err == nil && fi.Size() != 0 {
		t.Errorf("WAL is %d bytes after the snapshot, want drained (0 or absent)", fi.Size())
	}
	// The backup exists at the final name, opens standalone, and holds every row.
	backup := kineBackupPath(work, DefaultKineVersion)
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("backup not at its final name: %v", err)
	}
	if _, err := os.Stat(backup + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("staging .tmp survived the snapshot: %v", err)
	}
	if got := countRows(t, backup); got != rows {
		t.Errorf("backup holds %d rows, want %d — the WAL was not folded in before the copy", got, rows)
	}
	if err := integrityCheck(t.Context(), backup); err != nil {
		t.Errorf("backup failed integrity_check: %v", err)
	}
}

// TestKineSnapshotWriteOnce proves a re-boot does not overwrite a good backup. Under
// launchd a failing server respawns in a loop, so a snapshot that re-ran per boot would
// eventually copy a database the new pin had already migrated — over the only pristine
// copy that existed.
func TestKineSnapshotWriteOnce(t *testing.T) {
	work := newWALFixture(t, 5)
	ctx, log := t.Context(), discardLogger()
	if err := snapshotBeforeKineUpgrade(ctx, log, work, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	backup := kineBackupPath(work, DefaultKineVersion)
	before, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the live database the way a migration would, then boot again.
	if out, err := exec.Command(sqlite3Bin, StateDBPath(work), "INSERT INTO kine (name, value) VALUES ('post-migration', randomblob(64));").CombinedOutput(); err != nil {
		t.Fatalf("mutate db: %v: %s", err, out)
	}
	if err := snapshotBeforeKineUpgrade(ctx, log, work, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Error("a second boot overwrote the pre-migration backup")
	}
	if got := countRows(t, backup); got != 5 {
		t.Errorf("backup now holds %d rows, want the pre-migration 5", got)
	}
}

// TestKineSnapshotSkips pins the three no-op cases. Each matters on its own: a fresh
// node has nothing to protect, an unchanged pin must not re-copy the database on every
// boot, and the Postgres posture has no state.db at all.
func TestKineSnapshotSkips(t *testing.T) {
	ctx, log := t.Context(), discardLogger()

	t.Run("fresh node (no state.db)", func(t *testing.T) {
		work := t.TempDir()
		if err := snapshotBeforeKineUpgrade(ctx, log, work, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(kineBackupPath(work, DefaultKineVersion)); !os.IsNotExist(err) {
			t.Error("a fresh node produced a backup")
		}
	})

	t.Run("pin unchanged (stamp matches)", func(t *testing.T) {
		work := newWALFixture(t, 3)
		if err := recordKinePin(work, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if err := snapshotBeforeKineUpgrade(ctx, log, work, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(kineBackupPath(work, DefaultKineVersion)); !os.IsNotExist(err) {
			t.Error("an unchanged pin produced a backup")
		}
	})

	t.Run("stamp from an older pin snapshots", func(t *testing.T) {
		work := newWALFixture(t, 3)
		if err := os.WriteFile(kinePinStampPath(work), []byte("v1.14.2 cgo\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := snapshotBeforeKineUpgrade(ctx, log, work, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(kineBackupPath(work, DefaultKineVersion)); err != nil {
			t.Errorf("an older stamped pin did NOT produce a backup: %v", err)
		}
	})
}

// TestKineSnapshotFreeSpaceRefusal proves the floor refuses rather than half-writes. A
// truncated backup on a full volume is the worst outcome available: it looks like a
// safety net and is not one.
func TestKineSnapshotFreeSpaceRefusal(t *testing.T) {
	work := newWALFixture(t, 20)
	fi, err := os.Stat(StateDBPath(work))
	if err != nil {
		t.Fatal(err)
	}
	orig := freeSpace
	t.Cleanup(func() { freeSpace = orig })
	// Just under the 2x floor: enough for the copy, not enough for the margin.
	freeSpace = func(string) (uint64, error) { return uint64(fi.Size())*snapshotFreeSpaceFactor - 1, nil }

	err = snapshotBeforeKineUpgrade(t.Context(), discardLogger(), work, DefaultKineVersion)
	if !errors.Is(err, ErrKineSnapshotSpace) {
		t.Fatalf("snapshot on a nearly-full volume = %v, want ErrKineSnapshotSpace", err)
	}
	for _, leftover := range []string{kineBackupPath(work, DefaultKineVersion), kineBackupPath(work, DefaultKineVersion) + ".tmp"} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Errorf("refusal left %s behind: %v", leftover, err)
		}
	}
	// And the refusal is not sticky: with space, the same boot succeeds.
	freeSpace = orig
	if err := snapshotBeforeKineUpgrade(t.Context(), discardLogger(), work, DefaultKineVersion); err != nil {
		t.Fatalf("snapshot with space available = %v, want nil", err)
	}
}

// TestKineSnapshotPreservesOldBinary pins resolution 8's rollback half: the backup is
// only half a rollback if the kine that can read it is gone. The superseded pin has no
// upstream tag, so it is not reliably rebuildable — the bytes are kept.
func TestKineSnapshotPreservesOldBinary(t *testing.T) {
	work := newWALFixture(t, 3)
	if err := os.MkdirAll(binDir(work), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kinePath(binDir(work)), []byte("the-old-kine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := snapshotBeforeKineUpgrade(t.Context(), discardLogger(), work, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(kineBinaryBackupPath(work, DefaultKineVersion))
	if err != nil || string(got) != "the-old-kine" {
		t.Fatalf("old kine binary not preserved: %v %q", err, got)
	}
	if fi, err := os.Stat(kineBinaryBackupPath(work, DefaultKineVersion)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("preserved kine mode = %v, want 0755 (it has to be runnable to be a rollback)", fi.Mode())
	}
}

// TestRecordKinePinRoundTrip proves the stamp records version AND variant, and that it
// is not written for a datastore that does not exist (the Postgres posture).
func TestRecordKinePinRoundTrip(t *testing.T) {
	work := newWALFixture(t, 1)
	if err := recordKinePin(work, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	v, variant, ok := readKinePin(work)
	if !ok || v != DefaultKineVersion || variant != kineBuildVariant {
		t.Errorf("readKinePin = (%q,%q,%v), want (%q,%q,true)", v, variant, ok, DefaultKineVersion, kineBuildVariant)
	}

	empty := t.TempDir()
	if err := recordKinePin(empty, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kinePinStampPath(empty)); !os.IsNotExist(err) {
		t.Error("stamped a work dir with no state.db")
	}
}

// TestKineSnapshotRequiresSQLite3 pins the fail-closed posture. Without the SQLite CLI
// the WAL can be neither drained nor verified, so the ONLY safe answer is to stop the
// boot — a snapshot path that degraded to "copy state.db and hope" would hand back a
// backup that is silently missing every committed write still living in the log.
func TestKineSnapshotRequiresSQLite3(t *testing.T) {
	work := newWALFixture(t, 3)
	orig := sqlite3Bin
	t.Cleanup(func() { sqlite3Bin = orig })
	sqlite3Bin = filepath.Join(t.TempDir(), "no-sqlite3-here")

	err := snapshotBeforeKineUpgrade(t.Context(), discardLogger(), work, DefaultKineVersion)
	if err == nil {
		t.Fatal("snapshot with no sqlite3 = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want it to name the missing sqlite3", err)
	}
	if _, err := os.Stat(kineBackupPath(work, DefaultKineVersion)); !os.IsNotExist(err) {
		t.Error("an unverifiable snapshot was written anyway")
	}
}
