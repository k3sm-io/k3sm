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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// digestOf is the byte identity of a file — the "was this touched?" assertion every
// refusal test makes, in the form that also catches a same-length rewrite.
func digestOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// noServer is the live-control-plane probe for a stopped cluster.
func noServer(context.Context) (string, error) { return "", nil }

// snapshotFixture builds a work dir whose datastore holds rows COMMITTED INTO THE WAL
// (newWALFixture, from the pre-migration snapshot tests) plus enough further rows to
// span several pages — multi-page is what makes a mid-file corruption something
// PRAGMA integrity_check can actually see, and single-page fixtures silently absorb it.
func snapshotFixture(t *testing.T, walRows, pageRows int) string {
	t.Helper()
	work := newWALFixture(t, walRows)
	if pageRows > 0 {
		out, err := exec.Command(sqlite3Bin, StateDBPath(work),
			"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<"+strconv.Itoa(pageRows)+") "+
				"INSERT INTO kine (name, value) SELECT '/registry/pods/default/big'||x, randomblob(512) FROM c;").CombinedOutput()
		if err != nil {
			t.Fatalf("grow fixture db: %v: %s", err, out)
		}
	}
	return work
}

// walHeaderFlag reads the file-format write/read version bytes at offset 18-19 of a
// SQLite header: 2 means WAL, 1 means rollback journal. Read from the bytes rather than
// via PRAGMA because an immutable open (the only safe read of a snapshot) reports
// "delete" for a WAL database by definition.
func walHeaderFlag(t *testing.T, db string) [2]byte {
	t.Helper()
	f, err := os.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var b [2]byte
	if _, err := f.ReadAt(b[:], 18); err != nil {
		t.Fatalf("read the SQLite header of %s: %v", db, err)
	}
	return b
}

// corrupt overwrites n bytes at off with a fixed non-zero pattern — bit rot in a data
// page, the failure a snapshot's integrity check exists to catch.
func corrupt(t *testing.T, path string, off int64, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	junk := strings.Repeat("\xde\xad\xbe\xef", n/4+1)[:n]
	if _, err := f.WriteAt([]byte(junk), off); err != nil {
		t.Fatalf("corrupt %s: %v", path, err)
	}
}

// TestSaveSnapshotCapturesTheWALAndVerifies is the load-bearing save test. The fixture's
// first rows are committed ONLY into the -wal, so a snapshot that copied state.db alone
// would be a valid but SHORT database — which no size or integrity check would catch.
// It also pins the two properties a restore then depends on: the snapshot is a
// single-file WAL-mode database (no sidecars beside it), and it is 0600.
func TestSaveSnapshotCapturesTheWALAndVerifies(t *testing.T) {
	const walRows, pageRows = 40, 200
	work := snapshotFixture(t, walRows, pageRows)

	res, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work})
	if err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
	if got, want := filepath.Dir(res.Path), SnapshotDir(work); got != want {
		t.Errorf("default snapshot dir = %s, want %s", got, want)
	}
	if n := countRows(t, res.Path); n != walRows+pageRows {
		t.Errorf("snapshot holds %d rows, want %d — the write-ahead log was not captured", n, walRows+pageRows)
	}
	if res.Bytes <= 0 {
		t.Errorf("result reports %d bytes", res.Bytes)
	}
	fi, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("snapshot mode = %o, want 600", got)
	}
	if got := walHeaderFlag(t, res.Path); got != [2]byte{2, 2} {
		t.Errorf("snapshot journal-mode header = %v, want WAL {2 2} — a restored datastore must not report a non-WAL journal", got)
	}
	for _, side := range []string{"-wal", "-shm"} {
		if fileExists(res.Path + side) {
			t.Errorf("%s exists beside the snapshot — the snapshot must be a single self-contained file", res.Path+side)
		}
	}
	if !res.Checkpointed {
		t.Errorf("quiescent datastore reported an undrained WAL: %s", res.CheckpointNote)
	}
}

// TestSaveSnapshotOutSelection pins the three --out shapes: absent (the default dir), a
// directory (named inside it), and a file (used verbatim).
func TestSaveSnapshotOutSelection(t *testing.T) {
	work := snapshotFixture(t, 5, 0)
	dir := t.TempDir()
	exact := filepath.Join(t.TempDir(), "nested", "cluster.db")

	res, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Out: dir})
	if err != nil {
		t.Fatalf("save into a directory: %v", err)
	}
	if filepath.Dir(res.Path) != dir {
		t.Errorf("--out <dir> wrote %s, want a file inside %s", res.Path, dir)
	}
	res, err = SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Out: exact})
	if err != nil {
		t.Fatalf("save to an exact path: %v", err)
	}
	if res.Path != exact {
		t.Errorf("--out <file> wrote %s, want %s", res.Path, exact)
	}
	if !fileExists(exact) {
		t.Errorf("%s does not exist", exact)
	}
}

// TestSnapshotRefusesExternalDatastore pins the HA/Postgres refusal — the decision this
// item was gated on. Both signals refuse (the DSN and the on-disk .pgpass), both
// subcommands refuse, and the message names pg_dump WITHOUT echoing the DSN password.
func TestSnapshotRefusesExternalDatastore(t *testing.T) {
	const password = "sup3r-s3cret"
	dsn := "postgres://kine:" + password + "@db.example:5432/kine?sslmode=require"
	work := snapshotFixture(t, 3, 0)
	snap := filepath.Join(t.TempDir(), "s.db")
	if err := copyFile(StateDBPath(work), snap, 0o600); err != nil {
		t.Fatal(err)
	}

	assert := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, ErrSnapshotExternalDatastore) {
			t.Fatalf("err = %v, want ErrSnapshotExternalDatastore", err)
		}
		if !strings.Contains(err.Error(), "pg_dump") {
			t.Errorf("the refusal does not name pg_dump: %v", err)
		}
		if strings.Contains(err.Error(), password) {
			t.Errorf("the refusal echoed the datastore password: %v", err)
		}
	}

	t.Run("save with a postgres endpoint", func(t *testing.T) {
		_, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, DatastoreEndpoint: dsn})
		assert(t, err)
	})
	t.Run("restore with a postgres endpoint", func(t *testing.T) {
		_, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{
			WorkDir: work, DatastoreEndpoint: dsn, Snapshot: snap, Running: noServer,
		})
		assert(t, err)
	})
	t.Run("a pgpass file in the work dir is decisive on its own", func(t *testing.T) {
		pg := pgPassPath(work)
		if err := os.WriteFile(pg, []byte("*:*:*:kine:"+password+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(pg) })
		_, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work})
		assert(t, err)
		if !strings.Contains(err.Error(), pg) {
			t.Errorf("the refusal does not name the file that caused it: %v", err)
		}
	})
	t.Run("an unparseable endpoint is withheld entirely", func(t *testing.T) {
		_, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, DatastoreEndpoint: "postgres://k:" + password + "@%%%"})
		assert(t, err)
	})
}

// TestSaveSnapshotRefusals covers the two remaining save-side refusals: no datastore at
// all, and a volume without the free-space floor.
func TestSaveSnapshotRefusals(t *testing.T) {
	t.Run("no datastore", func(t *testing.T) {
		_, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: t.TempDir()})
		if !errors.Is(err, ErrNoDatastore) {
			t.Fatalf("err = %v, want ErrNoDatastore", err)
		}
	})
	t.Run("free-space floor", func(t *testing.T) {
		work := snapshotFixture(t, 5, 0)
		orig := freeSpace
		t.Cleanup(func() { freeSpace = orig })
		freeSpace = func(string) (uint64, error) { return 1, nil }
		_, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work})
		if !errors.Is(err, ErrKineSnapshotSpace) {
			t.Fatalf("err = %v, want ErrKineSnapshotSpace", err)
		}
		if entries, _ := os.ReadDir(SnapshotDir(work)); len(entries) != 0 {
			t.Errorf("a refused save left %d files behind: %v", len(entries), entries)
		}
	})
	t.Run("no work dir", func(t *testing.T) {
		if _, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{}); err == nil {
			t.Fatal("a save with no work dir succeeded")
		}
	})
}

// TestRestoreRefusesARunningControlPlane is the second half of the decision: replacing
// the datastore under a live kine is corruption, so the probe's answer is a refusal and
// an unanswerable probe is ALSO a refusal. In every case the datastore is byte-unchanged.
func TestRestoreRefusesARunningControlPlane(t *testing.T) {
	cases := []struct {
		name  string
		probe LiveControlPlaneProbe
		want  error
	}{
		{"a server is running", func(context.Context) (string, error) {
			return "the io.k3sm.server launchd job is running (pid 4242)", nil
		}, ErrControlPlaneRunning},
		{"the probe cannot answer", func(context.Context) (string, error) {
			return "", errors.New("launchctl print failed")
		}, ErrControlPlaneRunning},
		{"no probe at all", nil, ErrNoRunningProbe},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := snapshotFixture(t, 5, 0)
			snap, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Out: filepath.Join(t.TempDir(), "s.db")})
			if err != nil {
				t.Fatal(err)
			}
			before := digestOf(t, StateDBPath(work))

			_, err = RestoreSnapshot(context.Background(), SnapshotRestoreOptions{
				WorkDir: work, Snapshot: snap.Path, Running: tc.probe,
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got := digestOf(t, StateDBPath(work)); got != before {
				t.Errorf("a refused restore modified the datastore")
			}
			if bak, _ := filepath.Glob(StateDBPath(work) + ".restore-*"); len(bak) != 0 {
				t.Errorf("a refused restore left %v behind", bak)
			}
		})
	}
}

// TestRestoreVerifiesBeforeTouchingAnything is the integrity gate. A corrupt snapshot is
// rejected with the live datastore untouched — the property that makes a failed restore
// survivable, because the alternative is discovering the corruption only after the one
// good copy of the state has been moved aside.
func TestRestoreVerifiesBeforeTouchingAnything(t *testing.T) {
	work := snapshotFixture(t, 20, 200)
	snap, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Out: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	corrupt(t, snap.Path, 20000, 512)
	before := digestOf(t, StateDBPath(work))

	_, err = RestoreSnapshot(context.Background(), SnapshotRestoreOptions{
		WorkDir: work, Snapshot: snap.Path, Running: noServer,
	})
	if !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("err = %v, want ErrSnapshotIntegrity", err)
	}
	// WHICH check refused is the ordering assertion. The staged-copy check is a
	// backstop and would also reject this snapshot — but only after a full copy of
	// it had been written into the datastore directory. The refusal must come from
	// the one that runs BEFORE anything is staged, and its message is how that is
	// observable from outside.
	if !strings.Contains(err.Error(), "nothing was changed") || strings.Contains(err.Error(), "the copy of") {
		t.Errorf("the refusal came from the staged-copy backstop, not from the pre-touch verification: %v", err)
	}
	if got := digestOf(t, StateDBPath(work)); got != before {
		t.Errorf("the datastore was modified by a restore that refused")
	}
	if bak, _ := filepath.Glob(StateDBPath(work) + ".restore-*"); len(bak) != 0 {
		t.Errorf("the refused restore left %v behind", bak)
	}
	if fileExists(StateDBPath(work) + ".restoring.tmp") {
		t.Errorf("the refused restore left its staging file behind")
	}
}

// TestRestoreMissingSnapshot pins the not-a-file refusals.
func TestRestoreMissingSnapshot(t *testing.T) {
	work := snapshotFixture(t, 3, 0)
	for _, path := range []string{filepath.Join(t.TempDir(), "absent.db"), t.TempDir()} {
		_, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{
			WorkDir: work, Snapshot: path, Running: noServer,
		})
		if !errors.Is(err, ErrSnapshotNotFound) {
			t.Errorf("restore(%s) err = %v, want ErrSnapshotNotFound", path, err)
		}
	}
}

// TestRestoreReplacesAndPreserves is the drill: take a snapshot, let the cluster move on,
// restore, and get the snapshot's state back — with the state that was replaced preserved
// beside it, its sidecars taken with it, and the kine pin stamp (which describes the
// database that just moved) taken too.
func TestRestoreReplacesAndPreserves(t *testing.T) {
	const walRows = 30
	work := snapshotFixture(t, walRows, 0)
	snap, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Out: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	// The cluster moves on: rows the snapshot does not have.
	if out, err := exec.Command(sqlite3Bin, StateDBPath(work),
		"INSERT INTO kine (name, value) VALUES ('/registry/pods/default/after', randomblob(64));").CombinedOutput(); err != nil {
		t.Fatalf("post-snapshot write: %v: %s", err, out)
	}
	if err := recordKinePin(work, DefaultKineVersion, ""); err != nil {
		t.Fatal(err)
	}

	res, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{
		WorkDir: work, Snapshot: snap.Path, Running: noServer,
	})
	if err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if n := countRows(t, StateDBPath(work)); n != walRows {
		t.Errorf("restored datastore holds %d rows, want the snapshot's %d", n, walRows)
	}
	if res.PreviousDB == "" || !fileExists(res.PreviousDB) {
		t.Fatalf("the superseded datastore was not preserved (PreviousDB=%q)", res.PreviousDB)
	}
	if n := countRows(t, res.PreviousDB); n != walRows+1 {
		t.Errorf("the preserved datastore holds %d rows, want the pre-restore %d", n, walRows+1)
	}
	// Nothing of the old database may be left beside the restored one.
	for _, side := range []string{"-wal", "-shm"} {
		if fileExists(StateDBPath(work) + side) {
			t.Errorf("%s survived the restore — SQLite would replay it over the restored state", StateDBPath(work)+side)
		}
	}
	if fileExists(kinePinStampPath(work)) {
		t.Errorf("the kine pin stamp survived; it describes the superseded database and would suppress the next boot's pre-migration backup")
	}
	if !fileExists(res.PreviousDB + "-kine-pin") {
		t.Errorf("the kine pin stamp was not preserved beside the database it describes")
	}
	if fileExists(StateDBPath(work) + ".restoring.tmp") {
		t.Errorf("the restore left its staging file behind")
	}
	// The restored datastore is a WAL-mode database again.
	if got := walHeaderFlag(t, StateDBPath(work)); got != [2]byte{2, 2} {
		t.Errorf("restored datastore journal-mode header = %v, want WAL {2 2}", got)
	}
}

// TestRestoreOntoAWipedNode covers the disaster case the drill is FOR: the work dir has
// no datastore at all. That is not a refusal — it is the restore's whole point.
func TestRestoreOntoAWipedNode(t *testing.T) {
	const rows = 12
	src := snapshotFixture(t, rows, 0)
	snap, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: src, Out: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	fresh := t.TempDir()
	res, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{
		WorkDir: fresh, Snapshot: snap.Path, Running: noServer,
	})
	if err != nil {
		t.Fatalf("restore onto a wiped node: %v", err)
	}
	if res.PreviousDB != "" {
		t.Errorf("PreviousDB = %q, want empty (there was nothing to preserve)", res.PreviousDB)
	}
	if n := countRows(t, StateDBPath(fresh)); n != rows {
		t.Errorf("restored datastore holds %d rows, want %d", n, rows)
	}
}

// TestControlPlanePortProbe pins the port half of the running-server detection: a held
// loopback port is a refusal, a free one is not, and port 0 (the probe disabled) is not.
func TestControlPlanePortProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	held := ln.Addr().(*net.TCPAddr).Port

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()

	ctx := context.Background()
	if holder, err := ControlPlanePortProbe(held, 0)(ctx); err != nil || holder == "" {
		t.Errorf("datastore port %d held: holder=%q err=%v, want a non-empty holder", held, holder, err)
	} else if !strings.Contains(holder, strconv.Itoa(held)) {
		t.Errorf("holder %q does not name the port", holder)
	}
	if holder, err := ControlPlanePortProbe(0, held)(ctx); err != nil || holder == "" {
		t.Errorf("apiserver port %d held: holder=%q err=%v, want a non-empty holder", held, holder, err)
	}
	if holder, err := ControlPlanePortProbe(freePort, 0)(ctx); err != nil || holder != "" {
		t.Errorf("free port: holder=%q err=%v, want no holder", holder, err)
	}
	if holder, err := ControlPlanePortProbe(0, 0)(ctx); err != nil || holder != "" {
		t.Errorf("disabled probe: holder=%q err=%v, want no holder", holder, err)
	}
}

// TestSnapshotRequiresSQLite3 pins the fail-closed posture on a host without the bundled
// SQLite CLI: no verification is possible, so no snapshot is produced — the same refusal
// the pre-migration path makes.
func TestSnapshotRequiresSQLite3(t *testing.T) {
	work := snapshotFixture(t, 3, 0)
	orig := sqlite3Bin
	t.Cleanup(func() { sqlite3Bin = orig })
	sqlite3Bin = filepath.Join(t.TempDir(), "no-sqlite3-here")

	if _, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work}); err == nil {
		t.Fatal("SaveSnapshot succeeded with no sqlite3 available")
	}
	if entries, _ := os.ReadDir(SnapshotDir(work)); len(entries) != 0 {
		t.Errorf("a refused save left %d files behind", len(entries))
	}
	sqlite3Bin = orig
	snap, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Out: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	sqlite3Bin = filepath.Join(t.TempDir(), "no-sqlite3-here")
	before := digestOf(t, StateDBPath(work))
	if _, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{
		WorkDir: work, Snapshot: snap.Path, Running: noServer,
	}); err == nil {
		t.Fatal("RestoreSnapshot succeeded with no sqlite3 available to verify the snapshot")
	}
	if got := digestOf(t, StateDBPath(work)); got != before {
		t.Errorf("the unverifiable restore modified the datastore")
	}
}
