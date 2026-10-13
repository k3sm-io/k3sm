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
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// inflateToFile writes the single member of the archive at zipPath to a new file and
// returns its path: the plain snapshot a compressed one holds.
func inflateToFile(t *testing.T, zipPath string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "inflated")
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inflateSnapshot(zipPath, f, maxDecompressedSnapshotBytes); err != nil {
		t.Fatalf("inflate %s: %v", zipPath, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

// isZip reports whether the file opens with the zip local-header magic.
func isZip(t *testing.T, path string) bool {
	t.Helper()
	ok, err := isCompressedSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// noInflateDebris fails when a restore left its temporary decompressed copy in dir.
func noInflateDebris(t *testing.T, dir string) {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, ".k3sm-snapshot-inflate-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) > 0 {
		t.Errorf("the restore left its decompressed copy behind: %v", left)
	}
}

// zipOf builds a one-member archive of b in memory.
func zipOf(t *testing.T, name string, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeSnapshotZip(&buf, bytes.NewReader(b), name, time.Now()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSnapshotCompressRoundTrip is the compressed-snapshot gate: a compressed save
// restores in both postures to exactly the bytes a plain one does; a truncated or
// corrupt archive, and a deflate bomb past the cap, are refused with the datastore
// untouched; the format is decided by content in both directions, never by the file
// name; and the schedule's retention counts compressed and plain snapshots alike.
func TestSnapshotCompressRoundTrip(t *testing.T) {
	t.Run("kine: a compressed save restores to the bytes a plain restore installs", func(t *testing.T) {
		const walRows, pageRows = 25, 150
		work := snapshotFixture(t, walRows, pageRows)
		res, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Compress: true})
		if err != nil {
			t.Fatalf("SaveSnapshot(compress): %v", err)
		}
		if !res.Compressed || !strings.HasSuffix(res.Path, ".zip") || !isZip(t, res.Path) {
			t.Fatalf("save = %+v; want a compressed .zip archive", res)
		}
		if fi, err := os.Stat(res.Path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("compressed snapshot mode = %v (%v), want 0600", fi.Mode().Perm(), err)
		}
		for _, debris := range []string{res.Path + ".tmp", plainStagingPath(res.Path)} {
			if fileExists(debris) {
				t.Errorf("the save left %s behind", debris)
			}
		}
		plain := inflateToFile(t, res.Path)
		if n := countRows(t, plain); n != walRows+pageRows {
			t.Fatalf("the archive's member holds %d rows, want %d", n, walRows+pageRows)
		}

		// Restore the archive over the moved-on cluster, and the same snapshot plain
		// onto a wiped node: the live datastore bytes must be identical.
		rres, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{WorkDir: work, Snapshot: res.Path, Running: noServer})
		if err != nil {
			t.Fatalf("RestoreSnapshot(compressed): %v", err)
		}
		if !rres.Compressed {
			t.Error("the restore did not report a compressed input")
		}
		wiped := t.TempDir()
		if _, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{WorkDir: wiped, Snapshot: plain, Running: noServer}); err != nil {
			t.Fatalf("RestoreSnapshot(plain): %v", err)
		}
		if a, b := digestOf(t, StateDBPath(work)), digestOf(t, StateDBPath(wiped)); a != b {
			t.Fatalf("restored datastore from the archive (%s) differs from the plain restore (%s)", a, b)
		}
		if a, b := digestOf(t, StateDBPath(work)), digestOf(t, plain); a != b {
			t.Fatal("the restored datastore is not the snapshot's bytes")
		}
		if got := walHeaderFlag(t, StateDBPath(work)); got != [2]byte{2, 2} {
			t.Errorf("restored journal-mode header = %v, want WAL", got)
		}
		noInflateDebris(t, dbDir(work))
	})

	t.Run("etcd: a compressed save restores through the existing verification", func(t *testing.T) {
		stream := withTrailer(etcdBackendBytes(t, "key", "meta"))
		wd := t.TempDir()
		if err := writeEtcdStatus(wd, EtcdStatus{ClientURL: "https://127.0.0.1:2379"}); err != nil {
			t.Fatal(err)
		}
		fake := &fakeEtcd{snapshot: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(stream)), nil }}
		dial := func(context.Context, string, string) (etcdAdmin, error) { return fake, nil }
		dst := filepath.Join(t.TempDir(), "snaps", "etcd-snap.zip")
		if err := snapshotEtcd(t.Context(), wd, dst, true, dial); err != nil {
			t.Fatalf("compressed etcd save: %v", err)
		}
		if !isZip(t, dst) {
			t.Fatal("the etcd save did not write an archive")
		}
		for _, debris := range []string{dst + ".tmp", plainStagingPath(dst)} {
			if fileExists(debris) {
				t.Errorf("the save left %s behind", debris)
			}
		}
		if b, _ := os.ReadFile(inflateToFile(t, dst)); !bytes.Equal(b, stream) {
			t.Fatal("the archive's member is not the verified snapshot stream")
		}

		f := newRestoreFixture(t, true)
		var handed []byte
		seams := fakeRestoreSeams(t, nil)
		run := seams.run
		seams.run = func(ctx context.Context, bin string, a []string) ([]byte, error) {
			handed, _ = os.ReadFile(a[2]) // snapshot restore <file>
			return run(ctx, bin, a)
		}
		res, err := restoreEtcdSnapshot(t.Context(), f.opts(dst), seams)
		if err != nil {
			t.Fatalf("restore(compressed): %v", err)
		}
		if !bytes.Equal(handed, stream) {
			t.Fatal("etcdutl was not handed the decompressed snapshot bytes")
		}
		if !res.Compressed || res.Snapshot != dst {
			t.Errorf("result = %+v; want Compressed and the archive's own path", res)
		}
		noInflateDebris(t, f.wd)
	})

	t.Run("a truncated or corrupt archive is refused with the datastore untouched", func(t *testing.T) {
		work := snapshotFixture(t, 10, 120)
		res, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Compress: true, Out: filepath.Join(t.TempDir(), "s.zip")})
		if err != nil {
			t.Fatal(err)
		}
		whole, err := os.ReadFile(res.Path)
		if err != nil {
			t.Fatal(err)
		}
		truncated := filepath.Join(t.TempDir(), "truncated.zip")
		mustWrite(t, truncated, whole[:len(whole)/2])
		// A flipped byte inside the deflated member: the archive still opens, so the
		// refusal comes from the inflate or its CRC-32 check at the member's end.
		flipped := bytes.Clone(whole)
		flipped[len(flipped)/3] ^= 0xff
		corruptZip := filepath.Join(t.TempDir(), "corrupt.zip")
		mustWrite(t, corruptZip, flipped)

		before := digestOf(t, StateDBPath(work))
		for _, snap := range []string{truncated, corruptZip} {
			_, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{WorkDir: work, Snapshot: snap, Running: noServer})
			if !errors.Is(err, ErrSnapshotArchive) {
				t.Errorf("restore(%s) = %v, want ErrSnapshotArchive", filepath.Base(snap), err)
			}
			if got := digestOf(t, StateDBPath(work)); got != before {
				t.Fatalf("restore(%s) changed the datastore", filepath.Base(snap))
			}
			noInflateDebris(t, dbDir(work))
		}

		// The etcd posture refuses the same way, before anything in the work dir moves.
		f := newRestoreFixture(t, true)
		etcdZip := filepath.Join(t.TempDir(), "etcd.zip")
		good, _ := os.ReadFile(f.good)
		z := zipOf(t, "etcd-snapshot", good)
		mustWrite(t, etcdZip, z[:len(z)-40])
		entries := workDirEntries(t, f.wd)
		if _, err := restoreEtcdSnapshot(t.Context(), f.opts(etcdZip), fakeRestoreSeams(t, nil)); !errors.Is(err, ErrSnapshotArchive) {
			t.Errorf("etcd restore(truncated) = %v, want ErrSnapshotArchive", err)
		}
		if got := workDirEntries(t, f.wd); !slices.Equal(got, entries) {
			t.Errorf("the refused etcd restore changed the work dir: %v -> %v", entries, got)
		}
	})

	t.Run("a deflate bomb trips the cap with the datastore untouched", func(t *testing.T) {
		orig := maxDecompressedSnapshotBytes
		t.Cleanup(func() { maxDecompressedSnapshotBytes = orig })
		maxDecompressedSnapshotBytes = 1 << 20

		work := snapshotFixture(t, 5, 0)
		bomb := filepath.Join(t.TempDir(), "bomb.db")
		// 16 MiB of zeros deflates to a few kilobytes.
		mustWrite(t, bomb, zipOf(t, "k3sm-snapshot.db", make([]byte, 16<<20)))
		if fi, _ := os.Stat(bomb); fi.Size() > 1<<20 {
			t.Fatalf("the bomb fixture is %d bytes; it must be far smaller than what it inflates to", fi.Size())
		}
		before := digestOf(t, StateDBPath(work))
		_, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{WorkDir: work, Snapshot: bomb, Running: noServer})
		if !errors.Is(err, ErrSnapshotTooLarge) {
			t.Fatalf("restore(bomb) = %v, want ErrSnapshotTooLarge", err)
		}
		if got := digestOf(t, StateDBPath(work)); got != before {
			t.Fatal("the refused bomb changed the datastore")
		}
		noInflateDebris(t, dbDir(work))

		// The inflate itself is capped whatever the header says: read straight
		// through inflateSnapshot with a limit below the member's size.
		n, err := inflateSnapshot(bomb, io.Discard, 4096)
		if !errors.Is(err, ErrSnapshotTooLarge) || n > 4096 {
			t.Fatalf("inflateSnapshot past the cap = %d, %v; want ErrSnapshotTooLarge with at most the cap read", n, err)
		}
	})

	t.Run("a plain snapshot is never treated as compressed, even named .zip", func(t *testing.T) {
		work := snapshotFixture(t, 12, 0)
		res, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Out: filepath.Join(t.TempDir(), "plain.zip")})
		if err != nil {
			t.Fatal(err)
		}
		if isZip(t, res.Path) || res.Compressed {
			t.Fatal("a save without compression wrote an archive")
		}
		rres, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{WorkDir: work, Snapshot: res.Path, Running: noServer})
		if err != nil {
			t.Fatalf("restore(plain named .zip): %v", err)
		}
		if rres.Compressed {
			t.Error("a plain snapshot was reported as compressed")
		}
		if digestOf(t, StateDBPath(work)) != digestOf(t, res.Path) {
			t.Error("the plain restore did not install the snapshot's bytes")
		}
	})

	t.Run("a compressed snapshot with a misleading extension restores", func(t *testing.T) {
		const rows = 17
		work := snapshotFixture(t, rows, 0)
		res, err := SaveSnapshot(context.Background(), SnapshotSaveOptions{WorkDir: work, Compress: true, Out: filepath.Join(t.TempDir(), "looks-plain.db")})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(res.Path, "looks-plain.db") || !isZip(t, res.Path) {
			t.Fatalf("an exact --out was not honored as given: %s", res.Path)
		}
		if _, err := RestoreSnapshot(context.Background(), SnapshotRestoreOptions{WorkDir: work, Snapshot: res.Path, Running: noServer}); err != nil {
			t.Fatalf("restore(compressed named .db): %v", err)
		}
		if n := countRows(t, StateDBPath(work)); n != rows {
			t.Errorf("restored datastore holds %d rows, want %d", n, rows)
		}
	})

	t.Run("retention counts compressed and plain scheduled snapshots alike", func(t *testing.T) {
		good := withTrailer(etcdBackendBytes(t, "key", "meta"))
		cron, err := ParseCron(DefaultEtcdSnapshotCron)
		if err != nil {
			t.Fatal(err)
		}
		wd := t.TempDir()
		s := NewSupervised(Config{
			WorkDir: wd,
			Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP,
				Snapshots: &EtcdSnapshotSchedule{Cron: cron, Retention: 3, Compress: true}},
			Logger: slog.New(slog.DiscardHandler),
		})
		clk := newFakeClock(0)
		s.etcd.clock = clk
		now := clk.Now()
		dir := SnapshotDir(wd)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		name := func(ago time.Duration, zipped bool) string {
			n := ScheduledEtcdSnapshotName("server-a", now.Add(-ago))
			if zipped {
				n += compressedSnapshotExt
			}
			return n
		}
		older := []struct {
			ago    time.Duration
			zipped bool
		}{{4 * time.Hour, false}, {3 * time.Hour, true}, {2 * time.Hour, false}, {time.Hour, true}}
		for _, o := range older {
			p := filepath.Join(dir, name(o.ago, o.zipped))
			mustWrite(t, p, []byte("an older scheduled snapshot"))
			if err := os.Chtimes(p, now.Add(-o.ago), now.Add(-o.ago)); err != nil {
				t.Fatal(err)
			}
		}
		untouchable := []string{"k3sm-etcd-snapshot-20261001T000000Z.zip", "etcd-snapshot-server-b-1700000000.zip"}
		for _, n := range untouchable {
			mustWrite(t, filepath.Join(dir, n), []byte("not mine to delete"))
		}
		// Partial files a compressed tick of an earlier run may have left: removed at start.
		debris := []string{name(5*time.Hour, true) + ".tmp", name(5*time.Hour, false) + ".tmp"}
		for _, n := range debris {
			mustWrite(t, filepath.Join(dir, n), []byte("partial"))
		}

		fake := healthyFake()
		fake.snapshot = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(good)), nil }
		sc := s.newEtcdSnapshotScheduler(fake)
		sc.space = func(string, uint64) error { return nil }
		for _, n := range debris {
			if fileExists(filepath.Join(dir, n)) {
				t.Errorf("the start-up sweep left this node's partial %s", n)
			}
		}
		sc.tick(t.Context())

		snaps, err := sc.list(clk.Now())
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, sn := range snaps {
			got = append(got, filepath.Base(sn.path))
		}
		want := []string{name(0, true), name(time.Hour, true), name(2*time.Hour, false)}
		if !slices.Equal(got, want) {
			t.Fatalf("kept %v, want the 3 newest of either kind %v", got, want)
		}
		for _, n := range untouchable {
			if !fileExists(filepath.Join(dir, n)) {
				t.Errorf("retention removed %s, which this schedule did not write", n)
			}
		}
		taken := filepath.Join(dir, want[0])
		if !isZip(t, taken) {
			t.Fatal("the compressed schedule wrote a plain snapshot")
		}
		if b, _ := os.ReadFile(inflateToFile(t, taken)); !bytes.Equal(b, good) {
			t.Fatal("the scheduled archive does not hold the verified snapshot")
		}
		if v := sc.snapshotState(); v.kept != 3 || v.lastErr != "" {
			t.Errorf("state = %+v; want 3 kept and no error", v)
		}
	})
}

// TestCompressedSnapshotArchiveShape: a restore accepts exactly one regular member,
// and the generated names follow the plain ones.
func TestCompressedSnapshotArchiveShape(t *testing.T) {
	var two bytes.Buffer
	zw := zip.NewWriter(&two)
	for _, n := range []string{"a", "b"} {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("x"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "two.zip")
	mustWrite(t, p, two.Bytes())
	if _, err := inflateSnapshot(p, io.Discard, 1<<20); !errors.Is(err, ErrSnapshotArchive) {
		t.Errorf("a two-member archive = %v, want ErrSnapshotArchive", err)
	}
	for in, want := range map[string]string{
		"k3sm-snapshot-20261002T120000Z.db": "k3sm-snapshot-20261002T120000Z.zip",
		"etcd-snapshot-a-1":                 "etcd-snapshot-a-1.zip",
	} {
		if got := compressedSnapshotName(in); got != want {
			t.Errorf("compressedSnapshotName(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"/d/etcd-snapshot-a-1.zip": "/d/etcd-snapshot-a-1.tmp",
		"/d/looks-plain.db":        "/d/looks-plain.db.plain.tmp",
	} {
		if got := plainStagingPath(in); got != want {
			t.Errorf("plainStagingPath(%q) = %q, want %q", in, got, want)
		}
	}
}
