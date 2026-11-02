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

package gc

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// rootIno returns the inode of the store root.
func rootIno(t *testing.T, e *env) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(e.s.Root(), &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// emptyDir removes everything inside dir and keeps dir itself.
func emptyDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range ents {
		if err := os.RemoveAll(filepath.Join(dir, ent.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *env) markerExists(t *testing.T) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(e.s.StateDir(), MarkerName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// TestRestoredRootReportsOnlyAgain restores a backup that has no store id
// into the same root directory, as an rsync or tar restore does: the root's
// inode is unchanged, and the state directory still holds the marker. The
// restored root gets a new store id, so the next sweep only reports.
func TestRestoredRootReportsOnlyAgain(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	e.push(t, n, "v1", "app", []byte("l1"), []byte("l2"), []byte("l3"))
	orphan := e.blob(t, n, []byte("orphan"))
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	if rep := e.sweep(t, c); !rep.ReportOnly || !e.markerExists(t) {
		t.Fatalf("first sweep: %+v, want report-only and the marker written", rep)
	}

	backup := t.TempDir()
	copyTree(t, e.s.Root(), backup)
	if err := os.Remove(filepath.Join(backup, store.IDFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	ino := rootIno(t, e)
	emptyDir(t, e.s.Root())
	copyTree(t, backup, e.s.Root())
	if rootIno(t, e) != ino {
		t.Fatal("the restore replaced the root directory; the test exercises nothing")
	}

	rep := e.sweep(t, c)
	if !rep.ReportOnly || rep.Count(KindBlob) != 1 || !e.has(n, orphan.Digest) {
		t.Fatalf("sweep after the restore: %+v, want report-only naming the orphan, and the orphan kept", rep)
	}
	if rep := e.sweep(t, c); rep.ReportOnly || e.has(n, orphan.Digest) {
		t.Fatalf("sweep after the restored root's own first sweep: %+v, want the orphan reaped", rep)
	}
}

// TestEmptyFirstSweepThenRestoreReportsOnly sweeps an empty store, then
// restores content into its root. A sweep over a store with no repository
// reviews nothing, so it writes no marker, and the first sweep over the
// restored content only reports.
func TestEmptyFirstSweepThenRestoreReportsOnly(t *testing.T) {
	src := newEnv(t)
	n := name(t, "app")
	src.clk.set(-2 * time.Hour)
	src.push(t, n, "v1", "app", []byte("l1"), []byte("l2"), []byte("l3"))
	orphan := src.blob(t, n, []byte("orphan"))

	e := newEnv(t)
	e.clk = src.clk
	e.s.SetClock(e.clk.now)
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	if rep := e.sweep(t, c); !rep.ReportOnly || len(rep.Objects) != 0 {
		t.Fatalf("sweep over the empty store: %+v, want report-only and nothing", rep)
	}
	if e.markerExists(t) {
		t.Fatal("a sweep over an empty store wrote the marker")
	}

	copyTree(t, src.s.Root(), e.s.Root())
	rep := e.sweep(t, c)
	if !rep.ReportOnly || rep.Count(KindBlob) != 1 || !e.has(n, orphan.Digest) {
		t.Fatalf("sweep after the restore: %+v, want report-only naming the orphan, and the orphan kept", rep)
	}
}

// TestCopiedStoreFollowsItsStoreID copies a store whose first sweep has run,
// marker included, to a new root. A copy that carries the store id is the
// same store, so its sweep deletes; a copy without it gets a new id and
// only reports. The original's next sweep deletes.
func TestCopiedStoreFollowsItsStoreID(t *testing.T) {
	for _, tc := range []struct {
		name       string
		keepID     bool
		reportOnly bool
	}{
		{"with the store id", true, false},
		{"without the store id", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.push(t, n, "v1", "app", []byte("l1"), []byte("l2"), []byte("l3"))
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.clk.set(0)
			if rep := e.sweep(t, c); !rep.ReportOnly {
				t.Fatalf("first sweep: %+v, want report-only", rep)
			}

			dst := t.TempDir()
			root, state := filepath.Join(dst, "registry"), filepath.Join(dst, "registry-state")
			copyTree(t, e.s.Root(), root)
			copyTree(t, e.s.StateDir(), state)
			if !tc.keepID {
				if err := os.Remove(filepath.Join(root, store.IDFile)); err != nil {
					t.Fatal(err)
				}
			}
			s2, err := store.Open(root, state)
			if err != nil {
				t.Fatal(err)
			}
			s2.SetClock(e.clk.now)
			e2 := &env{s: s2, clk: e.clk, ctx: e.ctx}
			c2 := e2.collector(t, -3*time.Hour)
			e.clk.set(0)
			rep := e2.sweep(t, c2)
			if rep.ReportOnly != tc.reportOnly || rep.Count(KindBlob) != 1 || e2.has(n, orphan.Digest) != tc.reportOnly {
				t.Fatalf("sweep over the copy: %+v, want report-only %v naming the orphan", rep, tc.reportOnly)
			}

			if rep := e.sweep(t, c); rep.ReportOnly || e.has(n, orphan.Digest) {
				t.Fatalf("second sweep over the original: %+v, want the orphan reaped", rep)
			}
		})
	}
}

// TestTransientFailureLeavesNoMarker fails one repository of a first sweep
// for a reason that may pass (the repository removed mid-sweep, a manifest
// body that cannot be opened). The sweep reports it and writes no marker, so
// the next sweep only reports again and reviews that repository.
func TestTransientFailureLeavesNoMarker(t *testing.T) {
	for _, tc := range []struct {
		name    string
		root    bool // the case cannot run as root
		breakIt func(t *testing.T, e *env, c *Collector, bad image)
	}{
		{"repository removed during the sweep", false, func(t *testing.T, e *env, c *Collector, _ image) {
			done := false
			c.onRead = func(_ ref.Name, _ digest.Digest) {
				if !done {
					done = true
					if err := os.RemoveAll(e.dir(t, name(t, "bad"))); err != nil {
						t.Error(err)
					}
				}
			}
		}},
		{"manifest body that cannot be opened", true, func(t *testing.T, e *env, _ *Collector, bad image) {
			p := e.blobFile(t, name(t, "bad"), bad.manifest.Digest)
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.root && os.Geteuid() == 0 {
				t.Skip("root opens a mode-0 file")
			}
			e := newEnv(t)
			e.clk.set(-2 * time.Hour)
			var badImg image
			for _, r := range []string{"a", "bad"} {
				n := name(t, r)
				img := e.push(t, n, "v1", r, []byte(r+"1"), []byte(r+"2"), []byte(r+"3"))
				e.blob(t, n, []byte(r+" orphan"))
				if r == "bad" {
					badImg = img
				}
			}
			c := e.collector(t, -3*time.Hour)
			e.clk.set(0)
			tc.breakIt(t, e, c, badImg)

			rep, err := c.Sweep(e.ctx)
			if err == nil || errors.Is(err, ErrUnreadable) || !rep.ReportOnly || !slices.Equal(rep.Failed, []string{"bad"}) {
				t.Fatalf("first sweep: %+v, %v; want report-only, bad failed with an error that is not ErrUnreadable", rep, err)
			}
			if e.markerExists(t) {
				t.Fatal("a transient failure in the report-only sweep wrote the marker")
			}
			c.onRead = nil
			if rep, _ := c.Sweep(e.ctx); !rep.ReportOnly || !e.has(name(t, "a"), digest.FromString("a orphan")) {
				t.Fatalf("second sweep: %+v, want report-only again", rep)
			}
		})
	}
}
