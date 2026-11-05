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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestPushProceedsWhileTheSweepReadsManifests pauses the sweep at every
// manifest body it reads and pushes a blob into the same repository there.
// Each push must complete within its bound: the collector reads manifests
// without the repository lock, so a sweep never holds pushes for a time
// that grows with the number of manifests.
func TestPushProceedsWhileTheSweepReadsManifests(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	img := e.push(t, n, "v1", "app", []byte("l1"), []byte("l2"), []byte("l3"), []byte("l4"))
	untagged := e.push(t, n, "", "old", []byte("old layer"))
	orphan := e.blob(t, n, []byte("orphan"))
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	var pushed []digest.Digest
	var blocked error
	reads := 0
	c.onRead = func(m ref.Name, _ digest.Digest) {
		if blocked != nil {
			return
		}
		reads++
		body := fmt.Appendf(nil, "pushed during read %d", reads)
		d := digest.FromBytes(body)
		ctx, cancel := context.WithTimeout(e.ctx, 2*time.Second)
		defer cancel()
		if err := e.s.PutBlob(ctx, m, d, bytes.NewReader(body)); err != nil {
			blocked = fmt.Errorf("push during manifest read %d: %w", reads, err)
			return
		}
		pushed = append(pushed, d)
	}
	rep, err := c.Sweep(e.ctx)
	if blocked != nil {
		t.Fatalf("a push waited on the sweep: %v", blocked)
	}
	if err != nil {
		t.Fatal(err)
	}
	if reads < 2 {
		t.Fatalf("the sweep read %d manifests, want at least 2: the test exercises nothing", reads)
	}
	if rep.Count(KindManifest) != 1 || e.has(n, orphan.Digest) || e.has(n, untagged.manifest.Digest) {
		t.Fatalf("sweep: %+v, want the untagged manifest and the orphan reaped", rep)
	}
	for _, d := range append(img.blobs(), pushed...) {
		if !e.has(n, d) {
			t.Errorf("%s was reaped", d)
		}
	}
}

// TestOneUnreadableRepositoryStillWritesTheMarker runs a first sweep over
// three repositories, one of which has a tagged manifest whose body is gone.
// The sweep reports the bad repository, still writes the marker, and the
// next sweep reaps in the good ones while the bad one keeps everything.
func TestOneUnreadableRepositoryStillWritesTheMarker(t *testing.T) {
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	orphans := map[string]digest.Digest{}
	var badImg image
	for _, r := range []string{"a", "bad", "c"} {
		n := name(t, r)
		img := e.push(t, n, "v1", r, []byte(r+"1"), []byte(r+"2"), []byte(r+"3"), []byte(r+"4"))
		orphans[r] = e.blob(t, n, []byte(r+" orphan")).Digest
		if r == "bad" {
			badImg = img
			if err := os.Remove(e.blobFile(t, n, img.manifest.Digest)); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)

	rep, err := c.Sweep(e.ctx)
	if !errors.Is(err, ErrUnreadable) {
		t.Fatalf("first sweep: %v, want ErrUnreadable", err)
	}
	if !rep.ReportOnly || !slices.Equal(rep.Failed, []string{"bad"}) || rep.Count(KindBlob) != 2 {
		t.Fatalf("first sweep: %+v, want report-only, the bad repository failed, two orphans listed", rep)
	}
	if _, err := os.Lstat(filepath.Join(e.s.StateDir(), MarkerName)); err != nil {
		t.Fatalf("no marker after the first sweep: %v", err)
	}

	rep, err = c.Sweep(e.ctx)
	if !errors.Is(err, ErrUnreadable) {
		t.Fatalf("second sweep: %v, want ErrUnreadable", err)
	}
	if rep.ReportOnly || !slices.Equal(rep.Failed, []string{"bad"}) || rep.Count(KindBlob) != 2 {
		t.Fatalf("second sweep: %+v, want the two good orphans reaped and the bad repository failed", rep)
	}
	for _, r := range []string{"a", "c"} {
		if e.has(name(t, r), orphans[r]) {
			t.Errorf("%s: the orphan survived", r)
		}
	}
	bad := name(t, "bad")
	for _, d := range append(badImg.blobs()[1:], orphans["bad"]) {
		if !e.has(bad, d) {
			t.Errorf("bad: %s was reaped", d)
		}
	}
}

// copyTree copies the regular files and directories under src to dst,
// keeping modes and modification times, as a backup restore does.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	type stamp struct {
		p  string
		mt time.Time
	}
	var stamps []stamp
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.MkdirAll(out, fi.Mode().Perm()); err != nil {
				return err
			}
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, b, fi.Mode().Perm()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("copy %s: not a regular file or directory", p)
		}
		stamps = append(stamps, stamp{out, fi.ModTime()})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range slices.Backward(stamps) {
		if err := os.Chtimes(s.p, s.mt, s.mt); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLockedPassAnswersOnlyFromAnUnchangedRead covers the locked pass's
// reader: it answers from the mark's read only for a manifest that is still
// there with the size the mark read, or still absent, and is stale for
// anything else, including a digest the mark never read.
func TestLockedPassAnswersOnlyFromAnUnchangedRead(t *testing.T) {
	d := digest.FromString("manifest")
	gone := fmt.Errorf("%w: %s", store.ErrBlobUnknown, d)
	for _, tc := range []struct {
		name  string
		read  manifestRead
		blobs []store.Blob
		stale bool
	}{
		{"unchanged", manifestRead{present: true, size: 8}, []store.Blob{{Digest: d, Size: 8}}, false},
		{"still absent", manifestRead{err: gone}, nil, false},
		{"removed since", manifestRead{present: true, size: 8}, nil, true},
		{"appeared since", manifestRead{err: gone}, []store.Blob{{Digest: d, Size: 8}}, true},
		{"size changed", manifestRead{present: true, size: 8}, []store.Blob{{Digest: d, Size: 9}}, true},
		{"never read", manifestRead{}, []store.Blob{{Digest: d, Size: 8}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reads{}
			if tc.name != "never read" {
				r[d] = tc.read
			}
			_, err := r.locked(store.Contents{Blobs: tc.blobs})(d)
			if got := errors.Is(err, errStale); got != tc.stale {
				t.Fatalf("stale = %v (%v), want %v", got, err, tc.stale)
			}
		})
	}
}
