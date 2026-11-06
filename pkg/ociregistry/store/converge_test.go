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

package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// convergeFixture is a store plus what the tests of the pass need to name its
// blobs. Every repository it pushes to has a tagged row, so it can be a target.
type convergeFixture struct {
	t   *testing.T
	s   *Store
	ctx context.Context
}

func newConvergeFixture(t *testing.T) *convergeFixture {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "registry"), filepath.Join(dir, "registry-state"))
	if err != nil {
		t.Fatal(err)
	}
	return &convergeFixture{t: t, s: s, ctx: context.Background()}
}

// blobBytes is size bytes that differ with seed and hash to a digest no other
// seed's do.
func blobBytes(seed uint64, size int) []byte {
	b := make([]byte, size)
	r := rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8), byte(size), byte(size >> 8), byte(size >> 16)})
	_, _ = r.Read(b)
	return b
}

func (f *convergeFixture) name(repo string) ref.Name {
	f.t.Helper()
	n, err := ref.ParseName(repo)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// push stores body as a blob of repo, and a manifest unique to repo under the
// tag v1, and returns the blob's digest.
func (f *convergeFixture) push(repo string, body []byte) digest.Digest {
	f.t.Helper()
	n := f.name(repo)
	d := digest.FromBytes(body)
	if err := f.s.PutBlob(f.ctx, n, d, bytes.NewReader(body)); err != nil {
		f.t.Fatal(err)
	}
	r, err := ref.ParseReference("v1")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.s.PutManifest(f.ctx, n, r, "application/vnd.oci.image.manifest.v1+json", []byte(`{"repo":"`+repo+`"}`)); err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *convergeFixture) path(repo string, d digest.Digest) string {
	f.t.Helper()
	p, err := f.s.blobPath(f.name(repo), d)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *convergeFixture) stat(repo string, d digest.Digest) os.FileInfo {
	f.t.Helper()
	fi, err := os.Lstat(f.path(repo, d))
	if err != nil {
		f.t.Fatal(err)
	}
	return fi
}

// age sets the blob's mtime to ago before now.
func (f *convergeFixture) age(repo string, d digest.Digest, ago time.Duration) {
	f.t.Helper()
	at := time.Now().Add(-ago)
	if err := os.Chtimes(f.path(repo, d), at, at); err != nil {
		f.t.Fatal(err)
	}
}

// blobUsage is the disk the store's blob files take, each inode once, as du
// of the root counts them.
func (f *convergeFixture) blobUsage() int64 {
	f.t.Helper()
	seen := map[uint64]bool{}
	var total int64
	err := filepath.WalkDir(f.s.Root(), func(p string, e os.DirEntry, err error) error {
		if err != nil || !e.Type().IsRegular() || filepath.Base(filepath.Dir(filepath.Dir(p))) != blobsDir {
			return err
		}
		fi, err := e.Info()
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		if !seen[st.Ino] {
			seen[st.Ino] = true
			total += st.Blocks * 512
		}
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return total
}

// readBlob reads the blob through the store's own read path.
func (f *convergeFixture) readBlob(repo string, d digest.Digest) []byte {
	f.t.Helper()
	r, err := f.s.OpenBlob(f.name(repo), d)
	if err != nil {
		f.t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// allReviewed is a marker that names every repository.
func allReviewed(ref.Name) bool { return true }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestConvergeDedupesAcrossRepositories is the behavior the pass exists for: one
// blob pushed to two repositories without a mount takes one copy's disk after a
// pass, both repositories still read its bytes, nothing extra stays in the
// store, and the pass writes no mtime.
func TestConvergeDedupesAcrossRepositories(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(1, 2<<20)
	d := f.push("team/a", body)
	f.push("team/b", body)
	f.age("team/a", d, time.Hour)
	f.age("team/b", d, 2*time.Hour)
	if os.SameFile(f.stat("team/a", d), f.stat("team/b", d)) {
		t.Fatal("the two pushes already share an inode: the test proves nothing")
	}
	before, keeperTime := f.blobUsage(), f.stat("team/a", d).ModTime()

	rep, err := f.s.Converge(f.ctx, ConvergeOptions{Reviewed: allReviewed, Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}

	a, b := f.stat("team/a", d), f.stat("team/b", d)
	if !os.SameFile(a, b) {
		t.Fatal("the two repositories still hold separate inodes")
	}
	if !a.ModTime().Equal(keeperTime) {
		t.Errorf("the keeper's mtime moved from %v to %v: the pass writes no mtime", keeperTime, a.ModTime())
	}
	if got := before - f.blobUsage(); got < int64(len(body)) {
		t.Errorf("the pass freed %d bytes of a %d byte duplicate", got, len(body))
	}
	if rep.Merged != 1 || rep.ReclaimedBytes != int64(len(body)) {
		t.Errorf("report = %+v, want one merge reclaiming %d", rep, len(body))
	}
	for _, repo := range []string{"team/a", "team/b"} {
		if !bytes.Equal(f.readBlob(repo, d), body) {
			t.Errorf("%s no longer reads the blob's bytes", repo)
		}
		c, err := f.s.Contents(f.name(repo))
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Temps) != 0 || c.Unknown != 0 {
			t.Errorf("%s holds leftovers: %+v", repo, c)
		}
	}

	again, err := f.s.Converge(f.ctx, ConvergeOptions{Reviewed: allReviewed, Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	if again.Merged != 0 {
		t.Errorf("a second pass merged %d: a converged store has nothing to do", again.Merged)
	}
}

// converge is one pass with the options the tests share; set overrides them.
func (f *convergeFixture) converge(set func(*ConvergeOptions)) ConvergeReport {
	f.t.Helper()
	rep, err := f.convergeErr(set)
	if err != nil {
		f.t.Fatal(err)
	}
	return rep
}

func (f *convergeFixture) convergeErr(set func(*ConvergeOptions)) (ConvergeReport, error) {
	o := ConvergeOptions{Reviewed: allReviewed, Log: discardLog()}
	if set != nil {
		set(&o)
	}
	return f.s.Converge(f.ctx, o)
}

// three pushes body to a, b and c, in that order newest first, and returns its
// digest. a is the keeper unless a test changes that.
func (f *convergeFixture) three(body []byte) digest.Digest {
	f.t.Helper()
	d := f.push("a", body)
	f.push("b", body)
	f.push("c", body)
	f.age("a", d, time.Hour)
	f.age("b", d, 2*time.Hour)
	f.age("c", d, 3*time.Hour)
	return d
}

func (f *convergeFixture) same(a, b string, d digest.Digest) bool {
	f.t.Helper()
	return os.SameFile(f.stat(a, d), f.stat(b, d))
}

// noTemps fails when a repository holds a .tmp-<uuid>.
func (f *convergeFixture) noTemps(repos ...string) {
	f.t.Helper()
	for _, r := range repos {
		c, err := f.s.Contents(f.name(r))
		if err != nil {
			f.t.Fatal(err)
		}
		if len(c.Temps) != 0 {
			f.t.Errorf("%s holds a temp: %+v", r, c.Temps)
		}
	}
}

// wantSkip fails unless the report counts n of reason r.
func wantSkip(t *testing.T, rep ConvergeReport, r SkipReason, n int) {
	t.Helper()
	if got := rep.Skipped[r]; got != n {
		t.Errorf("skipped %s = %d, want %d (report %+v)", r, got, n, rep)
	}
}

// corrupt replaces repo's blob with a new inode of the same size and wrong bytes.
func (f *convergeFixture) corrupt(repo string, d digest.Digest, size int, ago time.Duration) {
	f.t.Helper()
	p := f.path(repo, d)
	if err := os.Remove(p); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, blobBytes(99, size), fileMode); err != nil {
		f.t.Fatal(err)
	}
	f.age(repo, d, ago)
}

// logBuffer is a logger whose output a test can read.
func logBuffer() (*slog.Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return slog.New(slog.NewTextHandler(&b, nil)), &b
}

// TestConvergeLimitValues pins the limits of one pass: the scan's entries, the
// merges, the bytes hashed and their rate, and the names on one inode.
func TestConvergeLimitValues(t *testing.T) {
	if convergeMaxEntries != 250_000 || convergeMaxMerges != 1024 || convergeMaxHashBytes != 16<<30 ||
		convergeHashRate != 256<<20 || convergeMaxNames != 32_000 {
		t.Errorf("entries %d, merges %d, hash bytes %d, rate %d, names %d", convergeMaxEntries, convergeMaxMerges,
			int64(convergeMaxHashBytes), convergeHashRate, convergeMaxNames)
	}
}

func TestConvergeChoosesTheNewestThenTheFirstRepository(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(2, 4096)
	d := f.three(body)
	wantInode := f.stat("b", d)
	f.age("b", d, time.Minute) // b is now the newest
	f.converge(nil)
	if !os.SameFile(f.stat("a", d), wantInode) || !os.SameFile(f.stat("c", d), wantInode) {
		t.Error("the newest inode was not the keeper")
	}

	f = newConvergeFixture(t)
	d = f.three(body)
	at := time.Now().Add(-time.Hour)
	for _, r := range []string{"a", "b", "c"} {
		if err := os.Chtimes(f.path(r, d), at, at); err != nil {
			t.Fatal(err)
		}
	}
	wantInode = f.stat("a", d)
	f.converge(nil)
	if !os.SameFile(f.stat("c", d), wantInode) {
		t.Error("a tie did not go to the first repository in lexical order")
	}
}

// TestConvergeKeeperFaults takes the keeper's name away, or swaps it, between its
// verification and the link. The link test sees it first, unless another link
// keeps the count the same, and then the link and its inode check do. Every copy
// stays and no temp is left.
func TestConvergeKeeperFaults(t *testing.T) {
	cases := []struct {
		name    string
		breakIt func(f *convergeFixture, d digest.Digest)
		reason  SkipReason
	}{
		{"gone", func(f *convergeFixture, d digest.Digest) {
			if err := os.Remove(f.path("a", d)); err != nil {
				f.t.Fatal(err)
			}
		}, SkipKeeperFull},
		{"swapped", func(f *convergeFixture, d digest.Digest) {
			p := f.path("a", d)
			if err := os.Remove(p); err != nil {
				f.t.Fatal(err)
			}
			if err := os.WriteFile(p, blobBytes(2, 4096), fileMode); err != nil {
				f.t.Fatal(err)
			}
		}, SkipKeeperFull},
		{"gone, its count held by a new link", func(f *convergeFixture, d digest.Digest) {
			f.linkSession("a", d)
			if err := os.Remove(f.path("a", d)); err != nil {
				f.t.Fatal(err)
			}
		}, SkipKeeperGone},
		{"swapped, its count held by a new link", func(f *convergeFixture, d digest.Digest) {
			f.linkSession("a", d)
			p := f.path("a", d)
			if err := os.Remove(p); err != nil {
				f.t.Fatal(err)
			}
			if err := os.WriteFile(p, blobBytes(2, 4096), fileMode); err != nil {
				f.t.Fatal(err)
			}
		}, SkipKeeperGone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConvergeFixture(t)
			d := f.three(blobBytes(2, 4096))
			b, c := f.stat("b", d), f.stat("c", d)
			done := false
			rep := f.converge(func(o *ConvergeOptions) {
				o.seams.beforeMerge = func(ref.Name) {
					if !done {
						done = true
						tc.breakIt(f, d)
					}
				}
			})
			if rep.Merged != 0 {
				t.Errorf("merged %d with no good keeper", rep.Merged)
			}
			wantSkip(t, rep, tc.reason, 2)
			if !os.SameFile(f.stat("b", d), b) || !os.SameFile(f.stat("c", d), c) {
				t.Error("a target lost its copy")
			}
			f.noTemps("b", "c")
		})
	}
}

// TestConvergeKeeperSwappedBeforeVerify gives step 3 another inode than the scan
// saw. It is refused, and the next-newest is the keeper of what is older than it.
func TestConvergeKeeperSwappedBeforeVerify(t *testing.T) {
	f := newConvergeFixture(t)
	d := f.three(blobBytes(3, 4096))
	b := f.stat("b", d)
	rep := f.converge(func(o *ConvergeOptions) {
		o.seams.scanned = func() {
			p := f.path("a", d)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, blobBytes(3, 4096), fileMode); err != nil {
				t.Fatal(err)
			}
		}
	})
	if rep.Merged != 1 || !os.SameFile(f.stat("c", d), b) {
		t.Errorf("c did not merge into the next-newest: %+v", rep)
	}
	wantSkip(t, rep, SkipKeeperRefused, 1)
}

// TestConvergeCorruptKeeper fails the newest inode's hash. It is logged and stays,
// because a newer target is not corrected by this pass, and the next-newest keeps.
func TestConvergeCorruptKeeper(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(4, 4096)
	d := f.three(body)
	f.corrupt("a", d, len(body), 30*time.Minute)
	bad, b := f.stat("a", d), f.stat("b", d)
	log, buf := logBuffer()
	rep := f.converge(func(o *ConvergeOptions) { o.Log = log })
	if rep.CorruptKeepers != 1 || rep.Merged != 1 {
		t.Errorf("report = %+v, want one corrupt keeper and one merge", rep)
	}
	if !os.SameFile(f.stat("a", d), bad) {
		t.Error("the corrupt inode was replaced: nothing verified was newer than it")
	}
	if !os.SameFile(f.stat("c", d), b) {
		t.Error("c did not merge into the next-newest")
	}
	wantSkip(t, rep, SkipNewer, 1)
	if !strings.Contains(buf.String(), ErrStoreCorrupt.Error()) || !strings.Contains(buf.String(), d.String()) {
		t.Errorf("no corrupt record in %q", buf)
	}
}

// TestConvergeEveryKeeperCorrupt leaves every copy when nothing hashes.
func TestConvergeEveryKeeperCorrupt(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(5, 4096)
	d := f.three(body)
	for i, r := range []string{"a", "b", "c"} {
		f.corrupt(r, d, len(body), time.Duration(i+1)*time.Hour)
	}
	rep := f.converge(nil)
	if rep.Merged != 0 || rep.CorruptKeepers != 2 {
		t.Errorf("report = %+v", rep)
	}
	wantSkip(t, rep, SkipNoKeeper, 2)
	if rep.Pending != 2 {
		t.Errorf("pending = %d, want 2", rep.Pending)
	}
}

// TestConvergeKeepsCopiesWhenTheLinkFails covers errors that are this target's:
// the copy stays, and the next target is still tried.
func TestConvergeKeepsCopiesWhenTheLinkFails(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason SkipReason
	}{
		{unix.EXDEV, SkipCrossDevice},
		{unix.ENOSPC, SkipNoSpace},
		{unix.EIO, SkipLinkFailed},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			f := newConvergeFixture(t)
			d := f.three(blobBytes(6, 4096))
			b, c := f.stat("b", d), f.stat("c", d)
			links := 0
			rep := f.converge(func(o *ConvergeOptions) {
				o.seams.link = func(oldpath, newpath string) error {
					links++
					return &os.LinkError{Op: "link", Old: oldpath, New: newpath, Err: tc.err}
				}
			})
			if links != 2 || rep.Merged != 0 {
				t.Errorf("links = %d, merged = %d, want each target tried and none merged", links, rep.Merged)
			}
			wantSkip(t, rep, tc.reason, 2)
			if !os.SameFile(f.stat("b", d), b) || !os.SameFile(f.stat("c", d), c) {
				t.Error("a target lost its copy")
			}
			if rep.Pending != 2 {
				t.Errorf("pending = %d, want 2", rep.Pending)
			}
		})
	}
}

// TestConvergeKeeperFullSpendsNoBudget is the link error that is the keeper's: one
// target finds out, and the rest are neither hashed nor attempted.
func TestConvergeKeeperFullSpendsNoBudget(t *testing.T) {
	for _, tc := range []error{unix.EMLINK, unix.EPERM, unix.ENOTSUP} {
		t.Run(tc.Error(), func(t *testing.T) {
			f := newConvergeFixture(t)
			size := 4096
			d := f.three(blobBytes(7, size))
			f.push("d", blobBytes(7, size))
			f.age("d", d, 4*time.Hour)
			links := 0
			rep := f.converge(func(o *ConvergeOptions) {
				o.seams.link = func(oldpath, newpath string) error {
					links++
					return &os.LinkError{Op: "link", Old: oldpath, New: newpath, Err: tc}
				}
			})
			if links != 1 {
				t.Errorf("link called %d times, want 1", links)
			}
			if rep.HashedBytes != int64(2*size) {
				t.Errorf("hashed %d, want the keeper and one target (%d)", rep.HashedBytes, 2*size)
			}
			if rep.Merged != 0 {
				t.Errorf("merged %d", rep.Merged)
			}
			wantSkip(t, rep, SkipKeeperFull, 3)
			f.noTemps("b", "c", "d")
		})
	}
}

// TestConvergeCrashAtTheTemp starts from what a crash between the link and the
// rename leaves. The temp's link refuses the keeper, the copy stays, and GC's own
// removal of the temp lets a later pass finish.
func TestConvergeCrashAtTheTemp(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(8, 4096)
	d := f.push("a", body)
	f.push("b", body)
	f.age("a", d, time.Hour)
	f.age("b", d, 2*time.Hour)
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(filepath.Dir(f.path("b", d)), tempPrefix+id)
	if err := os.Link(f.path("a", d), tmp); err != nil {
		t.Fatal(err)
	}
	copyOfB := f.stat("b", d)

	rep := f.converge(nil)
	if rep.Merged != 0 || !os.SameFile(f.stat("b", d), copyOfB) {
		t.Fatalf("merged with a crashed temp on the keeper: %+v", rep)
	}
	wantSkip(t, rep, SkipKeeperRefused, 1)
	if !bytes.Equal(f.readBlob("b", d), body) {
		t.Error("b no longer reads its blob")
	}

	err = f.s.WithLock(f.ctx, f.name("b"), func(l *Locked) error {
		c, err := l.Contents()
		if err != nil {
			return err
		}
		if len(c.Temps) != 1 {
			t.Fatalf("temps = %+v, want the crash's", c.Temps)
		}
		return l.RemoveTemp(c.Temps[0])
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep := f.converge(nil); rep.Merged != 1 || !f.same("a", "b", d) {
		t.Errorf("the pass after the temp was reaped did not merge: %+v", rep)
	}
}

// TestConvergeLeavesNoTempWhenTheRenameFails is the same point reached live.
func TestConvergeLeavesNoTempWhenTheRenameFails(t *testing.T) {
	f := newConvergeFixture(t)
	d := f.three(blobBytes(9, 4096))
	b := f.stat("b", d)
	rep := f.converge(func(o *ConvergeOptions) {
		o.seams.rename = func(oldpath, newpath string) error {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unix.ENOSPC}
		}
	})
	if rep.Merged != 0 || !os.SameFile(f.stat("b", d), b) {
		t.Errorf("report = %+v", rep)
	}
	wantSkip(t, rep, SkipNoSpace, 2)
	f.noTemps("a", "b", "c")
}

// linkSession gives repo's blob a second name as a session, as a commit that
// crashed before removing its session leaves.
func (f *convergeFixture) linkSession(repo string, d digest.Digest) string {
	f.t.Helper()
	id, err := newID()
	if err != nil {
		f.t.Fatal(err)
	}
	p, err := f.s.uploadPath(f.name(repo), id)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.Link(f.path(repo, d), p); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// TestConvergeSessionSharingATargetsInode replaces the target's name. The session
// drops to one link, so it may append again, and only to an inode nothing shares.
func TestConvergeSessionSharingATargetsInode(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(10, 4096)
	d := f.push("a", body)
	f.push("b", body)
	f.age("a", d, time.Hour)
	f.age("b", d, 2*time.Hour)
	id := f.linkSession("b", d)
	if _, err := f.s.AppendUpload(f.ctx, f.name("b"), id, -1, strings.NewReader("x")); !errors.Is(err, ErrUploadUnknown) {
		t.Fatalf("append to a session sharing a blob: %v", err)
	}

	rep := f.converge(nil)
	if rep.Merged != 1 || !f.same("a", "b", d) {
		t.Fatalf("report = %+v", rep)
	}
	if rep.ReclaimedBytes != 0 {
		t.Errorf("reclaimed %d while the session still holds the inode", rep.ReclaimedBytes)
	}
	if _, err := f.s.AppendUpload(f.ctx, f.name("b"), id, -1, strings.NewReader("x")); err != nil {
		t.Errorf("append after the merge: %v", err)
	}
	for _, r := range []string{"a", "b"} {
		if !bytes.Equal(f.readBlob(r, d), body) {
			t.Errorf("the append reached %s's blob", r)
		}
	}
}

// TestConvergeKeeperRefusedForAnUncountedLink covers each name the scan cannot
// see, and a next-newest inode taking over for what is older than it.
func TestConvergeKeeperRefusedForAnUncountedLink(t *testing.T) {
	t.Run("session", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(11, 4096))
		f.linkSession("a", d)
		b := f.stat("b", d)
		rep := f.converge(nil)
		wantSkip(t, rep, SkipKeeperRefused, 1)
		wantSkip(t, rep, SkipNewer, 1)
		if rep.Merged != 1 || !os.SameFile(f.stat("c", d), b) {
			t.Errorf("c did not merge into the next-newest: %+v", rep)
		}
		if f.same("a", "b", d) {
			t.Error("b merged into a refused keeper")
		}
	})
	t.Run("mount after the scan", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.push("a", blobBytes(12, 4096))
		f.push("b", blobBytes(12, 4096))
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.scanned = func() {
				if err := f.s.MountBlob(f.ctx, f.name("z"), f.name("a"), d); err != nil {
					t.Fatal(err)
				}
			}
		})
		if rep.Merged != 0 || f.same("a", "b", d) {
			t.Errorf("merged into a keeper mounted after the scan: %+v", rep)
		}
	})
	t.Run("scan cut off", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(13, 4096))
		if err := f.s.MountBlob(f.ctx, f.name("z"), f.name("a"), d); err != nil {
			t.Fatal(err)
		}
		f.age("a", d, time.Hour)
		// a, b and c each hold a blob and a manifest. Stopping there leaves z's
		// name unread, so a's inode shows one name of two.
		rep := f.converge(func(o *ConvergeOptions) { o.limits.entries = 6 })
		if !rep.ScanTruncated {
			t.Fatal("the scan did not stop at its limit")
		}
		if f.same("a", "b", d) {
			t.Errorf("merged into a keeper the cut-off scan undercounted: %+v", rep)
		}
	})
}

// TestConvergeKeeperRefusedForACountedNameGone is a removal racing the scan, as GC
// makes. Above all, two counted names gone hide one the scan did not count from a
// test of only "more than counted".
func TestConvergeKeeperRefusedForACountedNameGone(t *testing.T) {
	setup := func(t *testing.T) (*convergeFixture, digest.Digest) {
		t.Helper()
		f := newConvergeFixture(t)
		d := f.copies(blobBytes(15, 4096), "a", "b")
		for _, r := range []string{"y", "z"} {
			if err := f.s.MountBlob(f.ctx, f.name(r), f.name("a"), d); err != nil {
				t.Fatal(err)
			}
		}
		f.age("a", d, time.Hour)
		return f, d
	}
	remove := func(f *convergeFixture, d digest.Digest, repos ...string) {
		f.t.Helper()
		for _, r := range repos {
			if err := os.Remove(f.path(r, d)); err != nil {
				f.t.Fatal(err)
			}
		}
	}
	t.Run("an uncounted link behind two removals", func(t *testing.T) {
		f, d := setup(t)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.scanned = func() {
				remove(f, d, "y", "z")
				f.linkSession("a", d)
			}
		})
		if rep.Merged != 0 || f.same("a", "b", d) {
			t.Errorf("merged into a keeper with an uncounted link: %+v", rep)
		}
		wantSkip(t, rep, SkipKeeperRefused, 1)
		if rep.HashedBytes != 0 {
			t.Errorf("hashed %d for a keeper refused by a stat", rep.HashedBytes)
		}
	})
	t.Run("a removal alone costs one pass", func(t *testing.T) {
		f, d := setup(t)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.scanned = func() { remove(f, d, "z") }
		})
		if rep.Merged != 0 || f.same("a", "b", d) {
			t.Errorf("merged on a count the removal made stale: %+v", rep)
		}
		wantSkip(t, rep, SkipKeeperRefused, 1)
		rep = f.converge(nil)
		if rep.Merged != 1 || !f.same("a", "b", d) {
			t.Errorf("the next pass did not merge on its fresh count: %+v", rep)
		}
	})
	t.Run("a removal after the keeper verified stops its merges", func(t *testing.T) {
		f, d := setup(t)
		c := f.copies(blobBytes(15, 4096), "c")
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		f.age("c", c, 3*time.Hour)
		cBefore := f.stat("c", d)
		merges := 0
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.beforeMerge = func(ref.Name) {
				if merges++; merges == 2 {
					remove(f, d, "z")
				}
			}
		})
		if rep.Merged != 1 || !f.same("a", "b", d) {
			t.Errorf("the first merge should have gone through: %+v", rep)
		}
		wantSkip(t, rep, SkipKeeperFull, 1)
		if !os.SameFile(f.stat("c", d), cBefore) || !bytes.Equal(f.readBlob("c", d), blobBytes(15, 4096)) {
			t.Errorf("c lost its copy: %+v", rep)
		}
	})
}

// pinnedAfter reads the pin from the nth read of a link count on.
func pinnedAfter(n int) func(os.FileInfo) uint64 {
	reads := 0
	return func(fi os.FileInfo) uint64 {
		reads++
		if reads > n {
			return convergeNlinkPin
		}
		return nlink(fi)
	}
}

func TestConvergeKeeperRefusedForAPinnedRead(t *testing.T) {
	f := newConvergeFixture(t)
	d := f.three(blobBytes(14, 4096))
	rep := f.converge(func(o *ConvergeOptions) { o.seams.nlink = pinnedAfter(0) })
	if rep.Merged != 0 || f.same("a", "b", d) {
		t.Errorf("merged on a pinned read: %+v", rep)
	}
	if rep.HashedBytes != 0 {
		t.Errorf("hashed %d for a keeper refused by a stat", rep.HashedBytes)
	}

	// A pin first read under the lock stops the merge there. Reads: the keeper's
	// step 3 test and its re-test before the target's hash.
	rep = f.converge(func(o *ConvergeOptions) { o.seams.nlink = pinnedAfter(2) })
	if rep.Merged != 0 || f.same("a", "b", d) {
		t.Errorf("merged on a pinned read under the lock: %+v", rep)
	}
	wantSkip(t, rep, SkipKeeperFull, 2)
}

// TestConvergeLinkTest pins each arm of the keeper's link test. The name limit
// sits below the pin today, so the pin is read here with a larger limit: a read of
// it cannot tell how many names there are, whatever the limit says.
func TestConvergeLinkTest(t *testing.T) {
	for _, tc := range []struct {
		name           string
		links, counted uint64
		limit          uint64
		want           bool
	}{
		{"exact", 2, 2, 100, true},
		{"fewer than counted", 1, 2, 100, false},
		{"uncounted", 3, 2, 100, false},
		{"at the name limit", 100, 100, 100, false},
		{"just under the pin", convergeNlinkPin - 1, convergeNlinkPin - 1, 1 << 20, true},
		{"the pin", convergeNlinkPin, convergeNlinkPin, 1 << 20, false},
		{"the pin, counted past it", convergeNlinkPin, 70_000, 1 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &convergePass{lim: convergeLimits{names: tc.limit}}
			p.o.seams.nlink = func(os.FileInfo) uint64 { return tc.links }
			if got := p.nlinkOK(nil, tc.counted); got != tc.want {
				t.Errorf("nlinkOK = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestConvergeStopsAtTheNameLimit counts the pass's own merges against the limit.
func TestConvergeStopsAtTheNameLimit(t *testing.T) {
	f := newConvergeFixture(t)
	size := 4096
	d := f.three(blobBytes(15, size))
	f.push("d", blobBytes(15, size))
	f.age("d", d, 4*time.Hour)
	rep := f.converge(func(o *ConvergeOptions) { o.limits.names = 3 })
	if rep.Merged != 2 || !f.same("a", "b", d) || !f.same("a", "c", d) || f.same("a", "d", d) {
		t.Errorf("report = %+v, want b and c merged and d left", rep)
	}
	wantSkip(t, rep, SkipKeeperFull, 1)
	if rep.HashedBytes != int64(3*size) {
		t.Errorf("hashed %d, want d left unhashed (%d)", rep.HashedBytes, 3*size)
	}
}

// TestConvergeReplacesACorruptTarget is the repair: logged with its repository and
// digest, counted, and replaced in one rename by bytes verified against the name.
// Another repository sharing the bad inode is replaced too, and no name is lost.
func TestConvergeReplacesACorruptTarget(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(16, 4096)
	d := f.three(body)
	f.corrupt("b", d, len(body), 2*time.Hour)
	if err := os.Remove(f.path("c", d)); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(f.path("b", d), f.path("c", d)); err != nil {
		t.Fatal(err)
	}
	bad, err := os.Open(f.path("b", d))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	log, buf := logBuffer()
	rep := f.converge(func(o *ConvergeOptions) { o.Log = log })
	if rep.CorruptTargets != 1 || rep.CorruptReplaced != 2 || rep.Merged != 2 {
		t.Errorf("report = %+v, want one corrupt inode, two names replaced", rep)
	}
	if rep.ReclaimedBytes != int64(len(body)) {
		t.Errorf("reclaimed %d, want the inode once", rep.ReclaimedBytes)
	}
	for _, r := range []string{"b", "c"} {
		if !bytes.Equal(f.readBlob(r, d), body) {
			t.Errorf("%s does not read the verified bytes", r)
		}
	}
	out := buf.String()
	if !strings.Contains(out, ErrStoreCorrupt.Error()) || !strings.Contains(out, "repository=b") || !strings.Contains(out, d.String()) {
		t.Errorf("no record naming the repository and digest in %q", out)
	}
	if got, err := io.ReadAll(bad); err != nil || bytes.Equal(got, body) {
		t.Errorf("a reader of the old inode saw it change: %v", err)
	}
}

// TestConvergeTargetReadError treats an error reading a target as corruption, with
// the same outcome: logged, counted and replaced.
func TestConvergeTargetReadError(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(17, 4096)
	d := f.push("a", body)
	f.push("b", body)
	f.age("a", d, time.Hour)
	f.age("b", d, 2*time.Hour)
	rep := f.converge(func(o *ConvergeOptions) {
		o.seams.open = func(p string) (*os.File, error) {
			if p == f.path("b", d) {
				return os.OpenFile(p, os.O_WRONLY, 0) // reads fail with EBADF
			}
			return openRegular(p, os.O_RDONLY)
		}
	})
	if rep.CorruptTargets != 1 || rep.CorruptReplaced != 1 || !f.same("a", "b", d) {
		t.Errorf("report = %+v", rep)
	}
}

// TestConvergeLeavesANewerTargetAlone covers a target that is newer at the scan,
// one touched after its hash, and one of the wrong size.
func TestConvergeLeavesANewerTargetAlone(t *testing.T) {
	t.Run("touched after its hash", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.push("a", blobBytes(18, 4096))
		f.push("b", blobBytes(18, 4096))
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.beforeMerge = func(n ref.Name) {
				if err := f.s.TouchBlob(f.ctx, n, d); err != nil {
					t.Fatal(err)
				}
			}
		})
		if rep.Merged != 0 || f.same("a", "b", d) {
			t.Errorf("merged a target newer than its keeper: %+v", rep)
		}
		wantSkip(t, rep, SkipNewer, 1)
	})
	t.Run("wrong size", func(t *testing.T) {
		f := newConvergeFixture(t)
		body := blobBytes(19, 4096)
		d := f.push("a", body)
		f.push("b", body)
		f.push("c", body)
		f.age("a", d, time.Hour)
		f.age("c", d, 3*time.Hour)
		f.corrupt("b", d, len(body)-1, 2*time.Hour)
		short := f.stat("b", d)
		log, buf := logBuffer()
		rep := f.converge(func(o *ConvergeOptions) { o.Log = log })
		if rep.Merged != 1 || !os.SameFile(f.stat("b", d), short) {
			t.Errorf("report = %+v, want c merged and b left", rep)
		}
		wantSkip(t, rep, SkipSize, 1)
		if !strings.Contains(buf.String(), "wrong size") {
			t.Errorf("no record of the wrong size in %q", buf)
		}
	})
	t.Run("swapped after its hash", func(t *testing.T) {
		f := newConvergeFixture(t)
		body := blobBytes(20, 4096)
		d := f.push("a", body)
		f.push("b", body)
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.beforeMerge = func(ref.Name) { f.corrupt("b", d, len(body), 2*time.Hour) }
		})
		if rep.Merged != 0 || f.same("a", "b", d) {
			t.Errorf("merged a target the hash never saw: %+v", rep)
		}
		wantSkip(t, rep, SkipTargetChanged, 1)
	})
}

// TestConvergeDisqualifies covers step 2's tests on the keeper and on a target.
func TestConvergeDisqualifies(t *testing.T) {
	t.Run("a future mtime", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(21, 4096))
		future := time.Now().Add(time.Hour)
		if err := os.Chtimes(f.path("a", d), future, future); err != nil {
			t.Fatal(err)
		}
		b := f.stat("b", d)
		rep := f.converge(nil)
		wantSkip(t, rep, SkipKeeperRefused, 1)
		if rep.Merged != 1 || !os.SameFile(f.stat("c", d), b) || f.same("a", "b", d) {
			t.Errorf("report = %+v, want c merged into b and a left", rep)
		}
	})
	t.Run("a mode other than 0600", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(22, 4096))
		if err := os.Chmod(f.path("a", d), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f.path("c", d), 0o640); err != nil {
			t.Fatal(err)
		}
		b, c := f.stat("b", d), f.stat("c", d)
		rep := f.converge(nil)
		if rep.Merged != 0 || !os.SameFile(f.stat("b", d), b) || !os.SameFile(f.stat("c", d), c) {
			t.Errorf("report = %+v, want nothing merged", rep)
		}
	})
	t.Run("a target's mode changed under the lock", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.push("a", blobBytes(23, 4096))
		f.push("b", blobBytes(23, 4096))
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.beforeMerge = func(ref.Name) {
				if err := os.Chmod(f.path("b", d), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		})
		if rep.Merged != 0 {
			t.Errorf("report = %+v", rep)
		}
		wantSkip(t, rep, SkipOwnerOrMode, 1)
	})
	t.Run("a wrong owner", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(24, 4096))
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.uid = func() uint32 { return uint32(os.Geteuid()) + 1 }
		})
		if rep.Merged != 0 || f.same("a", "b", d) || rep.HashedBytes != 0 {
			t.Errorf("report = %+v", rep)
		}
	})
}

// TestConvergeTargetRepositoryRules: only a repository with a tagged row that the
// marker names is rewritten, and a miss costs no hash. A keeper needs neither.
func TestConvergeTargetRepositoryRules(t *testing.T) {
	t.Run("no marker", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(25, 4096))
		rep := f.converge(func(o *ConvergeOptions) { o.Reviewed = nil })
		if rep.Merged != 0 || rep.HashedBytes != 0 || f.same("a", "b", d) {
			t.Errorf("report = %+v", rep)
		}
		wantSkip(t, rep, SkipNotReviewed, 2)
	})
	t.Run("one repository not reviewed", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(26, 4096))
		rep := f.converge(func(o *ConvergeOptions) {
			o.Reviewed = func(n ref.Name) bool { return n.String() != "b" }
		})
		if rep.Merged != 1 || f.same("a", "b", d) || !f.same("a", "c", d) {
			t.Errorf("report = %+v", rep)
		}
		wantSkip(t, rep, SkipNotReviewed, 1)
	})
	t.Run("no tagged row", func(t *testing.T) {
		f := newConvergeFixture(t)
		body := blobBytes(27, 4096)
		d := f.push("a", body)
		if err := f.s.PutBlob(f.ctx, f.name("b"), d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		rep := f.converge(nil)
		if rep.Merged != 0 || rep.HashedBytes != 0 || f.same("a", "b", d) {
			t.Errorf("report = %+v", rep)
		}
		wantSkip(t, rep, SkipNoTag, 1)
	})
	t.Run("the keeper's repository has no tag", func(t *testing.T) {
		f := newConvergeFixture(t)
		body := blobBytes(28, 4096)
		d := f.push("b", body)
		if err := f.s.PutBlob(f.ctx, f.name("a"), d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		if rep := f.converge(nil); rep.Merged != 1 || !f.same("a", "b", d) {
			t.Errorf("report = %+v", rep)
		}
	})
	t.Run("last tag removed after the hash", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.push("a", blobBytes(29, 4096))
		f.push("b", blobBytes(29, 4096))
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.beforeMerge = func(n ref.Name) {
				if err := f.s.WithLock(f.ctx, n, func(l *Locked) error { return l.SetRows(nil) }); err != nil {
					t.Fatal(err)
				}
			}
		})
		if rep.Merged != 0 || f.same("a", "b", d) {
			t.Errorf("report = %+v", rep)
		}
		wantSkip(t, rep, SkipNoTag, 1)
	})
	t.Run("half-removed layout", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.push("a", blobBytes(30, 4096))
		f.push("b", blobBytes(30, 4096))
		f.age("a", d, time.Hour)
		f.age("b", d, 2*time.Hour)
		rep := f.converge(func(o *ConvergeOptions) {
			o.seams.beforeMerge = func(n ref.Name) {
				dir, err := f.s.repoDir(n)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(dir, indexFile)); err != nil {
					t.Fatal(err)
				}
			}
		})
		if rep.Merged != 0 {
			t.Errorf("report = %+v", rep)
		}
		wantSkip(t, rep, SkipTargetChanged, 1)
		if _, err := os.Lstat(f.path("b", d)); err != nil {
			t.Errorf("the blob went: %v", err)
		}
	})
}

// TestConvergeScanSkips: a temp, a symlink and an empty file take no part.
func TestConvergeScanSkips(t *testing.T) {
	f := newConvergeFixture(t)
	empty := f.push("a", nil)
	f.push("b", nil)
	body := blobBytes(31, 4096)
	d := f.push("a", body)
	f.push("b", body)
	f.age("a", d, time.Hour)
	f.age("b", d, 2*time.Hour)
	dir := filepath.Dir(f.path("c0", f.push("c0", blobBytes(32, 4096))))
	link := filepath.Join(dir, d.Encoded())
	if err := os.Symlink(f.path("b", d), link); err != nil {
		t.Fatal(err)
	}
	rep := f.converge(nil)
	if f.same("a", "b", empty) {
		t.Error("an empty file was merged")
	}
	if rep.Merged != 1 {
		t.Errorf("report = %+v", rep)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink changed: %v %v", fi, err)
	}
}

// TestConvergeTableGroupsByDevice: one digest on two devices is not a duplicate,
// because a link between them cannot exist.
func TestConvergeTableGroupsByDevice(t *testing.T) {
	a, _ := ref.ParseName("a")
	b, _ := ref.ParseName("b")
	c, _ := ref.ParseName("c")
	d := digest.FromString("x")
	at := time.Now()
	tb := newConvergeTable()
	tb.add(a, d, convergeStat{dev: 1, ino: 1, size: 9, mtime: at})
	tb.add(b, d, convergeStat{dev: 2, ino: 1, size: 9, mtime: at})
	if got := tb.work(); len(got) != 0 {
		t.Errorf("one inode per device went further: %+v", got)
	}
	tb.add(c, d, convergeStat{dev: 2, ino: 2, size: 9, mtime: at.Add(time.Second)})
	got := tb.work()
	if len(got) != 1 || got[0].dev != 2 || got[0].order[0].stat.ino != 2 {
		t.Errorf("work = %+v, want device 2, newest inode first", got)
	}
	if tb.names[inodeKey{2, 1}] != 1 {
		t.Errorf("names = %+v", tb.names)
	}
}

// TestConvergeLimits covers the merge limit, largest first, and the hash budget.
func TestConvergeLimits(t *testing.T) {
	t.Run("merge limit takes the largest first", func(t *testing.T) {
		f := newConvergeFixture(t)
		small := f.three(blobBytes(33, 4096))
		big := f.three(blobBytes(34, 8192))
		rep := f.converge(func(o *ConvergeOptions) { o.limits.merges = 2 })
		if rep.Merged != 2 || !f.same("a", "b", big) || !f.same("a", "c", big) || f.same("a", "b", small) {
			t.Errorf("report = %+v", rep)
		}
		if rep.Pending != 2 {
			t.Errorf("pending = %d, want the small blob's 2", rep.Pending)
		}
	})
	t.Run("a blob past the budget converges one target a pass", func(t *testing.T) {
		f := newConvergeFixture(t)
		size := 8192
		d := f.three(blobBytes(35, size))
		lim := func(o *ConvergeOptions) { o.limits.hashBytes = int64(size / 2) }
		rep := f.converge(lim)
		if rep.Merged != 1 || rep.HashedBytes != int64(2*size) {
			t.Errorf("first pass: %+v, want the keeper and one target allowed", rep)
		}
		wantSkip(t, rep, SkipHashBudget, 1)
		if rep.Pending != 1 {
			t.Errorf("pending = %d, want 1", rep.Pending)
		}
		rep = f.converge(lim)
		if rep.Merged != 1 || !f.same("a", "c", d) || !f.same("a", "b", d) {
			t.Errorf("second pass: %+v", rep)
		}
	})
	t.Run("the exemption is the first digest's", func(t *testing.T) {
		f := newConvergeFixture(t)
		big := f.three(blobBytes(36, 8192))
		small := f.three(blobBytes(37, 4096))
		rep := f.converge(func(o *ConvergeOptions) { o.limits.hashBytes = 8192 })
		if !f.same("a", "b", big) {
			t.Errorf("the first digest did not merge: %+v", rep)
		}
		if f.same("a", "b", small) || rep.HashedBytes != 2*8192 {
			t.Errorf("the second digest was hashed past the budget: %+v", rep)
		}
		wantSkip(t, rep, SkipHashBudget, 3)
	})
}

// copies pushes body to each repository, newest first, and returns its digest.
func (f *convergeFixture) copies(body []byte, repos ...string) digest.Digest {
	f.t.Helper()
	var d digest.Digest
	for i, r := range repos {
		d = f.push(r, body)
		f.age(r, d, time.Duration(i+1)*time.Hour)
	}
	return d
}

// passesUntil runs passes over budget until done reports true and returns how many
// it took, or fails at limit.
func (f *convergeFixture) passesUntil(budget int64, rot *ConvergeRotation, limit int, done func() bool) int {
	f.t.Helper()
	for pass := 1; pass <= limit; pass++ {
		f.converge(func(o *ConvergeOptions) {
			o.limits.hashBytes = budget
			o.Rotation = rot
		})
		if done() {
			return pass
		}
	}
	f.t.Fatalf("not done after %d passes", limit)
	return 0
}

// TestConvergeRotation is one pusher's large blob in many copies: it may not set
// the schedule of every pass until its last copy has merged.
func TestConvergeRotation(t *testing.T) {
	const budget = 10_000
	repos := []string{"p/a", "p/b", "p/c", "p/d", "p/e", "p/f"}
	for _, tc := range []struct {
		name string
		size int
	}{
		{"past the budget, on its exemption", 3 * budget},
		{"within the budget, spending all of it", budget / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConvergeFixture(t)
			big := f.copies(blobBytes(70, tc.size), repos...)
			small := f.copies(blobBytes(71, 1024), "v/a", "v/b")
			rot := &ConvergeRotation{}
			pass := f.passesUntil(budget, rot, len(repos), func() bool { return f.same("v/a", "v/b", small) })
			if pass != 2 {
				t.Errorf("the smaller digest merged on pass %d, want 2 of %d copies' passes", pass, len(repos)-1)
			}
			// The large digest still gets there, one target or two each time it leads.
			f.passesUntil(budget, rot, len(repos), func() bool {
				for _, r := range repos[1:] {
					if !f.same(repos[0], r, big) {
						return false
					}
				}
				return true
			})
		})
	}
	t.Run("two large digests take turns ahead of a small one", func(t *testing.T) {
		f := newConvergeFixture(t)
		f.copies(blobBytes(72, 3*budget), repos...)
		f.copies(blobBytes(73, 2*budget), repos...)
		small := f.copies(blobBytes(74, 1024), "v/a", "v/b")
		pass := f.passesUntil(budget, &ConvergeRotation{}, 3, func() bool { return f.same("v/a", "v/b", small) })
		if pass != 3 {
			t.Errorf("the smaller digest merged on pass %d, want 3", pass)
		}
	})
	t.Run("a large digest not hashed keeps its place", func(t *testing.T) {
		f := newConvergeFixture(t)
		big := f.copies(blobBytes(75, 3*budget), repos[:3]...)
		small := f.copies(blobBytes(76, 1024), repos[3:]...)
		rot := &ConvergeRotation{}
		reports := make([]ConvergeReport, 3)
		for i := range reports {
			reports[i] = f.converge(func(o *ConvergeOptions) {
				o.limits.hashBytes = budget
				o.Rotation = rot
			})
		}
		// Led, then waits while the small one leads, then leads again.
		if reports[0].HashedBytes != 6*budget || reports[0].Merged != 1 {
			t.Errorf("pass 1: %+v", reports[0])
		}
		if reports[1].HashedBytes != 2*1024+1024 || reports[1].Merged != 2 || !f.same(repos[3], repos[5], small) {
			t.Errorf("pass 2: %+v", reports[1])
		}
		wantSkip(t, reports[1], SkipHashBudget, 1)
		if reports[2].Merged != 1 || !f.same(repos[0], repos[2], big) {
			t.Errorf("pass 3: %+v", reports[2])
		}
	})
	t.Run("a digest that fails its sync gives way", func(t *testing.T) {
		f := newConvergeFixture(t)
		ds := f.groupsOf(77, 4096, convergeMaxSyncFailures)
		good := f.copies(blobBytes(80, 1024), "v/a", "v/b")
		bad := f.inodeOf("a", ds...)
		rot := &ConvergeRotation{}
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.Rotation = rot
			o.seams.sync = f.syncFailsFor(unix.EIO, bad)
		})
		if !errors.Is(err, unix.EIO) || rep.Merged != 0 {
			t.Fatalf("first pass: %v, %+v", err, rep)
		}
		// The three still fail after it and end this pass too. That error is theirs.
		rep, err = f.convergeErr(func(o *ConvergeOptions) {
			o.Rotation = rot
			o.seams.sync = f.syncFailsFor(unix.EIO, bad)
		})
		if !errors.Is(err, unix.EIO) {
			t.Errorf("second pass: err = %v", err)
		}
		if rep.Merged != 1 || !f.same("v/a", "v/b", good) {
			t.Errorf("the good digest never ran behind three bad ones: %+v", rep)
		}
	})
	t.Run("a finished digest leaves the rotation", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.copies(blobBytes(81, 2048), "v/a", "v/b")
		rot := &ConvergeRotation{}
		f.converge(func(o *ConvergeOptions) { o.Rotation = rot })
		if !f.same("v/a", "v/b", d) {
			t.Fatal("did not merge")
		}
		if len(rot.served) != 0 {
			t.Errorf("rotation holds %d groups with nothing left to do", len(rot.served))
		}
	})
}

// TestConvergeHoldsTheHashRate asks for the wait the bytes hashed so far owe.
func TestConvergeHoldsTheHashRate(t *testing.T) {
	f := newConvergeFixture(t)
	f.three(blobBytes(38, 2<<20))
	start := time.Now()
	var last time.Duration
	f.converge(func(o *ConvergeOptions) {
		o.limits.rate = 1 << 20
		o.seams.clock = func() time.Time { return start }
		o.seams.pace = func(_ context.Context, d time.Duration) error {
			last = max(last, d)
			return nil
		}
	})
	// Three inodes of 2 MiB at 1 MiB/s on a clock that never moves.
	if want := 6 * time.Second; last != want {
		t.Errorf("the last wait was %v, want %v", last, want)
	}
}

// TestConvergeSyncFailures: without F_FULLFSYNC nothing merges, and a directory
// that will not sync after a rename costs its digest with both names good.
func TestConvergeSyncFailures(t *testing.T) {
	t.Run("keeper", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(39, 4096))
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.seams.sync = func(*os.File) error { return unix.ENOTSUP }
		})
		if !errors.Is(err, unix.ENOTSUP) {
			t.Fatalf("err = %v", err)
		}
		if rep.Merged != 0 || f.same("a", "b", d) || rep.HashedBytes != 4096 {
			t.Errorf("report = %+v, want one hash and nothing merged", rep)
		}
		wantSkip(t, rep, SkipSync, 1)
	})
	t.Run("directory", func(t *testing.T) {
		f := newConvergeFixture(t)
		body := blobBytes(40, 4096)
		d := f.three(body)
		c := f.stat("c", d)
		log, buf := logBuffer()
		var dirs int
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.Log = log
			o.seams.sync = func(file *os.File) error {
				fi, err := file.Stat()
				if err != nil {
					return err
				}
				if fi.IsDir() {
					dirs++
					return unix.EIO
				}
				return fullSync(file)
			}
		})
		if err != nil {
			t.Fatalf("err = %v: one failed directory is not three digests in a row", err)
		}
		if dirs != 1 || rep.Merged != 1 {
			t.Errorf("dirs = %d, report = %+v, want the digest left at its first merge", dirs, rep)
		}
		wantSkip(t, rep, SkipSync, 1)
		if !f.same("a", "b", d) || !bytes.Equal(f.readBlob("b", d), body) {
			t.Error("b does not read the keeper")
		}
		if !os.SameFile(f.stat("c", d), c) {
			t.Error("the digest went on after the failed sync")
		}
		if !strings.Contains(buf.String(), "sync") {
			t.Errorf("no record of the failed sync in %q", buf)
		}
		f.noTemps("b")
	})
	t.Run("the real sync runs on a directory", func(t *testing.T) {
		f := newConvergeFixture(t)
		d := f.three(blobBytes(41, 4096))
		var dirs int
		f.converge(func(o *ConvergeOptions) {
			o.seams.sync = func(file *os.File) error {
				if fi, err := file.Stat(); err == nil && fi.IsDir() {
					dirs++
				}
				return fullSync(file)
			}
		})
		if dirs != 2 || !f.same("a", "c", d) {
			t.Errorf("synced %d directories, want one for each of two merges", dirs)
		}
	})
}

// syncFailsFor is a sync seam that fails with err for a file match accepts.
func (f *convergeFixture) syncFailsFor(err error, match func(os.FileInfo) bool) func(*os.File) error {
	return func(file *os.File) error {
		fi, serr := file.Stat()
		if serr != nil {
			return serr
		}
		if match(fi) {
			return err
		}
		return fullSync(file)
	}
}

// inodeOf matches the inode repo's blob d names now.
func (f *convergeFixture) inodeOf(repo string, ds ...digest.Digest) func(os.FileInfo) bool {
	f.t.Helper()
	var held []os.FileInfo
	for _, d := range ds {
		held = append(held, f.stat(repo, d))
	}
	return func(fi os.FileInfo) bool {
		return slices.ContainsFunc(held, func(h os.FileInfo) bool { return os.SameFile(h, fi) })
	}
}

// groupsOf pushes count blobs to a, b and c, each a size larger than the last
// from size up, and returns their digests, largest first.
func (f *convergeFixture) groupsOf(seed uint64, size, count int) []digest.Digest {
	f.t.Helper()
	out := make([]digest.Digest, count)
	for i := range count {
		out[count-1-i] = f.three(blobBytes(seed+uint64(i), size+i*512))
	}
	return out
}

// TestConvergeSyncFailureCostsItsDigest is the bad inode that used to stop every
// pass: the largest group runs first, so nothing after it ever merged.
func TestConvergeSyncFailureCostsItsDigest(t *testing.T) {
	t.Run("a keeper's failure leaves the others to merge", func(t *testing.T) {
		f := newConvergeFixture(t)
		ds := f.groupsOf(50, 4096, 2)
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.seams.sync = f.syncFailsFor(unix.EIO, f.inodeOf("a", ds[0]))
		})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		wantSkip(t, rep, SkipSync, 1)
		if f.same("a", "b", ds[0]) {
			t.Error("merged into a keeper that would not sync")
		}
		if rep.Merged != 2 || !f.same("a", "b", ds[1]) || !f.same("a", "c", ds[1]) {
			t.Errorf("the smaller digest did not merge: %+v", rep)
		}
		if rep.Pending != 2 {
			t.Errorf("pending = %d, want the bad digest's 2", rep.Pending)
		}
	})
	t.Run("a directory's failure leaves the others to merge", func(t *testing.T) {
		f := newConvergeFixture(t)
		ds := f.groupsOf(52, 4096, 2)
		c := f.stat("c", ds[0])
		dirs := 0
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.seams.sync = f.syncFailsFor(unix.EIO, func(fi os.FileInfo) bool {
				if fi.IsDir() {
					dirs++
				}
				return dirs == 1 && fi.IsDir()
			})
		})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		wantSkip(t, rep, SkipSync, 1)
		if !f.same("a", "b", ds[0]) || !os.SameFile(f.stat("c", ds[0]), c) {
			t.Errorf("the digest did not stop at its failed merge: %+v", rep)
		}
		if rep.Merged != 3 || !f.same("a", "c", ds[1]) {
			t.Errorf("the smaller digest did not merge: %+v", rep)
		}
	})
	for _, tc := range []struct {
		name string
		err  error
		dir  bool
	}{
		{"a keeper's ENOTSUP ends the pass", unix.ENOTSUP, false},
		{"a keeper's ENOTTY ends the pass", unix.ENOTTY, false},
		{"a directory's ENOTSUP ends the pass", unix.ENOTSUP, true},
		{"a directory's ENOTTY ends the pass", unix.ENOTTY, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConvergeFixture(t)
			ds := f.groupsOf(54, 4096, 2)
			rep, err := f.convergeErr(func(o *ConvergeOptions) {
				o.seams.sync = f.syncFailsFor(tc.err, func(fi os.FileInfo) bool { return fi.IsDir() == tc.dir })
			})
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			wantSkip(t, rep, SkipSync, 1)
			if f.same("a", "b", ds[1]) {
				t.Errorf("the pass went on to another digest: %+v", rep)
			}
		})
	}
	t.Run("three digests in a row end the pass", func(t *testing.T) {
		f := newConvergeFixture(t)
		f.groupsOf(56, 4096, 4)
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.seams.sync = f.syncFailsFor(unix.EIO, func(fi os.FileInfo) bool { return !fi.IsDir() })
		})
		if !errors.Is(err, unix.EIO) {
			t.Fatalf("err = %v", err)
		}
		wantSkip(t, rep, SkipSync, convergeMaxSyncFailures)
		if want := int64(4096+3*512) + 4096 + 2*512 + 4096 + 512; rep.HashedBytes != want {
			t.Errorf("hashed %d, want %d: the fourth digest should go unread", rep.HashedBytes, want)
		}
		if rep.Pending != 8 {
			t.Errorf("pending = %d, want all of the four digests' 8", rep.Pending)
		}
	})
	t.Run("a digest that syncs restarts the count", func(t *testing.T) {
		f := newConvergeFixture(t)
		ds := f.groupsOf(60, 4096, 5)
		bad := f.inodeOf("a", ds[0], ds[1], ds[3], ds[4])
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.seams.sync = f.syncFailsFor(unix.EIO, bad)
		})
		if err != nil {
			t.Fatalf("err = %v: no three failures were in a row", err)
		}
		wantSkip(t, rep, SkipSync, 4)
		if rep.Merged != 2 || !f.same("a", "b", ds[2]) {
			t.Errorf("the good digest did not merge: %+v", rep)
		}
	})
	t.Run("a directory failure after a keeper's sync still counts", func(t *testing.T) {
		f := newConvergeFixture(t)
		f.groupsOf(66, 4096, 4)
		rep, err := f.convergeErr(func(o *ConvergeOptions) {
			o.seams.sync = f.syncFailsFor(unix.EIO, os.FileInfo.IsDir)
		})
		if !errors.Is(err, unix.EIO) {
			t.Fatalf("err = %v: every keeper synced and every directory failed", err)
		}
		wantSkip(t, rep, SkipSync, convergeMaxSyncFailures)
		if rep.Merged != convergeMaxSyncFailures {
			t.Errorf("merged %d, want one a digest", rep.Merged)
		}
	})
}

// TestConvergeStopsOnContext ends the pass between merges and keeps what it did.
func TestConvergeStopsOnContext(t *testing.T) {
	f := newConvergeFixture(t)
	d := f.three(blobBytes(42, 4096))
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	seen := 0
	rep, err := f.s.Converge(ctx, ConvergeOptions{
		Reviewed: allReviewed,
		Log:      discardLog(),
		seams: convergeSeams{beforeMerge: func(ref.Name) {
			seen++
			if seen == 2 {
				cancel()
			}
		}},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if rep.Merged != 1 || !f.same("a", "b", d) || f.same("a", "c", d) {
		t.Errorf("report = %+v", rep)
	}
	if rep.Pending != 1 {
		t.Errorf("pending = %d, want 1", rep.Pending)
	}
}

// TestConvergeWithLiveReaders runs a pass against readers of every repository. A
// reader sees the blob's bytes throughout, including one holding an old inode
// across the rename.
func TestConvergeWithLiveReaders(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(43, 1<<20)
	repos := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	var d digest.Digest
	for i, r := range repos {
		d = f.push(r, body)
		f.age(r, d, time.Duration(i+1)*time.Hour)
	}
	held, err := f.s.OpenBlob(f.name("h"), d)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, r := range repos {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				rc, err := f.s.OpenBlob(f.name(r), d)
				if err != nil {
					t.Errorf("open %s: %v", r, err)
					return
				}
				got, err := io.ReadAll(rc)
				rc.Close()
				if err != nil || !bytes.Equal(got, body) {
					t.Errorf("%s read %d bytes, err %v", r, len(got), err)
					return
				}
			}
		})
	}
	rep := f.converge(nil)
	close(stop)
	wg.Wait()
	if rep.Merged != len(repos)-1 {
		t.Errorf("report = %+v", rep)
	}
	if got, err := io.ReadAll(held); err != nil || !bytes.Equal(got, body) {
		t.Errorf("a reader holding the old inode lost its bytes: %v", err)
	}
	if rep.ReclaimedBytes != int64((len(repos)-1)*len(body)) {
		t.Errorf("reclaimed %d", rep.ReclaimedBytes)
	}
}
