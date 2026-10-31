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
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

const testUUID = "0b0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b"

func repoPath(t *testing.T, s *Store, n ref.Name, elems ...string) string {
	t.Helper()
	d, err := n.Dir(s.Root())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(append([]string{d}, elems...)...)
}

func putBlob(t *testing.T, s *Store, n ref.Name, body string) digest.Digest {
	t.Helper()
	d := digest.FromString(body)
	if err := s.PutBlob(context.Background(), n, d, bytes.NewReader([]byte(body))); err != nil {
		t.Fatal(err)
	}
	return d
}

func backdate(t *testing.T, p string, by time.Duration) {
	t.Helper()
	ts := time.Now().Add(-by)
	if err := os.Chtimes(p, ts, ts); err != nil {
		t.Fatal(err)
	}
}

// locked runs fn under n's lock and fails the test on an error.
func locked(t *testing.T, s *Store, n ref.Name, fn func(*Locked) error) {
	t.Helper()
	if err := s.WithLock(context.Background(), n, fn); err != nil {
		t.Fatal(err)
	}
}

// TestWithLock: an unknown repository is refused, fn's error is returned,
// and while fn runs no other writer of the repository takes its lock, from
// this Store or from a second Store over the same root.
func TestWithLock(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := name(t, "app")
	called := false
	err := s.WithLock(ctx, n, func(*Locked) error { called = true; return nil })
	if !errors.Is(err, ErrRepositoryUnknown) || called {
		t.Fatalf("WithLock on a missing repository: %v, called %v; want ErrRepositoryUnknown, not called", err, called)
	}
	if err := s.Init(ctx, n); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if err := s.WithLock(ctx, n, func(*Locked) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("WithLock: %v, want fn's error", err)
	}

	other, err := Open(s.root, s.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct {
		name string
		s    *Store
	}{{"same store", s}, {"second store", other}} {
		t.Run(w.name, func(t *testing.T) {
			locked(t, s, n, func(*Locked) error {
				// Held: a writer that must take the lock cannot, and gives
				// up when its context ends.
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				if _, err := w.s.NewUpload(cctx, n); !errors.Is(err, context.Canceled) {
					t.Errorf("NewUpload under a held lock: %v, want context.Canceled", err)
				}
				return nil
			})
			// Released: the same writer goes through.
			if _, err := w.s.NewUpload(ctx, n); err != nil {
				t.Errorf("NewUpload after the lock was released: %v", err)
			}
		})
	}
}

func TestReapSession(t *testing.T) {
	ctx := context.Background()
	idleBefore := time.Now().Add(-time.Hour)
	cases := []struct {
		name    string
		prepare func(t *testing.T, s *Store, n ref.Name, id string) (cleanup func())
		want    SessionVerdict
		remains bool // the session path still exists afterwards
	}{
		{
			name:    "live session is kept",
			want:    SessionKept,
			remains: true,
		},
		{
			name: "idle session is removed",
			prepare: func(t *testing.T, s *Store, n ref.Name, id string) func() {
				backdate(t, repoPath(t, s, n, uploadsDir, id), 2*time.Hour)
				return nil
			},
			want: SessionIdle,
		},
		{
			name: "session idle exactly at the cutoff is removed",
			prepare: func(t *testing.T, s *Store, n ref.Name, id string) func() {
				p := repoPath(t, s, n, uploadsDir, id)
				if err := os.Chtimes(p, idleBefore, idleBefore); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			want: SessionIdle,
		},
		{
			name: "committed session is removed and the blob keeps the inode",
			prepare: func(t *testing.T, s *Store, n ref.Name, id string) func() {
				blob := repoPath(t, s, n, blobsDir, "sha256", digest.FromString("body").Encoded())
				if err := os.MkdirAll(filepath.Dir(blob), dirMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(repoPath(t, s, n, uploadsDir, id), blob); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			want: SessionCommitted,
		},
		{
			name: "session held by an upload is busy",
			prepare: func(t *testing.T, s *Store, n ref.Name, id string) func() {
				backdate(t, repoPath(t, s, n, uploadsDir, id), 2*time.Hour)
				f, err := os.Open(repoPath(t, s, n, uploadsDir, id))
				if err != nil {
					t.Fatal(err)
				}
				if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
					t.Fatal(err)
				}
				return func() { f.Close() }
			},
			want:    SessionBusy,
			remains: true,
		},
		{
			name: "missing session is gone",
			prepare: func(t *testing.T, s *Store, n ref.Name, id string) func() {
				if err := os.Remove(repoPath(t, s, n, uploadsDir, id)); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			want: SessionGone,
		},
		{
			name: "session removed between open and lock is gone",
			prepare: func(t *testing.T, s *Store, n ref.Name, id string) func() {
				backdate(t, repoPath(t, s, n, uploadsDir, id), 2*time.Hour)
				s.uploadOpened = func(string) {
					if err := os.Remove(repoPath(t, s, n, uploadsDir, id)); err != nil {
						t.Error(err)
					}
				}
				return nil
			},
			want: SessionGone,
		},
		{
			// The path names another inode after the lock: the opened file
			// is not the session any more, and the new file is not touched.
			name: "session replaced between open and lock is gone",
			prepare: func(t *testing.T, s *Store, n ref.Name, id string) func() {
				p := repoPath(t, s, n, uploadsDir, id)
				backdate(t, p, 2*time.Hour)
				s.uploadOpened = func(string) {
					repl := p + ".new"
					if err := os.WriteFile(repl, []byte("replacement"), fileMode); err != nil {
						t.Error(err)
					}
					backdate(t, repl, 2*time.Hour)
					if err := os.Rename(repl, p); err != nil {
						t.Error(err)
					}
				}
				return nil
			},
			want:    SessionGone,
			remains: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			n := name(t, "app")
			id, err := s.NewUpload(ctx, n)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.AppendUpload(ctx, n, id, 0, bytes.NewReader([]byte("body"))); err != nil {
				t.Fatal(err)
			}
			if tc.prepare != nil {
				if cleanup := tc.prepare(t, s, n, id); cleanup != nil {
					defer cleanup()
				}
			}
			var v SessionVerdict
			locked(t, s, n, func(l *Locked) error {
				var err error
				v, err = l.ReapSession(id, idleBefore)
				return err
			})
			if v != tc.want {
				t.Fatalf("verdict %d, want %d", v, tc.want)
			}
			_, err = os.Lstat(repoPath(t, s, n, uploadsDir, id))
			if exists := err == nil; exists != tc.remains {
				t.Fatalf("session exists %v, want %v (%v)", exists, tc.remains, err)
			}
		})
	}
}

func TestReapSessionRefusesABadID(t *testing.T) {
	s := newStore(t)
	n := name(t, "app")
	if err := s.Init(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if err := s.WithLock(context.Background(), n, func(l *Locked) error {
		_, err := l.ReapSession("../index.json", time.Now())
		return err
	}); err == nil {
		t.Fatal("ReapSession accepted a path as an id")
	}
}

func TestRemoveTemp(t *testing.T) {
	s := newStore(t)
	n := name(t, "app")
	d := putBlob(t, s, n, "blob")
	alg := repoPath(t, s, n, blobsDir, "sha256")
	tmp := filepath.Join(alg, tempPrefix+testUUID)
	if err := os.Link(filepath.Join(alg, d.Encoded()), tmp); err != nil {
		t.Fatal(err)
	}
	dirTemp := tempPrefix + "1b0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b"
	if err := os.Mkdir(filepath.Join(alg, dirTemp), dirMode); err != nil {
		t.Fatal(err)
	}
	refused := []Temp{
		{Algorithm: "sha256", Name: d.Encoded()},           // a blob, not a temp link
		{Algorithm: "sha256", Name: tempPrefix + "nope"},   // not a uuid
		{Algorithm: "md5", Name: tempPrefix + testUUID},    // not an algorithm
		{Algorithm: "..", Name: tempPrefix + testUUID},     // a path
		{Algorithm: "sha256", Name: dirTemp},               // not a regular file
		{Algorithm: "sha512", Name: tempPrefix + testUUID}, // missing
	}
	for _, tt := range refused {
		err := s.WithLock(context.Background(), n, func(l *Locked) error { return l.RemoveTemp(tt) })
		if err == nil {
			t.Errorf("RemoveTemp(%s/%s) succeeded", tt.Algorithm, tt.Name)
		}
	}
	locked(t, s, n, func(l *Locked) error { return l.RemoveTemp(Temp{Algorithm: "sha256", Name: tempPrefix + testUUID}) })
	if _, err := os.Lstat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the temp link survived: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(alg, d.Encoded())); err != nil || string(b) != "blob" {
		t.Fatalf("the blob sharing the temp link's inode: %q, %v", b, err)
	}
	err := s.WithLock(context.Background(), n, func(l *Locked) error { return l.RemoveTemp(Temp{Algorithm: "sha256", Name: tempPrefix + testUUID}) })
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RemoveTemp of a removed link: %v, want ErrNotExist", err)
	}
}

func TestContents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := name(t, "app")
	if _, err := s.Contents(n); !errors.Is(err, ErrRepositoryUnknown) {
		t.Fatalf("Contents of a missing repository: %v, want ErrRepositoryUnknown", err)
	}
	b1, b2 := putBlob(t, s, n, "one"), putBlob(t, s, n, "two")
	sess, err := s.NewUpload(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	linked, err := s.NewUpload(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(repoPath(t, s, n, uploadsDir, linked), repoPath(t, s, n, uploadsDir, linked)+"-x"); err != nil {
		t.Fatal(err)
	}
	alg := repoPath(t, s, n, blobsDir, "sha256")
	if err := os.Link(filepath.Join(alg, b1.Encoded()), filepath.Join(alg, tempPrefix+testUUID)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(alg, "not-a-digest"),
		filepath.Join(alg, tempPrefix+"not-a-uuid"),
		repoPath(t, s, n, blobsDir, "stray-file"),
	} {
		if err := os.WriteFile(p, nil, fileMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(alg, "subdir"), dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(alg, b2.Encoded()), filepath.Join(alg, digest.FromString("three").Encoded())); err != nil {
		t.Fatal(err)
	}
	backdate(t, repoPath(t, s, n, indexFile), time.Hour)
	ifi, err := os.Lstat(repoPath(t, s, n, indexFile))
	if err != nil {
		t.Fatal(err)
	}

	c, err := s.Contents(n)
	if err != nil {
		t.Fatal(err)
	}
	var got []digest.Digest
	for _, b := range c.Blobs {
		got = append(got, b.Digest)
		if b.Size != 3 {
			t.Errorf("blob %s size %d, want 3", b.Digest, b.Size)
		}
	}
	want := []digest.Digest{b1, b2}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("blobs %v, want %v sorted", got, want)
	}
	if len(c.Temps) != 1 || c.Temps[0].Algorithm != "sha256" || c.Temps[0].Name != tempPrefix+testUUID {
		t.Errorf("temps %+v, want the one temp link", c.Temps)
	}
	links := map[string]uint64{}
	for _, se := range c.Sessions {
		links[se.ID] = se.Links
	}
	if len(links) != 2 || links[sess] != 1 || links[linked] != 2 {
		t.Errorf("sessions %+v, want %s with 1 link and %s with 2", c.Sessions, sess, linked)
	}
	// not-a-digest, .tmp-not-a-uuid, the stray file, the subdirectory, the
	// symlink and the extra session link.
	if c.Unknown != 6 {
		t.Errorf("unknown %d, want 6", c.Unknown)
	}
	if !c.IndexModTime.Equal(ifi.ModTime()) {
		t.Errorf("index mtime %s, want %s", c.IndexModTime, ifi.ModTime())
	}
	// Locked.Contents lists the same.
	locked(t, s, n, func(l *Locked) error {
		lc, err := l.Contents()
		if err != nil {
			return err
		}
		if len(lc.Blobs) != len(c.Blobs) || len(lc.Temps) != len(c.Temps) || len(lc.Sessions) != len(c.Sessions) || lc.Unknown != c.Unknown {
			t.Errorf("locked contents %+v, unlocked %+v", lc, c)
		}
		return nil
	})
}

// emptyRepo makes n an empty repository whose index.json is an hour old.
func emptyRepo(t *testing.T, s *Store, n ref.Name) {
	t.Helper()
	if err := s.Init(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	backdate(t, repoPath(t, s, n, indexFile), time.Hour)
}

func removeLayout(t *testing.T, s *Store, n ref.Name, idleBefore time.Time) bool {
	t.Helper()
	var ok bool
	locked(t, s, n, func(l *Locked) error {
		var err error
		ok, err = l.RemoveLayout(idleBefore)
		return err
	})
	return ok
}

func TestRemoveLayout(t *testing.T) {
	ctx := context.Background()
	cutoff := time.Now().Add(-30 * time.Minute)
	refused := []struct {
		name    string
		prepare func(t *testing.T, s *Store, n ref.Name)
	}{
		{"a row", func(t *testing.T, s *Store, n ref.Name) {
			if _, err := s.PutManifest(ctx, n, ref.Reference{Tag: "v1"}, ispec.MediaTypeImageManifest, []byte("{}")); err != nil {
				t.Fatal(err)
			}
			// The manifest blob goes, the row stays.
			if err := os.Remove(repoPath(t, s, n, blobsDir, "sha256", digest.FromString("{}").Encoded())); err != nil {
				t.Fatal(err)
			}
			backdate(t, repoPath(t, s, n, indexFile), time.Hour)
		}},
		{"a young index", func(t *testing.T, s *Store, n ref.Name) {
			backdate(t, repoPath(t, s, n, indexFile), 0)
		}},
		{"a blob", func(t *testing.T, s *Store, n ref.Name) {
			putBlob(t, s, n, "blob")
			backdate(t, repoPath(t, s, n, indexFile), time.Hour)
		}},
		{"a temp link", func(t *testing.T, s *Store, n ref.Name) {
			alg := repoPath(t, s, n, blobsDir, "sha256")
			if err := os.MkdirAll(alg, dirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(alg, tempPrefix+testUUID), nil, fileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{"a session", func(t *testing.T, s *Store, n ref.Name) {
			if _, err := s.NewUpload(ctx, n); err != nil {
				t.Fatal(err)
			}
		}},
		{"an unknown entry", func(t *testing.T, s *Store, n ref.Name) {
			if err := os.WriteFile(repoPath(t, s, n, blobsDir, "stray"), nil, fileMode); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			s := newStore(t)
			n := name(t, "app")
			emptyRepo(t, s, n)
			tc.prepare(t, s, n)
			if removeLayout(t, s, n, cutoff) {
				t.Fatal("RemoveLayout removed a repository that is not empty")
			}
			if !isRepoDir(repoPath(t, s, n)) {
				t.Fatal("a refused RemoveLayout left no repository")
			}
		})
	}

	t.Run("removes an empty layout and keeps nested names", func(t *testing.T) {
		s := newStore(t)
		n, nested := name(t, "team"), name(t, "team/app")
		emptyRepo(t, s, n)
		emptyRepo(t, s, nested)
		if err := os.MkdirAll(repoPath(t, s, n, blobsDir, "sha256"), dirMode); err != nil {
			t.Fatal(err)
		}
		if !removeLayout(t, s, n, cutoff) {
			t.Fatal("RemoveLayout kept an empty repository")
		}
		ents, err := os.ReadDir(repoPath(t, s, n))
		if err != nil {
			t.Fatalf("the directory went: %v", err)
		}
		if names := entryNames(ents); !slices.Equal(names, []string{"app"}) {
			t.Fatalf("left %v, want only the nested repository", names)
		}
		repos, err := s.Repositories()
		if err != nil || len(repos) != 1 || repos[0] != nested {
			t.Fatalf("repositories %v, %v; want only %s", repos, err, nested)
		}
		if err := s.WithLock(ctx, n, func(*Locked) error { return nil }); !errors.Is(err, ErrRepositoryUnknown) {
			t.Fatalf("WithLock on a removed layout: %v, want ErrRepositoryUnknown", err)
		}
		// A push recreates it.
		d := putBlob(t, s, n, "again")
		if _, err := s.StatBlob(n, d); err != nil {
			t.Fatalf("push after removal: %v", err)
		}
	})
}

// TestRemoveLayoutStoppedAfterTheIndex: a removal that stops right after
// index.json is gone (a crash) leaves a directory that is not a repository:
// it is not listed, the lock refuses it, and a push makes a whole layout
// again.
func TestRemoveLayoutStoppedAfterTheIndex(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, other := name(t, "app"), name(t, "other")
	emptyRepo(t, s, n)
	putBlob(t, s, other, "other")
	crash := errors.New("crash")
	s.indexRemoved = func() error { return crash }
	err := s.WithLock(ctx, n, func(l *Locked) error {
		_, err := l.RemoveLayout(time.Now().Add(-30 * time.Minute))
		return err
	})
	if !errors.Is(err, crash) {
		t.Fatalf("RemoveLayout: %v, want the injected stop", err)
	}
	s.indexRemoved = nil
	if _, err := os.Lstat(repoPath(t, s, n, indexFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("index.json after the stop: %v", err)
	}
	if _, err := os.Lstat(repoPath(t, s, n, layoutFile)); err != nil {
		t.Fatalf("oci-layout after the stop: %v (the stop is after index.json only)", err)
	}
	repos, err := s.Repositories()
	if err != nil || !slices.Equal(repos, []ref.Name{other}) {
		t.Fatalf("repositories %v, %v; want only %s", repos, err, other)
	}
	if err := s.WithLock(ctx, n, func(*Locked) error { return nil }); !errors.Is(err, ErrRepositoryUnknown) {
		t.Fatalf("WithLock on a half-removed layout: %v, want ErrRepositoryUnknown", err)
	}
	if _, err := s.Contents(n); !errors.Is(err, ErrRepositoryUnknown) {
		t.Fatalf("Contents of a half-removed layout: %v, want ErrRepositoryUnknown", err)
	}
	// A manifest PUT stores its body as a blob first, which makes the layout.
	if _, err := s.PutManifest(ctx, n, ref.Reference{Tag: "v1"}, ispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2}`)); err != nil {
		t.Fatalf("PutManifest into a half-removed layout: %v", err)
	}
	d := putBlob(t, s, n, "again")
	if !isRepoDir(repoPath(t, s, n)) {
		t.Fatal("the push did not make a whole layout")
	}
	if _, err := s.StatBlob(n, d); err != nil {
		t.Fatal(err)
	}
	if tags, err := s.Tags(n); err != nil || !slices.Equal(tags, []string{"v1"}) {
		t.Fatalf("tags %v, %v", tags, err)
	}
}
