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
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// wantOnlyDigests fails unless every name in the directory of blob path p is a
// digest. A registry GC over the on-disk layout reads every name there and
// fails on one that is not.
func wantOnlyDigests(t *testing.T, p string) {
	t.Helper()
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if _, err := ref.ParseDigest("sha256:" + e.Name()); err != nil {
			t.Errorf("%s holds %s: %v", filepath.Dir(p), e.Name(), err)
		}
	}
}

// TestConvergeLinksThroughTemps follows one merge: the temp is made in the
// repository's .temps, never among its blobs, and both directories the rename
// crossed are synced after it.
func TestConvergeLinksThroughTemps(t *testing.T) {
	f := newConvergeFixture(t)
	d := f.three(blobBytes(60, 4096))
	var renames [][2]string
	var synced []string
	renamedAt := -1
	rep := f.converge(func(o *ConvergeOptions) {
		o.seams.rename = func(oldpath, newpath string) error {
			wantOnlyDigests(t, newpath)
			renames = append(renames, [2]string{oldpath, newpath})
			if renamedAt < 0 {
				renamedAt = len(synced)
			}
			return os.Rename(oldpath, newpath)
		}
		o.seams.sync = func(file *os.File) error {
			synced = append(synced, file.Name())
			return fullSync(file)
		}
	})
	if rep.Merged != 2 || !f.same("a", "b", d) || !f.same("a", "c", d) {
		t.Fatalf("report = %+v", rep)
	}
	if len(renames) != 2 {
		t.Fatalf("renames = %v", renames)
	}
	for _, r := range renames {
		repo := filepath.Dir(filepath.Dir(filepath.Dir(r[1])))
		if got, want := filepath.Dir(r[0]), filepath.Join(repo, tempsDir); got != want {
			t.Errorf("temp in %s, want %s", got, want)
		}
		if !strings.HasPrefix(filepath.Base(r[0]), tempPrefix) {
			t.Errorf("temp named %s", r[0])
		}
		for _, dir := range []string{filepath.Dir(r[0]), filepath.Dir(r[1])} {
			if !slices.Contains(synced[renamedAt:], dir) {
				t.Errorf("%s was not synced after the rename; synced %v", dir, synced[renamedAt:])
			}
		}
	}
	for _, r := range []string{"a", "b", "c"} {
		wantOnlyDigests(t, f.path(r, d))
	}
	f.noTemps("a", "b", "c")
}

// TestConvergeSyncFailureOnTemps is the temps side of a directory sync that
// fails: the rename stands, and it is counted as any other directory's failure.
func TestConvergeSyncFailureOnTemps(t *testing.T) {
	f := newConvergeFixture(t)
	body := blobBytes(61, 4096)
	d := f.push("a", body)
	f.push("b", body)
	f.age("a", d, time.Hour)
	f.age("b", d, 2*time.Hour)
	rep := f.converge(func(o *ConvergeOptions) {
		o.seams.sync = func(file *os.File) error {
			if filepath.Base(file.Name()) == tempsDir {
				return unix.EIO
			}
			return fullSync(file)
		}
	})
	if rep.Merged != 1 || !f.same("a", "b", d) {
		t.Errorf("report = %+v, want the merge to stand", rep)
	}
	wantSkip(t, rep, SkipSync, 1)
}

// TestConvergeRefusesAnOddTemps covers a .temps that is no directory. Nothing is
// linked through it, every copy stays, and a symlink's target stays empty.
func TestConvergeRefusesAnOddTemps(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, p, elsewhere string)
	}{
		{"file", func(t *testing.T, p, _ string) {
			if err := os.WriteFile(p, nil, fileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, p, elsewhere string) {
			if err := os.Symlink(elsewhere, p); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConvergeFixture(t)
			body := blobBytes(62, 4096)
			d := f.push("a", body)
			f.push("b", body)
			f.age("a", d, time.Hour)
			f.age("b", d, 2*time.Hour)
			elsewhere := t.TempDir()
			repo := filepath.Dir(filepath.Dir(filepath.Dir(f.path("b", d))))
			tc.plant(t, filepath.Join(repo, tempsDir), elsewhere)

			if rep := f.converge(nil); rep.Merged != 0 || f.same("a", "b", d) {
				t.Errorf("merged through a %s: %+v", tc.name, rep)
			}
			if !bytes.Equal(f.readBlob("b", d), body) {
				t.Error("b no longer reads its blob")
			}
			ents, err := os.ReadDir(elsewhere)
			if err != nil || len(ents) != 0 {
				t.Errorf("the symlink's target holds %v, %v", ents, err)
			}
			c, err := f.s.Contents(f.name("b"))
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Temps) != 0 || c.Unknown != 1 {
				t.Errorf("contents %+v, want it counted unknown", c)
			}
		})
	}
}

// TestReplaceBlobLinksThroughTemps covers the other path that makes a temp: a
// corrupt blob replaced by a commit.
func TestReplaceBlobLinksThroughTemps(t *testing.T) {
	ctx := context.Background()
	body := []byte("the real blob")
	d := digest.FromBytes(body)

	t.Run("replaces, leaving no temp", func(t *testing.T) {
		s := newStore(t)
		n := name(t, "app")
		corruptBlob(t, s, n, name(t, "share"), d)
		if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		p, _ := s.blobPath(n, d)
		if got, _ := os.ReadFile(p); !bytes.Equal(got, body) {
			t.Fatalf("blob after commit = %q", got)
		}
		ents, err := os.ReadDir(repoPath(t, s, n, tempsDir))
		if err != nil {
			t.Fatalf("the replacement went through no %s: %v", tempsDir, err)
		}
		if len(ents) != 0 {
			t.Errorf("%s holds %v", tempsDir, entryNames(ents))
		}
	})
	t.Run("keeps the blob when temps is no directory", func(t *testing.T) {
		s := newStore(t)
		n := name(t, "app")
		corruptBlob(t, s, n, name(t, "share"), d)
		if err := os.WriteFile(repoPath(t, s, n, tempsDir), nil, fileMode); err != nil {
			t.Fatal(err)
		}
		if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err == nil {
			t.Fatal("the replacement went through a file")
		}
		p, _ := s.blobPath(n, d)
		if got, _ := os.ReadFile(p); string(got) != "corrupt" {
			t.Fatalf("blob = %q, want it untouched", got)
		}
	})
}

// TestTempsContents is how .temps reads: a temp link is a Temp with no algorithm,
// beside one in the old place, and anything else there is unknown and is kept.
func TestTempsContents(t *testing.T) {
	s := newStore(t)
	n := name(t, "app")
	d := putBlob(t, s, n, "blob")
	alg := repoPath(t, s, n, blobsDir, "sha256")
	temps := repoPath(t, s, n, tempsDir)
	if err := os.Mkdir(temps, dirMode); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(alg, d.Encoded())
	newTemp, oldTemp := filepath.Join(temps, tempPrefix+testUUID), filepath.Join(alg, tempPrefix+testUUID)
	for _, p := range []string{newTemp, oldTemp} {
		if err := os.Link(src, p); err != nil {
			t.Fatal(err)
		}
	}
	stray := filepath.Join(temps, "stray")
	if err := os.WriteFile(stray, nil, fileMode); err != nil {
		t.Fatal(err)
	}
	dirTemp := tempPrefix + "1b0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b"
	if err := os.Mkdir(filepath.Join(temps, dirTemp), dirMode); err != nil {
		t.Fatal(err)
	}

	c, err := s.Contents(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Blobs) != 1 || c.Unknown != 2 {
		t.Errorf("contents %+v, want one blob and two unknown", c)
	}
	if !slices.ContainsFunc(c.Temps, func(x Temp) bool { return x.Algorithm == "" && x.Name == tempPrefix+testUUID }) ||
		!slices.ContainsFunc(c.Temps, func(x Temp) bool { return x.Algorithm == "sha256" && x.Name == tempPrefix+testUUID }) ||
		len(c.Temps) != 2 {
		t.Fatalf("temps %+v, want one in each place", c.Temps)
	}
	for _, refused := range []Temp{
		{Name: "stray"},
		{Name: dirTemp},
		{Name: tempPrefix + "1c0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b"}, // missing
	} {
		if err := s.WithLock(context.Background(), n, func(l *Locked) error { return l.RemoveTemp(refused) }); err == nil {
			t.Errorf("RemoveTemp(%q) succeeded", refused.Name)
		}
	}
	for _, x := range c.Temps {
		locked(t, s, n, func(l *Locked) error { return l.RemoveTemp(x) })
	}
	for _, p := range []string{newTemp, oldTemp} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived: %v", p, err)
		}
	}
	if b, err := os.ReadFile(src); err != nil || string(b) != "blob" {
		t.Fatalf("the blob sharing the temp's inode: %q, %v", b, err)
	}
}

// TestTempsLayout pins what the rest of the store does with the directory: it is
// no repository name, is removed with an empty layout, and a temp in it keeps
// the layout.
func TestTempsLayout(t *testing.T) {
	for _, bad := range []string{tempsDir, "a/" + tempsDir} {
		if _, err := ref.ParseName(bad); err == nil {
			t.Errorf("ParseName(%q) accepted a layout directory", bad)
		}
	}
	cutoff := time.Now().Add(-time.Minute)

	t.Run("removes an empty temps with the layout", func(t *testing.T) {
		s := newStore(t)
		n := name(t, "app")
		emptyRepo(t, s, n)
		if err := os.Mkdir(repoPath(t, s, n, tempsDir), dirMode); err != nil {
			t.Fatal(err)
		}
		if !removeLayout(t, s, n, cutoff) {
			t.Fatal("RemoveLayout kept an empty repository")
		}
		if ents, err := os.ReadDir(repoPath(t, s, n)); err != nil || len(ents) != 0 {
			t.Errorf("left %v, %v", ents, err)
		}
	})
	for _, entry := range []string{tempPrefix + testUUID, "stray"} {
		t.Run("keeps a layout whose temps holds "+entry, func(t *testing.T) {
			s := newStore(t)
			n := name(t, "app")
			emptyRepo(t, s, n)
			if err := os.Mkdir(repoPath(t, s, n, tempsDir), dirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(repoPath(t, s, n, tempsDir, entry), nil, fileMode); err != nil {
				t.Fatal(err)
			}
			if removeLayout(t, s, n, cutoff) {
				t.Fatal("RemoveLayout removed a repository holding a temp")
			}
		})
	}
}
