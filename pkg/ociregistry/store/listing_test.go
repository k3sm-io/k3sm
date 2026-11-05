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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// mkRepo lays out a repository directory by hand (what isRepoDir checks),
// without the fsyncs Init does, so a test can make thousands.
func mkRepo(t testing.TB, root, name string) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Join(dir, blobsDir), dirMode); err != nil {
		t.Fatal(err)
	}
	for f, b := range map[string]string{layoutFile: string(layoutBody), indexFile: `{"schemaVersion":2,"manifests":[]}`} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(b), fileMode); err != nil {
			t.Fatal(err)
		}
	}
}

func walkAll(t *testing.T, s *Store, after string, limit int) []string {
	t.Helper()
	var out []string
	err := s.WalkRepositories(after, func(n ref.Name) bool {
		out = append(out, n.String())
		return len(out) < limit
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestWalkRepositories: the walk is in lexical order (so '-' and '.' sort
// before a nested name's '/'), resumes after an exclusive cursor, and a page
// of a 2,000-repository store reads only the directories on the way to it.
func TestWalkRepositories(t *testing.T) {
	t.Run("lexical order matches Repositories", func(t *testing.T) {
		s, err := OpenWorkDir(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"a", "a-b", "a/b", "a.c", "a/b/c", "a/b-c", "b", "a_x/y"} {
			mkRepo(t, s.root, n)
		}
		repos, err := s.Repositories()
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, n := range repos {
			want = append(want, n.String())
		}
		got := walkAll(t, s, "", 100)
		if !slices.Equal(got, want) || !slices.IsSorted(got) {
			t.Fatalf("walk %v, Repositories %v", got, want)
		}
		for i, after := range want {
			if got := walkAll(t, s, after, 100); !slices.Equal(got, want[i+1:]) {
				t.Errorf("after %q: %v, want %v", after, got, want[i+1:])
			}
		}
	})
	t.Run("a page of 2,000 repositories reads only its path", func(t *testing.T) {
		s, err := OpenWorkDir(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for g := range 20 {
			for r := range 100 {
				n := fmt.Sprintf("g%02d/r%03d", g, r)
				mkRepo(t, s.root, n)
				want = append(want, n)
			}
		}
		slices.Sort(want)
		reads := 0
		s.dirRead = func(string) { reads++ }
		got := walkAll(t, s, "g10/r050", 10)
		if !slices.Equal(got, want[1051:1061]) {
			t.Fatalf("page %v", got)
		}
		// The root, g10, and the ten repositories of the page (each is read
		// for nested names below it); nothing of the other nineteen groups.
		if reads > 12 {
			t.Errorf("a ten-entry page read %d directories", reads)
		}
		reads = 0
		if got := walkAll(t, s, "", 1<<30); !slices.Equal(got, want) {
			t.Fatalf("the full walk returned %d names", len(got))
		}
		if reads < 2000 {
			t.Errorf("the full walk read %d directories", reads)
		}
	})
}

// TestIndexVersion: the version changes with every index write and IndexAt
// reports the version of what it read.
func TestIndexVersion(t *testing.T) {
	s, err := OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n, _ := ref.ParseName("app")
	if _, err := s.IndexVersionOf(n); err == nil {
		t.Fatal("an unknown repository has a version")
	}
	if err := s.Init(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	v1, err := s.IndexVersionOf(n)
	if err != nil {
		t.Fatal(err)
	}
	_, at, err := s.IndexAt(n)
	if err != nil || at != v1 {
		t.Fatalf("IndexAt version %v, %v; stat %v", at, err, v1)
	}
	s.now = func() time.Time { return time.Now().Add(time.Second) }
	if _, err := s.PutManifest(t.Context(), n, ref.Reference{Tag: "t"}, "application/vnd.oci.image.index.v1+json", []byte(`{"schemaVersion":2,"manifests":[]}`)); err != nil {
		t.Fatal(err)
	}
	v2, err := s.IndexVersionOf(n)
	if err != nil || v2 == v1 {
		t.Fatalf("version after a write %v, %v; before %v", v2, err, v1)
	}
}
