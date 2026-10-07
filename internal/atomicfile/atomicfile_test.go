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

package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// dirNames lists dir's entry names.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestWriteNew pins the install: the bytes and mode land at the path, an existing
// path is refused with fs.ErrExist and left untouched, and no temp file survives any
// return.
func TestWriteNew(t *testing.T) {
	t.Run("absent: installed with its mode, no temp left", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o600, 0o644} {
			dir := t.TempDir()
			p := filepath.Join(dir, "f")
			if err := WriteNew(p, []byte("data"), mode); err != nil {
				t.Fatalf("WriteNew: %v", err)
			}
			got, err := os.ReadFile(p)
			if err != nil || string(got) != "data" {
				t.Errorf("content %q, err %v", got, err)
			}
			if info, err := os.Lstat(p); err != nil || info.Mode() != mode {
				t.Errorf("mode %v, err %v, want %v", info.Mode(), err, mode)
			}
			if names := dirNames(t, dir); !slices.Equal(names, []string{"f"}) {
				t.Errorf("dir holds %v, want [f]", names)
			}
		}
	})
	t.Run("existing: fs.ErrExist, untouched, no temp left", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, []byte("incumbent"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := WriteNew(p, []byte("new"), 0o600); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("err = %v, want fs.ErrExist", err)
		}
		if got, _ := os.ReadFile(p); string(got) != "incumbent" {
			t.Errorf("the incumbent was changed to %q", got)
		}
		if names := dirNames(t, dir); !slices.Equal(names, []string{"f"}) {
			t.Errorf("dir holds %v, want [f]", names)
		}
	})
	t.Run("missing directory: error", func(t *testing.T) {
		if err := WriteNew(filepath.Join(t.TempDir(), "absent", "f"), []byte("x"), 0o600); err == nil {
			t.Fatal("WriteNew into a missing directory must fail")
		}
	})
}

// TestReapOrphans pins that only the target's own temp files go: an orphan temp is
// removed, while the target, another target's temp, look-alikes and a non-regular
// entry stay.
func TestReapOrphans(t *testing.T) {
	dir := t.TempDir()
	keep := map[string]string{
		"ca.key":             "the target",
		".other.key.tmp-123": "another target's temp",
		".ca.key.tmp-":       "no digits",
		".ca.key.tmp-12x":    "not all digits",
		"ca.key.tmp-123":     "no leading dot",
	}
	for name, data := range keep {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, orphan := range []string{".ca.key.tmp-1", ".ca.key.tmp-4294967295"} {
		if err := os.WriteFile(filepath.Join(dir, orphan), []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, ".ca.key.tmp-77"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ReapOrphans(dir, "ca.key"); err != nil {
		t.Fatalf("ReapOrphans: %v", err)
	}
	want := []string{".ca.key.tmp-", ".ca.key.tmp-12x", ".ca.key.tmp-77", ".other.key.tmp-123", "ca.key", "ca.key.tmp-123"}
	if got := dirNames(t, dir); !slices.Equal(got, want) {
		t.Errorf("after reaping dir holds %v, want %v", got, want)
	}
	for name, data := range keep {
		if got, _ := os.ReadFile(filepath.Join(dir, name)); string(got) != data {
			t.Errorf("%s changed", name)
		}
	}
	if err := ReapOrphans(filepath.Join(dir, "absent"), "ca.key"); err != nil {
		t.Errorf("an absent dir must not be an error: %v", err)
	}
}

// Replace must leave a fresh regular file with exactly the requested mode: a
// pre-existing wider-mode file does not keep its mode, and a symlink at the path is
// replaced rather than written through.
func TestReplaceNeverFollowsALinkAndResetsTheMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Replace(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("Replace over a 0644 file: %v", err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Fatalf("after Replace: mode %v, err %v; want a regular 0600 file", fi.Mode(), err)
	}

	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Replace(link, []byte("secret"), 0o600); err != nil {
		t.Fatalf("Replace over a symlink: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "victim" {
		t.Fatalf("Replace wrote through the symlink: target now %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the link path is %v (err %v); want a regular 0600 file", fi.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if isTempOf(e.Name(), tempPrefix("client.key")) || isTempOf(e.Name(), tempPrefix("linked.key")) {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}
