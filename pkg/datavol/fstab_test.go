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

package datavol_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/datavol/datavoltest"
)

// fstabAt writes content to a temp fstab and returns its path plus an FS that
// serves it, so the read side and the write side see the same file.
func fstabAt(t *testing.T, content string) (string, *datavoltest.Fake) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fstab")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write fstab: %v", err)
		}
	}
	f := datavoltest.New()
	f.Files[path] = content
	return path, f
}

// reread returns what is on disk at path now.
func reread(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fstab: %v", err)
	}
	return string(data)
}

// TestEnsureFstabLine pins the second declaration: the line an older k3sm and
// diskarbitrationd both read, written once and never duplicated.
func TestEnsureFstabLine(t *testing.T) {
	const line = "UUID=" + rigUUID + " " + testRoot + " apfs rw,nobrowse,nosuid,nodev"

	t.Run("an absent fstab is created with the line", func(t *testing.T) {
		path, f := fstabAt(t, "")
		added, err := datavol.EnsureFstabLine(f.FS(), path, rigUUID, testRoot)
		if err != nil {
			t.Fatalf("EnsureFstabLine: %v", err)
		}
		if !added {
			t.Fatal("added = false, want true")
		}
		if got := reread(t, path); got != line+"\n" {
			t.Fatalf("fstab = %q, want %q", got, line+"\n")
		}
		if _, err := os.Stat(path + ".k3sm-bak"); err == nil {
			t.Fatal("a file that did not exist was backed up")
		}
	})

	t.Run("the line is appended after the operator's own, which are kept", func(t *testing.T) {
		previous := "#\n# Warning - this file should only be modified with vifs(8)\n#\nLABEL=Backup /Volumes/Backup hfs rw\n"
		path, f := fstabAt(t, previous)
		added, err := datavol.EnsureFstabLine(f.FS(), path, rigUUID, testRoot)
		if err != nil {
			t.Fatalf("EnsureFstabLine: %v", err)
		}
		if !added {
			t.Fatal("added = false, want true")
		}
		got := reread(t, path)
		if !strings.HasPrefix(got, previous) || !strings.HasSuffix(got, line+"\n") {
			t.Fatalf("fstab = %q", got)
		}
		if backup := reread(t, path+".k3sm-bak"); backup != previous {
			t.Fatalf("backup = %q, want the previous content", backup)
		}
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("mode = %v, %v; want 0644", fi.Mode().Perm(), err)
		}
	})

	t.Run("an existing line for the mount point is kept exactly as written", func(t *testing.T) {
		previous := "UUID=SOMEONE-ELSES " + testRoot + " apfs rw\n"
		path, f := fstabAt(t, previous)
		added, err := datavol.EnsureFstabLine(f.FS(), path, rigUUID, testRoot)
		if err != nil {
			t.Fatalf("EnsureFstabLine: %v", err)
		}
		if added {
			t.Fatal("added = true over an existing declaration")
		}
		if got := reread(t, path); got != previous {
			t.Fatalf("fstab = %q, want it untouched", got)
		}
	})

	t.Run("a file with no trailing newline still gets a line of its own", func(t *testing.T) {
		path, f := fstabAt(t, "LABEL=Backup /Volumes/Backup hfs rw")
		if _, err := datavol.EnsureFstabLine(f.FS(), path, rigUUID, testRoot); err != nil {
			t.Fatalf("EnsureFstabLine: %v", err)
		}
		got := reread(t, path)
		if strings.Count(got, "\n") != 2 || !strings.HasSuffix(got, line+"\n") {
			t.Fatalf("fstab = %q", got)
		}
	})

	t.Run("a line for another mount point does not count as ours", func(t *testing.T) {
		path, f := fstabAt(t, "UUID=OTHER /Volumes/scratch apfs rw\n")
		added, err := datavol.EnsureFstabLine(f.FS(), path, rigUUID, testRoot)
		if err != nil {
			t.Fatalf("EnsureFstabLine: %v", err)
		}
		if !added {
			t.Fatal("added = false; an unrelated line is not a declaration of our mount point")
		}
	})
}

// TestRemoveFstabLine pins the delete side: exactly the lines for our mount
// point go, and nothing else in the operator's file is touched.
func TestRemoveFstabLine(t *testing.T) {
	t.Run("our line goes and the operator's stay", func(t *testing.T) {
		previous := "#\nLABEL=Backup /Volumes/Backup hfs rw\nUUID=" + rigUUID + " " + testRoot + " apfs rw,nobrowse\n"
		path, f := fstabAt(t, previous)
		removed, err := datavol.RemoveFstabLine(f.FS(), path, testRoot)
		if err != nil {
			t.Fatalf("RemoveFstabLine: %v", err)
		}
		if !removed {
			t.Fatal("removed = false, want true")
		}
		got := reread(t, path)
		if strings.Contains(got, testRoot) {
			t.Fatalf("fstab still declares the data root: %q", got)
		}
		if !strings.Contains(got, "LABEL=Backup") || !strings.Contains(got, "#") {
			t.Fatalf("fstab lost the operator's lines: %q", got)
		}
		if backup := reread(t, path+".k3sm-bak"); backup != previous {
			t.Fatalf("backup = %q", backup)
		}
	})

	t.Run("every line for the mount point goes, not just the first", func(t *testing.T) {
		path, f := fstabAt(t, "UUID=A "+testRoot+" apfs rw\nUUID=B "+testRoot+" apfs rw\nLABEL=X /Volumes/X hfs rw\n")
		removed, err := datavol.RemoveFstabLine(f.FS(), path, testRoot)
		if err != nil {
			t.Fatalf("RemoveFstabLine: %v", err)
		}
		if !removed {
			t.Fatal("removed = false, want true")
		}
		if got := reread(t, path); strings.Contains(got, testRoot) {
			t.Fatalf("a duplicate declaration survived: %q", got)
		}
	})

	t.Run("no line for the mount point rewrites nothing", func(t *testing.T) {
		previous := "LABEL=Backup /Volumes/Backup hfs rw\n"
		path, f := fstabAt(t, previous)
		removed, err := datavol.RemoveFstabLine(f.FS(), path, testRoot)
		if err != nil {
			t.Fatalf("RemoveFstabLine: %v", err)
		}
		if removed {
			t.Fatal("removed = true with nothing to remove")
		}
		if got := reread(t, path); got != previous {
			t.Fatalf("fstab = %q, want it untouched", got)
		}
		if _, err := os.Stat(path + ".k3sm-bak"); err == nil {
			t.Fatal("a no-op backed the file up")
		}
	})

	t.Run("an absent fstab is not an error", func(t *testing.T) {
		path, f := fstabAt(t, "")
		removed, err := datavol.RemoveFstabLine(f.FS(), path, testRoot)
		if err != nil || removed {
			t.Fatalf("RemoveFstabLine = %v, %v; want false, nil", removed, err)
		}
	})
}
