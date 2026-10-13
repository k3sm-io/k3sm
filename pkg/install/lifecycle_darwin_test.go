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

package install

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteStopMarkerOnDisk pins the marker write against a real directory:
// 0644 regular file, replaced atomically, and refused under a symlinked or a
// group-writable directory.
func TestWriteStopMarkerOnDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "io.k3sm.stop.json")
	for _, body := range []string{`{"phase":"stopping"}`, `{"phase":"stopped"}`} {
		if err := writeStopMarkerFile(path, []byte(body)); err != nil {
			t.Fatalf("write: %v", err)
		}
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
			t.Fatalf("marker = %v, %v; want a 0644 regular file", fi, err)
		}
		if got, _ := os.ReadFile(path); string(got) != body {
			t.Errorf("marker content = %q, want %q", got, body)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := writeStopMarkerFile(filepath.Join(link, "io.k3sm.stop.json"), []byte("{}")); err == nil {
		t.Error("a marker was written through a symlinked directory")
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := writeStopMarkerFile(filepath.Join(open, "io.k3sm.stop.json"), []byte("{}")); err == nil {
		t.Error("a marker was written into a world-writable directory")
	}
	if err := (darwinSystem{}).RemoveStopMarker(path); err != nil {
		t.Fatal(err)
	}
	if err := (darwinSystem{}).RemoveStopMarker(path); err != nil {
		t.Errorf("removing an absent marker: %v", err)
	}
}
