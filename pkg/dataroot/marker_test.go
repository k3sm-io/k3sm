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

package dataroot

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestPurgeMarkerRoundTrip writes a marker with the test's own identity (the
// chown to root needs privilege) and reads it back off the descriptor.
func TestPurgeMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := writeMarker(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("writeMarker: %v", err)
	}
	// Idempotent: a second write replaces the first with the same bytes.
	if err := writeMarker(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("second writeMarker: %v", err)
	}
	facts, err := ReadMarker(dir)
	if err != nil {
		t.Fatalf("ReadMarker: %v", err)
	}
	if !facts.Regular || facts.Mode != MarkerMode || int(facts.UID) != os.Getuid() {
		t.Fatalf("facts = %+v, want a regular %#o file owned by %d", facts, MarkerMode, os.Getuid())
	}
	if string(facts.Content) != filepath.Clean(dir)+"\n" {
		t.Fatalf("content = %q, want the marked path", facts.Content)
	}
	// Everything but the owner passes; as root-owned it would pass whole.
	facts.UID = 0
	if err := CheckMarker(dir, facts); err != nil {
		t.Fatalf("CheckMarker of a root-owned copy: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dir holds %v (%v), want only the marker (no temp left behind)", entries, err)
	}
}

// TestPurgeMarkerRefusals pins every way a marker fails the check.
func TestPurgeMarkerRefusals(t *testing.T) {
	dir := "/var/lib/k3sm"
	good := MarkerFacts{Regular: true, UID: 0, Mode: 0o644, Content: MarkerContent(dir)}
	if err := CheckMarker(dir, good); err != nil {
		t.Fatalf("good marker refused: %v", err)
	}
	for _, tc := range []struct {
		name  string
		edit  func(*MarkerFacts)
		where string
	}{
		{"not a regular file", func(f *MarkerFacts) { f.Regular = false }, dir},
		{"not root-owned", func(f *MarkerFacts) { f.UID = 501 }, dir},
		{"group-writable", func(f *MarkerFacts) { f.Mode = 0o664 }, dir},
		{"world-writable", func(f *MarkerFacts) { f.Mode = 0o646 }, dir},
		{"names another path", func(f *MarkerFacts) { f.Content = MarkerContent("/var/log/k3sm") }, dir},
		{"copied into another directory", func(*MarkerFacts) {}, "/Users/alice"},
		{"empty", func(f *MarkerFacts) { f.Content = nil }, dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := good
			tc.edit(&f)
			if err := CheckMarker(tc.where, f); !errors.Is(err, ErrMarker) {
				t.Fatalf("CheckMarker = %v, want ErrMarker", err)
			}
		})
	}
}

// TestPurgeMarkerReadRefusesSymlinkAndReportsAbsence proves the marker is
// never followed through a symlink, and that absence keeps ReadFile's contract.
func TestPurgeMarkerReadRefusesSymlinkAndReportsAbsence(t *testing.T) {
	dir := t.TempDir()
	if err := VerifyMarker(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("VerifyMarker of an unmarked dir = %v, want fs.ErrNotExist", err)
	}
	outside := filepath.Join(t.TempDir(), "real")
	if err := os.WriteFile(outside, MarkerContent(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, MarkerPath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMarker(dir); !errors.Is(err, ErrMarker) {
		t.Fatalf("ReadMarker through a symlink = %v, want ErrMarker", err)
	}
	if err := writeMarker(filepath.Join(dir, "nope"), os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("writeMarker into a missing dir succeeded")
	}
}
