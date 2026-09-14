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
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// recordJSON renders a record the way k3sm writes it, so the tests read the
// same bytes a running installer would produce.
func recordJSON(t *testing.T, r Record) string {
	t.Helper()
	r.Version = RecordVersion
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	return string(b)
}

// TestReadDeclaresFromRecord pins the second declaration source: a data root
// named by the k3sm data-volume record is declared a mount point even with no
// /etc/fstab line, so an unmounted one is still refused rather than shadowed.
func TestReadDeclaresFromRecord(t *testing.T) {
	declared := "UUID=DEADBEEF-0000-1111-2222-333344445555 " + testRoot + " apfs rw\n"
	rec := Record{UUID: "6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD", Name: "k3sm", Mountpoint: testRoot, QuotaBytes: 107374182400}

	// A real directory behind a real symlink, for the /private/var spelling:
	// EvalSymlinks is the only part of Read that touches the disk.
	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "private", "var", "lib", "k3sm")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink("private/var", filepath.Join(tmp, "var")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	linkDir := filepath.Join(tmp, "var", "lib", "k3sm")

	tests := []struct {
		name          string
		fsys          fakeFS
		dir           string
		wantDeclared  bool
		wantBy        []string
		wantVolume    *Record
		wantShadowed  bool
		wantMountedOK bool
	}{
		{
			name: "the record alone declares the mount point",
			fsys: fakeFS{
				record: recordJSON(t, rec),
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o755}},
				statfs: map[string]fakeMount{testRoot: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
			},
			dir:          testRoot,
			wantDeclared: true,
			wantBy:       []string{"record"},
			wantVolume:   &rec,
			wantShadowed: true,
		},
		{
			name: "the fstab line alone still declares it",
			fsys: fakeFS{
				fstab:  declared,
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o755}},
				statfs: map[string]fakeMount{testRoot: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
			},
			dir:          testRoot,
			wantDeclared: true,
			wantBy:       []string{"fstab"},
			wantShadowed: true,
		},
		{
			name: "both sources are reported, fstab first",
			fsys: fakeFS{
				fstab:  declared,
				record: recordJSON(t, rec),
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o750, uid: 250}},
				statfs: map[string]fakeMount{testRoot: {on: testRoot, fstype: "apfs", from: "/dev/disk3s7"}},
			},
			dir:           testRoot,
			wantDeclared:  true,
			wantBy:        []string{"fstab", "record"},
			wantVolume:    &rec,
			wantMountedOK: true,
		},
		{
			name: "a record for another directory declares nothing here",
			fsys: fakeFS{
				record: recordJSON(t, Record{UUID: "OTHER", Name: "scratch", Mountpoint: "/Volumes/scratch"}),
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o755}},
				statfs: map[string]fakeMount{testRoot: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
			},
			dir: testRoot,
		},
		{
			name: "a malformed record is ignored, not fatal",
			fsys: fakeFS{
				fstab:  declared,
				record: "{ this is not json",
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o755}},
				statfs: map[string]fakeMount{testRoot: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
			},
			dir:          testRoot,
			wantDeclared: true,
			wantBy:       []string{"fstab"},
			wantShadowed: true,
		},
		{
			name: "a record from a future k3sm is ignored here too",
			fsys: fakeFS{
				record: `{"version":99,"mountpoint":"` + testRoot + `"}`,
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o755}},
				statfs: map[string]fakeMount{testRoot: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
			},
			dir: testRoot,
		},
		{
			name: "a record spelt through /private matches the /var data root",
			fsys: fakeFS{
				record: recordJSON(t, Record{UUID: "SYMLINK", Name: "k3sm", Mountpoint: realDir}),
				stat:   map[string]fakeInfo{linkDir: {name: "k3sm", mode: 0o755}},
				statfs: map[string]fakeMount{linkDir: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
			},
			dir:          linkDir,
			wantDeclared: true,
			wantBy:       []string{"record"},
			wantVolume:   &Record{Version: RecordVersion, UUID: "SYMLINK", Name: "k3sm", Mountpoint: realDir},
			wantShadowed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(tc.fsys, tc.dir)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got.DeclaredMount != tc.wantDeclared {
				t.Fatalf("DeclaredMount = %v, want %v", got.DeclaredMount, tc.wantDeclared)
			}
			if !reflect.DeepEqual(got.DeclaredBy, tc.wantBy) {
				t.Fatalf("DeclaredBy = %v, want %v", got.DeclaredBy, tc.wantBy)
			}
			if tc.wantVolume == nil {
				if got.Volume != nil {
					t.Fatalf("Volume = %+v, want nil", got.Volume)
				}
			} else {
				want := *tc.wantVolume
				want.Version = RecordVersion
				if got.Volume == nil || !reflect.DeepEqual(*got.Volume, want) {
					t.Fatalf("Volume = %+v, want %+v", got.Volume, want)
				}
			}
			if got.Shadowed() != tc.wantShadowed {
				t.Fatalf("Shadowed() = %v, want %v", got.Shadowed(), tc.wantShadowed)
			}
			if got.Mounted != tc.wantMountedOK {
				t.Fatalf("Mounted = %v, want %v", got.Mounted, tc.wantMountedOK)
			}
		})
	}
}

// TestRecordRoundTrip pins the record's one owner: what WriteRecord writes,
// ReadRecord reads back; a removed record reads as "no declaration" rather
// than an error, and removal is idempotent.
func TestRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "io.k3sm.datavol.json")

	t.Run("a missing record is not an error", func(t *testing.T) {
		got, err := ReadRecord(OSFS{}, path)
		if err != nil || got != nil {
			t.Fatalf("ReadRecord = %+v, %v; want nil, nil", got, err)
		}
	})

	want := Record{
		UUID: "6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD", Name: "k3sm",
		Mountpoint: testRoot, QuotaBytes: 107374182400, Encrypted: true,
		CreatedBy: "k3sm 0.1.5", CreatedAt: "2026-09-13T12:00:00Z", Adopted: true,
	}

	t.Run("write then read returns the same record", func(t *testing.T) {
		if err := WriteRecord(path, want); err != nil {
			t.Fatalf("WriteRecord: %v", err)
		}
		got, err := ReadRecord(OSFS{}, path)
		if err != nil {
			t.Fatalf("ReadRecord: %v", err)
		}
		w := want
		w.Version = RecordVersion
		if got == nil || !reflect.DeepEqual(*got, w) {
			t.Fatalf("ReadRecord = %+v, want %+v", got, w)
		}
	})

	t.Run("the file is 0644 and carries the json field names", func(t *testing.T) {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("mode = %v, want 0644", fi.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"version", "uuid", "name", "mountpoint", "quotaBytes", "encrypted", "createdBy", "createdAt", "adopted"} {
			if _, ok := raw[key]; !ok {
				t.Fatalf("record is missing the %q field: %s", key, b)
			}
		}
	})

	t.Run("a version the binary does not know is an error", func(t *testing.T) {
		future := filepath.Join(dir, "future.json")
		if err := os.WriteFile(future, []byte(`{"version":99,"mountpoint":"`+testRoot+`"}`), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := ReadRecord(OSFS{}, future); err == nil {
			t.Fatal("ReadRecord accepted an unknown version")
		}
	})

	t.Run("the version is stamped by the writer, not the caller", func(t *testing.T) {
		lying := filepath.Join(dir, "lying.json")
		if err := WriteRecord(lying, Record{Version: 99, Mountpoint: testRoot}); err != nil {
			t.Fatalf("WriteRecord: %v", err)
		}
		got, err := ReadRecord(OSFS{}, lying)
		if err != nil {
			t.Fatalf("ReadRecord: %v", err)
		}
		if got.Version != RecordVersion {
			t.Fatalf("Version = %d, want %d", got.Version, RecordVersion)
		}
	})

	t.Run("remove is idempotent and leaves no temp files", func(t *testing.T) {
		if err := RemoveRecord(path); err != nil {
			t.Fatalf("RemoveRecord: %v", err)
		}
		if err := RemoveRecord(path); err != nil {
			t.Fatalf("RemoveRecord (second): %v", err)
		}
		got, err := ReadRecord(OSFS{}, path)
		if err != nil || got != nil {
			t.Fatalf("ReadRecord after remove = %+v, %v; want nil, nil", got, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("readdir: %v", err)
		}
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".json" && e.Name()[0] == '.' {
				t.Fatalf("WriteRecord left a temp file behind: %s", e.Name())
			}
		}
	})
}
