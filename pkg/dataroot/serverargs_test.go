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
	"slices"
	"strings"
	"testing"
	"time"
)

// TestServerArgsRecordPath pins where the record lives: inside the data root, so
// an uninstall (which preserves that directory) and a --data-volume migration
// (which copies it) both carry it, and a deliberate reset of the data root
// discards it with the cluster state it belonged to.
func TestServerArgsRecordPath(t *testing.T) {
	if got, want := ServerArgsRecordPath("/var/lib/k3sm"), "/var/lib/k3sm/server-args.json"; got != want {
		t.Errorf("ServerArgsRecordPath = %q, want %q", got, want)
	}
	if got := ServerArgsRecordPath("/opt/lab"); !strings.HasPrefix(got, "/opt/lab/") {
		t.Errorf("ServerArgsRecordPath(%q) = %q, want it inside the data root it was given", "/opt/lab", got)
	}
}

func TestServerArgsRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := ServerArgsRecordPath(dir)
	want := ServerArgsRecord{
		Args:      []string{"--mesh-ip", "100.64.0.1", "--registry-port", "5000"},
		CreatedBy: "k3sm v0.1.0",
		CreatedAt: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}

	t.Run("write then read returns the same record", func(t *testing.T) {
		if err := WriteServerArgsRecord(path, want); err != nil {
			t.Fatalf("WriteServerArgsRecord: %v", err)
		}
		got, err := ReadServerArgsRecord(OSFS{}, path)
		if err != nil {
			t.Fatalf("ReadServerArgsRecord: %v", err)
		}
		w := want
		w.Version = ServerArgsRecordVersion
		if got == nil || !reflect.DeepEqual(*got, w) {
			t.Fatalf("ReadServerArgsRecord = %+v, want %+v", got, w)
		}
	})

	t.Run("the argument ORDER survives, verbatim", func(t *testing.T) {
		got, err := ReadServerArgsRecord(OSFS{}, path)
		if err != nil {
			t.Fatalf("ReadServerArgsRecord: %v", err)
		}
		// The next install renders exactly this slice onto the server argv, so a
		// reordering here is a reordering of the daemon's command line.
		if !slices.Equal(got.Args, want.Args) {
			t.Errorf("args = %v, want %v", got.Args, want.Args)
		}
	})

	t.Run("the file is 0644 and carries the json field names", func(t *testing.T) {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("mode = %v, want 0644 (the record carries no credential)", fi.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"version", "args", "createdBy", "createdAt"} {
			if _, ok := raw[key]; !ok {
				t.Fatalf("record is missing the %q field: %s", key, b)
			}
		}
	})

	t.Run("EncodeServerArgsRecord is the bytes the writer writes", func(t *testing.T) {
		encoded, err := EncodeServerArgsRecord(want)
		if err != nil {
			t.Fatalf("EncodeServerArgsRecord: %v", err)
		}
		onDisk, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(encoded) != string(onDisk) {
			t.Errorf("encoder and writer disagree:\n encoded = %q\n on disk = %q", encoded, onDisk)
		}
	})

	t.Run("the version is stamped by the writer, not the caller", func(t *testing.T) {
		lying := filepath.Join(dir, "lying.json")
		if err := WriteServerArgsRecord(lying, ServerArgsRecord{Version: 99, Args: []string{"--mesh-ip", "100.64.0.1"}}); err != nil {
			t.Fatalf("WriteServerArgsRecord: %v", err)
		}
		got, err := ReadServerArgsRecord(OSFS{}, lying)
		if err != nil {
			t.Fatalf("ReadServerArgsRecord: %v", err)
		}
		if got.Version != ServerArgsRecordVersion {
			t.Fatalf("Version = %d, want %d", got.Version, ServerArgsRecordVersion)
		}
	})

	t.Run("an absent record is not an error", func(t *testing.T) {
		got, err := ReadServerArgsRecord(OSFS{}, filepath.Join(dir, "nothing-here.json"))
		if err != nil || got != nil {
			t.Fatalf("ReadServerArgsRecord = %+v, %v; want nil, nil (a first install has none)", got, err)
		}
	})

	t.Run("a record this binary cannot understand is an error, never an empty answer", func(t *testing.T) {
		for _, tc := range []struct{ name, content string }{
			{"an unknown version", `{"version":99,"args":["--mesh-ip","100.64.0.1"]}`},
			{"not json at all", "{ this is not json"},
			{"a version this binary predates", `{"version":0,"args":[]}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				bad := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".json")
				if err := os.WriteFile(bad, []byte(tc.content), 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
				got, err := ReadServerArgsRecord(OSFS{}, bad)
				if err == nil {
					t.Fatalf("ReadServerArgsRecord accepted %s: %+v", tc.name, got)
				}
				if !strings.Contains(err.Error(), bad) {
					t.Errorf("error %q must name the record %q", err, bad)
				}
			})
		}
	})

	t.Run("write leaves no temp file behind", func(t *testing.T) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("readdir: %v", err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".io.k3sm.") {
				t.Fatalf("WriteServerArgsRecord left a temp file behind: %s", e.Name())
			}
		}
	})
}
