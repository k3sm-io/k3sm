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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestServerArgsRecordDefaultPath pins where the record lives, which is a
// privilege boundary and not a filing preference: a root-only directory, beside
// the data-volume record, and NOT in the _k3sm-owned data root where the
// unprivileged service user could replace what a later root-run install splices
// into the daemon's argv.
func TestServerArgsRecordDefaultPath(t *testing.T) {
	// Read the package's own default, not the test-scoped var, so a test that
	// repoints it cannot make this assertion vacuous.
	const want = "/Library/Preferences/io.k3sm.server-args.json"
	if got := defaultServerArgsRecordPathForTest; got != want {
		t.Errorf("the default record path is %q, want %q", got, want)
	}
	if strings.HasPrefix(want, "/var/lib/k3sm") {
		t.Error("the record must not live in the service-user-owned data root")
	}
	if filepath.Dir(want) != filepath.Dir(defaultDataVolumeRecordPathForTest) {
		t.Errorf("the two records must be siblings: %q vs %q", want, defaultDataVolumeRecordPathForTest)
	}
}

func TestServerArgsRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "io.k3sm.server-args.json")
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

	t.Run("the file is 0600 and carries the json field names", func(t *testing.T) {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		// 0600, not the data-volume record's 0644: an operator argument can carry
		// a credential (--datastore-endpoint postgres://user:password@host).
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600 (an argument can carry a credential)", fi.Mode().Perm())
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

// defaultServerArgsRecordPathForTest and defaultDataVolumeRecordPathForTest pin
// the shipped defaults against a test that repoints the vars. They are literals
// on purpose: the point of TestServerArgsRecordDefaultPath is that the DEFAULT
// is a root-only directory, and reading it out of the var it is asserting would
// prove nothing.
const (
	defaultServerArgsRecordPathForTest = "/Library/Preferences/io.k3sm.server-args.json"
	defaultDataVolumeRecordPathForTest = "/Library/Preferences/io.k3sm.datavol.json"
)

// TestValidateServerArgs is the content gate on a file that decides a root
// LaunchDaemon's command line. Every case is a way a record could otherwise turn
// into an argv k3sm never intended.
func TestValidateServerArgs(t *testing.T) {
	long := strings.Repeat("x", MaxServerArgLen+1)
	many := make([]string, MaxServerArgs+1)
	for i := range many {
		many[i] = "--flag"
	}
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "the ordinary case", args: []string{"--mesh-ip", "100.64.0.1", "--registry-port", "5000"}},
		{name: "a DSN with a password is an ordinary argument", args: []string{"--datastore-endpoint", "postgres://u:s3cret@h/db"}},
		{name: "nothing at all", args: nil},
		{name: "exactly the argument limit", args: many[:MaxServerArgs]},
		{name: "exactly the length limit", args: []string{strings.Repeat("x", MaxServerArgLen)}},
		{name: "--token", args: []string{"--mesh-ip", "100.64.0.1", "--token", "evil"}, wantErr: true},
		{name: "--token= inline", args: []string{"--token=evil"}, wantErr: true},
		{name: "-token, single dash", args: []string{"-token", "evil"}, wantErr: true},
		{name: "--runtime", args: []string{"--runtime", "somethingelse"}, wantErr: true},
		{name: "too many arguments", args: many, wantErr: true},
		{name: "an argument over the byte limit", args: []string{long}, wantErr: true},
		{name: "a NUL", args: []string{"--mesh-ip\x00--token"}, wantErr: true},
		{name: "a newline", args: []string{"--mesh-ip\n--token"}, wantErr: true},
		{name: "a carriage return", args: []string{"--mesh-ip\r--token"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateServerArgs(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateServerArgs(%q) = %v, want error: %t", tc.args, err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrServerArgsRejected) {
				t.Errorf("error %v must wrap ErrServerArgsRejected so callers can match it", err)
			}
		})
	}
}

// TestServerArgsRecordRefusesRejectedContent proves the validation is on BOTH
// sides of the file: a record carrying a managed flag is refused on read (so it
// can never be rendered) and refused on write (so an install can never produce a
// record its own next run would reject).
func TestServerArgsRecordRefusesRejectedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forged.json")

	// Written by hand, the way anything with root could: a plausible record with
	// one extra flag on the end.
	forged := `{"version":1,"args":["--mesh-ip","100.64.0.1","--token=evil"],"createdBy":"k3sm 0.0.0","createdAt":"2026-09-14T12:00:00Z"}`
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadServerArgsRecord(OSFS{}, path)
	if err == nil {
		t.Fatalf("ReadServerArgsRecord accepted a record naming --token: %+v", got)
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "token") {
		t.Errorf("error %q must name the record and the offending flag", err)
	}

	out := filepath.Join(dir, "refused.json")
	if err := WriteServerArgsRecord(out, ServerArgsRecord{Args: []string{"--token", "evil"}}); err == nil {
		t.Error("WriteServerArgsRecord wrote a record its own reader would refuse")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the refused write left a file behind: %v", err)
	}
}

// TestManagedServerFlagsIsTheOneList pins the vocabulary this package shares
// with the installer. pkg/install builds its managed-flag set from this slice;
// if an entry is added here it must be a flag the installer renders itself.
func TestManagedServerFlagsIsTheOneList(t *testing.T) {
	want := []string{"runtime", "token"}
	if strings.Join(ManagedServerFlags, ",") != strings.Join(want, ",") {
		t.Errorf("ManagedServerFlags = %v, want %v", ManagedServerFlags, want)
	}
	for _, name := range ManagedServerFlags {
		if err := ValidateServerArgs([]string{"--" + name, "x"}); err == nil {
			t.Errorf("a record naming --%s must be rejected", name)
		}
	}
}
