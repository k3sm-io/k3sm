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

package registrysvc

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readStateFile reads and decodes the record in workDir, failing the test on
// anything but success.
func readStateFile(t *testing.T, workDir string) State {
	t.Helper()
	b, err := os.ReadFile(StatePath(workDir))
	if err != nil {
		t.Fatalf("read the state record: %v", err)
	}
	st, err := ParseState(b)
	if err != nil {
		t.Fatalf("ParseState: %v", err)
	}
	return st
}

// TestWriteState pins the record's on-disk contract: owner-only, a full
// replacement on every write, and a round trip through ParseState.
func TestWriteState(t *testing.T) {
	since := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		st   State
	}{
		{name: "serving", st: State{State: StateServing, Port: 5000, Addr: "127.0.0.1:5000", Since: since}},
		{name: "disabled carries its reason", st: State{State: StateDisabled, Port: 5000, Addr: "127.0.0.1:5000",
			Reason: "registry port already held", Since: since}},
		{name: "reclaimed carries the pid", st: State{State: StateReclaimed, Port: 5000, Addr: "127.0.0.1:5000",
			ReclaimedPID: 4242, Since: since}},
		{name: "stopped", st: State{State: StateStopped, Port: 5000, Addr: "127.0.0.1:5000", Since: since}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			// A previous record with a wider mode is replaced, not reused.
			if err := os.WriteFile(StatePath(wd), []byte(`{"state":"serving"}`), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := WriteState(wd, tc.st); err != nil {
				t.Fatalf("WriteState: %v", err)
			}
			fi, err := os.Stat(StatePath(wd))
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != 0o600 {
				t.Errorf("mode = %o, want 600", got)
			}
			got := readStateFile(t, wd)
			if !got.Since.Equal(tc.st.Since) {
				t.Errorf("since = %v, want %v", got.Since, tc.st.Since)
			}
			got.Since = tc.st.Since
			if got != tc.st {
				t.Errorf("round trip = %+v, want %+v", got, tc.st)
			}
		})
	}
}

// TestParseStateRejectsGarbage: a record that does not decode is an error, never
// a zero State a reader could mistake for a real one.
func TestParseStateRejectsGarbage(t *testing.T) {
	if _, err := ParseState([]byte("not json")); err == nil {
		t.Fatal("ParseState accepted a record that is not JSON")
	}
}

// TestServiceRecord: the service stamps its own port and address on every
// transition, and a Shutdown of a service with no child records nothing (so a
// failed or never-started registry is not reported as stopped).
func TestServiceRecord(t *testing.T) {
	wd := t.TempDir()
	s, err := New(Config{WorkDir: wd, Port: 5123})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(StatePath(wd)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Shutdown with no child wrote a record (stat err %v)", err)
	}

	before := time.Now().Add(-time.Second)
	s.record(StateDisabled, "bring up the ingest registry: port held", 77)
	got := readStateFile(t, wd)
	if got.State != StateDisabled || got.Port != 5123 || got.Addr != "127.0.0.1:5123" ||
		got.Reason != "bring up the ingest registry: port held" || got.ReclaimedPID != 77 {
		t.Errorf("record = %+v", got)
	}
	if got.Since.Before(before) {
		t.Errorf("since = %v, before the write", got.Since)
	}

	s.record(StateServing, "", 0)
	if got := readStateFile(t, wd); got.State != StateServing || got.Reason != "" || got.ReclaimedPID != 0 {
		t.Errorf("a later transition did not replace the record: %+v", got)
	}
}

// TestServiceRecordSurvivesAnUnwritableWorkDir: a write that fails is logged,
// never a panic or a change to what the registry does.
func TestServiceRecordSurvivesAnUnwritableWorkDir(t *testing.T) {
	s, err := New(Config{WorkDir: "/nonexistent-k3sm-registry-state-test", Port: 5123})
	if err != nil {
		t.Fatal(err)
	}
	s.record(StateServing, "", 0)
}

// TestWriteStatePublishesACopy: with the status directory beside the work dir,
// the record is also published there, 0644 and byte-identical, so an ordinary
// account can report it; without the directory only the original is written.
func TestWriteStatePublishesACopy(t *testing.T) {
	st := State{State: StateDisabled, Port: 5000, Addr: "127.0.0.1:5000", Reason: "port held",
		Since: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)}

	t.Run("status directory present", func(t *testing.T) {
		root := t.TempDir()
		wd := filepath.Join(root, "server")
		for _, d := range []string{wd, filepath.Join(root, statusSubdir)} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := WriteState(wd, st); err != nil {
			t.Fatalf("WriteState: %v", err)
		}
		orig, err := os.ReadFile(StatePath(wd))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := os.ReadFile(PublishedStatePath(wd))
		if err != nil {
			t.Fatalf("no published copy: %v", err)
		}
		if string(orig) != string(pub) {
			t.Errorf("published copy %q differs from the original %q", pub, orig)
		}
		for path, want := range map[string]os.FileMode{StatePath(wd): 0o600, PublishedStatePath(wd): 0o644} {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != want {
				t.Errorf("%s mode = %o, want %o", path, got, want)
			}
		}
	})

	t.Run("no status directory", func(t *testing.T) {
		root := t.TempDir()
		wd := filepath.Join(root, "server")
		if err := os.Mkdir(wd, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := WriteState(wd, st); err != nil {
			t.Fatalf("WriteState: %v", err)
		}
		if _, err := os.Stat(PublishedStatePath(wd)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a copy was published with no status directory (stat err %v)", err)
		}
	})
}
