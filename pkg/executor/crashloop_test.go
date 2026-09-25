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

package executor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The breaker's decisions are pure functions of the record and a clock, so the
// clock is a value here and no test sleeps. Each case is one sentence of the
// contract in pkg/executor/crashloop.go.
func TestCrashRecordTripsAtThresholdInsideWindow(t *testing.T) {
	t0 := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	step := CrashLoopWindow / time.Duration(CrashLoopThreshold+1) // all inside the window

	tests := []struct {
		name        string
		crashes     int
		spacing     time.Duration
		wantTripped bool
		wantRecent  int
	}{
		{"threshold minus one never trips", CrashLoopThreshold - 1, step, false, CrashLoopThreshold - 1},
		{"threshold inside the window trips", CrashLoopThreshold, step, true, CrashLoopThreshold},
		{"threshold spread wider than the window does not trip", CrashLoopThreshold, CrashLoopWindow / 2, false, 3},
		{"many crashes, all older than the window, do not trip", CrashLoopThreshold * 2, CrashLoopWindow * 2, false, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var r CrashRecord
			var tripped bool
			now := t0
			for i := 0; i < tc.crashes; i++ {
				now = t0.Add(time.Duration(i) * tc.spacing)
				if r.Record(now, CrashOriginCrash, "kine", "tail") {
					tripped = true
				}
			}
			if tripped != tc.wantTripped || r.Tripped() != tc.wantTripped {
				t.Fatalf("tripped = %v (record says %v), want %v", tripped, r.Tripped(), tc.wantTripped)
			}
			if got := r.Recent(now); got != tc.wantRecent {
				t.Fatalf("Recent = %d, want %d", got, tc.wantRecent)
			}
		})
	}
}

func TestCrashRecordTripPersistsThroughPruneUntilCleared(t *testing.T) {
	t0 := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	var r CrashRecord
	for i := 0; i < CrashLoopThreshold; i++ {
		r.Record(t0.Add(time.Duration(i)*time.Second), CrashOriginCrash, "kube-apiserver", "tail")
	}
	if !r.Tripped() {
		t.Fatal("not tripped after the threshold")
	}
	// A day later every crash is outside the window, but the trip is the
	// operator's to clear, not the clock's.
	r.Prune(t0.Add(24 * time.Hour))
	if len(r.Crashes) != 0 {
		t.Fatalf("Prune kept %d crashes older than the window", len(r.Crashes))
	}
	if !r.Tripped() {
		t.Fatal("Prune cleared the trip; only ClearCrashRecord may")
	}
	// Recording again while tripped does not report a second trip.
	if r.Record(t0.Add(25*time.Hour), CrashOriginCrash, "kine", "tail") {
		t.Fatal("Record reported a trip on an already-tripped record")
	}
}

func TestCrashRecordKeepsFutureDatedCrashes(t *testing.T) {
	// A clock that stepped backwards must not let the loop escape the count.
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	r := CrashRecord{Crashes: []Crash{{At: now.Add(time.Hour), Component: "kine"}}}
	r.Prune(now)
	if len(r.Crashes) != 1 {
		t.Fatal("Prune dropped a future-dated crash")
	}
	if r.Recent(now) != 1 {
		t.Fatal("Recent did not count a future-dated crash")
	}
}

// TestParseCrashRecordReadsAPreOriginRecord is the compatibility case that
// matters on upgrade: a record written by a daemon that predates the origin
// field has no "origin" key at all, and every reader of it — the daemon's park
// message, `k3sm status`, the installer's post-restart check — must treat those
// entries as crashes rather than inventing a distinction the file does not
// carry. The JSON is hand-written on purpose: marshalling a Crash here would
// test the round trip of today's struct, not yesterday's file.
func TestParseCrashRecordReadsAPreOriginRecord(t *testing.T) {
	const preB315 = `{
  "crashes": [
    {
      "at": "2026-09-09T12:00:00Z",
      "component": "kube-apiserver",
      "detail": "E0909 apiserver: boom"
    }
  ],
  "tripped_at": "2026-09-09T12:00:00Z"
}`
	rec, err := ParseCrashRecord([]byte(preB315))
	if err != nil {
		t.Fatalf("a record written before the origin field must still parse: %v", err)
	}
	if len(rec.Crashes) != 1 || !rec.Tripped() {
		t.Fatalf("parse lost the record's shape: %+v", rec)
	}
	last, ok := rec.Last()
	if !ok {
		t.Fatal("no last entry")
	}
	if last.Component != "kube-apiserver" || last.Detail != "E0909 apiserver: boom" {
		t.Fatalf("parse lost the entry: %+v", last)
	}
	// The absent key reads as the zero value, and every consumer compares
	// against CrashOriginBringUp — so an old record is a crash, which is what it
	// is: the daemon that wrote it counted nothing else.
	if last.Origin != "" {
		t.Errorf("origin = %q for a record that has no origin key, want the zero value", last.Origin)
	}
	if last.Origin == CrashOriginBringUp {
		t.Error("a pre-origin record must never read as a bring-up failure")
	}
}

func TestCrashRecordFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := CrashLoopPath(dir)
	if filepath.Dir(path) != dir {
		t.Fatalf("CrashLoopPath(%q) = %q, not under the work dir", dir, path)
	}

	// Absent is empty, not an error.
	r, err := ReadCrashRecord(path)
	if err != nil || len(r.Crashes) != 0 || r.Tripped() {
		t.Fatalf("absent record: %+v, %v", r, err)
	}

	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	r.Record(now, CrashOriginBringUp, "kube-scheduler", "E0909 scheduler: boom")
	if err := WriteCrashRecord(path, r); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("record mode = %o, want 0600", st.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind after the rename")
	}

	back, err := ReadCrashRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	last, ok := back.Last()
	if !ok || last.Component != "kube-scheduler" || !last.At.Equal(now) || last.Detail != "E0909 scheduler: boom" {
		t.Fatalf("round trip lost the crash: %+v", back)
	}
	// The origin survives the round trip: a parked daemon's message says whether
	// the control plane died or never came up, and it reads that from here.
	if last.Origin != CrashOriginBringUp {
		t.Fatalf("round trip lost the origin: %q, want %q", last.Origin, CrashOriginBringUp)
	}

	// Clear removes it, and clearing twice is still success.
	if err := ClearCrashRecord(path); err != nil {
		t.Fatal(err)
	}
	if err := ClearCrashRecord(path); err != nil {
		t.Fatalf("second clear: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("record still present after Clear")
	}
}

func TestCrashRecordMalformedFileIsAnError(t *testing.T) {
	path := CrashLoopPath(t.TempDir())
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCrashRecord(path); err == nil {
		t.Fatal("a malformed record read as empty; the caller must be told")
	}
}

// TestRecordPermanentTripsOnFirst is the second tier of the trip: a permanent
// failure opens the breaker on its own, an empty window notwithstanding, while
// the threshold tier (TestCrashRecordTripsAtThresholdInsideWindow's subject) is untouched.
func TestRecordPermanentTripsOnFirst(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var r CrashRecord
	if !r.RecordPermanent(now, CrashOriginBringUp, "provision/kine", "no go", NoGoToolchainRemedy) {
		t.Fatal("a permanent failure did not trip an empty record")
	}
	if !r.Tripped() || !r.TrippedAt.Equal(now) {
		t.Fatalf("TrippedAt = %v, want %v", r.TrippedAt, now)
	}
	last, _ := r.Last()
	if !last.Permanent || last.Remedy != NoGoToolchainRemedy {
		t.Errorf("last entry %+v does not carry the permanent mark and remedy", last)
	}
	if r.RecordPermanent(now.Add(time.Second), CrashOriginBringUp, "provision/kine", "no go", NoGoToolchainRemedy) {
		t.Error("an already-open breaker reported tripping again")
	}

	// Round trip: the mark and the remedy survive the file, which is how the
	// status row reads them after a respawn.
	path := CrashLoopPath(t.TempDir())
	if err := WriteCrashRecord(path, r); err != nil {
		t.Fatal(err)
	}
	back, err := ReadCrashRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if bl, _ := back.Last(); !bl.Permanent || bl.Remedy != NoGoToolchainRemedy {
		t.Errorf("round-tripped entry %+v lost the permanent mark or remedy", bl)
	}

	// A plain Record is still threshold-tier.
	var plain CrashRecord
	if plain.Record(now, CrashOriginBringUp, "provision/kine", "timeout") {
		t.Error("one unclassified failure tripped the breaker")
	}
}
