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
				if r.Record(now, "kine", "tail") {
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
		r.Record(t0.Add(time.Duration(i)*time.Second), "kube-apiserver", "tail")
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
	if r.Record(t0.Add(25*time.Hour), "kine", "tail") {
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
	r.Record(now, "kube-scheduler", "E0909 scheduler: boom")
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
