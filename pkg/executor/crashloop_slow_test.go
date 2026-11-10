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
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCrashLoopBringUpTimeoutUnderPressureBacksOff pins the slow bring-up
// contract: a pressure-flagged health timeout backs the next lap off instead of
// counting toward the park, a fast failure still counts, a healthy bring-up
// ends the streak, and a restart keeps the previous component log. The clock
// is a value; nothing sleeps.
func TestCrashLoopBringUpTimeoutUnderPressureBacksOff(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
		8 * time.Minute, 10 * time.Minute, 10 * time.Minute}

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"pressure-flagged timeouts back off and never trip below the limit", func(t *testing.T) {
			if len(want) < 6 || len(want) >= BringUpSlowStreakLimit {
				t.Fatalf("case needs 6 <= laps < limit, have %d laps and limit %d", len(want), BringUpSlowStreakLimit)
			}
			var r CrashRecord
			now := t0
			for i, w := range want {
				// Each lap is a full health wait, then the backoff the record asks for:
				// the laps together span far more than CrashLoopWindow.
				now = now.Add(healthTimeout)
				if r.RecordBringUpSlow(now, "kube-apiserver", "kube-apiserver not healthy within 1m30s") {
					t.Fatalf("lap %d tripped the breaker", i+1)
				}
				got, until := r.BringUpBackoff(now)
				if got != w {
					t.Fatalf("lap %d: backoff %s, want %s", i+1, got, w)
				}
				if !until.Equal(now.Add(w)) {
					t.Fatalf("lap %d: until %s, want %s", i+1, until, now.Add(w))
				}
				if n := r.Recent(now); n != 0 {
					t.Fatalf("lap %d: Recent = %d, want 0 (slow laps are not counted)", i+1, n)
				}
				// Survives the respawn: the next process reads the record back.
				b, err := jsonRoundTrip(r)
				if err != nil {
					t.Fatal(err)
				}
				r = b
				// Halfway through the wait the remainder is what is left.
				if half, _ := r.BringUpBackoff(now.Add(w / 2)); half != w-w/2 {
					t.Fatalf("lap %d: remaining at half %s, want %s", i+1, half, w-w/2)
				}
				now = now.Add(w)
				if left, _ := r.BringUpBackoff(now); left != 0 {
					t.Fatalf("lap %d: backoff still %s once it elapsed", i+1, left)
				}
			}
			if r.Tripped() {
				t.Fatal("record tripped below BringUpSlowStreakLimit")
			}
		}},
		{"the streak limit parks with a remedy", func(t *testing.T) {
			var r CrashRecord
			now := t0
			for i := 1; i <= BringUpSlowStreakLimit; i++ {
				now = now.Add(healthTimeout + BringUpSlowBackoffCap)
				tripped := r.RecordBringUpSlow(now, "kube-apiserver", "slow")
				if tripped != (i == BringUpSlowStreakLimit) {
					t.Fatalf("lap %d: tripped = %v", i, tripped)
				}
			}
			last, _ := r.Last()
			if last.Origin != CrashOriginBringUpSlow || !last.Permanent || last.Remedy != BringUpSlowRemedy {
				t.Fatalf("limit entry = %+v, want a slow entry carrying BringUpSlowRemedy", last)
			}
		}},
		{"five fast failures still trip", func(t *testing.T) {
			var r CrashRecord
			r.RecordBringUpSlow(t0, "kube-apiserver", "slow") // a streak does not shield them
			var tripped bool
			for i := 1; i <= CrashLoopThreshold; i++ {
				tripped = r.Record(t0.Add(time.Duration(i)*time.Second), CrashOriginBringUp, "kine", "kine exited during bring-up")
				if tripped != (i == CrashLoopThreshold) {
					t.Fatalf("fast failure %d: tripped = %v", i, tripped)
				}
			}
			if wait, _ := r.BringUpBackoff(t0.Add(10 * time.Second)); wait != 0 || r.SlowStreak != 0 {
				t.Fatalf("a non-slow entry must end the streak: wait %s, streak %d", wait, r.SlowStreak)
			}
		}},
		{"unpressured timeouts are counted as today", func(t *testing.T) {
			// The classification lives at the record site (cmd/k3sm): an apiserver
			// timeout with no pressure is recorded as a plain bring-up failure.
			err := apiTimeoutErr()
			if !errors.Is(err, ErrAPIServerHealthTimeout) {
				t.Fatal("the apiserver deadline must match ErrAPIServerHealthTimeout")
			}
			if got := err.Error(); got != "kube-apiserver not healthy within 1m30s" {
				t.Fatalf("message changed: %q", got)
			}
			var r CrashRecord
			for i := 1; i <= CrashLoopThreshold; i++ {
				if r.Record(t0.Add(time.Duration(i)*healthTimeout), CrashOriginBringUp, "kube-apiserver", err.Error()) != (i == CrashLoopThreshold) {
					t.Fatalf("unpressured timeout %d: wrong trip", i)
				}
			}
		}},
		{"a healthy bring-up resets the backoff", func(t *testing.T) {
			var r CrashRecord
			now := t0
			for i := 0; i < 4; i++ {
				now = now.Add(healthTimeout)
				r.RecordBringUpSlow(now, "kube-apiserver", "slow")
			}
			if wait, _ := r.BringUpBackoff(now); wait != 4*time.Minute {
				t.Fatalf("before reset: %s, want 4m", wait)
			}
			r.NoteBringUpHealthy()
			if wait, _ := r.BringUpBackoff(now); wait != 0 {
				t.Fatalf("after reset: %s, want 0", wait)
			}
			r.RecordBringUpSlow(now.Add(time.Hour), "kube-apiserver", "slow")
			if wait, _ := r.BringUpBackoff(now.Add(time.Hour)); wait != BringUpSlowBackoffBase {
				t.Fatalf("after reset the streak restarts: %s, want %s", wait, BringUpSlowBackoffBase)
			}
		}},
		{"a restart keeps the previous log as .log.1", func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "kine.log")
			if err := os.WriteFile(p, []byte("first crash: database is locked\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rotateComponentLog(p)
			got, err := os.ReadFile(p + ".1")
			if err != nil || string(got) != "first crash: database is locked\n" {
				t.Fatalf(".log.1 = %q, %v", got, err)
			}
			fi, err := os.Stat(p + ".1")
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf(".log.1 mode = %v, %v; want 0600", fi.Mode().Perm(), err)
			}
			// An empty current log does not push the kept generation out.
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			rotateComponentLog(p)
			if got, _ := os.ReadFile(p + ".1"); !strings.Contains(string(got), "first crash") {
				t.Fatalf("an empty log rotated over the kept one: %q", got)
			}
			// An absent log is a no-op.
			rotateComponentLog(filepath.Join(dir, "absent.log"))
			if _, err := os.Stat(filepath.Join(dir, "absent.log.1")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("absent log produced a .1: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// TestParseCrashRecordReadsAStreaklessRecord pins compatibility both ways: a
// record without the streak fields parses with no streak, and a streak-less
// record marshals without them.
func TestParseCrashRecordReadsAStreaklessRecord(t *testing.T) {
	r, err := ParseCrashRecord([]byte(`{"crashes":[{"at":"2026-11-09T12:00:00Z","component":"kine","origin":"bring-up"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.SlowStreak != 0 || r.LastSlowAt != nil {
		t.Fatalf("old record grew a streak: %+v", r)
	}
	b, err := jsonMarshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "slow_streak") || strings.Contains(string(b), "last_slow_at") {
		t.Fatalf("streak-less record wrote the streak fields: %s", b)
	}
}

func TestDecodeLoadavg(t *testing.T) {
	raw := make([]byte, 24)
	binary.NativeEndian.PutUint32(raw[0:4], 3*2048)
	binary.NativeEndian.PutUint64(raw[16:24], 2048)
	load, err := decodeLoadavg1(raw)
	if err != nil || load != 3 {
		t.Fatalf("load = %v, %v; want 3", load, err)
	}
	if _, err := decodeLoadavg1(raw[:20]); err == nil {
		t.Fatal("short answer accepted")
	}
	if !loadPressured(2*HostLoadPerCorePressured, 2) || loadPressured(HostLoadPerCorePressured, 2) {
		t.Fatal("loadPressured threshold wrong")
	}
}

func apiTimeoutErr() error {
	return &apiHealthTimeoutError{err: &healthDeadlineError{name: "kube-apiserver", timeout: healthTimeout}}
}

func jsonMarshal(r CrashRecord) ([]byte, error) { return json.Marshal(r) }

func jsonRoundTrip(r CrashRecord) (CrashRecord, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return CrashRecord{}, err
	}
	return ParseCrashRecord(b)
}
