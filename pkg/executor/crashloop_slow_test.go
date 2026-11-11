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
			if wait, _ := r.BringUpBackoff(t0.Add(10 * time.Second)); wait != 20*time.Second || r.SlowStreak != 1 {
				t.Fatalf("a non-slow entry must not end the streak: wait %s, streak %d", wait, r.SlowStreak)
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
		{"slow, fast failure, slow keeps the streak and counts the fast one", func(t *testing.T) {
			var r CrashRecord
			r.RecordBringUpSlow(t0, "kube-apiserver", "slow")
			r.Record(t0.Add(time.Minute), CrashOriginBringUp, "kine", "kine exited during bring-up")
			now := t0.Add(2 * time.Minute)
			r.RecordBringUpSlow(now, "kube-apiserver", "slow")
			if r.SlowStreak != 2 {
				t.Fatalf("SlowStreak = %d, want 2", r.SlowStreak)
			}
			if n := r.Recent(now); n != 1 {
				t.Fatalf("Recent = %d, want 1 (the fast failure)", n)
			}
			if wait, _ := r.BringUpBackoff(now); wait != 2*BringUpSlowBackoffBase {
				t.Fatalf("backoff %s, want %s", wait, 2*BringUpSlowBackoffBase)
			}
		}},
		{"a future-dated LastSlowAt never stretches the wait", func(t *testing.T) {
			var r CrashRecord
			now := t0
			for i := 0; i < 3; i++ {
				r.RecordBringUpSlow(now, "kube-apiserver", "slow")
			}
			future := now.Add(time.Hour)
			r.LastSlowAt = &future
			d := 4 * BringUpSlowBackoffBase // the streak-3 backoff
			wait, until := r.BringUpBackoff(now)
			if wait <= 0 || wait > d || wait > BringUpSlowBackoffCap {
				t.Fatalf("wait %s, want 0 < wait <= %s", wait, d)
			}
			if !until.Equal(now.Add(wait)) {
				t.Fatalf("until %s, want %s", until, now.Add(wait))
			}
		}},
		{"NoteBringUpHealthy zeroes the streak", func(t *testing.T) {
			var r CrashRecord
			r.RecordBringUpSlow(t0, "kube-apiserver", "slow")
			r.Record(t0.Add(time.Second), CrashOriginBringUp, "kine", "fast")
			r.RecordBringUpSlow(t0.Add(2*time.Second), "kube-apiserver", "slow")
			r.NoteBringUpHealthy()
			if r.SlowStreak != 0 || r.LastSlowAt != nil {
				t.Fatalf("after healthy: streak %d, LastSlowAt %v", r.SlowStreak, r.LastSlowAt)
			}
			if wait, _ := r.BringUpBackoff(t0.Add(2 * time.Second)); wait != 0 {
				t.Fatalf("after healthy: wait %s, want 0", wait)
			}
		}},
		{"a restart keeps the previous log as .log.1", func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "kine.log")
			if err := os.WriteFile(p, []byte("first crash: database is locked\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rotateComponentLog(p, false)
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
			rotateComponentLog(p, false)
			if got, _ := os.ReadFile(p + ".1"); !strings.Contains(string(got), "first crash") {
				t.Fatalf("an empty log rotated over the kept one: %q", got)
			}
			// An absent log is a no-op.
			rotateComponentLog(filepath.Join(dir, "absent.log"), true)
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
	binary.NativeEndian.PutUint32(raw[4:8], 2048)
	binary.NativeEndian.PutUint64(raw[16:24], 2048)
	l1, l5, err := decodeLoadavg(raw)
	if err != nil || l1 != 3 || l5 != 1 {
		t.Fatalf("load = %v, %v, %v; want 3, 1", l1, l5, err)
	}
	if _, _, err := decodeLoadavg(raw[:20]); err == nil {
		t.Fatal("short answer accepted")
	}
}

// TestHostLoadPressured pins the sustained-load verdict: both the one- and the
// five-minute average per core must reach the threshold, so a one-minute spike
// over a quiet five minutes is not pressure.
func TestHostLoadPressured(t *testing.T) {
	th := HostLoadPerCorePressured
	cases := []struct {
		name string
		load HostLoad
		want bool
	}{
		{"both high is pressure", HostLoad{Load1: 2 * th * 4, Load5: 2 * th * 4, Cores: 4}, true},
		{"both exactly at the threshold is pressure", HostLoad{Load1: th * 4, Load5: th * 4, Cores: 4}, true},
		{"1-minute high, 5-minute low is not pressure", HostLoad{Load1: 3 * th * 4, Load5: 0.5 * th * 4, Cores: 4}, false},
		{"1-minute low, 5-minute high is not pressure", HostLoad{Load1: 0.5 * th * 4, Load5: 3 * th * 4, Cores: 4}, false},
		{"both below is not pressure", HostLoad{Load1: th*4 - 0.01, Load5: th*4 - 0.01, Cores: 4}, false},
		{"no core count reads as one core", HostLoad{Load1: th, Load5: th}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.load.Pressured(); got != tc.want {
				t.Fatalf("Pressured(%+v) = %v, want %v", tc.load, got, tc.want)
			}
			if s := tc.load.String(); !strings.Contains(s, "1m ") || !strings.Contains(s, "5m ") {
				t.Fatalf("String() = %q; want both samples", s)
			}
		})
	}
}

// TestComponentLogRotationKeepsFirstCrash drives spawns against a real work
// dir and crash record: the first failing run's log is kept as .log.1 through
// every later spawn of the streak (the latest lap rides in .log.2), and only a
// healthy bring-up lets the next spawn replace it.
func TestComponentLogRotationKeepsFirstCrash(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	type step struct {
		log     string // the run's log content before the spawn rotates it
		failing bool   // the crash record holds a live failure at the spawn
		healthy bool   // the run reached a healthy bring-up before the spawn
		want1   string
		want2   string // "" is absent
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"first crash survives three further spawns and is replaced after a healthy bring-up", []step{
			{log: "run 0: clean stop", want1: "run 0: clean stop"},
			{log: "run 1: first crash, database is locked", failing: true, want1: "run 1: first crash, database is locked"},
			{log: "run 2: crash", failing: true, want1: "run 1: first crash, database is locked", want2: "run 2: crash"},
			{log: "run 3: crash", failing: true, want1: "run 1: first crash, database is locked", want2: "run 3: crash"},
			{log: "run 4: crash", failing: true, want1: "run 1: first crash, database is locked", want2: "run 4: crash"},
			{log: "run 5: healthy, then crashed at hour six", failing: true, healthy: true, want1: "run 5: healthy, then crashed at hour six"},
		}},
		{"a slow streak keeps the first slow lap", []step{
			{log: "slow lap 1", failing: true, want1: "slow lap 1"},
			{log: "slow lap 2", failing: true, want1: "slow lap 1", want2: "slow lap 2"},
			{log: "healthy", failing: true, healthy: true, want1: "healthy"},
			{log: "clean stop", want1: "clean stop"},
		}},
		{"no failure rotates every spawn", []step{
			{log: "run 0", want1: "run 0"},
			{log: "run 1", want1: "run 1"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "kine.log")
			for i, st := range tc.steps {
				if st.healthy {
					releaseComponentLogs(dir)
				}
				rec := CrashRecord{}
				if st.failing {
					rec.Record(now, CrashOriginCrash, "kine", "exited")
				}
				if err := WriteCrashRecord(CrashLoopPath(dir), rec); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(st.log), 0o600); err != nil {
					t.Fatal(err)
				}
				rotateComponentLog(p, failureLive(dir, now))
				if got, err := os.ReadFile(p + ".1"); err != nil || string(got) != st.want1 {
					t.Fatalf("step %d: .log.1 = %q, %v; want %q", i, got, err, st.want1)
				}
				got, err := os.ReadFile(p + ".2")
				switch {
				case st.want2 == "" && !errors.Is(err, os.ErrNotExist):
					t.Fatalf("step %d: .log.2 = %q, %v; want absent", i, got, err)
				case st.want2 != "" && (err != nil || string(got) != st.want2):
					t.Fatalf("step %d: .log.2 = %q, %v; want %q", i, got, err, st.want2)
				}
				for _, kept := range []string{p + ".1", p + ".2"} {
					if fi, err := os.Stat(kept); err == nil && fi.Mode().Perm() != 0o600 {
						t.Fatalf("step %d: %s mode %v; want 0600", i, kept, fi.Mode().Perm())
					}
				}
			}
		})
	}

	t.Run("a later lap over the cap keeps only its tail", func(t *testing.T) {
		dir := t.TempDir()
		src, dst := filepath.Join(dir, "kine.log"), filepath.Join(dir, "kine.log.2")
		if err := os.WriteFile(src, []byte("headhead-TAIL"), 0o600); err != nil {
			t.Fatal(err)
		}
		keepLogTail(src, dst, 13, 4)
		if got, err := os.ReadFile(dst); err != nil || string(got) != "TAIL" {
			t.Fatalf(".log.2 = %q, %v; want the 4-byte tail", got, err)
		}
		if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf(".log.2 mode: %v", err)
		}
		if _, err := os.Stat(src); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source log left behind: %v", err)
		}
	})

	t.Run("uninstall paths cover every kept file", func(t *testing.T) {
		paths := strings.Join(ComponentLogKeptPaths("/w"), " ")
		for _, want := range []string{"/w/kine.log.1", "/w/kine.log.1.pinned", "/w/kube-apiserver.log.2", "/w/etcd.log.1"} {
			if !strings.Contains(paths, want+" ") && !strings.HasSuffix(paths, want) {
				t.Fatalf("ComponentLogKeptPaths lacks %s: %s", want, paths)
			}
		}
		if strings.Contains(paths, "/w/kine.log ") {
			t.Fatalf("ComponentLogKeptPaths lists a live log: %s", paths)
		}
	})
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

// TestComponentLogRotationDropsStalePin pins the pin lifecycle the content
// checks cannot see: a failing spawn writes the pin, and a spawn with no live
// failure removes it even when the previous lap logged nothing.
func TestComponentLogRotationDropsStalePin(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "kine.log")
	pin := logPath + componentLogPinSuffix
	if err := os.WriteFile(logPath, []byte("first failure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotateComponentLog(logPath, true)
	if _, err := os.Stat(pin); err != nil {
		t.Fatalf("a failing spawn must pin the first failure's log: %v", err)
	}
	for _, tc := range []struct {
		name    string
		content []byte
		missing bool
	}{
		{name: "empty previous log", content: nil},
		{name: "missing previous log", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(pin, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(logPath)
			if !tc.missing {
				if err := os.WriteFile(logPath, tc.content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rotateComponentLog(logPath, false)
			if _, err := os.Stat(pin); !os.IsNotExist(err) {
				t.Fatalf("a spawn with no live failure must drop the pin, stat err = %v", err)
			}
			got, err := os.ReadFile(logPath + ".1")
			if err != nil || string(got) != "first failure\n" {
				t.Fatalf(".1 = %q, %v; want the first failure's log untouched", got, err)
			}
		})
	}
}
