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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"syscall"
	"testing"

	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// TestUninstallTearsDownRecordedPodGroups pins that `k3sm uninstall` stops the
// pods it would otherwise leave running. A native pod outlives its node daemon
// by design (a restart re-attaches to it), so booting the daemon out stops
// nothing; the uninstall reads the runtime's reap records AFTER every daemon is
// booted out and stops each recorded group — SIGTERM, one shared 10s grace,
// SIGKILL to the survivors — and signals ONLY a group whose leader is alive
// with exactly the recorded start time. A recycled pgid, a group whose leader
// is gone, and a record naming pgid 1 are never signalled.
func TestUninstallTearsDownRecordedPodGroups(t *testing.T) {
	t.Run("signals the verified groups in order, after the daemons", func(t *testing.T) {
		f := &fakeSystem{
			podReap: []runtimed.PodReapRecord{
				{PodID: "uid-a", Container: "c0", Pgid: 501, StartUnixNano: 111},
				{PodID: "uid-b", Container: "c0", Pgid: 502, StartUnixNano: 222},
				{PodID: "uid-c", Container: "c0", Pgid: 503, StartUnixNano: 333}, // pgid recycled
				{PodID: "uid-d", Container: "c0", Pgid: 504, StartUnixNano: 444}, // leader gone
				{PodID: "uid-e", Container: "c0", Pgid: 1, StartUnixNano: 555},   // never signalled
			},
			podLeaders:   map[int]int64{501: 111, 502: 222, 503: 999, 1: 555},
			podLingering: map[int]bool{502: true},
		}
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}

		read := slices.Index(f.calls, "ReadPodReapRecords:/var/lib/k3sm")
		if read < 0 {
			t.Fatalf("the reap store was never read: %v", f.calls)
		}
		for i, c := range f.calls {
			if strings.HasPrefix(c, "Bootout:") && i > read {
				t.Errorf("%s ran after the pod teardown began; a live daemon could restart the pods it stops", c)
			}
		}
		var got []string
		for _, c := range f.calls[read+1:] {
			if strings.HasPrefix(c, "Signal:") || strings.HasPrefix(c, "WaitGone:") {
				got = append(got, c)
			}
		}
		want := []string{
			"Signal:501:TERM",
			"Signal:502:TERM",
			"WaitGone:501,502:10s",
			"Signal:502:KILL",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("pod teardown = %v, want %v", got, want)
		}
	})

	t.Run("no records, no signals", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "Signal:") || strings.HasPrefix(c, "WaitGone:") {
				t.Errorf("unexpected %s on a node with no recorded pods", c)
			}
		}
	})
}

// TestTeardownPodGroupsUsesTheChildIdentity pins the uninstall teardown of a
// pod group whose resident shim died. Under the shim the group's leader (pid ==
// pgid) is the shim and the container is its child in the same group; the
// record carries both identities. When the leader is gone, the child alive in
// that group with exactly its recorded start time still proves the group is
// the pod's, so it is stopped (SIGTERM, grace, SIGKILL to a survivor). A child
// whose start differs, a child no longer in that group, and a record with no
// child identity are never signalled: nothing proves those groups ours.
func TestTeardownPodGroupsUsesTheChildIdentity(t *testing.T) {
	const pgid, child = 601, 602
	tests := []struct {
		name      string
		rec       runtimed.PodReapRecord
		leaders   map[int]int64
		members   map[int]map[int]int64
		lingering bool
		want      []string
	}{
		{
			name:    "leader alive: signalled by the leader identity, as before",
			rec:     runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: pgid, StartUnixNano: 111, ShimDir: "/x/run/shim/0a", ChildPid: child, ChildStartUnixNano: 222},
			leaders: map[int]int64{pgid: 111},
			want:    []string{"Signal:601:TERM", "WaitGone:601:10s"},
		},
		{
			name:    "leader gone, child alive with its recorded start: signalled",
			rec:     runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: pgid, StartUnixNano: 111, ShimDir: "/x/run/shim/0a", ChildPid: child, ChildStartUnixNano: 222},
			members: map[int]map[int]int64{pgid: {child: 222}},
			want:    []string{"Signal:601:TERM", "WaitGone:601:10s"},
		},
		{
			name:      "leader gone, child alive and outlives the grace: killed",
			rec:       runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: pgid, StartUnixNano: 111, ShimDir: "/x/run/shim/0a", ChildPid: child, ChildStartUnixNano: 222},
			members:   map[int]map[int]int64{pgid: {child: 222}},
			lingering: true,
			want:      []string{"Signal:601:TERM", "WaitGone:601:10s", "Signal:601:KILL"},
		},
		{
			name:    "leader gone, child start mismatch: not signalled",
			rec:     runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: pgid, StartUnixNano: 111, ShimDir: "/x/run/shim/0a", ChildPid: child, ChildStartUnixNano: 222},
			members: map[int]map[int]int64{pgid: {child: 999}},
		},
		{
			name:    "leader gone, child no longer in the group: not signalled",
			rec:     runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: pgid, StartUnixNano: 111, ShimDir: "/x/run/shim/0a", ChildPid: child, ChildStartUnixNano: 222},
			members: map[int]map[int]int64{700: {child: 222}},
		},
		{
			name:    "leader gone, no child identity recorded: not signalled, as before",
			rec:     runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: pgid, StartUnixNano: 111, ShimDir: "/x/run/shim/0a"},
			members: map[int]map[int]int64{pgid: {child: 222}},
		},
		{
			name:    "leader recycled to another process: not signalled, as before",
			rec:     runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: pgid, StartUnixNano: 111, ShimDir: "/x/run/shim/0a", ChildPid: child, ChildStartUnixNano: 222},
			leaders: map[int]int64{pgid: 333},
			members: map[int]map[int]int64{pgid: {child: 222}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSystem{
				podReap:      []runtimed.PodReapRecord{tt.rec},
				podLeaders:   tt.leaders,
				podMembers:   tt.members,
				podLingering: map[int]bool{pgid: tt.lingering},
			}
			if err := teardownPodGroups(context.Background(), f, Config{Logger: slog.New(slog.DiscardHandler)}); err != nil {
				t.Fatalf("teardownPodGroups: %v", err)
			}
			var got []string
			for _, c := range f.calls {
				if strings.HasPrefix(c, "Signal:") || strings.HasPrefix(c, "WaitGone:") {
					got = append(got, c)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("pod teardown = %v, want %v", got, tt.want)
			}
		})
	}
}

// survivorFake is fakeSystem plus the per-process seam (survivorProcs): starts
// and sids are the live process table by pid, the sweeper runs as pid
// sweeperPid in session sweeperSid, and every single-process signal is
// recorded as "Kill:<pid>:<sig>" in the same call log as the group signals.
type survivorFake struct {
	*fakeSystem
	starts map[int]int64
	sids   map[int]int
}

const sweeperPid, sweeperSid = 90, 90

func (s survivorFake) ProcessSession(pid int) (int, bool) {
	sid, ok := s.sids[pid]
	return sid, ok
}

func (s survivorFake) Self() (int, int) { return sweeperPid, sweeperSid }

func (s survivorFake) ProcessStart(pid int) (int64, bool) {
	start, ok := s.starts[pid]
	return start, ok
}

func (s survivorFake) SignalProcess(pid int, sig syscall.Signal) error {
	name := map[syscall.Signal]string{syscall.SIGTERM: "TERM", syscall.SIGKILL: "KILL"}[sig]
	s.calls = append(s.calls, fmt.Sprintf("Kill:%d:%s", pid, name))
	return nil
}

// TestPodGroupSweepKillsRecordedSurvivors pins that the stop/uninstall pod
// sweep finishes what the runtime's teardown could not: a record's Survivors
// (processes of the container's tree that outlived its kill, a setsid escapee
// among them) are SIGKILLed while each pid still reports exactly its recorded
// start time and its live session is the recorded one (never the sweeper's),
// even though the record's leader and group are gone. A survivor that leads
// its own session is killed with its group under the same guard. A recycled
// pid, a session mismatch, the sweeper's own pid and pid 1 are never
// signalled, the leader path is unchanged beside them, and a record written
// before the field existed decodes with none.
func TestPodGroupSweepKillsRecordedSurvivors(t *testing.T) {
	gone := runtimed.PodReapRecord{PodID: "uid-a", Container: "c0", Pgid: 601, StartUnixNano: 111}
	withSurvivors := func(rec runtimed.PodReapRecord, ss ...runtimed.ReapSurvivor) runtimed.PodReapRecord {
		rec.Survivors = ss
		return rec
	}
	var old runtimed.PodReapRecord
	if err := json.Unmarshal([]byte(`{"podId":"uid-a","container":"c0","pgid":601,"startUnixNano":111}`), &old); err != nil {
		t.Fatalf("decode a record without survivors: %v", err)
	}
	tests := []struct {
		name       string
		recs       []runtimed.PodReapRecord
		leaders    map[int]int64
		starts     map[int]int64
		sids       map[int]int
		want       []string
		wantKilled string
	}{
		{
			name:       "survivor alive with its recorded start: killed and counted",
			recs:       []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: 700, StartUnixNano: 222, Sid: 601})},
			starts:     map[int]int64{700: 222},
			sids:       map[int]int{700: 601},
			want:       []string{"Kill:700:KILL"},
			wantKilled: "killed=1",
		},
		{
			name:       "survivor leading its own session: its group is killed under the same guard",
			recs:       []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: 800, StartUnixNano: 333, Sid: 800})},
			leaders:    map[int]int64{800: 333},
			starts:     map[int]int64{800: 333},
			sids:       map[int]int{800: 800},
			want:       []string{"Signal:800:KILL"},
			wantKilled: "killed=1",
		},
		{
			name:    "survivor pid recycled to another process: skipped, not signalled",
			recs:    []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: 700, StartUnixNano: 222, Sid: 700})},
			leaders: map[int]int64{700: 999},
			starts:  map[int]int64{700: 999},
		},
		{
			name:   "survivor start matches but its session is not the recorded one: skipped",
			recs:   []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: 700, StartUnixNano: 222, Sid: 601})},
			starts: map[int]int64{700: 222},
			sids:   map[int]int{700: 650},
		},
		{
			name:   "survivor in the sweeper's own session: skipped",
			recs:   []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: 700, StartUnixNano: 222, Sid: sweeperSid})},
			starts: map[int]int64{700: 222},
			sids:   map[int]int{700: sweeperSid},
		},
		{
			name:   "survivor naming the sweeper's own pid: skipped",
			recs:   []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: sweeperPid, StartUnixNano: 222, Sid: 601})},
			starts: map[int]int64{sweeperPid: 222},
			sids:   map[int]int{sweeperPid: 601},
		},
		{
			name:    "survivor naming pid 1: skipped",
			recs:    []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: 1, StartUnixNano: 222, Sid: 1})},
			leaders: map[int]int64{1: 222},
			starts:  map[int]int64{1: 222},
			sids:    map[int]int{1: 1},
		},
		{
			name:   "survivor already gone: not signalled",
			recs:   []runtimed.PodReapRecord{withSurvivors(gone, runtimed.ReapSurvivor{Pid: 700, StartUnixNano: 222})},
			starts: map[int]int64{},
		},
		{
			name: "a live leader beside a survivor record: the leader path is unchanged",
			recs: []runtimed.PodReapRecord{
				{PodID: "uid-b", Container: "c0", Pgid: 501, StartUnixNano: 444},
				withSurvivors(gone, runtimed.ReapSurvivor{Pid: 700, StartUnixNano: 222, Sid: 601}, runtimed.ReapSurvivor{Pid: 701, StartUnixNano: 555, Sid: 601}),
			},
			leaders:    map[int]int64{501: 444},
			starts:     map[int]int64{700: 222, 701: 556},
			sids:       map[int]int{700: 601, 701: 601},
			want:       []string{"Kill:700:KILL", "Signal:501:TERM", "WaitGone:501:10s"},
			wantKilled: "killed=1",
		},
		{
			name:   "a record written before the field existed: decodes with none, no-op",
			recs:   []runtimed.PodReapRecord{old},
			starts: map[int]int64{601: 111},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := survivorFake{
				fakeSystem: &fakeSystem{podReap: tt.recs, podLeaders: tt.leaders},
				starts:     tt.starts,
				sids:       tt.sids,
			}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}
			if err := teardownPodGroups(context.Background(), f, cfg); err != nil {
				t.Fatalf("teardownPodGroups: %v", err)
			}
			var got []string
			for _, c := range f.calls {
				if strings.HasPrefix(c, "Signal:") || strings.HasPrefix(c, "WaitGone:") || strings.HasPrefix(c, "Kill:") {
					got = append(got, c)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("pod sweep = %v, want %v", got, tt.want)
			}
			if tt.wantKilled != "" && !strings.Contains(logs.String(), tt.wantKilled) {
				t.Errorf("no %q in the sweep's log:\n%s", tt.wantKilled, logs.String())
			}
			if tt.wantKilled == "" && strings.Contains(logs.String(), "killed=") {
				t.Errorf("a survivor kill was logged with nothing to kill:\n%s", logs.String())
			}
		})
	}
}
