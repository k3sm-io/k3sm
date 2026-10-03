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

package status

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWALFsyncP99 pins the quantile: linear interpolation inside the bucket the
// 0.99 rank lands in (histogram_quantile's rule), the highest finite bound when it
// lands in +Inf, and "no answer" for an absent or empty histogram. Other histograms
// in the same exposition are ignored.
func TestWALFsyncP99(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     string
		want   float64
		wantOK bool
	}{
		{name: "fixture", in: string(readFixture(t, "etcd-metrics.txt")), want: 0.0072, wantOK: true},
		{name: "rank in +Inf", in: `etcd_disk_wal_fsync_duration_seconds_bucket{le="0.5"} 90
etcd_disk_wal_fsync_duration_seconds_bucket{le="+Inf"} 100`, want: 0.5, wantOK: true},
		{name: "no observations", in: `etcd_disk_wal_fsync_duration_seconds_bucket{le="0.5"} 0
etcd_disk_wal_fsync_duration_seconds_bucket{le="+Inf"} 0`},
		{name: "no histogram", in: "etcd_server_has_leader 1\n"},
		{name: "empty", in: ""},
	} {
		got, ok := WALFsyncP99([]byte(tc.in))
		if ok != tc.wantOK || math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: WALFsyncP99 = %v, %v; want %v, %v", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}

func healthyEtcd(now time.Time) executor.EtcdStatus {
	return executor.EtcdStatus{
		UpdatedAt: now.Add(-30 * time.Second), ClientURL: "https://127.0.0.1:2379", MemberName: "server-a",
		Members: 3, Learners: 0, LeaderPresent: true, LeaderID: 1,
		DBSizeBytes: 20 << 20, QuotaBytes: 2 << 30,
		ExpectedPeerURL: "https://192.0.2.10:2380", RegisteredPeerURLs: []string{"https://192.0.2.10:2380"},
	}
}

// TestEtcdRowStates pins every answer the etcd row gives: healthy with the counts,
// leader, size against quota and p99; NO LEADER and NOSPACE as failures with their
// runbooks; any other alarm as a failure; peer-URL drift and a nearly full backend
// as warnings with their remedies; an unknown p99 said as such; and a record the
// server stopped refreshing as unknown, which only a failure outranks.
func TestEtcdRowStates(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p99 := 0.0072
	for _, tc := range []struct {
		name     string
		edit     func(*executor.EtcdStatus)
		noP99    bool
		sev      Severity
		state    RowState
		detail   []string
		remedyIn []string
	}{
		{name: "healthy", sev: SeverityOK, state: StateHealthy,
			detail: []string{"3 voting, 0 learners", "leader present", "db 20.0 MiB of 2.0 GiB quota", "wal fsync p99 7.2ms"}},
		{name: "a learner awaiting promotion", edit: func(s *executor.EtcdStatus) { s.Members, s.Learners = 1, 1 }, sev: SeverityOK, state: StateHealthy,
			detail: []string{"1 voting, 1 learner,"}},
		{name: "p99 unreachable", noP99: true, sev: SeverityOK, state: StateHealthy, detail: []string{"wal fsync p99 unknown"}},
		{name: "no leader", edit: func(s *executor.EtcdStatus) { s.LeaderPresent, s.LeaderID = false, 0 }, sev: SeverityFail, state: StateUnhealthy,
			detail: []string{"NO LEADER", "writes are stopped"}, remedyIn: []string{"--cluster-reset"}},
		{name: "NOSPACE", edit: func(s *executor.EtcdStatus) { s.Alarms = []string{"NOSPACE"} }, sev: SeverityFail, state: StateUnhealthy,
			detail: []string{"alarms: NOSPACE", "read-only"}, remedyIn: []string{"compact", "defragment", "disarm"}},
		{name: "CORRUPT", edit: func(s *executor.EtcdStatus) { s.Alarms = []string{"CORRUPT"} }, sev: SeverityFail, state: StateUnhealthy,
			detail: []string{"alarms: CORRUPT"}, remedyIn: []string{"re-joined"}},
		{name: "peer URL drift", edit: func(s *executor.EtcdStatus) {
			s.PeerURLDrift, s.RegisteredPeerURLs = true, []string{"https://192.0.2.49:2380"}
		}, sev: SeverityWarn, state: StateDrift,
			detail: []string{"https://192.0.2.49:2380", "https://192.0.2.10:2380"}, remedyIn: []string{"DHCP reservation"}},
		{name: "nearing quota", edit: func(s *executor.EtcdStatus) { s.DBSizeBytes = s.QuotaBytes * 9 / 10 }, sev: SeverityWarn, state: StateUnhealthy,
			detail: []string{"nearing the backend quota"}, remedyIn: []string{"compact"}},
		{name: "stale record", edit: func(s *executor.EtcdStatus) { s.UpdatedAt = now.Add(-20 * time.Minute) }, sev: SeverityUnknown, state: StateUnknown,
			detail: []string{"not refreshing it"}},
		{name: "stale but leaderless is still a failure", edit: func(s *executor.EtcdStatus) {
			s.UpdatedAt, s.LeaderPresent = now.Add(-20*time.Minute), false
		}, sev: SeverityFail, state: StateUnhealthy, detail: []string{"NO LEADER"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := healthyEtcd(now)
			if tc.edit != nil {
				tc.edit(&st)
			}
			var p *float64
			if !tc.noP99 {
				p = &p99
			}
			row := etcdRowFrom(st, p, now)
			if row.Name != RowEtcd || row.Severity != tc.sev || row.State != tc.state {
				t.Fatalf("row = %s %s %s %q, want %s %s", row.Name, row.State, row.Severity, row.Detail, tc.state, tc.sev)
			}
			for _, want := range tc.detail {
				if !strings.Contains(row.Detail, want) {
					t.Errorf("detail %q does not carry %q", row.Detail, want)
				}
			}
			for _, want := range tc.remedyIn {
				if !strings.Contains(row.Remedy, want) {
					t.Errorf("remedy %q does not carry %q", row.Remedy, want)
				}
			}
		})
	}
}

// TestEtcdRowCollect pins the row's wiring: present only in the etcd posture (the
// plist's role flag, a member dir, or a record), the record read through the FS
// seam (unreadable is unknown, absent is a skip), the metrics read from the plist's
// --etcd-metrics-port on loopback, and a metrics failure leaving the p99 unknown
// rather than failing the row.
func TestEtcdRowCollect(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	wd := t.TempDir()
	p := testPaths(wd)
	recPath := executor.EtcdStatusPath(wd)
	rec, _ := json.Marshal(healthyEtcd(now))
	etcdArgs := []string{"--cluster-init", "--node-ip", "192.0.2.10", "--etcd-metrics-port", "12381"}
	metrics := readFixture(t, "etcd-metrics.txt")

	newCollector := func(fsys fakeFS, fetch func(context.Context, string) ([]byte, error)) Collector {
		return Collector{FS: fsys, Paths: p, Now: func() time.Time { return now }, EtcdMetrics: fetch}
	}

	t.Run("not the etcd posture: no row", func(t *testing.T) {
		if _, ok := newCollector(fakeFS{}, nil).etcdRow(context.Background(), []string{"--mesh-ip", "198.51.100.10"}); ok {
			t.Error("a kine server got an etcd row")
		}
	})

	t.Run("healthy, metrics on the plist's port", func(t *testing.T) {
		var asked string
		c := newCollector(fakeFS{present: map[string]bool{recPath: true}, contents: map[string][]byte{recPath: rec}},
			func(_ context.Context, url string) ([]byte, error) { asked = url; return metrics, nil })
		row, ok := c.etcdRow(context.Background(), etcdArgs)
		if !ok || row.Severity != SeverityOK || !strings.Contains(row.Detail, "wal fsync p99 7.2ms") {
			t.Fatalf("row = %v %+v", ok, row)
		}
		if asked != "http://127.0.0.1:12381/metrics" {
			t.Errorf("metrics read from %q, want the loopback --etcd-metrics-port", asked)
		}
	})

	t.Run("metrics unreachable: p99 unknown, not an error", func(t *testing.T) {
		c := newCollector(fakeFS{present: map[string]bool{recPath: true}, contents: map[string][]byte{recPath: rec}},
			func(context.Context, string) ([]byte, error) { return nil, errors.New("connection refused") })
		row, _ := c.etcdRow(context.Background(), etcdArgs)
		if row.Severity != SeverityOK || !strings.Contains(row.Detail, "wal fsync p99 unknown") {
			t.Errorf("row = %s %q", row.Severity, row.Detail)
		}
	})

	t.Run("record unreadable as this user: unknown", func(t *testing.T) {
		c := newCollector(fakeFS{present: map[string]bool{recPath: true}, unreadable: map[string]bool{recPath: true}}, nil)
		row, ok := c.etcdRow(context.Background(), etcdArgs)
		if !ok || row.Severity != SeverityUnknown {
			t.Errorf("row = %v %s %q, want unknown", ok, row.Severity, row.Detail)
		}
	})

	t.Run("posture from the plist, no record yet: skip", func(t *testing.T) {
		row, ok := newCollector(fakeFS{}, nil).etcdRow(context.Background(), etcdArgs)
		if !ok || row.Severity != SeveritySkip {
			t.Errorf("row = %v %s %q, want skip", ok, row.Severity, row.Detail)
		}
	})
}
