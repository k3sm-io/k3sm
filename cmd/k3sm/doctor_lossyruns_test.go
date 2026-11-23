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

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
)

// TestDoctorKeystoreMaintenanceRow: the keystore-maintenance-runs row reads
// the lossy-run record through its seam: none is PASS; some is WARN naming
// the count, the newest run's time and its dropped total; a record that
// does not read is WARN, never PASS; a worker or no seam is SKIP. The row is
// in the registry, after keystore-maintenance.
func TestDoctorKeystoreMaintenanceRow(t *testing.T) {
	t.Parallel()
	older := keystore.MaintenanceRun{Run: "00000000000000a1", Verb: "floor-rebuild", Time: time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC), Ino: 11, Drops: map[string]int64{"dropped": 9}}
	newer := keystore.MaintenanceRun{Run: "00000000000000a2", Verb: "floor-rebuild", Time: time.Date(2026, 11, 23, 9, 30, 15, 0, time.UTC), Ino: 12, Drops: map[string]int64{"dropped": 1, "overlong": 2, "removed": 3}}
	cases := []struct {
		name   string
		mut    func(*doctorEnv)
		want   doctorStatus
		detail string
	}{
		{"pass-none", func(e *doctorEnv) {
			e.keystoreLossyRuns = func(context.Context) ([]keystore.MaintenanceRun, error) { return nil, nil }
		}, statusPass, "keystore maintenance: no lossy run recorded"},
		{"warn-lossy", func(e *doctorEnv) {
			e.keystoreLossyRuns = func(context.Context) ([]keystore.MaintenanceRun, error) {
				return []keystore.MaintenanceRun{older, newer}, nil
			}
		}, statusWarn, "keystore maintenance: 2 lossy run(s), latest 2026-11-23T09:30:15Z dropped 6 line(s)"},
		{"warn-corrupt", func(e *doctorEnv) {
			e.keystoreLossyRuns = func(context.Context) ([]keystore.MaintenanceRun, error) {
				return nil, errors.New("the record is damaged")
			}
		}, statusWarn, "could not be read"},
		{"warn-permission", func(e *doctorEnv) {
			e.keystoreLossyRuns = func(context.Context) ([]keystore.MaintenanceRun, error) {
				return nil, fmt.Errorf("open: %w", fs.ErrPermission)
			}
		}, statusWarn, "could not read " + keystore.MaintenanceRunsName},
		{"skip-unprobed", func(e *doctorEnv) { e.keystoreLossyRuns = nil }, statusSkip, "not probed"},
		{"skip-worker", func(e *doctorEnv) {
			e.nodeRole = func() (install.Role, bool) { return install.RoleAgent, true }
			e.keystoreLossyRuns = func(context.Context) ([]keystore.MaintenanceRun, error) { return []keystore.MaintenanceRun{newer}, nil }
		}, statusSkip, "a worker keeps no keystore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := healthyDoctorEnv()
			tc.mut(&e)
			r := checkKeystoreLossyRuns(e)
			if r.name != "keystore-maintenance-runs" || r.status != tc.want || !strings.Contains(r.detail, tc.detail) {
				t.Fatalf("row = %s %v %q, want %v containing %q", r.name, r.status, r.detail, tc.want, tc.detail)
			}
			if r.status == statusWarn && r.remedy == "" {
				t.Fatalf("a WARN row with no remedy: %q", r.detail)
			}
		})
	}
	t.Run("registry", func(t *testing.T) {
		t.Parallel()
		var names []string
		for _, dc := range doctorChecks() {
			names = append(names, dc.name)
		}
		got := strings.Join(names, ",")
		if !strings.Contains(got, "keystore-maintenance,keystore-maintenance-runs") {
			t.Fatalf("registry %s, want keystore-maintenance-runs after keystore-maintenance", got)
		}
	})
}
