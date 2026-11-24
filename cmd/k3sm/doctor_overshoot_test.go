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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// TestDoctorWarnsOnLogOvershoot (U84): a log past its hard cap is a
// keystore-logs WARN naming its overshoot in bytes, with the audit
// --rotate hint for the audit log and the floor --rebuild hint for the
// floor; a log at or below the hard cap names no overshoot. The sizes are
// within the design's bound: one user scope's 976 KiB of revocation
// budgets plus the 1 MiB reconciler budget.
func TestDoctorWarnsOnLogOvershoot(t *testing.T) {
	t.Parallel()
	const (
		soft  = 48 << 20
		hard  = 64 << 20
		bound = 976<<10 + 1<<20 // one user scope's budgets and the reconciler's
	)
	cases := []struct {
		name          string
		audit, floor  int64
		want          doctorStatus
		detail        []string
		remedy        string
		noOvershootIn string
	}{
		{"audit past the hard cap", hard + bound, 10, statusWarn,
			[]string{"the audit log is 69156864 bytes, 2048000 bytes past its hard cap of 67108864", "only revocations are recorded"},
			"audit --rotate", ""},
		{"floor past the hard cap", 10, hard + 1, statusWarn,
			[]string{"the user-scope floor log is 67108865 bytes, 1 bytes past its hard cap of 67108864"},
			"floor --rebuild", ""},
		{"audit at the hard cap", hard, 10, statusWarn,
			[]string{"past its soft cap of 50331648", "no user-scope change is recorded"},
			"audit --rotate", "bytes past its hard cap"},
		{"both under the soft cap", soft, soft, statusPass, []string{"flagged SF_APPEND"}, "", "hard cap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := healthyDoctorEnv()
			e.keystoreLogs = func(context.Context) error { return nil }
			e.keystorePreFrameDropped = nil
			e.keystoreLogSizes = func(context.Context) (keystore.LogSizes, error) {
				return keystore.LogSizes{Audit: tc.audit, UserFloor: tc.floor, SoftCap: soft, HardCap: hard}, nil
			}
			r := checkKeystoreLogs(e)
			if r.status != tc.want {
				t.Fatalf("status %v (%q), want %v", r.status, r.detail, tc.want)
			}
			for _, d := range tc.detail {
				if !strings.Contains(r.detail, d) {
					t.Errorf("detail %q, want it to contain %q", r.detail, d)
				}
			}
			if tc.noOvershootIn != "" && strings.Contains(r.detail, tc.noOvershootIn) {
				t.Errorf("detail %q names an overshoot at or below the hard cap", r.detail)
			}
			if !strings.Contains(r.remedy, tc.remedy) {
				t.Errorf("remedy %q, want the %q hint", r.remedy, tc.remedy)
			}
		})
	}
}
