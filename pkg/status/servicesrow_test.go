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
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
)

// fakeServicesComparer answers CompareServices from a canned comparison and
// counts its calls, so a test can assert no LIST was made.
type fakeServicesComparer struct {
	cmp   ServicesComparison
	err   error
	calls *int
}

func (f fakeServicesComparer) CompareServices(context.Context, ServicesRecord) (ServicesComparison, error) {
	*f.calls++
	return f.cmp, f.err
}

// TestServicesRowNamesADivergingVIP pins the services row: matching sets are ok
// with the port count; a Service port the proxy routes without a Ready backend
// the API has is a warning naming the Service, the VIP and the missing backend,
// and it moves the verdict; a change newer than the record is not a warning; an
// unreadable record is unknown with the sudo remedy and costs no LIST; an absent
// or stale record is unknown; a failed LIST is unknown.
func TestServicesRowNamesADivergingVIP(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	wd := "/var/lib/k3sm/server"
	path := ServicesPath(wd)
	fresh := ServicesRecord{UpdatedAt: now.Add(-10 * time.Second), VIPs: []VIPEntry{
		{ClusterIP: "10.43.0.20", Port: 80, Protocol: "TCP", Namespace: "web", Name: "front", Policy: "Cluster", Backends: []string{"100.64.0.7:8080"}},
	}}
	encode := func(rec ServicesRecord) []byte {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	diverging := ServicePortDivergence{Namespace: "web", Name: "front", Port: "10.43.0.20:80/TCP", Missing: []string{"100.64.0.9:8080"}}

	cases := []struct {
		name      string
		fs        fakeFS
		serving   bool
		cmp       ServicesComparison
		cmpErr    error
		wantSev   Severity
		wantState RowState
		detail    []string
		remedy    string
		wantCalls int
	}{
		{name: "matching", fs: fakeFS{contents: map[string][]byte{path: encode(fresh)}}, serving: true,
			wantSev: SeverityOK, wantState: StateOK, detail: []string{"1 Service port"}, wantCalls: 1},
		{name: "missing backend", fs: fakeFS{contents: map[string][]byte{path: encode(fresh)}}, serving: true,
			cmp:     ServicesComparison{Diverging: []ServicePortDivergence{diverging}},
			wantSev: SeverityWarn, wantState: StateUnhealthy,
			detail: []string{"web/front", "10.43.0.20:80/TCP", "missing 100.64.0.9:8080"}, remedy: ServicesRemedy, wantCalls: 1},
		{name: "settling", fs: fakeFS{contents: map[string][]byte{path: encode(fresh)}}, serving: true,
			cmp:     ServicesComparison{Settling: []ServicePortDivergence{diverging}},
			wantSev: SeverityOK, wantState: StateOK, detail: []string{"1 changed since the record"}, wantCalls: 1},
		{name: "unreadable", fs: fakeFS{unreadable: map[string]bool{path: true}}, serving: true,
			wantSev: SeverityUnknown, wantState: StateUnknown, detail: []string{"unreadable as this user"}, remedy: "sudo k3sm status"},
		{name: "absent", fs: fakeFS{}, serving: true,
			wantSev: SeverityUnknown, wantState: StateUnknown, detail: []string{"has not recorded"}},
		{name: "stale", fs: fakeFS{contents: map[string][]byte{path: encode(ServicesRecord{UpdatedAt: now.Add(-2 * time.Minute)})}}, serving: true,
			wantSev: SeverityUnknown, wantState: StateUnknown, detail: []string{"not refreshing"}},
		{name: "apiserver down", fs: fakeFS{contents: map[string][]byte{path: encode(fresh)}}, serving: false,
			wantSev: SeverityUnknown, wantState: StateUnknown, detail: []string{"not serving"}},
		{name: "list fails", fs: fakeFS{contents: map[string][]byte{path: encode(fresh)}}, serving: true,
			cmpErr: errors.New("forbidden"), wantSev: SeverityUnknown, wantState: StateUnknown, detail: []string{"forbidden"}, wantCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := Collector{FS: tc.fs, Paths: Paths{WorkDir: wd},
				Services: fakeServicesComparer{cmp: tc.cmp, err: tc.cmpErr, calls: &calls}}
			row, ok := c.servicesRow(context.Background(), tc.serving, now)
			if !ok {
				t.Fatal("no services row")
			}
			if row.Name != RowServices || row.Severity != tc.wantSev || row.State != tc.wantState {
				t.Errorf("row = %+v, want %s %v/%v", row, RowServices, tc.wantState, tc.wantSev)
			}
			for _, want := range tc.detail {
				if !strings.Contains(row.Detail, want) {
					t.Errorf("detail %q does not name %q", row.Detail, want)
				}
			}
			if row.Remedy != tc.remedy {
				t.Errorf("remedy = %q, want %q", row.Remedy, tc.remedy)
			}
			if calls != tc.wantCalls {
				t.Errorf("comparer called %d times, want %d", calls, tc.wantCalls)
			}
		})
	}
	if advisory(dataroot.RoleServer, RowServices) {
		t.Error("a Service port routed to the wrong backends is a claim about the cluster, not a note")
	}
	t.Run("no comparer, no row", func(t *testing.T) {
		if _, ok := (Collector{FS: fakeFS{}, Paths: Paths{WorkDir: wd}}).servicesRow(context.Background(), true, now); ok {
			t.Error("a report with no comparer carries a services row")
		}
	})
}
