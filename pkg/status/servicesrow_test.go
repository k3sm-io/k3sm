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
	"fmt"
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
// and it moves the verdict; a change newer than the record is unknown, never ok; an
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
			wantSev: SeverityUnknown, wantState: StateUnknown, detail: []string{"cannot be compared yet", "web/front", "missing 100.64.0.9:8080"}, wantCalls: 1},
		{name: "unreadable, and no user-readable copy", fs: fakeFS{unreadable: map[string]bool{path: true}}, serving: true,
			wantSev: SeveritySkip, wantState: StateNeedsAdmin, detail: []string{"needs sudo", path, Dir(wd)}, remedy: "sudo k3sm status"},
		{name: "unreadable, read from the user-readable copy", serving: true,
			fs:      fakeFS{unreadable: map[string]bool{path: true}, contents: map[string][]byte{UserReadablePath(wd, path): encode(fresh)}},
			wantSev: SeverityOK, wantState: StateOK, detail: []string{"1 Service port"}, wantCalls: 1},
		{name: "unreadable, and the status dir holds no copy yet", serving: true,
			fs:      fakeFS{unreadable: map[string]bool{path: true}, present: map[string]bool{Dir(wd): true}},
			wantSev: SeverityUnknown, wantState: StateUnknown, detail: []string{"has not recorded"}},
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

// TestServicesRowClipsItsText pins the bounds on the row's text: at most eight
// ports named, then a count, and at most four addresses per list, then a count.
func TestServicesRowClipsItsText(t *testing.T) {
	var ds []ServicePortDivergence
	for i := range 10 {
		d := ServicePortDivergence{Namespace: "web", Name: fmt.Sprintf("svc%d", i), Port: fmt.Sprintf("10.43.0.%d:80/TCP", i)}
		for j := range 6 {
			d.Missing = append(d.Missing, fmt.Sprintf("100.64.0.%d:80", j))
		}
		ds = append(ds, d)
	}
	row := servicesRowFrom(Row{Name: RowServices, Wide: map[string]string{}}, ServicesRecord{},
		ServicesComparison{Diverging: ds, Settling: ds})
	for _, text := range []string{row.Detail, row.Wide["settling"]} {
		if !strings.Contains(text, "web/svc7 ") || strings.Contains(text, "web/svc8 ") {
			t.Errorf("text names other than the first eight ports: %q", text)
		}
		if !strings.Contains(text, "and 2 more") {
			t.Errorf("text does not count the unnamed ports: %q", text)
		}
		if strings.Contains(text, "100.64.0.4:80") || !strings.Contains(text, "100.64.0.3:80 (+2 more)") {
			t.Errorf("text does not clip each port's addresses at four: %q", text)
		}
	}
	if row.Severity != SeverityWarn {
		t.Errorf("a diverging port with settling ones reported %v, want warn", row.Severity)
	}
}
