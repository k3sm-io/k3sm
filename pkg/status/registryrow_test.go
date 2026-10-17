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
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestIngestRegistryRow is the gate for the ingest-registry row: the server's
// recorded registry state, checked against a /v2/ probe of the loopback port.
func TestIngestRegistryRow(t *testing.T) {
	const workDir = "/var/lib/k3sm/server"
	const ldDir = "/Library/LaunchDaemons"
	plist := filepath.Join(ldDir, "io.k3sm.server.plist")
	since := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	record := func(st registrysvc.State) []byte {
		st.Port, st.Addr, st.Since = 5000, "127.0.0.1:5000", since
		b, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	answers := func(context.Context, string) error { return nil }
	silent := func(context.Context, string) error { return errors.New("connection refused") }

	cases := []struct {
		name string
		role dataroot.Role
		// state is the record's bytes; nil means no record on disk.
		state []byte
		// args is the installed server's argument list; nil means no plist.
		args       []string
		unreadable bool
		// published places the record at the world-readable copy as well, and
		// makes the 0600 original unreadable: an unprivileged account's view.
		published  bool
		probe      RegistryProbe
		wantRow    bool
		wantState  RowState
		wantSev    Severity
		wantDetail []string
		wantRemedy bool
	}{
		{
			name: "serving and /v2/ answers is ok", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateServing}), probe: answers,
			wantRow: true, wantState: StateOK, wantSev: SeverityOK, wantDetail: []string{"serving on 127.0.0.1:5000"},
		},
		{
			name: "serving claimed but /v2/ is silent warns", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateServing}), probe: silent,
			wantRow: true, wantState: StateDown, wantSev: SeverityWarn,
			wantDetail: []string{"recorded it serving", "connection refused"}, wantRemedy: true,
		},
		{
			name: "disabled warns with the reason", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateDisabled,
				Reason: "bring up the ingest registry on 127.0.0.1:5000 after 3 attempts: registry port already held\nzot log tail"}),
			probe:   answers,
			wantRow: true, wantState: StateDisabled, wantSev: SeverityWarn,
			wantDetail: []string{"after 3 attempts: registry port already held"}, wantRemedy: true,
		},
		{
			name: "reclaimed and /v2/ answers is ok with the pid", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateReclaimed, ReclaimedPID: 4242}), probe: answers,
			wantRow: true, wantState: StateOK, wantSev: SeverityOK,
			wantDetail: []string{"reclaimed an orphaned registry child (pid 4242) at this start"},
		},
		{
			name: "reclaimed but /v2/ is silent warns", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateReclaimed, ReclaimedPID: 4242}), probe: silent,
			wantRow: true, wantState: StateDown, wantSev: SeverityWarn, wantRemedy: true,
		},
		{
			name: "stopped is not a fault", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateStopped}), probe: silent,
			wantRow: true, wantState: StateStopped, wantSev: SeveritySkip,
		},
		{
			name: "no record (an older server) is no row", role: dataroot.RoleServer, probe: answers,
		},
		{
			name: "a worker has no row", role: dataroot.RoleAgent,
			state: record(registrysvc.State{State: registrysvc.StateServing}), probe: answers,
		},
		{
			name: "arguments that configure no registry are no row", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateServing}), probe: answers,
			args: []string{"--mesh-ip", "100.64.0.1"},
		},
		{
			name: "--registry-port=0 is no row", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateDisabled, Reason: "x"}), probe: answers,
			args: []string{"--registry-port=0"},
		},
		{
			name: "configured, record root-only needs admin", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateServing}), probe: answers,
			args: []string{"--registry-port", "5000"}, unreadable: true,
			wantRow: true, wantState: StateNeedsAdmin, wantSev: SeveritySkip,
		},
		{
			name: "unprivileged, published copy serving and answering is ok", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateServing}), probe: answers,
			args: []string{"--registry-port", "5000"}, published: true,
			wantRow: true, wantState: StateOK, wantSev: SeverityOK, wantDetail: []string{"serving on 127.0.0.1:5000"},
		},
		{
			name: "unprivileged, published copy disabled warns with the reason", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateDisabled, Reason: "registry port already held"}),
			probe: answers, args: []string{"--registry-port", "5000"}, published: true,
			wantRow: true, wantState: StateDisabled, wantSev: SeverityWarn,
			wantDetail: []string{"registry port already held"}, wantRemedy: true,
		},
		{
			name: "unprivileged, published copy serving but silent warns", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateServing}), probe: silent,
			published: true,
			wantRow:   true, wantState: StateDown, wantSev: SeverityWarn, wantRemedy: true,
		},
		{
			name: "unprivileged, published copy reclaimed is ok with the pid", role: dataroot.RoleServer,
			state: record(registrysvc.State{State: registrysvc.StateReclaimed, ReclaimedPID: 4242}), probe: answers,
			published: true,
			wantRow:   true, wantState: StateOK, wantSev: SeverityOK,
			wantDetail: []string{"(pid 4242)"},
		},
		{
			name: "garbage record is unknown", role: dataroot.RoleServer, state: []byte("{"), probe: answers,
			wantRow: true, wantState: StateUnknown, wantSev: SeverityUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fakeFS{contents: map[string][]byte{}, unreadable: map[string]bool{}}
			statePath := registrysvc.StatePath(workDir)
			if tc.state != nil {
				fsys.contents[statePath] = tc.state
			}
			if tc.unreadable {
				fsys.unreadable[statePath] = true
			}
			publishedPath := registrysvc.PublishedStatePath(workDir)
			if tc.published {
				fsys.contents[publishedPath] = tc.state
				fsys.unreadable[statePath] = true
			}
			if tc.args != nil {
				fsys.contents[plist] = []byte(strings.Join(tc.args, "\x00"))
			}
			var probed string
			c := Collector{
				FS:    fsys,
				Paths: Paths{WorkDir: workDir, LaunchDaemonDir: ldDir, ServerLabel: "io.k3sm.server"},
				ServerArgs: func(b []byte) ([]string, error) {
					return strings.Split(string(b), "\x00"), nil
				},
				RegistryProbe: func(ctx context.Context, url string) error {
					probed = url
					if _, ok := ctx.Deadline(); !ok {
						t.Error("the probe ran without a deadline")
					}
					return tc.probe(ctx, url)
				},
			}
			row, ok := c.ingestRegistryRow(t.Context(), tc.role)
			if ok != tc.wantRow {
				t.Fatalf("row present = %v, want %v (%+v)", ok, tc.wantRow, row)
			}
			if !ok {
				return
			}
			if row.Name != RowIngestRegistry || row.State != tc.wantState || row.Severity != tc.wantSev {
				t.Errorf("row = %s %s %s, want %s %s %s", row.Name, row.State, row.Severity,
					RowIngestRegistry, tc.wantState, tc.wantSev)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(row.Detail, want) {
					t.Errorf("detail %q does not carry %q", row.Detail, want)
				}
			}
			if strings.Contains(row.Detail, "\n") {
				t.Errorf("detail %q spans lines", row.Detail)
			}
			if got := row.Remedy != ""; got != tc.wantRemedy && tc.wantState != StateNeedsAdmin {
				t.Errorf("remedy = %q, want present=%v", row.Remedy, tc.wantRemedy)
			}
			if tc.wantRemedy && (!strings.Contains(row.Remedy, "k3sm status logs server") ||
				!strings.Contains(row.Remedy, "kickstart -k system/io.k3sm.server")) {
				t.Errorf("remedy = %q, want the server log and a server restart", row.Remedy)
			}
			if tc.wantState != StateNeedsAdmin && tc.wantState != StateUnknown {
				if row.Wide["port"] != "5000" || row.Wide["since"] != "2026-10-17T09:30:00Z" {
					t.Errorf("wide = %v, want port 5000 and since 2026-10-17T09:30:00Z", row.Wide)
				}
			}
			if tc.published {
				if row.State == StateNeedsAdmin {
					t.Errorf("an unprivileged read of the published copy said needs-admin")
				}
				if row.Wide["record"] != publishedPath {
					t.Errorf("wide.record = %q, want the published copy %q", row.Wide["record"], publishedPath)
				}
			}
			if tc.wantState == StateOK && probed != "http://127.0.0.1:5000/v2/" {
				t.Errorf("probed %q, want http://127.0.0.1:5000/v2/", probed)
			}
		})
	}
}

// TestRegistryAnswered pins what counts as a registry answering /v2/: the
// distribution spec's 200, or its 401 where it wants a credential.
func TestRegistryAnswered(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		wantOK bool
	}{
		{name: "200 answers", code: http.StatusOK, wantOK: true},
		{name: "401 answers", code: http.StatusUnauthorized, wantOK: true},
		{name: "404 is not a registry", code: http.StatusNotFound},
		{name: "500 is not serving", code: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := registryAnswered("http://127.0.0.1:5000/v2/", tc.code, http.StatusText(tc.code))
			if (err == nil) != tc.wantOK {
				t.Errorf("registryAnswered(%d) err = %v, want ok=%v", tc.code, err, tc.wantOK)
			}
		})
	}
}

// TestRegistryStatePathsAgree pins the record's two paths to the names the
// rest of k3sm uses: pkg/registrysvc cannot import pkg/install (which imports
// it), so it spells the basename and the status directory itself, and uninstall
// and the user-readable path rule must find the same files.
func TestRegistryStatePathsAgree(t *testing.T) {
	const workDir = "/var/lib/k3sm/server"
	orig := registrysvc.StatePath(workDir)
	if got := filepath.Base(orig); got != install.RegistryStateRecordName {
		t.Errorf("registrysvc record name %q, install removes %q", got, install.RegistryStateRecordName)
	}
	if got, want := registrysvc.PublishedStatePath(workDir), UserReadablePath(workDir, orig); got != want {
		t.Errorf("published copy %q, the status directory rule says %q", got, want)
	}
}
