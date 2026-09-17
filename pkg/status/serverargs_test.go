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
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// fakeServerArgs stands in for the installer's parser: it splits the "plist" on
// whitespace. The parse itself is pinned in pkg/install, which owns it; what is
// under test here is the ROW — what it says for each answer that seam can give.
func fakeServerArgs(plist []byte) ([]string, error) {
	if strings.HasPrefix(string(plist), "broken") {
		return nil, errors.New("no ProgramArguments array")
	}
	return strings.Fields(string(plist)), nil
}

// TestServerArgsRow covers every answer the row can give, including the two that
// must NOT move the verdict: an unreadable plist is an unprivileged report, not
// a degraded cluster.
func TestServerArgsRow(t *testing.T) {
	p := testPaths(t.TempDir())
	plist := filepath.Join(p.LaunchDaemonDir, p.ServerLabel+".plist")

	for _, tc := range []struct {
		name       string
		collector  func() Collector
		wantRow    bool
		wantState  RowState
		wantDetail string
	}{
		{
			name: "the operator's flags, in order",
			collector: func() Collector {
				fsys := installedFS(p)
				fsys.contents = map[string][]byte{plist: []byte("--mesh-ip 100.64.0.1 --registry-port 5000")}
				return Collector{FS: fsys, ServerArgs: fakeServerArgs, Paths: p}
			},
			wantRow: true, wantState: StateOK,
			wantDetail: "--mesh-ip 100.64.0.1 --registry-port 5000",
		},
		{
			name: "a stock template says so, and names what is not set",
			collector: func() Collector {
				fsys := installedFS(p)
				fsys.contents = map[string][]byte{plist: []byte("")}
				return Collector{FS: fsys, ServerArgs: fakeServerArgs, Paths: p}
			},
			wantRow: true, wantState: StateOK,
			wantDetail: "none (the stock template: no --mesh-ip, no --registry-port)",
		},
		{
			name: "a plist this account cannot read is unknown, never a failure",
			collector: func() Collector {
				fsys := installedFS(p)
				fsys.contents = map[string][]byte{plist: []byte("--mesh-ip 100.64.0.1")}
				fsys.unreadable = map[string]bool{plist: true}
				return Collector{FS: fsys, ServerArgs: fakeServerArgs, Paths: p}
			},
			wantRow: true, wantState: StateUnknown,
			wantDetail: "unreadable as this user: " + plist,
		},
		{
			name: "a plist whose argv will not parse is unknown too",
			collector: func() Collector {
				fsys := installedFS(p)
				fsys.contents = map[string][]byte{plist: []byte("broken")}
				return Collector{FS: fsys, ServerArgs: fakeServerArgs, Paths: p}
			},
			wantRow: true, wantState: StateUnknown,
		},
		{
			name: "no plist at all: no row (the install row already says it)",
			collector: func() Collector {
				return Collector{FS: installedFS(p), ServerArgs: fakeServerArgs, Paths: p}
			},
		},
		{
			name: "no parser wired: no row",
			collector: func() Collector {
				fsys := installedFS(p)
				fsys.contents = map[string][]byte{plist: []byte("--mesh-ip 100.64.0.1")}
				return Collector{FS: fsys, Paths: p}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, ok := tc.collector().serverArgsRow()
			if ok != tc.wantRow {
				t.Fatalf("row present = %t, want %t (%+v)", ok, tc.wantRow, row)
			}
			if !ok {
				return
			}
			if row.Name != RowServerArgs {
				t.Errorf("row name = %q, want %q", row.Name, RowServerArgs)
			}
			if row.State != tc.wantState {
				t.Errorf("state = %q, want %q (%s)", row.State, tc.wantState, row.Detail)
			}
			if tc.wantDetail != "" && row.Detail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", row.Detail, tc.wantDetail)
			}
			if row.Severity == SeverityFail || row.Severity == SeverityWarn {
				t.Errorf("severity = %v: a read-only report of the configured flags must never move the verdict", row.Severity)
			}
		})
	}
}

// TestServerArgsRowRedactsCredentials proves the row goes through Redact like
// every other field that quotes an argv. The installer never carries --token
// into the arguments this row reads, so this is a belt on a brace — and it is
// the belt that holds if a future flag carries a secret.
func TestServerArgsRowRedactsCredentials(t *testing.T) {
	p := testPaths(t.TempDir())
	plist := filepath.Join(p.LaunchDaemonDir, p.ServerLabel+".plist")
	fsys := installedFS(p)
	fsys.contents = map[string][]byte{plist: []byte("--mesh-ip 100.64.0.1 --agent-token " + fakeToken)}

	row, ok := Collector{FS: fsys, ServerArgs: fakeServerArgs, Paths: p}.serverArgsRow()
	if !ok {
		t.Fatal("no server-args row")
	}
	if strings.Contains(row.Detail, fakeToken) {
		t.Errorf("the row leaked a credential: %q", row.Detail)
	}
	if !strings.Contains(row.Detail, "100.64.0.1") {
		t.Errorf("the row redacted more than the credential: %q", row.Detail)
	}
}

// TestServerArgsRowRenders proves the row reaches the screens an operator
// actually looks at: the overview and the daemons view, right after the server
// it describes.
func TestServerArgsRowRenders(t *testing.T) {
	rows := append(healthyRows(), row(RowServerArgs, StateOK, SeverityOK, "--mesh-ip 100.64.0.1 --registry-port 5000", ""))
	rep := report(rows, true)

	screen := Render(rep, Style{})
	if !strings.Contains(screen, "server-args") || !strings.Contains(screen, "--registry-port 5000") {
		t.Fatalf("the overview must carry the server-args row:\n%s", screen)
	}
	if strings.Index(screen, "server-args") < strings.Index(screen, "server ") {
		t.Errorf("the server-args row must follow the server row:\n%s", screen)
	}
	if daemons := RenderDaemons(rep, Style{}); !strings.Contains(daemons, "server-args") {
		t.Errorf("the daemons view must carry the server-args row:\n%s", daemons)
	}
}
