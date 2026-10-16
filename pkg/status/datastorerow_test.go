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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
)

// TestDatastoreRowEtcdMember pins that an embedded etcd HA server's datastore row
// names the etcd member instead of reporting "no state.db yet", which would read as
// a server that never came up; a server with neither is still the fresh-node skip.
func TestDatastoreRowEtcdMember(t *testing.T) {
	wd := t.TempDir()
	c := Collector{Paths: testPaths(wd)}

	fresh := c.datastoreRow(dataroot.RoleServer, Row{})
	if fresh.State != StateSkip || fresh.Detail != "no state.db yet" {
		t.Fatalf("fresh server row = %s %q, want skip \"no state.db yet\"", fresh.State, fresh.Detail)
	}

	if err := os.MkdirAll(filepath.Join(executor.EtcdDataDir(wd), "member"), 0o700); err != nil {
		t.Fatal(err)
	}
	row := c.datastoreRow(dataroot.RoleServer, Row{})
	if row.State != StateOK || !strings.Contains(row.Detail, "etcd") || strings.Contains(row.Detail, "no state.db yet") {
		t.Errorf("etcd server row = %s %q, want an ok row naming the etcd member", row.State, row.Detail)
	}
	if row.Wide["path"] != executor.EtcdDataDir(wd) {
		t.Errorf("etcd server row path = %q, want %q", row.Wide["path"], executor.EtcdDataDir(wd))
	}
}

// unreadableWorkDir is a work dir this test process may not look inside, which
// is what the installed 0700 server work dir is to an ordinary account.
func unreadableWorkDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads every work dir; this case is about an ordinary account")
	}
	wd := filepath.Join(t.TempDir(), "server")
	if err := os.MkdirAll(filepath.Dir(executor.StateDBPath(wd)), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFakeSQLiteHeader(t, executor.StateDBPath(wd), 2, 1)
	if err := os.Chmod(wd, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(wd, 0o700) })
	return wd
}

// TestDatastoreRowThroughAPIServer pins the account that cannot read state.db:
// the row asks the apiserver's readiness check, which includes the datastore,
// and is unknown only when the apiserver did not answer.
func TestDatastoreRowThroughAPIServer(t *testing.T) {
	c := Collector{Paths: testPaths(unreadableWorkDir(t))}
	for _, tc := range []struct {
		name      string
		apiserver Row
		state     RowState
		sev       Severity
		detail    string
	}{
		{"a ready apiserver proves the datastore answers", Row{State: StateReady}, StateOK, SeverityOK, DatastoreAnswersDetail},
		{"an apiserver that did not answer leaves it unknown", Row{State: StateDown}, StateUnknown, SeverityUnknown, "the apiserver did not answer"},
		{"no apiserver probe at all leaves it unknown", Row{State: StateUnknown}, StateUnknown, SeverityUnknown, "the apiserver did not answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := c.datastoreRow(dataroot.RoleServer, tc.apiserver)
			if row.State != tc.state || row.Severity != tc.sev || !strings.Contains(row.Detail, tc.detail) {
				t.Errorf("row = %s/%s %q, want %s/%s containing %q", row.State, row.Severity, row.Detail, tc.state, tc.sev, tc.detail)
			}
			if row.Wide["source"] != "apiserver readyz" {
				t.Errorf("wide source = %q, want the apiserver named as the source", row.Wide["source"])
			}
		})
	}
}
