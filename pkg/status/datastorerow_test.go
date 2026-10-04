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

	fresh := c.datastoreRow(dataroot.RoleServer)
	if fresh.State != StateSkip || fresh.Detail != "no state.db yet" {
		t.Fatalf("fresh server row = %s %q, want skip \"no state.db yet\"", fresh.State, fresh.Detail)
	}

	if err := os.MkdirAll(filepath.Join(executor.EtcdDataDir(wd), "member"), 0o700); err != nil {
		t.Fatal(err)
	}
	row := c.datastoreRow(dataroot.RoleServer)
	if row.State != StateOK || !strings.Contains(row.Detail, "etcd") || strings.Contains(row.Detail, "no state.db yet") {
		t.Errorf("etcd server row = %s %q, want an ok row naming the etcd member", row.State, row.Detail)
	}
	if row.Wide["path"] != executor.EtcdDataDir(wd) {
		t.Errorf("etcd server row path = %q, want %q", row.Wide["path"], executor.EtcdDataDir(wd))
	}
}
