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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
)

// TestMeshClaimsRowFrom pins the abandoned-claim row: none is ok, any is a warning
// naming each claim with the sweep-or-delete remedy, and a record the server
// stopped refreshing vouches for nothing.
func TestMeshClaimsRowFrom(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	t.Run("none", func(t *testing.T) {
		row := meshClaimsRowFrom(MeshClaimsRecord{UpdatedAt: now.Add(-time.Minute)}, now)
		if row.Severity != SeverityOK || row.Name != RowMeshClaims {
			t.Errorf("row = %+v, want an ok %s row", row, RowMeshClaims)
		}
	})
	t.Run("abandoned", func(t *testing.T) {
		row := meshClaimsRowFrom(MeshClaimsRecord{UpdatedAt: now.Add(-time.Minute), Abandoned: []AbandonedMeshClaim{
			{Claim: "kube-system/meshrange-1", Holder: "laptop", PodCIDR: "100.64.1.0/24", Kind: MeshClaimServerReservation},
		}}, now)
		if row.Severity != SeverityWarn || row.Remedy != MeshClaimsRemedy {
			t.Errorf("row = %+v, want a warning with the remedy", row)
		}
		for _, want := range []string{"kube-system/meshrange-1", "laptop", "100.64.1.0/24"} {
			if !strings.Contains(row.Detail, want) {
				t.Errorf("detail %q does not name %q", row.Detail, want)
			}
		}
		if !advisory(dataroot.RoleServer, row.Name) {
			t.Error("an abandoned claim moves the verdict; it is housekeeping, the safe direction")
		}
	})
	t.Run("stale", func(t *testing.T) {
		row := meshClaimsRowFrom(MeshClaimsRecord{UpdatedAt: now.Add(-time.Hour)}, now)
		if row.Severity != SeverityUnknown {
			t.Errorf("a stale record reported %v, want unknown", row.Severity)
		}
	})
}

// TestMeshClaimsRowReadsTheUserReadableCopy pins the account that cannot read
// the work dir: the row reads the copy the server publishes in Dir, is absent
// when Dir holds none (the server has recorded nothing), and needs admin only
// when there is no status directory to read from.
func TestMeshClaimsRowReadsTheUserReadableCopy(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	wd := "/var/lib/k3sm/server"
	path := MeshClaimsPath(wd)
	rec, err := json.Marshal(MeshClaimsRecord{UpdatedAt: now.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		fs     fakeFS
		wantOK bool
		state  RowState
		record string
	}{
		{"the user-readable copy", fakeFS{unreadable: map[string]bool{path: true}, contents: map[string][]byte{UserReadablePath(wd, path): rec}}, true, StateOK, UserReadablePath(wd, path)},
		{"a status dir with no copy: no record", fakeFS{unreadable: map[string]bool{path: true}, present: map[string]bool{Dir(wd): true}}, false, "", ""},
		{"no status dir: needs admin", fakeFS{unreadable: map[string]bool{path: true}}, true, StateNeedsAdmin, path},
		{"root reads the work-dir copy", fakeFS{contents: map[string][]byte{path: rec}}, true, StateOK, path},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, ok := Collector{FS: tc.fs, Paths: Paths{WorkDir: wd}}.meshClaimsRow(now)
			if ok != tc.wantOK {
				t.Fatalf("row present = %v, want %v (%+v)", ok, tc.wantOK, row)
			}
			if !ok {
				return
			}
			if row.State != tc.state || row.Wide["record"] != tc.record {
				t.Errorf("row = %s from %q, want %s from %q", row.State, row.Wide["record"], tc.state, tc.record)
			}
		})
	}
	if got := Dir(wd); got != "/var/lib/k3sm/status" {
		t.Errorf("Dir(%q) = %q, want /var/lib/k3sm/status", wd, got)
	}
}
