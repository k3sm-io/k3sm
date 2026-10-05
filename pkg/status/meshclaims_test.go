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
