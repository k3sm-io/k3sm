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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

// RowMeshClaims reports the pod-range claims a server found abandoned: a joining
// server's reservation that never became a member, or a claim with no MeshPeer
// behind it. The row exists only on a server whose daemon has written the record.
const RowMeshClaims = "mesh-claims"

// MeshClaimsRecord is what a running server records about abandoned pod-range
// claims, refreshed every few minutes. The server sweeps abandoned claims on its
// own start; between starts it only records them, and this row is where an
// operator sees them.
type MeshClaimsRecord struct {
	UpdatedAt time.Time            `json:"updatedAt"`
	Abandoned []AbandonedMeshClaim `json:"abandoned,omitempty"`
}

// AbandonedMeshClaim is one abandoned claim.
type AbandonedMeshClaim struct {
	// Claim is the claim object, namespace/name.
	Claim string `json:"claim"`
	// Holder is the node name the claim reserves the range for.
	Holder  string `json:"holder"`
	PodCIDR string `json:"podCIDR"`
	// Kind is MeshClaimServerReservation or MeshClaimOrphan.
	Kind string `json:"kind"`
	// Acquired is when the claim was taken.
	Acquired time.Time `json:"acquired"`
}

// The abandoned-claim kinds.
const (
	// MeshClaimServerReservation: a server's range with a MeshPeer, no Ready Node
	// and no etcd member, past the abandonment age.
	MeshClaimServerReservation = "server-reservation"
	// MeshClaimOrphan: a claim whose holder has no MeshPeer at the range.
	MeshClaimOrphan = "orphan-claim"
)

// meshClaimsName is the record's basename, beside the etcd status record.
const meshClaimsName = "mesh-claims.json"

// MeshClaimsPath is the record's path for a work dir.
func MeshClaimsPath(workDir string) string { return filepath.Join(workDir, meshClaimsName) }

// meshClaimsStaleAfter is how old the record may get before the row stops
// vouching for it; the server refreshes it every few minutes.
const meshClaimsStaleAfter = 15 * time.Minute

// MeshClaimsRemedy is what to do about an abandoned claim.
const MeshClaimsRemedy = "restart a server (`sudo launchctl kickstart -k system/io.k3sm.server`), which sweeps abandoned claims on start; or remove each by hand: `kubectl -n kube-system delete lease <claim>` and `kubectl delete meshpeer <holder>`"

// meshClaimsRow reports the abandoned-claim record, or false when there is none.
func (c Collector) meshClaimsRow(now time.Time) (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil {
		return Row{}, false
	}
	path := MeshClaimsPath(wd)
	raw, err := c.FS.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Row{}, false
	case err != nil:
		return Row{Name: RowMeshClaims, State: StateUnknown, Severity: SeverityUnknown,
			Detail: "unreadable as this user: " + path, Remedy: "sudo k3sm status"}, true
	}
	var rec MeshClaimsRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Row{Name: RowMeshClaims, State: StateUnknown, Severity: SeverityUnknown,
			Detail: "the mesh claim record does not parse: " + path}, true
	}
	return meshClaimsRowFrom(rec, now), true
}

// meshClaimsRowFrom renders the row from a record. Pure.
func meshClaimsRowFrom(rec MeshClaimsRecord, now time.Time) Row {
	row := Row{Name: RowMeshClaims, Wide: map[string]string{"recorded": rec.UpdatedAt.UTC().Format(time.RFC3339)}}
	if now.Sub(rec.UpdatedAt) > meshClaimsStaleAfter {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = fmt.Sprintf("recorded %s ago; the server is not refreshing it", now.Sub(rec.UpdatedAt).Round(time.Second))
		return row
	}
	if len(rec.Abandoned) == 0 {
		row.State, row.Severity, row.Detail = StateOK, SeverityOK, "no abandoned pod-range claims"
		return row
	}
	parts := make([]string, 0, len(rec.Abandoned))
	for _, a := range rec.Abandoned {
		parts = append(parts, fmt.Sprintf("%s for %s at %s (%s)", a.Claim, a.Holder, a.PodCIDR, a.Kind))
	}
	row.State, row.Severity = StateUnhealthy, SeverityWarn
	row.Detail = fmt.Sprintf("%d abandoned pod-range claim(s): %s", len(rec.Abandoned), strings.Join(parts, "; "))
	row.Remedy = MeshClaimsRemedy
	return row
}
