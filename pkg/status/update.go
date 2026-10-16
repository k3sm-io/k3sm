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

// RowUpdate reports whether every node of the cluster runs the latest k3sm
// release, read from the record the last update check left. It exists only on
// a server. The report never asks GitHub itself: the server refreshes the
// record at most once an UpdateRecordInterval, and `k3sm update check` does on
// demand.
const RowUpdate = "update"

// The per-node words of an update record.
const (
	// UpdateCurrent is a node (or this binary) that runs the latest release.
	UpdateCurrent = "current"
	// UpdateBehind is one that runs any other release.
	UpdateBehind = "behind"
	// UpdateUnknown is a node whose kubelet reports no k3sm version.
	UpdateUnknown = "unknown"
)

// UpdateRecord is what an update check records for `k3sm status`.
type UpdateRecord struct {
	// CheckedAt is when the check ran.
	CheckedAt time.Time `json:"checkedAt"`
	// Error is why the check could not finish (GitHub unreachable, the node
	// list refused); empty when it did.
	Error string `json:"error,omitempty"`
	// Latest is the newest release tag, Published its publication time
	// (RFC 3339), and KubeVersion the Kubernetes version it ships; each is
	// empty when unknown.
	Latest      string `json:"latest,omitempty"`
	Published   string `json:"published,omitempty"`
	KubeVersion string `json:"kubeVersion,omitempty"`
	// Installed is the version of the binary that ran the check, and
	// InstalledState its UpdateCurrent/UpdateBehind word.
	Installed      string `json:"installed,omitempty"`
	InstalledState string `json:"installedState,omitempty"`
	// Nodes is every Node of the cluster, sorted by name.
	Nodes []UpdateNode `json:"nodes,omitempty"`
}

// UpdateNode is one Node of an update record.
type UpdateNode struct {
	Name string `json:"name"`
	// Version is Node.status.nodeInfo.kubeletVersion as the node reports it.
	Version string `json:"version"`
	// State is UpdateCurrent, UpdateBehind or UpdateUnknown.
	State string `json:"state"`
}

// UpdateRecordInterval is how often a server refreshes its UpdateRecord.
const UpdateRecordInterval = time.Hour

// updateStaleAfter is how old the record may get before the row stops
// vouching for it.
const updateStaleAfter = 24 * time.Hour

// UpdateCheckRemedy refreshes the record.
const UpdateCheckRemedy = "sudo k3sm update check"

// UpdateUpgradeRemedy is how a node moves to the latest release (docs/user/upgrade.md).
const UpdateUpgradeRemedy = "curl -fsSL https://k3sm.io/install.sh | sh"

// UpdateDirName is the record's directory under the server work dir.
const UpdateDirName = "status"

// updateName is the record's basename.
const updateName = "update.json"

// UpdatePath is the record's path for a server work dir.
func UpdatePath(workDir string) string {
	return filepath.Join(workDir, UpdateDirName, updateName)
}

// updateRow reads the update record, or false when this report has no work dir
// to read it from.
func (c Collector) updateRow(now time.Time) (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil {
		return Row{}, false
	}
	path := UpdatePath(wd)
	row := Row{Name: RowUpdate, State: StateUnknown, Severity: SeverityUnknown, Wide: map[string]string{"record": path}}
	raw, err := c.FS.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		row.Detail, row.Remedy = "no update check is recorded yet (the server checks once an hour)", UpdateCheckRemedy
		return row, true
	case err != nil:
		row.Detail, row.Remedy = "unreadable as this user: "+path, "sudo k3sm status"
		return row, true
	}
	var rec UpdateRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		row.Detail, row.Remedy = "the update record does not parse: "+path, UpdateCheckRemedy
		return row, true
	}
	r := UpdateRowFrom(rec, now)
	r.Wide["record"] = path
	return r, true
}

// UpdateRowFrom renders the update row from a record. Pure.
func UpdateRowFrom(rec UpdateRecord, now time.Time) Row {
	row := Row{Name: RowUpdate, State: StateUnknown, Severity: SeverityUnknown, Wide: map[string]string{
		"checked": rec.CheckedAt.UTC().Format(time.RFC3339),
	}}
	if rec.Latest != "" {
		row.Wide["latest"] = rec.Latest
	}
	if rec.KubeVersion != "" {
		row.Wide["latest-kubernetes"] = rec.KubeVersion
	}
	if age := now.Sub(rec.CheckedAt); age > updateStaleAfter {
		row.Detail = fmt.Sprintf("the last update check ran %s ago", age.Round(time.Minute))
		row.Remedy = UpdateCheckRemedy
		return row
	}
	if rec.Error != "" {
		row.Detail = "could not check for an update: " + Redact(firstLine(rec.Error))
		row.Remedy = UpdateCheckRemedy
		return row
	}
	if rec.Latest == "" {
		row.Detail, row.Remedy = "the update check found no release", UpdateCheckRemedy
		return row
	}
	var behind, unknown []string
	for _, n := range rec.Nodes {
		switch n.State {
		case UpdateCurrent:
		case UpdateBehind:
			behind = append(behind, fmt.Sprintf("%s (%s)", n.Name, n.Version))
		default:
			unknown = append(unknown, n.Name)
		}
	}
	// With no node list (no apiserver to ask), the binary that ran the check is
	// the one fact there is.
	if len(rec.Nodes) == 0 && rec.InstalledState == UpdateBehind {
		behind = append(behind, "this Mac ("+rec.Installed+")")
	}
	switch {
	case len(behind) > 0:
		row.State, row.Severity = StateBehind, SeverityWarn
		row.Detail = fmt.Sprintf("k3sm %s is available; behind: %s", rec.Latest, strings.Join(behind, ", "))
		row.Remedy = UpdateUpgradeRemedy
	case len(unknown) > 0:
		row.Detail = fmt.Sprintf("k3sm %s is the latest; no k3sm version reported by: %s", rec.Latest, strings.Join(unknown, ", "))
	case len(rec.Nodes) == 0:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("this Mac runs the latest release, k3sm %s", rec.Latest)
	default:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("every node runs the latest release, k3sm %s", rec.Latest)
	}
	return row
}
