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
	"unicode"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/validation"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/version"
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
	// UpdateBehind is one that runs an older release.
	UpdateBehind = "behind"
	// UpdateAhead is one that runs a release newer than the latest (a build
	// from a tag not yet published as a release).
	UpdateAhead = "ahead"
	// UpdateUnknown is one whose version is not a tagged release: no k3sm
	// version at all, a dev build, or a build from a modified tree.
	UpdateUnknown = "unknown"
)

// ReleaseState compares a k3sm release version with the latest release tag in
// semver order, build metadata ignored: UpdateCurrent, UpdateBehind,
// UpdateAhead, or UpdateUnknown when either is not a tagged release. It is the
// one comparison both the check and the status row make.
func ReleaseState(have, latest string) string {
	cmp, ok := version.CompareReleases(have, latest)
	switch {
	case !ok:
		return UpdateUnknown
	case cmp < 0:
		return UpdateBehind
	case cmp > 0:
		return UpdateAhead
	}
	return UpdateCurrent
}

// NodeReleaseState is ReleaseState for a node's kubelet version, which carries
// its k3sm release after "+k3sm." (version.Info.NodeVersion).
func NodeReleaseState(kubelet, latest string) string {
	rel, ok := version.NodeRelease(kubelet)
	if !ok {
		return UpdateUnknown
	}
	return ReleaseState(rel, latest)
}

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
	// Installed is the version of the binary that ran the check,
	// InstalledDirty whether it was built from a modified tree, and
	// InstalledState how it compares with Latest (a reader recomputes it).
	Installed      string `json:"installed,omitempty"`
	InstalledDirty bool   `json:"installedDirty,omitempty"`
	InstalledState string `json:"installedState,omitempty"`
	// Nodes is every Node of the cluster, sorted by name.
	Nodes []UpdateNode `json:"nodes,omitempty"`
	// Roll is the managed update in progress, nil when none is: the server
	// refreshes it while an Update is not finished, independently of the
	// hourly check.
	Roll *UpdateRoll `json:"roll,omitempty"`
}

// UpdateRoll is the managed update a record saw in progress.
type UpdateRoll struct {
	// ObservedAt is when the server last read the Update. The row trusts a
	// roll only while it is fresh (UpdateRollStaleAfter).
	ObservedAt time.Time `json:"observedAt"`
	// Version is the release the cluster is moving to (spec.version).
	Version string `json:"version"`
	// Phase is the Update's display phase (Pending, Rolling), empty before
	// the controller reconciles it.
	Phase string `json:"phase,omitempty"`
	// Node is the node being updated and NodePhase its step; both empty
	// before the first node starts.
	Node      string `json:"node,omitempty"`
	NodePhase string `json:"nodePhase,omitempty"`
}

// UpdateRollEvery is how often a server re-reads the Update while one may be
// in progress, and so how far the update row trails the controller.
const UpdateRollEvery = 30 * time.Second

// UpdateRollStaleAfter is how old a recorded roll may get before the row
// stops reporting it: several missed refreshes, as when the server is down.
const UpdateRollStaleAfter = 5 * time.Minute

// UpdateNode is one Node of an update record.
type UpdateNode struct {
	Name string `json:"name"`
	// Version is Node.status.nodeInfo.kubeletVersion as the node reports it.
	Version string `json:"version"`
	// State is UpdateCurrent, UpdateBehind, UpdateAhead or UpdateUnknown; a
	// reader recomputes it from Version.
	State string `json:"state"`
}

// UpdateErrorMax is how many bytes of a check's error a record keeps.
const UpdateErrorMax = 512

// ClipText control-strips s (every control and format character, so a
// newline, an escape sequence or a bidi override cannot reach a terminal) and
// clips it to max bytes on a rune boundary, marking a clip with "...".
func ClipText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			return strings.TrimRightFunc(b.String(), unicode.IsSpace) + "..."
		}
		b.WriteRune(r)
	}
	return b.String()
}

// updateTextMax bounds every record string that reaches a row.
const updateTextMax = 200

// updateClockSlack is how far in the future a record's CheckedAt may sit
// before it is treated as missing: clock skew, not a forged freshness.
const updateClockSlack = 5 * time.Minute

// errUpdateRecordInvalid is a record that fails validation.
var errUpdateRecordInvalid = errors.New("the update record is not valid")

// validUpdateRecord checks a record read from disk as untrusted input: the
// tag and every node version pass the tag grammar, every node name is a
// resource name, every stored state is a known word, and the free text is
// valid UTF-8 of bounded length. It reports the first problem.
func validUpdateRecord(rec UpdateRecord) error {
	if rec.Latest != "" && !version.ValidTag(rec.Latest) {
		return fmt.Errorf("%w: unusable latest tag", errUpdateRecordInvalid)
	}
	for _, s := range []string{rec.Installed, rec.KubeVersion} {
		if s != "" && !version.ValidTag(s) {
			return fmt.Errorf("%w: unusable version", errUpdateRecordInvalid)
		}
	}
	if !knownUpdateWord(rec.InstalledState, true) {
		return fmt.Errorf("%w: unknown installed state", errUpdateRecordInvalid)
	}
	if !utf8.ValidString(rec.Error) || len(rec.Error) > UpdateErrorMax+len("...") {
		return fmt.Errorf("%w: error text", errUpdateRecordInvalid)
	}
	if r := rec.Roll; r != nil {
		if !version.ValidTag(r.Version) || !UpdatePhaseWord(r.Phase) || !UpdatePhaseWord(r.NodePhase) ||
			(r.Node != "" && len(validation.IsDNS1123Subdomain(r.Node)) > 0) {
			return fmt.Errorf("%w: roll", errUpdateRecordInvalid)
		}
	}
	for _, n := range rec.Nodes {
		if len(validation.IsDNS1123Subdomain(n.Name)) > 0 {
			return fmt.Errorf("%w: node name", errUpdateRecordInvalid)
		}
		if n.Version != "" && !version.ValidTag(n.Version) {
			return fmt.Errorf("%w: node version", errUpdateRecordInvalid)
		}
		if !knownUpdateWord(n.State, false) {
			return fmt.Errorf("%w: node state", errUpdateRecordInvalid)
		}
	}
	return nil
}

// UpdatePhaseWord reports whether s may be a recorded update phase: empty, or
// a short run of ASCII letters (the phases are open-ended display words, so
// the shape is checked, not the value).
func UpdatePhaseWord(s string) bool {
	if len(s) > 32 {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// knownUpdateWord reports whether s is a per-node update word (or empty, when
// allowed).
func knownUpdateWord(s string, emptyOK bool) bool {
	switch s {
	case UpdateCurrent, UpdateBehind, UpdateAhead, UpdateUnknown:
		return true
	case "":
		return emptyOK
	}
	return false
}

// UpdateRecordInterval is how often a server refreshes its UpdateRecord.
const UpdateRecordInterval = time.Hour

// updateStaleAfter is how old the record may get before the row stops
// vouching for it.
const updateStaleAfter = 24 * time.Hour

// UpdateCheckRemedy refreshes the record, for an account that may not write
// the status directory; UpdateCheckRemedyWritable is the same for one that may
// (root and the service user).
const (
	UpdateCheckRemedy         = "sudo k3sm update check"
	UpdateCheckRemedyWritable = "k3sm update check"
)

// UpdateUpgradeRemedy is how a node moves to the latest release (docs/user/upgrade.md).
const UpdateUpgradeRemedy = "curl -fsSL https://k3sm.io/install.sh | sh"

// updateName is the record's basename.
const updateName = install.UpdateRecordName

// UpdatePath is the record's path for a server work dir: only in the
// user-readable status directory (Dir), 0644, so any account's `k3sm status`
// reads it.
func UpdatePath(workDir string) string {
	return filepath.Join(Dir(workDir), updateName)
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
		row.Detail, row.Remedy = updateMissingDetail, c.updateCheckRemedy()
		return row, true
	case err != nil:
		row.Detail, row.Remedy = "unreadable as this user: "+path, "sudo k3sm status"
		return row, true
	}
	var rec UpdateRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		row.Detail, row.Remedy = "the update record does not parse: "+path, c.updateCheckRemedy()
		return row, true
	}
	r := UpdateRowFrom(rec, now)
	r.Wide["record"] = path
	if r.Remedy == UpdateCheckRemedy {
		r.Remedy = c.updateCheckRemedy()
	}
	return r, true
}

// updateCheckRemedy is the refresh command for the account running the
// report: the bare check when it may write the status directory (root, or the
// service user who owns it), the sudo form otherwise.
func (c Collector) updateCheckRemedy() string {
	if c.EUID == 0 || (c.ServiceUID >= 0 && c.EUID == c.ServiceUID) {
		return UpdateCheckRemedyWritable
	}
	return UpdateCheckRemedy
}

// updateMissingDetail is the row's detail when no usable check is recorded.
const updateMissingDetail = "no update check is recorded yet (the server checks once an hour)"

// UpdateRowFrom renders the update row from a record. Pure. The record is
// untrusted input: it is validated, every string is control-stripped and
// clipped before it reaches Detail or Wide, a CheckedAt beyond the clock slack
// in the future reads as no record, and each node's state is recomputed from
// its recorded version rather than read from the stored word.
func UpdateRowFrom(rec UpdateRecord, now time.Time) Row {
	row := Row{Name: RowUpdate, State: StateUnknown, Severity: SeverityUnknown, Wide: map[string]string{}, Remedy: UpdateCheckRemedy}
	if rec.CheckedAt.After(now.Add(updateClockSlack)) {
		row.Detail = updateMissingDetail
		return row
	}
	if err := validUpdateRecord(rec); err != nil {
		row.Detail = err.Error()
		return row
	}
	if r := rec.Roll; r != nil && !r.ObservedAt.After(now.Add(updateClockSlack)) && now.Sub(r.ObservedAt) <= UpdateRollStaleAfter {
		return updateRollRow(row, *r)
	}
	row.Wide["checked"] = rec.CheckedAt.UTC().Format(time.RFC3339)
	if rec.Latest != "" {
		row.Wide["latest"] = rec.Latest
	}
	if rec.KubeVersion != "" {
		row.Wide["latest-kubernetes"] = rec.KubeVersion
	}
	if age := now.Sub(rec.CheckedAt); age > updateStaleAfter {
		row.Detail = fmt.Sprintf("the last update check ran %s ago", age.Round(time.Minute))
		return row
	}
	if rec.Error != "" {
		row.Detail = "could not check for an update: " + ClipText(Redact(firstLine(rec.Error)), updateTextMax)
		return row
	}
	if rec.Latest == "" {
		row.Detail = "the update check found no release"
		return row
	}
	var behind, ahead, unknown []string
	add := func(name, ver, state string) {
		label := name + " (" + ClipText(ver, updateTextMax) + ")"
		switch state {
		case UpdateBehind:
			behind = append(behind, label)
		case UpdateAhead:
			ahead = append(ahead, label)
		case UpdateUnknown:
			unknown = append(unknown, name)
		}
	}
	for _, n := range rec.Nodes {
		add(n.Name, n.Version, NodeReleaseState(n.Version, rec.Latest))
	}
	// With no node list (no apiserver to ask), the binary that ran the check is
	// the one fact there is.
	if len(rec.Nodes) == 0 {
		state := UpdateUnknown
		if !rec.InstalledDirty {
			state = ReleaseState(rec.Installed, rec.Latest)
		}
		add("this Mac", rec.Installed, state)
	}
	row.Remedy = ""
	newer := ""
	if len(ahead) > 0 {
		newer = "newer than the latest release: " + strings.Join(ahead, ", ")
	}
	switch {
	case len(behind) > 0:
		row.State, row.Severity = StateBehind, SeverityWarn
		row.Detail = fmt.Sprintf("k3sm %s is available; behind: %s", rec.Latest, strings.Join(behind, ", "))
		if newer != "" {
			row.Detail += "; " + newer
		}
		row.Remedy = UpdateUpgradeRemedy
	case len(unknown) > 0:
		row.Detail = fmt.Sprintf("k3sm %s is the latest; no tagged k3sm release reported by: %s", rec.Latest, strings.Join(unknown, ", "))
		if newer != "" {
			row.Detail += "; " + newer
		}
	case len(ahead) > 0:
		row.State, row.Severity = StateAhead, SeverityOK
		row.Detail = fmt.Sprintf("k3sm %s is the latest; %s", rec.Latest, newer)
	case len(rec.Nodes) == 0:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("this Mac runs the latest release, k3sm %s", rec.Latest)
	default:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("every node runs the latest release, k3sm %s", rec.Latest)
	}
	return row
}

// updateRollRow is the update row while a managed update is in progress. It
// is informational: severity ok, no remedy, the verdict unmoved.
func updateRollRow(row Row, r UpdateRoll) Row {
	row.State, row.Severity, row.Remedy = StateRolling, SeverityOK, ""
	phase := r.Phase
	if phase == "" {
		phase = "Pending"
	}
	row.Wide["target"] = r.Version
	row.Wide["phase"] = phase
	row.Wide["observed"] = r.ObservedAt.UTC().Format(time.RFC3339)
	row.Detail = fmt.Sprintf("updating the cluster to k3sm %s: %s", r.Version, phase)
	if r.Node != "" {
		row.Wide["node"] = r.Node
		row.Detail += ", node " + r.Node
		if r.NodePhase != "" {
			row.Wide["node-phase"] = r.NodePhase
			row.Detail += " " + r.NodePhase
		}
	}
	return row
}
