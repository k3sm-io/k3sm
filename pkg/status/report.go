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
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/version"
)

// RowState is the short token rendered in a row's STATE column. It is free text
// by type — new subsystems bring their own words — but the vocabulary below is
// the set the shipped rows use, and the words are part of what an operator (and
// a script reading -o json) reads, so they change like an API, not like prose.
type RowState string

// The shipped row-state vocabulary.
const (
	StateOK         RowState = "ok"
	StateRunning    RowState = "running"
	StateReady      RowState = "ready"
	StateCrashLoop  RowState = "crash-loop"
	StateFailed     RowState = "failed"
	StateStopped    RowState = "stopped"
	StateNotLoaded  RowState = "not-loaded"
	StateDisabled   RowState = "disabled"
	StateDown       RowState = "down"
	StateNotReady   RowState = "not-ready"
	StateWrongOwner RowState = "wrong-owner"
	StateNotMounted RowState = "not-mounted"
	StateAbsent     RowState = "absent"
	StatePartial    RowState = "partial"
	StateMissing    RowState = "missing"
	StateSkip       RowState = "skip"
	// StateWaiting, StateExpired, StateCorrupt and StateAddressMismatch are the
	// joining worker's credential words: a daemon that is up and has never
	// joined, one whose node certificate has run out, one whose stored
	// credential does not parse, and one whose serving certificate names an
	// address this node is not assigned. They describe the CREDENTIAL, not the
	// launchd job, which is why they are distinct from stopped/failed — the pid
	// is fine in all four.
	StateWaiting RowState = "waiting"
	StateExpired RowState = "expired"
	StateCorrupt RowState = "corrupt"
	// StateAddressMismatch is the fourth: the credential is complete and in
	// date, and names an address this node is not assigned.
	StateAddressMismatch RowState = "address-mismatch"
	// StateRefused is the kubeconfig row's word for a credential the
	// apiserver answered and refused as unauthenticated (401): the file is
	// there and parses, and what it holds is no longer accepted, typically an
	// admin credential a reinstall of the server replaced. A credential that
	// authenticates and is then denied by RBAC (403) is not refused.
	StateRefused RowState = "refused"
	// StateDrift is the shadow binary set's word for a copy made from a host
	// binary macOS has since replaced, or a set made by an older install.
	StateDrift     RowState = "drift"
	StateUnknown   RowState = "unknown"
	StateHealthy   RowState = "healthy"
	StateUnhealthy RowState = "unhealthy"
	// StateStale is the heartbeat row's word for a node whose last successful
	// status post or Lease renewal is older than the window the node lifecycle
	// allows it.
	StateStale RowState = "stale"
	// StateNeedsAdmin is a check only root can run: the runtime daemon's
	// owner-only socket, the admin kubeconfig install recorded, a root-only
	// file. It is not unknown: nothing went wrong and nothing is hidden by a
	// fault, the answer simply needs sudo. Its severity is skip (or, on a row
	// whose readable part found something, that part's severity), so it never
	// moves the verdict, and its remedy is the sudo command that answers it.
	StateNeedsAdmin RowState = "needs-admin"
	// StateBehind is the update row's word for a cluster with at least one
	// node that does not run the latest k3sm release.
	StateBehind RowState = "behind"
	// StateAhead is the update row's word for a cluster with a node newer than
	// the latest release and none behind it.
	StateAhead RowState = "ahead"
	// StateRolling is the update row's word for a cluster the server's update
	// controller is rolling to a release (an Update not yet finished).
	StateRolling RowState = "rolling"
	// StateOn is the developer-mode row's word for a valid marker: the
	// signature checks are off.
	StateOn RowState = "on"
	// StateInvalid is the developer-mode row's word for something at the
	// marker path that fails the checks, so it is ignored.
	StateInvalid RowState = "invalid"
)

// Row is one subsystem's line in the report.
//
// Name and State are stable tokens; Detail is the sentence an operator reads;
// Remedy is the command that fixes this row, and may carry several lines (one
// command each) when the repair genuinely takes more than one step. Wide holds
// the extra columns the wide and daemons views expand — it is never rendered on
// the default screen, and it never carries anything that has not been through
// Redact.
type Row struct {
	Name     string            `json:"name"`
	State    RowState          `json:"state"`
	Severity Severity          `json:"severity"`
	Detail   string            `json:"detail"`
	Remedy   string            `json:"remedy,omitempty"`
	Wide     map[string]string `json:"wide,omitempty"`
	// Alert is the structured cause, evidence, fix steps and docs page of a
	// row that needs attention: present on every row NeedsAlert accepts, and
	// on no other. Detail and Remedy carry the same facts for older readers.
	Alert *Alert `json:"alert,omitempty"`
}

// PeerStatus is one mesh peer's line. The multi-node mesh does not report here
// yet, so Report.Peers is always empty; the field exists so the JSON shape a
// consumer parses today is the shape it parses when peers arrive. The cluster's
// other nodes and their versions are Report.Workers, not peers: a mesh peer is
// a tunnel with a state, a worker is a Node with a version.
type PeerStatus struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// Report is the whole answer: one verdict, one summary sentence, a row per
// subsystem, the ordered next commands, and the provenance of the binary that
// produced it. The JSON encoding of this struct is the machine interface of
// `k3sm status -o json`; the text screen is rendered FROM it and never the
// other way round, so the two can never disagree.
type Report struct {
	// SchemaVersion is the version of this JSON contract (SchemaVersion, the
	// constant). Collect sets it; it is never stamped on at the render layer.
	SchemaVersion int `json:"schemaVersion"`
	// Capabilities lists the optional modes this binary's `k3sm status`
	// offers (Capabilities, the function), so a consumer can tell from one
	// report whether a mode is there instead of trying it and reading the
	// error. Collect sets it. An added word is an additive change; a reader
	// ignores a word it does not know.
	Capabilities []string `json:"capabilities"`
	Verdict      Verdict  `json:"verdict"`
	// Role is which node this Mac is installed as, decided from the two
	// node-daemon plists on disk (dataroot.RoleFromPlists). It picks the rows
	// the screens render and the daemon the verdict is about, so it is part of
	// the machine interface rather than a decoration.
	Role    dataroot.Role `json:"role"`
	Summary string        `json:"summary"`
	Rows    []Row         `json:"rows"`
	Next    []string      `json:"next,omitempty"`
	Peers   []PeerStatus  `json:"peers,omitempty"`
	// Interconnect is the cluster's interconnect and the pods attached to it,
	// present only when the cluster has one this report could read (the
	// interconnect row carries the same facts as a sentence).
	Interconnect *Interconnect `json:"interconnect,omitempty"`
	// StoppedBy is who stopped k3sm on this Mac, present only while a readable
	// stop marker exists. It adds no verdict or state word.
	StoppedBy *StoppedBy `json:"stoppedBy,omitempty"`
	// Network is this node's LAN access switch, present on an installed Mac
	// whose report wired the record reader; an unusable record is present
	// and marked (Network.RecordState). Absent means not installed, or a k3sm
	// older than the switch. It adds no verdict or state word.
	Network *Network `json:"network,omitempty"`
	// Workers is, on a server, every other node of the cluster with the
	// version its kubelet reports, read from the same node list the node row
	// uses. Absent (nil) means unknown: an agent, an apiserver that did not
	// answer, or a failed read. Present and empty means the read succeeded and
	// there are no other nodes. It adds no verdict or state word.
	Workers *[]Worker `json:"workers,omitempty"`
	// JoinTarget is, on an agent, the bootstrap endpoint (host:port) of the
	// server this Mac was installed to join. Empty when it cannot be read.
	JoinTarget string `json:"joinTarget,omitempty"`
	// ImageMigration is the image migration row (ImageMigrationRow), for the
	// text screen only. It is deliberately not in Rows and not in the JSON
	// encoding: the -o json contract is unchanged, and the verdict and the
	// Next block never turn on a copy that loses nothing while it is pending.
	ImageMigration *Row         `json:"-"`
	Version        version.Info `json:"version"`
	Host           string       `json:"host"`
	Timestamp      time.Time    `json:"timestamp"`
}

// CapabilityWatchJSON is the capability word for the NDJSON stream: on a
// stdout that is not a terminal, `k3sm status --watch -o json` writes one
// frame per change instead of refusing.
const CapabilityWatchJSON = "watch-json"

// Capabilities returns the capability words a report carries, in a fresh
// slice so no caller can change another's.
func Capabilities() []string { return []string{CapabilityWatchJSON} }

// Row returns the named row and whether it was present.
func (r Report) Row(name string) (Row, bool) {
	for _, row := range r.Rows {
		if row.Name == name {
			return row, true
		}
	}
	return Row{}, false
}

// Style is the rendering posture: colour and glyphs are decoration a caller
// enables only for a real terminal, and Wide adds the extra columns. The zero
// Style is the plain, pipe-safe screen — which is also what the goldens pin.
type Style struct {
	Color  bool
	Glyphs bool
	Wide   bool
}
