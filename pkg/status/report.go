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
	StateUnknown    RowState = "unknown"
	StateHealthy    RowState = "healthy"
	StateUnhealthy  RowState = "unhealthy"
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
}

// PeerStatus is one mesh peer's line. The multi-node mesh does not report here
// yet, so Report.Peers is always empty; the field exists so the JSON shape a
// consumer parses today is the shape it parses when peers arrive.
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
	Verdict   Verdict      `json:"verdict"`
	Summary   string       `json:"summary"`
	Rows      []Row        `json:"rows"`
	Next      []string     `json:"next,omitempty"`
	Peers     []PeerStatus `json:"peers,omitempty"`
	Version   version.Info `json:"version"`
	Host      string       `json:"host"`
	Timestamp time.Time    `json:"timestamp"`
}

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
