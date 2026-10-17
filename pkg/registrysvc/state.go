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

package registrysvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/internal/atomicfile"
)

// The registry's state record.
//
// Start, Shutdown and the orphan reclaim each log what they did, and a log line
// is the only place those transitions used to be visible: a registry disabled
// after its retries left a cluster that could not ingest an image with nothing
// in `k3sm status` to say so. So every transition is also written here, and
// pkg/status reads this record for its ingest-registry row.
//
// The record is a report, never an input: nothing that starts, stops or
// reclaims the registry reads it back, and a write that fails is logged and
// survived.

// The registry states the record carries.
const (
	// StateServing: the child is up and answered its readiness dial.
	StateServing = "serving"
	// StateDisabled: every bring-up attempt failed; Reason says why.
	StateDisabled = "disabled"
	// StateReclaimed: this start stopped a previous server's orphaned child
	// (ReclaimedPID) before binding. Written when the reclaim happens, and
	// again, in place of StateServing, once the registry serves.
	StateReclaimed = "reclaimed"
	// StateStopped: the server tore the registry down.
	StateStopped = "stopped"
)

// State is the registry's state record. It holds the port and a reason, never
// the push credential or anything derived from it.
type State struct {
	// State is one of the State* constants.
	State string `json:"state"`
	// Port and Addr are the loopback port and host:port the registry serves on.
	Port int    `json:"port"`
	Addr string `json:"addr"`
	// Reason is why the registry was disabled; empty in every other state.
	Reason string `json:"reason,omitempty"`
	// ReclaimedPID is the orphaned child this start reclaimed, or 0.
	ReclaimedPID int `json:"reclaimedPid,omitempty"`
	// Since is when the registry entered State.
	Since time.Time `json:"since"`
}

// stateName is the record's basename. It sits in the work dir beside
// registry.log rather than in StateDir, which is zot's storage root.
const stateName = "registry-state.json"

// statusSubdir is the server's world-readable status directory, a sibling of
// its work dir. It is spelled here rather than imported because pkg/install,
// which owns the name (install.StatusSubdir), imports this package; a pkg/status
// test pins that the two agree.
const statusSubdir = "status"

// StatePath returns the registry's state record for a work dir: the 0600
// original, which only the service user and root can read.
func StatePath(workDir string) string { return filepath.Join(workDir, stateName) }

// PublishedStatePath returns the record's world-readable copy for a work dir, in
// the status directory beside it (/var/lib/k3sm/status on an install), where the
// server publishes every record `k3sm status` reads so an account that cannot
// see inside the 0700 work dir can still report it.
func PublishedStatePath(workDir string) string {
	return filepath.Join(filepath.Dir(workDir), statusSubdir, stateName)
}

// WriteState records st for workDir atomically (a temp file renamed over the
// record): the 0600 original in the work dir, then, when the status directory
// exists, a 0644 copy there. The record holds a state, a port, an address, a
// reason and a pid, never a credential, so the copy is safe to publish; a
// server with no status directory (a hand-run server, an older data root)
// writes the original only.
func WriteState(workDir string, st State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode the registry state: %w", err)
	}
	b = append(b, '\n')
	if err := atomicfile.Replace(StatePath(workDir), b, 0o600); err != nil {
		return fmt.Errorf("write the registry state: %w", err)
	}
	published := PublishedStatePath(workDir)
	if _, err := os.Stat(filepath.Dir(published)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := atomicfile.Replace(published, b, 0o644); err != nil {
		return fmt.Errorf("publish the registry state: %w", err)
	}
	return nil
}

// ParseState decodes a record's bytes.
func ParseState(b []byte) (State, error) {
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("decode the registry state: %w", err)
	}
	return st, nil
}

// record writes this service's state, logging a failure rather than returning
// it: the record reports the registry and is never a reason to change what the
// registry does.
func (s *Service) record(state, reason string, reclaimedPID int) {
	st := State{
		State:        state,
		Port:         s.cfg.Port,
		Addr:         s.Addr(),
		Reason:       reason,
		ReclaimedPID: reclaimedPID,
		Since:        time.Now().UTC(),
	}
	if err := WriteState(s.cfg.WorkDir, st); err != nil {
		s.cfg.Logger.Warn("could not record the ingest registry state for `k3sm status`",
			"path", StatePath(s.cfg.WorkDir), "state", state, "err", err)
	}
}
