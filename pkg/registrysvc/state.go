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
	"sync"
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
	// Service is the in-cluster authority the registry is published under
	// (FlatAuthority, "registry-k3sm:6450") when this server publishes the flat
	// Service; empty otherwise.
	Service string `json:"service,omitempty"`
	// TLS is whether the cluster-facing relay serves HTTPS. It is the only way
	// the relay serves; false means no relay is serving at all.
	TLS bool `json:"tls,omitempty"`
	// CertNotAfter is the expiry of the relay's current serving certificate,
	// updated on every rotation; nil when the relay serves no certificate.
	CertNotAfter *time.Time `json:"certNotAfter,omitempty"`
	// GatePort is the loopback push gate's port (GatePort(Port)) once the gate
	// has bound it; 0 when no loopback gate serves. The k3sm CLI on this Mac
	// pushes there.
	GatePort int `json:"gatePort,omitempty"`

	// NodePortError is why the flat Service could not be published with its
	// opt-in NodePort (--registry-node-port), so it stands as a ClusterIP
	// Service only; empty when the NodePort is published or not asked for. The
	// server retries the NodePort on every refresh and clears this on success.
	NodePortError string `json:"nodePortError,omitempty"`
}

// ClusterFacing is what the server's bring-up learns about the registry's
// cluster-facing side after the registry itself is serving: the published
// name and the serving certificate. UpdateClusterFacing writes it into the
// record the Service already wrote.
type ClusterFacing struct {
	// Service is FlatAuthority() when the flat Service is published, else "".
	Service string
	// CertNotAfter is the serving certificate's expiry; zero means the relay
	// serves no certificate (and so does not serve).
	CertNotAfter time.Time
}

// UpdateClusterFacing records f into workDir's state record, keeping every
// other field the Service wrote. It is called after the Service records
// StateServing and before it records StateStopped, never concurrently with
// either, so the read-modify-write cannot lose a transition. A missing record
// is an error: there is no serving registry to describe.
func UpdateClusterFacing(workDir string, f ClusterFacing) error {
	return updateState(workDir, func(st *State) bool {
		st.Service = f.Service
		st.TLS = !f.CertNotAfter.IsZero()
		st.CertNotAfter = nil
		if st.TLS {
			t := f.CertNotAfter.UTC()
			st.CertNotAfter = &t
		}
		return true
	})
}

// UpdateNodePortError records reason as the record's NodePortError, keeping
// every other field: the publish error when the flat Service fell back to
// ClusterIP, or "" once the NodePort is published again. A record that
// already says reason is not rewritten, so a refresh that changes nothing
// writes nothing. The same ordering rule as UpdateClusterFacing applies, and a
// missing record is an error.
func UpdateNodePortError(workDir, reason string) error {
	return updateState(workDir, func(st *State) bool {
		if st.NodePortError == reason {
			return false
		}
		st.NodePortError = reason
		return true
	})
}

// updateState reads workDir's record, applies edit, and writes it back when
// edit reports a change.
func updateState(workDir string, edit func(*State) bool) error {
	stateUpdate.Lock()
	defer stateUpdate.Unlock()
	b, err := os.ReadFile(StatePath(workDir))
	if err != nil {
		return fmt.Errorf("read the registry state: %w", err)
	}
	st, err := ParseState(b)
	if err != nil {
		return err
	}
	if !edit(&st) {
		return nil
	}
	return WriteState(workDir, st)
}

// stateUpdate serialises this process's read-modify-write updates of the
// record: a serving certificate's rotation (from a TLS handshake), the loopback
// gate's bind and the NodePort error from the refresh loop can all land while
// the server runs, and two updates could otherwise each read the record before
// the other wrote it and lose one field.
var stateUpdate sync.Mutex

// RecordGatePort records the loopback push gate's port in workDir's state
// record, keeping every other field. A missing record is an error, as for
// UpdateClusterFacing.
func RecordGatePort(workDir string, port int) error {
	return updateState(workDir, func(st *State) bool {
		st.GatePort = port
		return true
	})
}

// ReadLocalState reads this Mac's registry state record as an ordinary account
// can: the world-readable published copy first, then the work-dir original. A
// Mac that runs no server has neither, and that is fs.ErrNotExist.
func ReadLocalState(workDir string) (State, error) {
	b, err := os.ReadFile(PublishedStatePath(workDir))
	if errors.Is(err, fs.ErrNotExist) {
		b, err = os.ReadFile(StatePath(workDir))
	}
	if err != nil {
		return State{}, fmt.Errorf("read the registry state: %w", err)
	}
	return ParseState(b)
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
