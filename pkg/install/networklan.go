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

package install

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/version"
)

// LAN is the one switch for whether this node's workload listeners answer on
// the networks the Mac is attached to: LANOn binds them on every interface,
// LANOff only on this Mac (loopback) and the node's own address (its mesh
// address when joined). It covers the NodePort, LoadBalancer and ingress
// listeners (LANCovers); the apiserver, the worker join port and the
// wireguard mesh port never follow it (LANAlwaysOn).
type LAN string

// The two LAN values.
const (
	LANOn  LAN = "on"
	LANOff LAN = "off"
)

// The listener families the LAN switch controls, as `k3sm status` and the
// network verb name them.
const (
	LANFamilyNodePorts     = "nodeports"
	LANFamilyLoadBalancers = "loadbalancers"
	LANFamilyIngress       = "ingress"
)

// The listeners that face the network whatever the switch says.
const (
	ListenerAPIServer = "apiserver"
	ListenerJoin      = "join"
	ListenerMesh      = "mesh"
)

// LANCovers is the families the switch controls on a node of role: every
// node runs NodePort and LoadBalancer listeners; only a server hosts the
// ingress.
func LANCovers(role Role) []string {
	if role == RoleAgent {
		return []string{LANFamilyNodePorts, LANFamilyLoadBalancers}
	}
	return []string{LANFamilyNodePorts, LANFamilyLoadBalancers, LANFamilyIngress}
}

// LANAlwaysOn is the network-facing listeners the switch does not control on
// a node of role. The worker join port stays reachable because a new worker
// joins over the LAN before it has a mesh (every request needs the join
// token); the apiserver is reached over the mesh or loopback.
func LANAlwaysOn(role Role) []string {
	if role == RoleAgent {
		return []string{ListenerMesh}
	}
	return []string{ListenerAPIServer, ListenerJoin, ListenerMesh}
}

// ErrNetworkRecord is the named refusal of a network record that cannot be
// used: a value other than on or off, an unknown schema version, or bytes
// that do not decode.
var ErrNetworkRecord = errors.New("invalid network record")

// ParseLAN parses an on/off value (surrounding spaces and case ignored).
func ParseLAN(s string) (LAN, error) {
	switch LAN(strings.ToLower(strings.TrimSpace(s))) {
	case LANOn:
		return LANOn, nil
	case LANOff:
		return LANOff, nil
	}
	return "", fmt.Errorf("%w: LAN access is %q, want on or off", ErrNetworkRecord, s)
}

// NetworkRecordVersion is the schema version EncodeNetworkRecord stamps and
// DecodeNetworkRecord accepts; a record from a newer k3sm is refused rather
// than guessed at.
const NetworkRecordVersion = 1

// DefaultNetworkRecordPath is where the LAN switch is recorded: beside the
// arguments records in root-owned /Library/Preferences, so only root can
// change it, but 0644 rather than their 0600, because the unprivileged node
// daemon reads it at start and on SIGHUP, and `k3sm status` reads it as the
// user. It carries no secret.
//
// It is a var only so tests can point it at a fixture.
var DefaultNetworkRecordPath = "/Library/Preferences/io.k3sm.network.json"

// networkRecordMode is the record's mode: root-owned, world-readable.
const networkRecordMode fs.FileMode = 0o644

// NetworkRecord is the recorded LAN switch.
type NetworkRecord struct {
	// Version is the schema version; always NetworkRecordVersion on write.
	Version int `json:"version"`
	// LAN is on or off.
	LAN LAN `json:"lan"`
	// Serial changes on every write, so a daemon's applied report can name the
	// write it applied (NetworkApplied.Serial).
	Serial string `json:"serial"`
	// UpdatedBy is the k3sm build and verb that wrote the record.
	UpdatedBy string `json:"updatedBy"`
	// UpdatedAt is when it was written.
	UpdatedAt time.Time `json:"updatedAt"`
}

// NewNetworkRecord returns a record of lan with a fresh serial, stamped by
// verb (for example "k3sm install").
func NewNetworkRecord(lan LAN, verb string) NetworkRecord {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	return NetworkRecord{
		Version:   NetworkRecordVersion,
		LAN:       lan,
		Serial:    hex.EncodeToString(b[:]),
		UpdatedBy: strings.TrimSpace(verb + " " + version.Get().Version),
		UpdatedAt: time.Now().UTC(),
	}
}

// EncodeNetworkRecord returns the bytes a record is written as.
func EncodeNetworkRecord(r NetworkRecord) ([]byte, error) {
	r.Version = NetworkRecordVersion
	if _, err := ParseLAN(string(r.LAN)); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode the network record: %w", err)
	}
	return append(data, '\n'), nil
}

// DecodeNetworkRecord parses a record, refusing an unknown version or value
// with ErrNetworkRecord.
func DecodeNetworkRecord(data []byte) (NetworkRecord, error) {
	var r NetworkRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&r); err != nil {
		return NetworkRecord{}, fmt.Errorf("%w: %v", ErrNetworkRecord, err)
	}
	if r.Version != NetworkRecordVersion {
		return NetworkRecord{}, fmt.Errorf("%w: unknown version %d, this k3sm understands %d", ErrNetworkRecord, r.Version, NetworkRecordVersion)
	}
	lan, err := ParseLAN(string(r.LAN))
	if err != nil {
		return NetworkRecord{}, err
	}
	r.LAN = lan
	return r, nil
}

// ReadNetworkRecord reads the record at path through read. A missing record
// is (record of LANOn, false, nil): a node installed before the switch
// existed served every interface, and keeps doing so until someone decides
// otherwise. Any other read failure or an unusable record is an error.
func ReadNetworkRecord(read func(string) ([]byte, error), path string) (NetworkRecord, bool, error) {
	data, err := read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return NetworkRecord{Version: NetworkRecordVersion, LAN: LANOn}, false, nil
	}
	if err != nil {
		return NetworkRecord{}, false, fmt.Errorf("read the network record %s: %w", path, err)
	}
	r, err := DecodeNetworkRecord(data)
	if err != nil {
		return NetworkRecord{}, true, fmt.Errorf("network record %s: %w", path, err)
	}
	return r, true, nil
}

// WriteNetworkRecord writes r at path, atomically (temp file and rename),
// root-owned and 0644, through the root-only write seam.
func WriteNetworkRecord(sys System, path string, r NetworkRecord) error {
	data, err := EncodeNetworkRecord(r)
	if err != nil {
		return err
	}
	if err := sys.WriteRootOnlyFile(path, data, networkRecordMode); err != nil {
		return fmt.Errorf("write the network record %s: %w", path, err)
	}
	return nil
}

// NetworkAppliedName is the file a node daemon writes in its work dir after
// it has applied (or failed to apply) the network record.
const NetworkAppliedName = "network-applied.json"

// NetworkAppliedPath is that file for the node daemon of role under dataRoot
// (empty takes DefaultDataRoot).
func NetworkAppliedPath(dataRoot string, role Role) string {
	cfg := Config{DataRoot: dataRoot}
	if cfg.DataRoot == "" {
		cfg.DataRoot = DefaultDataRoot
	}
	if role == RoleAgent {
		return filepath.Join(cfg.agentWorkDir(), NetworkAppliedName)
	}
	return filepath.Join(cfg.serverWorkDir(), NetworkAppliedName)
}

// NetworkApplied is the node daemon's report of the LAN state it serves.
type NetworkApplied struct {
	// LAN is the state the listeners are in now.
	LAN LAN `json:"lan"`
	// Serial is the serial of the record the daemon last acted on.
	Serial string `json:"serial"`
	// Error is why the record's value could not be applied; empty on success.
	// On an error LAN is still the previous state, which stays in force.
	Error string `json:"error,omitempty"`
	// At is when the daemon wrote this report.
	At time.Time `json:"at"`
}

// DecodeNetworkApplied parses a daemon's applied report.
func DecodeNetworkApplied(data []byte) (NetworkApplied, error) {
	var a NetworkApplied
	if err := json.Unmarshal(data, &a); err != nil {
		return NetworkApplied{}, fmt.Errorf("decode the network applied report: %w", err)
	}
	return a, nil
}

// DecideInstallLAN is the value an install records, and whether it has to
// write it: the explicit --lan when given; otherwise the recorded one (no
// write); otherwise on for a Mac that already ran k3sm (prior: a node plist
// or work dir was there before this install, so an upgrade keeps serving what
// it served), and off for a new install.
func DecideInstallLAN(explicit *LAN, recorded bool, current LAN, prior bool) (lan LAN, write bool) {
	switch {
	case explicit != nil:
		return *explicit, true
	case recorded:
		return current, false
	case prior:
		return LANOn, true
	}
	return LANOff, true
}

// priorInstall reports whether this Mac already ran k3sm before this install:
// a node daemon plist of either role, or a node work dir, is on disk. It is
// read before anything is written.
func priorInstall(sys System, cfg Config) (bool, error) {
	for _, p := range []string{cfg.plistPath(ServerLabel), cfg.plistPath(AgentLabel), cfg.serverWorkDir(), cfg.agentWorkDir()} {
		ok, err := sys.PathExists(p)
		if err != nil {
			return false, fmt.Errorf("install: check for an earlier install at %s: %w", p, err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// writeInstallNetworkRecord records the LAN switch for this install (see
// DecideInstallLAN). An unusable record on disk is refused with
// ErrNetworkRecord unless --lan replaces it.
func writeInstallNetworkRecord(sys System, cfg Config, prior bool) error {
	rec, present, err := ReadNetworkRecord(sys.ReadFile, cfg.NetworkRecord)
	if err != nil && cfg.LAN == nil {
		return fmt.Errorf("install: %w (pass --lan on or --lan off to replace it)", err)
	}
	lan, write := DecideInstallLAN(cfg.LAN, present && err == nil, rec.LAN, prior)
	if !write {
		cfg.Logger.Info("LAN access kept as recorded", "lan", string(lan), "record", cfg.NetworkRecord)
		return nil
	}
	if err := WriteNetworkRecord(sys, cfg.NetworkRecord, NewNetworkRecord(lan, "k3sm install")); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	cfg.Logger.Info("LAN access recorded", "lan", string(lan), "record", cfg.NetworkRecord, "explicit", cfg.LAN != nil, "earlier_install", prior)
	return nil
}
