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
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// Network is this node's LAN access switch, from the record `k3sm network
// lan` and `k3sm install --lan` write, and, when the caller can read it, the
// state the node daemon reports applying. It is additive and carries no
// verdict or state word.
type Network struct {
	// LAN is the RECORDED setting: "on" (workload listeners answer on every
	// interface) or "off" (only on this Mac and the cluster mesh). When the
	// record exists but cannot be used it is "off", which is what the node
	// daemon serves in that case.
	LAN string `json:"lan"`
	// Recorded is false when no setting is recorded (an install from before
	// the switch), which reads as on.
	Recorded bool `json:"recorded"`
	// RecordState is NetworkRecordUnreadable when a record exists but could
	// not be used (refused or undecodable); empty, and omitted, otherwise.
	// It carries no error text: the reason names paths and uids.
	RecordState string `json:"recordState,omitempty"`
	// Covers is the listener families the switch controls on this node.
	Covers []string `json:"covers"`
	// AlwaysOn is the network-facing listeners the switch does not control.
	AlwaysOn []string `json:"alwaysOn"`
	// Applied is the node daemon's own report of what it serves, present
	// only when this caller could read it (root).
	Applied *NetworkApplied `json:"applied,omitempty"`
	// AppliedReadable is false when the daemon's report exists but this
	// caller may not read it; nil, and omitted, otherwise (read, absent, or
	// not looked at, as in the daemons probe).
	AppliedReadable *bool `json:"appliedReadable,omitempty"`
}

// NetworkRecordUnreadable is Network.RecordState for a LAN record that exists
// but could not be used.
const NetworkRecordUnreadable = "unreadable"

// NetworkApplied is the node daemon's report of the LAN state it applied.
type NetworkApplied struct {
	LAN    string `json:"lan"`
	Serial string `json:"serial"`
	Error  string `json:"error,omitempty"`
}

// network reads the LAN switch through the Network seam on an installed
// Mac, and the daemon's report through NetworkApplied when wired. No seam or
// no install yields nil. A record that exists but cannot be used is reported
// as the node daemon treats it: off, recorded, and marked unreadable. It never
// fails the report.
func (c Collector) network(role dataroot.Role, installed bool) *Network {
	if c.Network == nil || !installed {
		return nil
	}
	n := &Network{Covers: install.LANCovers(role), AlwaysOn: install.LANAlwaysOn(role)}
	if rec, present, err := c.Network(); err != nil {
		n.LAN, n.Recorded, n.RecordState = string(install.LANOff), true, NetworkRecordUnreadable
	} else {
		n.LAN, n.Recorded = string(rec.LAN), present
	}
	if c.NetworkApplied != nil {
		data, err := c.NetworkApplied(role)
		switch {
		case err == nil:
			if a, derr := install.DecodeNetworkApplied(data); derr == nil {
				n.Applied = &NetworkApplied{LAN: string(a.LAN), Serial: a.Serial, Error: a.Error}
			}
		case errors.Is(err, fs.ErrPermission):
			unreadable := false
			n.AppliedReadable = &unreadable
		}
	}
	return n
}

// networkLine is the human view's line(s), or "" when the report has none.
func networkLine(r Report) string {
	n := r.Network
	if n == nil {
		return ""
	}
	line := fmt.Sprintf("LAN access %s (%s); always on: %s", n.LAN, strings.Join(n.Covers, ", "), strings.Join(n.AlwaysOn, ", "))
	switch {
	case n.RecordState == NetworkRecordUnreadable:
		line += "\nthe LAN access record cannot be used, so the node daemon serves LAN access off until it is fixed (sudo k3sm network lan on|off)"
	case !n.Recorded:
		line += "\nLAN access is on because no setting is recorded (an install from before the switch)"
	}
	switch {
	case n.Applied != nil && n.Applied.Error != "":
		line += fmt.Sprintf("\nthe node daemon serves LAN access %s; its last change was refused: %s", n.Applied.LAN, n.Applied.Error)
	case n.Applied != nil && n.Applied.LAN != n.LAN:
		line += fmt.Sprintf("\nthe node daemon still serves LAN access %s, not the recorded %s", n.Applied.LAN, n.LAN)
	case n.AppliedReadable != nil && !*n.AppliedReadable:
		line += "\nthe applied state is readable by root only (sudo k3sm network lan status)"
	}
	return line
}
