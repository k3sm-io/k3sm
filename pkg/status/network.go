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
	"fmt"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// Network is this node's LAN access switch, from the record `k3sm network
// lan` and `k3sm install --lan` write. It is additive and carries no verdict
// or state word.
type Network struct {
	// LAN is "on" (workload listeners answer on every interface) or "off"
	// (only on this Mac and the cluster mesh).
	LAN string `json:"lan"`
	// Covers is the listener families the switch controls on this node.
	Covers []string `json:"covers"`
	// AlwaysOn is the network-facing listeners the switch does not control.
	AlwaysOn []string `json:"alwaysOn"`
}

// network reads the LAN switch through the Network seam on an installed
// Mac. No seam, no install, or an unreadable record yields nil and never
// fails the report.
func (c Collector) network(role dataroot.Role, installed bool) *Network {
	if c.Network == nil || !installed {
		return nil
	}
	rec, _, err := c.Network()
	if err != nil {
		return nil
	}
	return &Network{LAN: string(rec.LAN), Covers: install.LANCovers(role), AlwaysOn: install.LANAlwaysOn(role)}
}

// networkLine is the human view's one line, or "" when the report has none.
func networkLine(r Report) string {
	n := r.Network
	if n == nil {
		return ""
	}
	return fmt.Sprintf("LAN access %s (%s); always on: %s", n.LAN, strings.Join(n.Covers, ", "), strings.Join(n.AlwaysOn, ", "))
}
