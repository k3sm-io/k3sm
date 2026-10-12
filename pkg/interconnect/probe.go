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

package interconnect

import (
	"context"
	"net/netip"
	"time"

	"k3sm.io/darwin-net/pkg/mesh"
)

// ProbeInterval is how often each peer's slot-0 address is probed; the
// darwin-net prober owns the cadence and the three-miss rule.
const ProbeInterval = mesh.ProbeInterval

// interconnectIface is the interface every interconnect address lives on. It is
// the prober's target key only; the echo itself is routed by destination.
const interconnectIface = "bridge0"

// PeerProbe is one peer's liveness as the probe sees it.
type PeerProbe struct {
	// Alive reports whether the peer answers.
	Alive bool
	// RTT is the last answered probe's round trip when the probe measures one
	// (darwin-net's prober does not; it reads zero). It is diagnostic only and
	// never enters a report, so an RTT change never causes a write.
	RTT time.Duration
}

// Liveness is the reporter's probe seam: the set of addresses to probe and
// their current verdicts.
type Liveness interface {
	// SetTargets replaces the probed set. A target that stays keeps its state;
	// a new one starts unreachable.
	SetTargets(targets []netip.Addr)
	// Probe returns addr's current verdict.
	Probe(addr netip.Addr) PeerProbe
}

// MeshLiveness is the node's Liveness: darwin-net's mesh.Prober (one ICMP echo
// per target every mesh.ProbeInterval, alive from the first answer, unreachable
// after mesh.ProbeMisses misses in a row, a new target unreachable until it
// answers) keyed on bridge0.
type MeshLiveness struct {
	p *mesh.Prober
}

// NewMeshLiveness returns a MeshLiveness that calls onChange (when non-nil,
// outside any lock) on every peer transition.
func NewMeshLiveness(onChange func()) *MeshLiveness {
	return &MeshLiveness{p: mesh.NewProber(func(mesh.ProbeTarget, bool) {
		if onChange != nil {
			onChange()
		}
	})}
}

// SetTargets implements Liveness.
func (l *MeshLiveness) SetTargets(targets []netip.Addr) {
	ts := make([]mesh.ProbeTarget, 0, len(targets))
	for _, a := range targets {
		ts = append(ts, mesh.ProbeTarget{Iface: interconnectIface, Peer: a})
	}
	l.p.SetTargets(ts)
}

// Probe implements Liveness.
func (l *MeshLiveness) Probe(addr netip.Addr) PeerProbe {
	return PeerProbe{Alive: l.p.Alive(interconnectIface, addr)}
}

// Run probes until ctx ends.
func (l *MeshLiveness) Run(ctx context.Context) { l.p.Run(ctx) }
