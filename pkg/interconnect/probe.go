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
	"fmt"
	"net/netip"
	"os/exec"
	"sync"
	"time"
)

const (
	// ProbeInterval is how often each peer's slot-0 address is probed.
	ProbeInterval = 5 * time.Second
	// ProbeMisses is how many unanswered probes in a row declare a peer
	// unreachable (15 s at ProbeInterval).
	ProbeMisses = 3
	// probeTimeout bounds one echo's wait for its reply.
	probeTimeout = 2 * time.Second
)

// PeerProbe is one peer's liveness as the probe sees it.
type PeerProbe struct {
	// Alive reports whether the peer answers.
	Alive bool
	// RTT is the last answered probe's round trip. It is diagnostic only and
	// never enters a report, so an RTT change never causes a write.
	RTT time.Duration
}

// Liveness is the reporter's probe seam: the set of addresses to probe and
// their current verdicts. darwin-net's mesh.Prober has the same shape and can
// stand behind it once it is constructible from this module.
type Liveness interface {
	// SetTargets replaces the probed set. A target that stays keeps its state;
	// a new one starts unreachable.
	SetTargets(targets []netip.Addr)
	// Probe returns addr's current verdict.
	Probe(addr netip.Addr) PeerProbe
}

// Pinger sends one echo to dst and waits for its reply.
type Pinger interface {
	Ping(ctx context.Context, dst netip.Addr, timeout time.Duration) error
}

// Prober is the Liveness the node runs: one echo per target every
// ProbeInterval, alive from the first answered echo, unreachable after
// ProbeMisses unanswered ones in a row. A new target starts unreachable, so a
// peer counts only once it has answered over the cable.
//
// Locking discipline: mu guards targets; Ping runs without it.
type Prober struct {
	ping Pinger

	mu      sync.Mutex
	targets map[netip.Addr]*probeState
}

type probeState struct {
	alive  bool
	misses int
	rtt    time.Duration
}

// NewProber returns a Prober over ping (nil: ExecPinger).
func NewProber(ping Pinger) *Prober {
	if ping == nil {
		ping = ExecPinger{}
	}
	return &Prober{ping: ping, targets: map[netip.Addr]*probeState{}}
}

// SetTargets implements Liveness.
func (p *Prober) SetTargets(targets []netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := make(map[netip.Addr]*probeState, len(targets))
	for _, t := range targets {
		if st, ok := p.targets[t]; ok {
			next[t] = st
			continue
		}
		next[t] = &probeState{}
	}
	p.targets = next
}

// Probe implements Liveness.
func (p *Prober) Probe(addr netip.Addr) PeerProbe {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.targets[addr]
	if !ok {
		return PeerProbe{}
	}
	return PeerProbe{Alive: st.alive, RTT: st.rtt}
}

// Round probes every target once, concurrently, and folds in the results.
func (p *Prober) Round(ctx context.Context) {
	p.mu.Lock()
	targets := make([]netip.Addr, 0, len(p.targets))
	for t := range p.targets {
		targets = append(targets, t)
	}
	p.mu.Unlock()

	type result struct {
		addr netip.Addr
		err  error
		rtt  time.Duration
	}
	results := make(chan result, len(targets))
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := p.ping.Ping(ctx, t, probeTimeout)
			results <- result{addr: t, err: err, rtt: time.Since(start)}
		}()
	}
	wg.Wait()
	close(results)

	p.mu.Lock()
	defer p.mu.Unlock()
	for r := range results {
		st, ok := p.targets[r.addr]
		if !ok {
			continue
		}
		if r.err == nil {
			st.alive, st.misses, st.rtt = true, 0, r.rtt
			continue
		}
		st.misses++
		if st.misses >= ProbeMisses {
			st.alive = false
		}
	}
}

// Run probes every target once per ProbeInterval until ctx ends, calling
// after (when non-nil) after each round.
func (p *Prober) Run(ctx context.Context, after func()) {
	t := time.NewTicker(ProbeInterval)
	defer t.Stop()
	for {
		p.Round(ctx)
		if after != nil {
			after()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ExecPinger pings with the system ping(8), which needs no privilege. It is
// the node's production Pinger.
type ExecPinger struct{}

// pingPath is the system ping binary.
const pingPath = "/sbin/ping"

// Ping implements Pinger with one echo and a whole-second wait.
func (ExecPinger) Ping(ctx context.Context, dst netip.Addr, timeout time.Duration) error {
	if !dst.Is4() {
		return fmt.Errorf("ping %s: not an IPv4 address", dst)
	}
	secs := max(int(timeout/time.Second), 1)
	ctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	// -n numeric, -q quiet, -c 1 one echo, -t the whole wait in seconds.
	cmd := exec.CommandContext(ctx, pingPath, "-n", "-q", "-c", "1", "-t", fmt.Sprint(secs), dst.String())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ping %s: %w", dst, err)
	}
	return nil
}
