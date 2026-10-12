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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
)

// DiscoverInterval is how often the reporter re-reads the local Thunderbolt
// ports (system_profiler is slow) and re-lists the peers' addresses.
const DiscoverInterval = 30 * time.Second

// ReasonHelperTooOld is the reason a node carries when its root helper predates
// the interconnect verbs. Such a node reports no interconnect (the deploy
// contract: an old helper is never asked, and the node is never a member).
const ReasonHelperTooOld = "HelperTooOld"

// LocalLinks is what discovery reports about this node's Thunderbolt ports.
type LocalLinks struct {
	// LocalDomainUUIDs are the domain UUIDs of this node's own ports.
	LocalDomainUUIDs []string
	// PeerDomainUUIDs are the domain UUIDs seen across this node's connected
	// ports, one entry per port (a repeat is a loop signal the server reads).
	PeerDomainUUIDs []string
	// Carrier reports whether any port has a peer.
	Carrier bool
	// SpeedGbps is the fastest connected port's speed (0 = unknown).
	SpeedGbps int32
}

// Discovery is the reporter's link-discovery seam.
type Discovery interface {
	Discover(ctx context.Context) (LocalLinks, error)
}

// LinkenumDiscovery adapts darwin-net's linkenum.Enumerator.
type LinkenumDiscovery struct {
	Enum linkenum.Enumerator
}

// Discover implements Discovery.
func (d LinkenumDiscovery) Discover(ctx context.Context) (LocalLinks, error) {
	ports, err := d.Enum.Ports(ctx)
	if err != nil {
		return LocalLinks{}, fmt.Errorf("enumerate thunderbolt ports: %w", err)
	}
	return linksFromPorts(ports), nil
}

// linksFromPorts folds enumerated ports into LocalLinks.
func linksFromPorts(ports []linkenum.Port) LocalLinks {
	var l LocalLinks
	for _, p := range ports {
		if p.DomainUUID != "" {
			l.LocalDomainUUIDs = append(l.LocalDomainUUIDs, p.DomainUUID)
		}
		if p.PeerDomainUUID != "" {
			l.Carrier = true
			l.PeerDomainUUIDs = append(l.PeerDomainUUIDs, p.PeerDomainUUID)
			l.SpeedGbps = max(l.SpeedGbps, int32(p.SpeedGbps))
		}
	}
	return l
}

// PeerSource returns every other node's slot-0 interconnect address, keyed by
// node name. A node without one (no index, or an index beyond the ceiling) is
// absent.
type PeerSource func(ctx context.Context) (map[string]netip.Addr, error)

// Annotator reads and writes one annotation on this node's own Node object.
type Annotator interface {
	// Current returns the annotation's value as the node cache holds it; ok is
	// false while the cache has not synced. An absent annotation is "", true.
	Current() (value string, ok bool)
	// Set writes value, or deletes the annotation when value is "".
	Set(ctx context.Context, value string) error
}

// EventSink records a Warning Event on this node's Node object.
type EventSink func(reason, message string)

// ReporterConfig is the node reporter's wiring.
type ReporterConfig struct {
	// Node is this node's name.
	Node string
	// Discovery reads the local ports.
	Discovery Discovery
	// Peers lists the other nodes' slot-0 addresses.
	Peers PeerSource
	// Liveness probes them.
	Liveness Liveness
	// Annotation is this node's k3sm.io/interconnect-report annotation.
	Annotation Annotator
	// Events records the helper reason; nil records none.
	Events EventSink
	// Metrics receives the per-peer probe gauge; nil records none.
	Metrics *Metrics
	// Log is the logger; nil uses slog.Default.
	Log *slog.Logger
	// MinInterval is the write rate limit; zero means
	// netv1alpha1.InterconnectReportMinInterval.
	MinInterval time.Duration
}

// Reporter writes this node's interconnect report on its own Node, only when
// the report changes, and at most once per MinInterval. The rate limit is
// trailing-edge: a change inside the window is held, and the report current
// when the window ends is written then, never dropped.
//
// Locking discipline: mu guards every field below it; no I/O runs under it
// except the annotation write in Sync, which is serialized on purpose.
type Reporter struct {
	cfg ReporterConfig

	mu          sync.Mutex
	links       LocalLinks
	discovered  bool
	peers       map[string]netip.Addr
	reason      string
	lastWrite   time.Time
	lastWritten string
	written     bool
	nudge       chan struct{}
}

// NewReporter returns a Reporter.
func NewReporter(cfg ReporterConfig) *Reporter {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MinInterval <= 0 {
		cfg.MinInterval = netv1alpha1.InterconnectReportMinInterval
	}
	return &Reporter{cfg: cfg, nudge: make(chan struct{}, 1)}
}

// Nudge asks Run for a Sync now (after a probe round or a reason change). It
// never blocks.
func (r *Reporter) Nudge() {
	select {
	case r.nudge <- struct{}{}:
	default:
	}
}

// SetHelperReason records the root helper's last interconnect verdict ("" for
// success). A change is a Warning Event on the Node and a Warn line. The
// report has no field for it (the apis schema 1 shape), so HelperTooOld is
// carried the way the deploy contract states it: the node withdraws its
// report. Every other reason rides the Event.
func (r *Reporter) SetHelperReason(reason string) {
	r.mu.Lock()
	changed := reason != r.reason
	r.reason = reason
	r.mu.Unlock()
	if !changed {
		return
	}
	if reason != "" {
		r.cfg.Log.Warn("interconnect: the root helper refused the node's interconnect alias", "node", r.cfg.Node, "reason", reason)
		if r.cfg.Events != nil {
			r.cfg.Events(reason, "the root helper refused this node's interconnect alias: "+reason)
		}
	}
	r.Nudge()
}

// HelperReason returns the last recorded helper reason.
func (r *Reporter) HelperReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reason
}

// Refresh re-reads the local ports and, when a cable has a peer, the peers'
// addresses, and points the probe at them.
func (r *Reporter) Refresh(ctx context.Context) error {
	links, err := r.cfg.Discovery.Discover(ctx)
	if err != nil {
		return err
	}
	var peers map[string]netip.Addr
	if links.Carrier && r.cfg.Peers != nil {
		peers, err = r.cfg.Peers(ctx)
		if err != nil {
			return fmt.Errorf("list interconnect peers: %w", err)
		}
		delete(peers, r.cfg.Node)
	}
	targets := make([]netip.Addr, 0, len(peers))
	for _, a := range peers {
		targets = append(targets, a)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Less(targets[j]) })
	r.cfg.Liveness.SetTargets(targets)
	r.mu.Lock()
	r.links, r.peers, r.discovered = links, peers, true
	r.mu.Unlock()
	return nil
}

// Report builds the annotation value from the last discovery and the current
// probe verdicts: "" means no report (no Thunderbolt port, or a helper too old
// to be asked).
func (r *Reporter) Report() (string, error) {
	r.mu.Lock()
	links, peers, reason, discovered := r.links, r.peers, r.reason, r.discovered
	r.mu.Unlock()
	if !discovered || len(links.LocalDomainUUIDs) == 0 || reason == ReasonHelperTooOld {
		return "", nil
	}
	rep := netv1alpha1.InterconnectReport{
		Schema:           netv1alpha1.InterconnectAnnotationSchema,
		LocalDomainUUIDs: boundedUUIDs(dedup(links.LocalDomainUUIDs), netv1alpha1.MaxInterconnectSlot+1),
		PeerDomainUUIDs:  boundedUUIDs(links.PeerDomainUUIDs, netv1alpha1.MaxInterconnectReportPeers),
		Carrier:          links.Carrier,
		SpeedGbps:        max(links.SpeedGbps, 0),
	}
	alive := map[string]bool{}
	if links.Carrier {
		for name, a := range peers {
			ok := r.cfg.Liveness.Probe(a).Alive
			alive[name] = ok
			if ok {
				rep.ReachablePeers = append(rep.ReachablePeers, name)
			}
		}
		sort.Strings(rep.ReachablePeers)
		if len(rep.ReachablePeers) > netv1alpha1.MaxInterconnectReportPeers {
			rep.ReachablePeers = rep.ReachablePeers[:netv1alpha1.MaxInterconnectReportPeers]
		}
	}
	r.cfg.Metrics.SetProbes(alive)
	return rep.Encode()
}

// Sync writes the current report if it differs from what the Node carries
// and the rate limit allows. It returns when the held change may be written
// (zero when nothing is held).
func (r *Reporter) Sync(ctx context.Context, now time.Time) (time.Time, error) {
	want, err := r.Report()
	if err != nil {
		return time.Time{}, fmt.Errorf("build the interconnect report: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, known := r.cfg.Annotation.Current()
	if !known {
		if !r.written {
			// The node cache has not synced: an unknown current value is not
			// "absent", and a delete on it would be a guess.
			return time.Time{}, nil
		}
		cur = r.lastWritten
	}
	if cur == want {
		return time.Time{}, nil
	}
	if r.written && now.Before(r.lastWrite.Add(r.cfg.MinInterval)) {
		return r.lastWrite.Add(r.cfg.MinInterval), nil
	}
	if err := r.cfg.Annotation.Set(ctx, want); err != nil {
		return time.Time{}, fmt.Errorf("write the interconnect report on node %s: %w", r.cfg.Node, err)
	}
	r.lastWrite, r.lastWritten, r.written = now, want, true
	return time.Time{}, nil
}

// Run discovers every DiscoverInterval, syncs on every Nudge and every
// ProbeInterval, and flushes a held change when its window ends, until ctx ends.
func (r *Reporter) Run(ctx context.Context) {
	var lastErr string
	logOnce := func(err error) {
		if err == nil {
			lastErr = ""
			return
		}
		if msg := err.Error(); msg != lastErr {
			lastErr = msg
			r.cfg.Log.Warn("interconnect reporter", "node", r.cfg.Node, "err", err)
		}
	}
	discover := time.NewTicker(DiscoverInterval)
	defer discover.Stop()
	tick := time.NewTicker(ProbeInterval)
	defer tick.Stop()
	var flush *time.Timer
	var flushC <-chan time.Time
	logOnce(r.Refresh(ctx))
	for {
		next, err := r.Sync(ctx, time.Now())
		if err != nil && !errors.Is(err, context.Canceled) {
			logOnce(err)
		}
		if !next.IsZero() && flush == nil {
			flush = time.NewTimer(time.Until(next))
			flushC = flush.C
		}
		select {
		case <-ctx.Done():
			if flush != nil {
				flush.Stop()
			}
			return
		case <-discover.C:
			logOnce(r.Refresh(ctx))
		case <-tick.C:
		case <-r.nudge:
		case <-flushC:
			flush, flushC = nil, nil
		}
	}
}

// dedup returns the distinct values of in, sorted.
func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// boundedUUIDs keeps the values the apis report validation accepts (1..64
// printable ASCII bytes), sorted, at most n of them. Repeats are kept: a peer
// domain seen on two ports is a loop signal.
func boundedUUIDs(in []string, n int) []string {
	var out []string
	for _, s := range in {
		if validUUID(s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func validUUID(s string) bool {
	if len(s) == 0 || len(s) > netv1alpha1.MaxInterconnectDomainUUIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
