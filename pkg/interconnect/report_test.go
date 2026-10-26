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
	"log/slog"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
)

// fakeDiscovery returns links.
type fakeDiscovery struct{ links LocalLinks }

func (d *fakeDiscovery) Discover(context.Context) (LocalLinks, error) { return d.links, nil }

// fakeLiveness answers from a map and records the targets.
type fakeLiveness struct {
	mu      sync.Mutex
	probes  map[netip.Addr]PeerProbe
	targets []netip.Addr
}

func (l *fakeLiveness) SetTargets(t []netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.targets = t
}

func (l *fakeLiveness) Probe(a netip.Addr) PeerProbe {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.probes[a]
}

func (l *fakeLiveness) set(a netip.Addr, p PeerProbe) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.probes[a] = p
}

// fakeAnnotation is a node annotation the cache reflects at once.
type fakeAnnotation struct {
	value  string
	synced bool
	writes []string
}

func (a *fakeAnnotation) Current() (string, bool) { return a.value, a.synced }

func (a *fakeAnnotation) Set(_ context.Context, v string) error {
	a.value = v
	a.writes = append(a.writes, v)
	return nil
}

var (
	addrB = netip.MustParseAddr("169.254.0.9")
	addrC = netip.MustParseAddr("169.254.0.17")
)

func newTestReporter(t *testing.T) (*Reporter, *fakeLiveness, *fakeAnnotation, *fakeDiscovery) {
	t.Helper()
	disc := &fakeDiscovery{links: LocalLinks{
		LocalDomainUUIDs: []string{"A1", "A2"},
		PeerDomainUUIDs:  []string{"B1"},
		Carrier:          true,
		SpeedGbps:        40,
	}}
	live := &fakeLiveness{probes: map[netip.Addr]PeerProbe{addrB: {Alive: true, RTT: time.Millisecond}}}
	ann := &fakeAnnotation{synced: true}
	r := NewReporter(ReporterConfig{
		Node:      "a",
		Discovery: disc,
		Peers: func(context.Context) (map[string]netip.Addr, error) {
			return map[string]netip.Addr{"a": netip.MustParseAddr("169.254.0.1"), "b": addrB, "c": addrC}, nil
		},
		Liveness:   live,
		Annotation: ann,
		Metrics:    NewMetrics(),
		Log:        slog.New(slog.DiscardHandler),
	})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return r, live, ann, disc
}

func decode(t *testing.T, v string) netv1alpha1.InterconnectReport {
	t.Helper()
	r, err := netv1alpha1.ParseInterconnectReport(v)
	if err != nil {
		t.Fatalf("parse written report %q: %v", v, err)
	}
	return r
}

// TestReportWrittenOnChange pins this contract: the report goes on the
// node's own Node only when its stable content changes (no RTT, no times), at
// most once per InterconnectReportMinInterval, and a change held by the rate
// limit is written when the window ends, never dropped.
func TestReportWrittenOnChange(t *testing.T) {
	ctx := context.Background()
	window := netv1alpha1.InterconnectReportMinInterval
	if window != 10*time.Second {
		t.Fatalf("InterconnectReportMinInterval = %s; this test pins the 10 s bound", window)
	}

	r, live, ann, _ := newTestReporter(t)
	if _, err := r.Sync(ctx, t0); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(ann.writes) != 1 {
		t.Fatalf("first sync wrote %d times, want 1", len(ann.writes))
	}
	first := decode(t, ann.writes[0])
	if !reflect.DeepEqual(first.ReachablePeers, []string{"b"}) || !first.Carrier || first.SpeedGbps != 40 ||
		!reflect.DeepEqual(first.LocalDomainUUIDs, []string{"A1", "A2"}) || !reflect.DeepEqual(first.PeerDomainUUIDs, []string{"B1"}) {
		t.Fatalf("report = %+v", first)
	}
	if got := live.targets; len(got) != 2 {
		t.Errorf("probe targets = %v, want b and c (never self)", got)
	}

	t.Run("no write when unchanged", func(t *testing.T) {
		if _, err := r.Sync(ctx, t0.Add(20*time.Second)); err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 1 {
			t.Errorf("an unchanged report was rewritten (%d writes)", len(ann.writes))
		}
	})

	t.Run("an RTT-only change is not a write", func(t *testing.T) {
		live.set(addrB, PeerProbe{Alive: true, RTT: 900 * time.Millisecond})
		if _, err := r.Sync(ctx, t0.Add(40*time.Second)); err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 1 {
			t.Errorf("an RTT change rewrote the report (%d writes)", len(ann.writes))
		}
	})

	t.Run("a stable-subset change is written", func(t *testing.T) {
		live.set(addrC, PeerProbe{Alive: true})
		next, err := r.Sync(ctx, t0.Add(60*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 2 || !next.IsZero() {
			t.Fatalf("writes = %d, next = %v; want a second write at once", len(ann.writes), next)
		}
		if got := decode(t, ann.writes[1]).ReachablePeers; !reflect.DeepEqual(got, []string{"b", "c"}) {
			t.Errorf("reachable = %v, want [b c]", got)
		}
	})

	t.Run("at most one write per window, and the trailing change is flushed", func(t *testing.T) {
		w := t0.Add(60 * time.Second) // the last write
		live.set(addrB, PeerProbe{Alive: false})
		next, err := r.Sync(ctx, w.Add(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 2 {
			t.Fatalf("a change 2 s after a write was written (%d writes)", len(ann.writes))
		}
		if !next.Equal(w.Add(window)) {
			t.Fatalf("held change due at %v, want %v", next, w.Add(window))
		}
		// A second change inside the window: still held.
		live.set(addrC, PeerProbe{Alive: false})
		if _, err := r.Sync(ctx, w.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 2 {
			t.Fatalf("a second change inside the window was written (%d writes)", len(ann.writes))
		}
		// The window ends: the CURRENT report (both peers lost) is written.
		if _, err := r.Sync(ctx, w.Add(window)); err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 3 {
			t.Fatalf("the held change was dropped at the window's end (%d writes)", len(ann.writes))
		}
		if got := decode(t, ann.writes[2]).ReachablePeers; len(got) != 0 {
			t.Errorf("flushed reachable = %v, want none (the last change in the window)", got)
		}
	})

	t.Run("an unsynced cache writes nothing", func(t *testing.T) {
		r, _, ann, _ := newTestReporter(t)
		ann.synced = false
		if _, err := r.Sync(ctx, t0); err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 0 {
			t.Errorf("wrote %v before the node cache synced", ann.writes)
		}
	})

	t.Run("a node with no thunderbolt port writes no report", func(t *testing.T) {
		r, _, ann, disc := newTestReporter(t)
		disc.links = LocalLinks{}
		if err := r.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Sync(ctx, t0); err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 0 {
			t.Errorf("wrote %v on a node with no port", ann.writes)
		}
	})

	t.Run("a helper too old withdraws the report", func(t *testing.T) {
		r, _, ann, _ := newTestReporter(t)
		if _, err := r.Sync(ctx, t0); err != nil {
			t.Fatal(err)
		}
		r.SetHelperReason(ReasonHelperTooOld)
		if _, err := r.Sync(ctx, t0.Add(window)); err != nil {
			t.Fatal(err)
		}
		if len(ann.writes) != 2 || ann.writes[1] != "" {
			t.Errorf("writes = %q, want the report withdrawn", ann.writes)
		}
	})
}

// TestLinksFromPorts pins the discovery fold: every local domain, one peer
// entry per cabled port (repeats kept for loop detection), the fastest speed.
func TestLinksFromPorts(t *testing.T) {
	got := linksFromPorts([]linkenum.Port{
		{Iface: "en1", DomainUUID: "A1", PeerDomainUUID: "B1", SpeedGbps: 40},
		{Iface: "en2", DomainUUID: "A2", PeerDomainUUID: "B1", SpeedGbps: 80},
		{Iface: "en3", DomainUUID: "A3"},
	})
	want := LocalLinks{LocalDomainUUIDs: []string{"A1", "A2", "A3"}, PeerDomainUUIDs: []string{"B1", "B1"}, Carrier: true, SpeedGbps: 80}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("linksFromPorts = %+v, want %+v", got, want)
	}
}
