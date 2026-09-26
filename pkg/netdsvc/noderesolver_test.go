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

package netdsvc

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// fakePublisher records every Publish/Remove, and models the dynamic store as a
// key -> entry map so "present after start, absent after stop" is a state
// assertion and not only a call count.
type fakePublisher struct {
	calls   []string
	store   map[string]ResolverEntry
	written []ResolverEntry
	failPub error
}

func (f *fakePublisher) Publish(key string, e ResolverEntry) error {
	f.calls = append(f.calls, "Publish:"+key)
	if f.failPub != nil {
		return f.failPub
	}
	if f.store == nil {
		f.store = map[string]ResolverEntry{}
	}
	f.store[key] = e
	f.written = append(f.written, e)
	return nil
}

func (f *fakePublisher) Remove(key string) error {
	f.calls = append(f.calls, "Remove:"+key)
	delete(f.store, key)
	return nil
}

// TestNodeResolverEntryIsPublishedOnStart is the netd half of B243's node
// resolver floor: netd publishes ONE dynamic-store entry at the fixed key with
// the exact supplemental DNS dictionary (the DNS VIP as the only server, svc and
// the cluster domain as NoSearch match domains, order 1000), writes the FULL
// entry on every start (a respawn after a crash rewrites rather than trusting
// what configd kept), and removes it on stop.
func TestNodeResolverEntryIsPublishedOnStart(t *testing.T) {
	t.Parallel()

	want := ResolverEntry{
		ServerAddresses:                  []string{"10.43.0.10"},
		SupplementalMatchDomains:         []string{"svc", "cluster.local"},
		SupplementalMatchDomainsNoSearch: true,
		SupplementalMatchOrder:           1000,
	}
	if NodeResolverKey != "State:/Network/Service/io.k3sm.dns/DNS" {
		t.Fatalf("NodeResolverKey = %q, want the fixed State:/Network/Service/io.k3sm.dns/DNS", NodeResolverKey)
	}

	pub := &fakePublisher{}
	nr, err := NewNodeResolver(pub, netip.MustParseAddr("10.43.0.10"), "Cluster.Local.", nil)
	if err != nil {
		t.Fatalf("NewNodeResolver: %v", err)
	}
	if err := nr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got, ok := pub.store[NodeResolverKey]; !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("published entry = %+v (present %v), want %+v", got, ok, want)
	}

	// A second daemon start (launchd's KeepAlive respawn after a crash) over a
	// store that still holds a stale, partial entry rewrites the full entry.
	pub.store[NodeResolverKey] = ResolverEntry{ServerAddresses: []string{"10.43.0.99"}}
	nr2, err := NewNodeResolver(pub, netip.MustParseAddr("10.43.0.10"), "cluster.local", nil)
	if err != nil {
		t.Fatalf("NewNodeResolver (respawn): %v", err)
	}
	if err := nr2.Start(); err != nil {
		t.Fatalf("Start (respawn): %v", err)
	}
	if got := pub.store[NodeResolverKey]; !reflect.DeepEqual(got, want) {
		t.Fatalf("re-published entry = %+v, want the full entry %+v", got, want)
	}
	if len(pub.written) != 2 || !reflect.DeepEqual(pub.written[0], pub.written[1]) {
		t.Fatalf("writes = %+v, want two identical full writes (idempotent re-publish)", pub.written)
	}

	if err := nr2.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, ok := pub.store[NodeResolverKey]; ok {
		t.Fatalf("entry still present after Stop")
	}
	wantCalls := []string{"Publish:" + NodeResolverKey, "Publish:" + NodeResolverKey, "Remove:" + NodeResolverKey}
	if !reflect.DeepEqual(pub.calls, wantCalls) {
		t.Fatalf("calls = %v, want %v (one fixed key, never another)", pub.calls, wantCalls)
	}

	// A publish failure is reported, never swallowed.
	bad := &fakePublisher{failPub: errors.New("SCDynamicStoreSetValue: permission denied")}
	nr3, err := NewNodeResolver(bad, netip.MustParseAddr("10.43.0.10"), "cluster.local", nil)
	if err != nil {
		t.Fatalf("NewNodeResolver: %v", err)
	}
	if err := nr3.Start(); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Start with a failing store = %v, want the store's error", err)
	}
}

// TestNodeResolverEntryRefusesUnsafeInputs pins the inputs NodeResolverEntry
// refuses: the entry is a host-wide DNS routing decision, so a cluster domain
// that is itself a real or special-use suffix, or a malformed one, must never
// be registered.
func TestNodeResolverEntryRefusesUnsafeInputs(t *testing.T) {
	t.Parallel()
	vip := netip.MustParseAddr("10.43.0.10")
	for _, tc := range []struct {
		name   string
		vip    netip.Addr
		domain string
	}{
		{"single label local", vip, "local"},
		{"single label com", vip, "com"},
		{"empty domain", vip, ""},
		{"bad label", vip, "clu_ster.local"},
		{"invalid vip", netip.Addr{}, "cluster.local"},
		{"ipv6 vip", netip.MustParseAddr("fd00::10"), "cluster.local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NodeResolverEntry(tc.vip, tc.domain); err == nil {
				t.Fatalf("NodeResolverEntry(%v, %q) = nil error, want a refusal", tc.vip, tc.domain)
			}
		})
	}
	if e, err := NodeResolverEntry(vip, "corp.example.internal"); err != nil || e.SupplementalMatchDomains[1] != "corp.example.internal" {
		t.Fatalf("a multi-label custom domain = %+v, %v, want it registered as given", e, err)
	}
}
