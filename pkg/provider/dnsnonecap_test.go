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

package provider

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/dns"
)

// eventDropList is the server list a DNSConfigPartial or DNSConfigForming event
// names: the text after its last ": ", split on spaces and commas.
func eventDropList(ev string) []string {
	i := strings.LastIndex(ev, ": ")
	if i < 0 {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(ev[i+2:], ",", " "))
}

// dnsEventsWith returns the recorded events containing substr.
func dnsEventsWith(events []string, substr string) []string {
	var out []string
	for _, ev := range events {
		if strings.Contains(ev, substr) {
			out = append(out, ev)
		}
	}
	return out
}

// TestDNSPolicyNoneCapKeepsIPv4Servers pins B1510: a dnsPolicy None pod's
// nameservers are filtered to IPv4 BEFORE the netv1.MaxNameservers cap, so IPv6
// servers listed first cannot crowd out the IPv4 servers the in-pod resolver can
// use. DNSConfigPartial names exactly the IPv6 servers left out, the
// DNSConfigForming cap event names only IPv4 servers past the cap, and an
// all-IPv6 list is still refused with msgDNSNoneIPv6Only before an address is
// drawn.
//
// Non-vacuity: on the pre-fix mapping (dedupe, cap, no family check) the
// [v6, v6, v6, v4] pod is refused as all-IPv6 and its cap event names 1.1.1.1;
// the mixed case runs on one IPv4 server instead of three; and the mapped config
// carries IPv6 servers, so it disagrees with darwin-net's kept list.
func TestDNSPolicyNoneCapKeepsIPv4Servers(t *testing.T) {
	const (
		v6a = "2606:4700:4700::1111"
		v6b = "2001:4860:4860::8888"
		v6c = "2620:fe::fe"
		v6d = "2001:db8::53"
	)
	tests := []struct {
		name     string
		ns       []string
		searches []string
		options  []corev1.PodDNSConfigOption
		// wantServers is the mapped (and injected) nameserver list; nil means the
		// pod is refused with msgDNSNoneIPv6Only.
		wantServers []string
		wantPartial []string // DNSConfigPartial's dropped list; nil means no event
		wantCapped  []string // the nameserver cap event's dropped list; nil means no event
		wantSearch  string   // K3SM_DNS_SEARCH, when the pod runs
		wantNdots   string   // K3SM_DNS_NDOTS, when the pod runs
		wantOptions []netv1.DNSOption
		wantNDots   int32
		// darwinNet pins that dnsPolicyNoneConfig's IPv4 predicate agrees with
		// darwin-net's (dns.ConfigToEnvChecked over the deduped raw list).
		darwinNet bool
	}{
		{
			name:        "three IPv6 then one IPv4 runs on the IPv4",
			ns:          []string{v6a, v6b, v6c, "1.1.1.1"},
			wantServers: []string{"1.1.1.1"},
			wantPartial: []string{v6a, v6b, v6c},
			wantSearch:  "", wantNdots: "5",
		},
		{
			name:        "four IPv4 keep the first three, the cap names the fourth",
			ns:          []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"},
			wantServers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
			wantCapped:  []string{"8.8.4.4"},
			wantSearch:  "", wantNdots: "5",
		},
		{
			name:        "mixed with more than three IPv4: cap names only IPv4, partial only IPv6",
			ns:          []string{v6a, "1.1.1.1", v6b, "8.8.8.8", "9.9.9.9", v6c, "8.8.4.4", "1.0.0.1"},
			wantServers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
			wantPartial: []string{v6a, v6b, v6c},
			wantCapped:  []string{"8.8.4.4", "1.0.0.1"},
			wantSearch:  "", wantNdots: "5",
		},
		{
			name: "all IPv6 is refused and draws no address",
			ns:   []string{v6a, v6b, v6c, v6d},
		},
		{
			name:        "a mapped IPv4 is kept in dotted form",
			ns:          []string{v6a, "::ffff:1.1.1.1"},
			wantServers: []string{"1.1.1.1"},
			wantPartial: []string{v6a},
			wantSearch:  "", wantNdots: "5",
			darwinNet: true,
		},
		{
			name:        "duplicates are merged before the filter and the cap",
			ns:          []string{v6a, v6a, "1.1.1.1", "::ffff:1.1.1.1", v6b, "9.9.9.9", "1.1.1.1", "8.8.8.8", v6b},
			wantServers: []string{"1.1.1.1", "9.9.9.9", "8.8.8.8"},
			wantPartial: []string{v6a, v6b},
			wantSearch:  "", wantNdots: "5",
		},
		{
			name:     "searches, options and ndots are untouched",
			ns:       []string{v6a, v6b, v6c, "1.1.1.1"},
			searches: []string{"a.example", "b.example"},
			options: []corev1.PodDNSConfigOption{
				{Name: "ndots", Value: ptr("2")},
				{Name: "edns0"},
				{Name: "timeout", Value: ptr("3")},
			},
			wantServers: []string{"1.1.1.1"},
			wantPartial: []string{v6a, v6b, v6c},
			wantSearch:  "a.example b.example", wantNdots: "2",
			wantOptions: []netv1.DNSOption{{Name: "edns0"}, {Name: "timeout", Value: "3"}},
			wantNDots:   2,
		},
		{
			name:        "the IPv4 predicate agrees with darwin-net",
			ns:          []string{"::ffff:8.8.8.8", v6d, "1.1.1.1"},
			wantServers: []string{"8.8.8.8", "1.1.1.1"},
			wantPartial: []string{v6d},
			wantSearch:  "", wantNdots: "5",
			darwinNet: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := &corev1.PodDNSConfig{Nameservers: tc.ns, Searches: tc.searches, Options: tc.options}

			// The mapping itself.
			cfg, forming := dnsPolicyNoneConfig(spec)
			if tc.wantServers != nil && !slices.Equal(cfg.Nameservers, tc.wantServers) {
				t.Errorf("mapped Nameservers = %v, want %v", cfg.Nameservers, tc.wantServers)
			}
			if !slices.Equal(cfg.SearchDomains, tc.searches) {
				t.Errorf("mapped SearchDomains = %v, want %v", cfg.SearchDomains, tc.searches)
			}
			if !slices.Equal(cfg.Options, tc.wantOptions) {
				t.Errorf("mapped Options = %v, want %v", cfg.Options, tc.wantOptions)
			}
			if cfg.NDots != tc.wantNDots {
				t.Errorf("mapped NDots = %d, want %d", cfg.NDots, tc.wantNDots)
			}
			if !slices.Equal(forming.droppedNameservers, tc.wantCapped) {
				t.Errorf("forming droppedNameservers = %v, want %v (IPv4 past the cap only)", forming.droppedNameservers, tc.wantCapped)
			}

			if tc.darwinNet {
				// The same raw list (no repeats, within the cap) through darwin-net's
				// own IPv4 split: its kept servers are the mapping's, and the servers
				// it drops are the ones DNSConfigPartial names.
				env, err := dns.ConfigToEnvChecked(netv1.DNSConfig{Policy: netv1.DNSPolicyNone, Nameservers: tc.ns})
				if !errors.Is(err, dns.ErrNameserversDropped) {
					t.Fatalf("darwin-net ConfigToEnvChecked(%v) err = %v, want ErrNameserversDropped", tc.ns, err)
				}
				if got := strings.Fields(env[dns.EnvDNSServers]); !slices.Equal(got, cfg.Nameservers) {
					t.Errorf("darwin-net keeps %v, the k3sm mapping keeps %v; the predicates disagree", got, cfg.Nameservers)
				}
				if got := eventDropList(err.Error()); !slices.Equal(got, tc.wantPartial) {
					t.Errorf("darwin-net drops %v, want %v", got, tc.wantPartial)
				}
			}

			// The create path: what runs, what is refused, what the pod is told.
			g := newGuestDNSRecorder(t)
			r, f, rec := noneTestProvider(t, g)
			pod := nonePod("cap", corev1.DNSNone, spec)
			pod.Spec.InitContainers = nil
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			events := recordedEvents(rec.Events)
			box := liveBox(f, pod)
			if tc.wantServers == nil {
				if box != nil {
					t.Fatalf("the runtime received a box for an all-IPv6 None pod")
				}
				if n := g.setupCount(); n != 0 {
					t.Errorf("pod network Setup calls = %d, want 0 (no address drawn for a refused pod)", n)
				}
				if ip, ok := g.ipam.allocations()[string(pod.UID)]; ok {
					t.Errorf("the refused pod holds address %s, want none", ip)
				}
				st, err := r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
				if err != nil {
					t.Fatalf("GetPodStatus: %v", err)
				}
				if w := waitingOf(st, "c0"); w == nil || w.Reason != reasonCreateContainerConfigError || w.Message != msgDNSNoneIPv6Only {
					t.Errorf("c0 waiting = %+v, want Waiting{CreateContainerConfigError, %q}", w, msgDNSNoneIPv6Only)
				}
			} else {
				if box == nil {
					t.Fatalf("the runtime received no box; want the pod running on %v (events %q)", tc.wantServers, events)
				}
				env := containerEnv(box.GetContainers()[0])
				if got := env[dns.EnvDNSServers]; got != strings.Join(tc.wantServers, " ") {
					t.Errorf("%s = %q, want %q", dns.EnvDNSServers, got, strings.Join(tc.wantServers, " "))
				}
				if got := env[dns.EnvDNSSearch]; got != tc.wantSearch {
					t.Errorf("%s = %q, want %q", dns.EnvDNSSearch, got, tc.wantSearch)
				}
				if got := env[dns.EnvDNSNdots]; got != tc.wantNdots {
					t.Errorf("%s = %q, want %q", dns.EnvDNSNdots, got, tc.wantNdots)
				}
			}

			partial := dnsEventsWith(events, "Warning "+reasonDNSConfigPartial+" ")
			switch {
			case tc.wantPartial == nil && len(partial) != 0:
				t.Errorf("DNSConfigPartial events = %q, want none", partial)
			case tc.wantPartial != nil && len(partial) != 1:
				t.Errorf("DNSConfigPartial events = %q, want exactly one", partial)
			case tc.wantPartial != nil:
				if got := eventDropList(partial[0]); !slices.Equal(got, tc.wantPartial) {
					t.Errorf("DNSConfigPartial names %v, want exactly the IPv6 servers %v (%q)", got, tc.wantPartial, partial[0])
				}
			}

			capped := dnsEventsWith(events, "Warning "+reasonDNSConfigForming+" k3sm: dnsPolicy None nameserver limits")
			switch {
			case tc.wantCapped == nil && len(capped) != 0:
				t.Errorf("nameserver cap events = %q, want none", capped)
			case tc.wantCapped != nil && len(capped) != 1:
				t.Errorf("nameserver cap events = %q, want exactly one", capped)
			case tc.wantCapped != nil:
				if want := "Warning " + reasonDNSConfigForming + " " + msgDNSNameserversCapped(tc.wantCapped); capped[0] != want {
					t.Errorf("nameserver cap event = %q, want %q", capped[0], want)
				}
			}
		})
	}
}
