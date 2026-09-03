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
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

// TestClusterEndpointAddress pins the address the per-node Service sends a caller
// to, and — the load-bearing half — every address it REFUSES.
//
// The choice is mesh-else-gateway because that is the relay's own preference
// order: the endpoint is taken from relayBinds, so it can only ever name an
// address the relay actually binds. The refusals come free from the same source,
// and the loopback one is the invariant this whole feature must not weaken —
// 127.0.0.1 is every caller's own address, and EndpointSlice validation refuses
// it outright, so a Service pointing there would be a broken object as well as a
// lie.
func TestClusterEndpointAddress(t *testing.T) {
	tests := []struct {
		name    string
		meshIP  string
		subnet  string
		want    string
		wantErr error
	}{
		{
			name:   "the mesh address wins when the node has one",
			meshIP: "100.64.1.1",
			subnet: "192.168.64.0/24",
			want:   "100.64.1.1",
		},
		{
			name:   "the vm gateway is used when there is no mesh address",
			subnet: "192.168.64.0/24",
			want:   "192.168.64.1",
		},
		{
			name:   "a mesh address alone is enough",
			meshIP: "100.64.2.7",
			want:   "100.64.2.7",
		},
		{
			name:    "neither is the single-node non-event",
			wantErr: ErrNoClusterAddress,
		},
		{
			name:    "a loopback mesh address is refused",
			meshIP:  "127.0.0.1",
			wantErr: ErrNonRelayableBind,
		},
		{
			name:    "the wildcard is refused",
			meshIP:  "0.0.0.0",
			wantErr: ErrNonRelayableBind,
		},
		{
			name:    "an address outside the cluster mesh range is refused",
			meshIP:  "192.0.2.5",
			wantErr: ErrNonRelayableBind,
		},
		{
			name:    "a non-address is refused",
			meshIP:  "not-an-ip",
			wantErr: ErrNonRelayableBind,
		},
		{
			name:    "a malformed vm subnet is refused",
			subnet:  "192.168.64.0",
			wantErr: ErrNonRelayableBind,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClusterEndpointAddress(tc.meshIP, tc.subnet)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClusterEndpointAddress: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("address = %s, want %s", got, tc.want)
			}
		})
	}

	// ErrNoClusterAddress must remain classifiable as the relay's own "no
	// address" sentinel, so a caller that already handles one handles both.
	t.Run("no cluster address is also no relay address", func(t *testing.T) {
		_, err := ClusterEndpointAddress("", "")
		if !errors.Is(err, ErrNoRelayAddress) {
			t.Errorf("err = %v, want it to wrap ErrNoRelayAddress", err)
		}
	})
}

// TestClusterService pins the Service spec. The three properties that decide
// whether the object works at all: it is SELECTOR-LESS (nothing schedules the
// registry, so no selector can find it, and a selector would hand the object to
// the EndpointSlice controller which would delete the hand-written slice), the
// port and target port are BOTH the registry port (the relay listens on the same
// port on every address), and the port NAME matches the slice's (that name is how
// a proxy pairs a Service port with a backend port).
func TestClusterService(t *testing.T) {
	t.Run("the rendered spec", func(t *testing.T) {
		svc, err := ClusterService("mac-a", 6450)
		if err != nil {
			t.Fatalf("ClusterService: %v", err)
		}
		if svc.Name != "registry-mac-a" {
			t.Errorf("Name = %q, want registry-mac-a", svc.Name)
		}
		if svc.Namespace != AdvertisementNamespace {
			t.Errorf("Namespace = %q, want %q", svc.Namespace, AdvertisementNamespace)
		}
		if svc.Spec.Selector != nil {
			t.Errorf("Selector = %v; a selector hands the object to the EndpointSlice controller, which deletes the hand-written slice", svc.Spec.Selector)
		}
		if svc.Spec.Type != corev1.ServiceTypeClusterIP {
			t.Errorf("Type = %q, want ClusterIP", svc.Spec.Type)
		}
		if len(svc.Spec.Ports) != 1 {
			t.Fatalf("Ports = %d, want 1", len(svc.Spec.Ports))
		}
		p := svc.Spec.Ports[0]
		if p.Name != ClusterServicePortName {
			t.Errorf("port name = %q, want %q", p.Name, ClusterServicePortName)
		}
		if p.Protocol != corev1.ProtocolTCP {
			t.Errorf("protocol = %q, want TCP", p.Protocol)
		}
		if p.Port != 6450 || p.TargetPort.IntValue() != 6450 {
			t.Errorf("port/targetPort = %d/%d, want 6450/6450 — the relay listens on the registry's own port", p.Port, p.TargetPort.IntValue())
		}
	})

	t.Run("a node name that will not compose a Service name is an error", func(t *testing.T) {
		// A Service name is a DNS-1035 LABEL — 63 characters, no dots — which is
		// stricter than the DNS-1123 subdomain a node name may be, so this fails
		// on node names that are themselves perfectly legal.
		for _, node := range []string{"", "mac.a", strings.Repeat("n", 60), "MacA", "mac_a", "mac-"} {
			if _, err := ClusterService(node, 6450); err == nil {
				t.Errorf("ClusterService(%q) = nil error, want a refusal", node)
			}
		}
	})

	t.Run("an out-of-range port is an error", func(t *testing.T) {
		for _, port := range []int{0, -1, 65536} {
			if _, err := ClusterService("mac-a", port); err == nil {
				t.Errorf("ClusterService(port=%d) = nil error, want a refusal", port)
			}
		}
	})
}

// TestClusterEndpointSlice pins the hand-written slice, including the LOOPBACK
// REFUSAL. EndpointSlice validation rejects a loopback address at the apiserver,
// so this refusal is not the only guard — it is the one that names the reason
// where the decision is made.
func TestClusterEndpointSlice(t *testing.T) {
	t.Run("the rendered slice", func(t *testing.T) {
		es, err := ClusterEndpointSlice("mac-a", 6450, netip.MustParseAddr("100.64.1.1"))
		if err != nil {
			t.Fatalf("ClusterEndpointSlice: %v", err)
		}
		if es.Name != "registry-mac-a" || es.Namespace != AdvertisementNamespace {
			t.Errorf("%s/%s, want %s/registry-mac-a", es.Namespace, es.Name, AdvertisementNamespace)
		}
		// The pairing label IS the association — without it the Service has a VIP
		// and no backends, whatever the names look like.
		if got := es.Labels[discoveryv1.LabelServiceName]; got != "registry-mac-a" {
			t.Errorf("%s = %q, want registry-mac-a", discoveryv1.LabelServiceName, got)
		}
		if es.AddressType != discoveryv1.AddressTypeIPv4 {
			t.Errorf("AddressType = %q, want IPv4", es.AddressType)
		}
		if len(es.Ports) != 1 || es.Ports[0].Name == nil || *es.Ports[0].Name != ClusterServicePortName {
			t.Fatalf("ports = %+v, want one named %q to match the Service port", es.Ports, ClusterServicePortName)
		}
		if es.Ports[0].Port == nil || *es.Ports[0].Port != 6450 {
			t.Errorf("port = %v, want 6450", es.Ports[0].Port)
		}
		if len(es.Endpoints) != 1 || len(es.Endpoints[0].Addresses) != 1 || es.Endpoints[0].Addresses[0] != "100.64.1.1" {
			t.Fatalf("endpoints = %+v, want the single relay address", es.Endpoints)
		}
		// Ready must be EXPLICIT: a nil Ready reads as not-ready, which would
		// leave the Service with no usable backend.
		if es.Endpoints[0].Conditions.Ready == nil || !*es.Endpoints[0].Conditions.Ready {
			t.Error("the endpoint is not explicitly Ready; a nil Ready is read as not-ready and the Service would have no backend")
		}
	})

	t.Run("every label value is one the apiserver accepts", func(t *testing.T) {
		// A label VALUE may not contain "/" — the managed-by value is a reverse-DNS
		// name for exactly that reason, and getting it wrong rejects the WHOLE
		// object, not the label. Caught by a server dry-run once; pinned here so it
		// cannot come back.
		es, err := ClusterEndpointSlice("mac-a", 6450, netip.MustParseAddr("100.64.1.1"))
		if err != nil {
			t.Fatalf("ClusterEndpointSlice: %v", err)
		}
		for k, v := range es.Labels {
			if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
				t.Errorf("label %s=%q is not a valid label value: %s", k, v, strings.Join(errs, "; "))
			}
		}
		if es.Labels[clusterServiceManagedBy] == "" {
			t.Errorf("%s is unset; nothing records that this slice is hand-written", clusterServiceManagedBy)
		}
	})

	t.Run("a loopback endpoint is refused", func(t *testing.T) {
		for _, addr := range []string{"127.0.0.1", "127.0.0.53", "::1"} {
			_, err := ClusterEndpointSlice("mac-a", 6450, netip.MustParseAddr(addr))
			if !errors.Is(err, ErrNonRelayableBind) {
				t.Errorf("ClusterEndpointSlice(%s) err = %v, want ErrNonRelayableBind — loopback is every caller's own address", addr, err)
			}
		}
	})

	t.Run("the wildcard and the zero address are refused", func(t *testing.T) {
		if _, err := ClusterEndpointSlice("mac-a", 6450, netip.MustParseAddr("0.0.0.0")); !errors.Is(err, ErrNonRelayableBind) {
			t.Errorf("err = %v, want ErrNonRelayableBind for the wildcard", err)
		}
		if _, err := ClusterEndpointSlice("mac-a", 6450, netip.Addr{}); !errors.Is(err, ErrNonRelayableBind) {
			t.Errorf("err = %v, want ErrNonRelayableBind for the zero address", err)
		}
	})

	t.Run("an IPv6 endpoint is refused while the slice is IPv4", func(t *testing.T) {
		if _, err := ClusterEndpointSlice("mac-a", 6450, netip.MustParseAddr("fd00::1")); !errors.Is(err, ErrNonRelayableBind) {
			t.Errorf("err = %v, want ErrNonRelayableBind — an IPv6 address in an IPv4 slice is rejected by the apiserver", err)
		}
	})
}

// TestClusterServiceAuthority pins the address published as
// hostFromClusterNetwork and handed to runtimed as a cluster-local spelling.
func TestClusterServiceAuthority(t *testing.T) {
	if got, want := ClusterServiceAuthority("mac-a", "cluster.local", 6450),
		"registry-mac-a.k3sm-registry.svc.cluster.local:6450"; got != want {
		t.Errorf("authority = %q, want %q", got, want)
	}
	if got, want := ClusterServiceAuthority("mac-a", "", 6450),
		"registry-mac-a.k3sm-registry.svc.cluster.local:6450"; got != want {
		t.Errorf("an empty cluster domain must default: authority = %q, want %q", got, want)
	}
	if got, want := ClusterServiceAuthority("mac-a", "k3sm.internal", 14507),
		"registry-mac-a.k3sm-registry.svc.k3sm.internal:14507"; got != want {
		t.Errorf("authority = %q, want %q", got, want)
	}
}

// TestClusterLocalAuthorities pins the spellings runtimed's puller must treat as
// naming THIS node's own ingest registry. runtimed classifies a reference as
// node-relative by loopback authority alone, so a Pod that names the Service is
// asking for the same registry under a name the classifier cannot derive — it has
// to be injected, which is what this list is for.
func TestClusterLocalAuthorities(t *testing.T) {
	got := ClusterLocalAuthorities("mac-a", "cluster.local", "10.43.7.9", 6450)
	want := []string{
		"registry-mac-a.k3sm-registry.svc.cluster.local:6450",
		"registry-mac-a.k3sm-registry.svc:6450",
		"registry-mac-a.k3sm-registry:6450",
		"10.43.7.9:6450",
	}
	if len(got) != len(want) {
		t.Fatalf("authorities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("authorities[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	t.Run("no ClusterIP yields only the name spellings", func(t *testing.T) {
		got := ClusterLocalAuthorities("mac-a", "", "", 6450)
		if len(got) != 3 {
			t.Fatalf("authorities = %v, want the three name spellings only", got)
		}
	})

	t.Run("a garbage ClusterIP is dropped, never spliced", func(t *testing.T) {
		for _, ip := range []string{"nope", "10.43.7.9/32", "http://10.43.7.9"} {
			for _, a := range ClusterLocalAuthorities("mac-a", "", ip, 6450) {
				if strings.Contains(a, ip) {
					t.Errorf("authority %q carries the unparseable ClusterIP %q", a, ip)
				}
			}
		}
	})

	t.Run("an unusable node or port yields nothing", func(t *testing.T) {
		if got := ClusterLocalAuthorities("", "", "", 6450); got != nil {
			t.Errorf("authorities = %v for an empty node, want nil", got)
		}
		if got := ClusterLocalAuthorities("mac-a", "", "", 0); got != nil {
			t.Errorf("authorities = %v for port 0, want nil", got)
		}
	})

	t.Run("the loopback authority is the localhost spelling", func(t *testing.T) {
		// `localhost` and not 127.0.0.1: the OCI toolchain special-cases the
		// literal name as an insecure registry, and this authority is what a
		// bare-name pull is rewritten to, so it ends up in a reference an operator
		// reads back.
		if got := LoopbackAuthority(6450); got != "localhost:6450" {
			t.Errorf("LoopbackAuthority = %q, want localhost:6450", got)
		}
		for _, port := range []int{0, -1, 65536} {
			if got := LoopbackAuthority(port); got != "" {
				t.Errorf("LoopbackAuthority(%d) = %q, want empty", port, got)
			}
		}
	})

	t.Run("every element is a bare host:port authority", func(t *testing.T) {
		// A value carrying a path, a scheme or userinfo would splice into the
		// repository half of a rewritten reference; runtimed refuses one, and
		// producing one here would be this side's bug.
		for _, a := range ClusterLocalAuthorities("mac-a", "cluster.local", "10.43.7.9", 6450) {
			if strings.ContainsAny(a, "/@") || strings.Contains(a, "://") {
				t.Errorf("authority %q is not a bare host:port", a)
			}
		}
	})
}

// TestPublishClusterService drives the three states the publisher has to get
// right — absent (create both), stale (refresh the endpoint, the case that
// matters because a mesh address is a per-boot fact), and identical (no write) —
// plus the retraction order.
func TestPublishClusterService(t *testing.T) {
	mesh := netip.MustParseAddr("100.64.1.1")

	t.Run("absent creates both objects", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		if svcs.creates != 1 || slices.creates != 1 {
			t.Fatalf("service creates=%d slice creates=%d, want 1/1", svcs.creates, slices.creates)
		}
		if slices.es.Endpoints[0].Addresses[0] != "100.64.1.1" {
			t.Errorf("endpoint = %v, want the relay address", slices.es.Endpoints[0].Addresses)
		}
	})

	t.Run("the assigned ClusterIP is returned", func(t *testing.T) {
		svcs, slices := &fakeServices{assignIP: "10.43.7.9"}, &fakeSlices{}
		ip, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh)
		if err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		if ip != "10.43.7.9" {
			t.Errorf("ClusterIP = %q, want the assigned VIP — it is the spelling runtimed must also treat as cluster-local", ip)
		}
	})

	t.Run("a moved relay address is refreshed", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		moved := netip.MustParseAddr("100.64.9.9")
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, moved); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		if slices.updates != 1 {
			t.Fatalf("slice updates = %d after the address moved, want 1 — callers would be sent to a dead address", slices.updates)
		}
		if slices.es.Endpoints[0].Addresses[0] != "100.64.9.9" {
			t.Errorf("endpoint = %v, want the new address", slices.es.Endpoints[0].Addresses)
		}
	})

	t.Run("an unchanged pair is not rewritten", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		for range 3 {
			if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
				t.Fatalf("PublishClusterService: %v", err)
			}
		}
		if svcs.updates != 0 || slices.updates != 0 {
			t.Errorf("service updates=%d slice updates=%d for an unchanged pair, want 0/0", svcs.updates, slices.updates)
		}
	})

	t.Run("a refresh preserves the assigned ClusterIP", func(t *testing.T) {
		// ClusterIP is assigned by the apiserver and is immutable; a refresh that
		// rewrote the whole spec would be rejected, and one that cleared it would
		// orphan every lo0 alias already carved for it.
		svcs, slices := &fakeServices{assignIP: "10.43.7.9"}, &fakeSlices{}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 14507, mesh); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		if svcs.updates != 1 {
			t.Fatalf("service updates = %d after a port change, want 1", svcs.updates)
		}
		if svcs.svc.Spec.ClusterIP != "10.43.7.9" {
			t.Errorf("ClusterIP = %q after a refresh, want it preserved", svcs.svc.Spec.ClusterIP)
		}
		if svcs.svc.Spec.Ports[0].Port != 14507 {
			t.Errorf("port = %d after a refresh, want 14507", svcs.svc.Spec.Ports[0].Port)
		}
	})

	t.Run("a selector that appeared is cleared", func(t *testing.T) {
		// A selector on this Service hands it to the EndpointSlice controller,
		// which deletes the hand-written slice as orphaned — the Service then has
		// a VIP and no backend.
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		svcs.svc.Spec.Selector = map[string]string{"app": "someone-elses"}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		if svcs.svc.Spec.Selector != nil {
			t.Errorf("Selector = %v after a refresh, want it cleared", svcs.svc.Spec.Selector)
		}
	})

	t.Run("a loopback endpoint publishes nothing at all", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		_, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, netip.MustParseAddr("127.0.0.1"))
		if !errors.Is(err, ErrNonRelayableBind) {
			t.Fatalf("err = %v, want ErrNonRelayableBind", err)
		}
		if svcs.creates != 0 || slices.creates != 0 {
			t.Errorf("service creates=%d slice creates=%d, want 0/0 — the refusal must precede every write", svcs.creates, slices.creates)
		}
	})

	t.Run("a read failure is reported, not swallowed", func(t *testing.T) {
		svcs, slices := &fakeServices{getErr: errors.New("apiserver said no")}, &fakeSlices{}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err == nil {
			t.Fatal("PublishClusterService = nil on a read failure, want an error")
		}
	})

	t.Run("a slice failure does not hide the Service's ClusterIP", func(t *testing.T) {
		svcs, slices := &fakeServices{assignIP: "10.43.7.9"}, &fakeSlices{createErr: errors.New("nope")}
		ip, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, mesh)
		if err == nil {
			t.Fatal("PublishClusterService = nil on a slice failure, want an error")
		}
		if ip != "10.43.7.9" {
			t.Errorf("ClusterIP = %q, want the assigned VIP even on the partial path", ip)
		}
	})
}

// TestRemoveClusterService pins the retraction, including the ORDER: the slice
// goes first, so the Service never outlives its backing endpoints.
func TestRemoveClusterService(t *testing.T) {
	t.Run("both objects are deleted, slice first", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, netip.MustParseAddr("100.64.1.1")); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		order := []string{}
		svcs.onDelete = func() { order = append(order, "service") }
		slices.onDelete = func() { order = append(order, "slice") }
		if err := RemoveClusterService(t.Context(), svcs, slices, "mac-a"); err != nil {
			t.Fatalf("RemoveClusterService: %v", err)
		}
		if len(order) != 2 || order[0] != "slice" || order[1] != "service" {
			t.Errorf("delete order = %v, want [slice service]", order)
		}
		if svcs.svc != nil || slices.es != nil {
			t.Error("an object survived the retraction")
		}
	})

	t.Run("an absent pair is success", func(t *testing.T) {
		if err := RemoveClusterService(t.Context(), &fakeServices{}, &fakeSlices{}, "mac-a"); err != nil {
			t.Errorf("RemoveClusterService on an absent pair = %v, want nil", err)
		}
	})

	t.Run("an empty node name is a no-op", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if err := RemoveClusterService(t.Context(), svcs, slices, ""); err != nil {
			t.Errorf("RemoveClusterService(\"\") = %v, want nil", err)
		}
		if svcs.deletes != 0 || slices.deletes != 0 {
			t.Errorf("service deletes=%d slice deletes=%d, want 0/0", svcs.deletes, slices.deletes)
		}
	})

	t.Run("a Service delete failure still reports after the slice was removed", func(t *testing.T) {
		svcs, slices := &fakeServices{deleteErr: errors.New("nope")}, &fakeSlices{}
		if _, err := PublishClusterService(t.Context(), svcs, slices, "mac-a", 6450, netip.MustParseAddr("100.64.1.1")); err != nil {
			t.Fatalf("PublishClusterService: %v", err)
		}
		if err := RemoveClusterService(t.Context(), svcs, slices, "mac-a"); err == nil {
			t.Fatal("RemoveClusterService = nil on a delete failure, want an error")
		}
		if slices.es != nil {
			t.Error("the slice survived a retraction whose Service delete failed")
		}
	})
}

// fakeServices is the four-method ServiceClient, backed by one stored object.
type fakeServices struct {
	svc                          *corev1.Service
	assignIP                     string
	creates, updates, deletes    int
	getErr, updateErr, deleteErr error
	onDelete                     func()
}

func (f *fakeServices) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.Service, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.svc == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, name)
	}
	return f.svc.DeepCopy(), nil
}

func (f *fakeServices) Create(_ context.Context, svc *corev1.Service, _ metav1.CreateOptions) (*corev1.Service, error) {
	f.creates++
	f.svc = svc.DeepCopy()
	// The apiserver assigns the ClusterIP; the fake does the same so the
	// immutability the refresh must respect is observable.
	f.svc.Spec.ClusterIP = f.assignIP
	return f.svc.DeepCopy(), nil
}

func (f *fakeServices) Update(_ context.Context, svc *corev1.Service, _ metav1.UpdateOptions) (*corev1.Service, error) {
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	f.updates++
	f.svc = svc.DeepCopy()
	return f.svc.DeepCopy(), nil
}

func (f *fakeServices) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	if f.onDelete != nil {
		f.onDelete()
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletes++
	if f.svc == nil {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, name)
	}
	f.svc = nil
	return nil
}

// fakeSlices is the four-method EndpointSliceClient, backed by one stored object.
type fakeSlices struct {
	es                                      *discoveryv1.EndpointSlice
	creates, updates, deletes               int
	getErr, createErr, updateErr, deleteErr error
	onDelete                                func()
}

func (f *fakeSlices) Get(_ context.Context, name string, _ metav1.GetOptions) (*discoveryv1.EndpointSlice, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.es == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "endpointslices"}, name)
	}
	return f.es.DeepCopy(), nil
}

func (f *fakeSlices) Create(_ context.Context, es *discoveryv1.EndpointSlice, _ metav1.CreateOptions) (*discoveryv1.EndpointSlice, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.creates++
	f.es = es.DeepCopy()
	return f.es.DeepCopy(), nil
}

func (f *fakeSlices) Update(_ context.Context, es *discoveryv1.EndpointSlice, _ metav1.UpdateOptions) (*discoveryv1.EndpointSlice, error) {
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	f.updates++
	f.es = es.DeepCopy()
	return f.es.DeepCopy(), nil
}

func (f *fakeSlices) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	if f.onDelete != nil {
		f.onDelete()
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletes++
	if f.es == nil {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "endpointslices"}, name)
	}
	f.es = nil
	return nil
}
