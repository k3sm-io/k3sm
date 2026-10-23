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

// TestFlatService pins the Service spec. The properties that decide whether the
// object works at all: it is SELECTOR-LESS (a selector would hand the object to
// the EndpointSlice controller, which would delete the hand-written slice), the
// Service port is the fixed 6450 every image reference carries while the target
// port follows the registry, and the port NAME matches the slice's.
func TestFlatService(t *testing.T) {
	t.Run("the rendered spec", func(t *testing.T) {
		svc, err := FlatService("mac-a", 14507)
		if err != nil {
			t.Fatalf("FlatService: %v", err)
		}
		if svc.Name != "registry-k3sm" || svc.Namespace != "k3sm-registry" {
			t.Errorf("%s/%s, want k3sm-registry/registry-k3sm", svc.Namespace, svc.Name)
		}
		if svc.Labels[clusterServiceNodeLabel] != "mac-a" {
			t.Errorf("labels = %v, want the publishing server recorded", svc.Labels)
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
		if p.Name != ClusterServicePortName || p.Protocol != corev1.ProtocolTCP {
			t.Errorf("port = %q/%q, want %q/TCP", p.Name, p.Protocol, ClusterServicePortName)
		}
		if p.Port != 6450 || p.TargetPort.IntValue() != 14507 {
			t.Errorf("port/targetPort = %d/%d, want 6450/14507", p.Port, p.TargetPort.IntValue())
		}
	})

	t.Run("an empty publisher or an out-of-range port is an error", func(t *testing.T) {
		if _, err := FlatService("", 6450); err == nil {
			t.Error("FlatService with no publisher = nil error")
		}
		for _, port := range []int{0, -1, 65536} {
			if _, err := FlatService("mac-a", port); err == nil {
				t.Errorf("FlatService(port=%d) = nil error, want a refusal", port)
			}
		}
	})
}

// TestFlatEndpointSlice pins the hand-written slice, including the LOOPBACK
// REFUSAL. EndpointSlice validation rejects a loopback address at the apiserver,
// so this refusal is not the only guard; it is the one that names the reason
// where the decision is made.
func TestFlatEndpointSlice(t *testing.T) {
	t.Run("the rendered slice", func(t *testing.T) {
		es, err := FlatEndpointSlice("mac-a", 14507, netip.MustParseAddr("100.64.1.1"))
		if err != nil {
			t.Fatalf("FlatEndpointSlice: %v", err)
		}
		if es.Name != "registry-k3sm" || es.Namespace != "k3sm-registry" {
			t.Errorf("%s/%s, want k3sm-registry/registry-k3sm", es.Namespace, es.Name)
		}
		// The pairing label IS the association: without it the Service has a VIP
		// and no backends, whatever the names look like.
		if got := es.Labels[discoveryv1.LabelServiceName]; got != "registry-k3sm" {
			t.Errorf("%s = %q, want registry-k3sm", discoveryv1.LabelServiceName, got)
		}
		if es.AddressType != discoveryv1.AddressTypeIPv4 {
			t.Errorf("AddressType = %q, want IPv4", es.AddressType)
		}
		if len(es.Ports) != 1 || es.Ports[0].Name == nil || *es.Ports[0].Name != ClusterServicePortName {
			t.Fatalf("ports = %+v, want one named %q to match the Service port", es.Ports, ClusterServicePortName)
		}
		// The backend port is the relay's, which is the registry's.
		if es.Ports[0].Port == nil || *es.Ports[0].Port != 14507 {
			t.Errorf("port = %v, want 14507", es.Ports[0].Port)
		}
		if len(es.Endpoints) != 1 || len(es.Endpoints[0].Addresses) != 1 || es.Endpoints[0].Addresses[0] != "100.64.1.1" {
			t.Fatalf("endpoints = %+v, want the single relay address", es.Endpoints)
		}
		if es.Endpoints[0].Conditions.Ready == nil || !*es.Endpoints[0].Conditions.Ready {
			t.Error("the endpoint is not explicitly Ready; a nil Ready is read as not-ready and the Service would have no backend")
		}
	})

	t.Run("every label value is one the apiserver accepts", func(t *testing.T) {
		// A label VALUE may not contain "/": getting it wrong rejects the WHOLE
		// object, not the label.
		es, err := FlatEndpointSlice("mac-a", 6450, netip.MustParseAddr("100.64.1.1"))
		if err != nil {
			t.Fatalf("FlatEndpointSlice: %v", err)
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

	t.Run("loopback, the wildcard, the zero address and IPv6 are refused", func(t *testing.T) {
		for _, addr := range []netip.Addr{
			netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("::1"),
			netip.MustParseAddr("0.0.0.0"), {}, netip.MustParseAddr("fd00::1"),
		} {
			if _, err := FlatEndpointSlice("mac-a", 6450, addr); !errors.Is(err, ErrNonRelayableBind) {
				t.Errorf("FlatEndpointSlice(%s) err = %v, want ErrNonRelayableBind", addr, err)
			}
		}
	})
}

// TestLoopbackAuthority pins the localhost spelling: the OCI toolchain
// special-cases the literal name as a plain-HTTP registry.
func TestLoopbackAuthority(t *testing.T) {
	if got := LoopbackAuthority(6450); got != "localhost:6450" {
		t.Errorf("LoopbackAuthority = %q, want localhost:6450", got)
	}
	for _, port := range []int{0, -1, 65536} {
		if got := LoopbackAuthority(port); got != "" {
			t.Errorf("LoopbackAuthority(%d) = %q, want empty", port, got)
		}
	}
}

// TestPublishFlatService drives the three states the publisher has to get
// right: absent (create both), stale (refresh the endpoint, the case that
// matters because a mesh address is a per-boot fact), and identical (no write).
func TestPublishFlatService(t *testing.T) {
	mesh := netip.MustParseAddr("100.64.1.1")

	t.Run("absent creates both objects", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
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
		ip, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh)
		if err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if ip != "10.43.7.9" {
			t.Errorf("ClusterIP = %q, want the assigned VIP: it is an IP SAN of the serving certificate", ip)
		}
	})

	t.Run("a moved relay address is refreshed", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, netip.MustParseAddr("100.64.9.9")); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if slices.updates != 1 || slices.es.Endpoints[0].Addresses[0] != "100.64.9.9" {
			t.Errorf("slice updates=%d endpoint=%v, want one refresh to the new address", slices.updates, slices.es.Endpoints[0].Addresses)
		}
	})

	t.Run("an unchanged pair is not rewritten", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		for range 3 {
			if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
				t.Fatalf("PublishFlatService: %v", err)
			}
		}
		if svcs.updates != 0 || slices.updates != 0 {
			t.Errorf("service updates=%d slice updates=%d for an unchanged pair, want 0/0", svcs.updates, slices.updates)
		}
	})

	t.Run("a refresh preserves the assigned ClusterIP and follows the target port", func(t *testing.T) {
		svcs, slices := &fakeServices{assignIP: "10.43.7.9"}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 14507, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if svcs.updates != 1 {
			t.Fatalf("service updates = %d after a target port change, want 1", svcs.updates)
		}
		if svcs.svc.Spec.ClusterIP != "10.43.7.9" {
			t.Errorf("ClusterIP = %q after a refresh, want it preserved", svcs.svc.Spec.ClusterIP)
		}
		if p := svcs.svc.Spec.Ports[0]; p.Port != 6450 || p.TargetPort.IntValue() != 14507 {
			t.Errorf("port/targetPort = %d/%d after a refresh, want 6450/14507", p.Port, p.TargetPort.IntValue())
		}
	})

	t.Run("a selector that appeared is cleared", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		svcs.svc.Spec.Selector = map[string]string{"app": "someone-elses"}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if svcs.svc.Spec.Selector != nil {
			t.Errorf("Selector = %v after a refresh, want it cleared", svcs.svc.Spec.Selector)
		}
	})

	t.Run("a loopback endpoint publishes nothing at all", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		_, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, netip.MustParseAddr("127.0.0.1"))
		if !errors.Is(err, ErrNonRelayableBind) {
			t.Fatalf("err = %v, want ErrNonRelayableBind", err)
		}
		if svcs.creates != 0 || slices.creates != 0 {
			t.Errorf("service creates=%d slice creates=%d, want 0/0: the refusal must precede every write", svcs.creates, slices.creates)
		}
	})

	t.Run("a read failure is reported, not swallowed", func(t *testing.T) {
		svcs, slices := &fakeServices{getErr: errors.New("apiserver said no")}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh); err == nil {
			t.Fatal("PublishFlatService = nil on a read failure, want an error")
		}
	})

	t.Run("a slice failure does not hide the Service's ClusterIP", func(t *testing.T) {
		svcs, slices := &fakeServices{assignIP: "10.43.7.9"}, &fakeSlices{createErr: errors.New("nope")}
		ip, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, mesh)
		if err == nil {
			t.Fatal("PublishFlatService = nil on a slice failure, want an error")
		}
		if ip != "10.43.7.9" {
			t.Errorf("ClusterIP = %q, want the assigned VIP even on the partial path", ip)
		}
	})
}

// TestRemoveServices pins both retractions, including the ORDER (the slice goes
// first, so the Service never outlives its backing endpoints) and the guard that
// keeps the retired per-node cleanup off the flat Service.
func TestRemoveServices(t *testing.T) {
	t.Run("the flat pair is deleted, slice first", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, netip.MustParseAddr("100.64.1.1")); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		order := []string{}
		svcs.onDelete = func() { order = append(order, "service") }
		slices.onDelete = func() { order = append(order, "slice") }
		if err := RemoveFlatService(t.Context(), svcs, slices); err != nil {
			t.Fatalf("RemoveFlatService: %v", err)
		}
		if len(order) != 2 || order[0] != "slice" || order[1] != "service" {
			t.Errorf("delete order = %v, want [slice service]", order)
		}
		if svcs.svc != nil || slices.es != nil {
			t.Error("an object survived the retraction")
		}
	})

	t.Run("an absent pair is success", func(t *testing.T) {
		if err := RemoveFlatService(t.Context(), &fakeServices{}, &fakeSlices{}); err != nil {
			t.Errorf("RemoveFlatService on an absent pair = %v, want nil", err)
		}
		if err := RemoveClusterService(t.Context(), &fakeServices{}, &fakeSlices{}, "mac-a"); err != nil {
			t.Errorf("RemoveClusterService on an absent pair = %v, want nil", err)
		}
	})

	t.Run("the retired per-node cleanup never deletes the flat Service", func(t *testing.T) {
		for _, node := range []string{"", "k3sm"} {
			svcs, slices := &fakeServices{}, &fakeSlices{}
			if err := RemoveClusterService(t.Context(), svcs, slices, node); err != nil {
				t.Errorf("RemoveClusterService(%q) = %v, want nil", node, err)
			}
			if svcs.deletes != 0 || slices.deletes != 0 {
				t.Errorf("RemoveClusterService(%q): service deletes=%d slice deletes=%d, want 0/0", node, svcs.deletes, slices.deletes)
			}
		}
		if ClusterServiceName("mac-a") != "registry-mac-a" {
			t.Errorf("ClusterServiceName = %q, want the retired registry-<node> name", ClusterServiceName("mac-a"))
		}
	})

	t.Run("a Service delete failure still reports after the slice was removed", func(t *testing.T) {
		svcs, slices := &fakeServices{deleteErr: errors.New("nope")}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, netip.MustParseAddr("100.64.1.1")); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if err := RemoveFlatService(t.Context(), svcs, slices); err == nil {
			t.Fatal("RemoveFlatService = nil on a delete failure, want an error")
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

// List satisfies ServiceClient; the single-object fake has nothing to sweep.
func (f *fakeServices) List(context.Context, metav1.ListOptions) (*corev1.ServiceList, error) {
	return &corev1.ServiceList{}, nil
}

// List satisfies EndpointSliceClient; the single-object fake has nothing to sweep.
func (f *fakeSlices) List(context.Context, metav1.ListOptions) (*discoveryv1.EndpointSliceList, error) {
	return &discoveryv1.EndpointSliceList{}, nil
}
