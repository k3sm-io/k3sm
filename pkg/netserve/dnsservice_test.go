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

package netserve

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestEnsureDNSService proves k3sm provisions the kube-system/kube-dns Service
// pinned to the DNS VIP and declaring port 53 — the declaring subject the netd port
// authorizer confirms the resolver's privileged :53 VIP bind against. Without it
// netd denies the bind ("no service declares port 53") and in-pod DNS stays dead.
func TestEnsureDNSService(t *testing.T) {
	cs := fake.NewClientset()
	s := New(Config{
		Client:        cs,
		WorkDir:       t.TempDir(),
		DNSVIP:        "10.43.0.10",
		ClusterDomain: "cluster.local",
		PodCIDR:       "100.64.1.0/24",
		NetdSocket:    "/var/lib/k3sm/run/netd.sock",
	})
	ctx := context.Background()
	if err := s.ensureDNSService(ctx); err != nil {
		t.Fatalf("ensureDNSService: %v", err)
	}

	svc, err := cs.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("kube-dns Service not created: %v", err)
	}
	if svc.Spec.ClusterIP != "10.43.0.10" {
		t.Errorf("kube-dns ClusterIP = %q, want the DNS VIP 10.43.0.10", svc.Spec.ClusterIP)
	}
	// It MUST declare port 53 on both protocols — the netd authorizer keys on the port.
	var udp53, tcp53 bool
	for _, p := range svc.Spec.Ports {
		if p.Port == 53 && p.Protocol == corev1.ProtocolUDP {
			udp53 = true
		}
		if p.Port == 53 && p.Protocol == corev1.ProtocolTCP {
			tcp53 = true
		}
	}
	if !udp53 || !tcp53 {
		t.Errorf("kube-dns must declare 53/UDP and 53/TCP, got %+v", svc.Spec.Ports)
	}
	// Selector-less: the per-node in-process resolver is the implementation.
	if len(svc.Spec.Selector) != 0 {
		t.Errorf("kube-dns must have no selector (the per-node resolver serves it), got %v", svc.Spec.Selector)
	}

	// Idempotent: a second call (Service already exists) must not error.
	if err := s.ensureDNSService(ctx); err != nil {
		t.Fatalf("ensureDNSService not idempotent: %v", err)
	}
}

// TestEnsureKubernetesEndpointSlice proves netserve provisions the
// default/kubernetes EndpointSlice the Service proxy needs for the API VIP. The
// single-node apiserver advertises 127.0.0.1 and its reconciler won't publish that
// loopback endpoint, so without this the slice is absent and the proxy resets in-pod
// HTTPS to 10.43.0.1:443 (EOF). The slice must carry the service-name label, an
// IPv4 Ready endpoint at the apiserver's loopback address, and the https/6444 port.
func TestEnsureKubernetesEndpointSlice(t *testing.T) {
	cs := fake.NewClientset()
	s := New(Config{
		Client:            cs,
		WorkDir:           t.TempDir(),
		APIServerEndpoint: "127.0.0.1:6444",
	})
	ctx := context.Background()
	if err := s.ensureKubernetesEndpointSlice(ctx); err != nil {
		t.Fatalf("ensureKubernetesEndpointSlice: %v", err)
	}

	sl, err := cs.DiscoveryV1().EndpointSlices("default").Get(ctx, "kubernetes-k3sm", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("kubernetes EndpointSlice not created: %v", err)
	}
	// The proxy maps a slice to its Service via this label — not the slice name.
	if got := sl.Labels[discoveryv1.LabelServiceName]; got != "kubernetes" {
		t.Errorf("service-name label = %q, want kubernetes (the proxy keys on it)", got)
	}
	// managed-by must NOT be the endpointslice-controller's value, or KCM GCs the slice.
	if got := sl.Labels[discoveryv1.LabelManagedBy]; got == "" || got == "endpointslice-controller.k8s.io" {
		t.Errorf("managed-by = %q, want a non-controller sentinel (else the endpointslice-controller reaps it)", got)
	}
	if sl.AddressType != discoveryv1.AddressTypeIPv4 {
		t.Errorf("AddressType = %q, want IPv4", sl.AddressType)
	}
	if len(sl.Endpoints) != 1 || len(sl.Endpoints[0].Addresses) != 1 || sl.Endpoints[0].Addresses[0] != "127.0.0.1" {
		t.Fatalf("endpoint addresses = %+v, want [127.0.0.1] (the apiserver's reachable loopback)", sl.Endpoints)
	}
	// The proxy drops non-Ready endpoints; the API backend must be Ready.
	if r := sl.Endpoints[0].Conditions.Ready; r == nil || !*r {
		t.Errorf("endpoint Ready = %v, want true (else the proxy has no backend)", r)
	}
	if len(sl.Ports) != 1 || sl.Ports[0].Port == nil || *sl.Ports[0].Port != 6444 || sl.Ports[0].Name == nil || *sl.Ports[0].Name != "https" {
		t.Fatalf("ports = %+v, want [https/6444] (must match the kubernetes Service port name)", sl.Ports)
	}

	// Idempotent: a second call (slice already exists) must not error.
	if err := s.ensureKubernetesEndpointSlice(ctx); err != nil {
		t.Fatalf("ensureKubernetesEndpointSlice not idempotent: %v", err)
	}
}
