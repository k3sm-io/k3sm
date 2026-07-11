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

// TestStaticAPIServerBackends pins the kubernetes-VIP static-backend derivation
// (the replacement for the withdrawn EndpointSlice provisioning: upstream
// validation hard-rejects loopback endpoint addresses on CREATE — the k8s.io
// "may not be in the loopback range" rule — so no slice can ever carry the
// single-node apiserver's 127.0.0.1:6444; the proxy carries it statically
// instead). A valid endpoint yields one always-Ready default/kubernetes backend;
// a malformed one errors so New degrades loudly rather than routing nowhere.
func TestStaticAPIServerBackends(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
		wantIP   string
		wantPort int32
	}{
		{"loopback apiserver", "127.0.0.1:6444", false, "127.0.0.1", 6444},
		{"custom port", "127.0.0.1:7443", false, "127.0.0.1", 7443},
		{"missing port", "127.0.0.1", true, "", 0},
		{"not host:port", "nonsense", true, "", 0},
		{"port out of range", "127.0.0.1:70000", true, "", 0},
		{"empty", "", true, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			static, err := staticAPIServerBackends(tt.endpoint)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("staticAPIServerBackends(%q) = %v, want error", tt.endpoint, static)
				}
				return
			}
			if err != nil {
				t.Fatalf("staticAPIServerBackends(%q): %v", tt.endpoint, err)
			}
			eps := static["default/kubernetes"]
			if len(eps) != 1 {
				t.Fatalf("default/kubernetes backends = %+v, want exactly one", eps)
			}
			if eps[0].IP != tt.wantIP || eps[0].Port != tt.wantPort {
				t.Errorf("backend = %s:%d, want %s:%d", eps[0].IP, eps[0].Port, tt.wantIP, tt.wantPort)
			}
			// The proxy drops non-Ready endpoints; the API backend must be Ready.
			if !eps[0].Ready {
				t.Errorf("backend Ready = false, want true (else the proxy has no backend)")
			}
		})
	}
}
