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
