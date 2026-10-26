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
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
)

// TestRegistryNodePortIsOptInAndGated is the opt-in NodePort's contract. With no
// --registry-node-port the flat Service is a ClusterIP Service and no node opens
// a NodePort for it. With one, it is a NodePort Service on exactly that port,
// whose one endpoint is still the relay; and the relay that answers there runs
// the push gate, so an anonymous read is served and an anonymous PUT is refused
// before it reaches the registry.
func TestRegistryNodePortIsOptInAndGated(t *testing.T) {
	const meshIP = "100.64.1.1"
	mesh := netip.MustParseAddr(meshIP)

	t.Run("no NodePort without the flag", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, 0, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		if svcs.svc.Spec.Type != corev1.ServiceTypeClusterIP {
			t.Errorf("Type = %q, want ClusterIP when no NodePort was asked for", svcs.svc.Spec.Type)
		}
		for _, p := range svcs.svc.Spec.Ports {
			if p.NodePort != 0 {
				t.Errorf("port %q carries NodePort %d with the flag off", p.Name, p.NodePort)
			}
		}
	})

	t.Run("turning the flag off moves the Service back to ClusterIP", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, 30650, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		// The apiserver defaults the traffic policy on a NodePort Service.
		svcs.svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 6450, 0, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		got := svcs.svc.Spec
		if got.Type != corev1.ServiceTypeClusterIP || got.Ports[0].NodePort != 0 || got.ExternalTrafficPolicy != "" {
			t.Errorf("after the flag is dropped: type=%q nodePort=%d policy=%q, want ClusterIP, 0 and none",
				got.Type, got.Ports[0].NodePort, got.ExternalTrafficPolicy)
		}
	})

	t.Run("with the flag, a NodePort Service on exactly that port", func(t *testing.T) {
		svcs, slices := &fakeServices{}, &fakeSlices{}
		for range 2 {
			if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", 14507, 30650, mesh); err != nil {
				t.Fatalf("PublishFlatService: %v", err)
			}
		}
		spec := svcs.svc.Spec
		if spec.Type != corev1.ServiceTypeNodePort {
			t.Fatalf("Type = %q, want NodePort", spec.Type)
		}
		if spec.Selector != nil {
			t.Errorf("Selector = %v, want none: the endpoint is hand-written", spec.Selector)
		}
		if len(spec.Ports) != 1 {
			t.Fatalf("Ports = %d, want 1", len(spec.Ports))
		}
		p := spec.Ports[0]
		if p.NodePort != 30650 || p.Port != FlatServicePort || p.TargetPort.IntValue() != 14507 {
			t.Errorf("nodePort/port/targetPort = %d/%d/%d, want 30650/%d/14507", p.NodePort, p.Port, p.TargetPort.IntValue(), FlatServicePort)
		}
		if svcs.updates != 0 {
			t.Errorf("an unchanged NodePort Service was rewritten %d times", svcs.updates)
		}
		// Only the apiserver's NodePort range is accepted.
		for _, bad := range []int{-1, 6450, 29999, 32768} {
			if _, err := FlatService("mac-a", 14507, bad); err == nil {
				t.Errorf("FlatService(nodePort=%d) = nil error, want a refusal", bad)
			}
		}
	})

	t.Run("an anonymous PUT through it is refused", func(t *testing.T) {
		z, zaddr := socketZot(t)
		registryPort := portOf(t, zaddr)
		svcs, slices := &fakeServices{}, &fakeSlices{}
		if _, err := PublishFlatService(t.Context(), svcs, slices, "mac-a", registryPort, 30650, mesh); err != nil {
			t.Fatalf("PublishFlatService: %v", err)
		}
		// The NodePort forwards to the Service's endpoint. That endpoint must be
		// an address the relay binds, on the relay's port, and never the
		// registry's own loopback listener.
		es := slices.es
		endpoint := net.JoinHostPort(es.Endpoints[0].Addresses[0], strconv.Itoa(int(*es.Ports[0].Port)))
		if want := net.JoinHostPort(meshIP, strconv.Itoa(registryPort)); endpoint != want {
			t.Fatalf("the NodePort's backend = %s, want the relay at %s", endpoint, want)
		}
		if strings.HasPrefix(endpoint, "127.") {
			t.Fatalf("the NodePort's backend %s is the registry's loopback listener, which bypasses the gate", endpoint)
		}

		ca, err := testCA()
		if err != nil {
			t.Fatalf("NewCA: %v", err)
		}
		front := newMemListener()
		var (
			mu    sync.Mutex
			bound []string
		)
		r, err := NewRelay(RelayConfig{
			Port:    registryPort,
			MeshIP:  meshIP,
			Auth:    GateAuth{Tokens: &fakeTokens{}, Access: &fakeAccess{allow: func(*authzv1.SubjectAccessReview) bool { return false }}, Namespaces: &fakeNamespaces{}},
			Serving: testServing(t),
			Listen: func(addr string) (net.Listener, error) {
				mu.Lock()
				bound = append(bound, addr)
				mu.Unlock()
				return front, nil
			},
			GateCredential: gateCred,
			Logger:         quietLogger(),
		})
		if err != nil {
			t.Fatalf("NewRelay: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); r.Run(ctx) }()
		t.Cleanup(func() { cancel(); <-done })

		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: FlatServiceName},
			DialContext:     func(context.Context, string, string) (net.Conn, error) { return front.dial() },
		}
		t.Cleanup(tr.CloseIdleConnections)
		client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
		base := "https://" + endpoint

		get, err := client.Get(base + "/v2/app/manifests/v1")
		if err != nil {
			t.Fatalf("anonymous GET through the NodePort's backend: %v", err)
		}
		_, _ = io.Copy(io.Discard, get.Body)
		_ = get.Body.Close()
		if get.StatusCode != http.StatusOK {
			t.Errorf("anonymous GET = %d, want 200: reads stay anonymous", get.StatusCode)
		}

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, base+"/v2/team/app/manifests/v1", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("build the PUT: %v", err)
		}
		put, err := client.Do(req)
		if err != nil {
			t.Fatalf("anonymous PUT through the NodePort's backend: %v", err)
		}
		_, _ = io.Copy(io.Discard, put.Body)
		_ = put.Body.Close()
		if put.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous PUT = %d, want 401 from the push gate", put.StatusCode)
		}
		if put.Header.Get("WWW-Authenticate") == "" {
			t.Error("the refused PUT carries no challenge")
		}
		for _, seen := range z.requests() {
			if seen.method != http.MethodGet {
				t.Errorf("the registry saw %s %s; an anonymous write must never reach it", seen.method, seen.uri)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if want := net.JoinHostPort(meshIP, strconv.Itoa(registryPort)); len(bound) != 1 || bound[0] != want {
			t.Errorf("the relay bound %v, want exactly the endpoint %s", bound, want)
		}
	})
}
