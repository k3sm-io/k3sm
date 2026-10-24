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

package main

import (
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestRegistryNodePortFlag pins --registry-node-port: off by default, refused
// outside the NodePort range or with the registry turned off, and carried to the
// Service the bootstrap server publishes.
func TestRegistryNodePortFlag(t *testing.T) {
	parse := func(t *testing.T, args ...string) serverOptions {
		t.Helper()
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		var opts serverOptions
		_ = registerServerFlags(fs, &opts)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		return opts
	}
	logger := slog.New(slog.DiscardHandler)

	t.Run("off by default", func(t *testing.T) {
		if opts := parse(t); opts.registryNodePort != 0 {
			t.Errorf("registryNodePort = %d with no flag, want 0", opts.registryNodePort)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		for _, tc := range []struct {
			args []string
			want string
		}{
			{[]string{"--registry-node-port", "6450"}, "outside the NodePort range"},
			{[]string{"--registry-node-port", "40000"}, "outside the NodePort range"},
			{[]string{"--registry-node-port", "30650", "--registry-port", "0"}, "--registry-port 0"},
		} {
			opts := parse(t, tc.args...)
			err := validateServerOptions(&opts, nil, logger)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v: err = %v, want one naming %q", tc.args, err, tc.want)
			}
		}
	})

	t.Run("the published Service carries the NodePort", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		r := ingestRegistry{
			port: 6450, nodePort: 30650, nodeName: "mac-a", meshIP: "100.64.0.1",
			clusterSvcs:   cs.CoreV1().Services(registrysvc.FlatServiceNamespace),
			clusterSlices: cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace),
			logger:        logger,
		}
		if _, ok := r.publishFlatService(t.Context()); !ok {
			t.Fatal("the flat Service was not published")
		}
		svc, err := cs.CoreV1().Services(registrysvc.FlatServiceNamespace).Get(t.Context(), registrysvc.FlatServiceName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get the Service: %v", err)
		}
		if svc.Spec.Type != corev1.ServiceTypeNodePort || svc.Spec.Ports[0].NodePort != 30650 {
			t.Errorf("type=%q nodePort=%d, want NodePort 30650", svc.Spec.Type, svc.Spec.Ports[0].NodePort)
		}
	})

	t.Run("an unallocatable NodePort leaves the cluster Service standing", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "services", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if a.(k8stesting.CreateAction).GetObject().(*corev1.Service).Spec.Ports[0].NodePort != 0 {
				return true, nil, errors.New("provided port is already allocated")
			}
			return false, nil, nil
		})
		r := ingestRegistry{
			port: 6450, nodePort: 30650, nodeName: "mac-a",
			clusterSvcs:   cs.CoreV1().Services(registrysvc.FlatServiceNamespace),
			clusterSlices: cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace),
			logger:        logger,
		}
		if _, err := r.publishFlat(t.Context(), netip.MustParseAddr("100.64.0.1")); err != nil {
			t.Fatalf("publishFlat: %v", err)
		}
		svc, err := cs.CoreV1().Services(registrysvc.FlatServiceNamespace).Get(t.Context(), registrysvc.FlatServiceName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("the cluster Service is gone with the NodePort: %v", err)
		}
		if svc.Spec.Type != corev1.ServiceTypeClusterIP {
			t.Errorf("type = %q, want the ClusterIP Service", svc.Spec.Type)
		}
	})
}

// TestRegistryNodePortServingSANs pins how the server feeds the NodePort SANs
// into the serving certificate: with the flag off it reads no Node and the set
// is exactly the in-cluster one; with it on, the server's own Node and hostname
// are added, a moved address is a change (the refresh re-mints on it), and a
// failed Node read keeps the addresses it already names.
func TestRegistryNodePortServingSANs(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	server := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "k3sm-studio"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "172.16.5.10"},
			{Type: corev1.NodeHostName, Address: "k3sm-studio"},
		}},
	}
	ipStrings := func(ips []net.IP) []string {
		var out []string
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out
	}
	newRegistry := func(cs *fake.Clientset, nodePort int) ingestRegistry {
		return ingestRegistry{
			nodePort: nodePort, nodeName: "k3sm-studio", meshIP: "100.64.0.1",
			nodes:    cs.CoreV1().Nodes(),
			hostname: func() (string, error) { return "Studio.local", nil },
			logger:   logger,
		}
	}

	t.Run("flag off: no Node read, the in-cluster set exactly", func(t *testing.T) {
		cs := fake.NewSimpleClientset(server)
		r := newRegistry(cs, 0)
		sans := &servingSANs{clusterIP: "10.43.0.20", ext: r.nodePortSANs(t.Context(), registrysvc.NodePortSANs{})}
		for _, a := range cs.Actions() {
			if a.GetResource().Resource == "nodes" {
				t.Errorf("the flag-off server read a Node: %v", a)
			}
		}
		dnsNames, ips := r.servingSANSet(sans)
		if want := registrysvc.FlatServiceDNSNames(""); !slices.Equal(dnsNames, want) {
			t.Errorf("DNS SANs = %v, want exactly %v", dnsNames, want)
		}
		if got, want := ipStrings(ips), []string{"10.43.0.20", "100.64.0.1"}; !slices.Equal(got, want) {
			t.Errorf("IP SANs = %v, want exactly %v", got, want)
		}
	})

	t.Run("flag on: the server's Node and hostname are named", func(t *testing.T) {
		cs := fake.NewSimpleClientset(server)
		r := newRegistry(cs, 30650)
		sans := &servingSANs{clusterIP: "10.43.0.20", ext: r.nodePortSANs(t.Context(), registrysvc.NodePortSANs{})}
		dnsNames, ips := r.servingSANSet(sans)
		if want := append(registrysvc.FlatServiceDNSNames(""), "studio.local", "studio"); !slices.Equal(dnsNames, want) {
			t.Errorf("DNS SANs = %v, want %v", dnsNames, want)
		}
		if got, want := ipStrings(ips), []string{"10.43.0.20", "100.64.0.1", "172.16.5.10"}; !slices.Equal(got, want) {
			t.Errorf("IP SANs = %v, want %v", got, want)
		}

		// Unchanged: no re-mint.
		_, prev := sans.snapshot()
		if sans.setExt(r.nodePortSANs(t.Context(), prev)) {
			t.Error("an unchanged Node reads as a change")
		}
		// The address moved: a change, and the next mint names the new one.
		moved := server.DeepCopy()
		moved.Status.Addresses[0].Address = "172.16.5.11"
		if _, err := cs.CoreV1().Nodes().Update(t.Context(), moved, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update the Node: %v", err)
		}
		_, prev = sans.snapshot()
		if !sans.setExt(r.nodePortSANs(t.Context(), prev)) {
			t.Fatal("a moved InternalIP does not read as a change, so nothing re-mints")
		}
		if _, ips := r.servingSANSet(sans); !slices.Contains(ipStrings(ips), "172.16.5.11") || slices.Contains(ipStrings(ips), "172.16.5.10") {
			t.Errorf("IP SANs after the move = %v, want the new InternalIP only", ipStrings(ips))
		}

		// A failed read keeps the addresses already named.
		cs.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver unavailable")
		})
		_, prev = sans.snapshot()
		if sans.setExt(r.nodePortSANs(t.Context(), prev)) {
			t.Error("a failed Node read changed the SAN set")
		}
	})

	t.Run("flag on, Node not registered yet: the hostname alone", func(t *testing.T) {
		r := newRegistry(fake.NewSimpleClientset(), 30650)
		ext := r.nodePortSANs(t.Context(), registrysvc.NodePortSANs{})
		if len(ext.IPs) != 0 || !slices.Equal(ext.DNS, []string{"studio.local", "studio"}) {
			t.Errorf("ext = %+v, want the hostname names and no address", ext)
		}
	})
}
