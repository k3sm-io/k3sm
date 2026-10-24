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
	"net/netip"
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
