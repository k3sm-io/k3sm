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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestServerRunsRegistryByDefaultOverTLSWithFlatService is the server's
// registry contract in one place: the registry runs unless --registry-port 0;
// every relay address serves HTTPS whose chain verifies against the cluster CA
// for the flat name, each search-suffixed spelling, the Service ClusterIP and
// the server's mesh and vm-gateway addresses; a plain-HTTP request is refused;
// the flat registry-k3sm Service and its EndpointSlice exist with the right
// ports; local-registry-hosting names registry-k3sm:6450; and the state record
// carries the name, TLS and the certificate's expiry for k3sm status.
func TestServerRunsRegistryByDefaultOverTLSWithFlatService(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	t.Run("on by default, off with 0", func(t *testing.T) {
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		var opts serverOptions
		_ = registerServerFlags(fs, &opts)
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if opts.registryPort != 6450 || executor.DefaultRegistryPort != 6450 {
			t.Fatalf("registryPort = %d with no flag, want 6450 (on by default)", opts.registryPort)
		}

		fs = flag.NewFlagSet("server", flag.ContinueOnError)
		opts = serverOptions{}
		_ = registerServerFlags(fs, &opts)
		if err := fs.Parse([]string{"--registry-port", "0"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		// A bootstrap server that opts out runs nothing and removes the flat
		// Service an earlier boot left, so no Pod resolves a dead name.
		cs := fake.NewSimpleClientset(
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: registrysvc.FlatServiceName, Namespace: registrysvc.FlatServiceNamespace}},
		)
		stop, puller := startServerRegistry(t.Context(), serverPlan{opts: opts}, nil, cs, false, nil, logger)
		stop()
		if puller.LocalHost != "" || len(puller.ClusterRegistries) != 0 {
			t.Errorf("an opted-out registry wired the runtime: %+v", puller)
		}
		if _, err := cs.CoreV1().Services(registrysvc.FlatServiceNamespace).
			Get(context.Background(), registrysvc.FlatServiceName, metav1.GetOptions{}); err == nil {
			t.Error("the flat Service survived a boot with --registry-port 0")
		}
	})

	t.Run("HTTPS under the cluster CA, the flat Service and the discovery document", func(t *testing.T) {
		ca, err := certs.NewCA("k3sm-cluster-ca")
		if err != nil {
			t.Fatalf("NewCA: %v", err)
		}
		const (
			clusterIP = "10.43.0.20"
			meshIP    = "100.64.0.1"
			vmSubnet  = "192.168.64.0/24"
			vmGateway = "192.168.64.1"
		)
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "services", func(a k8stesting.Action) (bool, runtime.Object, error) {
			a.(k8stesting.CreateAction).GetObject().(*corev1.Service).Spec.ClusterIP = clusterIP
			return false, nil, nil
		})

		// The relay binds the mesh address and the vm gateway; the seam points
		// each at a loopback listener this test dials, so the shipped relay,
		// gate and TLS configuration serve exactly as they would there.
		var (
			mu        sync.Mutex
			listeners = map[string]net.Listener{}
			bound     = make(chan struct{}, 2)
		)
		listen := func(addr string) (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			mu.Lock()
			listeners[addr] = ln
			mu.Unlock()
			bound <- struct{}{}
			return ln, nil
		}

		workDir := t.TempDir()
		if err := registrysvc.WriteState(workDir, registrysvc.State{State: registrysvc.StateServing, Port: 6450, Addr: "127.0.0.1:6450", Since: time.Now().UTC()}); err != nil {
			t.Fatalf("WriteState: %v", err)
		}
		stop, _ := startIngestRegistry(t.Context(), ingestRegistry{
			svc: &fakeRegistry{addr: "127.0.0.1:6450"}, port: 6450, nodeName: "mac-a",
			meshIP: meshIP, vmNetSubnet: vmSubnet, workDir: workDir,
			hostingCMs:    cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:     cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			clusterSvcs:   cs.CoreV1().Services(registrysvc.FlatServiceNamespace),
			clusterSlices: cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace),
			clusterDomain: "cluster.local",
			mintServing: func(dnsNames []string, ips []net.IP) (tls.Certificate, error) {
				return ca.IssueRegistryServing(registrysvc.FlatServiceName, dnsNames, ips, time.Hour)
			},
			relayListen: listen,
			logger:      logger,
		})
		defer stop()
		for range 2 {
			select {
			case <-bound:
			case <-time.After(10 * time.Second):
				t.Fatal("the relay did not bind both its addresses")
			}
		}

		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		wantDNS := []string{
			"registry-k3sm",
			"registry-k3sm.k3sm-registry",
			"registry-k3sm.k3sm-registry.svc",
			"registry-k3sm.k3sm-registry.svc.cluster.local",
		}
		for _, relayAddr := range []string{meshIP + ":6450", vmGateway + ":6450"} {
			mu.Lock()
			ln := listeners[relayAddr]
			mu.Unlock()
			if ln == nil {
				t.Fatalf("the relay did not bind %s (bound: %v)", relayAddr, listeners)
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(),
				&tls.Config{RootCAs: pool, ServerName: registrysvc.FlatServiceName})
			if err != nil {
				t.Fatalf("TLS to the relay on %s does not verify against the cluster CA: %v", relayAddr, err)
			}
			leaf := conn.ConnectionState().PeerCertificates[0]
			_ = conn.Close()
			for _, name := range wantDNS {
				if !slices.Contains(leaf.DNSNames, name) {
					t.Errorf("%s: the certificate lacks the DNS SAN %s (has %v)", relayAddr, name, leaf.DNSNames)
				}
			}
			for _, host := range append(slices.Clone(wantDNS), clusterIP, meshIP, vmGateway) {
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
					t.Errorf("%s: the chain does not verify for %s: %v", relayAddr, host, err)
				}
			}

			plain, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = plain.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := plain.Write([]byte("GET /v2/ HTTP/1.1\r\nHost: registry-k3sm:6450\r\n\r\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			line, _ := bufio.NewReader(plain).ReadString('\n')
			_ = plain.Close()
			if !strings.Contains(line, " 400 ") {
				t.Errorf("%s: a plain-HTTP request got %q, want it refused with 400", relayAddr, strings.TrimSpace(line))
			}
		}

		svc, err := cs.CoreV1().Services(registrysvc.FlatServiceNamespace).
			Get(context.Background(), "registry-k3sm", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("the flat Service registry-k3sm is not in k3sm-registry: %v", err)
		}
		if svc.Namespace != "k3sm-registry" || len(svc.Spec.Ports) != 1 ||
			svc.Spec.Ports[0].Port != 6450 || svc.Spec.Ports[0].TargetPort.IntValue() != 6450 {
			t.Errorf("Service %s/%s ports = %+v, want 6450 to target 6450", svc.Namespace, svc.Name, svc.Spec.Ports)
		}
		es, err := cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace).
			Get(context.Background(), "registry-k3sm", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("the flat Service has no EndpointSlice: %v", err)
		}
		if len(es.Ports) != 1 || es.Ports[0].Port == nil || *es.Ports[0].Port != 6450 ||
			len(es.Endpoints) != 1 || !slices.Equal(es.Endpoints[0].Addresses, []string{meshIP}) {
			t.Errorf("EndpointSlice ports=%+v endpoints=%+v, want port 6450 at the mesh address", es.Ports, es.Endpoints)
		}

		cm, err := cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace).
			Get(context.Background(), registrysvc.HostingConfigMapName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("local-registry-hosting was not published: %v", err)
		}
		var doc map[string]string
		if err := yaml.Unmarshal([]byte(cm.Data[registrysvc.HostingDataKey]), &doc); err != nil {
			t.Fatalf("decode local-registry-hosting: %v", err)
		}
		if doc["host"] != "registry-k3sm:6450" || doc["hostFromClusterNetwork"] != "registry-k3sm:6450" {
			t.Errorf("local-registry-hosting host=%q hostFromClusterNetwork=%q, want registry-k3sm:6450 for both", doc["host"], doc["hostFromClusterNetwork"])
		}

		st := readRegistryState(t, workDir)
		if st.Service != "registry-k3sm:6450" || !st.TLS || st.CertNotAfter == nil || !st.CertNotAfter.After(time.Now()) {
			t.Errorf("state record service=%q tls=%v certNotAfter=%v, want the flat name, TLS and a future expiry", st.Service, st.TLS, st.CertNotAfter)
		}
	})
}

// readRegistryState reads the state record in workDir.
func readRegistryState(t *testing.T, workDir string) registrysvc.State {
	t.Helper()
	b, err := os.ReadFile(registrysvc.StatePath(workDir))
	if err != nil {
		t.Fatalf("read the state record: %v", err)
	}
	st, err := registrysvc.ParseState(b)
	if err != nil {
		t.Fatalf("parse the state record: %v", err)
	}
	return st
}
