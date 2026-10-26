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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/runtimed/pkg/image"
)

// testClusterCAPEM is a throwaway CA certificate standing in for the cluster CA
// a join returns.
func testClusterCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "k3sm-cluster-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestFlatRegistryHostIsTheServiceAuthority pins the flat name to the flat
// Service's authority, whose port is fixed whatever --registry-port says.
func TestFlatRegistryHostIsTheServiceAuthority(t *testing.T) {
	if want := registrysvc.FlatAuthority(); flatRegistryHost != want {
		t.Fatalf("flatRegistryHost = %q, want %q", flatRegistryHost, want)
	}
}

// TestServerFlatRegistryPullerWiring pins the server's mapping: the flat name is
// fetched from this server's own registry on loopback over plain HTTP, the
// loopback spellings at the registry's port are its aliases, the bare-name
// local registry composes with it, and runtimed accepts the whole set. A server
// with no registry maps nothing.
func TestServerFlatRegistryPullerWiring(t *testing.T) {
	m := serverFlatRegistry(7000).mapping()
	if m.Host != flatRegistryHost {
		t.Errorf("Host = %q, want %q", m.Host, flatRegistryHost)
	}
	if m.Endpoint.Addr != "127.0.0.1:7000" || m.Endpoint.TLS {
		t.Errorf("Endpoint = %+v, want plain HTTP to 127.0.0.1:7000", m.Endpoint)
	}
	for _, alias := range []string{"localhost:7000", "127.0.0.1:7000"} {
		if !slices.Contains(m.Aliases, alias) {
			t.Errorf("Aliases = %v, want %q", m.Aliases, alias)
		}
	}
	cache, err := image.NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	p, err := image.NewPuller(cache, image.RemoteFetch, image.NoLocalIndex{},
		image.WithLocalRegistry("localhost:7000"), image.WithFlatRegistry(m))
	if err != nil {
		t.Fatalf("runtimed refuses the server's flat mapping: %v", err)
	}
	if got := p.CanonicalReference("localhost:7000/team/app:v1"); got != "registry-k3sm:6450/team/app:v1" {
		t.Errorf("CanonicalReference(localhost:7000/...) = %q, want the flat name", got)
	}
	if got := serverFlatRegistry(0).mapping(); got.Host != "" {
		t.Errorf("a server with no registry maps %+v, want nothing", got)
	}
}

// publishedFlatRegistry is a fake cluster holding the flat Service and its
// EndpointSlice exactly as a bootstrap server named "boot" publishes them, with
// its relay on relayAddr at port (its --registry-port).
func publishedFlatRegistry(t *testing.T, port int, relayAddr string) *fake.Clientset {
	t.Helper()
	cs := fake.NewSimpleClientset()
	ns := registrysvc.FlatServiceNamespace
	if _, err := registrysvc.PublishFlatService(t.Context(), cs.CoreV1().Services(ns), cs.DiscoveryV1().EndpointSlices(ns),
		"boot", port, 0, netip.MustParseAddr(relayAddr)); err != nil {
		t.Fatalf("publish the flat Service: %v", err)
	}
	return cs
}

// TestAgentFlatRegistryUsesServerRegistryPort pins the agent's mapping end to
// end through agentNodeOptions and runtimedConfig: the flat name is fetched from
// the address AND the port the server published for its relay (its
// --registry-port, here not the default), over TLS verified against the cluster
// CA the join returned. The default port is the Service port every reference
// carries, not the port the relay listens on, so a server on another port must
// not leave its agents dialing the default.
func TestAgentFlatRegistryUsesServerRegistryPort(t *testing.T) {
	const serverPort = 7000
	ca := testClusterCAPEM(t)
	logger := slog.New(slog.DiscardHandler)
	res := &bootstrap.JoinResult{
		PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1",
		APIServers:   []string{"100.64.0.1:6444"},
		ClusterCAPEM: ca,
	}
	cs := publishedFlatRegistry(t, serverPort, "100.64.0.1")
	ns := registrysvc.FlatServiceNamespace
	lookup := func(cs *fake.Clientset, ca []byte, wait time.Duration) flatRegistryEndpoint {
		return lookupClusterFlatRegistry(t.Context(), cs.CoreV1().Services(ns), cs.DiscoveryV1().EndpointSlices(ns),
			ca, wait, time.Millisecond, logger)
	}

	nodeOpts := agentNodeOptions(agentOptions{}, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
	nodeOpts.flatRegistry = lookup(cs, res.ClusterCAPEM, flatRegistryLookupWait)
	m := runtimedConfig(nodeOpts, nil).FlatRegistry
	if m.Host != flatRegistryHost {
		t.Errorf("Host = %q, want %q", m.Host, flatRegistryHost)
	}
	if want := "100.64.0.1:" + strconv.Itoa(serverPort); m.Endpoint.Addr != want {
		t.Errorf("Endpoint.Addr = %q, want the server's relay at its registry port %q", m.Endpoint.Addr, want)
	}
	if !m.Endpoint.TLS || string(m.Endpoint.CAPEM) != string(ca) {
		t.Errorf("Endpoint = TLS %v CA %d bytes, want TLS against the join's cluster CA", m.Endpoint.TLS, len(m.Endpoint.CAPEM))
	}
	if !slices.Contains(m.Aliases, "localhost:"+strconv.Itoa(serverPort)) {
		t.Errorf("Aliases = %v, want localhost:%d", m.Aliases, serverPort)
	}
	cache, err := image.NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if _, err := image.NewPuller(cache, image.RemoteFetch, image.NoLocalIndex{}, image.WithFlatRegistry(m)); err != nil {
		t.Fatalf("runtimed refuses the agent's flat mapping: %v", err)
	}

	t.Run("a cluster with no registry Service maps nothing at once", func(t *testing.T) {
		start := time.Now()
		if got := lookup(fake.NewSimpleClientset(), ca, time.Hour); got.Addr != "" {
			t.Errorf("lookup = %+v, want the zero endpoint", got)
		}
		if time.Since(start) > 10*time.Second {
			t.Error("a cluster with no registry Service was waited on")
		}
	})
	t.Run("a Service whose endpoints are retracted maps nothing after the wait", func(t *testing.T) {
		cs := publishedFlatRegistry(t, serverPort, "100.64.0.1")
		if err := cs.DiscoveryV1().EndpointSlices(ns).Delete(t.Context(), registrysvc.FlatServiceName, metav1.DeleteOptions{}); err != nil {
			t.Fatalf("retract: %v", err)
		}
		if got := lookup(cs, ca, 5*time.Millisecond); got.Addr != "" {
			t.Errorf("lookup = %+v, want the zero endpoint", got)
		}
	})
	t.Run("a join with no cluster CA maps nothing", func(t *testing.T) {
		if got := lookup(cs, nil, flatRegistryLookupWait); got.Addr != "" {
			t.Errorf("lookup = %+v, want the zero endpoint", got)
		}
		if got := agentFlatRegistry(t.Context(), "/nonexistent", &bootstrap.JoinResult{}, logger); got.Addr != "" {
			t.Errorf("agentFlatRegistry = %+v, want the zero endpoint", got)
		}
	})
}

// TestJoinedServerFlatRegistryPointsAtClusterRegistry pins a joined server's
// mapping: a server that joined an existing control plane fetches the flat name
// from the bootstrap server's relay, at the address and port its EndpointSlice
// names, over TLS against the cluster CA, never from its own loopback registry,
// which would split the cluster's one image store. Its own registry stays its
// bare-name local registry, and runtimed accepts the pair.
func TestJoinedServerFlatRegistryPointsAtClusterRegistry(t *testing.T) {
	const bootstrapPort = 7000
	ca := testClusterCAPEM(t)
	logger := slog.New(slog.DiscardHandler)
	ns := registrysvc.FlatServiceNamespace
	start := func(cs *fake.Clientset, ca []byte) (func(), registryPullerWiring) {
		return startIngestRegistry(t.Context(), ingestRegistry{
			svc: &fakeRegistry{addr: "127.0.0.1:6450"}, port: 6450, nodeName: "mac-b", meshIP: "100.64.2.1",
			joined: true, clusterCAPEM: ca, flatLookupWait: 5 * time.Millisecond,
			hostingCMs:    cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:     cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			clusterSvcs:   cs.CoreV1().Services(ns),
			clusterSlices: cs.DiscoveryV1().EndpointSlices(ns),
			logger:        logger,
		})
	}

	stop, puller := start(publishedFlatRegistry(t, bootstrapPort, "100.64.0.1"), ca)
	defer stop()
	if want := "100.64.0.1:" + strconv.Itoa(bootstrapPort); puller.Flat.Addr != want {
		t.Errorf("Flat.Addr = %q, want the bootstrap server's relay %q, not this server's loopback", puller.Flat.Addr, want)
	}
	if !puller.Flat.TLS || string(puller.Flat.CAPEM) != string(ca) {
		t.Errorf("Flat = TLS %v CA %d bytes, want TLS against the cluster CA", puller.Flat.TLS, len(puller.Flat.CAPEM))
	}
	if puller.LocalHost != registrysvc.LoopbackAuthority(6450) {
		t.Errorf("LocalHost = %q, want this server's own registry %q", puller.LocalHost, registrysvc.LoopbackAuthority(6450))
	}
	cache, err := image.NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if _, err := image.NewPuller(cache, image.RemoteFetch, image.NoLocalIndex{},
		image.WithLocalRegistry(puller.LocalHost), image.WithFlatRegistry(puller.Flat.mapping())); err != nil {
		t.Fatalf("runtimed refuses the joined server's wiring: %v", err)
	}

	t.Run("no cluster registry Service maps nothing, not this server's loopback", func(t *testing.T) {
		stop, puller := start(fake.NewSimpleClientset(), ca)
		defer stop()
		if puller.Flat.Addr != "" {
			t.Errorf("Flat = %+v, want the zero endpoint", puller.Flat)
		}
	})
	t.Run("no cluster CA maps nothing", func(t *testing.T) {
		stop, puller := start(publishedFlatRegistry(t, bootstrapPort, "100.64.0.1"), nil)
		defer stop()
		if puller.Flat.Addr != "" {
			t.Errorf("Flat = %+v, want the zero endpoint", puller.Flat)
		}
	})
	t.Run("the bootstrap server still maps its own loopback", func(t *testing.T) {
		if got, want := (ingestRegistry{port: 6450}).flatRegistry(t.Context()), serverFlatRegistry(6450); got.Addr != want.Addr || got.TLS {
			t.Errorf("bootstrap Flat = %+v, want %+v", got, want)
		}
	})
}
