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
	"math/big"
	"slices"
	"strconv"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
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

// TestFlatRegistryHostCarriesTheDefaultRegistryPort pins the flat name's port to
// the registry's default port, which the agent dials the server at.
func TestFlatRegistryHostCarriesTheDefaultRegistryPort(t *testing.T) {
	if want := "registry-k3sm:" + strconv.Itoa(executor.DefaultRegistryPort); flatRegistryHost != want {
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

// TestAgentFlatRegistryPullerWiring pins the agent's mapping end to end through
// agentNodeOptions and runtimedConfig: the flat name is fetched from the
// server's mesh address (the apiserver host the join advertised) at the default
// registry port, over TLS verified against the cluster CA the join returned.
func TestAgentFlatRegistryPullerWiring(t *testing.T) {
	ca := testClusterCAPEM(t)
	res := &bootstrap.JoinResult{
		PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1",
		APIServers:   []string{"100.64.0.1:6444"},
		ClusterCAPEM: ca,
	}
	nodeOpts := agentNodeOptions(agentOptions{}, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
	m := runtimedConfig(nodeOpts, nil).FlatRegistry
	if m.Host != flatRegistryHost {
		t.Errorf("Host = %q, want %q", m.Host, flatRegistryHost)
	}
	if want := "100.64.0.1:" + strconv.Itoa(executor.DefaultRegistryPort); m.Endpoint.Addr != want {
		t.Errorf("Endpoint.Addr = %q, want the server's mesh address %q", m.Endpoint.Addr, want)
	}
	if !m.Endpoint.TLS || string(m.Endpoint.CAPEM) != string(ca) {
		t.Errorf("Endpoint = TLS %v CA %d bytes, want TLS against the join's cluster CA", m.Endpoint.TLS, len(m.Endpoint.CAPEM))
	}
	if !slices.Contains(m.Aliases, "localhost:6450") {
		t.Errorf("Aliases = %v, want localhost:6450", m.Aliases)
	}
	cache, err := image.NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if _, err := image.NewPuller(cache, image.RemoteFetch, image.NoLocalIndex{}, image.WithFlatRegistry(m)); err != nil {
		t.Fatalf("runtimed refuses the agent's flat mapping: %v", err)
	}

	t.Run("a join that advertised no apiserver host maps nothing", func(t *testing.T) {
		bare := &bootstrap.JoinResult{PodCIDR: res.PodCIDR, MeshIP: res.MeshIP, ClusterCAPEM: ca}
		nodeOpts := agentNodeOptions(agentOptions{}, bare, "/k", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
		if got := runtimedConfig(nodeOpts, nil).FlatRegistry; got.Host != "" {
			t.Errorf("FlatRegistry = %+v, want the zero mapping", got)
		}
	})
	t.Run("a join with no cluster CA maps nothing", func(t *testing.T) {
		noCA := &bootstrap.JoinResult{PodCIDR: res.PodCIDR, MeshIP: res.MeshIP, APIServers: res.APIServers}
		if got := agentFlatRegistry(noCA); got.Addr != "" {
			t.Errorf("agentFlatRegistry = %+v, want the zero endpoint", got)
		}
	})
}
