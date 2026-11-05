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
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// TestAPIServerServingSANsCarryNodeIP is the gate for a server without
// --mesh-ip on a non-loopback --node-ip. The apiserver binds that address
// (executor apiServerHost), and the admin, scheduler and controller-manager
// kubeconfigs dial it, so the cluster-CA serving leaf must name it or every
// in-process client fails TLS. The rows pin that the leaf verifies for the
// node IP against the cluster CA, that a loopback node IP adds no address,
// that a --tls-san naming the node IP is issued once, and that issuing never
// changes the cluster CA pin.
//
// provisionControlPlane reads the package-level ensureHierarchy seam, which
// other tests swap, so it does not run parallel.
func TestAPIServerServingSANsCarryNodeIP(t *testing.T) {
	const nodeIP = "192.0.2.10"
	logger := slog.New(slog.DiscardHandler)
	issue := func(t *testing.T, opts serverOptions) *x509.Certificate {
		t.Helper()
		_, _, err := provisionControlPlane(context.Background(), &opts, "", logger)
		if err != nil {
			t.Fatalf("provisionControlPlane: %v", err)
		}
		return readServingLeaf(t, opts.workDir)
	}
	clusterPool := func(t *testing.T, workDir string) (*x509.CertPool, string) {
		t.Helper()
		h, err := certs.EnsureHierarchy(workDir, certs.RoleMintAuthority, certs.PostureKine)
		if err != nil {
			t.Fatalf("load hierarchy: %v", err)
		}
		caPEM, err := os.ReadFile(certs.ClusterCACertPath(workDir))
		if err != nil {
			t.Fatalf("read cluster CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			t.Fatal("cluster CA does not parse")
		}
		return pool, h.Cluster.PinHash()
	}
	count := func(leaf *x509.Certificate, ip string) int {
		n := 0
		for _, got := range leaf.IPAddresses {
			if got.Equal(net.ParseIP(ip)) {
				n++
			}
		}
		return n
	}

	t.Run("a meshless server on a non-loopback node IP is verifiable at it", func(t *testing.T) {
		opts := serverOptions{workDir: t.TempDir(), nodeName: "node-a", nodeIP: nodeIP, apiPort: 6444}
		leaf := issue(t, opts)
		pool, pin := clusterPool(t, opts.workDir)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: nodeIP, Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("the leaf does not verify for the bind address %s: %v (IPs %v)", nodeIP, err, leaf.IPAddresses)
		}
		if err := leaf.VerifyHostname(nodeIP); err != nil {
			t.Errorf("VerifyHostname(%s): %v", nodeIP, err)
		}
		// A second boot re-issues over the same CA: the pin is stable.
		issue(t, opts)
		if _, again := clusterPool(t, opts.workDir); again != pin {
			t.Errorf("re-issuing the serving leaf changed the cluster CA pin: %s -> %s", pin, again)
		}
	})

	t.Run("a loopback node IP adds no address", func(t *testing.T) {
		opts := serverOptions{workDir: t.TempDir(), nodeName: "node-a", nodeIP: "127.0.0.1", apiPort: 6444}
		leaf := issue(t, opts)
		_, fixed, err := apiServerServingSANs("", "", "node-a", nil)
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, ip := range fixed {
			want = append(want, ip.String())
		}
		if got := leafIPs(leaf); !slices.Equal(got, want) {
			t.Errorf("IP SANs = %v, want exactly the fixed set %v", got, want)
		}
	})

	t.Run("a --tls-san naming the node IP is issued once", func(t *testing.T) {
		opts := serverOptions{workDir: t.TempDir(), nodeName: "node-a", nodeIP: nodeIP, apiPort: 6444, tlsSANs: tlsSANList{nodeIP}}
		if n := count(issue(t, opts), nodeIP); n != 1 {
			t.Errorf("node IP issued %d times, want once", n)
		}
	})

	t.Run("a mesh server keeps its mesh IP and adds a distinct node IP", func(t *testing.T) {
		_, ips, err := apiServerServingSANs(tlsSANTestMesh, nodeIP, "node-a", nil)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(ips))
		for _, ip := range ips {
			got = append(got, ip.String())
		}
		if !slices.Contains(got, tlsSANTestMesh) || !slices.Contains(got, nodeIP) {
			t.Errorf("IP SANs = %v, want the mesh IP and the node IP", got)
		}
	})
}
