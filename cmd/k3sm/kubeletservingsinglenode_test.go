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
	"bytes"
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/ports"
)

// TestSingleNodeKubeletServingCertChainsToClusterCA is the gate for the single-node
// kubelet serving cert. A server with no --mesh-ip used to mint nothing, so its
// in-process node self-signed its :10250 leaf: metrics-server, which verifies each
// kubelet against kube-root-ca.crt (the cluster CA on every topology), could never
// scrape it. Every server now mints the pair from the cluster CA, as k3s does.
//
// The hierarchy is loaded exactly the way serverNodeOptions loads nodeHierarchy
// (certs.EnsureHierarchy with the server's own role and posture over a work dir the
// executor already provisioned), so the gate exercises the CA a real boot signs with.
func TestSingleNodeKubeletServingCertChainsToClusterCA(t *testing.T) {
	const (
		nodeName = "k3sm-solo"
		podCIDR  = "10.42.0.0/24"
	)
	singleNodeOpts := func() nodeOptions {
		return nodeOptions{
			nodeName:    nodeName,
			nodeIP:      loopbackNodeIP, // the single-node --node-ip default
			kubeletPort: ports.KubeletAPIPort,
			podCIDR:     podCIDR,
			netMode:     hostnet.Mode{Backend: hostnet.BackendDirect},
		}
	}
	loadHierarchy := func(t *testing.T) (*certs.Hierarchy, serverOptions) {
		t.Helper()
		opts := serverOptions{workDir: t.TempDir(), nodeName: nodeName}
		// The executor's provisioning step mints the CAs at exec.Start on every
		// topology; serverNodeOptions then LOADS them under the server's own role.
		if _, err := certs.EnsureHierarchy(opts.workDir, certs.RoleMintAuthority, certs.PostureKine); err != nil {
			t.Fatalf("provision the CA hierarchy: %v", err)
		}
		h, err := certs.EnsureHierarchy(opts.workDir, opts.role(), opts.posture())
		if err != nil {
			t.Fatalf("load the CA hierarchy as serverNodeOptions does: %v", err)
		}
		return h, opts
	}

	t.Run("the leaf chains to the cluster CA alone", func(t *testing.T) {
		hierarchy, opts := loadHierarchy(t)
		pinBefore := hierarchy.Cluster.PinHash()
		nodeOpts := singleNodeOpts()
		if err := setServerKubeletServing(&nodeOpts, hierarchy, ""); err != nil {
			t.Fatalf("setServerKubeletServing (single-node): %v", err)
		}
		// Minting a leaf never touches the CA: the join-token pin is unchanged, in
		// memory and on disk.
		reloaded, err := certs.EnsureHierarchy(opts.workDir, opts.role(), opts.posture())
		if err != nil {
			t.Fatalf("reload the CA hierarchy: %v", err)
		}
		if hierarchy.Cluster.PinHash() != pinBefore || reloaded.Cluster.PinHash() != pinBefore {
			t.Errorf("cluster CA pin changed across the mint: before %s, after %s (in memory) / %s (on disk)", pinBefore, hierarchy.Cluster.PinHash(), reloaded.Cluster.PinHash())
		}
		if len(nodeOpts.kubeletServingCertPEM) == 0 || len(nodeOpts.kubeletServingKeyPEM) == 0 {
			t.Fatal("a single-node server minted no kubelet serving pair; its node would self-sign and metrics-server's verified scrape fails")
		}
		leaf := parseCertPEM(t, nodeOpts.kubeletServingCertPEM)

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(hierarchy.Cluster.CertPEM) {
			t.Fatal("the cluster CA does not parse")
		}
		internalIP := proxyableNodeIP(nodeOpts)
		if internalIP == loopbackNodeIP {
			t.Fatalf("registered InternalIP = %s; the fixture expects the derived pod-range address", internalIP)
		}
		for _, name := range []string{nodeOpts.nodeIP, "127.0.0.1", nodeName, internalIP} {
			if _, err := leaf.Verify(x509.VerifyOptions{
				DNSName:   name,
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				t.Errorf("the leaf does not verify against the cluster CA as a server for %s: %v", name, err)
			}
		}
		// The signing (client) CA must not be what signed it: a pool of only that CA
		// must reject the leaf.
		signingPool := x509.NewCertPool()
		signingPool.AppendCertsFromPEM(hierarchy.Signing.CertPEM)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: signingPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			t.Error("the leaf verifies against the signing CA; the kubelet serving cert must come from the cluster CA")
		}
		if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
			t.Errorf("ExtKeyUsage = %v, want ServerAuth only", leaf.ExtKeyUsage)
		}
		if leaf.IsCA {
			t.Error("the kubelet serving leaf is a CA")
		}
		if !bytes.Equal(leaf.RawIssuer, hierarchy.Cluster.Cert.RawSubject) {
			t.Errorf("issuer = %q, want the cluster CA subject %q", leaf.Issuer, hierarchy.Cluster.Cert.Subject)
		}
		if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
			t.Error("the leaf is self-signed")
		}

		// What :10250 presents is that leaf, never a self-signed fallback.
		presented, err := kubeletServingCertificate(nodeOpts.kubeletServingCertPEM, nodeOpts.kubeletServingKeyPEM, nodeName, []string{nodeOpts.nodeIP, internalIP})
		if err != nil {
			t.Fatalf("kubeletServingCertificate: %v", err)
		}
		if len(presented.Certificate) == 0 || !bytes.Equal(presented.Certificate[0], leaf.Raw) {
			t.Error("kubeletServingCertificate did not return the minted leaf; a server without a mesh IP reached the self-signed path")
		}
	})

	t.Run("single-node SANs equal mesh SANs modulo the mesh IP", func(t *testing.T) {
		hierarchy, _ := loadHierarchy(t)
		const meshIP = "100.64.0.1"
		single := singleNodeOpts()
		mesh := singleNodeOpts()
		if err := setServerKubeletServing(&single, hierarchy, ""); err != nil {
			t.Fatalf("single-node mint: %v", err)
		}
		if err := setServerKubeletServing(&mesh, hierarchy, meshIP); err != nil {
			t.Fatalf("mesh mint: %v", err)
		}
		s, m := parseCertPEM(t, single.kubeletServingCertPEM), parseCertPEM(t, mesh.kubeletServingCertPEM)
		if !slices.Equal(s.DNSNames, m.DNSNames) {
			t.Errorf("DNS SANs differ: single-node %v, mesh %v", s.DNSNames, m.DNSNames)
		}
		meshMinus := slices.DeleteFunc(slices.Clone(m.IPAddresses), net.ParseIP(meshIP).Equal)
		if !slices.EqualFunc(s.IPAddresses, meshMinus, net.IP.Equal) {
			t.Errorf("IP SANs: single-node %v, mesh without %s %v", s.IPAddresses, meshIP, meshMinus)
		}
		if hasIPSAN(s, meshIP) {
			t.Errorf("the single-node leaf names a mesh IP: %v", s.IPAddresses)
		}
	})

	t.Run("a nil hierarchy or a key-less CA fails closed", func(t *testing.T) {
		hierarchy, _ := loadHierarchy(t)
		keyless := &certs.Hierarchy{Cluster: &certs.CA{Cert: hierarchy.Cluster.Cert, CertPEM: hierarchy.Cluster.CertPEM}, Signing: hierarchy.Signing}
		for name, h := range map[string]*certs.Hierarchy{"nil hierarchy": nil, "key-less cluster CA": keyless} {
			t.Run(name, func(t *testing.T) {
				nodeOpts := singleNodeOpts()
				if err := setServerKubeletServing(&nodeOpts, h, ""); err == nil {
					t.Fatal("a single-node server minted nothing and reported success; its node would self-sign")
				}
				if len(nodeOpts.kubeletServingCertPEM) != 0 || len(nodeOpts.kubeletServingKeyPEM) != 0 {
					t.Error("a failed mint left material on the node options")
				}
			})
		}
	})

	// Non-goal of this change: the single-node apiserver still names no
	// --kubelet-certificate-authority, and the mesh/enroll machinery stays unarmed.
	t.Run("single-node provisioning sets no kubelet CA and no mesh hierarchy", func(t *testing.T) {
		opts := serverOptions{workDir: t.TempDir(), nodeName: nodeName, nodeIP: loopbackNodeIP, apiPort: 6444}
		cfg, pki, err := provisionControlPlane(context.Background(), &opts, "", slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("provisionControlPlane (single-node): %v", err)
		}
		if cfg.KubeletCAFile != "" {
			t.Errorf("KubeletCAFile = %q on single-node; --kubelet-certificate-authority stays unset there in this change", cfg.KubeletCAFile)
		}
		if pki.hierarchy != nil {
			t.Error("single-node provisioning armed the mesh PKI hierarchy")
		}
	})
}
