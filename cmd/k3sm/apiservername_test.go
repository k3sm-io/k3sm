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
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"k8s.io/client-go/tools/clientcmd"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// TestAPIServerNameIsOnTheIssuedLeaf ties what a worker requires to what a server
// issues, through the real assembly of the apiserver's certificate.
func TestAPIServerNameIsOnTheIssuedLeaf(t *testing.T) {
	want := kubeclient.APIServerName()
	svc, err := parseServiceCIDR(install.DefaultServiceCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if got := kubernetesServiceIP(svc).String(); got != want {
		t.Fatalf("the server derives %s, a worker requires %s", got, want)
	}
	dir, ca := tlsSANWorkDir(t)
	if _, _, err := writeAPIServerServingCert(dir, ca, tlsSANTestMesh, "", "k3sm-cp", []string{"api.example.test"}, tlsSANTestLogger); err != nil {
		t.Fatalf("issue: %v", err)
	}
	data, err := os.ReadFile(certs.APIServerServingCertPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM in the issued certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname(want); err != nil {
		t.Errorf("the apiserver leaf does not verify for %s: %v", want, err)
	}
}

// TestAPIServerNameIsOutsideEveryNodeRange pins that the ranges nodes get addresses
// from cannot yield the address.
func TestAPIServerNameIsOutsideEveryNodeRange(t *testing.T) {
	addr := netip.MustParseAddr(kubeclient.APIServerName())
	for _, p := range []netip.Prefix{podnet.ClusterPodCIDR, netip.MustParsePrefix(netv1alpha1.InterconnectCIDR)} {
		if p.Contains(addr) {
			t.Errorf("%s holds %s", p, addr)
		}
	}
}

// TestOtherClusterLeavesLeaveOutTheAPIServerAddress pins the leaves a server mints
// from the cluster CA beside the apiserver's, when a flag or a Node names the address.
func TestOtherClusterLeavesLeaveOutTheAPIServerAddress(t *testing.T) {
	reserved := net.ParseIP(kubeclient.APIServerName())

	t.Run("the server's kubelet leaf", func(t *testing.T) {
		ips := serverKubeletServingIPs(nodeOptions{nodeName: "k3sm-cp", nodeIP: reserved.String()}, "100.64.0.1")
		if slices.ContainsFunc(ips, reserved.Equal) {
			t.Errorf("IP SANs %v carry %s", ips, reserved)
		}
		if !slices.ContainsFunc(ips, net.ParseIP("100.64.0.1").Equal) {
			t.Errorf("IP SANs %v lost the mesh address", ips)
		}
	})
	t.Run("the registry's leaf", func(t *testing.T) {
		dir, _ := tlsSANWorkDir(t)
		mint := serverRegistryServingMinter(serverOptions{workDir: dir}, slog.New(slog.DiscardHandler))
		if mint == nil {
			t.Fatal("no minter")
		}
		pair, err := mint([]string{"registry-k3sm"}, []net.IP{reserved, net.ParseIP("10.43.0.9")})
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if slices.ContainsFunc(pair.Leaf.IPAddresses, reserved.Equal) {
			t.Errorf("IP SANs %v carry %s", pair.Leaf.IPAddresses, reserved)
		}
		if len(pair.Leaf.IPAddresses) != 1 {
			t.Errorf("IP SANs %v, want the Service's own address kept", pair.Leaf.IPAddresses)
		}
	})
}

// TestWorkerClientsRequireTheAPIServerName pins each worker path to the name, with
// the kubeconfig's server kept for dialling. A server's paths stay as they were.
func TestWorkerClientsRequireTheAPIServerName(t *testing.T) {
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	store := savedStore(t, res)
	path := store.kubeconfigPath()
	anchor := fixtureCA(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fileServer, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := kubeclient.APIServerName()

	t.Run("the helper's informer", func(t *testing.T) {
		k := authorizerKube{kubeconfig: path, clusterCA: "/root/ca.crt", readFile: anchorReader(regular(0, 0o644, string(anchor)), nil)}
		cfg, _, err := k.load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.ServerName != want || cfg.Host != fileServer.Host {
			t.Errorf("ServerName %q host %q, want %q and %q", cfg.ServerName, cfg.Host, want, fileServer.Host)
		}
	})
	t.Run("the helper's informer on a server", func(t *testing.T) {
		cfg, _, err := authorizerKube{kubeconfig: path}.load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.ServerName != "" {
			t.Errorf("ServerName = %q on a server", cfg.ServerName)
		}
	})

	checked, err := checkKubeconfig(raw, path, "")
	if err != nil {
		t.Fatalf("checkKubeconfig: %v", err)
	}
	checked.caPEM = anchor

	t.Run("a root verb's client", func(t *testing.T) {
		cfg, err := checked.restConfig()
		if err != nil {
			t.Fatalf("restConfig: %v", err)
		}
		if cfg.ServerName != want || !bytes.Equal(cfg.CAData, anchor) || cfg.Host != fileServer.Host {
			t.Errorf("ServerName %q host %q, CA pinned %t", cfg.ServerName, cfg.Host, bytes.Equal(cfg.CAData, anchor))
		}
	})
	t.Run("root kubectl's handoff", func(t *testing.T) {
		prev := kubeconfigHandoffDir
		kubeconfigHandoffDir = t.TempDir()
		t.Cleanup(func() { kubeconfigHandoffDir = prev })
		f, handoffPath, err := checked.handoff()
		if err != nil {
			t.Fatalf("handoff: %v", err)
		}
		defer f.Close()
		cfg, err := clientcmd.BuildConfigFromFlags("", handoffPath)
		if err != nil {
			t.Fatalf("load the handoff: %v", err)
		}
		if cfg.ServerName != want || !bytes.Equal(cfg.CAData, anchor) || cfg.Host != fileServer.Host {
			t.Errorf("ServerName %q host %q, CA pinned %t", cfg.ServerName, cfg.Host, bytes.Equal(cfg.CAData, anchor))
		}
		if orig := checked.cfg.Clusters[checked.cfg.Contexts[checked.cfg.CurrentContext].Cluster]; orig.TLSServerName != "" {
			t.Error("the handoff changed the checked entries")
		}
	})
	t.Run("root kubectl's handoff with no root copy keeps the file's trust", func(t *testing.T) {
		plain, err := checkKubeconfig(raw, path, "")
		if err != nil {
			t.Fatal(err)
		}
		if plain.pinned() != plain.cfg {
			t.Error("entries with no root copy were rewritten")
		}
	})
	t.Run("the lifecycle verbs", func(t *testing.T) {
		dataRoot := t.TempDir()
		credential := install.AgentCredentialPath(dataRoot)
		if err := os.MkdirAll(filepath.Dir(credential), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(credential, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := lifecycleClient(dataRoot, credential)
		if err != nil {
			t.Fatalf("worker: %v", err)
		}
		if cfg.ServerName != want || cfg.Host != fileServer.Host {
			t.Errorf("worker ServerName %q host %q", cfg.ServerName, cfg.Host)
		}
		admin := filepath.Join(dataRoot, "k3sm.kubeconfig")
		if err := os.WriteFile(admin, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, _, err = lifecycleClient(dataRoot, admin)
		if err != nil {
			t.Fatalf("server: %v", err)
		}
		if cfg.ServerName != "" {
			t.Errorf("server ServerName = %q", cfg.ServerName)
		}
	})
}
