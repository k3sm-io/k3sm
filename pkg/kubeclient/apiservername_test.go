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

package kubeclient

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/certs"
)

// wantAPIServerName is the first address of the cluster's Service range. It is a
// literal here so a change to the derivation is a test failure.
const wantAPIServerName = "10.43.0.1"

// verifyLeaf judges certPEM as client-go's TLS configuration for cfg would on a
// handshake: against the configured roots, for the configured name, as a server. The
// tagged test in servername_integration_test.go runs the same cases over a connection.
func verifyLeaf(t *testing.T, cfg *rest.Config, certPEM []byte) error {
	t.Helper()
	clientTLS, err := rest.TLSConfigFor(cfg)
	if err != nil {
		t.Fatalf("TLSConfigFor: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM in the leaf")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     clientTLS.RootCAs,
		DNSName:   clientTLS.ServerName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// TestWorkerConfigAcceptsOnlyTheAPIServerLeaf takes the client config a worker
// builds and pins which leaves of the same CA pass.
func TestWorkerConfigAcceptsOnlyTheAPIServerLeaf(t *testing.T) {
	ca, err := certs.NewCA("test-cluster-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	otherCA, err := certs.NewCA("other-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	apiserverIP := net.ParseIP(wantAPIServerName)
	nodeIP := net.ParseIP("100.64.3.1")
	serverDNS := []string{"kubernetes", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local", "localhost"}

	path := writeCheckedFixture(t, inlineCluster(otherCA.CertPEM), inlineUser, "")
	withCA, _, err := FromCheckedPathWithCA(path, ca.CertPEM)
	if err != nil {
		t.Fatalf("FromCheckedPathWithCA: %v", err)
	}
	if withCA.ServerName != wantAPIServerName {
		t.Errorf("ServerName = %q, want %q", withCA.ServerName, wantAPIServerName)
	}
	if withCA.Host != "https://127.0.0.1:6443" {
		t.Errorf("Host = %q, want the file's server for dialling", withCA.Host)
	}

	tests := []struct {
		name     string
		issuer   *certs.CA
		cn       string
		dns      []string
		ips      []net.IP
		wantHost bool
		wantAuth bool
	}{
		{name: "the apiserver leaf passes", issuer: ca, cn: "kube-apiserver", dns: serverDNS, ips: []net.IP{apiserverIP, net.ParseIP("100.64.0.1"), net.ParseIP("127.0.0.1")}},
		{name: "a kubelet leaf of the same CA is refused", issuer: ca, cn: "worker-1", dns: []string{"worker-1", "localhost"}, ips: []net.IP{nodeIP}, wantHost: true},
		{name: "a leaf naming the DNS form alone is refused", issuer: ca, cn: "kubernetes.default.svc", dns: []string{"kubernetes.default.svc"}, ips: []net.IP{nodeIP}, wantHost: true},
		{name: "a leaf naming every fixed DNS form is refused", issuer: ca, cn: "kubernetes", dns: serverDNS, ips: []net.IP{nodeIP}, wantHost: true},
		{name: "the apiserver's names under another CA are refused", issuer: otherCA, cn: "kube-apiserver", dns: serverDNS, ips: []net.IP{apiserverIP}, wantAuth: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM, _, err := tt.issuer.IssueServing(tt.cn, tt.dns, tt.ips, time.Hour)
			if err != nil {
				t.Fatalf("issue leaf: %v", err)
			}
			err = verifyLeaf(t, withCA, certPEM)
			var hostErr x509.HostnameError
			var authErr x509.UnknownAuthorityError
			switch {
			case tt.wantHost && !errors.As(err, &hostErr):
				t.Errorf("verify = %v, want an x509.HostnameError", err)
			case tt.wantAuth && !errors.As(err, &authErr):
				t.Errorf("verify = %v, want an x509.UnknownAuthorityError", err)
			case !tt.wantHost && !tt.wantAuth && err != nil:
				t.Errorf("verify = %v, want it accepted", err)
			}
		})
	}
}

// TestFromCheckedWorkerPath pins the name on a worker's credential with its own CA.
func TestFromCheckedWorkerPath(t *testing.T) {
	ca, err := certs.NewCA("test-cluster-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	cfg, cs, err := FromCheckedWorkerPath(writeCheckedFixture(t, inlineCluster(ca.CertPEM), inlineUser, ""))
	if err != nil || cs == nil {
		t.Fatalf("FromCheckedWorkerPath: clientset %v, err %v", cs, err)
	}
	if cfg.ServerName != wantAPIServerName || cfg.Host != "https://127.0.0.1:6443" {
		t.Errorf("ServerName %q host %q", cfg.ServerName, cfg.Host)
	}
	apiserver, _, err := ca.IssueServing("kube-apiserver", nil, []net.IP{net.ParseIP(wantAPIServerName)}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLeaf(t, cfg, apiserver); err != nil {
		t.Errorf("verify = %v, want the apiserver leaf accepted", err)
	}
	insecure, _, err := FromCheckedWorkerPath(writeCheckedFixture(t, "    insecure-skip-tls-verify: true", inlineUser, ""))
	if err != nil {
		t.Fatalf("FromCheckedWorkerPath: %v", err)
	}
	if insecure.Insecure {
		t.Error("insecure-skip-tls-verify applied to a worker's credential")
	}
	path := writeCheckedFixture(t, inlineCluster(ca.CertPEM), "    tokenFile: /elsewhere/token", "")
	if _, _, err := FromCheckedWorkerPath(path); !errors.Is(err, ErrCredentialsNotInline) {
		t.Errorf("err = %v, want ErrCredentialsNotInline", err)
	}
}
