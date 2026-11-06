//go:build integration

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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/certs"
)

const (
	serverNameUnderTest = "kubernetes.default.svc"
	// serverNameTestWait bounds a request that a broken server would leave hanging.
	serverNameTestWait = 30 * time.Second
)

// TestServerNameWithAnIPAddressInServer dials a loopback server through client-go's
// real TLS path with server: holding an IP. With ServerName set, the certificate
// is verified against that name and not the dial address, and the name goes out as
// SNI. With it unset, the dial address is what is verified.
func TestServerNameWithAnIPAddressInServer(t *testing.T) {
	ca, err := certs.NewCA("test-cluster-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	loopback := []net.IP{net.ParseIP("127.0.0.1")}
	apiserverDNS := []string{"kubernetes", "kubernetes.default", serverNameUnderTest, "kubernetes.default.svc.cluster.local", "localhost"}

	for _, tc := range []struct {
		name       string
		cn         string
		dns        []string
		ips        []net.IP
		serverName string
		wantSNI    string
		wantHost   bool // a hostname mismatch is the expected refusal
	}{
		{
			name: "named leaf passes", cn: "kube-apiserver", dns: apiserverDNS, ips: loopback,
			serverName: serverNameUnderTest, wantSNI: serverNameUnderTest,
		},
		{
			name: "named leaf passes without the dial address in its SANs", cn: "kube-apiserver", dns: apiserverDNS,
			serverName: serverNameUnderTest, wantSNI: serverNameUnderTest,
		},
		{
			name: "same-CA leaf without the name is refused", cn: "worker-1", dns: []string{"worker-1", "localhost"}, ips: loopback,
			serverName: serverNameUnderTest, wantHost: true,
		},
		{
			name: "with no ServerName the dial address decides", cn: "worker-1", dns: []string{"worker-1", "localhost"}, ips: loopback,
		},
		{
			name: "with no ServerName a leaf without the dial address is refused", cn: "kube-apiserver", dns: apiserverDNS,
			wantHost: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM, err := ca.IssueServing(tc.cn, tc.dns, tc.ips, time.Hour)
			if err != nil {
				t.Fatalf("issue leaf: %v", err)
			}
			host, sni := serveVersion(t, certPEM, keyPEM)

			kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
			if err := os.WriteFile(kubeconfig, fmt.Appendf(nil, `apiVersion: v1
kind: Config
current-context: c
contexts:
- name: c
  context: {cluster: c, user: u}
clusters:
- name: c
  cluster: {server: %q}
users:
- name: u
  user: {token: t}
`, host), 0o600); err != nil {
				t.Fatalf("write kubeconfig: %v", err)
			}
			cfg, _, err := FromCheckedPathWithCA(kubeconfig, ca.CertPEM)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			cfg.ServerName = tc.serverName
			cfg.Timeout = serverNameTestWait
			cs, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				t.Fatalf("client: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), serverNameTestWait)
			defer cancel()
			_, err = cs.Discovery().RESTClient().Get().AbsPath("/version").DoRaw(ctx)
			if tc.wantHost {
				var hostErr x509.HostnameError
				if !errors.As(err, &hostErr) {
					t.Fatalf("err = %v, want an x509.HostnameError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if got, _ := sni.Load().(string); got != tc.wantSNI {
				t.Errorf("SNI = %q, want %q", got, tc.wantSNI)
			}
		})
	}
}

// serveVersion starts a TLS server with the given leaf, returning its URL, which
// holds an IP, and the SNI the last handshake carried.
func serveVersion(t *testing.T, certPEM, keyPEM []byte) (string, *atomic.Value) {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	sni := &atomic.Value{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"major":"1","minor":"0"}`)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni.Store(hello.ServerName)
			return nil, nil
		},
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, sni
}
