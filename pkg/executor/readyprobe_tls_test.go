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

package executor

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// writeClusterCA mints a cluster CA and writes its certificate where the executor
// reads it (certs.ClusterCACertPath), returning the CA for issuing leaves.
func writeClusterCA(t *testing.T, workDir string) *certs.CA {
	t.Helper()
	ca, err := certs.NewCA("k3sm-test-cluster-ca")
	if err != nil {
		t.Fatalf("new cluster CA: %v", err)
	}
	if err := os.MkdirAll(certs.PKIDir(workDir), 0o700); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	if err := os.WriteFile(certs.ClusterCACertPath(workDir), ca.CertPEM, 0o644); err != nil {
		t.Fatalf("write cluster CA: %v", err)
	}
	return ca
}

// servingPair issues a serving leaf for ip from ca as a tls.Certificate, carrying
// the name every apiserver leaf carries (probeServerName).
func servingPair(t *testing.T, ca *certs.CA, ip net.IP) tls.Certificate {
	t.Helper()
	return servingPairNames(t, ca, []string{probeServerName}, ip)
}

// servingPairNames issues a serving leaf for dnsNames and ip from ca.
func servingPairNames(t *testing.T, ca *certs.CA, dnsNames []string, ip net.IP) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueServing("kube-apiserver", dnsNames, []net.IP{ip}, time.Hour)
	if err != nil {
		t.Fatalf("issue serving leaf: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("serving keypair: %v", err)
	}
	return pair
}

// TestReadyProbeVerifiesClusterCA pins that the healthz probe, which carries the
// system:masters admin token, verifies the apiserver's serving certificate against
// the cluster CA in the work dir. A listener that took the bind address first, or
// answers while the apiserver restarts, must fail the TLS handshake, so no request
// (and so no token) ever reaches it. Without a cluster CA the probe fails closed.
func TestReadyProbeVerifiesClusterCA(t *testing.T) {
	t.Parallel()
	const token = "k3sm-readyprobe-tls"
	loopback := net.ParseIP("127.0.0.1")
	otherCA, err := certs.NewCA("k3sm-test-impostor-ca")
	if err != nil {
		t.Fatalf("new impostor CA: %v", err)
	}

	cases := []struct {
		name string
		// serving returns the server's certificate given the cluster CA; nil keeps
		// httptest's own self-signed certificate.
		serving   func(clusterCA *certs.CA) *tls.Certificate
		writeCA   bool
		wantReady bool
	}{
		{
			name:      "leaf issued by the cluster CA is accepted",
			serving:   func(ca *certs.CA) *tls.Certificate { p := servingPair(t, ca, loopback); return &p },
			writeCA:   true,
			wantReady: true,
		},
		{
			// A server without a mesh on a non-loopback --node-ip dials an IP its
			// leaf need not carry; the pinned name is what is verified.
			name:      "leaf from the cluster CA without the dialed IP is accepted",
			serving:   func(ca *certs.CA) *tls.Certificate { p := servingPair(t, ca, net.ParseIP("192.0.2.10")); return &p },
			writeCA:   true,
			wantReady: true,
		},
		{
			name: "leaf from the cluster CA without the pinned name is refused",
			serving: func(ca *certs.CA) *tls.Certificate {
				p := servingPairNames(t, ca, []string{"not-the-apiserver"}, loopback)
				return &p
			},
			writeCA: true,
		},
		{
			name:    "self-signed listener is refused",
			serving: nil,
			writeCA: true,
		},
		{
			name:    "leaf issued by another CA is refused",
			serving: func(*certs.CA) *tls.Certificate { p := servingPair(t, otherCA, loopback); return &p },
			writeCA: true,
		},
		{
			name:    "no cluster CA in the work dir fails closed",
			serving: func(*certs.CA) *tls.Certificate { p := servingPair(t, otherCA, loopback); return &p },
			writeCA: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			workDir := t.TempDir()
			var clusterCA *certs.CA
			if tc.writeCA {
				clusterCA = writeClusterCA(t, workDir)
			}
			var requests, tokens atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "" {
					tokens.Add(1)
				}
				if r.URL.Path != "/healthz" || r.Header.Get("Authorization") != "Bearer "+token {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				_, _ = w.Write([]byte("ok"))
			}))
			// Silence the handshake-failure log lines the refused cases produce.
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			if tc.serving != nil {
				srv.TLS = &tls.Config{Certificates: []tls.Certificate{*tc.serving(clusterCA)}}
			}
			srv.StartTLS()
			defer srv.Close()

			port := srv.Listener.Addr().(*net.TCPAddr).Port
			s := NewSupervised(Config{WorkDir: workDir, APIServerPort: port, BindAddress: "127.0.0.1", Token: token})
			if got := s.Ready(context.Background()); got != tc.wantReady {
				t.Fatalf("Ready = %v, want %v", got, tc.wantReady)
			}
			if !tc.wantReady && tokens.Load() != 0 {
				t.Fatalf("the admin token reached an unverified server (%d requests carried it)", tokens.Load())
			}
			if !tc.wantReady && requests.Load() != 0 {
				t.Fatalf("an unverified server received %d requests", requests.Load())
			}
		})
	}
}
