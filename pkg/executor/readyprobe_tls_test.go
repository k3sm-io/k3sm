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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
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

// selfSignedPair returns a self-signed serving certificate carrying probeServerName
// and ip, so the only thing wrong with it is that no trusted CA issued it.
func selfSignedPair(t *testing.T, ip net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		DNSNames:     []string{probeServerName},
		IPAddresses:  []net.IP{ip},

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// pipeListener is a net.Listener fed by in-memory net.Pipe connections, so the
// probe's TLS handshake and request run end to end without a socket.
type pipeListener struct {
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

// dial is the probe's dialer seam: it hands the server end to Accept and returns
// the client end, whatever address the probe asked for.
func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return newAsyncWriteConn(client), nil
	case <-l.done:
	case <-ctx.Done():
	}
	_ = client.Close()
	_ = server.Close()
	return nil, errors.New("pipe listener closed")
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6443} }

// asyncWriteConn queues writes to a net.Pipe end so a write never waits for the
// peer to read, as a kernel socket buffer would not. Without it a client that
// rejects the server's certificate blocks writing its alert while the server
// blocks writing the rest of its flight, and the refusal surfaces only as the
// probe's timeout instead of as the verification error.
type asyncWriteConn struct {
	net.Conn
	mu     sync.Mutex // guards closed and sends on q
	closed bool
	q      chan []byte
}

func newAsyncWriteConn(c net.Conn) *asyncWriteConn {
	a := &asyncWriteConn{Conn: c, q: make(chan []byte, 256)}
	go func() {
		for b := range a.q {
			if _, err := c.Write(b); err != nil {
				for range a.q {
				}
				return
			}
		}
	}()
	return a
}

func (a *asyncWriteConn) Write(b []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0, net.ErrClosed
	}
	a.q <- append([]byte(nil), b...)
	return len(b), nil
}

func (a *asyncWriteConn) Close() error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.q)
	}
	a.mu.Unlock()
	return a.Conn.Close()
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
		// serving returns the server's certificate given the cluster CA.
		serving   func(clusterCA *certs.CA) *tls.Certificate
		writeCA   bool
		wantReady bool
		// wantErr is a substring of the probe failure a refused case must record, so
		// a refusal is proven to be the certificate check and not a timeout.
		wantErr string
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
			wantErr: "tls: failed to verify certificate",
		},
		{
			name:    "self-signed listener is refused",
			serving: func(*certs.CA) *tls.Certificate { p := selfSignedPair(t, loopback); return &p },
			writeCA: true,
			wantErr: "tls: failed to verify certificate",
		},
		{
			name:    "leaf issued by another CA is refused",
			serving: func(*certs.CA) *tls.Certificate { p := servingPair(t, otherCA, loopback); return &p },
			writeCA: true,
			wantErr: "tls: failed to verify certificate",
		},
		{
			name:    "no cluster CA in the work dir fails closed",
			serving: func(*certs.CA) *tls.Certificate { p := servingPair(t, otherCA, loopback); return &p },
			writeCA: false,
			wantErr: "read the cluster CA",
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
			srv := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Header.Get("Authorization") != "" {
						tokens.Add(1)
					}
					if r.URL.Path != "/healthz" || r.Header.Get("Authorization") != "Bearer "+token {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					_, _ = w.Write([]byte("ok"))
				}),
				TLSConfig: &tls.Config{Certificates: []tls.Certificate{*tc.serving(clusterCA)}},
				// Silence the handshake-failure log lines the refused cases produce.
				ErrorLog: log.New(io.Discard, "", 0),
			}
			ln := newPipeListener()
			served := make(chan struct{})
			go func() {
				defer close(served)
				_ = srv.Serve(tls.NewListener(ln, srv.TLSConfig))
			}()
			defer func() {
				_ = srv.Close()
				<-served
			}()

			s := NewSupervised(Config{WorkDir: workDir, APIServerPort: 6443, BindAddress: "127.0.0.1", Token: token})
			var dials atomic.Int32
			s.probeDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dials.Add(1)
				return ln.dial(ctx, network, addr)
			}
			defer func() {
				s.probeMu.Lock()
				if s.probe != nil {
					s.probe.CloseIdleConnections()
				}
				s.probeMu.Unlock()
			}()
			if got := s.Ready(context.Background()); got != tc.wantReady {
				t.Fatalf("Ready = %v, want %v", got, tc.wantReady)
			}
			if tc.writeCA && dials.Load() == 0 {
				t.Fatal("the probe never dialed through the seam, so the handshake was not exercised")
			}
			if tc.wantReady && requests.Load() == 0 {
				t.Fatal("Ready reported true without the server receiving the healthz request")
			}
			s.probeMu.Lock()
			probeErr := s.probeErr
			s.probeMu.Unlock()
			if !strings.Contains(probeErr, tc.wantErr) {
				t.Fatalf("probe failure = %q, want it to contain %q", probeErr, tc.wantErr)
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
