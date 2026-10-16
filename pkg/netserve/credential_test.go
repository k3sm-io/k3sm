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

package netserve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	clocktesting "k8s.io/utils/clock/testing"

	"k3sm.io/k3sm/pkg/certs"
)

// pipeDialer hands out the client end of a net.Pipe per dial and keeps the
// server ends, so a test can see a connection being closed without a socket.
type pipeDialer struct {
	mu    sync.Mutex
	peers []net.Conn
}

func (d *pipeDialer) dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	d.mu.Lock()
	d.peers = append(d.peers, server)
	d.mu.Unlock()
	return client, nil
}

// closed reports whether peer i saw its client end close.
func (d *pipeDialer) closed(t *testing.T, i int) bool {
	t.Helper()
	d.mu.Lock()
	peer := d.peers[i]
	d.mu.Unlock()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := peer.Read(make([]byte, 1))
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

func leafOf(t *testing.T, c *tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return leaf
}

// TestRotatorRenewsBeforeExpiryAndSwaps drives the rotation on a fake clock: no
// renewal while the certificate is outside the margin; at the first tick inside
// it the Rotator renews, the client presents the new pair on the next handshake,
// and every connection opened under the old pair is closed so its watch
// reconnects. A renewal that fails is retried at the next tick and the old pair
// stays in use meanwhile.
func TestRotatorRenewsBeforeExpiryAndSwaps(t *testing.T) {
	ca, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	oldCert, oldKey, err := ca.IssueNetserveClient("worker-a", 30*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	newCert, newKey, err := ca.IssueNetserveClient("worker-a", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	d := &pipeDialer{}
	cred, err := NewRotatingCredential(oldCert, oldKey, d.dial)
	if err != nil {
		t.Fatalf("NewRotatingCredential: %v", err)
	}
	conn, err := cred.dialer.DialContext(context.Background(), "tcp", "apiserver:6444")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fc := clocktesting.NewFakeClock(time.Now())
	var attempts, renewals atomic.Int32
	rot := &Rotator{
		Credential: cred,
		Margin:     24 * time.Hour,
		Interval:   6 * time.Hour,
		Clock:      fc,
		Renew: func(context.Context) ([]byte, []byte, error) {
			if attempts.Add(1) == 1 { // the first renewal attempt fails
				return nil, nil, errors.New("the issuer is unreachable")
			}
			renewals.Add(1)
			return newCert, newKey, nil
		},
	}
	oldNotAfter := cred.NotAfter()

	if rot.Tick(context.Background(), fc.Now()) {
		t.Fatal("renewed at 30h to expiry, outside the 24h margin")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rot.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	waitTicker := func() {
		deadline := time.Now().Add(5 * time.Second)
		for !fc.HasWaiters() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}

	// 6h in: 24h left, inside the margin; the attempt fails and nothing moves.
	waitTicker()
	fc.Step(6 * time.Hour)
	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if attempts.Load() != 1 || renewals.Load() != 0 || !cred.NotAfter().Equal(oldNotAfter) {
		t.Fatal("a failed renewal changed the credential")
	}

	// 12h in: the next tick retries and succeeds.
	fc.Step(6 * time.Hour)
	deadline = time.Now().Add(5 * time.Second)
	for renewals.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if renewals.Load() != 1 {
		t.Fatalf("renewals = %d after the retry tick, want 1", renewals.Load())
	}
	deadline = time.Now().Add(5 * time.Second)
	for cred.NotAfter().Equal(oldNotAfter) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	presented, err := cred.clientCertificate(nil)
	if err != nil {
		t.Fatalf("clientCertificate: %v", err)
	}
	want, _ := tls.X509KeyPair(newCert, newKey)
	if !leafOf(t, presented).Equal(leafOf(t, &want)) {
		t.Error("the client does not present the renewed pair after the swap")
	}
	if !d.closed(t, 0) {
		t.Error("the connection opened under the old pair stayed open; its watch would keep the old identity")
	}
}

// TestRotatingCredentialRESTConfig pins the client config: the apiserver trust
// half only, the rotating pair as the only identity through a custom
// transport, and a refusal of a trust config that carries a credential.
func TestRotatingCredentialRESTConfig(t *testing.T) {
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	c, k, err := ca.IssueNetserveClient("worker-a", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cred, err := NewRotatingCredential(c, k, nil)
	if err != nil {
		t.Fatalf("NewRotatingCredential: %v", err)
	}
	trust := &rest.Config{Host: "https://100.64.0.1:6444", QPS: 7, Burst: 9, TLSClientConfig: rest.TLSClientConfig{CAData: ca.CertPEM, ServerName: "kubernetes"}}
	cfg, err := cred.RESTConfig(trust)
	if err != nil {
		t.Fatalf("RESTConfig: %v", err)
	}
	if cfg.Transport == nil || len(cfg.CertData) != 0 || cfg.BearerToken != "" || cfg.Host != trust.Host || cfg.QPS != 7 || cfg.Burst != 9 {
		t.Errorf("config = %+v; want the trust half, the budget, and a custom transport as the only credential", cfg)
	}
	if _, err := rest.HTTPClientFor(cfg); err != nil {
		t.Errorf("client-go refuses the config: %v", err)
	}
	for name, bad := range map[string]*rest.Config{
		"bearer token": {Host: trust.Host, BearerToken: "admin"},
		"client cert":  {Host: trust.Host, TLSClientConfig: rest.TLSClientConfig{CertData: c, KeyData: k}},
		"impersonate":  {Host: trust.Host, Impersonate: rest.ImpersonationConfig{UserName: "system:admin"}},
	} {
		if _, err := cred.RESTConfig(bad); !errors.Is(err, ErrCredentialInServerTrust) {
			t.Errorf("%s: err = %v, want ErrCredentialInServerTrust", name, err)
		}
	}
	if err := cred.Swap([]byte("not a cert"), k); err == nil {
		t.Error("Swap accepted a pair that does not parse")
	}
}
