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

package registrysvc

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// testCA is one cluster CA per test binary: minting a CA per subtest is slow
// for no extra coverage.
var testCA = sync.OnceValues(func() (*certs.CA, error) { return certs.NewCA("k3sm-cluster-ca") })

// testServing returns a serving identity minted from testCA for the flat names.
func testServing(t *testing.T) *ServingIdentity {
	t.Helper()
	ca, err := testCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	s, err := NewServingIdentity(ServingConfig{
		Mint: func() (tls.Certificate, error) {
			return ca.IssueRegistryServing(FlatServiceName, FlatServiceDNSNames(""), FlatServingIPs("", "127.0.0.1", ""), time.Hour)
		},
		Margin: time.Minute,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("NewServingIdentity: %v", err)
	}
	return s
}

// TestServingIdentityRotation pins the rotation contract: a certificate is
// replaced once it is inside the margin, kept while a replacement fails and it
// is still valid, never served once expired, and every mint is reported.
func TestServingIdentityRotation(t *testing.T) {
	var (
		mu       sync.Mutex
		now      = time.Now().Truncate(time.Second)
		failMint bool
		mints    int
		reported []time.Time
	)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	// The CA mints on the same clock, so every leaf's expiry is relative to it.
	ca, err := certs.NewCAWithClock("k3sm-cluster-ca", clock)
	if err != nil {
		t.Fatalf("NewCAWithClock: %v", err)
	}
	s, err := NewServingIdentity(ServingConfig{
		Mint: func() (tls.Certificate, error) {
			mu.Lock()
			fail := failMint
			if !fail {
				mints++
			}
			mu.Unlock()
			if fail {
				return tls.Certificate{}, errors.New("no CA today")
			}
			return ca.IssueRegistryServing(FlatServiceName, []string{FlatServiceName}, nil, time.Hour)
		},
		Margin: 10 * time.Minute,
		OnMint: func(na time.Time) { mu.Lock(); reported = append(reported, na); mu.Unlock() },
		Logger: quietLogger(),
		Now:    clock,
	})
	if err != nil {
		t.Fatalf("NewServingIdentity: %v", err)
	}
	first := s.NotAfter()
	if mints != 1 || len(reported) != 1 || !reported[0].Equal(first) {
		t.Fatalf("mints=%d reported=%v, want one mint reported with its expiry %v", mints, reported, first)
	}

	// Well inside validity: no re-mint.
	if _, err := s.GetCertificate(nil); err != nil || mints != 1 {
		t.Fatalf("GetCertificate err=%v mints=%d, want the current certificate and no mint", err, mints)
	}

	// Inside the margin: replaced.
	advance(55 * time.Minute)
	s.Refresh()
	if mints != 2 || !s.NotAfter().After(first) || len(reported) != 2 {
		t.Fatalf("mints=%d notAfter=%v reported=%d after entering the margin, want a second, later certificate reported", mints, s.NotAfter(), len(reported))
	}

	// A failing mint inside the margin keeps serving the still-valid one.
	advance(50 * time.Minute)
	mu.Lock()
	failMint = true
	mu.Unlock()
	if _, err := s.GetCertificate(nil); err != nil {
		t.Fatalf("GetCertificate = %v while the current certificate is still valid", err)
	}

	// Expired and unreplaceable: refused, never served.
	advance(time.Hour)
	if _, err := s.GetCertificate(nil); err == nil {
		t.Fatal("an expired certificate was served")
	}

	if _, err := NewServingIdentity(ServingConfig{}); !errors.Is(err, ErrNoServingIdentity) {
		t.Errorf("NewServingIdentity with no Mint = %v, want ErrNoServingIdentity", err)
	}
	if _, err := NewServingIdentity(ServingConfig{Mint: func() (tls.Certificate, error) { return tls.Certificate{}, errors.New("x") }}); err == nil {
		t.Error("a first mint that failed still produced an identity")
	}
}

// TestFlatServingSANs pins the certificate's names: the flat name and every
// search-suffixed spelling, and the ClusterIP, mesh and vm-gateway addresses.
func TestFlatServingSANs(t *testing.T) {
	want := []string{"registry-k3sm", "registry-k3sm.k3sm-registry", "registry-k3sm.k3sm-registry.svc", "registry-k3sm.k3sm-registry.svc.cluster.local"}
	if got := FlatServiceDNSNames(""); !slices.Equal(got, want) {
		t.Errorf("FlatServiceDNSNames = %v, want %v", got, want)
	}
	if got := FlatServiceDNSNames("k3sm.test"); got[3] != "registry-k3sm.k3sm-registry.svc.k3sm.test" {
		t.Errorf("FlatServiceDNSNames(k3sm.test) = %v, want the domain followed", got)
	}
	var ips []string
	for _, ip := range FlatServingIPs("10.43.0.20", "100.64.0.1", "192.168.64.0/24") {
		ips = append(ips, ip.String())
	}
	if want := []string{"10.43.0.20", "100.64.0.1", "192.168.64.1"}; !slices.Equal(ips, want) {
		t.Errorf("FlatServingIPs = %v, want %v", ips, want)
	}
	if got := FlatServingIPs("", "not-an-ip", "garbage"); len(got) != 0 {
		t.Errorf("FlatServingIPs of nothing usable = %v, want none", got)
	}
	if FlatAuthority() != "registry-k3sm:6450" {
		t.Errorf("FlatAuthority = %q", FlatAuthority())
	}
	// darwin-net and the runtime mapping read the namespace literal; it must be
	// the namespace the advertisements (and their RBAC scope) live in.
	if FlatServiceNamespace != AdvertisementNamespace {
		t.Errorf("FlatServiceNamespace %q != AdvertisementNamespace %q", FlatServiceNamespace, AdvertisementNamespace)
	}
}

// TestRelayServesTLSOnly drives a shipped relay (NewRelay, through the Listen
// seam onto an in-memory listener): the handshake verifies against the cluster CA for the
// flat name, and a plain-HTTP request is answered 400 and never reaches the
// registry.
func TestRelayServesTLSOnly(t *testing.T) {
	ca, err := testCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	var upstreamHits int
	var hmu sync.Mutex
	upstream := &fakeZot{h: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hmu.Lock()
		upstreamHits++
		hmu.Unlock()
		w.WriteHeader(http.StatusOK)
	})}
	front := newMemListener()
	r, err := NewRelay(RelayConfig{
		Port:    6450,
		MeshIP:  "100.64.9.1",
		Serving: testServing(t),
		Listen:  func(string) (net.Listener, error) { return front, nil },
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	// The registry is the in-process fake: the gate's upstream round trip is
	// answered without a socket.
	r.handler = newGate(gateConfig{Upstream: fakeZotHost, Transport: upstream, Logger: quietLogger()})
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	go func() { defer close(done); r.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: FlatServiceName},
		DialContext:     func(context.Context, string, string) (net.Conn, error) { return front.dial() },
	}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := client.Get("https://" + FlatAuthority() + "/v2/")
	if err != nil {
		t.Fatalf("HTTPS GET through the relay: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTPS /v2/ = %d, want 200 from the registry", resp.StatusCode)
	}
	hmu.Lock()
	hitsAfterTLS := upstreamHits
	hmu.Unlock()

	conn, err := front.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// A pipe write blocks until read, and the server answers before it has
	// consumed the whole request, so the write runs beside the read.
	go func() {
		_, _ = conn.Write([]byte("GET /v2/ HTTP/1.1\r\nHost: registry-k3sm:6450\r\n\r\n"))
	}()
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Errorf("a plain-HTTP request got %q, want 400", strings.TrimSpace(line))
	}
	hmu.Lock()
	defer hmu.Unlock()
	if upstreamHits != hitsAfterTLS {
		t.Error("a plain-HTTP request reached the registry")
	}
}

// TestNewRelayRefusesWithoutServingIdentity pins that there is no plain-HTTP
// relay to configure.
func TestNewRelayRefusesWithoutServingIdentity(t *testing.T) {
	if _, err := NewRelay(RelayConfig{Port: 6450, MeshIP: "100.64.1.1", Logger: quietLogger()}); !errors.Is(err, ErrNoServingIdentity) {
		t.Fatalf("NewRelay without a serving identity = %v, want ErrNoServingIdentity", err)
	}
}
