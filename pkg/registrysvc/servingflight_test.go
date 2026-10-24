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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of a logger.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// TestServingRefreshIsSingleFlight pins the refresh contract inside the
// margin: concurrent handshakes start one mint between them and keep being
// answered with the still-valid certificate while it runs; a failed mint is
// not retried, and not logged again, until the retry window has passed; and
// the minted leaf, an ECDSA key, carries no key-encipherment usage.
func TestServingRefreshIsSingleFlight(t *testing.T) {
	var (
		mu       sync.Mutex
		now      = time.Now().Truncate(time.Second)
		mints    int
		failMint bool
		block    chan struct{}
		entered  = make(chan struct{}, 64)
	)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	ca, err := certs.NewCAWithClock("k3sm-cluster-ca", clock)
	if err != nil {
		t.Fatalf("NewCAWithClock: %v", err)
	}
	logs := &syncBuffer{}
	s, err := NewServingIdentity(ServingConfig{
		Mint: func() (tls.Certificate, error) {
			mu.Lock()
			mints++
			b, fail := block, failMint
			mu.Unlock()
			entered <- struct{}{}
			if b != nil {
				<-b
			}
			if fail {
				return tls.Certificate{}, errors.New("no CA today")
			}
			return ca.IssueRegistryServing(FlatServiceName, []string{FlatServiceName}, nil, time.Hour)
		},
		Margin: 10 * time.Minute,
		Logger: slog.New(slog.NewTextHandler(logs, nil)),
		Now:    clock,
	})
	if err != nil {
		t.Fatalf("NewServingIdentity: %v", err)
	}
	<-entered
	first := s.NotAfter()

	t.Run("the minted leaf has no key encipherment", func(t *testing.T) {
		c, err := s.GetCertificate(nil)
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if c.Leaf.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			t.Errorf("KeyUsage = %b carries KeyEncipherment, which an ECDSA key cannot perform", c.Leaf.KeyUsage)
		}
		if c.Leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			t.Errorf("KeyUsage = %b lacks DigitalSignature", c.Leaf.KeyUsage)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.Cert)
		if _, err := c.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: FlatServiceName, CurrentTime: clock(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("the leaf does not chain to the cluster CA: %v", err)
		}
	})

	t.Run("concurrent handshakes in the margin share one mint", func(t *testing.T) {
		advance(55 * time.Minute) // 5 minutes left: inside the 10-minute margin
		release := make(chan struct{})
		mu.Lock()
		mints, block = 0, release
		mu.Unlock()

		const handshakes = 16
		var wg sync.WaitGroup
		served := make(chan time.Time, handshakes)
		for range handshakes {
			wg.Go(func() {
				c, err := s.GetCertificate(nil)
				if err != nil {
					t.Errorf("GetCertificate in the margin: %v", err)
					return
				}
				served <- c.Leaf.NotAfter
			})
		}
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("no handshake started a refresh inside the margin")
		}
		// While the one mint is held, every other handshake is still answered
		// with the current, still-valid certificate; only the one that started
		// the mint waits for it.
		for range handshakes - 1 {
			select {
			case na := <-served:
				if !na.Equal(first) {
					t.Errorf("served a certificate expiring %v while the mint was held, want the current one (%v)", na, first)
				}
			case <-time.After(5 * time.Second):
				close(release)
				wg.Wait()
				mu.Lock()
				n := mints
				mu.Unlock()
				t.Fatalf("handshakes waited on the refresh instead of being served the valid certificate (%d mints started)", n)
			}
		}
		close(release)
		wg.Wait()
		if na := <-served; !na.After(first) {
			t.Errorf("the handshake that minted was served a certificate expiring %v, want the new one", na)
		}
		mu.Lock()
		n := mints
		block = nil
		mu.Unlock()
		if n != 1 {
			t.Errorf("%d handshakes started %d mints, want exactly one", handshakes, n)
		}
		if !s.NotAfter().After(first) {
			t.Errorf("NotAfter = %v after the refresh, want a later certificate than %v", s.NotAfter(), first)
		}
	})

	t.Run("a failed mint is retried once per window", func(t *testing.T) {
		advance(55 * time.Minute)
		mu.Lock()
		mints, failMint = 0, true
		mu.Unlock()
		for range 20 {
			if _, err := s.GetCertificate(nil); err != nil {
				t.Fatalf("GetCertificate = %v while the current certificate is still valid", err)
			}
		}
		drain(entered)
		mu.Lock()
		n := mints
		mu.Unlock()
		if n != 1 {
			t.Errorf("20 handshakes in the margin with a failing mint made %d attempts, want one per window", n)
		}
		if got := strings.Count(logs.String(), "could not replace"); got != 1 {
			t.Errorf("logged %d failure warnings, want one per window:\n%s", got, logs.String())
		}

		advance(defaultServingRetry + time.Second)
		for range 20 {
			if _, err := s.GetCertificate(nil); err != nil {
				t.Fatalf("GetCertificate = %v while the current certificate is still valid", err)
			}
		}
		drain(entered)
		mu.Lock()
		n = mints
		failMint = false
		mu.Unlock()
		if n != 2 {
			t.Errorf("after the retry window, %d attempts in all, want exactly one more", n)
		}

		// Once the mint works again, the next window replaces the certificate.
		before := s.NotAfter()
		advance(defaultServingRetry + time.Second)
		s.Refresh()
		if !s.NotAfter().After(before) {
			t.Errorf("NotAfter = %v after a working mint, want a certificate later than %v", s.NotAfter(), before)
		}
	})
}

func drain(c chan struct{}) {
	for {
		select {
		case <-c:
		default:
			return
		}
	}
}

// TestServingRefreshSurvivesPanickingMint pins that a mint which panics during
// a refresh unwinds the identity: the panic reaches the caller, the refresh
// lock is free (a Rotate returns), no flight is left for later handshakes to
// wait on, the attempt counts as a failure, and the refresh after the retry
// window mints again.
func TestServingRefreshSurvivesPanickingMint(t *testing.T) {
	var (
		mu     sync.Mutex
		now    = time.Now().Truncate(time.Second)
		panics bool
	)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	ca, err := certs.NewCAWithClock("k3sm-cluster-ca", clock)
	if err != nil {
		t.Fatalf("NewCAWithClock: %v", err)
	}
	s, err := NewServingIdentity(ServingConfig{
		Mint: func() (tls.Certificate, error) {
			mu.Lock()
			p := panics
			panics = false
			mu.Unlock()
			if p {
				return tls.Certificate{}, errPanicMint.raise()
			}
			return ca.IssueRegistryServing(FlatServiceName, []string{FlatServiceName}, nil, time.Hour)
		},
		Margin: 10 * time.Minute,
		Logger: slog.New(slog.NewTextHandler(&syncBuffer{}, nil)),
		Now:    clock,
	})
	if err != nil {
		t.Fatalf("NewServingIdentity: %v", err)
	}
	first := s.NotAfter()

	// Past expiry, so a wedged flight would block every handshake.
	advance(61 * time.Minute)
	mu.Lock()
	panics = true
	mu.Unlock()
	if r := handshakeRecovering(s); r != errPanicMint {
		t.Fatalf("the panicking mint's handshake recovered %v, want the mint's panic re-raised", r)
	}

	within := func(name string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { defer close(done); f() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s blocked after a panicking mint: the refresh did not unwind", name)
		}
	}

	within("a handshake inside the retry window", func() {
		if _, err := s.GetCertificate(nil); err == nil {
			t.Errorf("GetCertificate inside the retry window = nil error, want the failed attempt reported")
		}
	})
	within("Rotate", func() {
		if err := s.Rotate(); err != nil {
			t.Errorf("Rotate after a panicking mint: %v", err)
		}
	})
	rotated := s.NotAfter()
	if !rotated.After(first) {
		t.Errorf("NotAfter = %v after Rotate, want later than %v", rotated, first)
	}

	advance(55 * time.Minute) // back inside the margin of the rotated certificate
	advance(defaultServingRetry + time.Second)
	within("the refresh after the retry window", s.Refresh)
	if !s.NotAfter().After(rotated) {
		t.Errorf("NotAfter = %v after the refresh, want a certificate later than %v", s.NotAfter(), rotated)
	}
}

// panicValue is what the test mint panics with.
type panicValue string

func (p panicValue) raise() error { panic(p) }

const errPanicMint panicValue = "mint panicked"

// handshakeRecovering runs one handshake and returns what it panicked with.
func handshakeRecovering(s *ServingIdentity) (r any) {
	defer func() { r = recover() }()
	_, _ = s.GetCertificate(nil)
	return nil
}
