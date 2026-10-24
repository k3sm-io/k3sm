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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// The SERVING IDENTITY: the TLS certificate every relay address presents.
//
// The relay is the registry's only off-loopback face, and it serves HTTPS and
// nothing else. The certificate is issued by the cluster CA (the anchor every
// Pod already trusts through its service-account ca.crt), minted in this
// process's memory and never written to disk, and re-minted before it expires,
// the way the push gate's own apiserver identity is. zot itself stays plain
// HTTP on loopback: TLS terminates here, in front of it.

// ErrNoServingIdentity reports a relay configured without a serving identity.
// The relay refuses to start rather than serve plain HTTP off loopback.
var ErrNoServingIdentity = errors.New("the ingest registry relay serves HTTPS only and has no serving certificate")

// defaultServingRetry is how long a failed replacement waits before the next
// attempt when ServingConfig.Retry is unset.
const defaultServingRetry = time.Minute

// ServingConfig configures a ServingIdentity.
type ServingConfig struct {
	// Mint issues a fresh serving certificate. It is called once by
	// NewServingIdentity and again whenever the current one comes within Margin
	// of its expiry, or on Rotate. Required.
	Mint func() (tls.Certificate, error)
	// Margin is how long before expiry a certificate is replaced.
	Margin time.Duration
	// Retry is how long a failed replacement waits before the next attempt:
	// the handshakes in between are served the current certificate while it is
	// valid, and the failure is logged once per attempt. Zero means one minute.
	Retry time.Duration
	// OnMint is told the expiry of every certificate minted, so the state record
	// can report it. nil means nobody is told.
	OnMint func(notAfter time.Time)
	// Logger receives rotation failures. nil means slog.Default.
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// ServingIdentity holds the relay's current serving certificate and replaces it
// before it expires. It is safe for concurrent use: every TLS handshake reads it.
//
// A replacement inside the margin is a single flight: the first handshake to
// see the certificate in the margin mints, and every other handshake meanwhile
// is answered with the current certificate while it is valid (or waits for the
// mint when it has expired). A failed mint is not attempted again until Retry
// has passed.
type ServingIdentity struct {
	cfg ServingConfig

	// mintMu serialises mints and the store of their result, so a Rotate and a
	// refresh can never leave the older certificate current. It is taken before
	// mu, never while mu is held.
	mintMu sync.Mutex

	// mu guards cur, flight, nextTry and lastErr. Mint and OnMint run outside it.
	mu  sync.Mutex
	cur tls.Certificate
	// flight is non-nil while a refresh mint runs, and closed when it ends.
	flight chan struct{}
	// nextTry is the earliest time a refresh is attempted after a failed one;
	// lastErr is that failure.
	nextTry time.Time
	lastErr error
}

// NewServingIdentity mints the first certificate and returns the identity. A
// mint that fails here is returned: there is no certificate to serve, so the
// caller must not start a listener.
func NewServingIdentity(cfg ServingConfig) (*ServingIdentity, error) {
	if cfg.Mint == nil {
		return nil, ErrNoServingIdentity
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Retry <= 0 {
		cfg.Retry = defaultServingRetry
	}
	s := &ServingIdentity{cfg: cfg}
	if err := s.Rotate(); err != nil {
		return nil, err
	}
	return s, nil
}

// mint issues a certificate and makes sure its leaf is parsed, so expiry is
// always readable.
func (s *ServingIdentity) mint() (tls.Certificate, error) {
	c, err := s.cfg.Mint()
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(c.Certificate) == 0 {
		return tls.Certificate{}, errors.New("mint the registry serving certificate: the minted pair carries no certificate")
	}
	if c.Leaf == nil {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse the registry serving certificate: %w", err)
		}
		c.Leaf = leaf
	}
	return c, nil
}

// replace mints a certificate and makes it current, under mintMu. A failure
// leaves the current certificate in place. OnMint is told of a success.
func (s *ServingIdentity) replace() (tls.Certificate, error) {
	c, err := s.mintAndStore()
	if err != nil {
		return tls.Certificate{}, err
	}
	if s.cfg.OnMint != nil {
		s.cfg.OnMint(c.Leaf.NotAfter)
	}
	return c, nil
}

// mintAndStore mints a certificate and makes it current while holding mintMu,
// which is released on every exit, a panicking Mint included.
func (s *ServingIdentity) mintAndStore() (tls.Certificate, error) {
	s.mintMu.Lock()
	defer s.mintMu.Unlock()
	c, err := s.mint()
	if err != nil {
		return tls.Certificate{}, err
	}
	s.mu.Lock()
	s.cur = c
	s.nextTry, s.lastErr = time.Time{}, nil
	s.mu.Unlock()
	return c, nil
}

// Rotate replaces the certificate now, whatever its expiry and whatever the
// retry window: the SAN set changed (a Service was recreated with another
// ClusterIP), or it is the first. A failure leaves the current certificate in
// place.
func (s *ServingIdentity) Rotate() error {
	_, err := s.replace()
	return err
}

// Refresh replaces the certificate when it is within the margin of expiry, and
// does nothing otherwise. A failed replacement is logged, and the current
// certificate is served for as long as it is still valid.
func (s *ServingIdentity) Refresh() {
	if _, err := s.current(); err != nil {
		s.cfg.Logger.Error("the ingest registry's serving certificate expired and could not be replaced: HTTPS handshakes fail until it is", "err", err)
	}
}

// NotAfter is the current certificate's expiry.
func (s *ServingIdentity) NotAfter() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur.Leaf == nil {
		return time.Time{}
	}
	return s.cur.Leaf.NotAfter
}

// current returns the certificate to present, replacing it first when it is
// within the margin of expiry. It fails only when the certificate has expired
// and no replacement could be minted: an expired certificate is never served.
func (s *ServingIdentity) current() (*tls.Certificate, error) {
	for {
		s.mu.Lock()
		cur := s.cur
		now := s.cfg.Now()
		if cur.Leaf != nil && now.Before(cur.Leaf.NotAfter.Add(-s.cfg.Margin)) {
			s.mu.Unlock()
			return &cur, nil
		}
		valid := cur.Leaf != nil && now.Before(cur.Leaf.NotAfter)
		if ch := s.flight; ch != nil {
			s.mu.Unlock()
			if valid {
				return &cur, nil
			}
			<-ch // expired: nothing to serve until the running mint ends
			continue
		}
		if now.Before(s.nextTry) {
			err := s.lastErr
			s.mu.Unlock()
			if valid {
				return &cur, nil
			}
			return nil, expiredError(cur, err)
		}
		ch := make(chan struct{})
		s.flight = ch
		s.mu.Unlock()

		c, err := s.refresh(ch, now)
		if err == nil {
			return &c, nil
		}
		if valid {
			s.cfg.Logger.Warn("could not replace the ingest registry's serving certificate before its expiry; serving the current one",
				"not_after", cur.Leaf.NotAfter, "retry_in", s.cfg.Retry, "err", err)
			return &cur, nil
		}
		return nil, expiredError(cur, err)
	}
}

// errMintPanicked is the failure recorded for a refresh whose Mint or OnMint
// panicked; the panic itself still reaches the caller.
var errMintPanicked = errors.New("mint the registry serving certificate: the mint panicked")

// refresh runs the single-flight replacement current started with flight ch,
// and ends the flight on every exit: flight is cleared, ch is closed, and a
// failure (a panic included, which is not recovered) holds the next attempt
// back until Retry has passed.
func (s *ServingIdentity) refresh(ch chan struct{}, now time.Time) (c tls.Certificate, err error) {
	returned := false
	defer func() {
		if !returned {
			err = errMintPanicked
		}
		s.mu.Lock()
		s.flight = nil
		if err != nil {
			s.nextTry, s.lastErr = now.Add(s.cfg.Retry), err
		}
		s.mu.Unlock()
		close(ch)
	}()
	c, err = s.replace()
	returned = true
	return c, err
}

// expiredError reports that no certificate can be served: the current one has
// expired (or there is none) and its replacement failed with err.
func expiredError(cur tls.Certificate, err error) error {
	if cur.Leaf == nil {
		return err
	}
	return fmt.Errorf("the registry serving certificate expired at %s and could not be replaced: %w", cur.Leaf.NotAfter.UTC().Format(time.RFC3339), err)
}

// GetCertificate is the tls.Config hook: every handshake is answered with the
// current certificate.
func (s *ServingIdentity) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.current()
}

// TLSConfig is the server configuration every relay listener serves: TLS 1.2
// or later, HTTP/1.1 only (the gate's ordering relies on 100-continue as Go's
// HTTP/1.1 server implements it), and the current certificate on every
// handshake.
func (s *ServingIdentity) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
		GetCertificate: s.GetCertificate,
	}
}
