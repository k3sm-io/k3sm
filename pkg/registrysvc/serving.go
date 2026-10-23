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

// ServingConfig configures a ServingIdentity.
type ServingConfig struct {
	// Mint issues a fresh serving certificate. It is called once by
	// NewServingIdentity and again whenever the current one comes within Margin
	// of its expiry, or on Rotate. Required.
	Mint func() (tls.Certificate, error)
	// Margin is how long before expiry a certificate is replaced.
	Margin time.Duration
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
type ServingIdentity struct {
	cfg ServingConfig

	// mu guards cur. OnMint runs outside it.
	mu  sync.Mutex
	cur tls.Certificate
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

// Rotate replaces the certificate now, whatever its expiry: the SAN set
// changed (a Service was recreated with another ClusterIP), or it is the first.
// A failure leaves the current certificate in place.
func (s *ServingIdentity) Rotate() error {
	c, err := s.mint()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = c
	s.mu.Unlock()
	if s.cfg.OnMint != nil {
		s.cfg.OnMint(c.Leaf.NotAfter)
	}
	return nil
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
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	now := s.cfg.Now()
	if cur.Leaf != nil && now.Before(cur.Leaf.NotAfter.Add(-s.cfg.Margin)) {
		return &cur, nil
	}
	if err := s.Rotate(); err != nil {
		if cur.Leaf == nil {
			return nil, err
		}
		if now.Before(cur.Leaf.NotAfter) {
			s.cfg.Logger.Warn("could not replace the ingest registry's serving certificate before its expiry; serving the current one", "not_after", cur.Leaf.NotAfter, "err", err)
			return &cur, nil
		}
		return nil, fmt.Errorf("the registry serving certificate expired at %s and could not be replaced: %w", cur.Leaf.NotAfter.UTC().Format(time.RFC3339), err)
	}
	s.mu.Lock()
	cur = s.cur
	s.mu.Unlock()
	return &cur, nil
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
