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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/connrotation"
	"k8s.io/utils/clock"
)

// RotatingCredential is the datapath's client certificate held so it can be
// replaced while the datapath runs. The client built from it (RESTConfig)
// presents whatever pair Swap last installed on every new TLS handshake, and Swap
// closes every connection the client holds, so each informer's watch breaks and
// reconnects under the new certificate. The datapath, its informers and its
// caches keep running throughout; only the connections are new.
//
// Locking discipline: mu guards cert and leaf. The dialer tracks connections on
// its own lock and is closed outside mu.
type RotatingCredential struct {
	mu   sync.Mutex
	cert *tls.Certificate
	leaf *x509.Certificate

	dialer *connrotation.Dialer
}

// NewRotatingCredential holds the pair certPEM/keyPEM. dial opens the client's
// connections; nil uses a net.Dialer with client-go's usual timeouts.
func NewRotatingCredential(certPEM, keyPEM []byte, dial connrotation.DialFunc) (*RotatingCredential, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	c := &RotatingCredential{dialer: connrotation.NewDialer(dial)}
	if err := c.set(certPEM, keyPEM); err != nil {
		return nil, err
	}
	return c, nil
}

// set parses and installs a pair, without touching connections.
func (c *RotatingCredential) set(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("datapath client keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse the datapath client certificate: %w", err)
	}
	pair.Leaf = leaf
	c.mu.Lock()
	c.cert, c.leaf = &pair, leaf
	c.mu.Unlock()
	return nil
}

// Swap installs a new pair and closes every connection the client holds, so the
// next request, and every informer's re-watch, authenticates with it. A pair
// that does not parse is refused and the current one stays.
func (c *RotatingCredential) Swap(certPEM, keyPEM []byte) error {
	if err := c.set(certPEM, keyPEM); err != nil {
		return err
	}
	c.dialer.CloseAll()
	return nil
}

// NotAfter is the current certificate's expiry.
func (c *RotatingCredential) NotAfter() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leaf.NotAfter
}

// clientCertificate is the TLS hook: the pair current at handshake time.
func (c *RotatingCredential) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert, nil
}

// ErrCredentialInServerTrust is returned when the server-trust config handed to
// RESTConfig carries a credential of its own: the rotating pair must be the
// client's only identity.
var ErrCredentialInServerTrust = errors.New("netserve: the apiserver trust config carries a credential; the datapath's certificate must be its only identity")

// RESTConfig builds the datapath's client config: the apiserver address and
// server trust from server (Host, CA, ServerName; any credential in it is an
// error), the client-side budget (QPS, Burst, UserAgent), and a transport whose
// client certificate is this credential's current pair, dialled through the
// tracking dialer Swap closes.
func (c *RotatingCredential) RESTConfig(server *rest.Config) (*rest.Config, error) {
	if server == nil {
		return nil, errors.New("netserve: no apiserver config")
	}
	if server.BearerToken != "" || server.BearerTokenFile != "" || server.Username != "" || server.ExecProvider != nil || server.AuthProvider != nil ||
		len(server.CertData) > 0 || server.CertFile != "" || len(server.KeyData) > 0 || server.KeyFile != "" || server.Impersonate.UserName != "" {
		return nil, ErrCredentialInServerTrust
	}
	trust := &rest.Config{Host: server.Host, TLSClientConfig: rest.TLSClientConfig{
		Insecure:   server.Insecure,
		ServerName: server.ServerName,
		CAData:     server.CAData,
		CAFile:     server.CAFile,
	}}
	tlsCfg, err := rest.TLSConfigFor(trust)
	if err != nil {
		return nil, fmt.Errorf("netserve: apiserver TLS config: %w", err)
	}
	if tlsCfg == nil {
		return nil, errors.New("netserve: the apiserver is not served over TLS; a client certificate cannot authenticate")
	}
	tlsCfg.GetClientCertificate = c.clientCertificate
	tr := utilnet.SetTransportDefaults(&http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 25,
		DialContext:         c.dialer.DialContext,
	})
	return &rest.Config{
		Host:      server.Host,
		APIPath:   server.APIPath,
		QPS:       server.QPS,
		Burst:     server.Burst,
		UserAgent: server.UserAgent,
		Transport: tr,
	}, nil
}

// Rotation defaults: the credential is re-checked every RotationInterval, and
// renewed once it is within the margin the caller passes (the node
// credential's own ExpiryMargin). A renewal that fails is retried at the next
// tick, so a transient outage of the issuer costs one interval, and the margin
// is four intervals wide.
const RotationInterval = 6 * time.Hour

// Rotator keeps a RotatingCredential in date while the datapath runs.
type Rotator struct {
	// Credential is the pair being kept.
	Credential *RotatingCredential
	// Due reports whether the credential needs renewing at now. Nil means
	// "within Margin of Credential.NotAfter".
	Due func(now time.Time) bool
	// Margin is the default Due's window.
	Margin time.Duration
	// Renew obtains a fresh pair (the agent: from the bootstrap endpoint with
	// its node credential; the server: minted from the signing CA).
	Renew func(ctx context.Context) (certPEM, keyPEM []byte, err error)
	// Interval is the re-check period; RotationInterval when zero.
	Interval time.Duration
	// Clock is the time source; the real clock when nil.
	Clock clock.WithTicker
	// Logger; a discard logger when nil.
	Logger *slog.Logger
}

// Run re-checks the credential every Interval until ctx ends, renewing and
// swapping it when Due. It always returns nil when ctx ends.
func (r *Rotator) Run(ctx context.Context) error {
	clk := r.Clock
	if clk == nil {
		clk = clock.RealClock{}
	}
	interval := r.Interval
	if interval <= 0 {
		interval = RotationInterval
	}
	t := clk.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C():
			r.Tick(ctx, clk.Now())
		}
	}
}

// Tick runs one re-check at now and reports whether a new pair was installed.
// A failure is logged and left for the next tick.
func (r *Rotator) Tick(ctx context.Context, now time.Time) bool {
	log := r.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	due := r.Due
	if due == nil {
		due = func(now time.Time) bool { return !r.Credential.NotAfter().After(now.Add(r.Margin)) }
	}
	if !due(now) {
		return false
	}
	certPEM, keyPEM, err := r.Renew(ctx)
	if err != nil {
		log.Warn("renew the datapath's netserve identity; retrying at the next check", "err", err, "notAfter", r.Credential.NotAfter().UTC().Format(time.RFC3339))
		return false
	}
	if err := r.Credential.Swap(certPEM, keyPEM); err != nil {
		log.Warn("install the renewed netserve identity; retrying at the next check", "err", err)
		return false
	}
	log.Info("renewed the datapath's netserve identity; its connections reconnect under it", "notAfter", r.Credential.NotAfter().UTC().Format(time.RFC3339))
	return true
}
