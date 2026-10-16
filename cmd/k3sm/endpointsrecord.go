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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"time"

	"k3sm.io/darwin-net/pkg/tcpseg"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/status"
)

// The endpoints record (status.EndpointsRecord) is how an unprivileged `k3sm
// status` learns which hosts name this cluster's apiserver, so it can anchor
// the user's kubeconfig to it. The node daemon publishes it at start, through
// writeFileAtomic, 0644 in the status directory.

// endpointHosts is the host set of an endpoints record: leaf's DNS and IP
// SANs plus extra, canonical, deduplicated and sorted.
func endpointHosts(leaf *x509.Certificate, extra ...string) []string {
	set := map[string]bool{}
	add := func(h string) {
		if h == "" {
			return
		}
		if a, err := netip.ParseAddr(h); err == nil {
			h = a.Unmap().String()
		}
		set[h] = true
	}
	if leaf != nil {
		for _, d := range leaf.DNSNames {
			add(d)
		}
		for _, ip := range leaf.IPAddresses {
			add(ip.String())
		}
	}
	for _, h := range extra {
		add(h)
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// publishEndpoints writes the endpoints record into statusDir, 0644. A missing
// status directory (a work dir outside an install) writes nothing.
func publishEndpoints(statusDir string, port int, hosts []string, now time.Time) error {
	if _, err := os.Stat(statusDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	rec := status.EndpointsRecord{UpdatedAt: now.UTC(), Port: port, Hosts: hosts}
	return writeFileAtomic(status.EndpointsPath(statusDir), rec, 0o644)
}

// publishServerEndpoints publishes a server's record: its serving
// certificate's SANs, loopback and this Mac's interface addresses, at the
// apiserver port. A failure is logged and survivable; the record only anchors
// an unprivileged report.
func publishServerEndpoints(workDir string, port int, logger *slog.Logger) {
	certFile := certs.APIServerServingCertPath(workDir)
	raw, err := os.ReadFile(certFile)
	var leaf *x509.Certificate
	if err == nil {
		leaf, err = firstCertificate(raw)
	}
	if err != nil {
		logger.Warn("could not read the apiserver serving certificate for the endpoints record", "path", certFile, "err", err)
		return
	}
	extra := []string{"127.0.0.1", "::1", "localhost"}
	for _, a := range localAddrs() {
		extra = append(extra, a.String())
	}
	if err := publishEndpoints(status.Dir(workDir), port, endpointHosts(leaf, extra...), time.Now()); err != nil {
		logger.Warn("could not publish the endpoints record for `k3sm status`", "err", err)
	}
}

// firstCertificate parses the first certificate of a PEM bundle.
func firstCertificate(raw []byte) (*x509.Certificate, error) {
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no certificate block")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// apiserverLeafDial dials one TCP connection to an apiserver.
type apiserverLeafDial func(ctx context.Context, addr string) (net.Conn, error)

// verifiedAPIServerLeaf reads the serving certificate the apiserver at
// apiserverURL presents, over a handshake VERIFIED against caPEM (the node
// credential's pinned cluster CA): only a certificate this node already trusts
// for that host contributes its SANs.
func verifiedAPIServerLeaf(ctx context.Context, apiserverURL string, caPEM []byte, dial apiserverLeafDial) (*x509.Certificate, error) {
	u, err := url.Parse(apiserverURL)
	if err != nil {
		return nil, fmt.Errorf("parse the apiserver URL %q: %w", apiserverURL, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the node credential carries no cluster CA")
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	raw, err := dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: u.Hostname(), RootCAs: roots, MinVersion: tls.VersionTLS12})
	defer func() { _ = tc.Close() }()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("the apiserver presented no certificate")
	}
	return chain[0], nil
}

// runAgentEndpointsPublisher publishes an agent's record once its apiserver
// answers a verified handshake: the join host, the apiserver URL's host and the
// SANs of the certificate it presents, at the URL's port. The apiserver is
// reached over the mesh, which may still be coming up, so it retries every
// interval until it has published or ctx ends.
func runAgentEndpointsPublisher(ctx context.Context, statusDir, apiserverURL, joinHost string, caPEM []byte, dial apiserverLeafDial, interval time.Duration, logger *slog.Logger) {
	u, err := url.Parse(apiserverURL)
	if err != nil {
		logger.Warn("not publishing the endpoints record: the apiserver URL does not parse", "url", apiserverURL, "err", err)
		return
	}
	port := 443
	if p := u.Port(); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			logger.Warn("not publishing the endpoints record: the apiserver port does not parse", "url", apiserverURL)
			return
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		hctx, cancel := context.WithTimeout(ctx, statusAPITimeout)
		leaf, err := verifiedAPIServerLeaf(hctx, apiserverURL, caPEM, dial)
		cancel()
		if err == nil {
			hosts := endpointHosts(leaf, joinHost, u.Hostname())
			if err := publishEndpoints(statusDir, port, hosts, time.Now()); err != nil {
				logger.Warn("could not publish the endpoints record for `k3sm status`", "err", err)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// agentEndpointsRetry is how often an agent retries the handshake its
// endpoints record waits on.
const agentEndpointsRetry = 5 * time.Second

// clampedDial is the production apiserverLeafDial: a segment-clamped TCP dial.
func clampedDial(ctx context.Context, addr string) (net.Conn, error) {
	return (&tcpseg.Dialer{Timeout: statusAPITimeout}).DialContext(ctx, "tcp", addr)
}

// agentStatusDir is the status directory beside an agent work dir. It is a
// function here because agent.go's run scope names a local `status`.
func agentStatusDir(workDir string) string { return status.Dir(workDir) }
