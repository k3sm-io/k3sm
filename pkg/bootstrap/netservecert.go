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

package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// netserveCertVerb names the netserve issuance verb in its rejection logs.
const netserveCertVerb = "netserve certificate issuance"

// ErrNetserveCertUnsupported reports that the control plane does not serve
// NetserveCertPath: it runs a k3sm older than this node. The remedy is to upgrade
// the server first, which is the documented order. Compare with errors.Is.
var ErrNetserveCertUnsupported = errors.New("bootstrap: the control plane does not issue netserve certificates (upgrade the server first)")

// handleNetserveCert serves the netserve issuance verb: it signs the calling
// node's netserve CSR into a CN=k3sm:netserve:<node>, O=k3sm:netservers client
// certificate.
//
// Authentication is the node's own client certificate, through the same two
// checks the endpoint refresh and the deregistration run, in the same order:
// verifiedNodeLeaf (401), then authorizeNodeSelf (403), which requires
// O=system:nodes and binds the body's node name to the certificate's. A netserve
// certificate therefore cannot obtain another one (it is not in system:nodes),
// and a node can obtain one for its own name and no other.
//
// The issued certificate never outlives the node certificate that obtained it:
// its lifetime is the configured node lifetime capped at the presenting leaf's
// remaining validity. So the datapath identity rotates with the node identity it
// was derived from, and a node whose credential has lapsed cannot keep its
// datapath alive by re-presenting a certificate the listener would refuse.
func (s *Server) handleNetserveCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	leaf := s.verifiedNodeLeaf(w, r, netserveCertVerb)
	if leaf == nil {
		return
	}

	var req NetserveCertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode netserve certificate request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.authorizeNodeSelf(w, leaf, req.NodeName, netserveCertVerb) {
		return
	}

	csr, err := parseCSR(req.CSRPEM)
	if err != nil {
		s.cfg.Logger.Warn(netserveCertVerb+" rejected", "reason", "csr-parse", "node", req.NodeName, "err", err)
		http.Error(w, "parse netserve CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	validFor := netserveValidity(s.cfg.NodeCertTTL, leaf.NotAfter, time.Now())
	if validFor <= 0 {
		s.cfg.Logger.Warn(netserveCertVerb+" rejected", "reason", "node-cert-expired", "node", req.NodeName)
		http.Error(w, "the presenting node certificate has expired", http.StatusForbidden)
		return
	}
	certPEM, err := ApproveAndSignNetserveCSR(s.cfg.SigningCA, csr, req.NodeName, validFor)
	if err != nil {
		s.cfg.Logger.Warn(netserveCertVerb+" rejected", "reason", "csr-denied", "node", req.NodeName, "err", err)
		http.Error(w, "netserve CSR denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(NetserveCertResponse{CertPEM: string(certPEM)}); err != nil {
		s.cfg.Logger.Error("encode netserve certificate response", "node", req.NodeName, "err", err)
		return
	}
	s.cfg.Logger.Info("issued netserve certificate", "node", req.NodeName,
		"cn", certs.NetserveUserPrefix+req.NodeName, "validFor", validFor.Round(time.Second).String())
}

// netserveValidity is the lifetime of a netserve certificate issued on the
// strength of a node certificate expiring at nodeNotAfter: ttl, capped at the
// node certificate's remaining validity. A non-positive result means the node
// certificate has already lapsed.
func netserveValidity(ttl time.Duration, nodeNotAfter, now time.Time) time.Duration {
	remaining := nodeNotAfter.Sub(now)
	if ttl <= 0 || remaining < ttl {
		return remaining
	}
	return ttl
}

// FetchNetserveCert obtains this node's netserve client keypair from the
// supervisor: it mints a P-256 key that never leaves the node, POSTs a CSR over
// it to NetserveCertPath, and returns the issued certificate with the key. client
// must present the node's own certificate (NodeIdentityClient); serverURL is the
// bootstrap base URL (https://<host>:9345).
//
// The returned certificate is checked before it is returned: it must name
// nodeName's netserve identity and pair with the key, so a server answering with
// anything else is an error here rather than a credential the datapath later
// fails to authenticate with.
//
// A 404 is ErrNetserveCertUnsupported: a control plane older than this node.
func FetchNetserveCert(ctx context.Context, client *http.Client, serverURL, nodeName string) (certPEM, keyPEM []byte, err error) {
	if nodeName == "" {
		return nil, nil, errors.New("fetch netserve certificate: no node name")
	}
	keyPEM, csrPEM, err := generateCSR(certs.NetserveSubject(nodeName), nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("generate netserve CSR: %w", err)
	}
	body, err := json.Marshal(NetserveCertRequest{NodeName: nodeName, CSRPEM: string(csrPEM)})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal netserve certificate request: %w", err)
	}
	url := strings.TrimRight(serverURL, "/") + NetserveCertPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("build netserve certificate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("post netserve certificate request to %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("%w: %s answered 404", ErrNetserveCertUnsupported, url)
	}
	if resp.StatusCode/100 != 2 {
		msg := make([]byte, 512)
		n, _ := resp.Body.Read(msg)
		return nil, nil, fmt.Errorf("netserve certificate request rejected (%s): %s", resp.Status, strings.TrimSpace(string(msg[:n])))
	}
	var out NetserveCertResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("decode netserve certificate response: %w", err)
	}
	if err := CheckNetserveKeyPair([]byte(out.CertPEM), keyPEM, nodeName); err != nil {
		return nil, nil, fmt.Errorf("the issued netserve certificate: %w", err)
	}
	return []byte(out.CertPEM), keyPEM, nil
}

// CheckNetserveKeyPair reports whether certPEM and keyPEM are a matching pair
// whose certificate is nodeName's netserve identity (certs.NetserveNodeName).
func CheckNetserveKeyPair(certPEM, keyPEM []byte, nodeName string) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("netserve keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return errors.New("netserve keypair carries no certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse netserve certificate: %w", err)
	}
	got, ok := certs.NetserveNodeName(leaf)
	if !ok {
		return fmt.Errorf("certificate subject %q (O=%v) is not a netserve identity", leaf.Subject.CommonName, leaf.Subject.Organization)
	}
	if got != nodeName {
		return fmt.Errorf("certificate names node %q, not %q", got, nodeName)
	}
	return nil
}
