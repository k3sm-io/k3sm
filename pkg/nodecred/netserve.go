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

package nodecred

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// NetserveKubeconfigFile is the kubeconfig this node's datapath (the Service
// proxy, the cluster DNS resolver and the NetworkPolicy watcher) authenticates
// to the apiserver with: the cluster CA plus the node's netserve client keypair
// (certs.NetserveSubject). It sits beside KubeconfigFile at the same 0600.
//
// It is deliberately NOT one of the five artifacts Paths lists. A node that
// joined before the netserve identity existed holds a complete credential
// without it, and counting it would turn every such node into an Absent store
// and a forced rejoin. Its absence is instead the signal for the agent to fetch
// one with the node credential it does hold.
const NetserveKubeconfigFile = "netserve.kubeconfig"

// NetserveCredential is a loaded, self-consistent netserve kubeconfig.
type NetserveCredential struct {
	APIServerURL string
	ClusterCAPEM []byte
	CertPEM      []byte
	KeyPEM       []byte
	NotAfter     time.Time
}

// NetserveKubeconfigPath is the netserve kubeconfig.
func (s Store) NetserveKubeconfigPath() string {
	return filepath.Join(s.Dir, NetserveKubeconfigFile)
}

// NetserveStatus reports whether the store holds a netserve credential this
// node can run its datapath with, returning it whenever it could be parsed.
//
// Valid requires all of: the keypair matches; the certificate is nodeName's
// netserve identity (certs.NetserveNodeName, so a credential for another node, or
// one carrying an extra group, is refused); it chains to clientCAPEM, the
// cluster's client-identity CA as this node's own credential records it (so a CA
// the cluster no longer trusts is noticed before the apiserver refuses it); and
// it is not within ExpiryMargin of NotAfter, the node credential's own margin.
//
// Unlike Status, a Corrupt verdict here is not a hard stop for the caller. The
// remedy for every non-Valid state is the same and safe to apply automatically:
// fetch a fresh certificate with the node credential, which is the authority the
// netserve identity is derived from. Overwriting it re-issues nothing the node
// credential could not re-issue anyway.
func (s Store) NetserveStatus(now time.Time, nodeName string, clientCAPEM []byte) (State, *NetserveCredential, error) {
	fsys := s.fsys()
	path := s.NetserveKubeconfigPath()
	raw, err := fsys.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Absent, nil, nil
		}
		return Corrupt, nil, netserveUnusable(path, err)
	}
	server, caPEM, certPEM, keyPEM, err := loadNodeKubeconfig(raw)
	if err != nil {
		return Corrupt, nil, netserveUnusable(path, err)
	}
	leaf, err := keyPairLeaf(certPEM, keyPEM)
	if err != nil {
		return Corrupt, nil, netserveUnusable(path, fmt.Errorf("netserve client keypair: %w", err))
	}
	cred := &NetserveCredential{APIServerURL: server, ClusterCAPEM: caPEM, CertPEM: certPEM, KeyPEM: keyPEM, NotAfter: leaf.NotAfter}
	got, ok := certs.NetserveNodeName(leaf)
	if !ok {
		return Corrupt, cred, netserveUnusable(path, fmt.Errorf("certificate subject %q (O=%v) is not a netserve identity", leaf.Subject.CommonName, leaf.Subject.Organization))
	}
	if got != nodeName {
		return Corrupt, cred, netserveUnusable(path, fmt.Errorf("certificate names node %q, not this node %q", got, nodeName))
	}
	if err := chainsTo(leaf, clientCAPEM, now); err != nil {
		return Corrupt, cred, netserveUnusable(path, err)
	}
	if !leaf.NotAfter.After(now.Add(ExpiryMargin)) {
		return Expired, cred, nil
	}
	return Valid, cred, nil
}

// chainsTo verifies leaf as a client certificate issued by the CA in caPEM, at
// now. The expiry half of the answer is NetserveStatus's own margin; this is
// about the issuer.
func chainsTo(leaf *x509.Certificate, caPEM []byte, now time.Time) error {
	ca, err := decodeCertPEM(caPEM)
	if err != nil {
		return fmt.Errorf("client-identity CA: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	// Verified at the leaf's own NotBefore when now is past NotAfter, so an
	// expired-but-otherwise-sound certificate reads as Expired, not Corrupt.
	at := now
	if !leaf.NotAfter.After(at) {
		at = leaf.NotBefore.Add(time.Minute)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("the netserve certificate does not chain to this node's client-identity CA: %w", err)
	}
	return nil
}

// netserveUnusable names the file and the automatic remedy.
func netserveUnusable(path string, err error) error {
	return fmt.Errorf("stored netserve credential %s is unusable: %w; the agent fetches a fresh one with the node credential", path, err)
}
