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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/certs"
)

// The node credential store's file names. They are the on-disk contract between
// the agent that writes them and everything that reads them.
const (
	KubeconfigFile     = "node.kubeconfig"
	ServingCertFile    = "kubelet-serving.crt"
	ServingKeyFile     = "kubelet-serving.key"
	ClientCAFile       = "kubelet-client-ca.crt"
	NodeAssignmentFile = "node-assignment.json"
)

// ExpiryMargin is how far ahead of the node client certificate's NotAfter a
// stored credential is already treated as expired.
//
// It is not a renewal window — nothing renews in process yet. It is the margin
// that decides WHICH failure an operator gets: a restart inside the margin
// still has a working token path available and reports "supply a token",
// whereas a restart past NotAfter with no token has already lost the node. A
// day is the smallest margin that survives a Mac being asleep over a weekend
// evening and still being restarted on Monday with the same answer.
const ExpiryMargin = 24 * time.Hour

// State is what the store holds, as the start decision sees it.
type State int

const (
	// Absent: at least one of the five artifacts is missing — this node has
	// never completed a join, or its state was wiped.
	Absent State = iota
	// Corrupt: every artifact is present but one of them does not parse, or a
	// private key does not match its certificate. Always accompanied by an
	// error naming the file.
	Corrupt
	// Expired: the credential is intact but no longer usable — the node client
	// cert is within ExpiryMargin of NotAfter, or the kubelet serving cert is
	// already past it.
	Expired
	// Valid: present, parseable, matched, and in date.
	Valid
)

// String renders the state for logs and reports.
func (s State) String() string {
	switch s {
	case Absent:
		return "absent"
	case Corrupt:
		return "corrupt"
	case Expired:
		return "expired"
	case Valid:
		return "valid"
	}
	return fmt.Sprintf("State(%d)", int(s))
}

// FS is the read surface a Store needs: whether an artifact is there, and its
// bytes. It exists so a reporting caller can describe a store no unprivileged
// test could create on a real disk, and so `k3sm status`'s own filesystem seam
// can be handed straight to Status.
//
// A nil FS means the real filesystem.
type FS interface {
	Stat(name string) (fs.FileInfo, error)
	ReadFile(name string) ([]byte, error)
}

// osFS is the real filesystem.
type osFS struct{}

func (osFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }
func (osFS) ReadFile(name string) ([]byte, error)  { return os.ReadFile(name) }

// Assignment is the non-credential half of a join outcome — the values the
// SERVER decided and this node cannot re-derive locally. Its JSON is the
// on-disk shape of NodeAssignmentFile.
type Assignment struct {
	// PodCIDR is the /24 assigned to this node: the mesh device's own prefix
	// and the pod IPAM range, which are one value by design.
	PodCIDR string `json:"podCIDR"`
	// MeshIP is this node's mesh-egress /32 — the source address its Service
	// proxy re-originates cross-node dials from.
	MeshIP string `json:"meshIP"`
	// APIServers are the advertised apiserver endpoints (host:port) the node's
	// kubeconfig targets; empty against a single-node server.
	APIServers []string `json:"apiServers,omitempty"`
	// Peers is the peer snapshot as of the last join. It is the SEED only: the
	// MeshPeer watch replaces it with live state moments after bring-up, so a
	// stale entry here costs one reconcile, not correctness.
	Peers []netv1.MeshPeerSpec `json:"peers,omitempty"`
}

// Credential is a loaded, parsed, self-consistent stored join outcome.
type Credential struct {
	APIServerURL string
	ClusterCAPEM []byte
	// ClusterCAPin is certs.CertPin over ClusterCAPEM — the pin a join token is
	// compared against.
	ClusterCAPin   string
	ClientCertPEM  []byte
	ClientKeyPEM   []byte
	ServingCertPEM []byte
	ServingKeyPEM  []byte
	ClientCAPEM    []byte
	Assignment     Assignment

	ClientNotAfter  time.Time
	ServingNotAfter time.Time
}

// Store is the agent work dir viewed as the home of one node's persisted join
// outcome, for READING. It owns path derivation, the load, the validation and
// the Status verdict — so no caller open-codes a file name or an expiry rule.
//
// Writing stays with the agent (cmd/k3sm), which is the only process that has
// a join outcome to persist. This package is the read half precisely so the
// report and the daemon cannot disagree: `k3sm status` reporting "valid" about
// a credential the daemon refuses to start with is worse than reporting
// nothing, and that is exactly what a second, looser check produced.
type Store struct {
	// Dir is the agent work dir the five artifacts live in.
	Dir string
	// FS is the read seam; nil means the real filesystem.
	FS FS
}

// KubeconfigPath is the node kubeconfig: the cluster CA plus this node's
// system:node client keypair.
func (s Store) KubeconfigPath() string { return filepath.Join(s.Dir, KubeconfigFile) }

// ServingCertPath is the cluster-CA-issued :10250 serving certificate.
func (s Store) ServingCertPath() string { return filepath.Join(s.Dir, ServingCertFile) }

// ServingKeyPath is the serving certificate's private key.
func (s Store) ServingKeyPath() string { return filepath.Join(s.Dir, ServingKeyFile) }

// ClientCAPath is the client-identity CA this node's :10250 verifies the
// apiserver against.
func (s Store) ClientCAPath() string { return filepath.Join(s.Dir, ClientCAFile) }

// AssignmentPath is the mesh/apiserver assignment the server decided.
func (s Store) AssignmentPath() string { return filepath.Join(s.Dir, NodeAssignmentFile) }

// Paths lists every artifact a complete credential consists of, in the order a
// missing one is reported.
func (s Store) Paths() []string {
	return []string{
		s.KubeconfigPath(),
		s.ServingCertPath(),
		s.ServingKeyPath(),
		s.ClientCAPath(),
		s.AssignmentPath(),
	}
}

// fsys returns the read seam, defaulting to the real filesystem.
func (s Store) fsys() FS {
	if s.FS == nil {
		return osFS{}
	}
	return s.FS
}

// Status reports whether this store holds a usable node credential, returning
// the loaded credential whenever one could be parsed.
//
// A corrupt credential is a hard ERROR, never a silent re-join: overwriting
// unreadable state would destroy the evidence of whatever damaged it, and would
// turn a fault into a silent re-issue of this node's identity. The error wraps
// the underlying cause, so a caller that must tell "unreadable as this user"
// apart from "damaged" — a status report run without sudo — can ask with
// errors.Is(err, fs.ErrPermission).
//
// now is a parameter so the expiry rule is testable without waiting a year.
func (s Store) Status(now time.Time) (State, *Credential, error) {
	fsys := s.fsys()
	for _, p := range s.Paths() {
		if _, err := fsys.Stat(p); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return Absent, nil, nil
			}
			return Corrupt, nil, corruptCredential(p, err)
		}
	}
	cred, err := s.load(fsys)
	if err != nil {
		return Corrupt, nil, err
	}
	switch {
	case !cred.ServingNotAfter.After(now):
		return Expired, cred, nil
	case !cred.ClientNotAfter.After(now.Add(ExpiryMargin)):
		return Expired, cred, nil
	}
	return Valid, cred, nil
}

// Status is Store.Status for a caller that has a directory and a read seam
// rather than a Store — the shape `k3sm status` uses, so the report and the
// daemon run the same five-artifact validation over the same files.
func Status(fsys FS, dir string, now time.Time) (State, *Credential, error) {
	return Store{Dir: dir, FS: fsys}.Status(now)
}

// load reads and validates every artifact. Every failure names the file that
// caused it, because the remedy is per-file.
func (s Store) load(fsys FS) (*Credential, error) {
	kubeconfigPath := s.KubeconfigPath()
	raw, err := fsys.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, corruptCredential(kubeconfigPath, err)
	}
	server, caPEM, clientCertPEM, clientKeyPEM, err := loadNodeKubeconfig(raw)
	if err != nil {
		return nil, corruptCredential(kubeconfigPath, err)
	}
	pin, err := certs.CertPin(caPEM)
	if err != nil {
		return nil, corruptCredential(kubeconfigPath, fmt.Errorf("cluster CA: %w", err))
	}
	// X509KeyPair is the check that matters: it parses both halves AND proves
	// the private key belongs to the certificate. A mismatched pair
	// authenticates as nothing, and would otherwise surface as an opaque TLS
	// handshake failure against the apiserver long after start.
	clientNotAfter, err := keyPairNotAfter(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, corruptCredential(kubeconfigPath, fmt.Errorf("node client keypair: %w", err))
	}

	servingCertPEM, err := fsys.ReadFile(s.ServingCertPath())
	if err != nil {
		return nil, corruptCredential(s.ServingCertPath(), err)
	}
	servingKeyPEM, err := fsys.ReadFile(s.ServingKeyPath())
	if err != nil {
		return nil, corruptCredential(s.ServingKeyPath(), err)
	}
	servingNotAfter, err := keyPairNotAfter(servingCertPEM, servingKeyPEM)
	if err != nil {
		return nil, corruptCredential(s.ServingCertPath(), fmt.Errorf("kubelet serving keypair: %w", err))
	}

	clientCAPEM, err := fsys.ReadFile(s.ClientCAPath())
	if err != nil {
		return nil, corruptCredential(s.ClientCAPath(), err)
	}
	if _, err := decodeCertPEM(clientCAPEM); err != nil {
		return nil, corruptCredential(s.ClientCAPath(), err)
	}

	blob, err := fsys.ReadFile(s.AssignmentPath())
	if err != nil {
		return nil, corruptCredential(s.AssignmentPath(), err)
	}
	var assignment Assignment
	if err := json.Unmarshal(blob, &assignment); err != nil {
		return nil, corruptCredential(s.AssignmentPath(), err)
	}
	if assignment.PodCIDR == "" {
		return nil, corruptCredential(s.AssignmentPath(), errors.New("no assigned podCIDR: the mesh device and the pod IPAM are both built from it"))
	}

	return &Credential{
		APIServerURL:    server,
		ClusterCAPEM:    caPEM,
		ClusterCAPin:    pin,
		ClientCertPEM:   clientCertPEM,
		ClientKeyPEM:    clientKeyPEM,
		ServingCertPEM:  servingCertPEM,
		ServingKeyPEM:   servingKeyPEM,
		ClientCAPEM:     clientCAPEM,
		Assignment:      assignment,
		ClientNotAfter:  clientNotAfter,
		ServingNotAfter: servingNotAfter,
	}, nil
}

// corruptCredential wraps a per-file fault with the remedy. The remedy is
// deliberately manual: an agent that deleted the file itself would re-issue
// this node's identity on the strength of a parse error.
func corruptCredential(path string, err error) error {
	return fmt.Errorf("stored node credential %s is unusable: %w; remove it to force a fresh token join", path, err)
}

// keyPairNotAfter proves certPEM and keyPEM are a matching pair and returns the
// leaf's NotAfter.
func keyPairNotAfter(certPEM, keyPEM []byte) (time.Time, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return time.Time{}, err
	}
	if len(pair.Certificate) == 0 {
		return time.Time{}, errors.New("keypair carries no certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// decodeCertPEM decodes a single CERTIFICATE PEM block.
func decodeCertPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// loadNodeKubeconfig reads back what the agent wrote: the apiserver URL, the
// cluster CA, and this node's client keypair, resolved through the file's
// current context so it stays the inverse of the writer rather than a second
// assumption about names.
func loadNodeKubeconfig(raw []byte) (server string, caPEM, certPEM, keyPEM []byte, err error) {
	cfg, err := clientcmd.Load(raw)
	if err != nil {
		return "", nil, nil, nil, err
	}
	ctx, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok || ctx == nil {
		return "", nil, nil, nil, fmt.Errorf("no context %q", cfg.CurrentContext)
	}
	cluster, ok := cfg.Clusters[ctx.Cluster]
	if !ok || cluster == nil {
		return "", nil, nil, nil, fmt.Errorf("no cluster %q", ctx.Cluster)
	}
	user, ok := cfg.AuthInfos[ctx.AuthInfo]
	if !ok || user == nil {
		return "", nil, nil, nil, fmt.Errorf("no user %q", ctx.AuthInfo)
	}
	switch {
	case cluster.Server == "":
		return "", nil, nil, nil, errors.New("the cluster entry names no apiserver")
	case len(cluster.CertificateAuthorityData) == 0:
		return "", nil, nil, nil, errors.New("the cluster entry carries no certificate-authority-data")
	case len(user.ClientCertificateData) == 0 || len(user.ClientKeyData) == 0:
		return "", nil, nil, nil, errors.New("the user entry carries no client keypair")
	}
	return cluster.Server, cluster.CertificateAuthorityData, user.ClientCertificateData, user.ClientKeyData, nil
}
