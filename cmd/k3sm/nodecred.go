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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// The node credential store: everything a joined worker must keep so a RESTART is
// not a rejoin.
//
// A join is a credential-issuing event — it costs a join token, which is
// TTL-bounded (bootstrap.DefaultTokenTTL), and it re-mints this node's certs. Yet
// `k3sm agent` used to re-run the whole join on every start and persist only the
// kubeconfig, so a restart after the token expired failed with "join rejected
// (401)" and a KeepAlive daemon respawned it into a loop. The kubelet's own answer
// is the one taken here: persist the credential, and on restart present it.
//
// What is persisted is the WHOLE join outcome, in five files under the agent work
// dir, because the two halves are useless apart:
//
//   - node.kubeconfig        the cluster CA + this node's system:node client keypair
//   - kubelet-serving.crt    the cluster-CA-issued :10250 serving cert
//   - kubelet-serving.key    its private key (generated here, never on the wire)
//   - kubelet-client-ca.crt  the client-identity CA this node's :10250 verifies the apiserver against
//   - node-assignment.json   the mesh/apiserver assignment: pod /24, mesh-egress /32, peer snapshot, apiserver endpoints
//
// The assignment file is the non-obvious one. The three certificate artifacts
// reconstruct this node's IDENTITY, but a worker also needs the values the server
// ASSIGNED it — the pod /24 the mesh device is built from and the mesh-egress /32
// the Service proxy sources — and those arrive only in a join response. They
// cannot be re-read from the apiserver at start either: a joined worker's
// kubeconfig points at the server's MESH address, which is reachable only once the
// mesh this data is needed to build is already up. So they are persisted with the
// certs, and the MeshPeer watch reconverges the peer list after bring-up.
//
// File ownership is implicit and deliberate: these are written by the agent
// process, so they are owned by the uid it runs as, and the secret halves are
// 0600. Nothing here chowns, and no path outside the agent's own work dir is
// touched.
const (
	nodeKubeconfigFile     = "node.kubeconfig"
	kubeletServingCertFile = "kubelet-serving.crt"
	kubeletServingKeyFile  = "kubelet-serving.key"
	kubeletClientCAFile    = "kubelet-client-ca.crt"
	nodeAssignmentFile     = "node-assignment.json"
)

// credentialExpiryMargin is how far ahead of a node client cert's NotAfter the
// stored credential is already treated as expired.
//
// It is not a renewal window — nothing renews in process yet (see the rotation
// caveat in certificateUsage). It is the margin that decides WHICH failure an
// operator gets: a restart inside the margin still has a working token path
// available and reports "supply a token", whereas a restart past NotAfter with no
// token has already lost the node. A day is the smallest margin that survives a
// Mac being asleep over a weekend evening and still being restarted on Monday
// with the same answer.
const credentialExpiryMargin = 24 * time.Hour

// credentialStatus is what the store holds, as the start decision sees it.
type credentialStatus int

const (
	// credentialAbsent: at least one of the five artifacts is missing — this node
	// has never completed a join, or its state was wiped.
	credentialAbsent credentialStatus = iota
	// credentialCorrupt: every artifact is present but one of them does not parse,
	// or the client key does not match the client cert. Always accompanied by an
	// error naming the file.
	credentialCorrupt
	// credentialExpired: the credential is intact but no longer usable — the node
	// client cert is within credentialExpiryMargin of NotAfter, or the kubelet
	// serving cert is already past it.
	credentialExpired
	// credentialValid: present, parseable, matched, and in date.
	credentialValid
)

// String renders the status for logs.
func (s credentialStatus) String() string {
	switch s {
	case credentialAbsent:
		return "absent"
	case credentialCorrupt:
		return "corrupt"
	case credentialExpired:
		return "expired"
	case credentialValid:
		return "valid"
	}
	return fmt.Sprintf("credentialStatus(%d)", int(s))
}

// nodeAssignment is the non-credential half of a join outcome — the values the
// SERVER decided and this node cannot re-derive locally. Its JSON is the on-disk
// shape of nodeAssignmentFile.
type nodeAssignment struct {
	// PodCIDR is the /24 assigned to this node: the mesh device's own prefix and
	// the pod IPAM range, which are one value by design.
	PodCIDR string `json:"podCIDR"`
	// MeshIP is this node's mesh-egress /32 — the source address its Service proxy
	// re-originates cross-node dials from.
	MeshIP string `json:"meshIP"`
	// APIServers are the advertised apiserver endpoints (host:port) the node's
	// kubeconfig targets; empty against a single-node server.
	APIServers []string `json:"apiServers,omitempty"`
	// Peers is the peer snapshot as of the last join. It is the SEED only: the
	// MeshPeer watch replaces it with live state moments after bring-up, so a
	// stale entry here costs one reconcile, not correctness.
	Peers []netv1.MeshPeerSpec `json:"peers,omitempty"`
}

// nodeCredential is a loaded, parsed, self-consistent stored join outcome.
type nodeCredential struct {
	apiserverURL   string
	clusterCAPEM   []byte
	clusterCAPin   string // certs.CertPin over clusterCAPEM — the pin a token is compared against
	clientCertPEM  []byte
	clientKeyPEM   []byte
	servingCertPEM []byte
	servingKeyPEM  []byte
	clientCAPEM    []byte
	assignment     nodeAssignment

	clientNotAfter  time.Time
	servingNotAfter time.Time
}

// nodeCredentialStore is the agent work dir viewed as the home of one node's
// persisted join outcome. It owns path derivation, the save, the load, and the
// Status verdict — so no caller open-codes a file name or an expiry rule.
type nodeCredentialStore struct {
	dir string
}

func (s nodeCredentialStore) kubeconfigPath() string {
	return filepath.Join(s.dir, nodeKubeconfigFile)
}
func (s nodeCredentialStore) servingCertPath() string {
	return filepath.Join(s.dir, kubeletServingCertFile)
}
func (s nodeCredentialStore) servingKeyPath() string {
	return filepath.Join(s.dir, kubeletServingKeyFile)
}
func (s nodeCredentialStore) clientCAPath() string {
	return filepath.Join(s.dir, kubeletClientCAFile)
}
func (s nodeCredentialStore) assignmentPath() string {
	return filepath.Join(s.dir, nodeAssignmentFile)
}

// paths lists every artifact a complete credential consists of, in the order a
// missing one is reported.
func (s nodeCredentialStore) paths() []string {
	return []string{
		s.kubeconfigPath(),
		s.servingCertPath(),
		s.servingKeyPath(),
		s.clientCAPath(),
		s.assignmentPath(),
	}
}

// Save persists a join outcome: the kubeconfig that authenticates as the issued
// system:node identity, the kubelet serving pair, the client-identity CA, and the
// server-assigned mesh/apiserver values.
//
// It is idempotent and is called on BOTH start paths — a fresh token join writes
// the newly issued material, a reuse start would rewrite byte-identical content
// (or update only the apiserver URL when `--api-port` moved). Writing on reuse
// keeps exactly one place where the on-disk shape is produced, and because every
// write goes through writeStoreFile, an ordinary restart re-writes nothing at all.
//
// Atomicity is PER FILE, not per store: each artifact is installed by a rename, so
// no reader ever sees a half-written file and a crash mid-Save leaves every
// artifact either wholly old or wholly new. It is deliberately not a transaction
// over the five, because the alternative (a staging dir swapped in one rename)
// buys little here: the store is only ever rewritten in full right after a join,
// so the worst mix is two generations of leaves from the same two CAs, each of
// which is individually usable and none of which is torn. The rejoin that follows
// converges it.
func (s nodeCredentialStore) Save(apiserverURL, nodeName string, res *bootstrap.JoinResult) error {
	if res == nil {
		return errors.New("save node credential: no join result")
	}
	if err := writeNodeKubeconfig(s.kubeconfigPath(), apiserverURL, nodeName, res); err != nil {
		return err
	}
	// 0600 for both halves of the serving pair. The certificate is public material,
	// but it is only ever read beside its key by this same process, and a uniform
	// mode is one fewer thing to get wrong than a split one.
	if err := writeStoreFile(s.servingCertPath(), res.KubeletServingCertPEM, 0o600); err != nil {
		return fmt.Errorf("persist kubelet serving certificate: %w", err)
	}
	if err := writeStoreFile(s.servingKeyPath(), res.KubeletServingKeyPEM, 0o600); err != nil {
		return fmt.Errorf("persist kubelet serving key: %w", err)
	}
	// The client-identity CA is a CA certificate: public, world-readable, and the
	// same 0644 it has on the server.
	if err := writeStoreFile(s.clientCAPath(), res.ClientCAPEM, 0o644); err != nil {
		return fmt.Errorf("persist kubelet client CA: %w", err)
	}
	blob, err := json.MarshalIndent(nodeAssignment{
		PodCIDR:    res.PodCIDR,
		MeshIP:     res.MeshIP,
		APIServers: res.APIServers,
		Peers:      res.Peers,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal node assignment: %w", err)
	}
	if err := writeStoreFile(s.assignmentPath(), append(blob, '\n'), 0o644); err != nil {
		return fmt.Errorf("persist node assignment: %w", err)
	}
	return nil
}

// storeTmpSuffix is appended to a target's name for the staging file an atomic
// install renames over it. It is a FIXED suffix rather than a random one so a
// crash leaves one recognisable leftover per artifact instead of accumulating
// them, and so the next write reuses it. It sits beside its target, in the same
// directory, because rename is only atomic within a filesystem.
const storeTmpSuffix = ".tmp"

// writeStoreFile installs data at path atomically, and skips the write entirely
// when the file already holds exactly those bytes at exactly that mode.
//
// Both halves matter, for different reasons. ATOMICITY: this runs on every agent
// start, including restarts that change nothing, so an interrupted write is no
// longer a rare event confined to first-join — and a truncated credential file is
// precisely the corrupt state Status refuses to repair on its own. Writing a
// sibling temp file, fsyncing it and renaming over the target means a reader
// (this process on its next start, or an operator) sees the old file or the new
// one, never a prefix of either. NO-OP ON IDENTICAL CONTENT: the common case by
// far is a restart whose credential has not changed, and a store that is not
// touched cannot be damaged by a crash in the first place.
//
// The mode is compared as well as the bytes, so a credential file that somehow
// acquired the wrong permissions is corrected rather than left because its
// content matched.
func writeStoreFile(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() == mode {
		if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
			return nil
		}
	}
	tmp := path + storeTmpSuffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	// O_CREATE's mode is masked by the process umask, so the bits a secret needs
	// are set explicitly instead of assumed. Done BEFORE the write: the file must
	// never be readable by anyone else, not even briefly.
	if err := f.Chmod(mode); err != nil {
		return cleanUpTmp(f, tmp, fmt.Errorf("set the mode of %s: %w", tmp, err))
	}
	if _, err := f.Write(data); err != nil {
		return cleanUpTmp(f, tmp, fmt.Errorf("write %s: %w", tmp, err))
	}
	// fsync before the rename: without it the rename can be durable while the
	// bytes it points at are not, which on a power loss is exactly the truncated
	// file this function exists to make impossible.
	if err := f.Sync(); err != nil {
		return cleanUpTmp(f, tmp, fmt.Errorf("sync %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// cleanUpTmp closes and removes a failed staging file and returns the original
// error. The removal is best-effort: a leftover temp file is harmless (nothing
// reads one, and the next write truncates it), whereas masking the real failure
// with a cleanup error would hide why the credential was not written.
func cleanUpTmp(f *os.File, tmp string, err error) error {
	_ = f.Close()
	_ = os.Remove(tmp)
	return err
}

// Status reports whether this store holds a usable node credential, returning the
// loaded credential whenever one could be parsed.
//
// A corrupt credential is a hard ERROR, never a silent re-join: the same posture
// loadOrCreateMeshKey takes for the mesh key. Overwriting unreadable state would
// destroy the evidence of whatever damaged it, and would turn a fault into a
// silent re-issue of this node's identity.
//
// now is a parameter so the expiry rule is testable without waiting a year.
func (s nodeCredentialStore) Status(now time.Time) (credentialStatus, *nodeCredential, error) {
	for _, p := range s.paths() {
		if _, err := os.Stat(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return credentialAbsent, nil, nil
			}
			return credentialCorrupt, nil, corruptCredential(p, err)
		}
	}
	cred, err := s.load()
	if err != nil {
		return credentialCorrupt, nil, err
	}
	switch {
	case !cred.servingNotAfter.After(now):
		return credentialExpired, cred, nil
	case !cred.clientNotAfter.After(now.Add(credentialExpiryMargin)):
		return credentialExpired, cred, nil
	}
	return credentialValid, cred, nil
}

// load reads and validates every artifact. Every failure names the file that
// caused it, because the remedy is per-file.
func (s nodeCredentialStore) load() (*nodeCredential, error) {
	kubeconfigPath := s.kubeconfigPath()
	server, caPEM, clientCertPEM, clientKeyPEM, err := loadNodeKubeconfig(kubeconfigPath)
	if err != nil {
		return nil, corruptCredential(kubeconfigPath, err)
	}
	pin, err := certs.CertPin(caPEM)
	if err != nil {
		return nil, corruptCredential(kubeconfigPath, fmt.Errorf("cluster CA: %w", err))
	}
	// X509KeyPair is the check that matters: it parses both halves AND proves the
	// private key belongs to the certificate. A mismatched pair authenticates as
	// nothing, and would otherwise surface as an opaque TLS handshake failure
	// against the apiserver long after start.
	clientNotAfter, err := keyPairNotAfter(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, corruptCredential(kubeconfigPath, fmt.Errorf("node client keypair: %w", err))
	}

	servingCertPEM, err := os.ReadFile(s.servingCertPath())
	if err != nil {
		return nil, corruptCredential(s.servingCertPath(), err)
	}
	servingKeyPEM, err := os.ReadFile(s.servingKeyPath())
	if err != nil {
		return nil, corruptCredential(s.servingKeyPath(), err)
	}
	servingNotAfter, err := keyPairNotAfter(servingCertPEM, servingKeyPEM)
	if err != nil {
		return nil, corruptCredential(s.servingCertPath(), fmt.Errorf("kubelet serving keypair: %w", err))
	}

	clientCAPEM, err := os.ReadFile(s.clientCAPath())
	if err != nil {
		return nil, corruptCredential(s.clientCAPath(), err)
	}
	if _, err := decodeCertPEM(clientCAPEM); err != nil {
		return nil, corruptCredential(s.clientCAPath(), err)
	}

	blob, err := os.ReadFile(s.assignmentPath())
	if err != nil {
		return nil, corruptCredential(s.assignmentPath(), err)
	}
	var assignment nodeAssignment
	if err := json.Unmarshal(blob, &assignment); err != nil {
		return nil, corruptCredential(s.assignmentPath(), err)
	}
	if assignment.PodCIDR == "" {
		return nil, corruptCredential(s.assignmentPath(), errors.New("no assigned podCIDR: the mesh device and the pod IPAM are both built from it"))
	}

	return &nodeCredential{
		apiserverURL:    server,
		clusterCAPEM:    caPEM,
		clusterCAPin:    pin,
		clientCertPEM:   clientCertPEM,
		clientKeyPEM:    clientKeyPEM,
		servingCertPEM:  servingCertPEM,
		servingKeyPEM:   servingKeyPEM,
		clientCAPEM:     clientCAPEM,
		assignment:      assignment,
		clientNotAfter:  clientNotAfter,
		servingNotAfter: servingNotAfter,
	}, nil
}

// joinResult rebuilds the join outcome downstream wiring consumes (the node
// options, the mesh bring-up, the datapath config) from stored state plus the
// node's persisted wireguard identity — so a reuse start and a fresh join feed
// exactly the same structure into exactly the same code.
func (c *nodeCredential) joinResult(nodeName, wgPrivB64, wgPubB64 string) *bootstrap.JoinResult {
	return &bootstrap.JoinResult{
		NodeName:              nodeName,
		ClusterCAPEM:          c.clusterCAPEM,
		ClientCAPEM:           c.clientCAPEM,
		NodeClientCertPEM:     c.clientCertPEM,
		NodeClientKeyPEM:      c.clientKeyPEM,
		KubeletServingCertPEM: c.servingCertPEM,
		KubeletServingKeyPEM:  c.servingKeyPEM,
		PodCIDR:               c.assignment.PodCIDR,
		MeshIP:                c.assignment.MeshIP,
		Peers:                 c.assignment.Peers,
		WGPrivateKeyB64:       wgPrivB64,
		WGPublicKeyB64:        wgPubB64,
		APIServers:            c.assignment.APIServers,
	}
}

// corruptCredential wraps a per-file fault with the remedy. The remedy is
// deliberately manual: an agent that deleted the file itself would re-issue this
// node's identity on the strength of a parse error.
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

// loadNodeKubeconfig reads back what writeNodeKubeconfig wrote: the apiserver URL,
// the cluster CA, and this node's client keypair, resolved through the file's
// current context so it stays the inverse of the writer rather than a second
// assumption about names.
func loadNodeKubeconfig(path string) (server string, caPEM, certPEM, keyPEM []byte, err error) {
	cfg, err := clientcmd.LoadFromFile(path)
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

// startMode is how `k3sm agent` obtains the identity it runs as.
type startMode int

const (
	// startModeTokenJoin runs the full bootstrap join: a token, a node-password,
	// CSRs, and freshly issued certificates.
	startModeTokenJoin startMode = iota + 1
	// startModeReuseCredential presents the stored credential and re-publishes
	// this node's wireguard endpoint, without a token and without re-issuing
	// anything.
	startModeReuseCredential
)

// String renders the mode for logs.
func (m startMode) String() string {
	switch m {
	case startModeTokenJoin:
		return "token-join"
	case startModeReuseCredential:
		return "reuse-credential"
	}
	return fmt.Sprintf("startMode(%d)", int(m))
}

// The terminal start failures. They are sentinels so the decision is assertable
// without matching on prose, and their text is what an operator reads out of a
// daemon log with no other context.
var (
	errNoCredentialNoToken = errors.New("no stored node credential and no join token; mint one on the server (k3sm token create) and start the agent with it")
	errExpiredCredential   = errors.New("the stored node credential has expired (or expires within 24h) and no join token was supplied; mint one on the server (k3sm token create) and start the agent with it so this node's certificates are re-issued")
	errCorruptCredential   = errors.New("the stored node credential is unusable; remove the offending file to force a fresh token join")
)

// agentStartPlan decides how an agent start obtains its identity. It is pure so
// the whole policy — including the cases that are easy to get subtly wrong, like a
// token for a DIFFERENT cluster — is table-tested without a work dir, a server, or
// a clock.
//
// The rules, and why each is what it is:
//
//   - valid, no token → reuse. The restart case this exists for: a joined node
//     comes back without a credential-issuing event.
//   - valid + a token whose CA pin MATCHES the stored cluster CA → reuse, and the
//     token is ignored. A daemon plist or a shell profile that still carries the
//     original token must not make every restart a rejoin.
//   - valid + a token whose CA pin DIFFERS → token join. The operator pointed this
//     Mac at another cluster, and a supplied token is the only unambiguous way to
//     say so; the stale credential is overwritten. This is the one case where
//     reuse would be actively wrong, which is why the pin is compared at all.
//   - valid + an unparseable token → reuse, with a warning. A garbage token is an
//     operator typo; refusing to start a node that holds a working credential
//     would turn a typo into an outage.
//   - absent or expired, with a token → token join.
//   - absent or expired, with no token → terminal. There is nothing to present
//     and nothing to join with.
//   - corrupt → terminal. Status has already produced the error naming the file;
//     this branch keeps the function total.
//
// storedCAHash is certs.CertPin over the stored cluster CA; it is non-empty
// whenever status is valid, because load derives it and fails the credential if it
// cannot.
func agentStartPlan(status credentialStatus, tokenPresent bool, tokenParses bool, tokenCAHash, storedCAHash string) (startMode, error) {
	switch status {
	case credentialValid:
		if tokenPresent && tokenParses && tokenCAHash != storedCAHash {
			return startModeTokenJoin, nil
		}
		return startModeReuseCredential, nil
	case credentialAbsent:
		if tokenPresent {
			return startModeTokenJoin, nil
		}
		return 0, errNoCredentialNoToken
	case credentialExpired:
		if tokenPresent {
			return startModeTokenJoin, nil
		}
		return 0, errExpiredCredential
	case credentialCorrupt:
		return 0, errCorruptCredential
	}
	return 0, fmt.Errorf("unknown stored node credential status %s", status)
}

// logStartPlan says out loud what the plan did with the token, once, at start.
// Each line exists because its case is silent otherwise and would be read as a
// bug: a token that was supplied and had no effect, and — loudly — a credential
// that is about to be overwritten because the token names another cluster.
func logStartPlan(logger *slog.Logger, mode startMode, status credentialStatus, tokenPresent, tokenParses bool, tokenCAHash, storedCAHash string) {
	switch {
	case mode == startModeReuseCredential && tokenPresent && tokenParses:
		logger.Info("ignoring the supplied join token: this node already holds a credential for this cluster (the token pins the same cluster CA)")
	case mode == startModeReuseCredential && tokenPresent:
		logger.Warn("ignoring an unparseable join token: this node already holds a valid credential, so a bad token does not stop it starting")
	case mode == startModeReuseCredential:
		logger.Info("reusing the stored node credential: no join token needed")
	case mode == startModeTokenJoin && status == credentialValid:
		logger.Warn("the supplied join token pins a DIFFERENT cluster CA than this node's stored credential: joining the token's cluster and OVERWRITING the stored credential",
			"tokenCAPin", tokenCAHash, "storedCAPin", storedCAHash)
	case mode == startModeTokenJoin:
		logger.Info("running a full token join", "credential", status.String())
	}
}
