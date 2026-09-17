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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/nodecred"
)

// The node credential store, WRITE half: the agent is the only process with a
// join outcome to persist, so Save lives here beside the join that produces it.
//
// Everything about READING the store — the five file names, the validation, the
// expiry rule and the Status verdict — is pkg/nodecred, because `k3sm status`
// and `k3sm doctor` must reach exactly the same verdict about the same
// directory as this daemon does. A report that called a credential valid while
// the daemon refused to start with it would send an operator to the wrong Mac.
//
// File ownership is implicit and deliberate: these are written by the agent
// process, so they are owned by the uid it runs as, and the secret halves are
// 0600. Nothing here chowns, and no path outside the agent's own work dir is
// touched.

// The store's types, as this package has always spelled them. They are aliases
// and re-exports of pkg/nodecred, so the start decision below reads unchanged
// while there is only one implementation of the verdict.
type (
	credentialStatus = nodecred.State
	nodeCredential   = nodecred.Credential
)

const (
	credentialAbsent  = nodecred.Absent
	credentialCorrupt = nodecred.Corrupt
	credentialExpired = nodecred.Expired
	credentialValid   = nodecred.Valid

	// credentialExpiryMargin is how far ahead of a node client cert's NotAfter
	// the stored credential is already treated as expired. See
	// nodecred.ExpiryMargin for why a day.
	credentialExpiryMargin = nodecred.ExpiryMargin

	nodeKubeconfigFile     = nodecred.KubeconfigFile
	kubeletServingCertFile = nodecred.ServingCertFile
	kubeletServingKeyFile  = nodecred.ServingKeyFile
	kubeletClientCAFile    = nodecred.ClientCAFile
	nodeAssignmentFile     = nodecred.NodeAssignmentFile
)

// nodeCredentialStore is the agent work dir viewed as the home of one node's
// persisted join outcome. It is the WRITER; every read goes through the
// pkg/nodecred store it wraps.
type nodeCredentialStore struct {
	dir string
}

// reader is the read half of this same directory.
func (s nodeCredentialStore) reader() nodecred.Store { return nodecred.Store{Dir: s.dir} }

// Status reports whether this store holds a usable node credential. It is
// pkg/nodecred's verdict verbatim — the same one `k3sm status` reports.
func (s nodeCredentialStore) Status(now time.Time) (credentialStatus, *nodeCredential, error) {
	return s.reader().Status(now)
}

func (s nodeCredentialStore) kubeconfigPath() string  { return s.reader().KubeconfigPath() }
func (s nodeCredentialStore) servingCertPath() string { return s.reader().ServingCertPath() }
func (s nodeCredentialStore) servingKeyPath() string  { return s.reader().ServingKeyPath() }
func (s nodeCredentialStore) clientCAPath() string    { return s.reader().ClientCAPath() }
func (s nodeCredentialStore) assignmentPath() string  { return s.reader().AssignmentPath() }

// paths lists every artifact a complete credential consists of.
func (s nodeCredentialStore) paths() []string { return s.reader().Paths() }

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
	blob, err := json.MarshalIndent(nodecred.Assignment{
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

// joinResultFrom rebuilds the join outcome downstream wiring consumes (the node
// options, the mesh bring-up, the datapath config) from stored state plus the
// node's persisted wireguard identity — so a reuse start and a fresh join feed
// exactly the same structure into exactly the same code.
func joinResultFrom(c *nodeCredential, nodeName, wgPrivB64, wgPubB64 string) *bootstrap.JoinResult {
	return &bootstrap.JoinResult{
		NodeName:              nodeName,
		ClusterCAPEM:          c.ClusterCAPEM,
		ClientCAPEM:           c.ClientCAPEM,
		NodeClientCertPEM:     c.ClientCertPEM,
		NodeClientKeyPEM:      c.ClientKeyPEM,
		KubeletServingCertPEM: c.ServingCertPEM,
		KubeletServingKeyPEM:  c.ServingKeyPEM,
		PodCIDR:               c.Assignment.PodCIDR,
		MeshIP:                c.Assignment.MeshIP,
		Peers:                 c.Assignment.Peers,
		WGPrivateKeyB64:       wgPrivB64,
		WGPublicKeyB64:        wgPubB64,
		APIServers:            c.Assignment.APIServers,
	}
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
