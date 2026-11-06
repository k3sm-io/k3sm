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

package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/nodecred"
)

// AgentClusterCAName is a node's root-only copy of the cluster CA, in MeshKeyDir,
// on a worker and on a server alike: the anchor its k3sm-netd checks a managed
// update's signer against (`k3sm netd --cluster-ca`), and the CA root's own
// clients verify the apiserver with.
//
// It is root's copy, in the root-only directory, because what it comes from (a
// worker's credential, a server's PKI dir) lives in a work dir the service user
// owns, and a root process's trust does not depend on that account's files.
const AgentClusterCAName = "cluster-ca.crt"

// AgentClusterCAPath is the full path of that copy.
var AgentClusterCAPath = filepath.Join(MeshKeyDir, AgentClusterCAName)

// agentClusterCAMode is the copy's mode: a CA certificate is public.
const agentClusterCAMode fs.FileMode = 0o644

// netdClusterCAPath is the --cluster-ca netd is given: the root-only copy, on either
// role.
func (c Config) netdClusterCAPath() string {
	return AgentClusterCAPath
}

// provisionAgentClusterCA writes a worker's root-only cluster CA copy.
//
//   - verified is the CA the join endpoint served and the operator's token
//     pinned (preflightJoinEndpoint): it is written, replacing any copy that
//     differs.
//   - With no token (a joined node reinstalled or updated in place), an
//     existing copy is kept as it is: it was written from a pinned CA or by an
//     earlier root install, and the service user can change neither.
//   - With no copy yet (a node joined before this file existed), it is taken
//     once from the node credential's certificate-authority-data. A root-held join
//     token's CA hash (rootHeldTokenPin) must match it, or nothing is written; with
//     no such token the copy is taken and logged as unverified.
//
// A worker with neither keeps its netd refusing managed updates, which is
// logged, not an install failure.
//
// A server joining a cluster passes the same verified CA and gets the same write.
// Any other server takes its copy from its control plane's CA
// (provisionServerClusterCA).
func provisionAgentClusterCA(sys System, cfg Config, verified []byte) error {
	if cfg.Role != RoleAgent && len(verified) == 0 {
		return nil
	}
	if len(verified) > 0 {
		if err := checkCAPEM(verified); err != nil {
			return fmt.Errorf("install: the cluster CA the join endpoint served: %w", err)
		}
		if existing, err := sys.ReadRegularFile(AgentClusterCAPath); err == nil && bytes.Equal(existing, verified) {
			return nil
		}
		return writeAgentClusterCA(sys, verified, cfg, "the cluster CA the join token pins")
	}
	existing, err := sys.ReadRegularFile(AgentClusterCAPath)
	switch {
	case err == nil && checkCAPEM(existing) == nil:
		return nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		cfg.Logger.Warn("the worker's root-only cluster CA copy cannot be read; replacing it from the node credential", "path", AgentClusterCAPath, "err", err)
	case err == nil:
		cfg.Logger.Warn("the worker's root-only cluster CA copy is not a CA certificate; replacing it from the node credential", "path", AgentClusterCAPath)
	}
	state, cred, err := nodecred.Status(sysFS{sys: sys}, cfg.agentWorkDir(), time.Now())
	if err != nil || cred == nil || (state != nodecred.Valid && state != nodecred.AddressMismatch && state != nodecred.Expired) {
		cfg.Logger.Warn("no cluster CA for this worker's root helper yet: managed updates are refused until an install with --token-file", "credential", state, "err", err)
		return nil
	}
	if err := checkCAPEM(cred.ClusterCAPEM); err != nil {
		cfg.Logger.Warn("the node credential's cluster CA is unusable: managed updates are refused until an install with --token-file", "err", err)
		return nil
	}
	if cfg.heldTokenPin == "" {
		cfg.Logger.Info("taking this worker's root-only cluster CA copy from the node credential, unverified: no root-held join token to compare it with", "path", AgentClusterCAPath)
		return writeAgentClusterCA(sys, cred.ClusterCAPEM, cfg, "the node credential")
	}
	if pin, err := certs.CertPin(cred.ClusterCAPEM); err != nil || !strings.EqualFold(pin, cfg.heldTokenPin) {
		cfg.Logger.Warn("the node credential's cluster CA does not match the CA hash in the root-held join token, so no root-only copy was written: managed updates are refused until an install with --token-file", "token", cfg.agentTokenPath(), "err", err)
		return nil
	}
	return writeAgentClusterCA(sys, cred.ClusterCAPEM, cfg, "the node credential, checked against the root-held join token")
}

// provisionServerClusterCA writes a server's root-only cluster CA copy from ca, its
// control plane's certificate. An upgrade calls it with the CA already on disk,
// before the swap and before netd restarts, so the new helper always finds the copy.
// A first install calls it once the control plane's first boot has written its CA;
// netd retries until then.
//
//   - An equal copy is left alone.
//   - No copy, or one that is not a CA certificate, is written, once the apiserver's
//     serving certificate has been checked against ca. A certificate that does not
//     chain to it writes nothing and warns. An apiserver that does not answer, as on a
//     stopped node or a first boot, leaves the write as it was and logs it as
//     unverified.
//   - A different valid copy is kept and a warning gives the remedy: the source is a
//     file the service user owns, so which of the two is right takes a person. On a
//     node that is starting a new cluster, a former worker or one whose work dir was
//     removed, that person removes the copy and installs again.
//
// A ca that is not a CA certificate writes nothing and is logged, as on a worker:
// the helper keeps refusing with the remedy.
func provisionServerClusterCA(ctx context.Context, sys System, cfg Config, ca []byte) error {
	if err := checkCAPEM(ca); err != nil {
		cfg.Logger.Warn("the control plane's cluster CA is unusable: this server's root helper keeps refusing until an install finds a usable one", "err", err)
		return nil
	}
	existing, err := sys.ReadRegularFile(AgentClusterCAPath)
	switch {
	case err == nil && bytes.Equal(existing, ca):
		return nil
	case err == nil && checkCAPEM(existing) == nil:
		cfg.Logger.Warn("the root-only cluster CA copy differs from the control plane's and is kept, and this node's root helper and root commands keep checking the apiserver against it; if this node really has a new cluster or a new CA, run `sudo rm "+AgentClusterCAPath+"` and then `sudo k3sm install` to write it again",
			"path", AgentClusterCAPath, "control-plane-ca", certs.ClusterCACertPath(cfg.serverWorkDir()))
		return nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		cfg.Logger.Warn("the root-only cluster CA copy cannot be read; replacing it from the control plane's", "path", AgentClusterCAPath, "err", err)
	}
	switch verdict, detail := servedCAVerdictFor(ctx, sys, cfg, ca); verdict {
	case servedCADiffers:
		cfg.Logger.Warn("the apiserver's certificate does not chain to the control plane's cluster CA, so no root-only copy was written: this node's root helper and root commands refuse until one exists; check the server, then run `sudo k3sm install` again",
			"path", AgentClusterCAPath, "control-plane-ca", certs.ClusterCACertPath(cfg.serverWorkDir()), "err", detail)
		return nil
	case servedCANoAnswer:
		cfg.Logger.Info("taking the root-only cluster CA copy from the control plane's, unverified: the apiserver did not answer the check", "path", AgentClusterCAPath, "detail", detail)
	}
	return writeAgentClusterCA(sys, ca, cfg, "the control plane's cluster CA")
}

// awaitServerClusterCA is awaitClusterCA, and a first install's root-only copy of
// the CA it waited for.
func awaitServerClusterCA(ctx context.Context, sys System, cfg *Config, b restartBudget) error {
	waited := len(cfg.ClusterCA) == 0
	if err := awaitClusterCA(ctx, sys, cfg, b); err != nil {
		return err
	}
	if !waited {
		return nil
	}
	return provisionServerClusterCA(ctx, sys, *cfg, cfg.ClusterCA)
}

// awaitClusterCA fills cfg.ClusterCA with the cluster CA the control plane mints on
// its first boot, reading certs.ClusterCACertPath every b.poll for at most
// b.running. A CA already read (step 2e, an upgrade) returns at once. A read error
// other than not-exist fails at once. A timeout is ErrClusterCATimeout naming the
// path and the recovery.
func awaitClusterCA(ctx context.Context, sys System, cfg *Config, b restartBudget) error {
	if len(cfg.ClusterCA) > 0 {
		return nil
	}
	caPath := certs.ClusterCACertPath(cfg.serverWorkDir())
	ctx, cancel := context.WithTimeout(ctx, b.running)
	defer cancel()
	for {
		ca, err := sys.ReadFile(caPath)
		switch {
		case err == nil && len(ca) > 0:
			cfg.ClusterCA = ca
			return nil
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("install: read cluster CA %s: %w", caPath, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("install: %w: waited %s for %s; check the server log, then run `sudo k3sm install` again", ErrClusterCATimeout, b.running, caPath)
		case <-time.After(b.poll):
		}
	}
}

// apiServerAddr is the address this server's apiserver answers on: its mesh IP,
// which it binds ONLY, else loopback.
func (c Config) apiServerAddr() string {
	host := adminLoopbackHost
	if mesh := c.meshIP(); mesh != "" {
		host = mesh
	}
	return net.JoinHostPort(host, strconv.Itoa(c.APIServerPort))
}

func writeAgentClusterCA(sys System, caPEM []byte, cfg Config, from string) error {
	if err := sys.WriteRootOnlyFile(AgentClusterCAPath, caPEM, agentClusterCAMode); err != nil {
		return fmt.Errorf("install: write the node's cluster CA %s: %w", AgentClusterCAPath, err)
	}
	cfg.Logger.Info("wrote the cluster CA this node's root helper and root commands check the apiserver against", "path", AgentClusterCAPath, "from", from)
	return nil
}

// checkCAPEM accepts exactly one PEM certificate that is a CA.
func checkCAPEM(raw []byte) error {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) > 0 {
		return errors.New("not one PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if !c.IsCA {
		return errors.New("not a CA certificate")
	}
	return nil
}

// apiServerCACheckTimeout bounds checkServedCA, the dial and the handshake together.
const apiServerCACheckTimeout = 3 * time.Second

// servedCAVerdict is what checkServedCA found.
type servedCAVerdict int

const (
	// servedCANoAnswer means no verdict: nothing listening, or no handshake.
	servedCANoAnswer servedCAVerdict = iota
	// servedCAMatches means the served certificate chains to the candidate.
	servedCAMatches
	// servedCADiffers means it does not.
	servedCADiffers
)

// servedCACheck is one checkServedCA answer and the bytes it was about.
type servedCACheck struct {
	candidate []byte
	verdict   servedCAVerdict
	detail    error
}

// errServedCADiffers marks a served certificate that does not chain to the candidate.
var errServedCADiffers = errors.New("the served certificate does not chain to the candidate")

// checkServedCA connects to the apiserver at addr and reports whether the certificate
// it serves chains to candidate. It sends nothing but a handshake and takes at most
// apiServerCACheckTimeout.
//
// The only question is which CA issued the certificate, so the chain is checked at the
// leaf's own start time, and an out-of-date leaf or one without a given name is not a
// difference.
func checkServedCA(ctx context.Context, sys System, addr string, candidate []byte) (servedCAVerdict, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(candidate) {
		return servedCANoAnswer, errors.New("the candidate holds no PEM certificate")
	}
	ctx, cancel := context.WithTimeout(ctx, apiServerCACheckTimeout)
	defer cancel()
	conn, err := sys.DialAPIServer(ctx, addr)
	if err != nil {
		return servedCANoAnswer, err
	}
	defer func() { _ = conn.Close() }()
	client := tls.Client(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		// VerifyConnection below is the verification: it applies the candidate as the
		// only root, without a name or the clock.
		InsecureSkipVerify: true, //nolint:gosec // see the comment above
		VerifyConnection: func(cs tls.ConnectionState) error {
			return chainsToCandidate(cs.PeerCertificates, roots)
		},
	})
	switch err := client.HandshakeContext(ctx); {
	case err == nil:
		return servedCAMatches, nil
	case errors.Is(err, errServedCADiffers):
		return servedCADiffers, err
	default:
		return servedCANoAnswer, err
	}
}

// chainsToCandidate checks the served chain against roots, wrapping errServedCADiffers
// on a failure.
func chainsToCandidate(served []*x509.Certificate, roots *x509.CertPool) error {
	if len(served) == 0 {
		return fmt.Errorf("%w: no certificate", errServedCADiffers)
	}
	intermediates := x509.NewCertPool()
	for _, c := range served[1:] {
		intermediates.AddCert(c)
	}
	if _, err := served[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   served[0].NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("%w: %w", errServedCADiffers, err)
	}
	return nil
}

// checkServedCABeforeStop asks the running apiserver about the CA a server's first
// copy would be taken from. It runs before an upgrade stops the daemons, the one point
// at which the apiserver can answer, and asks only when a copy is still to be written,
// so an install that already has one spends nothing here. serverArgs are the installed
// server's arguments, whose --mesh-ip says where it listens now.
func checkServedCABeforeStop(ctx context.Context, sys System, cfg Config, serverArgs []string) *servedCACheck {
	if cfg.Role == RoleAgent || cfg.serverJoining() {
		return nil
	}
	ca, err := sys.ReadFile(certs.ClusterCACertPath(cfg.serverWorkDir()))
	if err != nil || checkCAPEM(ca) != nil {
		return nil
	}
	if existing, err := sys.ReadRegularFile(AgentClusterCAPath); err == nil && checkCAPEM(existing) == nil {
		return nil
	}
	running := cfg
	running.ExtraServerArgs = serverArgs
	running.MeshIP = ""
	verdict, detail := checkServedCA(ctx, sys, running.apiServerAddr(), ca)
	return &servedCACheck{candidate: ca, verdict: verdict, detail: detail}
}

// servedCAVerdictFor answers for ca: from the check before the daemons stopped when
// one ran, as long as the file has not changed since, otherwise by asking now.
func servedCAVerdictFor(ctx context.Context, sys System, cfg Config, ca []byte) (servedCAVerdict, error) {
	if c := cfg.servedCA; c != nil {
		if !bytes.Equal(c.candidate, ca) {
			return servedCADiffers, errors.New("the control plane's cluster CA changed during this install")
		}
		return c.verdict, c.detail
	}
	return checkServedCA(ctx, sys, cfg.apiServerAddr(), ca)
}

// maxHeldTokenFile bounds the read of a staged join token.
const maxHeldTokenFile = 4096

// rootHeldTokenPin returns the K10 CA hash of the worker's staged join token when
// root alone can write that file: a regular file owned by root with no group or other
// write. Anything else, including no such file, returns "", which is no check. Install
// reads it before adoptLegacyAgentFiles hands the work dir's files to the service user.
func rootHeldTokenPin(sys System, cfg Config) string {
	raw, e, err := sys.ReadOwnedRegularFile(cfg.agentTokenPath(), maxHeldTokenFile)
	if err != nil || e.Kind != EntryRegular || e.UID != 0 || e.Mode.Perm()&0o022 != 0 {
		return ""
	}
	tok, err := bootstrap.ParseToken(string(raw))
	if err != nil {
		return ""
	}
	pin := strings.ToLower(strings.TrimSpace(tok.CAHash))
	if decoded, err := hex.DecodeString(pin); err != nil || len(decoded) != sha256.Size {
		return ""
	}
	return pin
}
