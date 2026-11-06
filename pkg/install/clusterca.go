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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

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
//     once from the node credential's certificate-authority-data.
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
	return writeAgentClusterCA(sys, cred.ClusterCAPEM, cfg, "the node credential")
}

// provisionServerClusterCA writes a server's root-only cluster CA copy from ca, its
// control plane's certificate. An upgrade calls it with the CA already on disk,
// before the swap and before netd restarts, so the new helper always finds the copy.
// A first install calls it with minted set, once the control plane's first boot has
// written its CA; netd retries until then.
//
//   - An equal copy is left alone.
//   - No copy, or one that is not a CA certificate, is written.
//   - A different copy is replaced only when minted: this boot made a new CA, so the
//     copy describes a cluster this node no longer serves (it was a worker before an
//     uninstall, or its work dir was removed). Otherwise it is kept and a warning
//     names it: the source is a file the service user owns, so which of the two is
//     right takes a person.
//
// A ca that is not a CA certificate writes nothing and is logged, as on a worker:
// the helper keeps refusing with the remedy.
func provisionServerClusterCA(sys System, cfg Config, ca []byte, minted bool) error {
	if err := checkCAPEM(ca); err != nil {
		cfg.Logger.Warn("the control plane's cluster CA is unusable: this server's root helper keeps refusing until an install finds a usable one", "err", err)
		return nil
	}
	existing, err := sys.ReadRegularFile(AgentClusterCAPath)
	switch {
	case err == nil && bytes.Equal(existing, ca):
		return nil
	case err == nil && checkCAPEM(existing) == nil && !minted:
		cfg.Logger.Warn("the root-only cluster CA copy differs from the control plane's and is kept; if the cluster's CA really changed, remove the copy and run `sudo k3sm install` to write it again",
			"path", AgentClusterCAPath, "control-plane-ca", certs.ClusterCACertPath(cfg.serverWorkDir()))
		return nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		cfg.Logger.Warn("the root-only cluster CA copy cannot be read; replacing it from the control plane's", "path", AgentClusterCAPath, "err", err)
	}
	return writeAgentClusterCA(sys, ca, cfg, "the control plane's cluster CA")
}

// awaitServerClusterCA is awaitClusterCA, and a first install's root-only copy of
// the CA it waited for.
func awaitServerClusterCA(ctx context.Context, sys System, cfg *Config, b restartBudget) error {
	minted := len(cfg.ClusterCA) == 0
	if err := awaitClusterCA(ctx, sys, cfg, b); err != nil {
		return err
	}
	if !minted {
		return nil
	}
	return provisionServerClusterCA(sys, *cfg, cfg.ClusterCA, true)
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
