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

// AgentClusterCAName is the worker's root-only copy of the cluster CA, in
// MeshKeyDir: the anchor its k3sm-netd checks a managed update's signer
// against (`k3sm netd --cluster-ca`).
//
// It is root's copy, in the root-only directory, because the credential it
// comes from lives in the agent work dir, which the service user owns: a
// helper reading the CA from there would let a compromised service user name
// the authority that may install software as root.
const AgentClusterCAName = "cluster-ca.crt"

// AgentClusterCAPath is the full path of that copy.
var AgentClusterCAPath = filepath.Join(MeshKeyDir, AgentClusterCAName)

// agentClusterCAMode is the copy's mode: a CA certificate is public.
const agentClusterCAMode fs.FileMode = 0o644

// netdClusterCAPath is the --cluster-ca netd is given: the server's own
// cluster CA in its PKI dir, or a worker's root-only copy.
func (c Config) netdClusterCAPath() string {
	if c.Role == RoleAgent {
		return AgentClusterCAPath
	}
	return certs.ClusterCACertPath(c.serverWorkDir())
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
func provisionAgentClusterCA(sys System, cfg Config, verified []byte) error {
	if cfg.Role != RoleAgent {
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

func writeAgentClusterCA(sys System, caPEM []byte, cfg Config, from string) error {
	if err := sys.WriteRootOnlyFile(AgentClusterCAPath, caPEM, agentClusterCAMode); err != nil {
		return fmt.Errorf("install: write the worker's cluster CA %s: %w", AgentClusterCAPath, err)
	}
	cfg.Logger.Info("wrote the cluster CA the worker's root helper checks managed updates against", "path", AgentClusterCAPath, "from", from)
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
