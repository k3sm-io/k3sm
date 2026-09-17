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

package status

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/install"
)

// The worker's half of the report: which node this Mac is, and — when it is a
// joining worker — whether it actually holds the credential that makes it one.
//
// A worker's health is TWO facts, not one. launchd will happily keep a `k3sm
// agent` pid alive that has never joined anything: a wrong or expired token
// leaves the daemon in its own backoff with a perfectly healthy process. So a
// report that stopped at the pid would show a green row on a Mac that is not in
// the cluster at all, which is exactly the posture an operator runs `k3sm
// status` to rule out.

// CredentialState is what the node credential store holds, as a REPORT sees it:
// present and usable, never written, no longer usable, unparseable, or not
// readable from this account. It is a string type so `-o json` carries the word
// rather than an integer whose meaning lives in this file.
type CredentialState string

// The credential vocabulary.
const (
	// CredentialValid: every artifact is there and this node's client
	// certificate parses and is in date.
	CredentialValid CredentialState = "valid"
	// CredentialAbsent: at least one artifact is missing — this worker has
	// never completed a join, or its state was wiped.
	CredentialAbsent CredentialState = "absent"
	// CredentialExpired: the client certificate is past NotAfter, or inside
	// CredentialExpiryMargin of it.
	CredentialExpired CredentialState = "expired"
	// CredentialCorrupt: an artifact is present and does not parse.
	CredentialCorrupt CredentialState = "corrupt"
	// CredentialUnknown: the store could not be read from this account (the
	// agent work dir is service-user-owned), or no store was configured. It is
	// deliberately distinct from absent: "I could not look" is not "it is not
	// there", and only one of those two is a fault.
	CredentialUnknown CredentialState = "unknown"
)

// CredentialExpiryMargin is how far ahead of the node client certificate's
// NotAfter this report already calls the credential expired.
//
// It mirrors the margin the agent's own start decision uses, and the two are
// bound by a test on the cmd side rather than by an import: the store itself
// lives in cmd/k3sm, and pkg/status is a reporting leaf that must not pull the
// join stack in behind one row. If that test goes red, `k3sm status` is
// reporting a credential the daemon would refuse to start with — or the other
// way round, which is worse.
const CredentialExpiryMargin = 24 * time.Hour

// The node credential store's file names, as the report reads them. They are
// the store's own names (cmd/k3sm/nodecred.go), pinned to it by the same
// cmd-side test that binds the margin above.
const (
	nodeKubeconfigName     = "node.kubeconfig"
	kubeletServingCertName = "kubelet-serving.crt"
	kubeletServingKeyName  = "kubelet-serving.key"
)

// NodeCredentialState reports what the node credential store in dir holds, and
// when this node's client certificate expires (the zero time when no
// certificate could be read).
//
// It is a READ, never a repair: a corrupt store is reported as corrupt and left
// exactly as it is, because the remedy re-issues this node's identity and that
// is an operator's decision, not a status command's.
//
// The check is deliberately narrower than the agent's own: the three artifacts
// that carry identity must be present, and the client certificate must parse
// and be in date. The agent additionally proves each private key matches its
// certificate before it starts; a report that re-derived that would be claiming
// to have validated a start it does not perform.
func NodeCredentialState(fsys FS, dir string, now time.Time) (CredentialState, time.Time) {
	if fsys == nil || dir == "" {
		return CredentialUnknown, time.Time{}
	}
	for _, name := range []string{nodeKubeconfigName, kubeletServingCertName, kubeletServingKeyName} {
		switch _, err := fsys.Stat(filepath.Join(dir, name)); {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			return CredentialAbsent, time.Time{}
		default:
			// Permission, or anything else this account cannot see past.
			return CredentialUnknown, time.Time{}
		}
	}
	raw, err := fsys.ReadFile(filepath.Join(dir, nodeKubeconfigName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return CredentialAbsent, time.Time{}
		}
		return CredentialUnknown, time.Time{}
	}
	notAfter, err := nodeClientNotAfter(raw)
	if err != nil {
		return CredentialCorrupt, time.Time{}
	}
	if !notAfter.After(now.Add(CredentialExpiryMargin)) {
		return CredentialExpired, notAfter
	}
	return CredentialValid, notAfter
}

// nodeClientNotAfter parses a node kubeconfig and returns its client
// certificate's NotAfter. It resolves through the file's CURRENT CONTEXT rather
// than assuming a name, so it stays the inverse of whatever wrote it.
func nodeClientNotAfter(raw []byte) (time.Time, error) {
	cfg, err := clientcmd.Load(raw)
	if err != nil {
		return time.Time{}, err
	}
	ctx, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok || ctx == nil {
		return time.Time{}, fmt.Errorf("no context %q", cfg.CurrentContext)
	}
	user, ok := cfg.AuthInfos[ctx.AuthInfo]
	if !ok || user == nil || len(user.ClientCertificateData) == 0 {
		return time.Time{}, errors.New("the user entry carries no client certificate")
	}
	block, _ := pem.Decode(user.ClientCertificateData)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("no CERTIFICATE PEM block in the client certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// installedRole reports which node this Mac is installed as, decided from the
// two node-daemon plists through the FS seam, plus whether BOTH are on disk.
//
// The decision itself is install.RoleFromPlists — one home, shared with the
// installer — and this method only supplies the two booleans. Nothing here
// consults a pid: see RoleFromPlists for why a running process cannot answer
// which node a Mac is.
func (c Collector) installedRole() (role install.Role, installed, both bool) {
	server := c.Paths.ServerLabel != "" && c.exists(c.plistPath(c.Paths.ServerLabel))
	agent := c.Paths.AgentLabel != "" && c.exists(c.plistPath(c.Paths.AgentLabel))
	role, installed = install.RoleFromPlists(server, agent)
	return role, installed, server && agent
}

// nodeLabel is the launchd label of the node daemon THIS Mac runs.
func (c Collector) nodeLabel(role install.Role) string {
	if role == install.RoleAgent {
		return c.Paths.AgentLabel
	}
	return c.Paths.ServerLabel
}

// agentRow reports the joining worker's daemon AND the credential that makes it
// a cluster member. It returns the row and the daemon's pid.
//
// The launchd verdict comes first and is never softened: a daemon that is not
// loaded, is disabled or is crash-looping is that, whatever the store holds.
// The credential only re-states a row whose daemon is otherwise healthy —
// which is the one case launchd cannot see past, and the reason this row is not
// just another daemonRow.
func (c Collector) agentRow(now time.Time) (Row, int) {
	row, pid := c.daemonRow(RowAgent, c.Paths.AgentLabel, c.Paths.AgentLog, true)
	state, notAfter := c.credentialState(now)
	row.Wide["credential"] = string(state)
	if c.Paths.AgentCredentialDir != "" {
		row.Wide["credential-dir"] = c.Paths.AgentCredentialDir
	}
	if !notAfter.IsZero() {
		row.Wide["credential-expires"] = notAfter.UTC().Format(time.RFC3339)
	}
	if row.State != StateRunning || row.Severity != SeverityOK {
		return row, pid
	}

	switch state {
	case CredentialValid:
		row.Detail += " · joined, node credential valid until " + notAfter.UTC().Format("2006-01-02")
	case CredentialAbsent:
		row.State, row.Severity = StateWaiting, SeverityWarn
		row.Detail += " · waiting for a join: this Mac holds no node credential yet"
		row.Remedy = c.joinRemedy()
	case CredentialExpired:
		row.State, row.Severity = StateExpired, SeverityWarn
		row.Detail += " · the node credential expired on " + notAfter.UTC().Format("2006-01-02") +
			", so this worker can no longer authenticate"
		row.Remedy = c.joinRemedy()
	case CredentialCorrupt:
		row.State, row.Severity = StateCorrupt, SeverityFail
		row.Detail += " · the stored node credential in " + c.Paths.AgentCredentialDir + " does not parse"
		row.Remedy = "k3sm status logs " + RowAgent + "\n" + c.joinRemedy()
	default:
		// Unknown: the store is service-user-owned, so an ordinary account is
		// EXPECTED not to read it. That is not a healthy verdict and not a
		// fault either — it is the same "could not see this" every other row
		// reports honestly.
		row.Severity = SeverityUnknown
		row.Detail += " · node credential state unknown (not readable as this user)"
		row.Remedy = "sudo k3sm status"
	}
	return row, pid
}

// credentialState reads the node credential store this report is about.
func (c Collector) credentialState(now time.Time) (CredentialState, time.Time) {
	return NodeCredentialState(c.FS, c.Paths.AgentCredentialDir, now)
}

// joinRemedy is what an operator does about a worker with no usable credential.
// It spans two Macs, which is why it is spelled out rather than reduced to a
// reinstall: the token is minted on the CONTROL PLANE and only then does this
// Mac have anything to re-install with.
func (c Collector) joinRemedy() string {
	return "k3sm token create   # on the control-plane Mac\n" +
		"sudo k3sm install --role agent --server <control-plane> --token-file <file>   # on this Mac\n" +
		"k3sm status logs " + RowAgent
}
