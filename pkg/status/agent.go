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
	"errors"
	"io/fs"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/nodecred"
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
// pkg/nodecred's verdict, plus the one posture a daemon never has to name —
// "this account may not read the store at all". It is a string type so `-o
// json` carries the word rather than an integer whose meaning lives in a file.
type CredentialState string

// The credential vocabulary. The first four are nodecred's states verbatim; the
// fifth is this report's own.
const (
	// CredentialValid: every artifact is present, parses, and is in date.
	CredentialValid CredentialState = "valid"
	// CredentialAbsent: at least one artifact is missing — this worker has
	// never completed a join, or its state was wiped.
	CredentialAbsent CredentialState = "absent"
	// CredentialExpired: the node client certificate is within
	// CredentialExpiryMargin of NotAfter, or the serving certificate is past
	// it.
	CredentialExpired CredentialState = "expired"
	// CredentialCorrupt: an artifact is present and does not parse, or a
	// private key does not match its certificate.
	CredentialCorrupt CredentialState = "corrupt"
	// CredentialUnknown: the store could not be READ from this account (the
	// agent work dir is service-user-owned), or no store was configured. It is
	// deliberately distinct from absent: "I could not look" is not "it is not
	// there", and only one of those two is a fault.
	CredentialUnknown CredentialState = "unknown"
)

// CredentialExpiryMargin is how far ahead of the node client certificate's
// NotAfter this report already calls the credential expired. It IS the agent's
// own margin — the constant, not a copy of its value.
const CredentialExpiryMargin = nodecred.ExpiryMargin

// NodeCredentialState reports what the node credential store in dir holds, and
// when this node's client certificate expires (the zero time when no
// certificate could be read).
//
// The verdict is pkg/nodecred's, unchanged: the same five artifacts, the same
// keypair proofs, the same expiry rule the agent's start decision runs. That is
// the whole point of the seam — a looser check here would report "valid" about
// a credential the daemon refuses to start with, which is a green row on a Mac
// that is not in the cluster.
//
// The one thing this function adds is the UNREADABLE arm. A daemon reading its
// own store never hits it; a status command run without sudo hits it almost
// every time, and calling that "corrupt" would accuse a healthy worker of
// damage. Permission is therefore separated out of nodecred's corrupt verdict
// by asking the wrapped error, which is why nodecred wraps rather than
// flattens.
//
// It is a READ, never a repair: a corrupt store is reported and left exactly as
// it is, because the remedy re-issues this node's identity and that is an
// operator's decision, not a status command's.
func NodeCredentialState(fsys FS, dir string, now time.Time) (CredentialState, time.Time) {
	if fsys == nil || dir == "" {
		return CredentialUnknown, time.Time{}
	}
	state, cred, err := nodecred.Status(fsys, dir, now)
	notAfter := time.Time{}
	if cred != nil {
		notAfter = cred.ClientNotAfter
	}
	switch state {
	case nodecred.Valid:
		return CredentialValid, notAfter
	case nodecred.Absent:
		return CredentialAbsent, time.Time{}
	case nodecred.Expired:
		return CredentialExpired, notAfter
	default:
		if errors.Is(err, fs.ErrPermission) {
			return CredentialUnknown, time.Time{}
		}
		return CredentialCorrupt, time.Time{}
	}
}

// installedRole reports which node this Mac is installed as, decided from the
// two node-daemon plists through the FS seam, plus whether BOTH are on disk.
//
// The decision itself is dataroot.RoleFromPlists — one home, shared with the
// installer — and this method only supplies the two booleans. Nothing here
// consults a pid: see RoleFromPlists for why a running process cannot answer
// which node a Mac is.
func (c Collector) installedRole() (role dataroot.Role, installed, both bool) {
	server := c.Paths.ServerLabel != "" && c.exists(c.plistPath(c.Paths.ServerLabel))
	agent := c.Paths.AgentLabel != "" && c.exists(c.plistPath(c.Paths.AgentLabel))
	role, installed = dataroot.RoleFromPlists(server, agent)
	return role, installed, server && agent
}

// nodeLabel is the launchd label of the node daemon THIS Mac runs.
func (c Collector) nodeLabel(role dataroot.Role) string {
	if role == dataroot.RoleAgent {
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
