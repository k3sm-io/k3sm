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
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
)

// The two addresses of the defect: the one the control plane assigned (and
// which this node therefore registers as its InternalIP, out of the /24 it was
// carved from), and the one an operator asserted at the join, which is all the
// stored certificate names.
const (
	assignedAddress = "100.64.1.1"
	assignedPodCIDR = "100.64.1.0/24"
	certAddress     = "100.64.9.9"
)

// The B340 gate: a worker whose stored kubelet serving certificate names an
// address the control plane did not assign it is NAMED, at the start that
// resumes from that certificate and in `k3sm status`.
//
// The defect: since the assigned mesh address became this node's InternalIP on
// the resume path (credInternalIP/agentInternalIP), a node that joined while
// asserting a wrong `--node-ip` registers the ASSIGNED address while still
// holding the certificate issued for the address it asserted. The apiserver
// dials :10250 at the InternalIP and verifies it against the cluster CA, so
// every `kubectl logs`/`kubectl exec` against that node fails the TLS
// handshake while the node stays Ready, and nothing in the cluster, the log or
// the status report names the certificate as the cause.
//
// What this test is NOT: a live apiserver dial. The handshake itself is the
// lab tier. This is the hermetic half, and it is the half that decides whether
// an operator can find the cause at all: real CA-issued certificates through
// pkg/certs, the real store writer and reader, the real start decision, and
// the real report.
func TestAgentResumeWarnsOnACertificateAddressMismatch(t *testing.T) {
	// Deliberately NOT t.Parallel: the status arm stages a whole Mac and runs
	// the production credential resolution, which sets environment variables.

	t.Run("a stored certificate for another address is an ERROR the start names, and starts anyway", func(t *testing.T) {
		t.Parallel()
		store := savedStore(t, credentialForAddresses(t, assignedAddress, certAddress))

		state, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if state != credentialAddressMismatch {
			t.Fatalf("Status = %s, want %s: the store is complete and in date, and its serving certificate names %s while this node is assigned %s",
				state, credentialAddressMismatch, certAddress, assignedAddress)
		}
		if cred == nil {
			t.Fatal("no credential returned: a mismatch is a loaded credential with a wrong address, not an unreadable one")
		}

		sink := &syncBuffer{}
		logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
		warnCredentialAddressMismatch(logger, startModeReuseCredential, state, cred, "192.168.1.10", "/var/lib/k3sm/agent/join-token")
		out := sink.String()
		if !strings.Contains(out, "level=ERROR") {
			t.Errorf("the mismatch was not reported at ERROR; log was:\n%s", out)
		}
		// BOTH addresses: one of them alone leaves an operator comparing a
		// number against nothing.
		for _, want := range []string{assignedAddress, certAddress} {
			if !strings.Contains(out, want) {
				t.Errorf("the log does not name %s; both the assigned address and the certificate's are what make this legible:\n%s", want, out)
			}
		}
		// The honest clause: the stale certificate is not retired by this
		// start, so the line says what is still true and asks for the rejoin
		// rather than implying the fault is contained.
		for _, want := range []string{"still answers", "Rejoin soon"} {
			if !strings.Contains(out, want) {
				t.Errorf("the log does not carry %q; a line that only says the dial fails overstates how contained this is:\n%s", want, out)
			}
		}
		// The remedy is a command, with this daemon's own argv in it.
		for _, want := range []string{"k3sm install --agent", "--server 192.168.1.10", "--token-file /var/lib/k3sm/agent/join-token", "re-issues"} {
			if !strings.Contains(out, want) {
				t.Errorf("the log does not carry the remedy fragment %q:\n%s", want, out)
			}
		}

		// ...and the agent still starts. A refusal would take a worker down
		// over a fault it has carried since its join, and would not retire the
		// stale certificate either; only a rejoin does that, which is what the
		// line above tells the operator to do soon.
		plan, err := agentStartPlan(state, false, false, "", "")
		if err != nil {
			t.Fatalf("agentStartPlan(%s) = %v; a mismatched certificate must not stop a running worker from starting", state, err)
		}
		if plan != startModeReuseCredential {
			t.Errorf("agentStartPlan(%s) = %s, want %s", state, plan, startModeReuseCredential)
		}
	})

	t.Run("a certificate that names the assigned address is valid and silent", func(t *testing.T) {
		t.Parallel()
		store := savedStore(t, credentialForAddresses(t, assignedAddress, assignedAddress))

		state, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if state != credentialValid {
			t.Fatalf("Status = %s, want valid: the serving certificate names %s, which is the address this node is assigned", state, assignedAddress)
		}

		sink := &syncBuffer{}
		logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
		warnCredentialAddressMismatch(logger, startModeReuseCredential, state, cred, "192.168.1.10", "")
		if out := sink.String(); out != "" {
			t.Errorf("a matching certificate produced a start-time report; a warning every worker sees is a warning nobody reads:\n%s", out)
		}

		// Nor does a start that is about to re-issue the certificate say
		// anything about the one it is replacing.
		mismatched := savedStore(t, credentialForAddresses(t, assignedAddress, certAddress))
		mstate, mcred, err := mismatched.Status(time.Now())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		sink = &syncBuffer{}
		logger = slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
		warnCredentialAddressMismatch(logger, startModeTokenJoin, mstate, mcred, "192.168.1.10", "")
		if out := sink.String(); out != "" {
			t.Errorf("a token join reported a mismatch it is about to fix by re-issuing the certificate:\n%s", out)
		}
	})

	t.Run("k3sm status reports the worker degraded, with the rejoin remedy", func(t *testing.T) {
		// The control: the same staged Mac whose certificate DOES name its
		// assigned address reports running, so the degraded verdict below is
		// this defect and not the fixture.
		healthy := stageNodeMac(t, macOpts{role: install.RoleAgent, joined: true})
		rep, _, err := collectFrom(t, healthy, install.RoleAgent, false)
		if err != nil {
			t.Fatalf("a joined worker could not resolve its own credentials: %v", err)
		}
		if row, ok := rep.Row(status.RowAgent); !ok || row.Severity != status.SeverityOK {
			t.Fatalf("the control worker's agent row = %s/%v (present=%t), want ok\n%s", row.State, row.Severity, ok, status.Render(rep, status.Style{}))
		}
		if rep.Verdict != status.VerdictRunning {
			t.Fatalf("the control worker's verdict = %v (%s), want running\n%s", rep.Verdict, rep.Summary, status.Render(rep, status.Style{}))
		}

		mac := stageNodeMac(t, macOpts{role: install.RoleAgent, joined: true, credentialAddress: certAddress})
		rep, _, err = collectFrom(t, mac, install.RoleAgent, false)
		if err != nil {
			t.Fatalf("a joined worker could not resolve its own credentials: %v", err)
		}
		row, ok := rep.Row(status.RowAgent)
		if !ok {
			t.Fatalf("no agent row\n%s", status.Render(rep, status.Style{}))
		}
		if row.Severity != status.SeverityFail || row.State != status.StateAddressMismatch {
			t.Errorf("agent row = %s/%v, want %s/%v — a node nothing can exec into is not a healthy row (%s)",
				row.State, row.Severity, status.StateAddressMismatch, status.SeverityFail, row.Detail)
		}
		if got := row.Wide["credential"]; got != string(status.CredentialAddressMismatch) {
			t.Errorf("credential = %q, want %q", got, status.CredentialAddressMismatch)
		}
		if !strings.Contains(row.Detail, "different address") {
			t.Errorf("agent detail = %q, want it to say the certificate names a different address", row.Detail)
		}
		// The remedy is the rejoin, and it spans two Macs: the token is minted
		// on the control plane.
		for _, want := range []string{"k3sm token create", "k3sm install --role agent", "--token-file"} {
			if !strings.Contains(row.Remedy, want) {
				t.Errorf("remedy = %q, want it to carry %q", row.Remedy, want)
			}
		}
		if rep.Verdict != status.VerdictDegraded {
			t.Errorf("verdict = %v (%s), want degraded\n%s", rep.Verdict, rep.Summary, status.Render(rep, status.Style{}))
		}
	})

	t.Run("--network none says which address it just registered", func(t *testing.T) {
		t.Parallel()
		mode, err := hostnet.Resolve(hostnet.NetworkNone)
		if err != nil {
			t.Fatalf("resolve --network none: %v", err)
		}

		sink := &syncBuffer{}
		logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
		warnNoDatapathInternalIP(logger, mode, assignedAddress)
		out := sink.String()
		if strings.Count(out, "level=WARN") != 1 {
			t.Errorf("want exactly one WARN line for --network none; log was:\n%s", out)
		}
		for _, want := range []string{assignedAddress, "mesh"} {
			if !strings.Contains(out, want) {
				t.Errorf("the --network none line does not carry %q:\n%s", want, out)
			}
		}

		// Every other backend brings the mesh up, so the address IS reachable
		// and there is nothing to say.
		sink = &syncBuffer{}
		logger = slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
		warnNoDatapathInternalIP(logger, hostnet.Mode{Backend: hostnet.BackendDirect}, assignedAddress)
		if out := sink.String(); out != "" {
			t.Errorf("a backend that runs the mesh datapath warned about reachability:\n%s", out)
		}
	})
}

// credentialForAddresses mints a join outcome whose ASSIGNMENT names assigned
// and whose kubelet serving certificate names certIP.
//
// Passing two different addresses reproduces the on-disk shape of a node that
// joined asserting a `--node-ip` the control plane did not assign: a real
// cluster-CA-issued serving certificate, a matching key, and an assignment
// naming the address the node actually holds on the mesh.
func credentialForAddresses(t *testing.T, assigned, certIP string) *bootstrap.JoinResult {
	t.Helper()
	res, clusterCA, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	res.NodeIP, res.MeshIP = assigned, assigned
	res.PodCIDR = assignedPodCIDR
	cert, key, err := clusterCA.IssueServing(nodeCredTestNode,
		[]string{nodeCredTestNode, "localhost"},
		[]net.IP{net.ParseIP(certIP)}, nodeCredClientTTL)
	if err != nil {
		t.Fatalf("issue a kubelet serving pair for %s: %v", certIP, err)
	}
	res.KubeletServingCertPEM, res.KubeletServingKeyPEM = cert, key
	return res
}
