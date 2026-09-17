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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/nodecred"
)

// agentPaths is an agent-role install laid out exactly like a real one: the
// worker's own daemon, its log, and the node credential store under the data
// root.
func agentPaths(workDir string) Paths {
	p := testPaths(workDir)
	p.AgentLabel = "io.k3sm.agent"
	p.AgentLog = "/var/log/k3sm/agent.log"
	p.AgentCredentialDir = "/var/lib/k3sm/agent"
	return p
}

// agentInstalledFS is a complete agent install on disk: the binary, the
// launcher symlink, the netd plist and the AGENT plist — and deliberately no
// server plist, because a worker never has one.
func agentInstalledFS(p Paths) fakeFS {
	return fakeFS{
		present: map[string]bool{
			p.Binary:     true,
			p.NetdSocket: true,
			filepath.Join(p.LaunchDaemonDir, p.NetdLabel+".plist"):  true,
			filepath.Join(p.LaunchDaemonDir, p.AgentLabel+".plist"): true,
		},
		links:    map[string]string{p.Link: p.Binary},
		tail:     map[string][]string{},
		contents: map[string][]byte{},
	}
}

// withCredential stages a COMPLETE node credential store in a fake filesystem:
// all five artifacts the agent writes, with matching keypairs, so the report's
// verdict is produced by the same validation the daemon runs — not by a fixture
// that only looks complete.
func withCredential(t *testing.T, fsys fakeFS, dir string, notAfter time.Time) fakeFS {
	t.Helper()
	certPEM, keyPEM := selfSigned(t, notAfter)
	files := map[string][]byte{
		nodecred.KubeconfigFile:     nodeKubeconfigBytes(t, certPEM, keyPEM),
		nodecred.ServingCertFile:    certPEM,
		nodecred.ServingKeyFile:     keyPEM,
		nodecred.ClientCAFile:       certPEM,
		nodecred.NodeAssignmentFile: []byte(`{"podCIDR":"100.64.2.0/24","meshIP":"100.64.2.1"}`),
	}
	for name, blob := range files {
		path := filepath.Join(dir, name)
		fsys.present[path] = true
		fsys.contents[path] = blob
	}
	return fsys
}

// selfSigned mints a certificate and its matching private key, expiring at
// notAfter. It is minted per case rather than loaded from testdata because the
// expiry is the value under test — a fixture certificate would expire and turn
// this gate into a time bomb — and because the keypair must genuinely MATCH:
// the store proves every pair with tls.X509KeyPair, and a fixture that faked
// the key would be testing a validation the daemon does not run.
func selfSigned(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "system:node:k3sm-worker", Organization: []string{"system:nodes"}},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	der8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
}

// nodeKubeconfigBytes builds the file `k3sm agent` persists after a join: a
// kubeconfig whose user entry carries this node's client keypair and whose
// cluster entry carries the CA it was issued under.
func nodeKubeconfigBytes(t *testing.T, certPEM, keyPEM []byte) []byte {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://10.42.0.1:6443", CertificateAuthorityData: certPEM}
	cfg.AuthInfos["node"] = &clientcmdapi.AuthInfo{ClientCertificateData: certPEM, ClientKeyData: keyPEM}
	cfg.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "node"}
	cfg.CurrentContext = "k3sm"
	raw, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return raw
}

// agentCollector is a worker Mac: netd and the agent daemon both running, no
// kubeconfig of its own to read the apiserver with (the ordinary posture — a
// worker's node kubeconfig points at the server's mesh address), and whatever
// credential store the caller staged.
func agentCollector(t *testing.T, p Paths, fsys fakeFS) Collector {
	t.Helper()
	return Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:  fixture(t, "launchctl_netd_running.txt"),
			p.AgentLabel: fixture(t, "launchctl_netd_running.txt"),
		}},
		FS:         fsys,
		Procs:      fakeProcs{live: LivenessRunning},
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
		Paths:      p,
		EUID:       0,
		ServiceUID: 250,
		Now:        func() time.Time { return goldenTime },
		Version:    goldenVersion,
		Host:       goldenHost,
	}
}

// TestStatusReportsTheAgentDaemon is the gate for B310: on a Mac installed as a
// joining worker, `k3sm status` reports the agent daemon AND the credential
// that makes it a cluster member — and on a control plane it reports exactly
// what it always did.
//
// The defect it pins is specific: the install row required the SERVER plist, so
// a perfectly good worker reported "not installed" and the report then had an
// opinion about a control plane that was never meant to be there.
func TestStatusReportsTheAgentDaemon(t *testing.T) {
	t.Parallel()

	t.Run("an agent-role Mac is installed, and its row is the agent daemon", func(t *testing.T) {
		t.Parallel()
		p := agentPaths(t.TempDir())
		fsys := withCredential(t, agentInstalledFS(p), p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
		rep := agentCollector(t, p, fsys).Collect(context.Background())

		if rep.Role != dataroot.RoleAgent {
			t.Fatalf("role = %q, want %q", rep.Role, dataroot.RoleAgent)
		}
		if rep.Verdict == VerdictNotInstalled {
			t.Fatalf("verdict = not-installed on a Mac with the agent plist and the binary on disk\n%s", Render(rep, Style{}))
		}
		if inst, ok := rep.Row(RowInstall); !ok || inst.State != StateOK {
			t.Fatalf("install row = %q (present=%t), want ok\n%s", inst.State, ok, Render(rep, Style{}))
		}
		if _, ok := rep.Row(RowServer); ok {
			t.Error("the report carries a server row on a worker — a node is one role or the other")
		}
		agent, ok := rep.Row(RowAgent)
		if !ok {
			t.Fatalf("no agent row\n%s", Render(rep, Style{}))
		}
		if agent.State != StateRunning || agent.Severity != SeverityOK {
			t.Errorf("agent row = %s/%v, want running/ok (%s)", agent.State, agent.Severity, agent.Detail)
		}
		if agent.Wide["label"] != p.AgentLabel || agent.Wide["pid"] == "" {
			t.Errorf("agent row carries no launchd state: %#v", agent.Wide)
		}
		if got := agent.Wide["credential"]; got != string(CredentialValid) {
			t.Errorf("credential = %q, want %q", got, CredentialValid)
		}
		if !strings.Contains(agent.Detail, "node credential valid until") {
			t.Errorf("agent detail = %q, want it to say the credential is valid", agent.Detail)
		}
		// The worker's own two facts are healthy, so the whole node is: the
		// datastore and kubeconfig rows describe a control plane it does not
		// run and must not make it permanently degraded.
		if rep.Verdict != VerdictRunning {
			t.Errorf("verdict = %v (%s), want running\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
		}
		screen := Render(rep, Style{})
		if !strings.Contains(screen, "  agent       running") {
			t.Errorf("the overview does not show the agent row:\n%s", screen)
		}
	})

	t.Run("credential states", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name      string
			stage     func(*testing.T, Paths, fakeFS) fakeFS
			wantState RowState
			wantSev   Severity
			wantCred  CredentialState
			wantIn    string
		}{
			{
				name:      "absent — the daemon is up and has never joined",
				stage:     func(_ *testing.T, _ Paths, fsys fakeFS) fakeFS { return fsys },
				wantState: StateWaiting, wantSev: SeverityWarn, wantCred: CredentialAbsent,
				wantIn: "waiting for a join",
			},
			{
				name: "valid — in date, with room to spare",
				stage: func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
					return withCredential(t, fsys, p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
				},
				wantState: StateRunning, wantSev: SeverityOK, wantCred: CredentialValid,
				wantIn: "node credential valid until",
			},
			{
				name: "expired — past NotAfter, so this worker cannot authenticate",
				stage: func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
					return withCredential(t, fsys, p.AgentCredentialDir, goldenTime.Add(-time.Hour))
				},
				wantState: StateExpired, wantSev: SeverityWarn, wantCred: CredentialExpired,
				wantIn: "the node credential expired on",
			},
			{
				name: "expired — inside the 24h margin, which is the agent's own rule",
				stage: func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
					return withCredential(t, fsys, p.AgentCredentialDir, goldenTime.Add(CredentialExpiryMargin-time.Hour))
				},
				wantState: StateExpired, wantSev: SeverityWarn, wantCred: CredentialExpired,
				wantIn: "the node credential expired on",
			},
			{
				name: "corrupt — the kubeconfig is there and does not parse",
				stage: func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
					fsys = withCredential(t, fsys, p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
					fsys.contents[filepath.Join(p.AgentCredentialDir, nodecred.KubeconfigFile)] = []byte("not a kubeconfig")
					return fsys
				},
				wantState: StateCorrupt, wantSev: SeverityFail, wantCred: CredentialCorrupt,
				wantIn: "does not parse",
			},
			{
				name: "unknown — the store is not readable as this user, which is not a fault",
				stage: func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
					fsys = withCredential(t, fsys, p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
					fsys.denied = map[string]bool{filepath.Join(p.AgentCredentialDir, nodecred.KubeconfigFile): true}
					return fsys
				},
				wantState: StateRunning, wantSev: SeverityUnknown, wantCred: CredentialUnknown,
				wantIn: "not readable as this user",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				p := agentPaths(t.TempDir())
				fsys := c.stage(t, p, agentInstalledFS(p))
				rep := agentCollector(t, p, fsys).Collect(context.Background())
				agent, ok := rep.Row(RowAgent)
				if !ok {
					t.Fatalf("no agent row\n%s", Render(rep, Style{}))
				}
				if agent.State != c.wantState || agent.Severity != c.wantSev {
					t.Errorf("agent row = %s/%v, want %s/%v (%s)", agent.State, agent.Severity, c.wantState, c.wantSev, agent.Detail)
				}
				if got := agent.Wide["credential"]; got != string(c.wantCred) {
					t.Errorf("credential = %q, want %q", got, c.wantCred)
				}
				if !strings.Contains(agent.Detail, c.wantIn) {
					t.Errorf("agent detail = %q, want it to contain %q", agent.Detail, c.wantIn)
				}
				// Every unhealthy credential names what to do about it, and the
				// remedy spans two Macs: the token is minted on the server.
				if c.wantSev == SeverityWarn && !strings.Contains(agent.Remedy, "k3sm token create") {
					t.Errorf("remedy = %q, want it to name the token the operator mints on the control plane", agent.Remedy)
				}
			})
		}
	})

	t.Run("a stopped agent daemon is stopped, not merely degraded", func(t *testing.T) {
		t.Parallel()
		p := agentPaths(t.TempDir())
		fsys := withCredential(t, agentInstalledFS(p), p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
		c := agentCollector(t, p, fsys)
		c.Launchd = fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:  fixture(t, "launchctl_netd_running.txt"),
			p.AgentLabel: fixture(t, "launchctl_stopped_clean.txt"),
		}}
		rep := c.Collect(context.Background())
		if rep.Verdict != VerdictStopped {
			t.Fatalf("verdict = %v (%s), want stopped\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
		}
		if !strings.Contains(rep.Summary, p.AgentLabel) {
			t.Errorf("summary = %q, want it to name the daemon that is down", rep.Summary)
		}
	})

	t.Run("a server-role Mac is untouched by any of this", func(t *testing.T) {
		t.Parallel()
		workDir := t.TempDir()
		// The same Mac, reported twice: once by a collector that knows about
		// the agent role and once by one that does not. A server screen that
		// differs by a byte is a regression in the role work.
		withAgent := agentPaths(workDir)
		withoutAgent := testPaths(workDir)

		fsys := installedFS(withAgent)
		fsys.contents = map[string][]byte{}
		// Even a credential store left behind by a previous agent install must
		// not put an agent row on a control plane's screen.
		fsys = withCredential(t, fsys, withAgent.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))

		roleAware := agentCollector(t, withAgent, fsys)
		roleAware.Launchd = fakeLaunchd{out: map[string][]byte{
			withAgent.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
			withAgent.ServerLabel: fixture(t, "launchctl_netd_running.txt"),
		}}
		unaware := roleAware
		unaware.Paths = withoutAgent

		rep := roleAware.Collect(context.Background())
		if rep.Role != dataroot.RoleServer {
			t.Fatalf("role = %q, want %q", rep.Role, dataroot.RoleServer)
		}
		if _, ok := rep.Row(RowAgent); ok {
			t.Error("a control plane's report carries an agent row")
		}
		if _, ok := rep.Row(RowServer); !ok {
			t.Fatal("no server row on a control plane")
		}
		got, want := Render(rep, Style{}), Render(unaware.Collect(context.Background()), Style{})
		if got != want {
			t.Errorf("the server screen changed:\n--- role-aware ---\n%s\n--- as before ---\n%s", got, want)
		}
	})

	t.Run("both plists on disk: the server leads, and the report says so", func(t *testing.T) {
		t.Parallel()
		p := agentPaths(t.TempDir())
		fsys := installedFS(p)
		fsys.contents = map[string][]byte{}
		fsys.present[filepath.Join(p.LaunchDaemonDir, p.AgentLabel+".plist")] = true

		c := agentCollector(t, p, fsys)
		c.Launchd = fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
			p.ServerLabel: fixture(t, "launchctl_netd_running.txt"),
		}}
		rep := c.Collect(context.Background())

		if rep.Role != dataroot.RoleServer {
			t.Fatalf("role = %q, want the server to lead", rep.Role)
		}
		if _, ok := rep.Row(RowAgent); ok {
			t.Error("the report describes both daemons at once")
		}
		inst, _ := rep.Row(RowInstall)
		if !strings.Contains(inst.Detail, p.AgentLabel) {
			t.Errorf("install detail = %q, want it to say the agent plist is on disk too", inst.Detail)
		}
		if !strings.Contains(inst.Detail, "3 LaunchDaemons") {
			t.Errorf("install detail = %q, want it to count the plist it found", inst.Detail)
		}
	})
}

// TestWorkerStatusIsNotDegradedByItsControlPlane is the pkg half of the B324
// gate: on a worker, the apiserver and node rows describe a control plane on
// ANOTHER Mac, so they warn and never carry the verdict — and a leftover
// control-plane work dir is named as a leftover rather than reported on. The
// cmd half (which credentials are resolved, and what is dialled) is
// cmd/k3sm's TestStatusOnAWorkerNeverProbesTheLoopbackApiserver.
func TestWorkerStatusIsNotDegradedByItsControlPlane(t *testing.T) {
	t.Parallel()

	// worker is a joined worker whose credential is in date, with whatever
	// apiserver seam the case describes.
	worker := func(t *testing.T, kube Kube, stale bool) Report {
		t.Helper()
		p := agentPaths(t.TempDir())
		fsys := withCredential(t, agentInstalledFS(p), p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
		if stale {
			fsys.present[p.WorkDir] = true
		}
		c := agentCollector(t, p, fsys)
		c.Kube = kube
		return c.Collect(context.Background())
	}

	unreachable := fakeKube{
		rawErr: map[string]error{"/readyz": errors.New("dial tcp: connect: connection refused")},
		server: "https://100.64.1.1:6444",
		tls:    "ca pinned",
	}

	t.Run("an unreachable control plane warns and leaves the verdict at the worker's own health", func(t *testing.T) {
		t.Parallel()
		rep := worker(t, unreachable, false)

		api, ok := rep.Row(RowAPIServer)
		if !ok {
			t.Fatalf("no apiserver row\n%s", Render(rep, Style{}))
		}
		if api.Severity != SeverityWarn {
			t.Errorf("apiserver row severity = %v, want warn: a worker does not run the control plane it could not reach", api.Severity)
		}
		if !strings.Contains(api.Detail, "another Mac") {
			t.Errorf("apiserver row = %q, want it to say the control plane is elsewhere", api.Detail)
		}
		if strings.Contains(api.Remedy, "launchctl kickstart") {
			t.Errorf("apiserver remedy restarts a control plane this Mac does not have: %q", api.Remedy)
		}
		if rep.Verdict != VerdictRunning {
			t.Errorf("verdict = %v (%s), want running\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
		}
	})

	t.Run("a cluster whose nodes are not ready does not degrade the worker", func(t *testing.T) {
		t.Parallel()
		notReady := readyNode("other-mac")
		notReady.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}
		rep := worker(t, fakeKube{
			raw:    map[string][]byte{"/readyz": []byte("ok")},
			nodes:  []corev1.Node{notReady},
			server: "https://100.64.1.1:6444",
			tls:    "ca pinned",
		}, false)

		node, ok := rep.Row(RowNode)
		if !ok {
			t.Fatal("no node row")
		}
		if node.Severity != SeverityWarn {
			t.Errorf("node row severity = %v, want warn on a worker", node.Severity)
		}
		if rep.Verdict != VerdictRunning {
			t.Errorf("verdict = %v (%s), want running\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
		}
	})

	t.Run("a leftover control-plane work dir is named as a leftover", func(t *testing.T) {
		t.Parallel()
		rep := worker(t, unreachable, true)

		inst, ok := rep.Row(RowInstall)
		if !ok {
			t.Fatal("no install row")
		}
		if !strings.Contains(inst.Detail, "control-plane data directory") {
			t.Errorf("install row = %q, want the stale control-plane directory named", inst.Detail)
		}
		if inst.Severity != SeverityOK {
			t.Errorf("install row severity = %v; the note is advisory and must not move the verdict", inst.Severity)
		}
		if rep.Verdict != VerdictRunning {
			t.Errorf("verdict = %v (%s), want running\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
		}
	})

	t.Run("a worker that has never joined says so instead of naming an apiserver", func(t *testing.T) {
		t.Parallel()
		p := agentPaths(t.TempDir())
		rep := agentCollector(t, p, agentInstalledFS(p)).Collect(context.Background())

		api, ok := rep.Row(RowAPIServer)
		if !ok {
			t.Fatal("no apiserver row")
		}
		if !strings.Contains(api.Detail, "has not joined") {
			t.Errorf("apiserver row = %q, want it to say this Mac has not joined", api.Detail)
		}
		if api.Wide["server"] != "" {
			t.Errorf("apiserver row names a server on a Mac that has never joined: %q", api.Wide["server"])
		}
	})

	t.Run("a control plane is unchanged: its own apiserver being down is a failure", func(t *testing.T) {
		t.Parallel()
		p := testPaths(t.TempDir())
		c := Collector{
			Launchd: fakeLaunchd{out: map[string][]byte{
				p.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
				p.ServerLabel: fixture(t, "launchctl_netd_running.txt"),
			}},
			FS:         installedFS(p),
			Kube:       fakeKube{rawErr: map[string]error{"/readyz": errors.New("connection refused")}, server: "https://127.0.0.1:6444", tls: "ca pinned"},
			Procs:      fakeProcs{live: LivenessRunning},
			DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
			Paths:      p,
			EUID:       0,
			ServiceUID: 250,
			Now:        func() time.Time { return goldenTime },
			Version:    goldenVersion,
			Host:       goldenHost,
		}
		rep := c.Collect(context.Background())

		api, ok := rep.Row(RowAPIServer)
		if !ok {
			t.Fatal("no apiserver row")
		}
		if api.Severity != SeverityFail {
			t.Errorf("apiserver row severity = %v on a control plane, want fail", api.Severity)
		}
		if rep.Verdict != VerdictDegraded {
			t.Errorf("verdict = %v (%s), want degraded\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
		}
	})
}
