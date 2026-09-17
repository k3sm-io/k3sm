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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/nodecred"
)

// nodeCredentialFixture is a complete, parseable node credential for ONE test
// cluster: the five artifacts pkg/nodecred validates, plus the join token whose
// K10 CA hash pins that cluster's CA. Two fixtures are two clusters, which is
// the whole point — a credential is only proof of THIS join if it names the
// cluster this install's token names.
type nodeCredentialFixture struct {
	files map[string][]byte
	token string
}

// mintNodeCredential issues a cluster CA and the material a completed join
// leaves in the agent work dir. The lifetimes are days rather than minutes
// because pkg/nodecred calls a client cert inside its 24h expiry margin
// EXPIRED, and an expired fixture would be describing a different case than the
// one under test.
func mintNodeCredential(t *testing.T, dir string) nodeCredentialFixture {
	t.Helper()
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("mint the cluster CA: %v", err)
	}
	clientCert, clientKey, err := ca.IssueClient("system:node:worker", []string{"system:nodes"}, 72*time.Hour)
	if err != nil {
		t.Fatalf("issue the node client keypair: %v", err)
	}
	servingCert, servingKey, err := ca.IssueServing("worker", []string{"worker"}, []net.IP{net.ParseIP("100.64.0.7")}, 72*time.Hour)
	if err != nil {
		t.Fatalf("issue the kubelet serving keypair: %v", err)
	}
	pin, err := certs.CertPin(ca.CertPEM)
	if err != nil {
		t.Fatalf("pin the cluster CA: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: "https://100.64.0.1:6444"
    certificate-authority-data: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: system:node:worker
current-context: k3sm
users:
- name: system:node:worker
  user:
    client-certificate-data: %s
    client-key-data: %s
`, b64(ca.CertPEM), b64(clientCert), b64(clientKey))
	return nodeCredentialFixture{
		files: map[string][]byte{
			filepath.Join(dir, nodecred.KubeconfigFile):     []byte(kubeconfig),
			filepath.Join(dir, nodecred.ServingCertFile):    servingCert,
			filepath.Join(dir, nodecred.ServingKeyFile):     servingKey,
			filepath.Join(dir, nodecred.ClientCAFile):       ca.CertPEM,
			filepath.Join(dir, nodecred.NodeAssignmentFile): []byte(`{"podCIDR":"10.42.1.0/24","meshIP":"100.64.0.7"}`),
		},
		token: "K10" + pin + "::node:s3cr3t",
	}
}

// seed writes the whole credential into the fake root filesystem.
func (c nodeCredentialFixture) seed(f *fakeSystem) {
	for path, content := range c.files {
		f.putFile(path, content)
	}
}

// seedAppearingDuringThePoll writes the credential with its KUBECONFIG held back
// for the first reads reads — a join that completes while the installer is
// already waiting. The kubeconfig is the artifact pkg/nodecred looks for first,
// so holding it back is enough to make the whole credential read as absent.
func (c nodeCredentialFixture) seedAppearingDuringThePoll(f *fakeSystem, dir string, reads int) {
	kubeconfig := filepath.Join(dir, nodecred.KubeconfigFile)
	for path, content := range c.files {
		if path == kubeconfig {
			f.putFileAfterReads(path, content, reads)
			continue
		}
		f.putFile(path, content)
	}
}

// seedAgentCrashRecord writes a crash-loop record where the AGENT daemon keeps
// its own — the witness that says a start failed, which no file's presence can.
func seedAgentCrashRecord(t *testing.T, f *fakeSystem, cfg Config, rec executor.CrashRecord) string {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	path := executor.CrashLoopPath(cfg.agentWorkDir())
	f.putFile(path, b)
	return path
}

// agentStartFailure is one recorded bring-up failure, in the shape `k3sm agent`
// writes when it backs off from a terminal start failure.
func agentStartFailure(at time.Time, detail string) executor.Crash {
	return executor.Crash{At: at, Origin: executor.CrashOriginBringUp, Component: "agent", Detail: detail}
}

// TestVerifyAgentJoinedIgnoresAPreExistingCredential is the regression for the
// 2026-09-17 install that announced "the agent joined the cluster" while the
// daemon was crash-looping on "persist node-password: permission denied".
//
// The check waited for the node credential to EXIST — and on a Mac that had been
// installed before, it already did. A file cannot attest THIS install's daemon:
// it says only that some start, at some point, once succeeded. The two witnesses
// that can are the ones asserted here: the crash record the agent writes when a
// start fails, and whether the credential names the cluster this install's token
// pins.
func TestVerifyAgentJoinedIgnoresAPreExistingCredential(t *testing.T) {
	installStart := time.Date(2026, 9, 17, 11, 0, 0, 0, time.UTC)
	dir := Config{}.withDefaults().agentWorkDir()

	cases := []struct {
		name string
		// seed describes the Mac at the moment the install starts verifying,
		// and returns the token the operator's file holds.
		seed       func(t *testing.T, f *fakeSystem, cfg Config) string
		wantErr    bool
		wantPhrase []string
	}{
		{
			// (a) The incident. The credential is there, it is even for the
			// right cluster — and the daemon recorded a start failure after
			// this install began.
			name: "a credential from an earlier install cannot cover a start that failed during this one",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				seedAgentCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
					agentStartFailure(installStart.Add(2*time.Second), "persist node-password: permission denied"),
				}})
				return cred.token
			},
			wantErr: true,
			wantPhrase: []string{
				"persist node-password: permission denied",
				"failed to start 1 times since this install began",
				AgentLogPath(),
				"k3sm token create",
			},
		},
		{
			// (b) A credential is present throughout, and it is for another
			// cluster entirely — the shape a Mac moved between clusters has.
			// Nothing else happens, so the wait runs out.
			name: "a credential for a different cluster is a leftover, not a join",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				mintNodeCredential(t, dir).seed(f)
				return mintNodeCredential(t, dir).token // a second cluster's token
			},
			wantErr: true,
			wantPhrase: []string{
				"DIFFERENT cluster",
				AgentCredentialPath(""),
				AgentLogPath(),
				"k3sm token create",
			},
		},
		{
			// (c) The reinstall that resumes: the node already holds a valid
			// credential for THIS cluster and writes nothing new, because
			// nothing needs re-issuing. That must pass, or every upgrade of a
			// joined worker fails.
			name: "a reinstall that resumes from the cluster's own credential passes without a new write",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				return cred.token
			},
		},
		{
			// (d) The first join: nothing on disk when the wait starts, and the
			// credential lands while the installer is polling.
			name: "a first join that completes during the wait passes",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seedAppearingDuringThePoll(f, dir, 3)
				return cred.token
			},
		},
		{
			// (e) The fault an operator is reinstalling to FIX. It is in the
			// record, it is older than this install, and it fails nothing.
			name: "a start failure older than this install is the fault being reinstalled over",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				seedAgentCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
					agentStartFailure(installStart.Add(-30*time.Minute), "join: the server rejected this token"),
				}})
				return cred.token
			},
		},
		{
			// (f) Bookkeeping is not a verdict: an unreadable record must not
			// fail an install that has every other reason to pass, for the same
			// reason the daemon treats a corrupt record as empty.
			name: "a malformed record is fail-open, not a refusal",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				f.putFile(executor.CrashLoopPath(cfg.agentWorkDir()), []byte("{not json"))
				return cred.token
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := &fakeSystem{}
			cfg := agentCfg(t).withDefaults()
			f.putFile(cfg.TokenFile, []byte(tc.seed(t, f, cfg)+"\n"))

			err := verifyAgentJoined(context.Background(), f, cfg, installStart)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("verifyAgentJoined: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("verifyAgentJoined reported a join this install has no witness for")
			}
			for _, want := range tc.wantPhrase {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must carry %q — the operator needs what failed and what to do next", err, want)
				}
			}
		})
	}
}

// TestVerifyAgentJoinedIsScopedToAStagedToken keeps the two negative halves of
// the contract: a control-plane install runs no agent to verify, and an agent
// install that staged NO token asked for no join — the daemon starts from
// whatever it holds, and an installer that judged that would be failing an
// install over a state it did not create and cannot fix.
func TestVerifyAgentJoinedIsScopedToAStagedToken(t *testing.T) {
	shrinkRestartBudgets(t)
	installStart := time.Now()
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"a server install has no agent to verify", installCfg().withDefaults()},
		{"an agent install that staged no token asked for no join", func() Config {
			c := agentCfg(t).withDefaults()
			c.TokenFile = ""
			return c
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{}
			// Deliberately empty: a record of failures and no credential at
			// all. Neither posture may look at either.
			seedAgentCrashRecord(t, f, agentCfg(t).withDefaults(), executor.CrashRecord{Crashes: []executor.Crash{
				agentStartFailure(installStart.Add(time.Second), "the cluster rejected this token"),
			}})
			if err := verifyAgentJoined(context.Background(), f, tc.cfg, installStart); err != nil {
				t.Fatalf("verifyAgentJoined: %v", err)
			}
		})
	}
}
