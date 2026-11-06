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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
)

const (
	statusNodeCredential = "/var/lib/k3sm/agent/kubeconfig"
	statusClusterCA      = "/var/lib/k3sm/keys/cluster-ca.crt"
	statusWorkDirFixture = "/var/lib/k3sm/server"
)

// credentialKubeconfig renders the shape the join writes, its CA inline.
func credentialKubeconfig(t *testing.T, caPEM []byte, mutate func(*clientcmdapi.Config)) string {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://192.0.2.1:6443", CertificateAuthorityData: caPEM}
	cfg.AuthInfos["node"] = &clientcmdapi.AuthInfo{Token: "node-token"}
	cfg.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "node"}
	cfg.CurrentContext = "k3sm"
	if mutate != nil {
		mutate(cfg)
	}
	data, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatalf("encode kubeconfig: %v", err)
	}
	return string(data)
}

// TestStatusAsRootReadsCheckedBytes walks the two default installs and each file
// a read-only report has to refuse.
func TestStatusAsRootReadsCheckedBytes(t *testing.T) {
	fileCA, anchor := fixtureCA(t), fixtureCA(t)
	adminKubeconfig := executor.KubeconfigPath(statusWorkDirFixture)
	node := credentialKubeconfig(t, fileCA, nil)
	withExec := credentialKubeconfig(t, fileCA, func(c *clientcmdapi.Config) {
		c.AuthInfos["node"] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{APIVersion: "client.authentication.k8s.io/v1", Command: "/elsewhere/plugin", InteractiveMode: clientcmdapi.NeverExecInteractiveMode}}
	})

	t.Run("default server", func(t *testing.T) {
		in := statusKubeInputs{
			role: install.RoleServer, workDir: statusWorkDirFixture, exists: func(string) bool { return false },
			root: fakeRootSources("", map[string]sudoKubeconfigFile{
				adminKubeconfig:            regular(501, 0o600, kubeconfigWithUser(`{token: admin-token}`)),
				install.AgentClusterCAPath: regular(0, 0o644, string(anchor)),
			}, nil),
		}
		kube, source, err := newStatusKube(in)
		if err != nil {
			t.Fatalf("newStatusKube: %v", err)
		}
		rk := kube.(restKube)
		if source != adminKubeconfig || rk.server != "https://192.0.2.1:6443" || rk.cfg.BearerToken != "admin-token" {
			t.Errorf("source = %q, server = %q, token = %q", source, rk.server, rk.cfg.BearerToken)
		}
	})
	t.Run("default worker: the node credential, with the CA from the root copy", func(t *testing.T) {
		in := statusKubeInputs{
			role: install.RoleAgent, nodeKubeconfig: statusNodeCredential, clusterCA: statusClusterCA,
			stat: func(string) error { t.Error("a worker as root went through stat"); return nil },
			root: fakeRootSources("", map[string]sudoKubeconfigFile{
				statusNodeCredential: regular(501, 0o600, node),
				statusClusterCA:      regular(0, 0o644, string(anchor)),
			}, nil),
		}
		kube, source, err := newStatusKube(in)
		if err != nil {
			t.Fatalf("newStatusKube: %v", err)
		}
		rk := kube.(restKube)
		if source != statusNodeCredential || rk.server != "https://192.0.2.1:6443" {
			t.Errorf("source = %q, server = %q", source, rk.server)
		}
		if !bytes.Equal(rk.cfg.CAData, anchor) || rk.tls != "ca pinned" {
			t.Errorf("the client's CA is the root copy = %t, posture %q", bytes.Equal(rk.cfg.CAData, anchor), rk.tls)
		}
	})

	refusals := []struct {
		name  string
		in    statusKubeInputs
		files map[string]sudoKubeconfigFile
		want  []string
	}{
		{
			name:  "worker with no root copy says how to get one",
			in:    statusKubeInputs{role: install.RoleAgent},
			files: map[string]sudoKubeconfigFile{statusNodeCredential: regular(501, 0o600, node)},
			want:  []string{"root-only cluster CA", "sudo k3sm install --agent --server"},
		},
		{
			name: "worker whose root copy has another owner",
			in:   statusKubeInputs{role: install.RoleAgent},
			files: map[string]sudoKubeconfigFile{
				statusNodeCredential: regular(501, 0o600, node),
				statusClusterCA:      regular(501, 0o644, string(anchor)),
			},
			want: []string{"owned by uid 501, not root"},
		},
		{
			name: "worker credential with a plugin",
			in:   statusKubeInputs{role: install.RoleAgent},
			files: map[string]sudoKubeconfigFile{
				statusNodeCredential: regular(501, 0o600, withExec),
				statusClusterCA:      regular(0, 0o644, string(anchor)),
			},
			want: []string{"runs a credential plugin", "sudo k3sm install"},
		},
		{
			name:  "worker with no credential",
			in:    statusKubeInputs{role: install.RoleAgent},
			files: map[string]sudoKubeconfigFile{statusClusterCA: regular(0, 0o644, string(anchor))},
			want:  []string{"no node credential at " + statusNodeCredential},
		},
		{
			name:  "server work dir kubeconfig with a plugin",
			in:    statusKubeInputs{role: install.RoleServer},
			files: map[string]sudoKubeconfigFile{adminKubeconfig: regular(501, 0o600, kubeconfigWithUser(execUser))},
			want:  []string{"runs a credential plugin", "sudo k3sm restart"},
		},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.in
			in.nodeKubeconfig, in.clusterCA, in.workDir = statusNodeCredential, statusClusterCA, statusWorkDirFixture
			in.exists = func(string) bool { return false }
			in.root = fakeRootSources("", tt.files, nil)
			kube, _, err := newStatusKube(in)
			if err == nil || kube != nil {
				t.Fatalf("newStatusKube = %v, %v, want a refusal", kube, err)
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err %q does not contain %q", err, want)
				}
			}
		})
	}
}

// TestStatusInputsAsRootTakeNothingFromTheEnvironmentHome pins the production
// inputs: root's choice is set, and the home comes from the user database.
func TestStatusInputsAsRootTakeNothingFromTheEnvironmentHome(t *testing.T) {
	t.Setenv("HOME", envHome)
	if got := statusKubeInputsFor(install.RoleServer, status.Paths{}); got.root != nil {
		t.Errorf("another account's inputs carry root's choice: %+v", got.root)
	}
	asRoot(t)
	got := statusKubeInputsFor(install.RoleAgent, status.Paths{})
	if got.root == nil || got.clusterCA != install.AgentClusterCAPath {
		t.Errorf("root = %v, clusterCA = %q", got.root, got.clusterCA)
	}
	if got.home == envHome {
		t.Errorf("home = %q, from the environment", got.home)
	}
}

// TestRootUserContextAcceptsOnlyTheJoinedCluster pins the worker's fallback as
// root: checked bytes, and only a context pointing at the joined server.
func TestRootUserContextAcceptsOnlyTheJoinedCluster(t *testing.T) {
	join := status.JoinAnchor("192.0.2.1")
	aliceConfig := filepath.Join(aliceHome, ".kube", "config")
	files := func(uid uint32, body string) map[string]sudoKubeconfigFile {
		return map[string]sudoKubeconfigFile{aliceConfig: regular(uid, 0o600, body)}
	}
	t.Run("the named context", func(t *testing.T) {
		cfg, err := fakeRootSources("alice", files(aliceUID, inlineKubeconfigText), nil).userContext("", "k3sm", join)
		if err != nil {
			t.Fatalf("userContext: %v", err)
		}
		if cfg.checked == nil || cfg.checked.cfg.CurrentContext != "k3sm" {
			t.Errorf("checked = %+v", cfg.checked)
		}
	})
	t.Run("another cluster gives none", func(t *testing.T) {
		_, err := fakeRootSources("alice", files(aliceUID, inlineKubeconfigText), nil).userContext("", "k3sm", status.JoinAnchor("198.51.100.1"))
		if err == nil || !strings.Contains(err.Error(), "points at the server this Mac joined") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a plugin is refused", func(t *testing.T) {
		_, err := fakeRootSources("alice", files(aliceUID, kubeconfigWithUser(execUser)), nil).userContext("", "k3sm", join)
		if err == nil || !strings.Contains(err.Error(), "runs a credential plugin") {
			t.Errorf("err = %v, want a refusal", err)
		}
	})
}

// TestUserKubeAsRootTakesOnlyCheckedFiles names a kubeconfig another account would
// use, and root refuses it by its owner.
func TestUserKubeAsRootTakesOnlyCheckedFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the fixture's owner is the test account, which must not be root")
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(kubeconfigWithUser(`{token: inline-token}`)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
	t.Setenv("SUDO_USER", "")
	if installedKubeconfigName() != installedContextName {
		t.Skip("this Mac's install names its own kubeconfig context")
	}
	join := func() (string, error) { return "192.0.2.1", nil }
	statusDir := t.TempDir()

	if _, source, err := statusUserKubeFor(install.RoleAgent, join, statusDir)(); err != nil || !strings.Contains(source, path) {
		t.Fatalf("as another account: source %q, err %v", source, err)
	}
	asRoot(t)
	_, source, err := statusUserKubeFor(install.RoleAgent, join, statusDir)()
	if err == nil || !strings.Contains(err.Error(), "not root") {
		t.Errorf("as root: source %q, err %v, want a refusal by owner", source, err)
	}
}
