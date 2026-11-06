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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/kubeclient"
)

const proxiedCluster = `{server: "https://192.0.2.9:6443", proxy-url: "http://192.0.2.10:3128"}`

// writeNamedKubeconfig writes body to a new file only its owner can write.
func writeNamedKubeconfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "named.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// kubeconfigWithCluster is a k3sm context whose cluster is the YAML given.
func kubeconfigWithCluster(clusterYAML string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: k3sm
clusters:
- name: k3sm
  cluster: %s
contexts:
- name: k3sm
  context: {cluster: k3sm, user: k3sm}
users:
- name: k3sm
  user: {token: named-token}
`, clusterYAML)
}

// TestRootParserRefusesWhatTheCheckedLoadRefuses keeps the two root checks one list:
// each entry the checked load refuses is refused for the selected context here too.
func TestRootParserRefusesWhatTheCheckedLoadRefuses(t *testing.T) {
	tests := map[string]string{
		"proxy-url":          kubeconfigWithCluster(proxiedCluster),
		"certificate":        kubeconfigWithCluster(`{server: "https://192.0.2.9:6443", certificate-authority: /elsewhere/ca}`),
		"exec":               kubeconfigWithUser(execUser),
		"auth-provider":      kubeconfigWithUser(`{auth-provider: {name: oidc}}`),
		"tokenFile":          kubeconfigWithUser(`{tokenFile: /elsewhere/token}`),
		"client-certificate": kubeconfigWithUser(`{client-certificate: /elsewhere/crt}`),
		"client-key":         kubeconfigWithUser(`{client-key: /elsewhere/key}`),
		"as":                 kubeconfigWithUser(`{token: t, as: someone}`),
		"as-uid":             kubeconfigWithUser(`{token: t, as-uid: "1"}`),
		"as-groups":          kubeconfigWithUser(`{token: t, as-groups: [g]}`),
		"as-user-extra":      kubeconfigWithUser(`{token: t, as-user-extra: {k: [v]}}`),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeNamedKubeconfig(t, body)
			if _, err := kubeclient.CheckedConfig(path); !errors.Is(err, kubeclient.ErrCredentialsNotInline) {
				t.Fatalf("checked load = %v, want a refusal", err)
			}
			if _, err := parseSudoUserKubeconfig([]byte(body), path, "k3sm"); !errors.Is(err, errSudoKubeconfigRefused) {
				t.Errorf("parseSudoUserKubeconfig = %v, want a refusal", err)
			}
		})
	}
}

// TestRootProxyURLRefusedOnEachRoute reads a file with proxy-url by each way root
// loads a person's kubeconfig, and pins a proxy-url the selected context does not use.
func TestRootProxyURLRefusedOnEachRoute(t *testing.T) {
	proxied := regular(aliceUID, 0o600, kubeconfigWithCluster(proxiedCluster))
	aliceFile := filepath.Join(aliceHome, ".kube", "config")

	t.Run("$KUBECONFIG", func(t *testing.T) {
		s := fakeRootSources("alice", map[string]sudoKubeconfigFile{"/copy/kubeconfig": proxied}, nil)
		_, err := s.resolve(kubectlInputs{workDir: rootTestWorkDir, kubeconfigEnv: "/copy/kubeconfig", contextName: "k3sm"})
		if err == nil || !strings.Contains(err.Error(), "proxy-url") || !strings.Contains(err.Error(), rootKubeconfigRemedy) {
			t.Errorf("resolve = %v, want a proxy-url refusal and the remedy", err)
		}
	})
	t.Run("the person's own file", func(t *testing.T) {
		s := fakeRootSources("alice", map[string]sudoKubeconfigFile{aliceFile: proxied}, nil)
		_, err := s.resolve(kubectlInputs{workDir: rootTestWorkDir, contextName: "k3sm"})
		if err == nil || !strings.Contains(err.Error(), "proxy-url") {
			t.Errorf("resolve = %v, want a proxy-url refusal", err)
		}
	})
	t.Run("another context's proxy-url is dropped, not used", func(t *testing.T) {
		const body = `apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster: {server: "https://192.0.2.1:6443"}
- name: other
  cluster: {server: "https://192.0.2.2:6443", proxy-url: "http://192.0.2.10:3128"}
contexts:
- name: k3sm
  context: {cluster: k3sm, user: k3sm}
- name: other
  context: {cluster: other, user: k3sm}
users:
- name: k3sm
  user: {token: inline-token}
`
		c, err := checkKubeconfig([]byte(body), "/copy/kubeconfig", "k3sm")
		if err != nil {
			t.Fatalf("checkKubeconfig: %v", err)
		}
		if len(c.cfg.Clusters) != 1 || c.cfg.Clusters["k3sm"] == nil || c.cfg.Clusters["k3sm"].ProxyURL != "" {
			t.Errorf("checked clusters = %+v", c.cfg.Clusters)
		}
	})
}
