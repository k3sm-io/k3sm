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
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/install"
)

// TestStatusUserKubeReadsTheInvokingAccountsKubeconfig pins the agent fallback's
// reader: it exists on an agent only, builds the client from the k3sm context
// of the account's own kubeconfig when that context points at the host this
// Mac joined, names that file and context, and refuses a k3sm context that
// points anywhere else.
func TestStatusUserKubeReadsTheInvokingAccountsKubeconfig(t *testing.T) {
	join := func() (string, error) { return "100.64.0.1:9345", nil }
	if statusUserKubeFor(install.RoleServer, join) != nil {
		t.Error("a server got the agent's kubeconfig fallback")
	}
	path := filepath.Join(t.TempDir(), "config")
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://100.64.0.1:6444"}
	cfg.AuthInfos["k3sm"] = &clientcmdapi.AuthInfo{Token: "not-a-real-token"}
	cfg.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "k3sm"}
	cfg.Contexts["other"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "k3sm"}
	cfg.CurrentContext = "other"
	if err := clientcmd.WriteToFile(*cfg, path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
	if installedKubeconfigName() != installedContextName {
		t.Skip("this Mac's install names its own kubeconfig context")
	}
	kube, source, err := statusUserKubeFor(install.RoleAgent, join)()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if kube.Server() != "https://100.64.0.1:6444" {
		t.Errorf("server = %q, want the k3sm context's", kube.Server())
	}
	if want := path + ` context "k3sm"`; source != want {
		t.Errorf("source = %q, want %q", source, want)
	}
	elsewhere := func() (string, error) { return "192.168.0.50", nil }
	if _, _, err := statusUserKubeFor(install.RoleAgent, elsewhere)(); err == nil {
		t.Error("a k3sm context on another host was used for this worker's cluster")
	}
}
