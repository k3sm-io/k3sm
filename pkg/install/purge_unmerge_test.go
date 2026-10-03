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
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// kubeFixture renders a kubeconfig holding the user's own "work" cluster, user
// and context, plus (withK3sm) the k3sm entries exactly as install merges them,
// with k3sm selected. It is rendered by clientcmd.Write because that is how
// install leaves the file.
func kubeFixture(t *testing.T, withK3sm bool) []byte {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["work"] = &clientcmdapi.Cluster{Server: "https://work.example:6443", CertificateAuthorityData: []byte("work-ca")}
	cfg.AuthInfos["work"] = &clientcmdapi.AuthInfo{Token: "work-token"}
	cfg.Contexts["work"] = &clientcmdapi.Context{Cluster: "work", AuthInfo: "work", Namespace: "dev"}
	cfg.CurrentContext = "work"
	if withK3sm {
		cfg.Clusters[adminContextName] = &clientcmdapi.Cluster{Server: "https://127.0.0.1:6443"}
		cfg.AuthInfos[adminContextName] = &clientcmdapi.AuthInfo{Token: "k3sm-admin"}
		cfg.Contexts[adminContextName] = &clientcmdapi.Context{Cluster: adminContextName, AuthInfo: adminContextName}
		cfg.CurrentContext = adminContextName
	}
	out, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPurgeKubeconfigUnmerge pins the pure inverse of the install-time merge.
func TestPurgeKubeconfigUnmerge(t *testing.T) {
	t.Run("removes only k3sm and leaves the rest byte-identical", func(t *testing.T) {
		out, changed, err := unmergeAdminKubeconfig(kubeFixture(t, true), adminContextName)
		if err != nil || !changed {
			t.Fatalf("unmerge = %v, changed=%v", err, changed)
		}
		want := kubeFixture(t, false)
		// The only difference from the user's own file is current-context,
		// which pointed at k3sm and is cleared rather than guessed.
		wantCfg, _ := clientcmd.Load(want)
		wantCfg.CurrentContext = ""
		want, _ = clientcmd.Write(*wantCfg)
		if string(out) != string(want) {
			t.Fatalf("unmerged =\n%s\nwant =\n%s", out, want)
		}
	})

	t.Run("current-context is kept when it is not k3sm", func(t *testing.T) {
		in, _ := clientcmd.Load(kubeFixture(t, true))
		in.CurrentContext = "work"
		b, _ := clientcmd.Write(*in)
		out, _, err := unmergeAdminKubeconfig(b, adminContextName)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := clientcmd.Load(out)
		if got.CurrentContext != "work" {
			t.Fatalf("current-context = %q, want work", got.CurrentContext)
		}
	})

	t.Run("a cluster another context still references is kept", func(t *testing.T) {
		in, _ := clientcmd.Load(kubeFixture(t, true))
		in.Contexts["k3sm-ops"] = &clientcmdapi.Context{Cluster: adminContextName, AuthInfo: "work"}
		b, _ := clientcmd.Write(*in)
		out, _, err := unmergeAdminKubeconfig(b, adminContextName)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := clientcmd.Load(out)
		if _, ok := got.Clusters[adminContextName]; !ok {
			t.Fatal("the shared k3sm cluster was removed while k3sm-ops still uses it")
		}
		if _, ok := got.AuthInfos[adminContextName]; ok {
			t.Fatal("the k3sm user nothing references any more survived")
		}
		if c := got.Contexts["k3sm-ops"]; c == nil || c.Cluster != adminContextName || c.AuthInfo != "work" {
			t.Fatal("the other context changed")
		}
	})

	t.Run("a k3sm context pointing at differently named entries removes only the context", func(t *testing.T) {
		in, _ := clientcmd.Load(kubeFixture(t, false))
		in.Contexts[adminContextName] = &clientcmdapi.Context{Cluster: "work", AuthInfo: "work"}
		b, _ := clientcmd.Write(*in)
		out, _, err := unmergeAdminKubeconfig(b, adminContextName)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := clientcmd.Load(out)
		if _, ok := got.Clusters["work"]; !ok {
			t.Fatal("the user's own cluster was removed")
		}
	})

	t.Run("no k3sm context and an empty file are no-ops", func(t *testing.T) {
		for _, in := range [][]byte{kubeFixture(t, false), nil} {
			out, changed, err := unmergeAdminKubeconfig(in, adminContextName)
			if err != nil || changed || out != nil {
				t.Fatalf("unmerge of a file with no k3sm context = %q, %v, %v", out, changed, err)
			}
		}
	})
}
