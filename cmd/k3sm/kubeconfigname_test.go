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
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

func nameTestSource() *clientcmdapi.Config {
	c := clientcmdapi.NewConfig()
	c.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://127.0.0.1:6444"}
	c.AuthInfos["admin"] = &clientcmdapi.AuthInfo{Token: "k3sm-abc"}
	c.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "admin"}
	c.CurrentContext = "k3sm"
	return c
}

func foreignConfig(name string) *clientcmdapi.Config {
	c := clientcmdapi.NewConfig()
	c.Clusters[name] = &clientcmdapi.Cluster{Server: "https://other.example:6443"}
	c.AuthInfos[name] = &clientcmdapi.AuthInfo{Token: "someone-elses"}
	c.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: name}
	return c
}

// TestInstallKubeconfigContextName pins B512: --kubeconfig-name is parsed,
// recorded with the other install arguments, read back by the lookups, and
// is the name the merge uses, with foreign entries refused.
func TestInstallKubeconfigContextName(t *testing.T) {
	const chosen = "lab"

	t.Run("flag is recorded and round-trips through the install record", func(t *testing.T) {
		o, err := parseInstallFlags([]string{"--user", "alice", "--kubeconfig-name", chosen})
		if err != nil {
			t.Fatal(err)
		}
		rec := dataroot.ServerArgsRecord{
			Version:   dataroot.ServerArgsRecordVersion,
			Args:      install.RecordedServerArgs(o.installConfig("", nil, nil)),
			CreatedBy: "test",
			CreatedAt: time.Now().UTC(),
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		read := func(path string) ([]byte, error) {
			if path == "/rec" {
				return raw, nil
			}
			return nil, fs.ErrNotExist
		}
		got, err := install.InstalledKubeconfigName(read, "/no-plist", "/rec")
		if err != nil || got != chosen {
			t.Fatalf("recorded name = %q, %v; want %q", got, err, chosen)
		}
	})

	t.Run("default name records nothing and reads back as k3sm", func(t *testing.T) {
		o, err := parseInstallFlags([]string{"--user", "alice"})
		if err != nil {
			t.Fatal(err)
		}
		args := install.RecordedServerArgs(o.installConfig("", nil, nil))
		if strings.Contains(strings.Join(args, " "), "kubeconfig-name") {
			t.Errorf("default install recorded a name: %v", args)
		}
		none := func(string) ([]byte, error) { return nil, fs.ErrNotExist }
		if got, err := install.InstalledKubeconfigName(none, "/p", "/r"); err != nil || got != "k3sm" {
			t.Errorf("no record = %q, %v; want k3sm", got, err)
		}
	})

	t.Run("an invalid name and an agent install are refused", func(t *testing.T) {
		if _, err := parseInstallFlags([]string{"--kubeconfig-name", "bad name"}); err == nil {
			t.Error("name with a space accepted")
		}
		if _, err := parseInstallFlags([]string{"--agent", "--server", "10.0.0.1", "--kubeconfig-name", chosen}); err == nil {
			t.Error("--kubeconfig-name accepted on a worker install")
		}
	})

	t.Run("the merge lands under the chosen name and renames", func(t *testing.T) {
		got, err := mergeKubeconfig(clientcmdapi.NewConfig(), nameTestSource(), chosen, true)
		if err != nil {
			t.Fatal(err)
		}
		kctx := got.Contexts[chosen]
		if kctx == nil || kctx.Cluster != chosen || kctx.AuthInfo != chosen || got.CurrentContext != chosen {
			t.Fatalf("merge did not land under %q: %+v current=%q", chosen, kctx, got.CurrentContext)
		}
		if _, ok := got.Contexts["k3sm"]; ok {
			t.Error("the default name was also written")
		}
		// Re-merging over our own entry is not a collision.
		if _, err := mergeKubeconfig(got, nameTestSource(), chosen, true); err != nil {
			t.Errorf("re-merge over our own entry refused: %v", err)
		}
	})

	t.Run("a name colliding with a foreign entry is refused and left intact", func(t *testing.T) {
		dst := foreignConfig(chosen)
		if _, err := mergeKubeconfig(dst, nameTestSource(), chosen, true); err == nil {
			t.Fatal("merge over a foreign context succeeded")
		}
		if dst.AuthInfos[chosen].Token != "someone-elses" {
			t.Error("foreign user was modified")
		}
		onlyCluster := clientcmdapi.NewConfig()
		onlyCluster.Clusters[chosen] = &clientcmdapi.Cluster{Server: "https://x"}
		if _, err := mergeKubeconfig(onlyCluster, nameTestSource(), chosen, true); err == nil {
			t.Error("merge over a foreign cluster succeeded")
		}
		onlyUser := clientcmdapi.NewConfig()
		onlyUser.AuthInfos[chosen] = &clientcmdapi.AuthInfo{Token: "x"}
		if _, err := mergeKubeconfig(onlyUser, nameTestSource(), chosen, true); err == nil {
			t.Error("merge over a foreign user succeeded")
		}
	})

	t.Run("the default name still replaces as before", func(t *testing.T) {
		dst := foreignConfig("k3sm")
		if _, err := mergeKubeconfig(dst, nameTestSource(), "k3sm", true); err != nil {
			t.Errorf("default-name merge refused: %v", err)
		}
	})
}
