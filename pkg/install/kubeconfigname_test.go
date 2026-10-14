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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/dataroot"
)

func TestKubeconfigNameMergeAndUnmerge(t *testing.T) {
	const name = "lab"
	admin := []byte(strings.Replace(adminKube, "admin-token", "k3sm-admin-token", 1))
	merged, err := mergeAdminKubeconfig([]byte(existingKube), admin, name)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(merged)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Contexts[name] == nil || cfg.CurrentContext != name || cfg.Contexts[adminContextName] != nil {
		t.Fatalf("merge did not land only under %q: %v current=%q", name, cfg.Contexts, cfg.CurrentContext)
	}

	// Purge removes that context and its cluster/user, and nothing else.
	out, changed, err := unmergeAdminKubeconfig(merged, name)
	if err != nil || !changed {
		t.Fatalf("unmerge: changed=%v err=%v", changed, err)
	}
	after, _ := clientcmd.Load(out)
	if after.Contexts[name] != nil || after.Clusters[name] != nil || after.AuthInfos[name] != nil {
		t.Errorf("entries named %q survived: %+v", name, after)
	}
	before, _ := clientcmd.Load([]byte(existingKube))
	if len(after.Contexts) != len(before.Contexts) || len(after.Clusters) != len(before.Clusters) || len(after.AuthInfos) != len(before.AuthInfos) {
		t.Errorf("unmerge touched other entries: %+v", after)
	}

	// A foreign entry under the name is refused by the merge and untouched by the purge.
	foreign := clientcmdapi.NewConfig()
	foreign.Clusters[name] = &clientcmdapi.Cluster{Server: "https://x"}
	foreign.AuthInfos[name] = &clientcmdapi.AuthInfo{Token: "theirs"}
	foreign.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: name}
	raw, _ := clientcmd.Write(*foreign)
	if _, err := mergeAdminKubeconfig(raw, admin, name); err == nil {
		t.Error("merge over a foreign entry succeeded")
	}
	if _, changed, _ := unmergeAdminKubeconfig(raw, name); changed {
		t.Error("purge removed a foreign entry")
	}
}

func TestPurgeRemovesRecordedKubeconfigName(t *testing.T) {
	r := newPurgeRig(t, RoleServer, false)
	rec, _ := json.Marshal(dataroot.ServerArgsRecord{
		Version: dataroot.ServerArgsRecordVersion, Args: []string{"--kubeconfig-name", "lab"},
		CreatedBy: "test", CreatedAt: time.Now().UTC(),
	})
	r.f.putFile(r.cfg.withDefaults().ServerArgsRecord, rec)
	if err := r.run(); err != nil {
		t.Fatal(err)
	}
	if got := r.f.purge.kubeNameRemoved; got != "lab" {
		t.Errorf("purge removed context %q, want lab", got)
	}
}

func TestPurgeDefaultKubeconfigName(t *testing.T) {
	r := newPurgeRig(t, RoleServer, false)
	if err := r.run(); err != nil {
		t.Fatal(err)
	}
	if got := r.f.purge.kubeNameRemoved; got != DefaultKubeconfigName {
		t.Errorf("purge removed context %q, want %q", got, DefaultKubeconfigName)
	}
}

func TestKubeconfigNameResolvedArgs(t *testing.T) {
	c := Config{ExtraServerArgs: []string{"--kubeconfig-name", "old", "--x", "1"}}
	if got := c.kubeconfigName(); got != "old" {
		t.Errorf("carried name = %q", got)
	}
	c.KubeconfigName = "new"
	if got := c.kubeconfigName(); got != "new" {
		t.Errorf("explicit name = %q", got)
	}
	c.KubeconfigName = DefaultKubeconfigName
	if got := c.kubeconfigName(); got != DefaultKubeconfigName {
		t.Errorf("reset name = %q", got)
	}
	for _, a := range c.resolvedExtraServerArgs() {
		if a == "--kubeconfig-name" {
			t.Error("default name left a flag in the record")
		}
	}
}
