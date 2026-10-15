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
	"encoding/base64"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
)

// existingKube is a developer's ~/.kube/config holding an UNRELATED cluster —
// exactly what install must not clobber.
const existingKube = `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://prod.example.com:6443
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
users:
- name: prod
  user:
    token: prod-token
`

// adminKube mirrors the shape of AdminKubeconfig: a single k3sm cluster/user/context.
const adminKube = `apiVersion: v1
kind: Config
current-context: k3sm
clusters:
- name: k3sm
  cluster:
    server: https://127.0.0.1:6444
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
users:
- name: k3sm
  user:
    token: admin-token
`

func TestMergeAdminKubeconfig(t *testing.T) {
	// The regression this fixes: install must MERGE, never overwrite. A developer's
	// other clusters survive; k3sm is added and selected current.
	t.Run("preserves existing contexts, adds k3sm as current", func(t *testing.T) {
		out, err := mergeAdminKubeconfig([]byte(existingKube), []byte(adminKube), adminContextName)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := clientcmd.Load(out)
		if err != nil {
			t.Fatalf("merged config unparseable: %v", err)
		}
		if _, ok := cfg.Contexts["prod"]; !ok {
			t.Error("merge CLOBBERED the existing 'prod' context — the data-loss bug")
		}
		if cfg.Clusters["prod"] == nil || cfg.Clusters["prod"].Server != "https://prod.example.com:6443" {
			t.Error("existing 'prod' cluster lost or altered")
		}
		if _, ok := cfg.Contexts[adminContextName]; !ok {
			t.Error("k3sm context was not merged in")
		}
		if cfg.CurrentContext != adminContextName {
			t.Errorf("current-context = %q, want %q", cfg.CurrentContext, adminContextName)
		}
	})

	t.Run("empty existing yields just the k3sm context", func(t *testing.T) {
		out, err := mergeAdminKubeconfig(nil, []byte(adminKube), adminContextName)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := clientcmd.Load(out)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Contexts[adminContextName] == nil || cfg.CurrentContext != adminContextName {
			t.Errorf("empty-existing merge missing the k3sm current context (current=%q)", cfg.CurrentContext)
		}
		if len(cfg.Contexts) != 1 {
			t.Errorf("expected exactly the k3sm context, got %d", len(cfg.Contexts))
		}
	})

	t.Run("re-merge is idempotent (a second install does not duplicate)", func(t *testing.T) {
		once, err := mergeAdminKubeconfig([]byte(existingKube), []byte(adminKube), adminContextName)
		if err != nil {
			t.Fatal(err)
		}
		twice, err := mergeAdminKubeconfig(once, []byte(adminKube), adminContextName)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := clientcmd.Load(twice)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Contexts) != 2 { // prod + k3sm, not 3
			t.Errorf("re-merge duplicated contexts: got %d, want 2 (prod + k3sm)", len(cfg.Contexts))
		}
	})

	t.Run("malformed admin kubeconfig errors (does not touch existing)", func(t *testing.T) {
		if _, err := mergeAdminKubeconfig([]byte(existingKube), []byte("{not valid"), adminContextName); err == nil {
			t.Error("expected an error on a malformed admin kubeconfig")
		}
	})
}

// TestMergeRewritesBothOldAnchorShapes pins the upgrade half of the admin
// kubeconfig contract: a ~/.kube/config an earlier release wrote carries the k3sm
// cluster either pinned to the apiserver's legacy self-signed certificate or with
// insecure-skip-tls-verify. Merging the new admin kubeconfig must replace that
// whole cluster entry, so the result pins the cluster CA and keeps no skip-verify.
func TestMergeRewritesBothOldAnchorShapes(t *testing.T) {
	clusterCA := []byte("-----BEGIN CERTIFICATE-----\nclusterca\n-----END CERTIFICATE-----\n")
	selfSigned := []byte("-----BEGIN CERTIFICATE-----\nselfsigned\n-----END CERTIFICATE-----\n")
	incoming, err := AdminKubeconfig(Config{AdminToken: "k3sm-tok", ClusterCA: clusterCA})
	if err != nil {
		t.Fatal(err)
	}
	for name, oldTLS := range map[string]string{
		"a self-signed pin": "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(selfSigned),
		"skip-verify":       "    insecure-skip-tls-verify: true",
	} {
		t.Run(name, func(t *testing.T) {
			old := "apiVersion: v1\nkind: Config\ncurrent-context: k3sm\nclusters:\n- name: k3sm\n  cluster:\n    server: https://127.0.0.1:6444\n" + oldTLS +
				"\ncontexts:\n- name: k3sm\n  context:\n    cluster: k3sm\n    user: k3sm\nusers:\n- name: k3sm\n  user:\n    token: k3sm-old\n"
			out, err := mergeAdminKubeconfig([]byte(old), incoming, adminContextName)
			if err != nil {
				t.Fatalf("merge: %v", err)
			}
			cfg, err := clientcmd.Load(out)
			if err != nil {
				t.Fatal(err)
			}
			cl := cfg.Clusters[adminContextName]
			if cl == nil {
				t.Fatalf("no %s cluster after the merge:\n%s", adminContextName, out)
			}
			if cl.InsecureSkipTLSVerify {
				t.Errorf("the merged cluster still skips verification:\n%s", out)
			}
			if string(cl.CertificateAuthorityData) != string(clusterCA) {
				t.Errorf("the merged cluster does not pin the cluster CA:\n%s", out)
			}
		})
	}
}
