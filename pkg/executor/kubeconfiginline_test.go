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

package executor

import (
	"testing"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// TestAdminKubeconfigIsInlineOnly pins the file's shape to what its readers
// accept: netd and the lifecycle verbs load it through FromCheckedPath, so a path
// added here would leave them without a usable kubeconfig.
func TestAdminKubeconfigIsInlineOnly(t *testing.T) {
	cfg := Config{WorkDir: t.TempDir()}.withDefaults()
	if _, err := certs.EnsureHierarchy(cfg.WorkDir, certs.RoleMintAuthority, certs.PostureKine); err != nil {
		t.Fatalf("ensure the CA hierarchy the kubeconfig pins: %v", err)
	}
	if err := writeKubeconfig(cfg, "k3sm-testtoken"); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	rest, _, err := kubeclient.FromCheckedPath(kubeconfigPath(cfg.WorkDir))
	if err != nil {
		t.Fatalf("FromCheckedPath: %v", err)
	}
	if rest.BearerToken != "k3sm-testtoken" || len(rest.CAData) == 0 {
		t.Errorf("token = %q, CA bytes = %d, want the token and the CA carried inline", rest.BearerToken, len(rest.CAData))
	}
}
