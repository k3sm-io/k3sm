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
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// flagValues returns every value following an occurrence of name in args. A repeated
// flag is not a duplicate to be tolerated: kube-controller-manager takes the LAST
// value, so a second occurrence is an invisible override of the first.
func flagValues(args []string, name string) []string {
	var out []string
	for i, a := range args {
		if a == name && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

// TestControllerManagerRootCAFollowsServingPosture is the guard,
// extended to the single-node serving leaf.
//
// --root-ca-file is the CA the controller-manager's root-ca-cert-publisher republishes
// into every namespace's kube-root-ca.crt ConfigMap — every Pod's trust anchor for the
// in-cluster API. It was once PINNED at the apiserver's self-signed --cert-dir file,
// which killed a mesh boot ("error parsing root-ca-file ... no such file or
// directory"). The apiserver now presents a cluster-CA-issued leaf on every topology,
// so every row, single-node included, must publish the cluster CA and never a file
// under the legacy cert dir.
//
// For every row the CROSS-FLAG INVARIANT holds: the CA named by --root-ca-file is the
// one under the PKI dir that issued the leaf named by --tls-cert-file.
func TestControllerManagerRootCAFollowsServingPosture(t *testing.T) {
	const wd = "/wd"
	pair := func(c Config) Config {
		c.ServingCertFile = certs.APIServerServingCertPath(c.WorkDir)
		c.ServingKeyFile = certs.APIServerServingKeyPath(c.WorkDir)
		return c
	}
	for _, tc := range []struct {
		name       string
		cfg        Config
		wantRootCA string
	}{
		{
			name:       "single-node presents a cluster-CA-issued leaf",
			cfg:        pair(Config{WorkDir: wd, KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}),
			wantRootCA: "/wd/tls/cluster-ca.crt",
		},
		{
			name:       "single-node through withDefaults",
			cfg:        pair(Config{WorkDir: wd}.withDefaults()),
			wantRootCA: "/wd/tls/cluster-ca.crt",
		},
		{
			name:       "single-node on the shipped default work dir",
			cfg:        pair(Config{}.withDefaults()),
			wantRootCA: "/var/lib/k3sm/server/tls/cluster-ca.crt",
		},
		{
			name: "mesh presents a cluster-CA-issued leaf",
			cfg: pair(Config{
				WorkDir: wd, KinePort: 2379, APIServerPort: 6444,
				NodeIP: "100.64.0.1", BindAddress: "100.64.0.1",
				ClientCAFile:  certs.SigningCACertPath(wd),
				KubeletCAFile: certs.ClusterCACertPath(wd),
			}),
			wantRootCA: certs.ClusterCACertPath(wd),
		},
		{
			name:       "mesh through withDefaults",
			cfg:        pair(Config{WorkDir: wd}).withDefaults(),
			wantRootCA: certs.ClusterCACertPath(wd),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kcm := controllerManagerArgs(tc.cfg)
			api := apiServerArgs(tc.cfg)

			got := flagValues(kcm, "--root-ca-file")
			if len(got) != 1 {
				t.Fatalf("--root-ca-file appears %d times (%v), want exactly 1: the last occurrence wins, so a second is an invisible override of the cluster's published trust anchor", len(got), got)
			}
			if got[0] != tc.wantRootCA {
				t.Errorf("--root-ca-file = %q, want %q", got[0], tc.wantRootCA)
			}

			// The invariant, asserted from the ARGV rather than from the Config: the
			// published root CA is the PKI-dir CA that issued the presented leaf, never
			// the legacy self-signed directory.
			serving := flagValues(api, "--tls-cert-file")
			certDirPrefix := APIServerCertDir(tc.cfg.WorkDir) + "/"
			pkiPrefix := certs.PKIDir(tc.cfg.WorkDir) + "/"
			if len(serving) != 1 || serving[0] != tc.cfg.ServingCertFile {
				t.Fatalf("rendered --tls-cert-file %v, want exactly [%q]", serving, tc.cfg.ServingCertFile)
			}
			if !strings.HasPrefix(got[0], pkiPrefix) {
				t.Errorf("--root-ca-file = %q, want a CA under the PKI dir %q — the apiserver presents a cluster-CA-issued leaf from there", got[0], pkiPrefix)
			}
			if strings.HasPrefix(got[0], certDirPrefix) {
				t.Errorf("--root-ca-file = %q points into the legacy self-signed --cert-dir, which nothing writes now", got[0])
			}

			// The security-relevant NEIGHBOUR rendered by the same function: the scoped
			// controller set. A reviewer scanning this diff has no other positive signal
			// that dropping the node-side controllers was left intact.
			ctrls := flagValues(kcm, "--controllers")
			if len(ctrls) != 1 {
				t.Fatalf("--controllers appears %d times (%v), want exactly 1", len(ctrls), ctrls)
			}
			if ctrls[0] != controllersFlag() {
				t.Errorf("--controllers = %q, want %q", ctrls[0], controllersFlag())
			}
			if !strings.HasPrefix(ctrls[0], "*") {
				t.Errorf("--controllers = %q, want it to start with * (enable every on-by-default controller, then subtract)", ctrls[0])
			}
			for _, c := range kcmDisabledControllers {
				if !strings.Contains(ctrls[0], ",-"+c) {
					t.Errorf("--controllers = %q no longer drops %s (the node-side controllers must stay off — they fight the Virtual Kubelet node)", ctrls[0], c)
				}
			}
			if strings.Contains(ctrls[0], ",-endpointslice-controller") {
				t.Errorf("--controllers = %q drops endpointslice-controller, which the Service proxy reconciles off", ctrls[0])
			}

			// The SA signing key is the other cert-shaped KCM flag; it is posture-INdependent
			// and this change must not have moved it.
			if got := flagValues(kcm, "--service-account-private-key-file"); len(got) != 1 || got[0] != filepath.Join(tc.cfg.WorkDir, "sa.key") {
				t.Errorf("--service-account-private-key-file = %v, want exactly [%q] (unchanged by posture)", got, filepath.Join(tc.cfg.WorkDir, "sa.key"))
			}
		})
	}
}
