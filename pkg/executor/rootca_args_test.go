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

// TestControllerManagerRootCAFollowsServingPosture is the B223 (lab defect D2) guard.
//
// --root-ca-file is the CA the controller-manager's root-ca-cert-publisher republishes
// into every namespace's kube-root-ca.crt ConfigMap — every Pod's trust anchor for the
// in-cluster API. It was PINNED at the apiserver's self-signed --cert-dir file, which is
// correct single-node and wrong on the mesh path: there cmd/k3sm issues a
// CLUSTER-CA-signed serving leaf and the apiserver presents THAT (--tls-cert-file), never
// self-signing. Observed on a `--mesh-ip 127.0.0.1` boot before the fix: the file does not
// exist at all, and the controller-manager dies at startup with "error parsing
// root-ca-file at <workdir>/apiserver-certs/apiserver.crt: no such file or directory"
// (and, on a work dir that once booted single-node, comes up publishing a stale CA that
// anchors nothing the apiserver serves).
//
// The table asserts BOTH branches and, for every row, the CROSS-FLAG INVARIANT: the CA
// named by --root-ca-file and the serving cert named by --tls-cert-file always come from
// the same posture. Deliberately built from the PRE-EXISTING Config fields only
// (ServingCertFile/ServingKeyFile), so it is a red-before-green assertion failure against
// the unfixed renderer rather than a compile error.
func TestControllerManagerRootCAFollowsServingPosture(t *testing.T) {
	const wd = "/wd"
	for _, tc := range []struct {
		name string
		cfg  Config
		// wantRootCA is spelled as a LITERAL for the single-node rows: the shipped path
		// must stay byte-for-byte what it has always been, so a change to certDir is a
		// failure here rather than a silently-agreeing derivation.
		wantRootCA string
		wantMesh   bool
	}{
		{
			name:       "single-node self-signs into --cert-dir",
			cfg:        Config{WorkDir: wd, KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"},
			wantRootCA: "/wd/apiserver-certs/apiserver.crt",
		},
		{
			name:       "single-node through withDefaults",
			cfg:        Config{WorkDir: wd}.withDefaults(),
			wantRootCA: "/wd/apiserver-certs/apiserver.crt",
		},
		{
			name:       "single-node on the shipped default work dir",
			cfg:        Config{}.withDefaults(),
			wantRootCA: "/var/lib/k3sm/server/apiserver-certs/apiserver.crt",
		},
		{
			name: "mesh presents a cluster-CA-issued leaf",
			cfg: Config{
				WorkDir: wd, KinePort: 2379, APIServerPort: 6444,
				NodeIP: "100.64.0.1", BindAddress: "100.64.0.1",
				ClientCAFile:    certs.SigningCACertPath(wd),
				KubeletCAFile:   certs.ClusterCACertPath(wd),
				ServingCertFile: certs.APIServerServingCertPath(wd),
				ServingKeyFile:  certs.APIServerServingKeyPath(wd),
			},
			wantRootCA: certs.ClusterCACertPath(wd),
			wantMesh:   true,
		},
		{
			name: "mesh through withDefaults",
			cfg: Config{
				WorkDir:         wd,
				ServingCertFile: certs.APIServerServingCertPath(wd),
				ServingKeyFile:  certs.APIServerServingKeyPath(wd),
			}.withDefaults(),
			wantRootCA: certs.ClusterCACertPath(wd),
			wantMesh:   true,
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

			// The invariant, asserted from the ARGV rather than from the Config: whichever
			// serving cert the apiserver is told to present, the published root CA must be
			// the one that can anchor it. Never the other posture's directory.
			serving := flagValues(api, "--tls-cert-file")
			certDirPrefix := APIServerCertDir(tc.cfg.WorkDir) + "/"
			pkiPrefix := certs.PKIDir(tc.cfg.WorkDir) + "/"
			if tc.wantMesh {
				if len(serving) != 1 || serving[0] != tc.cfg.ServingCertFile {
					t.Fatalf("mesh row rendered --tls-cert-file %v, want exactly [%q] (the table's posture claim is wrong)", serving, tc.cfg.ServingCertFile)
				}
				if !strings.HasPrefix(got[0], pkiPrefix) {
					t.Errorf("mesh --root-ca-file = %q, want a CA under the PKI dir %q — the apiserver presents a cluster-CA-issued leaf from there", got[0], pkiPrefix)
				}
				if strings.HasPrefix(got[0], certDirPrefix) {
					t.Errorf("mesh --root-ca-file = %q points into the apiserver's SELF-SIGNED --cert-dir; on the mesh path the apiserver never self-signs, so that file anchors nothing (and does not exist on a fresh work dir)", got[0])
				}
			} else {
				if len(serving) != 0 {
					t.Fatalf("single-node row rendered --tls-cert-file %v, want none (the table's posture claim is wrong)", serving)
				}
				if !strings.HasPrefix(got[0], certDirPrefix) {
					t.Errorf("single-node --root-ca-file = %q, want the apiserver's self-signed cert under %q — it is the only anchor for what the apiserver serves", got[0], certDirPrefix)
				}
				if strings.HasPrefix(got[0], pkiPrefix) {
					t.Errorf("single-node --root-ca-file = %q publishes a cluster CA that anchors NOTHING the apiserver presents (it self-signs into --cert-dir); in-pod API TLS would fail on the most-exercised path", got[0])
				}
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
