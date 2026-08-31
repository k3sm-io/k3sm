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
	"errors"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// TestRootCAFileIsPostureLocked pins the half of B223 that makes the two flags
// STRUCTURALLY unable to disagree: Config.RootCAFile is the mesh call site's explicit
// statement of which CA anchors the serving leaf it just issued, but it is resolved
// through the SAME predicate that gates --tls-cert-file. So a RootCAFile can never
// reach argv on the self-signed single-node path, where it would publish a trust anchor
// for a cert the apiserver does not present.
func TestRootCAFileIsPostureLocked(t *testing.T) {
	const wd = "/wd"
	mesh := Config{
		WorkDir:         wd,
		ServingCertFile: certs.APIServerServingCertPath(wd),
		ServingKeyFile:  certs.APIServerServingKeyPath(wd),
	}

	t.Run("mesh honors an explicit RootCAFile", func(t *testing.T) {
		cfg := mesh
		cfg.RootCAFile = "/wd/tls/some-other-ca.crt"
		if got := flagValue(controllerManagerArgs(cfg), "--root-ca-file"); got != cfg.RootCAFile {
			t.Errorf("--root-ca-file = %q, want the explicit %q (honored verbatim, as ClientCAFile is)", got, cfg.RootCAFile)
		}
	})

	t.Run("mesh defaults to the cluster CA", func(t *testing.T) {
		if got := flagValue(controllerManagerArgs(mesh), "--root-ca-file"); got != certs.ClusterCACertPath(wd) {
			t.Errorf("--root-ca-file = %q, want the cluster CA %q — the CA that issued the serving leaf", got, certs.ClusterCACertPath(wd))
		}
	})

	t.Run("single-node ignores a stray RootCAFile", func(t *testing.T) {
		cfg := Config{WorkDir: wd, RootCAFile: certs.ClusterCACertPath(wd)}
		want := "/wd/apiserver-certs/apiserver.crt"
		if got := flagValue(controllerManagerArgs(cfg), "--root-ca-file"); got != want {
			t.Errorf("single-node --root-ca-file = %q, want the self-signed %q: the renderer is posture-locked so the flag pair can never come from two modes", got, want)
		}
	})

	t.Run("a half-supplied serving keypair is not mesh", func(t *testing.T) {
		// Only ServingCertFile: apiServerArgs renders NO --tls-cert-file (it needs both),
		// so the posture is still self-signed and --root-ca-file must agree.
		cfg := Config{WorkDir: wd, ServingCertFile: certs.APIServerServingCertPath(wd)}
		if got := flagValue(apiServerArgs(cfg), "--tls-cert-file"); got != "" {
			t.Fatalf("--tls-cert-file = %q, want none: the apiserver needs BOTH cert and key", got)
		}
		want := "/wd/apiserver-certs/apiserver.crt"
		if got := flagValue(controllerManagerArgs(cfg), "--root-ca-file"); got != want {
			t.Errorf("--root-ca-file = %q, want %q — it must track --tls-cert-file's own predicate, not a looser one", got, want)
		}
	})
}

// TestValidateRejectsRootCAWithoutServingCert pins the loud half of the posture lock:
// the renderer ignoring a stray RootCAFile keeps argv correct, but silently ignoring
// configuration is how a wrong belief survives. Validate (called at the top of Start)
// fails the bring-up closed instead.
func TestValidateRejectsRootCAWithoutServingCert(t *testing.T) {
	const wd = "/wd"
	for _, tc := range []struct {
		name string
		cfg  Config
		want error
	}{
		{
			name: "single-node with no RootCAFile",
			cfg:  Config{WorkDir: wd},
		},
		{
			name: "mesh with both",
			cfg: Config{
				WorkDir:         wd,
				ServingCertFile: certs.APIServerServingCertPath(wd),
				ServingKeyFile:  certs.APIServerServingKeyPath(wd),
				RootCAFile:      certs.ClusterCACertPath(wd),
			},
		},
		{
			name: "RootCAFile without a serving keypair",
			cfg:  Config{WorkDir: wd, RootCAFile: certs.ClusterCACertPath(wd)},
			want: ErrRootCAWithoutServingCert,
		},
		{
			name: "RootCAFile with only half a serving keypair",
			cfg: Config{
				WorkDir:         wd,
				ServingCertFile: certs.APIServerServingCertPath(wd),
				RootCAFile:      certs.ClusterCACertPath(wd),
			},
			want: ErrRootCAWithoutServingCert,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
}
