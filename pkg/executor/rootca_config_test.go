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

// TestRootCAFileIsPostureLocked pins --root-ca-file to the cluster CA on every
// topology. Inverted from the self-signed single-node posture: the apiserver no longer
// self-signs into --cert-dir on any topology, so the published kube-root-ca.crt is
// always the cluster CA that issued the serving leaf (or an explicit RootCAFile), and
// never a file under the legacy cert dir.
func TestRootCAFileIsPostureLocked(t *testing.T) {
	const wd = "/wd"
	pair := Config{
		WorkDir:         wd,
		ServingCertFile: certs.APIServerServingCertPath(wd),
		ServingKeyFile:  certs.APIServerServingKeyPath(wd),
	}

	t.Run("an explicit RootCAFile is honored", func(t *testing.T) {
		cfg := pair
		cfg.RootCAFile = "/wd/tls/some-other-ca.crt"
		if got := flagValue(controllerManagerArgs(cfg), "--root-ca-file"); got != cfg.RootCAFile {
			t.Errorf("--root-ca-file = %q, want the explicit %q (honored verbatim, as ClientCAFile is)", got, cfg.RootCAFile)
		}
	})

	t.Run("defaults to the cluster CA", func(t *testing.T) {
		if got := flagValue(controllerManagerArgs(pair), "--root-ca-file"); got != certs.ClusterCACertPath(wd) {
			t.Errorf("--root-ca-file = %q, want the cluster CA %q — the CA that issued the serving leaf", got, certs.ClusterCACertPath(wd))
		}
	})

	t.Run("never the legacy self-signed cert dir", func(t *testing.T) {
		for _, cfg := range []Config{
			{WorkDir: wd},
			{WorkDir: wd, ServingCertFile: certs.APIServerServingCertPath(wd)},
		} {
			got := flagValue(controllerManagerArgs(cfg), "--root-ca-file")
			if got != certs.ClusterCACertPath(wd) {
				t.Errorf("--root-ca-file = %q for %+v, want the cluster CA %q; the legacy %s is never read", got, cfg, certs.ClusterCACertPath(wd), APIServerCertDir(wd))
			}
		}
	})

	t.Run("a half-supplied serving keypair renders no --tls-cert-file", func(t *testing.T) {
		cfg := Config{WorkDir: wd, ServingCertFile: certs.APIServerServingCertPath(wd)}
		if got := flagValue(apiServerArgs(cfg), "--tls-cert-file"); got != "" {
			t.Fatalf("--tls-cert-file = %q, want none: the apiserver needs BOTH cert and key (and Validate refuses this Config)", got)
		}
	})
}

// TestValidateRejectsRootCAWithoutServingCert pins Validate's serving-pair guard.
// Inverted from the self-signed single-node posture, where a Config without the pair
// was valid: the apiserver now serves the cluster-CA leaf on every topology, so any
// Config missing either half of the pair (with or without a RootCAFile) fails with
// ErrNoServingCert, and a Config with the pair passes whatever its topology.
func TestValidateRejectsRootCAWithoutServingCert(t *testing.T) {
	const wd = "/wd"
	for _, tc := range []struct {
		name string
		cfg  Config
		want error
	}{
		{
			name: "no serving keypair and no RootCAFile",
			cfg:  Config{WorkDir: wd},
			want: ErrNoServingCert,
		},
		{
			name: "single-node with both and the default RootCAFile",
			cfg: Config{
				WorkDir:         wd,
				NodeIP:          "127.0.0.1",
				ServingCertFile: certs.APIServerServingCertPath(wd),
				ServingKeyFile:  certs.APIServerServingKeyPath(wd),
			},
		},
		{
			name: "mesh with both",
			cfg: Config{
				WorkDir:         wd,
				NodeIP:          "100.64.0.1",
				ServingCertFile: certs.APIServerServingCertPath(wd),
				ServingKeyFile:  certs.APIServerServingKeyPath(wd),
				RootCAFile:      certs.ClusterCACertPath(wd),
			},
		},
		{
			name: "RootCAFile without a serving keypair",
			cfg:  Config{WorkDir: wd, RootCAFile: certs.ClusterCACertPath(wd)},
			want: ErrNoServingCert,
		},
		{
			name: "RootCAFile with only half a serving keypair",
			cfg: Config{
				WorkDir:         wd,
				ServingCertFile: certs.APIServerServingCertPath(wd),
				RootCAFile:      certs.ClusterCACertPath(wd),
			},
			want: ErrNoServingCert,
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
