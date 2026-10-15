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
	"slices"
	"testing"

	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/certs"
)

// TestClusterSignedServingArgsAreTopologyNeutral is the executor half of the gate for
// the single-node serving leaf: the apiserver serves the cluster-CA-issued leaf on
// every topology, so the argv and every in-process kubeconfig take one posture. On a
// single-node Config the apiserver used to self-sign into --cert-dir, the KCM
// published that self-signed file as kube-root-ca.crt, and the scheduler, KCM and
// bearer-token kubeconfigs skipped server verification. A single-node and a mesh
// Config with the serving pair must now render --tls-cert-file and no --cert-dir,
// publish the cluster CA, pin it in all three kubeconfigs, and pass Validate; a
// Config without the pair must fail Validate with ErrNoServingCert.
func TestClusterSignedServingArgsAreTopologyNeutral(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  func(wd string) Config
	}{
		{
			name: "single-node",
			cfg: func(wd string) Config {
				return Config{
					WorkDir: wd, KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1",
					ServingCertFile: certs.APIServerServingCertPath(wd),
					ServingKeyFile:  certs.APIServerServingKeyPath(wd),
					RootCAFile:      certs.ClusterCACertPath(wd),
				}
			},
		},
		{
			name: "mesh",
			cfg: func(wd string) Config {
				return Config{
					WorkDir: wd, KinePort: 2379, APIServerPort: 6444,
					NodeIP: "100.64.0.1", BindAddress: "100.64.0.1",
					ClientCAFile:    certs.SigningCACertPath(wd),
					KubeletCAFile:   certs.ClusterCACertPath(wd),
					ServingCertFile: certs.APIServerServingCertPath(wd),
					ServingKeyFile:  certs.APIServerServingKeyPath(wd),
					RootCAFile:      certs.ClusterCACertPath(wd),
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			wd := t.TempDir()
			cfg := tc.cfg(wd)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil: a Config with the serving pair is valid on every topology", err)
			}

			api := apiServerArgs(cfg)
			if got := flagValues(api, "--tls-cert-file"); !slices.Equal(got, []string{cfg.ServingCertFile}) {
				t.Errorf("--tls-cert-file = %v, want [%s]", got, cfg.ServingCertFile)
			}
			if got := flagValues(api, "--tls-private-key-file"); !slices.Equal(got, []string{cfg.ServingKeyFile}) {
				t.Errorf("--tls-private-key-file = %v, want [%s]", got, cfg.ServingKeyFile)
			}
			if slices.Contains(api, "--cert-dir") {
				t.Errorf("apiserver argv renders --cert-dir; the apiserver must never self-sign: %v", api)
			}
			if got := flagValues(controllerManagerArgs(cfg), "--root-ca-file"); !slices.Equal(got, []string{certs.ClusterCACertPath(wd)}) {
				t.Errorf("--root-ca-file = %v, want [%s]: kube-root-ca.crt must be the CA that issued the serving leaf", got, certs.ClusterCACertPath(wd))
			}

			s := NewSupervised(cfg)
			if err := s.provisionComponentCerts(); err != nil {
				t.Fatalf("provision component certs: %v", err)
			}
			if err := writeKubeconfig(s.cfg, "k3sm-testtoken"); err != nil {
				t.Fatalf("write the bearer-token kubeconfig: %v", err)
			}
			h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
			if err != nil {
				t.Fatalf("load hierarchy: %v", err)
			}
			for _, path := range []string{schedulerKubeconfigPath(wd), controllerManagerKubeconfigPath(wd), kubeconfigPath(wd)} {
				kc, err := clientcmd.LoadFromFile(path)
				if err != nil {
					t.Fatalf("load %s: %v", path, err)
				}
				cl := kc.Clusters["k3sm"]
				if cl == nil {
					t.Fatalf("%s has no k3sm cluster", path)
				}
				if cl.InsecureSkipTLSVerify {
					t.Errorf("%s skips server verification; it must pin the cluster CA", path)
				}
				if string(cl.CertificateAuthorityData) != string(h.Cluster.CertPEM) {
					t.Errorf("%s certificate-authority-data is not the cluster CA", path)
				}
			}
		})
	}

	t.Run("no serving pair fails Validate", func(t *testing.T) {
		t.Parallel()
		const wd = "/wd"
		for _, cfg := range []Config{
			{WorkDir: wd},
			{WorkDir: wd, ServingCertFile: certs.APIServerServingCertPath(wd)},
			{WorkDir: wd, ServingKeyFile: certs.APIServerServingKeyPath(wd)},
		} {
			if err := cfg.Validate(); !errors.Is(err, ErrNoServingCert) {
				t.Errorf("Validate(%+v) = %v, want %v", cfg, err, ErrNoServingCert)
			}
		}
	})
}

// withServingPair returns cfg with the apiserver serving keypair set to the PKI-dir
// paths cmd/k3sm issues the leaf at, so a test Config passes Validate the way every
// started server's does. The files need not exist for a test whose apiserver is faked.
func withServingPair(cfg Config) Config {
	cfg.ServingCertFile = certs.APIServerServingCertPath(cfg.WorkDir)
	cfg.ServingKeyFile = certs.APIServerServingKeyPath(cfg.WorkDir)
	return cfg
}
