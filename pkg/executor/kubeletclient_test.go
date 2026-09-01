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
	"crypto/x509"
	"encoding/pem"
	"os"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// TestAPIServerKubeletClientIdentity pins the producer half of B176: every boot
// provisions the client keypair the apiserver presents to a node's kubelet
// endpoint, and it carries the ONE identity that endpoint admits
// (certs.APIServerKubeletClientCN — the constant pkg/provider's accepted-identity
// predicate reads, so the two sides cannot drift apart).
//
// The negative assertion is as load-bearing as the positive one: this credential
// authenticates to the APISERVER as well (the signing CA is also
// --client-ca-file), so it must carry no Organization — a system:masters group
// here would leave a cluster-admin credential on disk for a job that needs no
// cluster authority at all.
func TestAPIServerKubeletClientIdentity(t *testing.T) {
	t.Parallel()
	wd := t.TempDir()
	s := NewSupervised(Config{WorkDir: wd, APIServerPort: 6444})
	if err := s.provisionComponentCerts(); err != nil {
		t.Fatalf("provision component certs: %v", err)
	}
	h, err := certs.EnsureHierarchy(wd) // idempotent — loads what provision created
	if err != nil {
		t.Fatalf("load hierarchy: %v", err)
	}

	certPEM, err := os.ReadFile(apiServerKubeletClientCertPath(wd))
	if err != nil {
		t.Fatalf("read apiserver kubelet-client cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("apiserver kubelet-client cert is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse apiserver kubelet-client cert: %v", err)
	}

	if leaf.Subject.CommonName != certs.APIServerKubeletClientCN {
		t.Errorf("apiserver kubelet-client CN = %q, want %q — the CN a node's :10250 admits",
			leaf.Subject.CommonName, certs.APIServerKubeletClientCN)
	}
	if len(leaf.Subject.Organization) != 0 {
		t.Errorf("apiserver kubelet-client Organization = %v, want none: this cert also authenticates to the apiserver, so it must grant no groups",
			leaf.Subject.Organization)
	}
	if err := leaf.CheckSignatureFrom(h.Signing.Cert); err != nil {
		t.Errorf("apiserver kubelet-client cert must be signed by the SIGNING CA (the anchor a node's kubelet endpoint verifies against): %v", err)
	}
	if !hasClientAuthEKU(leaf) {
		t.Errorf("apiserver kubelet-client cert must carry ExtKeyUsageClientAuth, got %v", leaf.ExtKeyUsage)
	}

	info, err := os.Stat(apiServerKubeletClientKeyPath(wd))
	if err != nil {
		t.Fatalf("stat apiserver kubelet-client key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("apiserver kubelet-client key mode = %o, want 600", perm)
	}
}

// TestAPIServerArgsAlwaysPresentKubeletClientCert pins that the apiserver is wired
// to PRESENT that identity in every posture, not only on the mesh.
//
// Unconditional is the whole point: a node's kubelet endpoint requires a client
// certificate on single-node and `k3sm dev` exactly as it does on a mesh, so an
// apiserver that omitted these flags anywhere would silently lose `kubectl logs`,
// `kubectl exec`, and the node proxy in that posture. The flags must also name the
// files provisionComponentCerts actually writes — a path that agreed with nothing
// would make kube-apiserver refuse to start.
func TestAPIServerArgsAlwaysPresentKubeletClientCert(t *testing.T) {
	t.Parallel()
	postures := map[string]Config{
		// M1/M2 single-node (and `k3sm dev`): no mesh fields set at all.
		"single-node": {WorkDir: "/var/lib/k3sm/server", APIServerPort: 6444},
		// M3 multi-node: the mesh trust posture.
		"mesh": {
			WorkDir:         "/var/lib/k3sm/server",
			APIServerPort:   6444,
			BindAddress:     "100.64.0.1",
			NodeIP:          "100.64.0.1",
			ClientCAFile:    "/var/lib/k3sm/server/tls/signing-ca.crt",
			KubeletCAFile:   "/var/lib/k3sm/server/tls/cluster-ca.crt",
			ServingCertFile: "/var/lib/k3sm/server/tls/apiserver.crt",
			ServingKeyFile:  "/var/lib/k3sm/server/tls/apiserver.key",
		},
	}
	for name, cfg := range postures {
		t.Run(name, func(t *testing.T) {
			args := apiServerArgs(cfg)
			if got, want := flagValue(args, "--kubelet-client-certificate"), apiServerKubeletClientCertPath(cfg.WorkDir); got != want {
				t.Errorf("--kubelet-client-certificate = %q, want %q", got, want)
			}
			if got, want := flagValue(args, "--kubelet-client-key"), apiServerKubeletClientKeyPath(cfg.WorkDir); got != want {
				t.Errorf("--kubelet-client-key = %q, want %q", got, want)
			}
		})
	}
}

// TestRotationReportsAPIServerKubeletClientCert keeps the rotation report honest:
// the kubelet-client keypair IS re-issued on every boot, so an operator reading
// `k3sm certificate rotate` must see it listed as rotated rather than have to
// infer it.
func TestRotationReportsAPIServerKubeletClientCert(t *testing.T) {
	t.Parallel()
	wd := "/var/lib/k3sm/server"
	paths := make([]string, 0, 8)
	for _, a := range reissuedArtifacts(wd) {
		paths = append(paths, a.Path)
	}
	for _, want := range []string{APIServerKubeletClientCertPath(wd), APIServerKubeletClientKeyPath(wd)} {
		if !slices.Contains(paths, want) {
			t.Errorf("reissuedArtifacts does not list %s; it lists %v", want, paths)
		}
	}
}
