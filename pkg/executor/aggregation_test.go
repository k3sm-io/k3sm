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
	"errors"
	"io/fs"
	"os"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// TestAPIServerArgsCarryAggregatorFlags pins the aggregation layer's eight apiserver
// flags, unconditional in every posture (single-node, `k3sm dev`, mesh, etcd HA),
// each rendered exactly once with the k3s values, routing explicitly off, and the
// request-header CA a different file from --client-ca-file.
func TestAPIServerArgsCarryAggregatorFlags(t *testing.T) {
	const wd = "/var/lib/k3sm/server"
	mesh := Config{
		WorkDir:         wd,
		APIServerPort:   6444,
		BindAddress:     "100.64.0.1",
		NodeIP:          "100.64.0.1",
		ClientCAFile:    certs.SigningCACertPath(wd),
		KubeletCAFile:   certs.ClusterCACertPath(wd),
		ServingCertFile: certs.APIServerServingCertPath(wd),
		ServingKeyFile:  certs.APIServerServingKeyPath(wd),
	}
	ha := mesh
	ha.Etcd = &EtcdConfig{Role: EtcdJoin, Name: "s2", PeerIP: "192.0.2.11", PeerPort: 2380, MetricsPort: 2381}
	postures := []struct {
		name string
		cfg  Config
	}{
		{"single-node", Config{WorkDir: wd, APIServerPort: 6444, NodeIP: "127.0.0.1", KinePort: 2379}},
		{"dev", Config{WorkDir: "/Users/dev/.k3sm/dev/server", APIServerPort: 16444, NodeIP: "127.0.0.1", KinePort: 12379}},
		{"mesh", mesh},
		{"etcd-HA", ha},
	}
	for _, p := range postures {
		t.Run(p.name, func(t *testing.T) {
			args := apiServerArgs(p.cfg)
			want := map[string]string{
				"--requestheader-client-ca-file":       certs.RequestHeaderCACertPath(p.cfg.WorkDir),
				"--requestheader-allowed-names":        "system:auth-proxy",
				"--requestheader-username-headers":     "X-Remote-User",
				"--requestheader-group-headers":        "X-Remote-Group",
				"--requestheader-extra-headers-prefix": "X-Remote-Extra-",
				"--proxy-client-cert-file":             ProxyClientCertPath(p.cfg.WorkDir),
				"--proxy-client-key-file":              ProxyClientKeyPath(p.cfg.WorkDir),
			}
			for flag, val := range want {
				if got := flagValues(args, flag); !slices.Equal(got, []string{val}) {
					t.Errorf("%s = %v, want exactly [%s]", flag, got, val)
				}
			}
			n := 0
			for _, a := range args {
				if a == "--enable-aggregator-routing=false" {
					n++
				}
				if a == "--enable-aggregator-routing" || a == "--enable-aggregator-routing=true" || a == "--requestheader-uid-headers" {
					t.Errorf("unexpected %s", a)
				}
			}
			if n != 1 {
				t.Errorf("--enable-aggregator-routing=false rendered %d times, want 1", n)
			}
			if rh, ca := flagValue(args, "--requestheader-client-ca-file"), flagValue(args, "--client-ca-file"); rh == "" || rh == ca {
				t.Errorf("--requestheader-client-ca-file %q must be set and differ from --client-ca-file %q", rh, ca)
			}
		})
	}
}

// TestProxyClientCertIdentity pins the front-proxy leaf provisionComponentCerts
// writes: CN system:auth-proxy, no Organization, clientAuth only, issued by the
// request-header CA (and by no other), key 0600, re-minted on every call.
func TestProxyClientCertIdentity(t *testing.T) {
	wd := t.TempDir()
	s := NewSupervised(Config{WorkDir: wd, APIServerPort: 6444})
	if err := s.provisionComponentCerts(); err != nil {
		t.Fatalf("provisionComponentCerts: %v", err)
	}
	read := func() *x509.Certificate {
		b, err := os.ReadFile(ProxyClientCertPath(wd))
		if err != nil {
			t.Fatalf("read the proxy client cert: %v", err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatal("the proxy client cert is not PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	leaf := read()
	if certs.ProxyClientCN != "system:auth-proxy" || leaf.Subject.CommonName != certs.ProxyClientCN {
		t.Errorf("CN = %q, want system:auth-proxy", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) != 0 {
		t.Errorf("Organization = %v, want none", leaf.Subject.Organization)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("EKU = %v, want clientAuth only (no serverAuth)", leaf.ExtKeyUsage)
	}
	pool := func(path string) *x509.CertPool {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(b) {
			t.Fatalf("%s holds no certificate", path)
		}
		return p
	}
	verify := func(c *x509.Certificate, roots *x509.CertPool) error {
		_, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return err
	}
	if err := verify(leaf, pool(certs.RequestHeaderCACertPath(wd))); err != nil {
		t.Errorf("the proxy leaf does not chain to the request-header CA: %v", err)
	}
	for _, other := range []string{certs.SigningCACertPath(wd), certs.ClusterCACertPath(wd)} {
		if err := verify(leaf, pool(other)); err == nil {
			t.Errorf("the proxy leaf verifies against %s", other)
		}
	}
	info, err := os.Stat(ProxyClientKeyPath(wd))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("proxy client key mode %o, want 600", info.Mode().Perm())
	}
	if err := s.provisionComponentCerts(); err != nil {
		t.Fatalf("second provisionComponentCerts: %v", err)
	}
	again := read()
	if again.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
		t.Error("the proxy leaf was not re-minted on the second boot")
	}
	if !slices.Equal(again.RawIssuer, leaf.RawIssuer) {
		t.Error("the re-minted proxy leaf has another issuer")
	}
}

// TestProvisionPassesRole pins that the executor's CA ensure takes its role from the
// server's HA role (Config.CARole): a joined member (EtcdJoin, set from --server-join)
// with no imported CA stops with certs.ErrCANotImported and mints nothing; an init
// member and a kine server are mint authorities and mint.
func TestProvisionPassesRole(t *testing.T) {
	joined := &EtcdConfig{Role: EtcdJoin, Name: "s2", PeerIP: "192.0.2.11"}
	for _, tc := range []struct {
		name string
		cfg  Config
		want certs.Role
	}{
		{"kine", Config{}, certs.RoleMintAuthority},
		{"init member", Config{Etcd: &EtcdConfig{Role: EtcdInit, Name: "s1", PeerIP: "192.0.2.10"}}, certs.RoleMintAuthority},
		{"joined member", Config{Etcd: joined}, certs.RoleJoined},
	} {
		if got := tc.cfg.CARole(); got != tc.want {
			t.Errorf("%s: CARole = %v, want %v", tc.name, got, tc.want)
		}
	}
	t.Run("joined member: nothing minted", func(t *testing.T) {
		wd := t.TempDir()
		err := NewSupervised(Config{WorkDir: wd, APIServerPort: 6444, Etcd: joined}).provisionComponentCerts()
		if !errors.Is(err, certs.ErrCANotImported) {
			t.Fatalf("err = %v, want certs.ErrCANotImported", err)
		}
		if _, err := os.Lstat(certs.PKIDir(wd)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a joined server created the PKI dir (stat err %v)", err)
		}
	})
	t.Run("mint authority: mints", func(t *testing.T) {
		wd := t.TempDir()
		if err := NewSupervised(Config{WorkDir: wd, APIServerPort: 6444}).provisionComponentCerts(); err != nil {
			t.Fatalf("provisionComponentCerts: %v", err)
		}
		if _, err := certs.LoadRequestHeaderPin(wd); err != nil {
			t.Errorf("a mint authority holds no request-header CA: %v", err)
		}
	})
}

// TestRotationReportListsProxyClientCert keeps the rotation report honest about the
// aggregation layer: the proxy pair is re-issued every boot, the request-header CA is
// never rotated.
func TestRotationReportListsProxyClientCert(t *testing.T) {
	const wd = "/var/lib/k3sm/server"
	paths := func(as []RotationArtifact) []string {
		var out []string
		for _, a := range as {
			out = append(out, a.Path)
		}
		return out
	}
	re, oos := paths(reissuedArtifacts(wd)), paths(outOfScopeArtifacts(wd))
	for _, want := range []string{ProxyClientCertPath(wd), ProxyClientKeyPath(wd)} {
		if !slices.Contains(re, want) {
			t.Errorf("reissuedArtifacts does not list %s", want)
		}
	}
	for _, want := range []string{certs.RequestHeaderCACertPath(wd), certs.RequestHeaderCAKeyPath(wd)} {
		if !slices.Contains(oos, want) {
			t.Errorf("outOfScopeArtifacts does not list %s", want)
		}
		if slices.Contains(re, want) {
			t.Errorf("reissuedArtifacts lists the CA file %s", want)
		}
	}
}
