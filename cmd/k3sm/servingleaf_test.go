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

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
)

// TestSingleNodeServingLeafIsClusterCASigned is the gate for the single-node
// apiserver serving leaf. A server with no --mesh-ip used to issue no leaf at all:
// kube-apiserver self-signed into its own --cert-dir, so nothing it served chained
// to the cluster CA the rest of the cluster trusts. provisionControlPlane must now
// issue the leaf from the cluster CA on the single-node branch, through the one
// issuance path, with loopback-aware names (never a nil IP), a 0600 key, and
// RootCAFile on the cluster CA; re-issuing it keeps the CA pin and replaces the
// pair. The rows pin --tls-san on a single node (issued; a reserved name refused
// by the existing validation), a node name that collides with a reserved name (skipped,
// never issued and never fatal), and a truncated key a crash left (overwritten).
//
// It swaps the package-level ensureHierarchy seam, so it does not run parallel.
func TestSingleNodeServingLeafIsClusterCASigned(t *testing.T) {
	const nodeName = "node-a"
	logger := slog.New(slog.DiscardHandler)
	provision := func(t *testing.T, opts serverOptions) (executor.Config, error) {
		t.Helper()
		cfg, _, err := provisionControlPlane(context.Background(), &opts, "", logger)
		return cfg, err
	}
	base := func(t *testing.T) serverOptions {
		return serverOptions{workDir: t.TempDir(), nodeName: nodeName, nodeIP: "127.0.0.1", apiPort: 6444}
	}
	leafOf := func(t *testing.T, path string) *x509.Certificate {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the serving leaf: %v (no leaf was issued on the single-node path)", err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatalf("%s holds no PEM block", path)
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		return leaf
	}

	t.Run("the leaf chains to the cluster CA alone", func(t *testing.T) {
		type call struct {
			role    certs.Role
			posture certs.Posture
		}
		var calls []call
		orig := ensureHierarchy
		t.Cleanup(func() { ensureHierarchy = orig })
		ensureHierarchy = func(workDir string, role certs.Role, posture certs.Posture) (*certs.Hierarchy, error) {
			calls = append(calls, call{role, posture})
			return orig(workDir, role, posture)
		}

		opts := base(t)
		cfg, err := provision(t, opts)
		if err != nil {
			t.Fatalf("provisionControlPlane (single-node): %v", err)
		}
		if want := (executor.Config{}).CARole(); !slices.Equal(calls, []call{{want, certs.PostureKine}}) {
			t.Errorf("hierarchy calls = %v, want exactly one with the server's CARole (%v) and PostureKine", calls, want)
		}
		wd := opts.workDir
		if cfg.ServingCertFile != certs.APIServerServingCertPath(wd) || cfg.ServingKeyFile != certs.APIServerServingKeyPath(wd) {
			t.Errorf("serving pair = %q, %q; want the PKI-dir leaf", cfg.ServingCertFile, cfg.ServingKeyFile)
		}
		if cfg.RootCAFile != certs.ClusterCACertPath(wd) {
			t.Errorf("RootCAFile = %q, want the cluster CA %q", cfg.RootCAFile, certs.ClusterCACertPath(wd))
		}

		caPEM, err := os.ReadFile(certs.ClusterCACertPath(wd))
		if err != nil {
			t.Fatalf("read cluster CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			t.Fatal("cluster CA does not parse")
		}
		leaf := leafOf(t, cfg.ServingCertFile)
		for _, name := range []string{"localhost", "127.0.0.1"} {
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				t.Errorf("the leaf does not verify against the cluster CA for %s: %v", name, err)
			}
		}
		for _, name := range []string{"kubernetes.default.svc.cluster.local", nodeName} {
			if !slices.Contains(leaf.DNSNames, name) {
				t.Errorf("leaf DNS names %v lack %s", leaf.DNSNames, name)
			}
		}
		if !slices.ContainsFunc(leaf.IPAddresses, net.ParseIP("10.43.0.1").Equal) {
			t.Errorf("leaf IPs %v lack the kubernetes Service IP 10.43.0.1", leaf.IPAddresses)
		}
		for _, ip := range leaf.IPAddresses {
			if len(ip) == 0 || ip.IsUnspecified() {
				t.Errorf("leaf carries a nil or unspecified IP: %v", leaf.IPAddresses)
			}
		}
		fi, err := os.Stat(cfg.ServingKeyFile)
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("serving key mode = %v, want no group or world bits", fi.Mode().Perm())
		}

		// A second boot re-issues the pair over the same CA.
		h1, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
		if err != nil {
			t.Fatalf("load hierarchy: %v", err)
		}
		firstCert, _ := os.ReadFile(cfg.ServingCertFile)
		firstKey, _ := os.ReadFile(cfg.ServingKeyFile)
		if _, err := provision(t, opts); err != nil {
			t.Fatalf("second provisionControlPlane: %v", err)
		}
		h2, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
		if err != nil {
			t.Fatalf("reload hierarchy: %v", err)
		}
		if h1.Cluster.PinHash() != h2.Cluster.PinHash() || h1.Signing.PinHash() != h2.Signing.PinHash() {
			t.Error("re-issuing the serving leaf changed a CA pin")
		}
		secondCert, _ := os.ReadFile(cfg.ServingCertFile)
		secondKey, _ := os.ReadFile(cfg.ServingKeyFile)
		if bytes.Equal(firstCert, secondCert) || bytes.Equal(firstKey, secondKey) {
			t.Error("a second boot did not replace the serving pair")
		}
	})

	t.Run("a --tls-san extra is issued", func(t *testing.T) {
		opts := base(t)
		opts.tlsSANs = tlsSANList{"api.example.com"}
		cfg, err := provision(t, opts)
		if err != nil {
			t.Fatalf("provisionControlPlane: %v", err)
		}
		if leaf := leafOf(t, cfg.ServingCertFile); !slices.Contains(leaf.DNSNames, "api.example.com") {
			t.Errorf("leaf DNS names %v lack the --tls-san extra", leaf.DNSNames)
		}
	})

	t.Run("a reserved extra is refused", func(t *testing.T) {
		opts := base(t)
		opts.tlsSANs = tlsSANList{"kubernetes.default"}
		if _, err := provision(t, opts); !errors.Is(err, ErrTLSSANInvalid) {
			t.Fatalf("provisionControlPlane = %v, want %v", err, ErrTLSSANInvalid)
		}
		if _, err := os.Stat(certs.APIServerServingCertPath(opts.workDir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refused extra still wrote a leaf (stat err %v)", err)
		}
	})

	t.Run("a node name equal to a reserved name is skipped", func(t *testing.T) {
		opts := base(t)
		opts.nodeName = "kubernetes"
		cfg, err := provision(t, opts)
		if err != nil {
			t.Fatalf("provisionControlPlane with a reserved node name: %v (must skip it, never fail the start)", err)
		}
		leaf := leafOf(t, cfg.ServingCertFile)
		if !slices.Equal(leaf.DNSNames, apiServerFixedDNS) {
			t.Errorf("leaf DNS names = %v, want exactly the fixed set %v (the reserved node name is not issued)", leaf.DNSNames, apiServerFixedDNS)
		}
	})

	t.Run("a truncated pre-existing key is overwritten", func(t *testing.T) {
		opts := base(t)
		keyPath := certs.APIServerServingKeyPath(opts.workDir)
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte("-----BEGIN EC PRIV"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := provision(t, opts)
		if err != nil {
			t.Fatalf("provisionControlPlane over a truncated key: %v", err)
		}
		raw, err := os.ReadFile(cfg.ServingKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		if block, _ := pem.Decode(raw); block == nil {
			t.Fatalf("the truncated key was not replaced: %q", raw)
		}
	})
}

// TestRotatePlistReadFailsClosed pins that a rotation with --restart reads the
// installed server plist (else the server-arguments record) for the probe address
// before anything is restarted, and that a read that fails aborts it.
func TestRotatePlistReadFailsClosed(t *testing.T) {
	t.Parallel()
	t.Run("a failed plist read aborts before the restart", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		seedHierarchy(t, dir)
		denied := func(path string) ([]byte, error) {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
		}
		r := &fakeRestarter{pid: 100}
		var out bytes.Buffer
		err := rotateInstalled(context.Background(), &out, denied, filepath.Join(dir, "server.plist"), filepath.Join(dir, "record.json"), dir, true, 6444, r)
		if err == nil || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("rotateInstalled = %v, want the plist read's permission error", err)
		}
		if len(r.calls) != 0 {
			t.Errorf("the restarter was called (%v) after a failed topology read; the rotation must abort first", r.calls)
		}
	})
}
