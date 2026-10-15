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
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// tlsSANTestMesh is the mesh IP the gate's server runs with.
const tlsSANTestMesh = "100.64.0.1"

// fixedServingSANs is the fixed apiserver serving set, derived from its one
// owner (apiServerServingSANs with no extras); an empty list must yield it
// exactly.
func fixedServingSANs(t *testing.T) (dns, ips []string) {
	t.Helper()
	d, i, err := apiServerServingSANs(tlsSANTestMesh, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range i {
		ips = append(ips, ip.String())
	}
	return d, ips
}

// TestTLSSANReservedSetIsTheFixedSet pins that the names and addresses a
// --tls-san may not claim are exactly the fixed serving set, other than the
// mesh IP, which a server may name again.
func TestTLSSANReservedSetIsTheFixedSet(t *testing.T) {
	dns, ips := fixedServingSANs(t)
	if !slices.Equal(reservedTLSSANNames, dns) {
		t.Errorf("reserved names %v, fixed DNS set %v", reservedTLSSANNames, dns)
	}
	var reserved []string
	for _, ip := range reservedTLSSANIPs(netip.MustParsePrefix(install.DefaultServiceCIDR)) {
		reserved = append(reserved, ip.String())
	}
	if want := slices.DeleteFunc(slices.Clone(ips), func(s string) bool { return s == tlsSANTestMesh }); !slices.Equal(reserved, want) {
		t.Errorf("reserved IPs %v, fixed IP set without the mesh IP %v", reserved, want)
	}
}

// tlsSANWorkDir is a work dir holding a freshly minted cluster CA on disk, the
// state writeAPIServerServingCert runs against.
func tlsSANWorkDir(t *testing.T) (string, *certs.CA) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(certs.PKIDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certs.ClusterCACertPath(dir), ca.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certs.ClusterCAKeyPath(dir), ca.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, ca
}

// readServingLeaf parses the apiserver serving leaf in dir.
func readServingLeaf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(certs.APIServerServingCertPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("serving cert holds no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// leafIPs renders a leaf's IP SANs as strings.
func leafIPs(leaf *x509.Certificate) []string {
	out := make([]string, 0, len(leaf.IPAddresses))
	for _, ip := range leaf.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// assertCAUntouched checks the CA's pin and its files on disk did not change.
func assertCAUntouched(t *testing.T, dir string, ca *certs.CA, pin string) {
	t.Helper()
	if got := ca.PinHash(); got != pin {
		t.Errorf("CA pin changed: %s -> %s", pin, got)
	}
	certPEM, err := os.ReadFile(certs.ClusterCACertPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(certs.ClusterCAKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certPEM, ca.CertPEM) || !bytes.Equal(keyPEM, ca.KeyPEM) {
		t.Error("the CA files on disk changed")
	}
	reloaded, err := certs.LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.PinHash() != pin {
		t.Errorf("CA on disk pins %s, want %s", reloaded.PinHash(), pin)
	}
}

// recordFor writes the server-arguments record an install with cfg leaves and
// returns a reader that sees it and no installed plist (the post-uninstall
// state).
func recordFor(t *testing.T, cfg install.Config) (read func(string) ([]byte, error), recPath string) {
	t.Helper()
	recPath = filepath.Join(t.TempDir(), "server-args.json")
	err := dataroot.WriteServerArgsRecord(recPath, dataroot.ServerArgsRecord{
		Version:   dataroot.ServerArgsRecordVersion,
		Args:      install.RecordedServerArgs(cfg),
		CreatedBy: "test",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return func(p string) ([]byte, error) {
		if p == recPath {
			return os.ReadFile(p)
		}
		return nil, fs.ErrNotExist
	}, recPath
}

// TestAPIServerServingCertTLSSAN is the --tls-san gate: the real serving-cert
// writer issues every validated extra name beside the fixed set from the
// existing cluster CA, which is never changed; invalid, colliding, non-local
// and single-node requests are refused before anything is written; the install
// record keeps and replaces the list; and a rotation checks the reissued leaf
// still carries the recorded names.
func TestAPIServerServingCertTLSSAN(t *testing.T) {
	stubLocalAddrs(t, "192.168.0.50", "fe80::1", tlsSANTestMesh)

	issued := []struct {
		name    string
		extra   []string
		wantDNS []string
		wantIPs []string
	}{
		{name: "no extras is exactly the fixed set", extra: nil},
		{
			name:    "hostnames and local IPs are added, canonicalised and deduplicated",
			extra:   []string{"API.Example.com", "lb.example.net", "api.example.com", "192.168.0.50", "::ffff:192.168.0.50", "::1"},
			wantDNS: []string{"api.example.com", "lb.example.net"},
			wantIPs: []string{"192.168.0.50", "::1"},
		},
		{name: "the mesh IP named again adds nothing", extra: []string{tlsSANTestMesh}},
	}
	for _, tc := range issued {
		t.Run(tc.name, func(t *testing.T) {
			dir, ca := tlsSANWorkDir(t)
			pin := ca.PinHash()
			canon, err := checkInstallTLSSANs(tc.extra, tlsSANTestMesh, install.DefaultServiceCIDR)
			if tc.extra != nil && err != nil {
				t.Fatalf("install check refused %v: %v", tc.extra, err)
			}
			if _, _, err := writeAPIServerServingCert(dir, ca, tlsSANTestMesh, canon); err != nil {
				t.Fatal(err)
			}
			leaf := readServingLeaf(t, dir)
			fixedDNS, fixedIPs := fixedServingSANs(t)
			wantDNS := append(fixedDNS, tc.wantDNS...)
			wantIPs := append(fixedIPs, tc.wantIPs...)
			if !slices.Equal(leaf.DNSNames, wantDNS) {
				t.Errorf("DNS SANs = %v, want %v", leaf.DNSNames, wantDNS)
			}
			if got := leafIPs(leaf); !slices.Equal(got, wantIPs) {
				t.Errorf("IP SANs = %v, want %v", got, wantIPs)
			}
			if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
				t.Errorf("leaf is not signed by the cluster CA: %v", err)
			}
			assertCAUntouched(t, dir, ca, pin)
		})
	}

	refused := []struct {
		name   string
		extra  []string
		mesh   string
		target error
	}{
		{name: "an IP this Mac does not hold", extra: []string{"203.0.113.7"}, mesh: tlsSANTestMesh, target: ErrTLSSANNotLocal},
		{name: "a wildcard", extra: []string{"*.example.com"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a fixed in-cluster name", extra: []string{"kubernetes.default.svc"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "localhost", extra: []string{"LocalHost"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "the kubernetes Service IP", extra: []string{"10.43.0.1"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a Service range address", extra: []string{"10.43.7.7"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a pod range address", extra: []string{"100.64.3.4"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a port suffix", extra: []string{"api.example.com:6443"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a URL", extra: []string{"https://api.example.com"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a trailing dot", extra: []string{"api.example.com."}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "an IPv6 zone", extra: []string{"fe80::1%en0"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "an empty name", extra: []string{""}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a label over 63 characters", extra: []string{strings.Repeat("a", 64) + ".example.com"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a last label of digits", extra: []string{"1.2.3"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a two-label legacy IPv4 form", extra: []string{"10.1"}, mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "more than 32 names", extra: manyTLSSANs(33), mesh: tlsSANTestMesh, target: ErrTLSSANInvalid},
		{name: "a single-node server", extra: []string{"api.example.com"}, mesh: "", target: ErrTLSSANSingleNode},
	}
	for _, tc := range refused {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			dir, ca := tlsSANWorkDir(t)
			pin := ca.PinHash()
			if _, err := checkInstallTLSSANs(tc.extra, tc.mesh, install.DefaultServiceCIDR); !errors.Is(err, tc.target) {
				t.Fatalf("install check = %v, want %v", err, tc.target)
			}
			if tc.target == ErrTLSSANInvalid {
				if err := checkServerTLSSANs(tc.extra, tc.mesh, install.DefaultServiceCIDR, slog.New(slog.DiscardHandler)); !errors.Is(err, tc.target) {
					t.Errorf("server start check = %v, want %v", err, tc.target)
				}
			}
			if tc.target == ErrTLSSANInvalid {
				if _, _, err := writeAPIServerServingCert(dir, ca, tc.mesh, tc.extra); !errors.Is(err, ErrTLSSANInvalid) {
					t.Errorf("writer = %v, want %v", err, ErrTLSSANInvalid)
				}
			}
			if _, err := os.Stat(certs.APIServerServingCertPath(dir)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a serving cert was written for a refused request: %v", err)
			}
			assertCAUntouched(t, dir, ca, pin)
		})
	}

	t.Run("at server start a moved IP is a warning and is still issued", func(t *testing.T) {
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		extra := []string{"203.0.113.7", "api.example.com"}
		if err := checkServerTLSSANs(extra, tlsSANTestMesh, install.DefaultServiceCIDR, logger); err != nil {
			t.Fatalf("server start refused a recorded IP that moved: %v", err)
		}
		if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "203.0.113.7") {
			t.Errorf("no warning naming the moved address: %s", logs.String())
		}
		dir, ca := tlsSANWorkDir(t)
		if _, _, err := writeAPIServerServingCert(dir, ca, tlsSANTestMesh, extra); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(leafIPs(readServingLeaf(t, dir)), "203.0.113.7") {
			t.Error("the moved address was not issued")
		}
	})

	t.Run("at server start a recorded list without --mesh-ip is a warning, not a refusal", func(t *testing.T) {
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		if err := checkServerTLSSANs([]string{"api.example.com", "*.bad"}, "", install.DefaultServiceCIDR, logger); err != nil {
			t.Fatalf("a single-node server refused to start on a recorded list: %v", err)
		}
		if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "api.example.com") {
			t.Errorf("no warning naming the ignored list: %s", logs.String())
		}
	})

	t.Run("the configured Service CIDR decides the reserved range", func(t *testing.T) {
		const custom = "10.96.0.0/12"
		for _, ip := range []string{"10.96.0.1", "10.100.0.5"} {
			if _, err := validateTLSSANs([]string{ip}, tlsSANTestMesh, custom); !errors.Is(err, ErrTLSSANInvalid) {
				t.Errorf("%s in Service range %s = %v, want %v", ip, custom, err, ErrTLSSANInvalid)
			}
			if _, err := checkInstallTLSSANs([]string{ip}, tlsSANTestMesh, custom); !errors.Is(err, ErrTLSSANInvalid) {
				t.Errorf("install: %s in Service range %s = %v, want %v", ip, custom, err, ErrTLSSANInvalid)
			}
		}
		if _, err := validateTLSSANs([]string{"10.43.0.1", "10.43.7.7"}, tlsSANTestMesh, custom); err != nil {
			t.Errorf("addresses outside the configured range %s refused: %v", custom, err)
		}
	})

	t.Run("the install record keeps the list and a new list replaces it", func(t *testing.T) {
		first := install.Config{Role: install.RoleServer, MeshIP: tlsSANTestMesh, TLSSANs: []string{"api.example.com", "192.168.0.50"}}
		read, rec := recordFor(t, first)
		got, err := install.InstalledTLSSANs(read, "/no-plist", rec)
		if err != nil || !slices.Equal(got, first.TLSSANs) {
			t.Fatalf("recorded = %v, %v; want %v", got, err, first.TLSSANs)
		}
		// Uninstall removed the plist; reinstall without --tls-san.
		carried, err := install.InstalledServerArgs(read, "/no-plist", rec)
		if err != nil {
			t.Fatal(err)
		}
		read2, rec2 := recordFor(t, install.Config{Role: install.RoleServer, ExtraServerArgs: carried})
		if got, err := install.InstalledTLSSANs(read2, "/no-plist", rec2); err != nil || !slices.Equal(got, first.TLSSANs) {
			t.Errorf("reinstall without --tls-san recorded %v, %v; want %v kept", got, err, first.TLSSANs)
		}
		// Reinstall with a new list.
		read3, rec3 := recordFor(t, install.Config{Role: install.RoleServer, ExtraServerArgs: carried, TLSSANs: []string{"lb.example.net"}})
		if got, err := install.InstalledTLSSANs(read3, "/no-plist", rec3); err != nil || !slices.Equal(got, []string{"lb.example.net"}) {
			t.Errorf("reinstall with a new list recorded %v, %v; want [lb.example.net]", got, err)
		}
		// The install flag resolves against the recorded mesh IP.
		o, err := parseInstallFlags([]string{"--user", "alice", "--tls-san", "API.example.com", "--tls-san=192.168.0.50"})
		if err != nil {
			t.Fatal(err)
		}
		sans, err := o.resolveTLSSANs(read, "/no-plist", rec)
		if err != nil || !slices.Equal(sans, []string{"api.example.com", "192.168.0.50"}) {
			t.Errorf("resolved = %v, %v", sans, err)
		}
		none := func(string) ([]byte, error) { return nil, fs.ErrNotExist }
		if _, err := o.resolveTLSSANs(none, "/p", "/r"); !errors.Is(err, ErrTLSSANSingleNode) {
			t.Errorf("no recorded mesh IP = %v, want %v", err, ErrTLSSANSingleNode)
		}
		if _, err := parseInstallFlags([]string{"--agent", "--server", "10.0.0.1", "--tls-san", "a.example.com"}); err == nil {
			t.Error("--tls-san accepted on a worker install")
		}
	})

	t.Run("rotation reissues a leaf that keeps the recorded names", func(t *testing.T) {
		read, rec := recordFor(t, install.Config{Role: install.RoleServer, MeshIP: tlsSANTestMesh, TLSSANs: []string{"api.example.com", "192.168.0.50"}})
		sans, err := install.InstalledTLSSANs(read, "/no-plist", rec)
		if err != nil {
			t.Fatal(err)
		}
		dir, ca := tlsSANWorkDir(t)
		pin := ca.PinHash()
		// A leaf without the names is what a rotation that dropped them leaves.
		if _, _, err := writeAPIServerServingCert(dir, ca, tlsSANTestMesh, nil); err != nil {
			t.Fatal(err)
		}
		if err := servingCertCarriesSANs(certs.APIServerServingCertPath(dir), sans); err == nil {
			t.Error("a leaf missing the recorded names passed the rotation check")
		}
		// The restarted server reissues from its argv, which carries the names.
		if _, _, err := writeAPIServerServingCert(dir, ca, tlsSANTestMesh, sans); err != nil {
			t.Fatal(err)
		}
		if err := servingCertCarriesSANs(certs.APIServerServingCertPath(dir), sans); err != nil {
			t.Errorf("reissued leaf: %v", err)
		}
		assertCAUntouched(t, dir, ca, pin)
	})
}

// TestTLSSANNeverBlocksMaintenanceExits pins that a recorded invalid
// --tls-san does not stop `k3sm server --clear-crashloop` or `--cluster-reset`.
func TestTLSSANNeverBlocksMaintenanceExits(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	parse := func(t *testing.T, extra ...string) serverOptions {
		t.Helper()
		var opts serverOptions
		fsys := flag.NewFlagSet("server", flag.ContinueOnError)
		_ = registerServerFlags(fsys, &opts)
		args := append([]string{"--work-dir", t.TempDir(), "--node-name", "server-a", "--mesh-ip", tlsSANTestMesh, "--tls-san=*.bad.example.com"}, extra...)
		if err := fsys.Parse(args); err != nil {
			t.Fatal(err)
		}
		return opts
	}

	t.Run("clear-crashloop", func(t *testing.T) {
		opts := parse(t, "--clear-crashloop")
		if _, _, done, err := preflightServer(&opts, nil, logger); !done || err != nil {
			t.Fatalf("preflightServer = done %v, %v; want done with no error", done, err)
		}
	})
	t.Run("cluster-reset", func(t *testing.T) {
		calls := 0
		clusterResetFunc = func(context.Context, executor.Config) error { calls++; return nil }
		t.Cleanup(func() { clusterResetFunc = executor.ClusterReset })
		opts := parse(t, "--cluster-reset", "--etcd-peer-ip", "192.0.2.10")
		if _, _, done, err := preflightServer(&opts, nil, logger); !done || err != nil || calls != 1 {
			t.Fatalf("preflightServer = done %v, %v, reset ran %d times; want done, no error, one reset", done, err, calls)
		}
	})
	t.Run("an ordinary start is refused", func(t *testing.T) {
		opts := parse(t, "--network", "none")
		if _, _, _, err := preflightServer(&opts, nil, logger); !errors.Is(err, ErrTLSSANInvalid) {
			t.Fatalf("preflightServer = %v, want %v", err, ErrTLSSANInvalid)
		}
	})
}

// manyTLSSANs is n distinct valid hostnames.
func manyTLSSANs(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("h%d.example.com", i))
	}
	return out
}

// TestTLSSANFlagRegistered pins the repeatable --tls-san on `k3sm server`.
func TestTLSSANFlagRegistered(t *testing.T) {
	var opts serverOptions
	fsys := flag.NewFlagSet("server", flag.ContinueOnError)
	_ = registerServerFlags(fsys, &opts)
	if err := fsys.Parse([]string{"--tls-san", "a.example.com", "--tls-san=192.168.0.50"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal([]string(opts.tlsSANs), []string{"a.example.com", "192.168.0.50"}) {
		t.Errorf("tlsSANs = %v", opts.tlsSANs)
	}
}
