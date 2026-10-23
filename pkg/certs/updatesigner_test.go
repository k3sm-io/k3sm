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

package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestIssueUpdateSigner pins the signer's shape: CN and O, code signing only,
// a P-256 key, a one-day lifetime, and a chain to the CA that issued it.
func TestIssueUpdateSigner(t *testing.T) {
	t.Parallel()
	ca, err := NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ca.IssueUpdateSigner()
	if err != nil {
		t.Fatalf("IssueUpdateSigner = %v", err)
	}
	c := s.Cert
	if c.Subject.CommonName != UpdateSignerCommonName || !slices.Equal(c.Subject.Organization, []string{UpdateSignerOrganization}) {
		t.Errorf("subject = %v", c.Subject)
	}
	if !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}) || c.IsCA {
		t.Errorf("EKU = %v, IsCA = %v; want code signing only, not a CA", c.ExtKeyUsage, c.IsCA)
	}
	if s.Key.Curve != elliptic.P256() {
		t.Errorf("key curve = %v", s.Key.Curve.Params().Name)
	}
	if life := c.NotAfter.Sub(c.NotBefore); life != UpdateSignerValidity+time.Hour || UpdateSignerValidity != 24*time.Hour {
		t.Errorf("validity = %v", life)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		t.Errorf("the signer does not chain to its CA for code signing: %v", err)
	}
	if b, _ := pem.Decode(s.CertPEM); b == nil || !slices.Equal(b.Bytes, c.Raw) {
		t.Error("CertPEM is not the certificate")
	}
}

// TestCAClockMintsTheSigner pins the clock seam: a CA made on an injected
// clock issues its signer on that clock, so the pair verifies at a time on it
// whether that time is before or after the wall clock, and not an hour before it.
func TestCAClockMintsTheSigner(t *testing.T) {
	t.Parallel()
	for name, at := range map[string]time.Time{
		"a year before the wall clock": time.Now().AddDate(-1, 0, 0),
		"a year after the wall clock":  time.Now().AddDate(1, 0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ca, err := NewCAWithClock("k3sm-cluster-ca", func() time.Time { return at })
			if err != nil {
				t.Fatal(err)
			}
			s, err := ca.IssueUpdateSigner()
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []*x509.Certificate{ca.Cert, s.Cert} {
				if !c.NotBefore.Equal(at.Add(-time.Hour).Truncate(time.Second)) {
					t.Errorf("%s NotBefore = %v, want an hour before %v", c.Subject.CommonName, c.NotBefore, at)
				}
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca.Cert)
			opts := x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
			if _, err := s.Cert.Verify(opts); err != nil {
				t.Errorf("the signer does not verify on the clock it was minted on: %v", err)
			}
			opts.CurrentTime = at.Add(-2 * time.Hour)
			if _, err := s.Cert.Verify(opts); err == nil {
				t.Error("the signer verifies two hours before the clock it was minted on")
			}
		})
	}
}

// TestLoadCAUsesTheRealClock pins that no injected clock survives a load: a CA
// minted on a clock a year back, persisted and reloaded with LoadCA, issues on
// the wall clock.
func TestLoadCAUsesTheRealClock(t *testing.T) {
	t.Parallel()
	ca, err := NewCAWithClock("k3sm-cluster-ca", func() time.Time { return time.Now().AddDate(-1, 0, 0) })
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.now != nil {
		t.Fatal("LoadCA kept a clock; a loaded CA must be on time.Now")
	}
	before := time.Now()
	s, err := loaded.IssueUpdateSigner()
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	nb := s.Cert.NotBefore
	if lo, hi := before.Add(-time.Hour).Truncate(time.Second), after.Add(-time.Hour); nb.Before(lo) || nb.After(hi) {
		t.Errorf("signer NotBefore = %v, want an hour before the wall clock (%v..%v)", nb, lo, hi)
	}
}

// TestNoOtherPathMintsTheUpdateSigner proves the update signer has one issuer.
// Every exported issuing path refuses its subject, none produces the
// code-signing usage, issueLeaf (the guard-free core) is called only by
// signLeaf and IssueUpdateSigner, and no file of the module outside this
// package calls x509.CreateCertificate (the join, the netserve endpoint, the
// CSR approval and the component certificates all issue through here).
func TestNoOtherPathMintsTheUpdateSigner(t *testing.T) {
	t.Parallel()
	ca, err := NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: UpdateSignerCommonName, Organization: []string{UpdateSignerOrganization}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	signerSubject := pkix.Name{CommonName: UpdateSignerCommonName, Organization: []string{UpdateSignerOrganization}}
	orgOnly := pkix.Name{CommonName: "system:node:worker", Organization: []string{UpdateSignerOrganization}}
	day := 24 * time.Hour
	refusals := map[string]func() error{
		"IssueServing CN": func() error { _, _, err := ca.IssueServing(UpdateSignerCommonName, nil, nil, day); return err },
		"IssueClient CN":  func() error { _, _, err := ca.IssueClient(UpdateSignerCommonName, nil, day); return err },
		"IssueClient O": func() error {
			_, _, err := ca.IssueClient("k3sm-admin", []string{UpdateSignerOrganization}, day)
			return err
		},
		"IssueServerClient CN": func() error { _, _, err := ca.IssueServerClient(UpdateSignerCommonName, nil, nil, day); return err },
		"ServingChainTLS CN":   func() error { _, err := ca.ServingChainTLS(UpdateSignerCommonName, nil, nil, day); return err },
		"SignClientCSR subject": func() error {
			_, err := ca.SignClientCSR(csr, signerSubject, nil, nil, day)
			return err
		},
		"SignClientCSR O":        func() error { _, err := ca.SignClientCSR(csr, orgOnly, nil, nil, day); return err },
		"SignServingCSR subject": func() error { _, err := ca.SignServingCSR(csr, signerSubject, nil, nil, day); return err },
		"signLeaf code signing": func() error {
			_, err := ca.signLeaf(&key.PublicKey, pkix.Name{CommonName: "x"}, nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, day)
			return err
		},
		"signLeaf any usage": func() error {
			_, err := ca.signLeaf(&key.PublicKey, pkix.Name{CommonName: "x"}, nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, day)
			return err
		},
	}
	for name, issue := range refusals {
		if err := issue(); !errors.Is(err, ErrUpdateSignerIdentity) {
			t.Errorf("%s = %v, want ErrUpdateSignerIdentity", name, err)
		}
	}

	// The ordinary issuers, as they are called, never carry code signing.
	var issued [][]byte
	add := func(certPEM []byte, err error) {
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		issued = append(issued, certPEM)
	}
	c1, _, err := ca.IssueServing("worker", []string{"worker"}, []net.IP{net.ParseIP("100.64.0.7")}, day)
	add(c1, err)
	c2, _, err := ca.IssueClient("system:node:worker", []string{"system:nodes"}, day)
	add(c2, err)
	c3, _, err := ca.IssueServerClient("etcd", nil, nil, day)
	add(c3, err)
	nodeCSR := csr
	c4, err := ca.SignClientCSR(nodeCSR, pkix.Name{CommonName: "system:node:worker", Organization: []string{"system:nodes"}}, nil, nil, day)
	add(c4, err)
	c5, err := ca.SignServingCSR(nodeCSR, pkix.Name{CommonName: "worker"}, nil, nil, day)
	add(c5, err)
	h := newTestHierarchy(t)
	c6, _, err := h.IssueProxyClient(day)
	add(c6, err)
	for i, p := range issued {
		b, _ := pem.Decode(p)
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) || slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
			t.Errorf("issuer %d minted %v with code signing", i, cert.Subject)
		}
	}

	// Source: issueLeaf's callers, and the module's other CreateCertificate calls.
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var callers []string
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "issueLeaf" {
						callers = append(callers, fn.Name.Name)
					}
					return true
				})
			}
		}
	}
	slices.Sort(callers)
	if !slices.Equal(callers, []string{"IssueUpdateSigner", "signLeaf"}) {
		t.Errorf("issueLeaf is called from %v, want only signLeaf and IssueUpdateSigner", callers)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var outside []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			switch rel {
			case ".git", "hack":
				return filepath.SkipDir // hack/ holds spike probes, never shipped
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || filepath.Dir(rel) == filepath.Join("pkg", "certs") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "CreateCertificate(") {
			outside = append(outside, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outside) != 0 {
		t.Errorf("certificates are issued outside pkg/certs, past the update-signer guard: %v", outside)
	}
}
