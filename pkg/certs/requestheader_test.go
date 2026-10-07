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
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// mkCA mints a CA for a test, failing it on error.
func mkCA(t *testing.T, cn string) *CA {
	t.Helper()
	ca, err := NewCA(cn)
	if err != nil {
		t.Fatalf("%s: %v", cn, err)
	}
	return ca
}

// fiveCAHierarchy is newTestHierarchy with a request-header CA set explicitly, so the
// gates below do not depend on how that helper is built.
func fiveCAHierarchy(t *testing.T) *Hierarchy {
	t.Helper()
	h := newTestHierarchy(t)
	h.requestHeader = mkCA(t, requestHeaderCACN)
	return h
}

// TestRequestHeaderCAProvisioned is B411's named gate: a mint authority's first
// EnsureHierarchy yields the request-header CA, a self-signed CA-only root with the
// documented CN, persisted 0644/0600 at RequestHeaderCACertPath, and loaded (not
// re-minted) on the next call.
func TestRequestHeaderCAProvisioned(t *testing.T) {
	wd := t.TempDir()
	h, err := EnsureHierarchy(wd, RoleMintAuthority, PostureKine)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	if h.requestHeader == nil {
		t.Fatal("EnsureHierarchy yields no request-header CA")
	}
	c := h.requestHeader.Cert
	if c.Subject.CommonName != "k3sm-request-header-ca" {
		t.Errorf("CN = %q, want k3sm-request-header-ca", c.Subject.CommonName)
	}
	if !c.IsCA || !c.BasicConstraintsValid || !c.MaxPathLenZero || c.MaxPathLen != 0 {
		t.Errorf("IsCA=%v basicConstraints=%v MaxPathLenZero=%v MaxPathLen=%d, want a path-length-zero CA",
			c.IsCA, c.BasicConstraintsValid, c.MaxPathLenZero, c.MaxPathLen)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Errorf("the request-header CA is not self-signed: %v", err)
	}
	for _, f := range []struct {
		path string
		data []byte
		mode fs.FileMode
	}{
		{RequestHeaderCACertPath(wd), h.requestHeader.CertPEM, 0o644},
		{RequestHeaderCAKeyPath(wd), h.requestHeader.KeyPEM, 0o600},
	} {
		info, err := os.Lstat(f.path)
		if err != nil {
			t.Fatalf("stat %s: %v", f.path, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != f.mode {
			t.Errorf("%s mode = %v, want regular %o", f.path, info.Mode(), f.mode)
		}
		if got, _ := os.ReadFile(f.path); !bytes.Equal(got, f.data) {
			t.Errorf("%s does not hold the CA's bytes", f.path)
		}
	}
	if filepath.Dir(RequestHeaderCACertPath(wd)) != PKIDir(wd) {
		t.Errorf("RequestHeaderCACertPath %s is not under the PKI dir %s", RequestHeaderCACertPath(wd), PKIDir(wd))
	}
	again, err := EnsureHierarchy(wd, RoleMintAuthority, PostureKine)
	if err != nil {
		t.Fatalf("second EnsureHierarchy: %v", err)
	}
	if again.requestHeader == nil || again.requestHeader.PinHash() != h.requestHeader.PinHash() {
		t.Error("a second EnsureHierarchy must LOAD the request-header CA, not mint another")
	}
}

// TestRequestHeaderCADistinctFromClusterAndSigning proves the five roots are distinct
// and that trust does not cross between them: a signing-CA node client cert (and a
// signing-CA cert that claims the proxy CN) is no request-header client, and the
// proxy leaf verifies against no other CA.
func TestRequestHeaderCADistinctFromClusterAndSigning(t *testing.T) {
	wd := t.TempDir()
	h, err := EnsureHierarchy(wd, RoleMintAuthority, PostureEtcd)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	if h.requestHeader == nil || h.EtcdServer == nil || h.EtcdPeer == nil {
		t.Fatalf("the etcd-posture hierarchy is incomplete: missing %v", h.Missing(PostureEtcd))
	}
	cas := map[CAID]*CA{CACluster: h.Cluster, CASigning: h.Signing, CAEtcdServer: h.EtcdServer, CAEtcdPeer: h.EtcdPeer, CARequestHeader: h.requestHeader}
	seen := map[string]CAID{}
	for id, ca := range cas {
		if other, dup := seen[ca.PinHash()]; dup {
			t.Errorf("the %s CA shares a pin with the %s CA", id, other)
		}
		seen[ca.PinHash()] = id
	}

	node, _, err := h.Signing.IssueClient("system:node:x", []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAs(t, node, poolOf(h.Signing), x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("precondition: the node cert verifies against the signing CA: %v", err)
	}
	if err := verifyAs(t, node, poolOf(h.requestHeader), x509.ExtKeyUsageClientAuth); err == nil {
		t.Error("a signing-CA system:node cert verifies as a request-header client")
	}
	forged, _, err := h.Signing.IssueClient(ProxyClientCN, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAs(t, forged, poolOf(h.requestHeader), x509.ExtKeyUsageClientAuth); err == nil {
		t.Error("a signing-CA cert claiming the proxy CN verifies as a request-header client")
	}

	proxy, _, err := h.IssueProxyClient(time.Hour)
	if err != nil {
		t.Fatalf("IssueProxyClient: %v", err)
	}
	if err := verifyAs(t, proxy, poolOf(h.requestHeader), x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("precondition: the proxy leaf verifies against the request-header CA: %v", err)
	}
	for id, ca := range cas {
		if id == CARequestHeader {
			continue
		}
		if err := verifyAs(t, proxy, poolOf(ca), x509.ExtKeyUsageClientAuth); err == nil {
			t.Errorf("the proxy leaf verifies against the %s CA", id)
		}
	}
}

// TestRequestHeaderCAIssuesOnlyProxyClient pins that the request-header CA issues one
// kind of leaf by structure: its field is read only by the CA table row and by
// IssueProxyClient (the codec, the reconcile and Missing reach it through the row),
// no exported field or method hands out its *CA, and IssueProxyClient yields exactly
// CN system:auth-proxy, no Organization, clientAuth only.
func TestRequestHeaderCAIssuesOnlyProxyClient(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatalf("parse pkg/certs: %v", err)
	}
	readers := map[string]int{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				name := ""
				switch d := decl.(type) {
				case *ast.FuncDecl:
					name = d.Name.Name
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						if vs, ok := spec.(*ast.ValueSpec); ok {
							for _, n := range vs.Names {
								name += n.Name
							}
						}
					}
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "requestHeader" {
						readers[name]++
					}
					return true
				})
			}
		}
	}
	var names []string
	for n := range readers {
		names = append(names, n)
	}
	sort.Strings(names)
	if want := []string{"IssueProxyClient", "caSpecs"}; !slices.Equal(names, want) {
		t.Errorf("Hierarchy.requestHeader is read in %v, want exactly %v", names, want)
	}

	caType := reflect.TypeOf((*CA)(nil))
	ht := reflect.TypeOf(Hierarchy{})
	for i := 0; i < ht.NumField(); i++ {
		if f := ht.Field(i); f.Name == "requestHeader" && f.IsExported() {
			t.Error("the request-header CA field is exported")
		}
	}
	pt := reflect.TypeOf(&Hierarchy{})
	for i := 0; i < pt.NumMethod(); i++ {
		m := pt.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			if m.Type.Out(j) == caType {
				t.Errorf("Hierarchy.%s returns a *CA", m.Name)
			}
		}
	}
	h, err := EnsureHierarchy(t.TempDir(), RoleMintAuthority, PostureKine)
	if err != nil {
		t.Fatal(err)
	}
	if h.requestHeader == nil {
		t.Fatal("no request-header CA to check the exported fields against")
	}
	hv := reflect.ValueOf(*h)
	for i := 0; i < ht.NumField(); i++ {
		if ht.Field(i).IsExported() && ht.Field(i).Type == caType && hv.Field(i).Interface().(*CA) == h.requestHeader {
			t.Errorf("exported field %s holds the request-header CA", ht.Field(i).Name)
		}
	}

	certPEM, keyPEM, err := h.IssueProxyClient(time.Hour)
	if err != nil {
		t.Fatalf("IssueProxyClient: %v", err)
	}
	leaf := parseFirstCert(t, certPEM)
	if leaf.Subject.CommonName != ProxyClientCN || ProxyClientCN != "system:auth-proxy" {
		t.Errorf("CN = %q, want system:auth-proxy", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) != 0 {
		t.Errorf("Organization = %v, want none", leaf.Subject.Organization)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("EKU = %v, want clientAuth only", leaf.ExtKeyUsage)
	}
	if leaf.IsCA {
		t.Error("the proxy leaf is a CA")
	}
	if err := leaf.CheckSignatureFrom(h.requestHeader.Cert); err != nil {
		t.Errorf("the proxy leaf is not issued by the request-header CA: %v", err)
	}
	if _, err := tlsPairMatches(certPEM, keyPEM); err != nil {
		t.Errorf("the proxy key does not match its cert: %v", err)
	}
	if _, _, err := (&Hierarchy{}).IssueProxyClient(time.Hour); err == nil {
		t.Error("IssueProxyClient on a hierarchy without the request-header CA must fail")
	}
}

// tlsPairMatches reports whether keyPEM is the private key of certPEM.
func tlsPairMatches(certPEM, keyPEM []byte) (bool, error) {
	_, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return false, err
	}
	cert, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(cert.Bytes)
	if err != nil {
		return false, err
	}
	if !key.PublicKey.Equal(c.PublicKey) {
		return false, errors.New("public keys differ")
	}
	return true, nil
}

// TestEnsureHierarchyJoinedNeverMints pins that a joined server never mints: any
// absent CA, the all-absent case of --server-join without --server included, is
// ErrCANotImported naming it, with the PKI dir unchanged; a complete hierarchy loads.
func TestEnsureHierarchyJoinedNeverMints(t *testing.T) {
	t.Run("all absent: nothing minted", func(t *testing.T) {
		wd := t.TempDir()
		_, err := EnsureHierarchy(wd, RoleJoined, PostureEtcd)
		if !errors.Is(err, ErrCANotImported) {
			t.Fatalf("err = %v, want ErrCANotImported", err)
		}
		if !strings.Contains(fmtErr(err), string(CACluster)) {
			t.Errorf("error %q does not name the cluster CA", err)
		}
		if _, err := os.Lstat(PKIDir(wd)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refused joined EnsureHierarchy created the PKI dir (stat err %v)", err)
		}
	})
	h := fiveCAHierarchy(t)
	for _, id := range []CAID{CACluster, CASigning, CAEtcdServer, CAEtcdPeer, CARequestHeader} {
		t.Run(string(id)+" absent", func(t *testing.T) {
			wd := writeFull(t, h)
			removeCA(t, wd, id)
			before := snapshotPKI(t, wd)
			_, err := EnsureHierarchy(wd, RoleJoined, PostureEtcd)
			if !errors.Is(err, ErrCANotImported) {
				t.Fatalf("err = %v, want ErrCANotImported", err)
			}
			if !strings.Contains(err.Error(), string(id)) {
				t.Errorf("error %q does not name the %s CA", err, id)
			}
			assertUnchanged(t, before, snapshotPKI(t, wd))
		})
	}
	t.Run("complete: loads the imported CAs", func(t *testing.T) {
		wd := writeFull(t, h)
		before := snapshotPKI(t, wd)
		got, err := EnsureHierarchy(wd, RoleJoined, PostureEtcd)
		if err != nil {
			t.Fatalf("EnsureHierarchy: %v", err)
		}
		if missing := got.Missing(PostureEtcd); len(missing) != 0 {
			t.Fatalf("loaded hierarchy misses %v", missing)
		}
		if got.Cluster.PinHash() != h.Cluster.PinHash() || got.requestHeader.PinHash() != h.requestHeader.PinHash() {
			t.Error("a joined EnsureHierarchy did not load the imported CAs")
		}
		assertUnchanged(t, before, snapshotPKI(t, wd))
	})
	t.Run("kine posture: the etcd pair is not needed", func(t *testing.T) {
		wd := writeFull(t, h)
		if err := os.RemoveAll(EtcdCertPaths(wd).Dir); err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureHierarchy(wd, RoleJoined, PostureKine); err != nil {
			t.Fatalf("EnsureHierarchy(kine): %v", err)
		}
	})
}

// fmtErr renders err, "<nil>" for nil.
func fmtErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// TestHalfPresentPairIsIncompleteNotMissing pins the half-present refusal in both
// roles as ErrIncompleteHierarchy (never "missing", never a mint), and MissingOnDisk
// returning that error rather than the CA's id.
func TestHalfPresentPairIsIncompleteNotMissing(t *testing.T) {
	h := newTestHierarchy(t)
	cases := []struct {
		name   string
		id     CAID
		remove func(cert, key string) string // returns the surviving file
	}{
		{"key without cert", CAEtcdPeer, func(cert, key string) string { must(os.Remove(cert)); return key }},
		{"cert without key", CASigning, func(cert, key string) string { must(os.Remove(key)); return cert }},
	}
	for _, tc := range cases {
		for _, role := range []Role{RoleMintAuthority, RoleJoined} {
			t.Run(tc.name+"/"+role.String(), func(t *testing.T) {
				wd := t.TempDir()
				if err := ReconcileImportedHierarchy(wd, h, PostureEtcd); err != nil {
					t.Fatal(err)
				}
				cert, key := caPaths(t, wd, tc.id)
				survivor := tc.remove(cert, key)
				before := snapshotPKI(t, wd)
				_, err := EnsureHierarchy(wd, role, PostureEtcd)
				if !errors.Is(err, ErrIncompleteHierarchy) {
					t.Fatalf("EnsureHierarchy err = %v, want ErrIncompleteHierarchy", err)
				}
				if !strings.Contains(err.Error(), survivor) {
					t.Errorf("error %q does not name the surviving %s", err, survivor)
				}
				assertUnchanged(t, before, snapshotPKI(t, wd))
				got, err := MissingOnDisk(wd, PostureEtcd)
				if !errors.Is(err, ErrIncompleteHierarchy) || got != nil {
					t.Errorf("MissingOnDisk = %v, %v; want nil and ErrIncompleteHierarchy", got, err)
				}
			})
		}
	}
}

// must panics on err; for test setup closures that have no *testing.T.
func must(err error) {
	if err != nil {
		panic(err)
	}
}

// v2Plaintext is a schema-2 bundle (B410's eight keys) for h's four B410 CAs.
func v2Plaintext(t *testing.T, h *Hierarchy, extra map[string]any) []byte {
	t.Helper()
	m := map[string]any{
		"schemaVersion":       2,
		"clusterCACertPEM":    h.Cluster.CertPEM,
		"clusterCAKeyPEM":     h.Cluster.KeyPEM,
		"signingCACertPEM":    h.Signing.CertPEM,
		"signingCAKeyPEM":     h.Signing.KeyPEM,
		"etcdServerCACertPEM": h.EtcdServer.CertPEM,
		"etcdServerCAKeyPEM":  h.EtcdServer.KeyPEM,
		"etcdPeerCACertPEM":   h.EtcdPeer.CertPEM,
		"etcdPeerCAKeyPEM":    h.EtcdPeer.KeyPEM,
	}
	for k, v := range extra {
		m[k] = v
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestBundleV2DecodesV3CarriesRequestHeaderCA pins the schema-3 codec: a v2 plaintext
// decodes to the four B410 CAs and reports the request-header CA missing; v3
// round-trips all five; v1, unknown keys and v4 are refused; Marshal refuses a
// hierarchy missing any of the five, or nil.
func TestBundleV2DecodesV3CarriesRequestHeaderCA(t *testing.T) {
	src := fiveCAHierarchy(t)
	pins := func(h *Hierarchy) map[CAID]string {
		out := map[CAID]string{}
		for _, spec := range caSpecs {
			if ca := spec.ca(h); ca != nil {
				out[spec.id] = ca.PinHash()
			}
		}
		return out
	}

	t.Run("v3 round trip: five CAs, identical pins, working keys", func(t *testing.T) {
		data, err := src.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var env struct {
			SchemaVersion int `json:"schemaVersion"`
		}
		if err := json.Unmarshal(data, &env); err != nil || env.SchemaVersion != 3 {
			t.Fatalf("schemaVersion = %d (err %v), want 3", env.SchemaVersion, err)
		}
		var dst Hierarchy
		if err := dst.Unmarshal(data); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got, want := pins(&dst), pins(src); !reflect.DeepEqual(got, want) || len(got) != 5 {
			t.Errorf("pins after the round trip = %v, want the five of %v", got, want)
		}
		if missing := dst.Missing(PostureEtcd); len(missing) != 0 {
			t.Errorf("Missing(etcd) = %v after a v3 round trip", missing)
		}
		leaf, _, err := dst.IssueProxyClient(time.Hour)
		if err != nil {
			t.Fatalf("IssueProxyClient from the decoded hierarchy: %v", err)
		}
		if err := parseFirstCert(t, leaf).CheckSignatureFrom(src.requestHeader.Cert); err != nil {
			t.Errorf("the decoded request-header key does not sign for the source CA: %v", err)
		}
	})

	t.Run("v2 decodes: four CAs, request-header missing", func(t *testing.T) {
		var dst Hierarchy
		if err := dst.Unmarshal(v2Plaintext(t, src, nil)); err != nil {
			t.Fatalf("a v2 bundle must decode: %v", err)
		}
		want := pins(src)
		delete(want, CARequestHeader)
		if got := pins(&dst); !reflect.DeepEqual(got, want) {
			t.Errorf("v2 pins = %v, want %v", got, want)
		}
		if got := dst.Missing(PostureEtcd); !slices.Equal(got, []CAID{CARequestHeader}) {
			t.Errorf("Missing(etcd) = %v, want [request-header]", got)
		}
	})

	refused := []struct {
		name string
		data []byte
		want string
	}{
		{"v1 keeps the predates-etcd refusal", mustJSON(t, map[string]any{"schemaVersion": 1, "clusterCACertPEM": src.Cluster.CertPEM}), "predates etcd HA"},
		{"v4 is unknown", v2Plaintext(t, src, map[string]any{"schemaVersion": 4}), "unsupported schema version 4"},
		{"unknown key in v3", func() []byte {
			data, err := src.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			must(json.Unmarshal(data, &m))
			m["bogusCACertPEM"] = src.Cluster.CertPEM
			return mustJSON(t, m)
		}(), "bogusCACertPEM"},
		{"request-header keys in a v2 envelope", v2Plaintext(t, src, map[string]any{
			"requestHeaderCACertPEM": src.requestHeader.CertPEM, "requestHeaderCAKeyPEM": src.requestHeader.KeyPEM}), "requestHeaderCACertPEM"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			var dst Hierarchy
			err := dst.Unmarshal(tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Unmarshal err = %v, want a refusal containing %q", err, tc.want)
			}
			if len(pins(&dst)) != 0 {
				t.Error("a refused Unmarshal populated the receiver")
			}
		})
	}

	t.Run("Marshal refuses an incomplete or nil hierarchy", func(t *testing.T) {
		if _, err := (*Hierarchy)(nil).Marshal(); err == nil {
			t.Error("Marshal(nil) must fail")
		}
		for _, id := range []CAID{CACluster, CASigning, CAEtcdServer, CAEtcdPeer, CARequestHeader} {
			h := dropCA(src, id)
			if _, err := h.Marshal(); err == nil || !strings.Contains(err.Error(), string(id)) {
				t.Errorf("Marshal without the %s CA: err = %v, want a refusal naming it", id, err)
			}
		}
	})
}

// dropCA returns a copy of h without the CA id.
func dropCA(h *Hierarchy, id CAID) *Hierarchy {
	c := *h
	switch id {
	case CACluster:
		c.Cluster = nil
	case CASigning:
		c.Signing = nil
	case CAEtcdServer:
		c.EtcdServer = nil
	case CAEtcdPeer:
		c.EtcdPeer = nil
	case CARequestHeader:
		c.requestHeader = nil
	}
	return &c
}

// mustJSON marshals v.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestBundleSchemaVersionSingleSourced pins the schema number and the set of CAs it
// carries together: a sixth CA cannot ride schema 3, and the number cannot move
// without this list.
func TestBundleSchemaVersionSingleSourced(t *testing.T) {
	if bundleSchemaVersion != 3 {
		t.Errorf("bundleSchemaVersion = %d, want 3", bundleSchemaVersion)
	}
	var ids []CAID
	for _, spec := range caSpecs {
		ids = append(ids, spec.id)
	}
	want := []CAID{CACluster, CASigning, CAEtcdServer, CAEtcdPeer, CARequestHeader}
	if !slices.Equal(ids, want) {
		t.Errorf("the CA table carries %v, want %v at schema %d", ids, want, bundleSchemaVersion)
	}
	data, err := fiveCAHierarchy(t).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 1+2*len(want) {
		t.Errorf("the bundle carries %d keys, want schemaVersion plus a cert and a key for each of %d CAs", len(m), len(want))
	}
}

// TestLoadCARejectsMismatchedKey pins that LoadCA refuses a key that is not the
// certificate's.
func TestLoadCARejectsMismatchedKey(t *testing.T) {
	a, b := mkCA(t, "a"), mkCA(t, "b")
	if _, err := LoadCA(a.CertPEM, a.KeyPEM); err != nil {
		t.Fatalf("a matching pair must load: %v", err)
	}
	if _, err := LoadCA(a.CertPEM, b.KeyPEM); err == nil {
		t.Error("LoadCA accepted a key that does not match the certificate")
	}
}

// TestLoadRequestHeaderPinIsReadOnly pins the read-only pin read: the pin without
// opening the key, ErrNoHierarchy when absent, ErrIncompleteHierarchy for a cert
// without its key, and nothing created.
func TestLoadRequestHeaderPinIsReadOnly(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		wd := t.TempDir()
		if _, err := LoadRequestHeaderPin(wd); !errors.Is(err, ErrNoHierarchy) {
			t.Errorf("err = %v, want ErrNoHierarchy", err)
		}
		if _, err := os.Lstat(PKIDir(wd)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("LoadRequestHeaderPin created the PKI dir (stat err %v)", err)
		}
	})
	t.Run("present, key unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file mode bits")
		}
		wd := t.TempDir()
		h, err := EnsureHierarchy(wd, RoleMintAuthority, PostureKine)
		if err != nil {
			t.Fatal(err)
		}
		if h.requestHeader == nil {
			t.Fatal("no request-header CA minted")
		}
		if err := os.Chmod(RequestHeaderCAKeyPath(wd), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(RequestHeaderCAKeyPath(wd), 0o600) })
		names := func() []string {
			entries, err := os.ReadDir(PKIDir(wd))
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, e := range entries {
				out = append(out, e.Name())
			}
			return out
		}
		before := names()
		pin, err := LoadRequestHeaderPin(wd)
		if err != nil {
			t.Fatalf("LoadRequestHeaderPin: %v", err)
		}
		if pin != h.requestHeader.PinHash() {
			t.Errorf("pin = %s, want %s", pin, h.requestHeader.PinHash())
		}
		if after := names(); !slices.Equal(before, after) {
			t.Errorf("LoadRequestHeaderPin changed the PKI dir: %v -> %v", before, after)
		}
	})
	t.Run("cert without key", func(t *testing.T) {
		wd := t.TempDir()
		if _, err := EnsureHierarchy(wd, RoleMintAuthority, PostureKine); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(RequestHeaderCAKeyPath(wd)); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRequestHeaderPin(wd); !errors.Is(err, ErrIncompleteHierarchy) {
			t.Errorf("err = %v, want ErrIncompleteHierarchy", err)
		}
	})
}

// TestReconcileInstallIsKeyThenCertAtomic crashes an install between a CA's key and
// its certificate: the key survives without the cert (never the reverse), and the
// next EnsureHierarchy, in either role, reports ErrIncompleteHierarchy naming that
// key instead of minting.
func TestReconcileInstallIsKeyThenCertAtomic(t *testing.T) {
	h := fiveCAHierarchy(t)
	wd := t.TempDir()
	orig := installCAFile
	t.Cleanup(func() { installCAFile = orig })
	installCAFile = func(dir, name string, data []byte, mode os.FileMode) error {
		if name == clusterCACert {
			return errors.New("simulated crash between the key and the certificate")
		}
		return orig(dir, name, data, mode)
	}
	if err := ReconcileImportedHierarchy(wd, h, PostureEtcd); err == nil {
		t.Fatal("the crashed install must fail")
	}
	installCAFile = orig
	cert, key := ClusterCACertPath(wd), ClusterCAKeyPath(wd)
	if _, err := os.Lstat(key); err != nil {
		t.Fatalf("the key was not installed first: %v", err)
	}
	if _, err := os.Lstat(cert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the certificate exists after the crash (stat err %v)", err)
	}
	for _, role := range []Role{RoleMintAuthority, RoleJoined} {
		_, err := EnsureHierarchy(wd, role, PostureEtcd)
		if !errors.Is(err, ErrIncompleteHierarchy) || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: EnsureHierarchy err = %v, want ErrIncompleteHierarchy naming %s", role, err, key)
		}
		if _, err := os.Lstat(cert); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: EnsureHierarchy minted a cluster CA over the orphaned key", role)
		}
	}
}

// TestNewCertErrorsCarryNoKeyMaterial formats every new pkg/certs error and asserts it
// carries ids, pins and paths, never a PEM block or any test key's DER. The wait
// loop's log lines live in cmd/k3sm and are checked there
// (TestServerJoinWaitsOnOlderBundleSource).
func TestNewCertErrorsCarryNoKeyMaterial(t *testing.T) {
	hA, hB := fiveCAHierarchy(t), fiveCAHierarchy(t)
	var keys [][]byte
	for _, h := range []*Hierarchy{hA, hB} {
		for _, spec := range caSpecs {
			if ca := spec.ca(h); ca != nil {
				keys = append(keys, ca.KeyPEM)
			}
		}
	}
	notImported := func() error {
		_, err := EnsureHierarchy(t.TempDir(), RoleJoined, PostureEtcd)
		return err
	}()
	diverged := func() error {
		return ReconcileImportedHierarchy(writeFull(t, hA), hB, PostureEtcd)
	}()
	incomplete := func() error {
		wd := writeFull(t, hA)
		must(os.Remove(ClusterCACertPath(wd)))
		_, err := EnsureHierarchy(wd, RoleMintAuthority, PostureEtcd)
		return err
	}()
	for _, tc := range []struct {
		name string
		err  error
		is   error
	}{
		{"ErrCANotImported", notImported, ErrCANotImported},
		{"ErrHierarchyDiverged", diverged, ErrHierarchyDiverged},
		{"ErrIncompleteHierarchy (half pair)", incomplete, ErrIncompleteHierarchy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.is) {
				t.Fatalf("err = %v, want %v", tc.err, tc.is)
			}
			msg := tc.err.Error()
			if strings.Contains(msg, "-----BEGIN") {
				t.Errorf("error carries a PEM block: %q", msg)
			}
			for _, k := range keys {
				block, _ := pem.Decode(k)
				for _, enc := range []string{base64.StdEncoding.EncodeToString(block.Bytes), base64.StdEncoding.EncodeToString(k)} {
					if strings.Contains(msg, enc[:24]) {
						t.Errorf("error carries key material: %q", msg)
					}
				}
			}
		})
	}
}
