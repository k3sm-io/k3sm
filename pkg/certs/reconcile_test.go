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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// allCAIDs is every id of the table, in table order.
var allCAIDs = []CAID{CACluster, CASigning, CAEtcdServer, CAEtcdPeer}

// specByID returns the table row for id.
func specByID(t *testing.T, id CAID) caSpec {
	t.Helper()
	for _, spec := range caSpecs {
		if spec.id == id {
			return spec
		}
	}
	t.Fatalf("no CA %q in the table", id)
	return caSpec{}
}

// caPaths returns the cert and key paths of CA id under wd.
func caPaths(t *testing.T, wd string, id CAID) (cert, key string) {
	t.Helper()
	spec := specByID(t, id)
	dir := spec.dir(wd)
	return filepath.Join(dir, spec.certFile), filepath.Join(dir, spec.keyFile)
}

// removeCA deletes both files of CA id under wd.
func removeCA(t *testing.T, wd string, id CAID) {
	t.Helper()
	cert, key := caPaths(t, wd, id)
	for _, p := range []string{cert, key} {
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove %s: %v", p, err)
		}
	}
}

// pkiFile is one entry of a PKI snapshot.
type pkiFile struct {
	data []byte
	mode fs.FileMode
	info fs.FileInfo
}

// snapshotPKI captures every entry under wd's PKI dir (an absent dir is empty).
func snapshotPKI(t *testing.T, wd string) map[string]pkiFile {
	t.Helper()
	out := map[string]pkiFile{}
	root := PKIDir(wd)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == root {
				return filepath.SkipDir
			}
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		f := pkiFile{mode: info.Mode(), info: info}
		if info.Mode().IsRegular() {
			if f.data, err = os.ReadFile(p); err != nil {
				return err
			}
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = f
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot PKI: %v", err)
	}
	return out
}

// assertUnchanged fails unless after holds exactly before's entries, each the same
// inode with the same bytes and mode.
func assertUnchanged(t *testing.T, before, after map[string]pkiFile) {
	t.Helper()
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			t.Errorf("%s disappeared", name)
			continue
		}
		if !bytes.Equal(a.data, b.data) || a.mode != b.mode || !os.SameFile(a.info, b.info) {
			t.Errorf("%s was modified or replaced", name)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("%s was written", name)
		}
	}
}

// writeFull installs h into a fresh work dir and returns it.
func writeFull(t *testing.T, h *Hierarchy) string {
	t.Helper()
	wd := t.TempDir()
	if err := ReconcileImportedHierarchy(wd, h, PostureEtcd); err != nil {
		t.Fatalf("install hierarchy: %v", err)
	}
	return wd
}

// TestMissingOnDisk pins the B435 probe the server-join consults before any fetch:
// fully absent CAs are reported by id in table order, fully present ones are not, and
// a half-present pair is an error that names the surviving file.
func TestMissingOnDisk(t *testing.T) {
	h := newTestHierarchy(t)
	cases := []struct {
		name    string
		setup   func(t *testing.T) string
		want    []CAID
		wantErr []string // substrings of the error; nil means no error
	}{
		{name: "empty work dir: all four", setup: func(t *testing.T) string { return t.TempDir() }, want: allCAIDs},
		{name: "complete hierarchy: none", setup: func(t *testing.T) string { return writeFull(t, h) }, want: nil},
		{name: "subset: the removed CAs only", setup: func(t *testing.T) string {
			wd := writeFull(t, h)
			removeCA(t, wd, "signing")
			removeCA(t, wd, "etcd-peer")
			return wd
		}, want: []CAID{CASigning, CAEtcdPeer}},
		{name: "etcd dir gone: both etcd CAs", setup: func(t *testing.T) string {
			wd := writeFull(t, h)
			if err := os.RemoveAll(EtcdCertPaths(wd).Dir); err != nil {
				t.Fatal(err)
			}
			return wd
		}, want: []CAID{CAEtcdServer, CAEtcdPeer}},
		{name: "key without cert: error names the key", setup: func(t *testing.T) string {
			wd := writeFull(t, h)
			cert, _ := caPaths(t, wd, "etcd-server")
			if err := os.Remove(cert); err != nil {
				t.Fatal(err)
			}
			return wd
		}, wantErr: []string{"etcd-server CA is half-present", etcdServerCAKey + " exists", "remove"}},
		{name: "cert without key: error names the cert", setup: func(t *testing.T) string {
			wd := writeFull(t, h)
			_, key := caPaths(t, wd, "cluster")
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			return wd
		}, wantErr: []string{"cluster CA is half-present", clusterCACert + " exists", "remove"}},
		{name: "symlinked cert: damaged hierarchy", setup: func(t *testing.T) string {
			wd := writeFull(t, h)
			cert, _ := caPaths(t, wd, "signing")
			if err := os.Remove(cert); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/hosts", cert); err != nil {
				t.Fatal(err)
			}
			return wd
		}, wantErr: []string{"not a regular file"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wd := tc.setup(t)
			got, err := MissingOnDisk(wd, PostureEtcd)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("MissingOnDisk = %v, want an error", got)
				}
				for _, s := range tc.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q must contain %q", err, s)
					}
				}
				if !errors.Is(err, ErrIncompleteHierarchy) {
					t.Errorf("error %v must wrap ErrIncompleteHierarchy", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("MissingOnDisk: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("MissingOnDisk = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReconcileImportedHierarchy pins the B435 import: only absent CAs are installed
// (key 0600, cert 0644, the etcd dir 0700), a present CA with the bundle's pin is left
// untouched, and a present CA with any other pin is ErrHierarchyDiverged with nothing
// written, even when another CA is missing.
func TestReconcileImportedHierarchy(t *testing.T) {
	hA := newTestHierarchy(t)
	hB := newTestHierarchy(t)

	t.Run("fresh dir: all four installed with their modes", func(t *testing.T) {
		wd := t.TempDir()
		if err := ReconcileImportedHierarchy(wd, hA, PostureEtcd); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		assertInstalled(t, wd, hA, allCAIDs)
		if info, err := os.Stat(EtcdCertPaths(wd).Dir); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("etcd PKI dir: err %v, want mode 0700", err)
		}
		assertLoads(t, wd, hA)
	})

	t.Run("missing only: absent CAs installed, present ones untouched", func(t *testing.T) {
		wd := writeFull(t, hA)
		if err := os.RemoveAll(EtcdCertPaths(wd).Dir); err != nil {
			t.Fatal(err)
		}
		removeCA(t, wd, "signing")
		before := snapshotPKI(t, wd)
		if err := ReconcileImportedHierarchy(wd, hA, PostureEtcd); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		after := snapshotPKI(t, wd)
		cert, key := caPaths(t, wd, "cluster")
		for _, p := range []string{cert, key} {
			rel, _ := filepath.Rel(PKIDir(wd), p)
			if !bytes.Equal(before[rel].data, after[rel].data) || !os.SameFile(before[rel].info, after[rel].info) {
				t.Errorf("present %s was modified or replaced", rel)
			}
		}
		assertInstalled(t, wd, hA, []CAID{CASigning, CAEtcdServer, CAEtcdPeer})
		if info, err := os.Stat(EtcdCertPaths(wd).Dir); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("etcd PKI dir: err %v, want mode 0700", err)
		}
		assertLoads(t, wd, hA)
	})

	t.Run("complete and same-pin: a no-op, byte-identical", func(t *testing.T) {
		wd := writeFull(t, hA)
		before := snapshotPKI(t, wd)
		if err := ReconcileImportedHierarchy(wd, hA, PostureEtcd); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		assertUnchanged(t, before, snapshotPKI(t, wd))
	})

	diverged := func(t *testing.T, wd string, h *Hierarchy, wantPins ...string) {
		t.Helper()
		before := snapshotPKI(t, wd)
		err := ReconcileImportedHierarchy(wd, h, PostureEtcd)
		if !errors.Is(err, ErrHierarchyDiverged) {
			t.Fatalf("reconcile err = %v, want ErrHierarchyDiverged", err)
		}
		for _, pin := range wantPins {
			if !strings.Contains(err.Error(), pin) {
				t.Errorf("error %q must name pin %s", err, pin)
			}
		}
		assertUnchanged(t, before, snapshotPKI(t, wd))
	}

	t.Run("divergent: every CA differs, nothing written", func(t *testing.T) {
		wd := writeFull(t, hA)
		diverged(t, wd, hB, hA.Cluster.PinHash(), hB.Cluster.PinHash())
	})

	t.Run("divergent later CA, earlier CA missing: nothing written", func(t *testing.T) {
		wd := writeFull(t, hA)
		removeCA(t, wd, "cluster")
		mixed := &Hierarchy{Cluster: hA.Cluster, Signing: hA.Signing, EtcdServer: hA.EtcdServer, EtcdPeer: hB.EtcdPeer}
		diverged(t, wd, mixed, hA.EtcdPeer.PinHash(), hB.EtcdPeer.PinHash())
		if got, err := MissingOnDisk(wd, PostureEtcd); err != nil || !slices.Equal(got, []CAID{CACluster}) {
			t.Errorf("after a refused reconcile MissingOnDisk = %v, %v; want [cluster]", got, err)
		}
	})

	t.Run("half-present CA: refused, nothing written", func(t *testing.T) {
		wd := writeFull(t, hA)
		_, key := caPaths(t, wd, "signing")
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		before := snapshotPKI(t, wd)
		if err := ReconcileImportedHierarchy(wd, hA, PostureEtcd); !errors.Is(err, ErrIncompleteHierarchy) || !strings.Contains(err.Error(), "half-present") {
			t.Fatalf("reconcile err = %v, want the half-present ErrIncompleteHierarchy", err)
		}
		assertUnchanged(t, before, snapshotPKI(t, wd))
	})

	t.Run("orphan temps reaped, complete CAs untouched", func(t *testing.T) {
		wd := writeFull(t, hA)
		before := snapshotPKI(t, wd)
		_, key := caPaths(t, wd, "cluster")
		peerCert, _ := caPaths(t, wd, "etcd-peer")
		orphans := []string{
			filepath.Join(filepath.Dir(key), "."+filepath.Base(key)+".tmp-12345"),
			filepath.Join(filepath.Dir(peerCert), "."+filepath.Base(peerCert)+".tmp-678"),
		}
		for _, o := range orphans {
			if err := os.WriteFile(o, []byte("orphan temp bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := ReconcileImportedHierarchy(wd, hA, PostureEtcd); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		for _, o := range orphans {
			if _, err := os.Lstat(o); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("orphan temp %s survived (stat err %v)", o, err)
			}
		}
		assertUnchanged(t, before, snapshotPKI(t, wd))
	})

	refusedBeforeWrite := func(t *testing.T, h *Hierarchy) {
		t.Helper()
		wd := t.TempDir()
		if err := ReconcileImportedHierarchy(wd, h, PostureEtcd); err == nil {
			t.Fatal("reconcile accepted an invalid bundle CA")
		}
		if got := snapshotPKI(t, wd); len(got) != 0 {
			t.Errorf("a refused reconcile wrote %d PKI entries", len(got))
		}
	}

	t.Run("bundle CA key does not match its cert: refused before any write", func(t *testing.T) {
		bad := *hA
		bad.Signing = &CA{Cert: hA.Signing.Cert, Key: hB.Signing.Key, CertPEM: hA.Signing.CertPEM, KeyPEM: hB.Signing.KeyPEM}
		refusedBeforeWrite(t, &bad)
	})

	t.Run("bundle CA that is not a CA: refused before any write", func(t *testing.T) {
		leafPEM, leafKey, err := hA.Cluster.IssueClient("not-a-ca", nil, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := LoadCA(leafPEM, leafKey)
		if err != nil {
			t.Fatalf("load the leaf as a CA struct: %v", err)
		}
		bad := *hA
		bad.EtcdPeer = leaf
		refusedBeforeWrite(t, &bad)
	})

	t.Run("bundle without the request-header CA: refused before any write", func(t *testing.T) {
		bad := *hA
		bad.requestHeader = nil
		refusedBeforeWrite(t, &bad)
	})

	t.Run("incomplete bundle: refused before any disk access", func(t *testing.T) {
		wd := t.TempDir()
		if err := ReconcileImportedHierarchy(wd, &Hierarchy{Cluster: hA.Cluster, Signing: hA.Signing}, PostureEtcd); err == nil {
			t.Fatal("reconcile must require all four CAs")
		}
		if err := ReconcileImportedHierarchy(wd, nil, PostureEtcd); err == nil {
			t.Fatal("reconcile must refuse a nil hierarchy")
		}
		if got := snapshotPKI(t, wd); len(got) != 0 {
			t.Errorf("a refused reconcile wrote %d PKI entries", len(got))
		}
	})
}

// assertInstalled checks that each CA in ids is on disk with h's bytes, the key 0600
// and the cert 0644, and that no temp file was left beside it.
func assertInstalled(t *testing.T, wd string, h *Hierarchy, ids []CAID) {
	t.Helper()
	for _, id := range ids {
		spec := specByID(t, id)
		cert, key := caPaths(t, wd, id)
		for _, f := range []struct {
			path string
			data []byte
			mode fs.FileMode
		}{{cert, spec.ca(h).CertPEM, 0o644}, {key, spec.ca(h).KeyPEM, 0o600}} {
			info, err := os.Lstat(f.path)
			if err != nil {
				t.Fatalf("%s CA: %v", id, err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != f.mode {
				t.Errorf("%s mode = %v, want regular %o", f.path, info.Mode(), f.mode)
			}
			got, err := os.ReadFile(f.path)
			if err != nil || !bytes.Equal(got, f.data) {
				t.Errorf("%s does not hold the bundle's bytes (err %v)", f.path, err)
			}
		}
		entries, err := os.ReadDir(spec.dir(wd))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), ".tmp-") {
				t.Errorf("temp file %s left in %s", e.Name(), spec.dir(wd))
			}
		}
	}
}

// assertLoads checks that EnsureHierarchy and EnsureEtcdCAs load h's CAs from wd
// rather than minting.
func assertLoads(t *testing.T, wd string, h *Hierarchy) {
	t.Helper()
	got, err := EnsureHierarchy(wd, RoleMintAuthority, PostureKine)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	if got.Cluster.PinHash() != h.Cluster.PinHash() || got.Signing.PinHash() != h.Signing.PinHash() {
		t.Error("EnsureHierarchy did not load the reconciled CAs")
	}
	server, peer, err := EnsureEtcdCAs(wd)
	if err != nil {
		t.Fatalf("EnsureEtcdCAs: %v", err)
	}
	if server.PinHash() != h.EtcdServer.PinHash() || peer.PinHash() != h.EtcdPeer.PinHash() {
		t.Error("EnsureEtcdCAs did not load the reconciled etcd CAs")
	}
}
