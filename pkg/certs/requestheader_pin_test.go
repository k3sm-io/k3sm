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

package certs_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// TestRequestHeaderCAPreservesClusterPin upgrades a work dir written in the
// four-CA layout of the release before the request-header CA (cluster and signing
// in tls/, the etcd pair in tls/etcd 0700; written raw, not through this package's
// writers) and proves the upgrade only ADDS the request-header pair: every existing
// CA file is byte-identical, the cluster CA's PinHash is unchanged, and a K10 join
// token built before and after is identical.
func TestRequestHeaderCAPreservesClusterPin(t *testing.T) {
	wd := t.TempDir()
	ep := certs.EtcdCertPaths(wd)
	if err := os.MkdirAll(certs.PKIDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ep.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	layout := []struct {
		cn, cert, key string
	}{
		{"k3sm-cluster-ca", certs.ClusterCACertPath(wd), certs.ClusterCAKeyPath(wd)},
		{"k3sm-signing-ca", certs.SigningCACertPath(wd), certs.SigningCAKeyPath(wd)},
		{"k3sm-etcd-server-ca", ep.ServerCACert, ep.ServerCAKey},
		{"k3sm-etcd-peer-ca", ep.PeerCACert, ep.PeerCAKey},
	}
	var clusterPin string
	for i, l := range layout {
		ca, err := certs.NewCA(l.cn)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			clusterPin = ca.PinHash()
		}
		if err := os.WriteFile(l.cert, ca.CertPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(l.key, ca.KeyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := tree(t, wd)
	pinBefore, _, err := certs.LoadCAPins(wd)
	if err != nil {
		t.Fatal(err)
	}
	tokenBefore := bootstrap.FormatToken(pinBefore, "k10user", "k10secret")

	h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureEtcd)
	if err != nil {
		t.Fatalf("EnsureHierarchy over the old layout: %v", err)
	}
	after := tree(t, wd)
	for p, b := range before {
		if !bytes.Equal(after[p], b) {
			t.Errorf("%s changed across the upgrade", p)
		}
	}
	var added []string
	for p := range after {
		if _, ok := before[p]; !ok {
			added = append(added, p)
		}
	}
	slices.Sort(added)
	want := []string{certs.RequestHeaderCACertPath(wd), certs.RequestHeaderCAKeyPath(wd)}
	slices.Sort(want)
	if !slices.Equal(added, want) {
		t.Errorf("the upgrade added %v, want only the request-header pair %v", added, want)
	}
	if h.Cluster.PinHash() != clusterPin {
		t.Errorf("cluster PinHash %s, want the unchanged %s", h.Cluster.PinHash(), clusterPin)
	}
	pinAfter, _, err := certs.LoadCAPins(wd)
	if err != nil {
		t.Fatal(err)
	}
	if tokenAfter := bootstrap.FormatToken(pinAfter, "k10user", "k10secret"); tokenAfter != tokenBefore {
		t.Errorf("the K10 token moved across the upgrade: %s -> %s", tokenBefore, tokenAfter)
	}
}

// tree reads every regular file under wd's PKI dir.
func tree(t *testing.T, wd string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(certs.PKIDir(wd), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[p] = b
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
