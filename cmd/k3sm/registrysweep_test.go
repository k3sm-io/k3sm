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
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestRegistryBootstrapSweepsRetiredNodeServices pins the orphan bound: the
// bootstrap server removes every k3sm-created registry-<node> Service and
// EndpointSlice, including a departed node's, and leaves the flat Service and
// an unlabelled foreign Service alone. A joined server sweeps only its own.
func TestRegistryBootstrapSweepsRetiredNodeServices(t *testing.T) {
	ns := registrysvc.FlatServiceNamespace
	managed := map[string]string{"k3sm.io/managed": "true", "k3sm.io/registry-node": "node-a"}
	build := func() *fake.Clientset {
		return fake.NewSimpleClientset(
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "registry-node-a", Namespace: ns, Labels: managed}},
			&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "registry-node-a", Namespace: ns, Labels: managed}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: registrysvc.FlatServiceName, Namespace: ns, Labels: managed}},
			&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: registrysvc.FlatServiceName, Namespace: ns, Labels: managed}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "registry-foreign", Namespace: ns}},
		)
	}
	run := func(cs *fake.Clientset, joined bool) {
		ingestRegistry{
			nodeName: "boot", joined: joined,
			clusterSvcs:   cs.CoreV1().Services(ns),
			clusterSlices: cs.DiscoveryV1().EndpointSlices(ns),
			logger:        slog.New(slog.DiscardHandler),
		}.retireNodeService(context.Background())
	}
	has := func(cs *fake.Clientset, name string) (svc, slice bool) {
		_, e1 := cs.CoreV1().Services(ns).Get(context.Background(), name, metav1.GetOptions{})
		_, e2 := cs.DiscoveryV1().EndpointSlices(ns).Get(context.Background(), name, metav1.GetOptions{})
		return e1 == nil, e2 == nil
	}

	cs := build()
	run(cs, false)
	if s, e := has(cs, "registry-node-a"); s || e {
		t.Errorf("stale registry-node-a survived the sweep: service=%v slice=%v", s, e)
	}
	if s, e := has(cs, registrysvc.FlatServiceName); !s || !e {
		t.Errorf("the flat registry-k3sm objects were swept: service=%v slice=%v", s, e)
	}
	if s, _ := has(cs, "registry-foreign"); !s {
		t.Error("an unlabelled foreign Service was swept")
	}

	cs = build()
	run(cs, true)
	if s, e := has(cs, "registry-node-a"); !s || !e {
		t.Errorf("a joined server swept another node's objects: service=%v slice=%v", s, e)
	}
}

// TestRegistryServingMinterLeavesTheCAAlone pins that minting the registry
// leaf only reads the on-disk hierarchy: every file under the PKI directory
// keeps its bytes and mtime, in both roles.
func TestRegistryServingMinterLeavesTheCAAlone(t *testing.T) {
	for _, join := range []bool{false, true} {
		dir := t.TempDir()
		opts := serverOptions{workDir: dir, serverJoin: join}
		if _, err := certs.EnsureHierarchy(dir, certs.RoleMintAuthority, opts.posture()); err != nil {
			t.Fatalf("seed hierarchy: %v", err)
		}
		type snap struct {
			data  []byte
			mtime time.Time
		}
		take := func() map[string]snap {
			out := map[string]snap{}
			err := filepath.Walk(certs.PKIDir(dir), func(p string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return err
				}
				b, err := os.ReadFile(p)
				out[p] = snap{b, fi.ModTime()}
				return err
			})
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			return out
		}
		before := take()
		if len(before) == 0 {
			t.Fatal("the seeded hierarchy wrote no files")
		}
		time.Sleep(20 * time.Millisecond)
		mint := serverRegistryServingMinter(opts, slog.New(slog.DiscardHandler))
		if mint == nil {
			t.Fatalf("join=%v: no minter for an existing hierarchy", join)
		}
		if _, err := mint([]string{"registry-k3sm"}, []net.IP{net.ParseIP("10.43.0.9")}); err != nil {
			t.Fatalf("join=%v: mint: %v", join, err)
		}
		after := take()
		if len(after) != len(before) {
			t.Errorf("join=%v: file count %d -> %d", join, len(before), len(after))
		}
		for p, b := range before {
			a, ok := after[p]
			if !ok || string(a.data) != string(b.data) || !a.mtime.Equal(b.mtime) {
				t.Errorf("join=%v: %s was rewritten or removed", join, p)
			}
		}
	}
}
