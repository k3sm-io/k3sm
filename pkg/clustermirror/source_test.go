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

package clustermirror

import (
	"errors"
	"log/slog"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/runtimed/pkg/image"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestMirrors is the whole selection rule in one table: which advertisements
// become candidates, in what order, and — the rows that matter most — which are
// silently dropped.
//
// Dropping this node's OWN advertisement is the load-bearing one. A pull only
// reaches the fallback after this node's registry already missed, so returning
// this node would ask the same registry the same question and turn every miss
// into a second round trip.
func TestMirrors(t *testing.T) {
	adv := func(node, host string, plain string) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      registrysvc.AdvertisementName(node),
				Namespace: registrysvc.AdvertisementNamespace,
			},
			Data: map[string]string{
				registrysvc.AdvertisementNodeKey:      node,
				registrysvc.AdvertisementMeshHostKey:  host,
				registrysvc.AdvertisementPlainHTTPKey: plain,
			},
		}
	}
	other := func(name string) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: registrysvc.AdvertisementNamespace},
			Data:       map[string]string{"host": "localhost:6450"},
		}
	}

	tests := []struct {
		name string
		node string
		objs []*corev1.ConfigMap
		want []image.Mirror
	}{
		{
			name: "a peer is a candidate",
			node: "mac-a",
			objs: []*corev1.ConfigMap{adv("mac-b", "100.64.2.1:6450", "true")},
			want: []image.Mirror{{Host: "100.64.2.1:6450", PlainHTTP: true}},
		},
		{
			name: "this node's own advertisement is never a candidate",
			node: "mac-a",
			objs: []*corev1.ConfigMap{adv("mac-a", "100.64.1.1:6450", "true")},
			want: nil,
		},
		{
			name: "self is dropped from a set of peers",
			node: "mac-b",
			objs: []*corev1.ConfigMap{
				adv("mac-a", "100.64.1.1:6450", "true"),
				adv("mac-b", "100.64.2.1:6450", "true"),
				adv("mac-c", "100.64.3.1:6450", "true"),
			},
			want: []image.Mirror{
				{Host: "100.64.1.1:6450", PlainHTTP: true},
				{Host: "100.64.3.1:6450", PlainHTTP: true},
			},
		},
		{
			name: "the order is by peer node name, not by list order",
			node: "mac-a",
			objs: []*corev1.ConfigMap{
				adv("mac-z", "100.64.9.1:6450", "true"),
				adv("mac-c", "100.64.3.1:6450", "true"),
				adv("mac-b", "100.64.2.1:6450", "true"),
			},
			want: []image.Mirror{
				{Host: "100.64.2.1:6450", PlainHTTP: true},
				{Host: "100.64.3.1:6450", PlainHTTP: true},
				{Host: "100.64.9.1:6450", PlainHTTP: true},
			},
		},
		{
			name: "a malformed peer is skipped, the rest still answer",
			node: "mac-a",
			objs: []*corev1.ConfigMap{
				adv("mac-b", "100.64.2.1:6450/evil", "true"), // a spliced repository path
				adv("mac-c", "not-an-address", "true"),
				adv("mac-d", "100.64.4.1:6450", "not-a-bool"),
				adv("mac-e", "100.64.5.1:6450", "true"),
			},
			want: []image.Mirror{{Host: "100.64.5.1:6450", PlainHTTP: true}},
		},
		{
			name: "objects outside the advertisement set are ignored",
			node: "mac-a",
			objs: []*corev1.ConfigMap{other("local-registry-hosting"), other("kube-root-ca.crt")},
			want: nil,
		},
		{
			name: "a cluster of one has no candidates",
			node: "mac-a",
			want: nil,
		},
		{
			name: "the advertiser's transport decision is carried through",
			node: "mac-a",
			objs: []*corev1.ConfigMap{adv("mac-b", "100.64.2.1:6450", "false")},
			want: []image.Mirror{{Host: "100.64.2.1:6450", PlainHTTP: false}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Config{NodeName: tc.node, Logger: quietLogger()})
			s.lister = fakeLister{objs: tc.objs}
			s.synced = true

			got := s.Mirrors("localhost:6450/team/app:v1")
			if !slices.Equal(got, tc.want) {
				t.Errorf("Mirrors() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestMirrorsDegrades pins the never-block contract from the three directions it
// can be reached. Each one must produce an EMPTY candidate list rather than a
// stall or a failure: a pull that reaches this seam has already failed against
// its own registry, so the worst honest answer here is the one it would have got
// on a single-node cluster.
func TestMirrorsDegrades(t *testing.T) {
	t.Run("before Start there is no cache to read", func(t *testing.T) {
		s := New(Config{NodeName: "mac-a", Logger: quietLogger()})
		if got := s.Mirrors("localhost:6450/app:v1"); got != nil {
			t.Errorf("Mirrors() = %+v before Start, want none", got)
		}
	})

	t.Run("an unsynced cache reports no candidates", func(t *testing.T) {
		s := New(Config{NodeName: "mac-a", Logger: quietLogger()})
		// A lister is wired but the sync has not completed: an empty cache would
		// otherwise be indistinguishable from a cluster with no peers, and
		// answering from it would hide a real peer behind a race.
		s.lister = fakeLister{}
		if got := s.Mirrors("localhost:6450/app:v1"); got != nil {
			t.Errorf("Mirrors() = %+v on an unsynced cache, want none", got)
		}
	})

	t.Run("a lister error is reported, not propagated", func(t *testing.T) {
		s := New(Config{NodeName: "mac-a", Logger: quietLogger()})
		s.lister = fakeLister{err: errors.New("cache is gone")}
		s.synced = true
		if got := s.Mirrors("localhost:6450/app:v1"); got != nil {
			t.Errorf("Mirrors() = %+v on a failing lister, want none", got)
		}
	})

	t.Run("Start with no client is a no-op, not a panic", func(t *testing.T) {
		s := New(Config{NodeName: "mac-a", Logger: quietLogger()})
		s.Start(t.Context())
		if got := s.Mirrors("localhost:6450/app:v1"); got != nil {
			t.Errorf("Mirrors() = %+v with no client, want none", got)
		}
	})
}

// TestStartWatchesTheCluster is the wiring test: a real shared informer over a
// fake clientset, so the namespace, the prefix and the lister plumbing are
// exercised end to end rather than mocked past.
//
// It is the one test that fails if Start watches the wrong namespace — every
// other test in this file injects the lister and would stay green against a
// Source that watched nothing at all.
func TestStartWatchesTheCluster(t *testing.T) {
	cs := fake.NewClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      registrysvc.AdvertisementName("mac-b"),
				Namespace: registrysvc.AdvertisementNamespace,
			},
			Data: map[string]string{
				registrysvc.AdvertisementNodeKey:      "mac-b",
				registrysvc.AdvertisementMeshHostKey:  "100.64.2.1:6450",
				registrysvc.AdvertisementPlainHTTPKey: "true",
			},
		},
		// A DECOY in the namespace the advertisements used to share with the
		// KEP-1755 document. It is well-formed, so only the watch's namespace
		// scoping keeps it out — and that scoping is what makes the node
		// identity's read grant narrow enough to be a namespaced Role over
		// configmaps (pkg/rbac). A Source that read kube-public would both dial a
		// peer anyone able to write there could name, and prove the grant needed
		// to be wider than it is.
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      registrysvc.AdvertisementName("mac-decoy"),
				Namespace: registrysvc.HostingNamespace,
			},
			Data: map[string]string{
				registrysvc.AdvertisementNodeKey:      "mac-decoy",
				registrysvc.AdvertisementMeshHostKey:  "100.64.9.9:6450",
				registrysvc.AdvertisementPlainHTTPKey: "true",
			},
		},
	)
	s := New(Config{NodeName: "mac-a", Client: cs, Logger: quietLogger()})
	s.Start(t.Context())

	deadline := time.Now().Add(10 * time.Second)
	for {
		got := s.Mirrors("localhost:6450/team/app:v1")
		if len(got) == 1 && got[0].Host == "100.64.2.1:6450" && got[0].PlainHTTP {
			return
		}
		for _, m := range got {
			if m.Host == "100.64.9.9:6450" {
				t.Fatalf("Mirrors() returned the %s decoy %+v: the watch is not scoped to %s, so the node read grant is wider than the Role that authorizes it",
					registrysvc.HostingNamespace, m, registrysvc.AdvertisementNamespace)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Mirrors() = %+v after the informer should have synced, want exactly the peer's advertisement from %s", got, registrysvc.AdvertisementNamespace)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeLister is the one-method advertisementLister, backed by a slice.
type fakeLister struct {
	objs []*corev1.ConfigMap
	err  error
}

func (f fakeLister) List(labels.Selector) ([]*corev1.ConfigMap, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.objs, nil
}

// quietLogger discards: these tests assert behavior, not log lines.
func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
