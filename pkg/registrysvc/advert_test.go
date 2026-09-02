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

package registrysvc

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestAdvertisement pins what a node publishes, and — the row that matters most —
// what it publishes when it has no mesh address. A node that is not on a mesh has
// no address any peer could dial, so an advertisement from it would send every
// peer's pull at something unreachable; the constructor must refuse rather than
// render a plausible-looking lie.
func TestAdvertisement(t *testing.T) {
	tests := []struct {
		name     string
		node     string
		meshIP   string
		port     int
		wantHost string // "" => expect ErrNoMeshAddress
		wantErr  bool   // a non-ErrNoMeshAddress error
	}{
		{name: "a mesh node advertises its own mesh address", node: "mac-a", meshIP: "100.64.1.1", port: 6450, wantHost: "100.64.1.1:6450"},
		{name: "a second node on the same mesh", node: "mac-b", meshIP: "100.64.2.1", port: 6450, wantHost: "100.64.2.1:6450"},
		{name: "a non-default port is carried through", node: "mac-a", meshIP: "100.64.1.1", port: 14507, wantHost: "100.64.1.1:14507"},
		{name: "no mesh address: nothing to advertise", node: "mac-a", meshIP: "", port: 6450},
		{name: "loopback is not an address a peer can dial", node: "mac-a", meshIP: "127.0.0.1", port: 6450},
		{name: "the wildcard is not an address at all", node: "mac-a", meshIP: "0.0.0.0", port: 6450},
		{name: "a non-address is not an address", node: "mac-a", meshIP: "not-an-ip", port: 6450},
		{name: "port 0 is the disabled registry", node: "mac-a", meshIP: "100.64.1.1", port: 0},
		{name: "an out-of-range port", node: "mac-a", meshIP: "100.64.1.1", port: 70000},
		{name: "an empty node name", node: "", meshIP: "100.64.1.1", port: 6450, wantErr: true},
		{name: "a node name that will not compose a valid object name", node: strings.Repeat("n", 250), meshIP: "100.64.1.1", port: 6450, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm, err := Advertisement(tc.node, tc.meshIP, tc.port)
			switch {
			case tc.wantErr:
				if err == nil {
					t.Fatalf("Advertisement(%q, %q, %d) = %v, want an error", tc.node, tc.meshIP, tc.port, cm)
				}
				if errors.Is(err, ErrNoMeshAddress) {
					t.Fatalf("err = %v, want a naming error rather than ErrNoMeshAddress", err)
				}
				return
			case tc.wantHost == "":
				if !errors.Is(err, ErrNoMeshAddress) {
					t.Fatalf("Advertisement(%q, %q, %d) err = %v, want ErrNoMeshAddress", tc.node, tc.meshIP, tc.port, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Advertisement: %v", err)
			}
			if want := AdvertisementPrefix + tc.node; cm.Name != want {
				t.Errorf("name = %q, want %q", cm.Name, want)
			}
			// Pinned as a LITERAL rather than against the constant the object was
			// rendered from, because the namespace is not an implementation
			// detail here: it IS the scope of the node identity's read grant
			// (pkg/rbac's registry-advertisement reader Role). A rename, or a
			// move back beside the KEP-1755 document in the shared kube-public
			// namespace, silently widens what every node may read — so it has to
			// be a red test, and an assertion against the constant could never
			// be one.
			if cm.Namespace != "k3sm-registry" {
				t.Errorf("namespace = %q, want the dedicated k3sm-registry namespace the node read grant is scoped to", cm.Namespace)
			}
			if AdvertisementNamespace == HostingNamespace {
				t.Errorf("the advertisements share %q with the KEP-1755 document, so the node read grant is no longer scoped to advertisements", HostingNamespace)
			}
			if cm.Data[AdvertisementNodeKey] != tc.node {
				t.Errorf("data[%s] = %q, want %q", AdvertisementNodeKey, cm.Data[AdvertisementNodeKey], tc.node)
			}
			if cm.Data[AdvertisementMeshHostKey] != tc.wantHost {
				t.Errorf("data[%s] = %q, want %q", AdvertisementMeshHostKey, cm.Data[AdvertisementMeshHostKey], tc.wantHost)
			}
			// The peer's transport decision comes from the advertiser, and the
			// ingest registry serves plain HTTP: a peer that inferred https from
			// the address family would fail the TLS handshake on every pull.
			if cm.Data[AdvertisementPlainHTTPKey] != "true" {
				t.Errorf("data[%s] = %q, want \"true\"", AdvertisementPlainHTTPKey, cm.Data[AdvertisementPlainHTTPKey])
			}
			// Round-trip: what one node writes is exactly what a peer decodes.
			p, perr := ParseAdvertisement(cm)
			if perr != nil {
				t.Fatalf("ParseAdvertisement of our own document: %v", perr)
			}
			if p.Node != tc.node || p.MeshHost != tc.wantHost || !p.PlainHTTP {
				t.Errorf("round trip = %+v, want node %q host %q plainHTTP true", p, tc.node, tc.wantHost)
			}
		})
	}
}

// TestParseAdvertisement pins the reader's strictness. Every rejection here is a
// document that, if consulted, would send a pull somewhere the pod never named —
// a spliced repository path, a host that is not this cluster's, an identity claim
// that does not match the object's own name.
func TestParseAdvertisement(t *testing.T) {
	adv := func(name string, data map[string]string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: AdvertisementNamespace}, Data: data}
	}
	good := map[string]string{
		AdvertisementNodeKey:      "mac-a",
		AdvertisementMeshHostKey:  "100.64.1.1:6450",
		AdvertisementPlainHTTPKey: "true",
	}
	with := func(k, v string) map[string]string {
		out := map[string]string{}
		for kk, vv := range good {
			out[kk] = vv
		}
		if v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
		return out
	}

	tests := []struct {
		name string
		cm   *corev1.ConfigMap
		ok   bool
	}{
		{name: "a well-formed advertisement", cm: adv("k3sm-node-registry-mac-a", good), ok: true},
		{name: "no object", cm: nil},
		{name: "a ConfigMap outside the advertisement set", cm: adv("local-registry-hosting", good)},
		{name: "no node key", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementNodeKey, ""))},
		{name: "the node claims an identity its name does not", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementNodeKey, "mac-b"))},
		{name: "no mesh host", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementMeshHostKey, ""))},
		{name: "a mesh host carrying a repository path", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementMeshHostKey, "100.64.1.1:6450/evil"))},
		{name: "a mesh host carrying a scheme", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementMeshHostKey, "http://100.64.1.1:6450"))},
		{name: "a mesh host carrying userinfo", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementMeshHostKey, "user@100.64.1.1:6450"))},
		{name: "a mesh host that is a name, not an address", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementMeshHostKey, "registry.example.com:6450"))},
		{name: "a mesh host with no port", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementMeshHostKey, "100.64.1.1"))},
		{name: "a mesh host with a nonsense port", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementMeshHostKey, "100.64.1.1:no"))},
		{name: "plainHTTP absent", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementPlainHTTPKey, ""))},
		{name: "plainHTTP is not a boolean", cm: adv("k3sm-node-registry-mac-a", with(AdvertisementPlainHTTPKey, "yes-please"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseAdvertisement(tc.cm)
			if tc.ok {
				if err != nil {
					t.Fatalf("ParseAdvertisement: %v", err)
				}
				if p.Node != "mac-a" || p.MeshHost != "100.64.1.1:6450" || !p.PlainHTTP {
					t.Errorf("parsed %+v, want the document's own values", p)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseAdvertisement = %+v, want a rejection", p)
			}
			// The caller classifies with errors.Is to skip exactly this peer.
			if !errors.Is(err, ErrMalformedAdvertisement) {
				t.Errorf("err = %v, want it to wrap ErrMalformedAdvertisement", err)
			}
		})
	}
}

// TestPublishAdvertisement drives the four states the publisher has to get right:
// absent (create), stale (refresh — the case that matters, because both the port
// and the mesh address are per-boot facts), identical (no write), and no mesh
// address at all (no write, and a sentinel the caller reads as a non-event).
func TestPublishAdvertisement(t *testing.T) {
	t.Run("absent is created", func(t *testing.T) {
		c := &fakeAdvertisements{}
		if err := PublishAdvertisement(t.Context(), c, "mac-a", "100.64.1.1", 6450); err != nil {
			t.Fatalf("PublishAdvertisement: %v", err)
		}
		if c.creates != 1 || c.updates != 0 {
			t.Fatalf("creates=%d updates=%d, want 1/0", c.creates, c.updates)
		}
		if c.cm.Data[AdvertisementMeshHostKey] != "100.64.1.1:6450" {
			t.Errorf("published %q", c.cm.Data[AdvertisementMeshHostKey])
		}
	})

	t.Run("a stale address is refreshed", func(t *testing.T) {
		c := &fakeAdvertisements{}
		if err := PublishAdvertisement(t.Context(), c, "mac-a", "100.64.1.1", 6450); err != nil {
			t.Fatalf("PublishAdvertisement: %v", err)
		}
		if err := PublishAdvertisement(t.Context(), c, "mac-a", "100.64.1.1", 14507); err != nil {
			t.Fatalf("PublishAdvertisement: %v", err)
		}
		if c.updates != 1 {
			t.Fatalf("updates = %d after a port change, want 1 — peers would dial a dead port", c.updates)
		}
		if c.cm.Data[AdvertisementMeshHostKey] != "100.64.1.1:14507" {
			t.Errorf("data = %q, want the new port", c.cm.Data[AdvertisementMeshHostKey])
		}
	})

	t.Run("an identical advertisement is not rewritten", func(t *testing.T) {
		c := &fakeAdvertisements{}
		for range 2 {
			if err := PublishAdvertisement(t.Context(), c, "mac-a", "100.64.1.1", 6450); err != nil {
				t.Fatalf("PublishAdvertisement: %v", err)
			}
		}
		if c.updates != 0 {
			t.Errorf("updates = %d for an unchanged advertisement, want 0", c.updates)
		}
	})

	t.Run("no mesh address publishes nothing", func(t *testing.T) {
		c := &fakeAdvertisements{}
		err := PublishAdvertisement(t.Context(), c, "mac-a", "", 6450)
		if !errors.Is(err, ErrNoMeshAddress) {
			t.Fatalf("err = %v, want ErrNoMeshAddress", err)
		}
		if c.creates != 0 || c.updates != 0 {
			t.Errorf("creates=%d updates=%d, want no write at all", c.creates, c.updates)
		}
	})

	t.Run("a read failure is reported, not swallowed", func(t *testing.T) {
		c := &fakeAdvertisements{getErr: errors.New("apiserver said no")}
		if err := PublishAdvertisement(t.Context(), c, "mac-a", "100.64.1.1", 6450); err == nil {
			t.Fatal("PublishAdvertisement = nil on a read failure, want an error")
		}
	})
}

// TestRemoveAdvertisement pins the retraction: it deletes the node's own object,
// and an object that is already gone is success — the state the call wanted.
func TestRemoveAdvertisement(t *testing.T) {
	t.Run("the node's advertisement is deleted", func(t *testing.T) {
		c := &fakeAdvertisements{}
		if err := PublishAdvertisement(t.Context(), c, "mac-a", "100.64.1.1", 6450); err != nil {
			t.Fatalf("PublishAdvertisement: %v", err)
		}
		if err := RemoveAdvertisement(t.Context(), c, "mac-a"); err != nil {
			t.Fatalf("RemoveAdvertisement: %v", err)
		}
		if c.deleted != AdvertisementName("mac-a") {
			t.Errorf("deleted %q, want %q", c.deleted, AdvertisementName("mac-a"))
		}
		if c.cm != nil {
			t.Error("the advertisement survived the retraction")
		}
	})

	t.Run("an absent advertisement is not an error", func(t *testing.T) {
		c := &fakeAdvertisements{}
		if err := RemoveAdvertisement(t.Context(), c, "mac-a"); err != nil {
			t.Errorf("RemoveAdvertisement on an absent object = %v, want nil", err)
		}
	})

	t.Run("an empty node name deletes nothing", func(t *testing.T) {
		c := &fakeAdvertisements{}
		if err := RemoveAdvertisement(t.Context(), c, ""); err != nil {
			t.Fatalf("RemoveAdvertisement: %v", err)
		}
		if c.deleted != "" {
			t.Errorf("deleted %q on an empty node name", c.deleted)
		}
	})
}

// fakeAdvertisements is the four-method AdvertisementClient backed by one stored
// object. No client-go machinery, which is the point of declaring the interface
// at the consumer.
type fakeAdvertisements struct {
	cm               *corev1.ConfigMap
	creates, updates int
	deleted          string
	getErr           error
}

func (f *fakeAdvertisements) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.cm == nil || f.cm.Name != name {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, name)
	}
	return f.cm.DeepCopy(), nil
}

func (f *fakeAdvertisements) Create(_ context.Context, cm *corev1.ConfigMap, _ metav1.CreateOptions) (*corev1.ConfigMap, error) {
	f.creates++
	f.cm = cm.DeepCopy()
	return f.cm, nil
}

func (f *fakeAdvertisements) Update(_ context.Context, cm *corev1.ConfigMap, _ metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	f.updates++
	f.cm = cm.DeepCopy()
	return f.cm, nil
}

func (f *fakeAdvertisements) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	if f.cm == nil || f.cm.Name != name {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, name)
	}
	f.deleted = name
	f.cm = nil
	return nil
}
