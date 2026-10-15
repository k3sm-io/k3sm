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
	"reflect"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"

	"k3sm.io/k3sm/pkg/provider"
)

// unservedDeclarableFeatures names, by hand, every registry key a v1.37.1 kubelet
// may declare that this node does NOT serve. It and the served set (what
// DeclaredFeatures returns with every capability on, plus every key named in
// capabilityDeclaredFeatures) partition the registry: disjoint, and together equal
// to it. Today it is all nine; when a provider capability starts serving one, that
// key moves out of this table and into capabilityDeclaredFeatures in the same change.
var unservedDeclarableFeatures = []string{
	"RestartAllContainersOnContainerExits",
	"InPlacePodLevelResourcesVerticalScaling",
	"InPlacePodVerticalScalingInitContainers",
	"InPlacePodVerticalScalingMemoryBackedVolumes",
	"ExtendWebSocketsToKubelet",
	"UserNamespacesHostNetworkSupport",
	"DRANodeAllocatableResources",
	"DRAOptionalNodeOperations",
	"VolumeBindMountOptions",
}

// capabilityDeclaredFeatures maps every bool field of provider.NodeCapabilities to
// the declaredFeatures keys that capability alone may turn on. Every field needs a
// row, even an empty one, so a new capability forces a decision here.
var capabilityDeclaredFeatures = map[string][]string{
	"VMBackend":    nil,
	"VMArtifacts":  nil,
	"RosettaHost":  nil,
	"RosettaGuest": nil,
}

// allCapabilities is every NodeCapabilities bool field on.
var allCapabilities = provider.NodeCapabilities{VMBackend: true, VMArtifacts: true, RosettaHost: true, RosettaGuest: true}

// configuredNode runs configureNode over a fresh Node with caps.
func configuredNode(caps provider.NodeCapabilities) *corev1.Node {
	n := &corev1.Node{}
	configureNode(n, "k3sm-node", "10.0.0.1", nodeKubeletListen, caps)
	return n
}

// heartbeatPublished returns the first node the status loop publishes when it is
// handed n, the way the node command hands it the configured node.
func heartbeatPublished(t *testing.T, n *corev1.Node) *corev1.Node {
	t.Helper()
	nsp, err := provider.NewNodeStatusProvider(provider.NodeStatusConfig{
		Node:     n,
		DataRoot: t.TempDir(),
		Interval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewNodeStatusProvider: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	got := make(chan *corev1.Node, 1)
	nsp.NotifyNodeStatus(ctx, func(pub *corev1.Node) {
		select {
		case got <- pub.DeepCopy():
		default:
		}
	})
	done := make(chan struct{})
	go func() { defer close(done); _ = nsp.Run(ctx) }() // Run returns ctx.Err() on cancel
	defer func() { cancel(); <-done }()
	select {
	case pub := <-got:
		return pub
	case <-time.After(30 * time.Second):
		t.Fatal("status loop published nothing within 30s")
		return nil
	}
}

// TestNodeDeclaredFeaturesTruthful pins node.status.declaredFeatures to what the
// Darwin provider actually serves: nothing today, only registry keys ever, and the
// same set on the registered Node and on every heartbeat.
func TestNodeDeclaredFeaturesTruthful(t *testing.T) {
	declarable := provider.KubeletDeclarableFeatures()

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "configureNode publishes no declared feature",
			check: func(t *testing.T) {
				n := configuredNode(provider.NodeCapabilities{})
				if len(n.Status.DeclaredFeatures) != 0 {
					t.Fatalf("declaredFeatures = %q, want none", n.Status.DeclaredFeatures)
				}
			},
		},
		{
			name: "every published key is a kubelet registry name",
			check: func(t *testing.T) {
				for _, caps := range []provider.NodeCapabilities{{}, allCapabilities} {
					for _, k := range configuredNode(caps).Status.DeclaredFeatures {
						if !slices.Contains(declarable, k) {
							t.Errorf("caps %+v: declaredFeatures key %q is not a kubelet registry name", caps, k)
						}
					}
				}
			},
		},
		{
			name: "no unserved registry key is published",
			check: func(t *testing.T) {
				served := map[string]bool{}
				for _, k := range provider.DeclaredFeatures(allCapabilities) {
					served[k] = true
				}
				for _, keys := range capabilityDeclaredFeatures {
					for _, k := range keys {
						served[k] = true
					}
				}
				union := map[string]bool{}
				for _, k := range unservedDeclarableFeatures {
					if served[k] {
						t.Errorf("%q is both served and in the unserved table", k)
					}
					union[k] = true
				}
				for k := range served {
					union[k] = true
				}
				for k := range union {
					if !slices.Contains(declarable, k) {
						t.Errorf("%q is in the served or unserved set but is not a registry name", k)
					}
				}
				for _, k := range declarable {
					if !union[k] {
						t.Errorf("registry name %q is in neither the served set nor the unserved table", k)
					}
				}
				got := configuredNode(provider.NodeCapabilities{}).Status.DeclaredFeatures
				for _, k := range unservedDeclarableFeatures {
					if !slices.Contains(declarable, k) {
						t.Errorf("unserved table names %q, which is not a registry name", k)
					}
					if slices.Contains(got, k) {
						t.Errorf("unserved feature %q is published", k)
					}
				}
			},
		},
		{
			name: "every capability field has a declared-features row",
			check: func(t *testing.T) {
				typ := reflect.TypeFor[provider.NodeCapabilities]()
				seen := map[string]bool{}
				for i := range typ.NumField() {
					f := typ.Field(i)
					if f.Type.Kind() != reflect.Bool {
						continue
					}
					seen[f.Name] = true
					allowed, ok := capabilityDeclaredFeatures[f.Name]
					if !ok {
						t.Errorf("NodeCapabilities.%s has no row in capabilityDeclaredFeatures", f.Name)
						continue
					}
					var caps provider.NodeCapabilities
					reflect.ValueOf(&caps).Elem().Field(i).SetBool(true)
					for _, k := range provider.DeclaredFeatures(caps) {
						if !slices.Contains(allowed, k) {
							t.Errorf("NodeCapabilities.%s alone declares %q, not in its row %q", f.Name, k, allowed)
						}
					}
				}
				for name, keys := range capabilityDeclaredFeatures {
					if !seen[name] {
						t.Errorf("capabilityDeclaredFeatures row %q names no bool NodeCapabilities field", name)
					}
					for _, k := range keys {
						if !slices.Contains(declarable, k) {
							t.Errorf("capabilityDeclaredFeatures row %q names %q, not a registry name", name, k)
						}
					}
				}
			},
		},
		{
			name: "heartbeat publishes the configured node's set",
			check: func(t *testing.T) {
				want := configuredNode(provider.NodeCapabilities{})
				got := heartbeatPublished(t, want.DeepCopy())
				if !reflect.DeepEqual(got.Status.DeclaredFeatures, want.Status.DeclaredFeatures) {
					t.Errorf("heartbeat declaredFeatures = %#v, configureNode = %#v", got.Status.DeclaredFeatures, want.Status.DeclaredFeatures)
				}
				// Only the conditions and phase are the status loop's own.
				got.Status.Conditions, got.Status.Phase = nil, ""
				want.Status.Conditions, want.Status.Phase = nil, ""
				if !equality.Semantic.DeepEqual(got, want) {
					t.Errorf("heartbeat object differs from configureNode's beyond conditions and phase")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, tc.check)
	}
}
