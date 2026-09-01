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
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// TestNodeVMArtifactsLabel is the advertisement half of B108: the
// VMArtifactsAvailable capability reaches the node object as
// k3sm.io/vm-artifacts, present ONLY when this daemon start ensured and verified
// the pinned guest boot artifacts.
//
// It mirrors TestNodeVirtualizationLabel (the B1 precedent) because it must obey
// the same presence-only, DELETE-on-loss discipline, and the delete direction is
// the one that matters most here: ensure re-verifies on EVERY start rather than
// trusting a marker file, so "this node had artifacts yesterday" is not a claim
// the label may keep making.
//
// The independence assertion is the non-obvious one. VMBackend and VMArtifacts
// answer different questions — can this Mac run a guest, and does this node have
// a guest to run — and each key must track its OWN fact. A wiring that conflated
// them (labelling artifacts from the VZ probe, or vice versa) would still pass a
// test that only ever set both together, and would mislabel exactly the two
// interesting nodes: an entitled Mac whose fetch failed, and an air-gap-seeded
// cache on a Mac with no VZ.
func TestNodeVMArtifactsLabel(t *testing.T) {
	t.Parallel()

	t.Run("present when ensured, DELETED when not", func(t *testing.T) {
		t.Parallel()

		ensured := &corev1.Node{}
		applyVMArtifactsLabel(ensured, true)
		if got := ensured.Labels[runtimeclass.LabelVMArtifacts]; got != runtimeclass.LabelTrue {
			t.Errorf("ensured: label %s = %q, want %q", runtimeclass.LabelVMArtifacts, got, runtimeclass.LabelTrue)
		}

		// Previously advertised, now unavailable: the key must go, not become "false"
		// (a "false" value still satisfies an exists-style selector).
		lost := &corev1.Node{}
		lost.Labels = map[string]string{
			runtimeclass.LabelVMArtifacts: runtimeclass.LabelTrue,
			"kubernetes.io/os":            "darwin",
		}
		applyVMArtifactsLabel(lost, false)
		if _, present := lost.Labels[runtimeclass.LabelVMArtifacts]; present {
			t.Errorf("lost: label %s must be DELETED, got present", runtimeclass.LabelVMArtifacts)
		}
		if lost.Labels["kubernetes.io/os"] != "darwin" {
			t.Error("clearing the vm-artifacts label must not disturb other node labels")
		}
	})

	t.Run("configureNode tracks each capability independently", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			name               string
			caps               provider.NodeCapabilities
			wantArtifacts      bool
			wantVirtualization bool
		}{
			{"neither (the fail-closed zero value)", provider.NodeCapabilities{}, false, false},
			{"artifacts only (seeded cache, no VZ)", provider.NodeCapabilities{VMArtifacts: true}, true, false},
			{"vm backend only (entitled Mac, fetch failed)", provider.NodeCapabilities{VMBackend: true}, false, true},
			{"both (a node that can actually boot a guest)", provider.NodeCapabilities{VMBackend: true, VMArtifacts: true}, true, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				n := &corev1.Node{}
				configureNode(n, "k3sm-node", "10.0.0.1", nodeKubeletListen, tc.caps)

				_, gotArtifacts := n.Labels[runtimeclass.LabelVMArtifacts]
				if gotArtifacts != tc.wantArtifacts {
					t.Errorf("label %s present = %v, want %v", runtimeclass.LabelVMArtifacts, gotArtifacts, tc.wantArtifacts)
				}
				_, gotVirt := n.Labels[runtimeclass.LabelVirtualization]
				if gotVirt != tc.wantVirtualization {
					t.Errorf("label %s present = %v, want %v (the two capabilities must not be conflated)",
						runtimeclass.LabelVirtualization, gotVirt, tc.wantVirtualization)
				}
			})
		}
	})
}
