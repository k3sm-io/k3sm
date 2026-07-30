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

// TestRosettaLabelDeleteOnLoss is the B103 proof of the two Rosetta capability node
// labels: k3sm.io/rosetta (host darwin/amd64 Mach-O translation) and
// k3sm.io/rosetta-linux (linux/amd64 ELF in a VZ guest, a CONJUNCTION of the vm
// backend and the guest probe). It follows the shape of TestNodeVirtualizationLabel
// (B1, the delete-on-loss precedent this mirrors) and pins three properties:
//
//  1. the label KEYS are the documented literals (a const rename is a red test, not a
//     silently-renamed node label the roadmap's four docs no longer describe);
//  2. presence-only with DELETE on loss — proven against PRE-SEEDED labels, because an
//     absence-only assertion also passes against an empty map, i.e. before any code
//     exists, and so cannot distinguish delete() from "never set";
//  3. the conjunction: a Rosetta-installed but VZ-INCAPABLE node carries
//     k3sm.io/rosetta but NOT k3sm.io/rosetta-linux.
//
// Every assertion is a t.Run SUBTEST of this one function on purpose — the named gate
// runs `go test -run '^TestRosettaLabelDeleteOnLoss$'`, so a sibling top-level test
// would be silently filtered out and never run.
//
// It is deliberately NOT t.Parallel: the configureNode_* subtests call configureNode,
// which reads the hostMemBytes package var that TestNodeCapacityFromHostMemory swaps.
// A non-parallel test runs entirely in the sequential phase, so the swap can never
// race these reads (the same reasoning TestNodeCapacityFromHostMemory documents).
func TestRosettaLabelDeleteOnLoss(t *testing.T) {
	// present reports whether key is on the node, via the two-value lookup — the only
	// form that distinguishes "absent" from "present but empty".
	present := func(t *testing.T, n *corev1.Node, key string) bool {
		t.Helper()
		_, ok := n.Labels[key]
		return ok
	}
	wantAbsent := func(t *testing.T, n *corev1.Node, key string) {
		t.Helper()
		if v, ok := n.Labels[key]; ok {
			t.Errorf("label %s must be ABSENT (fail-closed), got present with value %q; labels=%v", key, v, n.Labels)
		}
	}
	wantTrue := func(t *testing.T, n *corev1.Node, key string) {
		t.Helper()
		if got := n.Labels[key]; got != runtimeclass.LabelTrue {
			t.Errorf("label %s = %q, want %q; labels=%v", key, got, runtimeclass.LabelTrue, n.Labels)
		}
	}
	// The keys are pinned in the roadmap (four docs incl. a conformance-register row),
	// so they are asserted as VERBATIM literals here — not via the constants, which
	// would make a rename invisible.
	t.Run("label_keys_are_the_documented_literals", func(t *testing.T) {
		if runtimeclass.LabelRosetta != "k3sm.io/rosetta" {
			t.Errorf("LabelRosetta = %q, want %q (fixed by the roadmap; four docs cite it)", runtimeclass.LabelRosetta, "k3sm.io/rosetta")
		}
		if runtimeclass.LabelRosettaLinux != "k3sm.io/rosetta-linux" {
			t.Errorf("LabelRosettaLinux = %q, want %q (fixed by the roadmap; four docs cite it)", runtimeclass.LabelRosettaLinux, "k3sm.io/rosetta-linux")
		}
		if runtimeclass.LabelTrue != "true" {
			t.Errorf("LabelTrue = %q, want %q", runtimeclass.LabelTrue, "true")
		}
	})

	// A nil Labels map must be allocated, not panicked on.
	t.Run("host_capable_sets_label", func(t *testing.T) {
		n := &corev1.Node{}
		applyRosettaLabels(n, provider.NodeCapabilities{RosettaHost: true})
		wantTrue(t, n, runtimeclass.LabelRosetta)
		wantAbsent(t, n, runtimeclass.LabelRosettaLinux)
	})

	// LOSS direction, host key: the label was on the node (a prior boot advertised it)
	// and the capability is now gone ⇒ the key is DELETED, and a neighbour label is
	// untouched. Pre-seeding is what makes this a real delete() proof.
	t.Run("loss_deletes_host_label", func(t *testing.T) {
		n := &corev1.Node{}
		n.Labels = map[string]string{
			runtimeclass.LabelRosetta: runtimeclass.LabelTrue,
			"kubernetes.io/os":        "darwin",
		}
		applyRosettaLabels(n, provider.NodeCapabilities{RosettaHost: false})
		wantAbsent(t, n, runtimeclass.LabelRosetta)
		if n.Labels["kubernetes.io/os"] != "darwin" {
			t.Errorf("clearing %s must not disturb other node labels; labels=%v", runtimeclass.LabelRosetta, n.Labels)
		}
	})

	// LOSS direction, linux key: the guest probe still says yes but the vm backend is
	// gone, so the conjunction is false ⇒ the pre-seeded key is DELETED.
	t.Run("loss_deletes_linux_label", func(t *testing.T) {
		n := &corev1.Node{}
		n.Labels = map[string]string{
			runtimeclass.LabelRosettaLinux: runtimeclass.LabelTrue,
			"kubernetes.io/os":             "darwin",
		}
		applyRosettaLabels(n, provider.NodeCapabilities{VMBackend: false, RosettaGuest: true})
		wantAbsent(t, n, runtimeclass.LabelRosettaLinux)
		if n.Labels["kubernetes.io/os"] != "darwin" {
			t.Errorf("clearing %s must not disturb other node labels; labels=%v", runtimeclass.LabelRosettaLinux, n.Labels)
		}
	})

	// THE DECISIVE ROW: guest translation is possible in principle but this host has no
	// VZ backend, so there is no guest to translate in. A mapper that used the guest
	// condition ALONE would advertise linux/amd64 schedulability on a node that cannot
	// boot a guest.
	t.Run("composition_vz_incapable", func(t *testing.T) {
		n := &corev1.Node{}
		applyRosettaLabels(n, provider.NodeCapabilities{VMBackend: false, RosettaGuest: true})
		wantAbsent(t, n, runtimeclass.LabelRosettaLinux)
	})

	// The other half of the conjunction: a VZ node whose guest cannot translate.
	t.Run("composition_guest_false", func(t *testing.T) {
		n := &corev1.Node{}
		applyRosettaLabels(n, provider.NodeCapabilities{VMBackend: true, RosettaGuest: false})
		wantAbsent(t, n, runtimeclass.LabelRosettaLinux)
	})

	t.Run("composition_both_true", func(t *testing.T) {
		n := &corev1.Node{}
		applyRosettaLabels(n, provider.NodeCapabilities{VMBackend: true, RosettaGuest: true})
		wantTrue(t, n, runtimeclass.LabelRosettaLinux)
	})

	// The two keys are INDEPENDENT: host translation absent, guest translation present.
	// A node with no host Rosetta can still run linux/amd64 in a translating guest.
	t.Run("host_and_linux_are_independent", func(t *testing.T) {
		n := &corev1.Node{}
		applyRosettaLabels(n, provider.NodeCapabilities{RosettaHost: false, VMBackend: true, RosettaGuest: true})
		wantAbsent(t, n, runtimeclass.LabelRosetta)
		wantTrue(t, n, runtimeclass.LabelRosettaLinux)
		if !present(t, n, runtimeclass.LabelRosettaLinux) {
			t.Errorf("%s must be present via the two-value lookup", runtimeclass.LabelRosettaLinux)
		}
	})

	// A stale WRONG VALUE (e.g. an operator or an older build wrote "false") is
	// REPAIRED to "true", not left alone: presence-only means the value is always
	// LabelTrue when the capability holds.
	t.Run("stale_wrong_value_repaired", func(t *testing.T) {
		n := &corev1.Node{}
		n.Labels = map[string]string{runtimeclass.LabelRosetta: "false"}
		applyRosettaLabels(n, provider.NodeCapabilities{RosettaHost: true})
		wantTrue(t, n, runtimeclass.LabelRosetta)
	})

	// THE PRODUCTION-WIRING ROW: drive configureNode itself over all four corners of
	// (RosettaHost × rosetta-linux conjunction). Without this a mutation that removed
	// the applyRosettaLabels CALL from configureNode would leave every leaf-helper
	// subtest above green while the shipped node carried no Rosetta label at all.
	t.Run("configureNode_threads_caps", func(t *testing.T) {
		cases := []struct {
			name      string
			caps      provider.NodeCapabilities
			wantHost  bool
			wantLinux bool
		}{
			{"neither", provider.NodeCapabilities{}, false, false},
			{"host only", provider.NodeCapabilities{RosettaHost: true}, true, false},
			{"linux only", provider.NodeCapabilities{VMBackend: true, RosettaGuest: true}, false, true},
			{"both", provider.NodeCapabilities{RosettaHost: true, VMBackend: true, RosettaGuest: true}, true, true},
		}
		for _, tc := range cases {
			// Pre-seed BOTH keys so each corner proves a real set-or-delete through
			// configureNode, not merely an omission.
			n := &corev1.Node{}
			n.Labels = map[string]string{
				runtimeclass.LabelRosetta:      runtimeclass.LabelTrue,
				runtimeclass.LabelRosettaLinux: runtimeclass.LabelTrue,
			}
			configureNode(n, "k3sm-node", "10.0.0.1", tc.caps)
			if tc.wantHost {
				wantTrue(t, n, runtimeclass.LabelRosetta)
			} else {
				wantAbsent(t, n, runtimeclass.LabelRosetta)
			}
			if tc.wantLinux {
				wantTrue(t, n, runtimeclass.LabelRosettaLinux)
			} else {
				wantAbsent(t, n, runtimeclass.LabelRosettaLinux)
			}
			if n.Labels["kubernetes.io/os"] != "darwin" {
				t.Errorf("%s: configureNode must still stamp kubernetes.io/os=darwin; labels=%v", tc.name, n.Labels)
			}
			// Rosetta capability NEVER widens the arch the node reports: both the label
			// and NodeInfo.Architecture stay the machine's native arm64, so a generic
			// client is never told this node IS amd64 (that is B104's separate question).
			if got := n.Labels["kubernetes.io/arch"]; got != "arm64" {
				t.Errorf("%s: kubernetes.io/arch = %q, want arm64 (Rosetta must not widen the arch label)", tc.name, got)
			}
			if got := n.Status.NodeInfo.Architecture; got != "arm64" {
				t.Errorf("%s: NodeInfo.Architecture = %q, want arm64 (Rosetta must not widen the reported arch)", tc.name, got)
			}
		}
	})

	// B1 must not regress: the same configureNode call still stamps the virtualization
	// label from caps.VMBackend.
	t.Run("configureNode_preserves_vm_label", func(t *testing.T) {
		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{VMBackend: true})
		wantTrue(t, n, runtimeclass.LabelVirtualization)

		// And the loss direction of B1's label still deletes (pre-seeded).
		lost := &corev1.Node{}
		lost.Labels = map[string]string{runtimeclass.LabelVirtualization: runtimeclass.LabelTrue}
		configureNode(lost, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})
		wantAbsent(t, lost, runtimeclass.LabelVirtualization)
	})
}
