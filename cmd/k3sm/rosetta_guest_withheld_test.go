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

// TestRosettaLinuxWithheldWithoutGuestSupport is the k3sm half of B229: the node must
// NOT advertise a capability it does not have.
//
// The regression this pins is specific and this-milestone. runtimed evaluates
// RosettaGuestAvailable only when the vm backend is available, and cmd/k3sm composes
// k3sm.io/rosetta-linux as caps.VMBackend ∧ caps.RosettaGuest (applyRosettaLabels).
// The moment the vm backend becomes Available on an entitled Mac, the SECOND conjunct
// is the only thing standing between the node and a false linux/amd64 schedulability
// claim — because pkg/image adds linux/amd64 as a pull candidate for every vm pod on a
// node carrying that key, while the vmhost attaches no Rosetta share at v0.1. The
// runtimed side withholds the guest capability unless the vmhost helper advertises it;
// THIS is the node-side proof that a withheld capability produces a withheld label.
//
// It is deliberately distinct from TestRosettaLabelDeleteOnLoss's composition_guest_false
// subtest rather than folded into it. That test's decisive row is the VZ-INCAPABLE host
// (VMBackend false); this one's is the VZ-CAPABLE host whose guest cannot translate —
// the corner B229 opens, which reaches production only once VMBackend goes true. It is
// also the gate string B229 names, so it must be a top-level test that
// `go test -run '^TestRosettaLinuxWithheldWithoutGuestSupport$'` selects.
//
// Three properties, none of which the existing composition row asserts together:
//
//  1. WITHHELD, not falsified — the key is ABSENT, proven against a PRE-SEEDED label so
//     the assertion distinguishes delete() from "never set" (an absence-only check also
//     passes against an empty map, i.e. before any code exists);
//  2. the value "false" is never written — this codebase deletes rather than falsifies,
//     and a "false" value would still satisfy an `exists`-style node selector, so a
//     falsifying implementation would schedule the very pods this withholding prevents;
//  3. the SIBLING claim survives — a VZ-capable node still advertises
//     k3sm.io/virtualization. Withholding guest translation must not be implemented by
//     demoting the vm backend, which would silently strand every native vm pod.
//
// Deliberately NOT t.Parallel: the configureNode legs read the hostMemBytes package var
// that TestNodeCapacityFromHostMemory swaps, so this stays in the sequential phase.
func TestRosettaLinuxWithheldWithoutGuestSupport(t *testing.T) {
	// vmCapableGuestless is the B229 host: the vm backend IS available (so vm pods run
	// natively) but the guest advertises no Rosetta, so linux/amd64 is not translatable.
	vmCapableGuestless := provider.NodeCapabilities{VMBackend: true, RosettaGuest: false}

	// wantWithheld asserts the key is ABSENT — the fail-closed direction — and names the
	// falsified-instead-of-deleted failure explicitly, since "false" is the mistake this
	// test exists to catch.
	wantWithheld := func(t *testing.T, n *corev1.Node, key string) {
		t.Helper()
		v, ok := n.Labels[key]
		if !ok {
			return
		}
		if v == "false" {
			t.Errorf("label %s = %q: the capability must be WITHHELD (key deleted), not falsified — a \"false\" value still satisfies an `exists` node selector; labels=%v", key, v, n.Labels)
			return
		}
		t.Errorf("label %s must be ABSENT when guest Rosetta is not advertised, got %q; labels=%v", key, v, n.Labels)
	}

	// The mapper, on a clean node: the conjunction's second half is false, so the key is
	// never stamped.
	t.Run("guestless_vm_host_withholds_linux_label", func(t *testing.T) {
		n := &corev1.Node{}
		applyRosettaLabels(n, vmCapableGuestless)
		wantWithheld(t, n, runtimeclass.LabelRosettaLinux)
	})

	// The DELETE proof: a prior boot advertised the key (guest Rosetta was reported then,
	// or an older daemon reported it unconditionally) and this boot must retract it.
	// Pre-seeding is what makes this a delete() assertion rather than an omission.
	t.Run("preseeded_label_is_deleted_not_falsified", func(t *testing.T) {
		n := &corev1.Node{}
		n.Labels = map[string]string{
			runtimeclass.LabelRosettaLinux: runtimeclass.LabelTrue,
			"kubernetes.io/os":             "darwin",
		}
		applyRosettaLabels(n, vmCapableGuestless)
		wantWithheld(t, n, runtimeclass.LabelRosettaLinux)
		if n.Labels["kubernetes.io/os"] != "darwin" {
			t.Errorf("withholding %s must not disturb other node labels; labels=%v", runtimeclass.LabelRosettaLinux, n.Labels)
		}
	})

	// Host Rosetta is an INDEPENDENT probe: a Mac with Rosetta 2 installed still
	// advertises k3sm.io/rosetta (darwin/amd64 Mach-O on the native spine) while the
	// linux key stays withheld. A fix that withheld both would cost real host capability.
	t.Run("host_rosetta_unaffected", func(t *testing.T) {
		n := &corev1.Node{}
		caps := vmCapableGuestless
		caps.RosettaHost = true
		applyRosettaLabels(n, caps)
		if got := n.Labels[runtimeclass.LabelRosetta]; got != runtimeclass.LabelTrue {
			t.Errorf("label %s = %q, want %q: host Rosetta is a separate probe and must survive a withheld guest capability", runtimeclass.LabelRosetta, got, runtimeclass.LabelTrue)
		}
		wantWithheld(t, n, runtimeclass.LabelRosettaLinux)
	})

	// THE PRODUCTION-WIRING ROW: drive configureNode itself, pre-seeding the key, so a
	// change that dropped the applyRosettaLabels call (or re-composed the conjunction
	// elsewhere) is red here even with every mapper subtest above green. The host facts
	// are pinned so the arch assertion is hermetic on a translated toolchain.
	t.Run("configureNode_withholds_and_keeps_vm_label", func(t *testing.T) {
		withHostArchFacts(t, nativeAppleSilicon, nil)

		n := &corev1.Node{}
		n.Labels = map[string]string{runtimeclass.LabelRosettaLinux: runtimeclass.LabelTrue}
		configureNode(n, "k3sm-node", "10.0.0.1", nodeKubeletListen, vmCapableGuestless)

		wantWithheld(t, n, runtimeclass.LabelRosettaLinux)
		// The sibling claim: this node CAN boot a guest, so k3sm.io/virtualization must
		// still be advertised. Withholding translation is not demoting the vm backend.
		if got := n.Labels[runtimeclass.LabelVirtualization]; got != runtimeclass.LabelTrue {
			t.Errorf("label %s = %q, want %q: a guestless-Rosetta host is still VZ-capable and must keep advertising the vm backend", runtimeclass.LabelVirtualization, got, runtimeclass.LabelTrue)
		}
		if got := n.Labels["kubernetes.io/arch"]; got != "arm64" {
			t.Errorf("kubernetes.io/arch = %q, want arm64: withholding guest translation must not widen the reported arch", got)
		}
	})
}
