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
	"errors"
	"runtime"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// nativeAppleSilicon / translatedOnAppleSilicon / genuineIntel are the three host-fact
// shapes the table legs below drive, measured on real hardware (M2, macOS 26) natively
// and from a process spawned under `arch -x86_64`.
var (
	nativeAppleSilicon       = hostArchFacts{arm64Capable: true, machine: "arm64", procTranslated: false}
	translatedOnAppleSilicon = hostArchFacts{arm64Capable: true, machine: "x86_64", procTranslated: true}
	genuineIntel             = hostArchFacts{arm64Capable: false, machine: "x86_64", procTranslated: false}
)

// withHostArchFacts swaps the readHostArchFacts seam for the duration of the test.
func withHostArchFacts(t *testing.T, f hostArchFacts, err error) {
	t.Helper()
	restore := readHostArchFacts
	readHostArchFacts = func() (hostArchFacts, error) { return f, err }
	t.Cleanup(func() { readHostArchFacts = restore })
}

// TestNodeArchLabelTruthful is the B104 proof that the architecture this node reports —
// BOTH the kubernetes.io/arch label and NodeInfo.Architecture — is DERIVED from host
// facts through the readHostArchFacts seam, replacing the two hardcoded "arm64" literals
// in configureNode.
//
// The gate is deliberately shaped to be red against a WRONG implementation, not merely
// against a missing one:
//
//  1. The table carries a REAL non-arm64 leg (genuineIntel ⇒ amd64) alongside the arm64
//     legs, driven all the way through configureNode. Against the old hardcode the amd64
//     leg fails BY VALUE, not by compile.
//  2. Because the legs disagree, NO constant can satisfy the table — including
//     runtime.GOARCH, which is a constant per build. That is the specific defect this
//     item exists to prevent: this workspace's own Go toolchain is amd64-under-Rosetta
//     (`go env GOARCH` = amd64 on an arm64 Mac), so an implementation returning
//     runtime.GOARCH would label an Apple Silicon node kubernetes.io/arch=amd64 and
//     attract amd64-only workloads to a node whose native arch is arm64 — invisibly on a
//     correctly-configured host. Mutating hostNodeArch to `return runtime.GOARCH` turns
//     this test red under either GOARCH; the build_arch_independence subtest states that
//     property explicitly rather than leaving it implicit in the table.
//  3. The translated leg pins the hazard a bare hw.machine would ship: a daemon running
//     under Rosetta reads hw.machine == "x86_64" on arm64 hardware.
//
// The gate invocation PINS GOARCH rather than trusting the ambient toolchain
// (`GOARCH=arm64 CGO_ENABLED=1 go test ./cmd/k3sm/ -run '^TestNodeArchLabelTruthful$'`),
// so the arch the test binary is built for is a stated input; the assertions themselves
// are GOARCH-agnostic by construction, so the test is equally valid under either pin.
//
// Every assertion is a t.Run SUBTEST of this one function on purpose — the named gate
// runs `-run '^TestNodeArchLabelTruthful$'`, so a sibling top-level test would be
// silently filtered out and never run.
//
// It is deliberately NOT t.Parallel: its subtests swap the readHostArchFacts package
// var, which configureNode reads (the same reasoning TestNodeCapacityFromHostMemory and
// TestRosettaLabelDeleteOnLoss document for hostMemBytes). A non-parallel test runs
// entirely in the sequential phase, so the swap can never race a parked parallel test.
func TestNodeArchLabelTruthful(t *testing.T) {
	// The pure derivation, over every host-fact shape that can be observed on a Mac.
	t.Run("derivation", func(t *testing.T) {
		cases := []struct {
			name  string
			facts hostArchFacts
			want  string
		}{
			{"native apple silicon", nativeAppleSilicon, "arm64"},
			// The hazard: hw.machine LIES here. Only the hardware capability (and the
			// proc_translated witness) keep this node's arch truthful.
			{"daemon translated on apple silicon", translatedOnAppleSilicon, "arm64"},
			// The real non-arm64 leg: an Intel Mac has neither sysctl, so both flags
			// read false and hw.machine is truthful.
			{"genuine intel host", genuineIntel, "amd64"},
			{"arm64e machine", hostArchFacts{arm64Capable: true, machine: "arm64e"}, "arm64"},
			// Capability sysctl unreadable but the machine is truthful: still arm64.
			{"capability sysctl missing on arm64 machine", hostArchFacts{machine: "arm64"}, "arm64"},
			// Translation proves arm64 hardware even without the capability read.
			{"translated with capability unreadable", hostArchFacts{machine: "x86_64", procTranslated: true}, "arm64"},
			{"haswell-optimized intel machine", hostArchFacts{machine: "x86_64h"}, "amd64"},
			// Unrecognized ⇒ "" so the caller logs and falls back, rather than
			// advertising a made-up arch.
			{"unrecognized machine", hostArchFacts{machine: "sparc"}, ""},
			{"empty facts", hostArchFacts{}, ""},
		}
		for _, tc := range cases {
			if got := nodeArch(tc.facts); got != tc.want {
				t.Errorf("%s: nodeArch(%+v) = %q, want %q", tc.name, tc.facts, got, tc.want)
			}
		}
	})

	// THE PRODUCTION-WIRING ROW: drive configureNode itself, so a mutation that derived
	// the arch correctly but left either stamping site hardcoded is red.
	t.Run("configureNode_reports_derived_arch", func(t *testing.T) {
		cases := []struct {
			name  string
			facts hostArchFacts
			want  string
		}{
			{"native apple silicon", nativeAppleSilicon, "arm64"},
			{"daemon translated on apple silicon", translatedOnAppleSilicon, "arm64"},
			{"genuine intel host", genuineIntel, "amd64"},
		}
		for _, tc := range cases {
			withHostArchFacts(t, tc.facts, nil)
			n := &corev1.Node{}
			// Pre-seed a WRONG value so each leg proves a real write, not an omission.
			n.Labels = map[string]string{"kubernetes.io/arch": "riscv64"}
			n.Status.NodeInfo.Architecture = "riscv64"
			configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})

			if got := n.Labels["kubernetes.io/arch"]; got != tc.want {
				t.Errorf("%s: kubernetes.io/arch = %q, want %q", tc.name, got, tc.want)
			}
			if got := n.Status.NodeInfo.Architecture; got != tc.want {
				t.Errorf("%s: NodeInfo.Architecture = %q, want %q", tc.name, got, tc.want)
			}
			// The label and NodeInfo are one derivation; they must never disagree.
			if n.Labels["kubernetes.io/arch"] != n.Status.NodeInfo.Architecture {
				t.Errorf("%s: label %q and NodeInfo.Architecture %q disagree",
					tc.name, n.Labels["kubernetes.io/arch"], n.Status.NodeInfo.Architecture)
			}
			// The rest of the node identity is untouched by the arch derivation.
			if n.Labels["kubernetes.io/os"] != "darwin" {
				t.Errorf("%s: kubernetes.io/os = %q, want darwin", tc.name, n.Labels["kubernetes.io/os"])
			}
		}
	})

	// The property that makes this gate non-vacuous: the reported arch is a function of
	// the HOST, not of the build. Two host-fact shapes must yield DIFFERENT answers, so
	// any constant-valued implementation — `return "arm64"` (the retired hardcode) or
	// `return runtime.GOARCH` (a constant per build, and amd64 under this workspace's
	// own Rosetta-translated toolchain) — fails at least one leg.
	t.Run("build_arch_independence", func(t *testing.T) {
		onApple, onIntel := nodeArch(nativeAppleSilicon), nodeArch(genuineIntel)
		if onApple == onIntel {
			t.Fatalf("nodeArch must distinguish hosts: apple silicon = %q, intel = %q — "+
				"an implementation returning a constant (e.g. runtime.GOARCH) would pass", onApple, onIntel)
		}
		if onApple == runtime.GOARCH && onIntel == runtime.GOARCH {
			t.Errorf("both legs equal runtime.GOARCH (%q): the table cannot detect a "+
				"runtime.GOARCH implementation", runtime.GOARCH)
		}
		// State the contradiction explicitly for the reader of a failure: whichever arch
		// this test binary was built for, exactly one leg disagrees with it.
		t.Logf("built for GOARCH=%s; derived arch is arm64 on apple-silicon facts and amd64 on intel facts",
			runtime.GOARCH)
	})

	// A failed host-fact read is a hiccup, not a misconfiguration: log and fall back to
	// the supported-platform arch so the node still registers with a usable
	// kubernetes.io/arch (an absent label strands every pod that selects on it).
	t.Run("probe_failure_falls_back", func(t *testing.T) {
		withHostArchFacts(t, hostArchFacts{}, errors.New("sysctl hw.machine: boom"))
		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})
		if got := n.Labels["kubernetes.io/arch"]; got != defaultNodeArch {
			t.Errorf("probe error: kubernetes.io/arch = %q, want the %q fallback", got, defaultNodeArch)
		}
		if got := n.Status.NodeInfo.Architecture; got != defaultNodeArch {
			t.Errorf("probe error: NodeInfo.Architecture = %q, want the %q fallback", got, defaultNodeArch)
		}
	})

	// An unrecognized machine string takes the same documented fallback (nodeArch
	// returned ""), never an empty or invented arch on the wire.
	t.Run("unrecognized_host_falls_back", func(t *testing.T) {
		withHostArchFacts(t, hostArchFacts{machine: "sparc"}, nil)
		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})
		if got := n.Labels["kubernetes.io/arch"]; got != defaultNodeArch {
			t.Errorf("unrecognized machine: kubernetes.io/arch = %q, want the %q fallback", got, defaultNodeArch)
		}
	})

	// B103 must not regress THROUGH THIS CHANGE: Rosetta capability never widens the
	// arch the node reports. The full four-corner proof lives in
	// TestRosettaLabelDeleteOnLoss; this leg pins the interaction the derivation could
	// plausibly break — a Rosetta-host-capable Apple Silicon node still reports arm64.
	t.Run("rosetta_capability_never_widens_arch", func(t *testing.T) {
		withHostArchFacts(t, nativeAppleSilicon, nil)
		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{
			RosettaHost: true, VMBackend: true, RosettaGuest: true,
		})
		if got := n.Labels["kubernetes.io/arch"]; got != "arm64" {
			t.Errorf("rosetta-capable node: kubernetes.io/arch = %q, want arm64", got)
		}
		if got := n.Status.NodeInfo.Architecture; got != "arm64" {
			t.Errorf("rosetta-capable node: NodeInfo.Architecture = %q, want arm64", got)
		}
		if got := n.Labels[runtimeclass.LabelRosetta]; got != runtimeclass.LabelTrue {
			t.Errorf("the translation capability must still be advertised via %s, got %q",
				runtimeclass.LabelRosetta, got)
		}
	})
}
