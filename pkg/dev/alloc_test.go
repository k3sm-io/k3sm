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

package dev

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/ports"
)

func TestAllocatePortsStableAndDisjoint(t *testing.T) {
	sys := newFakeSystem()
	api, kine, kubelet, err := allocatePorts(sys, "dev", 501)
	if err != nil {
		t.Fatalf("allocatePorts: %v", err)
	}
	// Deterministic seed: a re-run for the same (name, euid) prefers the same ports.
	api2, kine2, kubelet2, err := allocatePorts(sys, "dev", 501)
	if err != nil {
		t.Fatalf("allocatePorts (2nd): %v", err)
	}
	if api != api2 || kine != kine2 || kubelet != kubelet2 {
		t.Errorf("ports not stable: (%d,%d,%d) vs (%d,%d,%d)", api, kine, kubelet, api2, kine2, kubelet2)
	}
	if api == kine || api == kubelet || kine == kubelet {
		t.Errorf("allocated ports collide: api=%d kine=%d kubelet=%d", api, kine, kubelet)
	}
	if api < apiPortBase || api >= apiPortBase+portSpan {
		t.Errorf("api port %d out of window [%d,%d)", api, apiPortBase, apiPortBase+portSpan)
	}
	if kine < kinePortBase || kine >= kinePortBase+portSpan {
		t.Errorf("kine port %d out of window [%d,%d)", kine, kinePortBase, kinePortBase+portSpan)
	}
	if kubelet < kubeletPortBase || kubelet >= kubeletPortBase+portSpan {
		t.Errorf("kubelet port %d out of window [%d,%d)", kubelet, kubeletPortBase, kubeletPortBase+portSpan)
	}
}

func TestAllocatePortsDistinctPerName(t *testing.T) {
	sys := newFakeSystem()
	apiA, _, _, _ := allocatePorts(sys, "a", 501)
	apiB, _, _, _ := allocatePorts(sys, "b", 501)
	// Two different names should not deterministically pick the SAME preferred
	// port (parallel rootless instances). A hash collision is astronomically
	// unlikely; assert they differ.
	if apiA == apiB {
		t.Errorf("distinct names got the same api port %d (parallel instances would collide)", apiA)
	}
}

func TestProbeFreePortSkipsBusy(t *testing.T) {
	sys := newFakeSystem()
	// Mark the first two candidate ports at the base busy; the probe must skip them.
	sys.busyPorts[apiPortBase] = true
	sys.busyPorts[apiPortBase+1] = true
	got, err := probeFreePort(sys, apiPortBase, 0)
	if err != nil {
		t.Fatalf("probeFreePort: %v", err)
	}
	if got == apiPortBase || got == apiPortBase+1 {
		t.Errorf("probeFreePort returned a busy port %d", got)
	}
	if !sys.PortFree(got) {
		t.Errorf("probeFreePort returned a non-free port %d", got)
	}
}

func TestProbeFreePortSaturated(t *testing.T) {
	sys := newFakeSystem()
	for i := 0; i < portSpan; i++ {
		sys.busyPorts[apiPortBase+i] = true
	}
	if _, err := probeFreePort(sys, apiPortBase, 0); err == nil {
		t.Error("probeFreePort on a saturated window = nil, want an error")
	}
}

func TestLo0FlushCIDRsRemovesOnlyInRange(t *testing.T) {
	sys := newFakeSystem()
	sys.aliases = []string{
		"127.0.0.1",    // loopback — never touched
		"10.43.0.10",   // Service VIP — flush
		"100.64.0.5",   // pod IP — flush
		"192.168.1.20", // LAN — never touched
	}
	removed, err := lo0FlushCIDRs(sys, ServiceCIDR, PodCIDR)
	if err != nil {
		t.Fatalf("lo0FlushCIDRs: %v", err)
	}
	want := []string{"10.43.0.10", "100.64.0.5"}
	if !reflect.DeepEqual(removed, want) {
		t.Errorf("removed = %v, want %v", removed, want)
	}
	// 127.0.0.1 and the LAN address must survive.
	rest, _ := sys.Lo0Aliases()
	for _, keep := range []string{"127.0.0.1", "192.168.1.20"} {
		found := false
		for _, a := range rest {
			if a == keep {
				found = true
			}
		}
		if !found {
			t.Errorf("flush removed out-of-range alias %s", keep)
		}
	}
}

func TestLo0FlushCIDRsEmptyIsNoop(t *testing.T) {
	sys := newFakeSystem()
	sys.aliases = []string{"10.43.0.10"}
	// No CIDRs → nothing to match, no listing needed.
	removed, err := lo0FlushCIDRs(sys)
	if err != nil {
		t.Fatalf("lo0FlushCIDRs(): %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %v, want none for empty CIDR set", removed)
	}
}

func TestHasAliasInCIDRs(t *testing.T) {
	sys := newFakeSystem()
	present, err := hasAliasInCIDRs(sys, ServiceCIDR, PodCIDR)
	if err != nil {
		t.Fatalf("hasAliasInCIDRs: %v", err)
	}
	if present {
		t.Error("hasAliasInCIDRs = true with no aliases, want false")
	}
	sys.aliases = []string{"100.64.0.1"}
	present, err = hasAliasInCIDRs(sys, ServiceCIDR, PodCIDR)
	if err != nil {
		t.Fatalf("hasAliasInCIDRs: %v", err)
	}
	if !present {
		t.Error("hasAliasInCIDRs = false with a pod-CIDR alias present, want true (singleton assert)")
	}
}

// TestDevPassesAllocatedKinePort pins BOTH halves of per-instance datastore
// isolation: two instances get different datastore ports, and the allocated port
// actually reaches the detached server's argv. Without the argv half the
// allocation is dead code — every instance's kine targets the one fixed server
// default, so the second instance up contends for the first one's datastore.
func TestDevPassesAllocatedKinePort(t *testing.T) {
	sys := newFakeSystem()

	apiA, kineA, kubeletA, err := allocatePorts(sys, "a", 501)
	if err != nil {
		t.Fatalf("allocatePorts(a): %v", err)
	}
	// Instance "a" is now up, so its ports are bound — which is the real condition
	// the second allocation must probe past, not merely a different hash seed.
	sys.busyPorts[apiA] = true
	sys.busyPorts[kineA] = true
	sys.busyPorts[kubeletA] = true
	apiB, kineB, kubeletB, err := allocatePorts(sys, "b", 501)
	if err != nil {
		t.Fatalf("allocatePorts(b): %v", err)
	}
	if kineA == kineB {
		t.Fatalf("both instances allocated datastore port %d — they would share one datastore", kineA)
	}

	for _, tc := range []struct {
		name        string
		apiPort     int
		kinePort    int
		kubeletPort int
	}{
		{"a", apiA, kineA, kubeletA},
		{"b", apiB, kineB, kubeletB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := serverArgs(tc.name, "/w", "/pods", tc.apiPort, tc.kinePort, tc.kubeletPort, "none", runtimeRuntimed, "", "")
			got, ok := argvFlagValue(args, "--kine-port")
			if !ok {
				t.Fatalf("serverArgs = %v, want a --kine-port flag (without it kine binds the fixed server default)", args)
			}
			if want := strconv.Itoa(tc.kinePort); got != want {
				t.Errorf("--kine-port = %q, want the allocated port %q", got, want)
			}
		})
	}
}

// TestDevAllocatesKubeletPort is the kubelet half of per-instance listener
// isolation, and it pins three things at once.
//
// Two instances must get DIFFERENT kubelet-API ports, and each must carry its own
// into the detached server's argv. The node's logs/exec/stats listener is a
// per-node singleton: on the one fixed default the second instance reached a
// healthy control plane and then died at `node exited during startup: … listen
// tcp :10250: bind: address already in use`, observed on a live two-instance run.
// Allocating without emitting would leave the same defect with a busier allocator.
//
// The third is the POSTURE, and it is the reason this test asserts a negative as
// well as a positive: dev hands the server a bare PORT and nothing else. It emits
// no listen address, no bind address, and no authn/authz flag for that listener,
// so renumbering the port cannot become the vector by which an exec/logs surface
// starts answering somewhere it did not answer before. The wildcard bind and the
// authn model of that API are the server's own, decided elsewhere; a dev argv
// that started carrying either would red here.
func TestDevAllocatesKubeletPort(t *testing.T) {
	sys := newFakeSystem()

	apiA, kineA, kubeletA, err := allocatePorts(sys, "a", 501)
	if err != nil {
		t.Fatalf("allocatePorts(a): %v", err)
	}
	// Instance "a" is up, so its ports are HELD — the real condition the second
	// allocation must probe past, not merely a different hash seed.
	sys.busyPorts[apiA] = true
	sys.busyPorts[kineA] = true
	sys.busyPorts[kubeletA] = true
	apiB, kineB, kubeletB, err := allocatePorts(sys, "b", 501)
	if err != nil {
		t.Fatalf("allocatePorts(b): %v", err)
	}
	if kubeletA == kubeletB {
		t.Fatalf("both instances allocated kubelet port %d — the second node would die on the bind", kubeletA)
	}
	// The allocation must also clear the fixed control-plane singletons: the
	// kubelet default itself and the scheduler/controller-manager ports every
	// instance's control plane still binds.
	for _, p := range []int{kubeletA, kubeletB} {
		for _, fixed := range []int{ports.KubeletAPIPort, 10257, 10259} {
			if p == fixed {
				t.Errorf("allocated kubelet port %d is a fixed control-plane singleton — it collides by construction", p)
			}
		}
	}

	for _, tc := range []struct {
		name        string
		apiPort     int
		kinePort    int
		kubeletPort int
	}{
		{"a", apiA, kineA, kubeletA},
		{"b", apiB, kineB, kubeletB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := serverArgs(tc.name, "/w", "/pods", tc.apiPort, tc.kinePort, tc.kubeletPort, "none", runtimeRuntimed, "", "")
			got, ok := argvFlagValue(args, "--kubelet-port")
			if !ok {
				t.Fatalf("serverArgs = %v, want a --kubelet-port flag (without it every instance's node binds the fixed default)", args)
			}
			if want := strconv.Itoa(tc.kubeletPort); got != want {
				t.Errorf("--kubelet-port = %q, want the allocated port %q", got, want)
			}

			// POSTURE: the value is a bare port. An address here would mean dev is
			// choosing where that listener answers.
			if _, err := strconv.Atoi(got); err != nil {
				t.Errorf("--kubelet-port = %q, want a bare port number: dev renumbers a port, it does not choose a bind address", got)
			}
			if strings.ContainsAny(got, ":[]") {
				t.Errorf("--kubelet-port = %q looks like an address, not a port — dev must not move the kubelet bind", got)
			}
			// POSTURE: and it is the ONLY kubelet-listener knob dev passes.
			for _, banned := range []string{
				"--listen", "--kubelet-listen", "--kubelet-address", "--kubelet-bind-address",
				"--bind-address", "--kubelet-authn", "--kubelet-authz",
				"--anonymous-auth", "--kubelet-anonymous-auth", "--read-only-port",
			} {
				if slices.Contains(args, banned) {
					t.Errorf("serverArgs = %v, must not carry %s: the kubelet API's bind address and auth posture are not dev's to set", args, banned)
				}
			}
		})
	}
}

// argvFlagValue returns the value following flag in args.
func argvFlagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}
