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
	"strconv"
	"testing"
)

func TestAllocatePortsStableAndDisjoint(t *testing.T) {
	sys := newFakeSystem()
	api, kine, err := allocatePorts(sys, "dev", 501)
	if err != nil {
		t.Fatalf("allocatePorts: %v", err)
	}
	// Deterministic seed: a re-run for the same (name, euid) prefers the same ports.
	api2, kine2, err := allocatePorts(sys, "dev", 501)
	if err != nil {
		t.Fatalf("allocatePorts (2nd): %v", err)
	}
	if api != api2 || kine != kine2 {
		t.Errorf("ports not stable: (%d,%d) vs (%d,%d)", api, kine, api2, kine2)
	}
	if api == kine {
		t.Errorf("api and kine ports collide on %d", api)
	}
	if api < apiPortBase || api >= apiPortBase+portSpan {
		t.Errorf("api port %d out of window [%d,%d)", api, apiPortBase, apiPortBase+portSpan)
	}
	if kine < kinePortBase || kine >= kinePortBase+portSpan {
		t.Errorf("kine port %d out of window [%d,%d)", kine, kinePortBase, kinePortBase+portSpan)
	}
}

func TestAllocatePortsDistinctPerName(t *testing.T) {
	sys := newFakeSystem()
	apiA, _, _ := allocatePorts(sys, "a", 501)
	apiB, _, _ := allocatePorts(sys, "b", 501)
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

	apiA, kineA, err := allocatePorts(sys, "a", 501)
	if err != nil {
		t.Fatalf("allocatePorts(a): %v", err)
	}
	// Instance "a" is now up, so its ports are bound — which is the real condition
	// the second allocation must probe past, not merely a different hash seed.
	sys.busyPorts[apiA] = true
	sys.busyPorts[kineA] = true
	apiB, kineB, err := allocatePorts(sys, "b", 501)
	if err != nil {
		t.Fatalf("allocatePorts(b): %v", err)
	}
	if kineA == kineB {
		t.Fatalf("both instances allocated datastore port %d — they would share one datastore", kineA)
	}

	for _, tc := range []struct {
		name     string
		apiPort  int
		kinePort int
	}{
		{"a", apiA, kineA},
		{"b", apiB, kineB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := serverArgs(tc.name, "/w", "/pods", tc.apiPort, tc.kinePort, "none", runtimeRuntimed, "", "")
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

// argvFlagValue returns the value following flag in args.
func argvFlagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}
