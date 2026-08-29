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

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/ports"
)

// testPorts is a fixed allocation for the argv tests that are not ABOUT the
// allocator — every value distinct, so a flag wired to the wrong member shows up
// as a wrong number rather than a coincidence.
var testPorts = instancePorts{api: 7443, kine: 12379, kubelet: 10450, scheduler: 11450, controllerManager: 13450}

func TestAllocatePortsStableAndDisjoint(t *testing.T) {
	sys := newFakeSystem()
	got, err := allocatePorts(sys, "dev", 501)
	if err != nil {
		t.Fatalf("allocatePorts: %v", err)
	}
	// Deterministic seed: a re-run for the same (name, euid) prefers the same ports.
	again, err := allocatePorts(sys, "dev", 501)
	if err != nil {
		t.Fatalf("allocatePorts (2nd): %v", err)
	}
	if got != again {
		t.Errorf("ports not stable: %+v vs %+v", got, again)
	}
	for _, w := range []struct {
		name string
		port int
		base int
	}{
		{"api", got.api, apiPortBase},
		{"kine", got.kine, kinePortBase},
		{"kubelet", got.kubelet, kubeletPortBase},
		{"scheduler", got.scheduler, schedulerPortBase},
		{"controller-manager", got.controllerManager, controllerManagerPortBase},
	} {
		if w.port < w.base || w.port >= w.base+portSpan {
			t.Errorf("%s port %d out of window [%d,%d)", w.name, w.port, w.base, w.base+portSpan)
		}
	}
	// Pairwise disjoint: two listeners handed the same number is one instance
	// contending with ITSELF, which no probe of a free port would ever catch.
	for i, a := range allPorts(got) {
		for _, b := range allPorts(got)[i+1:] {
			if a.port == b.port {
				t.Errorf("%s and %s share port %d", a.name, b.name, a.port)
			}
		}
	}
}

// allPorts flattens an allocation for the pairwise assertions. It is spelled out
// rather than reflected so a NEW port added to instancePorts without a row here
// stays visibly unchecked instead of silently appearing covered.
func allPorts(p instancePorts) []struct {
	name string
	port int
} {
	return []struct {
		name string
		port int
	}{
		{"api", p.api},
		{"kine", p.kine},
		{"kubelet", p.kubelet},
		{"scheduler", p.scheduler},
		{"controller-manager", p.controllerManager},
	}
}

func TestAllocatePortsDistinctPerName(t *testing.T) {
	sys := newFakeSystem()
	a, _ := allocatePorts(sys, "a", 501)
	b, _ := allocatePorts(sys, "b", 501)
	apiA, apiB := a.api, b.api
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

	a, b := twoLiveInstances(t, sys)
	if a.kine == b.kine {
		t.Fatalf("both instances allocated datastore port %d — they would share one datastore", a.kine)
	}

	for _, tc := range []struct {
		name  string
		alloc instancePorts
	}{{"a", a}, {"b", b}} {
		t.Run(tc.name, func(t *testing.T) {
			args := serverArgs(tc.name, "/w", "/pods", tc.alloc, "none", runtimeRuntimed, "", "")
			got, ok := argvFlagValue(args, "--kine-port")
			if !ok {
				t.Fatalf("serverArgs = %v, want a --kine-port flag (without it kine binds the fixed server default)", args)
			}
			if want := strconv.Itoa(tc.alloc.kine); got != want {
				t.Errorf("--kine-port = %q, want the allocated port %q", got, want)
			}
		})
	}
}

// twoLiveInstances allocates for instance "a", marks every port it took as BOUND,
// then allocates for "b". Holding a's ports is the condition the second allocation
// actually has to survive — a test that only changed the name would be satisfied by
// two different hash seeds and would still pass if the probe ignored the host.
func twoLiveInstances(t *testing.T, sys *fakeSystem) (a, b instancePorts) {
	t.Helper()
	a, err := allocatePorts(sys, "a", 501)
	if err != nil {
		t.Fatalf("allocatePorts(a): %v", err)
	}
	for _, p := range allPorts(a) {
		sys.busyPorts[p.port] = true
	}
	b, err = allocatePorts(sys, "b", 501)
	if err != nil {
		t.Fatalf("allocatePorts(b): %v", err)
	}
	return a, b
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

	a, b := twoLiveInstances(t, sys)
	if a.kubelet == b.kubelet {
		t.Fatalf("both instances allocated kubelet port %d — the second node would die on the bind", a.kubelet)
	}
	// The allocation must also clear the upstream fixed defaults, which a probe
	// walking a whole window could otherwise wander onto.
	for _, p := range []int{a.kubelet, b.kubelet} {
		for _, fixed := range []int{ports.KubeletAPIPort, executor.DefaultControllerManagerPort, executor.DefaultSchedulerPort} {
			if p == fixed {
				t.Errorf("allocated kubelet port %d is a fixed control-plane singleton — it collides by construction", p)
			}
		}
	}

	for _, tc := range []struct {
		name  string
		alloc instancePorts
	}{{"a", a}, {"b", b}} {
		t.Run(tc.name, func(t *testing.T) {
			args := serverArgs(tc.name, "/w", "/pods", tc.alloc, "none", runtimeRuntimed, "", "")
			got, ok := argvFlagValue(args, "--kubelet-port")
			if !ok {
				t.Fatalf("serverArgs = %v, want a --kubelet-port flag (without it every instance's node binds the fixed default)", args)
			}
			if want := strconv.Itoa(tc.alloc.kubelet); got != want {
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

// TestDevAllocatesControlPlanePorts is the scheduler + controller-manager half of
// per-instance listener isolation — the last two fixed singletons a `k3sm server`
// owned — and it pins four things.
//
// FIRST, two instances get DIFFERENT ports for both components. Second, ALL five
// of an instance's ports are pairwise disjoint: this is the assertion that scales,
// because each port added to the set is another chance for one instance to contend
// with itself, and a probe that only ever asks "is this port free on the host" can
// never notice that answer coming from its own other listener.
//
// THIRD, each port reaches the detached server's argv. Allocating without emitting
// is the exact defect this class keeps reproducing: the allocator looks correct,
// the manifest records a plausible number, and the component binds the fixed
// default anyway.
//
// FOURTH — and this is why the test reaches into the executor's own rendering — the
// bind stays on LOOPBACK. These two components serve /healthz and /metrics over
// HTTPS to the co-located control plane and to nothing else, so renumbering their
// ports must never become the edit that publishes them. dev chooses a port and
// passes nothing else; the executor renders 127.0.0.1 for whatever port it is
// given. Both halves are asserted, so widening either one reds here.
func TestDevAllocatesControlPlanePorts(t *testing.T) {
	sys := newFakeSystem()
	a, b := twoLiveInstances(t, sys)

	if a.scheduler == b.scheduler {
		t.Errorf("both instances allocated scheduler port %d — the second scheduler would die on the bind", a.scheduler)
	}
	if a.controllerManager == b.controllerManager {
		t.Errorf("both instances allocated controller-manager port %d — the second KCM would die on the bind, and the symptom appears at the namespace bootstrap", a.controllerManager)
	}
	// Neither may land on the upstream fixed default, which is what a host running
	// an unrelated control plane already holds.
	for _, c := range []struct {
		name  string
		ports []int
		fixed int
	}{
		{"scheduler", []int{a.scheduler, b.scheduler}, executor.DefaultSchedulerPort},
		{"controller-manager", []int{a.controllerManager, b.controllerManager}, executor.DefaultControllerManagerPort},
	} {
		for _, p := range c.ports {
			if p == c.fixed {
				t.Errorf("allocated %s port %d is the fixed default — it collides by construction", c.name, p)
			}
		}
	}
	// All five, pairwise, per instance.
	for _, inst := range []struct {
		name  string
		alloc instancePorts
	}{{"a", a}, {"b", b}} {
		list := allPorts(inst.alloc)
		for i, x := range list {
			for _, y := range list[i+1:] {
				if x.port == y.port {
					t.Errorf("instance %s: %s and %s both on port %d", inst.name, x.name, y.name, x.port)
				}
			}
		}
	}

	for _, tc := range []struct {
		name  string
		alloc instancePorts
	}{{"a", a}, {"b", b}} {
		t.Run(tc.name, func(t *testing.T) {
			args := serverArgs(tc.name, "/w", "/pods", tc.alloc, "none", runtimeRuntimed, "", "")
			for _, f := range []struct {
				flag string
				want int
			}{
				{"--scheduler-port", tc.alloc.scheduler},
				{"--controller-manager-port", tc.alloc.controllerManager},
			} {
				got, ok := argvFlagValue(args, f.flag)
				if !ok {
					t.Fatalf("serverArgs = %v, want a %s flag (without it the component binds the fixed server default)", args, f.flag)
				}
				if want := strconv.Itoa(f.want); got != want {
					t.Errorf("%s = %q, want the allocated port %q", f.flag, got, want)
				}
				// A bare port, not an address: dev renumbers a listener, it does not
				// choose where one answers.
				if _, err := strconv.Atoi(got); err != nil || strings.ContainsAny(got, ":[]") {
					t.Errorf("%s = %q, want a bare port number", f.flag, got)
				}

				// The POSITIVE half of the loopback posture, read off the argv the
				// executor actually renders for that port.
				serving := executor.LoopbackServingArgs(f.want)
				bind, ok := argvFlagValue(serving, "--bind-address")
				if !ok {
					t.Fatalf("LoopbackServingArgs(%d) = %v, want a --bind-address flag: an unbound component listens on every interface", f.want, serving)
				}
				if bind != "127.0.0.1" {
					t.Errorf("LoopbackServingArgs(%d) binds %q, want 127.0.0.1 — these components serve only the co-located control plane, and a port change must never publish them", f.want, bind)
				}
				if port, ok := argvFlagValue(serving, "--secure-port"); !ok || port != strconv.Itoa(f.want) {
					t.Errorf("LoopbackServingArgs(%d) --secure-port = %q (present=%v), want %d", f.want, port, ok, f.want)
				}
			}
			// The NEGATIVE half: dev passes no address knob for either component, so
			// there is no dev-side route to moving them off loopback at all.
			for _, banned := range []string{
				"--bind-address", "--scheduler-bind-address", "--controller-manager-bind-address",
				"--scheduler-address", "--controller-manager-address", "--secure-port", "--address",
			} {
				if slices.Contains(args, banned) {
					t.Errorf("serverArgs = %v, must not carry %s: where these components listen is not dev's to set", args, banned)
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
