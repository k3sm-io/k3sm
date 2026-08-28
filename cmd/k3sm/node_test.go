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
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k3sm.io/darwin-net/pkg/dns"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// TestNodeInternalIP pins the globally-unicast NodeInternalIP derivation the VK
// node advertises so the apiserver node-proxy accepts `kubectl top node`
// (isProxyableHostname → IsGlobalUnicast rejects a loopback InternalIP): the
// node's reserved mesh-egress .1 for a valid /24, and "" (keep the loopback
// default, never invent an address) for a malformed or non-/24 podCIDR.
func TestNodeInternalIP(t *testing.T) {
	tests := []struct {
		name    string
		podCIDR string
		want    string
	}{
		{"index-0 /24", "100.64.0.0/24", "100.64.0.1"},
		{"index-2 /24", "100.64.2.0/24", "100.64.2.1"},
		{"empty", "", ""},
		{"malformed", "not-a-cidr", ""},
		{"not a /24 (MeshEgressIP requires /24)", "100.64.0.0/16", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nodeInternalIP(tt.podCIDR); got != tt.want {
				t.Errorf("nodeInternalIP(%q) = %q, want %q", tt.podCIDR, got, tt.want)
			}
		})
	}
}

// TestRuntimedConfiguresPostureVIPs proves the runtimed runtime is configured with
// the correct per-pod Seatbelt egress VIPs (the k3sm half of M3.3 deliverable 5):
// ResolverVIP is the cluster DNS VIP (10.43.0.10) — the same VIP the per-node
// resolver binds and pods resolve against — NOT runtimed's legacy default
// (10.96.0.10), and APIServerVIP is the kubernetes Service ClusterIP (10.43.0.1)
// derived from the cluster service CIDR. runtimed threads both into its per-pod
// sandbox.Posture, so without this a confined pod's DNS is scoped to the wrong VIP
// and in-pod kubectl has no API-server egress rule. Maps to M3.3-a1.
func TestRuntimedConfiguresPostureVIPs(t *testing.T) {
	t.Parallel()

	// server/agent pass the resolved --dns-vip + --cluster-domain values as the
	// resolver VIP and the in-pod shim search domain.
	cfg := runtimedConfig(nodeOptions{
		nodeName: "k3sm-worker",
		nodeIP:   "100.64.2.1",
		podRoot:  "/var/lib/k3sm/pods",
		dnsVIP:   "10.43.0.10",
		domain:   "corp.internal",
	}, nil)
	if cfg.ResolverVIP != "10.43.0.10" {
		t.Errorf("ResolverVIP = %q, want 10.43.0.10 (the cluster DNS VIP, not runtimed's 10.96.0.10 default)", cfg.ResolverVIP)
	}
	if cfg.APIServerVIP != "10.43.0.1" {
		t.Errorf("APIServerVIP = %q, want 10.43.0.1 (the kubernetes Service ClusterIP, first host of the service CIDR)", cfg.APIServerVIP)
	}
	// ClusterDomain PREFERS the threaded --cluster-domain (B18): a hardcoded
	// cluster.local under a custom domain would make every unqualified Service lookup
	// NXDOMAIN (the shim search list must match the resolver's served zone).
	if cfg.ClusterDomain != "corp.internal" {
		t.Errorf("ClusterDomain = %q, want corp.internal (the threaded --cluster-domain, not a hardcoded cluster.local)", cfg.ClusterDomain)
	}

	// An unset --dns-vip falls back to the cluster DNS VIP default, never to
	// runtimed's built-in 10.96.0.10 (which would scope pod DNS to the wrong VIP).
	if got := runtimedConfig(nodeOptions{}, nil).ResolverVIP; got != "10.43.0.10" {
		t.Errorf("ResolverVIP with no --dns-vip = %q, want the cluster DNS VIP default 10.43.0.10", got)
	}
	// An unset --cluster-domain falls back to the single-sourced dns.DefaultClusterDomain
	// (B42 wave 2): the SAME const the per-node resolver's empty-domain fallback resolves to,
	// so this k3sm-side fallback can never silently diverge from the served zone (the B18
	// desync the consolidation closes). A regression that re-hardcoded a different literal here
	// fails against the const, not a copy of it.
	if got := runtimedConfig(nodeOptions{}, nil).ClusterDomain; got != dns.DefaultClusterDomain {
		t.Errorf("ClusterDomain with no --cluster-domain = %q, want dns.DefaultClusterDomain (%q)", got, dns.DefaultClusterDomain)
	}

	// The API VIP is derived from the single service-CIDR const (10.43.0.0/16 ⇒
	// 10.43.0.1), so it tracks the CIDR rather than a second hardcoded literal.
	if got := apiServerVIP(); got != "10.43.0.1" {
		t.Errorf("apiServerVIP() = %q, want 10.43.0.1 (first host of the cluster service CIDR)", got)
	}
}

// TestRuntimedConfigPrefersExplicitShimFlags pins the OTHER half of the B151
// pod-support-shim wiring: an explicitly-passed --path-shim / --dns-shim must win
// over the sibling-dylib lookup.
//
// Both shims were previously resolved ONLY as siblings of the running executable
// (resolvePathShim / resolveDNSShim), and the path shim had no override at all. A
// `k3sm dev` server is THIS binary re-exec'd out of a `go build` output dir, so
// the sibling lookup finds nothing: every absolute volume-mount path ENOENTs
// in-pod (no path rebase) and every cluster Service name NXDOMAINs (no getaddrinfo
// interception). The flags are the only channel by which a dev cluster can stage
// the dylibs somewhere pod-readable (/Library — the pod Seatbelt read baseline)
// and still have the node use them.
func TestRuntimedConfigPrefersExplicitShimFlags(t *testing.T) {
	t.Parallel()

	cfg := runtimedConfig(nodeOptions{
		pathShim: "/Library/k3sm-dev/libk3sm_pathrebase_shim.dylib",
		dnsShim:  "/Library/k3sm-dev/libk3sm_getaddrinfo_shim.dylib",
	}, nil)
	if cfg.PathShim != "/Library/k3sm-dev/libk3sm_pathrebase_shim.dylib" {
		t.Errorf("PathShim = %q, want the explicit --path-shim (absolute volume mounts ENOENT in-pod without it)", cfg.PathShim)
	}
	if cfg.DyldShim != "/Library/k3sm-dev/libk3sm_getaddrinfo_shim.dylib" {
		t.Errorf("DyldShim = %q, want the explicit --dns-shim", cfg.DyldShim)
	}

	// With neither flag the sibling lookup is the fallback, and a from-source run
	// has no staged sibling — empty, which disables injection rather than pointing
	// dyld at a path that is not there (dyld fails CLOSED on a missing insert).
	bare := runtimedConfig(nodeOptions{}, nil)
	if bare.PathShim != resolvePathShim() {
		t.Errorf("PathShim with no flag = %q, want the sibling-dylib fallback %q", bare.PathShim, resolvePathShim())
	}
	if bare.DyldShim != resolveDNSShim() {
		t.Errorf("DyldShim with no flag = %q, want the sibling-dylib fallback %q", bare.DyldShim, resolveDNSShim())
	}
}

// TestNodeVirtualizationLabel is the M5.1 proof of the vm RuntimeClass
// node-capability gate: the k3sm.io/virtualization label is present (value "true")
// iff the node can run the Virtualization.framework backend, and ABSENT otherwise —
// so the vm RuntimeClass nodeSelector keeps a vm pod off a non-VZ node. It also pins
// the fail-closed default: configureNode with vmCapable=false (the runtimed
// VMBackendAvailable probe absent/false — B1) stamps NO virtualization label, so a vm
// pod stays Unschedulable.
func TestNodeVirtualizationLabel(t *testing.T) {
	t.Parallel()

	// Capable node ⇒ label present == "true".
	capable := &corev1.Node{}
	applyVirtualizationLabel(capable, true)
	if got := capable.Labels[runtimeclass.LabelVirtualization]; got != runtimeclass.LabelTrue {
		t.Errorf("vmCapable=true: label %s = %q, want %q", runtimeclass.LabelVirtualization, got, runtimeclass.LabelTrue)
	}

	// Not capable ⇒ label absent (cleared, even if previously set).
	incapable := &corev1.Node{}
	incapable.Labels = map[string]string{runtimeclass.LabelVirtualization: runtimeclass.LabelTrue, "kubernetes.io/os": "darwin"}
	applyVirtualizationLabel(incapable, false)
	if _, present := incapable.Labels[runtimeclass.LabelVirtualization]; present {
		t.Errorf("vmCapable=false: label %s must be absent (fail-closed), got present", runtimeclass.LabelVirtualization)
	}
	if incapable.Labels["kubernetes.io/os"] != "darwin" {
		t.Error("clearing the virtualization label must not disturb other node labels")
	}

	// configureNode threads the runtimed vm-capability probe (B1) — now carried in the
	// provider.NodeCapabilities struct (B103): the zero value ⇒ the label is ABSENT
	// (no VZ node ⇒ vm pods stay Unschedulable, fail-closed); VMBackend: true ⇒
	// present, so the vm RuntimeClass nodeSelector can bind.
	incapableNode := &corev1.Node{}
	configureNode(incapableNode, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})
	if _, present := incapableNode.Labels[runtimeclass.LabelVirtualization]; present {
		t.Errorf("configureNode(vmCapable=false) must NOT stamp the virtualization label, got present: %v", incapableNode.Labels)
	}
	capableNode := &corev1.Node{}
	configureNode(capableNode, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{VMBackend: true})
	if got := capableNode.Labels[runtimeclass.LabelVirtualization]; got != runtimeclass.LabelTrue {
		t.Errorf("configureNode(vmCapable=true): label %s = %q, want %q", runtimeclass.LabelVirtualization, got, runtimeclass.LabelTrue)
	}
}

// TestNodeCapacityFromHostMemory is the B13 proof that the node advertises REAL
// host memory (hw.memsize) in its Capacity instead of the prior hardcoded 8Gi (with
// B41's system-reserved Allocatable carve-out layered on top). nodeCapacity is
// exercised directly (pure, hermetic, no syscall), and the configureNode wiring is
// exercised through an injected hostMemBytes reader — including the documented 8Gi
// fallback on a failed or implausible host-fact read (which must never advertise a
// negative/garbage quantity).
//
// It is intentionally NOT t.Parallel: its subtests swap the hostMemBytes package
// var, and TestNodeVirtualizationLabel (which IS t.Parallel) calls configureNode,
// which reads that var. A non-parallel test runs entirely in the sequential phase,
// before the parked parallel tests resume, so the swap can never race their read.
func TestNodeCapacityFromHostMemory(t *testing.T) {
	const (
		gib      = int64(1024 * 1024 * 1024)
		eightGiB = 8 * gib // the documented fallback / the old hardcode
	)

	// nodeCapacity is pure: a non-8Gi value flows straight through. This is the
	// real red vs the old hardcode, which advertised 8Gi for every host.
	t.Run("nodeCapacity reflects the injected host memory (64GiB)", func(t *testing.T) {
		sixtyFour := 64 * gib
		got := nodeCapacity(8, uint64(sixtyFour), 110)

		cpu := got[corev1.ResourceCPU]
		if cpu.Value() != 8 {
			t.Errorf("cpu = %d, want 8", cpu.Value())
		}
		mem := got[corev1.ResourceMemory]
		if mem.Value() != sixtyFour {
			t.Errorf("memory = %d bytes, want %d (64GiB, not the 8Gi hardcode)", mem.Value(), sixtyFour)
		}
		if mem.Value() == eightGiB {
			t.Errorf("memory regressed to the 8Gi hardcode (%d); nodeCapacity ignored its memBytes argument", mem.Value())
		}
		pods := got[corev1.ResourcePods]
		if pods.Value() != 110 {
			t.Errorf("pods = %d, want 110", pods.Value())
		}
	})

	// A second, distinct non-8Gi value (16GiB) confirms the value is genuinely
	// threaded through rather than coincidentally matching one constant.
	t.Run("nodeCapacity threads a second distinct value (16GiB)", func(t *testing.T) {
		sixteen := 16 * gib
		got := nodeCapacity(4, uint64(sixteen), 110)
		mem := got[corev1.ResourceMemory]
		if mem.Value() != sixteen {
			t.Errorf("memory = %d bytes, want %d (16GiB)", mem.Value(), sixteen)
		}
	})

	// configureNode advertises the injected host memory as Capacity, and B41 holds back
	// a system-reserved memory carve-out so Allocatable memory < Capacity memory (cpu
	// and pods pass through unchanged & present). This INVERTS B13's prior Allocatable
	// == Capacity: the scheduler must not be able to commit 100% of RAM to pod requests
	// and starve the co-located control plane.
	t.Run("configureNode advertises host memory; Allocatable = Capacity - reserve (B41)", func(t *testing.T) {
		thirtyTwo := 32 * gib
		restore := hostMemBytes
		hostMemBytes = func() (uint64, error) { return uint64(thirtyTwo), nil }
		t.Cleanup(func() { hostMemBytes = restore })

		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})

		capMem := n.Status.Capacity[corev1.ResourceMemory]
		if capMem.Value() != thirtyTwo {
			t.Errorf("Capacity memory = %d, want %d (32GiB from the injected host read; Capacity stays the true hw.memsize)", capMem.Value(), thirtyTwo)
		}

		// Allocatable carries every Capacity resource — the memory-only carve-out drops none.
		if len(n.Status.Allocatable) != len(n.Status.Capacity) {
			t.Fatalf("Allocatable has %d resources, Capacity has %d", len(n.Status.Allocatable), len(n.Status.Capacity))
		}

		// Memory is held back by exactly the computed reserve: Allocatable == Capacity −
		// reserve, strictly LESS than Capacity (the B41 inversion of Allocatable == Capacity).
		wantReserve := memReserveBytes(thirtyTwo)
		allocMem := n.Status.Allocatable[corev1.ResourceMemory]
		if got, want := allocMem.Value(), thirtyTwo-wantReserve; got != want {
			t.Errorf("Allocatable memory = %d, want %d (Capacity %d − reserve %d)", got, want, thirtyTwo, wantReserve)
		}
		if allocMem.Value() >= capMem.Value() {
			t.Errorf("Allocatable memory (%d) must be strictly < Capacity memory (%d) after the B41 reserve", allocMem.Value(), capMem.Value())
		}

		// cpu and pods pass through unchanged: present in Allocatable AND == Capacity
		// (the reserve is memory-only).
		for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourcePods} {
			allocQ, ok := n.Status.Allocatable[name]
			if !ok {
				t.Errorf("Allocatable is missing %s present in Capacity (memory-only reserve must not drop it)", name)
				continue
			}
			capQ := n.Status.Capacity[name]
			if capQ.Cmp(allocQ) != 0 {
				t.Errorf("Allocatable[%s] = %s, want == Capacity[%s] = %s (memory-only reserve)", name, allocQ.String(), name, capQ.String())
			}
		}
	})

	// The fallback path: a failed host-fact read (sysctl error) must not fail the
	// node — configureNode logs and advertises the documented 8Gi default.
	t.Run("read error falls back to the 8Gi default", func(t *testing.T) {
		restore := hostMemBytes
		hostMemBytes = func() (uint64, error) { return 0, errors.New("sysctl hw.memsize: boom") }
		t.Cleanup(func() { hostMemBytes = restore })

		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})

		mem := n.Status.Capacity[corev1.ResourceMemory]
		if mem.Value() != eightGiB {
			t.Errorf("on read error, Capacity memory = %d, want %d (8Gi fallback)", mem.Value(), eightGiB)
		}
	})

	// A garbage read larger than math.MaxInt64 would convert to a NEGATIVE int64
	// quantity; the guard must reject it and fall back to 8Gi rather than advertise
	// a non-positive capacity.
	t.Run("implausible (>maxInt64) read falls back, never a negative quantity", func(t *testing.T) {
		restore := hostMemBytes
		hostMemBytes = func() (uint64, error) { return math.MaxUint64, nil }
		t.Cleanup(func() { hostMemBytes = restore })

		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})

		mem := n.Status.Capacity[corev1.ResourceMemory]
		if mem.Value() <= 0 {
			t.Errorf("guard failed: built a non-positive memory quantity (%d) from a >maxInt64 read", mem.Value())
		}
		if mem.Value() != eightGiB {
			t.Errorf("on implausible read, Capacity memory = %d, want %d (8Gi fallback)", mem.Value(), eightGiB)
		}
	})

	// A zero read (another implausible host fact) also falls back.
	t.Run("zero read falls back to the 8Gi default", func(t *testing.T) {
		restore := hostMemBytes
		hostMemBytes = func() (uint64, error) { return 0, nil }
		t.Cleanup(func() { hostMemBytes = restore })

		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{})

		mem := n.Status.Capacity[corev1.ResourceMemory]
		if mem.Value() != eightGiB {
			t.Errorf("on zero read, Capacity memory = %d, want %d (8Gi fallback)", mem.Value(), eightGiB)
		}
	})
}

// TestConfigureNodeTopologyLabels proves configureNode advertises the well-known GA
// topology labels (B16): topology.kubernetes.io/zone and .../region. The load-bearing
// assertion is that zone is set to THIS node's name — byte-identical to
// kubernetes.io/hostname by construction — so it is a per-node failure domain, not a
// shared static zone (which would FALSELY claim co-located Macs are co-failing, and
// would make a whenUnsatisfiable: DoNotSchedule zone-spread strand pods Pending instead
// of degrading to host-spread). region is the single static value all nodes agree on.
func TestConfigureNodeTopologyLabels(t *testing.T) {
	t.Parallel()

	const host = "k3sm-node"
	node := &corev1.Node{}
	configureNode(node, host, "10.0.0.1", provider.NodeCapabilities{})

	// zone == the node name AND == the hostname label, by construction: this locks the
	// per-node zone==hostname coupling. A shared-static-zone regression fails here.
	if got := node.Labels[corev1.LabelTopologyZone]; got != host {
		t.Errorf("%s = %q, want %q (the node name — a per-node failure domain)", corev1.LabelTopologyZone, got, host)
	}
	if zone, hostname := node.Labels[corev1.LabelTopologyZone], node.Labels[corev1.LabelHostname]; zone != hostname {
		t.Errorf("zone (%s=%q) must equal hostname (%s=%q) by construction; a shared static zone would falsely claim co-located Macs share a failure domain",
			corev1.LabelTopologyZone, zone, corev1.LabelHostname, hostname)
	}

	// region is the single static value (k3sm has no cloud-region concept).
	if got := node.Labels[corev1.LabelTopologyRegion]; got != defaultNodeRegion {
		t.Errorf("%s = %q, want %q (defaultNodeRegion)", corev1.LabelTopologyRegion, got, defaultNodeRegion)
	}
}

// TestNodeAllocatableReserve is the B41 proof of the node system-reserved memory
// carve-out. nodeAllocatable holds back a memory reserve from Allocatable for the
// CO-LOCATED control plane (so the scheduler cannot commit 100% of RAM to pod requests
// and starve apiserver/scheduler/KCM/kine/runtimed), and memReserveBytes sizes that
// reserve as max(2Gi, 10% of capacity). It is pure and hermetic (no syscall, no
// configureNode, no hostMemBytes swap) so it — and its subtests — run parallel: the
// FLOOR assertion, the DeepCopy-not-alias guard, and the positive clamp are the resolved
// CRITICALs (under-reserving re-admits jetsam killing the control plane; a zero/negative
// Allocatable would strand every pod Pending).
func TestNodeAllocatableReserve(t *testing.T) {
	t.Parallel()

	const (
		gib  = int64(1024 * 1024 * 1024)
		twoG = 2 * gib // == defaultMemReserveBytes, the floor
	)

	// nodeAllocatable math: memory == Capacity − reserve, cpu/pods unchanged & present,
	// Allocatable < Capacity, and the input capacity map is NOT mutated (DeepCopy guard).
	t.Run("nodeAllocatable holds back memory only and never mutates capacity", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name      string
			capMemB   int64
			cpu       int64
			pods      int64
			reserveB  int64
			wantAlloc int64
		}{
			{"64Gi cap, 6Gi reserve", 64 * gib, 10, 110, 6 * gib, 64*gib - 6*gib},
			{"16Gi cap, 2Gi reserve", 16 * gib, 8, 110, twoG, 16*gib - twoG},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				capacity := corev1.ResourceList{
					corev1.ResourceCPU:    *resource.NewQuantity(tc.cpu, resource.DecimalSI),
					corev1.ResourceMemory: *resource.NewQuantity(tc.capMemB, resource.BinarySI),
					corev1.ResourcePods:   *resource.NewQuantity(tc.pods, resource.DecimalSI),
				}
				alloc := nodeAllocatable(capacity, tc.reserveB)

				if am := alloc[corev1.ResourceMemory]; am.Value() != tc.wantAlloc {
					t.Errorf("Allocatable memory = %d, want %d (Capacity %d − reserve %d)", am.Value(), tc.wantAlloc, tc.capMemB, tc.reserveB)
				}
				if am := alloc[corev1.ResourceMemory]; am.Value() >= tc.capMemB {
					t.Errorf("Allocatable memory (%d) must be strictly < Capacity memory (%d)", am.Value(), tc.capMemB)
				}
				// cpu and pods pass through unchanged: present AND equal to Capacity.
				if ac, ok := alloc[corev1.ResourceCPU]; !ok {
					t.Error("Allocatable missing cpu (memory-only reserve must not drop it)")
				} else if ac.Value() != tc.cpu {
					t.Errorf("Allocatable cpu = %d, want %d (unchanged)", ac.Value(), tc.cpu)
				}
				if ap, ok := alloc[corev1.ResourcePods]; !ok {
					t.Error("Allocatable missing pods (memory-only reserve must not drop it)")
				} else if ap.Value() != tc.pods {
					t.Errorf("Allocatable pods = %d, want %d (unchanged)", ap.Value(), tc.pods)
				}
				// every Capacity key survives in Allocatable.
				if len(alloc) != len(capacity) {
					t.Errorf("Allocatable has %d resources, want %d (every Capacity key must survive)", len(alloc), len(capacity))
				}
				// the input capacity map MUST be unmodified: nodeAllocatable writes
				// out[memory], which would clobber capacity[memory] if out aliased the
				// same backing map instead of DeepCopy-ing it.
				if cm := capacity[corev1.ResourceMemory]; cm.Value() != tc.capMemB {
					t.Errorf("input capacity memory mutated to %d, want %d (nodeAllocatable must DeepCopy, not alias)", cm.Value(), tc.capMemB)
				}
			})
		}
	})

	// memReserveBytes sizing — assert the FLOOR (the conformance/sre CRITICAL), not just
	// the arithmetic: a too-small reserve re-admits jetsam killing the co-located control plane.
	t.Run("memReserveBytes = max(2Gi, 10%): floor wins small, pct wins large", func(t *testing.T) {
		t.Parallel()
		// 8Gi host: 10% = 0.8Gi < 2Gi ⇒ the 2Gi floor dominates.
		if got, want := memReserveBytes(8*gib), twoG; got != want {
			t.Errorf("memReserveBytes(8Gi) = %d, want %d (the 2Gi floor dominates: 10%% of 8Gi = 0.8Gi < 2Gi)", got, want)
		}
		// 64Gi host: 10% = 6.4Gi > 2Gi ⇒ the 10% term dominates.
		if got, want := memReserveBytes(64*gib), (64*gib)/10; got != want {
			t.Errorf("memReserveBytes(64Gi) = %d, want %d (10%% of 64Gi = 6.4Gi > the 2Gi floor)", got, want)
		}
		// The floor is NEVER undercut, on any host size.
		for _, capB := range []int64{gib, 8 * gib, 16 * gib, 64 * gib} {
			if got := memReserveBytes(capB); got < defaultMemReserveBytes {
				t.Errorf("memReserveBytes(%d) = %d, must be >= the 2Gi floor %d (never under-reserve)", capB, got, defaultMemReserveBytes)
			}
		}
	})

	// Positive clamp: a reserve >= capacity on a pathologically tiny host must floor
	// Allocatable at minAllocatableMemBytes (512Mi), strictly > 0 — never zero/negative
	// (which would strand every pod Pending forever).
	t.Run("tiny capacity clamps Allocatable to the positive floor, never <= 0", func(t *testing.T) {
		t.Parallel()
		capacity := corev1.ResourceList{
			corev1.ResourceCPU:    *resource.NewQuantity(4, resource.DecimalSI),
			corev1.ResourceMemory: *resource.NewQuantity(gib, resource.BinarySI), // 1Gi
			corev1.ResourcePods:   *resource.NewQuantity(110, resource.DecimalSI),
		}
		alloc := nodeAllocatable(capacity, twoG) // reserve 2Gi > 1Gi capacity
		am := alloc[corev1.ResourceMemory]
		if am.Value() != minAllocatableMemBytes {
			t.Errorf("Allocatable memory = %d, want the %d floor (reserve 2Gi >= 1Gi capacity)", am.Value(), minAllocatableMemBytes)
		}
		if am.Value() <= 0 {
			t.Errorf("clamp failed: Allocatable memory = %d, must be strictly > 0 (a zero/negative Allocatable strands every pod Pending)", am.Value())
		}
	})
}

// TestNodeStartupBoundedAndDiagnostic pins the bounded startup wait (B158).
//
// Before this, startNode blocked FOREVER in a select on the VK node's Ready
// channel vs its Run error: observed live 2026-08-27, a node whose VK run loop
// was healthy but which had never created its Node object left the process
// silent after "starting k3sm node", `kubectl get node` empty, and every pod
// Unschedulable with no clue in any log. The wait is now bounded and names what
// it saw. It does NOT diagnose WHY registration failed — that is separate work.
func TestNodeStartupBoundedAndDiagnostic(t *testing.T) {
	const (
		nodeName = "k3sm-lab-1"
		listen   = "127.0.0.1:10250"
		// Short deadlines keep the test fast; the shipped value is
		// nodeStartupTimeout, pinned separately below.
		testTimeout = 50 * time.Millisecond
	)
	boom := errors.New("apiserver dial refused")

	t.Run("wedged node is bounded and named", func(t *testing.T) {
		// Neither channel ever fires — the observed wedge exactly: VK alive,
		// no Ready, no error.
		ready := make(chan struct{})
		errc := make(chan error, 1)

		start := time.Now()
		err := awaitNodeReady(context.Background(), ready, errc, testTimeout, nodeName, listen)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("wedged startup returned nil; want a bounded error")
		}
		if !errors.Is(err, errNodeStartupTimeout) {
			t.Errorf("err = %v; want errNodeStartupTimeout", err)
		}
		if elapsed > 20*testTimeout {
			t.Errorf("waited %s for a %s deadline; the wait is not bounded", elapsed, testTimeout)
		}
		// The message alone must tell an operator which channel never fired,
		// what was last observed, and which node/listener it was.
		for _, want := range []string{nodeName, listen, "neither ready nor exit", "Ready channel never closed", "Run loop has not returned"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("diagnostic %q lacks %q", err.Error(), want)
			}
		}
	})

	t.Run("ready returns promptly with no error", func(t *testing.T) {
		ready := make(chan struct{})
		close(ready)
		errc := make(chan error, 1)

		start := time.Now()
		if err := awaitNodeReady(context.Background(), ready, errc, time.Hour, nodeName, listen); err != nil {
			t.Fatalf("healthy startup: %v", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("healthy startup took %s; want prompt", elapsed)
		}
	})

	t.Run("early run error keeps the existing wrapping", func(t *testing.T) {
		ready := make(chan struct{})
		errc := make(chan error, 1)
		errc <- boom

		err := awaitNodeReady(context.Background(), ready, errc, time.Hour, nodeName, listen)
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v; want it to wrap %v", err, boom)
		}
		if errors.Is(err, errNodeStartupTimeout) {
			t.Errorf("run-loop error %v misreported as a startup timeout", err)
		}
		if got := err.Error(); !strings.HasPrefix(got, "node exited during startup: ") {
			t.Errorf("err = %q; want the unchanged \"node exited during startup\" prefix", got)
		}
	})

	t.Run("cancellation wins over the deadline", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := awaitNodeReady(ctx, make(chan struct{}), make(chan error, 1), time.Hour, nodeName, listen)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v; want context.Canceled", err)
		}
	})

	t.Run("shipped deadline clears the observed distributions", func(t *testing.T) {
		// Healthy bring-up is seconds; the observed wedge was still stuck at
		// 3 minutes. Keep the shipped value clear of both, in both directions.
		if nodeStartupTimeout <= 3*time.Minute {
			t.Errorf("nodeStartupTimeout = %s; must exceed the 3m the observed wedge survived", nodeStartupTimeout)
		}
		if nodeStartupTimeout > 15*time.Minute {
			t.Errorf("nodeStartupTimeout = %s; too long to be a useful bound", nodeStartupTimeout)
		}
	})
}

// writeNodeRESTKubeconfig writes a minimal kubeconfig pointing at server and returns
// its path, so the tests below drive the real nodeRESTConfig loader rather than
// hand-building a rest.Config the shipped path never sees.
func writeNodeRESTKubeconfig(t *testing.T, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
current-context: k3sm
users:
- name: k3sm
  user: {}
`, server)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// TestNodeRESTClientHasTimeout pins a request timeout on the rest.Config the
// node's apiserver clientset is built from (B161).
//
// clientcmd.BuildConfigFromFlags leaves rest.Config.Timeout at zero ("no
// timeout"), and nothing else in the node path set one — so a stalled HTTPS
// request to the loopback apiserver (a half-open socket, a listener that
// accepted but never answered) blocked its caller forever and logged nothing.
// Virtual Kubelet's node registration is exactly such an unbounded round-trip.
// This makes a stall a bounded, reported error; it does NOT claim to diagnose or
// fix any particular registration failure.
func TestNodeRESTClientHasTimeout(t *testing.T) {
	t.Run("the node rest config carries a request timeout", func(t *testing.T) {
		cfg, err := nodeRESTConfig(writeNodeRESTKubeconfig(t, "https://127.0.0.1:6443"))
		if err != nil {
			t.Fatalf("nodeRESTConfig: %v", err)
		}
		if cfg.Timeout == 0 {
			t.Fatal("rest.Config.Timeout = 0 (no timeout): a stalled apiserver round-trip hangs the node forever")
		}
		if cfg.Timeout != nodeAPIRequestTimeout {
			t.Errorf("rest.Config.Timeout = %s, want nodeAPIRequestTimeout %s", cfg.Timeout, nodeAPIRequestTimeout)
		}
	})

	t.Run("the timeout reaches the http client the node clientset dials with", func(t *testing.T) {
		// kubernetes.NewForConfig builds its transport via rest.HTTPClientFor(cfg),
		// so asserting there proves the value is carried end-to-end into every
		// request the node makes — not merely stored in a constant.
		cfg, err := nodeRESTConfig(writeNodeRESTKubeconfig(t, "https://127.0.0.1:6443"))
		if err != nil {
			t.Fatalf("nodeRESTConfig: %v", err)
		}
		hc, err := rest.HTTPClientFor(cfg)
		if err != nil {
			t.Fatalf("HTTPClientFor: %v", err)
		}
		if hc.Timeout != nodeAPIRequestTimeout {
			t.Errorf("http.Client.Timeout = %s, want %s: the timeout does not reach the node's transport", hc.Timeout, nodeAPIRequestTimeout)
		}
		if _, err := kubernetes.NewForConfig(cfg); err != nil {
			t.Fatalf("the timed-out config must still build a clientset: %v", err)
		}
	})

	t.Run("the value clears healthy latency and stays well inside the startup bound", func(t *testing.T) {
		// Floor: the apiserver's own --request-timeout default is 60s, so a
		// shorter client bound could pre-empt a request the server is still
		// legitimately serving — turning a slow-but-healthy start into a failure.
		if nodeAPIRequestTimeout < 60*time.Second {
			t.Errorf("nodeAPIRequestTimeout = %s; must be >= the apiserver's 60s default --request-timeout so the server, not the client, ends a slow-but-served request", nodeAPIRequestTimeout)
		}
		// Ceiling: it must surface a wedged round-trip well before the sibling
		// startup bound, not silently consume it.
		if nodeAPIRequestTimeout > nodeStartupTimeout/2 {
			t.Errorf("nodeAPIRequestTimeout = %s; must stay well under nodeStartupTimeout %s", nodeAPIRequestTimeout, nodeStartupTimeout)
		}
	})

	t.Run("a stalled apiserver round-trip errors instead of hanging", func(t *testing.T) {
		// A server that accepts and never answers — the observed stall shape.
		// stall releases the handler at teardown: httptest.Server.Close waits for
		// in-flight requests, and on a REGRESSION (no timeout) the client never
		// cancels, so without this the failing test would deadlock in Close
		// instead of reporting.
		stall := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-stall:
			}
		}))
		defer srv.Close()
		defer close(stall)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg, err := nodeRESTConfig(writeNodeRESTKubeconfig(t, srv.URL))
		if err != nil {
			t.Fatalf("nodeRESTConfig: %v", err)
		}
		// Scale the shipped bound down so the test is fast. The FIELD exercised is
		// the one nodeRESTConfig sets, and an unset (zero) Timeout scales to zero —
		// so this subtest hangs into its guard rather than passing vacuously.
		cfg.Timeout /= 600
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			t.Fatalf("build client: %v", err)
		}

		done := make(chan error, 1)
		go func() {
			_, gerr := cs.CoreV1().Nodes().Get(ctx, "k3sm-lab-1", metav1.GetOptions{})
			done <- gerr
		}()
		select {
		case gerr := <-done:
			if gerr == nil {
				t.Fatal("stalled Get returned nil error; want a timeout error")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Get against a stalled apiserver was still pending after 5s: the node client has no request timeout")
		}
	})
}
