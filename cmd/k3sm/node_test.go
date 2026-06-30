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
	"math"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/runtimeclass"
)

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
	// An unset --cluster-domain falls back to the canonical cluster.local default.
	if got := runtimedConfig(nodeOptions{}, nil).ClusterDomain; got != "cluster.local" {
		t.Errorf("ClusterDomain with no --cluster-domain = %q, want the cluster.local default", got)
	}

	// The API VIP is derived from the single service-CIDR const (10.43.0.0/16 ⇒
	// 10.43.0.1), so it tracks the CIDR rather than a second hardcoded literal.
	if got := apiServerVIP(); got != "10.43.0.1" {
		t.Errorf("apiServerVIP() = %q, want 10.43.0.1 (first host of the cluster service CIDR)", got)
	}
}

// TestNodeVirtualizationLabel is the M5.1 proof of the vm RuntimeClass
// node-capability gate: the k3sm.io/virtualization label is present (value "true")
// iff the node can run the Virtualization.framework backend, and ABSENT otherwise —
// so the vm RuntimeClass nodeSelector keeps a vm pod off a non-VZ node. It also pins
// the foundation's fail-closed default: nodeVMCapable() is false here (k3sm has no
// per-backend availability signal from runtimed yet), so a freshly configured node
// carries NO virtualization label and a vm pod stays Unschedulable.
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

	// The foundation default is ABSENT: nodeVMCapable() is false, so configureNode
	// stamps no virtualization label (no VZ node ⇒ vm pods stay Unschedulable).
	if nodeVMCapable() {
		t.Error("nodeVMCapable() must be false on this foundation (no runtimed per-backend availability signal); the label is sourced truthfully, never faked")
	}
	node := &corev1.Node{}
	configureNode(node, "k3sm-node", "10.0.0.1")
	if _, present := node.Labels[runtimeclass.LabelVirtualization]; present {
		t.Errorf("configureNode must NOT stamp the virtualization label while nodeVMCapable() is false, got present: %v", node.Labels)
	}
}

// TestNodeCapacityFromHostMemory is the B13 proof that the node advertises REAL
// host memory (hw.memsize) in its Capacity/Allocatable instead of the prior
// hardcoded 8Gi. nodeCapacity is exercised directly (pure, hermetic, no syscall),
// and the configureNode wiring is exercised through an injected hostMemBytes
// reader — including the documented 8Gi fallback on a failed or implausible
// host-fact read (which must never advertise a negative/garbage quantity).
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

	// configureNode advertises the injected host memory and pins Allocatable ==
	// Capacity. B15's system-reserved carve-out (Allocatable < Capacity) must be a
	// deliberate future diff, not introduced here.
	t.Run("configureNode advertises host memory; Allocatable == Capacity", func(t *testing.T) {
		thirtyTwo := 32 * gib
		restore := hostMemBytes
		hostMemBytes = func() (uint64, error) { return uint64(thirtyTwo), nil }
		t.Cleanup(func() { hostMemBytes = restore })

		n := &corev1.Node{}
		configureNode(n, "k3sm-node", "10.0.0.1")

		mem := n.Status.Capacity[corev1.ResourceMemory]
		if mem.Value() != thirtyTwo {
			t.Errorf("Capacity memory = %d, want %d (32GiB from the injected host read)", mem.Value(), thirtyTwo)
		}

		if len(n.Status.Allocatable) != len(n.Status.Capacity) {
			t.Fatalf("Allocatable has %d resources, Capacity has %d", len(n.Status.Allocatable), len(n.Status.Capacity))
		}
		for name, capQ := range n.Status.Capacity {
			allocQ, ok := n.Status.Allocatable[name]
			if !ok {
				t.Errorf("Allocatable is missing %s present in Capacity", name)
				continue
			}
			if capQ.Cmp(allocQ) != 0 {
				t.Errorf("Allocatable[%s] = %s, want == Capacity[%s] = %s (B15 reserve deferred)", name, allocQ.String(), name, capQ.String())
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
		configureNode(n, "k3sm-node", "10.0.0.1")

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
		configureNode(n, "k3sm-node", "10.0.0.1")

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
		configureNode(n, "k3sm-node", "10.0.0.1")

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
	configureNode(node, host, "10.0.0.1")

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
