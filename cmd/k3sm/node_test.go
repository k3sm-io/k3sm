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
