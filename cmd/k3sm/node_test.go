package main

import (
	"testing"
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

	// server/agent pass the resolved --dns-vip value as the resolver VIP.
	cfg := runtimedConfig(nodeOptions{
		nodeName: "k3sm-worker",
		nodeIP:   "100.64.2.1",
		podRoot:  "/var/lib/k3sm/pods",
		dnsVIP:   "10.43.0.10",
	}, nil)
	if cfg.ResolverVIP != "10.43.0.10" {
		t.Errorf("ResolverVIP = %q, want 10.43.0.10 (the cluster DNS VIP, not runtimed's 10.96.0.10 default)", cfg.ResolverVIP)
	}
	if cfg.APIServerVIP != "10.43.0.1" {
		t.Errorf("APIServerVIP = %q, want 10.43.0.1 (the kubernetes Service ClusterIP, first host of the service CIDR)", cfg.APIServerVIP)
	}

	// An unset --dns-vip falls back to the cluster DNS VIP default, never to
	// runtimed's built-in 10.96.0.10 (which would scope pod DNS to the wrong VIP).
	if got := runtimedConfig(nodeOptions{}, nil).ResolverVIP; got != "10.43.0.10" {
		t.Errorf("ResolverVIP with no --dns-vip = %q, want the cluster DNS VIP default 10.43.0.10", got)
	}

	// The API VIP is derived from the single service-CIDR const (10.43.0.0/16 ⇒
	// 10.43.0.1), so it tracks the CIDR rather than a second hardcoded literal.
	if got := apiServerVIP(); got != "10.43.0.1" {
		t.Errorf("apiServerVIP() = %q, want 10.43.0.1 (first host of the cluster service CIDR)", got)
	}
}
