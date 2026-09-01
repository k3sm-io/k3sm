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
	"flag"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/netserve"
)

// TestM3_3_WorkerNetserveConfig proves a joined worker constructs its node-local
// datapath (the Service proxy + per-node cluster DNS) with the right join-derived
// inputs — the M3.3-a1 worker-bringup wiring. The gap M3.3 closes is that the
// agent path ran NO netserve, so a worker had no proxy and no DNS; this asserts the
// config the worker now feeds netserve.New: the proxy's backend-dial source is this
// node's assigned mesh-egress /32 (so cross-node dials are not blackholed by
// wireguard), the routing locality is its assigned pod /24, and the privileged ops
// route through the netd helper when unprivileged. The live join is the m3.sh lab leg.
func TestM3_3_WorkerNetserveConfig(t *testing.T) {
	t.Parallel()

	opts := agentOptions{
		workDir:   "/var/lib/k3sm/agent",
		nodeIP:    "100.64.2.1",
		clusterIP: "10.43.0.10",
		domain:    "cluster.local",
	}
	res := &bootstrap.JoinResult{PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1"}

	t.Run("unprivileged helper worker", func(t *testing.T) {
		t.Parallel()
		cfg := workerNetserveConfig(opts, res, hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/run/netd.sock"}, false, nil)
		if cfg.MeshEgressIP != res.MeshIP {
			t.Errorf("MeshEgressIP = %q, want %q (the join-assigned mesh-egress /32)", cfg.MeshEgressIP, res.MeshIP)
		}
		if cfg.PodCIDR != res.PodCIDR {
			t.Errorf("PodCIDR = %q, want %q (the join-assigned pod /24)", cfg.PodCIDR, res.PodCIDR)
		}
		if cfg.NetdSocket != "/run/netd.sock" {
			t.Errorf("NetdSocket = %q, want /run/netd.sock (helper posture)", cfg.NetdSocket)
		}
		if cfg.Disabled {
			t.Error("Disabled = true, want false (the helper datapath is live)")
		}
		if cfg.DNSVIP != "10.43.0.10" || cfg.ClusterDomain != "cluster.local" {
			t.Errorf("DNS config = (%q,%q), want (10.43.0.10, cluster.local)", cfg.DNSVIP, cfg.ClusterDomain)
		}

		// The worker's netserve actually builds a proxy + DNS: it hands pods the
		// cluster DNS VIP (so a pod on the worker resolves cluster names).
		cfg.Client = fake.NewClientset()
		srv := netserve.New(cfg)
		if got := srv.PodDNSConfig("default").ClusterDNSIP; got != "10.43.0.10" {
			t.Errorf("worker pod DNSConfig ClusterDNSIP = %q, want 10.43.0.10", got)
		}
	})

	t.Run("network none worker", func(t *testing.T) {
		t.Parallel()
		cfg := workerNetserveConfig(opts, res, hostnet.Mode{Backend: hostnet.BackendNone}, false, nil)
		if !cfg.Disabled {
			t.Error("Disabled = false, want true (--network none runs no datapath)")
		}
		if cfg.NetdSocket != "" {
			t.Errorf("NetdSocket = %q, want empty (no helper in --network none)", cfg.NetdSocket)
		}
	})
}

// TestAgentPathShimFlag pins the B159 half of the pod-support-shim wiring on the
// WORKER path: `k3sm agent` accepts --path-shim, threads it to its in-process
// node, and gives it the SAME precedence `k3sm server` / `k3sm node` use — an
// explicit flag wins, else the sibling-dylib lookup.
//
// Fails-before: the agent registered --dns-shim only. A joined worker therefore
// had NO override for the path-rebase shim, so a worker whose k3sm binary has no
// staged sibling dylib (a from-source or `k3sm dev` run) silently ENOENTed every
// ABSOLUTE volume-mount path in-pod, with no argv by which to fix it.
func TestAgentPathShimFlag(t *testing.T) {
	t.Parallel()

	const staged = "/Library/k3sm-dev/libk3sm_pathrebase_shim.dylib"

	// parseAgent registers the real agent flag surface and parses argv through it.
	parseAgent := func(t *testing.T, args ...string) agentOptions {
		t.Helper()
		fs := flag.NewFlagSet("agent", flag.ContinueOnError)
		var opts agentOptions
		registerAgentFlags(fs, &opts)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("parse %v: %v (is --path-shim registered on `k3sm agent`?)", args, err)
		}
		return opts
	}

	res := &bootstrap.JoinResult{PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1"}

	t.Run("explicit --path-shim wins and reaches the node runtime", func(t *testing.T) {
		t.Parallel()
		opts := parseAgent(t, "--path-shim", staged)
		if opts.pathShim != staged {
			t.Fatalf("agent --path-shim = %q, want %q", opts.pathShim, staged)
		}
		nodeOpts := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
		if nodeOpts.pathShim != staged {
			t.Errorf("worker nodeOptions.pathShim = %q, want %q (the flag must reach the in-process node)", nodeOpts.pathShim, staged)
		}
		if got := runtimedConfig(nodeOpts, nil).PathShim; got != staged {
			t.Errorf("worker RuntimedConfig.PathShim = %q, want the explicit --path-shim %q", got, staged)
		}
	})

	t.Run("no flag falls back to the sibling dylib, like server and node", func(t *testing.T) {
		t.Parallel()
		opts := parseAgent(t)
		if opts.pathShim != "" {
			t.Errorf("agent --path-shim default = %q, want empty", opts.pathShim)
		}
		nodeOpts := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
		if got := runtimedConfig(nodeOpts, nil).PathShim; got != resolvePathShim() {
			t.Errorf("worker RuntimedConfig.PathShim with no flag = %q, want the sibling-dylib fallback %q", got, resolvePathShim())
		}
	})

	t.Run("the dns shim sibling still threads (no regression)", func(t *testing.T) {
		t.Parallel()
		const dnsStaged = "/Library/k3sm-dev/libk3sm_getaddrinfo_shim.dylib"
		opts := parseAgent(t, "--dns-shim", dnsStaged)
		nodeOpts := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
		if got := runtimedConfig(nodeOpts, nil).DyldShim; got != dnsStaged {
			t.Errorf("worker RuntimedConfig.DyldShim = %q, want the explicit --dns-shim %q", got, dnsStaged)
		}
	})
}
