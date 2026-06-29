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
		cfg := workerNetserveConfig(opts, res, hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/run/netd.sock"}, nil)
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
		cfg := workerNetserveConfig(opts, res, hostnet.Mode{Backend: hostnet.BackendNone}, nil)
		if !cfg.Disabled {
			t.Error("Disabled = false, want true (--network none runs no datapath)")
		}
		if cfg.NetdSocket != "" {
			t.Errorf("NetdSocket = %q, want empty (no helper in --network none)", cfg.NetdSocket)
		}
	})
}
