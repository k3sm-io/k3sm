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
	"os"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/netserve"
)

// testNetserve builds a Server the way a bring-up does, minus the cluster.
func testNetserve(t *testing.T) *netserve.Server {
	t.Helper()
	return netserve.New(netserve.Config{
		Client:  fake.NewClientset(),
		WorkDir: t.TempDir(),
		DNSVIP:  "10.43.0.10",
		PodCIDR: "100.64.0.0/24",
	})
}

// TestVMDatapathWiring is the B237 wiring gate for the cmd half of the guest-lease
// chain: the node-local datapath must be told this node's vm posture, and the
// in-process node must be given the Server to publish vm-pod transport overrides
// into. Neither is derivable later — netserve is constructed steps BEFORE the VK
// node exists — so both are decided here.
//
// The fails-before state was a worker/server whose netserve got neither field:
// the NetworkPolicy table was never scoped to the guests' NAT segment, and the
// provider's transport feed was inert on every node, so a lease reported by a
// guest agent reached no proxy and a vm pod's published /32 was undialable.
func TestVMDatapathWiring(t *testing.T) {
	t.Parallel()

	opts := agentOptions{
		workDir:   "/var/lib/k3sm/agent",
		nodeIP:    "100.64.2.1",
		clusterIP: "10.43.0.10",
		domain:    "cluster.local",
	}
	res := &bootstrap.JoinResult{PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1"}
	helper := hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/run/netd.sock"}
	none := hostnet.Mode{Backend: hostnet.BackendNone}

	t.Run("the worker datapath carries the node's vm posture", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name      string
			vmCapable bool
		}{
			{"vm-capable node arms the scoped policy table", true},
			{"non-vm node keeps the plain table", false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				cfg := workerNetserveConfig(opts, res, helper, tc.vmCapable, nil)
				if cfg.VMBackend != tc.vmCapable {
					t.Errorf("VMBackend = %v, want %v (the probe's verdict must reach the table)", cfg.VMBackend, tc.vmCapable)
				}
				// The segment rides unconditionally — it is a host fact, and the
				// selection ANDs it with VMBackend — so a non-vm node stays plain
				// while carrying it.
				if cfg.VMNetSubnet != netserve.DefaultVMNetSubnet {
					t.Errorf("VMNetSubnet = %q, want the one named constant %q", cfg.VMNetSubnet, netserve.DefaultVMNetSubnet)
				}
			})
		}
	})

	t.Run("the override sink is the datapath, and only when there is one", func(t *testing.T) {
		t.Parallel()
		srv := testNetserve(t)
		if got := nodeTransportOverrides(srv, helper); got != srv {
			t.Errorf("nodeTransportOverrides(server, datapath) = %v, want the Server itself", got)
		}
		if got := nodeTransportOverrides(srv, none); got != nil {
			t.Errorf("nodeTransportOverrides(server, --network none) = %v, want nil — there is no proxy to feed", got)
		}
		// A nil Server must yield a nil INTERFACE, not an interface holding a typed
		// nil: the provider tests its sink for nil to run the feed inert, and a
		// typed nil would pass that test and then panic on the first override.
		if got := nodeTransportOverrides(nil, helper); got != nil {
			t.Errorf("nodeTransportOverrides(nil, datapath) = %v, want an untyped nil interface", got)
		}
	})

	t.Run("the worker's in-process node is handed that sink", func(t *testing.T) {
		t.Parallel()
		srv := testNetserve(t)
		nodeOpts := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", helper, srv)
		if got := runtimedConfig(nodeOpts, nil).TransportOverrides; got != srv {
			t.Errorf("worker RuntimedConfig.TransportOverrides = %v, want the node-local datapath Server", got)
		}

		// `--network none`: the join runs no datapath, so the feed stays inert.
		bare := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", none, nil)
		if got := runtimedConfig(bare, nil).TransportOverrides; got != nil {
			t.Errorf("--network none RuntimedConfig.TransportOverrides = %v, want nil", got)
		}
	})

	// `k3sm server` builds its nodeOptions as an inline literal inside runServer,
	// which stands up a control plane and cannot be called from a unit test — so
	// the only mechanical hold on that path is the source itself. This is
	// deliberately a shape check, not a behaviour one: it cannot prove the wiring
	// works, only that it has not been deleted from the bring-up that no test can
	// call. The behaviour is proven on the agent path above, which uses the same
	// two helpers.
	t.Run("both bring-ups wire the datapath's vm posture and its override sink", func(t *testing.T) {
		t.Parallel()
		for _, file := range []string{"server.go", "agent.go"} {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			src := string(b)
			for _, want := range []string{
				"vmBackendAvailable()",        // the safe probe, before netserve.New
				"netserve.DefaultVMNetSubnet", // the one named segment constant
				"VMBackend:",                  // ...reaching the datapath config
				"nodeTransportOverrides(",     // the sink decision
				"transportOverrides:",         // ...reaching the in-process node
			} {
				if !strings.Contains(src, want) {
					t.Errorf("%s no longer contains %q; the vm datapath wiring was removed from a bring-up "+
						"no unit test can call, so nothing else would have caught it", file, want)
				}
			}
		}
	})
}
