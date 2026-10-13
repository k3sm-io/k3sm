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
	"net"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/nodecred"
	"k3sm.io/k3sm/pkg/ports"
	"k3sm.io/k3sm/pkg/provider"
)

// TestKubeletListensOnNodeAddress is the gate for the kubelet API listener: on a
// `k3sm server` or `k3sm agent` node the listener binds exactly the address the
// node registers as its InternalIP (proxyableNodeIP), in every posture, and
// never the wildcard. A joined node binds its ASSIGNED mesh address, never an
// asserted --node-ip; a single node binds its lo0 pod-range address, never a
// host LAN address; and an address missing from this Mac at start is the named
// errKubeletAddress, not a fallback.
func TestKubeletListensOnNodeAddress(t *testing.T) {
	const (
		lanAddr  = "192.0.2.10" // a Wi-Fi address: the one place the API must not be
		asserted = "192.0.2.60" // an operator-asserted --node-ip that was never assigned
	)
	direct := hostnet.Mode{Backend: hostnet.BackendDirect}
	none := hostnet.Mode{Backend: hostnet.BackendNone}

	// agree resolves opts and asserts the three views of the address are one value.
	agree := func(t *testing.T, opts nodeOptions, want string) {
		t.Helper()
		ep, err := resolveKubeletEndpoint(opts)
		if err != nil {
			t.Fatalf("resolveKubeletEndpoint: %v", err)
		}
		port := opts.kubeletPort
		if wantListen := net.JoinHostPort(want, strconv.Itoa(port)); ep.listen != wantListen {
			t.Errorf("kubelet API listens on %q, want %q", ep.listen, wantListen)
		}
		host, _, err := net.SplitHostPort(ep.listen)
		if err != nil || host == "" || net.ParseIP(host).IsUnspecified() {
			t.Fatalf("kubelet API listen %q is the wildcard", ep.listen)
		}
		advertised := opts
		advertised.nodeIP = advertisedNodeIP(opts)
		if got := proxyableNodeIP(advertised); got != want || ep.internalIP != want {
			t.Errorf("proxyableNodeIP = %q, endpoint InternalIP = %q, want both %q", got, ep.internalIP, want)
		}
		n := &corev1.Node{}
		configureNode(n, "k3sm-node", ep.internalIP, ep.listen, provider.NodeCapabilities{})
		var registered string
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				registered = a.Address
			}
		}
		if registered != want {
			t.Errorf("Node registers InternalIP %q, want the listen address %q", registered, want)
		}
		if got := n.Status.DaemonEndpoints.KubeletEndpoint.Port; got != int32(port) {
			t.Errorf("Node advertises kubelet port %d, want %d", got, port)
		}
	}

	t.Run("joined agent binds its assigned mesh address", func(t *testing.T) {
		stubLocalAddrs(t, "127.0.0.1", lanAddr, asserted, "100.64.2.1")
		res := &bootstrap.JoinResult{NodeIP: "100.64.2.1", MeshIP: "100.64.2.1", PodCIDR: "100.64.2.0/24"}
		opts := agentNodeOptions(agentOptions{nodeName: "worker", nodeIP: asserted}, res, "/k", direct, nil)
		agree(t, opts, "100.64.2.1")
	})

	t.Run("address-mismatch credential binds the assignment, not the asserted address", func(t *testing.T) {
		stubLocalAddrs(t, "127.0.0.1", lanAddr, asserted, "100.64.3.1")
		cred := &nodeCredential{Assignment: nodecred.Assignment{MeshIP: "100.64.3.1", PodCIDR: "100.64.3.0/24"}}
		res := joinResultFrom(cred, "worker", "", "")
		opts := agentNodeOptions(agentOptions{nodeName: "worker", nodeIP: asserted}, res, "/k", direct, nil)
		agree(t, opts, "100.64.3.1")
	})

	t.Run("mesh server binds its mesh address", func(t *testing.T) {
		stubLocalAddrs(t, "127.0.0.1", lanAddr, "100.64.0.1")
		nodeIP := meshNodeIP(serverOptions{nodeIP: loopbackNodeIP, meshIP: "100.64.0.1"})
		agree(t, nodeOptions{nodeIP: nodeIP, kubeletPort: 10450, podCIDR: "100.64.0.0/24", netMode: direct}, "100.64.0.1")
	})

	t.Run("single node binds its lo0 pod-range address, not the LAN", func(t *testing.T) {
		stubLocalAddrs(t, "127.0.0.1", lanAddr, "100.64.0.1")
		agree(t, nodeOptions{nodeIP: loopbackNodeIP, kubeletPort: ports.KubeletAPIPort, podCIDR: "100.64.0.0/24", netMode: direct}, "100.64.0.1")
	})

	t.Run("single node with no pod network binds loopback", func(t *testing.T) {
		stubLocalAddrs(t, "127.0.0.1", lanAddr)
		agree(t, nodeOptions{nodeIP: loopbackNodeIP, kubeletPort: ports.KubeletAPIPort, podCIDR: "100.64.0.0/24", netMode: none}, loopbackNodeIP)
	})

	refused := []struct {
		name  string
		addrs []string
		opts  nodeOptions
	}{
		{
			name:  "single node whose lo0 address is missing",
			addrs: []string{"127.0.0.1", lanAddr},
			opts:  nodeOptions{nodeIP: loopbackNodeIP, kubeletPort: ports.KubeletAPIPort, podCIDR: "100.64.0.0/24", netMode: direct},
		},
		{
			name:  "joined agent with no mesh up",
			addrs: []string{"127.0.0.1", lanAddr, asserted},
			opts: agentNodeOptions(agentOptions{nodeName: "worker", nodeIP: asserted},
				&bootstrap.JoinResult{MeshIP: "100.64.2.1", PodCIDR: "100.64.2.0/24"}, "/k", none, nil),
		},
		{
			name:  "a join that named no address",
			addrs: []string{"127.0.0.1", lanAddr},
			opts:  agentNodeOptions(agentOptions{nodeName: "worker"}, &bootstrap.JoinResult{}, "/k", direct, nil),
		},
		{
			// The credential loader requires only the podCIDR, so a stored
			// assignment can lack a meshIP: the asserted --node-ip, present on
			// this Mac, must still never become the kubelet's address.
			name:  "a stored assignment with no meshIP",
			addrs: []string{"127.0.0.1", lanAddr, asserted},
			opts: agentNodeOptions(agentOptions{nodeName: "worker", nodeIP: asserted},
				joinResultFrom(&nodeCredential{Assignment: nodecred.Assignment{PodCIDR: "100.64.3.0/24"}}, "worker", "", ""), "/k", direct, nil),
		},
		{
			// A server that predates the NodeIP field echoes the asserted value
			// back in JoinResult.NodeIP; it is not an assignment.
			name:  "a join result whose only address is the asserted one",
			addrs: []string{"127.0.0.1", lanAddr, asserted},
			opts: agentNodeOptions(agentOptions{nodeName: "worker", nodeIP: asserted},
				&bootstrap.JoinResult{NodeIP: asserted, PodCIDR: "100.64.3.0/24"}, "/k", direct, nil),
		},
		{
			name:  "an unspecified node address",
			addrs: []string{"127.0.0.1", lanAddr},
			opts:  nodeOptions{nodeIP: "0.0.0.0", kubeletPort: ports.KubeletAPIPort, netMode: none},
		},
	}
	for _, tc := range refused {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			stubLocalAddrs(t, tc.addrs...)
			ep, err := resolveKubeletEndpoint(tc.opts)
			if !errors.Is(err, errKubeletAddress) {
				t.Fatalf("resolveKubeletEndpoint = %+v, %v; want errKubeletAddress", ep, err)
			}
			if ep.listen != "" {
				t.Errorf("a refusal still produced a listen address %q", ep.listen)
			}
		})
	}
}

// TestCredInternalIPFallback pins when credInternalIP's flag fallback is used:
// only when the stored assignment carries no meshIP, which the credential loader
// permits. It feeds the wireguard endpoint exclusion, never the kubelet listener.
func TestCredInternalIPFallback(t *testing.T) {
	withMesh := &nodeCredential{Assignment: nodecred.Assignment{PodCIDR: "100.64.3.0/24", MeshIP: "100.64.3.1"}}
	if got := credInternalIP(withMesh, "192.0.2.60"); got != "100.64.3.1" {
		t.Errorf("credInternalIP with a stored meshIP = %q, want the assignment", got)
	}
	noMesh := &nodeCredential{Assignment: nodecred.Assignment{PodCIDR: "100.64.3.0/24"}}
	if got := credInternalIP(noMesh, "192.0.2.60"); got != "192.0.2.60" {
		t.Errorf("credInternalIP without a stored meshIP = %q, want the flag fallback", got)
	}
	if got := credInternalIP(nil, ""); got != "" {
		t.Errorf("credInternalIP(nil) = %q, want empty", got)
	}
	if got := agentInternalIP(joinResultFrom(noMesh, "worker", "", "")); got != "" {
		t.Errorf("agentInternalIP for a stored assignment with no meshIP = %q, want empty (the kubelet then refuses)", got)
	}
}
