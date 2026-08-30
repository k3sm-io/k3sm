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
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/ports"
	"k3sm.io/k3sm/pkg/provider"
)

// devKubeletPort is a port from the per-instance kubelet window `k3sm dev`
// allocates from (pkg/dev: base 10450, span 512). It is a LITERAL on purpose —
// deriving it from the allocator would make this test agree with whatever that
// package computes, where the property under test is that the node advertises
// whatever port it was told to bind, from ANY source.
const devKubeletPort = 10800

// TestNodeKubeletEndpointMatchesTheListener pins the one invariant that makes
// `kubectl logs`, `kubectl exec` and `kubectl top node` reach this node: the port
// in .status.daemonEndpoints.kubeletEndpoint is the port the kubelet HTTP API
// listener actually binds.
//
// The apiserver node-proxy dials NodeInternalIP:<that advertised port>. It never
// consults a config, a default, or the process — only the Node object — so an
// advertised port that is merely PLAUSIBLE produces a connection refusal at
// exactly the moment a human is trying to read logs off a broken pod, with a
// node that is otherwise Ready and healthy. That is the shape this test exists
// for: the endpoint was the fixed ports.KubeletAPIPort constant while
// `k3sm server --kubelet-port` (and the `k3sm dev` allocation that drives it)
// moved the listener to a per-instance port.
//
// The rows drive configureNode — the production stamping path — not the
// derivation helper alone, so removing the call and re-hardcoding the constant
// fails here rather than passing on a leaf test of an unused function.
func TestNodeKubeletEndpointMatchesTheListener(t *testing.T) {
	// Non-vacuity: the whole point is a port that is NOT the default, so a
	// mutation to the default constant cannot make the interesting rows tautological.
	if devKubeletPort == ports.KubeletAPIPort {
		t.Fatalf("the per-instance fixture port %d equals the default %d; every non-default row below is vacuous",
			devKubeletPort, ports.KubeletAPIPort)
	}

	cases := []struct {
		name   string
		listen string
		want   int32
	}{
		{
			// THE REGRESSION: a per-instance allocation, exactly as
			// `k3sm server --kubelet-port` derives its listen address.
			name:   "per-instance allocation advertises the allocated port",
			listen: serverKubeletListenOn(devKubeletPort),
			want:   devKubeletPort,
		},
		{
			// The root/default server posture — the real *:10250 — is unchanged.
			name:   "server default posture still advertises the kubelet API port",
			listen: serverKubeletListen,
			want:   int32(ports.KubeletAPIPort),
		},
		{
			// The standalone `k3sm node` default (loopback-scoped) likewise.
			name:   "standalone node default posture still advertises the kubelet API port",
			listen: nodeKubeletListen,
			want:   int32(ports.KubeletAPIPort),
		},
		{
			name:   "an explicitly scoped host on a moved port advertises the moved port",
			listen: "127.0.0.1:" + strconv.Itoa(devKubeletPort),
			want:   devKubeletPort,
		},
		{
			name:   "an IPv6 wildcard on a moved port advertises the moved port",
			listen: "[::]:" + strconv.Itoa(devKubeletPort),
			want:   devKubeletPort,
		},
		{
			// Degenerate inputs fall back to the default rather than advertising 0,
			// which no client can dial. Any listen address that reaches these rows
			// is one the process could not have bound either.
			name:   "an empty listen address falls back to the default port",
			listen: "",
			want:   int32(ports.KubeletAPIPort),
		},
		{
			name:   "an unparseable listen address falls back to the default port",
			listen: "not-an-address",
			want:   int32(ports.KubeletAPIPort),
		},
		{
			name:   "a non-numeric port falls back to the default port",
			listen: "127.0.0.1:kubelet",
			want:   int32(ports.KubeletAPIPort),
		},
		{
			name:   "an out-of-range port falls back to the default port",
			listen: ":99999",
			want:   int32(ports.KubeletAPIPort),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &corev1.Node{}
			configureNode(n, "k3sm-node", "10.0.0.1", tc.listen, provider.NodeCapabilities{})
			got := n.Status.DaemonEndpoints.KubeletEndpoint.Port
			if got != tc.want {
				t.Errorf("configureNode(listen=%q) advertised kubeletEndpoint.Port = %d, want %d "+
					"(the apiserver node-proxy dials the advertised port; a mismatch is a refused logs/exec)",
					tc.listen, got, tc.want)
			}
		})
	}

	// The listen address the node ADVERTISES from and the one it BINDS are the same
	// value in production: startNode hands opts.listen to both vkadapter.NodeConfig.
	// HTTPListenAddr and configureNode. Assert the derivation over the server
	// command's own port→address mapping so a change to serverKubeletListenOn that
	// stopped round-tripping the port is caught here too.
	t.Run("the derivation round-trips every port the server command can be given", func(t *testing.T) {
		for _, port := range []int{ports.KubeletAPIPort, devKubeletPort, 10450, 10961, 65535, 1} {
			if got := kubeletEndpointPort(serverKubeletListenOn(port)); got != int32(port) {
				t.Errorf("kubeletEndpointPort(serverKubeletListenOn(%d)) = %d, want %d", port, got, port)
			}
		}
	})
}
