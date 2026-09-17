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

	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netdsvc"
)

// TestNetdFlagDefaultsShareTheNodeIdentityDerivation proves `k3sm netd`'s
// --node-pod-cidr default is the SAME index-0 carve of the cluster pod CIDR the
// server gives itself (defaultNodePodCIDR), not a second hand-typed literal.
//
// The two are load-bearing together. netd's adoption path treats "the identity
// already in force" as a no-op and refuses a DIFFERENT identity once the daemon
// holds anything live (an alias, a mesh route, a mesh device that is up). On a
// server the ConfigureMesh carries exactly the index-0 carve — so while the flag
// default equals it, every server ConfigureMesh is a silent no-op, and the moment
// the two drift that same call becomes an adoption attempt on a node that already
// has aliases, i.e. a refusal, on a code path nothing else exercises. A literal
// cannot be kept equal by review alone; one derivation makes the drift
// inexpressible, and this test is what pins the flag to it.
func TestNetdFlagDefaultsShareTheNodeIdentityDerivation(t *testing.T) {
	// Read the default off the REGISTERED flag, not off the helper — the bug this
	// guards against is a literal typed into the flag, which a test that called
	// defaultNodePodCIDR() twice would never see.
	fs := netdFlags(&netdOptions{})

	index0, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 0)
	if err != nil {
		t.Fatalf("carve node index 0 out of %s: %v", podnet.ClusterPodCIDR, err)
	}

	for _, tc := range []struct {
		name string
		flag string
		want string
	}{
		{
			name: "node-pod-cidr defaults to the server's own /24",
			flag: "node-pod-cidr",
			want: index0.String(),
		},
		{
			name: "mesh-key-dir defaults to the installer's root-only key dir",
			flag: "mesh-key-dir",
			want: install.MeshKeyDir,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fs.Lookup(tc.flag)
			if f == nil {
				t.Fatalf("`k3sm netd` registers no --%s flag", tc.flag)
			}
			if f.DefValue != tc.want {
				t.Errorf("--%s default = %q, want %q", tc.flag, f.DefValue, tc.want)
			}
		})
	}

	// The server command's own default is the same value: they are one derivation
	// (defaultNodePodCIDR), and this asserts the value that reaches BOTH.
	if got := defaultNodePodCIDR(); got != index0.String() {
		t.Errorf("defaultNodePodCIDR() = %q, want %q (an empty string means the derivation failed and netd would refuse to start)", got, index0.String())
	}

	// The adopted-identity file the daemon persists to lives inside that same
	// root-only mesh key dir — the pairing netd's restart path depends on.
	if got, want := netdsvc.NodeIdentityPath(install.MeshKeyDir), install.MeshKeyDir+"/"+netdsvc.NodeIdentityFileName; got != want {
		t.Errorf("NodeIdentityPath(%q) = %q, want %q", install.MeshKeyDir, got, want)
	}
}
