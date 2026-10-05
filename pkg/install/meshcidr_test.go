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

package install

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestServerInstallSeedsNetdNodePodCIDRFromMeshIP is the B446 gate.
//
// The defect: a control-plane server plumbs its --mesh-ip as an lo0 alias
// before control-plane bring-up and before its own mesh enrol, but the netd
// plist passed no --node-pod-cidr, so netd started on the first-server default
// node range (100.64.0.0/24) and refused every other server's mesh address as
// "not in node podCIDR". A second server (--server-join --mesh-ip 100.64.1.1)
// crash-looped; the first worked only because its range is the default.
//
// The fix renders netd's node pod range from the server's --mesh-ip, on every
// server role, and refuses at install time a --mesh-ip that names no range.
func TestServerInstallSeedsNetdNodePodCIDRFromMeshIP(t *testing.T) {
	netdNodePodCIDR := func(t *testing.T, cfg Config) (string, bool) {
		t.Helper()
		args, err := parseProgramArguments(NetdPlist(cfg))
		if err != nil {
			t.Fatalf("parse netd ProgramArguments: %v", err)
		}
		n := 0
		for _, a := range args {
			if a == "--node-pod-cidr" || strings.HasPrefix(a, "--node-pod-cidr=") {
				n++
			}
		}
		if n > 1 {
			t.Fatalf("netd argv carries --node-pod-cidr %d times (argv: %v)", n, args)
		}
		return flagValue(args, "node-pod-cidr"), n == 1
	}

	roles := []struct {
		name string
		cfg  func(mesh string) Config
	}{
		{"single server", func(mesh string) Config { return Config{Role: RoleServer, MeshIP: mesh} }},
		{"cluster-init server", func(mesh string) Config {
			return Config{Role: RoleServer, MeshIP: mesh, ClusterInit: true, NodeIP: "192.0.2.10"}
		}},
		{"server-join server", func(mesh string) Config {
			return Config{Role: RoleServer, MeshIP: mesh, ServerJoin: true, JoinServer: "192.0.2.10", NodeIP: "192.0.2.20"}
		}},
		{"carried --mesh-ip", func(mesh string) Config {
			return Config{Role: RoleServer, ExtraServerArgs: []string{"--mesh-ip", mesh}}
		}},
	}
	for _, role := range roles {
		for _, tc := range []struct{ mesh, want string }{
			{"100.64.1.1", "100.64.1.0/24"},
			{"100.64.0.1", "100.64.0.0/24"},
			{"100.127.255.1", "100.127.255.0/24"},
		} {
			t.Run(role.name+" "+tc.mesh, func(t *testing.T) {
				got, ok := netdNodePodCIDR(t, role.cfg(tc.mesh))
				if !ok || got != tc.want {
					t.Errorf("netd --node-pod-cidr = %q (present=%t), want %q", got, ok, tc.want)
				}
			})
		}
	}

	t.Run("this install's --mesh-ip wins over a carried one", func(t *testing.T) {
		cfg := Config{Role: RoleServer, MeshIP: "100.64.2.1", ExtraServerArgs: []string{"--mesh-ip", "100.64.1.1"}}
		if got, _ := netdNodePodCIDR(t, cfg); got != "100.64.2.0/24" {
			t.Errorf("netd --node-pod-cidr = %q, want 100.64.2.0/24", got)
		}
	})

	t.Run("no --mesh-ip renders the default unchanged", func(t *testing.T) {
		for _, cfg := range []Config{{}, {Role: RoleServer}, {Role: RoleServer, ClusterInit: true, NodeIP: "192.0.2.10"}} {
			if got, ok := netdNodePodCIDR(t, cfg); ok {
				t.Errorf("netd argv carries --node-pod-cidr %q with no --mesh-ip; the flag default is the single-node range", got)
			}
		}
	})

	t.Run("a worker never gets one", func(t *testing.T) {
		// A worker's range is decided by its join and adopted over ConfigureMesh;
		// a mesh address in its carried arguments must not pin a guess.
		cfg := Config{Role: RoleAgent, MeshIP: "100.64.1.1", ExtraServerArgs: []string{"--mesh-ip", "100.64.1.1"}}
		if got, ok := netdNodePodCIDR(t, cfg); ok {
			t.Errorf("a worker's netd argv carries --node-pod-cidr %q", got)
		}
	})

	refused := []struct{ name, mesh string }{
		{"a host other than the range's .1", "100.64.1.5"},
		{"the range's network address", "100.64.1.0"},
		{"the range's last address", "100.64.1.255"},
		{"outside the cluster pod range", "198.51.100.1"},
		{"just past the cluster pod range", "100.128.0.1"},
		{"not IPv4", "fd00::1"},
	}
	for _, tc := range refused {
		t.Run("MeshNodePodCIDR refuses "+tc.name, func(t *testing.T) {
			if cidr, err := MeshNodePodCIDR(tc.mesh); !errors.Is(err, ErrMeshIPNotNodeGateway) {
				t.Fatalf("MeshNodePodCIDR(%q) = %v, %v; want ErrMeshIPNotNodeGateway", tc.mesh, cidr, err)
			} else if !strings.Contains(err.Error(), tc.mesh) {
				t.Errorf("the refusal does not name the offending value %q: %v", tc.mesh, err)
			}
		})
	}

	for _, tc := range refused[:4] {
		for _, source := range []string{"explicit", "carried"} {
			t.Run("Install refuses "+source+" "+tc.name, func(t *testing.T) {
				f := &fakeSystem{}
				cfg := testConfig(t)
				if source == "explicit" {
					cfg.MeshIP = tc.mesh
				} else {
					putServerArgsRecord(t, f, cfg.withDefaults().ServerArgsRecord, "--mesh-ip", tc.mesh)
				}
				err := Install(context.Background(), f, cfg)
				if !errors.Is(err, ErrMeshIPNotNodeGateway) {
					t.Fatalf("Install = %v, want ErrMeshIPNotNodeGateway", err)
				}
				if m := mutatingCalls(f.calls); len(m) > 0 {
					t.Errorf("the refusal came after the install changed the machine: %v", m)
				}
			})
		}
	}

	t.Run("an install with a valid --mesh-ip writes the seeded netd plist", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		cfg.MeshIP = "100.64.1.1"
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		raw, ok := f.files[cfg.withDefaults().plistPath(NetdLabel)]
		if !ok {
			t.Fatal("no netd plist was written")
		}
		args, err := parseProgramArguments(raw)
		if err != nil {
			t.Fatalf("parse the written netd plist: %v", err)
		}
		if got := flagValue(args, "node-pod-cidr"); got != "100.64.1.0/24" {
			t.Errorf("written netd --node-pod-cidr = %q, want 100.64.1.0/24 (argv: %v)", got, args)
		}
		if slices.Contains(args, "--node-ip") {
			t.Errorf("netd argv must not carry --node-ip (argv: %v)", args)
		}
	})
}
