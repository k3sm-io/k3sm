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

import "testing"

// TestRoleFromPlists pins the whole decision, including the two postures that
// are not "one plist, one role": both plists (the hand-made cross-role Mac) and
// neither (no install). It is a pure table because every caller — the installer
// and `k3sm status` alike — must reach the same verdict from the same two
// booleans.
func TestRoleFromPlists(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		server, agent bool
		wantRole      Role
		wantInstalled bool
	}{
		{"server plist only → the control plane", true, false, RoleServer, true},
		{"agent plist only → a joining worker", false, true, RoleAgent, true},
		{"both plists → the server leads, and it is installed", true, true, RoleServer, true},
		{"neither plist → not installed, zero role", false, false, RoleServer, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			role, installed := RoleFromPlists(c.server, c.agent)
			if role != c.wantRole || installed != c.wantInstalled {
				t.Fatalf("RoleFromPlists(%v, %v) = (%q, %v), want (%q, %v)",
					c.server, c.agent, role, installed, c.wantRole, c.wantInstalled)
			}
		})
	}

	// A Mac with no install is never reported as a worker: the bool is what a
	// caller branches on, and the role it comes back with is the named default
	// rather than an empty string nobody handles.
	t.Run("no install is never the agent role", func(t *testing.T) {
		t.Parallel()
		role, installed := RoleFromPlists(false, false)
		if installed {
			t.Fatal("no plists reported as installed")
		}
		if role == RoleAgent {
			t.Fatal("no plists reported as the agent role")
		}
	})
}
