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
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/netdsvc"
)

// TestRoleTransitionRewritesNetdPolicyInputs pins the two netd policy inputs a
// role change must replace, and the one it must not.
//
// A role change is `k3sm uninstall` followed by `k3sm install` of the other
// role (refuseCrossRole refuses anything else). netd reads two role-scoped
// inputs at start: the kubeconfig its Service informer authorizes privileged
// binds with (named in its plist), and the pod CIDR it adopted from the last
// join (persisted inside the root-only mesh key dir). The plist is rewritten by
// the install; the adopted identity is not written by install at all, so if
// uninstall left it, the returning role's netd would restore the OTHER role's
// /24. The key dir and every key in it are the node's mesh identity and must
// survive the same uninstall untouched.
func TestRoleTransitionRewritesNetdPolicyInputs(t *testing.T) {
	identity := netdsvc.NodeIdentityPath(MeshKeyDir)
	keep := []string{
		MeshKeyDir,
		filepath.Join(MeshKeyDir, MeshKeyRefAgent),
		filepath.Join(MeshKeyDir, MeshKeyRefServer),
		Config{Role: RoleServer}.withDefaults().meshKeyWorkPath(),
		Config{Role: RoleAgent}.withDefaults().meshKeyWorkPath(),
	}

	t.Run("uninstall retires the adopted identity and keeps the keys", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			cfg  Config
			// agentPlistOnDisk also puts the other role's plist on disk, so the
			// merged (both-role) manifest is exercised too.
			agentPlistOnDisk bool
		}{
			{name: "server", cfg: Config{Role: RoleServer}},
			{name: "server with a stray agent plist", cfg: Config{Role: RoleServer}, agentPlistOnDisk: true},
			{name: "agent", cfg: Config{Role: RoleAgent}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeSystem{}
				if tc.agentPlistOnDisk {
					f.putFile(tc.cfg.withDefaults().plistPath(AgentLabel), []byte("<plist/>"))
				}
				if err := Uninstall(context.Background(), f, tc.cfg); err != nil {
					t.Fatalf("Uninstall: %v", err)
				}
				removed := toSet(recorded(f.calls, "RemoveAll:"))
				if !removed[identity] {
					t.Errorf("uninstall did not remove the adopted identity %s; the next role's netd would restore this role's pod CIDR (removed: %v)", identity, recorded(f.calls, "RemoveAll:"))
				}
				for _, p := range keep {
					if removed[p] {
						t.Errorf("uninstall removed %s; the mesh key dir and its keys are the node's identity and must be preserved", p)
					}
				}
				// Exactly one removal lands inside the key dir, and it is the leaf.
				for p := range removed {
					if filepath.Dir(p) == MeshKeyDir && p != identity {
						t.Errorf("uninstall removed %s inside the key dir; only %s may go", p, identity)
					}
				}
			})
		}
	})

	t.Run("netd plist names the role's own credential", func(t *testing.T) {
		const dataRoot = "/opt/k3sm-role-change"
		for _, tc := range []struct {
			role Role
			want string
		}{
			{role: RoleAgent, want: AgentCredentialPath(dataRoot)},
			{role: RoleServer, want: filepath.Join(Config{Role: RoleServer, DataRoot: dataRoot}.serverWorkDir(), "k3sm.kubeconfig")},
		} {
			t.Run(string(tc.role), func(t *testing.T) {
				args, err := parseProgramArguments(NetdPlist(Config{Role: tc.role, DataRoot: dataRoot}))
				if err != nil {
					t.Fatalf("parse netd ProgramArguments: %v", err)
				}
				if got := flagValue(args, "kubeconfig"); got != tc.want {
					t.Errorf("%s netd --kubeconfig = %q, want %q", tc.role, got, tc.want)
				}
			})
		}
	})
}
