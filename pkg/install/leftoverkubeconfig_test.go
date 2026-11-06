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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestAgentInstallRemovesOnlyTheLeftoverServerKubeconfig pins what an agent
// install does with the admin kubeconfig an earlier server role left in the
// server work dir: that one file goes, a worker's migration journal beside it
// stays, and a server install and an uninstall touch neither.
func TestAgentInstallRemovesOnlyTheLeftoverServerKubeconfig(t *testing.T) {
	work := Config{}.withDefaults().serverWorkDir()
	leftover := executor.KubeconfigPath(work)
	// A sibling standing for the journal and whatever else the work dir holds.
	neighbours := []string{
		filepath.Join(work, "image-migration", "journal.json"),
		filepath.Join(work, "k3sm.kubeconfig.bak"),
		filepath.Join(work, "registry-state.json"),
	}
	shrinkRestartBudgets(t)
	stage := func() *fakeSystem {
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		f.putFile(leftover, []byte("admin"))
		for _, p := range neighbours {
			f.putFile(p, []byte("keep"))
		}
		return f
	}
	keepsNeighbours := func(t *testing.T, f *fakeSystem) {
		t.Helper()
		for _, p := range neighbours {
			if _, ok := f.files[p]; !ok {
				t.Errorf("%s did not survive", p)
			}
		}
	}

	t.Run("agent install removes it", func(t *testing.T) {
		f := stage()
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if _, ok := f.files[leftover]; ok {
			t.Errorf("%s survived the agent install", leftover)
		}
		keepsNeighbours(t, f)
		if !slices.Contains(f.calls, "RemoveEntryBeneath:/var/lib/k3sm:server:k3sm.kubeconfig") {
			t.Errorf("the removal did not go through the no-follow walk: %v", recorded(f.calls, "RemoveEntryBeneath:"))
		}
	})
	t.Run("an agent install with nothing left over succeeds", func(t *testing.T) {
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
	})
	t.Run("a server install keeps its own", func(t *testing.T) {
		f := stage()
		if err := Install(context.Background(), f, Config{BinarySource: "/tmp/build/k3sm", TargetUser: "alice"}); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if _, ok := f.files[leftover]; !ok {
			t.Errorf("a server install removed %s", leftover)
		}
	})
	t.Run("an agent uninstall keeps it", func(t *testing.T) {
		f := stage()
		if err := Uninstall(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if _, ok := f.files[leftover]; !ok {
			t.Errorf("an uninstall removed %s", leftover)
		}
		keepsNeighbours(t, f)
	})
	t.Run("a failed install keeps it", func(t *testing.T) {
		f := stage()
		f.bootstrapAlways = map[string]error{AgentLabel: errors.New("refused")}
		err := Install(context.Background(), f, agentCfg(t))
		if err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("Install = %v, want the agent's refused bootstrap", err)
		}
		if _, ok := f.files[leftover]; !ok {
			t.Errorf("a failed install removed %s", leftover)
		}
	})
	t.Run("a failed removal does not fail the install", func(t *testing.T) {
		f := stage()
		f.removeEntryErrs = map[string]error{leftover: errors.New("operation not permitted")}
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
	})
}

// TestLeftoverKubeconfigRemovalStaysInItsWorkDir: the removal walks one directory
// name beneath the data root, so a work dir elsewhere must remove nothing rather
// than the file in the data root's directory of the same base name.
func TestLeftoverKubeconfigRemovalStaysInItsWorkDir(t *testing.T) {
	cfg := agentCfg(t).withDefaults()
	root := cfg.DataRoot
	underRoot := executor.KubeconfigPath(filepath.Join(root, "server"))
	for _, tc := range []struct {
		name    string
		workDir string
		// want is the kubeconfig removed; "" means no removal at all.
		want string
	}{
		{name: "the default work dir", workDir: filepath.Join(root, "server"), want: underRoot},
		{name: "a trailing slash is the same work dir", workDir: filepath.Join(root, "server") + "/", want: underRoot},
		{name: "another directory directly under the data root", workDir: filepath.Join(root, "custom"), want: executor.KubeconfigPath(filepath.Join(root, "custom"))},
		{name: "a work dir outside the data root with the same base name", workDir: "/custom/server"},
		{name: "a work dir nested under the data root with the same base name", workDir: filepath.Join(root, "nested", "server")},
		{name: "the data root itself", workDir: root},
		{name: "a path that climbs out of the data root", workDir: filepath.Join(root, "..") + "/server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{}
			f.putFile(underRoot, []byte("admin"))
			if tc.want != "" {
				f.putFile(tc.want, []byte("admin"))
			}
			removeLeftoverKubeconfigIn(f, cfg, tc.workDir)
			calls := recorded(f.calls, "RemoveEntryBeneath:")
			if tc.want == "" {
				if len(calls) != 0 {
					t.Errorf("removed %v for a work dir outside the data root", calls)
				}
				if _, ok := f.files[underRoot]; !ok {
					t.Errorf("%s was removed for the work dir %s", underRoot, tc.workDir)
				}
				return
			}
			if _, ok := f.files[tc.want]; ok {
				t.Errorf("%s survived", tc.want)
			}
		})
	}
}
