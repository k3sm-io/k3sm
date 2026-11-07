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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/runtimed/pkg/sandbox"
)

// isUnder reports whether path is dir or lies beneath it.
func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// TestRegistryStoreDeniedForCustomWorkDir pins that a daemon only starts with a
// work dir the pod sandbox denies. The sandbox denies <data root>/server and
// <data root>/agent, with the data root the work dir's parent: an accepted
// server work dir must hold the registry store inside the server deny, an
// accepted agent work dir must sit inside the agent deny, and a work dir under
// any other name, whose state the deny would miss, is refused.
func TestRegistryStoreDeniedForCustomWorkDir(t *testing.T) {
	for _, tc := range []struct {
		name    string
		workDir string
		subdir  string
		refused bool
	}{
		{"root server default", executor.DefaultWorkDir, sandbox.ServerSubdir, false},
		{"unprivileged server under a home", "/Users/dev/server", sandbox.ServerSubdir, false},
		{"server under a custom data root", "/data/k3sm/server", sandbox.ServerSubdir, false},
		{"server with a trailing slash", "/data/k3sm/server/", sandbox.ServerSubdir, false},
		{"server work dir named srv", "/data/k3sm/srv", sandbox.ServerSubdir, true},
		{"server work dir named agent", "/data/k3sm/agent", sandbox.ServerSubdir, true},
		{"agent default", "/var/lib/k3sm/agent", sandbox.AgentSubdir, false},
		{"agent work dir named srv", "/data/k3sm/srv", sandbox.AgentSubdir, true},
		{"agent work dir named server", "/data/k3sm/server", sandbox.AgentSubdir, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkWorkDirLayout(tc.workDir, tc.subdir)
			if tc.refused {
				if !errors.Is(err, ErrWorkDirLayout) {
					t.Fatalf("checkWorkDirLayout(%q, %q) = %v, want ErrWorkDirLayout", tc.workDir, tc.subdir, err)
				}
				if want := "--work-dir <data root>/" + tc.subdir; !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not name the required layout %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkWorkDirLayout(%q, %q) = %v, want accepted", tc.workDir, tc.subdir, err)
			}
			denied := filepath.Join(executor.RuntimeRoot(tc.workDir), tc.subdir)
			guarded := tc.workDir
			if tc.subdir == sandbox.ServerSubdir {
				guarded = registrysvc.StateDir(tc.workDir)
			}
			if !isUnder(filepath.Clean(guarded), denied) {
				t.Errorf("accepted work dir %q leaves %q outside the deny %q", tc.workDir, guarded, denied)
			}
		})
	}

	// The checks are wired into both daemons ahead of any state they write.
	t.Run("server start refuses srv", func(t *testing.T) {
		workDir := filepath.Join(t.TempDir(), "srv")
		opts := serverOptions{workDir: workDir, nodeName: "server-a"}
		err := validateServerOptions(&opts, nil, slog.New(slog.DiscardHandler))
		if !errors.Is(err, ErrWorkDirLayout) {
			t.Fatalf("validateServerOptions = %v, want ErrWorkDirLayout", err)
		}
		if _, statErr := os.Stat(workDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("the refused work dir was created (stat: %v)", statErr)
		}
	})
	t.Run("agent start refuses srv", func(t *testing.T) {
		workDir := filepath.Join(t.TempDir(), "srv")
		err := runAgent([]string{"--server", "192.0.2.10", "--network", "none", "--work-dir", workDir})
		if !errors.Is(err, ErrWorkDirLayout) {
			t.Fatalf("k3sm agent = %v, want ErrWorkDirLayout", err)
		}
		if _, statErr := os.Stat(workDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("the refused work dir was created (stat: %v)", statErr)
		}
	})
}

// tempServerWorkDir returns a fresh server work dir that checkWorkDirLayout
// accepts: <temp>/server, not yet created.
func tempServerWorkDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), sandbox.ServerSubdir)
}
