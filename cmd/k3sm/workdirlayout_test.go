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

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	mkdirs(t, filepath.Dir(link))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// TestRegistryStoreDeniedForCustomWorkDir pins that a daemon only starts with a
// work dir the pod sandbox denies. The sandbox denies <data root>/server and
// <data root>/agent, with the data root the work dir's parent. An accepted work
// dir comes back absolute and clean, a server's registry store sits inside the
// server deny, and when the directory exists it resolves to <resolved data
// root>/<subdir>. A work dir under any other name, a symlinked work dir, and one
// whose on-disk name differs in case are refused. Symlinks in parent
// components (macOS's /var) are accepted.
func TestRegistryStoreDeniedForCustomWorkDir(t *testing.T) {
	if filepath.Base(executor.DefaultWorkDir) != sandbox.ServerSubdir {
		t.Errorf("the default work dir %q is not named %q", executor.DefaultWorkDir, sandbox.ServerSubdir)
	}
	server, agent := sandbox.ServerSubdir, sandbox.AgentSubdir
	for _, tc := range []struct {
		name   string
		subdir string
		// setup builds the tree under root and returns the raw --work-dir, the
		// directory to run from ("" keeps the current one) and the accepted
		// path ("" when refused).
		setup func(t *testing.T, root string) (raw, cwd, want string)
	}{
		{"server under a custom data root", server, func(t *testing.T, root string) (string, string, string) {
			return root + "/data/server", "", root + "/data/server"
		}},
		{"server with a trailing slash", server, func(t *testing.T, root string) (string, string, string) {
			return root + "/data/server/", "", root + "/data/server"
		}},
		{"server work dir named srv", server, func(t *testing.T, root string) (string, string, string) {
			return root + "/data/srv", "", ""
		}},
		{"server work dir named agent", server, func(t *testing.T, root string) (string, string, string) {
			return root + "/data/agent", "", ""
		}},
		{"agent under a custom data root", agent, func(t *testing.T, root string) (string, string, string) {
			return root + "/data/agent", "", root + "/data/agent"
		}},
		{"agent work dir named srv", agent, func(t *testing.T, root string) (string, string, string) {
			return root + "/data/srv", "", ""
		}},
		{"agent work dir named server", agent, func(t *testing.T, root string) (string, string, string) {
			return root + "/data/server", "", ""
		}},
		{"relative server is made absolute", server, func(t *testing.T, root string) (string, string, string) {
			return "server", root, root + "/server"
		}},
		{"dot from inside a server dir", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/server")
			return ".", root + "/server", root + "/server"
		}},
		{"dot from another dir", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/srv")
			return ".", root + "/srv", ""
		}},
		{"dotdot to a server dir", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/server/sub")
			return "..", root + "/server/sub", root + "/server"
		}},
		{"dotdot to another dir", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/data/sub")
			return "..", root + "/data/sub", ""
		}},
		// a points elsewhere, so the kernel would read a/../server as
		// <root>/far/server; the work dir is cleaned lexically first, and the
		// check and every later use see <root>/server.
		{"through a symlink then dotdot", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/far/deep", root+"/far/server", root+"/server")
			symlink(t, root+"/far/deep", root+"/a")
			return "a/../server", root, root + "/server"
		}},
		{"symlinked server dir", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/real")
			symlink(t, root+"/real", root+"/server")
			return root + "/server", "", ""
		}},
		{"symlink to another server dir", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/other/server")
			symlink(t, root+"/other/server", root+"/server")
			return root + "/server", "", ""
		}},
		{"symlinked agent dir", agent, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/real")
			symlink(t, root+"/real", root+"/agent")
			return root + "/agent", "", ""
		}},
		{"on-disk Server behind a server flag", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/Server")
			if _, err := os.Lstat(root + "/server"); err != nil {
				t.Skip("case-sensitive volume: server and Server are different directories")
			}
			return root + "/server", "", ""
		}},
		{"existing default under a /var-style symlinked parent", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/private/var/lib/k3sm/server")
			symlink(t, root+"/private/var", root+"/var")
			return root + "/var/lib/k3sm/server", "", root + "/var/lib/k3sm/server"
		}},
		{"absent default under a /var-style symlinked parent", server, func(t *testing.T, root string) (string, string, string) {
			mkdirs(t, root+"/private/var/lib/k3sm")
			symlink(t, root+"/private/var", root+"/var")
			return root + "/var/lib/k3sm/server", "", root + "/var/lib/k3sm/server"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// t.TempDir is itself under a symlinked parent on macOS
			// (/var/folders), so every row also runs through one.
			root := t.TempDir()
			raw, cwd, want := tc.setup(t, root)
			if cwd != "" {
				t.Chdir(cwd)
			}
			got, err := resolveWorkDirLayout(raw, tc.subdir)
			if want == "" {
				if !errors.Is(err, ErrWorkDirLayout) {
					t.Fatalf("resolveWorkDirLayout(%q, %q) = %q, %v; want ErrWorkDirLayout", raw, tc.subdir, got, err)
				}
				if layout := "--work-dir <data root>/" + tc.subdir; !strings.Contains(err.Error(), layout) {
					t.Errorf("refusal %q does not name the required layout %q", err, layout)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveWorkDirLayout(%q, %q) = %v, want %q", raw, tc.subdir, err, want)
			}
			if got != want {
				t.Fatalf("resolveWorkDirLayout(%q, %q) = %q, want the absolute, clean %q", raw, tc.subdir, got, want)
			}
			dataRoot := executor.RuntimeRoot(got)
			denied := filepath.Join(dataRoot, tc.subdir)
			guarded := got
			if tc.subdir == sandbox.ServerSubdir {
				guarded = registrysvc.StateDir(got)
			}
			if !isUnder(guarded, denied) {
				t.Errorf("accepted work dir %q leaves %q outside the deny %q", got, guarded, denied)
			}
			// On disk, the deny's root resolves to where the work dir really is.
			if _, err := os.Lstat(got); err == nil {
				resolvedRoot, err := filepath.EvalSymlinks(dataRoot)
				if err != nil {
					t.Fatal(err)
				}
				resolved, err := filepath.EvalSymlinks(got)
				if err != nil {
					t.Fatal(err)
				}
				if resolved != filepath.Join(resolvedRoot, tc.subdir) {
					t.Errorf("work dir %q resolves to %q, outside the resolved deny %q", got, resolved, filepath.Join(resolvedRoot, tc.subdir))
				}
			}
		})
	}

	// The checks are wired into both daemons ahead of any state they write,
	// and the server keeps the normalised path.
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
	t.Run("server start keeps the absolute work dir", func(t *testing.T) {
		t.Chdir(t.TempDir())
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		opts := serverOptions{workDir: "./x/../server", nodeName: "server-a"}
		if err := validateServerOptions(&opts, nil, slog.New(slog.DiscardHandler)); err != nil {
			t.Fatalf("validateServerOptions: %v", err)
		}
		if want := filepath.Join(cwd, "server"); opts.workDir != want {
			t.Errorf("opts.workDir = %q, want %q", opts.workDir, want)
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
	t.Run("agent start refuses a symlinked work dir", func(t *testing.T) {
		root := t.TempDir()
		mkdirs(t, root+"/real")
		symlink(t, root+"/real", root+"/agent")
		err := runAgent([]string{"--server", "192.0.2.10", "--network", "none", "--work-dir", root + "/agent"})
		if !errors.Is(err, ErrWorkDirLayout) {
			t.Fatalf("k3sm agent = %v, want ErrWorkDirLayout", err)
		}
	})
}

// tempServerWorkDir returns a fresh server work dir that checkWorkDirLayout
// accepts: <temp>/server, not yet created.
func tempServerWorkDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), sandbox.ServerSubdir)
}
