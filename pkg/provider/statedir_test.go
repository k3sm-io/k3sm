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

package provider

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TestStateDirReachesTheRuntimeConfig pins the plumbing: the work dir set on the
// provider config is the value runtime.Config.StateDir carries, made absolute when
// it is relative, and unset stays unset.
func TestStateDirReachesTheRuntimeConfig(t *testing.T) {
	t.Parallel()
	abs, err := filepath.Abs("relative-work-dir")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cfg  RuntimedConfig
		want string
	}{
		{"a custom leaf under a custom pod root", RuntimedConfig{Root: "/opt/k3sm-pods", DataRoot: "/var/lib/k3sm", StateDir: "/var/lib/k3sm/cp"}, "/var/lib/k3sm/cp"},
		{"a custom leaf under the data root as the pod root", RuntimedConfig{Root: "/var/lib/k3sm", DataRoot: "/var/lib/k3sm", StateDir: "/var/lib/k3sm/cp"}, "/var/lib/k3sm/cp"},
		{"a default leaf", RuntimedConfig{Root: "/var/lib/k3sm", DataRoot: "/var/lib/k3sm", StateDir: "/var/lib/k3sm/server"}, "/var/lib/k3sm/server"},
		{"a relative work dir is made absolute", RuntimedConfig{Root: "/opt/k3sm-pods", StateDir: "relative-work-dir"}, abs},
		{"unset stays unset", RuntimedConfig{Root: "/opt/k3sm-pods", DataRoot: "/var/lib/k3sm"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dataRoot, stateDir, err := dataRootOf(tc.cfg)
			if err != nil {
				t.Fatalf("dataRootOf: %v", err)
			}
			got := runtimedConfigOf(tc.cfg, slog.New(slog.DiscardHandler), "", dataRoot, stateDir)
			if got.StateDir != tc.want {
				t.Errorf("runtime.Config.StateDir = %q, want %q", got.StateDir, tc.want)
			}
			if got.DataRoot != dataRoot {
				t.Errorf("runtime.Config.DataRoot = %q, want %q", got.DataRoot, dataRoot)
			}
		})
	}
}

// TestDefaultLeafStateDirKeepsTheProfile pins the no-drift half: a work dir with
// the default leaf names a tree the profile denies already, so a node's profile is
// byte for byte the one it had without the field.
func TestDefaultLeafStateDirKeepsTheProfile(t *testing.T) {
	t.Parallel()
	const root = "/var/lib/k3sm"
	profile := func(stateDir string) string {
		t.Helper()
		out, err := sandbox.Generate(&runtimev1.SandboxProfile{DataVolumePath: filepath.Join(root, "pods", "p1", "rootfs")}, sandbox.GenerateOptions{
			Posture: sandbox.Posture{WorkDir: root, DataRoot: root, StateDir: stateDir},
		})
		if err != nil {
			t.Fatalf("sandbox.Generate: %v", err)
		}
		return out
	}
	for _, leaf := range []string{"server", "agent"} {
		if profile(filepath.Join(root, leaf)) != profile("") {
			t.Errorf("a default %s leaf changed the profile, which refuses every re-attach as drift", leaf)
		}
	}
	if custom := profile(filepath.Join(root, "cp")); !strings.Contains(custom, `(subpath "`+root+`/cp")`) {
		t.Errorf("a custom leaf is not denied:\n%s", custom)
	}
}

// TestStateDirSymlinkIsRefused pins the canonical-path check on the state dir: a
// work dir that is, or sits behind, a symlink would leave its deny matching
// nothing, so it is refused on both dataRootOf paths. The runtime's own server or
// agent directory is the one exception, as it is for the data root's children.
func TestStateDirSymlinkIsRefused(t *testing.T) {
	t.Parallel()
	mkdir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	// A real data root whose leaf child is a symlink to a real directory.
	linkedLeaf := func(leaf string) func(t *testing.T, base string) (string, string) {
		return func(t *testing.T, base string) (string, string) {
			data := filepath.Join(base, "data")
			mkdir(t, data)
			mkdir(t, filepath.Join(base, "elsewhere"))
			link(t, filepath.Join(base, "elsewhere"), filepath.Join(data, leaf))
			return data, filepath.Join(data, leaf)
		}
	}
	realLeaf := func(t *testing.T, base string) (string, string) {
		data := filepath.Join(base, "data")
		mkdir(t, filepath.Join(data, "cp"))
		return data, filepath.Join(data, "cp")
	}
	customRoot := func(base, _ string) string { return filepath.Join(base, "pods-root") }
	ownRoot := func(_, data string) string { return data }
	cases := []struct {
		name    string
		setup   func(t *testing.T, base string) (dataRoot, stateDir string)
		root    func(base, dataRoot string) string
		refused bool
	}{
		{"a real custom leaf under a custom pod root", realLeaf, customRoot, false},
		{"a real custom leaf under the data root as the pod root", realLeaf, ownRoot, false},
		{"a missing custom leaf has nothing to mismatch", func(t *testing.T, base string) (string, string) {
			data := filepath.Join(base, "data")
			mkdir(t, data)
			return data, filepath.Join(data, "cp")
		}, ownRoot, false},
		{"a firmlink spelling is not a mismatch", func(t *testing.T, base string) (string, string) {
			data, state := realLeaf(t, base)
			return data, strings.TrimPrefix(state, "/private")
		}, customRoot, false},
		{"a symlinked custom leaf under a custom pod root", linkedLeaf("cp"), customRoot, true},
		{"a symlinked custom leaf under the data root as the pod root", linkedLeaf("cp"), ownRoot, true},
		{"a custom leaf behind a symlinked ancestor", func(t *testing.T, base string) (string, string) {
			mkdir(t, filepath.Join(base, "target", "cp"))
			data := filepath.Join(base, "data")
			mkdir(t, data)
			link(t, filepath.Join(base, "target"), filepath.Join(base, "via"))
			return data, filepath.Join(base, "via", "cp")
		}, ownRoot, true},
		{"a dangling custom leaf cannot be checked", func(t *testing.T, base string) (string, string) {
			data := filepath.Join(base, "data")
			mkdir(t, data)
			link(t, filepath.Join(base, "gone"), filepath.Join(data, "cp"))
			return data, filepath.Join(data, "cp")
		}, ownRoot, true},
		{"a symlinked state dir with no data root", func(t *testing.T, base string) (string, string) {
			_, state := linkedLeaf("cp")(t, base)
			return "", state
		}, customRoot, true},
		{"a symlinked default leaf under a custom pod root", linkedLeaf("server"), customRoot, true},
		{"a symlinked default leaf of the runtime's own root starts", linkedLeaf("server"), ownRoot, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := resolvedTempDir(t)
			dataRoot, stateDir := tc.setup(t, base)
			cfg := RuntimedConfig{Root: tc.root(base, filepath.Join(base, "data")), DataRoot: dataRoot, StateDir: stateDir}
			_, _, err := dataRootOf(cfg)
			if got := errors.Is(err, ErrDataRootNotCanonical); got != tc.refused {
				t.Errorf("dataRootOf(%+v) = %v, refused = %v, want %v", cfg, err, got, tc.refused)
			}
		})
	}
}

// TestNewRuntimedRefusesAStateDirItCannotDeny drives the constructor, so the value
// is proven to reach both refusals, each logged by name as well as returned.
func TestNewRuntimedRefusesAStateDirItCannotDeny(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, base string) (root, stateDir string)
		want  error
	}{
		{"a symlinked custom leaf, refused here", func(t *testing.T, base string) (string, string) {
			data := filepath.Join(base, "data")
			if err := os.MkdirAll(data, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(base, filepath.Join(data, "cp")); err != nil {
				t.Fatal(err)
			}
			return data, filepath.Join(data, "cp")
		}, ErrDataRootNotCanonical},
		{"a pods root under the state dir, refused by the runtime", func(_ *testing.T, base string) (string, string) {
			return filepath.Join(base, "cp", "pods-root"), filepath.Join(base, "cp")
		}, sandbox.ErrInvalidStateDir},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := resolvedTempDir(t)
			root, stateDir := tc.setup(t, base)
			var logged bytes.Buffer
			_, err := NewRuntimed(context.Background(), RuntimedConfig{
				NodeName:   "n1",
				Root:       root,
				PodLogsDir: filepath.Join(base, "podlogs"),
				StateDir:   stateDir,
				Logger:     slog.New(slog.NewTextHandler(&logged, nil)),
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewRuntimed err = %v, want %v", err, tc.want)
			}
			if !strings.Contains(logged.String(), "level=ERROR") || !strings.Contains(logged.String(), tc.want.Error()) {
				t.Errorf("the refusal is not logged by name:\n%s", logged.String())
			}
		})
	}
}
