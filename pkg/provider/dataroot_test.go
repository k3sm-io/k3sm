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
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/runtimed/pkg/sandbox"
)

// dataRootProfile renders the profile a node with work dir workDir gets for a data
// root of dataRoot.
func dataRootProfile(t *testing.T, workDir, dataRoot string) string {
	t.Helper()
	out, err := sandbox.Generate(&runtimev1.SandboxProfile{DataVolumePath: filepath.Join(workDir, "pods", "p1", "rootfs")}, sandbox.GenerateOptions{
		Posture: sandbox.Posture{WorkDir: workDir, DataRoot: dataRoot},
	})
	if err != nil {
		t.Fatalf("sandbox.Generate: %v", err)
	}
	return out
}

// TestDataRootOnADefaultNode pins the no-drift half: the data root is the runtime's
// own root, in the /var spelling, and the rendered profile is byte for byte the one
// a node without the field gets, so an upgrade does not refuse a single re-attach.
func TestDataRootOnADefaultNode(t *testing.T) {
	t.Parallel()
	root := runtimeRoot("")
	got, err := dataRootOf(RuntimedConfig{DataRoot: install.DefaultDataRoot})
	if err != nil {
		t.Fatalf("dataRootOf(%q) on the default path: %v", install.DefaultDataRoot, err)
	}
	if got != root {
		t.Errorf("default value = %q, want the runtime's own root %q", got, root)
	}
	if dataRootProfile(t, root, got) != dataRootProfile(t, root, "") {
		t.Error("a default node's profile changed, which refuses every re-attach as drift")
	}
}

// TestDataRootUnderACustomPodRoot pins the reason the field exists: with the runtime
// root moved, the data root's server and agent directories are still what is denied.
func TestDataRootUnderACustomPodRoot(t *testing.T) {
	t.Parallel()
	got, err := dataRootOf(RuntimedConfig{Root: "/opt/k3sm-pods", DataRoot: install.DefaultDataRoot})
	if err != nil {
		t.Fatalf("dataRootOf: %v", err)
	}
	profile := dataRootProfile(t, "/opt/k3sm-pods", got)
	for _, dir := range []string{install.DefaultDataRoot + "/server", install.DefaultDataRoot + "/agent"} {
		for _, form := range []string{dir, "/private" + dir} {
			if !strings.Contains(profile, `(subpath "`+form+`")`) {
				t.Errorf("profile under a custom pod root does not deny %q", form)
			}
		}
	}
}

// TestDataRootSymlinkCheckFollowsThePodRoot pins that the check runs only where it
// protects a deny. With the data root as the runtime's own root the profile adds
// nothing, so a symlinked server directory, or a root behind a symlink, keeps
// starting as it did. The same symlink under a custom pod root is refused, because
// there the new deny would match nothing.
func TestDataRootSymlinkCheckFollowsThePodRoot(t *testing.T) {
	symlinkedChild := func(t *testing.T, base string) string {
		t.Helper()
		root := filepath.Join(base, "data")
		for _, dir := range []string{root, filepath.Join(base, "elsewhere")} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(root, "server")); err != nil {
			t.Fatal(err)
		}
		return root
	}
	start := func(t *testing.T, base, root, dataRoot string) error {
		t.Helper()
		stageExecShim(t)
		_, err := NewRuntimed(context.Background(), RuntimedConfig{
			NodeName:   "n1",
			Root:       root,
			PodLogsDir: filepath.Join(base, "podlogs"),
			DataRoot:   dataRoot,
			Logger:     slog.New(slog.DiscardHandler),
		})
		return err
	}

	t.Run("a default node with a symlinked server directory starts", func(t *testing.T) {
		base := resolvedTempDir(t)
		root := symlinkedChild(t, base)
		if err := start(t, base, root, root); err != nil {
			t.Errorf("NewRuntimed: %v", err)
		}
	})
	t.Run("a default node with a root behind a symlink starts", func(t *testing.T) {
		base := resolvedTempDir(t)
		real := filepath.Join(base, "real")
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		via := filepath.Join(base, "via")
		if err := os.Symlink(real, via); err != nil {
			t.Fatal(err)
		}
		if err := start(t, base, via, via); err != nil {
			t.Errorf("NewRuntimed: %v", err)
		}
	})
	t.Run("a custom pod root with the same symlink is refused", func(t *testing.T) {
		base := resolvedTempDir(t)
		root := symlinkedChild(t, base)
		if err := start(t, base, filepath.Join(base, "pods-root"), root); !errors.Is(err, ErrDataRootNotCanonical) {
			t.Errorf("NewRuntimed err = %v, want ErrDataRootNotCanonical", err)
		}
	})
	t.Run("a firmlink spelling of the runtime root takes the runtime's spelling", func(t *testing.T) {
		const root, spelled = "/private/var/k3sm-data", "/var/k3sm-data"
		for _, tc := range []struct{ root, dataRoot string }{{root, spelled}, {spelled, root}} {
			got, err := dataRootOf(RuntimedConfig{Root: tc.root, DataRoot: tc.dataRoot})
			if err != nil {
				t.Fatalf("dataRootOf(%+v): %v", tc, err)
			}
			if got != tc.root {
				t.Errorf("dataRootOf(%+v) = %q, want the runtime's %q", tc, got, tc.root)
			}
			if dataRootProfile(t, tc.root, got) != dataRootProfile(t, tc.root, "") {
				t.Errorf("the spelling %q changed the profile of a node on root %q", tc.dataRoot, tc.root)
			}
		}
	})
	t.Run("the default root is the runtime's own when Root is empty", func(t *testing.T) {
		got, err := dataRootOf(RuntimedConfig{DataRoot: install.DefaultDataRoot})
		if err != nil {
			t.Fatalf("dataRootOf: %v", err)
		}
		if got != runtimeRoot("") {
			t.Errorf("dataRootOf = %q, want %q", got, runtimeRoot(""))
		}
	})
	t.Run("unset stays unset", func(t *testing.T) {
		if got, err := dataRootOf(RuntimedConfig{Root: "/opt/k3sm-pods"}); err != nil || got != "" {
			t.Errorf("dataRootOf = %q, %v; want empty", got, err)
		}
	})
}

func TestDataRootOfMakesARelativeValueAbsolute(t *testing.T) {
	t.Parallel()
	got, err := dataRootOf(RuntimedConfig{DataRoot: "relative-data-root"})
	if err != nil {
		t.Fatalf("dataRootOf: %v", err)
	}
	want, err := filepath.Abs("relative-data-root")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("dataRootOf = %q, want %q", got, want)
	}
}

func TestCheckDataRoot(t *testing.T) {
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
	// A real data root whose named child is a symlink to a real directory.
	childLink := func(sub string) func(t *testing.T, base string) string {
		return func(t *testing.T, base string) string {
			root := filepath.Join(base, "data")
			mkdir(t, root)
			mkdir(t, filepath.Join(base, "elsewhere"))
			link(t, filepath.Join(base, "elsewhere"), filepath.Join(root, sub))
			return root
		}
	}
	cases := []struct {
		name    string
		setup   func(t *testing.T, base string) string
		refused bool
	}{
		{"empty is unset", func(*testing.T, string) string { return "" }, false},
		{"missing has nothing to mismatch", func(_ *testing.T, base string) string {
			return filepath.Join(base, "data")
		}, false},
		{"a real root with missing children", func(t *testing.T, base string) string {
			root := filepath.Join(base, "data")
			mkdir(t, root)
			return root
		}, false},
		{"a real root with real children", func(t *testing.T, base string) string {
			root := filepath.Join(base, "data")
			mkdir(t, filepath.Join(root, "server"))
			mkdir(t, filepath.Join(root, "agent"))
			return root
		}, false},
		{"a firmlink spelling is not a mismatch", func(t *testing.T, base string) string {
			root := filepath.Join(base, "data")
			mkdir(t, filepath.Join(root, "server"))
			return strings.TrimPrefix(root, "/private")
		}, false},
		{"another child may be a symlink", func(t *testing.T, base string) string {
			return childLink("updates")(t, base)
		}, false},
		{"the root itself is a symlink", func(t *testing.T, base string) string {
			target := filepath.Join(base, "target")
			mkdir(t, target)
			root := filepath.Join(base, "data")
			link(t, target, root)
			return root
		}, true},
		{"an ancestor is a symlink", func(t *testing.T, base string) string {
			mkdir(t, filepath.Join(base, "target", "data"))
			link(t, filepath.Join(base, "target"), filepath.Join(base, "via"))
			return filepath.Join(base, "via", "data")
		}, true},
		{"the server directory is a symlink", childLink("server"), true},
		{"the agent directory is a symlink", childLink("agent"), true},
		{"a dangling server symlink cannot be checked", func(t *testing.T, base string) string {
			root := filepath.Join(base, "data")
			mkdir(t, root)
			link(t, filepath.Join(base, "gone"), filepath.Join(root, "server"))
			return root
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := tc.setup(t, resolvedTempDir(t))
			err := checkDataRoot(dir)
			if got := errors.Is(err, ErrDataRootNotCanonical); got != tc.refused {
				t.Errorf("checkDataRoot(%q) = %v, refused = %v, want %v", dir, err, got, tc.refused)
			}
		})
	}
}

// TestNewRuntimedRefusesADataRootItCannotDeny drives the constructor, so the value is
// proven to reach both refusals, and each is proven to name itself in the log as well
// as in the returned error.
func TestNewRuntimedRefusesADataRootItCannotDeny(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, base string) (root, dataRoot string)
		want  error
	}{
		{"a symlinked server directory, refused here", func(t *testing.T, base string) (string, string) {
			data := filepath.Join(base, "data")
			if err := os.MkdirAll(data, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(base, filepath.Join(data, "server")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(base, "pods-root"), data
		}, ErrDataRootNotCanonical},
		{"under the pods root, refused by the runtime", func(_ *testing.T, base string) (string, string) {
			return base, filepath.Join(base, "pods", "data")
		}, sandbox.ErrInvalidDataRoot},
		{"a pod root inside the server directory, refused by the runtime", func(_ *testing.T, base string) (string, string) {
			return filepath.Join(base, "server", "pods-root"), base
		}, sandbox.ErrInvalidDataRoot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := resolvedTempDir(t)
			root, dataRoot := tc.setup(t, base)
			var logged bytes.Buffer
			_, err := NewRuntimed(context.Background(), RuntimedConfig{
				NodeName:   "n1",
				Root:       root,
				PodLogsDir: filepath.Join(base, "podlogs"),
				DataRoot:   dataRoot,
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
