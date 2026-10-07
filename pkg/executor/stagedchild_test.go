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

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// stagedChildDeclarations are the real declarations TestStagedChildProtocol runs the
// protocol over. Each keeps its own name, marker and variant; only the build is faked.
func stagedChildDeclarations() map[string]stagedChild {
	return map[string]stagedChild{
		"kine": kineChild(DefaultKineVersion),
		"etcd": etcdChild(DefaultEtcdVersion),
	}
}

// TestStagedChildProtocol pins the staging choreography every source-built child
// shares, over each real declaration with a fake build seam (nothing is fetched):
//
//   - a matching marker is a no-op: the build never runs and the bytes stay;
//   - with no Go toolchain, ErrNoGoToolchain is returned BEFORE the stale marker is
//     dropped, so the previously staged binary and marker survive untouched;
//   - the stale marker is gone by the time the build runs, and the old binary has
//     not been touched yet;
//   - the marker is written LAST: a failed build or a failed install leaves no
//     marker, and a successful stage leaves exactly "<version> <variant>\n".
func TestStagedChildProtocol(t *testing.T) {
	const oldBytes, newBytes = "old-binary", "new-binary"

	// stale seeds bd with an old binary and a marker naming another version.
	stale := func(t *testing.T, c stagedChild, bd string) {
		t.Helper()
		if err := os.WriteFile(c.binPath(bd), []byte(oldBytes), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.markerPath(bd), []byte("v0.0.1 "+c.variant+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	readFile := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return "<absent>"
		}
		return string(b)
	}

	for name, decl := range stagedChildDeclarations() {
		t.Run(name+"/matching marker is a no-op", func(t *testing.T) {
			c, bd := decl, t.TempDir()
			if err := os.WriteFile(c.binPath(bd), []byte(oldBytes), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := c.writeMarker(bd); err != nil {
				t.Fatal(err)
			}
			c.build = func(context.Context, string) (string, error) {
				t.Error("the build ran although the marker vouches for the target")
				return "", errors.New("unreachable")
			}
			if err := c.ensureInto(t.Context(), bd); err != nil {
				t.Fatalf("ensureInto = %v, want nil", err)
			}
			if got := readFile(c.binPath(bd)); got != oldBytes {
				t.Errorf("binary = %q, want the staged bytes left alone", got)
			}
		})

		t.Run(name+"/presence without a matching marker re-stages", func(t *testing.T) {
			c, bd := decl, t.TempDir()
			stale(t, c, bd)
			built := false
			c.build = func(_ context.Context, scratch string) (string, error) {
				built = true
				p := filepath.Join(scratch, "out")
				return p, os.WriteFile(p, []byte(newBytes), 0o755)
			}
			if err := c.ensureInto(t.Context(), bd); err != nil {
				t.Fatalf("ensureInto = %v", err)
			}
			if !built {
				t.Fatal("a stale marker was trusted: the build never ran")
			}
			if got := readFile(c.binPath(bd)); got != newBytes {
				t.Errorf("binary = %q, want %q", got, newBytes)
			}
			if got, want := readFile(c.markerPath(bd)), c.version+" "+c.variant+"\n"; got != want {
				t.Errorf("marker = %q, want %q", got, want)
			}
			if _, err := os.Stat(c.markerPath(bd) + ".tmp"); !os.IsNotExist(err) {
				t.Error("the atomic marker write left its .tmp behind")
			}
		})

		t.Run(name+"/no toolchain fails before the marker is dropped", func(t *testing.T) {
			t.Setenv("PATH", t.TempDir()) // exists, holds no `go`
			c, bd := decl, t.TempDir()
			stale(t, c, bd)
			staleMarker := readFile(c.markerPath(bd))
			c.build = func(context.Context, string) (string, error) {
				t.Error("the build ran without a toolchain on PATH")
				return "", errors.New("unreachable")
			}
			err := c.ensureInto(t.Context(), bd)
			if !errors.Is(err, ErrNoGoToolchain) {
				t.Fatalf("ensureInto = %v, want ErrNoGoToolchain", err)
			}
			if got := readFile(c.markerPath(bd)); got != staleMarker {
				t.Errorf("marker = %q, want the previous %q left untouched by a toolchain-less park", got, staleMarker)
			}
			if got := readFile(c.binPath(bd)); got != oldBytes {
				t.Errorf("binary = %q, want the previous bytes left untouched", got)
			}
		})

		t.Run(name+"/marker dropped before the binary is touched", func(t *testing.T) {
			c, bd := decl, t.TempDir()
			stale(t, c, bd)
			c.build = func(_ context.Context, scratch string) (string, error) {
				if _, err := os.Stat(c.markerPath(bd)); !os.IsNotExist(err) {
					t.Errorf("the stale marker still exists when the build runs (%v)", err)
				}
				if got := readFile(c.binPath(bd)); got != oldBytes {
					t.Errorf("the binary was touched before the build: %q", got)
				}
				return "", errors.New("build failed")
			}
			if err := c.ensureInto(t.Context(), bd); err == nil {
				t.Fatal("ensureInto with a failing build = nil")
			}
			if _, err := os.Stat(c.markerPath(bd)); !os.IsNotExist(err) {
				t.Error("a marker exists after a failed build: it vouches for bytes nobody built")
			}
		})

		t.Run(name+"/marker written last: a failed install leaves none", func(t *testing.T) {
			c, bd := decl, t.TempDir()
			// The binary's path is a non-empty directory, so the rename that installs
			// the built bytes fails AFTER the build succeeded.
			if err := os.MkdirAll(filepath.Join(c.binPath(bd), "occupied"), 0o755); err != nil {
				t.Fatal(err)
			}
			c.build = func(_ context.Context, scratch string) (string, error) {
				p := filepath.Join(scratch, "out")
				return p, os.WriteFile(p, []byte(newBytes), 0o755)
			}
			if err := c.ensureInto(t.Context(), bd); err == nil {
				t.Fatal("ensureInto with an uninstallable binary = nil")
			}
			if _, err := os.Stat(c.markerPath(bd)); !os.IsNotExist(err) {
				t.Error("the marker was written although the binary never installed")
			}
		})
	}
}
