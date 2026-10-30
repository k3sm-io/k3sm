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

package layout_test

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install/order"
	"k3sm.io/k3sm/pkg/updater/layout"
)

// leafPackages are the two packages the updater and the installer share, each
// of which must import only the standard library.
var leafPackages = []string{"k3sm.io/k3sm/pkg/install/order", "k3sm.io/k3sm/pkg/updater/layout"}

// fakeTree is an lstat over a fixed map of absolute paths.
type fakeTree map[string]layout.Entry

func (f fakeTree) lstat(name string) (layout.Entry, error) {
	if e, ok := f[name]; ok {
		return e, nil
	}
	return layout.Entry{}, fs.ErrNotExist
}

// rootDir is a root-owned 0755 directory.
var rootDir = layout.Entry{UID: 0, Mode: fs.ModeDir | 0o755}

// sound is the tree under /Library/k3sm as the installer leaves it.
func sound() fakeTree {
	return fakeTree{
		"/":                             rootDir,
		"/Library":                      rootDir,
		"/Library/k3sm":                 rootDir,
		"/Library/k3sm/versions":        rootDir,
		"/Library/k3sm/versions/0.3.0":  rootDir,
		"/Library/k3sm/updater-state":   {UID: 0, Mode: fs.ModeDir | 0o700},
		"/Library/k3sm/updater/current": {UID: 0, Mode: fs.ModeSymlink | 0o755},
	}
}

// TestLeafContract is the contract the updater's leaf packages keep with the
// installer: the restart order, the import boundary, the ownership refusals,
// the frozen launchd arguments and the installer-only releases.
func TestLeafContract(t *testing.T) {
	l := layout.New(layout.DefaultRoot)
	for _, tc := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"restart order unchanged from the installer", func(t *testing.T) {
			// The sequence the installer has always used: the data-volume
			// oneshot (when declared), netd, the role's node daemon; stopped
			// node daemon first, then netd.
			labels := func(js []order.Job) []string {
				var out []string
				for _, j := range js {
					out = append(out, j.Label)
				}
				return out
			}
			for _, c := range []struct {
				role      order.Role
				datavol   bool
				start     []string
				stop      []string
				oneshotAt int
			}{
				{order.Server, false, []string{"io.k3sm.netd", "io.k3sm.server"}, []string{"io.k3sm.server", "io.k3sm.netd"}, -1},
				{order.Agent, false, []string{"io.k3sm.netd", "io.k3sm.agent"}, []string{"io.k3sm.agent", "io.k3sm.netd"}, -1},
				{order.Server, true, []string{"io.k3sm.datavol", "io.k3sm.netd", "io.k3sm.server"}, []string{"io.k3sm.server", "io.k3sm.netd"}, 0},
				{order.Agent, true, []string{"io.k3sm.datavol", "io.k3sm.netd", "io.k3sm.agent"}, []string{"io.k3sm.agent", "io.k3sm.netd"}, 0},
			} {
				start := order.Start(c.role, c.datavol)
				if got := labels(start); !slices.Equal(got, c.start) {
					t.Errorf("Start(%v, %v) = %v, want %v", c.role, c.datavol, got, c.start)
				}
				for i, j := range start {
					if j.Oneshot != (i == c.oneshotAt) {
						t.Errorf("Start(%v, %v)[%d] %s oneshot = %v", c.role, c.datavol, i, j.Label, j.Oneshot)
					}
				}
				if got := labels(order.Stop(c.role)); !slices.Equal(got, c.stop) {
					t.Errorf("Stop(%v) = %v, want %v", c.role, got, c.stop)
				}
			}
		}},
		{"leaves import only the standard library", func(t *testing.T) {
			// go list -deps at CGO_ENABLED=1, the posture the repo builds at.
			// Anything not in the standard library, the installer's launchd
			// renderer and client-go included, is a failure.
			args := append([]string{"list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}"}, leafPackages...)
			cmd := exec.Command("go", args...)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps: %v\n%s", err, out)
			}
			for _, dep := range strings.Fields(string(out)) {
				if !slices.Contains(leafPackages, dep) {
					t.Errorf("a leaf package depends on %s, outside the standard library", dep)
				}
			}
		}},
		{"ancestor writable by group or other refused", func(t *testing.T) {
			for _, mode := range []fs.FileMode{0o775, 0o757, 0o777} {
				tree := sound()
				tree["/Library"] = layout.Entry{UID: 0, Mode: fs.ModeDir | mode}
				if err := layout.CheckOwnership(tree.lstat, "/Library/k3sm/versions/0.3.0"); !errors.Is(err, layout.ErrWritableByOthers) {
					t.Errorf("ancestor mode %s: err = %v, want ErrWritableByOthers", mode, err)
				}
			}
			if err := layout.CheckOwnership(sound().lstat, "/Library/k3sm/versions/0.3.0"); err != nil {
				t.Errorf("sound tree refused: %v", err)
			}
		}},
		{"ancestor not root-owned refused", func(t *testing.T) {
			tree := sound()
			tree["/Library/k3sm/versions"] = layout.Entry{UID: 501, Mode: fs.ModeDir | 0o755}
			if err := layout.CheckOwnership(tree.lstat, "/Library/k3sm/versions/0.3.0"); !errors.Is(err, layout.ErrNotRootOwned) {
				t.Errorf("err = %v, want ErrNotRootOwned", err)
			}
			// A symlinked component is refused too: the check is about
			// where the bytes live, and a link can move.
			if err := layout.CheckOwnership(sound().lstat, "/Library/k3sm/updater/current"); !errors.Is(err, layout.ErrNotDirectory) {
				t.Errorf("symlink: err = %v, want ErrNotDirectory", err)
			}
			if err := layout.CheckOwnership(sound().lstat, "/Library/k3sm/absent"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("absent: err = %v, want fs.ErrNotExist", err)
			}
		}},
		{"frozen program arguments for every label", func(t *testing.T) {
			seen := map[string]bool{}
			for _, role := range []order.Role{order.Server, order.Agent} {
				for _, j := range order.Start(role, true) {
					if seen[j.Label] {
						continue
					}
					seen[j.Label] = true
					got, err := l.DaemonArguments(layout.K3smBinary, j.Label)
					want := []string{"/Library/k3sm/current/k3sm", "daemon", j.Label}
					if err != nil || !slices.Equal(got, want) {
						t.Errorf("DaemonArguments(k3sm, %s) = %v, %v; want %v", j.Label, got, err, want)
					}
				}
			}
			if len(seen) != 4 {
				t.Errorf("order names %d labels, want 4", len(seen))
			}
			if got, want := l.UpdaterArguments(), []string{"/Library/k3sm/updater/current/k3sm-updater", "daemon", layout.UpdaterLabel}; !slices.Equal(got, want) {
				t.Errorf("UpdaterArguments = %v, want %v", got, want)
			}
			if got, want := l.GuardArguments(), []string{"/Library/k3sm/updater/guard/k3sm-updater", "guard"}; !slices.Equal(got, want) {
				t.Errorf("GuardArguments = %v, want %v", got, want)
			}
			for _, bad := range [][2]string{{"../k3sm", order.NetdLabel}, {"", order.NetdLabel}, {"k3sm", "com.example.x"}, {"k3sm", "io.k3sm.Netd"}, {"k3sm", ""}} {
				if _, err := l.DaemonArguments(bad[0], bad[1]); !errors.Is(err, layout.ErrBadName) {
					t.Errorf("DaemonArguments(%q, %q) err = %v, want ErrBadName", bad[0], bad[1], err)
				}
			}
		}},
		{"requiresInstaller refused by the layout check", func(t *testing.T) {
			if err := layout.CheckActivatable("0.3.0", true); !errors.Is(err, layout.ErrRequiresInstaller) {
				t.Errorf("err = %v, want ErrRequiresInstaller", err)
			}
			if err := layout.CheckActivatable("0.3.0", false); err != nil {
				t.Errorf("an ordinary release refused: %v", err)
			}
			if err := layout.CheckActivatable("../0.3.0", false); !errors.Is(err, layout.ErrBadVersion) {
				t.Errorf("bad version: err = %v, want ErrBadVersion", err)
			}
		}},
	} {
		t.Run(tc.name, tc.run)
	}
}
