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
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The fake's real-filesystem seams (EnsureRootDir, CopyTree, Rename and
// RemoveTree) really perform their call; see the comment above EnsureRootDir.
// That is only safe while every path they are handed lies inside the test's own
// temp dir. A config that leaves InstallDir at its default hands them
// /Library/k3sm.swap, and a test run as root would then delete or create a live
// system tree. The guard below makes that a test failure instead.
//
// Containment is a LEXICAL prefix test against the same t.TempDir() string the
// test's config was built from. Neither side is symlink-resolved: on macOS the
// temp dir lives under /var, which is a link to /private/var, so resolving one
// side only would put every legitimate path "outside".

// fakeFSGuard is the root a fake's real-filesystem seams are confined to, and
// the violations they were refused for.
type fakeFSGuard struct {
	root       string
	mu         sync.Mutex
	violations []string
}

// errOutsideFakeRoot is what a refused real-filesystem seam returns.
var errOutsideFakeRoot = errors.New("outside the test's temp root")

// testRoots memoizes testRoot per test, so a test's config (stageCfg(t)) and
// its fake (newFakeSystem(t)) agree on one directory however often each is
// built.
var testRoots sync.Map // testing.TB -> string

// testRoot is this test's scratch system root: one t.TempDir(), the same string
// on every call within the test. A test builds every system path it hands the
// installer under it.
func testRoot(t testing.TB) string {
	t.Helper()
	if r, ok := testRoots.Load(t); ok {
		return r.(string)
	}
	r := t.TempDir()
	testRoots.Store(t, r)
	t.Cleanup(func() { testRoots.Delete(t) })
	return r
}

// newFakeSystem is a fakeSystem whose real-filesystem seams are confined to
// testRoot(t).
func newFakeSystem(t testing.TB) *fakeSystem {
	t.Helper()
	return (&fakeSystem{}).rootedIn(t)
}

// rootedIn confines f's real-filesystem seams to testRoot(t), and fails t at
// cleanup for every call that was refused for leaving it. It returns f, so a
// fake built with fields can be rooted where it is built.
func (f *fakeSystem) rootedIn(t testing.TB) *fakeSystem {
	t.Helper()
	g := &fakeFSGuard{root: filepath.Clean(testRoot(t))}
	f.fsGuard = g
	t.Cleanup(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, v := range g.violations {
			t.Errorf("fakeSystem: %s", v)
		}
	})
	return f
}

// inFakeRoot reports whether the real-filesystem seam op may touch paths. A
// path outside the root is recorded as a violation (the test fails at cleanup)
// and refused with errOutsideFakeRoot, so nothing outside the temp dir is ever
// touched. A fake with no root cannot fail its test, so it panics.
func (f *fakeSystem) inFakeRoot(op string, paths ...string) error {
	g := f.fsGuard
	for _, p := range paths {
		if g == nil {
			panic(fmt.Sprintf("fakeSystem: %s(%s) would touch the real filesystem, and this fake has no root: build it with newFakeSystem(t)", op, p))
		}
		c := filepath.Clean(p)
		if c == g.root || strings.HasPrefix(c, g.root+string(filepath.Separator)) {
			continue
		}
		msg := fmt.Sprintf("%s(%s) is outside the test root %s", op, p, g.root)
		g.mu.Lock()
		g.violations = append(g.violations, msg)
		g.mu.Unlock()
		return fmt.Errorf("%s: %w", msg, errOutsideFakeRoot)
	}
	return nil
}

// TestFakeSystemRefusesPathsOutsideItsRoot pins the guard itself: a path in the
// root passes, and a system path, a relative path, and a path that climbs out
// of the root are each refused.
func TestFakeSystemRefusesPathsOutsideItsRoot(t *testing.T) {
	f := &fakeSystem{fsGuard: &fakeFSGuard{root: filepath.Clean(t.TempDir())}}
	root := f.fsGuard.root
	if err := f.inFakeRoot("RemoveTree", root, filepath.Join(root, "Library", "k3sm.swap")); err != nil {
		t.Fatalf("a path inside the root was refused: %v", err)
	}
	for _, p := range []string{
		"/Library/k3sm.swap",
		"Library/k3sm.swap",
		filepath.Join(root, "..", "elsewhere"),
		root + "-sibling",
	} {
		if err := f.inFakeRoot("RemoveTree", p); !errors.Is(err, errOutsideFakeRoot) {
			t.Errorf("inFakeRoot(%q) = %v, want errOutsideFakeRoot", p, err)
		}
	}
	if got := len(f.fsGuard.violations); got != 4 {
		t.Errorf("recorded %d violations, want 4", got)
	}
}
