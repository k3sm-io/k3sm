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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// vkModulePath is the Virtual Kubelet module import path. B67 confines every
// import of it (and its subpackages) to the vkadapter package; TestVKImportsConfined
// ToAdapter is the module-wide gate that keeps it that way.
const vkModulePath = "github.com/virtual-kubelet/virtual-kubelet"

// vkAdapterRelDir is the vkadapter package directory, module-root-relative. It is
// the ONE directory allowed to import Virtual Kubelet directly (the single seam).
var vkAdapterRelDir = filepath.Join("pkg", "provider", "vkadapter")

// moduleRoot walks up from this test file's directory to the module root (the
// directory holding go.mod), independent of the `go test` working directory. It
// mirrors hack/acceptance/phases_test.go's repoRoot so the module-wide walk below
// is anchored to the repo, never to CWD.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0): could not resolve this test file's path")
	}
	dir := filepath.Dir(file)
	start := dir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("moduleRoot: no go.mod found walking up from %s", start)
		}
		dir = parent
	}
}

// importsVK reports whether an import path IS the Virtual Kubelet module or one of
// its subpackages. The check is a path-BOUNDARY match ("…/virtual-kubelet" exactly,
// or a "…/virtual-kubelet/" prefix), NOT a substring — so a hypothetical unrelated
// path merely containing the string is not falsely flagged.
func importsVK(importPath string) bool {
	return importPath == vkModulePath || strings.HasPrefix(importPath, vkModulePath+"/")
}

// TestVKImportsConfinedToAdapter is the B67 module-wide gate: EVERY .go file under
// the module (including _test.go) is lexically parsed for its imports, and any
// import of the Virtual Kubelet module (or a subpackage) is a FAILURE unless the
// file lives in the vkadapter package directory — the single sanctioned seam.
//
// It parses imports only (go/parser.ParseFile with parser.ImportsOnly), a hermetic
// lexical pass that never builds the CGO/kine module, so it runs anywhere `go test`
// does. The vkadapter directory is excluded by DIRECTORY IDENTITY (an exact
// filepath compare), not a substring of the path, so no sibling could smuggle a VK
// import past the gate by name.
//
// Positive controls guard against a mis-rooted or empty walk passing vacuously:
// the walk must visit a plausible number of .go files AND the vkadapter package
// itself must genuinely import Virtual Kubelet (the confinement target really holds
// the coupling). If either fails, the walk did not actually run and the test errors.
func TestVKImportsConfinedToAdapter(t *testing.T) {
	root := moduleRoot(t)
	adapterDir := filepath.Join(root, vkAdapterRelDir)
	fset := token.NewFileSet()

	type offender struct {
		file       string
		importPath string
	}
	var (
		offenders    []offender
		goFilesSeen  int
		adapterFiles int
		adapterVKimp bool
	)

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip vendored/toolchain trees that are not part of this module's source.
			if info.Name() == "vendor" || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		goFilesSeen++

		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Errorf("parse imports of %s: %v", path, perr)
			return nil
		}

		inAdapter := filepath.Dir(path) == adapterDir
		if inAdapter {
			adapterFiles++
		}
		for _, spec := range f.Imports {
			ip, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				t.Errorf("unquote import %q in %s: %v", spec.Path.Value, path, uerr)
				continue
			}
			if !importsVK(ip) {
				continue
			}
			if inAdapter {
				adapterVKimp = true
				continue // the one sanctioned seam
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			offenders = append(offenders, offender{file: rel, importPath: ip})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk module root %s: %v", root, walkErr)
	}

	t.Run("no_vk_imports_outside_adapter", func(t *testing.T) {
		if len(offenders) == 0 {
			return
		}
		for _, o := range offenders {
			t.Errorf("%s imports %q directly — route it through k3sm.io/k3sm/pkg/provider/vkadapter instead (B67 confinement)", o.file, o.importPath)
		}
	})

	// Positive controls: prove the walk actually ran and actually inspected VK
	// imports, so a mis-rooted or zero-file walk cannot green this test vacuously.
	t.Run("walk_visited_plausible_file_count", func(t *testing.T) {
		if goFilesSeen <= 20 {
			t.Fatalf("walk visited only %d .go files under %s; expected the module's full source tree (>20) — the walk is mis-rooted, so a green result would be vacuous", goFilesSeen, root)
		}
	})
	t.Run("adapter_package_genuinely_imports_vk", func(t *testing.T) {
		if adapterFiles == 0 {
			t.Fatalf("no .go files found in the vkadapter dir %s; the confinement target is missing, so the gate proves nothing", adapterDir)
		}
		if !adapterVKimp {
			t.Fatalf("vkadapter (%s) does not import %q — B67 confines VK coupling THERE, so if the adapter holds none the confinement is a no-op and this gate is vacuous", adapterDir, vkModulePath)
		}
	})
}
