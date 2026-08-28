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

package images

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// shippedManifest is the committed record this package's constants are pinned against.
// The relative path is the seam: every other test builds its own manifest in a TempDir.
func shippedManifest() string {
	return filepath.Join("..", "..", "hack", "images", "mirror.yaml")
}

// TestLockstepShippedManifest is the drift gate. It rides `go test ./...`, so a constant
// bumped without its manifest entry (or the reverse) reds every CI run with no extra
// wiring anywhere.
func TestLockstepShippedManifest(t *testing.T) {
	if err := LockstepFile(shippedManifest()); err != nil {
		t.Fatalf("the pin constants and %s have drifted apart:\n%v", shippedManifest(), err)
	}
}

// TestShippedManifestValidates keeps the schema rules pointed at the real record, not
// only at fixtures — a fixture-only schema test proves the parser, never the manifest.
func TestShippedManifestValidates(t *testing.T) {
	m, err := LoadManifest(shippedManifest())
	if err != nil {
		t.Fatalf("the committed manifest does not satisfy its own schema: %v", err)
	}
	if len(m.Images) == 0 {
		t.Fatal("the committed manifest has no entries")
	}
	if _, ok := m.Entry("buildkit"); !ok {
		t.Fatalf("the committed manifest lost its buildkit entry (has: %s)", strings.Join(m.Names(), ", "))
	}
}

// TestEveryPinnedConstantIsRegistered closes the one hole Lockstep cannot see: a pinned
// CONSTANT that was never added to Pins() has no manifest partner to lose, so both
// directions of the 1:1 check stay silent about it. Go cannot enumerate constants at run
// time, so this walks the package's own syntax tree instead. It reads Go source with
// go/parser, never with a text scraper — a regexp over source is how a check like this
// starts passing for the wrong reason.
func TestEveryPinnedConstantIsRegistered(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse this package: %v", err)
	}
	registered := make(map[string]bool)
	for _, p := range Pins() {
		registered[p.Ref] = true
	}

	found := 0
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						lit, ok := v.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						s, err := strconv.Unquote(lit.Value)
						if err != nil || !strings.Contains(s, "@sha256:") {
							continue
						}
						found++
						name := "?"
						if i < len(vs.Names) {
							name = vs.Names[i].Name
						}
						if !registered[s] {
							t.Errorf("%s: constant %s is a digest pin but is not returned by Pins(); "+
								"nothing checks it against the mirror manifest", filepath.Base(path), name)
						}
					}
				}
			}
		}
	}
	// Positive control: if the walk found no pinned constants at all it measured
	// nothing, and "no unregistered constants" would be true for the wrong reason.
	if found == 0 {
		t.Fatal("found no digest-pinned string constants in this package — the walk measured nothing")
	}
	if found != len(Pins()) {
		t.Errorf("found %d digest-pinned constants but Pins() returns %d", found, len(Pins()))
	}
}

func TestLockstep(t *testing.T) {
	const ref = "ghcr.io/k3sm-io/mirror/buildkit@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const other = "ghcr.io/k3sm-io/mirror/buildkit@sha256:9999999999999999999999999999999999999999999999999999999999999999"

	man := func(entries ...Entry) *Manifest { return &Manifest{Images: entries} }
	entry := func(name, mirror string) Entry { return Entry{Name: name, Mirror: mirror} }

	tests := []struct {
		name     string
		pins     []Pin
		manifest *Manifest
		wantErr  string
	}{
		{
			name:     "1:1 match",
			pins:     []Pin{{Name: "buildkit", Ref: ref}},
			manifest: man(entry("buildkit", ref)),
		},
		{
			name:     "digest flipped in the manifest",
			pins:     []Pin{{Name: "buildkit", Ref: ref}},
			manifest: man(entry("buildkit", other)),
			wantErr:  "disagree",
		},
		{
			name:     "constant with no manifest entry",
			pins:     []Pin{{Name: "buildkit", Ref: ref}},
			manifest: man(entry("something-else", ref)),
			wantErr:  "has NO manifest entry",
		},
		{
			name:     "manifest entry with no constant is an orphan",
			pins:     []Pin{{Name: "buildkit", Ref: ref}},
			manifest: man(entry("buildkit", ref), entry("stale", other)),
			wantErr:  "ORPHAN",
		},
		{
			name:     "no pins declared is not vacuously green",
			pins:     nil,
			manifest: man(entry("buildkit", ref)),
			wantErr:  "no pins declared",
		},
		{
			name:     "nil manifest",
			pins:     []Pin{{Name: "buildkit", Ref: ref}},
			manifest: nil,
			wantErr:  "nil manifest",
		},
		{
			name:     "duplicate pin name",
			pins:     []Pin{{Name: "buildkit", Ref: ref}, {Name: "buildkit", Ref: ref}},
			manifest: man(entry("buildkit", ref)),
			wantErr:  "declared twice",
		},
		{
			name:     "empty pin ref",
			pins:     []Pin{{Name: "buildkit", Ref: ""}},
			manifest: man(entry("buildkit", ref)),
			wantErr:  "empty name or ref",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Lockstep(tc.pins, tc.manifest)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want lockstep, got: %v", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
