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

package childreq

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testReq = Requirement{Path: "golang.org/x/net", Version: "v0.60.0", Sum: "h1:zip=", GoModSum: "h1:mod="}

// TestApply pins the raise: exactly the one requirement line moves, the hashes are
// appended to go.sum, and every tree the raise does not fit is refused by name.
func TestApply(t *testing.T) {
	cases := []struct {
		name, mod, wantMod, wantErr string
		notARaise                   bool
	}{
		{
			name:    "block line, indirect",
			mod:     "module x\n\nrequire (\n\tgolang.org/x/crypto v0.57.0 // indirect\n\tgolang.org/x/net v0.59.0 // indirect\n)\n",
			wantMod: "module x\n\nrequire (\n\tgolang.org/x/crypto v0.57.0 // indirect\n\tgolang.org/x/net v0.60.0 // indirect\n)\n",
		},
		{
			name:    "single require line",
			mod:     "module x\n\nrequire golang.org/x/net v0.9.0\n",
			wantMod: "module x\n\nrequire golang.org/x/net v0.60.0\n",
		},
		{name: "not required", mod: "module x\n\nrequire golang.org/x/text v0.42.0\n", wantErr: "does not require it"},
		{name: "a prefix module is not the module", mod: "module x\n\nrequire golang.org/x/network v0.1.0\n", wantErr: "does not require it"},
		{name: "required twice", mod: "module x\n\nrequire golang.org/x/net v0.59.0\nrequire (\n\tgolang.org/x/net v0.58.0\n)\n", wantErr: "more than one line"},
		{name: "already at the raise", mod: "module x\n\nrequire golang.org/x/net v0.60.0\n", notARaise: true},
		{name: "already past the raise", mod: "module x\n\nrequire golang.org/x/net v0.61.0\n", notARaise: true},
		{name: "a pseudo-version is refused", mod: "module x\n\nrequire golang.org/x/net v0.0.0-20260101000000-abcdef123456\n", wantErr: "not a vX.Y.Z release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(tc.mod), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("golang.org/x/net v0.59.0 h1:old="), 0o644); err != nil {
				t.Fatal(err)
			}
			err := Apply(root, []Requirement{testReq})
			switch {
			case tc.notARaise:
				if !errors.Is(err, ErrNotARaise) {
					t.Fatalf("Apply = %v, want ErrNotARaise", err)
				}
				return
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Apply = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			case err != nil:
				t.Fatalf("Apply: %v", err)
			}
			mod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
			if string(mod) != tc.wantMod {
				t.Errorf("go.mod =\n%s\nwant\n%s", mod, tc.wantMod)
			}
			sum, _ := os.ReadFile(filepath.Join(root, "go.sum"))
			want := "golang.org/x/net v0.59.0 h1:old=\ngolang.org/x/net v0.60.0 h1:zip=\ngolang.org/x/net v0.60.0/go.mod h1:mod=\n"
			if string(sum) != want {
				t.Errorf("go.sum =\n%s\nwant\n%s", sum, want)
			}
		})
	}
}

// TestRaises pins the raise set: x/net at XNetVersion, with both hashes present.
func TestRaises(t *testing.T) {
	if len(Raises) != 1 || Raises[0].Path != "golang.org/x/net" || Raises[0].Version != XNetVersion {
		t.Fatalf("Raises = %+v, want golang.org/x/net at %s alone", Raises, XNetVersion)
	}
	for _, r := range Raises {
		if !strings.HasPrefix(r.Sum, "h1:") || !strings.HasPrefix(r.GoModSum, "h1:") {
			t.Errorf("%s %s: go.sum hashes missing", r.Path, r.Version)
		}
		if _, err := parseRelease(r.Version); err != nil {
			t.Error(err)
		}
	}
}
