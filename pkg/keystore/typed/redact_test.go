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

package typed

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSecretTypesRedactWhenFormatted is U149's formatting case: an Envelope
// and a Credential print the kind, field names, presence and lengths, and
// never a byte of RefreshToken, AccessToken, Value or Seed, under every fmt
// verb, through slog (the JSON handler included, alone or in a slice or a
// map), encoding/json, encoding/gob, MarshalText and inside a wrapped error.
func TestSecretTypesRedactWhenFormatted(t *testing.T) {
	markers := map[string][]byte{
		"refresh": []byte("MARKERrefreshQ7"),
		"access":  []byte("MARKERaccessW3"),
		"value":   []byte("MARKERvalueZ9"),
		"seed":    bytes.Repeat([]byte("SEEDMRK!"), 4),
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	cases := map[string]Envelope{
		"oauth": {Credential: Credential{AccessToken: markers["access"], AccessExpiresAt: now, RefreshOwner: "local"}, RefreshToken: markers["refresh"]},
		"token": {Credential: Credential{Value: markers["value"], ExpiresAt: now}},
		"ssh":   {Credential: Credential{Algorithm: SSHAlgorithmEd25519, Seed: markers["seed"]}},
		// Every secret field at once, as no valid envelope holds.
		"all": {Credential: Credential{Value: markers["value"], Seed: markers["seed"], AccessToken: markers["access"]}, RefreshToken: markers["refresh"]},
	}
	forms := func(secret []byte) []string {
		return []string{
			string(secret), hex.EncodeToString(secret), strings.ToUpper(hex.EncodeToString(secret)),
			base64.StdEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret),
			fmt.Sprintf("%v", secret), fmt.Sprintf("%q", secret), fmt.Sprintf("% x", secret),
		}
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10.3v"}
	for name, e := range cases {
		var outs []string
		for _, tm := range []encoding.TextMarshaler{e, e.Credential} {
			b, err := tm.MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			outs = append(outs, string(b))
		}
		for i, v := range []any{e, &e, e.Credential, &e.Credential, []Envelope{e}, map[string]Credential{"c": e.Credential}} {
			for _, verb := range verbs {
				outs = append(outs, fmt.Sprintf(verb, v))
			}
			outs = append(outs, fmt.Errorf("wrapped: %v", v).Error(), fmt.Sprint(v), fmt.Sprintln(v))
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("msg", "credential", v, slog.Group("g", "c", v))
			// The JSON handler resolves a LogValuer it is handed, and hands a
			// slice or map of them to encoding/json, which MarshalJSON
			// reaches.
			slog.New(slog.NewJSONHandler(&buf, nil)).Info("msg", "credential", v, slog.Group("g", "c", v))
			outs = append(outs, buf.String())
			j, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("%s: json.Marshal of case %d: %v", name, i, err)
			}
			outs = append(outs, string(j))
			var g bytes.Buffer
			if err := gob.NewEncoder(&g).Encode(v); err != nil {
				t.Fatalf("%s: gob of case %d: %v", name, i, err)
			}
			outs = append(outs, g.String())
		}
		outs = append(outs, e.String(), e.GoString(), e.Credential.String(), e.Credential.GoString(),
			e.LogValue().String(), e.Credential.LogValue().String())
		for _, out := range outs {
			for m, secret := range markers {
				for _, f := range forms(secret) {
					if strings.Contains(out, f) {
						t.Fatalf("%s: the %s marker appears as %q in %q", name, m, f, out)
					}
				}
			}
		}
	}
	got := fmt.Sprint(cases["oauth"])
	for _, want := range []string{"oauth", "accessToken", "14 bytes", "refreshToken", "15 bytes", "refreshOwner"} {
		if !strings.Contains(got, want) {
			t.Errorf("redacted oauth envelope %q does not show %q", got, want)
		}
	}
	if got := fmt.Sprint(cases["ssh"].Credential); !strings.Contains(got, "ssh") || !strings.Contains(got, "seed") || !strings.Contains(got, "32 bytes") {
		t.Errorf("redacted ssh credential %q does not name its kind, field and length", got)
	}
}

// TestNoUnexportedSecretField is the vet-style half of U149's formatting
// case. fmt and the reflection encoders cannot call a method on an
// unexported struct field, so a struct with an unexported field of type
// Credential or Envelope (or a pointer, slice, array or map of one) prints
// that field's bytes under %v, whatever its methods say. No non-test file in
// pkg/keystore or below declares one.
func TestNoUnexportedSecretField(t *testing.T) {
	root := ".." // pkg/keystore
	fset := token.NewFileSet()
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		inTyped := f.Name.Name == "typed"
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				if !secretType(fld.Type, inTyped) {
					continue
				}
				for _, name := range fld.Names {
					if !name.IsExported() {
						found = append(found, fset.Position(name.Pos()).String()+": "+name.Name)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Fatalf("unexported fields of a secret type, which %%v prints byte for byte: %v", found)
	}
}

// secretType reports whether expr names Credential or Envelope (qualified
// typed. outside package typed), directly or through a pointer, slice,
// array or map.
func secretType(expr ast.Expr, inTyped bool) bool {
	switch x := expr.(type) {
	case *ast.StarExpr:
		return secretType(x.X, inTyped)
	case *ast.ArrayType:
		return secretType(x.Elt, inTyped)
	case *ast.MapType:
		return secretType(x.Key, inTyped) || secretType(x.Value, inTyped)
	case *ast.Ident:
		return inTyped && (x.Name == "Credential" || x.Name == "Envelope")
	case *ast.SelectorExpr:
		pkg, ok := x.X.(*ast.Ident)
		return ok && pkg.Name == "typed" && (x.Sel.Name == "Credential" || x.Sel.Name == "Envelope")
	}
	return false
}
