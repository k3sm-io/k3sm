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

package keystore

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore/typed"
)

// A typed version that authenticates but does not decode is ErrCorrupt
// (or ErrKindUnsupported for another envelope version) through the real
// store, and its error carries no byte, tag or length of the decrypted
// envelope: an error's text can reach a log.
func TestUndecodableTypedVersionErrorCarriesNoValueBytes(t *testing.T) {
	ctx := context.Background()
	big := bytes.Repeat([]byte("S"), typed.MaxEnvelopeSize+5)
	big[0] = typed.EnvelopeVersion
	for _, tc := range []struct {
		name  string
		pt    []byte
		leaks []string
		want  error
	}{
		{"a field past the end", []byte{typed.EnvelopeVersion, 0x7e, 0x10, 0x92, 'S', 'E', 'C', 'R', 'E', 'T'}, []string{"0x7e", "126", "4242", "SECRET"}, ErrCorrupt},
		{"an unknown tag", []byte{typed.EnvelopeVersion, 0x7e, 0x00, 0x06, 'S', 'E', 'C', 'R', 'E', 'T'}, []string{"0x7e", "126", "SECRET"}, ErrCorrupt},
		{"another envelope version", []byte{0xee, 'S', 'E', 'C', 'R', 'E', 'T'}, []string{"0xee", "238", "SECRET"}, ErrKindUnsupported},
		{"over the envelope cap", big, []string{strconv.Itoa(len(big)), "SSSS"}, ErrCorrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTypedStore(t)
			mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
			sealVersion(t, s, server, "tok", 1, KindToken, tc.pt)
			_, _, err := s.CurrentCredential(ctx, "tok")
			if !errors.Is(err, tc.want) {
				t.Fatalf("reading the undecodable version: %v, want %v", err, tc.want)
			}
			for _, leak := range tc.leaks {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("the error %q carries %q from the decrypted envelope", err, leak)
				}
			}
		})
	}
}

// valueLengthAllowed are the error arguments in pkg/keystore that take a
// length, an index or a tag and are not of a stored value: ciphertext,
// key files, metadata records and counts. Each is "file: expression".
// Anything else of that shape in an error is a value-derived number, which
// no error may carry.
var valueLengthAllowed = []string{
	"auditlog.go: len(b)",
	"deliver/declaration.go: len(d.Targets)",
	"deliver/state.go: len(d.Secrets)",
	"deliveries.go: len(b)",
	"deliveries.go: len(ds)",
	"deliveries.go: len(errs)",
	"deliveries.go: len(pt)",
	"deliveries.go: len(r.b)",
	"deliveries.go: len(sealed)",
	"deliveries.go: pt[0]",
	"deliveries.go: state[0]",
	"files.go: len(b)",
	"floor_merge_retired.go: len(b)",
	"floor_merge.go: len(mergedBytes)",
	"floor.go: len(b)",
	"floor.go: len(bs)",
	"floor.go: len(found)",
	"maintruns.go: keys[i]",
	"maintruns.go: len(f)",
	"maintruns.go: len(keys)",
	"maintruns.go: len(lines)",
	"master.go: len(raw)",
	"quota.go: len(order)",
	"quota.go: len(took)",
	"record.go: b[0]",
	"record.go: b[1]",
	"record.go: len(b)",
	"record.go: len(key)",
	"removedscopes.go: len(ids)",
	"rewrap.go: len(key)",
	"rewrap.go: len(newMaster)",
	"rotateaudit.go: len(left)",
	"serverlogs.go: len(line)",
	"socket/frame.go: len(f.Header)",
	"store.go: len(pt)",
	"typed/envelope.go: fs[i]",
	"typed/envelope.go: fs[next]",
	"typed/envelope.go: other[i]",
	"userscope.go: len(ku)",
	"userscope.go: len(names)",
}

// errorShapes are the calls whose arguments become an error's text.
var errorShapes = []string{"fmt.Errorf", "errors.New", "protocolErrorf", "refusedf", "valueRefusedf"}

// No error constructor in pkg/keystore takes a length, an index or a tag
// that is not on the reviewed list (valueLengthAllowed): a length or tag
// byte read from a value never appears in an error's text.
func TestNoErrorCarriesValueDerivedNumbers(t *testing.T) {
	fset := token.NewFileSet()
	var found []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !slices.Contains(errorShapes, exprString(call.Fun)) {
				return true
			}
			for _, arg := range call.Args {
				ast.Inspect(arg, func(m ast.Node) bool {
					switch x := m.(type) {
					case *ast.CallExpr:
						if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "len" {
							found = append(found, path+": "+exprString(x))
							return false
						}
					case *ast.IndexExpr:
						found = append(found, path+": "+exprString(x))
						return false
					case *ast.Ident:
						if x.Name == "tag" {
							found = append(found, path+": tag")
						}
					}
					return true
				})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(found)
	found = slices.Compact(found)
	for _, f := range found {
		if !slices.Contains(valueLengthAllowed, f) {
			t.Errorf("an error takes %s: a length, index or tag not on the reviewed list; if it is of no value, add it to valueLengthAllowed", f)
		}
	}
	for _, a := range valueLengthAllowed {
		if !slices.Contains(found, a) {
			t.Errorf("valueLengthAllowed lists %s, which no error takes any more", a)
		}
	}
}

// exprString is e as source, for the shapes the check matches.
func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprString(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		args := make([]string, len(x.Args))
		for i, a := range x.Args {
			args[i] = exprString(a)
		}
		return exprString(x.Fun) + "(" + strings.Join(args, ", ") + ")"
	case *ast.IndexExpr:
		return exprString(x.X) + "[" + exprString(x.Index) + "]"
	case *ast.BasicLit:
		return x.Value
	case *ast.BinaryExpr:
		return exprString(x.X) + x.Op.String() + exprString(x.Y)
	case *ast.SliceExpr:
		return exprString(x.X) + "[:]"
	}
	return "?"
}
