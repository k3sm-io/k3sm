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

// The errors the syntactic check (TestNoErrorCarriesValueDerivedNumbers)
// cannot see, a value's number or bytes passed through a variable, carry
// none either: a quota refusal names the cap, never the total that counts
// the value's length, and a refused refresh-owner change names neither
// owner, both read from a value.
func TestValueNumbersNotInErrorTexts(t *testing.T) {
	t.Run("quota", func(t *testing.T) {
		value := bytes.Repeat([]byte("v"), 4321)
		base := int64(maxScopeBytes - 100)
		err := judgeScopeQuota(map[string]int64{}, "token", value, base)
		if !errors.Is(err, ErrQuota) {
			t.Fatalf("a put past the byte budget: %v, want ErrQuota", err)
		}
		total := base + entryWriteBytes("token", value)
		for _, leak := range []string{strconv.FormatInt(total, 10), strconv.Itoa(len(value))} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("the quota refusal %q carries %s, a number counting the value's length", err, leak)
			}
		}
	})
	t.Run("refresh owner", func(t *testing.T) {
		owned := func(access, owner string) typed.Envelope {
			e := oauthEnvelope(access, "r-"+access)
			e.Credential.RefreshOwner = owner
			return e
		}
		s, _ := newTypedStore(t)
		mustPutCredential(t, s, "pair", KindOAuth, owned("a1", "server/owner-one"))
		_, err := s.RotateCredential(context.Background(), "pair", KindOAuth, owned("a2", "server/owner-two"))
		if !errors.Is(err, ErrRefreshOwnerFixed) {
			t.Fatalf("a rotation to another owner: %v, want ErrRefreshOwnerFixed", err)
		}
		for _, leak := range []string{"owner-one", "owner-two"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("the refusal %q carries %q, read from a value", err, leak)
			}
		}
	})
}

// valueLengthAllowed are the error arguments in pkg/keystore that take a
// length, an index or a tag and are not of a stored value: ciphertext,
// key files, metadata records and counts. Each is "file: function:
// expression", the function a method's Type.Name and a package-level
// declaration's "var", so an entry reviewed in one function never admits
// the same expression in another function of its file.
// Anything else of that shape in an error is a value-derived number, which
// no error may carry.
var valueLengthAllowed = []string{
	"auditlog.go: marshalAuditLine: len(b)",
	"deliver/declaration.go: Parse: len(d.Targets)",
	"deliver/state.go: ParseState: len(d.Secrets)",
	"deliveries.go: parseDeliveries: len(pt)",
	"deliveries.go: parseDeliveries: len(r.b)",
	"deliveries.go: parseDeliveries: pt[0]",
	"deliveries.go: parseDeliveries: state[0]",
	"deliveries.go: parseDeliveriesRecord: len(b)",
	"deliveries.go: UserScope.addDeliveryLocked: len(ds)",
	"deliveries.go: UserScope.auditSealed: len(errs)",
	"deliveries.go: UserScope.auditSealed: len(sealed)",
	"deliveries.go: UserScope.writeDeliveries: len(b)",
	"deliveries.go: UserScope.writeDeliveries: len(pt)",
	"files.go: FileStore.readRandom: len(b)",
	"floor_merge_retired.go: FileStore.writeRetiredPending: len(b)",
	"floor_merge.go: FileStore.mergeFloor: len(mergedBytes)",
	"floor.go: FileStore.syncFloor: len(found)",
	"floor.go: floorLock.updatePruned: len(b)",
	"floor.go: parseFloor: len(bs)",
	"maintruns.go: parseMaintenanceRun: keys[i]",
	"maintruns.go: parseMaintenanceRun: len(f)",
	"maintruns.go: parseMaintenanceRun: len(keys)",
	"maintruns.go: parseMaintenanceRuns: len(lines)",
	"master.go: FileStore.readKeyFile: len(raw)",
	"quota.go: userBurial.bury: len(order)",
	"quota.go: userBurial.bury: len(took)",
	"record.go: newGCM: len(key)",
	"record.go: parseRecord: b[1]",
	"record.go: parseRecordOf: b[0]",
	"record.go: parseRecordOf: len(b)",
	"removedscopes.go: parseRemovedScopes: len(ids)",
	"rewrap.go: FileStore.recordsSealedUnder: len(key)",
	"rewrap.go: FileStore.rewrap: len(newMaster)",
	"rotateaudit.go: cloneArchive: len(left)",
	"rotateaudit.go: stripXattrs: len(left)",
	"serverlogs.go: ServerLogs.appendLocked: len(line)",
	"socket/frame.go: AppendFrame: len(f.Header)",
	"store.go: decodePointer: len(pt)",
	"typed/envelope.go: Decode: fs[i]",
	"typed/envelope.go: Decode: fs[next]",
	"typed/envelope.go: Encode: other[i]",
	"userscope.go: UserScope.checkMintable: len(names)",
	"userscope.go: UserScope.mint: len(names)",
	"userscope.go: UserScope.openScopeKey: len(ku)",
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
		for _, decl := range f.Decls {
			where := path + ": " + declName(decl) + ": "
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !slices.Contains(errorShapes, exprString(call.Fun)) {
					return true
				}
				for _, arg := range call.Args {
					ast.Inspect(arg, func(m ast.Node) bool {
						switch x := m.(type) {
						case *ast.CallExpr:
							if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "len" {
								found = append(found, where+exprString(x))
								return false
							}
						case *ast.IndexExpr:
							found = append(found, where+exprString(x))
							return false
						case *ast.Ident:
							if x.Name == "tag" {
								found = append(found, where+"tag")
							}
						}
						return true
					})
				}
				return true
			})
		}
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

// declName names a top-level declaration for valueLengthAllowed: a
// function by its name, a method as Type.Name, anything else as "var".
func declName(d ast.Decl) string {
	fd, ok := d.(*ast.FuncDecl)
	if !ok {
		return "var"
	}
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	return exprString(t) + "." + fd.Name.Name
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
