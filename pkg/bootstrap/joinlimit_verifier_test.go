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

package bootstrap

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// verifierMint mints a token through one shipped verifier's OWN creation path
// and returns the verifier, the raw token a joining node would present, and the
// public id that creation handed back.
type verifierMint func(t *testing.T) (v TokenVerifier, tok, user string)

// shippedVerifiers is the coverage table: one row per package-level type in
// pkg/bootstrap that satisfies TokenVerifier, keyed by the type's name. The
// structural scan in TestJoinTokenIDMatchesEveryShippedVerifier fails when a
// type satisfies the interface without a row here, so a new verifier cannot
// join the package without proving its tokens key the limiter correctly.
var shippedVerifiers = map[string]verifierMint{
	"TokenStore": func(t *testing.T) (TokenVerifier, string, string) {
		s := NewTokenStore(time.Now)
		user, secret, _, err := s.Create(time.Hour)
		if err != nil {
			t.Fatalf("TokenStore.Create: %v", err)
		}
		return s, FormatToken("deadbeef", user, secret), user
	},
	"FileTokenStore": func(t *testing.T) (TokenVerifier, string, string) {
		s := NewFileTokenStore(filepath.Join(t.TempDir(), BootstrapTokensFile), time.Now)
		user, secret, _, err := s.Create(time.Hour)
		if err != nil {
			t.Fatalf("FileTokenStore.Create: %v", err)
		}
		return s, FormatToken("deadbeef", user, secret), user
	},
}

// TestJoinTokenIDMatchesEveryShippedVerifier pins the TokenVerifier contract
// joinTokenID rests on: every token a shipped verifier accepts parses with
// ParseToken to the exact id its creation returned, so each token gets its own
// post-auth limiter bucket instead of the shared unparsedTokenBucket.
func TestJoinTokenIDMatchesEveryShippedVerifier(t *testing.T) {
	t.Run("coverage", func(t *testing.T) {
		names := make([]string, 0, len(shippedVerifiers))
		for name := range shippedVerifiers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			mint := shippedVerifiers[name]
			t.Run(name, func(t *testing.T) {
				v, tok, user := mint(t)
				if got := reflect.Indirect(reflect.ValueOf(v)).Type().Name(); got != name {
					t.Fatalf("row %q mints a %s; the row key must name the verifier it exercises", name, got)
				}
				if err := v.VerifyToken(t.Context(), tok); err != nil {
					t.Fatalf("%s.VerifyToken rejected its own freshly minted token: %v", name, err)
				}
				if got := joinTokenID(tok); got != user {
					t.Errorf("joinTokenID(%s token) = %q, want the minted id %q", name, got, user)
				}
			})
		}
	})

	t.Run("structural", func(t *testing.T) {
		for _, name := range tokenVerifierImplementations(t) {
			if _, ok := shippedVerifiers[name]; !ok {
				t.Errorf("type %s satisfies TokenVerifier but has no row in shippedVerifiers: "+
					"add one proving joinTokenID keys its tokens by their real id, or its whole "+
					"token population shares the %q limiter bucket", name, unparsedTokenBucket)
			}
		}
	})

	t.Run("fallback", func(t *testing.T) {
		const malformed = "not-a-k10-token"
		for name, mint := range shippedVerifiers {
			v, _, _ := mint(t)
			if err := v.VerifyToken(t.Context(), malformed); err == nil {
				t.Fatalf("%s accepted the malformed control token %q", name, malformed)
			}
		}
		if got := joinTokenID(malformed); got != unparsedTokenBucket {
			t.Errorf("joinTokenID(%q) = %q, want the shared fallback bucket", malformed, got)
		}
	})
}

// tokenVerifierImplementations type-checks the non-test sources of this
// package from source and returns, sorted, the name of every package-level
// named type whose value or pointer type satisfies TokenVerifier.
func tokenVerifierImplementations(t *testing.T) []string {
	t.Helper()
	bp, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("locate package sources: %v", err)
	}
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(bp.GoFiles))
	for _, f := range bp.GoFiles {
		af, err := parser.ParseFile(fset, filepath.Join(bp.Dir, f), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		files = append(files, af)
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check(bp.Name, fset, files, nil)
	if err != nil {
		t.Fatalf("type-check %s: %v", bp.Dir, err)
	}
	obj, ok := pkg.Scope().Lookup("TokenVerifier").(*types.TypeName)
	if !ok {
		t.Fatal("TokenVerifier is not a package-level type")
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		t.Fatal("TokenVerifier is not an interface")
	}
	var impls []string
	for _, name := range pkg.Scope().Names() {
		tn, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok || types.IsInterface(tn.Type()) {
			continue
		}
		if types.Implements(tn.Type(), iface) || types.Implements(types.NewPointer(tn.Type()), iface) {
			impls = append(impls, name)
		}
	}
	if len(impls) == 0 {
		t.Fatalf("found no TokenVerifier implementation in %s: the scan is not seeing the package (%s)",
			bp.Dir, strings.Join(bp.GoFiles, ", "))
	}
	return impls
}
