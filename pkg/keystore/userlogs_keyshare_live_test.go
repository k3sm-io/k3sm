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
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The per-uid key share is a lifetime share: every key a uid adds is
// charged to it, buried or live, since a buried key stays in the floor and
// counts against keyBound for good. A uid whose put/rm churn spends its
// share is refused its next grant before any write; its rm of an entry the
// floor holds still succeeds, since that tombstone adds no key; and another
// uid's grant is unaffected. The global key count holds every buried key.
func TestFloorKeyShareChargesBuriedKeys(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	l := syncedFloor(t, s)
	const room = 3
	l.mu.Lock()
	held := l.state.uidKeys[1001]
	l.maxKeys, l.maxShare = l.state.keys+100, held+room
	keys0 := l.state.keys
	l.mu.Unlock()
	for i := range room {
		name := fmt.Sprintf("user/1001/churn%d", i)
		if _, err := u.Put(ctx, name, KindOpaque, []byte("v")); err != nil {
			t.Fatalf("churn put %d: %v", i, err)
		}
		if err := u.Delete(ctx, name); err != nil {
			t.Fatalf("churn rm %d: %v", i, err)
		}
	}
	syncedFloor(t, s)
	l.mu.Lock()
	keys, charged := l.state.keys, l.state.uidKeys[1001]
	l.mu.Unlock()
	if want := keys0 + room; keys != want {
		t.Fatalf("the floor's global key count is %d, want %d with buried keys counted", keys, want)
	}
	if want := held + room; charged != want {
		t.Fatalf("uid 1001 is charged %d keys, want %d with its buried keys charged", charged, want)
	}
	checkPutRefusedFirst(t, u, server, "user/1001/after", ErrLogFull)
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm past the lifetime share: %v, want it to succeed", err)
	}
	u2 := userScope(t, s, 1002)
	if _, err := u2.Put(ctx, "user/1002/token", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("another uid's put with uid 1001 past its lifetime share: %v", err)
	}
}

// The lifetime share at the default caps is uidKeyShare, at least 16 times
// one scope's live keys (its maxScopeEntries entries and its delivery
// record), and small enough that fewer than 64 uids at their shares cannot
// fill the global key bound.
func TestFloorKeyShareLifetimeArithmetic(t *testing.T) {
	s, _, _ := fileLogScope(t)
	l := syncedFloor(t, s)
	share, bound := l.keyShare(), l.keyBound()
	if share != uidKeyShare {
		t.Fatalf("keyShare() = %d at the default caps, want uidKeyShare %d", share, uidKeyShare)
	}
	if live := maxScopeEntries + 1; share < 16*live {
		t.Fatalf("the share %d is under 16 times a scope's %d live keys", share, live)
	}
	if bound != maxFloorKeysCeiling {
		t.Fatalf("keyBound() = %d at the default caps, want the ceiling %d", bound, maxFloorKeysCeiling)
	}
	if 63*share >= bound {
		t.Fatalf("63 uids at the share %d hold %d keys, the key bound %d: fewer than 64 fill it", share, 63*share, bound)
	}
}

// No text in the package offers larger caps as a remedy: the key bound's
// ceiling is not configurable, so raising the caps frees no key, and a
// uid's spent lifetime share is freed only by rm-scope and a rebuild.
func TestNoRaiseTheCapsRemedy(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				low := strings.ToLower(lit.Value)
				if strings.Contains(low, "raise the caps") || strings.Contains(low, "larger caps") {
					t.Errorf("%s: %s offers larger caps as a remedy", p, lit.Value)
				}
			}
			return true
		})
	}
}
