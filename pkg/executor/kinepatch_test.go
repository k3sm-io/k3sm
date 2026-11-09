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

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/internal/childreq"
)

// TestApplyKinePatches pins the patch applier's fail-closed contract: an anchor
// that occurs exactly once is replaced, and a missing or repeated anchor is an error
// that leaves the file untouched, so a pin bump can never silently drop a fix.
func TestApplyKinePatches(t *testing.T) {
	p := kineSourcePatch{name: "demo", file: "pkg/x/x.go", old: "BUG\n", new: "FIX\n"}
	for _, tc := range []struct {
		name, content, want string
		wantErr             bool
	}{
		{name: "anchor once is replaced", content: "a\nBUG\nb\n", want: "a\nFIX\nb\n"},
		{name: "missing anchor fails", content: "a\nb\n", want: "a\nb\n", wantErr: true},
		{name: "repeated anchor fails", content: "BUG\nBUG\n", want: "BUG\nBUG\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "pkg", "x", "x.go")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			err := applyKinePatches(root, []kineSourcePatch{p})
			if (err != nil) != tc.wantErr {
				t.Fatalf("applyKinePatches = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "demo") {
				t.Errorf("error %q does not name the patch", err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.want {
				t.Errorf("file = %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("missing file fails", func(t *testing.T) {
		if err := applyKinePatches(t.TempDir(), []kineSourcePatch{p}); err == nil {
			t.Fatal("applyKinePatches on a tree without the file = nil, want an error")
		}
	})
}

// kinePatchSetDigest is the sha256 of the patch set's content: kinePatches, then
// the requirement raises (childreq.Raises) applied to the same tree. The p1 entry of
// kinePatchSetHistory predates the raises and was the source patches alone.
func kinePatchSetDigest() string {
	h := sha256.New()
	for _, p := range kinePatches {
		for _, f := range []string{p.name, p.file, p.old, p.new} {
			h.Write([]byte(f))
			h.Write([]byte{0})
		}
	}
	for _, r := range childreq.Raises {
		for _, f := range []string{"raise", r.Path, r.Version, r.Sum, r.GoModSum} {
			h.Write([]byte(f))
			h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// kinePatchSetHistory records every carried patch set by the variant that named it.
// It is APPEND-ONLY: a variant is never reused for different patches, because a node
// whose marker names that variant would never re-stage onto the new ones. Changing
// kinePatches means a new "+p<n>" in kineBuildVariant and a new line here.
var kinePatchSetHistory = map[string]string{
	"nocgo+p1": "d6c6334601320bd1bc3c88c5e97144f0df8c38e41ede21f225bdff71ff19af24",
	"nocgo+p2": "4056b8ca92fa544e024153ec01765ff84468be118b516dd5b2e02052a93397ea",
	"nocgo+p3": "b5c727f93e5e3acbd30118700fe6b46aa3677123ed632841ceff4a694fbac1a1",
	"nocgo+p4": "b116e0d06b6453fcd929a4bc62da794ad957ea3895b51f192c652e7f01115cc9",
	"nocgo+p5": "14db0c216afa353618c5548f54f1df1161e7559ba6748b44af811bdbe17e7f56",
	"nocgo+p6": "1486cdaeb3dafca24d9b684260ebcbc5507ba1265eade5fa0e8b5a7e21a557ee",
}

// TestKinePatchSetIsMarked pins the link between the carried patches and the staging
// marker: a patched build must not share a variant with the unpatched one, or nodes
// that staged the unpatched kine would never re-stage; and the patches cannot change
// without the variant changing, for the same reason.
func TestKinePatchSetIsMarked(t *testing.T) {
	got := kinePatchSetDigest()
	want, ok := kinePatchSetHistory[kineBuildVariant]
	switch {
	case !ok:
		t.Errorf("kineBuildVariant %q has no kinePatchSetHistory entry; add %q: %q", kineBuildVariant, kineBuildVariant, got)
	case want != got:
		t.Errorf("the kine patch set changed (digest %s) but kineBuildVariant is still %q, which names %s: bump the \"+p<n>\" suffix and add the new pair to kinePatchSetHistory", got, kineBuildVariant, want)
	}
	seen := map[string]string{}
	for variant, digest := range kinePatchSetHistory {
		if prev, dup := seen[digest]; dup {
			t.Errorf("variants %q and %q name the same patch set", prev, variant)
		}
		seen[digest] = variant
	}
	if len(kinePatches) == 0 {
		t.Fatal("no carried kine patches; if upstream fixed them, return kineBuildVariant to \"nocgo\" and delete this test")
	}
	if kineBuildVariant == "nocgo" {
		t.Errorf("kineBuildVariant = %q with %d carried patches: the unpatched builds' marker would vouch for the patched one", kineBuildVariant, len(kinePatches))
	}
	for _, p := range kinePatches {
		if p.name == "" || p.file == "" || p.old == "" || p.old == p.new {
			t.Errorf("patch %+v is incomplete or a no-op", p)
		}
	}
}

// TestKineBuildArgs pins the build argv: -mod=readonly hash-checks every module
// against kine's own go.sum, -trimpath keeps host paths out, and the pin plus the
// patch set is stamped into kine's version package.
func TestKineBuildArgs(t *testing.T) {
	args := kineBuildArgs("v0.17.1", "/out/kine")
	stamp := "-X github.com/k3s-io/kine/pkg/version.Version=v0.17.1+" + kinePatchSetID()
	for _, want := range []string{"build", "-trimpath", "-mod=readonly", stamp, "/out/kine"} {
		if !slices.Contains(args, want) {
			t.Errorf("kineBuildArgs = %q, missing %q", args, want)
		}
	}
}

// kineV0172SQLLogCompact is pkg/logstructured/sqllog/sql.go of kine v0.17.2 cut to
// its package clause, imports, compactStart() and compact(), verbatim, so the patches
// are tested against the upstream text without the module cache or the network.
// compactStart() is kept because it also defers t.MustRollback(): the rollback patch's
// anchor must still occur once, and compactStart must keep upstream behaviour.
const kineV0172SQLLogCompact = `package sqllog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/k3s-io/kine/pkg/broadcaster"
	"github.com/k3s-io/kine/pkg/metrics"
	"github.com/k3s-io/kine/pkg/server"
	"github.com/sirupsen/logrus"
)

func (s *SQLLog) compactStart(ctx context.Context) error {
	logrus.Tracef("COMPACTSTART")

	rows, err := s.d.After(ctx, "compact_rev_key", "", 0, 0)
	if err != nil {
		return err
	}

	batch, _, err := RowsToEvents(rows, true, true)
	if err != nil {
		return err
	}

	logrus.Tracef("COMPACTSTART len(events)=%v", len(batch.Events))

	if len(batch.Events) == 0 {
		_, err := s.Append(ctx, &server.Event{
			Create: true,
			KV: &server.KeyValue{
				Key:   "compact_rev_key",
				Value: []byte(""),
			},
		})
		return err
	} else if len(batch.Events) == 1 {
		return nil
	}

	t, err := s.d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer t.MustRollback()

	// this is to work around a bug in which we ended up with two compact_rev_key rows
	maxRev := int64(0)
	maxID := int64(0)
	for _, event := range batch.Events {
		if event.PrevKV != nil && event.PrevKV.ModRevision > maxRev {
			maxRev = event.PrevKV.ModRevision
			maxID = event.KV.ModRevision
		}
		logrus.Tracef("COMPACTSTART maxRev=%v maxID=%v", maxRev, maxID)
	}

	for _, event := range batch.Events {
		logrus.Tracef("COMPACTSTART event.KV.ModRevision=%v maxID=%v", event.KV.ModRevision, maxID)
		if event.KV.ModRevision == maxID {
			continue
		}
		if err := t.DeleteRevision(ctx, event.KV.ModRevision); err != nil {
			return err
		}
	}

	return t.Commit()
}

func (s *SQLLog) compact(compactRev int64, targetCompactRev int64) (int64, int64, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.compactTimeout)
	defer cancel()

	t, err := s.d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer t.MustRollback()

	currentRev, err := t.CurrentRevision(s.ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get current revision: %w", err)
	}

	dbCompactRev, err := t.GetCompactRevision(s.ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get compact revision: %w", err)
	}

	// Check to see if another node already compacted. This is normal on a multi-server cluster.
	if compactRev != dbCompactRev {
		logrus.Infof("COMPACT compact revision changed since last iteration: %d => %d", compactRev, dbCompactRev)
		return dbCompactRev, currentRev, server.ErrCompacted
	}

	// Ensure that we never compact the most recent 1000 revisions
	targetCompactRev = safeCompactRev(targetCompactRev, currentRev, s.compactMinRetain)

	// Don't bother compacting to a revision that has already been compacted
	if targetCompactRev <= compactRev {
		logrus.Tracef("COMPACT revision %d has already been compacted", targetCompactRev)
		return dbCompactRev, currentRev, server.ErrCompacted
	}

	logrus.Infof("COMPACT compactRev=%d targetCompactRev=%d currentRev=%d", compactRev, targetCompactRev, currentRev)

	start := time.Now()

	// Set compact revision before compacting - if the compact transaction times
	// out this will get rolled back. Otherwise it is possible for Compact to
	// succeed within the time limit, but SetCompactRevision occurs too late, and
	// the work is wasted.
	if err := t.SetCompactRevision(s.ctx, targetCompactRev); err != nil {
		return 0, 0, fmt.Errorf("failed to record compact revision: %w", err)
	}

	// compact revisions from old compact revision to new target
	deletedRows, err := t.Compact(s.ctx, compactRev, targetCompactRev)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to compact to revision %d: %w", targetCompactRev, err)
	}

	// Commit the transaction if we make it all the way through deleting without any
	// errors. The deferred rollback becomes a no-op if the transaction is committed.
	t.MustCommit()
	logrus.Infof("COMPACT deleted %d rows from %d revisions in %s - compacted to %d/%d", deletedRows, (targetCompactRev - compactRev), time.Since(start), targetCompactRev, currentRev)

	return targetCompactRev, currentRev, nil
}
`

// TestKineCompactCommitFailureIsReturnedNotFatal pins compact-commit-returns-error:
// after kinePatches, kine's compact() must not call MustCommit (logrus.Fatalf on a
// failed commit, which takes the whole control plane down) and must call Commit and
// return its error, which compactIter logs and retries on the next interval.
func TestKineCompactCommitFailureIsReturnedNotFatal(t *testing.T) {
	const file = "pkg/logstructured/sqllog/sql.go"
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(file))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(kineV0172SQLLogCompact), 0o644); err != nil {
		t.Fatal(err)
	}
	var patches []kineSourcePatch
	for _, p := range kinePatches {
		if p.file == file {
			patches = append(patches, p)
		}
	}
	if err := applyKinePatches(root, patches); err != nil {
		t.Fatal(err)
	}

	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("patched %s does not parse: %v", file, err)
	}
	if !slices.ContainsFunc(f.Imports, func(is *ast.ImportSpec) bool { return is.Path.Value == `"fmt"` }) {
		t.Errorf("patched %s does not import fmt, which the returned commit error is wrapped with", file)
	}
	var compact *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "compact" && fd.Recv != nil {
			compact = fd
		}
	}
	if compact == nil {
		t.Fatalf("patched %s has no compact method", file)
	}

	// selectorCall reports whether call is t.<name>().
	selectorCall := func(e ast.Expr, name string) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return false
		}
		x, ok := sel.X.(*ast.Ident)
		return ok && x.Name == "t"
	}
	commitReturned := false
	ast.Inspect(compact.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if selectorCall(n, "MustCommit") {
				t.Error("compact() still calls t.MustCommit(), which is fatal when the commit fails")
			}
		case *ast.IfStmt:
			// if err := t.Commit(); err != nil { return ..., <expr using err> }
			as, ok := n.Init.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || !selectorCall(as.Rhs[0], "Commit") {
				return true
			}
			errVar, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			for _, s := range n.Body.List {
				ret, ok := s.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 3 {
					continue
				}
				ast.Inspect(ret.Results[2], func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok && id.Name == errVar.Name {
						commitReturned = true
					}
					return true
				})
			}
		}
		return true
	})
	if !commitReturned {
		t.Error("compact() does not call t.Commit() and return its error")
	}
}

// TestKineCompactRollbackFailureIsNotFatal pins compact-rollback-logs-error: after
// kinePatches, kine's compact() must not defer t.MustRollback() (logrus.Fatalf on any
// rollback error but sql.ErrTxDone, which takes the whole control plane down) and must
// defer a closure that calls t.Rollback() instead. compactStart() keeps its deferred
// t.MustRollback(): the patch is scoped to the compaction interval's path.
func TestKineCompactRollbackFailureIsNotFatal(t *testing.T) {
	const file = "pkg/logstructured/sqllog/sql.go"
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(file))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(kineV0172SQLLogCompact), 0o644); err != nil {
		t.Fatal(err)
	}
	var patches []kineSourcePatch
	for _, p := range kinePatches {
		if p.file == file {
			patches = append(patches, p)
		}
	}
	if err := applyKinePatches(root, patches); err != nil {
		t.Fatal(err)
	}

	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("patched %s does not parse: %v", file, err)
	}
	for _, imp := range []string{`"errors"`, `"database/sql"`, `"github.com/sirupsen/logrus"`} {
		if !slices.ContainsFunc(f.Imports, func(is *ast.ImportSpec) bool { return is.Path.Value == imp }) {
			t.Errorf("patched %s does not import %s, which the deferred rollback uses", file, imp)
		}
	}
	methods := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil {
			methods[fd.Name.Name] = fd
		}
	}

	// selectorCall reports whether e is t.<name>().
	selectorCall := func(e ast.Expr, name string) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return false
		}
		x, ok := sel.X.(*ast.Ident)
		return ok && x.Name == "t"
	}
	// deferred reports whether fn defers t.MustRollback() directly, and whether it
	// defers a closure whose body calls t.Rollback().
	deferred := func(fn *ast.FuncDecl) (mustRollback, rollbackClosure bool) {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ds, ok := n.(*ast.DeferStmt)
			if !ok {
				return true
			}
			if selectorCall(ds.Call, "MustRollback") {
				mustRollback = true
			}
			if lit, ok := ds.Call.Fun.(*ast.FuncLit); ok {
				ast.Inspect(lit.Body, func(m ast.Node) bool {
					if e, ok := m.(ast.Expr); ok && selectorCall(e, "Rollback") {
						rollbackClosure = true
					}
					return true
				})
			}
			return true
		})
		return mustRollback, rollbackClosure
	}

	compact, ok := methods["compact"]
	if !ok {
		t.Fatalf("patched %s has no compact method", file)
	}
	must, closure := deferred(compact)
	if must {
		t.Error("compact() still defers t.MustRollback(), which is fatal when the rollback fails")
	}
	if !closure {
		t.Error("compact() does not defer a closure that calls t.Rollback()")
	}

	// The deferred closures themselves must not exit kine either, and must tolerate
	// the sql.ErrTxDone a committed or already rolled-back tx returns.
	ast.Inspect(compact.Body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		lit, ok := ds.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		txDoneChecked := false
		ast.Inspect(lit.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, _ := sel.X.(*ast.Ident)
			switch {
			case strings.HasPrefix(sel.Sel.Name, "Fatal"), strings.HasPrefix(sel.Sel.Name, "Panic"):
				t.Errorf("compact()'s deferred closure calls %s, which exits kine", sel.Sel.Name)
			case pkg != nil && pkg.Name == "os" && sel.Sel.Name == "Exit":
				t.Error("compact()'s deferred closure calls os.Exit")
			case pkg != nil && pkg.Name == "errors" && sel.Sel.Name == "Is" && len(call.Args) == 2:
				if target, ok := call.Args[1].(*ast.SelectorExpr); ok && target.Sel.Name == "ErrTxDone" {
					if x, ok := target.X.(*ast.Ident); ok && x.Name == "sql" {
						txDoneChecked = true
					}
				}
			}
			return true
		})
		if !txDoneChecked {
			t.Error("compact()'s deferred closure does not check errors.Is(err, sql.ErrTxDone)")
		}
		return true
	})

	compactStart, ok := methods["compactStart"]
	if !ok {
		t.Fatalf("patched %s has no compactStart method", file)
	}
	if must, _ := deferred(compactStart); !must {
		t.Error("compactStart() no longer defers t.MustRollback(): the rollback patch must change compact() only")
	}
}

// TestKineCompactRollbackFailureDiscardsConn pins compact-rollback-failures-bounded.
// modernc.org/sqlite's tx.Rollback returns a plain *Error, never driver.ErrBadConn,
// and its IsValid does not check for an open transaction, so database/sql can pool
// a connection a failed ROLLBACK left inside its transaction, and every later
// compaction BEGIN on it fails. The patch discards that connection the only way kine
// can, by exiting so the supervisor restarts it with a clean pool. After kinePatches,
// kine's sql.go must declare the bound of 3; compact() must check it before BEGIN,
// count a failed rollback in its deferred closure and a failed BEGIN once a rollback
// has failed, and reset the count only after a successful commit; and the exit must
// sit in the top-level helper, never in the deferred closure.
func TestKineCompactRollbackFailureDiscardsConn(t *testing.T) {
	const file = "pkg/logstructured/sqllog/sql.go"
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(file))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(kineV0172SQLLogCompact), 0o644); err != nil {
		t.Fatal(err)
	}
	var patches []kineSourcePatch
	for _, p := range kinePatches {
		if p.file == file {
			patches = append(patches, p)
		}
	}
	if err := applyKinePatches(root, patches); err != nil {
		t.Fatal(err)
	}

	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("patched %s does not parse: %v", file, err)
	}
	if !slices.ContainsFunc(f.Imports, func(is *ast.ImportSpec) bool { return is.Path.Value == `"sync/atomic"` }) {
		t.Errorf("patched %s does not import sync/atomic, which the failure count uses", file)
	}

	const (
		counter = "compactRollbackFailures"
		limit   = "compactRollbackFailureLimit"
		exit    = "exitOnCompactRollbackFailures"
	)
	// The bound: const compactRollbackFailureLimit = 3, and an atomic.Int64 counter.
	var limitValue string
	counterTyped := false
	funcs := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.GenDecl:
			for _, s := range d.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 {
					continue
				}
				switch vs.Names[0].Name {
				case limit:
					if len(vs.Values) == 1 {
						if lit, ok := vs.Values[0].(*ast.BasicLit); ok {
							limitValue = lit.Value
						}
					}
				case counter:
					if sel, ok := vs.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Int64" {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "atomic" {
							counterTyped = true
						}
					}
				}
			}
		case *ast.FuncDecl:
			if d.Recv == nil {
				funcs[d.Name.Name] = d
			} else {
				funcs["(*SQLLog)."+d.Name.Name] = d
			}
		}
	}
	if limitValue != "3" {
		t.Errorf("patched %s: %s = %q, want 3", file, limit, limitValue)
	}
	if !counterTyped {
		t.Errorf("patched %s does not declare %s as an atomic.Int64", file, counter)
	}

	// isCall reports whether e is <x>.<name>() (x == "" for a plain call to name).
	isCall := func(e ast.Node, x, name string) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		if x == "" {
			id, ok := call.Fun.(*ast.Ident)
			return ok && id.Name == name
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == x
	}
	// contains reports whether n holds a call matching x.name.
	contains := func(n ast.Node, x, name string) bool {
		found := false
		ast.Inspect(n, func(m ast.Node) bool {
			if isCall(m, x, name) {
				found = true
			}
			return !found
		})
		return found
	}

	// The exit: the helper calls logrus.Fatalf under "if n > compactRollbackFailureLimit".
	helper, ok := funcs[exit]
	if !ok {
		t.Fatalf("patched %s has no %s function", file, exit)
	}
	guardedFatal := false
	ast.Inspect(helper.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		be, ok := is.Cond.(*ast.BinaryExpr)
		if !ok || be.Op != token.GTR {
			return true
		}
		if id, ok := be.Y.(*ast.Ident); ok && id.Name == limit && contains(is.Body, "logrus", "Fatalf") {
			guardedFatal = true
		}
		return true
	})
	if !guardedFatal {
		t.Errorf("%s does not call logrus.Fatalf once the count passes %s", exit, limit)
	}

	compact, ok := funcs["(*SQLLog).compact"]
	if !ok {
		t.Fatalf("patched %s has no compact method", file)
	}
	body := compact.Body.List

	// Before BEGIN: the bound is checked at the top level of compact().
	beginAt, commitAt, checkAt, resetAt := -1, -1, -1, -1
	for i, s := range body {
		switch s := s.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 && isBeginTx(s.Rhs[0]) {
				beginAt = i
			}
		case *ast.ExprStmt:
			if isCall(s.X, "", exit) {
				checkAt = i
			}
			if isCall(s.X, counter, "Store") {
				resetAt = i
				if lit, ok := s.X.(*ast.CallExpr).Args[0].(*ast.BasicLit); !ok || lit.Value != "0" {
					t.Errorf("compact() stores a non-zero value into %s", counter)
				}
			}
		case *ast.IfStmt:
			if as, ok := s.Init.(*ast.AssignStmt); ok && len(as.Rhs) == 1 && isCall(as.Rhs[0], "t", "Commit") {
				commitAt = i
			}
		}
	}
	switch {
	case beginAt < 0:
		t.Fatal("compact() has no BeginTx assignment")
	case checkAt < 0 || checkAt > beginAt:
		t.Errorf("compact() does not call %s() before BeginTx", exit)
	}
	// The reset: only after the commit has succeeded.
	switch {
	case commitAt < 0:
		t.Error("compact() has no if-err-Commit statement")
	case resetAt < 0:
		t.Errorf("compact() never resets %s", counter)
	case resetAt < commitAt:
		t.Errorf("compact() resets %s before the commit succeeds", counter)
	}
	resets := 0
	ast.Inspect(compact.Body, func(n ast.Node) bool {
		if isCall(n, counter, "Store") {
			resets++
		}
		return true
	})
	if resets != 1 {
		t.Errorf("compact() resets %s %d times, want once, after the commit", counter, resets)
	}

	// A failed BEGIN after a failed rollback counts and is checked against the bound.
	if beginAt+1 >= len(body) {
		t.Fatal("compact() ends at BeginTx")
	}
	beginErr, ok := body[beginAt+1].(*ast.IfStmt)
	if !ok {
		t.Fatal("compact() does not check the BeginTx error right after it")
	}
	if !contains(beginErr.Body, counter, "Add") || !contains(beginErr.Body, "", exit) {
		t.Errorf("compact()'s BeginTx error branch does not count the failure and call %s()", exit)
	}

	// A failed rollback counts in the deferred closure, which still never exits.
	counted := false
	ast.Inspect(compact.Body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		lit, ok := ds.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(lit.Body, func(m ast.Node) bool {
			is, ok := m.(*ast.IfStmt)
			if !ok {
				return true
			}
			as, ok := is.Init.(*ast.AssignStmt)
			if ok && len(as.Rhs) == 1 && isCall(as.Rhs[0], "t", "Rollback") && contains(is.Body, counter, "Add") {
				counted = true
			}
			return true
		})
		if contains(lit.Body, "", exit) || contains(lit.Body, "logrus", "Fatalf") {
			t.Error("compact()'s deferred closure can exit kine; only the counted paths outside it may")
		}
		return true
	})
	if !counted {
		t.Errorf("compact()'s deferred closure does not count a failed t.Rollback() in %s", counter)
	}
}

// isBeginTx reports whether e is s.d.BeginTx(...).
func isBeginTx(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "BeginTx"
}
