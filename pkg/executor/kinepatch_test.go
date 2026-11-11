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
	"go/build"
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
// kinePatches means a new "+p<n>" in kineBuildVariant and a new line here, unless
// the change returns to a set already recorded, as the p5 revert returned to p4: the
// variant then names that set again, and every other variant's marker re-stages.
var kinePatchSetHistory = map[string]string{
	"nocgo+p1": "d6c6334601320bd1bc3c88c5e97144f0df8c38e41ede21f225bdff71ff19af24",
	"nocgo+p2": "4056b8ca92fa544e024153ec01765ff84468be118b516dd5b2e02052a93397ea",
	"nocgo+p3": "b5c727f93e5e3acbd30118700fe6b46aa3677123ed632841ceff4a694fbac1a1",
	"nocgo+p4": "b116e0d06b6453fcd929a4bc62da794ad957ea3895b51f192c652e7f01115cc9",
	"nocgo+p5": "14db0c216afa353618c5548f54f1df1161e7559ba6748b44af811bdbe17e7f56",
	"nocgo+p6": "121ae7c6e733c7c140effda0fe5980037102274184aba16ffc088d6522ed5d4d",
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
// compactStart() is kept because it also defers t.MustRollback(), so a patch aimed
// at compact()'s deferred rollback has a second occurrence to avoid.
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

// kineV0172GenericTx is pkg/drivers/generic/tx.go of kine v0.17.2 cut to its package
// clause, imports, the Tx type, Rollback() and MustRollback(), verbatim.
// TestKineCompactRollbackFailureDiscardsConn checks MustRollback against it, and
// against the module cache's copy of the pinned version when that is present.
const kineV0172GenericTx = `package generic

import (
	"context"
	"database/sql"
	"time"

	"github.com/k3s-io/kine/pkg/metrics"
	"github.com/k3s-io/kine/pkg/query"
	"github.com/k3s-io/kine/pkg/server"
	"github.com/sirupsen/logrus"
)

// explicit interface check
var _ server.Transaction = (*Tx)(nil)

type Tx struct {
	x *sql.Tx
	d *Generic
}

func (t *Tx) Rollback() error {
	logrus.Tracef("TX ROLLBACK")
	return t.x.Rollback()
}

func (t *Tx) MustRollback() {
	if err := t.Rollback(); err != nil {
		if err != sql.ErrTxDone {
			logrus.Fatalf("Transaction rollback failed: %v", err)
		}
	}
}
`

// TestKineCompactRollbackFailureDiscardsConn pins why a failed compaction rollback
// still exits kine. A ROLLBACK that fails with anything but sql.ErrTxDone can return
// its connection to the pool still inside the transaction and holding the WAL write
// lock: database/sql discards a connection only on driver.ErrBadConn, which
// modernc.org/sqlite's tx.Rollback never returns. kine cannot drop that one
// connection, so it exits and restarts with a clean pool. That rests on two facts,
// both pinned here: after kinePatches, compact() still defers t.MustRollback() and
// never handles a rollback error itself, and the pinned kine's MustRollback calls
// logrus.Fatalf for any rollback error other than sql.ErrTxDone. A failed commit does
// not trip it: database/sql marks the tx done before the driver commits, so the
// deferred rollback returns sql.ErrTxDone. This is a structural test of the source;
// exercising the real driver would need modernc.org/sqlite in this module's graph.
func TestKineCompactRollbackFailureDiscardsConn(t *testing.T) {
	// patched writes the fixture for file under a temp root, applies every patch in
	// kinePatches aimed at it, and parses the result.
	patched := func(file, src string) *ast.File {
		t.Helper()
		root := t.TempDir()
		path := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
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
		return f
	}
	method := func(f *ast.File, name string) *ast.FuncDecl {
		t.Helper()
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && fd.Name.Name == name {
				return fd
			}
		}
		t.Fatalf("no %s method", name)
		return nil
	}
	// selectorCall reports whether n is <x>.<name>(...).
	selectorCall := func(n ast.Node, x, name string) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == x
	}

	t.Run("compact keeps upstream's deferred MustRollback", func(t *testing.T) {
		compact := method(patched("pkg/logstructured/sqllog/sql.go", kineV0172SQLLogCompact), "compact")
		mustRollback := 0
		for _, s := range compact.Body.List {
			if ds, ok := s.(*ast.DeferStmt); ok && selectorCall(ds.Call, "t", "MustRollback") && len(ds.Call.Args) == 0 {
				mustRollback++
			}
		}
		if mustRollback != 1 {
			t.Errorf("compact() defers t.MustRollback() %d times at top level, want once: a failed rollback must exit kine", mustRollback)
		}
		ast.Inspect(compact.Body, func(n ast.Node) bool {
			if ds, ok := n.(*ast.DeferStmt); ok {
				if _, lit := ds.Call.Fun.(*ast.FuncLit); lit {
					t.Error("compact() defers a closure; a closure that handles the rollback error itself keeps kine up on a connection that may hold the write lock")
				}
			}
			if selectorCall(n, "t", "Rollback") {
				t.Error("compact() calls t.Rollback() itself; only t.MustRollback() may handle the compaction's rollback")
			}
			return true
		})
	})

	t.Run("MustRollback exits on a rollback error other than ErrTxDone", func(t *testing.T) {
		mr := method(patched("pkg/drivers/generic/tx.go", kineV0172GenericTx), "MustRollback")
		// if err := t.Rollback(); err != nil { if err != sql.ErrTxDone { logrus.Fatalf(...) } }
		guarded := false
		ast.Inspect(mr.Body, func(n ast.Node) bool {
			outer, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			as, ok := outer.Init.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || !selectorCall(as.Rhs[0], "t", "Rollback") {
				return true
			}
			for _, s := range outer.Body.List {
				inner, ok := s.(*ast.IfStmt)
				if !ok {
					continue
				}
				be, ok := inner.Cond.(*ast.BinaryExpr)
				if !ok || be.Op != token.NEQ {
					continue
				}
				y, ok := be.Y.(*ast.SelectorExpr)
				if !ok || y.Sel.Name != "ErrTxDone" {
					continue
				}
				if pkg, ok := y.X.(*ast.Ident); !ok || pkg.Name != "sql" {
					continue
				}
				for _, s := range inner.Body.List {
					if es, ok := s.(*ast.ExprStmt); ok && selectorCall(es.X, "logrus", "Fatalf") {
						guarded = true
					}
				}
			}
			return false
		})
		if !guarded {
			t.Error("the pinned kine's MustRollback no longer calls logrus.Fatalf for a rollback error other than sql.ErrTxDone; compact() relies on it to exit")
		}
	})

	t.Run("fixture matches the pinned module source", func(t *testing.T) {
		cache := os.Getenv("GOMODCACHE")
		if cache == "" {
			cache = filepath.Join(build.Default.GOPATH, "pkg", "mod")
		}
		path := filepath.Join(cache, filepath.FromSlash(kineModulePath)+"@"+DefaultKineVersion, "pkg", "drivers", "generic", "tx.go")
		src, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("kine %s is not in the module cache (%v); the fixture is checked where it is", DefaultKineVersion, err)
		}
		_, fns, _ := strings.Cut(kineV0172GenericTx, "\n}\n\n")
		if fns == "" || !strings.Contains(string(src), fns) {
			t.Errorf("Rollback/MustRollback in %s differ from kineV0172GenericTx: the pin moved or upstream changed, so re-check that a failed rollback still exits kine", path)
		}
	})
}
