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

package main

import (
	"context"
	"errors"
	"go/ast"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
)

// countingNodePasswords wraps a store and counts its Ensure calls, optionally
// failing the first `failFirst` of them with `fault` before delegating.
//
// Locking discipline: mu guards calls.
type countingNodePasswords struct {
	inner     bootstrap.NodePasswordStore
	fault     error
	failFirst int

	mu    sync.Mutex
	calls int
}

func (c *countingNodePasswords) Ensure(ctx context.Context, nodeName, password string) error {
	c.mu.Lock()
	c.calls++
	n := c.calls
	c.mu.Unlock()
	if n <= c.failFirst {
		return c.fault
	}
	return c.inner.Ensure(ctx, nodeName, password)
}

func (c *countingNodePasswords) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// shrinkSelfBindRetry makes bindSelfNodePassword's backoff test-sized. Callers
// must not be parallel: it writes a package var.
func shrinkSelfBindRetry(t *testing.T) {
	t.Helper()
	restore := selfBindRetryBase
	selfBindRetryBase = time.Millisecond
	t.Cleanup(func() { selfBindRetryBase = restore })
}

// TestSingleServerNodePasswordBindingSurvivesRestart is the gate for keeping
// node-password bindings across a single-server restart.
//
// A single server used to keep the bindings in memory, so a restart forgot every
// one of them and any join-token holder could claim an existing worker's name
// until that worker rejoined. The store is now built by serverNodePasswordStore
// on every server and lives in the datastore; a second store built the same way
// over the same datastore is what a restart is.
//
// The fake clientset stands in for the datastore. The real-kine leg (a binding
// written, the server restarted with `launchctl kickstart`, the binding still
// enforced) is a lab rig run: cmd/k3sm has no real-kine harness.
//
// Fails before the fix: serverNodePasswordStore does not exist, and the single
// server's in-memory store comes back empty.
func TestSingleServerNodePasswordBindingSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := fake.NewClientset()

	first := serverNodePasswordStore(cs, quietLogger())
	if err := first.Ensure(ctx, "worker-1", "worker-1-password"); err != nil {
		t.Fatalf("bind worker-1 before the restart: %v", err)
	}

	restarted := serverNodePasswordStore(cs, quietLogger())
	if err := restarted.Ensure(ctx, "worker-1", "a-claimants-password"); !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
		t.Errorf("a second claimant after the restart: err = %v, want ErrNodePasswordMismatch (the binding must outlive the process)", err)
	}
	if err := restarted.Ensure(ctx, "worker-1", "worker-1-password"); err != nil {
		t.Errorf("the original worker after the restart: %v, want its password still to verify", err)
	}
}

// TestSingleServerStoreBuiltAfterAPIServerHealthy pins WHERE runServer builds the
// node-password store: after the control plane's health wait (exec.Start) and
// the admin client built on it (the store reads and writes
// Secrets through it), before this node's own enroll binds its name in it, and
// before the join supervisor that checks every worker against it. It also pins
// that runServer no longer builds an in-memory store at all.
//
// Non-vacuous: before the fix serverNodePasswordStore did not exist and
// server.go built bootstrap.NewMemoryNodePasswords().
func TestSingleServerStoreBuiltAfterAPIServerHealthy(t *testing.T) {
	tr := runServerTrace(t)
	first := map[string]int{}
	where := map[string]ast.Node{}
	for name, c := range tr.firstCalls() {
		first[name], where[name] = c.pos, c.call
	}

	var depsLit *ast.CompositeLit
	tr.inspect(func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok && depsLit == nil {
			if ident, ok := lit.Type.(*ast.Ident); ok && ident.Name == "bootstrapServerDeps" {
				depsLit = lit
			}
		}
		return true
	})
	if depsLit == nil {
		t.Fatal("runServer builds no bootstrapServerDeps literal: the join supervisor wiring moved, re-anchor this pin")
	}
	first["bootstrapServerDeps{}"], where["bootstrapServerDeps{}"] = tr.pos(depsLit), depsLit

	// exec.Start returns only once the control plane is healthy (the "control
	// plane healthy" line follows it), so it anchors the health wait.
	order := []string{"exec.Start", "kubeclient.FromPath", "serverNodePasswordStore", "enrollSelfAndBringUpMesh", "bootstrapServerDeps{}"}
	for _, name := range order {
		if _, ok := first[name]; !ok {
			t.Fatalf("runServer never calls %s", name)
		}
	}
	for i := 1; i < len(order); i++ {
		before, after := order[i-1], order[i]
		if first[before] >= first[after] {
			t.Errorf("runServer reaches %s at %s, NOT before %s at %s",
				before, tr.where(where[before]), after, tr.where(where[after]))
		}
	}

	// Every non-test server*.go file, not only the bring-up trace: an in-memory
	// store built anywhere in the server's sources is the regression.
	for name, file := range tr.files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name == "NewMemoryNodePasswords" {
					t.Errorf("%s still builds an in-memory node-password store at %s: its bindings die with the process", name, tr.where(x))
				}
			case *ast.Ident:
				if x.Name == "MemoryNodePasswords" {
					t.Errorf("%s still names MemoryNodePasswords", name)
				}
			}
			return true
		})
	}
}

// twoBootSelfBind runs this control plane's own bind twice over ONE datastore,
// each boot with a fresh store built by the production function (the restart),
// and lets the caller damage the work dir in between. It returns how many times
// the second boot asked the store, and that boot's error.
func twoBootSelfBind(t *testing.T, between func(workDir string)) (serverOptions, int, error) {
	t.Helper()
	ctx := context.Background()
	const nodeName = "k3sm-host"
	mode := hostnet.Mode{Backend: hostnet.BackendNone}
	cs := fake.NewClientset()
	workDir := t.TempDir()
	opts := selfEnrollOptions(workDir, nodeName)
	e, _ := enrollerOverStub(t)

	if _, _, err := enrollSelfAndBringUpMesh(ctx, e, serverNodePasswordStore(cs, quietLogger()), opts, mode, "", quietLogger()); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	between(workDir)
	second := &countingNodePasswords{inner: serverNodePasswordStore(cs, quietLogger())}
	_, _, err := enrollSelfAndBringUpMesh(ctx, e, second, opts, mode, "", quietLogger())
	return opts, second.count(), err
}

// TestRegeneratedServerPasswordFileNamesTheMismatch: the server's own
// node-password file is lost and re-minted between two boots, so the second boot
// presents a password the datastore's binding does not match. That is a verdict,
// not a fault: it is returned on the FIRST attempt (no backoff spent on it) and
// the bring-up failure names the file and the node.
func TestRegeneratedServerPasswordFileNamesTheMismatch(t *testing.T) {
	shrinkSelfBindRetry(t)
	opts, attempts, err := twoBootSelfBind(t, func(workDir string) {
		if err := os.Remove(filepath.Join(workDir, serverNodePasswordRef)); err != nil {
			t.Fatalf("remove the server node-password file: %v", err)
		}
	})
	if !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
		t.Fatalf("second boot err = %v, want ErrNodePasswordMismatch", err)
	}
	if attempts != 1 {
		t.Errorf("the second boot asked the store %d times, want 1: a mismatch is never retried", attempts)
	}

	sink := &syncBuffer{}
	msg, attrs := serverMeshBringUpFailure(opts, err)
	slog.New(slog.NewTextHandler(sink, nil)).Error(msg, attrs...)
	out := sink.String()
	for _, want := range []string{filepath.Join(opts.workDir, serverNodePasswordRef), opts.nodeName, "no longer matches", "restore the original"} {
		if !strings.Contains(out, want) {
			t.Errorf("diagnosis does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, genericBringUpFailure) {
		t.Errorf("a mismatch logged the generic wording:\n%s", out)
	}
}

// TestPersistedServerPasswordFileRebindsCleanly is the ordinary restart: the
// file is kept, the second boot presents the same password, and the binding the
// first boot wrote to the datastore verifies.
func TestPersistedServerPasswordFileRebindsCleanly(t *testing.T) {
	shrinkSelfBindRetry(t)
	_, attempts, err := twoBootSelfBind(t, func(string) {})
	if err != nil {
		t.Fatalf("second boot with the persisted file: %v", err)
	}
	if attempts != 1 {
		t.Errorf("the second boot asked the store %d times, want 1", attempts)
	}
}

// TestSecretNodePasswordStoreKineBusy drives the datastore-backed store through
// a busy datastore. The property under test: every datastore fault comes back as
// an ordinary error, never ErrNodePasswordMismatch, and never leaves a binding
// the next call cannot honour.
func TestSecretNodePasswordStoreKineBusy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	busy := apierrors.NewServerTimeout(corev1.Resource("secrets"), "get", 1)

	// failNext makes the next n calls of verb on secrets fail with busy (or with
	// err when set); commit writes the Create to the tracker first, so the call
	// fails AFTER it landed.
	type reactorSpec struct {
		verb   string
		n      int
		commit bool
		err    error
	}
	newStore := func(t *testing.T, spec reactorSpec) (*fake.Clientset, *secretNodePasswords) {
		t.Helper()
		cs := fake.NewClientset()
		var mu sync.Mutex
		left := spec.n
		cs.PrependReactor(spec.verb, "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			mu.Lock()
			defer mu.Unlock()
			if left == 0 {
				return false, nil, nil
			}
			left--
			if spec.commit {
				obj := action.(k8stesting.CreateAction).GetObject()
				if err := cs.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), obj, action.GetNamespace()); err != nil {
					t.Errorf("commit the create: %v", err)
				}
			}
			if spec.err != nil {
				return true, nil, spec.err
			}
			return true, nil, busy
		})
		return cs, newSecretNodePasswords(cs, quietLogger())
	}
	secretExists := func(t *testing.T, cs *fake.Clientset) bool {
		t.Helper()
		_, err := cs.CoreV1().Secrets(bootstrapStateNamespace).Get(ctx, "worker-1"+nodePasswordSecretSuffix, metav1.GetOptions{})
		return err == nil
	}

	t.Run("a Get that times out is an error, not a mismatch, and binds nothing", func(t *testing.T) {
		t.Parallel()
		cs, s := newStore(t, reactorSpec{verb: "get", n: 1})
		err := s.Ensure(ctx, "worker-1", "pw")
		if err == nil || errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("err = %v, want a transient error", err)
		}
		if secretExists(t, cs) {
			t.Error("a failed Get created a binding")
		}
		if err := s.Ensure(ctx, "worker-1", "pw"); err != nil {
			t.Errorf("the retry once the datastore answers: %v", err)
		}
	})

	t.Run("a Create that fails before it lands is an error, then a later call binds", func(t *testing.T) {
		t.Parallel()
		cs, s := newStore(t, reactorSpec{verb: "create", n: 1})
		err := s.Ensure(ctx, "worker-1", "pw")
		if err == nil || errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("err = %v, want a transient error", err)
		}
		if secretExists(t, cs) {
			t.Fatal("a Create that failed left a binding")
		}
		if err := s.Ensure(ctx, "worker-1", "pw"); err != nil {
			t.Fatalf("the retry: %v", err)
		}
		if !secretExists(t, cs) {
			t.Error("the retry did not bind")
		}
	})

	t.Run("a Create refused NotFound (kube-system not created yet) is an error, then a later call binds", func(t *testing.T) {
		t.Parallel()
		nsMissing := apierrors.NewNotFound(corev1.Resource("namespaces"), bootstrapStateNamespace)
		cs, s := newStore(t, reactorSpec{verb: "create", n: 1, err: nsMissing})
		err := s.Ensure(ctx, "worker-1", "pw")
		if err == nil || errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("err = %v, want a transient error", err)
		}
		if secretExists(t, cs) {
			t.Fatal("a refused Create left a binding")
		}
		if err := s.Ensure(ctx, "worker-1", "pw"); err != nil {
			t.Fatalf("the retry once the namespace exists: %v", err)
		}
		if !secretExists(t, cs) {
			t.Error("the retry did not bind")
		}
	})

	t.Run("a Create that lands then errors is safe to retry with the same password", func(t *testing.T) {
		t.Parallel()
		cs, s := newStore(t, reactorSpec{verb: "create", n: 1, commit: true})
		err := s.Ensure(ctx, "worker-1", "pw")
		if err == nil || errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("err = %v, want a transient error", err)
		}
		if !secretExists(t, cs) {
			t.Fatal("the committed Create left no Secret; this row tests nothing")
		}
		if err := s.Ensure(ctx, "worker-1", "pw"); err != nil {
			t.Errorf("the same password after a committed-then-failed Create: %v, want it to verify", err)
		}
		if err := s.Ensure(ctx, "worker-1", "someone-else"); !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Errorf("a different password: err = %v, want ErrNodePasswordMismatch", err)
		}
	})
}

// TestSelfNodePasswordBindRetriesStoreFaults pins bindSelfNodePassword's
// bounded retry: a store fault right after bring-up is waited out, a persistent
// one is reported after selfBindAttempts tries, and a mismatch is never retried.
func TestSelfNodePasswordBindRetriesStoreFaults(t *testing.T) {
	shrinkSelfBindRetry(t)
	ctx := context.Background()
	busy := errors.New("get node-password secret: the server was unable to return a response in the time allotted")

	t.Run("transient faults then success binds", func(t *testing.T) {
		store := &countingNodePasswords{inner: bootstrap.NewMemoryNodePasswords(), fault: busy, failFirst: selfBindAttempts - 1}
		if err := bindSelfNodePassword(ctx, store, "k3sm-host", t.TempDir()); err != nil {
			t.Fatalf("bind after %d transient faults: %v", selfBindAttempts-1, err)
		}
		if store.count() != selfBindAttempts {
			t.Errorf("attempts = %d, want %d", store.count(), selfBindAttempts)
		}
	})

	t.Run("a persistent fault is reported after the bounded attempts", func(t *testing.T) {
		store := &countingNodePasswords{inner: bootstrap.NewMemoryNodePasswords(), fault: busy, failFirst: 1 << 30}
		err := bindSelfNodePassword(ctx, store, "k3sm-host", t.TempDir())
		if !errors.Is(err, busy) {
			t.Fatalf("err = %v, want the store's fault", err)
		}
		if errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Error("a store fault was reported as a mismatch")
		}
		if store.count() != selfBindAttempts {
			t.Errorf("attempts = %d, want exactly %d", store.count(), selfBindAttempts)
		}
	})

	t.Run("a mismatch is returned at once", func(t *testing.T) {
		store := &countingNodePasswords{inner: bootstrap.NewMemoryNodePasswords(), fault: bootstrap.ErrNodePasswordMismatch, failFirst: 1 << 30}
		err := bindSelfNodePassword(ctx, store, "k3sm-host", t.TempDir())
		if !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("err = %v, want ErrNodePasswordMismatch", err)
		}
		if store.count() != 1 {
			t.Errorf("attempts = %d, want 1", store.count())
		}
	})

	t.Run("a cancelled context stops the backoff", func(t *testing.T) {
		restore := selfBindRetryBase
		selfBindRetryBase = time.Hour
		t.Cleanup(func() { selfBindRetryBase = restore })
		cctx, cancel := context.WithCancel(ctx)
		store := &countingNodePasswords{inner: bootstrap.NewMemoryNodePasswords(), fault: busy, failFirst: 1 << 30}
		done := make(chan error, 1)
		go func() { done <- bindSelfNodePassword(cctx, store, "k3sm-host", t.TempDir()) }()
		time.Sleep(20 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v, want it to carry context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the backoff ignored a cancelled context")
		}
	})
}

// TestSecretNodePasswordStoreConcurrentFirstWriteWins: N callers race to bind one
// name with distinct passwords on one datastore-backed store. Exactly one wins;
// every other gets a mismatch, never a second binding and never a store error.
func TestSecretNodePasswordStoreConcurrentFirstWriteWins(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newSecretNodePasswords(fake.NewClientset(), quietLogger())
	const n = 4
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Ensure(ctx, "worker-1", "password-"+string(rune('a'+i)))
		}()
	}
	wg.Wait()
	wins, mismatches := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, bootstrap.ErrNodePasswordMismatch):
			mismatches++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || mismatches != n-1 {
		t.Errorf("wins = %d, mismatches = %d; want 1 and %d", wins, mismatches, n-1)
	}
}

// TestSelfBindStoreFaultBringUpFailure: a self-bind that gave up because the
// datastore never answered is logged as that, with the restart that retries it,
// and neither as the mismatch diagnosis nor as the generic mesh failure.
func TestSelfBindStoreFaultBringUpFailure(t *testing.T) {
	shrinkSelfBindRetry(t)
	ctx := context.Background()
	busy := errors.New("get node-password secret: the server was unable to return a response in the time allotted")
	opts := selfEnrollOptions(t.TempDir(), "k3sm-host")
	logOf := func(err error) string {
		sink := &syncBuffer{}
		msg, attrs := serverMeshBringUpFailure(opts, err)
		slog.New(slog.NewTextHandler(sink, nil)).Error(msg, attrs...)
		return sink.String()
	}

	store := &countingNodePasswords{inner: bootstrap.NewMemoryNodePasswords(), fault: busy, failFirst: 1 << 30}
	err := bindSelfNodePassword(ctx, store, opts.nodeName, opts.workDir)
	if !errors.Is(err, errSelfBindStoreUnavailable) || !errors.Is(err, busy) {
		t.Fatalf("err = %v, want it marked store-unavailable and carrying the store's fault", err)
	}
	out := logOf(err)
	for _, want := range []string{"datastore did not answer", "Restarting the server retries the bind", opts.nodeName} {
		if !strings.Contains(out, want) {
			t.Errorf("store-fault failure does not contain %q:\n%s", want, out)
		}
	}
	for _, banned := range []string{genericBringUpFailure, "restore the original", "no longer matches"} {
		if strings.Contains(out, banned) {
			t.Errorf("store-fault failure contains %q:\n%s", banned, out)
		}
	}

	mismatch := &countingNodePasswords{inner: bootstrap.NewMemoryNodePasswords(), fault: bootstrap.ErrNodePasswordMismatch, failFirst: 1 << 30}
	if err := bindSelfNodePassword(ctx, mismatch, opts.nodeName, opts.workDir); errors.Is(err, errSelfBindStoreUnavailable) {
		t.Errorf("a mismatch was marked store-unavailable: %v", err)
	}
	if out := logOf(errors.New("enroll self: boom")); !strings.Contains(out, genericBringUpFailure) {
		t.Errorf("an unrelated failure lost the generic wording:\n%s", out)
	}
}
