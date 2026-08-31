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
	"go/parser"
	"go/token"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	k8stesting "k8s.io/client-go/testing"

	crdconfig "k3sm.io/apis/config/crd"
	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/k3sm/pkg/crdensure"
)

// newFakeCRDAPI builds a fake API server for CustomResourceDefinitions that
// performs REAL server-side-apply field management.
//
// It mirrors pkg/crdensure's own test fixture, and for the same reason: the stock
// fake clientset degrades an apply patch to a strategic merge patch, so a test
// against it would pass without ever exercising the apply this bring-up depends on.
// The tracker is field-managed with a DEDUCED type converter, which derives the
// merge structure from the object itself — the only option for a schema document
// this client-go has no typed model for.
func newFakeCRDAPI(t *testing.T) *apiextensionsfake.Clientset {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiextensions types: %v", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	tracker := k8stesting.NewFieldManagedObjectTracker(scheme, codecs.UniversalDecoder(), managedfields.NewDeducedTypeConverter())

	cs := apiextensionsfake.NewSimpleClientset()
	// Prepended, so it runs BEFORE the stock reactor and is the only tracker that
	// ever sees a verb.
	cs.PrependReactor("*", "*", k8stesting.ObjectReaction(tracker))
	return cs
}

// establishCRDAsync mimics the one thing the fake API server does not do: build the
// custom resource's REST handler and report it by setting Established. Without it
// every Ensure would burn its whole timeout, because the wait is real.
func establishCRDAsync(t *testing.T, cs *apiextensionsfake.Clientset, name string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			client := cs.ApiextensionsV1().CustomResourceDefinitions()
			got, err := client.Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			alreadyEstablished := false
			for _, cond := range got.Status.Conditions {
				if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
					alreadyEstablished = true
				}
			}
			if alreadyEstablished {
				continue
			}
			got.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{
				{Type: apiextensionsv1.NamesAccepted, Status: apiextensionsv1.ConditionTrue, Reason: "NoConflicts"},
				{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue, Reason: "InitialNamesAccepted"},
			}
			_, _ = client.UpdateStatus(ctx, got, metav1.UpdateOptions{}) // best effort; the loop retries
		}
	}()
}

// TestEnsureMeshPeerCRDProvisionsOnlyOnTheMeshPath is the B224 core: `k3sm server
// --mesh-ip` establishes the MeshPeer CRD, and plain single-node `k3sm server` does
// not touch the API server at all.
//
// The single-node case asserts on the CLIENT FACTORY, not merely on the recorded
// actions: the contract is that a bring-up with no MeshPeer consumer builds no
// apiextensions client, so single-node gains no new failure mode from this change.
// A test that only counted actions would still pass if the client were constructed
// and then left unused, which is the thing being ruled out.
func TestEnsureMeshPeerCRDProvisionsOnlyOnTheMeshPath(t *testing.T) {
	tests := []struct {
		name          string
		meshIP        string
		wantClients   int
		wantEstablish bool
	}{
		{name: "single_node_provisions_nothing", meshIP: "", wantClients: 0},
		{name: "mesh_path_establishes_the_crd", meshIP: "100.64.0.1", wantClients: 1, wantEstablish: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := newFakeCRDAPI(t)
			establishCRDAsync(t, cs, crdconfig.MeshPeerCRDName)

			clients := 0
			factory := func() (crdensure.CRDClient, error) {
				clients++
				return cs, nil
			}
			if err := ensureMeshPeerCRD(context.Background(), tc.meshIP, factory, quietLogger()); err != nil {
				t.Fatalf("ensureMeshPeerCRD(meshIP=%q): %v", tc.meshIP, err)
			}
			if clients != tc.wantClients {
				t.Errorf("built %d apiextensions clients, want %d", clients, tc.wantClients)
			}

			applies := 0
			for _, action := range cs.Actions() {
				pa, ok := action.(k8stesting.PatchActionImpl)
				if !ok {
					continue
				}
				applies++
				if pa.GetPatchType() != types.ApplyPatchType {
					t.Errorf("patch type %q, want %q (server-side apply)", pa.GetPatchType(), types.ApplyPatchType)
				}
				if pa.GetName() != crdconfig.MeshPeerCRDName {
					t.Errorf("applied crd %q, want %q", pa.GetName(), crdconfig.MeshPeerCRDName)
				}
				if pa.PatchOptions.FieldManager != crdensure.DefaultFieldManager {
					t.Errorf("field manager %q, want %q", pa.PatchOptions.FieldManager, crdensure.DefaultFieldManager)
				}
			}
			if !tc.wantEstablish {
				if applies != 0 {
					t.Fatalf("single-node bring-up issued %d crd applies, want 0", applies)
				}
				return
			}
			if applies != 1 {
				t.Fatalf("recorded %d crd applies, want exactly 1", applies)
			}
			stored, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(
				context.Background(), crdconfig.MeshPeerCRDName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("read back the stored MeshPeer crd: %v", err)
			}
			if stored.Spec.Group != netv1.SchemeGroupVersion.Group {
				t.Errorf("stored crd group %q, want %q", stored.Spec.Group, netv1.SchemeGroupVersion.Group)
			}
			if stored.Spec.Names.Plural != meshPeerResource {
				t.Errorf("stored crd plural %q, want %q (the resource the enroller writes)", stored.Spec.Names.Plural, meshPeerResource)
			}
		})
	}
}

// TestEnsureMeshPeerCRDFailsClosed pins the fail-closed contract: neither a client
// that cannot be built nor an API server that rejects the apply is swallowed.
//
// This is the half that distinguishes step 4a from the log-and-continue admission
// provisioners beside it. A MeshPeer CRD that silently failed to apply produces a
// control plane whose join listener accepts workers and then 500s every enroll —
// the exact defect B224 exists to remove, re-created one level up.
func TestEnsureMeshPeerCRDFailsClosed(t *testing.T) {
	errFactory := errors.New("no apiextensions client")
	errApply := errors.New("apiserver refused the apply")

	t.Run("client_construction_failure", func(t *testing.T) {
		err := ensureMeshPeerCRD(context.Background(), "100.64.0.1",
			func() (crdensure.CRDClient, error) { return nil, errFactory }, quietLogger())
		if !errors.Is(err, errFactory) {
			t.Fatalf("err = %v, want it to wrap %v", err, errFactory)
		}
	})

	t.Run("apply_rejected", func(t *testing.T) {
		cs := newFakeCRDAPI(t)
		cs.PrependReactor("patch", "customresourcedefinitions",
			func(k8stesting.Action) (bool, k8sruntime.Object, error) { return true, nil, errApply })
		err := ensureMeshPeerCRD(context.Background(), "100.64.0.1",
			func() (crdensure.CRDClient, error) { return cs, nil }, quietLogger())
		if !errors.Is(err, errApply) {
			t.Fatalf("err = %v, want it to wrap %v", err, errApply)
		}
	})
}

// TestRunServerEnsuresMeshPeerCRDBeforeTheJoinListener is the ORDERING gate, and it
// reads the source rather than running it.
//
// runServer boots a real control plane, so no unit test can call it; and this
// repo's recurring defect class is precisely a well-tested helper that bring-up
// never calls (B195, B209). So the invariant is asserted structurally: within
// runServer, the ensureMeshPeerCRD call must appear BEFORE newMeshEnroller and
// before startBootstrapServer, and its error must be RETURNED rather than logged.
//
// Ordering matters because startBootstrapServer opens the join listener: the first
// worker to reach it writes a MeshPeer, so a CRD established afterwards would still
// lose that join. Source position is a sound proxy here because all three calls sit
// in runServer's straight-line bring-up sequence — there is no loop or branch that
// could execute them out of textual order.
func TestRunServerEnsuresMeshPeerCRDBeforeTheJoinListener(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	var runServerDecl *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "runServer" {
			runServerDecl = fn
		}
	}
	if runServerDecl == nil {
		t.Fatal("server.go declares no runServer function")
	}

	first := map[string]token.Pos{}
	ast.Inspect(runServerDecl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if _, seen := first[ident.Name]; !seen {
			first[ident.Name] = call.Pos()
		}
		return true
	})

	for _, name := range []string{"ensureMeshPeerCRD", "newMeshEnroller", "startBootstrapServer"} {
		if _, ok := first[name]; !ok {
			t.Fatalf("runServer never calls %s — the MeshPeer CRD wiring is absent (a worker join will 500 at the enroll write)", name)
		}
	}
	for _, later := range []string{"newMeshEnroller", "startBootstrapServer"} {
		if first["ensureMeshPeerCRD"] >= first[later] {
			t.Errorf("runServer calls ensureMeshPeerCRD at %s, NOT before %s at %s — a join racing bring-up would meet a missing CRD",
				fset.Position(first["ensureMeshPeerCRD"]), later, fset.Position(first[later]))
		}
	}

	// Fail-closed: the ensure sits in an `if err := ...; err != nil { return ... }`,
	// not in a logged-and-ignored branch.
	returned := false
	ast.Inspect(runServerDecl.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			return true
		}
		calls := false
		ast.Inspect(ifStmt.Init, func(m ast.Node) bool {
			if ident, ok := m.(*ast.Ident); ok && ident.Name == "ensureMeshPeerCRD" {
				calls = true
			}
			return true
		})
		if !calls {
			return true
		}
		ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
			if _, ok := m.(*ast.ReturnStmt); ok {
				returned = true
			}
			return true
		})
		return true
	})
	if !returned {
		t.Error("runServer does not RETURN on an ensureMeshPeerCRD failure; bring-up would continue with no MeshPeer CRD and 500 every worker join")
	}
}
