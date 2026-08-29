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

package addons

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The GroupVersionKinds the fixtures use: one namespaced (ConfigMap), one
// cluster-scoped (Namespace), and one that is deliberately absent from the mapper so an
// unmappable document can be exercised.
var (
	configMapGVK = schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}
	namespaceGVK = schema.GroupVersionKind{Version: "v1", Kind: "Namespace"}

	configMapGVR = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	namespaceGVR = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
)

// testMapper is the RESTMapper seam the reconciler maps GroupVersionKinds through. A
// static mapper (rather than fake discovery) keeps the test hermetic and lets an
// unmapped kind be expressed simply by not registering it.
func testMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Version: "v1"}})
	m.Add(configMapGVK, meta.RESTScopeNamespace)
	m.Add(namespaceGVK, meta.RESTScopeRoot)
	return m
}

// applyRecord is one apply patch the reconciler issued, reduced to the dimensions the
// assertions care about.
type applyRecord struct {
	resource  schema.GroupVersionResource
	namespace string
	name      string
}

// newFakeDynamic builds a fake dynamic client seeded with objects and taught SSA's
// create-on-absent semantics.
//
// The stock fake tracker's apply is a documented Kubernetes-1.30-compatibility shim: it
// Gets the object first and fails NotFound, so it cannot model an apply that CREATES.
// The upsert reactor below supplies exactly that missing half and nothing else — every
// assertion in this file is over the API traffic the reconciler emitted (recorded before
// any reactor runs) and over the resulting object presence, never over apiserver merge
// semantics the fake does not implement.
func newFakeDynamic(t *testing.T, seed ...*unstructured.Unstructured) *dynamicfake.FakeDynamicClient {
	t.Helper()
	objs := make([]runtime.Object, 0, len(seed))
	for _, o := range seed {
		objs = append(objs, o)
	}
	// The list kinds are registered even though the reconciler must never LIST: without
	// them the fake PANICS on a list call, which would red the gate for the wrong reason
	// and hide the verb assertion in verifyTrafficShape. Registered, a LIST succeeds and
	// is RECORDED — so the ban is enforced by the assertion, not by a fake's limitation.
	listKinds := map[schema.GroupVersionResource]string{
		configMapGVR: "ConfigMapList",
		namespaceGVR: "NamespaceList",
	}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)
	tracker := dc.Tracker()
	dc.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pa, ok := action.(k8stesting.PatchActionImpl)
		if !ok || pa.GetPatchType() != types.ApplyPatchType {
			return false, nil, nil
		}
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(pa.GetPatch()); err != nil {
			return true, nil, err
		}
		gvr, ns := pa.GetResource(), pa.GetNamespace()
		_, err := tracker.Get(gvr, ns, pa.GetName(), metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return true, obj, tracker.Create(gvr, obj, ns)
		case err != nil:
			return true, nil, err
		default:
			return true, obj, tracker.Update(gvr, obj, ns)
		}
	})
	return dc
}

// failApplyOf makes the apply of the named object fail, so a per-object failure can be
// injected without disturbing its siblings.
func failApplyOf(dc *dynamicfake.FakeDynamicClient, name, msg string) {
	dc.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pa, ok := action.(k8stesting.PatchActionImpl)
		if !ok || pa.GetName() != name {
			return false, nil, nil
		}
		return true, nil, apierrors.NewInternalError(&internalErr{msg})
	})
}

// internalErr is a minimal error carrying a fixed message, for injecting apply failures.
type internalErr struct{ msg string }

func (e *internalErr) Error() string { return e.msg }

// verifyTrafficShape asserts the invariants that must hold for EVERY converge, whatever
// the manifest set: the reconciler issues apply patches and NOTHING else.
//
// This is where B170's two BINDING prune constraints are encoded mechanically rather
// than trusted:
//
//   - "never LIST to decide a DELETE" — a list verb is a failure here, so the decision
//     input cannot exist;
//   - "never delete on a label" — a delete verb is a failure here, so no deletion path
//     of any kind (label-keyed or otherwise) can be reached. The reconciler shipped in
//     this slice is converge-only, so the constraint is encoded in its strongest form:
//     zero delete verbs, ever.
//
// It also pins the SSA contract itself (apply patch type, the k3sm-addons field manager,
// force) and the ban on writing kubectl's last-applied-configuration annotation.
func verifyTrafficShape(t *testing.T, actions []k8stesting.Action) []applyRecord {
	t.Helper()
	var applies []applyRecord
	for i, action := range actions {
		if action.GetVerb() != "patch" {
			t.Errorf("action %d: verb %q; the reconciler must issue apply patches ONLY (a list/delete verb is the prune constraint being violated)", i, action.GetVerb())
			continue
		}
		pa, ok := action.(k8stesting.PatchActionImpl)
		if !ok {
			t.Errorf("action %d: patch verb with a %T action", i, action)
			continue
		}
		if pa.GetPatchType() != types.ApplyPatchType {
			t.Errorf("action %d: patch type %q, want %q (server-side apply)", i, pa.GetPatchType(), types.ApplyPatchType)
		}
		if got := pa.PatchOptions.FieldManager; got != FieldManager {
			t.Errorf("action %d: field manager %q, want %q", i, got, FieldManager)
		}
		if pa.PatchOptions.Force == nil || !*pa.PatchOptions.Force {
			t.Errorf("action %d: apply is not forced; a field another manager claimed would wedge convergence", i)
		}
		if strings.Contains(string(pa.GetPatch()), "last-applied-configuration") {
			t.Errorf("action %d: patch writes kubectl's last-applied-configuration annotation", i)
		}
		applies = append(applies, applyRecord{resource: pa.GetResource(), namespace: pa.GetNamespace(), name: pa.GetName()})
	}
	return applies
}

// patchesOf renders the raw apply payloads, so two converge passes can be compared byte
// for byte.
func patchesOf(actions []k8stesting.Action) []string {
	var out []string
	for _, a := range actions {
		if pa, ok := a.(k8stesting.PatchActionImpl); ok {
			out = append(out, string(pa.GetPatch()))
		}
	}
	return out
}

// unstructuredObj builds a seed object for the fake tracker.
func unstructuredObj(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind}}
	o.SetName(name)
	if namespace != "" {
		o.SetNamespace(namespace)
	}
	return o
}

const cmA = `apiVersion: v1
kind: ConfigMap
metadata:
  name: addon-a
  namespace: kube-system
data:
  greeting: hello
`

const nsCluster = `apiVersion: v1
kind: Namespace
metadata:
  name: addon-space
`

func TestEmbeddedManifestReconcile(t *testing.T) {
	tests := []struct {
		name string
		// files is the fixture manifest tree bound to the fs.FS seam production binds
		// the embedded tree to.
		files fstest.MapFS
		// failApply names an object whose apply the fake rejects.
		failApply string
		// wantApplies is the apply traffic expected, in order.
		wantApplies []applyRecord
		// wantErrs are substrings every one of which must appear in the joined error; an
		// empty slice means Converge must return nil.
		wantErrs []string
	}{
		{
			name: "an empty manifest set applies nothing and is not an error",
			files: fstest.MapFS{
				"README.md": &fstest.MapFile{Data: []byte("# notes, not a manifest\n")},
			},
		},
		{
			name: "namespaced and cluster-scoped objects are applied in the tree's lexical order",
			files: fstest.MapFS{
				"a-configmap.yaml": &fstest.MapFile{Data: []byte(cmA)},
				"b-namespace.yaml": &fstest.MapFile{Data: []byte(nsCluster)},
			},
			wantApplies: []applyRecord{
				{resource: configMapGVR, namespace: "kube-system", name: "addon-a"},
				{resource: namespaceGVR, name: "addon-space"},
			},
		},
		{
			name: "every document of a multi-document file is applied and blank documents are skipped",
			files: fstest.MapFS{
				"multi.yaml": &fstest.MapFile{Data: []byte("---\n" + cmA + "---\n# just a comment\n---\n" + nsCluster)},
			},
			wantApplies: []applyRecord{
				{resource: configMapGVR, namespace: "kube-system", name: "addon-a"},
				{resource: namespaceGVR, name: "addon-space"},
			},
		},
		{
			name: "non-manifest files are ignored",
			files: fstest.MapFS{
				"notes.txt":   &fstest.MapFile{Data: []byte("not yaml at all")},
				"README.md":   &fstest.MapFile{Data: []byte("# authoring contract")},
				"stray.json":  &fstest.MapFile{Data: []byte(`{"apiVersion":"v1","kind":"ConfigMap"}`)},
				"real.yaml":   &fstest.MapFile{Data: []byte(cmA)},
				"other.yml":   &fstest.MapFile{Data: []byte(nsCluster)},
				"skip.yaml.t": &fstest.MapFile{Data: []byte("garbage")},
			},
			wantApplies: []applyRecord{
				{resource: namespaceGVR, name: "addon-space"},
				{resource: configMapGVR, namespace: "kube-system", name: "addon-a"},
			},
		},
		{
			name: "nested directories are walked",
			files: fstest.MapFS{
				"metrics/deploy.yaml": &fstest.MapFile{Data: []byte(cmA)},
			},
			wantApplies: []applyRecord{
				{resource: configMapGVR, namespace: "kube-system", name: "addon-a"},
			},
		},
		{
			name: "a rejected apply does not abort the objects after it",
			files: fstest.MapFS{
				"a.yaml": &fstest.MapFile{Data: []byte(cmA)},
				"b.yaml": &fstest.MapFile{Data: []byte(nsCluster)},
			},
			failApply: "addon-a",
			wantApplies: []applyRecord{
				{resource: configMapGVR, namespace: "kube-system", name: "addon-a"},
				{resource: namespaceGVR, name: "addon-space"},
			},
			wantErrs: []string{"apply", "addon-a", "apiserver said no"},
		},
		{
			name: "an undecodable document does not abort its siblings",
			files: fstest.MapFS{
				"a-broken.yaml": &fstest.MapFile{Data: []byte("apiVersion: v1\nkind: ConfigMap\n\tname: tabbed\n")},
				"b-good.yaml":   &fstest.MapFile{Data: []byte(nsCluster)},
			},
			wantApplies: []applyRecord{
				{resource: namespaceGVR, name: "addon-space"},
			},
			wantErrs: []string{"a-broken.yaml"},
		},
		{
			name: "a document with no name is refused and its siblings still apply",
			files: fstest.MapFS{
				"a-unnamed.yaml": &fstest.MapFile{Data: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  namespace: kube-system\n")},
				"b-good.yaml":    &fstest.MapFile{Data: []byte(nsCluster)},
			},
			wantApplies: []applyRecord{
				{resource: namespaceGVR, name: "addon-space"},
			},
			wantErrs: []string{"a-unnamed.yaml", "no metadata.name"},
		},
		{
			name: "a document using generateName is refused",
			files: fstest.MapFS{
				"gen.yaml": &fstest.MapFile{Data: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: seed\n  generateName: seed-\n  namespace: kube-system\n")},
			},
			wantErrs: []string{"generateName"},
		},
		{
			name: "an unmappable GroupVersionKind is refused and its siblings still apply",
			files: fstest.MapFS{
				"a-widget.yaml": &fstest.MapFile{Data: []byte("apiVersion: example.k3sm.io/v1\nkind: Widget\nmetadata:\n  name: w\n  namespace: kube-system\n")},
				"b-good.yaml":   &fstest.MapFile{Data: []byte(nsCluster)},
			},
			wantApplies: []applyRecord{
				{resource: namespaceGVR, name: "addon-space"},
			},
			wantErrs: []string{"map example.k3sm.io/v1, Kind=Widget"},
		},
		{
			name: "a namespaced object with no namespace is refused rather than defaulted",
			files: fstest.MapFS{
				"cm.yaml": &fstest.MapFile{Data: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: homeless\n")},
			},
			wantErrs: []string{"namespaced object declares no metadata.namespace"},
		},
		{
			name: "a cluster-scoped object carrying a namespace is refused",
			files: fstest.MapFS{
				"ns.yaml": &fstest.MapFile{Data: []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: addon-space\n  namespace: kube-system\n")},
			},
			wantErrs: []string{"cluster-scoped object declares a metadata.namespace"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dc := newFakeDynamic(t)
			if tc.failApply != "" {
				failApplyOf(dc, tc.failApply, "apiserver said no")
			}
			r := New(tc.files, dc, testMapper())

			err := r.Converge(ctx)
			checkErr(t, err, tc.wantErrs)

			first := dc.Actions()
			got := verifyTrafficShape(t, first)
			if !equalRecords(got, tc.wantApplies) {
				t.Errorf("apply traffic = %v, want %v", got, tc.wantApplies)
			}

			// Idempotence: a second converge must issue the SAME apply patches, byte for
			// byte, and no other verb. Identical bytes is the mechanical form of "the
			// manifests stamp nothing per-boot-varying" — under server-side apply an
			// identical re-apply by the same field manager is a benign no-op at the
			// apiserver (no resourceVersion bump), which is what makes converging on
			// every start free against an append-only datastore.
			dc.ClearActions()
			checkErr(t, r.Converge(ctx), tc.wantErrs)
			second := dc.Actions()
			verifyTrafficShape(t, second)
			if got, want := patchesOf(second), patchesOf(first); !equalStrings(got, want) {
				t.Errorf("second converge issued different apply payloads:\n got %v\nwant %v", got, want)
			}
		})
	}

	t.Run("dropping a manifest from the set never issues a delete and leaves the object in the cluster", func(t *testing.T) {
		// The BINDING prune constraint, exercised end to end: the embedded set SHRINKS
		// between two converges. A label-keyed prune or a LIST-diff prune would delete
		// addon-space here; a converge-only reconciler leaves it alone.
		ctx := context.Background()
		dc := newFakeDynamic(t)
		mapper := testMapper()

		full := fstest.MapFS{
			"a.yaml": &fstest.MapFile{Data: []byte(cmA)},
			"b.yaml": &fstest.MapFile{Data: []byte(nsCluster)},
		}
		if err := New(full, dc, mapper).Converge(ctx); err != nil {
			t.Fatalf("converge full set: %v", err)
		}
		shrunk := fstest.MapFS{
			"a.yaml": &fstest.MapFile{Data: []byte(cmA)},
		}
		dc.ClearActions()
		if err := New(shrunk, dc, mapper).Converge(ctx); err != nil {
			t.Fatalf("converge shrunk set: %v", err)
		}

		got := verifyTrafficShape(t, dc.Actions())
		want := []applyRecord{{resource: configMapGVR, namespace: "kube-system", name: "addon-a"}}
		if !equalRecords(got, want) {
			t.Errorf("traffic after the set shrank = %v, want %v", got, want)
		}
		if _, err := dc.Tracker().Get(namespaceGVR, "", "addon-space", metav1.GetOptions{}); err != nil {
			t.Errorf("the dropped object was removed from the cluster: %v; the reconciler must never delete", err)
		}
	})

	t.Run("an object the embedded set never contained is untouched", func(t *testing.T) {
		// The other half of the prune constraint: objects k3sm's other packages stamp
		// with k3sm.io/managed (PersistentVolumes, the kube-dns Service, the node-datapath
		// ClusterRoleBinding, the admission policies) are not this reconciler's to reason
		// about at all. Converge-only means it cannot see them, let alone delete them.
		ctx := context.Background()
		foreign := unstructuredObj("v1", "ConfigMap", "kube-system", "someone-elses")
		foreign.SetLabels(map[string]string{"k3sm.io/managed": "true"})
		dc := newFakeDynamic(t, foreign)

		files := fstest.MapFS{"a.yaml": &fstest.MapFile{Data: []byte(cmA)}}
		if err := New(files, dc, testMapper()).Converge(ctx); err != nil {
			t.Fatalf("converge: %v", err)
		}
		got := verifyTrafficShape(t, dc.Actions())
		want := []applyRecord{{resource: configMapGVR, namespace: "kube-system", name: "addon-a"}}
		if !equalRecords(got, want) {
			t.Errorf("traffic = %v, want %v (the foreign object must not be touched)", got, want)
		}
		if _, err := dc.Tracker().Get(configMapGVR, "kube-system", "someone-elses", metav1.GetOptions{}); err != nil {
			t.Errorf("a k3sm.io/managed object authored by another package was removed: %v", err)
		}
	})

	t.Run("the production embedded set ships empty of product manifests", func(t *testing.T) {
		// The shipped slice: FS() binds the compiled-in tree, which today holds only the
		// authoring README. Converging it must be a complete no-op — no API traffic at
		// all — which is what makes wiring it into server bring-up inert until the first
		// real add-on lands.
		ctx := context.Background()
		dc := newFakeDynamic(t)
		if err := New(FS(), dc, testMapper()).Converge(ctx); err != nil {
			t.Fatalf("converge the production embedded set: %v", err)
		}
		if actions := dc.Actions(); len(actions) != 0 {
			t.Errorf("the production embedded set issued %d API calls, want 0: %v", len(actions), actions)
		}
	})
}

// checkErr asserts that err carries every wanted substring, or is nil when none are
// wanted.
func checkErr(t *testing.T, err error, want []string) {
	t.Helper()
	if len(want) == 0 {
		if err != nil {
			t.Fatalf("Converge() = %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("Converge() = nil, want an error containing %v", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("Converge() error %q does not contain %q", err, w)
		}
	}
}

func equalRecords(got, want []applyRecord) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
