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

package crdensure

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strings"
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
	"sigs.k8s.io/yaml"

	"k3sm.io/apis/config/crd"
)

// fastOptions keeps the establishment wait short enough that a test that is
// SUPPOSED to time out does so in well under a second, while still exercising the
// real poll loop rather than a stubbed one.
func fastOptions() Options {
	return Options{Timeout: 2 * time.Second, PollInterval: 5 * time.Millisecond}
}

// newFakeAPIExtensions builds a fake API server for CustomResourceDefinitions
// that performs REAL server-side-apply field management, which the stock fake
// does not.
//
// apiextensionsfake.NewClientset would be the obvious choice, but its generated
// type converter carries an EMPTY schema for the apiextensions types, so every
// apply fails with "no type found matching". The stock NewSimpleClientset is no
// better for this test: its tracker degrades an apply to a strategic merge patch,
// which only ever ADDS — so a drift test against it would pass without the
// convergence this package's whole design rests on.
//
// So the tracker here is field-managed with a DEDUCED type converter, which
// derives the merge structure from the object itself. It gives the removal
// semantics of a real apply on a schema this client-go has no typed model for,
// which is exactly the situation a CRD document is in.
func newFakeAPIExtensions(t *testing.T) *apiextensionsfake.Clientset {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiextensions types: %v", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	tracker := k8stesting.NewFieldManagedObjectTracker(scheme, codecs.UniversalDecoder(), managedfields.NewDeducedTypeConverter())

	cs := apiextensionsfake.NewSimpleClientset()
	// Prepended, so it runs BEFORE the stock reactor and is the only tracker that
	// ever sees a verb. The stock one stays installed but unreachable.
	cs.PrependReactor("*", "*", k8stesting.ObjectReaction(tracker))
	return cs
}

// establishAsync mimics the one thing the fake API server does not do: build the
// custom resource's REST handler and report it by setting Established.
//
// It re-stamps for the lifetime of the test rather than stamping once, because a
// later apply may drop the status the previous pass wrote — and a helper that
// stopped after the first success would make the SECOND Ensure in a convergence
// test hang for reasons that have nothing to do with what the test asserts.
func establishAsync(t *testing.T, cs *apiextensionsfake.Clientset, name string) {
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
			if established(got) {
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

func established(c *apiextensionsv1.CustomResourceDefinition) bool {
	for _, cond := range c.Status.Conditions {
		if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
			return true
		}
	}
	return false
}

// storedCRD reads the CRD the fake API server actually holds.
func storedCRD(t *testing.T, cs *apiextensionsfake.Clientset, name string) *apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	got, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read stored crd %s: %v", name, err)
	}
	return got
}

// specSchema returns the spec sub-schema of the CRD's single version, which is
// where every drift this file cares about lives.
func specSchema(t *testing.T, c *apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.JSONSchemaProps {
	t.Helper()
	if len(c.Spec.Versions) != 1 {
		t.Fatalf("crd has %d versions, want 1", len(c.Spec.Versions))
	}
	v := c.Spec.Versions[0]
	if v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
		t.Fatal("crd version carries no openAPIV3Schema")
	}
	spec, ok := v.Schema.OpenAPIV3Schema.Properties["spec"]
	if !ok {
		t.Fatal("crd schema has no spec property")
	}
	return &spec
}

// TestEnsureAppliesTheCRDAndAwaitsEstablished is the core of the M8.5-a1 ensure
// slice: the manifest is written by a FORCED server-side apply under the bare
// "k3sm" field manager, and Ensure does not return until the API server reports
// the CRD Established.
//
// The field manager and the apply patch type are asserted on the recorded action
// rather than inferred from the stored object, because that is the only place the
// distinction between an apply and an update is observable — and an update would
// converge nothing on the second boot.
func TestEnsureAppliesTheCRDAndAwaitsEstablished(t *testing.T) {
	cs := newFakeAPIExtensions(t)
	establishAsync(t, cs, crd.MLXModelCRDName)

	got, err := Ensure(context.Background(), cs, crd.MLXModelCRD(), fastOptions())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got == nil || got.Name != crd.MLXModelCRDName {
		t.Fatalf("Ensure returned %+v, want the %s crd", got, crd.MLXModelCRDName)
	}
	if !established(got) {
		t.Error("Ensure returned a crd that is not Established; the wait did not observe the transition")
	}

	var patches int
	for _, action := range cs.Actions() {
		pa, ok := action.(k8stesting.PatchActionImpl)
		if !ok {
			continue
		}
		patches++
		if pa.GetPatchType() != types.ApplyPatchType {
			t.Errorf("patch type %q, want %q (server-side apply)", pa.GetPatchType(), types.ApplyPatchType)
		}
		if pa.PatchOptions.FieldManager != DefaultFieldManager {
			t.Errorf("field manager %q, want %q", pa.PatchOptions.FieldManager, DefaultFieldManager)
		}
		if pa.PatchOptions.Force == nil || !*pa.PatchOptions.Force {
			t.Error("apply was not forced; a field claimed by another manager would wedge convergence forever")
		}
		if pa.GetName() != crd.MLXModelCRDName {
			t.Errorf("applied crd name %q, want %q", pa.GetName(), crd.MLXModelCRDName)
		}
	}
	if patches != 1 {
		t.Errorf("recorded %d apply patches, want exactly 1", patches)
	}
}

// TestEnsureConvergesSchemaDrift is the convergence half of M8.5-a1: a CRD whose
// stored schema has DRIFTED from the shipped bytes — a stale property this binary
// no longer ships, and a missing validation rule it does — is brought back to the
// shipped schema by a re-ensure, not merely added to.
//
// Drift is seeded through Ensure itself, under the same field manager, because
// that is how it arises in production: an older binary applied an older manifest.
// Seeding it as an unmanaged object would make the test pass for the wrong
// reason — server-side apply only reclaims fields its own manager owns, so drift
// nobody owns is not the case that has to work.
func TestEnsureConvergesSchemaDrift(t *testing.T) {
	cs := newFakeAPIExtensions(t)
	establishAsync(t, cs, crd.MLXModelCRDName)
	ctx := context.Background()

	if _, err := Ensure(ctx, cs, driftedManifest(t), fastOptions()); err != nil {
		t.Fatalf("Ensure drifted manifest: %v", err)
	}
	drifted := specSchema(t, storedCRD(t, cs, crd.MLXModelCRDName))
	if _, ok := drifted.Properties["staleFromAnOlderBinary"]; !ok {
		t.Fatal("the drift seed did not take; the convergence assertion below would be vacuous")
	}
	if len(drifted.XValidations) != 0 {
		t.Fatal("the drift seed left the CEL rule in place; the convergence assertion below would be vacuous")
	}

	if _, err := Ensure(ctx, cs, crd.MLXModelCRD(), fastOptions()); err != nil {
		t.Fatalf("Ensure shipped manifest: %v", err)
	}

	converged := specSchema(t, storedCRD(t, cs, crd.MLXModelCRDName))
	if _, ok := converged.Properties["staleFromAnOlderBinary"]; ok {
		t.Error("the stale property survived the re-ensure; the apply added to the schema instead of converging it")
	}
	if len(converged.XValidations) == 0 {
		t.Error("the re-ensure did not restore the spec.distributed CEL rule")
	}
	if _, ok := converged.Properties["model"]; !ok {
		t.Error("convergence dropped spec.model; the apply is removing fields it does ship")
	}
}

// driftedManifest returns the shipped manifest mutated the way an older binary's
// schema would differ from it: one property this binary no longer ships, and no
// x-kubernetes-validations on spec.
func driftedManifest(t *testing.T) []byte {
	t.Helper()
	var c apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(crd.MLXModelCRD(), &c); err != nil {
		t.Fatalf("decode shipped manifest: %v", err)
	}
	spec := specSchema(t, &c)
	spec.XValidations = nil
	spec.Properties["staleFromAnOlderBinary"] = apiextensionsv1.JSONSchemaProps{Type: "string"}
	c.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"] = *spec

	out, err := yaml.Marshal(&c)
	if err != nil {
		t.Fatalf("re-encode drifted manifest: %v", err)
	}
	return out
}

// TestEnsureRefusesToProceedWithoutEstablishment pins that the wait is real. Both
// cases would otherwise return success and hand the caller a CRD whose REST
// handler does not exist — an informer started against it 404s and retries
// forever, which reads as a controller that started and sees nothing.
func TestEnsureRefusesToProceedWithoutEstablishment(t *testing.T) {
	t.Run("never established times out", func(t *testing.T) {
		cs := newFakeAPIExtensions(t) // nothing stamps Established
		opts := Options{Timeout: 100 * time.Millisecond, PollInterval: 5 * time.Millisecond}

		_, err := Ensure(context.Background(), cs, crd.MLXModelCRD(), opts)
		if !errors.Is(err, ErrNotEstablished) {
			t.Fatalf("Ensure error = %v, want ErrNotEstablished", err)
		}
	})

	t.Run("rejected names fail fast", func(t *testing.T) {
		cs := newFakeAPIExtensions(t)
		cs.PrependReactor("get", "customresourcedefinitions", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
			return true, &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: crd.MLXModelCRDName},
				Status: apiextensionsv1.CustomResourceDefinitionStatus{
					Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{{
						Type:    apiextensionsv1.NamesAccepted,
						Status:  apiextensionsv1.ConditionFalse,
						Reason:  "ListKindConflict",
						Message: "\"MLXModelList\" is already in use",
					}},
				},
			}, nil
		})
		// A generous timeout: if the name conflict were merely waited out rather
		// than short-circuited, this case would take the full 10s and the test
		// would notice as a timeout rather than as a wrong error.
		start := time.Now()
		_, err := Ensure(context.Background(), cs, crd.MLXModelCRD(), Options{Timeout: 10 * time.Second, PollInterval: 5 * time.Millisecond})
		if !errors.Is(err, ErrNamesRejected) {
			t.Fatalf("Ensure error = %v, want ErrNamesRejected", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("name conflict took %s to report; it must short-circuit, not wait out the timeout", elapsed)
		}
	})
}

// TestEnsureRejectsAManifestItCannotIdentify covers the manifest contract. Each
// case is a wiring mistake that, accepted, would either apply nothing (and hide a
// lost embed) or apply an object nobody asked for under the CRD applier's field
// manager.
func TestEnsureRejectsAManifestItCannotIdentify(t *testing.T) {
	cases := []struct {
		name     string
		manifest []byte
		want     error
	}{
		{"empty", nil, ErrNoManifest},
		{"not a crd", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"), ErrNotCRD},
		{"wrong apiextensions version", []byte("apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\n"), ErrNotCRD},
		{"unnamed", []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec: {}\n"), ErrUnnamed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := newFakeAPIExtensions(t)
			if _, err := Ensure(context.Background(), cs, tc.manifest, fastOptions()); !errors.Is(err, tc.want) {
				t.Fatalf("Ensure error = %v, want %v", err, tc.want)
			}
			for _, action := range cs.Actions() {
				if action.GetVerb() == "patch" {
					t.Error("a manifest that failed the contract was still applied")
				}
			}
		})
	}

	t.Run("malformed yaml", func(t *testing.T) {
		cs := newFakeAPIExtensions(t)
		if _, err := Ensure(context.Background(), cs, []byte("\tnot: [yaml"), fastOptions()); err == nil {
			t.Fatal("Ensure accepted malformed yaml")
		}
	})
}

// TestEnsureAppliesTheManifestBytesVerbatim pins that the applied body is the
// manifest's own JSON and not a re-marshalling of the compiled-in Go type.
//
// The difference is invisible until the manifest carries a field this client-go
// does not know — a newer schema keyword, say. A typed round trip drops it
// silently, so the cluster would run a quietly smaller CRD than the one that
// shipped, and no test that only reads the typed struct back could tell.
func TestEnsureAppliesTheManifestBytesVerbatim(t *testing.T) {
	manifest := []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.io
spec:
  group: example.io
  aFieldThisClientGoDoesNotKnow: keep-me
`)
	cs := newFakeAPIExtensions(t)
	_, _ = Ensure(context.Background(), cs, manifest, Options{Timeout: 50 * time.Millisecond, PollInterval: 5 * time.Millisecond})

	var body []byte
	for _, action := range cs.Actions() {
		if pa, ok := action.(k8stesting.PatchActionImpl); ok {
			body = pa.GetPatch()
		}
	}
	if body == nil {
		t.Fatal("no apply patch was recorded")
	}
	if !strings.Contains(string(body), "aFieldThisClientGoDoesNotKnow") {
		t.Errorf("the applied body lost an unknown field, so it is a typed re-marshalling, not the manifest bytes: %s", body)
	}
}

// TestPackageEmbedsNoManifestSet is the structural guard behind the "apply
// mlxmodels ONLY" decision.
//
// This package is neutral by construction: it takes the bytes of exactly one
// manifest from its caller. The moment it embeds a manifest — or worse, a
// directory of them — the set of CRDs k3sm creates becomes a property of what
// happens to be next to the embed, and the MeshPeer CRD that sits beside the
// MLXModel manifest in apis would be enlisted with no diff to review, giving the
// out-of-band bootstrap path a second, competing writer.
//
// The embed scan reads RAW source (an embed directive is a comment), while the
// MeshPeer scan reads source with the comments stripped — the package doc has to
// be able to explain why MeshPeer is excluded without that explanation reading as
// a violation.
func TestPackageEmbedsNoManifestSet(t *testing.T) {
	for _, name := range []string{"crdensure.go", "doc.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//go:embed") {
				t.Errorf("%s:%d declares an embed directive; this package must take its manifest from the caller", name, i+1)
			}
		}
		code := codeWithoutComments(t, name)
		for _, banned := range []string{"MeshPeer", "meshpeer", "embed.FS", "config/crd"} {
			if strings.Contains(code, banned) {
				t.Errorf("%s code references %q; the applied CRD set is the caller's decision, not this package's", name, banned)
			}
		}
	}
}

// codeWithoutComments renders the Go source at path with every comment removed,
// so a scan for a banned identifier cannot be tripped by prose that names it in
// order to explain its absence.
func codeWithoutComments(t *testing.T, path string) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0) // no ParseComments: comments are dropped
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, file); err != nil {
		t.Fatalf("print %s: %v", path, err)
	}
	return buf.String()
}
