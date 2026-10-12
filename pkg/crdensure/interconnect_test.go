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
	"context"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/apis/config/crd"
)

// TestEnsuresInterconnectCRD is the B524 gate for the Interconnect CRD: the
// server's resolver hands this package crd.InterconnectCRD() beside the CRDs it
// already ensures (MeshPeer, MLXModel), and the ensure must apply exactly that
// manifest, wait for Established, and leave the shape the resolver and the
// `k3sm interconnect` verbs depend on: cluster scope (one object per medium),
// v1alpha1 served and stored, the status subresource the resolver writes
// through, and spec.enabled defaulting to false (an admin arms the cable,
// never a plug-in). A re-ensure on the next boot converges without error.
func TestEnsuresInterconnectCRD(t *testing.T) {
	cs := newFakeAPIExtensions(t)
	for _, name := range []string{crd.InterconnectCRDName, crd.MeshPeerCRDName, crd.MLXModelCRDName} {
		establishAsync(t, cs, name)
	}
	ctx := context.Background()

	// Beside the existing CRDs: ensuring the others first must not stop the
	// Interconnect ensure, and vice versa.
	for _, manifest := range [][]byte{crd.MeshPeerCRD(), crd.MLXModelCRD()} {
		if _, err := Ensure(ctx, cs, manifest, fastOptions()); err != nil {
			t.Fatalf("Ensure sibling CRD: %v", err)
		}
	}
	got, err := Ensure(ctx, cs, crd.InterconnectCRD(), fastOptions())
	if err != nil {
		t.Fatalf("Ensure(InterconnectCRD): %v", err)
	}
	if got == nil || got.Name != crd.InterconnectCRDName {
		t.Fatalf("Ensure returned %+v, want the %s crd", got, crd.InterconnectCRDName)
	}
	if !established(got) {
		t.Fatal("Ensure returned an Interconnect CRD that is not Established; an informer started now would 404")
	}

	var applied int
	for _, action := range cs.Actions() {
		pa, ok := action.(k8stesting.PatchActionImpl)
		if !ok || pa.GetName() != crd.InterconnectCRDName {
			continue
		}
		applied++
		if pa.PatchOptions.FieldManager != DefaultFieldManager || pa.PatchOptions.Force == nil || !*pa.PatchOptions.Force {
			t.Errorf("Interconnect CRD applied with manager %q force %v, want a forced apply under %q",
				pa.PatchOptions.FieldManager, pa.PatchOptions.Force, DefaultFieldManager)
		}
	}
	if applied != 1 {
		t.Errorf("recorded %d applies of %s, want exactly 1", applied, crd.InterconnectCRDName)
	}

	stored := storedCRD(t, cs, crd.InterconnectCRDName)
	if stored.Spec.Group != "net.k3sm.io" || stored.Spec.Names.Kind != "Interconnect" || stored.Spec.Names.Plural != "interconnects" {
		t.Errorf("stored CRD names %s/%s/%s, want net.k3sm.io Interconnect interconnects",
			stored.Spec.Group, stored.Spec.Names.Kind, stored.Spec.Names.Plural)
	}
	if stored.Spec.Scope != apiextensionsv1.ClusterScoped {
		t.Errorf("scope = %s, want Cluster (one object per medium)", stored.Spec.Scope)
	}
	if len(stored.Spec.Versions) != 1 {
		t.Fatalf("stored CRD has %d versions, want 1", len(stored.Spec.Versions))
	}
	v := stored.Spec.Versions[0]
	if v.Name != "v1alpha1" || !v.Served || !v.Storage {
		t.Errorf("version %s served=%v storage=%v, want v1alpha1 served and stored", v.Name, v.Served, v.Storage)
	}
	if v.Subresources == nil || v.Subresources.Status == nil {
		t.Error("the status subresource is missing; the resolver's UpdateStatus would 404")
	}
	enabled, ok := specSchema(t, stored).Properties["enabled"]
	if !ok || enabled.Default == nil || string(enabled.Default.Raw) != "false" {
		t.Errorf("spec.enabled default = %v, want false (armed by an admin, never by plugging in)", enabled.Default)
	}

	// The next boot re-ensures the same bytes; it must converge, not fail.
	if _, err := Ensure(ctx, cs, crd.InterconnectCRD(), fastOptions()); err != nil {
		t.Fatalf("re-Ensure(InterconnectCRD): %v", err)
	}
	for _, name := range []string{crd.MeshPeerCRDName, crd.MLXModelCRDName, crd.InterconnectCRDName} {
		storedCRD(t, cs, name)
	}
}
