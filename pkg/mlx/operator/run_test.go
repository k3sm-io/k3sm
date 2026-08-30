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

package operator

import (
	"context"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/managedfields"
	k8stesting "k8s.io/client-go/testing"

	crdconfig "k3sm.io/apis/config/crd"
)

// fakeCRDServer builds a fake apiextensions API server that performs real
// server-side apply and, like the real one, marks a CRD Established shortly after
// it appears.
//
// The stock fakes cannot do the apply: NewClientset's generated type converter
// carries an empty schema for the apiextensions types, and NewSimpleClientset
// degrades an apply to a strategic merge patch. A field-managed tracker with a
// deduced type converter gives real apply semantics on a schema this client-go
// has no typed model for.
func fakeCRDServer(t *testing.T) *apiextensionsfake.Clientset {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiextensions types: %v", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	tracker := k8stesting.NewFieldManagedObjectTracker(scheme, codecs.UniversalDecoder(), managedfields.NewDeducedTypeConverter())

	cs := apiextensionsfake.NewSimpleClientset()
	cs.PrependReactor("*", "*", k8stesting.ObjectReaction(tracker))

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
			list, err := client.List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
			for i := range list.Items {
				item := list.Items[i]
				if hasEstablished(&item) {
					continue
				}
				item.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{
					{Type: apiextensionsv1.NamesAccepted, Status: apiextensionsv1.ConditionTrue, Reason: "NoConflicts"},
					{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue, Reason: "InitialNamesAccepted"},
				}
				_, _ = client.UpdateStatus(ctx, &item, metav1.UpdateOptions{})
			}
		}
	}()
	return cs
}

func hasEstablished(c *apiextensionsv1.CustomResourceDefinition) bool {
	for _, cond := range c.Status.Conditions {
		if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
			return true
		}
	}
	return false
}

// TestRunEnsuresTheMLXModelCRDAndNothingElse is the Res. 10 guard seen from the
// operator's side: starting the controller creates EXACTLY ONE
// CustomResourceDefinition, the MLXModel one.
//
// The MeshPeer CRD ships in the same apis directory as the MLXModel manifest and
// is applied out-of-band by the existing bootstrap path. If this ensure ever
// widened — an embed glob, a "the CRDs k3sm applies" list — MeshPeer would be
// adopted as a side effect, giving that bootstrap path a second, competing
// writer with a forced field manager and no diff anywhere to review it. This test
// is what makes that widening loud.
func TestRunEnsuresTheMLXModelCRDAndNothingElse(t *testing.T) {
	crdClient := fakeCRDServer(t)
	h := newHarness(t, model(), func(c *Config) { c.CRD = crdClient })

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- h.ctrl.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		list, err := crdClient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
		return err == nil && len(list.Items) > 0
	}, "the mlxmodels CRD was never applied")

	list, err := crdClient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list crds: %v", err)
	}
	if len(list.Items) != 1 {
		var names []string
		for _, item := range list.Items {
			names = append(names, item.Name)
		}
		t.Fatalf("the operator applied %d CRDs (%v), want exactly the mlxmodels one", len(list.Items), names)
	}
	if got := list.Items[0].Name; got != crdconfig.MLXModelCRDName {
		t.Errorf("applied CRD %q, want %q", got, crdconfig.MLXModelCRDName)
	}
	if list.Items[0].Spec.Group == "net.k3sm.io" {
		t.Error("the operator applied the MeshPeer CRD; adopting it owes a mesh-regression check and must not be a side effect")
	}

	// The drain contract: Run returns only after the worker has stopped, so the
	// control plane can be torn down knowing no write is in flight.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned %v after a clean cancel, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx was cancelled; the drain would hang shutdown")
	}
}

// TestRunReconcilesEveryExistingModelOnStart pins the recovery path: the
// informer's initial sync re-delivers every existing MLXModel as an Add, so a
// control-plane restart re-reconciles each one and strands none.
func TestRunReconcilesEveryExistingModelOnStart(t *testing.T) {
	h := newHarness(t, model(), nil) // no CRD client: something else established it

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- h.ctrl.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		sts, err := h.kube.AppsV1().StatefulSets(testNamespace).Get(ctx, testModelName, metav1.GetOptions{})
		return err == nil && sts != nil
	}, "the pre-existing MLXModel was never reconciled after start")

	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx was cancelled")
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}
